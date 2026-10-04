/**
 * opencode-bunker — `onnx-local` classifier provider.
 *
 * Runs the fine-tuned Laya decision model (`impacte/bunker-laya`) fully
 * in-process: Transformers.js provides the tokenizer, ONNX Runtime runs the
 * exported decision graph. No Python sidecar.
 *
 * The graph contract (see the model card):
 *   inputs : input_ids, attention_mask, marker_pos, marker_mask, qtype
 *   outputs: logits [batch, num_markers], act_logits [batch, 2]
 *
 * Each question is one row. The head is:
 *   [CLS] <qtype> question: <instructions> [SEP] [MASK] false: ... [MASK] true: ... [SEP] <state> [SEP]
 * and `marker_pos` points at each option's [MASK]. For a `noul` question there
 * are exactly two options, so P(true) = softmax(logits[:2] / temperature)[1].
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { createWriteStream } from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import { Readable } from "node:stream"
import { pipeline } from "node:stream/promises"

export interface OnnxQuestion {
  type: "noul"
  instructions: string
}

export interface OnnxLocalOptions {
  /** Hugging Face repo id, e.g. `impacte/bunker-laya`. */
  model: string
  /** Which ONNX file to use: `q8` -> model.int8.onnx, `fp32` -> model.onnx. */
  dtype?: "q8" | "fp32"
  /** Cache directory (default `~/.cache/opencode-bunker`). */
  cacheDir?: string
  /** Model context length (from rl_agent_config.json). */
  maxLen?: number
  /** Head budget (from rl_agent_config.json). */
  headMaxLen?: number
  /** Per-question-type temperatures (from rl_agent_config.json). */
  temperature?: number[]
  /** noul question bank. */
  questions: Record<string, OnnxQuestion>
  /** Optional progress callback. */
  onProgress?: (message: string) => void
}

export interface OnnxLocalProvider {
  predict(text: string): Promise<Record<string, number>>
  dispose(): Promise<void>
}

const HF_BASE = "https://huggingface.co"

function expandHome(p: string): string {
  return p.startsWith("~") ? join(homedir(), p.slice(1)) : p
}

function slug(model: string): string {
  return model.replace(/[^a-zA-Z0-9._-]+/g, "__")
}

async function downloadFile(
  url: string,
  dest: string,
  onProgress?: (m: string) => void
): Promise<void> {
  if (existsSync(dest)) return
  mkdirSync(dirname(dest), { recursive: true })
  onProgress?.(`downloading ${url}`)
  const res = await fetch(url)
  if (!res.ok || !res.body) {
    throw new Error(`download failed (${res.status}) for ${url}`)
  }
  const tmp = `${dest}.part`
  await pipeline(Readable.fromWeb(res.body as any), createWriteStream(tmp))
  // Atomic-ish move: write to .part then rename.
  const { renameSync } = await import("node:fs")
  renameSync(tmp, dest)
}

/** Encode text to token ids without special tokens (mirrors laya `encode_text`). */
function encodeIds(tokenizer: any, text: string, opts: Record<string, unknown> = {}): number[] {
  const out = tokenizer(text, { add_special_tokens: false, ...opts })
  const ids = out?.input_ids
  if (!ids) return []
  const data = ids.data ?? ids
  return Array.from(data as ArrayLike<bigint | number>).map((x) => Number(x))
}

function renderNoulOptions(): string[] {
  return [
    "false: no, the statement does not hold",
    "true: yes, the statement holds",
  ]
}

/** Port of laya `build_head` for a `noul` question. */
export function buildHead(
  tokenizer: any,
  q: OnnxQuestion,
  headMaxLen: number
): { ids: number[]; markers: number[] } {
  const maskTok: string = tokenizer.mask_token ?? "[MASK]"
  const opts = renderNoulOptions()
  const ins = String(q.instructions).replaceAll(maskTok, " ")
  let headIds = encodeIds(tokenizer, `${q.type} question: ${ins}`)
  const optIds: number[][] = opts.map((o) => [
    tokenizer.mask_token_id,
    ...encodeIds(tokenizer, " " + o.replaceAll(maskTok, " "), {
      truncation: true,
      max_length: 48,
    }),
  ])
  let optBudget = headMaxLen - optIds.reduce((a, o) => a + o.length, 0)
  if (optBudget < 16) {
    const per = Math.max(4, Math.floor((headMaxLen - 16) / Math.max(1, optIds.length)))
    for (let i = 0; i < optIds.length; i++) optIds[i] = optIds[i].slice(0, per)
    optBudget = headMaxLen - optIds.reduce((a, o) => a + o.length, 0)
  }
  headIds = headIds.slice(0, Math.max(8, optBudget))
  const clsId = tokenizer.cls_token_id ?? tokenizer.bos_token_id
  const ids = [clsId, ...headIds, tokenizer.sep_token_id]
  const markers: number[] = []
  for (const o of optIds) {
    markers.push(ids.length)
    ids.push(...o)
  }
  ids.push(tokenizer.sep_token_id)
  return { ids, markers }
}

/** Port of laya `build_sequence` for a `noul` question. */
export function buildSequence(
  tokenizer: any,
  state: string,
  q: OnnxQuestion,
  maxLen: number,
  headMaxLen: number
): { ids: number[]; markers: number[] } {
  const { ids: headIds, markers } = buildHead(tokenizer, q, headMaxLen)
  const room = Math.max(0, maxLen - headIds.length - 1)
  const maskTok: string = tokenizer.mask_token ?? "[MASK]"
  const stateIds = encodeIds(tokenizer, state.replaceAll(maskTok, " "))
  const st = stateIds.slice(0, room)
  let ids = [...headIds, ...st, tokenizer.sep_token_id]
  ids = ids.slice(0, maxLen)
  return { ids, markers: markers.filter((m) => m < maxLen) }
}

function softmax(logits: number[], temperature: number): number[] {
  const z = logits.map((v) => v / temperature)
  const max = Math.max(...z)
  const exps = z.map((v) => Math.exp(v - max))
  const sum = exps.reduce((a, b) => a + b, 0)
  return exps.map((v) => v / sum)
}

export async function createOnnxLocalProvider(
  options: OnnxLocalOptions
): Promise<OnnxLocalProvider> {
  const dtype = options.dtype ?? "fp32"
  const cacheRoot = expandHome(options.cacheDir ?? "~/.cache/opencode-bunker")
  const dir = join(cacheRoot, slug(options.model))
  const onnxRel = dtype === "fp32" ? "onnx/model.onnx" : "onnx/model.int8.onnx"
  const onnxPath = join(dir, onnxRel)
  const tokDir = join(dir, "tokenizer")
  const cfgPath = join(dir, "rl_agent_config.json")
  const encCfgPath = join(dir, "encoder/config.json")

  const base = `${HF_BASE}/${options.model}/resolve/main`
  await downloadFile(`${base}/tokenizer/tokenizer.json`, join(tokDir, "tokenizer.json"), options.onProgress)
  await downloadFile(
    `${base}/tokenizer/tokenizer_config.json`,
    join(tokDir, "tokenizer_config.json"),
    options.onProgress
  )
  await downloadFile(`${base}/rl_agent_config.json`, cfgPath, options.onProgress)
  await downloadFile(`${base}/encoder/config.json`, encCfgPath, options.onProgress)
  await downloadFile(`${base}/${onnxRel}`, onnxPath, options.onProgress)
  if (dtype === "fp32") {
    await downloadFile(`${base}/onnx/model.onnx.data`, join(dir, "onnx/model.onnx.data"), options.onProgress)
  }

  const { AutoTokenizer } = await import("@huggingface/transformers")
  const ort = await import("onnxruntime-node")

  const tokenizer = await AutoTokenizer.from_pretrained(tokDir)
  // ModernBERT uses the BOS id as CLS; Transformers.js does not expose
  // `cls_token_id`, so read it from the encoder config.
  const encCfg = JSON.parse(
    (await import("node:fs")).readFileSync(encCfgPath, "utf8")
  ) as { cls_token_id?: number }
  if ((tokenizer as any).cls_token_id == null) {
    ;(tokenizer as any).cls_token_id =
      (tokenizer as any).bos_token_id ?? encCfg.cls_token_id ?? 50281
  }
  const session = await ort.InferenceSession.create(onnxPath, {
    intraOpNumThreads: 1,
    interOpNumThreads: 1,
  })

  const cfg = JSON.parse(
    (await import("node:fs")).readFileSync(cfgPath, "utf8")
  ) as { max_len?: number; head_max_len?: number; temperature?: number[] }
  const maxLen = options.maxLen ?? cfg.max_len ?? 1024
  const headMaxLen = options.headMaxLen ?? cfg.head_max_len ?? 256
  const temperature = options.temperature ?? cfg.temperature ?? [1, 1, 1]

  const qids = Object.keys(options.questions)

  async function predict(text: string): Promise<Record<string, number>> {
    const rows = qids.map((qid) => ({
      qid,
      ...buildSequence(tokenizer, text, options.questions[qid], maxLen, headMaxLen),
    }))
    const n = rows.length
    if (n === 0) return {}
    const L = Math.max(...rows.map((r) => r.ids.length))
    const kmax = Math.max(...rows.map((r) => r.markers.length))

    const inputIds = new BigInt64Array(n * L)
    const attn = new BigInt64Array(n * L)
    const mpos = new BigInt64Array(n * kmax)
    const mmask = new Uint8Array(n * kmax)
    const qtype = new BigInt64Array(n)
    const padId = BigInt(tokenizer.pad_token_id ?? 0)

    for (let i = 0; i < n; i++) {
      const row = rows[i]
      for (let j = 0; j < L; j++) {
        inputIds[i * L + j] = j < row.ids.length ? BigInt(row.ids[j]) : padId
        attn[i * L + j] = j < row.ids.length ? 1n : 0n
      }
      for (let k = 0; k < row.markers.length; k++) {
        mpos[i * kmax + k] = BigInt(row.markers[k])
        mmask[i * kmax + k] = 1
      }
      qtype[i] = 2n // noul
    }

    const feeds: Record<string, unknown> = {
      input_ids: new ort.Tensor("int64", inputIds, [n, L]),
      attention_mask: new ort.Tensor("int64", attn, [n, L]),
      marker_pos: new ort.Tensor("int64", mpos, [n, kmax]),
      marker_mask: new ort.Tensor("bool", mmask, [n, kmax]),
      qtype: new ort.Tensor("int64", qtype, [n]),
    }
    const out = await session.run(feeds as any)
    const logits = out.logits.data as Float32Array

    const probs: Record<string, number> = {}
    for (let i = 0; i < n; i++) {
      const k = rows[i].markers.length
      const row = Array.from(logits.slice(i * kmax, i * kmax + k))
      const p = softmax(row, temperature[2] ?? 1)
      probs[rows[i].qid] = p[1] ?? 0
    }
    return probs
  }

  return {
    predict,
    async dispose() {
      await session.release?.()
    },
  }
}
