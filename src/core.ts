/**
 * opencode-bunker — a local guardrail plugin for opencode.
 *
 * Classifies and redacts prompts AND tool calls before they reach a model
 * provider. Uses a Laya-style typed-decision interface; the default provider is
 * a deterministic local heuristic so the plugin works with zero dependencies.
 * A `laya-http` / `onnx-local` provider can be slotted in later (see
 * .planning/FILEMAP.md).
 *
 * Hooks used:
 *   chat.message                       -> classify + redact the input; block = revert + throw
 *   experimental.chat.messages.transform -> re-scan the exact outgoing messages
 *   tool.execute.before                -> block sensitive reads / credential commands
 *   tool.execute.after                 -> redact secrets/PII from tool output
 */
import type { Plugin } from "@opencode-ai/plugin"
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs"
import { createHash, randomUUID } from "node:crypto"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import {
  createRedactor,
  stripInvisibleUnicode,
  type Redactor,
  type SecretPattern,
} from "./regex/engine"
import { SECRET_PATTERNS } from "./regex/secret-patterns"
import { INJECTION_PATTERNS } from "./regex/injection-patterns"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
export type Action = "allow" | "flag" | "redact" | "block"

export interface CustomPattern {
  pattern: string
  action?: Action
  label?: string
  increment?: number
  target?: string
  force?: boolean
}

export interface BunkerConfig {
  enabled: boolean
  mode: "observe" | "flag" | "redact" | "enforce"
  failMode: "open" | "closed"
  allowRemote: boolean
  builtins: Record<string, Action>
  custom: CustomPattern[]
  coverage: { minConfidence: number; injectionConfidence: number; deferTo: "human" | "allow" | "block" }
  tools: {
    enabled: boolean
    defaultAction: Action
    outputRedaction: boolean
    redactArgs: boolean
    askFallback: "block" | "allow"
    sensitivePaths: Record<string, Action | "ask">
    credentialCommands: Record<string, Action | "ask">
  }
  logging: { path: string; includeRaw: boolean; rotateBytes: number }
  secrets: {
    enabled: boolean
    action: Action
    patterns: boolean
    extraPatterns: SecretPattern[]
    redactPaths: string[]
    pathCensor: string
    stripInvisibleUnicode: boolean
  }
  classifier: {
    provider: "heuristic" | "onnx-local"
    model: string
    dtype: "q8" | "fp32"
    cacheDir: string
    maxLen: number
    headMaxLen: number
    timeoutMs: number
    intraOpNumThreads: number
  }
}

interface Hit {
  id: string
  question: string
  action: Action
  label: string
  pattern: RegExp
  count: number
  increment?: number
  target?: string
  force?: boolean
  /** Set for secret-pattern hits; redaction is handled by the engine. */
  secretId?: string
}

export interface Entity {
  type: string
  source: "regex" | "model" | "both"
  action: Action
  count: number
  label: string
  confidence: number
}

export interface Decision {
  decisionId: string
  action: Action
  confidence: number
  deferred: boolean
  entities: Entity[]
  regexIncrements: Array<{ label: string; delta: number; action: Action; target: string }>
  hits: Hit[]
  latencyMs: number
  original: string
}

// ---------------------------------------------------------------------------
// Default config
// ---------------------------------------------------------------------------
const DEFAULT_CONFIG: BunkerConfig = {
  enabled: true,
  mode: "enforce",
  failMode: "open",
  allowRemote: false,
  builtins: {
    email: "redact",
    phone: "redact",
    ssn: "block",
    "credit-card": "block",
    "ip-address": "redact",
    secrets: "redact",
    "person-name": "redact",
    address: "redact",
  },
  custom: [
    { pattern: "PROJ-\\d{4,6}", action: "redact", label: "internal-project-code", increment: 0.25, target: "confidential" },
    { pattern: "AKIA[0-9A-Z]{16}", action: "block", label: "aws-access-key", increment: 0.5, target: "pii_secret", force: true },
  ],
  coverage: { minConfidence: 0.75, injectionConfidence: 0.8, deferTo: "human" },
  tools: {
    enabled: true,
    defaultAction: "flag",
    outputRedaction: true,
    redactArgs: true,
    askFallback: "block",
    sensitivePaths: {
      "**/.env": "block",
      "**/.env.*": "block",
      "**/.aws/credentials": "block",
      "**/.aws/config": "block",
      "**/*.{pem,key,p12,pfx,jks,keystore}": "block",
      "**/id_{rsa,ed25519,ecdsa}": "block",
      "**/.{npmrc,pypirc,netrc,git-credentials}": "block",
      "**/.kube/config": "block",
      "**/*.{tfvars,tfstate}": "block",
      "**/service-account*.json": "block",
      "**/.ssh/**": "ask",
    },
    credentialCommands: {
      "aws\\s+secretsmanager\\s+get-secret-value": "block",
      "aws\\s+ssm\\s+get-parameter[s]?.*--with-decryption": "block",
      "gcloud\\s+secrets\\s+versions\\s+access": "block",
      "az\\s+keyvault\\s+secret\\s+show": "block",
      "vault\\s+(read|kv\\s+get)": "block",
      "kubectl\\s+get\\s+secret": "block",
      "(printenv|^env$|^set$)": "ask",
    },
  },
  logging: { path: "~/.local/share/opencode/bunker/audit.jsonl", includeRaw: false, rotateBytes: 5 * 1024 * 1024 },
  secrets: {
    enabled: true,
    action: "redact",
    patterns: true,
    extraPatterns: [],
    redactPaths: [],
    pathCensor: "[REDACTED]",
    stripInvisibleUnicode: true,
  },
  classifier: {
    provider: "heuristic",
    model: "impacte/bunker-laya",
    dtype: "fp32",
    cacheDir: "~/.cache/opencode-bunker",
    maxLen: 1024,
    headMaxLen: 256,
    timeoutMs: 120_000,
    intraOpNumThreads: 4,
  },
}

const ORDER: Record<Action, number> = { allow: 0, flag: 1, redact: 2, block: 3 }

// ---------------------------------------------------------------------------
// Config loading (deep-merged; project wins over global)
// ---------------------------------------------------------------------------
function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
}

function deepMerge<T>(base: T, override: unknown): T {
  if (!isObject(override)) return base
  const out: Record<string, unknown> = isObject(base) ? { ...(base as Record<string, unknown>) } : {}
  for (const [k, v] of Object.entries(override)) {
    out[k] = isObject(v) && isObject(out[k]) ? deepMerge(out[k], v) : v
  }
  return out as T
}

function expandHome(p: string): string {
  return p.startsWith("~") ? join(homedir(), p.slice(1)) : p
}

export function loadConfig(): BunkerConfig {
  let cfg: BunkerConfig = JSON.parse(JSON.stringify(DEFAULT_CONFIG))
  // Lowest precedence first; later entries win. `$BUNKER_CONFIG` is highest.
  const candidates = [
    join(process.cwd(), "bunker.config.json"),
    expandHome("~/.config/opencode/bunker.config.json"),
    process.env.BUNKER_CONFIG,
  ].filter(Boolean) as string[]
  for (const path of candidates) {
    try {
      if (existsSync(path)) cfg = deepMerge(cfg, JSON.parse(readFileSync(path, "utf8")))
    } catch {
      /* ignore malformed config; defaults apply */
    }
  }
  return cfg
}

let config: BunkerConfig = loadConfig()

// ---------------------------------------------------------------------------
// Secret redaction engine (opencode-redact heuristics)
// ---------------------------------------------------------------------------
let redactor: Redactor | null = null

function getRedactor(): Redactor {
  if (!redactor) {
    const patterns = config.secrets.patterns
      ? [...SECRET_PATTERNS, ...config.secrets.extraPatterns]
      : config.secrets.extraPatterns
    redactor = createRedactor(patterns, {
      redactPaths: config.secrets.redactPaths,
      pathCensor: config.secrets.pathCensor,
    })
  }
  return redactor
}

/** Reset the cached redactor (used when config changes / in tests). */
export function resetRedactor(): void {
  redactor = null
}

/** Re-read the config and drop cached singletons (used in tests). */
export function reloadConfig(): void {
  config = loadConfig()
  redactor = null
  providerPromise = null
}

// ---------------------------------------------------------------------------
// Regex safety (OpenRouter parity)
// ---------------------------------------------------------------------------
export function isSafeRegex(pattern: string): boolean {
  if (pattern.length > 100_000) return false
  if (/\(\?<?[=!]/.test(pattern)) return false // lookahead / lookbehind
  if (/\\[1-9]/.test(pattern) || /\\k<[^>]+>/.test(pattern)) return false // backrefs
  if (/\([^)]*[+*][^)]*\)[+*]/.test(pattern)) return false // nested quantifier (heuristic)
  return true
}

// ---------------------------------------------------------------------------
// Built-in presets
// ---------------------------------------------------------------------------
const BUILTIN_DEFS: Record<string, { question: string; label: string; pattern: string }> = {
  email: { question: "pii_email", label: "[EMAIL]", pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" },
  phone: { question: "pii_phone", label: "[PHONE]", pattern: "(?:\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]\\d{3}[-.\\s]\\d{4}" },
  ssn: { question: "pii_ssn", label: "[SSN]", pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b" },
  "credit-card": { question: "pii_credit_card", label: "[CREDIT_CARD]", pattern: "\\b(?:\\d[ -]*?){13,16}\\b" },
  "ip-address": { question: "pii_ip_address", label: "[IP_ADDRESS]", pattern: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b" },
  secrets: {
    question: "pii_secret",
    label: "[SECRET]",
    pattern: "\\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-or-v1-[A-Za-z0-9]{32,}|xox[baprs]-[A-Za-z0-9-]{10,})\\b",
  },
}

const OUTPUT_SECRETS: Array<{ label: string; pattern: RegExp }> = [
  { label: "[SECRET:aws-access-key-id]", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "[SECRET]", pattern: /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*[=:]\s*["']?[^\s"']{6,}["']?/g },
]

// ---------------------------------------------------------------------------
// Laya-style typed questions + local heuristic provider
// ---------------------------------------------------------------------------
const QUESTIONS = [
  "pii_present",
  "pii_email",
  "pii_phone",
  "pii_ssn",
  "pii_credit_card",
  "pii_ip_address",
  "pii_secret",
  "pii_person_name",
  "pii_address",
  "injection_present",
  "jailbreak_attempt",
  "harmful_request",
  "confidential",
] as const

const PROBE = {
  email: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/,
  phone: /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}/,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  cc: /\b(?:\d[ -]*?){13,16}\b/,
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  secret: /\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-or-v1-[A-Za-z0-9]{32,})\b/,
  person: /\b[A-Z][a-z]+\s+[A-Z][a-z]+\b/,
  injection: /\b(ignore\s+(all\s+)?previous\s+instructions|disable\s+(all\s+)?filters?|bypass\s+(all\s+)?filters?|developer\s+mode|reveal\s+your\s+system\s+prompt)\b/i,
  confidential: /\b(confidential|internal|escalat)/i,
}

function modelProb(key: string, text: string): number {
  switch (key) {
    case "pii_present":
      return PROBE.email.test(text) || PROBE.phone.test(text) || PROBE.secret.test(text) || PROBE.ssn.test(text)
        ? 0.95
        : PROBE.person.test(text)
          ? 0.6
          : 0.03
    case "pii_email": return PROBE.email.test(text) ? 0.97 : 0.02
    case "pii_phone": return PROBE.phone.test(text) ? 0.9 : 0.02
    case "pii_ssn": return PROBE.ssn.test(text) ? 0.96 : 0.01
    case "pii_credit_card": return PROBE.cc.test(text) ? 0.93 : 0.02
    case "pii_ip_address": return PROBE.ip.test(text) ? 0.9 : 0.02
    case "pii_secret": return PROBE.secret.test(text) ? 0.88 : 0.02
    case "pii_person_name": return PROBE.person.test(text) ? 0.62 : 0.05
    case "pii_address": return /\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd)/.test(text) ? 0.7 : 0.03
    case "injection_present": return PROBE.injection.test(text) ? 0.94 : 0.03
    case "jailbreak_attempt": return PROBE.injection.test(text) ? 0.9 : 0.03
    case "harmful_request": return /\b(bomb|exploit|malware|ransomware|kill|weapon)\b/i.test(text) ? 0.85 : 0.03
    case "confidential": return PROBE.confidential.test(text) ? 0.55 : 0.5
    default: return 0.05
  }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------
export function classify(text: string, modelProbs?: Record<string, number>): Decision {
  const t0 = Date.now()
  const scanText = config.secrets.stripInvisibleUnicode ? stripInvisibleUnicode(text) : text
  const probs: Record<string, number> = {}
  for (const q of QUESTIONS) probs[q] = modelProbs?.[q] ?? modelProb(q, scanText)

  const hits: Hit[] = []
  for (const [slug, def] of Object.entries(BUILTIN_DEFS)) {
    // When the secret engine is on, its 112 specific patterns supersede the
    // generic built-in `secrets` preset (so labels are `[REDACTED:<id>]`).
    if (slug === "secrets" && config.secrets.enabled) continue
    const action = config.builtins[slug] ?? "redact"
    if (action === "allow") continue
    const re = new RegExp(def.pattern, "g")
    const count = (scanText.match(re) ?? []).length
    if (count) hits.push({ id: slug, question: def.question, action, label: def.label, pattern: re, count })
  }
  for (const c of config.custom) {
    if (!isSafeRegex(c.pattern)) continue
    const re = new RegExp(c.pattern, "g")
    const count = (scanText.match(re) ?? []).length
    if (!count) continue
    hits.push({
      id: c.label ?? c.pattern,
      question: c.target ?? "custom",
      action: c.action ?? "redact",
      label: c.label ?? "[REDACTED]",
      pattern: re,
      count,
      increment: c.increment,
      target: c.target,
      force: c.force,
    })
  }
  // opencode-redact secret patterns (keyword pre-filtered)
  if (config.secrets.enabled) {
    for (const id of getRedactor().detect(scanText)) {
      hits.push({
        id,
        question: "pii_secret",
        action: config.secrets.action,
        label: `[REDACTED:${id}]`,
        pattern: /$^/,
        count: 1,
        secretId: id,
      })
    }
  }
  // deterministic injection / jailbreak patterns (always block)
  for (const p of INJECTION_PATTERNS) {
    const re = new RegExp(p.pattern, "gi")
    const count = (scanText.match(re) ?? []).length
    if (count) {
      hits.push({ id: p.id, question: "injection_present", action: "block", label: p.label, pattern: re, count })
    }
  }

  const incremented = new Set<string>()
  const regexIncrements: Decision["regexIncrements"] = []
  for (const h of hits) {
    if (h.increment && h.target) {
      probs[h.target] = Math.min(1, (probs[h.target] ?? 0) + h.increment)
      incremented.add(h.target)
      regexIncrements.push({ label: h.id, delta: h.increment, action: h.action, target: h.target })
    }
  }

  const entities: Entity[] = hits.map((h) => ({
    type: h.id,
    source: incremented.has(h.question) ? "both" : "regex",
    action: h.action,
    count: h.count,
    label: h.label,
    confidence: Number((probs[h.question] ?? 0.9).toFixed(2)),
  }))
  const deferredEntities: Entity[] = []
  const modelCats: Array<{ key: string; type: string; action: Action; label: string }> = [
    { key: "pii_person_name", type: "PERSON_NAME", action: "redact", label: "[PERSON_NAME]" },
    { key: "pii_address", type: "ADDRESS", action: "redact", label: "[ADDRESS]" },
    { key: "confidential", type: "CONFIDENTIAL", action: "flag", label: "[CONFIDENTIAL]" },
  ]
  for (const c of modelCats) {
    const p = probs[c.key]
    if (p >= config.coverage.minConfidence) {
      entities.push({ type: c.type, source: incremented.has(c.key) ? "both" : "model", action: c.action, count: 1, label: c.label, confidence: Number(p.toFixed(2)) })
    } else if (p > 0.5) {
      deferredEntities.push({ type: c.type, source: "model", action: "flag", count: 1, label: c.label, confidence: Number(p.toFixed(2)) })
    }
  }
  if (probs.injection_present >= config.coverage.injectionConfidence) {
    entities.push({ type: "PROMPT_INJECTION", source: "model", action: "block", count: 1, label: "[PROMPT_INJECTION]", confidence: Number(probs.injection_present.toFixed(2)) })
  }
  if (probs.jailbreak_attempt >= config.coverage.injectionConfidence) {
    entities.push({ type: "JAILBREAK_ATTEMPT", source: "model", action: "block", count: 1, label: "[JAILBREAK]", confidence: Number(probs.jailbreak_attempt.toFixed(2)) })
  }
  if (probs.harmful_request >= config.coverage.injectionConfidence) {
    entities.push({ type: "HARMFUL_REQUEST", source: "model", action: "block", count: 1, label: "[HARMFUL]", confidence: Number(probs.harmful_request.toFixed(2)) })
  }

  let action: Action = "allow"
  for (const e of entities) if (ORDER[e.action] > ORDER[action]) action = e.action
  for (const h of hits) if (h.force && ORDER[h.action] > ORDER[action]) action = h.action

  let deferred = false
  if (action === "allow" && deferredEntities.length) {
    action = "flag"
    deferred = true
  }
  if (config.mode === "observe" || config.mode === "flag") action = action === "allow" ? "allow" : "flag"
  else if (config.mode === "redact" && action === "block") action = "redact"

  const all = [...entities, ...deferredEntities]
  const confidence = all.length ? Math.max(...all.map((e) => e.confidence)) : 1
  return {
    decisionId: randomUUID(),
    action,
    confidence: Number(confidence.toFixed(2)),
    deferred,
    entities,
    regexIncrements,
    hits,
    latencyMs: Date.now() - t0,
    original: text,
  }
}

// ---------------------------------------------------------------------------
// Classifier provider (heuristic | onnx-local)
// ---------------------------------------------------------------------------
type ModelProvider = { predict: (text: string) => Promise<Record<string, number>>; dispose?: () => Promise<void> }
let providerPromise: Promise<ModelProvider | null> | null = null

async function getModelProvider(): Promise<ModelProvider | null> {
  if (config.classifier.provider !== "onnx-local") return null
  if (!providerPromise) {
    providerPromise = (async () => {
      try {
        const { createOnnxLocalProvider } = await import("./classifier/onnx-local")
        const { MODEL_QUESTIONS } = await import("./classifier/questions")
        return await createOnnxLocalProvider({
          model: config.classifier.model,
          dtype: config.classifier.dtype,
          cacheDir: config.classifier.cacheDir,
          maxLen: config.classifier.maxLen,
          headMaxLen: config.classifier.headMaxLen,
          intraOpNumThreads: config.classifier.intraOpNumThreads,
          questions: MODEL_QUESTIONS,
        })
      } catch {
        providerPromise = null
        return null
      }
    })()
  }
  return providerPromise
}

/**
 * Classify with the configured provider. `onnx-local` runs the fine-tuned Laya
 * model in-process; on any failure it falls back to the zero-dependency
 * heuristic (fail-open), so a missing model never breaks a turn.
 */
export async function classifyWithProvider(text: string): Promise<Decision> {
  if (config.classifier.provider === "onnx-local") {
    try {
      const provider = await getModelProvider()
      if (provider) {
        const scanText = config.secrets.stripInvisibleUnicode ? stripInvisibleUnicode(text) : text
        const probs = await Promise.race([
          provider.predict(scanText),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error("classifier timeout")), config.classifier.timeoutMs)
          ),
        ])
        return classify(text, probs)
      }
    } catch {
      /* fail-open: fall back to the heuristic */
    }
  }
  return classify(text)
}

export function redact(text: string, hits: Hit[]): string {
  let out = config.secrets.stripInvisibleUnicode ? stripInvisibleUnicode(text) : text
  for (const h of hits) {
    if (h.action === "redact" && !h.secretId) out = out.replace(h.pattern, h.label)
  }
  if (config.secrets.enabled) out = getRedactor().string(out) ?? out
  return out
}

export function redactOutput(text: string): string {
  let out = text
  // Specific secret patterns first, then the generic output presets.
  if (config.secrets.enabled) out = getRedactor().string(out) ?? out
  for (const s of OUTPUT_SECRETS) out = out.replace(s.pattern, s.label)
  return out
}

function redactDeep<T>(value: T, fn: (s: string) => string): T {
  if (typeof value === "string") return fn(value) as unknown as T
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, fn)) as unknown as T
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>
    // Preserve image / base64 payloads (opencode-redact parity).
    if ("type" in obj && (obj.type === "base64" || obj.type === "image") && "data" in obj) {
      return value
    }
    if ("isImage" in obj && obj.isImage === true && typeof obj.content === "string") {
      const out: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(obj)) out[k] = k === "content" ? v : redactDeep(v, fn)
      return out as unknown as T
    }
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(obj)) out[k] = redactDeep(v, fn)
    return out as unknown as T
  }
  return value
}

/**
 * Deep-scrub a value: PII/custom hits first, then the secret engine
 * (image/base64-safe) and any path-based redaction rules.
 */
export function scrubValue<T>(value: T, hits: Hit[]): T {
  const withPii = redactDeep(value, (s) => redactOutput(redact(s, hits)))
  if (!config.secrets.enabled) return withPii
  let out = getRedactor().deep(withPii) as T
  if (config.secrets.redactPaths.length > 0) out = getRedactor().paths(out) as T
  return out
}

// ---------------------------------------------------------------------------
// Tool guard
// ---------------------------------------------------------------------------
export function globToRegex(glob: string): RegExp {
  let re = ""
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]
    if (c === "*" && glob[i + 1] === "*") {
      if (glob[i + 2] === "/") { re += "(?:.*/)?"; i += 2 } else { re += ".*"; i++ }
    } else if (c === "*") re += "[^/]*"
    else if (c === "?") re += "."
    else if (c === "{") {
      const end = glob.indexOf("}", i)
      if (end > -1) { re += "(" + glob.slice(i + 1, end).split(",").join("|") + ")"; i = end }
      else re += "\\{"
    } else if ("\\^$+?.()|[]".includes(c)) re += "\\" + c
    else re += c
  }
  return new RegExp(re, "i")
}

export function classifyTool(tool: string, args: unknown): Decision {
  const t0 = Date.now()
  const state = `${tool} ${JSON.stringify(args ?? {})}`
  const entities: Entity[] = []
  const a = (args ?? {}) as Record<string, unknown>
  const path = String(a.filePath ?? a.path ?? a.file ?? "")

  if (config.tools.enabled) {
    for (const [glob, action] of Object.entries(config.tools.sensitivePaths)) {
      if (action === "allow") continue
      if (path && globToRegex(glob).test(path)) {
        entities.push({ type: `SENSITIVE_PATH:${glob}`, source: "regex", action: action === "ask" ? "flag" : action, count: 1, label: glob, confidence: 0.98 })
      }
    }
    const command = String(a.command ?? "")
    for (const [pat, action] of Object.entries(config.tools.credentialCommands)) {
      if (action === "allow") continue
      if (command && new RegExp(pat, "i").test(command)) {
        entities.push({ type: `CREDENTIAL_ACCESS:${pat}`, source: "regex", action: action === "ask" ? "flag" : action, count: 1, label: pat, confidence: 0.97 })
      }
    }
    if (/\brm\s+-rf\b|drop\s+table|terraform\s+destroy/i.test(state)) {
      entities.push({ type: "DESTRUCTIVE_ACTION", source: "model", action: "block", count: 1, label: "destructive", confidence: 0.9 })
    }
  }

  const textDecision = classify(state)
  for (const e of textDecision.entities) if (e.source === "regex") entities.push(e)

  let action: Action = config.tools.defaultAction
  for (const e of entities) if (ORDER[e.action] > ORDER[action]) action = e.action
  if (config.mode === "observe" || config.mode === "flag") action = action === "allow" ? "allow" : "flag"

  return {
    decisionId: randomUUID(),
    action,
    confidence: entities.length ? Math.max(...entities.map((e) => e.confidence)) : 1,
    deferred: false,
    entities,
    regexIncrements: textDecision.regexIncrements,
    hits: textDecision.hits,
    latencyMs: Date.now() - t0,
    original: state,
  }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------
function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex")
}

function audit(decision: Decision, extra: Record<string, unknown>): void {
  if (!config.logging.path) return
  const path = expandHome(config.logging.path)
  const record = {
    ts: new Date().toISOString(),
    event: "bunker.decision",
    stage: "pre_provider",
    ...extra,
    decisionId: decision.decisionId,
    decision: decision.action,
    confidence: decision.confidence,
    deferred: decision.deferred,
    entities: decision.entities.map((e) => ({ type: e.type, source: e.source, action: e.action, count: e.count, confidence: e.confidence })),
    regexIncrements: decision.regexIncrements,
    promptSha256: sha256(decision.original),
    promptBytes: Buffer.byteLength(decision.original, "utf8"),
    latencyMs: decision.latencyMs,
    rawIncluded: config.logging.includeRaw,
    ...(config.logging.includeRaw ? { raw: decision.original } : {}),
  }
  try {
    mkdirSync(dirname(path), { recursive: true })
    appendFileSync(path, JSON.stringify(record) + "\n", { mode: 0o600 })
  } catch {
    /* never let logging break a turn */
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------
const plugin: Plugin = async (ctx) => {
  config = loadConfig()
  if (!config.enabled) return {}

  async function rollback(sessionID?: string, messageID?: string): Promise<void> {
    if (!sessionID || !messageID) return
    try {
      await ctx.client.session.revert({ path: { id: sessionID }, body: { messageID } })
    } catch {
      /* best effort */
    }
    try {
      await ctx.client.session.abort({ path: { id: sessionID } })
    } catch {
      /* best effort */
    }
  }

  function blockError(decision: Decision, where: string): Error {
    const labels = decision.entities.map((e) => e.label || e.type).join(", ")
    return new Error(`BunkerBlockedError (${where}): ${labels || "policy"}`)
  }

  return {
    "chat.message": async (inp, out) => {
      const text = (out.parts ?? [])
        .filter((p: any) => p?.type === "text" && typeof p.text === "string")
        .map((p: any) => p.text)
        .join("\n")
      if (!text) return
      const decision = await classifyWithProvider(text)
      audit(decision, {
        hook: "chat.message",
        sessionID: inp.sessionID,
        messageID: inp.messageID,
        providerDispatched: decision.action === "block" ? false : null,
      })
      if (decision.action === "redact") {
        for (const p of out.parts as any[]) if (p?.type === "text" && typeof p.text === "string") p.text = redact(p.text, decision.hits)
      }
      if (decision.action === "block") {
        await rollback(inp.sessionID, inp.messageID)
        throw blockError(decision, "chat.message")
      }
    },

    "experimental.chat.messages.transform": async (_inp, out) => {
      for (const m of out.messages ?? []) {
        for (const p of m.parts ?? []) {
          const part = p as any
          if (part?.type !== "text" || typeof part.text !== "string" || !part.text) continue
          const decision = await classifyWithProvider(part.text)
          if (decision.action === "block") {
            audit(decision, { hook: "experimental.chat.messages.transform", providerDispatched: false })
            throw blockError(decision, "messages.transform")
          }
          if (decision.action === "redact") part.text = redact(part.text, decision.hits)
        }
      }
    },

    "tool.execute.before": async (inp, out) => {
      const decision = classifyTool(inp.tool, out.args)
      audit(decision, {
        surface: "tool",
        hook: "tool.execute.before",
        sessionID: inp.sessionID,
        tool: inp.tool,
        callID: inp.callID,
        providerDispatched: decision.action === "block" ? false : null,
        argsSha256: sha256(JSON.stringify(out.args ?? {})),
      })
      if (decision.action === "block") throw blockError(decision, `tool ${inp.tool}`)
      if (decision.action === "redact" && config.tools.redactArgs) {
        out.args = scrubValue(out.args, decision.hits)
      }
    },

    "tool.execute.after": async (inp, out) => {
      if (!config.tools.outputRedaction) return
      const text = typeof out.output === "string" ? out.output : ""
      const decision = await classifyWithProvider(text)
      const scrubbed = scrubValue(text, decision.hits)
      const changed = scrubbed !== text
      const canRedact = config.mode === "enforce" || config.mode === "redact"
      audit({ ...decision, action: changed && canRedact ? "redact" : changed ? "flag" : "allow" }, {
        surface: "tool",
        hook: "tool.execute.after",
        sessionID: inp.sessionID,
        tool: inp.tool,
        callID: inp.callID,
        outputSha256: sha256(text),
        outputRedacted: changed && canRedact,
        outputWouldRedact: changed,
      })
      if (changed && canRedact) {
        out.output = scrubbed
        if (out.metadata) out.metadata = scrubValue(out.metadata, decision.hits)
      }
    },
  }
}

export default plugin
