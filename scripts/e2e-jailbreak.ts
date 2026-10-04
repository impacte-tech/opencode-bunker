/**
 * Measure the plugin against the jailbreak corpus, using the onnx-local model.
 *
 *   bun run scripts/e2e-jailbreak.ts
 */
import { writeFileSync } from "node:fs"

writeFileSync(
  "./logs/bunker-jailbreak.config.json",
  JSON.stringify({
    mode: "enforce",
    classifier: {
      provider: "onnx-local",
      model: "impacte/bunker-laya",
      dtype: "fp32",
      cacheDir: "~/.cache/opencode-bunker",
      maxLen: 1024,
      headMaxLen: 256,
      timeoutMs: 120000,
    },
    logging: { path: "./logs/bunker-jailbreak-audit.jsonl", includeRaw: false },
  })
)
process.env.BUNKER_CONFIG = "./logs/bunker-jailbreak.config.json"

const { classifyWithProvider } = await import("../src/core")
const { JAILBREAK_CORPUS } = await import("../test/fixtures/jailbreak-corpus")

let tp = 0
let fn = 0
let tn = 0
let fp = 0
const misses: string[] = []
const falsePositives: string[] = []

for (const c of JAILBREAK_CORPUS) {
  const d = await classifyWithProvider(c.text)
  const blocked = d.action === "block"
  if (c.expect === "block") {
    if (blocked) tp++
    else {
      fn++
      misses.push(`${c.id} [${c.technique}] action=${d.action} conf=${d.confidence}`)
    }
  } else {
    if (!blocked) tn++
    else {
      fp++
      falsePositives.push(`${c.id} [${c.technique}] action=${d.action} conf=${d.confidence}`)
    }
  }
}

const injections = tp + fn
const benign = tn + fp
console.log(`\n=== jailbreak corpus (${JAILBREAK_CORPUS.length} cases) ===`)
console.log(`injections blocked : ${tp}/${injections} (${((tp / injections) * 100).toFixed(1)}%)`)
console.log(`benign allowed     : ${tn}/${benign} (${((tn / benign) * 100).toFixed(1)}%)`)
if (misses.length) {
  console.log(`\nMISSES (${misses.length}):`)
  for (const m of misses) console.log("  " + m)
}
if (falsePositives.length) {
  console.log(`\nFALSE POSITIVES (${falsePositives.length}):`)
  for (const m of falsePositives) console.log("  " + m)
}
