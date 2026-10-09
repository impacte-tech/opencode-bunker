# opencode-bunker

A local, Laya-style guardrail plugin for [opencode](https://opencode.ai) that
classifies and redacts **prompts and tool calls before they reach a model
provider** — PII, secrets, prompt injection, jailbreak/harmful requests,
sensitive file reads, and credential-store commands.

> **Status: usable, with a real local model.** The plugin is implemented in
> [`src/core.ts`](./src/core.ts) and verified against opencode 1.18.34: a
> prompt-injection prompt is blocked **before any provider call**, with the
> decision written to the audit log first. The classifier can run either a
> zero-dependency heuristic or the fine-tuned
> [`impacte/bunker-laya`](https://huggingface.co/impacte/bunker-laya) ONNX model
> in-process via Transformers.js. The full target architecture and file map are
> in [`.planning/`](./.planning/README.md).

## Requirements

- [opencode](https://opencode.ai) `>= 1.2.0`
- [Bun](https://bun.sh) (or Node 22+) to install dependencies
- Optional: ~1.6 GB free disk for the `onnx-local` model (downloaded on first
  use; the heuristic provider needs no download)

## Quick start

```bash
git clone https://github.com/impacte-tech/opencode-bunker.git
cd opencode-bunker
bun install

# register the plugin (global) — see "Install" for per-project
# add to ~/.config/opencode/opencode.jsonc:
#   { "plugin": ["file:///absolute/path/to/opencode-bunker/src/index.ts"] }

# start in observe mode so nothing is blocked while you tune
cp bunker.config.json ~/.config/opencode/bunker.config.json
# then set "mode": "flag" in that file and restart opencode
```

## Install

### 1. Get the code and dependencies

```bash
git clone https://github.com/impacte-tech/opencode-bunker.git
cd opencode-bunker
bun install
```

### 2. Register the plugin with opencode

**Global (all projects)** — edit `~/.config/opencode/opencode.jsonc`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["file:///absolute/path/to/opencode-bunker/src/index.ts"]
}
```

**Per project** — add the same `plugin` entry to that project's
`opencode.json`. Use an absolute `file://` path.

### 3. Configure

Copy the shipped defaults and edit them:

```bash
cp bunker.config.json ~/.config/opencode/bunker.config.json
```

Or keep a project-local `./bunker.config.json`. Start in **observe mode** so
the plugin logs decisions without blocking anything:

```jsonc
{ "mode": "flag" }
```

### 4. Restart opencode

Config is loaded at startup, so restart after editing it.

### 5. Verify

```bash
bun test                                     # 10 unit + hook tests
tail -f ~/.local/share/opencode/bunker/audit.jsonl   # watch decisions
```

Send a prompt containing an email or an injection phrase and confirm a
`bunker.decision` line appears. When you are happy with the decisions, switch
`"mode"` to `"enforce"`.

## Features

### Prompt & message guardrails
- **`chat.message`** — the earliest interception point. Classifies the prompt,
  redacts matched spans in place, and on `block` calls `session.revert` +
  `session.abort` then throws, so the provider is never called.
- **`experimental.chat.messages.transform`** — the last pre-dispatch net.
  Re-scans the **exact outgoing message array** (history + tool output) and
  blocks/redacts anything added after `chat.message`.

### PII & secrets
- **Regex presets** (OpenRouter parity): email, phone, SSN, credit card, IP
  address, provider secrets (`AKIA…`, `ghp_…`, `sk-or-v1-…`, `xox…`) →
  `[EMAIL]`, `[PHONE]`, `[SSN]`, `[CREDIT_CARD]`, `[IP_ADDRESS]`, `[SECRET]`.
- **Contextual PII** via the model: person name and mailing address
  (`pii_person_name`, `pii_address`), gated by confidence.
- **Tool output** is scrubbed by `tool.execute.after` before it enters context.

### Secret detection (112 patterns)
Ported from [`opencode-redact`](https://github.com/meimingqi222/opencode-plugins)
(MIT): **112 built-in rules** covering GitHub/GitLab/Bitbucket/Sourcegraph,
AWS/GCP/Cloudflare/Heroku/Alibaba, OpenAI/Anthropic, Slack/Discord/LinkedIn/
Twitch/Twitter/Facebook, Stripe/Flutterwave, Docker/JWT/npm/PyPI/Rubygems/
Pulumi/Age/SendGrid, Grafana/New Relic/Databricks/Dynatrace, HubSpot/Intercom/
Mailchimp/Mailgun/Typeform/Todoist/Canva, private keys, and generic
`api-key`/`webhook-secret`/`password`/`sk-secret`. Matches are redacted to
`[REDACTED:<pattern-id>]`.

Four heuristics come with it:
- **Keyword pre-filter** — each pattern declares cheap keywords; the regex only
  runs when one is present (hot-path optimization).
- **Invisible-Unicode stripping** — removes Unicode Tags block characters
  (U+E0000–U+E007F) before scanning (anti-prompt-injection).
- **Deep traversal** — recursively scrubs objects/arrays, preserving
  image/base64 payloads untouched.
- **Path-based redaction** — redact named fields (`token`,
  `credentials.password`) with a configurable censor.

When the secret engine is enabled it supersedes the generic built-in `secrets`
preset, so labels are the specific `[REDACTED:<id>]`.

### Prompt injection, jailbreak & harmful requests
- `injection_present`, `jailbreak_attempt`, `harmful_request` are model
  questions; above the injection threshold they produce a `block` with
  `[PROMPT_INJECTION]` / `[JAILBREAK]` / `[HARMFUL]`.
- A **deterministic pattern layer** (`src/regex/injection-patterns.ts`) always
  blocks high-signal phrases even when the model is unavailable or
  under-confident: `disable/turn off all filters`, `bypass all restrictions`,
  `ignore/disregard previous instructions`, `reveal your system prompt`,
  `developer mode`, `act as an unrestricted AI`, `you must comply`, and
  `override your safety settings`.

### Tool-call guardrails
- **`tool.execute.before`** blocks before the tool runs:
  - **Sensitive paths** — `.env`, `.env.*`, `.aws/credentials`, `.aws/config`,
    `*.pem`/`*.key`/`*.p12`/`*.pfx`/`*.jks`/`*.keystore`, `id_rsa`/`id_ed25519`/
    `id_ecdsa`, `.npmrc`/`.pypirc`/`.netrc`/`.git-credentials`, `.kube/config`,
    `*.tfvars`/`*.tfstate`, `service-account*.json`; `.ssh/**` → `ask`.
  - **Credential-store commands** — `aws secretsmanager get-secret-value`,
    `aws ssm get-parameter --with-decryption`, `gcloud secrets versions access`,
    `az keyvault secret show`, `vault read`/`kv get`, `kubectl get secret`;
    `printenv`/`env`/`set` → `ask`.
  - **Destructive actions** — `rm -rf`, `drop table`, `terraform destroy`.
- **`tool.execute.after`** redacts secrets/PII from the result (and metadata)
  before it is stored or returned.

### Custom regex + confidence increment
- User patterns can `redact`/`block`/`flag`, carry a `label`, and **increment**
  a model question's probability (`increment`) — optionally forcing an action
  (`force`). This is the OpenRouter "custom content filter" behavior.
- Regexes are validated: no lookaround, backreferences, or nested quantifiers;
  invalid patterns are skipped while the rest still apply.

### Classifier providers
- **`heuristic`** (default) — zero-dependency regex probes; works offline with
  no model download.
- **`onnx-local`** — the fine-tuned Laya decision model, run in-process with
  Transformers.js + ONNX Runtime. No Python sidecar. Fail-open to the heuristic
  if the model is missing or errors.

### Audit & proof
- Append-only JSONL at `~/.local/share/opencode/bunker/audit.jsonl` (mode
  `0600`), recording **metadata + sha256 of the prompt, never raw text** unless
  `includeRaw: true`. Every record carries `stage: "pre_provider"`,
  `providerDispatched`, `decision`, `confidence`, `entities`, `latencyMs`, and
  `promptSha256`.

## How it works

### Hooks

| Hook | Role |
| --- | --- |
| `chat.message` | classify + redact the input; `block` → `session.revert` + `session.abort` + throw |
| `experimental.chat.messages.transform` | re-scan the exact outgoing messages; `block` → throw |
| `tool.execute.before` | classify tool + args; `block` → throw (tool never runs); `redact` → scrub args |
| `tool.execute.after` | scrub secrets/PII from tool output + metadata |

### Decision pipeline

```
normalize(text)
  ├─ builtin regex presets ──────────────► hits
  ├─ custom regex (+increment/force) ────► hits
  ├─ model typed questions ──────────────► probabilities
  │    (heuristic | onnx-local)
  ├─ coverage gate ──────────────────────► decided | deferred
  ├─ fuse(model, regex) ─────────────────► probability += Σ increments (clamp 1)
  └─ action precedence ──────────────────► Decision
       block > redact > flag > allow
       mode downgrades (observe/flag/redact)
```

### Actions & modes

- **Actions:** `allow`, `flag`, `redact`, `block` (precedence
  `block > redact > flag > allow`).
- **Modes:**
  - `observe` / `flag` — audit only; never blocks or redacts.
  - `redact` — redacts matched content; downgrades `block` to `redact`.
  - `enforce` — blocks and redacts as decided.

## Configure

Config is deep-merged, **highest precedence first**:

1. `$BUNKER_CONFIG` (path to a JSON file)
2. `~/.config/opencode/bunker.config.json`
3. `./bunker.config.json`
4. built-in defaults

Restart opencode after editing (config is loaded at startup). Shipped defaults
live in [`bunker.config.json`](./bunker.config.json); the full reference is in
[`.planning/SPEC.md`](./.planning/SPEC.md) §5.

### Full reference

```jsonc
{
  "enabled": true,
  "mode": "enforce",              // observe | flag | redact | enforce
  "failMode": "open",             // open | closed (classifier failure)
  "allowRemote": false,           // refuse non-loopback classifier endpoints

  "builtins": {                   // per-preset action
    "email": "redact", "phone": "redact", "ssn": "block",
    "credit-card": "block", "ip-address": "redact", "secrets": "redact",
    "person-name": "redact", "address": "redact"
  },

  "custom": [
    { "pattern": "PROJ-\\d{4,6}", "action": "redact",
      "label": "internal-project-code", "increment": 0.25, "target": "confidential" },
    { "pattern": "AKIA[0-9A-Z]{16}", "action": "block",
      "label": "aws-access-key", "increment": 0.5, "target": "pii_secret", "force": true }
  ],

  "coverage": {
    "minConfidence": 0.75,        // model PII questions
    "injectionConfidence": 0.8,   // injection/jailbreak/harmful
    "deferTo": "human"            // human | allow | block
  },

  "tools": {
    "enabled": true,
    "defaultAction": "flag",
    "outputRedaction": true,
    "redactArgs": true,
    "askFallback": "block",
    "sensitivePaths": { "**/.env": "block", "**/.ssh/**": "ask" },
    "credentialCommands": { "aws\\s+secretsmanager\\s+get-secret-value": "block" }
  },

  "logging": {
    "path": "~/.local/share/opencode/bunker/audit.jsonl",
    "includeRaw": false,
    "rotateBytes": 5242880
  },

  "secrets": {
    "enabled": true,              // 112-pattern secret engine
    "action": "redact",           // redact | block | flag
    "patterns": true,             // use the built-in 112 patterns
    "extraPatterns": [],          // { id, category, title, pattern, keywords }
    "redactPaths": [],            // e.g. ["token", "credentials.password"]
    "pathCensor": "[REDACTED]",
    "stripInvisibleUnicode": true
  },

  "classifier": {
    "provider": "heuristic",      // heuristic | onnx-local
    "model": "impacte/bunker-laya",
    "dtype": "fp32",              // fp32 (correct) | q8 (INT8, degraded)
    "cacheDir": "~/.cache/opencode-bunker",
    "maxLen": 1024,
    "headMaxLen": 256,
    "timeoutMs": 120000
  }
}
```

### Custom patterns

| Field | Meaning |
| --- | --- |
| `pattern` | JS regex source (validated for safety) |
| `action` | `allow` \| `flag` \| `redact` \| `block` |
| `label` | replacement text (default `[REDACTED]`) |
| `increment` | confidence delta added to `target` (clamped to 1) |
| `target` | model question to increment (e.g. `pii_secret`, `confidential`) |
| `force` | escalate to `action` regardless of the model |

## Local model (`onnx-local`)

The default classifier is a zero-dependency heuristic. For real accuracy, point
the plugin at the fine-tuned Laya decision model
[`impacte/bunker-laya`](https://huggingface.co/impacte/bunker-laya) — a
ModernBERT-large fine-tune that answers the typed `noul` questions
(`pii_*`, `injection_present`, `jailbreak_attempt`, `harmful_request`) in a
single forward pass:

```jsonc
"classifier": {
  "provider": "onnx-local",
  "model": "impacte/bunker-laya",
  "dtype": "fp32",              // fp32 is correct; q8 (INT8) degrades the PII head
  "cacheDir": "~/.cache/opencode-bunker",
  "maxLen": 1024,
  "headMaxLen": 256,
  "timeoutMs": 120000
}
```

On first use the provider downloads the tokenizer, config and ONNX graph
(~1.6 GB, cached under `cacheDir`) and runs it **in-process** — no Python
sidecar. If the model is missing or fails, the plugin falls back to the
heuristic (fail-open) so a turn is never broken.

### GPU acceleration

The provider tries the **CUDA** execution provider first and falls back to CPU.
The default `onnxruntime-node` build is CPU-only, so to use a GPU:

1. Download the CUDA EP binaries (not bundled — too large for npm):
   ```bash
   ONNXRUNTIME_NODE_INSTALL=cuda12 node node_modules/onnxruntime-node/script/install.js
   ```
2. Make the CUDA 13 libraries discoverable, e.g. via `LD_LIBRARY_PATH` pointing
   at your CUDA 13 `lib` directories.
3. Ensure `CUDA_VISIBLE_DEVICES` uses **ordinals** (`0`, `1`) or is unset — PCI
   bus IDs (e.g. `0000:01:00.0`) break device selection with
   `CUDA failure 101: invalid device ordinal`.

Measured on an RTX 5060 Ti: **~58 ms/prompt on CUDA vs ~2.7 s on CPU (~46×)**.
Note: the snap `bun` strips `LD_LIBRARY_PATH`, so run under Node (or a non-snap
Bun) for GPU. Set `"classifier": { "useGpu": false }` to force CPU.

### How it pairs with Transformers.js

Transformers.js provides the tokenizer and the ONNX Runtime backend; the graph
is a custom decision head, so the provider tokenizes with `AutoTokenizer` and
runs the session directly (`src/classifier/onnx-local.ts`):

```
text ──AutoTokenizer──► input_ids
     ──build Laya head──► marker_pos, marker_mask, qtype
     ──ONNX Runtime─────► logits ──softmax/temperature──► P(true) per question
```

The head is
`[CLS] <qtype> question: <instructions> [SEP] [MASK] false: … [MASK] true: … [SEP] <state> [SEP]`,
with `marker_pos` pointing at each option's `[MASK]`. The model card documents
the full contract. The provider is a faithful port of Laya's
`build_sequence` / `_decode_answers`, verified against the Python
`laya.ONNXAgent` (identical sequences and probabilities).

## Audit log & proof

One JSON line per decision. Example (blocked injection):

```jsonc
{
  "ts": "2026-10-04T10:07:00.000Z",
  "event": "bunker.decision",
  "stage": "pre_provider",
  "hook": "chat.message",
  "sessionID": "…", "messageID": "…",
  "providerDispatched": false,
  "decisionId": "…",
  "decision": "block",
  "confidence": 0.99,
  "deferred": false,
  "entities": [{ "type": "PROMPT_INJECTION", "source": "model", "action": "block", "count": 1, "confidence": 0.99 }],
  "regexIncrements": [],
  "promptSha256": "…64 hex…",
  "promptBytes": 62,
  "latencyMs": 41,
  "rawIncluded": false
}
```

Tool records add `surface: "tool"`, `tool`, `callID`, `argsSha256`, and (for
`tool.execute.after`) `outputSha256`, `outputRedacted`, `outputWouldRedact`.

## Test

```bash
bun test                                     # 113 unit + hook + jailbreak tests
bun run scripts/e2e-onnx-local.ts            # model vs the Python reference (8 checks)
bun run scripts/e2e-plugin.ts                # full pipeline: block/revert/redact/audit (8 checks)
bun run scripts/e2e-jailbreak.ts             # jailbreak corpus report
node .planning/proof/pre-provider-proof.mjs  # standalone proof harness + audit log
```

The jailbreak suite (`test/jailbreak.test.ts`) scores a **68-case corpus** of
state-of-the-art injection/jailbreak techniques — direct override, DAN/AIM/STAN
personas, developer-mode, prompt extraction, fictional framing, base64/hex/
typoglycemia/leetspeak obfuscation, delimiter injection, refusal suppression,
and harmful requests — plus 12 benign controls. Current result: **100% of
injections blocked, 100% of benign allowed** (the corpus is scored once against
the `onnx-local` model; first run downloads ~1.6 GB).

The E2E scripts download the model on first run (cached afterwards).

## Project layout

```
src/
  index.ts                 # plugin entry — default export only
  core.ts                  # config, regex, pipeline, hooks, audit
  classifier/
    onnx-local.ts          # Transformers.js + ONNX Runtime provider
    questions.ts           # typed question bank (mirrors the Python)
  regex/
    engine.ts              # secret engine (Unicode strip, keyword filter, deep walk, paths)
    secret-patterns.ts     # 112 built-in secret patterns
    injection-patterns.ts  # deterministic injection/jailbreak patterns
scripts/
  e2e-onnx-local.ts        # model-vs-Python check
  e2e-plugin.ts            # full plugin-pipeline check
  e2e-jailbreak.ts         # jailbreak corpus report
test/
  smoke.test.ts            # 10 unit + hook tests
  secrets.test.ts          # 12 secret-pattern + heuristic tests
  injection.test.ts        # 21 deterministic injection-pattern tests
  jailbreak.test.ts        # 68-case injection/jailbreak E2E suite
  fixtures/jailbreak-corpus.ts
.planning/                 # spec, architecture, file map, proof
```

## Current state & roadmap

**Built**
- Config loading/merging/validation, regex safety, built-in + custom patterns
  with increment/force.
- **112-pattern secret engine** (opencode-redact parity): keyword pre-filter,
  invisible-Unicode stripping, deep traversal (image/base64-safe), path-based
  redaction, string cache.
- Heuristic classifier and the `onnx-local` provider
  ([`impacte/bunker-laya`](https://huggingface.co/impacte/bunker-laya) v5, fixed
  for the short-prompt injection over-firing).
- Deterministic model backstops: `INJECTION_PATTERNS` (jailbreak/override) and
  `HARMFUL_PATTERNS` (drugs/explosives/malware/phishing/unauthorized access).
- All four hooks, rollback, action precedence, modes, coverage gate.
- Tool-call guardrails (sensitive paths, credential commands, destructive
  actions, output redaction).
- JSONL audit log with the pre-provider proof fields.
- 146 tests: unit/hook, secret/heuristic, injection + harmful patterns, and a
  85-case jailbreak/injection E2E suite, plus end-to-end scripts.

**Pending** (tracked in [`.planning/FILEMAP.md`](./.planning/FILEMAP.md))
- `laya-http` transport (opt-in remote/sidecar classifier).
- Temperature calibration table, per-scope rules, allowlist.
- `bunker_scan` tool and `/bunker` command.
- The full per-file split of `src/core.ts`.

## Contributor note

opencode treats **every named export** of a plugin module as a plugin factory.
`src/index.ts` therefore exports only `default`; all helpers live in
`src/core.ts`. Do not add named exports to `src/index.ts`.

## Repository

<https://github.com/impacte-tech/opencode-bunker> · MIT (plugin); Laya is
Apache-2.0. Model: <https://huggingface.co/impacte/bunker-laya>.
