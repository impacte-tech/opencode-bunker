# `opencode-bunker` — Evidence & Proof

This document is the **documentation proof** required by the project: it shows
that classification and redaction happen *before* any provider call, and that a
`block` decision rolls the message back and dispatches nothing.

Because the implementation files are still `pending` (`FILEMAP.md`), this
folder also contains a **runnable, zero-dependency proof harness** that models
the exact current-opencode flow — chat (redact the input + `session.revert`
rollback) and **tool calls** (`tool.execute.before` block, `tool.execute.after`
output redaction). It emits a **real audit log** you can inspect.

> Harness: [`proof/pre-provider-proof.mjs`](./proof/pre-provider-proof.mjs)
> Generated log: [`proof/audit.jsonl`](./proof/audit.jsonl)

## 1. The three claims being proven

| # | Claim | How it is proven |
| --- | --- | --- |
| C1 | Classification runs **before** provider dispatch | audit record has `stage:"pre_provider"` and `hook:"chat.message"` / `"experimental.chat.messages.transform"`; it is written before the throw |
| C2 | A `block` decision dispatches **nothing** | mock provider's HTTP request counter stays at **0**; `session.revert` is called with the offending `messageID` |
| C3 | Redaction happens **on the input** | `promptSha256` is of the original; the entity list + redaction counts are recorded; `rawIncluded:false` |
| C4 | Risky **tool calls never execute** | `tool.execute.before` throws on `.env` / `.aws/credentials` / `aws secretsmanager get-secret-value`; the tool-execution counter stays at **0** |
| C5 | Secrets in **tool output** are redacted before context | `tool.execute.after` rewrites an allowed read's output; audit records `surface:"tool"`, `outputRedacted:true` |

## 2. Reproduce

```bash
cd ~/Projects/homelab/opencode-bunker
node .planning/proof/pre-provider-proof.mjs
cat .planning/proof/audit.jsonl
```

## 3. Captured run (2026-10-03)

```
opencode-bunker · pre-provider proof — chat surface

scenario                     action   deferred  provider calls  reverted  threw
-----------------------------------------------------------------------------------------------
redact email + phone         redact   no        1               0         -
regex increment (PROJ-)      redact   no        1               0         -
block AWS secret (force)     block    no        0               1         BunkerBlockedError
defer person name            flag     yes       1               0         -

opencode-bunker · pre-provider proof — tool surface

scenario                         tool   action   executed   output redacted  threw
-----------------------------------------------------------------------------------------------
read .env                        read   block    0          no               BunkerBlockedError
read ~/.aws/credentials          read   block    0          no               BunkerBlockedError
aws get-secret-value             bash   block    0          no               BunkerBlockedError
read notes.txt (secret inside)   read   allow    1          yes              -

PROOF:
  chat: block "block AWS secret (force)" -> provider calls = 0, reverted = 1, aborted = 1
  tool: block "read .env" -> executions = 0 (never ran)
  tool: "read notes.txt (secret inside)" -> output redacted before it entered context = true
  audit records written: 12 -> .planning/proof/audit.jsonl
  every record has stage=pre_provider and rawIncluded=false
```

Reading the table:

- **`block AWS secret (force)`** → `provider calls = 0`, `reverted = 1`. This is
  C2: the message was rolled back and the provider was never called.
- **`regex increment (PROJ-)`** → the user regex `internal-project-code` raised
  the model's `confidential` probability by `+0.25` (0.55 → 0.80), producing a
  `CONFIDENTIAL` entity with `source:"both"`. This is the "regex increments the
  model classification" requirement.
- **`defer person name`** → confidence 0.62 < 0.75 → `deferred:true`,
  `decision:"flag"` (selective coverage), and the provider still receives the
  redacted input.
- Every row that proceeded shows `provider calls = 1` **after** an audit record
  was written, i.e. classification precedes dispatch.
- **`read .env` / `read ~/.aws/credentials` / `aws get-secret-value`** →
  `executed = 0`. This is C4: the path/command policy matched and the tool was
  blocked **before execution**, so no secret was ever read.
- **`read notes.txt (secret inside)`** → `executed = 1`, `output redacted = yes`.
  This is C5: the read was allowed, but `tool.execute.after` replaced the key
  with `[SECRET:…]` before the result entered context.

## 4. Real audit records (extract from `proof/audit.jsonl`)

The block record (C2), verbatim:

```json
{
  "ts": "2026-10-03T23:32:57.793Z",
  "event": "bunker.decision",
  "stage": "pre_provider",
  "hook": "chat.message",
  "sessionID": "ses_proof_2",
  "messageID": "4e7f126d-4214-43b2-a2c3-b19d75e1b929",
  "providerDispatched": false,
  "decisionId": "545c1874-90a0-4cb2-99ea-15c5cbf5df0b",
  "decision": "block",
  "confidence": 1,
  "deferred": false,
  "entities": [
    { "type": "aws-access-key", "source": "regex", "action": "block", "count": 1, "confidence": 1 }
  ],
  "regexIncrements": [
    { "label": "aws-access-key", "delta": 0.5, "action": "block", "target": "pii_secret" }
  ],
  "promptSha256": "8b454fa6db14e28f6bdef47b86fb91ac499b26a51eaa8fd3345cc62cbaaf4716",
  "promptBytes": 56,
  "latencyMs": 0.42,
  "rawIncluded": false
}
```

The increment record (regex → model classification), condensed:

```
chat.message   dec=redact disp=null  def=false
  ents=[email:redact@0.97(regex),
        internal-project-code:redact@0.8(regex),
        CONFIDENTIAL:flag@0.8(both)]
  inc=[internal-project-code+0.25->confidential]
```

The deferral record (selective coverage):

```
chat.message   dec=flag disp=null  def=true ents=[] inc=[]
```

The tool records (C4/C5):

```
tool.execute.before  tool=read  dec=block  ents=[SENSITIVE_PATH:dotenv:block(regex)]
tool.execute.before  tool=read  dec=block  ents=[SENSITIVE_PATH:aws-credentials:block(regex)]
tool.execute.before  tool=bash  dec=block  ents=[CREDENTIAL_ACCESS:aws-secretsmanager:block(regex)]
tool.execute.after   tool=read  dec=redact outputRedacted=true ents=[aws-access-key:block(regex)]
```

Note `rawIncluded:false` on every record and that no record contains the prompt
text — only `promptSha256` and `promptBytes`. The log is proof, not a leak.

## 5. Audit record schema

| Field | Meaning |
| --- | --- |
| `ts` | ISO-8601 timestamp |
| `event` | always `bunker.decision` |
| `stage` | `pre_provider` (classification precedes dispatch) |
| `hook` | `chat.message` or `experimental.chat.messages.transform` |
| `surface` | absent for chat; `"tool"` for tool records |
| `tool` / `callID` | tool name + opencode call id (tool records) |
| `argsSha256` / `outputSha256` | hashes of the tool args / output (tool records) |
| `outputRedacted` | `true` when `tool.execute.after` rewrote the output |
| `sessionID` / `messageID` | opencode identifiers; `messageID` is what `session.revert` targets |
| `providerDispatched` | `false` when blocked, `true` after a permitted dispatch, `null` at first sight |
| `decision` | `allow` \| `flag` \| `redact` \| `block` |
| `confidence` | fused confidence after increments |
| `deferred` | selective-coverage deferral flag |
| `entities[]` | `{ type, source: regex\|model\|both, action, count, confidence }` |
| `regexIncrements[]` | `{ label, delta, action, target }` — the auditable boost |
| `promptSha256` | sha256 of the original prompt |
| `promptBytes` | original byte length |
| `latencyMs` | local classification latency |
| `rawIncluded` | always `false` in the proof run |

## 6. How the shipped plugin proves the same thing

The harness is a model; the real plugin (once `FILEMAP.md` is built) proves the
claims with:

1. **`tests/pre-provider.test.ts`** — a mock provider server asserts zero
   requests when `block` is returned, and that the audit line is flushed first.
2. **`tests/rollback.test.ts`** — asserts `session.revert` is called with the
   offending `messageID` on `block` (and `session.abort` when a turn is
   running), and is not called on `redact`/`allow`.
3. **`/bunker prove`** — runs a sample through the live pipeline, prints the
   decision card, then prints the last audit line.
4. **`docs/proof.md`** — the user-facing version of this document, populated
   with a real capture from the installed plugin.
5. **`tests/tool-guard.test.ts`** — asserts `.env` / `.aws/credentials` reads
   and `aws secretsmanager get-secret-value` are blocked before execution.
6. **`tests/secret-output-redaction.test.ts`** — asserts a secret in an allowed
   tool output is redacted before it enters context.

## 7. Honest limits

- The harness uses a deterministic heuristic in place of the real Laya
  checkpoint; it models the *interface and ordering*, not model accuracy.
- opencode exposes no editor-draft hook, so the textarea itself is not redacted
  while typing. The input that reaches a provider always is (see
  `DECISIONS.md` D13).
- Regex-only detection is not exhaustive, and model detection of names/addresses
  is probabilistic — the same limits OpenRouter documents for its NLP presets.
