# `opencode-bunker` — Architecture

## 1. Component overview

```
                         opencode process (Bun)
┌──────────────────────────────────────────────────────────────────────────┐
│  src/index.ts  (Plugin)                                                   │
│     │                                                                     │
│     ├── config.ts ───────────────► BunkerConfig                           │
│     │                                                                     │
│     ├── policy/pipeline.ts ──────► run(text, ctx) -> Decision             │
│     │      │                                                              │
│     │      ├── regex/builtins + custom ─┐                                 │
│     │      │   (+ increment deltas)     │                                 │
│     │      ├── classifier/decision ◄────┘   fuse + action precedence      │
│     │      │      ▲                                                       │
│     │      │      └── classifier/coverage (selective coverage)            │
│     │      │                                                              │
│     │      └── classifier/laya-client ──HTTP──► sidecar (loopback)        │
│     │                 │                         ┌──────────────────────┐  │
│     │                 └── classifier/onnx-local │ laya-serve           │  │
│     │                     (in-process fallback) │ POST /v1/systemone   │  │
│     │                                           └──────────────────────┘  │
│     │                                                                     │
│     ├── hooks/chat-message.ts        (A) classify + redact + log          │
│     ├── hooks/messages-transform.ts  (B) re-scan + block (throws)         │
│     ├── hooks/chat-params.ts         (C) metadata                          │
│     ├── hooks/chat-headers.ts        (C) X-Bunker-*                        │
│     ├── hooks/tool-execute-before.ts destructive-action guard             │
│     └── hooks/permission-ask.ts      human gate for deferred/high risk     │
│                                                                           │
│  telemetry/logger.ts ──append──► ~/.local/share/opencode/bunker/audit.jsonl│
│  telemetry/decision-card.ts ──► terminal card                             │
└──────────────────────────────────────────────────────────────────────────┘
```

## 2. Hook ordering (the pre-provider guarantee)

```
user input
   │
   ▼
┌───────────────────────────────────────────┐
│ chat.message  (hook A)                     │  output.message + output.parts
│  decision = pipeline.run(parts)            │  ── cache by messageID
│  redact(parts)  ← "redact on the input"    │  ── audit: hook=chat.message
│  if block:                                 │
│      log(providerDispatched=false)         │  ← audit BEFORE any dispatch
│      client.session.revert({messageID})    │  ← "roll back the sent message"
│      client.session.abort()                │
│      throw BunkerBlockedError ─────────────┼──► ✗ provider never called
└───────────────────┬───────────────────────┘
                    ▼
     (opencode assembles full message array incl. history + tool output)
                    ▼
┌───────────────────────────────────────────┐
│ experimental.chat.messages.transform (B)   │  output.messages = EXACT bytes
│  re-scan ALL messages                      │  ── catches anything added after A
│  redact(messages)                          │
│  if block:                                 │
│      log(providerDispatched=false)         │
│      session.revert({messageID}) + abort   │
│      throw BunkerBlockedError ─────────────┼──► ✗ provider never called
└───────────────────┬───────────────────────┘
                    ▼
┌───────────────────────────────────────────┐
│ chat.params / chat.headers                 │  bunker_decision_id + X-Bunker-*
└───────────────────┬───────────────────────┘
                    ▼
            provider HTTP request
```

`session.revert` is the current-opencode rollback primitive
(`POST /session/{id}/revert`, body `{ messageID, partID? }`); `session.abort`
stops a running turn; `session.unrevert` restores. See `DECISIONS.md` D13.

`tests/pre-provider.test.ts` asserts that the provider mock observes zero
requests when hook B throws, and that the audit record exists first.
`tests/rollback.test.ts` asserts `session.revert` is called with the offending
`messageID` on block and not called on redact/allow.

## 2.1 Tool-call guard flow (same pipeline, different enforcement points)

```
tool call (tool name + args)
   │
   ▼
┌────────────────────────────────────────────┐
│ tool.execute.before                         │
│  decision = toolPipeline.classify(tool,args)│
│   - sensitive path policy (§7.2 SPEC)       │
│   - credential command policy (§7.3 SPEC)   │
│   - secret/PII regex + increments over args │
│   - model questions (sensitive_path,        │
│     credential_access, destructive_action)  │
│  redact(output.args)  ← secrets in args     │
│  if block:                                  │
│      log(surface:"tool", providerDispatched:false)
│      throw BunkerBlockedError ──────────────┼──► ✗ tool never runs
└───────────────────┬────────────────────────┘
                    ▼
              tool executes
                    ▼
┌────────────────────────────────────────────┐
│ tool.execute.after                          │
│  scan output.output + output.metadata       │
│  redact secrets/PII → "[SECRET:…]"          │
│  log(surface:"tool", outputRedacted:true)   │
└───────────────────┬────────────────────────┘
                    ▼
   tool result enters model context (already sanitized)
                    ▼
   experimental.chat.messages.transform re-scans everything again
```

Key points:

- `tool.execute.before` is the **block/rollback** point: throwing aborts the
  call, so a `.env` read or `aws secretsmanager get-secret-value` never runs.
- `tool.execute.after` is the **redaction** point: a read that was allowed (or
  a tool whose output unexpectedly contains a secret) is scrubbed before the
  result is stored or returned.
- `permission.ask` is the human gate for high-risk tools; `tools.askFallback`
  decides what happens when no permission check is triggered (default `block`).
- The chat-surface transform hook is a second net over tool results, so a
  missed `after` redaction is still caught before the next provider call.

## 3. Decision pipeline

```
normalize(text)
   │
   ├─ 1. builtin regex presets ──────────────► RegexHit[]
   │        (email, phone, ssn, credit-card,
   │         ip-address, secrets)
   │
   ├─ 2. custom regex (+increment/force) ────► RegexHit[]
   │        unsafe patterns rejected at load
   │
   ├─ 3. model typed questions ──────────────► ClassifierResult
   │        laya-http | onnx-local | heuristic
   │        (person-name, address, injection,
   │         sensitivity, action)
   │
   ├─ 4. coverage gate ──────────────────────► decided | deferred
   │        per-question thresholds
   │
   ├─ 5. fuse(model, regex) ─────────────────► effective probabilities
   │        probability += Σ increments (clamp 1.0)
   │        force/preset block overrides
   │
   └─ 6. action precedence ──────────────────► Decision
            block > redact > flag > allow
            mode downgrades (observe/flag/redact)
```

Every stage appends a `PipelineStage` entry, so a decision carries a trace
analogous to OpenRouter's `openrouter_metadata.pipeline[]`.

## 4. Data shapes

```ts
type Action = "allow" | "flag" | "redact" | "block";

interface Entity {
  type: string;                 // "EMAIL" | "pii_person_name" | "SECRET:github-token"
  source: "regex" | "model" | "both";
  action: Action;
  count: number;
  confidence?: number;          // model probability after increments
  label?: string;               // "[EMAIL]" / custom label
}

interface RegexHit {
  patternId: string;
  label?: string;
  action: Action;
  increment: number;
  spans: Array<{ start: number; end: number }>;
}

interface Decision {
  decisionId: string;
  action: Action;
  confidence: number;
  deferred: boolean;
  entities: Entity[];
  regexIncrements: Array<{ label: string; delta: number; action: Action }>;
  stages: PipelineStage[];
  latencyMs: number;
  promptSha256: string;
  promptBytes: number;
}

interface ToolDecision extends Decision {
  surface: "tool";
  tool: string;
  callID: string;
  argsSha256: string;
  outputSha256?: string;
  outputRedacted?: boolean;
}
```

## 5. Laya integration

- **Transport.** `laya-serve` exposes `POST /v1/systemone` with
  `{ state, questions }`; unknown fields are ignored; malformed questions get
  a `422`. The client sends `X-Client: opencode-bunker` and an optional
  `Authorization: Bearer $LAYA_API_KEY`.
- **State.** `{ "document": <prompt text> }` (or a JSON object for tool
  args). Long inputs use `model:"multilingual", max_len:8192`.
- **Questions.** The bank in `SPEC.md` §2.1. Each `noul` returns a
  probability; `choice` returns the option + confidence; `score` returns an
  ordinal value.
- **Confidence.** Gate on `confidence`, not `action.act_probability` (Laya
  documents `act_probability` as unusable; AUROC 0.30 vs 0.77 for
  confidence).
- **Calibration.** Apply per-(question type, option count) temperature scaling
  from `calibration.ts` before thresholding, because the base checkpoint ships
  over-confident (ECE 0.466 → 0.081 after fitting).
- **Fail modes.**
  - `failMode:"open"` → classifier error falls back to `heuristic.ts`; if
    that yields no block, the turn proceeds. Audit `degraded:true`.
  - `failMode:"closed"` → classifier error is treated as `block`/defer per
    config. Audit `degraded:true, failClosed:true`.

## 6. OpenRouter Guardrails parity map

| OpenRouter feature | bunker implementation | Test |
| --- | --- | --- |
| Sensitive Info presets (`email`, `phone`, `ssn`, `credit-card`, `ip-address`, `secrets`) | `regex/builtins.ts`, `regex/secret-formats.ts` | `redaction.test.ts` |
| NLP presets (`person-name`, `address`) | model questions `pii_person_name`, `pii_address` | `classifier-decision.test.ts` |
| Custom content filters (`pattern`, `action`, `label`) | `regex/custom.ts` + `increment` | `redaction.test.ts`, `classifier-decision.test.ts` |
| Pattern safety (no lookaround/backref/ReDoS, ≤100k chars) | `regex/safety.ts` | `regex-safety.test.ts` |
| `redact` / `block` actions; `block` wins over `redact` | `policy/actions.ts` | `redaction.test.ts` |
| Filters unioned across scopes | `policy/scopes.ts` | M5 |
| Prompt-injection patterns + evasion (typoglycemia, misspelling, base64/hex, char-spacing) | `regex/injection-patterns.ts` | M5 |
| `flag` / `redact` / `block` priority `block>redact>flag` | `policy/actions.ts` | `redaction.test.ts` |
| Pipeline stage trace (`openrouter_metadata.pipeline`) | `policy/pipeline.ts` `stages[]` | `classifier-decision.test.ts` |
| Input-side only (no response scanning) | pipeline runs on outgoing messages only | `pre-provider.test.ts` |
| 403 + `metadata.patterns` error | `BunkerBlockedError` carries labels/patterns | `pre-provider.test.ts` |
| Sensitive data in tool calls / tool results | `tool.execute.before` (args) + `tool.execute.after` (output) reuse the same presets/model/increments | `tool-guard.test.ts`, `secret-output-redaction.test.ts` |
| Credential-store access (secret managers) | `policy/credential-commands.ts` blocks `aws secretsmanager get-secret-value`, `ssm --with-decryption`, `gcloud secrets`, `az keyvault`, `vault`, `kubectl get secret` | `tool-guard.test.ts` |
| Sensitive file reads | `policy/paths.ts` globs (`.env*`, `.aws/credentials`, keys, `.kube/config`, `*.tfvars`, …) | `sensitive-path.test.ts` |

## 7. Logging & proof

`telemetry/logger.ts` appends one JSON line per decision to
`~/.local/share/opencode/bunker/audit.jsonl`. The proof fields are
`stage`, `hook`, `providerDispatched`, `promptSha256`, and `decision`. Tool
records add `surface:"tool"`, `tool`, `callID`, `argsSha256`,
`outputSha256`, and `outputRedacted`. See [`EVIDENCE.md`](./EVIDENCE.md) for
the schema and captured examples.

## 8. Failure handling

| Failure | Behavior |
| --- | --- |
| Config invalid | plugin logs an error and disables itself (does not break opencode startup). |
| Classifier timeout | per `failMode`; timeout above the warm-up cost (default 1200 ms, warm ~22–35 ms). |
| Unsafe user regex | rejected at load with the offending index; plugin continues with remaining patterns. |
| Audit log unwritable | plugin continues but surfaces a warning event; decisions still enforced. |
| Non-loopback endpoint | rejected unless `allowRemote:true`. |
