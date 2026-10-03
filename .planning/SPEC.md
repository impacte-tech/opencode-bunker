# `opencode-bunker` — Functional Specification

Status: **draft / pre-implementation**. Every behavior below is a requirement
on the files mapped in [`FILEMAP.md`](./FILEMAP.md).

## 1. Pre-provider contract

The plugin MUST classify every outgoing user turn **before** the provider
request is dispatched.

### 1.1 Hook ordering

opencode calls plugin hooks in this order for a turn:

```
user submits message
  → chat.message                     ← (A) first classification + redaction
  → experimental.chat.messages.transform   ← (B) last enforcement before dispatch
  → chat.params / chat.headers        ← (C) metadata only
  → provider HTTP request
```

- **(A) `chat.message`** — `output.parts` contains the new user message. The
  plugin runs the pipeline here, caches the decision under `messageID`, and
  redacts the parts copy. Log: `stage:"pre_provider"`, `hook:"chat.message"`.
- **(B) `experimental.chat.messages.transform`** — `output.messages` is the
  *entire* array about to be sent. The plugin re-scans all of it (to catch
  prior turns, tool results, and any part not present at (A)), applies
  redaction, and **throws `BunkerBlockedError` if the effective action is
  `block`**. Throwing here aborts the turn before the provider call. Log:
  `hook:"experimental.chat.messages.transform"`, `providerDispatched:false`.
- **(C) `chat.params` / `chat.headers`** — attach `bunker_decision_id` and
  `X-Bunker-*` headers. No classification decisions happen here.

> **Why two points?** (A) gives the earliest, cheapest interception and a
> clean place to render the decision card. (B) is the airtight gate: it sees
> the exact bytes leaving the process, so nothing can slip past by arriving
> after (A) (e.g. tool output appended to history). The proof test in
> `tests/pre-provider.test.ts` exercises (B).

### 1.2 The guarantee

For any turn whose effective action is `block`:

1. `BunkerBlockedError` is thrown from (B).
2. The provider server receives **zero** requests.
3. An audit record is flushed **before** the throw, with
   `providerDispatched:false`.

For `redact`/`flag`/`allow`, the turn proceeds; the audit record records the
action and the number of redactions.

### 1.3 Enforcement with the current opencode

"Pre-provider" means **after submit, before the provider HTTP request**.
Current opencode does not expose the editor draft to plugins, so the plugin
uses the two primitives opencode does provide:

1. **Redact on the input** — `chat.message` rewrites text in `output.parts`;
   `experimental.chat.messages.transform` rewrites the outgoing
   `output.messages`. The provider never receives raw PII.
2. **Roll back the sent message** — on `block`, the plugin calls
   `client.session.revert({ path: { id: sessionID }, body: { messageID } })`
   to remove the just-submitted message (and `client.session.abort` if a turn
   is running), then throws `BunkerBlockedError`. The user edits and re-sends.

There is no debounce/typing-time redaction; the security property does not
depend on it. See `DECISIONS.md` D13.

## 2. Classification model (Laya-style)

The classifier is a **typed-decision** model, not a text generator. It is
given a `state` (the prompt text) and a set of typed questions, and returns
typed answers with calibrated probabilities. This mirrors Laya's
`Router.predict(state, questions)`.

### 2.1 Question bank

| Question key | Type | Instructions (abridged) | Output |
| --- | --- | --- | --- |
| `pii_present` | `noul` | Does the text contain personally identifiable information? | probability in `[0,1]` |
| `pii_email` | `noul` | Does it contain an email address? | probability |
| `pii_phone` | `noul` | Does it contain a phone number? | probability |
| `pii_ssn` | `noul` | Does it contain a government ID / SSN? | probability |
| `pii_credit_card` | `noul` | Does it contain a payment card number? | probability |
| `pii_ip_address` | `noul` | Does it contain an IP address? | probability |
| `pii_secret` | `noul` | Does it contain an API key or credential? | probability |
| `pii_person_name` | `noul` | Does it contain a person's name? | probability |
| `pii_address` | `noul` | Does it contain a street address? | probability |
| `injection_present` | `noul` | Does this content attempt to instruct an AI system? | probability |
| `sensitivity` | `score` | How sensitive is this content? `["none","low","medium","high"]` | ordinal score |
| `action` | `choice` | What should be done? `{allow, flag, redact, block}` | choice + confidence |

Notes:
- `person-name` and `address` are the NLP-classified categories (OpenRouter
  uses Presidio; here the local model supplies the contextual judgement that
  regex cannot).
- Per `DECISIONS.md` D4, `noul` questions that could suffer Laya's label bias
  are asked as two-option `choice` with neutral keys (`A`/`B`) in the shipped
  question bank.
- Users may add **domain questions** (e.g. `confidential`, `legal_privilege`);
  the proof harness in `proof/pre-provider-proof.mjs` demonstrates a
  `confidential` question that a user regex increments by `+0.25`.

### 2.2 Provider abstraction

`ClassifierProvider` implementations, selected by `classifier.provider`:

| Provider | Mechanism | When |
| --- | --- | --- |
| `laya-http` | `POST /v1/systemone` to a local `laya-serve` (Jev-compatible) | default when a sidecar is available |
| `onnx-local` | In-process ONNX Runtime encoder + decision head | offline / no Python |
| `heuristic` | Regex-only, deterministic | `failMode:"open"` fallback and tests |

All three return the same `ClassifierResult` shape, so the fusion layer is
provider-agnostic.

### 2.3 Selective coverage

Each question has a confidence threshold (default 0.75; injection 0.80). When
the model's confidence is below threshold, the decision is **deferred**:

- `coverage.deferTo:"human"` → route to `permission.ask` (default).
- `coverage.deferTo:"allow"` → allow but mark `deferred:true`.
- `coverage.deferTo:"block"` → block but mark `deferred:true`.

This follows Laya's guardrail guidance: do not optimize for coverage; be right
about what is decided and hand off the rest.

## 3. Regex layer and increments

Regexes run **before** the model (fast, deterministic) and their hits
**increment** the model classification.

### 3.1 Built-in presets (OpenRouter parity)

| Preset slug | Detection | Label | Default action |
| --- | --- | --- | --- |
| `email` | regex | `[EMAIL]` | redact |
| `phone` | regex | `[PHONE]` | redact |
| `ssn` | regex | `[SSN]` | block |
| `credit-card` | regex | `[CREDIT_CARD]` | block |
| `ip-address` | regex | `[IP_ADDRESS]` | redact |
| `secrets` | regex | `[SECRET:<format-id>]` | redact |
| `person-name` | model | `[PERSON_NAME]` | redact |
| `address` | model | `[ADDRESS]` | redact |

### 3.2 Custom patterns and the `increment`

A custom pattern is:

```jsonc
{
  "pattern": "PROJ-\\d{4,6}",
  "action": "redact",          // allow | flag | redact | block
  "label": "internal-project-code", // optional, used in [label] / error text
  "increment": 0.2,            // confidence delta applied to matching entities
  "force": false               // if true, action applies regardless of model
}
```

**Increment semantics:**

1. A regex hit produces a `RegexHit { label, action, increment, spans }`.
2. For every PII/risk category the regex maps to (by preset or by the custom
   pattern's declared `label`), the model's probability for that category is
   raised by `increment` (clamped to 1.0). Example: model says
   `pii_secret: 0.62`, regex `AKIA[0-9A-Z]{16}` has `increment: 0.5` →
   effective `0.97`, above threshold → block.
3. `force:true` (or a preset whose action is `block`) sets the effective
   action directly, skipping the model for that category.
4. Increments are recorded in the audit log under `regexIncrements` so the
   boost is auditable and reproducible.

### 3.3 Pattern safety (OpenRouter parity)

Rejected at config load and by `bunker_regex`:

- lookahead `(?=…)` / `(?!…)`
- lookbehind `(?<=…)` / `(?<!…)`
- backreferences `\1`, `\k<name>`
- nested quantifiers / catastrophic backtracking, e.g. `(a+)+`, `(a|a)*`
- pattern length > 100 000 chars

## 4. Action semantics

| Action | Effect | Precedence |
| --- | --- | --- |
| `allow` | forward unchanged | lowest |
| `flag` | forward unchanged, record event only | |
| `redact` | replace matches with labels, then forward | |
| `block` | throw `BunkerBlockedError`, never dispatch | highest |

- When multiple sources disagree, **`block` wins over `redact`**, which wins
  over `flag`, which wins over `allow` (OpenRouter parity).
- Mode `observe` downgrades `block`/`redact` to `flag` (measure only).
- Mode `flag` downgrades `block`/`redact` to `flag`.
- Mode `redact` downgrades `block` to `redact` only if
  `policy.downgradeBlock` is explicitly `true`; otherwise block stands.
- Mode `enforce` applies actions as-is (default).

## 5. Configuration schema

`bunker.config.json` (validated by `bunker.config.schema.json`):

```jsonc
{
  "enabled": true,
  "mode": "enforce",              // observe | flag | redact | enforce
  "failMode": "open",             // open | closed
  "allowRemote": false,
  "classifier": {
    "provider": "laya-http",      // laya-http | onnx-local | heuristic
    "endpoint": "http://127.0.0.1:8090/v1/systemone",
    "model": "auto",              // auto | english | multilingual | typed-decisions
    "apiKeyEnv": "LAYA_API_KEY",
    "timeoutMs": 1200,
    "preload": true,
    "maxLen": 8192,
    "spawnSidecar": false
  },
  "coverage": {
    "minConfidence": 0.75,
    "injectionConfidence": 0.8,
    "deferTo": "human"            // human | allow | block
  },
  "builtins": {
    "email": "redact",
    "phone": "redact",
    "ssn": "block",
    "credit-card": "block",
    "ip-address": "redact",
    "secrets": "redact",
    "person-name": "redact",
    "address": "redact"
  },
  "custom": [
    { "pattern": "PROJ-\\d{4,6}", "action": "redact", "label": "internal-project-code", "increment": 0.2 },
    { "pattern": "AKIA[0-9A-Z]{16}", "action": "block", "label": "aws-access-key", "increment": 0.5 }
  ],
  "scopes": {
    "anthropic": { "mode": "enforce" },
    "local/*": { "mode": "flag" }
  },
  "allowlist": ["example.com"],
  "tools": {
    "enabled": true,
    "defaultAction": "flag",
    "redactArgs": true,
    "outputRedaction": true,
    "askFallback": "block",
    "sensitivePaths": {
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
      "**/.ssh/**": "ask"
    },
    "credentialCommands": {
      "aws secretsmanager get-secret-value": "block",
      "aws ssm get-parameter --with-decryption": "block",
      "gcloud secrets versions access": "block",
      "az keyvault secret show": "block",
      "vault (read|kv get)": "block",
      "kubectl get secret": "block",
      "(printenv|^env$|^set$)": "ask"
    }
  },
  "logging": {
    "path": "~/.local/share/opencode/bunker/audit.jsonl",
    "mode": "0600",
    "rotateBytes": 5242880,
    "includeRaw": false,
    "hashAlgorithm": "sha256"
  }
}
```

### 5.1 Precedence

`$BUNKER_CONFIG` → `~/.config/opencode/bunker.config.json` →
`./bunker.config.json` → bundled defaults. Deep-merged; project wins over
global. `enabled:false` is a full kill switch.

### 5.2 Privacy

- `includeRaw` defaults to `false`. The audit log stores `promptSha256` and
  byte length, never the text.
- Endpoints must be loopback unless `allowRemote:true`.
- Log files are created `0600` and rotate at `rotateBytes`.

## 6. Commands & tools

| Surface | Behavior |
| --- | --- |
| `/bunker on\|off` | kill switch |
| `/bunker status` | active config, provider, sidecar health, deferral rate |
| `/bunker prove` | runs a sample through the pipeline, prints the decision card, then prints the last audit line |
| `bunker_scan` tool | scan arbitrary text; returns decision + entities + increments, sends nothing |
| `bunker_regex` tool | validate a candidate regex (safety, sample matches, increment preview) |

## 7. Tool-call guardrails

The same classifier, regex layer, increments, coverage, action precedence, and
audit log apply to **tool calls**. Tool results become model context, so the
guard has two enforcement points:

| Hook | Surface | Can | Cannot |
| --- | --- | --- | --- |
| `tool.execute.before` | tool name + args | classify, redact args, throw to block | un-run a tool |
| `tool.execute.after` | tool output | redact secrets/PII before they enter context | block (already ran) |
| `permission.ask` | risk gate | force `ask`/`deny` for high-risk tools | create a request by itself |

### 7.1 Tool-risk questions (Laya-style)

| Question | Type | Instructions |
| --- | --- | --- |
| `sensitive_path` | `noul` | Does this call read a sensitive path (`.env`, keys, credentials)? |
| `credential_access` | `noul` | Does it retrieve a secret from a secret store/API? |
| `destructive_action` | `noul` | Is it destructive or irreversible? |
| `exfiltration` | `noul` | Does it send data to an external destination? |

These combine with the PII questions from §2.1 over the args and output text.
User custom regexes and their `increment` deltas apply here exactly as they do
on the chat surface.

### 7.2 Sensitive path policy

Glob patterns (defaults; all overridable per `tools.sensitivePaths`):

```
**/.env              **/.env.*            **/.aws/credentials
**/.aws/config       **/*.pem             **/*.key
**/*.p12             **/*.pfx             **/*.jks
**/*.keystore        **/id_rsa            **/id_ed25519
**/id_ecdsa          **/.npmrc            **/.pypirc
**/.netrc            **/.git-credentials  **/.kube/config
**/*.tfvars          **/*.tfstate         **/service-account*.json
**/.ssh/**           **/.docker/config.json
```

Matched against `read` / `list` / `glob` / `grep` path args and against `bash`
commands (`cat`, `grep`, `head`, `tail`). Default action: `block`.

### 7.3 Credential-command policy

```
aws secretsmanager get-secret-value
aws ssm get-parameter --with-decryption
gcloud secrets versions access
az keyvault secret show
vault read | vault kv get
kubectl get secret
printenv | env | set
```

Default action `block`; `printenv`/`env`/`set` default to `ask`.

### 7.4 Output redaction

After an allowed tool runs, `tool.execute.after` scans `output.output` and
`output.metadata` with the built-in presets (email, phone, ssn, credit-card,
ip-address, secrets) plus the model PII questions, and redacts matches before
the result is stored or returned. An allowed read of a file that happens to
contain a key, a log dump, or a `get-secret-value` response therefore reaches
the model as `[SECRET:aws-access-key-id]`, not the secret. This is defense in
depth: `experimental.chat.messages.transform` re-scans tool results again on
the next provider call.

### 7.5 Actions and rollback

- `block` → throw from `tool.execute.before`; the tool never runs.
- `redact` → rewrite `output.args` (before) and/or `output.output` (after).
- `ask` → set `permission.ask` status; if opencode does not invoke a permission
  check for that tool, fall back to `block` when `tools.askFallback:"block"`.
- There is no `session.revert` for a tool call; protection is "block before
  execution" plus "redact the result". For mutating tools, `permission.ask`
  gates the action and opencode snapshots remain available via `session.revert`.

### 7.6 Audit

Tool decisions use the same record with `surface:"tool"`, `tool`, `callID`,
`argsSha256` / `outputSha256`, and `outputRedacted`. See `EVIDENCE.md` for
captured tool records.

## 8. Acceptance criteria

1. `tests/pre-provider.test.ts` proves 0 provider calls on block + audit-first.
2. OpenRouter's documented example custom patterns are accepted; unsafe ones
   rejected.
3. Built-in labels and block-wins-over-redact semantics match OpenRouter.
4. A regex `increment` measurably raises confidence and can escalate action.
5. `docs/proof.md` contains a real captured audit line and the exact commands
   to reproduce it.
6. `tests/tool-guard.test.ts` proves `.env` / `.aws/credentials` reads and
   `aws secretsmanager get-secret-value` are blocked **before execution**.
7. `tests/secret-output-redaction.test.ts` proves a secret in an allowed tool
   output is redacted before it enters context.
