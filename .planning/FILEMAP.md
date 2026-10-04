# `opencode-bunker` — Missing Implementation Files Map

Companion to [`README.md`](./README.md). Project root: `<repo-root>/`.

This is the **authoritative map of the target implementation**. A working
**M0-lite** slice is already implemented — consolidated in a single module
[`src/core.ts`](../src/core.ts) with a default-only entry
[`src/index.ts`](../src/index.ts) — and is live-verified against opencode
1.18.34. The per-file split below remains the target; rows not yet written are
`pending`.

## Implemented now (M0-lite)

| File | Notes |
| --- | --- |
| `package.json`, `tsconfig.json`, `opencode.json`, `bunker.config.json` | package + local plugin registration + shipped defaults |
| `src/index.ts` | plugin entry; **default export only** (opencode treats named exports as plugin factories) |
| `src/core.ts` | all logic: config, regex presets, custom + increment, heuristic Laya-style provider, coverage, action precedence, chat/tool hooks, rollback, audit logger |
| `test/smoke.test.ts` | 10 tests (classify, increment, path/command guard, output redaction, regex safety, hooks + rollback) |

Deferred to the milestones below: real `laya-http` / `onnx-local` providers,
calibration, per-scope rules, allowlist, `bunker_scan` / `/bunker` command,
prompt-injection evasion passes, and the full file split.

## Legend

- **Origin** — `new` (written from scratch) · `adapt` (adapted from a known
  pattern) · `port` (near-verbatim copy).
- **Status** — `pending` (not created) · `in_progress` · `built` · `verified`.
- **Priority** — `P0` blocks the proof; `P1` needed for a usable plugin;
  `P2` hardening/parity; `P3` polish.
- **Refs** — `OR` = OpenRouter Guardrails parity point, `LY` = Laya API,
  `OC` = opencode plugin hook.

## 1. Repository scaffolding

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 1.1 | `package.json` | P0 | new | pending | Bun/Node package manifest. `type: module`, entry `src/index.ts`, `exports`, `repository: "github:impacte-tech/opencode-bunker"`, deps (`@opencode-ai/plugin`, `zod`, `onnxruntime-node` optional, `@noble/hashes` for sha256), scripts `test`/`typecheck`/`build`. `OC` |
| 1.2 | `tsconfig.json` | P0 | new | pending | Strict TS, Node22/Bun libs, `noEmit` for typecheck, path alias `@/*`. |
| 1.3 | `opencode.json` | P0 | new | pending | Registers the plugin: `{ "$schema": "https://opencode.ai/config.json", "plugin": ["./src/index.ts"] }`. `OC` |
| 1.4 | `bunker.config.json` | P0 | new | pending | Shipped default config (see `SPEC.md` §5). Classifier endpoint, coverage thresholds, builtins, custom regexes, **tool guard (sensitive paths, credential commands, output redaction)**, logging. |
| 1.5 | `bunker.config.schema.json` | P1 | new | pending | JSON Schema for user config validation; referenced by editors. |
| 1.6 | `.gitignore` | P0 | new | pending | `node_modules/`, `dist/`, `*.log`, local audit logs, `.env`. |
| 1.7 | `LICENSE` | P1 | new | pending | MIT (plugin) — note Laya is Apache-2.0 and ONNX weights carry their own license. |
| 1.8 | `README.md` | P1 | new | **stub created** | User-facing docs incl. install, config, **Evidence/Proof** section pointing at `docs/proof.md`. Current root `README.md` is a minimal landing page linking to `.planning/`. |
| 1.9 | `biome.json` | P2 | adapt | pending | Lint/format config (mirrors `pi-laya-router`). |

## 2. Plugin core (`src/`)

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 2.1 | `src/index.ts` | P0 | adapt | pending | Plugin entry: `export default (async (input) => ({ ...hooks })) satisfies Plugin`. Loads config, builds the classifier + pipeline singletons, wires all hooks, returns `{ config, "chat.message", "chat.params", "chat.headers", "experimental.chat.messages.transform", "tool.execute.before", "permission.ask", tool }`. `OC` |
| 2.2 | `src/types.ts` | P0 | new | pending | Shared types: `BunkerConfig`, `Decision`, `Entity`, `RegexHit`, `Action`, `ClassifierResult`, `AuditRecord`, `PipelineStage`. `OR` |
| 2.3 | `src/config.ts` | P0 | new | pending | Load/merge/validate config with precedence: `$BUNKER_CONFIG` → `~/.config/opencode/bunker.config.json` → `./bunker.config.json` → defaults. Zod validation + `failMode` semantics. |
| 2.4 | `src/constants.ts` | P1 | new | pending | Placeholder labels (`[EMAIL]`, `[PHONE]`, `[SSN]`, `[CREDIT_CARD]`, `[IP_ADDRESS]`, `[SECRET:<id>]`, `[PERSON_NAME]`, `[ADDRESS]`, `[REDACTED]`, `[PROMPT_INJECTION]`), preset→label map, hook name constants. `OR` |
| 2.5 | `src/errors.ts` | P1 | new | pending | `BunkerBlockedError` (thrown from the transform hook to abort the provider call), `ClassifierUnavailableError`, `UnsafeRegexError`. |

## 3. opencode hooks (`src/hooks/`)

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 3.1 | `src/hooks/chat-message.ts` | P0 | new | pending | **Earliest pre-provider interception.** On `chat.message`, extract text from `output.parts`, run the full pipeline, cache the `Decision` keyed by `messageID`, log `hook:"chat.message"`. **Redacts text in `output.parts` in place** ("redact on the input"). On `block`, calls `hooks/rollback.ts` (session.revert + abort) and throws `BunkerBlockedError`. `OC` |
| 3.2 | `src/hooks/messages-transform.ts` | P0 | new | pending | **Last pre-dispatch enforcement.** On `experimental.chat.messages.transform`, re-scan the *entire* outgoing `output.messages` array (catches prior turns + tool output), redact it, and on `block` call `rollback.ts` then **throw `BunkerBlockedError`**. This is the hook that makes the guarantee airtight. `OC` |
| 3.3 | `src/hooks/chat-params.ts` | P1 | new | pending | On `chat.params`, attach bunker metadata to `output.options` (e.g. `bunker_decision_id`) so downstream tracing can correlate. No model rewriting. `OC` |
| 3.4 | `src/hooks/chat-headers.ts` | P2 | new | pending | On `chat.headers`, add `X-Bunker-Decision`, `X-Bunker-Model`, `X-Bunker-Latency-Ms` for observability. `OC` |
| 3.5 | `src/hooks/tool-execute-before.ts` | P0 | adapt | pending | **Tool-call block/redact point.** Classify `tool` + `output.args` with the tool pipeline (sensitive-path + credential-command policy, secret/PII regex, model questions). Redact secrets in args; on `block` throw `BunkerBlockedError` (tool never runs); on `ask` route to `permission.ask`. `OC` |
| 3.6 | `src/hooks/permission-ask.ts` | P1 | adapt | pending | Human-approval gate: force `status:"ask"`/`"deny"` for high-risk or deferred decisions; honor `tools.askFallback` (default `block`) when no permission check is triggered. Never silently allow a deferred block. `LY`/`OC` |
| 3.7 | `src/hooks/config.ts` | P1 | new | pending | `config` hook: read opencode's merged config to learn active providers/models and apply per-provider scopes. `OC` |
| 3.8 | `src/hooks/rollback.ts` | P0 | new | pending | **Roll back the sent message.** Wraps `client.session.revert({ path:{id:sessionID}, body:{ messageID, partID? } })` and `client.session.abort()`; returns the updated `Session.revert` handle. Used by 3.1/3.2 on `block`. No future-version probes (`DECISIONS.md` D13). `OC` |
| 3.9 | `src/hooks/tool-execute-after.ts` | P0 | new | pending | **Tool-output redaction.** Scan `output.output` + `output.metadata` with the built-in presets, model PII questions, and `regex/redact.ts`; replace secrets/PII before the result is stored/returned. Audit `surface:"tool"`, `outputSha256`, `outputRedacted:true`. Cannot block (tool already ran). `OC` |

## 4. Classifier — Laya-style decision model (`src/classifier/`)

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 4.1 | `src/classifier/questions.ts` | P0 | adapt | pending | The **typed question bank**. One `noul` per PII category + injection + destructive + a `choice` action and a `score` sensitivity. Uses neutral keys to dodge Laya's `noul` label bias (see `DECISIONS.md` D4). `LY` |
| 4.2 | `src/classifier/laya-client.ts` | P0 | adapt | pending | HTTP client for a Laya-compatible endpoint: `POST /v1/systemone` (Jev shape) with timeout, bearer `LAYA_API_KEY`, `X-Client: opencode-bunker`, warm-up call, fail-open/closed per config. `LY` |
| 4.3 | `src/classifier/laya-server.ts` | P1 | new | pending | Sidecar lifecycle: detect `laya-serve` on `127.0.0.1:8090`, optionally spawn `python -m laya.serve` / `uv run`, health-check, preload, shutdown on plugin dispose. Refuses non-loopback endpoints unless `allowRemote`. `LY` |
| 4.4 | `src/classifier/onnx-local.ts` | P2 | new | pending | **"Laya-style" in-process fallback**: ONNX Runtime ModernBERT encoder + decision head (choice/score/noul) so the plugin classifies with no Python sidecar. Loads `models/bunker-pii/` (see 4.5). |
| 4.5 | `src/classifier/model-manager.ts` | P2 | new | pending | Resolve/download/cache local ONNX weights (`convaiinnovations/laya` export or a PII-fine-tuned head), verify sha256, LRU-load, expose `.predict()`. |
| 4.6 | `src/classifier/decision.ts` | P0 | new | pending | Fuse model answers + regex hits into a single `Decision`. Implements **increment**: regex `increment` deltas raise per-entity confidence and can escalate action. Applies action precedence `block > redact > flag > allow`. `OR` |
| 4.7 | `src/classifier/coverage.ts` | P0 | adapt | pending | Selective-coverage gate: per-question confidence thresholds; above threshold auto-decide, below threshold defer (to human / allow / block per config). Reports `deferred` in the audit record. `LY` |
| 4.8 | `src/classifier/calibration.ts` | P2 | new | pending | Temperature scaling per (question type, option count) to fix Laya's over-confidence (ECE 0.466→0.081). Table-driven, measured on local fixtures. `LY` |
| 4.9 | `src/classifier/heuristic.ts` | P1 | new | pending | Zero-dependency regex-only classifier used when the model is unavailable and `failMode:"open"`, and as the test oracle. |
| 4.10 | `src/classifier/tool-questions.ts` | P1 | new | pending | Tool-risk typed questions: `sensitive_path`, `credential_access`, `destructive_action`, `exfiltration` (`noul`). Reuses the model provider and coverage gate. `LY` |

## 5. Regex layer (`src/regex/`)

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 5.1 | `src/regex/builtins.ts` | P0 | adapt | pending | OpenRouter-parity presets with detection method + default action + label: `email`, `phone`, `ssn`, `credit-card`, `ip-address`, `secrets`, `person-name` (model), `address` (model). Regex presets ported from OpenRouter's published list. `OR` |
| 5.2 | `src/regex/secret-formats.ts` | P1 | adapt | pending | Provider-prefixed secret formats (`sk-or-v1-…`, `ghp_…`, `AKIA…`, `pypi-…`) → `[SECRET:<format-id>]`. `OR` |
| 5.3 | `src/regex/custom.ts` | P0 | new | pending | Compile user patterns with flags, per-pattern `action`, optional `label`, and **`increment`** (confidence delta / force-escalate). Dedupes + orders patterns. `OR` |
| 5.4 | `src/regex/safety.ts` | P0 | adapt | pending | Reject unsafe JS regexes exactly as OpenRouter does: no lookahead/lookbehind, no backreferences, no nested quantifiers (`(a+)+`), length ≤ 100 000 chars. Compile-time + ReDoS heuristics. `OR` |
| 5.5 | `src/regex/redact.ts` | P0 | new | pending | Replace matched spans with the configured label, preserving length-agnostic correctness; returns offsets so the audit log can record counts without storing raw text. `OR` |
| 5.6 | `src/regex/injection-patterns.ts` | P1 | adapt | pending | Ported OpenRouter prompt-injection pattern set (override, mode activation, extraction, role spoofing, control tokens) + evasion passes (typoglycemia, misspelled phrase, base64/hex, char-spaced). `OR` |

## 6. Policy & pipeline (`src/policy/`)

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 6.1 | `src/policy/actions.ts` | P0 | new | pending | `Action` union + precedence (`block > redact > flag > allow`), mode mapping (`observe`/`flag`/`redact`/`enforce`), OpenRouter "block wins over redact" semantics. `OR` |
| 6.2 | `src/policy/pipeline.ts` | P0 | new | pending | Ordered stages: normalize → regex builtins → custom regex (+increment) → model classify → coverage gate → fuse → action. Emits a `PipelineStage[]` trace like OpenRouter's `openrouter_metadata.pipeline`. `OR` |
| 6.3 | `src/policy/scopes.ts` | P2 | new | pending | Per-provider / per-model / per-agent overrides (intersection for allowlists, union for filters), mirroring OpenRouter's guardrail hierarchy. `OR` |
| 6.4 | `src/policy/allowlist.ts` | P2 | new | pending | Known-safe phrase allowlist that exempts exact strings from injection detection (OpenRouter parity). `OR` |
| 6.5 | `src/policy/tool-pipeline.ts` | P0 | new | pending | Tool-call variant of `pipeline.ts`: builds a state from `tool` + args, runs path/command policy + regex + model, applies increments and action precedence, returns a `ToolDecision`. `OR`/`LY` |
| 6.6 | `src/policy/paths.ts` | P0 | new | pending | Sensitive-path glob policy (`.env*`, `.aws/credentials`, `*.pem`/`*.key`, `id_rsa`, `.npmrc`, `.kube/config`, `*.tfvars`, `service-account*.json`, `.ssh/**`) matched against path args and `bash` read commands. Default `block`. `OR` |
| 6.7 | `src/policy/credential-commands.ts` | P0 | new | pending | Credential-store command policy: `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`, `gcloud secrets versions access`, `az keyvault secret show`, `vault read`/`kv get`, `kubectl get secret`, `printenv`/`env`/`set`. Default `block` (env dump `ask`). `OR` |

## 7. Telemetry & proof (`src/telemetry/`)

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 7.1 | `src/telemetry/logger.ts` | P0 | adapt | pending | Append-only JSONL audit log at `~/.local/share/opencode/bunker/audit.jsonl`, mode `0600`, rotate at 5 MB. Records **metadata + sha256 of the prompt, never raw text** unless `includeRaw:true`. `LY` |
| 7.2 | `src/telemetry/proof.ts` | P0 | new | pending | Builds the `AuditRecord` that constitutes the proof: `stage:"pre_provider"`, `hook`, `providerDispatched` (false on block), `decision`, `confidence`, `entities`, `regexIncrements`, `latencyMs`, `promptSha256`. |
| 7.3 | `src/telemetry/decision-card.ts` | P1 | adapt | pending | Terminal decision card rendered before execution (domain/decision/confidence/entities/increments/latency/sha). Mirrors `pi-laya-router`'s TUI card. |
| 7.4 | `src/telemetry/trace.ts` | P2 | new | pending | Optional OTLP/console span per decision for correlating with opencode session tracing. |

## 8. Tools & commands

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 8.1 | `src/tools/bunker-scan.ts` | P1 | new | pending | Custom opencode tool `bunker_scan`: run the pipeline on supplied text and return the decision + entities without sending anything to a provider. Useful for testing patterns. `OC` |
| 8.2 | `src/tools/bunker-regex.ts` | P2 | new | pending | Tool `bunker_regex` to validate a candidate regex (safety + sample matches + increment preview). `OR` |
| 8.3 | `src/commands/bunker.ts` | P1 | adapt | pending | `/bunker on\|off\|status\|prove` slash command: kill switch, status, and `prove` which prints a decision card + last audit line. Mirrors `pi-laya-router`'s `/router`. |
| 8.4 | `src/commands/bunker-regex.ts` | P2 | new | pending | `/bunker-regex add <pattern> <action> [--increment N] [--label L]` writes to the local config. `OR` |

## 9. Sidecar (optional Python Laya host)

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 9.1 | `sidecar/requirements.txt` | P2 | new | pending | `laya[serve]>=0.3.20`, pinned. `LY` |
| 9.2 | `sidecar/run_laya.sh` | P2 | new | pending | `LAYA_DEVICE=… LAYA_PRELOAD=1 LAYA_API_KEY=… laya-serve` launcher + health probe. `LY` |
| 9.3 | `sidecar/bunker_questions.py` | P2 | new | pending | Optional Python helper to A/B the typed question bank against `Router().predict` directly. `LY` |
| 9.4 | `sidecar/finetune_pii.py` | P3 | new | pending | Fine-tune a Laya checkpoint on domain PII labels (from the Laya fine-tune notebook) and export to ONNX for 4.4. `LY` |

## 10. Tests & fixtures

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 10.1 | `tests/regex-safety.test.ts` | P0 | new | pending | Rejects lookaround/backrefs/nested quantifiers; accepts OpenRouter's documented example patterns. `OR` |
| 10.2 | `tests/redaction.test.ts` | P0 | new | pending | `[EMAIL]`, `[PHONE]`, `[SSN]`, `[CREDIT_CARD]`, `[IP_ADDRESS]`, `[SECRET:id]`, custom `[REDACTED]`/label; block wins over redact. `OR` |
| 10.3 | `tests/classifier-decision.test.ts` | P0 | new | pending | Model + regex fusion; **increment** raises confidence and escalates action; coverage deferral. |
| 10.4 | `tests/pre-provider.test.ts` | **P0 — the proof test** | new | pending | With a mocked provider server, assert: (a) a `block` decision throws from `messages-transform`; (b) the provider server received **zero** requests; (c) an audit line with `providerDispatched:false` was written first. |
| 10.5 | `tests/hook-order.test.ts` | P0 | new | pending | Asserts `chat.message` runs before `experimental.chat.messages.transform` and that the transform re-scans prior turns. `OC` |
| 10.6 | `tests/tool-guard.test.ts` | P0 | new | pending | `tool.execute.before` blocks `.env` / `.aws/credentials` reads and `aws secretsmanager get-secret-value` / `ssm --with-decryption` **before execution**; destructive tools route to `permission.ask`. `OR` |
| 10.7 | `tests/fixtures/pii-corpus.jsonl` | P1 | new | pending | ≥50 examples per failure type + 50 normal (per Laya guardrail guidance) for threshold calibration and catch/miss reporting. `LY` |
| 10.8 | `tests/fixtures/audit.sample.jsonl` | P1 | new | pending | Golden audit records used by `docs/proof.md`. |
| 10.9 | `tests/config.test.ts` | P2 | new | pending | Config precedence + schema validation. |
| 10.10 | `tests/rollback.test.ts` | P0 | new | pending | Asserts `session.revert` is called with the offending `messageID` on `block` (and `session.abort` when a turn is running), and is **not** called on `redact`/`allow`. `OC` |
| 10.11 | `tests/sensitive-path.test.ts` | P0 | new | pending | Path glob policy matches every documented sensitive path and does not match ordinary files. `OR` |
| 10.12 | `tests/secret-output-redaction.test.ts` | P0 | new | pending | A secret in an **allowed** tool output is redacted by `tool.execute.after` before it enters context; audit records `outputRedacted:true`. `OR` |

## 11. Documentation

| # | File | Pri | Origin | Status | Responsibility / refs |
| --- | --- | --- | --- | --- | --- |
| 11.1 | `docs/architecture.md` | P1 | new | pending | Rendered architecture (from `ARCHITECTURE.md`) + hook ordering diagram. |
| 11.2 | `docs/openrouter-parity.md` | P1 | new | pending | Field-by-field mapping: OpenRouter guardrail feature → bunker implementation → test. `OR` |
| 11.3 | `docs/threat-model.md` | P2 | new | pending | What the bunker does/doesn't catch; evasion limits; false-positive handling. `OR`/`LY` |
| 11.4 | `docs/proof.md` | **P0 — the documentation proof** | new | pending | Captured audit lines + decision card + exact commands to reproduce, proving classification precedes provider dispatch. |
| 11.5 | `docs/config.md` | P2 | new | pending | Full config reference incl. regex-increment syntax. |

---

## Milestone assignment

| Milestone | Files | Gate |
| --- | --- | --- |
| **M0 — Scaffold + proof harness** | 1.1–1.6, 2.1–2.3, 3.1, 3.2, 3.8, 7.1, 7.2, 10.4, 10.10, 11.4 | `tests/pre-provider.test.ts` + `tests/rollback.test.ts` pass: blocked prompt → 0 provider requests, `session.revert(messageID)`, audit line first. |
| **M1 — Regex parity layer** | 5.1–5.6, 6.1, 6.2, 10.1, 10.2 | OpenRouter example patterns accepted; documented unsafe patterns rejected; redaction/block semantics match. |
| **M2 — Laya-style classifier** | 4.1, 4.2, 4.6, 4.7, 4.9, 10.3 | Typed `noul`/`choice`/`score` answers fused with regex; increment proven. |
| **M3 — Hooks enforcement** | 3.3, 3.7, 10.5, 8.1, 8.3 | Transform hook blocks and redacts; `/bunker prove` prints card + log line. |
| **M4 — Local model / sidecar** | 4.3, 4.4, 4.5, 9.1–9.3 | Works offline via ONNX or `laya-serve`; health-check + fail mode. |
| **M5 — Tool-call guardrails** | 3.5, 3.6, 3.9, 4.10, 6.5, 6.6, 6.7, 10.6, 10.11, 10.12 | `.env` / credentials / secret-manager calls blocked before execution; allowed tool output redacted before it enters context. |
| **M6 — Guardrails parity + hardening** | 3.4, 5.2, 6.3, 6.4, 8.2, 8.4, 10.8, 10.9, 11.2, 11.3, 11.5 | Per-scope rules, allowlist, calibration. |
| **M7 — Fine-tune + polish** | 4.8, 9.4, 1.7–1.9, 10.7 | Catch/miss rates measured on the fixture corpus; README evidence section. |

See [`TODO.md`](./TODO.md) for the durable task table and
[`EVIDENCE.md`](./EVIDENCE.md) for the proof contract.
