# `opencode-bunker` — TODO / Task State

> Native `todowrite` is the live tracker. This file is the durable mirror so a
> fresh session can resume without re-deriving context.

## Goal

An opencode plugin that runs a local, Laya-style typed decision model over
every prompt **before** provider dispatch, classifies PII (+ injection /
sensitivity), lets users add regexes that **increment** the classification, and
proves the pre-provider guarantee in documentation and structured logs.

## Status legend

`pending` · `in_progress` · `completed` · `blocked` · `cancelled`

## Current implementation (M0-lite)

Working plugin in [`src/core.ts`](../src/core.ts) (entry
[`src/index.ts`](../src/index.ts), default export only). Implements chat
redaction/block + rollback, tool path/command guards, tool-output redaction,
regex presets + custom increments, heuristic Laya-style provider, coverage, and
the audit log. Verified: `bun test` → 10 pass; live opencode run → prompt
blocked before dispatch with an audit record. Enabled globally in `flag`
(observe) mode via `~/.config/opencode/bunker.config.json`.

## Task table

| # | Task | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Research Laya typed-decision model + self-host server | completed | `README.md` refs; HF model card |
| 2 | Research OpenRouter Guardrails (sensitive info, injection, custom filters) | completed | `SPEC.md`, `ARCHITECTURE.md` §6 |
| 3 | Verify current opencode plugin hooks + SDK rollback API | completed | `DECISIONS.md` D13; `session.revert` |
| 4 | Write authoritative missing-files map | completed | `FILEMAP.md` |
| 5 | Write spec, architecture, decisions | completed | `SPEC.md`, `ARCHITECTURE.md`, `DECISIONS.md` |
| 6 | Build runnable pre-provider proof harness + real audit log (chat + tool surfaces) | completed | `proof/pre-provider-proof.mjs`, `proof/audit.jsonl` |
| 7 | Document the proof | completed | `EVIDENCE.md` |
| 8 | **M0 — Scaffold + proof harness** | in_progress | M0-lite built in `src/core.ts` + default-only `src/index.ts`; `bun test` 10 pass; live `opencode run` blocked a prompt-injection prompt with `BunkerBlockedError` and 0 provider calls; full file split + `tests/pre-provider.test.ts` still pending |
| 9 | **M1 — Regex parity layer** | pending | `FILEMAP.md` M1 |
| 10 | **M2 — Laya-style classifier** | pending | `FILEMAP.md` M2 |
| 11 | **M3 — Hooks enforcement (redact input + rollback)** | pending | `FILEMAP.md` M3 |
| 12 | **M4 — Local model / sidecar** | pending | `FILEMAP.md` M4 |
| 13 | **M5 — Tool-call guardrails** | pending | `FILEMAP.md` M5 |
| 14 | **M6 — Guardrails parity + hardening** | pending | `FILEMAP.md` M6 |
| 15 | **M7 — Fine-tune + polish** | pending | `FILEMAP.md` M7 |

## Acceptance gates

| Gate | Pass condition |
| --- | --- |
| G1 (M0) | `tests/pre-provider.test.ts`: block → 0 provider requests + audit flushed first |
| G2 (M1) | OpenRouter's documented custom patterns accepted; unsafe patterns rejected; labels + block-wins-over-redact match |
| G3 (M2) | typed `noul`/`choice`/`score` answers fused with regex; a regex `increment` measurably raises confidence and escalates action |
| G4 (M3) | `chat.message` redacts input; `block` calls `session.revert(messageID)` + abort then throws; `/bunker prove` prints card + log line |
| G5 (M4) | works offline via `onnx-local` or `laya-serve`; health check + fail mode honored |
| G6 (M5) | `.env` / `.aws/credentials` / secret-manager tool calls blocked before execution; allowed tool output redacted before context |
| G7 (M6) | per-scope rules, allowlist, calibration pass |
| G8 (M7) | catch/miss rates measured on `tests/fixtures/pii-corpus.jsonl` |

## Blockers / notes

- **Environment PII scrubber.** This host redacts literal emails / phones /
  IPs / secrets in tool I/O. The proof harness therefore builds its test values
  at runtime from fragments, and the audit log stores only `promptSha256`.
  Any future fixtures must avoid hardcoding real PII.
- **opencode version pinned.** `@opencode-ai/plugin@1.2.26` /
  `@opencode-ai/sdk@1.2.26`. Relevant hooks: `chat.message`,
  `experimental.chat.messages.transform`, `chat.params`, `chat.headers`,
  `tool.execute.before`, `permission.ask`. Rollback:
  `client.session.revert({ path:{id}, body:{ messageID, partID? } })`.
- **No draft hook.** opencode does not expose the editor buffer to plugins;
  redaction is post-submit / pre-provider. Do not add future-version capability
  probes — use the two current primitives (`DECISIONS.md` D13).
- **Laya is Python.** Plugins run in Bun; prefer the `laya-serve` sidecar and
  keep the in-process `onnx-local` / `heuristic` fallbacks.
- **Tool calls have no rollback.** `tool.execute.before` blocks by throwing
  (tool never runs); `tool.execute.after` redacts output because a tool cannot
  be un-run. `permission.ask` is the human gate. See `DECISIONS.md` D14 and
  `SPEC.md` §7.
- **2026-10-08 hardening round 2.** (1) `messages.transform` no longer throws
  on a `block` decision — the message is already committed, so throwing
  bricked every future dispatch of the session (observed live: 4 consecutive
  full-history blocks). It now downgrades block → redact on the outgoing
  payload (`downgradedFrom: "block"` in the audit record); enforcement with
  rollback stays at `chat.message`. (2) SSN pattern widened to bare/space
  forms (`(?<!\d)\d{3}[-\s]?\d{2}[-\s]?\d{4}(?!\d)`), phone to bare 10-digit;
  credit-card no longer matches bare 13-digit runs (epoch-ms timestamps) —
  bare digits must be exactly 16, separated formats 13–16. (3) The generic
  `KEY=` output pattern requires a digit / quoted value / `[REDACTED]`
  placeholder and excludes code punctuation, so TS declarations in tool
  output are no longer redacted in flight (was misread twice as "file
  corruption"). Verified: fast suites 43/43 + 15-case replay harness.
  `test/jailbreak.test.ts` needs the cached ONNX model (~minutes) and a
  `logs/` dir.
- **Model calibration + mitigation (2026-10-08 → 2026-10-10).** The v3
  `injection_present` head returned ~0.98 on many short benign dev prompts
  ("fix the login bug", "hi") — caused by ~1,700 ultra-short injection-*positive*
  rows (mostly Mosscap blanket-label-1 noise). v3 shipped a mitigation:
  `classify()` gates model-only injection/jailbreak verdicts on
  `INJECTION_LEXICON` / length. `opencode-bunker-laya` v5 fixed the short
  dev-prompt flood and the PII formats; v6 fixed the v5 harmful-recall and
  bare-secret regressions (gates pass). **But the gate stays on by default**:
  the injection head still over-fires on benign account/UI text ("The password
  field is required." → 0.98) even with those exact strings trained as
  negatives. Measured: the gate downgrades those to `flag` with **zero** real
  attacks downgraded (65/65 still block), so `coverage.gateModelInjection`
  remains `true`. Other findings: `dtype: "q8"` is unusable — dynamic INT8
  collapses the decision head (max|Δ|=0.99); **fp16 is lossless** (max|Δ|=0.0000,
  846 MB) and is the artifact for 8 GB hosts; on 8 GB hosts fp32 alongside an
  active TUI can be jetsam-killed at ~1.26 GB RSS; `audit.jsonl` records
  `provider` so fail-open fallbacks are distinguishable. `HARMFUL_PATTERNS`
  remains as a deterministic backstop for the catastrophic categories.

## Resume instructions

1. Read `README.md`, then `FILEMAP.md` for the file list and milestones.
2. Read `SPEC.md` §1–§3 for the contract, PII taxonomy, and increment rules;
   §7 for tool-call guardrails.
3. Read `ARCHITECTURE.md` §2 for the exact hook ordering.
4. Read `EVIDENCE.md` and run `node .planning/proof/pre-provider-proof.mjs`.
5. Implement milestone M0 first; do not proceed past a red gate.
6. Update this table and the live `todowrite` list as work lands.
