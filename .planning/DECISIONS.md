# `opencode-bunker` — Design Decisions

Each decision records the alternatives and the evidence behind the choice.

## D1 — Classify pre-provider via opencode hooks, not a proxy

**Decision.** Enforce inside opencode's plugin hooks (`chat.message` +
`experimental.chat.messages.transform`), not by interposing an HTTP proxy in
front of every provider.

**Why.** The plugin API is the documented extension point and sees the exact
message array opencode is about to send, for every provider, without
certificate/proxy setup. `experimental.chat.messages.transform` is the last
mutation point before dispatch, which is what makes the guarantee airtight.
A proxy would be provider-specific and would not know opencode's session
identity, which the audit log needs.

**Consequence.** We depend on `experimental.*` hooks; `tests/hook-order.test.ts`
pins the ordering so a future opencode change is caught.

## D2 — "Laya-style" typed decisions, not a generative guard model

**Decision.** Use Laya's typed-question interface (`choice`, `score`, `noul`)
with calibrated probabilities, and never generate text for the decision.

**Why.** Laya is a non-autoregressive System 1 model: one forward pass (~33 ms
on GPU), no generation, "nothing to parse and nothing to hallucinate"
(HF model card). That is exactly the profile a per-turn guardrail needs: it
runs on every action, works offline, and keeps prompt state local. A
generative guard model would add latency, cost, and a parsing failure mode.

**References.**
- <https://huggingface.co/convaiinnovations/laya>
- <https://auspia.ai/blog/laya-agent-guardrails>

## D3 — Regex first, model second, regex *increments* the model

**Decision.** Regexes are evaluated before the model, and their hits raise
("increment") the model's probability for the matching category; a regex can
also `force` its action.

**Why.** The user explicitly asked that "the plugin should allow users to
create regexes to increment the model classification." This hybrid matches
OpenRouter's design: deterministic regex presets handle known formats
(emails, SSNs, provider API keys) with negligible latency, while the model
handles contextual categories (person names, addresses, injection) that regex
cannot. Incrementing lets a high-precision user pattern rescue a
low-confidence model answer without a retrain.

**Consequence.** Every increment is recorded in the audit log so a decision is
reproducible from `(model probs, regex hits)`.

## D4 — Ask ambiguous `noul` questions as neutral two-option `choice`

**Decision.** In the shipped question bank, questions prone to label bias are
asked as `choice` with neutral keys (`A`/`B`) rather than `noul`.

**Why.** Laya's own "Honest Limits" documents that `noul` can follow its
`false:`/`true:` option labels instead of the state (issue #156), returning a
confident "no" for clearly positive input. The recommended workaround is a
two-option `choice` with neutral keys and the yes/no wording as descriptions.

**Consequence.** The question bank is slightly more verbose; accuracy on
guardrail holdout sets is not sacrificed to label bias.

## D5 — Local by default, with an explicit remote opt-in

**Decision.** The classifier endpoint must be loopback unless
`allowRemote:true`. No prompt content is sent to a third party by default.

**Why.** The prompt is the sensitive artifact. Laya's guardrail case is
specifically that agent state "often contains exactly the things you would not
want to transmit." A local classifier is also free per call, so we can check
every turn rather than sampling.

## D6 — Store sha256 + metadata, not raw prompt text

**Decision.** The audit log records `promptSha256` and byte length by default;
`includeRaw:false` unless explicitly enabled. Logs are `0600` and rotate.

**Why.** The log is the proof artifact, and it must not become the leak it is
meant to prevent. Hashing lets a user confirm *which* prompt was classified
without the log containing PII. This mirrors `pi-laya-router`, which logs only
metadata (timestamps, domain, effort, latency, tokens, fail-open reasons) and
never user text.

## D7 — Mirror OpenRouter Guardrails semantics

**Decision.** Adopt OpenRouter's vocabulary and rules: preset slugs, labels
(`[EMAIL]`, `[SSN]`, `[SECRET:format-id]`), `redact`/`block`/`flag` actions,
`block > redact > flag` precedence, filter union across scopes, JS-regex
safety rules (no lookaround/backrefs/nested quantifiers, ≤100k chars), and a
pipeline-stage trace.

**Why.** The user asked to use OpenRouter's Guardrails docs as a reference.
Reusing the semantics means the plugin's config is familiar, the security
properties are already reasoned through by OpenRouter, and parity can be
tested field-by-field (`docs/openrouter-parity.md`).

**Divergence.** OpenRouter's NLP presets use Presidio; we use the local Laya
model. Both are contextual/probabilistic and share the same limitation
(uncommon names/addresses may be missed), which we document.

## D8 — Selective coverage over forced decisions

**Decision.** Below a per-question confidence threshold, defer (default to a
human via `permission.ask`) rather than force a decision.

**Why.** Laya's guardrail write-up reports 0.75–0.76 accuracy at full coverage
rising to 0.931 at 50% selective coverage: "the model did not get better; it
got better at knowing when to answer." For a guardrail, being right about what
it decides matters more than coverage.

**Consequence.** `coverage.deferTo` is configurable; deferral rate is a
first-class metric in `logger.ts` and `/bunker status`.

## D9 — Two interception points for defense in depth

**Decision.** Classify at `chat.message` and re-enforce at
`experimental.chat.messages.transform`.

**Why.** `chat.message` is earliest and ideal for the decision card, but the
outgoing array can grow (history, tool output). The transform hook sees the
final bytes. Re-scanning there closes the gap and is where `block` throws.

## D10 — Fail-open default, fail-closed opt-in

**Decision.** `failMode:"open"` by default: a classifier outage falls back to
the regex heuristic and lets the turn proceed, logging `degraded:true`.
`failMode:"closed"` is available for high-security deployments.

**Why.** A guardrail that bricks the editor when a sidecar is down will be
disabled by users. `pi-laya-router` makes the same call ("fail-open
resilience… never block user work") and warns that a timeout tighter than the
cold-start cost makes every first turn fail. We set the timeout above the
warm-up cost (default 1200 ms vs ~310 ms cold / ~22 ms warm).

## D11 — Optional Python sidecar, with an in-process ONNX fallback

**Decision.** Prefer `laya-serve` (HTTP, Jev-compatible) when present, but ship
an `onnx-local` provider and a `heuristic` provider so the plugin works with
no Python.

**Why.** Laya is a Python package; opencode plugins run in Bun. A sidecar is
the least-effort path to the real model. But requiring Python/CUDA for a
guardrail is a hard install; ONNX Runtime in-process keeps the default usable
on CPU, and the heuristic keeps tests deterministic.

## D12 — Config precedence mirrors opencode conventions

**Decision.** `$BUNKER_CONFIG` → global `~/.config/opencode/bunker.config.json`
→ project `./bunker.config.json` → bundled defaults; deep-merge, project wins.

**Why.** Matches opencode's own scope model, so users already know where to put
project vs global rules.

## D13 — Enforce with the current opencode: redact the input + roll back the sent message

**Decision.** Use only the opencode API that exists today. There are exactly
two enforcement primitives, and the plugin uses both:

1. **Redact on the input** — rewrite the message content before it is
   dispatched: text in `output.parts` in `chat.message`, and the outgoing
   `output.messages` array in `experimental.chat.messages.transform`. The
   provider receives sanitized text.
2. **Roll back the sent message** — when the effective action is `block`, call
   `client.session.revert({ path: { id: sessionID }, body: { messageID } })`
   to remove the just-submitted message from the session, `client.session.abort`
   if a turn is running, then throw `BunkerBlockedError` so no provider request
   is made. The user can edit and re-send.

**Why (verified against `@opencode-ai/plugin@1.2.26` and
`@opencode-ai/sdk@1.2.26`).**

- `chat.message` receives `output.message` and `output.parts`, and fires when
  the message is received — the input is still mutable.
- `experimental.chat.messages.transform` receives the exact outgoing
  `output.messages` array immediately before dispatch.
- `session.revert` is a first-class rollback: `POST /session/{id}/revert` with
  body `{ messageID, partID? }` returns the updated `Session`, whose
  `revert` field records `{ messageID, partID, snapshot, diff }`. So the
  message is removed and file snapshots are restored. `session.unrevert`
  (`POST /session/{id}/unrevert`) reverses it, and `EventMessageRemoved`
  (`message.removed`) confirms removal is an expected bus event.

**Consequence.** No future-version capability probes, no reliance on a
typing-time hook. The message may exist for the instant between submit and the
hook, but on `block` it is reverted, and on `redact` the bytes that reach the
provider are already sanitized.

**Ordering.** `chat.message` handles the common case (redact the input, or
revert + throw on block). `experimental.chat.messages.transform` repeats the
check as a final gate for anything appended after `chat.message` (history,
tool output) and reverts the offending user message if it is still present.

**Limit we accept.** opencode exposes no editor/draft hook to plugins, so the
plugin cannot redact the textarea while the user types. That is a UX gap, not
a security gap: the input that reaches a provider is always sanitized.

## D14 — The same pipeline guards tool calls, with two enforcement points

**Decision.** Apply the identical classifier / regex / increment / coverage /
action pipeline to **tool calls**, but enforce at `tool.execute.before` (args)
and `tool.execute.after` (output), with `permission.ask` as the human gate.

**Why.** Tool results are injected into the model context, so they are an
input to the provider exactly like a user message. A `.env` read or
`aws secretsmanager get-secret-value` leaks a secret into context even though
no "prompt" was typed. The same logic must cover these.

**Enforcement mapping.**

- `tool.execute.before` — block by throwing (the tool never runs); redact
  secrets passed in args. This is the tool-call analogue of the chat block.
- `tool.execute.after` — redact `output.output` / `output.metadata` before the
  result is stored. A tool cannot be "un-run", so output redaction is the only
  option once it has executed; the audit record uses `decision:"redact"`, never
  `"block"`.
- `permission.ask` — force `ask` / `deny` for high-risk reads;
  `tools.askFallback` (default `block`) decides what happens if opencode does
  not invoke a permission check for that tool.

**No `session.revert` for tool calls.** Reverting a message does not undo a
side-effecting tool. Protection is "block before execution" plus "redact the
result". For mutating tools, `permission.ask` gates execution and opencode
snapshots remain available through `session.revert` if a file edit must be
rolled back.

**Defense in depth.** `experimental.chat.messages.transform` re-scans tool
results on the next provider call, so a missed `after` redaction is still
caught before the model sees it.

**Patterns.** Sensitive paths (`.env*`, `.aws/credentials`, keys,
`.kube/config`, `*.tfvars`, service-account JSON) and credential commands
(AWS Secrets Manager / SSM `--with-decryption`, GCP / Azure / Vault /
Kubernetes secret reads, `printenv`) are declarative, user-overridable policies
in `policy/paths.ts` and `policy/credential-commands.ts`.

## D15 — Trust the v5 model; deterministic harmful-request backstop

**Context.** `impacte/bunker-laya` v3's `injection_present` head over-fired on
short benign dev prompts ("fix the login bug" → 0.98), so `classify()` gated
model-only injection/jailbreak verdicts on lexical corroboration (default
`gateModelInjection: true`).

**Decision.** The v5 checkpoint (2026-10-09) fixed the root cause (pipeline
D15): short benign prompts now score ≤0.008 and both retrain gates pass. Set
`coverage.gateModelInjection` to **false** by default; keep the gate only as an
opt-in fallback for hosts pinned to an older checkpoint.

v5 also under-scored a few catastrophic `harmful_request` asks it had not seen
in that phrasing ("How do I make illegal drugs at home?" → 0.008). Add
`HARMFUL_PATTERNS` (drugs / explosives / malware / phishing / unauthorized
access) that always block, mirroring `INJECTION_PATTERNS`; the heuristic harmful
probe now reuses them, which also removes a crude `ransomware` keyword match
that flagged benign discussion.

**Consequence.** 146 tests pass. The deterministic layers are a backstop, not a
substitute — a v6 data fix (more harmful positives / rebalance vs the enlarged
PII corpus) is recommended so the model itself recovers that headline.
