# `opencode-bunker` — Planning

> **Goal.** An [opencode](https://opencode.ai) plugin that runs a **local,
> Laya-style decision model** over every prompt **before** it is sent to any
> model provider, classifies **PII** (and prompt-injection / sensitivity),
> lets users **add regexes that increment the model's classification**, applies
> the same logic to **tool calls** (`.env` reads, credential-store commands,
> secret-bearing tool output), and **proves** the pre-provider guarantee in
> both its documentation and its structured logs.

This folder is the authoritative plan. `FILEMAP.md` maps every implementation
file that still has to be written (all currently `pending`). The rest of the
folder specifies *what* those files must do and *how the proof works*.

## Index

| File | Purpose |
| --- | --- |
| [`FILEMAP.md`](./FILEMAP.md) | **Authoritative map of every missing implementation file** (status, priority, origin, responsibility). Start here. |
| [`SPEC.md`](./SPEC.md) | Functional specification: pre-provider contract, PII taxonomy, regex-increment rules, config schema. |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Component diagram, opencode hook ordering, decision pipeline, Laya integration. |
| [`DECISIONS.md`](./DECISIONS.md) | Design decisions with rationale, grounded in Laya + OpenRouter Guardrails. |
| [`EVIDENCE.md`](./EVIDENCE.md) | **How the plugin proves it works**: audit-log schema, captured example records, decision card, reproduction commands. |
| [`TODO.md`](./TODO.md) | Milestones, acceptance gates, durable task mirror. |

## Status

**Phase: mapping / pre-implementation.** No source files exist yet in the
project root (only this `.planning/` folder). Every implementation file is
`pending` and tracked in `FILEMAP.md`.

## The one-sentence contract

> *No user prompt — and no tool result — reaches a provider until a local
> classifier has produced a typed decision — `allow`, `flag`, `redact`, or
> `block` — and that decision, its confidence, and the exact hook that enforced
> it are written to an audit log **before** the provider request is dispatched.*

## Primary references

- **Repository**: <https://github.com/impacte-tech/opencode-bunker>
  (git remote `origin`).
- **Laya — local System 1 decision model** (`convaiinnovations/laya`, Apache-2.0):
  <https://huggingface.co/convaiinnovations/laya> · <https://github.com/NandhaKishorM/laya>
  - Non-autoregressive; typed questions (`choice`, `score`, `noul`); calibrated
    probabilities; ~33 ms single forward pass; never generates text.
  - Self-hostable Jev-compatible server: `laya-serve`, `POST /v1/systemone`.
  - Guardrail usage pattern (selective coverage): <https://auspia.ai/blog/laya-agent-guardrails>
- **OpenRouter Guardrails** (parity target for policy semantics):
  - Overview: <https://openrouter.ai/docs/guides/features/guardrails>
  - Sensitive Info / PII: <https://openrouter.ai/docs/guides/features/guardrails/sensitive-info>
  - Prompt injection: <https://openrouter.ai/docs/guides/features/guardrails/prompt-injection>
- **opencode plugin API** (`@opencode-ai/plugin@1.2.26`): hooks are typed in
  `node_modules/@opencode-ai/plugin/dist/index.d.ts`. Relevant hooks:
  `chat.message`, `chat.params`, `chat.headers`,
  `experimental.chat.messages.transform`, `tool.execute.before`,
  `permission.ask`.

## Non-goals

- We do **not** scan model responses. The bunker is input-side only, matching
  OpenRouter's Sensitive Info Guardrail.
- We do **not** require a cloud call. Classification is local by default and
  must work offline; a remote classifier endpoint is opt-in.
- We do **not** rewrite the user's prompt in the transcript. Redaction happens
  on the copy of the messages that is about to be dispatched (and is recorded
  as a redaction event), never on the user's stored message.
