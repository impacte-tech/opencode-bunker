# opencode-bunker

A local, Laya-style guardrail plugin for [opencode](https://opencode.ai) that
classifies and redacts **prompts and tool calls before they reach a model
provider** — PII, secrets, prompt injection, sensitive file reads, and
credential-store commands.

**Status: planning / pre-implementation.** The authoritative plan — including
the missing-files map, specification, architecture, decisions, and a runnable
proof harness that emits a real audit log — lives in
[`.planning/`](./.planning/README.md).

| Artifact | Link |
| --- | --- |
| Missing implementation files | [`.planning/FILEMAP.md`](./.planning/FILEMAP.md) |
| Specification | [`.planning/SPEC.md`](./.planning/SPEC.md) |
| Architecture | [`.planning/ARCHITECTURE.md`](./.planning/ARCHITECTURE.md) |
| Decisions | [`.planning/DECISIONS.md`](./.planning/DECISIONS.md) |
| Evidence & proof | [`.planning/EVIDENCE.md`](./.planning/EVIDENCE.md) |
| Task state / milestones | [`.planning/TODO.md`](./.planning/TODO.md) |

## Reproduce the proof

```bash
node .planning/proof/pre-provider-proof.mjs
cat .planning/proof/audit.jsonl
```

The harness demonstrates that a blocked prompt dispatches nothing, a blocked
tool call never executes, and secrets in allowed tool output are redacted
before they enter context.

## Repository

<https://github.com/impacte-tech/opencode-bunker>
