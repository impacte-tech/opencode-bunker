# opencode-bunker

A local, Laya-style guardrail plugin for [opencode](https://opencode.ai) that
classifies and redacts **prompts and tool calls before they reach a model
provider** — PII, secrets, prompt injection, sensitive file reads, and
credential-store commands.

> **Status: usable now (M0-lite).** A working plugin is implemented in
> [`src/core.ts`](./src/core.ts) and live-verified against opencode 1.18.34:
> a prompt-injection prompt was blocked **before any provider call**, with the
> decision written to the audit log. The full target architecture and file map
> are in [`.planning/`](./.planning/README.md).

## What works today

| Area | Behavior |
| --- | --- |
| Chat prompts | `chat.message` classifies + redacts; `block` calls `session.revert` + `session.abort` then throws |
| Outgoing messages | `experimental.chat.messages.transform` re-scans the exact bytes and blocks/redacts |
| PII (regex) | email, phone, SSN, credit card, IP, provider secrets → `[EMAIL]`, `[SSN]`, `[SECRET]`, … |
| PII (contextual) | person-name / address via the local heuristic provider (Laya-style typed questions) |
| Injection | prompt-injection phrases → `block` |
| Custom regex + increment | user regexes raise the model's confidence and can force an action (OpenRouter-style) |
| Tool calls | `tool.execute.before` blocks `.env`, `.aws/credentials`, keys, `.kube/config`, `*.tfvars`, … and `aws secretsmanager get-secret-value`, `aws ssm … --with-decryption`, `gcloud secrets`, `az keyvault`, `vault`, `kubectl get secret` |
| Tool output | `tool.execute.after` redacts secrets/PII before the result enters context |
| Audit | JSONL at `~/.local/share/opencode/bunker/audit.jsonl` (metadata + sha256, never raw text by default) |

Not yet built (tracked in [`.planning/FILEMAP.md`](./.planning/FILEMAP.md)):
the real Laya `laya-http` / `onnx-local` providers, calibration, per-scope
rules, allowlist, the `bunker_scan` tool and `/bunker` command.

## Use it

The plugin is **already enabled globally** on this machine in **`flag`
(observe) mode** — it logs decisions but never blocks or redacts. To change
behavior, edit `~/.config/opencode/bunker.config.json`:

```jsonc
{
  "mode": "flag"      // observe | flag | redact | enforce
}
```

- `flag` / `observe` — audit only, never blocks or redacts (current default).
- `redact` — redacts matched content; downgrades `block` to `redact`.
- `enforce` — blocks and redacts as decided.

Restart opencode after editing config (config is loaded at startup).

To enable it in another project only, add to that project's `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["file:///path/to/opencode-bunker/src/index.ts"]
}
```

To disable globally, remove the `"plugin": [...]` entry from
`~/.config/opencode/opencode.jsonc`.

## Configure

Full reference: [`.planning/SPEC.md`](./.planning/SPEC.md) §5. Precedence:
`$BUNKER_CONFIG` → `~/.config/opencode/bunker.config.json` → `./bunker.config.json`
→ defaults. See [`bunker.config.json`](./bunker.config.json) for the shipped
defaults, including custom patterns:

```jsonc
"custom": [
  { "pattern": "PROJ-\\d{4,6}", "action": "redact", "label": "internal-project-code", "increment": 0.25, "target": "confidential" },
  { "pattern": "AKIA[0-9A-Z]{16}", "action": "block", "label": "aws-access-key", "increment": 0.5, "target": "pii_secret", "force": true }
]
```

Regexes are validated (no lookaround, backreferences, or nested quantifiers —
OpenRouter parity). Invalid patterns are skipped with the rest still applied.

## Test

```bash
bun test                                   # 10 unit + hook tests
node .planning/proof/pre-provider-proof.mjs # standalone proof harness + audit log
```

## Contributor note

opencode treats **every named export** of a plugin module as a plugin factory.
That is why `src/index.ts` exports only `default` and all helpers live in
`src/core.ts`. Do not add named exports to `src/index.ts`.

## Repository

<https://github.com/impacte-tech/opencode-bunker> · MIT (plugin); Laya is
Apache-2.0.
