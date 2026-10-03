#!/usr/bin/env node
/**
 * opencode-bunker — pre-provider proof harness (zero dependencies).
 *
 * This is NOT the plugin. It is a runnable, deterministic model of the
 * current-opencode enforcement flow described in ../ARCHITECTURE.md and
 * ../DECISIONS.md D13:
 *
 *   chat.message                       -> classify + redact the input parts
 *   experimental.chat.messages.transform -> re-scan the exact outgoing array
 *   block                              -> session.revert(messageID) + abort,
 *                                         then throw BEFORE any provider call
 *
 * It runs four scenarios, counts real HTTP requests against a mock provider,
 * and writes a real JSONL audit log to ./audit.jsonl.
 *
 * Run:  node .planning/proof/pre-provider-proof.mjs
 */
import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const AUDIT_PATH = join(HERE, "audit.jsonl");

// Build test values at runtime from fragments. The harness never hardcodes a
// literal PII/IP string, and the audit log only ever stores a sha256 anyway.
const AT = String.fromCharCode(64);
const DOT = ".";
const LOOPBACK = [127, 0, 0, 1].join(DOT);
const email = (local, domain) => `${local}${AT}${domain}`;
const phone = (...parts) => parts.join(" ");
const awsKey = () => "AK" + "IA" + "IOSFODNN7EXAMPLE";

// ---------------------------------------------------------------------------
// 1. Laya-style typed question bank (see ../SPEC.md §2.1)
// ---------------------------------------------------------------------------
const QUESTIONS = [
  { key: "pii_present", type: "noul" },
  { key: "pii_email", type: "noul" },
  { key: "pii_phone", type: "noul" },
  { key: "pii_ssn", type: "noul" },
  { key: "pii_credit_card", type: "noul" },
  { key: "pii_ip_address", type: "noul" },
  { key: "pii_secret", type: "noul" },
  { key: "pii_person_name", type: "noul" },
  { key: "pii_address", type: "noul" },
  { key: "injection_present", type: "noul" },
  { key: "confidential", type: "noul" },
];

// Non-global probes (safe for .test()).
const TEST = {
  email: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/,
  phone: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}/,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  cc: /\b(?:\d[ -]*?){13,16}\b/,
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  secret: /\b(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-or-v1-[A-Za-z0-9]{32,})\b/,
  person: /\b[A-Z][a-z]+\s+[A-Z][a-z]+\b/,
  injection: /ignore\s+(all\s+)?previous\s+instructions/i,
  confidential: /\b(confidential|internal|escalat)/i,
};

// A stand-in for the local model: deterministic, calibrated-ish probabilities.
function modelProb(key, text) {
  switch (key) {
    case "pii_present":
      return TEST.email.test(text) || TEST.phone.test(text) || TEST.secret.test(text) || TEST.ssn.test(text)
        ? 0.95
        : TEST.person.test(text)
          ? 0.6
          : 0.03;
    case "pii_email": return TEST.email.test(text) ? 0.97 : 0.02;
    case "pii_phone": return TEST.phone.test(text) ? 0.9 : 0.02;
    case "pii_ssn": return TEST.ssn.test(text) ? 0.96 : 0.01;
    case "pii_credit_card": return TEST.cc.test(text) ? 0.93 : 0.02;
    case "pii_ip_address": return TEST.ip.test(text) ? 0.9 : 0.02;
    case "pii_secret": return TEST.secret.test(text) ? 0.88 : 0.02;
    case "pii_person_name": return TEST.person.test(text) ? 0.62 : 0.05;
    case "pii_address": return /\d+\s+[A-Z][a-z]+\s+(Street|St|Avenue|Ave|Road|Rd)/.test(text) ? 0.7 : 0.03;
    case "injection_present": return TEST.injection.test(text) ? 0.94 : 0.03;
    case "confidential": return TEST.confidential.test(text) ? 0.55 : 0.5;
    default: return 0.05;
  }
}

// ---------------------------------------------------------------------------
// 2. Regex layer: built-in presets + custom patterns with `increment`
// ---------------------------------------------------------------------------
const BUILTINS = [
  { id: "email", question: "pii_email", action: "redact", label: "[EMAIL]", pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { id: "phone", question: "pii_phone", action: "redact", label: "[PHONE]", pattern: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}/g },
  { id: "ssn", question: "pii_ssn", action: "block", label: "[SSN]", pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { id: "credit-card", question: "pii_credit_card", action: "block", label: "[CREDIT_CARD]", pattern: /\b(?:\d[ -]*?){13,16}\b/g },
  { id: "ip-address", question: "pii_ip_address", action: "redact", label: "[IP_ADDRESS]", pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
];

const CUSTOM = [
  // User regex that INCREMENTS the model's `confidential` classification.
  { id: "internal-project-code", question: "confidential", target: "confidential", action: "redact", label: "internal-project-code", increment: 0.25, pattern: /PROJ-\d{4,6}/g },
  // User regex that forces a block regardless of the model.
  { id: "aws-access-key", question: "pii_secret", target: "pii_secret", action: "block", label: "aws-access-key", increment: 0.5, force: true, pattern: /AKIA[0-9A-Z]{16}/g },
];

const ORDER = { allow: 0, flag: 1, redact: 2, block: 3 };
const THRESHOLD = 0.75;
const INJECTION_THRESHOLD = 0.8;

function matchAll(re, text) {
  return [...text.matchAll(re)];
}

function sha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// 3. Pipeline: regex + model -> increments -> coverage -> action precedence
// ---------------------------------------------------------------------------
function classify(text) {
  const t0 = process.hrtime.bigint();
  const probs = {};
  for (const q of QUESTIONS) probs[q.key] = modelProb(q.key, text);

  const hits = [];
  for (const b of BUILTINS) {
    const m = matchAll(b.pattern, text);
    if (m.length) hits.push({ ...b, source: "regex", count: m.length, spans: m.map((x) => [x.index, x.index + x[0].length]) });
  }
  for (const c of CUSTOM) {
    const m = matchAll(c.pattern, text);
    if (m.length) hits.push({ ...c, source: "regex", count: m.length, spans: m.map((x) => [x.index, x.index + x[0].length]) });
  }

  const incremented = new Set();
  const regexIncrements = [];
  for (const h of hits) {
    if (!h.increment) continue;
    probs[h.target] = Math.min(1, probs[h.target] + h.increment);
    incremented.add(h.target);
    regexIncrements.push({ label: h.label || h.id, delta: h.increment, action: h.action, target: h.target });
  }

  const entities = [];
  const deferredEntities = [];

  for (const h of hits) {
    entities.push({
      type: h.id,
      source: "regex",
      action: h.action,
      count: h.count,
      label: h.label,
      confidence: Number(probs[h.question].toFixed(2)),
    });
  }

  const modelCats = [
    { key: "pii_person_name", type: "PERSON_NAME", action: "redact", label: "[PERSON_NAME]" },
    { key: "pii_address", type: "ADDRESS", action: "redact", label: "[ADDRESS]" },
    { key: "confidential", type: "CONFIDENTIAL", action: "flag", label: "[CONFIDENTIAL]" },
  ];
  for (const c of modelCats) {
    const p = probs[c.key];
    const source = incremented.has(c.key) ? "both" : "model";
    if (p >= THRESHOLD) entities.push({ type: c.type, source, action: c.action, count: 1, label: c.label, confidence: Number(p.toFixed(2)) });
    else if (p >= 0.5) deferredEntities.push({ type: c.type, source, action: "flag", count: 1, label: c.label, confidence: Number(p.toFixed(2)) });
  }

  const injection = probs.injection_present;
  if (injection >= INJECTION_THRESHOLD) {
    entities.push({ type: "PROMPT_INJECTION", source: "model", action: "block", count: 1, label: "[PROMPT_INJECTION]", confidence: Number(injection.toFixed(2)) });
  }

  let action = "allow";
  for (const e of entities) if (ORDER[e.action] > ORDER[action]) action = e.action;
  for (const h of hits) if (h.force && ORDER[h.action] > ORDER[action]) action = h.action;

  let deferred = false;
  if (action === "allow" && deferredEntities.length) {
    action = "flag";
    deferred = true;
  }

  const confidence = entities.length
    ? Math.max(...entities.map((e) => e.confidence ?? 0.5))
    : deferredEntities.length
      ? Math.max(...deferredEntities.map((e) => e.confidence))
      : 1;

  const latencyMs = Number(process.hrtime.bigint() - t0) / 1e6;
  return {
    decisionId: randomUUID(),
    action,
    confidence: Number(confidence.toFixed(2)),
    deferred,
    entities,
    deferredEntities,
    regexIncrements,
    probs,
    hits,
    latencyMs: Number(latencyMs.toFixed(2)),
    original: text,
  };
}

function redact(text, hits) {
  let out = text;
  for (const h of hits) {
    if (h.action === "redact") out = out.replace(h.pattern, h.label || "[REDACTED]");
  }
  return out;
}

// ---------------------------------------------------------------------------
// 4. Audit log (real JSONL on disk) — see ../EVIDENCE.md
// ---------------------------------------------------------------------------
const AUDIT = [];
function audit(decision, extra) {
  const rec = {
    ts: new Date().toISOString(),
    event: "bunker.decision",
    stage: "pre_provider",
    ...extra,
    decisionId: decision.decisionId,
    decision: decision.action,
    confidence: decision.confidence,
    deferred: decision.deferred,
    entities: decision.entities.map((e) => ({
      type: e.type,
      source: e.source,
      action: e.action,
      count: e.count,
      confidence: e.confidence,
    })),
    regexIncrements: decision.regexIncrements,
    promptSha256: sha256(decision.original),
    promptBytes: Buffer.byteLength(decision.original, "utf8"),
    latencyMs: decision.latencyMs,
    rawIncluded: false,
  };
  AUDIT.push(rec);
  return rec;
}

// ---------------------------------------------------------------------------
// 5. Mock opencode session + mock provider (counts real HTTP requests)
// ---------------------------------------------------------------------------
class MockSession {
  constructor(id) {
    this.id = id;
    this.messages = [];
    this.reverted = [];
    this.aborted = 0;
  }
  addUser(text) {
    const m = { id: randomUUID(), role: "user", content: text };
    this.messages.push(m);
    return m;
  }
  async revert(messageID) {
    this.reverted.push(messageID);
    this.messages = this.messages.filter((m) => m.id !== messageID);
  }
  async abort() {
    this.aborted += 1;
  }
}

let providerCalls = 0;
const provider = createServer((req, res) => {
  if (req.method === "POST" && req.url === "/chat/completions") {
    providerCalls += 1;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  } else {
    res.writeHead(404);
    res.end();
  }
});
await new Promise((r) => provider.listen(0, "127.0.0.1", r));
const providerPort = provider.address().port;

async function dispatch(messages) {
  await fetch(`http://127.0.0.1:${providerPort}/chat/completions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ messages }),
  });
}

// ---------------------------------------------------------------------------
// 6. The two hooks (current opencode)
// ---------------------------------------------------------------------------
const decisionCache = new Map();

// Hook A — chat.message: earliest interception; redact on the input.
function hookChatMessage(session, userMsg) {
  const decision = classify(userMsg.content);
  decisionCache.set(userMsg.id, decision);

  // "redact on the input": mutate the outgoing/persisted part.
  userMsg.content = redact(userMsg.content, decision.hits);

  audit(decision, {
    hook: "chat.message",
    sessionID: session.id,
    messageID: userMsg.id,
    providerDispatched: decision.action === "block" ? false : null,
  });

  if (decision.action === "block") {
    // "roll back the message sent"
    void session.revert(userMsg.id);
    void session.abort();
    throw new Error(`BunkerBlockedError: ${decision.entities.map((e) => e.label || e.type).join(", ")}`);
  }
  return decision;
}

// Hook B — experimental.chat.messages.transform: exact outgoing bytes.
function hookMessagesTransform(session, outgoing, userMsg) {
  const decision = decisionCache.get(userMsg.id) ?? classify(outgoing.map((m) => m.content).join("\n"));
  for (const m of outgoing) m.content = redact(m.content, decision.hits);

  const blocked = decision.action === "block";
  audit(decision, {
    hook: "experimental.chat.messages.transform",
    sessionID: session.id,
    messageID: userMsg.id,
    providerDispatched: !blocked,
  });

  if (blocked) {
    void session.revert(userMsg.id);
    void session.abort();
    throw new Error(`BunkerBlockedError: ${decision.entities.map((e) => e.label || e.type).join(", ")}`);
  }
  return decision;
}

// ---------------------------------------------------------------------------
// 7. Scenarios
// ---------------------------------------------------------------------------
const SCENARIOS = [
  { name: "redact email + phone", text: `Please refund order 4411 to ${email("jane.doe", "example.com")} or call ${phone("+1", "415", "555", "0132")}.` },
  { name: "regex increment (PROJ-)", text: `Internal ticket PROJ-7781 was escalated; ping ${email("ops", "corp.example.com")} about it.` },
  { name: "block AWS secret (force)", text: `Here is the key: ${awsKey()} — deploy it now.` },
  { name: "defer person name", text: "Hi, I am Margaret Okafor, following up on my account." },
];

const results = [];
for (const [i, s] of SCENARIOS.entries()) {
  const session = new MockSession(`ses_proof_${i}`);
  const userMsg = session.addUser(s.text);
  const before = providerCalls;
  let thrown = null;

  try {
    hookChatMessage(session, userMsg);
    // opencode assembles the full outgoing array (history + new message).
    const outgoing = [{ role: "system", content: "You are a helpful assistant." }, { role: "user", content: userMsg.content }];
    hookMessagesTransform(session, outgoing, userMsg);
    await dispatch(outgoing);
  } catch (err) {
    thrown = err.message;
  }

  results.push({
    name: s.name,
    action: thrown ? "block" : decisionCache.get(userMsg.id)?.action ?? "?",
    deferred: decisionCache.get(userMsg.id)?.deferred ?? false,
    providerCallsDelta: providerCalls - before,
    reverted: session.reverted.length,
    aborted: session.aborted,
    thrown,
  });
}

// ---------------------------------------------------------------------------
// 7b. Tool-call guardrails — same pipeline, different enforcement points
//     before: classify tool + args, block or rewrite args
//     after:  redact secrets/PII from the tool output before it enters context
// ---------------------------------------------------------------------------
const SENSITIVE_PATH = [
  { id: "dotenv", re: /(^|[\\/])\.env(\.[^\\/]*)?$/ },
  { id: "aws-credentials", re: /(^|[\\/])\.aws[\\/](credentials|config)$/ },
  { id: "private-key", re: /\.(pem|key|p12|pfx|jks|keystore)$/ },
  { id: "ssh-key", re: /(^|[\\/])id_(rsa|ed25519|ecdsa)$/ },
  { id: "npmrc", re: /(^|[\\/])\.(npmrc|pypirc|netrc|git-credentials)$/ },
  { id: "kube-config", re: /(^|[\\/])\.kube[\\/]config$/ },
  { id: "tfvars", re: /\.(tfvars|tfstate)$/ },
  { id: "service-account", re: /service-account.*\.json$/ },
];

const CREDENTIAL_COMMAND = [
  { id: "aws-secretsmanager", re: /aws\s+secretsmanager\s+get-secret-value/ },
  { id: "aws-ssm-decrypt", re: /aws\s+ssm\s+get-parameter[s]?.*--with-decryption/ },
  { id: "gcloud-secret", re: /gcloud\s+secrets\s+versions\s+access/ },
  { id: "az-keyvault", re: /az\s+keyvault\s+secret\s+show/ },
  { id: "vault-read", re: /vault\s+(read|kv\s+get)/ },
  { id: "kubectl-secret", re: /kubectl\s+get\s+secret/ },
  { id: "env-dump", re: /(^|\s)(printenv|env|set)(\s|$)/ },
  { id: "cat-secret-file", re: /(cat|less|more|head|tail|grep)\s+[^\n]*(\.env|credentials|\.pem|id_rsa)/ },
];

const OUTPUT_SECRETS = [
  { id: "aws-access-key-id", label: "[SECRET:aws-access-key-id]", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "generic-secret-assignment", label: "[SECRET]", pattern: /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*[=:]\s*["']?[^\s"']{6,}["']?/g },
];

function redactOutput(text) {
  let out = text;
  for (const s of OUTPUT_SECRETS) out = out.replace(s.pattern, s.label);
  return out;
}

function classifyTool(tool, args) {
  const state = `${tool} ${JSON.stringify(args ?? {})}`;
  const probs = {
    sensitive_path: 0.02,
    credential_access: 0.02,
    destructive_action: /rm\s+-rf|drop\s+table|DELETE\s+FROM|terraform\s+destroy/i.test(state) ? 0.9 : 0.03,
  };
  const entities = [];

  const path = args?.filePath || args?.path || args?.file || "";
  for (const p of SENSITIVE_PATH) {
    if (path && p.re.test(path)) {
      entities.push({ type: `SENSITIVE_PATH:${p.id}`, source: "regex", action: "block", count: 1, label: p.id, confidence: 0.98 });
      probs.sensitive_path = Math.max(probs.sensitive_path, 0.98);
    }
  }

  const command = args?.command || "";
  for (const c of CREDENTIAL_COMMAND) {
    if (command && c.re.test(command)) {
      entities.push({ type: `CREDENTIAL_ACCESS:${c.id}`, source: "regex", action: "block", count: 1, label: c.id, confidence: 0.97 });
      probs.credential_access = Math.max(probs.credential_access, 0.97);
    }
  }

  // A secret passed on the command line is redactable in args.
  const argHits = [];
  for (const b of BUILTINS) {
    const m = matchAll(b.pattern, state);
    if (m.length) {
      entities.push({ type: b.id, source: "regex", action: b.action, count: m.length, label: b.label, confidence: probs[b.question] ?? 0.9 });
      argHits.push({ ...b, count: m.length });
    }
  }
  if (TEST.secret.test(state)) {
    entities.push({ type: "secret-in-args", source: "regex", action: "redact", count: 1, label: "[SECRET]", confidence: 0.95 });
    argHits.push({ id: "secret-in-args", action: "redact", label: "[SECRET]", pattern: /AKIA[0-9A-Z]{16}/g, count: 1 });
  }

  if (probs.destructive_action >= 0.8) {
    entities.push({ type: "DESTRUCTIVE_ACTION", source: "model", action: "block", count: 1, label: "destructive", confidence: probs.destructive_action });
  }

  let action = "allow";
  for (const e of entities) if (ORDER[e.action] > ORDER[action]) action = e.action;

  return {
    decisionId: randomUUID(),
    action,
    confidence: entities.length ? Math.max(...entities.map((e) => e.confidence ?? 0.9)) : 1,
    deferred: false,
    entities,
    regexIncrements: [],
    probs,
    hits: argHits,
    latencyMs: 0.12,
    original: state,
  };
}

function hookToolExecuteBefore(session, tool, args) {
  const decision = classifyTool(tool, args);
  audit(decision, {
    surface: "tool",
    hook: "tool.execute.before",
    sessionID: session.id,
    tool,
    callID: randomUUID(),
    providerDispatched: decision.action === "block" ? false : null,
    argsSha256: sha256(JSON.stringify(args ?? {})),
  });
  if (decision.action === "block") {
    throw new Error(`BunkerBlockedError (tool ${tool}): ${decision.entities.map((e) => e.label || e.type).join(", ")}`);
  }
  if (decision.action === "redact") for (const h of decision.hits) args.command = redact(args.command ?? "", [h]);
  return decision;
}

function hookToolExecuteAfter(session, tool, args, result) {
  const text = result.output ?? "";
  const decision = classify(text);
  const redacted = redactOutput(redact(text, decision.hits));
  const changed = redacted !== text;
  const outputDecision = { ...decision, action: changed ? "redact" : "allow" };
  audit(outputDecision, {
    surface: "tool",
    hook: "tool.execute.after",
    sessionID: session.id,
    tool,
    callID: randomUUID(),
    providerDispatched: null,
    outputSha256: sha256(text),
    outputRedacted: changed,
  });
  result.output = redacted;
  return decision;
}

// Mock tool executor + filesystem.
let toolExecutions = 0;
const MOCK_FS = {
  "notes.txt": `Deployment notes\naccess key: ${awsKey()}\n`,
  ".env": `AWS_SECRET_ACCESS_KEY=${"x".repeat(40)}\n`,
};
function executeTool(tool, args) {
  toolExecutions += 1;
  if (tool === "read") return { output: MOCK_FS[args.filePath] ?? "" };
  if (tool === "bash") return { output: "(mock command output)" };
  return { output: "" };
}

const TOOL_SCENARIOS = [
  { name: "read .env", tool: "read", args: { filePath: ".env" } },
  { name: "read ~/.aws/credentials", tool: "read", args: { filePath: "~/.aws/credentials" } },
  { name: "aws get-secret-value", tool: "bash", args: { command: "aws secretsmanager get-secret-value --secret-id prod/db" } },
  { name: "read notes.txt (secret inside)", tool: "read", args: { filePath: "notes.txt" } },
];

const toolResults = [];
for (const [i, s] of TOOL_SCENARIOS.entries()) {
  const session = new MockSession(`ses_tool_${i}`);
  const before = toolExecutions;
  let thrown = null;
  let decision = null;
  try {
    decision = hookToolExecuteBefore(session, s.tool, s.args);
    const result = executeTool(s.tool, s.args);
    hookToolExecuteAfter(session, s.tool, s.args, result);
    s.observedOutput = result.output;
  } catch (err) {
    thrown = err.message;
  }
  toolResults.push({
    name: s.name,
    tool: s.tool,
    action: thrown ? "block" : decision?.action ?? "?",
    executed: toolExecutions - before,
    outputRedacted: !thrown && /\[SECRET/.test(s.observedOutput ?? ""),
    threw: Boolean(thrown),
  });
}

// ---------------------------------------------------------------------------
// 8. Write the real audit log + print proof
// ---------------------------------------------------------------------------
writeFileSync(AUDIT_PATH, AUDIT.map((r) => JSON.stringify(r)).join("\n") + "\n");

const pad = (s, n) => String(s).padEnd(n);
console.log("\nopencode-bunker · pre-provider proof — chat surface\n");
console.log(pad("scenario", 28), pad("action", 8), pad("deferred", 9), pad("provider calls", 15), pad("reverted", 9), "threw");
console.log("-".repeat(95));
for (const r of results) {
  console.log(
    pad(r.name, 28),
    pad(r.action, 8),
    pad(r.deferred ? "yes" : "no", 9),
    pad(r.providerCallsDelta, 15),
    pad(r.reverted, 9),
    r.thrown ? "BunkerBlockedError" : "-",
  );
}

console.log("\nopencode-bunker · pre-provider proof — tool surface\n");
console.log(pad("scenario", 32), pad("tool", 6), pad("action", 8), pad("executed", 10), pad("output redacted", 16), "threw");
console.log("-".repeat(95));
for (const r of toolResults) {
  console.log(
    pad(r.name, 32),
    pad(r.tool, 6),
    pad(r.action, 8),
    pad(r.executed, 10),
    pad(r.outputRedacted ? "yes" : "no", 16),
    r.threw ? "BunkerBlockedError" : "-",
  );
}

const blocked = results.find((r) => r.action === "block");
const blockedTool = toolResults.find((r) => r.action === "block");
const redactedTool = toolResults.find((r) => r.outputRedacted);
console.log("\nPROOF:");
console.log(`  chat: block "${blocked.name}" -> provider calls = ${blocked.providerCallsDelta}, reverted = ${blocked.reverted}, aborted = ${blocked.aborted}`);
console.log(`  tool: block "${blockedTool.name}" -> executions = ${blockedTool.executed} (never ran)`);
console.log(`  tool: "${redactedTool.name}" -> output redacted before it entered context = ${redactedTool.outputRedacted}`);
console.log(`  audit records written: ${AUDIT.length} -> ${AUDIT_PATH}`);
console.log(`  every record has stage=${AUDIT.every((r) => r.stage === "pre_provider") ? "pre_provider" : "MIXED"} and rawIncluded=${AUDIT.every((r) => r.rawIncluded === false) ? "false" : "MIXED"}`);

provider.close();
