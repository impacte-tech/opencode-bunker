import { test, expect, beforeAll } from "bun:test"
import { classify, redact, scrubValue, reloadConfig } from "../src/core"
import { createRedactor, redactByPaths, stripInvisibleUnicode } from "../src/regex/engine"
import { SECRET_PATTERNS } from "../src/regex/secret-patterns"

beforeAll(() => {
  delete process.env.BUNKER_CONFIG
  reloadConfig()
})

const gh = "ghp_" + "a".repeat(36)
const aws = "AKIAIOSFODNN7EXAMPLE"

test("all 112 secret patterns compile", () => {
  const r = createRedactor(SECRET_PATTERNS)
  expect(r.patternCount).toBe(112)
})

test("detects and redacts a GitHub PAT", () => {
  const d = classify(`token ${gh}`)
  expect(d.entities.some((e) => e.type === "github-pat")).toBe(true)
  expect(redact(`token ${gh}`, d.hits)).toContain("[REDACTED:github-pat]")
  expect(redact(`token ${gh}`, d.hits)).not.toContain(gh)
})

test("detects an AWS access key id", () => {
  const d = classify(aws)
  expect(d.entities.some((e) => e.type === "aws-access-key-id")).toBe(true)
})

test("detects OpenAI and Anthropic keys", () => {
  expect(classify("sk-" + "a".repeat(50)).entities.some((e) => e.type === "openai-api-key")).toBe(true)
  expect(
    classify("sk-ant-api03-" + "a".repeat(40)).entities.some((e) => e.type === "anthropic-api-key")
  ).toBe(true)
})

test("detects Slack, Stripe and JWT tokens", () => {
  expect(classify("xoxb-1234567890-abcdefghij").entities.some((e) => e.type === "slack-access-token")).toBe(true)
  expect(classify("sk_live_" + "a".repeat(24)).entities.some((e) => e.type === "stripe-secret-token")).toBe(true)
  const jwt = "eyJ" + "a".repeat(20) + ".eyJ" + "b".repeat(20) + ".c".repeat(20)
  expect(classify(jwt).entities.some((e) => e.type === "jwt-token")).toBe(true)
})

test("detects a private key block", () => {
  const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
  expect(classify(key).entities.some((e) => e.type === "private-key")).toBe(true)
})

test("detects generic api-key and password assignments", () => {
  expect(classify("api_key=qwerty9876543210").entities.some((e) => e.type === "api-key")).toBe(true)
  expect(classify("password=hunter2xyz").entities.some((e) => e.type === "password")).toBe(true)
})

test("keyword pre-filter skips non-matching text", () => {
  const d = classify("just a normal sentence about nothing")
  expect(d.entities.length).toBe(0)
})

test("invisible Unicode tags are stripped on redaction", () => {
  const tag = "\uDB40\uDC00"
  expect(stripInvisibleUnicode(`hello${tag} world`)).toBe("hello world")
  expect(redact(`hello${tag} world`, [])).toBe("hello world")
})

test("deep traversal redacts nested secrets", () => {
  const value = { a: { b: gh }, list: [aws] }
  const out = scrubValue(value, []) as { a: { b: string }; list: string[] }
  expect(out.a.b).toContain("[REDACTED:github-pat]")
  expect(out.list[0]).toContain("[REDACTED:aws-access-key-id]")
})

test("image/base64 payloads are preserved", () => {
  const value = { type: "base64", data: gh }
  const out = scrubValue(value, []) as { data: string }
  expect(out.data).toBe(gh)
})

test("path-based redaction replaces only the named fields", () => {
  const out = redactByPaths(
    { user: { password: "x", name: "keep" }, token: "y" },
    ["token", "user.password"]
  ) as { user: { password: string; name: string }; token: string }
  expect(out.token).toBe("[REDACTED]")
  expect(out.user.password).toBe("[REDACTED]")
  expect(out.user.name).toBe("keep")
})
