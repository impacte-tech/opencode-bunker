import { test, expect, beforeAll } from "bun:test"
import plugin, { classify, classifyTool, globToRegex, isSafeRegex, redact, redactOutput, reloadConfig } from "../src/core"

beforeAll(() => {
  // Ensure this file uses the shipped defaults, not another suite's config.
  delete process.env.BUNKER_CONFIG
  reloadConfig()
})

const AT = String.fromCharCode(64)
const email = (l: string, d: string) => `${l}${AT}${d}`
const awsKey = () => "AK" + "IA" + "IOSFODNN7EXAMPLE"

test("classify redacts an email address", () => {
  const text = `reach me at ${email("jane.doe", "example.com")}`
  const d = classify(text)
  expect(d.action).toBe("redact")
  expect(redact(text, d.hits)).toContain("[EMAIL]")
})

test("classify blocks a bare AWS access key", () => {
  const d = classify(`key ${awsKey()}`)
  expect(d.action).toBe("block")
  expect(d.entities.some((e) => e.type === "aws-access-key")).toBe(true)
})

test("custom regex increments the model classification", () => {
  const d = classify("internal ticket PROJ-7781")
  expect(d.regexIncrements.some((i) => i.target === "confidential")).toBe(true)
  expect(d.entities.some((e) => e.type === "CONFIDENTIAL" && e.confidence >= 0.75)).toBe(true)
})

test("tool guard blocks sensitive paths and credential commands", () => {
  expect(classifyTool("read", { filePath: ".env" }).action).toBe("block")
  expect(classifyTool("read", { filePath: "~/.aws/credentials" }).action).toBe("block")
  expect(classifyTool("read", { filePath: "src/app.ts" }).action).not.toBe("block")
  expect(classifyTool("bash", { command: "aws secretsmanager get-secret-value --secret-id prod/db" }).action).toBe("block")
  expect(classifyTool("bash", { command: "aws ssm get-parameter --name x --with-decryption" }).action).toBe("block")
})

test("tool output redaction scrubs secrets", () => {
  const out = `AWS_ACCESS_KEY_ID=${awsKey()}`
  expect(redactOutput(out)).toContain("[SECRET")
  expect(redactOutput(out)).not.toContain(awsKey())
})

test("globToRegex handles **/ and braces", () => {
  expect(globToRegex("**/.env").test(".env")).toBe(true)
  expect(globToRegex("**/.env").test("app/.env")).toBe(true)
  expect(globToRegex("**/*.{pem,key}").test("certs/server.pem")).toBe(true)
  expect(globToRegex("**/*.{pem,key}").test("certs/server.txt")).toBe(false)
})

test("regex safety rejects lookaround and nested quantifiers", () => {
  expect(isSafeRegex("PROJ-\\d{4,6}")).toBe(true)
  expect(isSafeRegex("(?=foo)")).toBe(false)
  expect(isSafeRegex("(?<=foo)")).toBe(false)
  expect(isSafeRegex("(a+)+")).toBe(false)
  expect(isSafeRegex("\\1")).toBe(false)
})

test("chat.message hook redacts and blocks with rollback", async () => {
  const reverted: string[] = []
  const aborted: string[] = []
  const ctx: any = {
    client: {
      session: {
        revert: async (o: any) => reverted.push(o.body.messageID),
        abort: async () => aborted.push("x"),
      },
    },
  }
  const hooks = await plugin(ctx)

  // redact path: mutates the part in place, no throw
  const parts = [{ type: "text", text: `ping ${email("ops", "corp.example.com")}` }]
  await hooks["chat.message"]!({ sessionID: "s1", messageID: "m1" } as any, { message: {} as any, parts: parts as any })
  expect((parts[0] as any).text).toContain("[EMAIL]")

  // block path: reverts and throws
  const badParts = [{ type: "text", text: `key ${awsKey()}` }]
  let threw = false
  try {
    await hooks["chat.message"]!({ sessionID: "s1", messageID: "m2" } as any, { message: {} as any, parts: badParts as any })
  } catch {
    threw = true
  }
  expect(threw).toBe(true)
  expect(reverted).toEqual(["m2"])
  expect(aborted.length).toBe(1)
})

test("tool.execute.before hook blocks .env before execution", async () => {
  const hooks = await plugin({ client: { session: {} } } as any)
  let threw = false
  try {
    await hooks["tool.execute.before"]!({ tool: "read", sessionID: "s", callID: "c" } as any, { args: { filePath: ".env" } })
  } catch {
    threw = true
  }
  expect(threw).toBe(true)
})

test("tool.execute.after hook redacts output", async () => {
  const hooks = await plugin({ client: { session: {} } } as any)
  const out: any = { output: `AWS_ACCESS_KEY_ID=${awsKey()}`, title: "", metadata: {} }
  await hooks["tool.execute.after"]!({ tool: "read", sessionID: "s", callID: "c", args: {} } as any, out)
  expect(out.output).toContain("[SECRET")
  expect(out.output).not.toContain(awsKey())
})
