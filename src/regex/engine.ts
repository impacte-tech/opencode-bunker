/**
 * Self-contained secret-redaction engine, ported from `opencode-redact`
 * (https://github.com/meimingqi222/opencode-plugins, MIT).
 *
 * - strips invisible Unicode Tags characters (anti-prompt-injection)
 * - detects secrets via a keyword pre-filter + regex
 * - recursively redacts objects/arrays, preserving image/base64 data
 * - path-based redaction (`token`, `credentials.password`)
 * - hot path: precompiled keywords, one `toLowerCase` per string, a shared
 *   string cache, and a copy-on-write deep walk
 */

// Unicode Tags block (U+E0000–U+E007F) as UTF-16 surrogate pairs.
const UNICODE_TAGS_RE = /[\uDB40][\uDC00-\uDC7F]/g
const HIGH_SURROGATE = "\uDB40"
const DEFAULT_CACHE_SIZE = 4000
const DEFAULT_CACHE_ENTRY_LENGTH = 512_000

export interface SecretPattern {
  id: string
  category: string
  title: string
  pattern: string
  keywords: string[]
  caseInsensitive?: boolean
}

interface CompiledPattern {
  readonly id: string
  readonly regex: RegExp
  readonly keywords: readonly string[]
  readonly keywordsLower: readonly string[]
  readonly caseInsensitive: boolean
}

function compilePatterns(patterns: readonly SecretPattern[]): CompiledPattern[] {
  return patterns.map((entry) => {
    let regex: RegExp
    try {
      regex = new RegExp(entry.pattern, entry.caseInsensitive ? "gi" : "g")
    } catch {
      regex = /^$/
    }
    const keywords = entry.keywords ?? []
    return {
      id: entry.id,
      regex,
      keywords,
      keywordsLower: keywords.map((kw) => kw.toLowerCase()),
      caseInsensitive: entry.caseInsensitive === true,
    }
  })
}

/** Remove Unicode Tags block characters (U+E0000–U+E007F). */
export function stripInvisibleUnicode(input: string): string {
  if (!input.includes(HIGH_SURROGATE)) return input
  return input.replace(UNICODE_TAGS_RE, "")
}

function matchesKeyword(entry: CompiledPattern, text: string, lower: string | undefined): boolean {
  if (entry.caseInsensitive) {
    const haystack = lower ?? text.toLowerCase()
    return entry.keywordsLower.some((kw) => haystack.includes(kw))
  }
  return entry.keywords.some((kw) => text.includes(kw))
}

function applyPatterns(input: string, compiled: readonly CompiledPattern[]): string {
  let lower: string | undefined
  let out = input

  for (const entry of compiled) {
    if (!matchesKeyword(entry, out, lower)) continue

    entry.regex.lastIndex = 0
    out = out.replace(entry.regex, (full, ...rest) => {
      const captured = typeof rest[0] === "string" ? rest[0] : full
      const censor = `[REDACTED:${entry.id}]`
      if (captured === full) return censor
      return full.replace(captured, censor)
    })
    // Lower snapshot is invalid after replacement.
    lower = undefined
  }

  return out
}

function detectPatterns(input: string, compiled: readonly CompiledPattern[]): string[] {
  const ids: string[] = []
  let lower: string | undefined
  for (const entry of compiled) {
    if (!matchesKeyword(entry, input, lower)) continue
    entry.regex.lastIndex = 0
    if (entry.regex.test(input)) ids.push(entry.id)
    lower = undefined
  }
  return ids
}

function redactStringCompiled(
  input: string,
  compiled: readonly CompiledPattern[],
  cache: Map<string, string>,
  maxCache: number
): string {
  const existing = cache.get(input)
  if (existing !== undefined) return existing

  const result = applyPatterns(stripInvisibleUnicode(input), compiled)

  if (input.length > DEFAULT_CACHE_ENTRY_LENGTH) return result
  if (cache.size >= maxCache) cache.clear()
  cache.set(input, result)
  return result
}

type DeepResult = { value: unknown; changed: boolean }

function unchanged(value: unknown): DeepResult {
  return { value, changed: false }
}

function redactDeepInner(
  value: unknown,
  compiled: readonly CompiledPattern[],
  cache: Map<string, string>,
  maxCache: number
): DeepResult {
  if (value === null || value === undefined) return unchanged(value)

  if (typeof value === "string") {
    const next = redactStringCompiled(value, compiled, cache, maxCache)
    return next === value ? unchanged(value) : { value: next, changed: true }
  }

  if (typeof value !== "object") return unchanged(value)

  if (Array.isArray(value)) {
    let changed = false
    const next = value.map((item) => {
      const r = redactDeepInner(item, compiled, cache, maxCache)
      if (r.changed) changed = true
      return r.value
    })
    return changed ? { value: next, changed: true } : unchanged(value)
  }

  const obj = value as Record<string, unknown>

  // Preserve image / base64 payloads untouched.
  if ("type" in obj && (obj.type === "base64" || obj.type === "image") && "data" in obj) {
    return unchanged(value)
  }
  if ("isImage" in obj && obj.isImage === true && typeof obj.content === "string") {
    let changed = false
    const result: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(obj)) {
      if (k === "content") {
        result[k] = v
        continue
      }
      const r = redactDeepInner(v, compiled, cache, maxCache)
      if (r.changed) changed = true
      result[k] = r.value
    }
    return changed ? { value: result, changed: true } : unchanged(value)
  }

  let changed = false
  const entries: Array<[string, unknown]> = []
  for (const [k, v] of Object.entries(obj)) {
    const r = redactDeepInner(v, compiled, cache, maxCache)
    if (r.changed) changed = true
    entries.push([k, r.value])
  }
  return changed ? { value: Object.fromEntries(entries), changed: true } : unchanged(value)
}

const PATH_NOT_FOUND = Symbol("path_not_found")

function parsePath(path: string): string[] {
  const segs: string[] = []
  let current = ""
  let inBrackets = false
  let inQuotes = false
  let quoteChar = ""

  const flush = () => {
    if (current) {
      segs.push(current)
      current = ""
    }
  }

  for (const ch of path) {
    if (!inBrackets && ch === ".") {
      flush()
    } else if (ch === "[") {
      flush()
      inBrackets = true
    } else if (ch === "]" && inBrackets) {
      segs.push(current)
      current = ""
      inBrackets = false
      inQuotes = false
    } else if ((ch === '"' || ch === "'") && inBrackets) {
      if (!inQuotes) {
        inQuotes = true
        quoteChar = ch
      } else if (ch === quoteChar) {
        inQuotes = false
        quoteChar = ""
      } else {
        current += ch
      }
    } else {
      current += ch
    }
  }
  flush()
  return segs
}

function getAtPath(obj: unknown, segs: string[]): unknown | typeof PATH_NOT_FOUND {
  let current: unknown = obj
  for (const key of segs) {
    if (current === null || current === undefined || typeof current !== "object") {
      return PATH_NOT_FOUND
    }
    const record = current as Record<string, unknown>
    if (!(key in record)) return PATH_NOT_FOUND
    current = record[key]
  }
  return current
}

/** Shallow-copy only the nodes along `segs`; returns the original if missing. */
function setAtPathCopy(root: unknown, segs: string[], val: unknown): unknown {
  if (segs.length === 0) return val
  if (root === null || typeof root !== "object") return root

  if (Array.isArray(root)) {
    const idx = Number(segs[0])
    if (!Number.isInteger(idx) || idx < 0 || idx >= root.length) return root
    const next = root.slice()
    next[idx] = setAtPathCopy(next[idx], segs.slice(1), val)
    return next
  }

  const obj = root as Record<string, unknown>
  const key = segs[0]!
  if (!(key in obj)) return root
  const next = { ...obj }
  next[key] = setAtPathCopy(obj[key], segs.slice(1), val)
  return next
}

export function redactByPaths(value: unknown, paths: string[], censor = "[REDACTED]"): unknown {
  if (value === null || typeof value !== "object") return value
  let result: unknown = value
  for (const path of paths) {
    const segs = parsePath(path)
    if (getAtPath(result, segs) === PATH_NOT_FOUND) continue
    result = setAtPathCopy(result, segs, censor)
  }
  return result
}

export interface Redactor {
  readonly patternCount: number
  readonly pathCount: number
  string(input: string | null | undefined): string | null | undefined
  deep(value: unknown): unknown
  paths(value: unknown): unknown
  /** Ids of the patterns that match `input` (for the decision record). */
  detect(input: string): string[]
  clearCache(): void
}

export interface RedactorOptions {
  redactPaths?: string[]
  pathCensor?: string
  cacheSize?: number
}

export function createRedactor(
  patterns: readonly SecretPattern[],
  options: RedactorOptions = {}
): Redactor {
  const compiled = compilePatterns(patterns)
  const redactPaths = options.redactPaths ?? []
  const pathCensor = options.pathCensor ?? "[REDACTED]"
  const maxCache = options.cacheSize ?? DEFAULT_CACHE_SIZE
  const cache = new Map<string, string>()

  return {
    patternCount: compiled.length,
    pathCount: redactPaths.length,
    string(input) {
      if (!input || typeof input !== "string") return input
      return redactStringCompiled(input, compiled, cache, maxCache)
    },
    deep(value) {
      return redactDeepInner(value, compiled, cache, maxCache).value
    },
    paths(value) {
      if (redactPaths.length === 0) return value
      return redactByPaths(value, redactPaths, pathCensor)
    },
    detect(input) {
      return detectPatterns(stripInvisibleUnicode(input), compiled)
    },
    clearCache() {
      cache.clear()
    },
  }
}
