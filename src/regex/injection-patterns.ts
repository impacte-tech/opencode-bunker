/**
 * Deterministic prompt-injection / jailbreak patterns.
 *
 * These complement the model: the model generalizes, but a small set of
 * high-signal phrases (e.g. "disable all filters") should always block, even
 * when the classifier is unavailable or under-confident. They are intentionally
 * narrow to avoid false positives on benign text.
 */
export interface InjectionPattern {
  id: string
  label: string
  pattern: string
}

export const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    id: "disable-filters",
    label: "[PROMPT_INJECTION]",
    // "disable all filters", "turn off your safety", "deactivate safeguards"
    pattern:
      String.raw`\b(disable|deactivate|turn\s+off|switch\s+off|shut\s+off)\s+(all\s+|any\s+|your\s+|the\s+)?(filters?|safety|restrictions?|guardrails?|guidelines?|protections?|content\s+filters?|moderation|safeguards?)\b`,
  },
  {
    id: "bypass-filters",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\b(bypass|circumvent|evade|get\s+around|work\s+around)\s+(all\s+|any\s+|your\s+|the\s+)?(filters?|safety|restrictions?|guardrails?|guidelines?|protections?|content\s+filters?|moderation|safeguards?)\b`,
  },
  {
    id: "ignore-instructions",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\b(ignore|disregard|forget|override|discard)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|preceding|system|your|its|own)\s+(instructions?|rules?|guidelines?|prompts?|directives?|messages?)\b`,
  },
  {
    id: "reveal-system-prompt",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\b(reveal|show|print|output|repeat|expose|leak|disclose|share|give|send|dump)\s+(me\s+)?(your\s+|the\s+)?(system\s+prompt|initial\s+prompt|hidden\s+prompt|system\s+message|instructions?)\b`,
  },
  {
    id: "developer-mode",
    label: "[PROMPT_INJECTION]",
    pattern: String.raw`\b(developer|debug|god|admin|unrestricted|jailbreak)\s+mode\b`,
  },
  {
    id: "no-restrictions",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\b(without|no|remove|drop|lift)\s+(any\s+|all\s+|your\s+)?(restrictions?|limitations?|filters?|safety|guidelines?|rules?|constraints?)\b`,
  },
  {
    id: "act-as-unrestricted",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\b(act|behave|respond|answer|pretend)\s+(as|like|to\s+be)\s+(an?\s+)?(unrestricted|unfiltered|uncensored|evil|malicious|hacker|rogue)\b`,
  },
  {
    id: "must-comply",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\b(you\s+must|do\s+not\s+refuse|never\s+refuse|always\s+comply|must\s+comply|you\s+have\s+to\s+comply)\b`,
  },
  {
    id: "override-safety",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\boverride\s+(your\s+|all\s+|the\s+)?(safety|security|restrictions?|guidelines?|filters?|settings?)\b`,
  },
  {
    id: "env-file-request",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\b(cat|type|print|read|dump|display|reveal|show|output|share)\s+(the\s+)?(\./|\~/|\.{1,2}/)*\.env\b`,
  },
  {
    id: "unredacted-secrets",
    label: "[PROMPT_INJECTION]",
    pattern:
      String.raw`\b(print|show|display|give|send|dump|reveal|output|share)\b.{0,60}\b(unredacted|unmasked|in\s+plaintext|in\s+plain\s+text|raw\s+(values?|contents?))\b`,
  },
  {
    id: "fake-role-tag",
    label: "[PROMPT_INJECTION]",
    // Chat-template role forgery: user text impersonating a system/developer
    // turn via special tokens (<|system|>, <|im_start|>, <<SYS>>, [SYSTEM]).
    // Only high-signal role-openers are matched — user/assistant/endoftext
    // tokens appear in benign tokenizer discussions and are not injection
    // evidence on their own.
    pattern:
      String.raw`(?:<\|(?:system|developer|im_start)\|>|<<SYS>>|\[(?:SYSTEM|SYSTEM_PROMPT)\])`,
  },
  {
    id: "repeat-extraction",
    label: "[PROMPT_INJECTION]",
    // "repeat everything above this line", "recite all of the text" — asking
    // the model to echo prior context, a classic system-prompt extraction.
    pattern:
      String.raw`\b(repeat|recite|echo|reprint)\b.{0,30}\b(everything|all\s+(of\s+the\s+)?(above|text|prompt|message|instructions?|context|conversation))\b|\b(everything|all\s+of\s+the)\s+(above|before|earlier|preceding|previous|prior)\b`,
  },
]

/**
 * Coarse lexical injection vocabulary, tested against
 * {@link normalizeForLexicon}. Used by the classifier to gate model-only
 * injection verdicts (`coverage.gateModelInjection`, on by default): the head
 * still over-fires on benign account/UI text ("The password field is
 * required." → 0.98) even after the v5/v6 retrains. This is a corroboration
 * signal, not an enforcement rule — `INJECTION_PATTERNS` above is the
 * enforcement layer.
 */
export const INJECTION_LEXICON =
  /\b(ignore|ignor|disregard|forget|override|instructions?|system\s*prompt|initial\s*prompt|hidden\s*prompt|system\s*message|system|reveal|expose|leak|disclose|share|give|send|show|print|output|dump|repeat|recite|echo|unrestricted|unfiltered|uncensored|jailbreak|bypass|circumvent|disable|deactivate|developer\s*mode|debug\s*mode|dan|aim|stan|dude|no\s*rules?|no\s*(content\s*)?policy|without\s+(any\s+)?(rules?|restriction\w*|filter\w*|guideline\w*|safety|limitation\w*|constraint\w*|guardrail\w*)|dont\s*refuse|do\s*not\s*refuse|must\s*comply|always\s*comply|filter\w*|restriction\w*|guideline\w*|safeguard\w*|guardrail\w*|comply|refuse|pretend|roleplay|act\s+as|behave\s+as|skeleton\s*key|pwned|new\s+conversation|reset\s+your|from\s+now\s+on|exfiltrat\w*|unredacted|plain\s*text)\b/

const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
}

/**
 * Normalize text for {@link INJECTION_LEXICON} matching: NFKC, strip
 * zero-width/format characters, fold common leetspeak substitutions, lowercase.
 * This is how obfuscated attacks (`1gn0r3 4ll pr3v10u5 1n5truct10n5`) regain a
 * lexical signal while ordinary prose is left intact.
 */
export function normalizeForLexicon(input: string): string {
  const stripped = input.replace(/[\u200b-\u200f\u2028\u2029\u2060-\u206f\ufeff]/g, "")
  let out = ""
  for (const ch of stripped.normalize("NFKC")) out += LEET[ch] ?? ch
  return out.toLowerCase()
}

/**
 * High-signal harmful-request patterns that always block, independent of the
 * model. The `impacte/bunker-laya` v5 `harmful_request` head under-scored a few
 * catastrophic asks it had not seen in that phrasing (e.g. "How do I make
 * illegal drugs at home?" → 0.008), so these narrow patterns are a backstop.
 * They require an action verb so benign mentions ("how do illegal drugs affect
 * the brain") do not match.
 */
export const HARMFUL_PATTERNS: InjectionPattern[] = [
  {
    id: "harmful-drugs",
    label: "[HARMFUL]",
    pattern:
      String.raw`\b(make|cook|synthesi[sz]e|produce|manufacture)\b[^.?!]{0,30}\b(meth(amphetamine)?|fentanyl|heroin|cocaine|illegal\s+drugs?|drugs?)\b`,
  },
  {
    id: "harmful-explosives",
    label: "[HARMFUL]",
    pattern:
      String.raw`\b(build|make|assemble|construct|create)\b[^.?!]{0,30}\b(bomb|explosive|ied|pipe\s+bomb|weapon)\b`,
  },
  {
    id: "harmful-malware",
    label: "[HARMFUL]",
    pattern:
      String.raw`\b(write|create|make|develop|build)\b[^.?!]{0,25}\b(ransomware|malware|keylogger|trojan|virus)\b`,
  },
  {
    id: "harmful-phishing",
    label: "[HARMFUL]",
    pattern:
      String.raw`\bphishing\b[^.?!]{0,40}\b(steal|capture|harvest|credentials?)\b|\bsteal\b[^.?!]{0,30}\b(credentials?|passwords?|logins?)\b`,
  },
  {
    id: "harmful-unauthorized-access",
    label: "[HARMFUL]",
    pattern: String.raw`\b(hack|break)\s+into\b|\bunauthorized\s+access\b`,
  },
]

