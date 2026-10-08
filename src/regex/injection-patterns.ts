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
]
