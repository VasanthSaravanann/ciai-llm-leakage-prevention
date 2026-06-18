// LDOT sanitization pipeline — pure TS simulation of the backend proxy.

export type Action = "allow" | "redact" | "block";

export interface PIIHit {
  type: string;
  value: string;
  start: number;
  end: number;
}

export interface PipelineStep {
  name: string;
  output: string;
  note?: string;
}

export interface PipelineResult {
  raw: string;
  normalized: string;
  steps: PipelineStep[];
  hits: PIIHit[];
  redactedPrompt: string;
  action: Action;
  triggeredPatterns: string[];
  latencyMs: number;
  base64Decoded?: string[];
}

// ---------- Normalization helpers ----------

const ZERO_WIDTH = /\u200b|\u200c|\u200d|\u2060|\uFEFF/g;

const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic / Greek / fullwidth lookalikes -> ASCII
  а: "a",
  А: "A",
  е: "e",
  Е: "E",
  о: "o",
  О: "O",
  р: "p",
  Р: "P",
  с: "c",
  С: "C",
  у: "y",
  У: "Y",
  х: "x",
  Х: "X",
  і: "i",
  І: "I",
  ј: "j",
  Ј: "J",
  ѕ: "s",
  Ѕ: "S",
  κ: "k",
  Κ: "K",
  ν: "v",
  Ν: "N",
  // Fullwidth digits
  "０": "0",
  "１": "1",
  "２": "2",
  "３": "3",
  "４": "4",
  "５": "5",
  "６": "6",
  "７": "7",
  "８": "8",
  "９": "9",
};

const LEET_MAP: Record<string, string> = {
  "@": "a",
  "4": "a",
  "1": "i",
  "0": "o",
  "3": "e",
  "5": "s",
  "7": "t",
  $: "s",
};

function stripZeroWidth(s: string): string {
  return s.replace(ZERO_WIDTH, "");
}

function homoglyph(s: string): string {
  let out = "";
  for (const ch of s) out += HOMOGLYPH_MAP[ch] ?? ch;
  return out;
}

function deLeet(s: string): string {
  let out = "";
  for (const ch of s) {
    const lower = ch.toLowerCase();
    out += LEET_MAP[lower] ?? ch;
  }
  return out;
}

function compressDelimiters(s: string): string {
  return s.replace(/[\s._-]/g, "");
}

const BASE64_RE = /^[A-Za-z0-9+/=]{12,}$/;

function tryBase64Decode(
  s: string,
  depth = 0,
  acc: string[] = [],
): { text: string; decoded: string[] } {
  if (depth >= 3) return { text: s, decoded: acc };
  const tokens = s.split(/\s+/);
  let changed = false;
  const next = tokens.map((tok) => {
    if (!BASE64_RE.test(tok)) return tok;
    try {
      const decoded =
        typeof atob !== "undefined" ? atob(tok) : Buffer.from(tok, "base64").toString("utf-8");
      if (/^[\x20-\x7e\s]+$/.test(decoded) && decoded.length > 2) {
        changed = true;
        acc.push(decoded);
        return decoded;
      }
    } catch (error) {
      void error;
    }
    return tok;
  });
  const joined = next.join(" ");
  return changed ? tryBase64Decode(joined, depth + 1, acc) : { text: joined, decoded: acc };
}

// ---------- PII patterns ----------

export interface PatternDef {
  type: string;
  re: RegExp;
  severity: "low" | "medium" | "high" | "critical";
}

export const PII_PATTERNS: PatternDef[] = [
  { type: "AADHAAR", re: /\b[2-9]\d{3}[\s.\-]?\d{4}[\s.\-]?\d{4}\b/g, severity: "critical" },
  { type: "PAN", re: /(?<![a-zA-Z0-9])[\.]?[a-zA-Z]{5}[\.]?[0-9]{4}[\.]?[a-zA-Z]{1}[\.]?(?![a-zA-Z0-9])/gi, severity: "critical" },
  { type: "VOTER_ID", re: /\b[A-Z]{3}[0-9]{7}\b/g, severity: "high" },
  {
    type: "DRIVING_LICENSE",
    re: /\b[A-Z]{2}[-\s]?\d{2}[-\s]?\d{4}[-\s]?\d{7}\b/g,
    severity: "high",
  },
  {
    type: "GSTIN",
    re: /\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}\b/g,
    severity: "high",
  },
  { type: "PASSPORT_IN", re: /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/g, severity: "critical" },
  { type: "UPI", re: /\b[\w.-]{2,}@[a-zA-Z]{2,}\b/g, severity: "medium" },
  { type: "CREDIT_CARD", re: /\b(?:\d[ -]*?){13,16}\b/g, severity: "critical" },
  {
    type: "API_KEY",
    re: /\b(?:sk|pk|rk)_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b/g,
    severity: "critical",
  },
  { type: "EMAIL", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, severity: "low" },
  { type: "PHONE_IN", re: /\b(?:\+91[\s-]?)?[6-9]\d{9}\b/g, severity: "medium" },
];

// Severity policy — anything critical => block, otherwise redact.
const BLOCK_TYPES = new Set(["AADHAAR", "PAN", "PASSPORT_IN", "CREDIT_CARD", "API_KEY"]);

function findHits(text: string): PIIHit[] {
  const hits: PIIHit[] = [];
  for (const p of PII_PATTERNS) {
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(text)) !== null) {
      hits.push({ type: p.type, value: m[0], start: m.index, end: m.index + m[0].length });
    }
  }
  return hits;
}

function redactRaw(raw: string, normHits: PIIHit[]): { redacted: string; types: string[] } {
  // Run pattern matching against the RAW text too so we can replace cleanly
  // in the user-visible form. Normalization-only hits get appended as notes.
  let redacted = raw;
  const types = new Set<string>();
  for (const p of PII_PATTERNS) {
    redacted = redacted.replace(p.re, () => {
      types.add(p.type);
      return `[${p.type}]`;
    });
  }
  for (const h of normHits) types.add(h.type);
  // If normalization revealed extra hits not in raw, prepend a marker
  const onlyInNorm = normHits.filter((h) => !redacted.includes(`[${h.type}]`));
  if (onlyInNorm.length) {
    const extras = Array.from(new Set(onlyInNorm.map((h) => `[${h.type}]`))).join(" ");
    redacted = `${redacted} ⟪evasion-normalized: ${extras}⟫`;
  }
  return { redacted, types: Array.from(types) };
}

export function runPipeline(raw: string): PipelineResult {
  const t0 = performance.now();
  const steps: PipelineStep[] = [{ name: "Raw input", output: raw }];

  const s1 = stripZeroWidth(raw);
  steps.push({
    name: "Zero-width stripped",
    output: s1,
    note: s1 !== raw ? "Removed invisible chars" : "no-op",
  });

  const s2 = homoglyph(s1);
  steps.push({
    name: "Homoglyph normalized",
    output: s2,
    note: s2 !== s1 ? "Mapped lookalikes" : "no-op",
  });

  const s3 = deLeet(s2);
  steps.push({ name: "De-leeted", output: s3, note: s3 !== s2 ? "Translated leetspeak" : "no-op" });

  const { text: s4, decoded } = tryBase64Decode(s3);
  steps.push({
    name: "Base64 recursively decoded",
    output: s4,
    note: decoded.length ? `Decoded ${decoded.length} layer(s)` : "no-op",
  });

  const s5 = compressDelimiters(s4);
  steps.push({ name: "Delimiters compressed", output: s5, note: "Stripped whitespace/.-_" });

  const hits = [...findHits(s2), ...findHits(s4)];
  // Dedupe by type+value
  const seen = new Set<string>();
  const uniqHits = hits.filter((h) => {
    const k = `${h.type}:${h.value}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const { redacted, types } = redactRaw(raw, uniqHits);
  const triggered = types;
  const shouldBlock = triggered.some((t) => BLOCK_TYPES.has(t));
  const action: Action = triggered.length === 0 ? "allow" : shouldBlock ? "block" : "redact";

  const latencyMs = +(performance.now() - t0).toFixed(2);

  return {
    raw,
    normalized: s5,
    steps,
    hits: uniqHits,
    redactedPrompt: action === "allow" ? raw : redacted,
    action,
    triggeredPatterns: triggered,
    latencyMs,
    base64Decoded: decoded,
  };
}

// SHA-1ish lightweight origin hash (non-crypto, audit display only).
export function hashOrigin(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}
