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
  // Cyrillic lowercase
  "\u0430":"a","\u0431":"b","\u0432":"v","\u0433":"g","\u0434":"d","\u0435":"e",
  "\u0436":"zh","\u0437":"z","\u0438":"i","\u0439":"y","\u043a":"k","\u043b":"l",
  "\u043c":"m","\u043d":"n","\u043e":"o","\u043f":"p","\u0440":"r","\u0441":"c",
  "\u0442":"t","\u0443":"y","\u0444":"f","\u0445":"x","\u0446":"ts","\u0447":"ch",
  "\u0448":"sh","\u0449":"shch","\u044a":"soft","\u044b":"y","\u044c":"soft",
  "\u044d":"e","\u044e":"yu","\u044f":"ya",
  // Cyrillic uppercase
  "\u0410":"A","\u0411":"B","\u0412":"B","\u0413":"G","\u0414":"D","\u0415":"E",
  "\u0416":"Zh","\u0417":"Z","\u0418":"I","\u0419":"Y","\u041a":"K","\u041b":"L",
  "\u041c":"M","\u041d":"H","\u041e":"O","\u041f":"P","\u0420":"P","\u0421":"C",
  "\u0422":"T","\u0423":"Y","\u0424":"F","\u0425":"X","\u0426":"Ts","\u0427":"Ch",
  "\u0428":"Sh","\u0429":"Shch","\u042a":"Hard","\u042b":"Y","\u042c":"Soft",
  "\u042d":"E","\u042e":"Yu","\u042f":"Ya",
  // Greek lowercase
  "\u03b1":"a","\u03b2":"b","\u03b3":"g","\u03b4":"d","\u03b5":"e","\u03b6":"z",
  "\u03b7":"h","\u03b8":"th","\u03b9":"i","\u03ba":"k","\u03bb":"l","\u03bc":"m",
  "\u03bd":"n","\u03be":"x","\u03bf":"o","\u03c0":"p","\u03c1":"r","\u03c2":"s",
  "\u03c3":"s","\u03c4":"t","\u03c5":"u","\u03c6":"ph","\u03c7":"ch","\u03c8":"ps",
  "\u03c9":"o",
  // Greek uppercase
  "\u0391":"A","\u0392":"B","\u0393":"G","\u0394":"D","\u0395":"E","\u0396":"Z",
  "\u0397":"H","\u0398":"Th","\u0399":"I","\u039a":"K","\u039b":"L","\u039c":"M",
  "\u039d":"N","\u039e":"X","\u039f":"O","\u03a0":"P","\u03a1":"P","\u03a3":"S",
  "\u03a4":"T","\u03a5":"Y","\u03a6":"Ph","\u03a7":"X","\u03a8":"Ps","\u03a9":"O",
  // Fullwidth digits
  "０":"0","１":"1","２":"2","３":"3","４":"4","５":"5","６":"6","７":"7","８":"8","９":"9",
  // Fullwidth letters
  "Ａ":"A","Ｂ":"B","Ｃ":"C","Ｄ":"D","Ｅ":"E","Ｆ":"F","Ｇ":"G","Ｈ":"H","Ｉ":"I","Ｊ":"J",
  "Ｋ":"K","Ｌ":"L","Ｍ":"M","Ｎ":"N","Ｏ":"O","Ｐ":"P","Ｑ":"Q","Ｒ":"R","Ｓ":"S","Ｔ":"T",
  "Ｕ":"U","Ｖ":"V","Ｗ":"W","Ｘ":"X","Ｙ":"Y","Ｚ":"Z",
  // Latin special lookalikes
  "\u0251":"a","\u0261":"g","\u0285":"r","\u029c":"H","\u0131":"i","\u017f":"s",
  "\u2113":"l","\u2116":"N",
  // Dashes → hyphen
  "\u2013":"-","\u2014":"-","\u2015":"-","\u2012":"-","\u2010":"-","\u2011":"-","\u2212":"-",
  // Quotes
  "\u2018":"'","\u2019":"'","\u201a":"'","\u201b":"'",
  "\u201c":'"',"\u201d":'"',"\u201e":'"',"\u201f":'"',
  "\u00ab":'"',"\u00bb":'"',"\u2039":"'",'\u203a':"'",
  // Underscore / slash
  "\uff3f":"_","\u2044":"/","\u2215":"/",
  // Unicode letters that look like ASCII
  "\u1d05":"a","\u1d07":"e","\u029f":"l","\u026a":"i",
  "\u1d1c":"u","\u028f":"y","\u1d22":"z",
};

const LEET_MAP: Record<string, string> = {
  "@":"a","4":"a","!":"i","|":"i","1":"i","0":"o","3":"e","€":"e",
  "5":"s","$":"s","7":"t","+":"t","8":"b",
};

function stripZeroWidth(s: string): string { return s.replace(ZERO_WIDTH, ""); }

function homoglyph(s: string): string {
  let out = "";
  for (const ch of s) out += HOMOGLYPH_MAP[ch] ?? ch;
  return out;
}

function deLeet(s: string): string {
  let out = "";
  for (const ch of s) { const lower = ch.toLowerCase(); out += LEET_MAP[lower] ?? ch; }
  return out;
}

function compressDelimiters(s: string): string { return s.replace(/[^\w]/g, ""); }

const BASE64_RE = /^[A-Za-z0-9+/=]{12,}$/;
function tryBase64Decode(s: string, depth = 0, acc: string[] = []): { text: string; decoded: string[] } {
  if (depth >= 3) return { text: s, decoded: acc };
  const tokens = s.split(/\s+/);
  let changed = false;
  const next = tokens.map((tok) => {
    if (!BASE64_RE.test(tok)) return tok;
    try {
      const decoded = typeof atob !== "undefined" ? atob(tok) : Buffer.from(tok, "base64").toString("utf-8");
      if (/^[\x20-\x7e\s]+$/.test(decoded) && decoded.length > 2) { changed = true; acc.push(decoded); return decoded; }
    } catch (e) { void e; }
    return tok;
  });
  const joined = next.join(" ");
  return changed ? tryBase64Decode(joined, depth + 1, acc) : { text: joined, decoded: acc };
}

// ---------- PII patterns ----------

export interface PatternDef { type: string; re: RegExp; severity: "low" | "medium" | "high" | "critical"; }

export const PII_PATTERNS: PatternDef[] = [
  { type: "AADHAAR", re: /\b\d{3,4}[\s.\-_/—–]{0,3}\d{4}[\s.\-_/—–]{0,3}\d{4}\b/g, severity: "critical" },
  { type: "PAN", re: /(?<![a-zA-Z0-9])[\.]?[a-zA-Z]{5}[\. \-_]?[0-9]{4}[\. \-_]?[a-zA-Z]{1}[\.]?(?![a-zA-Z0-9])/gi, severity: "critical" },
  { type: "DRIVING_LICENSE", re: /\b[A-Z]{2}[\s.\-_/—–]?\d{2}[\s.\-_/—–]?\d{4}[\s.\-_/—–]?\d{7}\b/g, severity: "high" },
  { type: "GSTIN", re: /\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}\b/g, severity: "high" },
  { type: "PASSPORT_IN", re: /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/g, severity: "critical" },
  { type: "EMAIL", re: /(?:"[^"]*"|\([^)]*\)|[A-Za-z0-9._%+-]+)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, severity: "low" },
  { type: "UPI", re: /\b[\w.\-+]{2,}@(okicici|okhdfcbank|oksbi|okaxis|okbob|ybl|paytm|icici|icicibank|hdfc|hdfcbank|bob|upi|kvb|dbs|federal|axis|axisbank|pnb|canara|indianbank|unionbank|iob|karurvyasa|city|standardchartered|kotak|kotakbank|yesbank|yes|googlepay|gpay|phonepe|amazonpay|msidbi|jio|airtel|vi|bsnl)\b/gi, severity: "medium" },
  { type: "CREDIT_CARD", re: /\b(?:\d[\s.\-—–/]*?){13,16}\b/g, severity: "critical" },
  { type: "API_KEY", re: /\b(?:sk|pk|rk)_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b/g, severity: "critical" },
  { type: "PHONE_IN", re: /(?:\(?\+?91\)?[\s.\-]?)?\(?0\)?[\s.\-]?[6-9]\d{4}[\s.\-]?\d{5}/g, severity: "medium" },
];

const BLOCK_TYPES = new Set(["AADHAAR", "PAN", "PASSPORT_IN", "CREDIT_CARD", "API_KEY"]);

function findHits(text: string, rawText?: string): PIIHit[] {
  const hits: PIIHit[] = [];
  for (const p of PII_PATTERNS) {
    p.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(text)) !== null) {
      hits.push({ type: p.type, value: m[0], start: m.index, end: m.index + m[0].length });
    }
  }

  const src = text; // use normalized text for extraction, not raw

  // Aadhaar: 12 consecutive digits
  if (!hits.some(h => h.type === "AADHAAR")) {
    const digitsOnly = src.replace(/\D/g, "");
    if (digitsOnly.length === 12) {
      hits.push({ type: "AADHAAR", value: digitsOnly, start: -1, end: -1 });
    }
  }

  // PAN: strip non-alphanumeric from normalized text, look for 5L+4D+1L
  if (!hits.some(h => h.type === "PAN")) {
    const stripped = src.replace(/[^A-Za-z0-9]/g, "");
    const panMatch = stripped.match(/[A-Za-z]{5}\d{4}[A-Za-z]{1}/);
    if (panMatch) {
      hits.push({ type: "PAN", value: panMatch[0].toUpperCase(), start: -1, end: -1 });
    }
  }

  // Phone: must be ONLY digits and phone separators, no letters at all
  if (!hits.some(h => h.type === "PHONE_IN")) {
    const hasLetters = /[a-zA-Z\u0400-\u04FF\u0370-\u03FF]/.test(src);
    if (!hasLetters) {
      const digitsOnly = src.replace(/\D/g, "");
      const phoneMatch = digitsOnly.match(/(?:91|0091)?([6-9]\d{9})/);
      if (phoneMatch && phoneMatch[1].length === 10) {
        hits.push({ type: "PHONE_IN", value: phoneMatch[0], start: -1, end: -1 });
      }
    }
  }

  // Driving License: allow O→0 substitution for DL detection
  if (!hits.some(h => h.type === "DRIVING_LICENSE")) {
    const dlText = src.replace(/[Oo]/g, "0");
    const stripped = dlText.replace(/[^A-Za-z0-9]/g, "");
    const dlMatch = stripped.match(/[A-Z]{2}\d{2}\d{4}\d{7}/i);
    if (dlMatch) {
      hits.push({ type: "DRIVING_LICENSE", value: dlMatch[0].toUpperCase(), start: -1, end: -1 });
    }
  }

  // Email: handle spaced-out emails
  if (!hits.some(h => h.type === "EMAIL")) {
    const noSpaces = src.replace(/\s/g, "");
    const emailMatch = noSpaces.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
    if (emailMatch) {
      hits.push({ type: "EMAIL", value: emailMatch[0], start: -1, end: -1 });
    }
  }

  return hits;
}

function redactRaw(raw: string, normHits: PIIHit[]): { redacted: string; types: string[] } {
  let redacted = raw;
  const types = new Set<string>();

  // First pass: replace patterns that match directly in raw text
  for (const p of PII_PATTERNS) {
    redacted = redacted.replace(p.re, () => { types.add(p.type); return `[${p.type}]`; });
  }

  // Second pass: replace normalization-only hits by finding their value in raw text
  for (const h of normHits) {
    if (types.has(h.type)) continue;
    types.add(h.type);
    if (h.start >= 0) {
      // Hit came from a specific match in normalized text — skip direct replacement
      continue;
    }
    // Try to find the value (or a variant) in the raw text and replace
    const val = h.value;
    // Try exact match first, then case-insensitive, then with flexible separators
    const patterns = [
      new RegExp(val.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"),
      new RegExp(val.replace(/(.)/g, "$1[\\s.\\-_—–/]*"), "i"),
    ];
    for (const pat of patterns) {
      if (pat.test(redacted)) {
        redacted = redacted.replace(pat, `[${h.type}]`);
        break;
      }
    }
  }

  // If any types were detected but not yet represented in redacted text, append marker
  const missingTypes = [...types].filter(t => !redacted.includes(`[${t}]`));
  if (missingTypes.length) {
    redacted = `${redacted} ⟪evasion-normalized: ${missingTypes.map(t => `[${t}]`).join(" ")}⟫`;
  }

  return { redacted, types: Array.from(types) };
}

export function runPipeline(raw: string): PipelineResult {
  const t0 = performance.now();
  const steps: PipelineStep[] = [{ name: "Raw input", output: raw }];

  const s1 = stripZeroWidth(raw);
  steps.push({ name: "Zero-width stripped", output: s1, note: s1 !== raw ? "Removed invisible chars" : "no-op" });

  const s2 = homoglyph(s1);
  steps.push({ name: "Homoglyph normalized", output: s2, note: s2 !== s1 ? "Mapped lookalikes" : "no-op" });

  const s3 = deLeet(s2);
  steps.push({ name: "De-leeted", output: s3, note: s3 !== s2 ? "Translated leetspeak" : "no-op" });

  const { text: s4, decoded } = tryBase64Decode(s3);
  steps.push({ name: "Base64 recursively decoded", output: s4, note: decoded.length ? `Decoded ${decoded.length} layer(s)` : "no-op" });

  const s5 = compressDelimiters(s4);
  steps.push({ name: "Delimiters compressed", output: s5, note: "Stripped all non-alphanumeric chars" });

  const hits = [...findHits(s2, raw), ...findHits(s3), ...findHits(s4), ...findHits(s5)];
  const seen = new Set<string>();
  const uniqHits = hits.filter((h) => { const k = `${h.type}:${h.value}`; if (seen.has(k)) return false; seen.add(k); return true; });

  const { redacted, types } = redactRaw(raw, uniqHits);
  const triggered = types;
  const shouldBlock = triggered.some((t) => BLOCK_TYPES.has(t));
  const action: Action = triggered.length === 0 ? "allow" : shouldBlock ? "block" : "redact";
  const latencyMs = +(performance.now() - t0).toFixed(2);

  return { raw, normalized: s5, steps, hits: uniqHits, redactedPrompt: action === "allow" ? raw : redacted, action, triggeredPatterns: triggered, latencyMs, base64Decoded: decoded };
}

export function hashOrigin(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) { h ^= input.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
  return h.toString(16).padStart(8, "0");
}
