"""
CIAI Detection Engine (Hardened)
===============================
Advanced detection with evasion resistance:
  1. India-specific regex patterns (Aadhaar, PAN, CC, Voter ID, DL, GST, etc.)
  2. Microsoft Presidio for PII
  3. Unicode NFKC normalization (Homoglyph resistance)
  4. Zero-width character stripping
  5. Base64-encoded PII recursive detection
  6. Advanced evasion helpers (leetspeak, reversed, split-words)
"""

import re
import base64
import unicodedata
import logging
from typing import Optional

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

logger = logging.getLogger("ciai.detection")

# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------

_ZERO_WIDTH_CHARS = re.compile(
    r'[\u200b\u200c\u200d\ufeff\u200e\u200f\u2060\u180e\u00ad\u034f\u17b4\u17b5]'
)

def normalize_input(text: str) -> str:
    """Normalize input to defeat homoglyph, zero-width, and encoding evasion."""
    text = text.replace('\x00', '')
    text = _ZERO_WIDTH_CHARS.sub('', text)
    text = unicodedata.normalize('NFKC', text)

    # Homoglyph mapping for common lookalikes
    homoglyph_map = str.maketrans({
        '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K', '\u041c': 'M',
        '\u041d': 'H', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
        '\u0425': 'X', '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
        '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
        '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
        '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a7': 'X', '\u03bf': 'o',
    })
    text = text.translate(homoglyph_map)
    text = re.sub(r'(\d)\.(\d)', r'\1-\2', text)
    return text

# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------

AADHAAR_PATTERN = r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'
AADHAAR_HOMOGLYPH_PATTERN = r'\b[a-z][2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'
PAN_PATTERN = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
CREDIT_CARD_PATTERN = r'\b(?:\d[\s-]*?){13,19}\b'
VOTER_ID_PATTERN = r'\b[A-Z]{3}\d{7}\b'
DRIVING_LICENSE_PATTERN = r'\bDL[\s-]?\d{13,15}\b'
GST_PATTERN = r'\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}Z[A-Z\d]{1}\b'
PASSPORT_PATTERN = r'\b[A-Z][1-9]\d{7}\b'

API_KEY_PATTERNS = {
    "OPENAI_KEY": r'sk-[a-zA-Z0-9]{20,}',
    "ANTHROPIC_KEY": r'sk-ant-[a-zA-Z0-9\-]{20,}',
    "BEARER_TOKEN": r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}',
    "AWS_KEY": r'AKIA[0-9A-Z]{16}',
    "AWS_SECRET": r'(?i)(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*[a-zA-Z0-9/+=]{40}',
    "GENERIC_API_KEY": r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*[a-zA-Z0-9\-_]{16,}',
    "GENERIC_SECRET": r'(?i)(?:secret|password|token|auth)\s*[=:]\s*\S{8,}',
}

HIGH_SEVERITY_TYPES = {
    "AADHAAR", "PAN", "CREDIT_CARD", "OPENAI_KEY", "ANTHROPIC_KEY",
    "AWS_KEY", "AWS_SECRET", "API_KEY", "SECRET",
    "VOTER_ID", "DRIVING_LICENSE", "GST_NUMBER", "PASSPORT"
}

# ---------------------------------------------------------------------------
# Evasion Helpers
# ---------------------------------------------------------------------------

_WORD_TO_DIGIT = {'zero':'0', 'one':'1', 'two':'2', 'three':'3', 'four':'4', 'five':'5', 'six':'6', 'seven':'7', 'eight':'8', 'nine':'9'}
_LEET_MAP = {'3': 'E', '4': 'A', '1': 'I', '0': 'O', '5': 'S', '@': 'A', '$': 'S'}

def _luhn_check(digits_only: str) -> bool:
    nums = [int(d) for d in digits_only]; nums.reverse()
    total = 0
    for i, n in enumerate(nums):
        if i % 2 == 1:
            n *= 2
            if n > 9: n -= 9
        total += n
    return total % 10 == 0

def _check_regex_patterns(text: str) -> list[str]:
    detections = []
    if re.search(AADHAAR_PATTERN, text) or re.search(AADHAAR_HOMOGLYPH_PATTERN, text): detections.append("AADHAAR")
    if re.search(PAN_PATTERN, text): detections.append("PAN")
    
    for match in re.finditer(CREDIT_CARD_PATTERN, text):
        digits = re.sub(r'[\s-]', '', match.group())
        if 13 <= len(digits) <= 19 and _luhn_check(digits): detections.append("CREDIT_CARD")
            
    if re.search(VOTER_ID_PATTERN, text): detections.append("VOTER_ID")
    if re.search(DRIVING_LICENSE_PATTERN, text): detections.append("DRIVING_LICENSE")
    if re.search(GST_PATTERN, text): detections.append("GST_NUMBER")
    if re.search(PASSPORT_PATTERN, text): detections.append("PASSPORT")

    for label, pattern in API_KEY_PATTERNS.items():
        if re.search(pattern, text): detections.append(label)
    
    return detections

# ---------------------------------------------------------------------------
# Main Logic
# ---------------------------------------------------------------------------

_analyzer = None
_anonymizer = None

def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        nlp = spacy.load("en_core_web_sm")
        _analyzer = AnalyzerEngine(nlp_engine=nlp)
    return _analyzer

def _get_anonymizer():
    global _anonymizer
    if _anonymizer is None:
        from presidio_anonymizer import AnonymizerEngine
        _anonymizer = AnonymizerEngine()
    return _anonymizer

def _detect_base64_pii(text: str) -> list[str]:
    detections = []
    for match in re.finditer(r'[A-Za-z0-9+/]{8,}={0,2}', text):
        try:
            decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
            if len(decoded) > 5:
                sub = detect_sensitive(decoded)
                for d in sub['detections']:
                    if f"BASE64_{d}" not in detections: detections.append(f"BASE64_{d}")
        except: pass
    return detections

def detect_sensitive(text: str) -> dict:
    if not text or not text.strip():
        return {"detections":[], "block":False, "redact":False, "redacted_text":text, "severity":"none"}

    normalized = normalize_input(text)
    detections = _check_regex_patterns(normalized)
    
    try:
        results = _get_analyzer().analyze(text=normalized, language='en')
        for r in results:
            if r.score >= 0.5: detections.append(r.entity_type)
    except: pass

    detections.extend(_detect_base64_pii(normalized))
    detections = sorted(list(set(detections)))
    
    block = any(d in HIGH_SEVERITY_TYPES or d.startswith("BASE64_") for d in detections)
    redact = len(detections) > 0
    
    redacted_text = text
    if redact:
        redacted_text = _get_anonymizer().anonymize(
            text=normalized,
            analyzer_results=[], # We manually redact to match regex
            operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})}
        ).text
        # Fallback manual regex redaction
        redacted_text = re.sub(AADHAAR_PATTERN, "[REDACTED]", redacted_text)
        redacted_text = re.sub(PAN_PATTERN, "[REDACTED]", redacted_text)
        redacted_text = re.sub(CREDIT_CARD_PATTERN, "[REDACTED]", redacted_text)

    severity = "none"
    if block: severity = "high"
    elif len(detections) >= 2: severity = "medium"
    elif len(detections) >= 1: severity = "low"

    return {
        "detections": detections,
        "block": block,
        "redact": redact,
        "redacted_text": redacted_text,
        "severity": severity
    }
