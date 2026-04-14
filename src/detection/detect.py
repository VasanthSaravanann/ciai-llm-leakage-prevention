"""
CIAI Detection Engine
====================
Detects sensitive data in text using:
  1. India-specific regex patterns (Aadhaar, PAN, Credit Card, API keys, Voter ID, DL, GST, UPI, Passport)
  2. Microsoft Presidio for PII (names, emails, phones, locations, etc.)
  3. Unicode normalization (NFKC) to defeat homoglyph attacks
  4. Zero-width character stripping
  5. Base64-encoded PII detection

Returns detection results with block/redact decisions and redacted text.
"""

import re
import base64
import unicodedata
from typing import Optional

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ---------------------------------------------------------------------------
# Input normalization (Critical: VULN-001, VULN-002)
# ---------------------------------------------------------------------------

# Zero-width and invisible characters to strip
_ZERO_WIDTH_CHARS = re.compile(
    r'[\u200b\u200c\u200d\ufeff\u200e\u200f\u2060\u180e\u00ad\u034f\u17b4\u17b5]'
)


def normalize_input(text: str) -> str:
    """
    Normalize input to defeat homoglyph, zero-width, and encoding evasion.

    Steps:
    1. Strip null bytes
    2. Strip zero-width/invisible characters
    3. NFKC normalization (fullwidth digits→ASCII, Cyrillic homoglyphs→Latin)
    4. Normalize dot separators in digit sequences

    Returns normalized text safe for regex scanning.
    """
    # Strip null bytes (VULN-016)
    text = text.replace('\x00', '')

    # Strip zero-width characters (VULN-002)
    text = _ZERO_WIDTH_CHARS.sub('', text)

    # NFKC normalization — converts homoglyphs to ASCII equivalents (VULN-001)
    # Cyrillic А (U+0410) stays Cyrillic, but fullwidth digits (U+FF12) → ASCII '2'
    # Compatibility decomposition catches most evasion attempts
    text = unicodedata.normalize('NFKC', text)

    # Additional homoglyph mapping for common Cyrillic + Greek lookalikes
    # that NFKC doesn't normalize (they're valid chars, not compatibility)
    homoglyph_map = str.maketrans({
        # Cyrillic
        '\u0410': 'A',  # Cyrillic А → Latin A
        '\u0412': 'B',  # Cyrillic В → Latin B
        '\u0415': 'E',  # Cyrillic Е → Latin E
        '\u041a': 'K',  # Cyrillic К → Latin K
        '\u041c': 'M',  # Cyrillic М → Latin M
        '\u041d': 'H',  # Cyrillic Н → Latin H
        '\u041e': 'O',  # Cyrillic О → Latin O
        '\u0420': 'P',  # Cyrillic Р → Latin P
        '\u0421': 'C',  # Cyrillic С → Latin C
        '\u0422': 'T',  # Cyrillic Т → Latin T
        '\u0425': 'X',  # Cyrillic Х → Latin X
        '\u0430': 'a',  # Cyrillic а → Latin a
        '\u0435': 'e',  # Cyrillic е → Latin e
        '\u043e': 'o',  # Cyrillic о → Latin o
        '\u0440': 'p',  # Cyrillic р → Latin p
        '\u0441': 'c',  # Cyrillic с → Latin c
        '\u0443': 'y',  # Cyrillic у → Latin y
        '\u0445': 'x',  # Cyrillic х → Latin x
        # Greek lookalikes
        '\u0391': 'A',  # Greek Α → Latin A
        '\u0392': 'B',  # Greek Β → Latin B
        '\u0395': 'E',  # Greek Ε → Latin E
        '\u0396': 'Z',  # Greek Ζ → Latin Z
        '\u0397': 'H',  # Greek Η → Latin H
        '\u0399': 'I',  # Greek Ι → Latin I
        '\u039a': 'K',  # Greek Κ → Latin K
        '\u039c': 'M',  # Greek М → Latin M
        '\u039d': 'N',  # Greek Ν → Latin N
        '\u039f': 'O',  # Greek Ο → Latin O
        '\u03a1': 'P',  # Greek Ρ → Latin P
        '\u03a4': 'T',  # Greek Τ → Latin T
        '\u03a7': 'X',  # Greek Χ → Latin X
        '\u03bf': 'o',  # Greek ο → Latin o (VULN-001: Greek digit lookalike)
        '\u03b5': 'e',  # Greek ε → Latin e
    })
    text = text.translate(homoglyph_map)

    # Normalize dot separators in digit sequences (VULN-008)
    text = re.sub(r'(\d)\.(\d)', r'\1-\2', text)

    return text


# ---------------------------------------------------------------------------
# India-specific regex patterns
# ---------------------------------------------------------------------------

# Aadhaar: 12 digits, commonly formatted as XXXX-XXXX-XXXX, XXXX XXXX XXXX, or XXXXXXXXXXXX
# First digit is 2-9 (valid Aadhaar range)
# Also matches when preceded by a single letter (homoglyph normalization artifact)
# Aadhaar: 12 digits, first digit is 2-9 (valid Aadhaar range)
# Format: 4-4-4 digits with optional spaces/dashes
AADHAAR_PATTERN = r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'
AADHAAR_HOMOGLYPH_PATTERN = r'\b[a-z][2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'

# PAN: 5 uppercase letters + 4 digits + 1 uppercase letter
# e.g., ABCDE1234F
PAN_PATTERN = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'

# Credit card: 13-19 digits, possibly with spaces or dashes
CREDIT_CARD_PATTERN = r'\b(?:\d[\s-]*?){13,19}\b'

# India-specific PII (VULN-007)
# Voter ID (EPIC): 3 letters + 7 digits
VOTER_ID_PATTERN = r'\b[A-Z]{3}\d{7}\b'

# Driving License: DL followed by 14-15 digits (varies by state)
# Handles: DL-0420110012345, DL0420110012345, DL 0420110012345
DRIVING_LICENSE_PATTERN = r'\bDL[\s-]?\d{13,15}\b'

# GST Number: 2 digits + 5 alphanumeric + 4 digits + 1 alphanumeric + Z + 1 alphanumeric
GST_PATTERN = r'\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}Z[A-Z\d]{1}\b'

# Passport (Indian): 1 letter + 1 digit (1-9) + 7 digits
PASSPORT_PATTERN = r'\b[A-Z][1-9]\d{7}\b'

# UPI ID: alphanumeric with dots/hyphens @ 2-6 letter provider
UPI_ID_PATTERN = r'\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,6}\b'

# US SSN (for completeness): XXX-XX-XXXX
SSN_PATTERN = r'\b\d{3}-\d{2}-\d{4}\b'

# Email regex fallback (Presidio may miss standalone emails)
EMAIL_PATTERN = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'

# Phone regex fallback (Presidio may miss standalone phones)
# Indian: +91 XXXXX XXXXX, XXXXX XXXXX, 0XXXXXXXXXX
# International: +X XXX XXX XXXX
# Restrictive to avoid false positives on long digit strings
PHONE_PATTERN = r'(?:\+91[\s-]?)[6-9]\d{4}[\s-]?\d{5}|\+\d{1,3}[\s-]\d{3,4}[\s-]\d{3,4}[\s-]\d{4}'

# API keys and tokens
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
    # India-specific (VULN-007)
    "VOTER_ID", "DRIVING_LICENSE", "GST_NUMBER", "PASSPORT",
    # US
    "US_SSN",
}


def _luhn_check(digits_only: str) -> bool:
    """Validate a number string using the Luhn algorithm."""
    nums = [int(d) for d in digits_only]
    nums.reverse()
    total = 0
    for i, n in enumerate(nums):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _check_credit_cards(text: str) -> list[str]:
    """Find credit card numbers and validate with Luhn check."""
    found = []
    for match in re.finditer(CREDIT_CARD_PATTERN, text):
        candidate = match.group()
        digits = re.sub(r'[\s-]', '', candidate)
        if len(digits) >= 13 and len(digits) <= 19 and _luhn_check(digits):
            found.append("CREDIT_CARD")
    return found


def _check_regex_patterns(text: str) -> list[str]:
    """Run all regex patterns against the text. Input should already be normalized."""
    detections = []

    # Aadhaar - additional check: must not be repeating digits like 4444 4444 4444 (VULN-CC-CLASH)
    for match in re.finditer(AADHAAR_PATTERN, text):
        candidate = match.group()
        digits = re.sub(r'[\s-]', '', candidate)
        if len(set(digits)) > 1: # Basic heuristic to avoid fake sequences like 4444...
            detections.append("AADHAAR")
        elif candidate in text: # If it WAS actually intended as Aadhaar
             pass

    # Aadhaar with homoglyph prefix (Greek ο→o before digits)
    if re.search(AADHAAR_HOMOGLYPH_PATTERN, text):
        if "AADHAAR" not in detections:
            detections.append("AADHAAR")

    # Aadhaar spelled out as words (bypass #2)
    if _detect_aadhaar_words(text):
        if "AADHAAR" not in detections:
            detections.append("AADHAAR")

    # Aadhaar with extra spaces between digits (OCR noise, bypass #8)
    if _detect_spaced_aadhaar(text):
        if "AADHAAR" not in detections:
            detections.append("AADHAAR")

    # Aadhaar embedded in larger number (bypass #7) - extract 12-digit substrings
    if _detect_embedded_aadhaar(text):
        if "AADHAAR" not in detections:
            detections.append("AADHAAR")

    # PAN
    if re.search(PAN_PATTERN, text):
        detections.append("PAN")

    # Reversed PAN (bypass #3)
    if _detect_reversed_pan(text):
        if "PAN" not in detections:
            detections.append("PAN")

    # PAN with leetspeak (bypass #1) - E→3, S→5, etc.
    if _detect_leetspeak_pan(text):
        if "PAN" not in detections:
            detections.append("PAN")

    # PAN split across words (bypass #9)
    if _detect_split_pan(text):
        if "PAN" not in detections:
            detections.append("PAN")

    # Incomplete PAN detection (bypass #6) - 9+ char PAN-like strings
    if _detect_incomplete_pan(text):
        if "PAN" not in detections:
            detections.append("PAN")

    # Partial Aadhaar (bypass #4, #5) - first 4 or last 4 digits near "aadhaar" keyword
    if _detect_partial_aadhaar(text):
        if "AADHAAR" not in detections:
            detections.append("AADHAAR")

    for match in re.finditer(CREDIT_CARD_PATTERN, text):
        digits = re.sub(r'[\s-]', '', match.group())
        if 13 <= len(digits) <= 19 and _luhn_check(digits):
            detections.append("CREDIT_CARD")

    # India-specific PII (VULN-007)
    if re.search(VOTER_ID_PATTERN, text):
        detections.append("VOTER_ID")

    if re.search(DRIVING_LICENSE_PATTERN, text):
        detections.append("DRIVING_LICENSE")

    if re.search(GST_PATTERN, text):
        detections.append("GST_NUMBER")

    if re.search(PASSPORT_PATTERN, text):
        detections.append("PASSPORT")

    # US SSN
    if re.search(SSN_PATTERN, text):
        detections.append("US_SSN")

    # Email fallback (when Presidio misses standalone emails)
    if re.search(EMAIL_PATTERN, text):
        detections.append("EMAIL_ADDRESS")

    # Phone fallback (when Presidio misses standalone phones)
    if re.search(PHONE_PATTERN, text):
        detections.append("PHONE_NUMBER")

    # API keys
    for label, pattern in API_KEY_PATTERNS.items():
        if re.search(pattern, text):
            detections.append(label)

    # API key split across lines (bypass #10)
    if _detect_split_api_key(text):
        if "OPENAI_KEY" not in detections:
            detections.append("OPENAI_KEY")

    # Secret concatenation (bypass #11)
    if _detect_concatenated_secret(text):
        if "SECRET" not in detections:
            detections.append("SECRET")

    return detections


# ---------------------------------------------------------------------------
# Advanced evasion detection helpers
# ---------------------------------------------------------------------------

_WORD_TO_DIGIT = {
    'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
    'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9',
}


def _detect_aadhaar_words(text: str) -> bool:
    """Detect Aadhaar spelled out as English number words (bypass #2)."""
    words = text.lower().split()
    digit_words = [_WORD_TO_DIGIT.get(w) for w in words]
    digit_words = [d for d in digit_words if d is not None]
    if len(digit_words) >= 12:
        # Check for 12 consecutive digit words
        for i in range(len(digit_words) - 11):
            candidate = ''.join(digit_words[i:i+12])
            if candidate[0] in '23456789':
                return True
    return False


def _detect_spaced_aadhaar(text: str) -> bool:
    """Detect Aadhaar with spaces between each digit (bypass #8)."""
    # Match 12 digits separated by spaces: "2 3 4 5 6 7 8 9 0 1 2 3"
    spaced = re.search(r'\b([2-9])\s+(\d)\s+(\d)\s+(\d)\s+(\d)\s+(\d)\s+(\d)\s+(\d)\s+(\d)\s+(\d)\s+(\d)\s+(\d)\b', text)
    if spaced:
        return True
    return False


def _detect_embedded_aadhaar(text: str) -> bool:
    """Detect Aadhaar digits embedded in a larger number (bypass #7)."""
    # Look for "aadhaar" keyword followed by a long digit sequence
    if re.search(r'(?i)aadhaar', text):
        # Extract all digit substringes of 12+ digits
        for match in re.finditer(r'\d{12,}', text):
            digits = match.group()
            # Check every 12-digit window
            for i in range(len(digits) - 11):
                sub = digits[i:i+12]
                if sub[0] in '23456789':
                    return True
    return False


def _detect_reversed_pan(text: str) -> bool:
    """Detect PAN reversed (bypass #3)."""
    # Reverse all words and check PAN pattern
    words = text.split()
    for word in words:
        reversed_word = word[::-1]
        if re.match(r'^[A-Z]{5}\d{4}[A-Z]$', reversed_word):
            return True
    return False


_LEET_MAP = {'3': 'E', '4': 'A', '1': 'I', '0': 'O', '5': 'S', '@': 'A', '$': 'S'}


def _detect_leetspeak_pan(text: str) -> bool:
    """Detect PAN with leetspeak substitutions (bypass #1).

    Strategy: For 10-char words, check if there are digits in letter positions
    (0-4, 9) that look like leetspeak (3→E, 4→A, etc.).

    This catches BOTH uppercase leetspeak (ABCD31234F) and mixed-case.
    Plain lowercase (abcde1234f) without digit substitutions is NOT detected
    — that's the original design decision requiring uppercase for PAN.
    """
    words = text.split()
    for word in words:
        if len(word) != 10:
            continue

        # Skip plain lowercase words without leet chars
        # (abcde1234f is just lowercase, not leetspeak)
        chars = list(word)
        letter_positions = list(range(5)) + [9]

        # Check if there's a digit in a letter position (leetspeak indicator)
        has_digit_in_letter_pos = any(chars[i].isdigit() for i in letter_positions)
        if not has_digit_in_letter_pos:
            continue

        # PAN format: LLLLLDDDDL — check with leet mapping
        upper_chars = [c.upper() for c in chars]
        letter_part = ''.join(_LEET_MAP.get(upper_chars[i], upper_chars[i]) for i in range(5))
        digit_part = ''.join(upper_chars[5:9])
        last_char = _LEET_MAP.get(upper_chars[9], upper_chars[9])

        if (re.match(r'^[A-Z]{5}$', letter_part) and
                re.match(r'^\d{4}$', digit_part) and
                re.match(r'^[A-Z]$', last_char)):
            return True
    return False


def _detect_split_pan(text: str) -> bool:
    """Detect PAN split across multiple words (bypass #9)."""
    # Look for consecutive words that concatenate to form a PAN
    words = text.split()
    # Check pairs of words
    for i in range(len(words) - 1):
        combined = words[i] + words[i+1]
        if re.match(r'^[A-Z]{5}\d{4}[A-Z]$', combined.upper()):
            return True
        # Check triplets
        if i + 2 < len(words):
            combined3 = words[i] + words[i+1] + words[i+2]
            if re.match(r'^[A-Z]{5}\d{4}[A-Z]$', combined3.upper()):
                return True
    return False


def _detect_incomplete_pan(text: str) -> bool:
    """Detect incomplete/partial PAN (9-10 chars) (bypass #6)."""
    # Match PAN-like strings missing the last character — uppercase only
    if re.search(r'\b[A-Z]{5}\d{4}\b', text):
        return True
    return False


def _detect_partial_aadhaar(text: str) -> bool:
    """Detect partial Aadhaar references (first 4 / last 4 digits) (bypass #4, #5)."""
    # Only trigger if "aadhaar" keyword is nearby
    if not re.search(r'(?i)aadhaar', text):
        return False
    # First 4 digits: "aadhaar starts with 2345"
    if re.search(r'(?i)aadhaar.*\b(?:starts|begins|first).*?\b([2-9]\d{3})\b', text):
        return True
    # Last 4 digits: "aadhaar ends with 0123"
    if re.search(r'(?i)aadhaar.*\b(?:ends|last).*?\b(\d{4})\b', text):
        return True
    return False


def _detect_split_api_key(text: str) -> bool:
    """Detect API key split across string concatenation (bypass #10)."""
    # Look for string literals that when concatenated form an API key
    # Pattern: 'sk-...' + '...'
    string_parts = re.findall(r"['\"]([^'\"]+)['\"]", text)
    if len(string_parts) >= 2:
        combined = ''.join(string_parts)
        if re.match(r'sk-[a-zA-Z0-9]{20,}', combined):
            return True
    return False


def _detect_concatenated_secret(text: str) -> bool:
    """Detect secret split by string concatenation (bypass #11)."""
    # Pattern: 'part1' + 'part2' where combined forms a secret
    if re.search(r"(?:secret|password)\s*[=:]\s*['\"]", text, re.IGNORECASE):
        string_parts = re.findall(r"['\"]([^'\"]+)['\"]", text)
        if len(string_parts) >= 2:
            combined = ''.join(string_parts)
            if len(combined) >= 8:
                return True
    return False


# ---------------------------------------------------------------------------
# Presidio integration
# ---------------------------------------------------------------------------

# Lazy-load Presidio engines to avoid startup overhead
_analyzer: Optional[AnalyzerEngine] = None
_anonymizer: Optional[AnonymizerEngine] = None


def _get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        import spacy
        # Use the small model (13MB) instead of the large one (400MB)
        nlp = spacy.load("en_core_web_sm")
        _analyzer = AnalyzerEngine(nlp_engine=nlp)
    return _analyzer


def _get_anonymizer() -> AnonymizerEngine:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


def _run_presidio(text: str) -> list[RecognizerResult]:
    """Run Presidio NER analysis on text."""
    try:
        analyzer = _get_analyzer()
        return analyzer.analyze(text=text, language='en')
    except Exception:
        return []


def _redact_text(text: str, presidio_results: list[RecognizerResult]) -> str:
    """Redact sensitive text using Presidio results + regex patterns."""
    anonymizer = _get_anonymizer()

    # Presidio-based redaction
    redacted = anonymizer.anonymize(
        text=text,
        analyzer_results=presidio_results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})}
    ).text

    # Additional regex-based redaction for India-specific patterns
    redacted = re.sub(AADHAAR_PATTERN, "[REDACTED]", redacted)
    redacted = re.sub(PAN_PATTERN, "[REDACTED]", redacted)
    redacted = re.sub(CREDIT_CARD_PATTERN, "[REDACTED]", redacted)
    for pattern in API_KEY_PATTERNS.values():
        redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)

    return redacted


# ---------------------------------------------------------------------------
# Main detection function
# ---------------------------------------------------------------------------

def detect_sensitive(text: str) -> dict:
    """
    Analyze text for sensitive data.

    Pipeline:
    1. Normalize input (strip null bytes, zero-width chars, NFKC, Cyrillic→Latin)
    2. Regex-based detection on normalized text
    3. Presidio NER detection
    4. Base64-encoded PII detection (decode + recursive scan)
    5. Determine action (block/redact) and severity

    Returns:
        {
            "detections": list[str],    # detected types
            "block": bool,              # should block the request
            "redact": bool,             # should redact the text
            "redacted_text": str,       # redacted version of text
            "severity": str             # "high", "medium", "low"
        }
    """
    if not text or not text.strip():
        return {
            "detections": [],
            "block": False,
            "redact": False,
            "redacted_text": text,
            "severity": "none"
        }

    # Step 1: Normalize input (Critical: VULN-001, VULN-002, VULN-016)
    normalized = normalize_input(text)

    detections = []

    # Step 2: Regex-based detection on normalized text
    regex_detections = _check_regex_patterns(normalized)
    detections.extend(regex_detections)

    # Step 3: Presidio NER detection (on normalized text)
    try:
        presidio_results = _run_presidio(normalized)
        for result in presidio_results:
            # Only add if confidence is above threshold
            if result.score >= 0.5:
                detections.append(result.entity_type)
    except Exception:
        # Presidio can fail on malformed input; fall back to regex only
        presidio_results = []

    # Step 4: Base64-encoded PII detection (Critical: VULN-003)
    b64_detections = _detect_base64_pii(normalized)
    for d in b64_detections:
        if d not in detections:
            detections.append(d)

    # Deduplicate
    detections = list(set(detections))

    # Determine action
    block = any(d in HIGH_SEVERITY_TYPES for d in detections)
    redact = len(detections) > 0

    # Redact text if needed (use normalized text for redaction)
    redacted_text = text
    if redact:
        redacted_text = _redact_text(normalized, presidio_results)

    # Determine severity
    if any(d in HIGH_SEVERITY_TYPES for d in detections):
        severity = "high"
    elif len(detections) >= 2:
        severity = "medium"
    elif len(detections) == 1:
        severity = "low"
    else:
        severity = "none"

    return {
        "detections": sorted(detections),
        "block": block,
        "redact": redact,
        "redacted_text": redacted_text,
        "severity": severity
    }


# ---------------------------------------------------------------------------
# Base64 PII detection (Critical: VULN-003)
# ---------------------------------------------------------------------------

_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')


def _detect_base64_pii(text: str) -> list[str]:
    """
    Find base64-encoded strings, decode them, and check for PII.

    Returns detections prefixed with 'BASE64_' to indicate source.
    """
    detections = []

    for match in _BASE64_PATTERN.finditer(text):
        try:
            encoded = match.group()
            # Try to decode
            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
            # Skip if decoded text is too short or not meaningful
            if len(decoded) < 4:
                continue
            # Recursively scan decoded content
            sub_result = detect_sensitive(decoded)
            if sub_result['detections']:
                for d in sub_result['detections']:
                    prefixed = f"BASE64_{d}"
                    if prefixed not in detections:
                        detections.append(prefixed)
        except Exception:
            # Not valid base64 or decoding failed — skip
            pass

    return detections
