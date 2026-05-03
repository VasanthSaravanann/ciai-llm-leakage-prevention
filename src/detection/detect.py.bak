"""
CIAI Detection Engine
====================
Detects sensitive data in text using:
  1. India-specific regex patterns (Aadhaar, PAN, Credit Card, API keys)
  2. Microsoft Presidio for PII (names, emails, phones, locations, etc.)

Returns detection results with block/redact decisions and redacted text.
"""

import re
from typing import Optional

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ---------------------------------------------------------------------------
# India-specific regex patterns
# ---------------------------------------------------------------------------

# Aadhaar: 12 digits, commonly formatted as XXXX-XXXX-XXXX, XXXX XXXX XXXX, or XXXXXXXXXXXX
# First digit is 2-9 (valid Aadhaar range)
AADHAAR_PATTERN = r'\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b'

# PAN: 5 uppercase letters + 4 digits + 1 uppercase letter
# e.g., ABCDE1234F
PAN_PATTERN = r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'

# Credit card: 13-19 digits, possibly with spaces or dashes
CREDIT_CARD_PATTERN = r'\b(?:\d[\s-]*?){13,19}\b'

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

HIGH_SEVERITY_TYPES = {"AADHAAR", "PAN", "CREDIT_CARD", "OPENAI_KEY", "ANTHROPIC_KEY",
                       "AWS_KEY", "AWS_SECRET", "API_KEY", "SECRET"}


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
    """Run all regex patterns against the text."""
    detections = []

    # Aadhaar
    if re.search(AADHAAR_PATTERN, text):
        detections.append("AADHAAR")

    # PAN
    if re.search(PAN_PATTERN, text):
        detections.append("PAN")

    # Credit cards with Luhn validation
    cc_detections = _check_credit_cards(text)
    detections.extend(cc_detections)

    # API keys
    for label, pattern in API_KEY_PATTERNS.items():
        if re.search(pattern, text):
            detections.append(label)

    return detections


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

    detections = []

    # 1. Regex-based detection
    regex_detections = _check_regex_patterns(text)
    detections.extend(regex_detections)

    # 2. Presidio NER detection
    try:
        presidio_results = _run_presidio(text)
        for result in presidio_results:
            # Only add if confidence is above threshold
            if result.score >= 0.5:
                detections.append(result.entity_type)
    except Exception:
        # Presidio can fail on malformed input; fall back to regex only
        presidio_results = []

    # Deduplicate
    detections = list(set(detections))

    # Determine action
    block = any(d in HIGH_SEVERITY_TYPES for d in detections)
    redact = len(detections) > 0

    # Redact text if needed
    redacted_text = text
    if redact:
        redacted_text = _redact_text(text, presidio_results)

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
