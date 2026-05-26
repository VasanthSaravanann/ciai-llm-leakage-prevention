"""Simple response moderation hook using existing detection engine.

This module exposes `moderate_response(text, block_on_high=True)` which returns
a dict similar to `detect_sensitive` and can be toggled per-tenant by the
caller.
"""
from src.detection.hardened_detect import detect_sensitive


def moderate_response(text: str, block_on_high: bool = True) -> dict:
    """Run detection on model output and decide whether to block/redact.

    Returns a dict with keys: detections, block, redact, redacted_text, severity
    """
    result = detect_sensitive(text)
    # For responses, be conservative: if severity high and block_on_high -> block
    if block_on_high and result.get('severity') == 'high':
        return {**result, 'block': True}
    return result
