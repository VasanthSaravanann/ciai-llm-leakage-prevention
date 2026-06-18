from typing import Tuple
from src.detection.hardened_detect import detect_sensitive


def moderate_response(response_text: str, tenant_id: str | None = None) -> Tuple[bool, str]:
    """Run a simple moderation pass on the response_text.

    Returns (blocked: bool, reason: str).
    Uses the same detection engine to find PII/secrets in outputs.
    """
    try:
        res = detect_sensitive(response_text)
        if res.get("detections"):
            # Block if any detections found
            return True, f"contains_detection:{','.join(res.get('detections', []))}"
        return False, "clean"
    except Exception:
        # If moderation fails, default to blocking when tenant requires strict mode.
        return True, "moderation_failed"
