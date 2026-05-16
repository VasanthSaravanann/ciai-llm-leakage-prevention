import base64
from src.detection.detect import detect_sensitive


def _nested_base64(payload: str, layers: int) -> str:
    data = payload
    for _ in range(layers):
        data = base64.b64encode(data.encode()).decode()
    return data


def test_b64_recursion_limit():
    # Create a synthetic API key-like payload and nest it beyond recursion cap
    secret = "sk-" + "A" * 24
    nested = _nested_base64(secret, 6)

    # detect_sensitive enforces a recursion cap (default 3); scanning deeply nested
    # base64 payloads should not recurse indefinitely or find the secret when beyond cap
    result = detect_sensitive(nested)
    assert isinstance(result, dict)
    # Ensure function returns quickly and does not report direct OPENAI key without decoding
    assert not any("OPENAI_KEY" == d or d.startswith("BASE64_OPENAI_KEY") for d in result["detections"]) 
