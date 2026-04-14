"""
Tests for CIAI Detection Engine — Fast (regex-only) subset
============================================================
Covers India-specific regex patterns, Luhn check, block/redact decisions.
Presidio tests are in test_detection_presidio.py (slow, skipped by default).
"""

import pytest

from src.detection.detect import detect_sensitive, _luhn_check


# ---------------------------------------------------------------------------
# Luhn check tests
# ---------------------------------------------------------------------------

class TestLuhnCheck:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_check("5500000000000004") is True

    def test_invalid_number(self):
        assert _luhn_check("1234567890123456") is False


# ---------------------------------------------------------------------------
# Aadhaar detection tests
# ---------------------------------------------------------------------------

class TestAadhaarDetection:
    def test_aadhaar_plain(self):
        result = detect_sensitive("My Aadhaar number is 234567890123")
        assert "AADHAAR" in result["detections"]
        assert result["block"] is True
        assert result["severity"] == "high"

    def test_aadhaar_dashes(self):
        result = detect_sensitive("Aadhaar: 4567-8901-2345")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_spaces(self):
        result = detect_sensitive("Aadhaar: 4567 8901 2345")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_invalid_first_digit(self):
        result = detect_sensitive("Not Aadhaar: 123456789012")
        assert "AADHAAR" not in result["detections"]


# ---------------------------------------------------------------------------
# PAN detection tests
# ---------------------------------------------------------------------------

class TestPANDetection:
    def test_pan_valid(self):
        result = detect_sensitive("My PAN is ABCDE1234F")
        assert "PAN" in result["detections"]
        assert result["block"] is True
        assert result["severity"] == "high"

    def test_pan_lowercase_invalid(self):
        result = detect_sensitive("My pan is abcde1234f")
        assert "PAN" not in result["detections"]

    def test_pan_in_sentence(self):
        result = detect_sensitive("Please use PAN ABCDE5678Z for the tax filing")
        assert "PAN" in result["detections"]


# ---------------------------------------------------------------------------
# Credit card detection tests
# ---------------------------------------------------------------------------

class TestCreditCardDetection:
    def test_visa_valid(self):
        result = detect_sensitive("Card: 4111111111111111")
        assert "CREDIT_CARD" in result["detections"]
        assert result["block"] is True

    def test_mastercard_valid(self):
        result = detect_sensitive("Card: 5500000000000004")
        assert "CREDIT_CARD" in result["detections"]

    def test_invalid_luhn(self):
        result = detect_sensitive("Card: 1234567890123456")
        assert "CREDIT_CARD" not in result["detections"]

    def test_card_with_spaces(self):
        result = detect_sensitive("Card: 4111 1111 1111 1111")
        assert "CREDIT_CARD" in result["detections"]


# ---------------------------------------------------------------------------
# API key detection tests
# ---------------------------------------------------------------------------

class TestAPIKeyDetection:
    def test_openai_key(self):
        result = detect_sensitive("api_key = sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD")
        assert "OPENAI_KEY" in result["detections"]
        assert result["block"] is True

    def test_anthropic_key(self):
        result = detect_sensitive("ANTHROPIC_API_KEY=sk-ant-api03-abc123def456ghi789jkl012mno345")
        assert "ANTHROPIC_KEY" in result["detections"]
        assert result["block"] is True

    def test_bearer_token(self):
        result = detect_sensitive("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")
        assert "BEARER_TOKEN" in result["detections"]

    def test_aws_access_key(self):
        result = detect_sensitive("aws_key = AKIAIOSFODNN7EXAMPLE")
        assert "AWS_KEY" in result["detections"]

    def test_generic_api_key(self):
        result = detect_sensitive("api_key=my_secret_api_key_value_12345678")
        assert "GENERIC_API_KEY" in result["detections"]

    def test_password_exposure(self):
        result = detect_sensitive("password = SuperSecret123!")
        assert "GENERIC_SECRET" in result["detections"]


# ---------------------------------------------------------------------------
# Combined / severity tests
# ---------------------------------------------------------------------------

class TestSeverityClassification:
    def test_no_detection_clean_text(self):
        result = detect_sensitive("Hello, how are you today?")
        assert result["severity"] == "none"
        assert result["block"] is False
        assert result["redact"] is False

    def test_empty_text(self):
        result = detect_sensitive("")
        assert result["severity"] == "none"
        assert result["block"] is False
        assert result["redact"] is False

    def test_high_severity_single(self):
        result = detect_sensitive("PAN: ABCDE1234F")
        assert result["severity"] == "high"

    def test_redaction_applied(self):
        result = detect_sensitive("My email is test@test.com, PAN: ABCDE1234F")
        assert result["redact"] is True


# ---------------------------------------------------------------------------
# Redaction tests
# ---------------------------------------------------------------------------

class TestRedaction:
    def test_aadhaar_redacted(self):
        result = detect_sensitive("Aadhaar: 234567890123")
        assert "234567890123" not in result["redacted_text"]
        assert "[REDACTED]" in result["redacted_text"]

    def test_pan_redacted(self):
        result = detect_sensitive("PAN: ABCDE1234F")
        assert "ABCDE1234F" not in result["redacted_text"]

    def test_credit_card_redacted(self):
        result = detect_sensitive("Card: 4111111111111111")
        assert "4111111111111111" not in result["redacted_text"]

    def test_clean_text_unchanged(self):
        result = detect_sensitive("Hello world, this is a test")
        assert result["redacted_text"] == "Hello world, this is a test"

    def test_api_key_redacted(self):
        result = detect_sensitive("key = sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD")
        assert "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD" not in result["redacted_text"]
        assert "[REDACTED]" in result["redacted_text"]


# ---------------------------------------------------------------------------
# FastAPI endpoint tests
# ---------------------------------------------------------------------------

class TestAPIEndpoints:
    """Test FastAPI endpoints using TestClient."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from src.api.main import app
        from src.logging.db import init_db
        from src.config import settings
        import asyncio

        asyncio.run(init_db())

        # Set test API key so auth passes
        settings.API_KEY = "test-key"
        return TestClient(app, headers={"X-API-KEY": "test-key"})

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_detect_clean(self, client):
        resp = client.post("/detect", json={"text": "Hello world"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["severity"] == "none"

    def test_detect_pii(self, client):
        resp = client.post("/detect", json={"text": "PAN: ABCDE1234F"})
        assert resp.status_code == 200
        data = resp.json()
        assert "PAN" in data["detections"]
        assert data["block"] is True

    def test_detect_empty_rejected(self, client):
        resp = client.post("/detect", json={"text": ""})
        assert resp.status_code == 422

    def test_log_valid_entry(self, client):
        resp = client.post("/log", json={
            "user_id": "test-user",
            "redacted_prompt": "Hello [REDACTED]",
            "detection_types": ["EMAIL_ADDRESS"],
            "action": "redact"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "logged"
        assert data["id"] is not None
