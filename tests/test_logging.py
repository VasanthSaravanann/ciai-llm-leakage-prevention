"""
Tests for CIAI Phase 2: SQLite Logging + Email Alerts
======================================================
Covers:
  - SQLite persistence (create, query, filtering)
  - Email alerts (mocked SMTP, rate limiting, severity filtering)
  - /log endpoint integration tests
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from src.logging.db import (
    init_db, create_audit_log, get_audit_logs, AuditLog, Base, engine, AsyncSessionLocal
)
from src.logging.alerts import (
    send_alert_email, should_send_alert, _is_rate_limited, _record_alert, _alert_timestamps
)


# ---------------------------------------------------------------------------
# Helper to run async functions in sync tests (Python 3.14 compatible)
# ---------------------------------------------------------------------------

def _async_run(coro):
    """Run an async coroutine in a sync test context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already in async context – shouldn't happen in sync tests
        raise RuntimeError("Unexpected async context in sync test")
    else:
        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_db():
    """Create fresh DB tables before each test, clean after."""
    _async_run(_setup_db())
    yield
    _async_run(_teardown_db())


async def _setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def _teardown_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    _alert_timestamps.clear()


@pytest.fixture
def sample_log_entry():
    return {
        "user_id": "test-user-001",
        "redacted_prompt": "My PAN is [REDACTED] and email is [REDACTED]",
        "detection_types": ["PAN", "EMAIL_ADDRESS"],
        "action_taken": "block",
        "llm_response_redacted": None,
        "severity": "high",
    }


# ---------------------------------------------------------------------------
# SQLite Persistence tests
# ---------------------------------------------------------------------------

class TestSQLitePersistence:
    """Test SQLite audit log persistence."""

    def test_create_log_returns_id(self):
        """Creating a log entry returns a valid ID."""
        async def _run():
            log_id = await create_audit_log(
                user_id="user-1",
                redacted_prompt="Hello [REDACTED]",
                detection_types=["EMAIL_ADDRESS"],
                action_taken="redact",
                severity="low",
            )
            assert log_id is not None
            assert isinstance(log_id, int)
            assert log_id > 0
        _async_run(_run())

    def test_query_logs_newest_first(self):
        """Logs are returned in newest-first order."""
        async def _run():
            await create_audit_log(
                user_id="user-1", redacted_prompt="First",
                detection_types=["EMAIL"], action_taken="redact", severity="low"
            )
            await asyncio.sleep(0.01)
            await create_audit_log(
                user_id="user-2", redacted_prompt="Second",
                detection_types=["PAN"], action_taken="block", severity="high"
            )

            logs = await get_audit_logs(limit=10)
            assert len(logs) == 2
            assert logs[0]["redacted_prompt"] == "Second"
            assert logs[1]["redacted_prompt"] == "First"
        _async_run(_run())

    def test_null_llm_response_handled(self):
        """NULL llm_response_redacted is handled gracefully."""
        async def _run():
            log_id = await create_audit_log(
                user_id="user-1",
                redacted_prompt="Test prompt",
                detection_types=["AADHAAR"],
                action_taken="block",
                llm_response_redacted=None,
                severity="high",
            )
            logs = await get_audit_logs(limit=10)
            assert len(logs) == 1
            assert logs[0]["llm_response_redacted"] is None
            assert logs[0]["id"] == log_id
        _async_run(_run())

    def test_severity_filter(self):
        """Filtering logs by severity works."""
        async def _run():
            await create_audit_log(
                user_id="user-1", redacted_prompt="Low severity",
                detection_types=["EMAIL"], action_taken="redact", severity="low"
            )
            await create_audit_log(
                user_id="user-2", redacted_prompt="High severity",
                detection_types=["PAN"], action_taken="block", severity="high"
            )
            await create_audit_log(
                user_id="user-3", redacted_prompt="Medium severity",
                detection_types=["EMAIL", "PHONE"], action_taken="redact", severity="medium"
            )

            high_logs = await get_audit_logs(severity_filter="high")
            assert len(high_logs) == 1
            assert high_logs[0]["severity"] == "high"

            low_logs = await get_audit_logs(severity_filter="low")
            assert len(low_logs) == 1
            assert low_logs[0]["severity"] == "low"
        _async_run(_run())


# ---------------------------------------------------------------------------
# Email Alert tests (mocked SMTP)
# ---------------------------------------------------------------------------

class TestEmailAlerts:
    """Test email alert system with mocked SMTP."""

    @pytest.fixture(autouse=True)
    def clear_rate_limits(self):
        """Clear rate limiter state before/after each test."""
        _alert_timestamps.clear()
        yield
        _alert_timestamps.clear()

    def test_high_severity_triggers_alert(self):
        """should_send_alert returns True for high severity."""
        assert should_send_alert("high") is True

    def test_medium_severity_skips_alert(self):
        """should_send_alert returns False for medium severity."""
        assert should_send_alert("medium") is False

    def test_low_severity_skips_alert(self):
        """should_send_alert returns False for low severity."""
        assert should_send_alert("low") is False

    @pytest.mark.asyncio
    async def test_send_email_mocked_smtp(self, sample_log_entry):
        """send_alert_email calls aiosmtplib.SMTP with correct params."""
        mock_smtp = AsyncMock()
        mock_smtp.connect = AsyncMock()
        mock_smtp.login = AsyncMock()
        mock_smtp.send_message = AsyncMock()
        mock_smtp.quit = AsyncMock()

        with patch("src.logging.alerts.SMTP_USER", "test@gmail.com"), \
             patch("src.logging.alerts.SMTP_PASS", "testpass"), \
             patch("src.logging.alerts.ALERT_EMAIL", "security@test.com"), \
             patch("aiosmtplib.SMTP", return_value=mock_smtp):

            result = await send_alert_email(sample_log_entry)
            assert result is True
            mock_smtp.connect.assert_called_once()
            mock_smtp.login.assert_called_once_with("test@gmail.com", "testpass")
            mock_smtp.send_message.assert_called_once()
            mock_smtp.quit.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_email_no_smtp_config(self, sample_log_entry):
        """send_alert_email returns False when SMTP not configured."""
        with patch("src.logging.alerts.SMTP_USER", ""), \
             patch("src.logging.alerts.SMTP_PASS", ""):

            result = await send_alert_email(sample_log_entry)
            assert result is False

    @pytest.mark.asyncio
    async def test_send_email_smtp_failure(self, sample_log_entry):
        """send_alert_email returns False on SMTP error (doesn't raise)."""
        with patch("src.logging.alerts.SMTP_USER", "test@gmail.com"), \
             patch("src.logging.alerts.SMTP_PASS", "testpass"), \
             patch("aiosmtplib.send", new_callable=AsyncMock, side_effect=Exception("Connection refused")):

            result = await send_alert_email(sample_log_entry)
            assert result is False  # Graceful failure

    def test_rate_limiting(self):
        """Rate limiting blocks alerts after MAX_ALERTS_PER_HOUR."""
        recipient = "test@test.com"

        # Record MAX_ALERTS_PER_HOUR alerts
        for _ in range(10):
            _record_alert(recipient)

        # Next alert should be rate limited
        assert _is_rate_limited(recipient) is True

    def test_rate_limit_resets_after_hour(self):
        """Rate limit resets after 1 hour."""
        recipient = "test@test.com"

        # Fill up rate limit
        for _ in range(10):
            _record_alert(recipient)
        assert _is_rate_limited(recipient) is True

        # Simulate time passage by clearing old timestamps
        import time
        _alert_timestamps[recipient] = [time.time() - 3700]  # 1 hour + 100 sec ago
        assert _is_rate_limited(recipient) is False


# ---------------------------------------------------------------------------
# FastAPI /log endpoint tests
# ---------------------------------------------------------------------------

class TestLogEndpoint:
    """Test the /log endpoint integration."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from src.api.main import app
        from src.logging.db import init_db

        _async_run(init_db())
        return TestClient(app)

    def test_log_valid_data_returns_id(self, client):
        """POST /log with valid data returns 200 + log ID."""
        resp = client.post("/log", json={
            "user_id": "test-user",
            "redacted_prompt": "My PAN is [REDACTED]",
            "detection_types": ["PAN"],
            "action": "block",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "logged"
        assert data["id"] is not None

    def test_log_missing_fields_rejected(self, client):
        """POST /log with missing required fields returns 422."""
        resp = client.post("/log", json={
            "user_id": "test-user",
            # missing redacted_prompt, detection_types, action
        })
        assert resp.status_code == 422

    def test_log_high_severity_triggers_email(self, client):
        """POST /log with high severity triggers email alert (mocked)."""
        with patch("src.api.main.send_alert_email", new_callable=AsyncMock) as mock_email:
            resp = client.post("/log", json={
                "user_id": "test-user",
                "redacted_prompt": "My Aadhaar is [REDACTED]",
                "detection_types": ["AADHAAR"],
                "action": "block",
            })
            assert resp.status_code == 200
            mock_email.assert_called_once()

    def test_log_low_severity_skips_email(self, client):
        """POST /log with low severity does NOT trigger email alert."""
        with patch("src.api.main.send_alert_email", new_callable=AsyncMock) as mock_email:
            resp = client.post("/log", json={
                "user_id": "test-user",
                "redacted_prompt": "My email is [REDACTED]",
                "detection_types": ["EMAIL_ADDRESS"],
                "action": "redact",
            })
            assert resp.status_code == 200
            mock_email.assert_not_called()
