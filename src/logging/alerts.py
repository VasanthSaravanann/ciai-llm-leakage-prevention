"""
CIAI Email Alert System
=======================
SMTP-based email alerts for high-severity detections.
Features:
  - HTML-formatted alert emails
  - Rate limiting (max 10 alerts/hour)
  - Graceful fallback on SMTP failure (logs warning, doesn't block)
"""

import os
import logging
import time
from collections import defaultdict
from typing import Optional

logger = logging.getLogger("ciai.alerts")

# ---------------------------------------------------------------------------
# SMTP configuration (from environment variables)
# ---------------------------------------------------------------------------

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "security@yourcompany.com")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER or "alerts@ciai.com")

# ---------------------------------------------------------------------------
# Rate limiting: max alerts per hour (per recipient)
# ---------------------------------------------------------------------------

MAX_ALERTS_PER_HOUR = 10
_alert_timestamps: dict[str, list[float]] = defaultdict(list)


def _is_rate_limited(recipient: str) -> bool:
    """Check if recipient has exceeded alert rate limit."""
    now = time.time()
    hour_ago = now - 3600

    # Clean old entries
    _alert_timestamps[recipient] = [
        ts for ts in _alert_timestamps[recipient] if ts > hour_ago
    ]

    return len(_alert_timestamps[recipient]) >= MAX_ALERTS_PER_HOUR


def _record_alert(recipient: str):
    """Record an alert timestamp for rate limiting."""
    _alert_timestamps[recipient].append(time.time())


# ---------------------------------------------------------------------------
# Email sending
# ---------------------------------------------------------------------------

def _build_alert_html(entry: dict) -> str:
    """Build HTML email body from audit log entry."""
    return f"""
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px;">
        <h2 style="color: #dc2626; margin-top: 0;">🚨 CIAI Alert: Sensitive Data Detected</h2>

        <table style="border-collapse: collapse; width: 100%; max-width: 600px;">
            <tr>
                <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #e5e7eb;">User ID</td>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">{entry.get('user_id', 'N/A')}</td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #e5e7eb;">Severity</td>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">
                    <span style="background: {'#fecaca' if entry.get('severity') == 'high' else '#fef3c7'};
                                 padding: 2px 8px; border-radius: 4px; font-weight: bold;">
                        {entry.get('severity', 'N/A').upper()}
                    </span>
                </td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #e5e7eb;">Detection Types</td>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">{entry.get('detection_types', 'N/A')}</td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #e5e7eb;">Action Taken</td>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">{entry.get('action_taken', 'N/A').upper()}</td>
            </tr>
            <tr>
                <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #e5e7eb;">Timestamp</td>
                <td style="padding: 8px; border-bottom: 1px solid #e5e7eb;">{entry.get('timestamp', 'N/A')}</td>
            </tr>
        </table>

        <h3 style="margin-top: 24px;">Redacted Prompt</h3>
        <pre style="background: #f9fafb; padding: 12px; border-radius: 6px; border: 1px solid #e5e7eb;
                     white-space: pre-wrap; word-break: break-word; max-width: 600px;">{entry.get('redacted_prompt', 'N/A')}</pre>

        <p style="color: #6b7280; margin-top: 24px; font-size: 12px;">
            This alert was sent by the CIAI LLM Data Leakage Prevention system.<br>
            <a href="#" style="color: #3b82f6;">View in Dashboard</a> (coming soon)
        </p>
    </body>
    </html>
    """


def _build_alert_text(entry: dict) -> str:
    """Build plain-text fallback email body."""
    return f"""
CIAI ALERT: Sensitive Data Detected
====================================

User ID:          {entry.get('user_id', 'N/A')}
Severity:         {entry.get('severity', 'N/A').upper()}
Detection Types:  {entry.get('detection_types', 'N/A')}
Action Taken:     {entry.get('action_taken', 'N/A').upper()}
Timestamp:        {entry.get('timestamp', 'N/A')}

Redacted Prompt:
----------------------------------------
{entry.get('redacted_prompt', 'N/A')}
----------------------------------------

-- CIAI LLM Data Leakage Prevention System
"""


async def send_alert_email(entry: dict, recipient: Optional[str] = None) -> bool:
    """
    Send an alert email for a high-severity detection.

    Args:
        entry: Audit log entry dict (from AuditLog.to_dict())
        recipient: Override default ALERT_EMAIL

    Returns:
        True if email was sent, False if skipped/failed.
    """
    recipient = recipient or ALERT_EMAIL

    if not SMTP_USER or not SMTP_PASS:
        logger.warning("SMTP not configured (SMTP_USER/SMTP_PASS not set). Skipping alert email.")
        return False

    if _is_rate_limited(recipient):
        logger.warning(f"Rate limit exceeded for {recipient}. Skipping alert.")
        return False

    try:
        import aiosmtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 CIAI Alert: {entry.get('severity', 'HIGH').upper()} — {entry.get('detection_types', 'Unknown')}"
        msg["From"] = FROM_EMAIL
        msg["To"] = recipient

        # Attach both plain text and HTML
        text_part = MIMEText(_build_alert_text(entry), "plain", "utf-8")
        html_part = MIMEText(_build_alert_html(entry), "html", "utf-8")
        msg.attach(text_part)
        msg.attach(html_part)

        # Send via async SMTP (aiosmtplib 5.x uses SMTP class)
        smtp = aiosmtplib.SMTP(hostname=SMTP_HOST, port=SMTP_PORT, start_tls=True)
        await smtp.connect()
        await smtp.login(SMTP_USER, SMTP_PASS)
        await smtp.send_message(msg)
        await smtp.quit()

        _record_alert(recipient)
        logger.info(f"Alert email sent to {recipient} for detection: {entry.get('detection_types')}")
        return True

    except Exception as e:
        logger.error(f"Failed to send alert email to {recipient}: {e}")
        return False


def should_send_alert(severity: str) -> bool:
    """Determine if an alert should be sent based on severity level."""
    return severity == "high"
