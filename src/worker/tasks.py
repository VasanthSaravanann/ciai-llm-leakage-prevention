from src.worker.celery_app import worker
from src.detection.detect import detect_sensitive
from src.logging.database import SessionLocal
from src.logging.models import AuditLog
from src.api.main import sanitize
from src.config import settings
from src.logging.encryption import encrypt as _encrypt
import base64
import os
from datetime import datetime, timedelta


@worker.task(name='ciai.detect_and_log')
def detect_and_log(text: str, user_id: str = 'worker'):
    result = detect_sensitive(text)
    db = SessionLocal()
    try:
        entry = AuditLog(
            user_id=user_id,
            redacted_prompt=(lambda s: (lambda t: t)(sanitize(s)))(result.get('redacted_text')),
            redacted_fingerprint='',
            detection_types=result.get('detections', []),
            action='block' if result.get('block') else 'pass',
            severity=result.get('severity')
        )
        # Optionally encrypt redacted prompt when configured
        text_to_store = sanitize(result.get('redacted_text')) if result.get('redacted_text') else ''
        if os.environ.get('ENCRYPT_LOGS', '0') == '1':
            try:
                keyid, ciphertext = _encrypt(text_to_store.encode('utf-8'))
                ciphertext_b64 = base64.b64encode(ciphertext).decode('ascii')
                entry.redacted_prompt = '__encrypted__'
                entry.redacted_prompt_ciphertext = ciphertext_b64
                entry.redacted_prompt_key_id = keyid
            except Exception:
                entry.redacted_prompt = text_to_store
        else:
            entry.redacted_prompt = text_to_store
        db.add(entry)
        db.commit()
    finally:
        db.close()
    return result


@worker.task(name='ciai.purge_old_logs')
def purge_old_logs():
    """Delete logs older than the configured retention period."""
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=int(settings.RETENTION_DAYS))
        # SQLAlchemy Core delete
        from sqlalchemy import delete
        delete_stmt = delete(AuditLog).where(AuditLog.timestamp < cutoff)
        db.execute(delete_stmt)
        db.commit()
    finally:
        db.close()
