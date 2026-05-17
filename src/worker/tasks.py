from src.worker.celery_app import worker
from src.detection.detect import detect_sensitive
from src.logging.database import SessionLocal
from src.logging.models import AuditLog
from src.api.main import sanitize


@worker.task(name='ciai.detect_and_log')
def detect_and_log(text: str, user_id: str = 'worker'):
    result = detect_sensitive(text)
    db = SessionLocal()
    try:
        entry = AuditLog(
            user_id=user_id,
            redacted_prompt=sanitize(result.get('redacted_text')),
            redacted_fingerprint='',
            detection_types=result.get('detections', []),
            action='block' if result.get('block') else 'pass',
            severity=result.get('severity')
        )
        db.add(entry)
        db.commit()
    finally:
        db.close()
    return result
