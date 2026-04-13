from fastapi import FastAPI, Request
from models import AuditLog, engine
from sqlalchemy.orm import sessionmaker

Session = sessionmaker(bind=engine)

@app.post("/log")
async def log_event(request: Request):
    data = await request.json()
    session = Session()
    log_entry = AuditLog(
        user_id=data["user_id"],
        redacted_prompt=data["redacted_prompt"],
        detection_types=",".join(data["detections"]),
        action_taken=data["action"]
    )
    session.add(log_entry)
    session.commit()
    session.close()

    # Send alert if high severity
    if "AADHAAR" in data["detections"] or "PAN" in data["detections"]:
        send_alert_email(data)
    return {"status": "logged"}
