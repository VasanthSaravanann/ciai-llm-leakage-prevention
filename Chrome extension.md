
---

## File 5: `BUILD_DETECTION.md`

```markdown
# Build the Detection Engine

## Dependencies
```bash
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg





---------XXX-------
detection.py - 

import re
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Custom regex patterns (India‑specific)
PATTERNS = {
    "AADHAAR": r'\b[2-9]{1}[0-9]{3}[0-9]{4}[0-9]{4}\b',  # simplified
    "PAN": r'[A-Z]{5}[0-9]{4}[A-Z]{1}',
    "CREDIT_CARD": r'\b(?:\d[ -]*?){13,16}\b',
    "API_KEY": r'sk-[a-zA-Z0-9]{48}|Bearer\s+[a-zA-Z0-9_\-]+',
}

def detect_sensitive(text):
    detections = []
    # 1. Run regex
    for label, pattern in PATTERNS.items():
        if re.search(pattern, text):
            detections.append(label)

    # 2. Run Presidio for PII (names, emails, phones)
    analyzer_results = analyzer.analyze(text=text, language='en')
    for result in analyzer_results:
        detections.append(result.entity_type)  # PERSON, EMAIL, PHONE_NUMBER, etc.

    # Determine action
    high_severity = ["AADHAAR", "PAN", "CREDIT_CARD", "API_KEY"]
    block = any(d in high_severity for d in detections)
    redact = len(detections) > 0

    # Redact text using Presidio
    redacted_text = text
    if redact:
        redacted_text = anonymizer.anonymize(text=text, analyzer_results=analyzer_results).text
        for label, pattern in PATTERNS.items():
            redacted_text = re.sub(pattern, "[REDACTED]", redacted_text)

    return {
        "detections": list(set(detections)),
        "block": block,
        "redact": redact,
        "redacted_text": redacted_text if redact else text
    }
    
    
    
 ---------XXXXX--------------



api.py - 

from fastapi import FastAPI, HTTPException
from detection import detect_sensitive
from pydantic import BaseModel

app = FastAPI()

class DetectRequest(BaseModel):
    text: str

@app.post("/detect")
async def detect(req: DetectRequest):
    result = detect_sensitive(req.text)
    return result
    
    
------XXXXXX------

Run with: uvicorn api:app --reload --port 8000





---

## File 6: `BUILD_LOGGING_ALERTS.md`

```markdown
# Build Logging & Alerting

## Database (SQLite)
```python
# models.py
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()
engine = create_engine("sqlite:///audit.db")

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(String)
    redacted_prompt = Column(String)
    detection_types = Column(String)   # comma separated
    action_taken = Column(String)      # "block" or "redact"
    llm_response_redacted = Column(String, nullable=True)

Base.metadata.create_all(engine)

