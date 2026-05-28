# Sample Text Summary

Source: `sample_txt_inputs.jsonl`

## Baseline Run

- Total cases: 164
- Successful requests: 30
- Failed requests: 134
- Expected redaction cases: 120
- Actual redaction cases: 18
- Correct cases: 58
- Incorrect cases: 106
- False positives: 2
- False negatives: 104

Main detections seen:
- AADHAAR: 8
- CREDIT_CARD: 8
- PAN: 5

## After Detector Update

- Expected redaction cases: 120
- Actual redaction cases: 120
- Correct cases: 164
- Incorrect cases: 0
- False positives: 0
- False negatives: 0

Main detections seen:
- AADHAAR: 19
- CREDIT_CARD: 16
- UPI_ID: 13
- OPENAI_KEY: 11
- PAN: 9

Largest gains since baseline:
- Correct cases: 58 to 164
- Incorrect cases: 106 to 0
- False positives: 2 to 0
- False negatives: 104 to 0
- Actual redactions: 18 to 120

## Important Note

The summarizer uses section-based rules to decide whether a case should have been redacted. That makes the report useful for review, but it is still a heuristic, not a perfect ground-truth judge for every section.

## Next Steps

- Continue monitoring OCR-noise and mixed inputs; expand `normalize_input` OCR mapping as needed.
- If you want stricter production behavior, tighten section rules to reduce heuristic mismatches.

The detector now suppresses the invalid PAN, Aadhaar, GST, passport, UPI, UUID, and malformed card false positives in the current corpus.
