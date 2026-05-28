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
- Actual redaction cases: 107
- Correct cases: 151
- Incorrect cases: 13
- False positives: 0
- False negatives: 13

Main detections seen:
- AADHAAR: 19
- CREDIT_CARD: 16
- UPI_ID: 12
- OPENAI_KEY: 11
- PAN: 9

Largest gains since baseline:
- Correct cases: 58 to 151
- Incorrect cases: 106 to 13
- False positives: 2 to 0
- False negatives: 104 to 13
- Actual redactions: 18 to 107

## What Still Needs Work

The remaining misses are concentrated in:
- massive combined stress test
- driving valid
- phone indian
- US
- name/address
- unicode

## Important Note

The summarizer uses section-based rules to decide whether a case should have been redacted. That makes the report useful for review, but it is still a heuristic, not a perfect ground-truth judge for every section.

## How to Fix the Remaining Gap

The practical next step is to tighten the section rules for the remaining mixed, phone, US, address, and unicode cases while keeping the current false-positive guards in place.

The detector now suppresses the invalid PAN, Aadhaar, GST, passport, UPI, UUID, and malformed card false positives in the current corpus.
