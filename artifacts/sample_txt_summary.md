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

- Correct cases: 129
- Incorrect cases: 35
- False negatives: 28
- Actual redactions: 99

Largest gains:
- IP4: 0/3 to 3/3
- IP6: 0/2 to 2/2
- dates: 0/5 to 5/5
- upiid: 0/4 to 4/4
- name/address: 0/7 to 6/7

## What Still Needs Work

The remaining misses are concentrated in:
- OCR noise
- broken OCR inputs
- some AWS secret edge cases
- mixed or line-broken secrets

## Important Note

The summarizer uses section-based rules to decide whether a case should have been redacted. That makes the report useful for review, but it is still a heuristic, not a perfect ground-truth judge for every section.

## How to Fix the Remaining Gap

The practical fix is to make the section rules more conservative for ambiguous sections and add targeted heuristics for the failure shapes the corpus still shows:
- treat OCR/noisy sections as redact-leaning when they contain tokenized IDs or digit-letter patterns
- detect line-broken API keys and secrets before Presidio runs
- keep a false-positive guard for UUIDs, order IDs, and random hex strings

The detector already improved after adding IPv4, IPv6, dates, UPI IDs, JWTs, and basic name/address cues in `src/detection/detect.py`.
