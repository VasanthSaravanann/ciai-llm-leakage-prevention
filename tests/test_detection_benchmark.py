import time
import csv
from pathlib import Path

import pytest

# Skip these slow/integration-style benchmark tests when Presidio isn't installed
pytest.importorskip("presidio_analyzer")

from src.detection.hardened_detect import detect_sensitive

# Sample dataset (placeholder). In real use, supply richer datasets.
POSITIVE = [
    "My PAN is ABCDE1234F",
    "Card: 4111111111111111",
    "api_key = sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD",
]

NEGATIVE = [
    "Hello, how are you today?",
    "This is a sample sentence with no secrets.",
]

ADVERSARIAL = [
    "UGFyZW50IGtleTogc2stYWJjMTIz",  # base64-ish
    "P A N : A B C D E 1 2 3 4 F",
]

ALL_CASES = [(p, 'positive') for p in POSITIVE] + [(n, 'negative') for n in NEGATIVE] + [(a, 'adversarial') for a in ADVERSARIAL]

REPORT_CSV = 'data/detect_benchmark.csv'


def test_detection_benchmark():
    results = []
    for text, label in ALL_CASES:
        start = time.time()
        res = detect_sensitive(text)
        duration = time.time() - start
        results.append({'text': text, 'label': label, 'detections': res.get('detections', []), 'block': res.get('block', False), 'latency': duration})

    # Write a simple CSV report
    Path(REPORT_CSV).parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_CSV, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['text', 'label', 'detections', 'block', 'latency'])
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    # Basic assertions to ensure detectors run
    assert any(len(r['detections']) > 0 for r in results if r['label'] == 'positive')
    assert all(len(r['detections']) == 0 for r in results if r['label'] == 'negative')
