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

from collections import defaultdict


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

    # Compute per-class basic metrics (precision/recall)
    metrics = {}
    by_label = defaultdict(list)
    for r in results:
        by_label[r['label']].append(r)

    # Treat positive as ground-truth for detection presence; adversarial treated as positive for recall
    for label, items in by_label.items():
        tp = sum(1 for i in items if i['label'] in ('positive', 'adversarial') and len(i['detections']) > 0)
        fn = sum(1 for i in items if i['label'] in ('positive', 'adversarial') and len(i['detections']) == 0)
        fp = sum(1 for i in items if i['label'] == 'negative' and len(i['detections']) > 0)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        metrics[label] = {'tp': tp, 'fp': fp, 'fn': fn, 'precision': round(precision, 3), 'recall': round(recall, 3), 'samples': len(items)}

    # Append metrics to CSV
    with open(REPORT_CSV, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([])
        writer.writerow(['label', 'samples', 'tp', 'fp', 'fn', 'precision', 'recall'])
        for label, m in metrics.items():
            writer.writerow([label, m['samples'], m['tp'], m['fp'], m['fn'], m['precision'], m['recall']])

    # Basic assertions to ensure detectors run
    assert any(len(r['detections']) > 0 for r in results if r['label'] == 'positive')
    assert all(len(r['detections']) == 0 for r in results if r['label'] == 'negative')
