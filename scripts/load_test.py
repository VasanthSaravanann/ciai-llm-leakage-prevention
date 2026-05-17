#!/usr/bin/env python3
"""Basic load test script hitting /detect repeatedly.

Usage: export API_KEY and run `python scripts/load_test.py --concurrency 5 --requests 100`.
"""
import argparse
import requests
import os
from concurrent.futures import ThreadPoolExecutor

API_KEY = os.environ.get('API_KEY')
BASE = os.environ.get('BASE_URL', 'http://127.0.0.1:8000')

def worker(prompt):
    try:
        r = requests.post(f"{BASE}/detect", json={'text': prompt}, headers={'X-API-KEY': API_KEY}, timeout=5)
        return r.status_code
    except Exception as e:
        return str(e)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--concurrency', type=int, default=5)
    parser.add_argument('--requests', type=int, default=50)
    args = parser.parse_args()

    prompts = [f"Load test prompt {i}" for i in range(args.requests)]
    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        results = list(ex.map(worker, prompts))

    from collections import Counter
    print('Results:', Counter(results))

if __name__ == '__main__':
    if not API_KEY:
        print('Export API_KEY before running'); exit(1)
    main()
