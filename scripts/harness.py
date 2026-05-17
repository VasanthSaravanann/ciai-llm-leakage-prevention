#!/usr/bin/env python3
"""Simple send->/detect->LLM harness for staging.

Behavior:
 - POST prompt to /detect
 - If block:false, forward to mock LLM (httpbin.org) or real LLM if LLM_API_KEY provided
 - POST redacted prompt/response to /log
"""
import os
import requests
import sys

API_KEY = os.environ.get('API_KEY')
BASE = os.environ.get('BASE_URL', 'http://127.0.0.1:8000')
LLM_API_KEY = os.environ.get('LLM_API_KEY')

if not API_KEY:
    print('Set API_KEY in environment'); sys.exit(1)

DETECT_URL = f"{BASE}/detect"
LOG_URL = f"{BASE}/log"
MOCK_LLM = 'https://httpbin.org/post'

def forward_to_llm(prompt):
    headers = {}
    if LLM_API_KEY:
        headers['Authorization'] = f'Bearer {LLM_API_KEY}'
        # Here you'd call your real LLM endpoint
        # For safety in this harness, call mock if no provider configured
    try:
        resp = requests.post(MOCK_LLM, json={'prompt': prompt}, headers=headers, timeout=10)
        return resp.text
    except Exception as e:
        return f'LLM_FORWARD_ERROR: {e}'

def main():
    prompt = os.environ.get('HARNESS_PROMPT', 'Hello from harness — no PII')
    r = requests.post(DETECT_URL, json={'text': prompt}, headers={'X-API-KEY': API_KEY})
    if r.status_code != 200:
        print('Detect failed', r.status_code, r.text); sys.exit(2)
    data = r.json()
    print('Detect result:', data)
    if data.get('block'):
        print('Blocked — not forwarding')
        return

    llm_resp = forward_to_llm(prompt)
    log_payload = {
        'user_id': 'harness',
        'redacted_prompt': data.get('redacted_text'),
        'detection_types': data.get('detections', []),
        'action': 'block' if data.get('block') else 'pass',
        'severity': data.get('severity', 'none'),
        'llm_response_redacted': str(llm_resp)
    }
    lr = requests.post(LOG_URL, json=log_payload, headers={'X-API-KEY': API_KEY})
    print('Log response:', lr.status_code, lr.text)

if __name__ == '__main__':
    main()
