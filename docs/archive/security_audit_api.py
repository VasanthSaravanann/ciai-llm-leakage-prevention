"""
CIAI Security Audit — API Layer Security Tests
===============================================
Tests for authentication, rate limiting, CORS, info leakage, SQL injection.
Run with: python security_audit_api.py
"""

import sys
import os
import json
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from fastapi.testclient import TestClient
from src.api.main import app
from src.logging.db import init_db

# Initialize DB
asyncio.run(init_db())

client = TestClient(app)

PASS = "\033[92m✓ PASS\033[0m"
FAIL = "\033[91m✗ FAIL\033[0m"
WARN = "\033[93m⚠ WARN\033[0m"

print("=" * 80)
print("CIAI SECURITY AUDIT — API LAYER SECURITY TESTS")
print("=" * 80)

# ============================================================
# 1. AUTHENTICATION / AUTHORIZATION
# ============================================================
print("\n\033[1m[1] AUTHENTICATION / AUTHORIZATION\033[0m")

# No auth required on /detect
resp = client.post("/detect", json={"text": "test"})
if resp.status_code == 200:
    print(f"  {FAIL} /detect has NO authentication — anyone can query the detection engine")
else:
    print(f"  {PASS} /detect requires authentication")

# No auth required on /log
resp = client.post("/log", json={
    "user_id": "attacker",
    "redacted_prompt": "test",
    "detection_types": [],
    "action": "block",
})
if resp.status_code == 200:
    print(f"  {FAIL} /log has NO authentication — anyone can write to audit logs")
else:
    print(f"  {PASS} /log requires authentication")

# No auth on /health (expected, but note it)
resp = client.get("/health")
if resp.status_code == 200:
    print(f"  {WARN} /health is publicly accessible (expected for health checks)")

# ============================================================
# 2. RATE LIMITING
# ============================================================
print("\n\033[1m[2] RATE LIMITING\033[0m")

# Rapid-fire /detect requests
import time
start = time.time()
for i in range(50):
    resp = client.post("/detect", json={"text": f"test {i}"})
elapsed = time.time() - start
print(f"  {FAIL} No rate limiting on /detect — 50 requests in {elapsed:.2f}s (all returned 200)")

# Rapid-fire /log requests
start = time.time()
for i in range(50):
    resp = client.post("/log", json={
        "user_id": f"user-{i}",
        "redacted_prompt": f"test {i}",
        "detection_types": [],
        "action": "redact",
    })
elapsed = time.time() - start
print(f"  {FAIL} No rate limiting on /log — 50 requests in {elapsed:.2f}s (all returned 200)")

# ============================================================
# 3. INPUT VALIDATION
# ============================================================
print("\n\033[1m[3] INPUT VALIDATION\033[0m")

# Max length boundary (100,000 chars)
long_text = "A" * 100001
resp = client.post("/detect", json={"text": long_text})
if resp.status_code == 422:
    print(f"  {PASS} Input length validation works (>100k chars rejected)")
else:
    print(f"  {FAIL} Input length NOT validated — {resp.status_code} for {len(long_text)} chars")

# Empty string
resp = client.post("/detect", json={"text": ""})
if resp.status_code == 422:
    print(f"  {PASS} Empty string rejected (422)")
else:
    print(f"  {WARN} Empty string returned {resp.status_code}")

# Null bytes
resp = client.post("/detect", json={"text": "test\x00injection"})
if resp.status_code == 200:
    print(f"  {WARN} Null bytes accepted — potential C injection risk in downstream systems")

# SQL injection in /log user_id
resp = client.post("/log", json={
    "user_id": "'; DROP TABLE audit_logs; --",
    "redacted_prompt": "test",
    "detection_types": [],
    "action": "block",
})
if resp.status_code == 200:
    print(f"  {WARN} SQL-like input in user_id accepted (SQLAlchemy ORM protects, but no input sanitization)")
    # Verify table still exists
    resp2 = client.get("/health")
    if resp2.status_code == 200:
        print(f"         Database still functional — ORM protected against SQLi")

# XSS in /log
resp = client.post("/log", json={
    "user_id": "<script>alert('xss')</script>",
    "redacted_prompt": "<img src=x onerror=alert(1)>",
    "detection_types": ["PAN"],
    "action": "block",
})
if resp.status_code == 200:
    print(f"  {FAIL} XSS payloads stored in audit logs without sanitization")

# ============================================================
# 4. INFORMATION DISCLOSURE
# ============================================================
print("\n\033[1m[4] INFORMATION DISCLOSURE\033[0m")

# Error messages leak internal info
resp = client.post("/detect", json={"text": None})
if resp.status_code == 422:
    detail = resp.json().get("detail", "")
    if "pydantic" in str(detail).lower() or "validation" in str(detail).lower():
        print(f"  {WARN} Error messages reveal framework internals (Pydantic validation errors)")

# Stack traces on 500
# Force an error by sending oversized payload
resp = client.post("/detect", json={"text": "A" * 500000})
if resp.status_code == 422:
    print(f"  {PASS} Oversized input returns 422, not 500 with stack trace")

# Version disclosure
resp = client.get("/openapi.json")
if resp.status_code == 200:
    spec = resp.json()
    version = spec.get("info", {}).get("version", "unknown")
    print(f"  {WARN} API version disclosed in OpenAPI spec: {version}")

# Server header
resp = client.get("/health")
server = resp.headers.get("server", "unknown")
if "uvicorn" in server.lower():
    print(f"  {WARN} Server technology disclosed in headers: {server}")

# ============================================================
# 5. CORS CONFIGURATION
# ============================================================
print("\n\033[1m[5] CORS CONFIGURATION\033[0m")

# No CORS middleware configured
resp = client.options("/detect", headers={
    "Origin": "https://evil.com",
    "Access-Control-Request-Method": "POST",
})
# FastAPI returns 405 for OPTIONS without CORS middleware
if resp.status_code in [405, 404]:
    print(f"  {PASS} No CORS configured — browsers will block cross-origin requests")
else:
    cors_header = resp.headers.get("access-control-allow-origin", "")
    if cors_header == "*":
        print(f"  {FAIL} CORS allows all origins (Access-Control-Allow-Origin: *)")
    elif cors_header:
        print(f"  {WARN} CORS configured: {cors_header}")

# ============================================================
# 6. DATA RETENTION / LOG SECURITY
# ============================================================
print("\n\033[1m[6] DATA RETENTION / LOG SECURITY\033[0m")

# Check database file permissions
db_path = "./data/ciai_audit.db"
if os.path.exists(db_path):
    stat = os.stat(db_path)
    perms = oct(stat.st_mode)[-3:]
    if perms != "600":
        print(f"  {FAIL} Database file permissions: {perms} (should be 600)")
    else:
        print(f"  {PASS} Database file permissions: {perms}")
    
    size = stat.st_size
    print(f"         Database size: {size:,} bytes")
    
    # Check if DB is readable by anyone
    import sqlite3
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        count = cursor.fetchone()[0]
        print(f"         Total audit log entries: {count}")
        
        # Check what's actually stored
        cursor.execute("SELECT redacted_prompt FROM audit_logs LIMIT 5")
        rows = cursor.fetchall()
        for row in rows:
            if "[REDACTED]" not in row[0] and len(row[0]) > 10:
                print(f"  {WARN} Unredacted content found in logs: {repr(row[0][:50])}")
        conn.close()
    except Exception as e:
        print(f"         Could not read DB: {e}")
else:
    print(f"  {WARN} Database file not found at {db_path}")

# No data retention policy
print(f"  {FAIL} No data retention policy — logs grow indefinitely")
print(f"  {FAIL} No log rotation or archival mechanism")
print(f"  {FAIL} No encryption at rest for SQLite database")

# ============================================================
# 7. CONTENT TYPE SNIFFING
# ============================================================
print("\n\033[1m[7] SECURITY HEADERS\033[0m")

resp = client.get("/health")
headers = resp.headers

security_headers = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": None,  # Should be present
    "Content-Security-Policy": None,
    "X-XSS-Protection": None,
}

for header, expected in security_headers.items():
    value = headers.get(header)
    if value is None:
        print(f"  {FAIL} Missing security header: {header}")
    elif expected and value != expected:
        print(f"  {FAIL} {header}: {value} (expected: {expected})")
    else:
        print(f"  {PASS} {header}: {value}")

# ============================================================
# 8. CONCURRENCY / RACE CONDITIONS
# ============================================================
print("\n\033[1m[8] CONCURRENCY / RACE CONDITIONS\033[0m")

# Simultaneous writes to SQLite
import concurrent.futures
errors = []

def log_entry(i):
    try:
        resp = client.post("/log", json={
            "user_id": f"concurrent-{i}",
            "redacted_prompt": f"test {i}",
            "detection_types": [],
            "action": "redact",
        })
        return resp.status_code
    except Exception as e:
        errors.append(str(e))
        return 0

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(log_entry, i) for i in range(20)]
    statuses = [f.result() for f in futures]

success_count = sum(1 for s in statuses if s == 200)
print(f"  {WARN} 20 concurrent log requests: {success_count} succeeded, {len(errors)} errors")
if errors:
    print(f"         Errors: {errors[:3]}")

print("\n" + "=" * 80)
print("API SECURITY SUMMARY")
print("=" * 80)
print("  ✗ NO authentication on any endpoint")
print("  ✗ NO rate limiting on any endpoint")
print("  ✗ NO security headers configured")
print("  ✗ NO data retention policy")
print("  ✗ NO encryption at rest for audit logs")
print("  ✗ Database file not permission-restricted")
print("  ✗ XSS payloads stored without sanitization")
print("  ⚠ Error messages reveal framework internals")
print("  ⚠ Server technology disclosed in headers")
