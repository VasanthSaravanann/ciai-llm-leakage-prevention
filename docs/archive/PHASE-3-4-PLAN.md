# Implementation Plan: Phase 3 (mitmproxy) & Phase 4 (Dashboard)

## 🚀 Phase 3: mitmproxy Interceptor Implementation Plan

The goal is to intercept LLM API requests, analyze them for sensitive data, and block or redact before they leave the organization.

### 1. Interceptor Core (`src/proxy/addon.py`)
- Create a `mitmproxy` addon using the `request` event hook.
- **Target URL Filtering:** Only process requests to `https://api.openai.com/v1/chat/completions` (expandable to Anthropic/Google).
- **Body Parsing:** Extract the `messages` content from the JSON request body.
- **API Call to `/detect`:** Synchronously call the local `ciai-llm-leakage-prevention` API (`/detect` endpoint) for analysis.
- **Action Handling:**
    - **Block:** If `result["block"]` is `True`, return a 403 Forbidden response with a custom JSON error message: `{"error": "Request blocked by CIAI - Sensitive data detected."}`.
    - **Redact:** If `result["redact"]` is `True`, replace the original prompt text in the JSON body with `result["redacted_text"]` and continue the request.
    - **Pass:** If neither, forward the request unchanged.
- **Asynchronous Logging:** After the LLM returns a response, call the `/log` endpoint to record the entire transaction (redacted prompt, detections, and action).

### 2. mitmproxy Configuration
- Configure `mitmproxy` to listen on port 8080.
- Use `mitmproxy --scripts src/proxy/addon.py` for execution.

---

## 🚀 Phase 4: Dashboard & Integration Implementation Plan

The goal is to provide a user-friendly interface to monitor audit logs and manage detection events.

### 1. Dashboard Backend (`src/api/main.py`)
- Add a new GET endpoint `/dashboard` that renders an HTML template using `Jinja2`.
- Fetch the last 100 audit logs from the SQLite database using `sqlalchemy`.
- Add simple search and filter (by `user_id`, `severity`, or `detection_type`).

### 2. Dashboard Frontend (`src/api/templates/dashboard.html`)
- Use a clean, modern UI (Simple CSS/Bootstrap) to display a table of audit events.
- **Severity Highlighting:** Use colors (Red for High, Yellow for Medium, Green for Low) for quick identification.
- **Redacted Preview:** Allow clicking to view the full redacted prompt and detection types.

### 3. Basic Authentication
- Protect the `/dashboard` and `/log` endpoints with the same `X-API-KEY` mechanism or basic auth for the dashboard browser view.

---

## ✅ Evaluation Criteria

To verify the implementation of Phase 3 and 4, the following tests must be performed:

### 1. Proxy Interception Test (Phase 3)
- **Scenario:** Send a request to `api.openai.com` via the proxy with a clean prompt.
    - **Expected Result:** Request passes through and returns a valid LLM response.
- **Scenario:** Send a request to `api.openai.com` with a PAN number (`ABCDE1234F`).
    - **Expected Result:** Proxy returns `403 Forbidden` with the custom CIAI error. Request never reaches OpenAI.
- **Scenario:** Send a request with a phone number (PII).
    - **Expected Result:** OpenAI receives the prompt but the phone number is replaced with `[REDACTED]`.

### 2. Logging Integrity Test
- **Scenario:** Perform a blocked request.
    - **Expected Result:** A new entry appears in the `audit_log` table with `action="block"` and `severity="high"`.

### 3. Dashboard Functionality Test (Phase 4)
- **Scenario:** Access `http://localhost:8000/dashboard` in a browser.
    - **Expected Result:** The audit logs are displayed in a formatted table with timestamp, user ID, and detection types.
- **Scenario:** Filter by "High" severity.
    - **Expected Result:** Only Aadhaar/PAN/API Key leaks are shown.

### 4. Performance Latency Check
- **Benchmark:** Measure time taken for a request with and without the proxy.
    - **Target:** The detection engine overhead should be less than **200ms** per request.
