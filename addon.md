# Build the Proxy (mitmproxy addon)

## Install mitmproxy
```bash
pip install mitmproxy




Python code - 
"
import json
import requests

DETECTION_API = "http://localhost:8000/detect"
LOG_API = "http://localhost:8000/log"

class LLMInterceptor:
    def request(self, flow):
        # Only intercept OpenAI-like requests (adjust URL as needed)
        if "api.openai.com/v1/chat/completions" in flow.request.pretty_host:
            body = json.loads(flow.request.content)
            prompt = body.get("messages", [])[-1].get("content", "")

            # Call detection API
            resp = requests.post(DETECTION_API, json={"text": prompt})
            result = resp.json()

            if result["block"]:
                # Block the request and return error
                flow.response = http.Response.make(
                    403,
                    json.dumps({"error": "Request blocked due to sensitive data"}),
                    {"Content-Type": "application/json"}
                )
            elif result["redacted"]:
                # Modify the prompt with redacted version
                body["messages"][-1]["content"] = result["redacted_text"]
                flow.request.content = json.dumps(body).encode()

            # Log asynchronously (fire and forget)
            requests.post(LOG_API, json={
                "user_id": flow.request.headers.get("X-User-ID", "unknown"),
                "original_prompt": prompt,
                "redacted_prompt": result.get("redacted_text", prompt),
                "detections": result["detections"],
                "action": "block" if result["block"] else "redact"
            })

addons = [LLMInterceptor()]"






to run it  - "mitmdump -s proxy_addon.py --listen-port 8080"

Configure browser to use proxy

    Set HTTP/HTTPS proxy to localhost:8080.

    Install mitmproxy certificate (visit mitm.it).



