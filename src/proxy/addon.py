"""
CIAI mitmproxy Interceptor Addon (Phase 3)
=========================================
Intercepts LLM API requests, analyzes them for sensitive data, 
and blocks or redacts before they reach the provider.
"""

import json
import logging
import asyncio
import httpx
from mitmproxy import http

# Configuration
CIAI_API_URL = "http://localhost:8000"
API_KEY = "ciai-dev-key"  # Matches settings.API_KEY
TARGET_HOSTS = ["api.openai.com", "api.anthropic.com"]
TARGET_PATH = "/v1/chat/completions"

logger = logging.getLogger("ciai.proxy")


class CIAIInterceptor:
    def __init__(self):
        self.client = httpx.AsyncClient(base_url=CIAI_API_URL, timeout=10.0)

    async def request(self, flow: http.HTTPFlow) -> None:
        """
        Intercept and process LLM API requests asynchronously.
        """
        # 1. Filter for target LLM providers
        if flow.request.pretty_host not in TARGET_HOSTS or TARGET_PATH not in flow.request.path:
            return

        logger.info(f"Intercepted LLM request to {flow.request.pretty_host}")

        try:
            # 2. Extract request body
            data = json.loads(flow.request.content)
            messages = data.get("messages", [])
            full_text = " ".join([m.get("content", "") for m in messages if isinstance(m.get("content"), str)])

            if not full_text:
                return

            # 3. Call local CIAI detection API
            headers = {"X-API-KEY": API_KEY, "Content-Type": "application/json"}
            resp = await self.client.post(
                "/detect",
                json={"text": full_text},
                headers=headers
            )

            if resp.status_code != 200:
                logger.error(f"CIAI API error: {resp.status_code}")
                return

            result = resp.json()

            # 4. Handle Actions
            if result.get("block"):
                logger.warning(f"BLOCKING request from {flow.client_conn.address[0]}")
                flow.response = http.Response.make(
                    403,
                    json.dumps({
                        "error": {
                            "message": "Request blocked by CIAI - Sensitive data detected.",
                            "detections": result["detections"]
                        }
                    }),
                    {"Content-Type": "application/json"}
                )
                return

            if result.get("redact"):
                logger.info(f"REDACTING request from {flow.client_conn.address[0]}")
                for msg in reversed(messages):
                    if msg.get("role") == "user":
                        msg["content"] = result["redacted_text"]
                        break
                flow.request.content = json.dumps(data).encode("utf-8")

        except Exception as e:
            logger.error(f"Interceptor error: {str(e)}")

    def _log_event(self, flow: http.HTTPFlow, result: dict, action: str) -> None:
        """
        Record the event in the audit log via the /log endpoint.
        """
        try:
            log_data = {
                "user_id": flow.client_conn.address[0],
                "redacted_prompt": result.get("redacted_text", "Blocked request"),
                "detection_types": result.get("detections", []),
                "action": action,
                "severity": result.get("severity", "low")
            }
            
            requests.post(
                f"{CIAI_API_URL}/log",
                json=log_data,
                headers={"X-API-KEY": API_KEY},
                timeout=2
            )
        except Exception as e:
            logger.error(f"Failed to log event to CIAI API: {str(e)}")


addons = [CIAIInterceptor()]
