import os
import time
from typing import Optional

import redis
import logging

from src.config import settings

DEFAULT_QUOTA = int(os.getenv('DEFAULT_QUOTA_PER_MINUTE', '60'))
DEFAULT_WINDOW = int(os.getenv('DEFAULT_QUOTA_WINDOW_SECONDS', '60'))


class RateLimiter:
    """Simple Redis-backed fixed-window rate limiter per API key."""

    def __init__(self, redis_url: str | None = None):
        candidate = redis_url if redis_url is not None else os.getenv("REDIS_URL", "")
        self.redis_url = candidate.strip() if isinstance(candidate, str) else ""
        if not self.redis_url or self.redis_url.lower() in {"none", "false"}:
            self.r = None
        else:
            self.r = redis.from_url(self.redis_url)

    def allow(self, key: str, quota: Optional[int] = None, window: Optional[int] = None) -> bool:
        if not self.r:
            # No Redis configured: default to allow to preserve backward compatibility
            return True
        q = quota or DEFAULT_QUOTA
        w = window or DEFAULT_WINDOW
        # use fixed window key based on current epoch window
        window_start = int(time.time() / w) * w
        redis_key = f"quota:{key}:{window_start}"
        try:
            val = self.r.incr(redis_key)
            if val == 1:
                self.r.expire(redis_key, w + 1)
            return val <= q
        except Exception as e:
            # On Redis errors, respect GATEWAY_MODE: fail_closed (deny) or fail_open (allow)
            logging.exception("RateLimiter Redis error")
            gateway_mode = settings.GATEWAY_MODE
            if gateway_mode == 'fail_closed':
                return False
            return True
