import pytest

import fakeredis
from src.api.main import limiter as slowapi_limiter, rate_limiter
from slowapi.extension import Limiter as SlowapiLimiter


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Replace redis.from_url with a fakeredis instance for tests by default."""
    fake = fakeredis.FakeServer()

    def _from_url(url):
        return fakeredis.FakeRedis(server=fake)

    monkeypatch.setattr('redis.from_url', _from_url)
    monkeypatch.setattr(rate_limiter, 'r', fakeredis.FakeRedis(server=fake))
    monkeypatch.setattr(slowapi_limiter._limiter.storage, 'incr', lambda *args, **kwargs: 1)

    def _skip_rate_limit(self, request, *args, **kwargs):
        request.state.view_rate_limit = None
        return None

    monkeypatch.setattr(SlowapiLimiter, '_check_request_limit', _skip_rate_limit)
    yield