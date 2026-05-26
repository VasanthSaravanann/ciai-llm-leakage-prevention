import pytest

import fakeredis


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    """Replace redis.from_url with a fakeredis instance for tests by default."""
    fake = fakeredis.FakeServer()

    def _from_url(url):
        return fakeredis.FakeRedis(server=fake)

    monkeypatch.setattr('redis.from_url', _from_url)
    yield