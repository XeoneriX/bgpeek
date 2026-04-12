"""Tests for the sliding-window rate limiter."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from bgpeek.core.rate_limit import (
    RateLimitResult,
    _effective_limit,
    check_rate_limit,
    rate_limit_login,
    rate_limit_query,
)
from bgpeek.models.user import User, UserRole

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(role: UserRole = UserRole.PUBLIC, user_id: int = 1) -> User:
    from datetime import UTC, datetime

    return User(
        id=user_id,
        username="tester",
        email=None,
        role=role,
        enabled=True,
        auth_provider="local",
        api_key_hash=None,
        password_hash=None,
        created_at=datetime.now(tz=UTC),
        last_login_at=None,
    )


class FakeRedis:
    """In-memory Redis mock that implements sorted-set operations."""

    def __init__(self) -> None:
        self._data: dict[str, list[tuple[str, float]]] = {}

    def pipeline(self, transaction: bool = True) -> FakePipeline:  # noqa: ARG002
        return FakePipeline(self)

    async def zrange(
        self,
        key: str,
        start: int,
        stop: int,
        withscores: bool = False,  # noqa: ARG002
    ) -> list[tuple[str, float]]:
        entries = sorted(self._data.get(key, []), key=lambda e: e[1])
        # Python slice is exclusive on the right; Redis ZRANGE is inclusive.
        return entries[start : stop + 1 if stop >= 0 else None]

    # Internal helpers used by FakePipeline
    def _zremrangebyscore(self, key: str, lo: float, hi: float) -> int:
        if key not in self._data:
            return 0
        before = len(self._data[key])
        self._data[key] = [(m, s) for m, s in self._data[key] if not (lo <= s <= hi)]
        return before - len(self._data[key])

    def _zcard(self, key: str) -> int:
        return len(self._data.get(key, []))

    def _zadd(self, key: str, mapping: dict[str, float]) -> int:
        if key not in self._data:
            self._data[key] = []
        added = 0
        for member, score in mapping.items():
            self._data[key].append((member, score))
            added += 1
        return added

    def _expire(self, key: str, seconds: int) -> bool:  # noqa: ARG002
        return True


class FakePipeline:
    """Accumulates commands and executes them against FakeRedis."""

    def __init__(self, redis: FakeRedis) -> None:
        self._redis = redis
        self._commands: list[tuple[str, tuple[object, ...]]] = []

    def zremrangebyscore(self, key: str, lo: float, hi: float) -> FakePipeline:
        self._commands.append(("zremrangebyscore", (key, lo, hi)))
        return self

    def zcard(self, key: str) -> FakePipeline:
        self._commands.append(("zcard", (key,)))
        return self

    def zadd(self, key: str, mapping: dict[str, float]) -> FakePipeline:
        self._commands.append(("zadd", (key, mapping)))
        return self

    def expire(self, key: str, seconds: int) -> FakePipeline:
        self._commands.append(("expire", (key, seconds)))
        return self

    async def execute(self) -> list[object]:
        results: list[object] = []
        for cmd, args in self._commands:
            fn = getattr(self._redis, f"_{cmd}")
            results.append(fn(*args))
        self._commands.clear()
        return results


# ---------------------------------------------------------------------------
# Core sliding-window tests
# ---------------------------------------------------------------------------


async def test_allows_requests_under_limit():
    fake = FakeRedis()
    with patch("bgpeek.core.rate_limit.get_redis", return_value=fake):
        result = await check_rate_limit("test:1.2.3.4", limit=5, window=60)
    assert result.allowed is True
    assert result.remaining == 4
    assert result.limit == 5


async def test_blocks_requests_over_limit():
    fake = FakeRedis()
    with patch("bgpeek.core.rate_limit.get_redis", return_value=fake):
        for _ in range(5):
            result = await check_rate_limit("test:1.2.3.4", limit=5, window=60)
        assert result.allowed is True
        assert result.remaining == 0

        # The 6th request should be denied.
        result = await check_rate_limit("test:1.2.3.4", limit=5, window=60)
    assert result.allowed is False
    assert result.remaining == 0


async def test_remaining_decrements():
    fake = FakeRedis()
    with patch("bgpeek.core.rate_limit.get_redis", return_value=fake):
        r1 = await check_rate_limit("test:dec", limit=3, window=60)
        r2 = await check_rate_limit("test:dec", limit=3, window=60)
        r3 = await check_rate_limit("test:dec", limit=3, window=60)
    assert r1.remaining == 2
    assert r2.remaining == 1
    assert r3.remaining == 0


async def test_different_keys_dont_interfere():
    fake = FakeRedis()
    with patch("bgpeek.core.rate_limit.get_redis", return_value=fake):
        for _ in range(3):
            await check_rate_limit("test:alpha", limit=3, window=60)

        # alpha is exhausted
        r_alpha = await check_rate_limit("test:alpha", limit=3, window=60)
        # beta should still be fine
        r_beta = await check_rate_limit("test:beta", limit=3, window=60)

    assert r_alpha.allowed is False
    assert r_beta.allowed is True


async def test_graceful_degradation_redis_unavailable():
    with patch("bgpeek.core.rate_limit.get_redis", side_effect=RuntimeError("no redis")):
        result = await check_rate_limit("test:no-redis", limit=5, window=60)
    assert result.allowed is True
    assert result.remaining == 5


async def test_graceful_degradation_redis_error_during_pipeline():
    mock_redis = AsyncMock()
    broken_pipe = AsyncMock()
    broken_pipe.execute = AsyncMock(side_effect=ConnectionError("boom"))
    mock_redis.pipeline = lambda transaction=True: broken_pipe  # noqa: ARG005

    with patch("bgpeek.core.rate_limit.get_redis", return_value=mock_redis):
        result = await check_rate_limit("test:broken", limit=5, window=60)
    assert result.allowed is True


async def test_rate_limit_result_fields():
    result = RateLimitResult(allowed=True, limit=30, remaining=29, reset=60)
    assert result.limit == 30
    assert result.remaining == 29
    assert result.reset == 60


async def test_reset_is_positive_when_blocked():
    fake = FakeRedis()
    with patch("bgpeek.core.rate_limit.get_redis", return_value=fake):
        for _ in range(2):
            await check_rate_limit("test:reset", limit=2, window=60)
        result = await check_rate_limit("test:reset", limit=2, window=60)
    assert result.allowed is False
    assert result.reset >= 1


# ---------------------------------------------------------------------------
# Admin bypass / NOC multiplier
# ---------------------------------------------------------------------------


def test_effective_limit_admin_bypass():
    assert _effective_limit(30, _make_user(UserRole.ADMIN)) == 0


def test_effective_limit_noc_double():
    assert _effective_limit(30, _make_user(UserRole.NOC)) == 60


def test_effective_limit_public_unchanged():
    assert _effective_limit(30, _make_user(UserRole.PUBLIC)) == 30


def test_effective_limit_anonymous():
    assert _effective_limit(30, None) == 30


# ---------------------------------------------------------------------------
# FastAPI dependency integration (using a tiny test app)
# ---------------------------------------------------------------------------


def _build_app(
    user: User | None = None,
    rate_limit_enabled: bool = True,
) -> FastAPI:
    """Build a minimal app with rate-limited endpoints for testing."""
    test_app = FastAPI()

    async def _override_optional_auth() -> User | None:
        return user

    async def _override_auth() -> User:
        assert user is not None
        return user

    from bgpeek.core.auth import authenticate, optional_auth

    test_app.dependency_overrides[optional_auth] = _override_optional_auth
    test_app.dependency_overrides[authenticate] = _override_auth

    @test_app.post("/query")
    async def _query(
        _rl: None = Depends(rate_limit_query),  # noqa: B008
    ) -> dict[str, str]:
        return {"ok": "true"}

    @test_app.post("/login")
    async def _login(
        _rl: None = Depends(rate_limit_login),  # noqa: B008
    ) -> dict[str, str]:
        return {"ok": "true"}

    return test_app


async def test_query_endpoint_returns_rate_limit_headers():
    fake = FakeRedis()
    app = _build_app(user=_make_user(UserRole.PUBLIC))

    with (
        patch("bgpeek.core.rate_limit.get_redis", return_value=fake),
        patch("bgpeek.core.rate_limit.settings") as mock_settings,
    ):
        mock_settings.rate_limit_enabled = True
        mock_settings.rate_limit_query = 30
        client = TestClient(app)
        resp = client.post("/query")

    assert resp.status_code == 200
    assert "X-RateLimit-Limit" in resp.headers
    assert "X-RateLimit-Remaining" in resp.headers
    assert "X-RateLimit-Reset" in resp.headers


async def test_query_endpoint_429_when_limit_exceeded():
    fake = FakeRedis()
    app = _build_app(user=_make_user(UserRole.PUBLIC))

    with (
        patch("bgpeek.core.rate_limit.get_redis", return_value=fake),
        patch("bgpeek.core.rate_limit.settings") as mock_settings,
    ):
        mock_settings.rate_limit_enabled = True
        mock_settings.rate_limit_query = 2
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/query")
        client.post("/query")
        resp = client.post("/query")

    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


async def test_admin_bypasses_rate_limit():
    fake = FakeRedis()
    app = _build_app(user=_make_user(UserRole.ADMIN))

    with (
        patch("bgpeek.core.rate_limit.get_redis", return_value=fake),
        patch("bgpeek.core.rate_limit.settings") as mock_settings,
    ):
        mock_settings.rate_limit_enabled = True
        mock_settings.rate_limit_query = 1
        client = TestClient(app)
        # Even after exceeding the limit, admin still gets through.
        resp1 = client.post("/query")
        resp2 = client.post("/query")
        resp3 = client.post("/query")

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp3.status_code == 200


async def test_noc_gets_double_limit():
    fake = FakeRedis()
    app = _build_app(user=_make_user(UserRole.NOC))

    with (
        patch("bgpeek.core.rate_limit.get_redis", return_value=fake),
        patch("bgpeek.core.rate_limit.settings") as mock_settings,
    ):
        mock_settings.rate_limit_enabled = True
        mock_settings.rate_limit_query = 2  # NOC gets 4
        client = TestClient(app, raise_server_exceptions=False)
        for _ in range(4):
            resp = client.post("/query")
            assert resp.status_code == 200

        # 5th should be blocked
        resp = client.post("/query")
    assert resp.status_code == 429


async def test_login_rate_limiting():
    fake = FakeRedis()
    app = _build_app(user=None)

    with (
        patch("bgpeek.core.rate_limit.get_redis", return_value=fake),
        patch("bgpeek.core.rate_limit.settings") as mock_settings,
    ):
        mock_settings.rate_limit_enabled = True
        mock_settings.rate_limit_login = 2
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/login")
        client.post("/login")
        resp = client.post("/login")

    assert resp.status_code == 429
    assert "too many login attempts" in resp.json()["detail"]


async def test_rate_limit_disabled():
    app = _build_app(user=_make_user(UserRole.PUBLIC))

    with patch("bgpeek.core.rate_limit.settings") as mock_settings:
        mock_settings.rate_limit_enabled = False
        client = TestClient(app)
        resp = client.post("/query")

    assert resp.status_code == 200
    assert "X-RateLimit-Limit" not in resp.headers
