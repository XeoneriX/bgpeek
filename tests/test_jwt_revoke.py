"""Tests for the Redis-backed JWT revocation list (B3 — prod-gate hardening)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from bgpeek.core import jwt_revoke


class TestRevokeNoRedis:
    """With Redis unreachable, revocation is a best-effort no-op (fail-open)."""

    async def test_revoke_no_redis(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(jwt_revoke, "_get_redis", AsyncMock(return_value=None))
        # Must not raise — operator would be locked out of logout otherwise.
        await jwt_revoke.revoke("abc123", ttl_seconds=60)

    async def test_is_revoked_no_redis_returns_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(jwt_revoke, "_get_redis", AsyncMock(return_value=None))
        # Fail-open: a Redis outage must not 401 every authenticated request.
        assert await jwt_revoke.is_revoked("abc123") is False


class TestRevokeHappyPath:
    async def test_revoke_sets_key_with_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        redis = MagicMock()
        redis.setex = AsyncMock()
        monkeypatch.setattr(jwt_revoke, "_get_redis", AsyncMock(return_value=redis))
        await jwt_revoke.revoke("abc123", ttl_seconds=60)
        redis.setex.assert_awaited_once_with("bgpeek:jwt_revoked:abc123", 60, "1")

    async def test_revoke_skips_expired_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-positive TTL means the token has already expired; no need to
        track it (Redis wouldn't accept TTL=0 as SETEX anyway)."""
        redis = MagicMock()
        redis.setex = AsyncMock()
        monkeypatch.setattr(jwt_revoke, "_get_redis", AsyncMock(return_value=redis))
        await jwt_revoke.revoke("abc", ttl_seconds=0)
        await jwt_revoke.revoke("abc", ttl_seconds=-1)
        redis.setex.assert_not_awaited()

    async def test_is_revoked_true_when_key_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        redis = MagicMock()
        redis.exists = AsyncMock(return_value=1)
        monkeypatch.setattr(jwt_revoke, "_get_redis", AsyncMock(return_value=redis))
        assert await jwt_revoke.is_revoked("abc123") is True
        redis.exists.assert_awaited_once_with("bgpeek:jwt_revoked:abc123")

    async def test_is_revoked_false_when_key_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        redis = MagicMock()
        redis.exists = AsyncMock(return_value=0)
        monkeypatch.setattr(jwt_revoke, "_get_redis", AsyncMock(return_value=redis))
        assert await jwt_revoke.is_revoked("abc123") is False


class TestRevokeRedisErrors:
    """Redis exceptions must be swallowed — fail-open on both sides."""

    async def test_revoke_swallows_exceptions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        redis = MagicMock()
        redis.setex = AsyncMock(side_effect=Exception("boom"))
        monkeypatch.setattr(jwt_revoke, "_get_redis", AsyncMock(return_value=redis))
        # Must not raise.
        await jwt_revoke.revoke("abc", ttl_seconds=60)

    async def test_is_revoked_swallows_exceptions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        redis = MagicMock()
        redis.exists = AsyncMock(side_effect=Exception("boom"))
        monkeypatch.setattr(jwt_revoke, "_get_redis", AsyncMock(return_value=redis))
        assert await jwt_revoke.is_revoked("abc") is False
