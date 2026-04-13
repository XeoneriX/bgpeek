"""Tests for the Redis-backed circuit breaker."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from bgpeek.core.circuit_breaker import is_device_available, record_failure, record_success


def _mock_redis() -> AsyncMock:
    """Return a mock Redis client with pipeline support."""
    redis = AsyncMock()
    redis.zcount = AsyncMock(return_value=0)
    redis.zadd = AsyncMock()
    redis.zremrangebyscore = AsyncMock()
    redis.delete = AsyncMock()

    pipe = MagicMock()
    pipe.zadd = MagicMock()
    pipe.zremrangebyscore = MagicMock()
    pipe.expire = MagicMock()
    pipe.execute = AsyncMock()

    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=pipe)
    ctx.__aexit__ = AsyncMock(return_value=False)
    redis.pipeline = lambda **kw: ctx

    return redis


async def test_is_available_when_no_failures() -> None:
    redis = _mock_redis()
    redis.zcount = AsyncMock(return_value=0)
    with patch("bgpeek.core.circuit_breaker._get_redis", return_value=redis):
        with patch("bgpeek.core.circuit_breaker.settings") as mock_settings:
            mock_settings.circuit_breaker_enabled = True
            mock_settings.circuit_breaker_threshold = 3
            mock_settings.circuit_breaker_cooldown = 300
            assert await is_device_available("rt1") is True


async def test_unavailable_after_threshold_failures() -> None:
    redis = _mock_redis()
    redis.zcount = AsyncMock(return_value=3)
    with patch("bgpeek.core.circuit_breaker._get_redis", return_value=redis):
        with patch("bgpeek.core.circuit_breaker.settings") as mock_settings:
            mock_settings.circuit_breaker_enabled = True
            mock_settings.circuit_breaker_threshold = 3
            mock_settings.circuit_breaker_cooldown = 300
            assert await is_device_available("rt1") is False


async def test_record_success_clears_failures() -> None:
    redis = _mock_redis()
    with patch("bgpeek.core.circuit_breaker._get_redis", return_value=redis):
        with patch("bgpeek.core.circuit_breaker.settings") as mock_settings:
            mock_settings.circuit_breaker_enabled = True
            await record_success("rt1")
    redis.delete.assert_awaited_once_with("bgpeek:cb:rt1")


async def test_record_failure_uses_pipeline() -> None:
    redis = _mock_redis()
    ctx = redis.pipeline()
    pipe = await ctx.__aenter__()
    with patch("bgpeek.core.circuit_breaker._get_redis", return_value=redis):
        with patch("bgpeek.core.circuit_breaker.settings") as mock_settings:
            mock_settings.circuit_breaker_enabled = True
            mock_settings.circuit_breaker_cooldown = 300
            mock_settings.circuit_breaker_threshold = 3
            await record_failure("rt1")
    pipe.zadd.assert_called_once()
    pipe.zremrangebyscore.assert_called_once()
    pipe.execute.assert_awaited_once()


async def test_graceful_degradation_when_redis_unavailable() -> None:
    with patch("bgpeek.core.circuit_breaker._get_redis", return_value=None):
        with patch("bgpeek.core.circuit_breaker.settings") as mock_settings:
            mock_settings.circuit_breaker_enabled = True
            assert await is_device_available("rt1") is True


async def test_disabled_breaker_always_returns_true() -> None:
    with patch("bgpeek.core.circuit_breaker.settings") as mock_settings:
        mock_settings.circuit_breaker_enabled = False
        assert await is_device_available("rt1") is True


async def test_disabled_breaker_record_failure_is_noop() -> None:
    with patch("bgpeek.core.circuit_breaker.settings") as mock_settings:
        mock_settings.circuit_breaker_enabled = False
        await record_failure("rt1")


async def test_disabled_breaker_record_success_is_noop() -> None:
    with patch("bgpeek.core.circuit_breaker.settings") as mock_settings:
        mock_settings.circuit_breaker_enabled = False
        await record_success("rt1")
