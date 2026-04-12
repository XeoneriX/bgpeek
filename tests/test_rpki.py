"""Tests for the RPKI validation module."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx

from bgpeek.core.rpki import (
    RpkiStatus,
    _extract_origin_asn,
    validate_routes,
    validate_rpki,
)
from bgpeek.models.query import BGPRoute


def test_extract_origin_asn_simple() -> None:
    assert _extract_origin_asn("64496 64497 64498") == 64498


def test_extract_origin_asn_single() -> None:
    assert _extract_origin_asn("64496") == 64496


def test_extract_origin_asn_empty_string() -> None:
    assert _extract_origin_asn("") is None


def test_extract_origin_asn_none() -> None:
    assert _extract_origin_asn("") is None


def test_extract_origin_asn_whitespace_only() -> None:
    assert _extract_origin_asn("   ") is None


def test_extract_origin_asn_trailing_spaces() -> None:
    assert _extract_origin_asn("64496 64497  ") == 64497


def _mock_redis_unavailable() -> AsyncMock:
    return patch("bgpeek.core.rpki.get_redis", side_effect=RuntimeError)


def _mock_redis_empty() -> AsyncMock:
    mock = AsyncMock()
    mock.get = AsyncMock(return_value=None)
    mock.set = AsyncMock()
    return mock


def _make_route(
    prefix: str = "8.8.8.0/24",
    as_path: str = "64496 64497 15169",
    best: bool = False,
) -> BGPRoute:
    return BGPRoute(prefix=prefix, as_path=as_path, next_hop="10.0.0.1", best=best)


async def test_validate_rpki_valid() -> None:
    mock_response = httpx.Response(
        200,
        json={"prefix": "8.8.8.0/24", "asn": 15169, "state": "Valid"},
        request=httpx.Request("GET", "https://example.com"),
    )
    redis_mock = _mock_redis_empty()
    with (
        patch("bgpeek.core.rpki.get_redis", return_value=redis_mock),
        patch("bgpeek.core.rpki.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await validate_rpki("8.8.8.0/24", 15169)

    assert result == RpkiStatus.VALID


async def test_validate_rpki_invalid() -> None:
    mock_response = httpx.Response(
        200,
        json={"prefix": "1.2.3.0/24", "asn": 99999, "state": "Invalid"},
        request=httpx.Request("GET", "https://example.com"),
    )
    redis_mock = _mock_redis_empty()
    with (
        patch("bgpeek.core.rpki.get_redis", return_value=redis_mock),
        patch("bgpeek.core.rpki.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await validate_rpki("1.2.3.0/24", 99999)

    assert result == RpkiStatus.INVALID


async def test_validate_rpki_not_found() -> None:
    mock_response = httpx.Response(
        200,
        json={"prefix": "10.0.0.0/8", "asn": 64496, "state": "NotFound"},
        request=httpx.Request("GET", "https://example.com"),
    )
    redis_mock = _mock_redis_empty()
    with (
        patch("bgpeek.core.rpki.get_redis", return_value=redis_mock),
        patch("bgpeek.core.rpki.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await validate_rpki("10.0.0.0/8", 64496)

    assert result == RpkiStatus.NOT_FOUND


async def test_validate_rpki_timeout_returns_unknown() -> None:
    redis_mock = _mock_redis_empty()
    with (
        patch("bgpeek.core.rpki.get_redis", return_value=redis_mock),
        patch("bgpeek.core.rpki.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await validate_rpki("8.8.8.0/24", 15169)

    assert result == RpkiStatus.UNKNOWN


async def test_validate_rpki_http_error_returns_unknown() -> None:
    redis_mock = _mock_redis_empty()
    with (
        patch("bgpeek.core.rpki.get_redis", return_value=redis_mock),
        patch("bgpeek.core.rpki.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await validate_rpki("8.8.8.0/24", 15169)

    assert result == RpkiStatus.UNKNOWN


async def test_validate_routes_enriches_routes() -> None:
    routes = [
        _make_route("8.8.8.0/24", "64496 15169"),
        _make_route("1.1.1.0/24", "64496 13335"),
    ]
    with (
        patch("bgpeek.core.rpki.settings") as mock_settings,
        patch("bgpeek.core.rpki.validate_rpki") as mock_validate,
    ):
        mock_settings.rpki_enabled = True
        mock_validate.side_effect = [RpkiStatus.VALID, RpkiStatus.NOT_FOUND]

        result = await validate_routes(routes)

    assert result[0].rpki_status == "valid"
    assert result[1].rpki_status == "not_found"


async def test_validate_routes_deduplication() -> None:
    routes = [
        _make_route("8.8.8.0/24", "64496 15169"),
        _make_route("8.8.8.0/24", "64497 15169"),  # same prefix+origin
    ]
    with (
        patch("bgpeek.core.rpki.settings") as mock_settings,
        patch("bgpeek.core.rpki.validate_rpki") as mock_validate,
    ):
        mock_settings.rpki_enabled = True
        mock_validate.return_value = RpkiStatus.VALID

        result = await validate_routes(routes)

    # Should only call once for the same (prefix, origin_asn) pair
    mock_validate.assert_awaited_once_with("8.8.8.0/24", 15169)
    assert result[0].rpki_status == "valid"
    assert result[1].rpki_status == "valid"


async def test_validate_routes_disabled_via_config() -> None:
    routes = [_make_route()]
    with patch("bgpeek.core.rpki.settings") as mock_settings:
        mock_settings.rpki_enabled = False

        result = await validate_routes(routes)

    assert result[0].rpki_status is None


async def test_validate_routes_empty_as_path_gets_unknown() -> None:
    routes = [_make_route("8.8.8.0/24", "")]
    with (
        patch("bgpeek.core.rpki.settings") as mock_settings,
        patch("bgpeek.core.rpki.validate_rpki") as mock_validate,
    ):
        mock_settings.rpki_enabled = True

        result = await validate_routes(routes)

    # Empty as_path means no origin ASN can be extracted → UNKNOWN
    assert result[0].rpki_status == "unknown"
    mock_validate.assert_not_awaited()


async def test_validate_routes_none_as_path_gets_unknown() -> None:
    route = BGPRoute(prefix="8.8.8.0/24", as_path=None, next_hop="10.0.0.1")
    with (
        patch("bgpeek.core.rpki.settings") as mock_settings,
        patch("bgpeek.core.rpki.validate_rpki") as mock_validate,
    ):
        mock_settings.rpki_enabled = True

        result = await validate_routes([route])

    assert result[0].rpki_status == "unknown"
    mock_validate.assert_not_awaited()


async def test_validate_rpki_uses_cache() -> None:
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value="valid")
    redis_mock.set = AsyncMock()

    with (
        patch("bgpeek.core.rpki.get_redis", return_value=redis_mock),
        patch("bgpeek.core.rpki.httpx.AsyncClient") as mock_client_cls,
    ):
        result = await validate_rpki("8.8.8.0/24", 15169)

    assert result == RpkiStatus.VALID
    # HTTP client should not be called when cache hit
    mock_client_cls.assert_not_called()


async def test_validate_routes_handles_api_exception_gracefully() -> None:
    routes = [_make_route("8.8.8.0/24", "64496 15169")]
    with (
        patch("bgpeek.core.rpki.settings") as mock_settings,
        patch("bgpeek.core.rpki.validate_rpki", side_effect=Exception("boom")),
    ):
        mock_settings.rpki_enabled = True

        result = await validate_routes(routes)

    # Exception in validate_rpki is caught by gather, status set to UNKNOWN
    assert result[0].rpki_status == "unknown"
