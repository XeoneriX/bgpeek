"""Tests for bgpeek.core.log_shipper."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from bgpeek.config import settings
from bgpeek.core import log_shipper
from bgpeek.core.log_shipper import (
    LogShipper,
    _format_elasticsearch,
    _format_loki,
    _format_ndjson,
    _parse_headers,
    _shipping_processor,
    build_shipper_from_settings,
)

# ---------------------------------------------------------------------------
# Format adapters
# ---------------------------------------------------------------------------


def test_format_ndjson_one_event_per_line() -> None:
    batch = [{"event": "one", "x": 1}, {"event": "two", "x": 2}]
    body, ct = _format_ndjson(batch)
    assert ct == "application/x-ndjson"
    lines = [line for line in body.decode().split("\n") if line]
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"event": "one", "x": 1}
    assert json.loads(lines[1]) == {"event": "two", "x": 2}


def test_format_elasticsearch_interleaves_action_and_doc() -> None:
    batch = [{"event": "one"}, {"event": "two"}]
    body, ct = _format_elasticsearch(batch)
    assert ct == "application/x-ndjson"
    lines = [line for line in body.decode().split("\n") if line]
    # Expect alternating action / document lines.
    assert len(lines) == 4
    assert json.loads(lines[0]) == {"index": {}}
    assert json.loads(lines[1]) == {"event": "one"}
    assert json.loads(lines[2]) == {"index": {}}
    assert json.loads(lines[3]) == {"event": "two"}


def test_format_loki_single_stream_with_values() -> None:
    batch = [
        {"event": "one", "timestamp": "2026-04-20T12:00:00+00:00"},
        {"event": "two"},  # no timestamp; shipper fills from wall clock
    ]
    body, ct = _format_loki(batch)
    assert ct == "application/json"
    payload = json.loads(body)
    assert payload["streams"][0]["stream"] == {"service": "bgpeek"}
    values = payload["streams"][0]["values"]
    assert len(values) == 2
    assert values[0][0].isdigit()  # ns timestamp string
    assert json.loads(values[0][1])["event"] == "one"


# ---------------------------------------------------------------------------
# Queue behaviour
# ---------------------------------------------------------------------------


def test_enqueue_drops_oldest_when_full() -> None:
    shipper = LogShipper(url="http://example.com/ignored", queue_max=3)
    shipper.enqueue({"n": 1})
    shipper.enqueue({"n": 2})
    shipper.enqueue({"n": 3})
    shipper.enqueue({"n": 4})  # overflow → drops {"n": 1}

    assert shipper.queue_depth == 3
    remaining = shipper._drain(3)
    assert [e["n"] for e in remaining] == [2, 3, 4]


def test_invalid_format_raises() -> None:
    with pytest.raises(ValueError, match="unknown log_ship_format"):
        LogShipper(url="http://x", format="garbage")


# ---------------------------------------------------------------------------
# Flush / HTTP path
# ---------------------------------------------------------------------------


def _http_client_mock(response_status: int = 200) -> MagicMock:
    """Build a MagicMock that replaces `httpx.AsyncClient` and captures POST args."""
    posted_payloads: list[dict[str, Any]] = []

    async def _fake_post(url: str, *, content: bytes, headers: dict[str, str]) -> httpx.Response:
        posted_payloads.append({"url": url, "content": content, "headers": headers})
        req = httpx.Request("POST", url)
        return httpx.Response(response_status, request=req)

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(side_effect=_fake_post)
    mock_client.posted = posted_payloads
    return mock_client


async def test_flush_posts_batch_and_records_content_type() -> None:
    shipper = LogShipper(
        url="http://example.com/ingest", batch_size=5, batch_timeout=0.1, queue_max=10
    )
    shipper.enqueue({"event": "a"})
    shipper.enqueue({"event": "b"})

    mock_client = _http_client_mock()
    with patch("bgpeek.core.log_shipper.httpx.AsyncClient", return_value=mock_client):
        await shipper._flush(shipper._drain(5))

    assert len(mock_client.posted) == 1
    call = mock_client.posted[0]
    assert call["url"] == "http://example.com/ingest"
    assert call["headers"]["Content-Type"] == "application/x-ndjson"
    body_lines = [line for line in call["content"].decode().split("\n") if line]
    assert [json.loads(line)["event"] for line in body_lines] == ["a", "b"]


async def test_flush_skips_empty_batch() -> None:
    shipper = LogShipper(url="http://example.com/ingest")
    with patch("bgpeek.core.log_shipper.httpx.AsyncClient") as mock_ctx:
        await shipper._flush([])
    mock_ctx.assert_not_called()


async def test_flush_swallows_http_errors() -> None:
    """Delivery failure must not raise — the shipper keeps running."""
    shipper = LogShipper(url="http://example.com/ingest")

    def _raise(*_: object, **__: object) -> None:
        raise httpx.ConnectError("boom")

    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(side_effect=_raise)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("bgpeek.core.log_shipper.httpx.AsyncClient", return_value=mock_client):
        await shipper._flush([{"event": "x"}])  # must not raise


async def test_run_loop_flushes_on_interval_then_shuts_down() -> None:
    shipper = LogShipper(
        url="http://example.com/ingest", batch_size=5, batch_timeout=0.05, queue_max=10
    )
    mock_client = _http_client_mock()
    with patch("bgpeek.core.log_shipper.httpx.AsyncClient", return_value=mock_client):
        shipper.enqueue({"event": "a"})
        await shipper.start()
        # give the loop a couple of batch_timeout ticks
        await asyncio.sleep(0.15)
        assert len(mock_client.posted) >= 1

        shipper.enqueue({"event": "b"})
        await shipper.shutdown()

    # Final flush on shutdown guarantees the trailing event was POSTed.
    flushed_events: list[str] = []
    for call in mock_client.posted:
        for line in call["content"].decode().split("\n"):
            if line:
                flushed_events.append(json.loads(line)["event"])
    assert "a" in flushed_events
    assert "b" in flushed_events


# ---------------------------------------------------------------------------
# Structlog processor glue
# ---------------------------------------------------------------------------


def test_shipping_processor_noop_when_shipper_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(log_shipper, "_shipper", None)
    event = {"event": "hello", "x": 1}
    returned = _shipping_processor(None, "info", event)
    assert returned is event  # pass-through


def test_shipping_processor_enqueues_copy_when_shipper_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = LogShipper(url="http://example.com")
    monkeypatch.setattr(log_shipper, "_shipper", fake)
    event = {"event": "hello", "x": 1}

    _shipping_processor(None, "info", event)

    assert fake.queue_depth == 1
    snapshot = fake._drain(1)[0]
    assert snapshot == {"event": "hello", "x": 1}
    # Mutating the original after shipping must not corrupt the snapshot.
    event["x"] = 99
    assert snapshot["x"] == 1


# ---------------------------------------------------------------------------
# Settings plumbing
# ---------------------------------------------------------------------------


def test_build_from_settings_disabled_by_default() -> None:
    # The default in settings has log_ship_url="" so build returns None.
    assert build_shipper_from_settings() is None or settings.log_ship_url == ""


def test_build_from_settings_uses_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_ship_url", "http://example.com/x")
    monkeypatch.setattr(settings, "log_ship_format", "ndjson")
    shipper = build_shipper_from_settings()
    assert shipper is not None
    assert shipper._url == "http://example.com/x"


def test_build_from_settings_rejects_unknown_format(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_ship_url", "http://example.com/x")
    monkeypatch.setattr(settings, "log_ship_format", "garbage")
    with pytest.raises(ValueError, match="unknown log_ship_format"):
        build_shipper_from_settings()


def test_parse_headers_empty_returns_empty() -> None:
    assert _parse_headers("") == {}
    assert _parse_headers("   ") == {}


def test_parse_headers_valid_json() -> None:
    assert _parse_headers('{"Authorization": "Bearer xyz"}') == {"Authorization": "Bearer xyz"}


def test_parse_headers_invalid_json_returns_empty() -> None:
    assert _parse_headers("not json") == {}


def test_parse_headers_non_object_returns_empty() -> None:
    assert _parse_headers("[1,2,3]") == {}


def test_scrub_url_drops_query_string() -> None:
    from bgpeek.core.log_shipper import _scrub_url

    assert _scrub_url("http://vl:9428/insert/jsonline?api_key=secret") == (
        "http://vl:9428/insert/jsonline"
    )
    assert _scrub_url("http://vl:9428/") == "http://vl:9428/"
