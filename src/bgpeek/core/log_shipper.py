"""Asynchronous HTTP log shipper — optional secondary sink for structlog events.

Set `BGPEEK_LOG_SHIP_URL` to any endpoint that accepts one of three wire
formats (`ndjson`, `loki`, `elasticsearch`). A background task batches events
and POSTs them; the log call path never blocks. If the endpoint is down,
events accumulate up to `BGPEEK_LOG_SHIP_QUEUE_MAX` then drop oldest-first.
`stdout` remains the always-live sink, regardless of shipper state.

Design choices:

- A `deque(maxlen=N)` is the queue. `append` is atomic in CPython and auto-
  drops the oldest entry on overflow, giving us backpressure-safe enqueuing
  from synchronous structlog processors without explicit locking.
- The structlog processor takes a defensive snapshot (`.copy()`) of the
  event dict before any downstream renderer mutates it.
- The flusher loop wakes every `batch_timeout` seconds or when the queue is
  full; whichever comes first. Delivery failures are logged to stderr (not
  shipped, to avoid feedback loops) and the batch is dropped.
- On shutdown we cancel the loop and perform a final best-effort flush so
  events produced late in the request cycle still land at the backend.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
import time
from collections import deque
from collections.abc import Callable, Iterable, MutableMapping
from typing import Any

import httpx

from bgpeek import __version__
from bgpeek.config import settings

_USER_AGENT = f"bgpeek/{__version__}"

_shipper: LogShipper | None = None


Formatter = Callable[[Iterable[dict[str, Any]]], tuple[bytes, str]]
"""Format adapter: takes a batch of event dicts, returns (body_bytes, content_type)."""


def _format_ndjson(batch: Iterable[dict[str, Any]]) -> tuple[bytes, str]:
    lines = (json.dumps(evt, default=str) for evt in batch)
    return ("\n".join(lines) + "\n").encode(), "application/x-ndjson"


def _format_elasticsearch(batch: Iterable[dict[str, Any]]) -> tuple[bytes, str]:
    """Bulk API NDJSON: `{"index":{}}\n<event>\n` pairs, one action + doc per event."""
    parts: list[str] = []
    for evt in batch:
        parts.append('{"index":{}}')
        parts.append(json.dumps(evt, default=str))
    body = "\n".join(parts) + "\n"
    return body.encode(), "application/x-ndjson"


def _format_loki(batch: Iterable[dict[str, Any]]) -> tuple[bytes, str]:
    """Loki push schema. Everything in a single stream labelled service=bgpeek."""
    values: list[list[str]] = []
    for evt in batch:
        # Loki expects nanosecond-precision string timestamps and a string line.
        ts = evt.get("timestamp")
        ns = _loki_ts(ts)
        values.append([ns, json.dumps(evt, default=str)])
    body = json.dumps(
        {"streams": [{"stream": {"service": "bgpeek"}, "values": values}]},
        default=str,
    ).encode()
    return body, "application/json"


def _loki_ts(value: object) -> str:
    """Best-effort ISO-string → nanoseconds-since-epoch. Falls back to current time."""
    if isinstance(value, str):
        try:
            from datetime import datetime

            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return str(int(dt.timestamp() * 1_000_000_000))
        except ValueError:
            pass
    return str(time.time_ns())


_FORMATTERS: dict[str, Formatter] = {
    "ndjson": _format_ndjson,
    "elasticsearch": _format_elasticsearch,
    "loki": _format_loki,
}


class LogShipper:
    """Queue + background flusher that POSTs structured events to an HTTP sink."""

    def __init__(
        self,
        url: str,
        *,
        format: str = "ndjson",  # noqa: A002
        headers: dict[str, str] | None = None,
        batch_size: int = 100,
        batch_timeout: float = 2.0,
        queue_max: int = 10000,
        http_timeout: float = 5.0,
    ) -> None:
        if format not in _FORMATTERS:
            raise ValueError(
                f"unknown log_ship_format {format!r}; expected one of {sorted(_FORMATTERS)}"
            )
        self._url = url
        self._formatter: Formatter = _FORMATTERS[format]
        self._headers = dict(headers or {})
        self._batch_size = max(1, batch_size)
        self._batch_timeout = max(0.05, batch_timeout)
        self._queue: deque[dict[str, Any]] = deque(maxlen=max(1, queue_max))
        self._http_timeout = http_timeout
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    def enqueue(self, event: dict[str, Any]) -> None:
        """Add an event to the queue. Never blocks; oldest entry is dropped on overflow."""
        self._queue.append(event)

    @property
    def queue_depth(self) -> int:
        return len(self._queue)

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run())

    async def shutdown(self) -> None:
        """Stop the background loop and drain whatever remains in a final POST."""
        if self._task is None:
            return
        self._stopping.set()
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None
        # Best-effort final flush so events produced late in the request cycle land.
        if self._queue:
            batch = self._drain(len(self._queue))
            await self._flush(batch)

    def _drain(self, limit: int) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        while self._queue and len(batch) < limit:
            batch.append(self._queue.popleft())
        return batch

    async def _run(self) -> None:
        while not self._stopping.is_set():
            await asyncio.sleep(self._batch_timeout)
            if not self._queue:
                continue
            batch = self._drain(self._batch_size)
            if batch:
                await self._flush(batch)

    async def _flush(self, batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        body, content_type = self._formatter(batch)
        headers = {
            "Content-Type": content_type,
            "User-Agent": _USER_AGENT,
            **self._headers,
        }
        try:
            async with httpx.AsyncClient(timeout=self._http_timeout) as client:
                resp = await client.post(self._url, content=body, headers=headers)
            if not resp.is_success:
                _warn_to_stderr(
                    "log_ship_http_error",
                    count=len(batch),
                    status=resp.status_code,
                )
        except Exception as exc:
            _warn_to_stderr("log_ship_delivery_failed", count=len(batch), error=str(exc))


def _warn_to_stderr(event: str, **fields: object) -> None:
    """Emit a delivery-failure notice outside the shipping pipeline.

    We deliberately avoid structlog here to prevent a broken endpoint from
    producing a storm of shipped warnings that the shipper would try to
    re-ship and fail on again.
    """
    parts = [f"{k}={v!r}" for k, v in fields.items()]
    sys.stderr.write(f"[bgpeek] {event} {' '.join(parts)}\n")
    sys.stderr.flush()


def get_shipper() -> LogShipper | None:
    """Return the active shipper, or None when shipping is disabled."""
    return _shipper


def build_shipper_from_settings() -> LogShipper | None:
    """Construct a LogShipper from current settings, or return None when disabled."""
    url = settings.log_ship_url.strip()
    if not url:
        return None
    headers = _parse_headers(settings.log_ship_headers)
    return LogShipper(
        url=url,
        format=settings.log_ship_format.lower(),
        headers=headers,
        batch_size=settings.log_ship_batch_size,
        batch_timeout=settings.log_ship_batch_timeout_sec,
        queue_max=settings.log_ship_queue_max,
        http_timeout=settings.log_ship_timeout_sec,
    )


def _parse_headers(raw: str) -> dict[str, str]:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _warn_to_stderr("log_ship_invalid_headers_json", raw=raw)
        return {}
    if not isinstance(parsed, dict):
        _warn_to_stderr("log_ship_headers_not_object", type=type(parsed).__name__)
        return {}
    return {str(k): str(v) for k, v in parsed.items()}


async def install_shipper() -> None:
    """Build the shipper from settings and start it. Call on app startup."""
    global _shipper
    if _shipper is not None:
        return
    shipper = build_shipper_from_settings()
    if shipper is None:
        return
    await shipper.start()
    _shipper = shipper


async def shutdown_shipper() -> None:
    """Drain + stop the shipper. Call on app shutdown."""
    global _shipper
    if _shipper is None:
        return
    await _shipper.shutdown()
    _shipper = None


def _shipping_processor(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor: snapshot the event into the shipper queue, pass-through."""
    if _shipper is not None:
        _shipper.enqueue(dict(event_dict))
    return event_dict
