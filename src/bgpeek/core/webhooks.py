"""Async webhook dispatcher — fire-and-forget HTTP POST notifications."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from bgpeek import __version__
from bgpeek.db.pool import get_pool
from bgpeek.db.webhooks import list_webhooks_for_event
from bgpeek.models.webhook import (
    Webhook,
    WebhookEvent,
    WebhookPayload,
    resolve_and_pin_webhook_target,
)

log = structlog.get_logger(__name__)

_TIMEOUT = httpx.Timeout(10.0)
_RETRY_DELAY = 2.0
_MAX_RETRIES = 2
_USER_AGENT = f"bgpeek/{__version__}"

_pending_tasks: set[asyncio.Task[None]] = set()


def _sign_payload(body: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for the request body."""
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


async def _deliver(webhook: Webhook, body: bytes, event: WebhookEvent) -> None:
    """POST the payload to a single webhook URL with one retry on failure."""
    try:
        pinned_url, original_host = resolve_and_pin_webhook_target(webhook.url)
    except ValueError as exc:
        log.warning(
            "webhook_target_blocked",
            webhook=webhook.name,
            event=event.value,
            reason=str(exc),
        )
        return

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": _USER_AGENT,
        "X-Webhook-Event": event.value,
        # Preserve virtual-host routing on the receiver side; httpx would
        # otherwise send Host: <ip> for the pinned URL.
        "Host": original_host,
    }
    if webhook.secret:
        headers["X-Webhook-Signature"] = _sign_payload(body, webhook.secret)

    # For HTTPS, force SNI + certificate verification to match the original
    # hostname even though the URL now carries an IP literal.
    extensions: dict[str, Any] = {"sni_hostname": original_host}

    for attempt in range(_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    pinned_url, content=body, headers=headers, extensions=extensions
                )
            if resp.is_success:
                log.debug(
                    "webhook_delivered",
                    webhook=webhook.name,
                    webhook_event=event.value,
                    status=resp.status_code,
                )
                return
            log.warning(
                "webhook_http_error",
                webhook=webhook.name,
                event=event.value,
                status=resp.status_code,
                attempt=attempt + 1,
            )
        except Exception:
            log.warning(
                "webhook_delivery_failed",
                webhook=webhook.name,
                event=event.value,
                attempt=attempt + 1,
                exc_info=True,
            )
        if attempt < _MAX_RETRIES:
            await asyncio.sleep(_RETRY_DELAY * (2**attempt))


async def dispatch_webhook(event: WebhookEvent, data: dict[str, Any]) -> None:
    """Fire webhooks for the given event. Non-blocking, best-effort."""
    try:
        pool = get_pool()
        hooks = await list_webhooks_for_event(pool, event)
    except Exception:
        log.warning("webhook_lookup_failed", webhook_event=event.value, exc_info=True)
        return

    if not hooks:
        return

    payload = WebhookPayload(
        event=event,
        timestamp=datetime.now(tz=UTC).isoformat(),
        data=data,
    )
    body = json.dumps(payload.model_dump(), default=str).encode()

    for hook in hooks:
        task = asyncio.create_task(_deliver(hook, body, event))
        _pending_tasks.add(task)
        task.add_done_callback(_pending_tasks.discard)


async def shutdown() -> None:
    """Cancel and await all pending webhook delivery tasks."""
    if not _pending_tasks:
        return
    log.info("cancelling pending webhook tasks", count=len(_pending_tasks))
    for task in _pending_tasks:
        task.cancel()
    await asyncio.gather(*_pending_tasks, return_exceptions=True)
    _pending_tasks.clear()


async def send_test_payload(webhook: Webhook) -> bool:
    """Send a test payload to a webhook. Returns True on 2xx response."""
    try:
        pinned_url, original_host = resolve_and_pin_webhook_target(webhook.url)
    except ValueError as exc:
        log.warning("webhook_test_target_blocked", webhook=webhook.name, reason=str(exc))
        return False

    payload = WebhookPayload(
        event=WebhookEvent.QUERY,
        timestamp=datetime.now(tz=UTC).isoformat(),
        data={"test": True, "message": "bgpeek webhook test"},
    )
    body = json.dumps(payload.model_dump(), default=str).encode()

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": _USER_AGENT,
        "X-Webhook-Event": "test",
        "Host": original_host,
    }
    if webhook.secret:
        headers["X-Webhook-Signature"] = _sign_payload(body, webhook.secret)

    extensions: dict[str, Any] = {"sni_hostname": original_host}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                pinned_url, content=body, headers=headers, extensions=extensions
            )
        return resp.is_success
    except Exception:
        log.warning("webhook_test_failed", webhook=webhook.name, exc_info=True)
        return False
