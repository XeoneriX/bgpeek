"""Tests for webhook CRUD, dispatch, and API endpoints."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import asyncpg
import httpx
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

from bgpeek.core.webhooks import _sign_payload, dispatch_webhook, send_test_payload
from bgpeek.db import webhooks as crud
from bgpeek.models.user import User, UserRole
from bgpeek.models.webhook import Webhook, WebhookCreate, WebhookEvent, WebhookUpdate

_NOW = datetime.now(tz=UTC)

_ADMIN = User(
    id=1,
    username="admin",
    email="admin@example.com",
    role=UserRole.ADMIN,
    auth_provider="api_key",
    api_key_hash="fakehash",
    enabled=True,
    created_at=_NOW,
    last_login_at=None,
)

_NOC = User(
    id=2,
    username="noc-user",
    email=None,
    role=UserRole.NOC,
    auth_provider="api_key",
    api_key_hash="fakehash2",
    enabled=True,
    created_at=_NOW,
    last_login_at=None,
)


def _webhook_payload(
    name: str = "test-hook",
    url: str = "https://example.com/hook",
    **overrides: object,
) -> WebhookCreate:
    base: dict[str, object] = {
        "name": name,
        "url": url,
        "events": [WebhookEvent.QUERY],
        "enabled": True,
    }
    base.update(overrides)
    return WebhookCreate(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# DB CRUD tests (real postgres via testcontainers)
# ---------------------------------------------------------------------------


async def test_create_webhook(pool: asyncpg.Pool) -> None:
    hook = await crud.create_webhook(pool, _webhook_payload())
    assert hook.id > 0
    assert hook.name == "test-hook"
    assert hook.url == "https://example.com/hook"
    assert hook.events == [WebhookEvent.QUERY]
    assert hook.enabled is True


async def test_get_webhook(pool: asyncpg.Pool) -> None:
    created = await crud.create_webhook(pool, _webhook_payload())
    fetched = await crud.get_webhook(pool, created.id)
    assert fetched is not None
    assert fetched.id == created.id
    assert fetched.name == created.name


async def test_get_missing_returns_none(pool: asyncpg.Pool) -> None:
    assert await crud.get_webhook(pool, 9999) is None


async def test_list_webhooks(pool: asyncpg.Pool) -> None:
    await crud.create_webhook(pool, _webhook_payload("hook-b"))
    await crud.create_webhook(pool, _webhook_payload("hook-a"))
    hooks = await crud.list_webhooks(pool)
    assert len(hooks) == 2
    assert hooks[0].name == "hook-a"
    assert hooks[1].name == "hook-b"


async def test_list_webhooks_for_event_filters(pool: asyncpg.Pool) -> None:
    await crud.create_webhook(pool, _webhook_payload("query-hook", events=[WebhookEvent.QUERY]))
    await crud.create_webhook(pool, _webhook_payload("login-hook", events=[WebhookEvent.LOGIN]))
    await crud.create_webhook(
        pool,
        _webhook_payload("disabled-hook", events=[WebhookEvent.QUERY], enabled=False),
    )

    query_hooks = await crud.list_webhooks_for_event(pool, WebhookEvent.QUERY)
    assert len(query_hooks) == 1
    assert query_hooks[0].name == "query-hook"

    login_hooks = await crud.list_webhooks_for_event(pool, WebhookEvent.LOGIN)
    assert len(login_hooks) == 1
    assert login_hooks[0].name == "login-hook"


async def test_update_webhook(pool: asyncpg.Pool) -> None:
    created = await crud.create_webhook(pool, _webhook_payload())
    updated = await crud.update_webhook(
        pool, created.id, WebhookUpdate(name="renamed", enabled=False)
    )
    assert updated is not None
    assert updated.name == "renamed"
    assert updated.enabled is False
    assert updated.updated_at >= created.updated_at


async def test_update_empty_returns_unchanged(pool: asyncpg.Pool) -> None:
    created = await crud.create_webhook(pool, _webhook_payload())
    unchanged = await crud.update_webhook(pool, created.id, WebhookUpdate())
    assert unchanged is not None
    assert unchanged.name == created.name


async def test_update_missing_returns_none(pool: asyncpg.Pool) -> None:
    assert await crud.update_webhook(pool, 9999, WebhookUpdate(name="x")) is None


async def test_delete_webhook(pool: asyncpg.Pool) -> None:
    created = await crud.create_webhook(pool, _webhook_payload())
    assert await crud.delete_webhook(pool, created.id) is True
    assert await crud.get_webhook(pool, created.id) is None


async def test_delete_missing_returns_false(pool: asyncpg.Pool) -> None:
    assert await crud.delete_webhook(pool, 9999) is False


# ---------------------------------------------------------------------------
# Dispatch tests (mocked httpx)
# ---------------------------------------------------------------------------


def test_hmac_signature() -> None:
    body = b'{"event":"query","data":{}}'
    hmac_secret = "test-secret"  # noqa: S105
    sig = _sign_payload(body, hmac_secret)
    expected = hmac.new(hmac_secret.encode(), body, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


async def test_dispatch_sends_post() -> None:
    hook = Webhook(
        id=1,
        name="test",
        url="https://example.com/hook",
        secret="s3cret",
        events=[WebhookEvent.QUERY],
        enabled=True,
        created_at=_NOW,
        updated_at=_NOW,
    )

    mock_response = httpx.Response(200)

    with (
        patch("bgpeek.core.webhooks.get_pool"),
        patch("bgpeek.core.webhooks.list_webhooks_for_event", new_callable=AsyncMock) as mock_list,
        patch("bgpeek.core.webhooks.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_list.return_value = [hook]
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client_instance

        await dispatch_webhook(WebhookEvent.QUERY, {"target": "8.8.8.8"})

        # Give the fire-and-forget task a chance to run
        import asyncio

        await asyncio.sleep(0.1)

        mock_client_instance.post.assert_called_once()
        call_kwargs = mock_client_instance.post.call_args
        assert call_kwargs[1]["headers"]["X-Webhook-Event"] == "query"
        assert "X-Webhook-Signature" in call_kwargs[1]["headers"]


async def test_dispatch_no_matching_webhooks() -> None:
    with (
        patch("bgpeek.core.webhooks.get_pool"),
        patch("bgpeek.core.webhooks.list_webhooks_for_event", new_callable=AsyncMock) as mock_list,
        patch("bgpeek.core.webhooks.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_list.return_value = []
        await dispatch_webhook(WebhookEvent.LOGIN, {"user": "test"})
        mock_client_cls.assert_not_called()


async def test_dispatch_skips_blocked_webhook_target() -> None:
    hook = Webhook(
        id=1,
        name="blocked-hook",
        url="https://example.com/hook",
        secret=None,
        events=[WebhookEvent.QUERY],
        enabled=True,
        created_at=_NOW,
        updated_at=_NOW,
    )

    with (
        patch("bgpeek.core.webhooks.get_pool"),
        patch("bgpeek.core.webhooks.list_webhooks_for_event", new_callable=AsyncMock) as mock_list,
        patch(
            "bgpeek.core.webhooks.validate_webhook_delivery_target",
            side_effect=ValueError("blocked target"),
        ),
        patch("bgpeek.core.webhooks.httpx.AsyncClient") as mock_client_cls,
    ):
        mock_list.return_value = [hook]
        await dispatch_webhook(WebhookEvent.QUERY, {"target": "1.1.1.1"})

        import asyncio

        await asyncio.sleep(0.1)
        mock_client_cls.assert_not_called()


async def test_dispatch_http_failure_logged_not_raised() -> None:
    hook = Webhook(
        id=1,
        name="fail-hook",
        url="https://example.com/hook",
        secret=None,
        events=[WebhookEvent.QUERY],
        enabled=True,
        created_at=_NOW,
        updated_at=_NOW,
    )

    with (
        patch("bgpeek.core.webhooks.get_pool"),
        patch("bgpeek.core.webhooks.list_webhooks_for_event", new_callable=AsyncMock) as mock_list,
        patch("bgpeek.core.webhooks.httpx.AsyncClient") as mock_client_cls,
        patch("bgpeek.core.webhooks.asyncio.sleep", new_callable=AsyncMock),
    ):
        mock_list.return_value = [hook]
        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = httpx.ConnectError("connection refused")
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client_instance

        # Should not raise
        await dispatch_webhook(WebhookEvent.QUERY, {"target": "1.1.1.1"})

        import asyncio

        await asyncio.sleep(0.1)


async def test_send_test_payload_success() -> None:
    hook = Webhook(
        id=1,
        name="test",
        url="https://example.com/hook",
        secret=None,
        events=[WebhookEvent.QUERY],
        enabled=True,
        created_at=_NOW,
        updated_at=_NOW,
    )
    mock_response = httpx.Response(200)

    with patch("bgpeek.core.webhooks.httpx.AsyncClient") as mock_client_cls:
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client_instance

        result = await send_test_payload(hook)
        assert result is True


async def test_send_test_payload_failure() -> None:
    hook = Webhook(
        id=1,
        name="test",
        url="https://example.com/hook",
        secret=None,
        events=[WebhookEvent.QUERY],
        enabled=True,
        created_at=_NOW,
        updated_at=_NOW,
    )

    with patch("bgpeek.core.webhooks.httpx.AsyncClient") as mock_client_cls:
        mock_client_instance = AsyncMock()
        mock_client_instance.post.side_effect = httpx.ConnectError("fail")
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client_instance

        result = await send_test_payload(hook)
        assert result is False


async def test_send_test_payload_blocked_target_returns_false() -> None:
    hook = Webhook(
        id=1,
        name="test",
        url="https://example.com/hook",
        secret=None,
        events=[WebhookEvent.QUERY],
        enabled=True,
        created_at=_NOW,
        updated_at=_NOW,
    )

    with (
        patch(
            "bgpeek.core.webhooks.validate_webhook_delivery_target",
            side_effect=ValueError("blocked target"),
        ),
        patch("bgpeek.core.webhooks.httpx.AsyncClient") as mock_client_cls,
    ):
        result = await send_test_payload(hook)
        assert result is False
        mock_client_cls.assert_not_called()


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


def _patch_lookup(return_value: User | None) -> object:
    return patch(
        "bgpeek.core.auth.user_crud.get_user_by_api_key",
        new_callable=AsyncMock,
        return_value=return_value,
    )


def _patch_pool() -> object:
    return patch("bgpeek.core.auth.get_pool", return_value=AsyncMock())


def _build_api_app() -> FastAPI:
    from bgpeek.api.webhooks import router

    app = FastAPI()
    app.include_router(router)
    return app


_SAMPLE_HOOK = Webhook(
    id=1,
    name="test-hook",
    url="https://example.com/hook",
    secret="s3cret",
    events=[WebhookEvent.QUERY],
    enabled=True,
    created_at=_NOW,
    updated_at=_NOW,
)


class TestWebhookAPI:
    def test_list_webhooks_admin(self) -> None:
        app = _build_api_app()
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.list_webhooks", new_callable=AsyncMock) as mock_list,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_list.return_value = [_SAMPLE_HOOK]
            client = TestClient(app)
            resp = client.get("/api/webhooks", headers={"X-API-Key": "test"})
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert len(data) == 1
        assert data[0]["secret"] == "****"  # noqa: S105

    def test_list_webhooks_non_admin_403(self) -> None:
        app = _build_api_app()
        with _patch_pool(), _patch_lookup(_NOC):
            client = TestClient(app)
            resp = client.get("/api/webhooks", headers={"X-API-Key": "test"})
        assert resp.status_code == status.HTTP_403_FORBIDDEN

    def test_create_webhook_admin(self) -> None:
        app = _build_api_app()
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.create_webhook", new_callable=AsyncMock) as mock_create,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_create.return_value = _SAMPLE_HOOK
            client = TestClient(app)
            resp = client.post(
                "/api/webhooks",
                headers={"X-API-Key": "test"},
                json={
                    "name": "test-hook",
                    "url": "https://example.com/hook",
                    "events": ["query"],
                },
            )
        assert resp.status_code == status.HTTP_201_CREATED

    def test_get_webhook_admin(self) -> None:
        app = _build_api_app()
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.get_webhook", new_callable=AsyncMock) as mock_get,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_get.return_value = _SAMPLE_HOOK
            client = TestClient(app)
            resp = client.get("/api/webhooks/1", headers={"X-API-Key": "test"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["secret"] == "****"  # noqa: S105

    def test_get_webhook_not_found(self) -> None:
        app = _build_api_app()
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.get_webhook", new_callable=AsyncMock) as mock_get,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_get.return_value = None
            client = TestClient(app)
            resp = client.get("/api/webhooks/999", headers={"X-API-Key": "test"})
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_update_webhook_admin(self) -> None:
        app = _build_api_app()
        updated = _SAMPLE_HOOK.model_copy(update={"name": "renamed"})
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.update_webhook", new_callable=AsyncMock) as mock_update,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_update.return_value = updated
            client = TestClient(app)
            resp = client.patch(
                "/api/webhooks/1",
                headers={"X-API-Key": "test"},
                json={"name": "renamed"},
            )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["name"] == "renamed"

    def test_delete_webhook_admin(self) -> None:
        app = _build_api_app()
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.delete_webhook", new_callable=AsyncMock) as mock_del,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_del.return_value = True
            client = TestClient(app)
            resp = client.delete("/api/webhooks/1", headers={"X-API-Key": "test"})
        assert resp.status_code == status.HTTP_204_NO_CONTENT

    def test_delete_webhook_not_found(self) -> None:
        app = _build_api_app()
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.delete_webhook", new_callable=AsyncMock) as mock_del,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_del.return_value = False
            client = TestClient(app)
            resp = client.delete("/api/webhooks/999", headers={"X-API-Key": "test"})
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_test_webhook_sends_payload(self) -> None:
        app = _build_api_app()
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.get_webhook", new_callable=AsyncMock) as mock_get,
            patch("bgpeek.api.webhooks.send_test_payload", new_callable=AsyncMock) as mock_send,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_get.return_value = _SAMPLE_HOOK
            mock_send.return_value = True
            client = TestClient(app)
            resp = client.post("/api/webhooks/1/test", headers={"X-API-Key": "test"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["success"] is True

    def test_test_webhook_not_found(self) -> None:
        app = _build_api_app()
        with (
            _patch_pool(),
            _patch_lookup(_ADMIN),
            patch("bgpeek.api.webhooks.crud.get_webhook", new_callable=AsyncMock) as mock_get,
            patch("bgpeek.api.webhooks.get_pool", return_value=AsyncMock()),
        ):
            mock_get.return_value = None
            client = TestClient(app)
            resp = client.post("/api/webhooks/999/test", headers={"X-API-Key": "test"})
        assert resp.status_code == status.HTTP_404_NOT_FOUND
