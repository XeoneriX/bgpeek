"""Tests for the admin panel UI (SSR routes)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from bgpeek.main import app
from bgpeek.models.user import User, UserRole

_NOW = datetime.now(tz=UTC)

_ADMIN = User(
    id=1,
    username="admin",
    email="admin@example.com",
    role=UserRole.ADMIN,
    auth_provider="api_key",
    api_key_hash="h",
    enabled=True,
    created_at=_NOW,
)

_NOC = User(
    id=2,
    username="noc",
    email=None,
    role=UserRole.NOC,
    auth_provider="api_key",
    api_key_hash="h2",
    enabled=True,
    created_at=_NOW,
)


def test_admin_index_no_auth_returns_401() -> None:
    client = TestClient(app)
    response = client.get("/admin")
    assert response.status_code == 401


def test_admin_index_noc_user_returns_403() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_NOC),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin", headers={"X-API-Key": "any"})
    assert response.status_code == 403


def test_admin_index_admin_renders_dashboard() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch(
            "bgpeek.main.device_crud.list_devices",
            new=AsyncMock(return_value=[1, 2, 3]),
        ),
        patch(
            "bgpeek.main.user_crud.list_users",
            new=AsyncMock(return_value=[_ADMIN, _NOC]),
        ),
        patch(
            "bgpeek.main.credential_crud.list_credentials",
            new=AsyncMock(return_value=[1]),
        ),
        patch(
            "bgpeek.main.webhook_crud.list_webhooks",
            new=AsyncMock(return_value=[]),
        ),
        patch("bgpeek.main.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    body = response.text
    assert "Dashboard" in body
    # Stat counts rendered
    assert ">3<" in body  # devices
    assert ">2<" in body  # users
    assert ">1<" in body  # credentials
    assert ">0<" in body  # webhooks
    # Sidebar nav present
    assert "/admin/devices" in body
    assert "/admin/users" in body


def test_admin_link_shown_for_admin_in_main_navbar() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.main.get_pool", return_value=object()),
        patch("bgpeek.main.device_crud.list_devices", new=AsyncMock(return_value=[])),
    ):
        client = TestClient(app)
        response = client.get("/", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'href="/admin"' in response.text


def test_admin_link_hidden_for_noc_in_main_navbar() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_NOC),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.main.get_pool", return_value=object()),
        patch("bgpeek.main.device_crud.list_devices", new=AsyncMock(return_value=[])),
    ):
        client = TestClient(app)
        response = client.get("/", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'href="/admin"' not in response.text
