"""Tests for the API key authentication dependency."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from fastapi import Depends, FastAPI, status
from fastapi.testclient import TestClient

from bgpeek.core.auth import optional_api_key, require_api_key, require_role
from bgpeek.models.user import User, UserRole

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


_admin_dep = require_role(UserRole.ADMIN)


def _build_app() -> FastAPI:
    """Minimal app with auth-protected endpoints for testing."""
    app = FastAPI()

    @app.get("/protected")
    async def protected(user: User = Depends(require_api_key)) -> dict[str, str]:  # noqa: B008  # type: ignore[assignment]
        return {"user": user.username}

    @app.get("/optional")
    async def optional(user: User | None = Depends(optional_api_key)) -> dict[str, str]:  # noqa: B008  # type: ignore[assignment]
        return {"user": user.username if user else "anonymous"}

    @app.get("/admin-only")
    async def admin_only(user: User = Depends(_admin_dep)) -> dict[str, str]:  # noqa: B008  # type: ignore[assignment]
        return {"user": user.username}

    return app


def _patch_lookup(return_value: User | None) -> object:
    return patch(
        "bgpeek.core.auth.user_crud.get_user_by_api_key",
        new_callable=AsyncMock,
        return_value=return_value,
    )


def _patch_pool() -> object:
    return patch("bgpeek.core.auth.get_pool", return_value=AsyncMock())


class TestRequireApiKey:
    def test_valid_key_returns_user(self) -> None:
        app = _build_app()
        with _patch_pool(), _patch_lookup(_ADMIN):
            client = TestClient(app)
            resp = client.get("/protected", headers={"X-API-Key": "test-key"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "admin"

    def test_missing_key_returns_422(self) -> None:
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/protected")
        assert resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_invalid_key_returns_401(self) -> None:
        app = _build_app()
        with _patch_pool(), _patch_lookup(None):
            client = TestClient(app)
            resp = client.get("/protected", headers={"X-API-Key": "bad-key"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


class TestOptionalApiKey:
    def test_no_key_returns_anonymous(self) -> None:
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/optional")
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "anonymous"

    def test_valid_key_returns_user(self) -> None:
        app = _build_app()
        with _patch_pool(), _patch_lookup(_NOC):
            client = TestClient(app)
            resp = client.get("/optional", headers={"X-API-Key": "test-key"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "noc-user"

    def test_invalid_key_returns_401(self) -> None:
        app = _build_app()
        with _patch_pool(), _patch_lookup(None):
            client = TestClient(app)
            resp = client.get("/optional", headers={"X-API-Key": "bad-key"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


class TestRequireRole:
    def test_correct_role_succeeds(self) -> None:
        app = _build_app()
        with _patch_pool(), _patch_lookup(_ADMIN):
            client = TestClient(app)
            resp = client.get("/admin-only", headers={"X-API-Key": "test-key"})
        assert resp.status_code == status.HTTP_200_OK

    def test_wrong_role_returns_403(self) -> None:
        app = _build_app()
        with _patch_pool(), _patch_lookup(_NOC):
            client = TestClient(app)
            resp = client.get("/admin-only", headers={"X-API-Key": "test-key"})
        assert resp.status_code == status.HTTP_403_FORBIDDEN
