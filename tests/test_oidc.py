"""Tests for OIDC authentication backend, role extraction, and user provisioning."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import asyncpg
import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient

from bgpeek.core.oidc import extract_role_from_token, get_oidc_client, setup_oidc
from bgpeek.db import users as crud
from bgpeek.models.user import User, UserCreateLocal, UserRole

_COOKIE_NAME = "bgpeek_token"
_NOW = datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# extract_role_from_token — unit tests
# ---------------------------------------------------------------------------


def _oidc_settings(**overrides: object) -> MagicMock:
    s = MagicMock()
    defaults: dict[str, object] = {
        "oidc_enabled": True,
        "oidc_client_id": "bgpeek",
        "oidc_client_secret": "secret",
        "oidc_server_url": "https://keycloak.example.com/realms/bgpeek",
        "oidc_discovery_url": "",
        "oidc_scopes": "openid email profile",
        "oidc_role_claim": "realm_access.roles",
        "oidc_role_mapping": json.dumps({"bgpeek-admin": "admin", "bgpeek-noc": "noc"}),
        "oidc_default_role": "public",
        "session_secret": "test-session-secret",
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(s, k, v)
    return s


def test_extract_role_admin() -> None:
    token = {"realm_access": {"roles": ["bgpeek-admin", "bgpeek-noc"]}}
    with patch("bgpeek.core.oidc.settings", _oidc_settings()):
        role = extract_role_from_token(token)
    assert role == UserRole.ADMIN


def test_extract_role_noc() -> None:
    token = {"realm_access": {"roles": ["bgpeek-noc"]}}
    with patch("bgpeek.core.oidc.settings", _oidc_settings()):
        role = extract_role_from_token(token)
    assert role == UserRole.NOC


def test_extract_role_default_when_no_match() -> None:
    token = {"realm_access": {"roles": ["some-other-role"]}}
    with patch("bgpeek.core.oidc.settings", _oidc_settings()):
        role = extract_role_from_token(token)
    assert role == UserRole.PUBLIC


def test_extract_role_default_when_claim_missing() -> None:
    token = {"no_realm_access": {}}
    with patch("bgpeek.core.oidc.settings", _oidc_settings()):
        role = extract_role_from_token(token)
    assert role == UserRole.PUBLIC


def test_extract_role_with_empty_mapping() -> None:
    token = {"realm_access": {"roles": ["bgpeek-admin"]}}
    with patch("bgpeek.core.oidc.settings", _oidc_settings(oidc_role_mapping="")):
        role = extract_role_from_token(token)
    assert role == UserRole.PUBLIC


def test_extract_role_single_string_claim() -> None:
    token = {"role": "bgpeek-noc"}
    with patch("bgpeek.core.oidc.settings", _oidc_settings(oidc_role_claim="role")):
        role = extract_role_from_token(token)
    assert role == UserRole.NOC


# ---------------------------------------------------------------------------
# get_oidc_client — unit tests
# ---------------------------------------------------------------------------


def test_get_oidc_client_disabled() -> None:
    with patch("bgpeek.core.oidc.settings", _oidc_settings(oidc_enabled=False)):
        assert get_oidc_client() is None


# ---------------------------------------------------------------------------
# setup_oidc — unit tests
# ---------------------------------------------------------------------------


def test_setup_oidc_disabled_does_nothing() -> None:
    app = FastAPI()
    with patch("bgpeek.core.oidc.settings", _oidc_settings(oidc_enabled=False)):
        setup_oidc(app)
    # No SessionMiddleware added
    assert len(app.user_middleware) == 0


def test_setup_oidc_enabled_adds_session_middleware() -> None:
    app = FastAPI()
    with patch("bgpeek.core.oidc.settings", _oidc_settings()):
        setup_oidc(app)
    # SessionMiddleware should be added
    middleware_classes = [m.cls.__name__ for m in app.user_middleware]
    assert "SessionMiddleware" in middleware_classes


def test_setup_oidc_auto_derives_discovery_url() -> None:
    app = FastAPI()
    with (
        patch("bgpeek.core.oidc.settings", _oidc_settings(oidc_discovery_url="")),
        patch("bgpeek.core.oidc.oauth") as mock_oauth,
    ):
        setup_oidc(app)

    mock_oauth.register.assert_called_once()
    call_kwargs = mock_oauth.register.call_args
    assert call_kwargs[1]["server_metadata_url"] == (
        "https://keycloak.example.com/realms/bgpeek/.well-known/openid-configuration"
    )


def test_setup_oidc_uses_explicit_discovery_url() -> None:
    app = FastAPI()
    custom_url = "https://custom.example.com/.well-known/openid-configuration"
    with (
        patch("bgpeek.core.oidc.settings", _oidc_settings(oidc_discovery_url=custom_url)),
        patch("bgpeek.core.oidc.oauth") as mock_oauth,
    ):
        setup_oidc(app)

    call_kwargs = mock_oauth.register.call_args
    assert call_kwargs[1]["server_metadata_url"] == custom_url


# ---------------------------------------------------------------------------
# OIDC routes — integration tests (mocked OAuth client)
# ---------------------------------------------------------------------------


def _make_oidc_user(user_id: int = 10, username: str = "oidcuser") -> User:
    return User(
        id=user_id,
        username=username,
        email="oidc@example.com",
        role=UserRole.NOC,
        auth_provider="oidc",
        enabled=True,
        created_at=_NOW,
        last_login_at=None,
    )


def _build_oidc_app() -> FastAPI:
    from bgpeek.api.auth import router

    app = FastAPI()
    app.include_router(router)
    return app


class TestOidcLoginRoute:
    def test_oidc_login_disabled_returns_404(self) -> None:
        app = _build_oidc_app()
        with patch("bgpeek.api.auth.get_oidc_client", return_value=None):
            client = TestClient(app, follow_redirects=False)
            resp = client.get("/auth/oidc/login")
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_oidc_login_redirects(self) -> None:
        mock_client = AsyncMock()
        mock_client.authorize_redirect = AsyncMock(
            return_value=MagicMock(
                status_code=302,
                headers={"location": "https://keycloak.example.com/auth"},
                body=b"",
            ),
        )
        app = _build_oidc_app()
        with patch("bgpeek.api.auth.get_oidc_client", return_value=mock_client):
            client = TestClient(app, follow_redirects=False)
            client.get("/auth/oidc/login")
        # The mock returns a Response object directly — Starlette may forward it.
        mock_client.authorize_redirect.assert_called_once()


class TestOidcCallbackRoute:
    def _patch_pool(self) -> object:
        pool = AsyncMock()
        pool.execute = AsyncMock(return_value="UPDATE 1")
        return patch("bgpeek.api.auth.get_pool", return_value=pool)

    def test_oidc_callback_disabled_returns_404(self) -> None:
        app = _build_oidc_app()
        with patch("bgpeek.api.auth.get_oidc_client", return_value=None):
            client = TestClient(app, follow_redirects=False)
            resp = client.get("/auth/oidc/callback")
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_oidc_callback_token_exchange_failure(self) -> None:
        mock_client = AsyncMock()
        mock_client.authorize_access_token = AsyncMock(side_effect=Exception("bad state"))
        app = _build_oidc_app()
        with patch("bgpeek.api.auth.get_oidc_client", return_value=mock_client):
            client = TestClient(app, follow_redirects=False)
            resp = client.get("/auth/oidc/callback?code=abc&state=xyz")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_oidc_callback_success(self) -> None:
        # Authlib nests the parsed ID-token claims under "userinfo"; the role
        # claim (realm_access) lives inside it, not at the response root.
        token_data = {
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 3600,
            "userinfo": {
                "sub": "oidc-sub-123",
                "email": "oidc@example.com",
                "preferred_username": "oidcuser",
                "realm_access": {"roles": ["bgpeek-noc"]},
            },
        }

        mock_client = AsyncMock()
        mock_client.authorize_access_token = AsyncMock(return_value=token_data)

        oidc_user = _make_oidc_user()

        app = _build_oidc_app()
        with (
            patch("bgpeek.api.auth.get_oidc_client", return_value=mock_client),
            patch("bgpeek.api.auth.extract_role_from_token", return_value=UserRole.NOC),
            patch(
                "bgpeek.api.auth.crud.upsert_oidc_user",
                new_callable=AsyncMock,
                return_value=oidc_user,
            ),
            self._patch_pool(),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get("/auth/oidc/callback?code=abc&state=xyz")

        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/"
        assert _COOKIE_NAME in resp.cookies

    def test_oidc_callback_maps_nested_role_claim(self) -> None:
        """Role must be resolved from the real claim path nested under userinfo.

        Regression guard for the authz bug where role extraction read
        ``token_data`` at the root while Authlib nests claims under
        ``userinfo`` — every OIDC login silently fell back to the default
        role. This test does *not* mock ``extract_role_from_token``; it drives
        the real traversal against an Authlib-shaped token and asserts the
        mapped role reaches ``upsert_oidc_user``.
        """
        token_data = {
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 3600,
            "userinfo": {
                "sub": "oidc-sub-123",
                "email": "oidc@example.com",
                "preferred_username": "oidcuser",
                "realm_access": {"roles": ["bgpeek-noc"]},
            },
        }

        mock_client = AsyncMock()
        mock_client.authorize_access_token = AsyncMock(return_value=token_data)

        upsert_mock = AsyncMock(return_value=_make_oidc_user())

        app = _build_oidc_app()
        with (
            patch("bgpeek.api.auth.get_oidc_client", return_value=mock_client),
            patch("bgpeek.core.oidc.settings", _oidc_settings()),
            patch("bgpeek.api.auth.crud.upsert_oidc_user", new=upsert_mock),
            self._patch_pool(),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get("/auth/oidc/callback?code=abc&state=xyz")

        assert resp.status_code == status.HTTP_303_SEE_OTHER
        upsert_mock.assert_awaited_once()
        assert upsert_mock.await_args.kwargs["role"] == UserRole.NOC

    def test_oidc_callback_missing_claims(self) -> None:
        token_data = {
            "userinfo": {},
        }

        mock_client = AsyncMock()
        mock_client.authorize_access_token = AsyncMock(return_value=token_data)

        app = _build_oidc_app()
        with (
            patch("bgpeek.api.auth.get_oidc_client", return_value=mock_client),
            patch("bgpeek.api.auth.extract_role_from_token", return_value=UserRole.PUBLIC),
            self._patch_pool(),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get("/auth/oidc/callback?code=abc&state=xyz")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_oidc_callback_uses_sub_when_no_preferred_username(self) -> None:
        token_data = {
            "userinfo": {
                "sub": "oidc-sub-456",
                "email": "sub@example.com",
            },
            "realm_access": {"roles": []},
        }

        mock_client = AsyncMock()
        mock_client.authorize_access_token = AsyncMock(return_value=token_data)

        oidc_user = _make_oidc_user(username="oidc-sub-456")

        app = _build_oidc_app()
        with (
            patch("bgpeek.api.auth.get_oidc_client", return_value=mock_client),
            patch("bgpeek.api.auth.extract_role_from_token", return_value=UserRole.PUBLIC),
            patch(
                "bgpeek.api.auth.crud.upsert_oidc_user",
                new_callable=AsyncMock,
                return_value=oidc_user,
            ) as mock_upsert,
            self._patch_pool(),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get("/auth/oidc/callback?code=abc&state=xyz")

        assert resp.status_code == status.HTTP_303_SEE_OTHER
        mock_upsert.assert_called_once()
        call_kwargs = mock_upsert.call_args
        assert call_kwargs[1]["username"] == "oidc-sub-456"


# ---------------------------------------------------------------------------
# upsert_oidc_user — integration tests (real PostgreSQL)
# ---------------------------------------------------------------------------


async def test_upsert_oidc_user_creates_new(pool: asyncpg.Pool) -> None:
    user = await crud.upsert_oidc_user(
        pool, "oidcuser", "oidc@example.com", UserRole.NOC, "oidc-sub-123"
    )
    assert user.username == "oidcuser"
    assert user.email == "oidc@example.com"
    assert user.role == UserRole.NOC
    assert user.auth_provider == "oidc"
    assert user.enabled is True


async def test_upsert_oidc_user_updates_existing(pool: asyncpg.Pool) -> None:
    first = await crud.upsert_oidc_user(
        pool, "oidcuser", "old@example.com", UserRole.PUBLIC, "oidc-sub-123"
    )
    assert first.email == "old@example.com"
    assert first.role == UserRole.PUBLIC

    second = await crud.upsert_oidc_user(
        pool, "oidcuser", "new@example.com", UserRole.NOC, "oidc-sub-123"
    )
    assert second.id == first.id
    assert second.email == "new@example.com"
    assert second.role == UserRole.NOC
    assert second.last_login_at is not None


async def test_upsert_oidc_user_rejects_cross_provider_collision(pool: asyncpg.Pool) -> None:
    """A local user's row must not be mutated by an OIDC upsert of the same username."""
    local = await crud.create_local_user(
        pool,
        UserCreateLocal(
            username="alice",
            email="alice@local",
            password="local-pw-12345",  # noqa: S106
            role=UserRole.PUBLIC,
        ),
    )
    assert local.auth_provider == "local"

    with pytest.raises(crud.IdentityProviderConflictError) as excinfo:
        await crud.upsert_oidc_user(pool, "alice", "alice@idp", UserRole.ADMIN, "sub-999")
    assert excinfo.value.username == "alice"
    assert excinfo.value.existing_provider == "local"
    assert excinfo.value.attempted_provider == "oidc"

    reloaded = await crud.get_user_by_username(pool, "alice")
    assert reloaded is not None
    assert reloaded.auth_provider == "local"
    assert reloaded.role == UserRole.PUBLIC
