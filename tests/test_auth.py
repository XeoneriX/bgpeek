"""Tests for the authentication dependencies (API key + JWT + cookie)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from fastapi import Depends, FastAPI, status
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from bgpeek.core.auth import authenticate, optional_auth, require_api_key, require_role
from bgpeek.models.user import User, UserRole

_COOKIE_NAME = "bgpeek_token"

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

_LOCAL_USER = User(
    id=3,
    username="local-user",
    email="local@example.com",
    role=UserRole.PUBLIC,
    auth_provider="local",
    password_hash="fakebcrypt",
    enabled=True,
    created_at=_NOW,
    last_login_at=None,
)

_DISABLED_USER = User(
    id=4,
    username="disabled",
    email=None,
    role=UserRole.PUBLIC,
    auth_provider="local",
    enabled=False,
    created_at=_NOW,
    last_login_at=None,
)

_admin_dep = require_role(UserRole.ADMIN)


def _extract_csrf_token(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/protected")
    async def protected(user: User = Depends(require_api_key)) -> dict[str, str]:  # noqa: B008  # type: ignore[assignment]
        return {"user": user.username}

    @app.get("/optional")
    async def optional(user: User | None = Depends(optional_auth)) -> dict[str, str]:  # noqa: B008  # type: ignore[assignment]
        return {"user": user.username if user else "anonymous"}

    @app.get("/admin-only")
    async def admin_only(user: User = Depends(_admin_dep)) -> dict[str, str]:  # noqa: B008  # type: ignore[assignment]
        return {"user": user.username}

    @app.get("/unified")
    async def unified(user: User = Depends(authenticate)) -> dict[str, str]:  # noqa: B008  # type: ignore[assignment]
        return {"user": user.username}

    return app


def _patch_lookup(return_value: User | None) -> object:
    return patch(
        "bgpeek.core.auth.user_crud.get_user_by_api_key",
        new_callable=AsyncMock,
        return_value=return_value,
    )


def _patch_user_by_id(return_value: User | None) -> object:
    return patch(
        "bgpeek.core.auth.user_crud.get_user_by_id",
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

    def test_missing_key_returns_401(self) -> None:
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/protected")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_invalid_key_returns_401(self) -> None:
        app = _build_app()
        with _patch_pool(), _patch_lookup(None):
            client = TestClient(app)
            resp = client.get("/protected", headers={"X-API-Key": "bad-key"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


class TestOptionalAuth:
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


class TestJWTAuth:
    def test_valid_jwt_returns_user(self) -> None:
        from bgpeek.core.jwt import create_token

        token = create_token(_LOCAL_USER.id, _LOCAL_USER.username, _LOCAL_USER.role.value)
        app = _build_app()
        with _patch_pool(), _patch_user_by_id(_LOCAL_USER):
            client = TestClient(app)
            resp = client.get("/unified", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "local-user"

    def test_expired_jwt_returns_401(self) -> None:
        import jwt as pyjwt

        from bgpeek.config import settings

        payload = {
            "sub": "3",
            "username": "local-user",
            "role": "public",
            "iat": 1000000,
            "exp": 1000001,
        }
        token = pyjwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
        app = _build_app()
        with _patch_pool():
            client = TestClient(app)
            resp = client.get("/unified", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_invalid_jwt_returns_401(self) -> None:
        app = _build_app()
        with _patch_pool():
            client = TestClient(app)
            resp = client.get("/unified", headers={"Authorization": "Bearer not-a-valid-token"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_jwt_disabled_user_returns_401(self) -> None:
        from bgpeek.core.jwt import create_token

        token = create_token(_DISABLED_USER.id, _DISABLED_USER.username, _DISABLED_USER.role.value)
        app = _build_app()
        with _patch_pool(), _patch_user_by_id(_DISABLED_USER):
            client = TestClient(app)
            resp = client.get("/unified", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_api_key_still_works_on_unified(self) -> None:
        app = _build_app()
        with _patch_pool(), _patch_lookup(_ADMIN):
            client = TestClient(app)
            resp = client.get("/unified", headers={"X-API-Key": "test-key"})
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "admin"

    def test_no_credentials_returns_401(self) -> None:
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/unified")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED


class TestCookieAuth:
    def test_valid_cookie_returns_user(self) -> None:
        from bgpeek.core.jwt import create_token

        token = create_token(_LOCAL_USER.id, _LOCAL_USER.username, _LOCAL_USER.role.value)
        app = _build_app()
        with _patch_pool(), _patch_user_by_id(_LOCAL_USER):
            client = TestClient(app)
            client.cookies.set(_COOKIE_NAME, token)
            resp = client.get("/unified")
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "local-user"

    def test_invalid_cookie_returns_401(self) -> None:
        app = _build_app()
        with _patch_pool():
            client = TestClient(app)
            client.cookies.set(_COOKIE_NAME, "garbage-token")
            resp = client.get("/unified")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_optional_auth_with_valid_cookie(self) -> None:
        from bgpeek.core.jwt import create_token

        token = create_token(_LOCAL_USER.id, _LOCAL_USER.username, _LOCAL_USER.role.value)
        app = _build_app()
        with _patch_pool(), _patch_user_by_id(_LOCAL_USER):
            client = TestClient(app)
            client.cookies.set(_COOKIE_NAME, token)
            resp = client.get("/optional")
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "local-user"

    def test_optional_auth_with_invalid_cookie_returns_anonymous(self) -> None:
        app = _build_app()
        with _patch_pool():
            client = TestClient(app)
            client.cookies.set(_COOKIE_NAME, "garbage-token")
            resp = client.get("/optional")
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "anonymous"

    def test_api_key_takes_priority_over_cookie(self) -> None:
        from bgpeek.core.jwt import create_token

        token = create_token(_LOCAL_USER.id, _LOCAL_USER.username, _LOCAL_USER.role.value)
        app = _build_app()
        with _patch_pool(), _patch_lookup(_ADMIN):
            client = TestClient(app)
            client.cookies.set(_COOKIE_NAME, token)
            resp = client.get(
                "/unified",
                headers={"X-API-Key": "test-key"},
            )
        assert resp.status_code == status.HTTP_200_OK
        assert resp.json()["user"] == "admin"


class TestWebLogin:
    def _patch_templates(self) -> object:
        return patch("bgpeek.api.auth.templates")

    def _patch_credentials(self, return_value: User | None) -> object:
        return patch(
            "bgpeek.api.auth.crud.get_user_by_credentials",
            new_callable=AsyncMock,
            return_value=return_value,
        )

    def _patch_ldap(self, return_value: object = None) -> object:
        return patch(
            "bgpeek.api.auth.authenticate_ldap",
            new_callable=AsyncMock,
            return_value=return_value,
        )

    def _patch_api_pool(self) -> object:
        pool = AsyncMock()
        pool.execute = AsyncMock(return_value="UPDATE 1")
        return patch("bgpeek.api.auth.get_pool", return_value=pool)

    def test_login_page_renders(self) -> None:
        from bgpeek.api.auth import router as auth_router
        from bgpeek.main import I18nMiddleware

        app = FastAPI()
        app.add_middleware(I18nMiddleware)
        app.include_router(auth_router)
        client = TestClient(app)
        with self._patch_templates() as mock_tpl:
            mock_tpl.TemplateResponse.return_value = HTMLResponse("<html></html>")
            resp = client.get("/auth/login")
        assert resp.status_code == status.HTTP_200_OK

    def test_login_success_sets_cookie_and_redirects(self) -> None:
        from bgpeek.api.auth import router as auth_router
        from bgpeek.main import I18nMiddleware

        app = FastAPI()
        app.add_middleware(I18nMiddleware)
        app.include_router(auth_router)
        with self._patch_api_pool(), self._patch_credentials(_LOCAL_USER), self._patch_ldap():
            client = TestClient(app, follow_redirects=False)
            csrf_page = client.get("/auth/login")
            assert csrf_page.status_code == status.HTTP_200_OK
            csrf_token = _extract_csrf_token(csrf_page.text)
            resp = client.post(
                "/auth/login",
                data={
                    "username": "local-user",
                    "password": "secret123",
                    "csrf_token": csrf_token,
                },
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/"
        assert _COOKIE_NAME in resp.cookies

    def test_login_invalid_credentials_returns_401(self) -> None:
        from bgpeek.api.auth import router as auth_router
        from bgpeek.main import I18nMiddleware

        app = FastAPI()
        app.add_middleware(I18nMiddleware)
        app.include_router(auth_router)
        with (
            self._patch_api_pool(),
            self._patch_credentials(None),
            self._patch_ldap(None),
        ):
            client = TestClient(app, follow_redirects=False)
            csrf_page = client.get("/auth/login")
            assert csrf_page.status_code == status.HTTP_200_OK
            csrf_token = _extract_csrf_token(csrf_page.text)
            resp = client.post(
                "/auth/login",
                data={"username": "bad-user", "password": "wrong", "csrf_token": csrf_token},
            )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_clears_cookie(self) -> None:
        from bgpeek.api.auth import router as auth_router
        from bgpeek.main import I18nMiddleware

        app = FastAPI()
        app.add_middleware(I18nMiddleware)
        app.include_router(auth_router)
        client = TestClient(app, follow_redirects=False)
        client.cookies.set(_COOKIE_NAME, "some-token")
        csrf_page = client.get("/auth/login")
        assert csrf_page.status_code == status.HTTP_200_OK
        csrf_token = _extract_csrf_token(csrf_page.text)
        resp = client.post("/auth/logout", data={"csrf_token": csrf_token})
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] in ("/", "/auth/login")
        # Cookie should be cleared (max-age=0 or deleted)
        cookie_header = resp.headers.get("set-cookie", "")
        assert _COOKIE_NAME in cookie_header


class TestAccountSettings:
    def _build_settings_app(self, current_user: User) -> FastAPI:
        from bgpeek.api.auth import router as auth_router
        from bgpeek.main import I18nMiddleware

        app = FastAPI()
        app.add_middleware(I18nMiddleware)
        app.include_router(auth_router)

        async def _override_auth() -> User:
            return current_user

        app.dependency_overrides[authenticate] = _override_auth
        return app

    def _patch_settings_pool(self) -> object:
        pool = AsyncMock()
        return patch("bgpeek.api.auth.get_pool", return_value=pool)

    def _csrf_token_for_settings(self, client: TestClient) -> str:
        response = client.get("/account/settings")
        assert response.status_code == status.HTTP_200_OK
        return _extract_csrf_token(response.text)

    def test_settings_page_renders_for_authenticated_user(self) -> None:
        app = self._build_settings_app(_LOCAL_USER)
        client = TestClient(app)
        resp = client.get("/account/settings")
        assert resp.status_code == status.HTTP_200_OK
        assert "Account settings" in resp.text

    def test_settings_page_requires_authentication(self) -> None:
        from bgpeek.api.auth import router as auth_router
        from bgpeek.main import I18nMiddleware

        app = FastAPI()
        app.add_middleware(I18nMiddleware)
        app.include_router(auth_router)
        client = TestClient(app)
        resp = client.get("/account/settings")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_email_redirects_on_success(self) -> None:
        app = self._build_settings_app(_LOCAL_USER)
        with (
            self._patch_settings_pool(),
            patch(
                "bgpeek.api.auth.crud.update_user",
                new_callable=AsyncMock,
                return_value=_LOCAL_USER.model_copy(update={"email": "new@example.com"}),
            ),
        ):
            client = TestClient(app, follow_redirects=False)
            csrf_token = self._csrf_token_for_settings(client)
            resp = client.post(
                "/account/settings/email",
                data={"email": "new@example.com", "csrf_token": csrf_token},
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/account/settings?updated=email"

    def test_update_email_rejects_too_long_value(self) -> None:
        app = self._build_settings_app(_LOCAL_USER)
        with self._patch_settings_pool():
            client = TestClient(app, follow_redirects=False)
            csrf_token = self._csrf_token_for_settings(client)
            resp = client.post(
                "/account/settings/email",
                data={"email": ("a" * 256) + "@example.com", "csrf_token": csrf_token},
            )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "valid email address" in resp.text

    def test_update_email_rejects_missing_csrf(self) -> None:
        app = self._build_settings_app(_LOCAL_USER)
        with self._patch_settings_pool():
            client = TestClient(app, follow_redirects=False)
            resp = client.post("/account/settings/email", data={"email": "new@example.com"})
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert resp.json()["detail"] == "invalid CSRF token"

    def test_update_password_requires_matching_confirmation(self) -> None:
        app = self._build_settings_app(_LOCAL_USER)
        with self._patch_settings_pool():
            client = TestClient(app, follow_redirects=False)
            csrf_token = self._csrf_token_for_settings(client)
            resp = client.post(
                "/account/settings/password",
                data={
                    "current_password": "secret123",
                    "new_password": "new-secret-123",
                    "confirm_password": "different-secret-123",
                    "csrf_token": csrf_token,
                },
            )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "do not match" in resp.text

    def test_update_password_redirects_on_success(self) -> None:
        app = self._build_settings_app(_LOCAL_USER)
        with (
            self._patch_settings_pool(),
            patch(
                "bgpeek.api.auth.crud.verify_local_user_password",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "bgpeek.api.auth.crud.update_local_user_password",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            client = TestClient(app, follow_redirects=False)
            csrf_token = self._csrf_token_for_settings(client)
            resp = client.post(
                "/account/settings/password",
                data={
                    "current_password": "secret123",
                    "new_password": "new-secret-123",
                    "confirm_password": "new-secret-123",
                    "csrf_token": csrf_token,
                },
            )
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] == "/account/settings?updated=password"

    def test_update_password_rejects_invalid_current_password(self) -> None:
        app = self._build_settings_app(_LOCAL_USER)
        with (
            self._patch_settings_pool(),
            patch(
                "bgpeek.api.auth.crud.verify_local_user_password",
                new_callable=AsyncMock,
                return_value=False,
            ),
        ):
            client = TestClient(app, follow_redirects=False)
            csrf_token = self._csrf_token_for_settings(client)
            resp = client.post(
                "/account/settings/password",
                data={
                    "current_password": "wrong-pass",
                    "new_password": "new-secret-123",
                    "confirm_password": "new-secret-123",
                    "csrf_token": csrf_token,
                },
            )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "Current password is incorrect" in resp.text

    def test_update_password_disallowed_for_non_local_accounts(self) -> None:
        non_local_user = _ADMIN.model_copy(update={"auth_provider": "api_key"})
        app = self._build_settings_app(non_local_user)
        with self._patch_settings_pool():
            client = TestClient(app, follow_redirects=False)
            csrf_token = self._csrf_token_for_settings(client)
            resp = client.post(
                "/account/settings/password",
                data={
                    "current_password": "secret123",
                    "new_password": "new-secret-123",
                    "confirm_password": "new-secret-123",
                    "csrf_token": csrf_token,
                },
            )
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert "authentication provider" in resp.text
