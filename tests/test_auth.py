"""Tests for the authentication dependencies (API key + JWT + cookie)."""

from __future__ import annotations

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

    def test_revoked_cookie_returns_401(self) -> None:
        """A syntactically-valid but server-side-revoked JWT must be rejected.
        Without this check, logout would clear the cookie but the token would
        still authenticate anyone who captured it pre-logout.
        """
        from bgpeek.core.jwt import create_token

        token = create_token(_LOCAL_USER.id, _LOCAL_USER.username, _LOCAL_USER.role.value)
        app = _build_app()
        with (
            _patch_pool(),
            _patch_user_by_id(_LOCAL_USER),
            patch(
                "bgpeek.core.auth.jwt_revoke.is_revoked",
                new=AsyncMock(return_value=True),
            ),
        ):
            client = TestClient(app)
            client.cookies.set(_COOKIE_NAME, token)
            resp = client.get("/unified")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED
        assert "revoked" in resp.json()["detail"].lower()

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

    def _patch_log_audit(self) -> object:
        """Silence audit writes in unit tests that mock the pool at AsyncMock level.

        log_audit calls pool.fetchrow which returns an AsyncMock coroutine by
        default, which AuditEntry.model_validate cannot parse. Integration
        tests with a real Postgres fixture exercise the audit path end-to-end.
        """
        return patch("bgpeek.api.auth.log_audit", new=AsyncMock(return_value=None))

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

        app = FastAPI()
        app.include_router(auth_router)
        with (
            self._patch_api_pool(),
            self._patch_credentials(_LOCAL_USER),
            self._patch_ldap(),
            self._patch_log_audit(),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.post(
                "/auth/login",
                data={"username": "local-user", "password": "secret123"},
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
            self._patch_templates() as mock_tpl,
            self._patch_log_audit(),
        ):
            mock_tpl.TemplateResponse.return_value = HTMLResponse(
                "<html>error</html>", status_code=401
            )
            client = TestClient(app, follow_redirects=False)
            resp = client.post(
                "/auth/login",
                data={"username": "bad-user", "password": "wrong"},
            )
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_logout_clears_cookie(self) -> None:
        from bgpeek.api.auth import router as auth_router

        app = FastAPI()
        app.include_router(auth_router)
        with self._patch_api_pool(), self._patch_log_audit():
            client = TestClient(app, follow_redirects=False)
            client.cookies.set(_COOKIE_NAME, "some-token")
            resp = client.post("/auth/logout")
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"] in ("/", "/auth/login")
        # Cookie should be cleared (max-age=0 or deleted)
        cookie_header = resp.headers.get("set-cookie", "")
        assert _COOKIE_NAME in cookie_header

    def test_logout_revokes_current_jwt(self) -> None:
        """A valid cookie on logout must be server-side revoked so anyone who
        captured it pre-logout can't keep using it until natural expiry."""
        from bgpeek.api.auth import router as auth_router
        from bgpeek.core.jwt import create_token

        app = FastAPI()
        app.include_router(auth_router)
        token = create_token(1, "alice", "admin")
        with (
            self._patch_api_pool(),
            self._patch_log_audit(),
            patch("bgpeek.api.auth.revoke_jwt", new_callable=AsyncMock) as revoke_spy,
        ):
            client = TestClient(app, follow_redirects=False)
            client.cookies.set(_COOKIE_NAME, token)
            resp = client.post("/auth/logout")
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        # revoke called once with the cookie's jti and a positive TTL
        # (remaining lifetime of the fresh token).
        revoke_spy.assert_awaited_once()
        jti_arg, ttl_arg = revoke_spy.await_args.args
        assert isinstance(jti_arg, str)
        assert len(jti_arg) >= 16
        assert ttl_arg > 0

    def test_logout_without_cookie_does_not_call_revoke(self) -> None:
        """No cookie → no token → no revoke call (nothing to revoke)."""
        from bgpeek.api.auth import router as auth_router

        app = FastAPI()
        app.include_router(auth_router)
        with (
            self._patch_api_pool(),
            self._patch_log_audit(),
            patch("bgpeek.api.auth.revoke_jwt", new_callable=AsyncMock) as revoke_spy,
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.post("/auth/logout")
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        revoke_spy.assert_not_awaited()

    def test_logout_with_expired_cookie_does_not_raise(self) -> None:
        """An expired or tampered cookie on logout must not 500 — logout is a
        user-initiated action and must always succeed."""
        from bgpeek.api.auth import router as auth_router

        app = FastAPI()
        app.include_router(auth_router)
        with (
            self._patch_api_pool(),
            self._patch_log_audit(),
            patch("bgpeek.api.auth.revoke_jwt", new_callable=AsyncMock) as revoke_spy,
        ):
            client = TestClient(app, follow_redirects=False)
            client.cookies.set(_COOKIE_NAME, "not.a.valid.jwt")
            resp = client.post("/auth/logout")
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        revoke_spy.assert_not_awaited()
