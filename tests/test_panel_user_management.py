"""End-to-end tests for the panel user-management endpoints.

Covers:
* ``role_subsumes`` helper (pure unit).
* ``count_enabled_admins`` and ``invalidate_user_sessions`` CRUD against a
  real PostgreSQL — migration 0011 must have applied so that
  ``users.sessions_valid_after`` exists.
* ``POST /api/users/local`` — the role-based replacement of the old
  scope-subsumption block, so a scoped ``users:create`` caller (the operator's
  ``noc-svc``) can actually create local users.
* ``PATCH /api/users/{user_id}`` — enable/disable, role/email/username,
  last-admin-lockout, role-escalation guard, ``allowed_actions`` rejection.
* ``POST /api/users/{user_id}/password`` — admin-driven reset, side effects
  (sessions invalidated), local-only restriction.

The endpoint tests build a tiny FastAPI app from the ``bgpeek.api.auth``
router rather than importing ``bgpeek.main.app`` to keep the test surface
small (no middleware, no CSRF, no static files). The pool is injected via
``bgpeek.db.pool._pool`` per ``test_role_filtering`` precedent.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import asyncpg
import httpx
import pytest
from fastapi import FastAPI, status

from bgpeek.api.auth import router as auth_router
from bgpeek.core.auth import authenticate, role_subsumes
from bgpeek.db import users as user_crud
from bgpeek.models.user import User, UserCreateLocal, UserRole

# ---------------------------------------------------------------------------
# role_subsumes — pure unit (no DB)
# ---------------------------------------------------------------------------


class TestRoleSubsumes:
    def test_admin_can_act_on_admin(self) -> None:
        assert role_subsumes(UserRole.ADMIN, UserRole.ADMIN) is True

    def test_admin_can_act_on_noc(self) -> None:
        assert role_subsumes(UserRole.ADMIN, UserRole.NOC) is True

    def test_noc_cannot_act_on_admin(self) -> None:
        assert role_subsumes(UserRole.NOC, UserRole.ADMIN) is False

    def test_public_cannot_act_on_noc(self) -> None:
        assert role_subsumes(UserRole.PUBLIC, UserRole.NOC) is False


# ---------------------------------------------------------------------------
# CRUD helpers — real PG
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _patch_pool(pool: asyncpg.Pool) -> Iterator[None]:
    """Inject the testcontainers pool into the `bgpeek.db.pool` module global.

    Endpoints reach for ``get_pool()`` directly (not through ``Depends``),
    so the ``app.dependency_overrides`` channel doesn't help. Stomping on
    the module global is the same trick ``test_role_filtering`` uses.
    """
    import bgpeek.db.pool as pool_mod

    saved = pool_mod._pool
    pool_mod._pool = pool
    try:
        yield
    finally:
        pool_mod._pool = saved


async def test_count_enabled_admins_zero_on_empty(pool: asyncpg.Pool) -> None:
    assert await user_crud.count_enabled_admins(pool) == 0


async def test_count_enabled_admins_excludes_disabled(pool: asyncpg.Pool) -> None:
    await _create_local(pool, "admin1", role=UserRole.ADMIN)
    await _create_local(pool, "admin2", role=UserRole.ADMIN, enabled=False)
    await _create_local(pool, "noc1", role=UserRole.NOC)
    assert await user_crud.count_enabled_admins(pool) == 1


async def test_invalidate_user_sessions_bumps_column(pool: asyncpg.Pool) -> None:
    user = await _create_local(pool, "alice")
    assert user.sessions_valid_after is None

    # Sample around the call rather than asserting strict ordering — the PG
    # `now()` runs inside the testcontainer, and clock skew between the
    # container and the host is regularly in the sub-millisecond range, so a
    # `before <= … <= after` bracket flakes.
    midpoint = datetime.now(tz=UTC)
    await user_crud.invalidate_user_sessions(pool, user.id)

    refreshed = await user_crud.get_user_by_id(pool, user.id)
    assert refreshed is not None
    assert refreshed.sessions_valid_after is not None
    assert abs((refreshed.sessions_valid_after - midpoint).total_seconds()) < 5


# ---------------------------------------------------------------------------
# Endpoint tests — minimal FastAPI app with auth router only
# ---------------------------------------------------------------------------


_NOW = datetime.now(tz=UTC)


def _user(
    *,
    user_id: int = 100,
    username: str = "noc-svc",
    role: UserRole = UserRole.ADMIN,
    auth_provider: str = "api_key",
    allowed_actions: list[str] | None = None,
    enabled: bool = True,
) -> User:
    return User(
        id=user_id,
        username=username,
        email=None,
        role=role,
        auth_provider=auth_provider,
        api_key_hash="x" if auth_provider == "api_key" else None,
        password_hash=None,
        enabled=enabled,
        created_at=_NOW,
        last_login_at=None,
        allowed_actions=allowed_actions,
    )


def _build_app(caller: User) -> FastAPI:
    app = FastAPI()
    app.include_router(auth_router)

    async def _override() -> User:
        return caller

    app.dependency_overrides[authenticate] = _override
    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    """ASGI-transport httpx client.

    httpx + ASGITransport runs the app on the test's own event loop, which
    matters here because the asyncpg pool was created on that loop. The
    sync ``TestClient`` runs the app in a worker thread with its own loop
    and crashes asyncpg with "another operation is in progress".
    """
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )


async def _create_local(
    pool: asyncpg.Pool,
    username: str,
    *,
    role: UserRole = UserRole.PUBLIC,
    enabled: bool = True,
) -> User:
    user = await user_crud.create_local_user(
        pool,
        UserCreateLocal(
            username=username,
            password="initial-password-1234",
            role=role,
        ),
    )
    if not enabled:
        await pool.execute("UPDATE users SET enabled = FALSE WHERE id = $1", user.id)
        refreshed = await user_crud.get_user_by_id(pool, user.id)
        assert refreshed is not None
        return refreshed
    return user


def _silenced_audit() -> AsyncMock:
    return AsyncMock(return_value=None)


# Caller fixtures — admin-role identities used as the authenticated user
# in dependency_overrides.

_PANEL_SVC = _user(
    user_id=6,
    username="noc-svc",
    role=UserRole.ADMIN,
    allowed_actions=["users:create", "users:read", "users:update", "users:reset_password"],
)

# Same ID as noc-svc but missing reset-password scope — used to verify
# the scope guard refuses the request even when the role check would pass.
_PANEL_SVC_NO_RESET = _user(
    user_id=6,
    username="noc-svc",
    role=UserRole.ADMIN,
    allowed_actions=["users:create", "users:read", "users:update"],
)

_LEGACY_ADMIN = _user(
    user_id=1,
    username="nocgod",
    role=UserRole.ADMIN,
    allowed_actions=None,  # legacy mode — bypasses scope_gate
)


# ---------------------------------------------------------------------------
# Local create
# ---------------------------------------------------------------------------


class TestLocalCreate:
    """``POST /api/users/local`` — scoped noc-svc must succeed at NOC role."""

    async def test_panel_svc_creates_noc_user(self, pool: asyncpg.Pool) -> None:
        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.post(
                    "/api/users/local",
                    json={
                        "username": "alice",
                        "password": "alice-password-12",
                        "role": "noc",
                    },
                )
        assert r.status_code == status.HTTP_201_CREATED, r.text
        assert r.json()["username"] == "alice"
        assert r.json()["role"] == "noc"

    async def test_panel_svc_can_create_admin_at_same_role(self, pool: asyncpg.Pool) -> None:
        """role_subsumes is non-strict — admin caller can mint another admin."""
        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.post(
                    "/api/users/local",
                    json={
                        "username": "newadmin",
                        "password": "admin-password-12",
                        "role": "admin",
                    },
                )
        assert r.status_code == status.HTTP_201_CREATED, r.text


# ---------------------------------------------------------------------------
# PATCH /api/users/{user_id}
# ---------------------------------------------------------------------------


class TestPatch:
    async def test_disable_invalidates_sessions(self, pool: asyncpg.Pool) -> None:
        # Need a second admin so disabling the target doesn't trip last-admin.
        await _create_local(pool, "admin-a", role=UserRole.ADMIN)
        target = await _create_local(pool, "admin-b", role=UserRole.ADMIN)

        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.patch(
                    f"/api/users/{target.id}",
                    json={"enabled": False},
                )
        assert r.status_code == status.HTTP_200_OK, r.text
        assert r.json()["enabled"] is False

        refreshed = await user_crud.get_user_by_id(pool, target.id)
        assert refreshed is not None
        assert refreshed.sessions_valid_after is not None

    async def test_disable_last_admin_blocked(self, pool: asyncpg.Pool) -> None:
        only_admin = await _create_local(pool, "only-admin", role=UserRole.ADMIN)
        # Sanity check on fixture state — exactly one enabled admin in DB.
        assert await user_crud.count_enabled_admins(pool) == 1

        app = _build_app(_LEGACY_ADMIN)  # legacy — passes scope_gate freely
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.patch(
                    f"/api/users/{only_admin.id}",
                    json={"enabled": False},
                )
        assert r.status_code == status.HTTP_409_CONFLICT
        assert "last enabled admin" in r.json()["detail"]

        # Side effect: nothing changed.
        refreshed = await user_crud.get_user_by_id(pool, only_admin.id)
        assert refreshed is not None
        assert refreshed.enabled is True
        assert refreshed.sessions_valid_after is None

    async def test_demote_last_admin_blocked(self, pool: asyncpg.Pool) -> None:
        only_admin = await _create_local(pool, "only-admin", role=UserRole.ADMIN)

        app = _build_app(_LEGACY_ADMIN)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.patch(
                    f"/api/users/{only_admin.id}",
                    json={"role": "noc"},
                )
        assert r.status_code == status.HTTP_409_CONFLICT

    async def test_allowed_actions_rejected_at_pydantic(self, pool: asyncpg.Pool) -> None:
        target = await _create_local(pool, "victim")

        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.patch(
                    f"/api/users/{target.id}",
                    json={"allowed_actions": ["users:create"]},
                )
        # extra="forbid" on UserUpdate → 422.
        assert r.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_unknown_id(self, pool: asyncpg.Pool) -> None:
        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.patch("/api/users/9999", json={"enabled": False})
            assert r.status_code == status.HTTP_404_NOT_FOUND

    async def test_username_conflict(self, pool: asyncpg.Pool) -> None:
        await _create_local(pool, "taken-name")
        target = await _create_local(pool, "renameable")

        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.patch(
                    f"/api/users/{target.id}",
                    json={"username": "taken-name"},
                )
        assert r.status_code == status.HTTP_409_CONFLICT


# ---------------------------------------------------------------------------
# POST /api/users/{user_id}/password
# ---------------------------------------------------------------------------


class TestPasswordReset:
    async def test_admin_reset_invalidates_sessions(self, pool: asyncpg.Pool) -> None:
        target = await _create_local(pool, "alice")

        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.post(
                    f"/api/users/{target.id}/password",
                    json={"new_password": "fresh-pass-1234"},
                )
        assert r.status_code == status.HTTP_204_NO_CONTENT, r.text

        refreshed = await user_crud.get_user_by_id(pool, target.id)
        assert refreshed is not None
        assert refreshed.sessions_valid_after is not None

        # Old password no longer authenticates; new password does.
        assert (
            await user_crud.get_user_by_credentials(pool, "alice", "initial-password-1234") is None
        )
        authed = await user_crud.get_user_by_credentials(pool, "alice", "fresh-pass-1234")
        assert authed is not None
        assert authed.id == target.id

    async def test_non_local_user_rejected(self, pool: asyncpg.Pool) -> None:
        # Manually insert a user with auth_provider='oidc' — exercising the
        # 400 branch without standing up a real OIDC flow.
        await pool.execute(
            """
            INSERT INTO users (username, role, auth_provider, enabled)
            VALUES ('oidc-bob', 'public', 'oidc', TRUE)
            """,
        )
        bob = await user_crud.get_user_by_username(pool, "oidc-bob")
        assert bob is not None

        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.post(
                    f"/api/users/{bob.id}/password",
                    json={"new_password": "doesnt-matter-12"},
                )
        assert r.status_code == status.HTTP_400_BAD_REQUEST
        assert "auth_provider" in r.json()["detail"]

    async def test_unknown_id(self, pool: asyncpg.Pool) -> None:
        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.post(
                    "/api/users/9999/password",
                    json={"new_password": "doesnt-matter-12"},
                )
        assert r.status_code == status.HTTP_404_NOT_FOUND

    async def test_short_password(self, pool: asyncpg.Pool) -> None:
        target = await _create_local(pool, "alice")
        app = _build_app(_PANEL_SVC)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.post(
                    f"/api/users/{target.id}/password",
                    json={"new_password": "short"},
                )
        assert r.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    async def test_caller_without_scope_blocked(self, pool: asyncpg.Pool) -> None:
        target = await _create_local(pool, "alice")

        app = _build_app(_PANEL_SVC_NO_RESET)
        with patch("bgpeek.api.auth.log_audit", _silenced_audit()):
            async with _client(app) as client:
                r = await client.post(
                    f"/api/users/{target.id}/password",
                    json={"new_password": "fresh-pass-1234"},
                )
        assert r.status_code == status.HTTP_403_FORBIDDEN

        refreshed = await user_crud.get_user_by_id(pool, target.id)
        assert refreshed is not None
        # No session invalidation when the request was rejected upstream.
        assert refreshed.sessions_valid_after is None


# ---------------------------------------------------------------------------
# JWT epoch — `_resolve_jwt` must reject tokens issued before the epoch
# ---------------------------------------------------------------------------


class TestJwtEpoch:
    """Pure-unit on `_resolve_jwt` — patches user_crud lookup, no real DB."""

    async def test_token_predating_epoch_rejected(self, pool: asyncpg.Pool) -> None:
        target = await _create_local(pool, "alice")
        await user_crud.invalidate_user_sessions(pool, target.id)
        refreshed = await user_crud.get_user_by_id(pool, target.id)
        assert refreshed is not None
        assert refreshed.sessions_valid_after is not None

        # Build a JWT whose `iat` is one minute before the epoch — would
        # normally verify, must be rejected by the new check.
        import jwt as pyjwt
        from fastapi import HTTPException

        from bgpeek.config import settings
        from bgpeek.core.auth import _resolve_jwt

        epoch_unix = int(refreshed.sessions_valid_after.timestamp())
        payload = {
            "sub": str(target.id),
            "username": target.username,
            "role": target.role.value,
            "iat": epoch_unix - 60,
            "exp": int((datetime.now(tz=UTC) + timedelta(hours=1)).timestamp()),
            "jti": "test-jti",
        }
        token = pyjwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

        with pytest.raises(HTTPException) as exc:
            await _resolve_jwt(token)
        assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "session invalidated" in exc.value.detail
