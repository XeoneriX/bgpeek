"""End-to-end tests for scope_gate behaviour.

These tests build a tiny FastAPI app rather than importing ``bgpeek.main``,
following the same pattern as the existing ``test_auth.py`` suite — keeps
the asyncpg pool / migrations stack out of the way and lets us focus on
the dependency chain alone.

The audit-log side effect of scope_gate denials is verified separately
in ``test_db_audit.py`` (which needs a real Postgres). Here we mock
``log_audit`` so the dep chain runs but the DB call is a no-op.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from fastapi import Depends, FastAPI, status
from fastapi.testclient import TestClient

from bgpeek.core.auth import require_role, scope_gate, scoped_endpoint
from bgpeek.models.user import User, UserRole

_NOW = datetime.now(tz=UTC)


def _user(*, allowed_actions: list[str] | None, role: UserRole = UserRole.ADMIN) -> User:
    return User(
        id=42,
        username="test-user",
        email=None,
        role=role,
        auth_provider="api_key",
        api_key_hash="x",
        password_hash=None,
        enabled=True,
        created_at=_NOW,
        last_login_at=None,
        allowed_actions=allowed_actions,
    )


def _build_app(authenticated: User) -> FastAPI:
    """Build a tiny app with a few representative endpoints and override
    ``authenticate`` to return the given user."""
    app = FastAPI()

    @app.get("/tagged-read")
    @scoped_endpoint("users:read")
    async def tagged_read(
        _user: User = Depends(scope_gate),  # noqa: B008
    ) -> dict[str, str]:
        return {"ok": "1"}

    @app.get("/tagged-create")
    @scoped_endpoint("users:create")
    async def tagged_create(
        _user: User = Depends(scope_gate),  # noqa: B008
    ) -> dict[str, str]:
        return {"ok": "1"}

    @app.get("/untagged")
    async def untagged(
        _user: User = Depends(scope_gate),  # noqa: B008
    ) -> dict[str, str]:
        return {"ok": "1"}

    _admin = require_role(UserRole.ADMIN)

    @app.get("/role-tagged")
    @scoped_endpoint("devices:read")
    async def role_tagged(
        _user: User = Depends(_admin),  # noqa: B008
    ) -> dict[str, str]:
        return {"ok": "1"}

    @app.get("/role-untagged")
    async def role_untagged(
        _user: User = Depends(_admin),  # noqa: B008
    ) -> dict[str, str]:
        return {"ok": "1"}

    # Override the underlying authenticate dep so every request resolves to
    # the same fixture user. scope_gate / require_role wrap authenticate.
    from bgpeek.core.auth import authenticate

    async def _auth_override() -> User:
        return authenticated

    app.dependency_overrides[authenticate] = _auth_override
    return app


def _silenced_audit() -> AsyncMock:
    """Patch the lazy-imported log_audit so denials don't try to reach the DB."""
    return AsyncMock(return_value=None)


def test_legacy_user_passes_tagged_endpoint() -> None:
    """``allowed_actions=None`` is the legacy mode — scope checks no-op."""
    app = _build_app(_user(allowed_actions=None))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        assert client.get("/tagged-read").status_code == status.HTTP_200_OK
        assert client.get("/tagged-create").status_code == status.HTTP_200_OK


def test_legacy_user_passes_untagged_endpoint() -> None:
    """Default-deny only fires for scoped tokens; legacy users still pass."""
    app = _build_app(_user(allowed_actions=None))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        assert client.get("/untagged").status_code == status.HTTP_200_OK


def test_scoped_user_passes_matching_endpoint() -> None:
    app = _build_app(_user(allowed_actions=["users:read"]))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        assert client.get("/tagged-read").status_code == status.HTTP_200_OK


def test_scoped_user_blocked_on_mismatched_endpoint() -> None:
    app = _build_app(_user(allowed_actions=["users:read"]))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        resp = client.get("/tagged-create")
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        assert "users:create" in resp.json()["detail"]


def test_scoped_user_blocked_on_untagged_endpoint() -> None:
    """T2: default-deny coverage — forgotten ``@scoped_endpoint`` does not leak."""
    app = _build_app(_user(allowed_actions=["users:read"]))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        resp = client.get("/untagged")
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        assert "endpoint not scoped" in resp.json()["detail"]


def test_wildcard_scope_grants_all() -> None:
    app = _build_app(_user(allowed_actions=["*"]))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        assert client.get("/tagged-read").status_code == status.HTTP_200_OK
        assert client.get("/tagged-create").status_code == status.HTTP_200_OK
        # Even with `*`, untagged still 403 — no tag means we can't decide
        # whether the action is in scope, and default-deny wins.
        assert client.get("/untagged").status_code == status.HTTP_403_FORBIDDEN


def test_namespace_wildcard_scope() -> None:
    app = _build_app(_user(allowed_actions=["users:*"]))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        assert client.get("/tagged-read").status_code == status.HTTP_200_OK
        assert client.get("/tagged-create").status_code == status.HTTP_200_OK


def test_empty_scope_blocks_everything() -> None:
    """Empty list is deny-all — every action mismatches."""
    app = _build_app(_user(allowed_actions=[]))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        assert client.get("/tagged-read").status_code == status.HTTP_403_FORBIDDEN
        assert client.get("/tagged-create").status_code == status.HTTP_403_FORBIDDEN
        assert client.get("/untagged").status_code == status.HTTP_403_FORBIDDEN


def test_role_check_layers_above_scope_gate() -> None:
    """``require_role(ADMIN)`` for a NOC user → 403 even when scope matches."""
    app = _build_app(
        _user(allowed_actions=["devices:read"], role=UserRole.NOC),
    )
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        # scope_gate passes (devices:read ∈ allowed) but require_role(ADMIN) blocks
        resp = client.get("/role-tagged")
        assert resp.status_code == status.HTTP_403_FORBIDDEN
        assert "role" in resp.json()["detail"].lower()


def test_role_check_admin_with_scope_passes() -> None:
    app = _build_app(_user(allowed_actions=["devices:read"], role=UserRole.ADMIN))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        assert client.get("/role-tagged").status_code == status.HTTP_200_OK


def test_role_check_admin_blocked_on_untagged_role_endpoint() -> None:
    """T2 still applies through the require_role wrapper — untagged + scoped = 403."""
    app = _build_app(_user(allowed_actions=["devices:read"], role=UserRole.ADMIN))
    with TestClient(app) as client, patch("bgpeek.db.audit.log_audit", _silenced_audit()):
        resp = client.get("/role-untagged")
        assert resp.status_code == status.HTTP_403_FORBIDDEN


def test_audit_is_invoked_on_denial() -> None:
    """scope_gate calls ``log_audit`` for every denial. Verify it's not silent.

    scope_gate calls ``get_pool()`` before passing the pool to ``log_audit``;
    in this no-DB harness ``get_pool()`` raises, and the surrounding
    try/except swallows the failure. To assert the audit *intent* without a
    DB, patch ``get_pool`` to return a sentinel so the call reaches the
    ``log_audit`` mock.
    """
    app = _build_app(_user(allowed_actions=["users:read"]))
    audit = AsyncMock(return_value=None)
    with (
        TestClient(app) as client,
        patch("bgpeek.db.audit.log_audit", audit),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client.get("/tagged-create")  # mismatched scope → audit
    assert audit.await_count == 1
    _, entry = audit.await_args.args
    assert entry.success is False
    assert entry.action.value == "scope_violation"


def test_audit_is_not_invoked_on_legacy_pass() -> None:
    app = _build_app(_user(allowed_actions=None))
    audit = AsyncMock(return_value=None)
    with (
        TestClient(app) as client,
        patch("bgpeek.db.audit.log_audit", audit),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client.get("/tagged-read")
    assert audit.await_count == 0


def test_denial_does_not_500_when_audit_log_fails() -> None:
    """The user-facing 403 must not turn into a 500 just because the audit
    insert raised — denial is the security event, audit is best-effort."""
    app = _build_app(_user(allowed_actions=["users:read"]))
    audit_raises = AsyncMock(side_effect=RuntimeError("audit DB down"))
    with (
        TestClient(app) as client,
        patch("bgpeek.db.audit.log_audit", audit_raises),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        resp = client.get("/tagged-create")
    assert resp.status_code == status.HTTP_403_FORBIDDEN
