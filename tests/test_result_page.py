"""HTTP-layer tests for the /result/{id} share permalink endpoint.

The DB-fixture suite (`test_results.py`) covers the storage layer; this file
covers the auth-flow contract: anonymous callers bounce through login while
authenticated-but-unprivileged callers see a 404 (never 403, no existence
oracle).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, status
from fastapi.testclient import TestClient

from bgpeek.core.auth import optional_auth
from bgpeek.models.query import BGPRoute, QueryType, StoredResult
from bgpeek.models.user import User, UserRole

_NOW = datetime.now(tz=UTC)

_PUBLIC_USER = User(
    id=10,
    username="public-user",
    email=None,
    role=UserRole.PUBLIC,
    auth_provider="local",
    enabled=True,
    created_at=_NOW,
    last_login_at=None,
)

_ADMIN_USER = User(
    id=11,
    username="admin",
    email=None,
    role=UserRole.ADMIN,
    auth_provider="api_key",
    api_key_hash="x",
    enabled=True,
    created_at=_NOW,
    last_login_at=None,
)


def _stored(*, user_id: int | None = 10, device_restricted: bool = False) -> StoredResult:
    return StoredResult(
        id=uuid.uuid4(),
        device_name="rt1",
        query_type=QueryType.BGP_ROUTE,
        target="8.8.8.0/24",
        command="show route 8.8.8.0/24",
        raw_output="raw",
        filtered_output="filtered",
        runtime_ms=10,
        parsed_routes=[BGPRoute(prefix="8.8.8.0/24", next_hop="10.0.0.1", best=True)],
        user_id=user_id,
        username="someone",
        device_restricted=device_restricted,
        created_at=_NOW,
        expires_at=_NOW + timedelta(days=7),
    )


def _build_app(current_user: User | None) -> FastAPI:
    """Wire just the query router with optional_auth overridden."""
    from bgpeek.api.query import router as query_router
    from bgpeek.main import I18nMiddleware

    app = FastAPI()
    app.add_middleware(I18nMiddleware)
    app.include_router(query_router)

    async def _override() -> User | None:
        return current_user

    app.dependency_overrides[optional_auth] = _override
    return app


class TestResultPageAuthFlow:
    def test_anon_redirects_to_login_with_next(self) -> None:
        result_id = uuid.uuid4()
        app = _build_app(current_user=None)
        with (
            patch("bgpeek.api.query.get_result", new_callable=AsyncMock, return_value=None),
            patch("bgpeek.api.query.get_pool", return_value=AsyncMock()),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get(f"/result/{result_id}")
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        # Path is URL-encoded; either form is acceptable, but verify next= carries
        # the original target so the browser can decode and bounce back.
        location = resp.headers["location"]
        assert location.startswith("/auth/login?")
        assert f"%2Fresult%2F{result_id}" in location or f"/result/{result_id}" in location

    def test_anon_existing_result_still_redirects_no_existence_leak(self) -> None:
        """Even if the result exists, an anon caller must see the same redirect
        as for a missing result — status code can't be used to enumerate."""
        result_id = uuid.uuid4()
        app = _build_app(current_user=None)
        with (
            patch(
                "bgpeek.api.query.get_result",
                new_callable=AsyncMock,
                return_value=_stored(user_id=10),
            ),
            patch("bgpeek.api.query.get_pool", return_value=AsyncMock()),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get(f"/result/{result_id}")
        assert resp.status_code == status.HTTP_303_SEE_OTHER
        assert resp.headers["location"].startswith("/auth/login?")

    def test_authenticated_no_rights_returns_404(self) -> None:
        """A logged-in user looking at someone else's result gets 404, not 403."""
        result_id = uuid.uuid4()
        app = _build_app(current_user=_PUBLIC_USER)
        with (
            patch(
                "bgpeek.api.query.get_result",
                new_callable=AsyncMock,
                return_value=_stored(user_id=999),  # owned by a different user
            ),
            patch("bgpeek.api.query.get_pool", return_value=AsyncMock()),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get(f"/result/{result_id}")
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_authenticated_missing_returns_404(self) -> None:
        result_id = uuid.uuid4()
        app = _build_app(current_user=_PUBLIC_USER)
        with (
            patch("bgpeek.api.query.get_result", new_callable=AsyncMock, return_value=None),
            patch("bgpeek.api.query.get_pool", return_value=AsyncMock()),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get(f"/result/{result_id}")
        assert resp.status_code == status.HTTP_404_NOT_FOUND

    def test_admin_can_view_any_result(self) -> None:
        result_id = uuid.uuid4()
        app = _build_app(current_user=_ADMIN_USER)
        with (
            patch(
                "bgpeek.api.query.get_result",
                new_callable=AsyncMock,
                return_value=_stored(user_id=999),
            ),
            patch("bgpeek.api.query.get_pool", return_value=AsyncMock()),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get(f"/result/{result_id}")
        assert resp.status_code == status.HTTP_200_OK

    def test_owner_can_view_own_result(self) -> None:
        result_id = uuid.uuid4()
        app = _build_app(current_user=_PUBLIC_USER)
        with (
            patch(
                "bgpeek.api.query.get_result",
                new_callable=AsyncMock,
                return_value=_stored(user_id=_PUBLIC_USER.id),
            ),
            patch("bgpeek.api.query.get_pool", return_value=AsyncMock()),
        ):
            client = TestClient(app, follow_redirects=False)
            resp = client.get(f"/result/{result_id}")
        assert resp.status_code == status.HTTP_200_OK
