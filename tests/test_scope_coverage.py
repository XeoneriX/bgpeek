"""Lint test: every protected endpoint declares a scope tag.

The default-deny coverage in :func:`bgpeek.core.auth.scope_gate` blocks
scoped tokens on any endpoint that does not carry an
``@scoped_endpoint`` tag. That keeps a developer who forgets the
decorator from silently leaking a new endpoint to scoped users — but
only at runtime. This file is the build-time partner: any new endpoint
on a protected router must carry a tag, or this test fails and the
PR cannot merge.

The exclusion list (``_UNSCOPED_PATHS``) names the small set of
endpoints that should NEVER carry a scope tag — the public web flows
(login, OIDC callback), self-action endpoints (logout, account
settings, ``/api/auth/me``), and endpoints that intentionally support
anonymous use (the HTMX query UI in guest mode, public permalinks,
the public read of community labels). Every other endpoint in
:func:`PROTECTED_ROUTERS` must be tagged.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest
from fastapi.routing import APIRoute

from bgpeek.api import (
    auth as auth_api,
)
from bgpeek.api import (
    community_labels as community_labels_api,
)
from bgpeek.api import (
    credentials as credentials_api,
)
from bgpeek.api import (
    devices as devices_api,
)
from bgpeek.api import (
    query as query_api,
)
from bgpeek.api import (
    webhooks as webhooks_api,
)
from bgpeek.core.auth import get_endpoint_action
from bgpeek.ui import admin as admin_ui

# Routers whose protected endpoints must declare a scope tag.
PROTECTED_ROUTERS = (
    auth_api.router,
    devices_api.router,
    credentials_api.router,
    webhooks_api.router,
    community_labels_api.router,
    query_api.router,
    admin_ui.router,
)

# Endpoint paths exempted from the tagging requirement. Each entry has a
# specific reason — keep this list short and audit it on every change.
_UNSCOPED_PATHS = frozenset(
    {
        # Login / logout — public or self-action; cannot require a scope.
        "/auth/login",
        "/auth/logout",
        "/api/auth/login",
        "/api/auth/me",  # self-introspection — every authenticated caller
        "/auth/oidc/login",
        "/auth/oidc/callback",
        # Account settings — caller acts on own data.
        "/account/settings",
        "/account/settings/email",
        "/account/settings/password",
        # HTMX query UI — supports anonymous (guest mode).
        "/query",
        "/query/multi",
        # Permalink permalinks — optional auth, public-facing.
        "/result/{result_id}",
        "/api/results/{result_id}",
        # Community labels are non-sensitive read-only public metadata.
        "/api/community-labels",
    }
)


def _all_protected_routes(routers: Iterable[object]) -> list[APIRoute]:
    out: list[APIRoute] = []
    for r in routers:
        for route in getattr(r, "routes", []):
            if isinstance(route, APIRoute):
                out.append(route)
    return out


def test_every_protected_endpoint_has_scope_tag() -> None:
    """A new endpoint on a protected router without ``@scoped_endpoint`` fails CI."""
    missing: list[str] = []
    for route in _all_protected_routes(PROTECTED_ROUTERS):
        if route.path in _UNSCOPED_PATHS:
            continue
        if get_endpoint_action(route.endpoint) is None:
            methods = ",".join(sorted(route.methods or {"?"}))
            missing.append(f"{methods} {route.path}")
    assert not missing, (
        "endpoints without @scoped_endpoint(...) — either tag them or add to "
        f"_UNSCOPED_PATHS with a comment explaining why: {missing}"
    )


def test_unscoped_paths_actually_exist() -> None:
    """Catch typos / stale entries in the exemption list — every path here must
    correspond to a real route, otherwise the exemption silently loses meaning."""
    real_paths = {route.path for route in _all_protected_routes(PROTECTED_ROUTERS)}
    bogus = _UNSCOPED_PATHS - real_paths
    assert not bogus, f"_UNSCOPED_PATHS contains entries with no matching route: {bogus}"


def test_no_endpoint_tagged_with_wildcard() -> None:
    """Wildcards belong on the user side (granted scope), never as required tags."""
    bad: list[str] = []
    for route in _all_protected_routes(PROTECTED_ROUTERS):
        action = get_endpoint_action(route.endpoint)
        if action and "*" in action:
            bad.append(f"{route.path} → {action}")
    assert not bad, f"endpoints tagged with wildcard scope: {bad}"


@pytest.mark.parametrize("router", PROTECTED_ROUTERS, ids=lambda r: r.prefix or "<root>")
def test_router_has_at_least_one_route(router: object) -> None:
    """Sanity check — empty router would silently skip the coverage assertion."""
    routes = list(getattr(router, "routes", []))
    assert routes, f"router {router!r} has no routes"
