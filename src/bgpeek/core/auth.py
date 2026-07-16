"""Authentication dependencies for FastAPI (API key + JWT + cookie)."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

import jwt as pyjwt
import structlog
from fastapi import Cookie, Depends, Header, HTTPException, Request, status

from bgpeek.core import jwt_revoke, scopes
from bgpeek.core.jwt import decode_token
from bgpeek.db import users as user_crud
from bgpeek.db.pool import get_pool
from bgpeek.models.audit import AuditAction
from bgpeek.models.user import User, UserRole

# `audit_helpers` and `db.audit` would cycle through this module
# (audit_helpers → rate_limit → auth → ...), so they're imported lazily
# inside `_log_scope_denial` only.

log = structlog.get_logger(__name__)

_COOKIE_NAME = "bgpeek_token"

# Marker attribute attached to route handlers by `scoped_endpoint`. Read by
# `scope_gate` to determine the action a request is asking for. Stored on the
# function rather than in a registry so `route.endpoint.__bgpeek_action__`
# survives FastAPI's route registration unchanged.
_ENDPOINT_ACTION_ATTR = "__bgpeek_action__"


def guest_user() -> User:
    """Return a synthetic guest user for anonymous access in guest mode."""
    from datetime import UTC, datetime

    return User(
        id=0,
        username="guest",
        role=UserRole.GUEST,
        enabled=True,
        auth_provider="anonymous",
        created_at=datetime.now(tz=UTC),
    )


async def _resolve_bearer(authorization: str) -> User | None:
    """Decode a Bearer token and look up the user."""
    if not authorization.lower().startswith("bearer "):
        return None
    token = authorization[7:]
    return await _resolve_jwt(token)


async def _resolve_jwt(token: str) -> User:
    """Decode a JWT string and look up the user. Raises 401 on failure."""
    try:
        payload = decode_token(token)
    except pyjwt.InvalidTokenError:
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired JWT token",
        )
    # Server-side revocation check: `/auth/logout` puts a token's `jti` on a
    # Redis blocklist for the remainder of its lifetime. Without this, the
    # cookie would be cleared client-side but the JWT itself would keep
    # working for anyone who captured it before logout.
    jti = payload.get("jti")
    if isinstance(jti, str) and await jwt_revoke.is_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token has been revoked",
        )
    user_id = int(str(payload["sub"]))
    user = await user_crud.get_user_by_id(get_pool(), user_id)
    if user is None or not user.enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user not found or disabled",
        )
    # Per-user JWT invalidation epoch. Bumped by admin password reset and by
    # ``enabled=false`` so that a single column flip kicks out every live
    # session for the user without having to enumerate live `jti`s. A token
    # whose `iat` predates the epoch is rejected even though it would
    # otherwise verify.
    if user.sessions_valid_after is not None:
        iat = payload.get("iat")
        if isinstance(iat, int) and iat < int(user.sessions_valid_after.timestamp()):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="session invalidated — please log in again",
            )
    return user


# ---------------------------------------------------------------------------
# Unified dependencies
# ---------------------------------------------------------------------------


async def authenticate(
    x_api_key: str | None = Header(default=None),  # noqa: B008
    authorization: str | None = Header(default=None),  # noqa: B008
    bgpeek_token: str | None = Cookie(default=None),  # noqa: B008
) -> User:
    """Resolve X-API-Key, Authorization Bearer, or cookie to a User, or 401."""
    # 1. Try API key
    if x_api_key is not None:
        user = await user_crud.get_user_by_api_key(get_pool(), x_api_key)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or disabled API key",
            )
        return user

    # 2. Try Bearer JWT
    if authorization is not None:
        user = await _resolve_bearer(authorization)
        if user is not None:
            return user

    # 3. Try cookie
    if bgpeek_token is not None:
        return await _resolve_jwt(bgpeek_token)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing credentials — provide X-API-Key, Authorization header, or login cookie",
    )


async def optional_auth(
    x_api_key: str | None = Header(default=None),  # noqa: B008
    authorization: str | None = Header(default=None),  # noqa: B008
    bgpeek_token: str | None = Cookie(default=None),  # noqa: B008
) -> User | None:
    """Like ``authenticate`` but returns None when no credentials are provided."""
    if x_api_key is not None:
        user = await user_crud.get_user_by_api_key(get_pool(), x_api_key)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or disabled API key",
            )
        return user

    if authorization is not None:
        user = await _resolve_bearer(authorization)
        if user is not None:
            return user

    if bgpeek_token is not None:
        try:
            return await _resolve_jwt(bgpeek_token)
        except HTTPException:
            # Invalid/expired cookie — treat as unauthenticated, not an error
            return None

    return None


# ---------------------------------------------------------------------------
# Legacy aliases — kept so existing imports and tests keep working.
# ---------------------------------------------------------------------------

require_api_key = authenticate
optional_api_key = optional_auth


# ---------------------------------------------------------------------------
# Per-key action scopes (Phase 1)
# ---------------------------------------------------------------------------


def scoped_endpoint(action: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Tag an endpoint with the action a scoped caller must hold.

    Apply alongside the route decorator — order matters: this decorator runs
    first (innermost), attaches ``__bgpeek_action__`` to the function, then
    FastAPI's ``router.post`` etc. registers the now-tagged function::

        @router.post("/api/users")
        @scoped_endpoint("users:create")
        async def create_user(...): ...

    The action string must be a concrete scope (no wildcards) — wildcards
    only make sense as *granted* permissions, not as required tags.
    """
    if not scopes.validate_scope_string(action) or "*" in action:
        raise ValueError(
            f"invalid action tag: {action!r} — must be a concrete scope "
            f"like 'users:create', not a wildcard"
        )

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        setattr(fn, _ENDPOINT_ACTION_ATTR, action)
        return fn

    return decorator


def get_endpoint_action(endpoint: Callable[..., Any] | None) -> str | None:
    """Return the action tag set by :func:`scoped_endpoint`, or None."""
    if endpoint is None:
        return None
    return getattr(endpoint, _ENDPOINT_ACTION_ATTR, None)


async def scope_gate(
    request: Request,
    user: User = Depends(authenticate),  # noqa: B008
) -> User:
    """Enforce default-deny scope coverage on every request.

    Behaviour:

    * Legacy users (``allowed_actions=None``) — pass through unchanged.
      ``require_role`` / ``require_admin`` continue to be the floor.
    * Scoped users (``allowed_actions=non-null``) hit one of:

      - The endpoint has no ``__bgpeek_action__`` tag → 403 with
        ``AuditAction.SCOPE_VIOLATION`` logged. Default-deny coverage:
        a developer who forgets ``@scoped_endpoint`` does not silently
        leak the endpoint to scoped tokens (T2).
      - The endpoint has an action tag the caller's scopes do not match
        → 403 + audit. Standard scope enforcement.
      - The endpoint has an action tag the caller's scopes cover → pass.

    Wired as a router-level dependency on every protected router. Public
    endpoints (login, healthz, static, openapi.json) are not under this
    gate and do not need ``@scoped_endpoint``.
    """
    if user.allowed_actions is None:
        return user

    route = request.scope.get("route")
    endpoint = getattr(route, "endpoint", None) if route is not None else None
    declared_action = get_endpoint_action(endpoint)

    if declared_action is None:
        await _log_scope_denial(
            request=request,
            user=user,
            error_message=(
                f"endpoint {request.url.path} has no action declared; "
                f"scoped tokens cannot access untagged endpoints"
            ),
            action=AuditAction.SCOPE_VIOLATION,
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="endpoint not scoped; scoped tokens cannot access",
        )

    if not scopes.matches(user.allowed_actions, declared_action):
        await _log_scope_denial(
            request=request,
            user=user,
            error_message=(f"required={declared_action} allowed={user.allowed_actions}"),
            action=AuditAction.SCOPE_VIOLATION,
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=f"missing required scope: {declared_action}",
        )

    return user


async def _log_scope_denial(
    *,
    request: Request,
    user: User,
    error_message: str,
    action: AuditAction,
) -> None:
    """Best-effort audit insert. Never raises — denial is the security event,
    a stuck audit table must not turn it into a 500."""
    # Lazy import to break the auth → audit_helpers → rate_limit → auth cycle.
    from bgpeek.core.audit_helpers import request_ctx, user_ctx
    from bgpeek.db.audit import log_audit
    from bgpeek.models.audit import AuditEntryCreate

    try:
        await log_audit(
            get_pool(),
            AuditEntryCreate(
                action=action,
                success=False,
                error_message=error_message,
                **user_ctx(user),
                **request_ctx(request),
            ),
        )
    except Exception:
        log.exception(
            "scope_gate_audit_failed",
            user_id=user.id,
            path=str(request.url.path),
        )


def require_role(
    *roles: UserRole,
) -> Callable[..., Coroutine[Any, Any, User]]:
    """Factory: return a dependency that requires one of the given roles.

    The returned dependency layers ``scope_gate`` underneath the role check,
    so any role-restricted endpoint automatically participates in scope
    enforcement. Untagged role-restricted endpoints are default-deny for
    scoped tokens (T2 coverage); tagged endpoints additionally require the
    caller's scopes to cover the declared action.
    """

    async def _check(user: User = Depends(scope_gate)) -> User:  # noqa: B008
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {user.role!r} not in {[r.value for r in roles]}",
            )
        return user

    return _check


# Numeric role ranks — strictly increasing privilege. `role_subsumes` uses
# them to gate cross-role admin actions (PATCH, password reset, local-create
# with role override). Kept as an opaque mapping rather than encoding the
# order on `UserRole` itself so the comparison rule stays in one place and
# can evolve independently of the enum (e.g. inserting a new tier between
# NOC and ADMIN later).
_ROLE_RANK: dict[UserRole, int] = {
    UserRole.GUEST: 0,
    UserRole.PUBLIC: 10,
    UserRole.NOC: 20,
    UserRole.ADMIN: 100,
}


def role_subsumes(caller: UserRole, target: UserRole) -> bool:
    """True iff ``caller`` may perform privileged ops on a ``target``-roled user.

    Non-strict (``>=``): admin can act on another admin. Operationally
    necessary — without this the admin pool becomes self-locking the moment
    one admin forgets a password and there's no separate "root" tier above
    them. Cross-admin actions are still recorded in the audit log
    (``UPDATE_USER`` / ``RESET_PASSWORD``) so abuse is detectable post-fact.
    """
    return _ROLE_RANK[caller] >= _ROLE_RANK[target]
