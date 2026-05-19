"""HTTP handlers for /api/auth, /api/users, and web login/logout."""

from __future__ import annotations

import time
from urllib.parse import urlparse

import asyncpg
import jwt as pyjwt
import structlog
from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi_csrf_protect import CsrfProtect

from bgpeek.config import settings
from bgpeek.core.audit_helpers import request_ctx, user_ctx
from bgpeek.core.auth import authenticate, require_role, role_subsumes, scoped_endpoint
from bgpeek.core.csrf import issue_csrf_token, set_csrf_cookie, validate_csrf
from bgpeek.core.jwt import create_token, decode_token
from bgpeek.core.jwt_revoke import revoke as revoke_jwt
from bgpeek.core.ldap import authenticate_ldap
from bgpeek.core.oidc import extract_role_from_token, get_oidc_client
from bgpeek.core.rate_limit import rate_limit_login
from bgpeek.core.scopes import subsumes as scopes_subsume
from bgpeek.core.templates import templates
from bgpeek.db import users as crud
from bgpeek.db.audit import log_audit
from bgpeek.db.pool import get_pool
from bgpeek.models.audit import AuditAction, AuditEntryCreate
from bgpeek.models.user import (
    LoginRequest,
    LoginResponse,
    PasswordResetRequest,
    User,
    UserAdmin,
    UserCreate,
    UserCreated,
    UserCreateLocal,
    UserPublic,
    UserRole,
    UserUpdate,
)
from bgpeek.models.webhook import WebhookEvent

log = structlog.get_logger()

router = APIRouter(tags=["auth"])

_COOKIE_NAME = "bgpeek_token"


def _normalize_email(raw: str) -> str | None:
    """Normalize optional email form value."""
    value = raw.strip()
    return value or None


def _safe_next(next_url: str | None) -> str | None:
    """Return ``next_url`` only if it's a same-origin relative path.

    Rejects empty, protocol-relative (``//evil``), and absolute URLs to avoid
    open-redirect on the post-login bounce.
    """
    if not next_url or not next_url.startswith("/") or next_url.startswith("//"):
        return None
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return None
    return next_url


def _render_account_settings(
    request: Request,
    user: User,
    *,
    email_error: str | None = None,
    password_error: str | None = None,
    success_message: str | None = None,
    email_value: str | None = None,
    csrf_token: str = "",
) -> HTMLResponse:
    """Render account settings page with optional status messages."""
    return templates.TemplateResponse(
        request=request,
        name="account_settings.html",
        context={
            "user": user,
            "t": request.state.t,
            "lang": request.state.lang,
            "email_error": email_error,
            "password_error": password_error,
            "success_message": success_message,
            "email_value": email_value if email_value is not None else (user.email or ""),
            "can_change_password": user.auth_provider == "local",
            "csrf_token": csrf_token,
        },
        status_code=status.HTTP_400_BAD_REQUEST
        if email_error or password_error
        else status.HTTP_200_OK,
    )


def _render_account_settings_with_csrf(
    request: Request,
    user: User,
    csrf_protect: CsrfProtect,
    *,
    email_error: str | None = None,
    password_error: str | None = None,
    success_message: str | None = None,
    email_value: str | None = None,
) -> HTMLResponse:
    """Render account settings with a fresh CSRF token and cookie."""
    csrf_token, signed_token = issue_csrf_token(csrf_protect)
    response = _render_account_settings(
        request,
        user,
        email_error=email_error,
        password_error=password_error,
        success_message=success_message,
        email_value=email_value,
        csrf_token=csrf_token,
    )
    set_csrf_cookie(csrf_protect, response, signed_token)
    return response


# ---------------------------------------------------------------------------
# Web login / logout
# ---------------------------------------------------------------------------


@router.get("/auth/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    csrf_protect: CsrfProtect = Depends(),  # noqa: B008
    next_url: str | None = Query(default=None, alias="next"),  # noqa: B008
) -> HTMLResponse:
    """Render the login form."""
    csrf_token, signed_token = issue_csrf_token(csrf_protect)
    response = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": None,
            "t": request.state.t,
            "lang": request.state.lang,
            "oidc_enabled": settings.oidc_enabled,
            "allow_guest_continue": settings.access_mode in ("guest", "open"),
            "csrf_token": csrf_token,
            "next_url": _safe_next(next_url),
        },
    )
    set_csrf_cookie(csrf_protect, response, signed_token)
    return response


@router.post("/auth/login", response_model=None)
async def login_submit(
    request: Request,
    _csrf_ok: None = Depends(validate_csrf),  # noqa: B008
    csrf_protect: CsrfProtect = Depends(),  # noqa: B008
    username: str = Form(),  # noqa: B008
    password: str = Form(),  # noqa: B008
    next_url: str | None = Form(default=None, alias="next"),  # noqa: B008
    _rl: None = Depends(rate_limit_login),  # noqa: B008
) -> Response:
    """Handle web login form submission."""
    # 1. Try local DB
    user = await crud.get_user_by_credentials(get_pool(), username, password)

    # 2. Fallback to LDAP
    if user is None:
        ldap_info = await authenticate_ldap(username, password)
        if ldap_info is not None:
            try:
                user = await crud.upsert_ldap_user(
                    get_pool(),
                    username=ldap_info.username,
                    email=ldap_info.email,
                    role=ldap_info.role,
                )
            except crud.IdentityProviderConflictError as exc:
                log.warning(
                    "identity_provider_conflict",
                    username=exc.username,
                    existing_provider=exc.existing_provider,
                    attempted_provider=exc.attempted_provider,
                )
                await log_audit(
                    get_pool(),
                    AuditEntryCreate(
                        action=AuditAction.LOGIN,
                        success=False,
                        username=exc.username,
                        error_message=(
                            f"identity-provider conflict: username owned by "
                            f"{exc.existing_provider}, rejected {exc.attempted_provider} bind"
                        ),
                        **request_ctx(request),
                    ),
                )
                user = None

    if user is None:
        log.info("web login failed", username=username)
        await log_audit(
            get_pool(),
            AuditEntryCreate(
                action=AuditAction.LOGIN,
                success=False,
                username=username,
                error_message="invalid credentials",
                **request_ctx(request),
            ),
        )
        csrf_token, signed_token = issue_csrf_token(csrf_protect)
        login_response = templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": request.state.t["invalid_credentials"],
                "t": request.state.t,
                "lang": request.state.lang,
                "oidc_enabled": settings.oidc_enabled,
                "allow_guest_continue": settings.access_mode in ("guest", "open"),
                "csrf_token": csrf_token,
                "next_url": _safe_next(next_url),
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
        set_csrf_cookie(csrf_protect, login_response, signed_token)
        return login_response

    # Update last_login_at
    await get_pool().execute(
        "UPDATE users SET last_login_at = now() WHERE id = $1",
        user.id,
    )

    token = create_token(user.id, user.username, user.role.value)
    max_age = settings.jwt_expire_minutes * 60

    redirect_target = _safe_next(next_url) or "/"
    redirect_response = RedirectResponse(url=redirect_target, status_code=status.HTTP_303_SEE_OTHER)
    redirect_response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
        max_age=max_age,
    )

    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.LOGIN,
            success=True,
            **user_ctx(user),
            **request_ctx(request),
        ),
    )

    from bgpeek.core.webhooks import dispatch_webhook

    await dispatch_webhook(
        WebhookEvent.LOGIN,
        {"user_id": user.id, "username": user.username, "method": "web"},
    )

    return redirect_response


@router.post("/auth/logout")
async def logout(
    request: Request,
    _csrf_ok: None = Depends(validate_csrf),  # noqa: B008
    bgpeek_token: str | None = Cookie(default=None),  # noqa: B008
) -> RedirectResponse:
    """Clear the auth cookie, revoke the JWT server-side, and redirect.

    Without the revocation step, clearing the cookie only logs the current
    browser tab out — the JWT itself stays valid until ``exp`` (up to
    ``jwt_expire_minutes`` minutes), so anyone who captured it pre-logout
    could keep using it. Revocation writes the token's ``jti`` to Redis with
    a TTL equal to the token's remaining lifetime.
    """
    # Best-effort: pull the user out of the cookie if present so the audit row
    # carries who logged out. The cookie middleware doesn't run on POST
    # bodies, so we reach into `request.state` where the auth middleware
    # attached it for the current request (if any).
    user = getattr(request.state, "user", None)
    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.LOGOUT,
            success=True,
            **user_ctx(user),
            **request_ctx(request),
        ),
    )

    # Decode the cookie to pull out ``jti`` + ``exp`` for revocation. An
    # already-expired or invalid token is a no-op — there's nothing left to
    # revoke. We do NOT want logout to fail the request on a bad cookie.
    if bgpeek_token:
        try:
            payload = decode_token(bgpeek_token)
            jti = payload.get("jti")
            exp = payload.get("exp")
            if isinstance(jti, str) and isinstance(exp, int):
                remaining = exp - int(time.time())
                await revoke_jwt(jti, remaining)
        except pyjwt.InvalidTokenError:
            pass  # expired or tampered — nothing to revoke

    url = "/auth/login" if settings.access_mode in ("closed", "guest") else "/"
    response = RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(
        key=_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
    )
    return response


@router.get("/account/settings", response_class=HTMLResponse)
async def account_settings_page(
    request: Request,
    user: User = Depends(authenticate),  # noqa: B008
    csrf_protect: CsrfProtect = Depends(),  # noqa: B008
    updated: str | None = None,
) -> HTMLResponse:
    """Render account settings for the authenticated user."""
    success_message: str | None = None
    if updated == "email":
        success_message = request.state.t["account_email_updated"]
    elif updated == "password":
        success_message = request.state.t["account_password_updated"]
    return _render_account_settings_with_csrf(
        request,
        user,
        csrf_protect,
        success_message=success_message,
    )


@router.post("/account/settings/email", response_class=HTMLResponse)
async def account_settings_update_email(
    request: Request,
    email: str = Form(""),
    _csrf_ok: None = Depends(validate_csrf),  # noqa: B008
    csrf_protect: CsrfProtect = Depends(),  # noqa: B008
    user: User = Depends(authenticate),  # noqa: B008
) -> Response:
    """Update the authenticated user's email address."""
    normalized_email = _normalize_email(email)
    if normalized_email is not None and len(normalized_email) > 255:
        return _render_account_settings_with_csrf(
            request,
            user,
            csrf_protect,
            email_error=request.state.t["account_email_invalid"],
            email_value=email,
        )

    updated_user = await crud.update_user(
        get_pool(),
        user.id,
        UserUpdate(email=normalized_email),
    )
    if updated_user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
    return RedirectResponse(
        "/account/settings?updated=email", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/account/settings/password", response_class=HTMLResponse)
async def account_settings_update_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    _csrf_ok: None = Depends(validate_csrf),  # noqa: B008
    csrf_protect: CsrfProtect = Depends(),  # noqa: B008
    user: User = Depends(authenticate),  # noqa: B008
) -> Response:
    """Change password for the authenticated local-auth user."""
    if user.auth_provider != "local":
        return _render_account_settings_with_csrf(
            request,
            user,
            csrf_protect,
            password_error=request.state.t["account_password_unavailable"],
        )

    if len(new_password) < 8:
        return _render_account_settings_with_csrf(
            request,
            user,
            csrf_protect,
            password_error=request.state.t["account_password_too_short"],
        )
    if len(new_password) > 128:
        return _render_account_settings_with_csrf(
            request,
            user,
            csrf_protect,
            password_error=request.state.t["account_password_too_long"],
        )
    if new_password != confirm_password:
        return _render_account_settings_with_csrf(
            request,
            user,
            csrf_protect,
            password_error=request.state.t["account_password_mismatch"],
        )

    valid_current = await crud.verify_local_user_password(get_pool(), user.id, current_password)
    if not valid_current:
        return _render_account_settings_with_csrf(
            request,
            user,
            csrf_protect,
            password_error=request.state.t["account_password_invalid_current"],
        )

    updated = await crud.update_local_user_password(get_pool(), user.id, new_password)
    if not updated:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
    return RedirectResponse(
        "/account/settings?updated=password", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/api/auth/me", response_model=UserPublic)
async def whoami(user: User = Depends(authenticate)) -> User:  # noqa: B008
    """Return the authenticated user."""
    return user


@router.post("/api/auth/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    _rl: None = Depends(rate_limit_login),  # noqa: B008
) -> LoginResponse:
    """Authenticate with username/password and receive a JWT token.

    Auth chain: local DB → LDAP (if enabled). LDAP users are auto-provisioned.
    """
    # 1. Try local DB first
    user = await crud.get_user_by_credentials(get_pool(), body.username, body.password)

    # 2. Fallback to LDAP
    if user is None:
        ldap_info = await authenticate_ldap(body.username, body.password)
        if ldap_info is not None:
            try:
                user = await crud.upsert_ldap_user(
                    get_pool(),
                    username=ldap_info.username,
                    email=ldap_info.email,
                    role=ldap_info.role,
                )
            except crud.IdentityProviderConflictError as exc:
                log.warning(
                    "identity_provider_conflict",
                    username=exc.username,
                    existing_provider=exc.existing_provider,
                    attempted_provider=exc.attempted_provider,
                )
                await log_audit(
                    get_pool(),
                    AuditEntryCreate(
                        action=AuditAction.LOGIN,
                        success=False,
                        username=exc.username,
                        error_message=(
                            f"identity-provider conflict: username owned by "
                            f"{exc.existing_provider}, rejected {exc.attempted_provider} bind"
                        ),
                        **request_ctx(request),
                    ),
                )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="username already registered with a different authentication provider",
                ) from exc

    if user is None:
        await log_audit(
            get_pool(),
            AuditEntryCreate(
                action=AuditAction.LOGIN,
                success=False,
                username=body.username,
                error_message="invalid credentials",
                **request_ctx(request),
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
        )

    # Update last_login_at
    await get_pool().execute(
        "UPDATE users SET last_login_at = now() WHERE id = $1",
        user.id,
    )

    token = create_token(user.id, user.username, user.role.value)

    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.LOGIN,
            success=True,
            **user_ctx(user),
            **request_ctx(request),
        ),
    )

    from bgpeek.core.webhooks import dispatch_webhook

    await dispatch_webhook(
        WebhookEvent.LOGIN,
        {"user_id": user.id, "username": user.username, "method": "api"},
    )

    return LoginResponse(
        token=token,
        token_type="bearer",  # noqa: S106
        expires_in=settings.jwt_expire_minutes * 60,
        user=UserPublic.model_validate(user, from_attributes=True),
    )


# ---------------------------------------------------------------------------
# OIDC login / callback
# ---------------------------------------------------------------------------


@router.get("/auth/oidc/login")
async def oidc_login(request: Request) -> Response:
    """Redirect to the OIDC provider's authorization endpoint."""
    client = get_oidc_client()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OIDC authentication is not enabled",
        )
    redirect_uri = str(request.url_for("oidc_callback"))
    return await client.authorize_redirect(request, redirect_uri)  # type: ignore[no-any-return]


@router.get("/auth/oidc/callback")
async def oidc_callback(request: Request) -> Response:
    """Handle the OIDC callback: exchange code, upsert user, set cookie."""
    client = get_oidc_client()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OIDC authentication is not enabled",
        )

    try:
        token_data = await client.authorize_access_token(request)
    except Exception:
        log.warning("oidc callback failed: token exchange error", exc_info=True)
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC authentication failed",
        )

    # Extract user info from the ID token claims
    userinfo: dict[str, object] = token_data.get("userinfo", {})
    if not userinfo:
        # Fallback: parse the id_token ourselves
        id_token = token_data.get("id_token")
        if id_token and hasattr(id_token, "claims"):
            userinfo = id_token.claims

    oidc_sub = str(userinfo.get("sub", ""))
    email = str(userinfo.get("email", "")) or None
    preferred_username = str(userinfo.get("preferred_username", ""))
    username = preferred_username or oidc_sub

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC token missing required claims (sub/preferred_username)",
        )

    # Extract role from the full token data (includes realm_access, etc.)
    role = extract_role_from_token(dict(token_data))

    # Upsert user
    try:
        user = await crud.upsert_oidc_user(
            get_pool(),
            username=username,
            email=email,
            role=role,
            oidc_sub=oidc_sub,
        )
    except crud.IdentityProviderConflictError as exc:
        log.warning(
            "identity_provider_conflict",
            username=exc.username,
            existing_provider=exc.existing_provider,
            attempted_provider=exc.attempted_provider,
        )
        await log_audit(
            get_pool(),
            AuditEntryCreate(
                action=AuditAction.LOGIN,
                success=False,
                username=exc.username,
                error_message=(
                    f"identity-provider conflict: username owned by "
                    f"{exc.existing_provider}, rejected {exc.attempted_provider} bind"
                ),
                **request_ctx(request),
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication failed — contact your administrator",
        ) from exc

    log.info("oidc login success", username=username, role=role.value)

    # Create local JWT and set cookie
    jwt_token = create_token(user.id, user.username, user.role.value)
    max_age = settings.jwt_expire_minutes * 60
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=_COOKIE_NAME,
        value=jwt_token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
        max_age=max_age,
    )
    return response


_admin = require_role(UserRole.ADMIN)


async def _enforce_subsumption(
    *,
    caller: User,
    granted: list[str] | None,
    target_username: str,
    request: Request,
) -> None:
    """Reject scope-grant attempts that exceed the caller's own scopes.

    Subsumption is the core T1 / T1' invariant: a scoped caller cannot mint
    a user whose scopes are wider than their own — including (especially) a
    user with ``allowed_actions=None`` (legacy admin god-mode). Callers
    invoke this *before* mutating state so a denied attempt costs nothing.
    """
    if scopes_subsume(caller.allowed_actions, granted):
        return
    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.PRIVILEGE_ESCALATION_ATTEMPT,
            success=False,
            **user_ctx(caller),
            **request_ctx(request),
            error_message=(
                f"target_username={target_username} "
                f"caller_scopes={caller.allowed_actions} "
                f"granted_scopes={granted}"
            ),
        ),
    )
    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        detail="cannot grant scopes wider than your own",
    )


async def _audit_role_escalation(
    caller: User, target_username: str, request: Request, *, reason: str
) -> None:
    """Log a privilege-escalation attempt with consistent shape.

    Used by every admin-mutation endpoint that gates on
    ``role_subsumes`` — keeping the audit row format uniform makes it
    much easier to alert on. ``reason`` should describe the specific
    check that failed (caller-vs-target role, target-role escalation,
    cross-role password reset).
    """
    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.PRIVILEGE_ESCALATION_ATTEMPT,
            success=False,
            **user_ctx(caller),
            **request_ctx(request),
            error_message=f"{reason} target_username={target_username}",
        ),
    )


@router.post("/api/users", response_model=UserCreated, status_code=status.HTTP_201_CREATED)
@scoped_endpoint("users:create")
async def create_user(
    payload: UserCreate,
    request: Request,
    caller: User = Depends(_admin),  # noqa: B008
) -> UserCreated:
    """Create a new API-key user (admin only).

    Returns the plaintext API key in the 201 response — it is not recoverable
    afterwards. Callers should omit ``api_key`` from the request body and let
    the server generate a strong value; supplying the field remains supported
    for one more release cycle but is deprecated (removal in v1.5.0).
    """
    await _enforce_subsumption(
        caller=caller,
        granted=payload.allowed_actions,
        target_username=payload.username,
        request=request,
    )
    try:
        created, plaintext_key = await crud.create_user(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"user with username {payload.username!r} already exists",
        ) from exc
    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.CREATE_USER,
            success=True,
            **user_ctx(caller),
            **request_ctx(request),
            error_message=f"target_username={created.username}, auth=api_key",
        ),
    )
    return UserCreated.model_validate(
        {
            **UserAdmin.model_validate(created, from_attributes=True).model_dump(),
            "api_key": plaintext_key,
        }
    )


@router.post("/api/users/local", response_model=UserAdmin, status_code=status.HTTP_201_CREATED)
@scoped_endpoint("users:create")
async def create_local_user(
    payload: UserCreateLocal,
    request: Request,
    caller: User = Depends(_admin),  # noqa: B008
) -> User:
    """Create a new local (password) user (admin only).

    Local users carry no scope payload — ``UserCreateLocal`` deliberately
    excludes ``allowed_actions`` so the row is always created in legacy
    role-based mode. That means scope-subsumption (a scoped caller cannot
    grant ``None`` scopes) is the wrong gate here: it would block
    ``noc-svc`` from ever creating a local user even though local-mode
    grants no scopes at all. Apply role-subsumption instead — the caller
    can mint a user only at or below their own role, with the existing
    ``_admin`` dependency setting the floor.
    """
    if not role_subsumes(caller.role, payload.role):
        await _audit_role_escalation(
            caller,
            payload.username,
            request,
            reason=(
                f"local-create role escalation: caller_role={caller.role.value} "
                f"target_role={payload.role.value}"
            ),
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="cannot create user with role higher than your own",
        )
    try:
        created = await crud.create_local_user(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"user with username {payload.username!r} already exists",
        ) from exc
    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.CREATE_USER,
            success=True,
            **user_ctx(caller),
            **request_ctx(request),
            error_message=f"target_username={created.username}, auth=local_password",
        ),
    )
    return created


@router.get("/api/users", response_model=list[UserAdmin])
@scoped_endpoint("users:read")
async def list_users(
    _caller: User = Depends(_admin),  # noqa: B008
) -> list[User]:
    """List all users (admin only)."""
    return await crud.list_users(get_pool())


@router.delete("/api/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
@scoped_endpoint("users:delete")
async def delete_user(
    user_id: int,
    request: Request,
    caller: User = Depends(_admin),  # noqa: B008
) -> None:
    """Delete a user (admin only)."""
    target = await crud.get_user_by_id(get_pool(), user_id)
    deleted = await crud.delete_user(get_pool(), user_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.DELETE_USER,
            success=True,
            **user_ctx(caller),
            **request_ctx(request),
            error_message=(
                f"target_user_id={user_id}, target_username={target.username if target else None}"
            ),
        ),
    )


@router.patch("/api/users/{user_id}", response_model=UserAdmin)
@scoped_endpoint("users:update")
async def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    caller: User = Depends(_admin),  # noqa: B008
) -> User:
    """Partial update of a user (admin only).

    Guards (in order):
        1. Target exists (404 if not).
        2. Caller's role >= target's current role (403 + audit if not).
        3. If ``payload.role`` is set, caller's role >= new role (403 + audit).
        4. Last-admin lockout: if the change would leave zero enabled
           admins, refuse (409). Covers both ``enabled=false`` on the only
           admin and ``role=<not admin>`` demoting the only admin.

    On ``enabled=false`` we bump ``sessions_valid_after`` so every live
    JWT for the target is rejected on its next request. ``allowed_actions``
    is rejected at the Pydantic layer (`UserUpdate.model_config["extra"]
    == "forbid"`); a Phase 2 endpoint will add scope mutation with its
    own subsumption guard.
    """
    target = await crud.get_user_by_id(get_pool(), user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")

    if not role_subsumes(caller.role, target.role):
        await _audit_role_escalation(
            caller,
            target.username,
            request,
            reason=(
                f"PATCH on higher-role target: caller_role={caller.role.value} "
                f"target_role={target.role.value}"
            ),
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="cannot modify user with role higher than your own",
        )

    if payload.role is not None and not role_subsumes(caller.role, payload.role):
        await _audit_role_escalation(
            caller,
            target.username,
            request,
            reason=(
                f"PATCH role escalation: caller_role={caller.role.value} "
                f"new_role={payload.role.value}"
            ),
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="cannot grant role higher than your own",
        )

    # Last-admin lockout — only relevant when the target is currently an
    # enabled admin and the change would either disable them or demote.
    # We compute "would the row remain an enabled admin after PATCH" and
    # only count when it would not.
    if target.role == UserRole.ADMIN and target.enabled:
        will_remain_admin = payload.enabled is not False and (
            payload.role is None or payload.role == UserRole.ADMIN
        )
        if not will_remain_admin:
            admin_count = await crud.count_enabled_admins(get_pool())
            if admin_count <= 1:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    detail="cannot disable or demote the last enabled admin",
                )

    try:
        updated = await crud.update_user(get_pool(), user_id, payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="username already exists",
        ) from exc

    if updated is None:
        # Race: target deleted between the fetch above and the update.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")

    if payload.enabled is False:
        await crud.invalidate_user_sessions(get_pool(), user_id)

    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.UPDATE_USER,
            success=True,
            **user_ctx(caller),
            **request_ctx(request),
            error_message=(
                f"target_username={updated.username}, "
                f"fields={sorted(payload.model_dump(exclude_unset=True).keys())}"
            ),
        ),
    )
    return updated


@router.post(
    "/api/users/{user_id}/password",
    status_code=status.HTTP_204_NO_CONTENT,
)
@scoped_endpoint("users:reset_password")
async def admin_reset_password(
    user_id: int,
    payload: PasswordResetRequest,
    request: Request,
    caller: User = Depends(_admin),  # noqa: B008
) -> Response:
    """Admin-driven password reset for a local-auth user.

    Separate from PATCH per industry practice (Keycloak, Okta, AWS
    Cognito, MS Graph all expose a dedicated endpoint). Reasons:

        * Side effects PATCH shouldn't have — bumps ``sessions_valid_after``
          so every live JWT for the target dies.
        * Audit clarity — ``RESET_PASSWORD`` is a high-value security
          event and shouldn't be conflated with profile updates.
        * Forward-compat — ``users:reset_password`` is a separate scope
          so a future "support" role can rotate credentials without
          having edit-everything power.

    Only accepts ``auth_provider='local'``; LDAP / OIDC passwords aren't
    ours to manage.
    """
    target = await crud.get_user_by_id(get_pool(), user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")

    if target.auth_provider != "local":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=(
                f"password reset only available for local users; "
                f"target has auth_provider={target.auth_provider!r}"
            ),
        )

    if not role_subsumes(caller.role, target.role):
        await _audit_role_escalation(
            caller,
            target.username,
            request,
            reason=(
                f"password reset on higher-role target: "
                f"caller_role={caller.role.value} target_role={target.role.value}"
            ),
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="cannot reset password for user with role higher than your own",
        )

    updated = await crud.update_local_user_password(get_pool(), user_id, payload.new_password)
    if not updated:
        # Race: target deleted between fetch and update.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")

    await crud.invalidate_user_sessions(get_pool(), user_id)

    await log_audit(
        get_pool(),
        AuditEntryCreate(
            action=AuditAction.RESET_PASSWORD,
            success=True,
            **user_ctx(caller),
            **request_ctx(request),
            error_message=f"target_username={target.username}",
        ),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
