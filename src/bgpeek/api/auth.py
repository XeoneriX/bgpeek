"""HTTP handlers for /api/auth, /api/users, and web login/logout."""

from __future__ import annotations

import asyncpg
import structlog
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi_csrf_protect import CsrfProtect

from bgpeek.config import settings
from bgpeek.core.auth import authenticate, require_role
from bgpeek.core.csrf import issue_csrf_token, set_csrf_cookie, validate_csrf
from bgpeek.core.jwt import create_token
from bgpeek.core.ldap import authenticate_ldap
from bgpeek.core.oidc import extract_role_from_token, get_oidc_client
from bgpeek.core.rate_limit import rate_limit_login
from bgpeek.core.templates import templates
from bgpeek.db import users as crud
from bgpeek.db.pool import get_pool
from bgpeek.models.user import (
    LoginRequest,
    LoginResponse,
    User,
    UserAdmin,
    UserCreate,
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
    _rl: None = Depends(rate_limit_login),  # noqa: B008
) -> Response:
    """Handle web login form submission."""
    # 1. Try local DB
    user = await crud.get_user_by_credentials(get_pool(), username, password)

    # 2. Fallback to LDAP
    if user is None:
        ldap_info = await authenticate_ldap(username, password)
        if ldap_info is not None:
            user = await crud.upsert_ldap_user(
                get_pool(),
                username=ldap_info.username,
                email=ldap_info.email,
                role=ldap_info.role,
            )

    if user is None:
        log.info("web login failed", username=username)
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

    redirect_response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    redirect_response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
        max_age=max_age,
    )

    from bgpeek.core.webhooks import dispatch_webhook

    await dispatch_webhook(
        WebhookEvent.LOGIN,
        {"user_id": user.id, "username": user.username, "method": "web"},
    )

    return redirect_response


@router.post("/auth/logout")
async def logout(_csrf_ok: None = Depends(validate_csrf)) -> RedirectResponse:  # noqa: B008
    """Clear the auth cookie and redirect to login or main page."""
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
            user = await crud.upsert_ldap_user(
                get_pool(),
                username=ldap_info.username,
                email=ldap_info.email,
                role=ldap_info.role,
            )

    if user is None:
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
    user = await crud.upsert_oidc_user(
        get_pool(),
        username=username,
        email=email,
        role=role,
        oidc_sub=oidc_sub,
    )

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


@router.post("/api/users", response_model=UserAdmin, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> User:
    """Create a new API-key user (admin only)."""
    try:
        return await crud.create_user(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"user with username {payload.username!r} already exists",
        ) from exc


@router.post("/api/users/local", response_model=UserAdmin, status_code=status.HTTP_201_CREATED)
async def create_local_user(
    payload: UserCreateLocal,
    _caller: User = Depends(_admin),  # noqa: B008
) -> User:
    """Create a new local (password) user (admin only)."""
    try:
        return await crud.create_local_user(get_pool(), payload)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"user with username {payload.username!r} already exists",
        ) from exc


@router.get("/api/users", response_model=list[UserAdmin])
async def list_users(
    _caller: User = Depends(_admin),  # noqa: B008
) -> list[User]:
    """List all users (admin only)."""
    return await crud.list_users(get_pool())


@router.delete("/api/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> None:
    """Delete a user (admin only)."""
    deleted = await crud.delete_user(get_pool(), user_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
