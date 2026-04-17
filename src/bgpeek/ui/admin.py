"""Admin panel SSR routes (admin role only)."""

from __future__ import annotations

import secrets
from ipaddress import IPv4Address, IPv6Address, ip_address

import asyncpg
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError

from bgpeek import __version__
from bgpeek.config import settings
from bgpeek.core.auth import require_role
from bgpeek.core.cache import invalidate_device
from bgpeek.core.circuit_breaker import failure_counts as cb_failure_counts
from bgpeek.core.commands import supported_platforms
from bgpeek.core.community_labels import color_pairs as _color_pairs
from bgpeek.core.community_labels import refresh_cache as refresh_label_cache
from bgpeek.core.templates import templates
from bgpeek.db import audit as audit_crud
from bgpeek.db import community_labels as label_crud
from bgpeek.db import credentials as credential_crud
from bgpeek.db import devices as device_crud
from bgpeek.db import users as user_crud
from bgpeek.db import webhooks as webhook_crud
from bgpeek.db.pool import get_pool
from bgpeek.models.community_label import (
    ALLOWED_COLORS,
    CommunityLabelCreate,
    CommunityLabelUpdate,
    MatchType,
)
from bgpeek.models.credential import CredentialCreate, CredentialUpdate
from bgpeek.models.device import DeviceCreate, DeviceUpdate
from bgpeek.models.user import User, UserCreate, UserCreateLocal, UserRole, UserUpdate
from bgpeek.models.webhook import WebhookCreate, WebhookEvent, WebhookUpdate

router = APIRouter(prefix="/admin", tags=["admin-ui"])

_admin = require_role(UserRole.ADMIN)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@router.get("", response_class=HTMLResponse)
async def admin_index(
    request: Request,
    user: User = Depends(_admin),  # noqa: B008
) -> Response:
    """Admin dashboard — aggregate counts."""
    pool = get_pool()
    devices = await device_crud.list_devices(pool)
    users = await user_crud.list_users(pool)
    credentials = await credential_crud.list_credentials(pool)
    webhooks = await webhook_crud.list_webhooks(pool)
    stats = {
        "devices": len(devices),
        "users": len(users),
        "credentials": len(credentials),
        "webhooks": len(webhooks),
    }
    return templates.TemplateResponse(
        request=request,
        name="admin/index.html",
        context={
            "version": __version__,
            "user": user,
            "stats": stats,
            "t": request.state.t,
            "lang": request.state.lang,
        },
    )


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


def _parse_optional_ip(raw: str | None, version: int) -> IPv4Address | IPv6Address | None:
    """Return ip_address(raw) of the expected version, or None for blank input."""
    if raw is None or raw.strip() == "":
        return None
    addr = ip_address(raw.strip())
    if version == 4 and not isinstance(addr, IPv4Address):
        raise ValueError("expected an IPv4 address")
    if version == 6 and not isinstance(addr, IPv6Address):
        raise ValueError("expected an IPv6 address")
    return addr


def _parse_int_or_none(raw: str | None) -> int | None:
    if raw is None or raw.strip() == "":
        return None
    return int(raw)


async def _render_device_form(
    request: Request,
    *,
    title: str,
    form_action: str,
    form: dict[str, object],
    device_id: int | None = None,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    pool = get_pool()
    creds = await credential_crud.list_credentials(pool)
    return templates.TemplateResponse(
        request=request,
        name="admin/devices_form.html",
        context={
            "version": __version__,
            "t": request.state.t,
            "lang": request.state.lang,
            "title": title,
            "form_action": form_action,
            "form": form,
            "device_id": device_id,
            "error": error,
            "platforms": supported_platforms(),
            "credentials": creds,
        },
        status_code=status_code,
    )


@router.get("/devices", response_class=HTMLResponse)
async def devices_list(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    pool = get_pool()
    devices = await device_crud.list_devices(pool)
    creds = await credential_crud.list_credentials(pool)
    credential_names = {c.id: c.name for c in creds}
    failures = await cb_failure_counts([d.name for d in devices])
    query_stats = await audit_crud.device_query_stats(pool, since_days=7)
    return templates.TemplateResponse(
        request=request,
        name="admin/devices_list.html",
        context={
            "version": __version__,
            "t": request.state.t,
            "lang": request.state.lang,
            "devices": devices,
            "credential_names": credential_names,
            "cb_failures": failures,
            "cb_threshold": settings.circuit_breaker_threshold,
            "query_stats": query_stats,
        },
    )


@router.get("/devices/new", response_class=HTMLResponse)
async def devices_new(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    form: dict[str, object] = {"port": 22, "enabled": True, "restricted": False}
    return await _render_device_form(
        request,
        title=request.state.t["admin_devices_new"],
        form_action="/admin/devices",
        form=form,
    )


@router.post("/devices")
async def devices_create(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    name: str = Form(...),
    address: str = Form(...),
    platform: str = Form(...),
    port: int = Form(22),
    credential_id: str | None = Form(None),
    description: str | None = Form(None),
    location: str | None = Form(None),
    region: str | None = Form(None),
    source4: str | None = Form(None),
    source6: str | None = Form(None),
    enabled: str | None = Form(None),
    restricted: str | None = Form(None),
) -> Response:
    raw = {
        "name": name,
        "address": address,
        "platform": platform,
        "port": port,
        "credential_id": credential_id,
        "description": description,
        "location": location,
        "region": region,
        "source4": source4,
        "source6": source6,
        "enabled": enabled == "1",
        "restricted": restricted == "1",
    }
    try:
        payload = DeviceCreate(
            name=name,
            address=ip_address(address.strip()),
            port=port,
            platform=platform,
            description=description or None,
            location=location or None,
            region=region or None,
            enabled=enabled == "1",
            restricted=restricted == "1",
            credential_id=_parse_int_or_none(credential_id),
            source4=_parse_optional_ip(source4, 4),  # type: ignore[arg-type]
            source6=_parse_optional_ip(source6, 6),  # type: ignore[arg-type]
        )
    except (ValidationError, ValueError) as exc:
        return await _render_device_form(
            request,
            title=request.state.t["admin_devices_new"],
            form_action="/admin/devices",
            form=raw,
            error=str(exc),
            status_code=400,
        )

    try:
        await device_crud.create_device(get_pool(), payload)
    except asyncpg.UniqueViolationError:
        return await _render_device_form(
            request,
            title=request.state.t["admin_devices_new"],
            form_action="/admin/devices",
            form=raw,
            error=f"device with name {name!r} already exists",
            status_code=409,
        )
    return RedirectResponse("/admin/devices", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/devices/{device_id}/edit", response_class=HTMLResponse)
async def devices_edit(
    device_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    device = await device_crud.get_device_by_id(get_pool(), device_id)
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    form = device.model_dump()
    return await _render_device_form(
        request,
        title=request.state.t["admin_devices_edit"],
        form_action=f"/admin/devices/{device_id}",
        form=form,
        device_id=device_id,
    )


@router.post("/devices/{device_id}")
async def devices_update(
    device_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    name: str = Form(...),
    address: str = Form(...),
    platform: str = Form(...),
    port: int = Form(22),
    credential_id: str | None = Form(None),
    description: str | None = Form(None),
    location: str | None = Form(None),
    region: str | None = Form(None),
    source4: str | None = Form(None),
    source6: str | None = Form(None),
    enabled: str | None = Form(None),
    restricted: str | None = Form(None),
) -> Response:
    raw = {
        "name": name,
        "address": address,
        "platform": platform,
        "port": port,
        "credential_id": _parse_int_or_none(credential_id),
        "description": description,
        "location": location,
        "region": region,
        "source4": source4,
        "source6": source6,
        "enabled": enabled == "1",
        "restricted": restricted == "1",
    }
    try:
        payload = DeviceUpdate(
            name=name,
            address=ip_address(address.strip()),
            port=port,
            platform=platform,
            description=description or None,
            location=location or None,
            region=region or None,
            enabled=enabled == "1",
            restricted=restricted == "1",
            credential_id=_parse_int_or_none(credential_id),
            source4=_parse_optional_ip(source4, 4),  # type: ignore[arg-type]
            source6=_parse_optional_ip(source6, 6),  # type: ignore[arg-type]
        )
    except (ValidationError, ValueError) as exc:
        return await _render_device_form(
            request,
            title=request.state.t["admin_devices_edit"],
            form_action=f"/admin/devices/{device_id}",
            form=raw,
            device_id=device_id,
            error=str(exc),
            status_code=400,
        )

    try:
        device = await device_crud.update_device(get_pool(), device_id, payload)
    except asyncpg.UniqueViolationError:
        return await _render_device_form(
            request,
            title=request.state.t["admin_devices_edit"],
            form_action=f"/admin/devices/{device_id}",
            form=raw,
            device_id=device_id,
            error=f"device with name {name!r} already exists",
            status_code=409,
        )
    if device is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    await invalidate_device(device.name)
    return RedirectResponse("/admin/devices", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/devices/{device_id}/delete")
async def devices_delete(
    device_id: int,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    device = await device_crud.get_device_by_id(get_pool(), device_id)
    deleted = await device_crud.delete_device(get_pool(), device_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="device not found")
    if device is not None:
        await invalidate_device(device.name)
    return RedirectResponse("/admin/devices", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# SSH credentials
# ---------------------------------------------------------------------------


def _validate_credential_fields(auth_type: str, key_name: str | None, password: str | None) -> None:
    """Mirror API-side validation for auth_type coherence."""
    if "key" in auth_type and not key_name:
        raise ValueError("key filename is required when auth type includes 'key'")
    if "password" in auth_type and not password:
        raise ValueError("password is required when auth type includes 'password'")


async def _render_credential_form(
    request: Request,
    *,
    title: str,
    form_action: str,
    form: dict[str, object],
    is_edit: bool,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    t = request.state.t
    return templates.TemplateResponse(
        request=request,
        name="admin/credentials_form.html",
        context={
            "version": __version__,
            "t": t,
            "lang": request.state.lang,
            "title": title,
            "form_action": form_action,
            "form": form,
            "error": error,
            "password_hint": t["admin_creds_password_hint_edit"]
            if is_edit
            else t["admin_creds_password_hint_new"],
            "password_placeholder": t["admin_creds_password_placeholder_edit"] if is_edit else "",
        },
        status_code=status_code,
    )


@router.get("/credentials", response_class=HTMLResponse)
async def credentials_list(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    creds = await credential_crud.list_credentials(get_pool())
    return templates.TemplateResponse(
        request=request,
        name="admin/credentials_list.html",
        context={
            "version": __version__,
            "t": request.state.t,
            "lang": request.state.lang,
            "credentials": creds,
        },
    )


@router.get("/credentials/new", response_class=HTMLResponse)
async def credentials_new(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    form: dict[str, object] = {"auth_type": "key"}
    return await _render_credential_form(
        request,
        title=request.state.t["admin_creds_new"],
        form_action="/admin/credentials",
        form=form,
        is_edit=False,
    )


@router.post("/credentials")
async def credentials_create(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    name: str = Form(...),
    auth_type: str = Form(...),
    username: str = Form(...),
    key_name: str | None = Form(None),
    password: str | None = Form(None),
    description: str | None = Form(None),
) -> Response:
    raw: dict[str, object] = {
        "name": name,
        "auth_type": auth_type,
        "username": username,
        "key_name": key_name,
        "description": description,
    }
    try:
        _validate_credential_fields(auth_type, key_name or None, password or None)
        payload = CredentialCreate(
            name=name,
            description=description or "",
            auth_type=auth_type,
            username=username,
            key_name=key_name or None,
            password=password or None,
        )
    except (ValidationError, ValueError) as exc:
        return await _render_credential_form(
            request,
            title=request.state.t["admin_creds_new"],
            form_action="/admin/credentials",
            form=raw,
            is_edit=False,
            error=str(exc),
            status_code=400,
        )

    try:
        await credential_crud.create_credential(get_pool(), payload)
    except asyncpg.UniqueViolationError:
        return await _render_credential_form(
            request,
            title=request.state.t["admin_creds_new"],
            form_action="/admin/credentials",
            form=raw,
            is_edit=False,
            error=f"credential with name {name!r} already exists",
            status_code=409,
        )
    return RedirectResponse("/admin/credentials", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/credentials/{credential_id}/edit", response_class=HTMLResponse)
async def credentials_edit(
    credential_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    cred = await credential_crud.get_credential(get_pool(), credential_id)
    if cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="credential not found")
    form = cred.model_dump()
    # Password is masked ("****") on read; don't pre-fill the input — empty = keep.
    form["password"] = ""
    return await _render_credential_form(
        request,
        title=request.state.t["admin_creds_edit"],
        form_action=f"/admin/credentials/{credential_id}",
        form=form,
        is_edit=True,
    )


@router.post("/credentials/{credential_id}")
async def credentials_update(
    credential_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    name: str = Form(...),
    auth_type: str = Form(...),
    username: str = Form(...),
    key_name: str | None = Form(None),
    password: str | None = Form(None),
    description: str | None = Form(None),
) -> Response:
    raw: dict[str, object] = {
        "name": name,
        "auth_type": auth_type,
        "username": username,
        "key_name": key_name,
        "description": description,
    }

    # On edit: empty password means "keep the existing one", so we omit it
    # from the update payload. Non-empty means "replace".
    update_fields: dict[str, object] = {
        "name": name,
        "auth_type": auth_type,
        "username": username,
        "key_name": key_name or None,
        "description": description or "",
    }
    if password:
        update_fields["password"] = password

    try:
        # When auth_type requires a password but none is being set (neither now nor
        # previously), validation happens at the update layer. For key-only flows
        # this check still enforces key_name presence.
        existing = await credential_crud.get_credential(get_pool(), credential_id)
        if existing is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="credential not found")
        effective_password = password if password else (existing.password or None)
        _validate_credential_fields(auth_type, key_name or None, effective_password)
        payload = CredentialUpdate(**update_fields)  # type: ignore[arg-type]
    except (ValidationError, ValueError) as exc:
        return await _render_credential_form(
            request,
            title=request.state.t["admin_creds_edit"],
            form_action=f"/admin/credentials/{credential_id}",
            form=raw,
            is_edit=True,
            error=str(exc),
            status_code=400,
        )

    try:
        cred = await credential_crud.update_credential(get_pool(), credential_id, payload)
    except asyncpg.UniqueViolationError:
        return await _render_credential_form(
            request,
            title=request.state.t["admin_creds_edit"],
            form_action=f"/admin/credentials/{credential_id}",
            form=raw,
            is_edit=True,
            error=f"credential with name {name!r} already exists",
            status_code=409,
        )
    if cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="credential not found")
    return RedirectResponse("/admin/credentials", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/credentials/{credential_id}/delete")
async def credentials_delete(
    credential_id: int,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    try:
        deleted = await credential_crud.delete_credential(get_pool(), credential_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="credential not found")
    return RedirectResponse("/admin/credentials", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


_ROLE_CHOICES = [UserRole.ADMIN.value, UserRole.NOC.value, UserRole.PUBLIC.value]


async def _render_user_form(
    request: Request,
    *,
    title: str,
    form_action: str,
    form: dict[str, object],
    is_edit: bool,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    return templates.TemplateResponse(
        request=request,
        name="admin/users_form.html",
        context={
            "version": __version__,
            "t": request.state.t,
            "lang": request.state.lang,
            "title": title,
            "form_action": form_action,
            "form": form,
            "error": error,
            "is_edit": is_edit,
            "roles": _ROLE_CHOICES,
        },
        status_code=status_code,
    )


@router.get("/users", response_class=HTMLResponse)
async def users_list(
    request: Request,
    current_user: User = Depends(_admin),  # noqa: B008
) -> Response:
    users = await user_crud.list_users(get_pool())
    return templates.TemplateResponse(
        request=request,
        name="admin/users_list.html",
        context={
            "version": __version__,
            "t": request.state.t,
            "lang": request.state.lang,
            "users": users,
            "current_user": current_user,
        },
    )


@router.get("/users/new", response_class=HTMLResponse)
async def users_new(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    form: dict[str, object] = {
        "auth_type": "local",
        "role": UserRole.PUBLIC.value,
        "enabled": True,
    }
    return await _render_user_form(
        request,
        title=request.state.t["admin_users_new"],
        form_action="/admin/users",
        form=form,
        is_edit=False,
    )


@router.post("/users")
async def users_create(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    auth_type: str = Form("local"),
    username: str = Form(...),
    email: str | None = Form(None),
    role: str = Form(...),
    password: str | None = Form(None),
    enabled: str | None = Form(None),
) -> Response:
    raw: dict[str, object] = {
        "auth_type": auth_type,
        "username": username,
        "email": email,
        "role": role,
        "enabled": enabled == "1",
    }

    if role not in _ROLE_CHOICES:
        return await _render_user_form(
            request,
            title=request.state.t["admin_users_new"],
            form_action="/admin/users",
            form=raw,
            is_edit=False,
            error=f"invalid role: {role!r}",
            status_code=400,
        )

    role_enum = UserRole(role)

    if auth_type == "api_key":
        api_key = secrets.token_urlsafe(32)
        try:
            payload_ak = UserCreate(
                username=username,
                email=email or None,
                role=role_enum,
                enabled=enabled == "1",
                api_key=api_key,
            )
        except ValidationError as exc:
            return await _render_user_form(
                request,
                title=request.state.t["admin_users_new"],
                form_action="/admin/users",
                form=raw,
                is_edit=False,
                error=str(exc),
                status_code=400,
            )
        try:
            await user_crud.create_user(get_pool(), payload_ak)
        except asyncpg.UniqueViolationError:
            return await _render_user_form(
                request,
                title=request.state.t["admin_users_new"],
                form_action="/admin/users",
                form=raw,
                is_edit=False,
                error=f"user with username {username!r} already exists",
                status_code=409,
            )
        # Show the generated key once — it won't be retrievable later.
        return templates.TemplateResponse(
            request=request,
            name="admin/users_key_shown.html",
            context={
                "version": __version__,
                "t": request.state.t,
                "lang": request.state.lang,
                "username": username,
                "api_key": api_key,
            },
        )

    # auth_type == "local"
    try:
        payload_local = UserCreateLocal(
            username=username,
            password=password or "",
            email=email or None,
            role=role_enum,
        )
    except ValidationError as exc:
        return await _render_user_form(
            request,
            title=request.state.t["admin_users_new"],
            form_action="/admin/users",
            form=raw,
            is_edit=False,
            error=str(exc),
            status_code=400,
        )
    try:
        await user_crud.create_local_user(get_pool(), payload_local)
    except asyncpg.UniqueViolationError:
        return await _render_user_form(
            request,
            title=request.state.t["admin_users_new"],
            form_action="/admin/users",
            form=raw,
            is_edit=False,
            error=f"user with username {username!r} already exists",
            status_code=409,
        )
    return RedirectResponse("/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
async def users_edit(
    user_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    u = await user_crud.get_user_by_id(get_pool(), user_id)
    if u is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
    form = u.model_dump()
    return await _render_user_form(
        request,
        title=request.state.t["admin_users_edit"],
        form_action=f"/admin/users/{user_id}",
        form=form,
        is_edit=True,
    )


@router.post("/users/{user_id}")
async def users_update(
    user_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    email: str | None = Form(None),
    role: str = Form(...),
    enabled: str | None = Form(None),
) -> Response:
    if role not in _ROLE_CHOICES:
        existing = await user_crud.get_user_by_id(get_pool(), user_id)
        if existing is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
        form = existing.model_dump()
        form["role"] = role
        return await _render_user_form(
            request,
            title=request.state.t["admin_users_edit"],
            form_action=f"/admin/users/{user_id}",
            form=form,
            is_edit=True,
            error=f"invalid role: {role!r}",
            status_code=400,
        )

    payload = UserUpdate(
        email=email or None,
        role=UserRole(role),
        enabled=enabled == "1",
    )
    updated = await user_crud.update_user(get_pool(), user_id, payload)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
    return RedirectResponse("/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/delete")
async def users_delete(
    user_id: int,
    current_user: User = Depends(_admin),  # noqa: B008
) -> Response:
    if user_id == current_user.id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="you cannot delete your own account",
        )
    deleted = await user_crud.delete_user(get_pool(), user_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
    return RedirectResponse("/admin/users", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Community labels
# ---------------------------------------------------------------------------


async def _render_label_form(
    request: Request,
    *,
    title: str,
    form_action: str,
    form: dict[str, object],
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    return templates.TemplateResponse(
        request=request,
        name="admin/community_labels_form.html",
        context={
            "version": __version__,
            "t": request.state.t,
            "lang": request.state.lang,
            "title": title,
            "form_action": form_action,
            "form": form,
            "error": error,
            "color_pairs": _color_pairs(),
        },
        status_code=status_code,
    )


@router.get("/community-labels", response_class=HTMLResponse)
async def community_labels_list(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    labels = await label_crud.list_labels(get_pool())
    return templates.TemplateResponse(
        request=request,
        name="admin/community_labels_list.html",
        context={
            "version": __version__,
            "t": request.state.t,
            "lang": request.state.lang,
            "labels": labels,
            "color_pairs": _color_pairs(),
        },
    )


@router.get("/community-labels/new", response_class=HTMLResponse)
async def community_labels_new(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    form: dict[str, object] = {"match_type": "exact"}
    return await _render_label_form(
        request,
        title=request.state.t["admin_cl_new"],
        form_action="/admin/community-labels",
        form=form,
    )


def _validate_label_inputs(match_type: str, color: str | None) -> None:
    if match_type not in {"exact", "prefix"}:
        raise ValueError(f"invalid match_type: {match_type!r}")
    if color and color not in ALLOWED_COLORS:
        raise ValueError(f"invalid color: {color!r}")


@router.post("/community-labels")
async def community_labels_create(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    pattern: str = Form(...),
    match_type: str = Form("exact"),
    label: str = Form(...),
    color: str | None = Form(None),
) -> Response:
    color_value = color or None
    raw: dict[str, object] = {
        "pattern": pattern,
        "match_type": match_type,
        "label": label,
        "color": color_value,
    }
    try:
        _validate_label_inputs(match_type, color_value)
        payload = CommunityLabelCreate(
            pattern=pattern,
            match_type=MatchType(match_type),
            label=label,
            color=color_value,
        )
    except (ValidationError, ValueError) as exc:
        return await _render_label_form(
            request,
            title=request.state.t["admin_cl_new"],
            form_action="/admin/community-labels",
            form=raw,
            error=str(exc),
            status_code=400,
        )

    try:
        await label_crud.create_label(get_pool(), payload)
    except Exception as exc:  # noqa: BLE001 — surface DB uniqueness as 409
        msg = str(exc).lower()
        if "unique" in msg or "duplicate" in msg:
            return await _render_label_form(
                request,
                title=request.state.t["admin_cl_new"],
                form_action="/admin/community-labels",
                form=raw,
                error="a label with this pattern and match_type already exists",
                status_code=409,
            )
        raise
    await refresh_label_cache()
    return RedirectResponse("/admin/community-labels", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/community-labels/{label_id}/edit", response_class=HTMLResponse)
async def community_labels_edit(
    label_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    row = await label_crud.get_label(get_pool(), label_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="community label not found")
    return await _render_label_form(
        request,
        title=request.state.t["admin_cl_edit"],
        form_action=f"/admin/community-labels/{label_id}",
        form=row.model_dump(),
    )


@router.post("/community-labels/{label_id}")
async def community_labels_update(
    label_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    pattern: str = Form(...),
    match_type: str = Form("exact"),
    label: str = Form(...),
    color: str | None = Form(None),
) -> Response:
    color_value = color or None
    raw: dict[str, object] = {
        "pattern": pattern,
        "match_type": match_type,
        "label": label,
        "color": color_value,
    }
    try:
        _validate_label_inputs(match_type, color_value)
        payload = CommunityLabelUpdate(
            pattern=pattern,
            match_type=MatchType(match_type),
            label=label,
            color=color_value,
        )
    except (ValidationError, ValueError) as exc:
        return await _render_label_form(
            request,
            title=request.state.t["admin_cl_edit"],
            form_action=f"/admin/community-labels/{label_id}",
            form=raw,
            error=str(exc),
            status_code=400,
        )

    updated = await label_crud.update_label(get_pool(), label_id, payload)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="community label not found")
    await refresh_label_cache()
    return RedirectResponse("/admin/community-labels", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/community-labels/{label_id}/delete")
async def community_labels_delete(
    label_id: int,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    deleted = await label_crud.delete_label(get_pool(), label_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="community label not found")
    await refresh_label_cache()
    return RedirectResponse("/admin/community-labels", status_code=status.HTTP_303_SEE_OTHER)


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


_AVAILABLE_EVENTS = [e.value for e in WebhookEvent]


async def _render_webhook_form(
    request: Request,
    *,
    title: str,
    form_action: str,
    form: dict[str, object],
    is_edit: bool,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    t = request.state.t
    return templates.TemplateResponse(
        request=request,
        name="admin/webhooks_form.html",
        context={
            "version": __version__,
            "t": t,
            "lang": request.state.lang,
            "title": title,
            "form_action": form_action,
            "form": form,
            "error": error,
            "available_events": _AVAILABLE_EVENTS,
            "secret_hint": t["admin_wh_secret_hint_edit"]
            if is_edit
            else t["admin_wh_secret_hint_new"],
            "secret_placeholder": t["admin_wh_secret_placeholder_edit"] if is_edit else "",
        },
        status_code=status_code,
    )


def _normalize_event_list(events: list[str]) -> list[WebhookEvent]:
    result: list[WebhookEvent] = []
    for e in events:
        if e not in _AVAILABLE_EVENTS:
            raise ValueError(f"invalid event: {e!r}")
        result.append(WebhookEvent(e))
    return result


@router.get("/webhooks", response_class=HTMLResponse)
async def webhooks_list(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    hooks = await webhook_crud.list_webhooks(get_pool())
    # Mask secrets for display (just in case a template ever dumps them).
    hooks = [h.mask_secret() for h in hooks]
    return templates.TemplateResponse(
        request=request,
        name="admin/webhooks_list.html",
        context={
            "version": __version__,
            "t": request.state.t,
            "lang": request.state.lang,
            "webhooks": hooks,
        },
    )


@router.get("/webhooks/new", response_class=HTMLResponse)
async def webhooks_new(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    form: dict[str, object] = {"enabled": True, "events": []}
    return await _render_webhook_form(
        request,
        title=request.state.t["admin_wh_new"],
        form_action="/admin/webhooks",
        form=form,
        is_edit=False,
    )


@router.post("/webhooks")
async def webhooks_create(
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    name: str = Form(...),
    url: str = Form(...),
    secret: str | None = Form(None),
    enabled: str | None = Form(None),
) -> Response:
    raw_events = (await request.form()).getlist("events")
    events_list = [str(e) for e in raw_events]
    raw: dict[str, object] = {
        "name": name,
        "url": url,
        "events": events_list,
        "enabled": enabled == "1",
    }
    if not events_list:
        return await _render_webhook_form(
            request,
            title=request.state.t["admin_wh_new"],
            form_action="/admin/webhooks",
            form=raw,
            is_edit=False,
            error="select at least one event",
            status_code=400,
        )
    try:
        normalized_events = _normalize_event_list(events_list)
        payload = WebhookCreate(
            name=name,
            url=url,
            events=normalized_events,
            enabled=enabled == "1",
            secret=secret or None,
        )
    except (ValidationError, ValueError) as exc:
        return await _render_webhook_form(
            request,
            title=request.state.t["admin_wh_new"],
            form_action="/admin/webhooks",
            form=raw,
            is_edit=False,
            error=str(exc),
            status_code=400,
        )

    await webhook_crud.create_webhook(get_pool(), payload)
    return RedirectResponse("/admin/webhooks", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/webhooks/{webhook_id}/edit", response_class=HTMLResponse)
async def webhooks_edit(
    webhook_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    hook = await webhook_crud.get_webhook(get_pool(), webhook_id)
    if hook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="webhook not found")
    form = hook.model_dump()
    # events come back as a list of WebhookEvent enums — template expects raw strings
    form["events"] = [e.value if isinstance(e, WebhookEvent) else str(e) for e in hook.events]
    form["secret"] = ""  # never echo back; blank = keep existing
    return await _render_webhook_form(
        request,
        title=request.state.t["admin_wh_edit"],
        form_action=f"/admin/webhooks/{webhook_id}",
        form=form,
        is_edit=True,
    )


@router.post("/webhooks/{webhook_id}")
async def webhooks_update(
    webhook_id: int,
    request: Request,
    _user: User = Depends(_admin),  # noqa: B008
    name: str = Form(...),
    url: str = Form(...),
    secret: str | None = Form(None),
    enabled: str | None = Form(None),
) -> Response:
    raw_events = (await request.form()).getlist("events")
    events_list = [str(e) for e in raw_events]
    raw: dict[str, object] = {
        "name": name,
        "url": url,
        "events": events_list,
        "enabled": enabled == "1",
    }
    if not events_list:
        return await _render_webhook_form(
            request,
            title=request.state.t["admin_wh_edit"],
            form_action=f"/admin/webhooks/{webhook_id}",
            form=raw,
            is_edit=True,
            error="select at least one event",
            status_code=400,
        )

    # Empty secret field means "keep existing"; non-empty replaces.
    update_fields: dict[str, object] = {
        "name": name,
        "url": url,
        "events": events_list,
        "enabled": enabled == "1",
    }
    if secret:
        update_fields["secret"] = secret

    try:
        _normalize_event_list(events_list)
        payload = WebhookUpdate(**update_fields)  # type: ignore[arg-type]
    except (ValidationError, ValueError) as exc:
        return await _render_webhook_form(
            request,
            title=request.state.t["admin_wh_edit"],
            form_action=f"/admin/webhooks/{webhook_id}",
            form=raw,
            is_edit=True,
            error=str(exc),
            status_code=400,
        )

    updated = await webhook_crud.update_webhook(get_pool(), webhook_id, payload)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="webhook not found")
    return RedirectResponse("/admin/webhooks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/webhooks/{webhook_id}/delete")
async def webhooks_delete(
    webhook_id: int,
    _user: User = Depends(_admin),  # noqa: B008
) -> Response:
    deleted = await webhook_crud.delete_webhook(get_pool(), webhook_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="webhook not found")
    return RedirectResponse("/admin/webhooks", status_code=status.HTTP_303_SEE_OTHER)
