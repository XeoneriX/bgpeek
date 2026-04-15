"""bgpeek FastAPI application entry point."""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from itertools import groupby
from operator import attrgetter

import structlog
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from prometheus_fastapi_instrumentator import Instrumentator
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from bgpeek import __version__
from bgpeek.api import auth as auth_api
from bgpeek.api import community_labels as community_labels_api
from bgpeek.api import credentials as credentials_api
from bgpeek.api import devices as devices_api
from bgpeek.api import query as query_api
from bgpeek.api import webhooks as webhooks_api
from bgpeek.config import settings
from bgpeek.core.auth import guest_user, optional_auth
from bgpeek.core.i18n import SUPPORTED_LANGS, detect_language, get_translations
from bgpeek.core.oidc import setup_oidc
from bgpeek.core.redis import close_redis, get_redis, init_redis
from bgpeek.core.templates import templates
from bgpeek.core.webhooks import shutdown as shutdown_webhooks
from bgpeek.db import devices as device_crud
from bgpeek.db.pool import close_pool, get_pool, init_pool
from bgpeek.db.results import list_results
from bgpeek.models.user import User, UserRole

log = structlog.get_logger()


def _parse_lg_links() -> list[dict[str, str]]:
    """Parse the ``lg_links`` JSON config into a list of link dicts."""
    raw = settings.lg_links.strip()
    if not raw:
        return []
    try:
        links = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("invalid lg_links JSON, ignoring", raw=raw)
        return []
    if not isinstance(links, list):
        return []
    result: list[dict[str, str]] = []
    for entry in links:
        if isinstance(entry, dict) and "name" in entry and "url" in entry:
            result.append({"name": str(entry["name"]), "url": str(entry["url"])})
    return result


_lg_links: list[dict[str, str]] = _parse_lg_links()

_LANG_COOKIE = "bgpeek_lang"
_LANG_COOKIE_MAX_AGE = 365 * 24 * 60 * 60  # 1 year

# ---------------------------------------------------------------------------
# Cleanup task handle
# ---------------------------------------------------------------------------
_cleanup_task: asyncio.Task[None] | None = None


async def _ensure_default_credential() -> None:
    """Create a 'default' credential from global SSH config if none exists.

    This provides backward compatibility: existing deployments with a single
    SSH key/username get a credential row auto-created, and all devices with
    ``credential_id IS NULL`` get assigned to it.
    """
    from bgpeek.db.credentials import get_credential_by_name

    pool = get_pool()
    existing = await get_credential_by_name(pool, "default")
    if existing is not None:
        return  # already set up

    # Determine key_name: look for default.key or id_rsa in keys_dir
    key_name: str | None = None
    for candidate in ("default.key", "id_rsa"):
        if (settings.keys_dir / candidate).is_file():
            key_name = candidate
            break
    # Also check legacy config_dir/id_rsa
    if key_name is None and (settings.config_dir / "id_rsa").is_file():
        key_name = None  # will still need manual setup, but create the row

    if key_name is None:
        log.info("no default SSH key found, skipping auto-credential creation")
        return

    from bgpeek.db.credentials import create_credential
    from bgpeek.models.credential import CredentialCreate

    cred = await create_credential(
        pool,
        CredentialCreate(
            name="default",
            description="Auto-created from global SSH config",
            auth_type="key",
            username=settings.ssh_username,
            key_name=key_name,
        ),
    )
    log.info("auto_created_default_credential", credential_id=cred.id, key_name=key_name)

    # Assign to all devices that have no credential
    result = await pool.execute(
        "UPDATE devices SET credential_id = $1 WHERE credential_id IS NULL",
        cred.id,
    )
    count = int(result.split()[-1])
    if count:
        log.info("assigned_default_credential", device_count=count)


async def _periodic_cleanup() -> None:
    """Background loop: clean up expired results and old audit entries."""
    from bgpeek.db.audit import cleanup_old_entries
    from bgpeek.db.results import cleanup_expired

    while True:
        await asyncio.sleep(3600)  # run every hour
        try:
            pool = get_pool()
            removed = await cleanup_expired(pool)
            if removed:
                log.info("cleanup_expired_results", removed=removed)
        except Exception:
            log.warning("cleanup_expired_results_failed", exc_info=True)

        if settings.audit_ttl_days > 0:
            try:
                pool = get_pool()
                removed = await cleanup_old_entries(pool, settings.audit_ttl_days)
                if removed:
                    log.info("cleanup_old_audit", removed=removed)
            except Exception:
                log.warning("cleanup_old_audit_failed", exc_info=True)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class I18nMiddleware(BaseHTTPMiddleware):
    """Detect language preference and attach ``t`` / ``lang`` to request state."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        query_lang = request.query_params.get("lang")
        cookie_lang = request.cookies.get(_LANG_COOKIE)
        accept_lang = request.headers.get("accept-language")

        lang = detect_language(query_lang, cookie_lang, accept_lang, settings.default_lang)
        request.state.lang = lang
        request.state.t = get_translations(lang)

        response = await call_next(request)

        # Persist language choice in cookie when explicitly set via query param.
        if query_lang and query_lang in SUPPORTED_LANGS:
            response.set_cookie(
                key=_LANG_COOKIE,
                value=query_lang,
                max_age=_LANG_COOKIE_MAX_AGE,
                httponly=False,
                samesite="lax",
                path="/",
            )

        return response


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Attach a unique request ID to every request for log correlation."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        # Bind to structlog context for all downstream log calls
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to all responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.cookie_secure:  # implies HTTPS
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown hooks."""
    global _cleanup_task

    log.info("bgpeek starting", version=__version__, host=settings.host, port=settings.port)

    # Security: refuse to start with default secrets
    _insecure_defaults = {"change-me-in-production", "change-me-session-secret"}  # noqa: S105
    if not settings.debug:
        if settings.jwt_secret in _insecure_defaults:
            log.critical(
                "BGPEEK_JWT_SECRET is set to the default value — refusing to start. Set a strong secret."
            )
            raise SystemExit(1)
        if settings.session_secret in _insecure_defaults:
            log.critical(
                "BGPEEK_SESSION_SECRET is set to the default value — refusing to start. Set a strong secret."
            )
            raise SystemExit(1)

    await init_pool(
        settings.database_url,
        min_size=settings.db_pool_min,
        max_size=settings.db_pool_max,
    )

    # Auto-migrate on startup
    if settings.auto_migrate:
        try:
            from bgpeek.db.migrate import apply_migrations

            applied = await asyncio.to_thread(apply_migrations)
            if applied:
                log.info("auto_migrate_applied", count=applied)
        except Exception:
            log.error("auto_migrate_failed", exc_info=True)

    # Auto-create default credential for backward compatibility
    try:
        await _ensure_default_credential()
    except Exception:
        log.warning("default_credential_setup_failed", exc_info=True)

    # Preload community labels into the process-local cache
    try:
        from bgpeek.core.community_labels import refresh_cache as refresh_community_labels

        await refresh_community_labels()
    except Exception:
        log.warning("community_labels_preload_failed", exc_info=True)

    try:
        await init_redis(settings.redis_url)
    except Exception:
        log.warning("redis unavailable — cache disabled", exc_info=True)

    # Start periodic cleanup
    _cleanup_task = asyncio.create_task(_periodic_cleanup())

    yield

    # Shutdown
    if _cleanup_task is not None:
        _cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _cleanup_task

    await shutdown_webhooks()
    await close_redis()
    await close_pool()
    log.info("bgpeek shutting down")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="bgpeek",
    description="Open-source looking glass for ISPs and IX operators",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if settings.debug else None,
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(I18nMiddleware)

# OIDC must be set up before routes are registered (needs SessionMiddleware).
setup_oidc(app)

# Prometheus metrics
if settings.metrics_enabled:
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

app.mount(
    "/static",
    StaticFiles(directory=str(settings.static_dir)),
    name="static",
)

app.include_router(auth_api.router)
app.include_router(credentials_api.router)
app.include_router(devices_api.router)
app.include_router(query_api.router)
app.include_router(webhooks_api.router)
app.include_router(community_labels_api.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


@app.get("/api/health", response_class=JSONResponse)
async def health(deep: bool = False) -> dict[str, object]:
    """Liveness probe. Pass ?deep=true for DB + Redis connectivity check."""
    result: dict[str, object] = {"status": "ok", "version": __version__}

    if not deep:
        return result

    # DB check
    try:
        pool = get_pool()
        await pool.fetchval("SELECT 1")
        result["database"] = "ok"
    except Exception:
        result["database"] = "error"
        result["status"] = "degraded"

    # Redis check
    try:
        r = get_redis()
        await r.ping()  # type: ignore[misc]
        result["redis"] = "ok"
    except Exception:
        result["redis"] = "error"
        result["status"] = "degraded"

    return result


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    user: User | None = Depends(optional_auth),  # noqa: B008
) -> Response:
    """Main looking glass form — loads devices from DB for the dropdown."""
    if user is None:
        if settings.access_mode == "closed":
            return RedirectResponse(url="/auth/login", status_code=303)
        if settings.access_mode == "guest":
            user = guest_user()
    include_restricted = user is not None and user.role in (UserRole.ADMIN, UserRole.NOC)
    try:
        devices = await device_crud.list_devices(
            get_pool(), enabled_only=True, include_restricted=include_restricted
        )
    except RuntimeError:
        devices = []

    # Group devices by region for <optgroup> rendering.
    # Within each region, devices sorted by (location, name).
    sorted_devices = sorted(devices, key=lambda d: (d.region or "", d.location or "", d.name))
    device_groups = [
        (region, list(grp)) for region, grp in groupby(sorted_devices, key=attrgetter("region"))
    ]

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "version": __version__,
            "devices": devices,
            "device_groups": device_groups,
            "user": user,
            "t": request.state.t,
            "lang": request.state.lang,
            "lg_links": _lg_links,
        },
    )


_HISTORY_PAGE_SIZE = 25


@app.get("/history", response_class=HTMLResponse)
async def history(
    request: Request,
    offset: int = 0,
    partial: int = 0,
    user: User | None = Depends(optional_auth),  # noqa: B008
) -> Response:
    """Query history page with offset-based pagination."""
    if user is None:
        if settings.access_mode == "closed":
            return RedirectResponse(url="/auth/login", status_code=303)
        if settings.access_mode == "guest":
            user = guest_user()
    user_id = user.id if user and user.id != 0 else None
    try:
        results = await list_results(
            get_pool(),
            user_id=user_id,
            limit=_HISTORY_PAGE_SIZE + 1,
            offset=max(offset, 0),
        )
    except RuntimeError:
        results = []

    has_more = len(results) > _HISTORY_PAGE_SIZE
    if has_more:
        results = results[:_HISTORY_PAGE_SIZE]

    next_offset = max(offset, 0) + _HISTORY_PAGE_SIZE
    ctx = {
        "results": results,
        "has_more": has_more,
        "next_offset": next_offset,
        "user": user,
        "t": request.state.t,
        "lang": request.state.lang,
    }

    if partial:
        return templates.TemplateResponse(
            request=request,
            name="partials/history_rows.html",
            context=ctx,
        )
    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context=ctx,
    )


def run() -> None:
    """Console entry point: start uvicorn."""
    import uvicorn

    uvicorn.run(
        "bgpeek.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_config=None,
    )


if __name__ == "__main__":
    run()
