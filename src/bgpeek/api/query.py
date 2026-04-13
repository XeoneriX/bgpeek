"""HTTP handlers for /api/query, /query (HTMX partial), and result permalinks."""

from __future__ import annotations

import uuid
from pathlib import Path

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from bgpeek.config import settings
from bgpeek.core.auth import authenticate, optional_auth
from bgpeek.core.parallel import execute_parallel
from bgpeek.core.query import QueryExecutionError, execute_query
from bgpeek.core.rate_limit import rate_limit_query
from bgpeek.core.response_filter import filter_response
from bgpeek.core.validators import TargetValidationError
from bgpeek.db.pool import get_pool
from bgpeek.db.results import get_result, list_results, save_result
from bgpeek.models.query import (
    MultiQueryRequest,
    MultiQueryResponse,
    QueryError,
    QueryRequest,
    QueryResponse,
    QueryType,
    StoredResult,
)
from bgpeek.models.user import User

log = structlog.get_logger(__name__)

router = APIRouter(tags=["query"])
templates = Jinja2Templates(directory=str(settings.templates_dir))


def _ssh_key_path() -> Path | None:
    """Return the SSH private key path if it exists in config_dir."""
    key = settings.config_dir / "id_rsa"
    return key if key.is_file() else None


@router.post("/api/query", response_model=QueryResponse)
async def api_query(
    request: Request,
    body: QueryRequest,
    caller: User = Depends(authenticate),  # noqa: B008
    _rl: None = Depends(rate_limit_query),  # noqa: B008
) -> QueryResponse:
    """Execute a looking glass query (JSON API)."""
    try:
        result = await execute_query(
            body,
            source_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            user_id=caller.id,
            username=caller.username,
            user_role=caller.role.value,
            ssh_key_path=_ssh_key_path(),
        )
        result_id = await _persist_result(result, caller.id, caller.username)
        result.result_id = str(result_id)
        return filter_response(result, caller.role.value)
    except TargetValidationError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=QueryError(detail=exc.reason, target=exc.target).model_dump(),
        ) from exc
    except QueryExecutionError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail=QueryError(
                detail=exc.detail, target=exc.target, device_name=exc.device_name
            ).model_dump(),
        ) from exc


@router.post("/query", response_class=HTMLResponse)
async def htmx_query(
    request: Request,
    caller: User | None = Depends(optional_auth),  # noqa: B008
    _rl: None = Depends(rate_limit_query),  # noqa: B008
) -> HTMLResponse:
    """Execute a query and return an HTMX partial (server-rendered HTML fragment)."""
    form = await request.form()
    try:
        body = QueryRequest(
            device_name=str(form.get("location", "")),
            query_type=QueryType(str(form.get("query_type", "bgp_route"))),
            target=str(form.get("target", "")),
        )
    except (ValueError, KeyError):
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={
                "error": "Invalid query parameters.",
                "t": request.state.t,
                "lang": request.state.lang,
            },
        )

    try:
        result = await execute_query(
            body,
            source_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            user_id=caller.id if caller else None,
            username=caller.username if caller else None,
            user_role=caller.role.value if caller else None,
            ssh_key_path=_ssh_key_path(),
        )
        result_id = await _persist_result(
            result,
            caller.id if caller else None,
            caller.username if caller else None,
        )
        result.result_id = str(result_id)
        filtered = filter_response(result, caller.role.value if caller else None)
        return templates.TemplateResponse(
            request=request,
            name="partials/result.html",
            context={
                "result": filtered,
                "t": request.state.t,
                "lang": request.state.lang,
            },
        )
    except TargetValidationError as exc:
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={
                "error": exc.reason,
                "t": request.state.t,
                "lang": request.state.lang,
            },
        )
    except QueryExecutionError as exc:
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={
                "error": exc.detail,
                "t": request.state.t,
                "lang": request.state.lang,
            },
        )


# ---------------------------------------------------------------------------
# Multi-device parallel query endpoints
# ---------------------------------------------------------------------------


@router.post("/api/query/multi", response_model=MultiQueryResponse)
async def api_multi_query(
    request: Request,
    body: MultiQueryRequest,
    caller: User = Depends(authenticate),  # noqa: B008
    _rl: None = Depends(rate_limit_query),  # noqa: B008
) -> MultiQueryResponse:
    """Execute a query against multiple devices in parallel (JSON API)."""
    response = await execute_parallel(
        body,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        user_id=caller.id,
        username=caller.username,
        user_role=caller.role.value,
        ssh_key_path=_ssh_key_path(),
    )
    for result in response.results:
        result_id = await _persist_result(result, caller.id, caller.username)
        result.result_id = str(result_id)
    response.results = [filter_response(r, caller.role.value) for r in response.results]
    return response


@router.post("/query/multi", response_class=HTMLResponse)
async def htmx_multi_query(
    request: Request,
    caller: User | None = Depends(optional_auth),  # noqa: B008
    _rl: None = Depends(rate_limit_query),  # noqa: B008
) -> HTMLResponse:
    """Execute a parallel query and return an HTMX partial with all results."""
    form = await request.form()
    raw_names = form.getlist("device_names") or form.getlist("location")
    device_names = [str(n) for n in raw_names if str(n).strip()]
    if not device_names:
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={
                "error": "At least one device must be selected.",
                "t": request.state.t,
                "lang": request.state.lang,
            },
        )

    try:
        body = MultiQueryRequest(
            device_names=device_names,
            query_type=QueryType(str(form.get("query_type", "bgp_route"))),
            target=str(form.get("target", "")),
        )
    except (ValueError, KeyError):
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={
                "error": "Invalid query parameters.",
                "t": request.state.t,
                "lang": request.state.lang,
            },
        )

    response = await execute_parallel(
        body,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        user_id=caller.id if caller else None,
        username=caller.username if caller else None,
        user_role=caller.role.value if caller else None,
        ssh_key_path=_ssh_key_path(),
    )
    for result in response.results:
        result_id = await _persist_result(
            result,
            caller.id if caller else None,
            caller.username if caller else None,
        )
        result.result_id = str(result_id)

    role = caller.role.value if caller else None
    response.results = [filter_response(r, role) for r in response.results]

    return templates.TemplateResponse(
        request=request,
        name="partials/multi_result.html",
        context={
            "response": response,
            "t": request.state.t,
            "lang": request.state.lang,
        },
    )


# ---------------------------------------------------------------------------
# Permalink endpoints
# ---------------------------------------------------------------------------


@router.get("/api/results/{result_id}", response_model=StoredResult)
async def api_get_result(result_id: uuid.UUID) -> StoredResult:
    """Return a stored query result as JSON."""
    stored = await get_result(get_pool(), result_id)
    if stored is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Result not found or expired.")
    return stored


@router.get("/result/{result_id}", response_class=HTMLResponse)
async def result_page(request: Request, result_id: uuid.UUID) -> HTMLResponse:
    """Render a standalone HTML page for a shared result."""
    stored = await get_result(get_pool(), result_id)
    return templates.TemplateResponse(
        request=request,
        name="result_page.html",
        context={
            "stored": stored,
            "result_id": result_id,
            "t": request.state.t,
            "lang": request.state.lang,
        },
    )


@router.get("/api/results", response_model=list[StoredResult])
async def api_list_results(
    caller: User = Depends(authenticate),  # noqa: B008
) -> list[StoredResult]:
    """List recent results for the authenticated user."""
    return await list_results(get_pool(), user_id=caller.id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _persist_result(
    response: QueryResponse,
    user_id: int | None,
    username: str | None,
) -> uuid.UUID:
    """Save a query result to the database and return its UUID."""
    try:
        return await save_result(
            get_pool(),
            response,
            user_id=user_id,
            username=username,
            ttl_days=settings.result_ttl_days,
        )
    except Exception:
        log.warning("failed to persist query result", exc_info=True)
        return uuid.UUID(int=0)
