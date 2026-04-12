"""HTTP handlers for /api/query, /query (HTMX partial), and result permalinks."""

from __future__ import annotations

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from bgpeek.config import settings
from bgpeek.core.auth import authenticate, optional_auth
from bgpeek.core.query import QueryExecutionError, execute_query
from bgpeek.core.validators import TargetValidationError
from bgpeek.db.pool import get_pool
from bgpeek.db.results import get_result, list_results, save_result
from bgpeek.models.query import (
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


@router.post("/api/query", response_model=QueryResponse)
async def api_query(
    request: Request,
    body: QueryRequest,
    caller: User = Depends(authenticate),  # noqa: B008
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
        )
        result_id = await _persist_result(result, caller.id, caller.username)
        result.result_id = str(result_id)
        return result
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
) -> HTMLResponse:
    """Execute a query and return an HTMX partial (server-rendered HTML fragment)."""
    form = await request.form()
    try:
        body = QueryRequest(
            device_name=str(form.get("location", "")),
            query_type=QueryType(str(form.get("query_type", "bgp_route"))),
            target=str(form.get("target", "")),
        )
    except Exception:
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={"error": "Invalid query parameters."},
        )

    try:
        result = await execute_query(
            body,
            source_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            user_id=caller.id if caller else None,
            username=caller.username if caller else None,
            user_role=caller.role.value if caller else None,
        )
        result_id = await _persist_result(
            result,
            caller.id if caller else None,
            caller.username if caller else None,
        )
        result.result_id = str(result_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/result.html",
            context={"result": result},
        )
    except TargetValidationError as exc:
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={"error": exc.reason},
        )
    except QueryExecutionError as exc:
        return templates.TemplateResponse(
            request=request,
            name="partials/error.html",
            context={"error": exc.detail},
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
        context={"stored": stored, "result_id": result_id},
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
        raise
