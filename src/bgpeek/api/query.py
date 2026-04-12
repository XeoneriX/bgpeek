"""HTTP handlers for /api/query and /query (HTMX partial)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from bgpeek.config import settings
from bgpeek.core.auth import authenticate, optional_auth
from bgpeek.core.query import QueryExecutionError, execute_query
from bgpeek.core.validators import TargetValidationError
from bgpeek.models.query import QueryError, QueryRequest, QueryResponse, QueryType
from bgpeek.models.user import User

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
        return await execute_query(
            body,
            source_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            user_id=caller.id,
            username=caller.username,
            user_role=caller.role.value,
        )
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
