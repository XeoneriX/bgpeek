"""Parallel query execution across multiple devices."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import structlog

from bgpeek.config import settings
from bgpeek.core.query import QueryExecutionError, execute_query
from bgpeek.core.validators import TargetValidationError
from bgpeek.models.query import (
    MultiQueryRequest,
    MultiQueryResponse,
    QueryError,
    QueryRequest,
    QueryResponse,
)

log = structlog.get_logger(__name__)

# Global semaphore — caps total concurrent SSH sessions across all requests.
_global_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    """Return (and lazily create) the process-wide concurrency semaphore."""
    global _global_semaphore  # noqa: PLW0603
    if _global_semaphore is None:
        _global_semaphore = asyncio.Semaphore(settings.max_parallel_queries)
    return _global_semaphore


async def execute_parallel(
    request: MultiQueryRequest,
    *,
    source_ip: str | None = None,
    user_agent: str | None = None,
    user_id: int | None = None,
    username: str | None = None,
    user_role: str | None = None,
    max_concurrency: int | None = None,
    ssh_key_path: Path | None = None,
    ssh_password: str | None = None,
) -> MultiQueryResponse:
    """Execute the same query against multiple devices concurrently."""
    # Use explicit limit for tests; otherwise fall back to global semaphore.
    if max_concurrency is not None:
        semaphore = asyncio.Semaphore(max_concurrency)
    else:
        semaphore = _get_semaphore()
    start = time.monotonic()

    async def _run_one(device_name: str) -> QueryResponse | QueryError:
        single = QueryRequest(
            device_name=device_name,
            query_type=request.query_type,
            target=request.target,
        )
        async with semaphore:
            try:
                return await execute_query(
                    single,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    user_id=user_id,
                    username=username,
                    user_role=user_role,
                    ssh_key_path=ssh_key_path,
                    ssh_password=ssh_password,
                )
            except (QueryExecutionError, TargetValidationError) as exc:
                detail = exc.detail if isinstance(exc, QueryExecutionError) else exc.reason
                log.warning(
                    "parallel_query_failed",
                    device=device_name,
                    error=detail,
                )
                return QueryError(
                    detail=detail,
                    target=request.target,
                    device_name=device_name,
                )

    tasks = [_run_one(name) for name in request.device_names]
    outcomes = await asyncio.gather(*tasks)

    total_runtime_ms = int((time.monotonic() - start) * 1000)

    results: list[QueryResponse] = []
    errors: list[QueryError] = []
    for outcome in outcomes:
        if isinstance(outcome, QueryResponse):
            results.append(outcome)
        else:
            errors.append(outcome)

    return MultiQueryResponse(
        results=results,
        errors=errors,
        total_runtime_ms=total_runtime_ms,
        device_count=len(request.device_names),
    )
