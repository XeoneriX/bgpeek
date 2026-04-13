"""High-level query orchestrator: validate → look up device → SSH → filter → audit."""

from __future__ import annotations

import time
from pathlib import Path

import structlog

from bgpeek.config import settings
from bgpeek.core.bgp_parser import parse_bgp_output
from bgpeek.core.circuit_breaker import is_device_available, record_failure, record_success
from bgpeek.core.cache import get_cached, set_cached
from bgpeek.core.commands import UnsupportedPlatformError, build_command
from bgpeek.core.dns import DNSResolutionError, resolve_target
from bgpeek.core.output_filter import filter_route_text
from bgpeek.core.rpki import validate_routes
from bgpeek.core.ssh import SSHClient, SSHError
from bgpeek.core.validators import TargetValidationError, validate_target
from bgpeek.db import devices as device_crud
from bgpeek.db.audit import log_audit
from bgpeek.db.pool import get_pool
from bgpeek.models.audit import AuditAction, AuditEntryCreate
from bgpeek.models.query import BGPRoute, QueryRequest, QueryResponse, QueryType
from bgpeek.models.user import UserRole
from bgpeek.models.webhook import WebhookEvent

log = structlog.get_logger(__name__)

_PRIVILEGED_ROLES: frozenset[UserRole] = frozenset({UserRole.ADMIN, UserRole.NOC})


def _role_bypasses_filter(user_role: str | None) -> bool:
    """Return True if the role should see unfiltered output."""
    if user_role is None:
        return False
    try:
        role = UserRole(user_role)
    except ValueError:
        return False
    return role in _PRIVILEGED_ROLES


class QueryExecutionError(Exception):
    """Raised when a query fails at any stage after validation."""

    def __init__(self, detail: str, *, target: str, device_name: str) -> None:
        self.detail = detail
        self.target = target
        self.device_name = device_name
        super().__init__(detail)


async def execute_query(
    request: QueryRequest,
    *,
    source_ip: str | None = None,
    user_agent: str | None = None,
    user_id: int | None = None,
    username: str | None = None,
    user_role: str | None = None,
    ssh_key_path: Path | None = None,
    ssh_password: str | None = None,
) -> QueryResponse:
    """Run a looking glass query end-to-end.

    Steps:
      1. Validate target (bogons, prefix length)
      2. Look up device from database
      3. Build platform-specific command
      4. Execute via SSH
      5. Filter output (strip more-specific routes for BGP queries)
      6. Write audit log
      7. Return response
    """
    pool = get_pool()
    start = time.monotonic()
    audit_entry = AuditEntryCreate(
        action=AuditAction.QUERY,
        success=False,
        user_id=user_id,
        username=username,
        user_role=user_role,
        source_ip=source_ip,  # type: ignore[arg-type]
        user_agent=user_agent,
        query_type=request.query_type.value,
        query_target=request.target,
        device_name=request.device_name,
    )

    resolved_target: str | None = None
    try:
        # 0. Resolve hostname to IP if needed (ping/trace/bgp all benefit)
        resolution = await resolve_target(request.target)
        effective_target = resolution.resolved
        if resolution.is_hostname:
            resolved_target = resolution.resolved
            audit_entry.query_target = f"{resolution.original} ({resolution.resolved})"

        # 1. Validate target (only for BGP — ping/trace accept any reachable target)
        if request.query_type == QueryType.BGP_ROUTE:
            validate_target(effective_target)

        # 1b. Check cache
        cached = await get_cached(request)
        if cached is not None:
            runtime_ms = int((time.monotonic() - start) * 1000)
            cached.cached = True
            cached.runtime_ms = runtime_ms
            audit_entry.success = True
            audit_entry.runtime_ms = runtime_ms
            audit_entry.response_bytes = len(cached.filtered_output.encode())
            await log_audit(pool, audit_entry)
            log.info("cache_hit", device=request.device_name, target=request.target)
            return cached

        # 2. Look up device
        device = await device_crud.get_device_by_name(pool, request.device_name)
        if device is None:
            raise QueryExecutionError(
                f"device {request.device_name!r} not found",
                target=request.target,
                device_name=request.device_name,
            )
        if not device.enabled:
            raise QueryExecutionError(
                f"device {request.device_name!r} is disabled",
                target=request.target,
                device_name=request.device_name,
            )
        audit_entry.device_id = device.id

        # 2b. Circuit breaker check
        if not await is_device_available(device.name):
            raise QueryExecutionError(
                f"device {device.name!r} is temporarily unavailable (circuit breaker open)",
                target=request.target,
                device_name=request.device_name,
            )

        # 3. Build command (use resolved IP for the actual SSH command)
        command = build_command(device.platform, request.query_type, effective_target)

        # 4. Execute SSH
        cmd_timeout = (
            settings.ssh_timeout_traceroute
            if request.query_type == QueryType.TRACEROUTE
            else None
        )
        async with SSHClient(
            host=str(device.address),
            username=settings.ssh_username,
            platform=device.platform,
            port=device.port,
            key_path=ssh_key_path,
            password=ssh_password,
            timeout=settings.ssh_timeout,
        ) as ssh:
            raw_output = await ssh.send_command(command, timeout=cmd_timeout)

        await record_success(device.name)

        # 5. Filter output (privileged roles bypass prefix filtering)
        if request.query_type == QueryType.BGP_ROUTE and not _role_bypasses_filter(user_role):
            filtered_output = filter_route_text(raw_output)
        else:
            filtered_output = raw_output

        runtime_ms = int((time.monotonic() - start) * 1000)

        # 6. Audit (success)
        audit_entry.success = True
        audit_entry.runtime_ms = runtime_ms
        audit_entry.response_bytes = len(filtered_output.encode())
        await log_audit(pool, audit_entry)

        # 7. Parse structured BGP routes (best-effort)
        parsed_routes: list[BGPRoute] = []
        if request.query_type == QueryType.BGP_ROUTE:
            parsed_routes = parse_bgp_output(filtered_output, platform=device.platform)
            if parsed_routes:
                parsed_routes = await validate_routes(parsed_routes)

        # 8. Response
        response = QueryResponse(
            device_name=device.name,
            query_type=request.query_type,
            target=request.target,
            command=command,
            raw_output=raw_output,
            filtered_output=filtered_output,
            runtime_ms=runtime_ms,
            parsed_routes=parsed_routes,
            resolved_target=resolved_target,
        )

        # 9. Store in cache
        await set_cached(request, response)

        # 10. Dispatch webhook (fire-and-forget)
        from bgpeek.core.webhooks import dispatch_webhook

        await dispatch_webhook(
            WebhookEvent.QUERY,
            {
                "device_name": device.name,
                "query_type": request.query_type.value,
                "target": request.target,
                "runtime_ms": runtime_ms,
                "username": username,
            },
        )

        return response

    except TargetValidationError as exc:
        runtime_ms = int((time.monotonic() - start) * 1000)
        audit_entry.error_message = exc.reason
        audit_entry.runtime_ms = runtime_ms
        await log_audit(pool, audit_entry)
        raise

    except DNSResolutionError as exc:
        runtime_ms = int((time.monotonic() - start) * 1000)
        audit_entry.error_message = str(exc)
        audit_entry.runtime_ms = runtime_ms
        await log_audit(pool, audit_entry)
        raise QueryExecutionError(
            detail=str(exc),
            target=request.target,
            device_name=request.device_name,
        ) from exc

    except (UnsupportedPlatformError, SSHError, QueryExecutionError) as exc:
        if isinstance(exc, SSHError):
            await record_failure(request.device_name)
        runtime_ms = int((time.monotonic() - start) * 1000)
        audit_entry.error_message = str(exc)
        audit_entry.runtime_ms = runtime_ms
        await log_audit(pool, audit_entry)
        raise QueryExecutionError(
            detail=str(exc),
            target=request.target,
            device_name=request.device_name,
        ) from exc
