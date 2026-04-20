"""CRUD queries for the `audit_log` table."""

from __future__ import annotations

from datetime import datetime

import asyncpg
import structlog

from bgpeek.config import settings
from bgpeek.models.audit import AuditAction, AuditEntry, AuditEntryCreate

# Dedicated logger name so downstream shippers can filter by `logger:audit`
# (or the equivalent) without regex-matching event names.
_audit_log = structlog.get_logger("audit")


async def log_audit(pool: asyncpg.Pool, entry: AuditEntryCreate) -> AuditEntry:
    """Insert an audit log entry and return the persisted row. Propagates DB errors."""
    row = await pool.fetchrow(
        """
        INSERT INTO audit_log (
            user_id, username, user_role, source_ip, user_agent,
            action, device_id, device_name, query_type, query_target,
            success, error_message, runtime_ms, response_bytes
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING *
        """,
        entry.user_id,
        entry.username,
        entry.user_role,
        entry.source_ip,
        entry.user_agent,
        entry.action.value,
        entry.device_id,
        entry.device_name,
        entry.query_type,
        entry.query_target,
        entry.success,
        entry.error_message,
        entry.runtime_ms,
        entry.response_bytes,
    )
    assert row is not None
    persisted = AuditEntry.model_validate(dict(row))

    if settings.audit_stdout:
        # Mirror the audit row to the standard log stream so external shippers
        # (Loki, VictoriaLogs, …) can index audit events alongside app logs.
        # The PG row remains the source of truth for compliance.
        _audit_log.info(
            "audit",
            action=entry.action.value,
            success=entry.success,
            username=entry.username,
            user_role=entry.user_role,
            source_ip=str(entry.source_ip) if entry.source_ip is not None else None,
            device=entry.device_name,
            query_type=entry.query_type,
            target=entry.query_target,
            runtime_ms=entry.runtime_ms,
        )

    return persisted


def _build_filter(
    *,
    action: AuditAction | None,
    user_id: int | None,
    device_id: int | None,
    success: bool | None,
) -> tuple[str, list[object]]:
    """Build a parameterised WHERE clause from optional filters."""
    fragments: list[str] = []
    values: list[object] = []
    if action is not None:
        values.append(action.value)
        fragments.append(f"action = ${len(values)}")
    if user_id is not None:
        values.append(user_id)
        fragments.append(f"user_id = ${len(values)}")
    if device_id is not None:
        values.append(device_id)
        fragments.append(f"device_id = ${len(values)}")
    if success is not None:
        values.append(success)
        fragments.append(f"success = ${len(values)}")
    where = f" WHERE {' AND '.join(fragments)}" if fragments else ""
    return where, values


async def list_audit_entries(
    pool: asyncpg.Pool,
    *,
    limit: int = 100,
    offset: int = 0,
    action: AuditAction | None = None,
    user_id: int | None = None,
    device_id: int | None = None,
    success: bool | None = None,
) -> list[AuditEntry]:
    """List audit entries newest-first with optional filters."""
    where, values = _build_filter(
        action=action, user_id=user_id, device_id=device_id, success=success
    )
    values.append(limit)
    limit_idx = len(values)
    values.append(offset)
    offset_idx = len(values)
    query = (
        f"SELECT * FROM audit_log{where} "  # noqa: S608
        f"ORDER BY timestamp DESC, id DESC "
        f"LIMIT ${limit_idx} OFFSET ${offset_idx}"
    )
    rows = await pool.fetch(query, *values)
    return [AuditEntry.model_validate(dict(r)) for r in rows]


async def count_audit_entries(
    pool: asyncpg.Pool,
    *,
    action: AuditAction | None = None,
    user_id: int | None = None,
    device_id: int | None = None,
    success: bool | None = None,
) -> int:
    """Count rows matching the same filter set as `list_audit_entries`."""
    where, values = _build_filter(
        action=action, user_id=user_id, device_id=device_id, success=success
    )
    query = f"SELECT COUNT(*) FROM audit_log{where}"  # noqa: S608
    result = await pool.fetchval(query, *values)
    return int(result)


async def device_query_stats(
    pool: asyncpg.Pool,
    *,
    since_days: int = 7,
) -> dict[int, tuple[datetime, int]]:
    """Return ``{device_id: (last_query_at, count)}`` over the last ``since_days``.

    Counts only successful ``query`` actions. Devices with no queries in the
    window are absent from the returned dict.
    """
    rows = await pool.fetch(
        """
        SELECT device_id, MAX(timestamp) AS last_query, COUNT(*) AS query_count
        FROM audit_log
        WHERE device_id IS NOT NULL
          AND action = 'query'
          AND timestamp > now() - make_interval(days => $1)
        GROUP BY device_id
        """,
        since_days,
    )
    return {int(r["device_id"]): (r["last_query"], int(r["query_count"])) for r in rows}


async def devices_with_success_history(pool: asyncpg.Pool) -> set[int]:
    """Return device_ids that have at least one successful query or probe on record.

    Used by the admin devices list to distinguish devices that have never been
    talked to successfully (show as "Unknown") from devices that have been
    reached at least once (eligible for "Healthy"). A never-queried device
    cannot honestly be rendered as Healthy.
    """
    rows = await pool.fetch(
        """
        SELECT DISTINCT device_id
        FROM audit_log
        WHERE device_id IS NOT NULL
          AND success IS TRUE
          AND action IN ('query', 'probe')
        """
    )
    return {int(r["device_id"]) for r in rows}


async def cleanup_old_entries(pool: asyncpg.Pool, ttl_days: int) -> int:
    """Delete audit entries older than ``ttl_days``. Returns deleted row count."""
    result: str = await pool.execute(
        "DELETE FROM audit_log WHERE timestamp < now() - make_interval(days => $1)",
        ttl_days,
    )
    return int(result.split()[-1])
