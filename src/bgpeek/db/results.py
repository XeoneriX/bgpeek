"""CRUD queries for the `query_results` table."""

from __future__ import annotations

import json
import uuid

import asyncpg

from bgpeek.models.query import QueryResponse, StoredResult


async def save_result(
    pool: asyncpg.Pool,
    response: QueryResponse,
    *,
    user_id: int | None,
    username: str | None,
    ttl_days: int,
) -> uuid.UUID:
    """Insert a query result and return the generated UUID."""
    parsed_json = json.dumps([r.model_dump() for r in response.parsed_routes])
    row = await pool.fetchrow(
        """
        INSERT INTO query_results (
            user_id, username, device_name, query_type, target,
            command, raw_output, filtered_output, parsed_routes,
            runtime_ms, cached, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11,
                now() + make_interval(days => $12))
        RETURNING id
        """,
        user_id,
        username,
        response.device_name,
        response.query_type.value,
        response.target,
        response.command,
        response.raw_output,
        response.filtered_output,
        parsed_json,
        response.runtime_ms,
        response.cached,
        ttl_days,
    )
    assert row is not None
    result_id: uuid.UUID = row["id"]
    return result_id


async def get_result(pool: asyncpg.Pool, result_id: uuid.UUID) -> StoredResult | None:
    """Fetch a result by UUID. Returns None if missing or expired."""
    row = await pool.fetchrow(
        """
        SELECT * FROM query_results
        WHERE id = $1 AND expires_at > now()
        """,
        result_id,
    )
    if row is None:
        return None
    return _row_to_model(row)


async def list_results(
    pool: asyncpg.Pool,
    *,
    user_id: int | None = None,
    limit: int = 50,
) -> list[StoredResult]:
    """List recent non-expired results, optionally filtered by user."""
    if user_id is not None:
        rows = await pool.fetch(
            """
            SELECT * FROM query_results
            WHERE user_id = $1 AND expires_at > now()
            ORDER BY created_at DESC
            LIMIT $2
            """,
            user_id,
            limit,
        )
    else:
        rows = await pool.fetch(
            """
            SELECT * FROM query_results
            WHERE expires_at > now()
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    return [_row_to_model(r) for r in rows]


async def cleanup_expired(pool: asyncpg.Pool) -> int:
    """Delete expired results. Returns the number of rows removed."""
    result: str = await pool.execute("DELETE FROM query_results WHERE expires_at < now()")
    # asyncpg returns e.g. "DELETE 5"
    return int(result.split()[-1])


def _row_to_model(row: asyncpg.Record) -> StoredResult:
    """Convert an asyncpg Record to a StoredResult, handling JSONB parsing."""
    data = dict(row)
    # asyncpg returns JSONB as a string; parse if needed
    raw_routes = data.get("parsed_routes")
    if isinstance(raw_routes, str):
        data["parsed_routes"] = json.loads(raw_routes)
    return StoredResult.model_validate(data)
