"""CRUD queries for the `devices` table."""

from __future__ import annotations

import asyncpg

from bgpeek.models.device import Device, DeviceCreate, DeviceUpdate


async def list_devices(
    pool: asyncpg.Pool,
    *,
    enabled_only: bool = False,
    include_restricted: bool = True,
) -> list[Device]:
    """Return all devices, optionally filtering on `enabled` and `restricted`."""
    query = "SELECT * FROM devices"
    conditions: list[str] = []
    if enabled_only:
        conditions.append("enabled IS TRUE")
    if not include_restricted:
        conditions.append("NOT restricted")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY name ASC"
    rows = await pool.fetch(query)
    return [Device.model_validate(dict(r)) for r in rows]


async def get_device_by_id(pool: asyncpg.Pool, device_id: int) -> Device | None:
    """Fetch a single device by primary key, or None."""
    row = await pool.fetchrow("SELECT * FROM devices WHERE id = $1", device_id)
    return Device.model_validate(dict(row)) if row else None


async def get_device_by_name(pool: asyncpg.Pool, name: str) -> Device | None:
    """Fetch a single device by unique name, or None."""
    row = await pool.fetchrow("SELECT * FROM devices WHERE name = $1", name)
    return Device.model_validate(dict(row)) if row else None


async def create_device(pool: asyncpg.Pool, payload: DeviceCreate) -> Device:
    """Insert a new device. Raises `asyncpg.UniqueViolationError` on duplicate name."""
    row = await pool.fetchrow(
        """
        INSERT INTO devices (name, address, port, platform, description, location, region, enabled, restricted, credential_id, source4, source6)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING *
        """,
        payload.name,
        payload.address,
        payload.port,
        payload.platform,
        payload.description,
        payload.location,
        payload.region,
        payload.enabled,
        payload.restricted,
        payload.credential_id,
        payload.source4,
        payload.source6,
    )
    assert row is not None
    return Device.model_validate(dict(row))


# Whitelist of columns the API may update. Pydantic enforces this on the
# DeviceUpdate model, but we double-check here so the dynamic SQL builder
# below can never see an attacker-controlled column name.
_UPDATABLE_COLUMNS: frozenset[str] = frozenset(
    {"name", "address", "port", "platform", "description", "location", "region", "enabled", "restricted", "credential_id", "source4", "source6"}
)


async def update_device(pool: asyncpg.Pool, device_id: int, payload: DeviceUpdate) -> Device | None:
    """Apply a partial update; returns the updated row or None if not found."""
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        return await get_device_by_id(pool, device_id)

    set_clause_parts: list[str] = []
    values: list[object] = []
    for idx, (column, value) in enumerate(fields.items(), start=1):
        if column not in _UPDATABLE_COLUMNS:
            raise ValueError(f"refusing to update unknown column: {column!r}")
        set_clause_parts.append(f"{column} = ${idx}")
        values.append(value)
    set_clause_parts.append("updated_at = now()")
    set_clause = ", ".join(set_clause_parts)
    values.append(device_id)

    query = f"UPDATE devices SET {set_clause} WHERE id = ${len(values)} RETURNING *"  # noqa: S608
    row = await pool.fetchrow(query, *values)
    return Device.model_validate(dict(row)) if row else None


async def delete_device(pool: asyncpg.Pool, device_id: int) -> bool:
    """Delete a device. Returns True if a row was removed."""
    result: str = await pool.execute("DELETE FROM devices WHERE id = $1", device_id)
    return result.endswith(" 1")
