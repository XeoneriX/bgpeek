"""CRUD queries for the ``community_labels`` table."""

from __future__ import annotations

import asyncpg

from bgpeek.models.community_label import (
    CommunityLabel,
    CommunityLabelCreate,
    CommunityLabelUpdate,
)


async def create_label(pool: asyncpg.Pool, payload: CommunityLabelCreate) -> CommunityLabel:
    row = await pool.fetchrow(
        """
        INSERT INTO community_labels (pattern, match_type, label, color)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        """,
        payload.pattern,
        payload.match_type.value,
        payload.label,
        payload.color,
    )
    assert row is not None
    return CommunityLabel.model_validate(dict(row))


async def get_label(pool: asyncpg.Pool, label_id: int) -> CommunityLabel | None:
    row = await pool.fetchrow("SELECT * FROM community_labels WHERE id = $1", label_id)
    return CommunityLabel.model_validate(dict(row)) if row else None


async def list_labels(pool: asyncpg.Pool) -> list[CommunityLabel]:
    rows = await pool.fetch(
        "SELECT * FROM community_labels ORDER BY match_type DESC, pattern ASC"
    )
    return [CommunityLabel.model_validate(dict(r)) for r in rows]


_UPDATABLE: frozenset[str] = frozenset({"pattern", "match_type", "label", "color"})


async def update_label(
    pool: asyncpg.Pool, label_id: int, payload: CommunityLabelUpdate
) -> CommunityLabel | None:
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        return await get_label(pool, label_id)

    set_parts: list[str] = []
    values: list[object] = []
    for idx, (column, value) in enumerate(fields.items(), start=1):
        if column not in _UPDATABLE:
            raise ValueError(f"refusing to update unknown column: {column!r}")
        if column == "match_type" and value is not None:
            value = value.value if hasattr(value, "value") else value
        set_parts.append(f"{column} = ${idx}")
        values.append(value)
    set_parts.append("updated_at = now()")
    values.append(label_id)

    query = (
        f"UPDATE community_labels SET {', '.join(set_parts)} "  # noqa: S608
        f"WHERE id = ${len(values)} RETURNING *"
    )
    row = await pool.fetchrow(query, *values)
    return CommunityLabel.model_validate(dict(row)) if row else None


async def delete_label(pool: asyncpg.Pool, label_id: int) -> bool:
    result: str = await pool.execute("DELETE FROM community_labels WHERE id = $1", label_id)
    return result.endswith(" 1")
