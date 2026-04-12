"""CRUD queries for the `users` table."""

from __future__ import annotations

import hashlib

import asyncpg

from bgpeek.models.user import User, UserCreate, UserUpdate


def _hash_key(api_key: str) -> str:
    """SHA-256 hash of a raw API key for safe storage and lookup."""
    return hashlib.sha256(api_key.encode()).hexdigest()


async def create_user(pool: asyncpg.Pool, payload: UserCreate) -> User:
    """Insert a new API-key user. Raises `asyncpg.UniqueViolationError` on duplicate username."""
    row = await pool.fetchrow(
        """
        INSERT INTO users (username, email, role, auth_provider, api_key_hash, enabled)
        VALUES ($1, $2, $3, 'api_key', $4, $5)
        RETURNING *
        """,
        payload.username,
        payload.email,
        payload.role.value,
        _hash_key(payload.api_key),
        payload.enabled,
    )
    assert row is not None
    return User.model_validate(dict(row))


async def get_user_by_id(pool: asyncpg.Pool, user_id: int) -> User | None:
    """Fetch a single user by primary key, or None."""
    row = await pool.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
    return User.model_validate(dict(row)) if row else None


async def get_user_by_api_key(pool: asyncpg.Pool, api_key: str) -> User | None:
    """Fetch a user by raw API key (hashed before lookup), or None."""
    row = await pool.fetchrow(
        "SELECT * FROM users WHERE api_key_hash = $1 AND enabled IS TRUE",
        _hash_key(api_key),
    )
    return User.model_validate(dict(row)) if row else None


async def list_users(pool: asyncpg.Pool) -> list[User]:
    """Return all users ordered by username."""
    rows = await pool.fetch("SELECT * FROM users ORDER BY username ASC")
    return [User.model_validate(dict(r)) for r in rows]


_UPDATABLE_COLUMNS: frozenset[str] = frozenset({"username", "email", "role", "enabled"})


async def update_user(pool: asyncpg.Pool, user_id: int, payload: UserUpdate) -> User | None:
    """Apply a partial update; returns the updated row or None if not found."""
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        return await get_user_by_id(pool, user_id)

    set_clause_parts: list[str] = []
    values: list[object] = []
    for idx, (column, value) in enumerate(fields.items(), start=1):
        if column not in _UPDATABLE_COLUMNS:
            raise ValueError(f"refusing to update unknown column: {column!r}")
        set_clause_parts.append(f"{column} = ${idx}")
        values.append(value)
    set_clause = ", ".join(set_clause_parts)
    values.append(user_id)

    query = f"UPDATE users SET {set_clause} WHERE id = ${len(values)} RETURNING *"  # noqa: S608
    row = await pool.fetchrow(query, *values)
    return User.model_validate(dict(row)) if row else None


async def delete_user(pool: asyncpg.Pool, user_id: int) -> bool:
    """Delete a user. Returns True if a row was removed."""
    result: str = await pool.execute("DELETE FROM users WHERE id = $1", user_id)
    return result.endswith(" 1")
