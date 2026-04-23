"""CRUD tests for bgpeek.db.users against a real PostgreSQL container."""

from __future__ import annotations

import asyncpg
import pytest

from bgpeek.db import users as crud
from bgpeek.models.user import UserCreate, UserCreateLocal, UserRole, UserUpdate


def _payload(name: str = "alice", **overrides: object) -> UserCreate:
    base: dict[str, object] = {
        "username": name,
        "email": f"{name}@example.com",
        "role": UserRole.NOC,
        "api_key": "a" * 40,
        "enabled": True,
    }
    base.update(overrides)
    return UserCreate(**base)  # type: ignore[arg-type]


async def test_list_users_empty(pool: asyncpg.Pool) -> None:
    assert await crud.list_users(pool) == []


async def test_create_and_get_by_id(pool: asyncpg.Pool) -> None:
    created, _key = await crud.create_user(pool, _payload())
    assert created.id > 0
    assert created.username == "alice"
    assert created.role == UserRole.NOC
    assert created.auth_provider == "api_key"
    assert created.api_key_hash is not None

    fetched = await crud.get_user_by_id(pool, created.id)
    assert fetched is not None
    assert fetched.id == created.id


async def test_create_generates_api_key_when_none(pool: asyncpg.Pool) -> None:
    """Omitted api_key → server generates a strong URL-safe token, returned once."""
    _created, plaintext = await crud.create_user(pool, _payload("autogen", api_key=None))
    assert isinstance(plaintext, str)
    assert len(plaintext) >= 32
    # The generated key authenticates.
    fetched = await crud.get_user_by_api_key(pool, plaintext)
    assert fetched is not None
    assert fetched.username == "autogen"


async def test_get_by_api_key(pool: asyncpg.Pool) -> None:
    raw_key = "b" * 40
    await crud.create_user(pool, _payload("bob", api_key=raw_key))
    fetched = await crud.get_user_by_api_key(pool, raw_key)
    assert fetched is not None
    assert fetched.username == "bob"


async def test_get_by_api_key_wrong_key(pool: asyncpg.Pool) -> None:
    await crud.create_user(pool, _payload("charlie", api_key="c" * 40))
    assert await crud.get_user_by_api_key(pool, "wrong" * 10) is None


async def test_get_by_api_key_disabled(pool: asyncpg.Pool) -> None:
    raw_key = "d" * 40
    await crud.create_user(pool, _payload("dave", api_key=raw_key, enabled=False))
    assert await crud.get_user_by_api_key(pool, raw_key) is None


async def test_get_missing_returns_none(pool: asyncpg.Pool) -> None:
    assert await crud.get_user_by_id(pool, 9999) is None


async def test_list_users_orders_by_username(pool: asyncpg.Pool) -> None:
    for name in ("zoe", "alice", "mike"):
        await crud.create_user(pool, _payload(name, api_key=f"{name:<40}"))
    users = await crud.list_users(pool)
    assert [u.username for u in users] == ["alice", "mike", "zoe"]


async def test_create_duplicate_username_raises(pool: asyncpg.Pool) -> None:
    await crud.create_user(pool, _payload("dup", api_key="e" * 40))
    with pytest.raises(asyncpg.UniqueViolationError):
        await crud.create_user(pool, _payload("dup", api_key="f" * 40))


async def test_update_partial(pool: asyncpg.Pool) -> None:
    created, _key = await crud.create_user(pool, _payload())
    updated = await crud.update_user(
        pool, created.id, UserUpdate(email="new@example.com", enabled=False)
    )
    assert updated is not None
    assert updated.email == "new@example.com"
    assert updated.enabled is False
    assert updated.username == created.username


async def test_update_empty_payload_returns_unchanged(pool: asyncpg.Pool) -> None:
    created, _key = await crud.create_user(pool, _payload())
    unchanged = await crud.update_user(pool, created.id, UserUpdate())
    assert unchanged is not None
    assert unchanged.id == created.id
    assert unchanged.email == created.email


async def test_update_missing_returns_none(pool: asyncpg.Pool) -> None:
    assert await crud.update_user(pool, 9999, UserUpdate(enabled=False)) is None


async def test_delete(pool: asyncpg.Pool) -> None:
    created, _key = await crud.create_user(pool, _payload())
    assert await crud.delete_user(pool, created.id) is True
    assert await crud.get_user_by_id(pool, created.id) is None


async def test_delete_missing_returns_false(pool: asyncpg.Pool) -> None:
    assert await crud.delete_user(pool, 9999) is False


# ---------------------------------------------------------------------------
# Local user (password-based) CRUD
# ---------------------------------------------------------------------------


def _local_payload(name: str = "local-alice", **overrides: object) -> UserCreateLocal:
    base: dict[str, object] = {
        "username": name,
        "password": "secure-password-123",
        "email": f"{name}@example.com",
        "role": UserRole.NOC,
    }
    base.update(overrides)
    return UserCreateLocal(**base)  # type: ignore[arg-type]


async def test_create_local_user(pool: asyncpg.Pool) -> None:
    user = await crud.create_local_user(pool, _local_payload())
    assert user.id > 0
    assert user.username == "local-alice"
    assert user.auth_provider == "local"
    assert user.password_hash is not None
    assert user.api_key_hash is None


async def test_get_user_by_credentials_correct_password(pool: asyncpg.Pool) -> None:
    await crud.create_local_user(pool, _local_payload("cred-user"))
    user = await crud.get_user_by_credentials(pool, "cred-user", "secure-password-123")
    assert user is not None
    assert user.username == "cred-user"


async def test_get_user_by_credentials_wrong_password(pool: asyncpg.Pool) -> None:
    await crud.create_local_user(pool, _local_payload("wrong-pw"))
    user = await crud.get_user_by_credentials(pool, "wrong-pw", "bad-password-999")
    assert user is None


async def test_get_user_by_credentials_disabled_user(pool: asyncpg.Pool) -> None:
    created = await crud.create_local_user(pool, _local_payload("disabled-user"))
    await pool.execute("UPDATE users SET enabled = FALSE WHERE id = $1", created.id)
    user = await crud.get_user_by_credentials(pool, "disabled-user", "secure-password-123")
    assert user is None


async def test_get_user_by_credentials_nonexistent(pool: asyncpg.Pool) -> None:
    user = await crud.get_user_by_credentials(pool, "ghost", "password12345678")
    assert user is None


async def test_get_user_by_username(pool: asyncpg.Pool) -> None:
    await crud.create_local_user(pool, _local_payload("lookup-user"))
    user = await crud.get_user_by_username(pool, "lookup-user")
    assert user is not None
    assert user.username == "lookup-user"


async def test_get_user_by_username_missing(pool: asyncpg.Pool) -> None:
    user = await crud.get_user_by_username(pool, "no-such-user")
    assert user is None


async def test_update_user_email_via_update_user(pool: asyncpg.Pool) -> None:
    created = await crud.create_local_user(pool, _local_payload("email-user"))
    updated = await crud.update_user(
        pool,
        created.id,
        UserUpdate(email="new-email@example.com"),
    )
    assert updated is not None
    assert updated.email == "new-email@example.com"


async def test_verify_local_user_password(pool: asyncpg.Pool) -> None:
    created = await crud.create_local_user(pool, _local_payload("verify-pass"))
    assert await crud.verify_local_user_password(pool, created.id, "secure-password-123") is True
    assert await crud.verify_local_user_password(pool, created.id, "wrong-password") is False


async def test_update_local_user_password(pool: asyncpg.Pool) -> None:
    created = await crud.create_local_user(pool, _local_payload("change-pass"))
    assert await crud.verify_local_user_password(pool, created.id, "secure-password-123") is True
    changed = await crud.update_local_user_password(pool, created.id, "new-secure-password-456")
    assert changed is True
    assert await crud.verify_local_user_password(pool, created.id, "secure-password-123") is False
    assert (
        await crud.verify_local_user_password(pool, created.id, "new-secure-password-456") is True
    )
