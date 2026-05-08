"""Pydantic-level tests for user models — focused on the allowed_actions field.

The DB-backed CRUD path is exercised separately in tests/test_db_users.py
(which needs a real PostgreSQL via testcontainers). These tests run pure
Python against the Pydantic models alone.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from bgpeek.models.user import (
    User,
    UserAdmin,
    UserCreate,
    UserRole,
    UserUpdate,
)


class TestUserCreateAllowedActions:
    """Write-side validation on POST /api/users payloads."""

    def test_default_is_none(self) -> None:
        # Legacy (role-based) users send no allowed_actions field — default None
        # preserves the existing behaviour unchanged.
        u = UserCreate(username="alice", role=UserRole.NOC)
        assert u.allowed_actions is None

    def test_explicit_null_is_legacy(self) -> None:
        u = UserCreate(username="alice", role=UserRole.NOC, allowed_actions=None)
        assert u.allowed_actions is None

    def test_well_formed_list_passes(self) -> None:
        u = UserCreate(
            username="noc-svc",
            role=UserRole.ADMIN,
            allowed_actions=["users:create", "users:read"],
        )
        assert u.allowed_actions == ["users:create", "users:read"]

    def test_empty_list_is_accepted(self) -> None:
        # Operationally meaningless (locks the user out of every endpoint) but
        # not a format error. Operators sometimes use this as a soft-delete.
        u = UserCreate(username="parked", role=UserRole.ADMIN, allowed_actions=[])
        assert u.allowed_actions == []

    def test_full_wildcard_passes(self) -> None:
        u = UserCreate(username="root", role=UserRole.ADMIN, allowed_actions=["*"])
        assert u.allowed_actions == ["*"]

    def test_namespace_wildcards_pass(self) -> None:
        u = UserCreate(
            username="user-mgr",
            role=UserRole.ADMIN,
            allowed_actions=["users:*", "query:history:*"],
        )
        assert u.allowed_actions == ["users:*", "query:history:*"]

    @pytest.mark.parametrize(
        "bad",
        [
            ["users"],  # bare resource
            ["users:"],
            [":create"],
            ["Users:Create"],  # uppercase
            ["users:create OR 1=1"],
            ["*:create"],  # cross-resource wildcard rejected at format layer
            ["users:create", "devices"],  # mixed valid + bare resource
            ["users-admin:create"],  # hyphen not in alphabet
        ],
    )
    def test_malformed_scopes_rejected(self, bad: list[str]) -> None:
        with pytest.raises(ValidationError, match="invalid scope format"):
            UserCreate(username="x", role=UserRole.NOC, allowed_actions=bad)

    def test_non_list_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UserCreate(
                username="x",
                role=UserRole.NOC,
                allowed_actions="users:create",  # type: ignore[arg-type]
            )

    def test_non_string_element_rejected(self) -> None:
        # Pydantic's own list[str] type check catches this before our
        # field_validator runs — either error path is acceptable, both reject.
        with pytest.raises(ValidationError, match="(should be a valid string|must be a string)"):
            UserCreate(
                username="x",
                role=UserRole.NOC,
                allowed_actions=[123],  # type: ignore[list-item]
            )

    def test_unknown_action_warns_but_passes(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Forward-compat: well-formed but not in Action enum. Allowed for forward
        # compatibility with future endpoints, but stdout warns the operator
        # since "users:creat" is more likely a typo than a future-dated scope.
        u = UserCreate(
            username="x",
            role=UserRole.NOC,
            allowed_actions=["users:creat"],
        )
        assert u.allowed_actions == ["users:creat"]
        captured = capsys.readouterr()
        assert "scope_not_in_action_registry" in captured.out
        assert "users:creat" in captured.out


class TestUserUpdateAllowedActions:
    """Write-side validation on PATCH /api/users/{id} payloads."""

    def test_unset_field_excluded_from_dump(self) -> None:
        # PATCH `{}` should leave allowed_actions untouched on the row — i.e.
        # exclude_unset must filter it out so it never reaches the SET clause.
        payload = UserUpdate()
        assert "allowed_actions" not in payload.model_dump(exclude_unset=True)
        assert "allowed_actions" not in payload.model_fields_set

    def test_explicit_null_distinguishable_from_unset(self) -> None:
        # PATCH `{"allowed_actions": null}` — operator wants to revert a scoped
        # user to legacy mode. Must be visible in `model_fields_set` so the
        # update path can tell "set to null" apart from "don't touch".
        payload = UserUpdate(allowed_actions=None)
        assert "allowed_actions" in payload.model_fields_set
        assert payload.model_dump(exclude_unset=True) == {"allowed_actions": None}

    def test_explicit_list_visible(self) -> None:
        payload = UserUpdate(allowed_actions=["users:read"])
        assert payload.allowed_actions == ["users:read"]

    def test_malformed_scopes_rejected(self) -> None:
        with pytest.raises(ValidationError, match="invalid scope format"):
            UserUpdate(allowed_actions=["nosemicolon"])


class TestUserReadJsonbCoercion:
    """Read-side: asyncpg returns JSONB as a string. The BeforeValidator must
    parse it once so callers always see a Python list (or None)."""

    def _stamp(self) -> datetime:
        return datetime(2026, 5, 8, tzinfo=UTC)

    def test_list_passes_through(self) -> None:
        u = User(
            id=1,
            username="alice",
            email=None,
            role=UserRole.NOC,
            enabled=True,
            auth_provider="api_key",
            api_key_hash="x",
            password_hash=None,
            created_at=self._stamp(),
            allowed_actions=["users:read"],
        )
        assert u.allowed_actions == ["users:read"]

    def test_jsonb_string_parsed(self) -> None:
        # Simulate asyncpg returning JSONB as a serialised string.
        u = User.model_validate(
            {
                "id": 1,
                "username": "alice",
                "email": None,
                "role": "noc",
                "enabled": True,
                "auth_provider": "api_key",
                "api_key_hash": "x",
                "password_hash": None,
                "created_at": self._stamp(),
                "last_login_at": None,
                "allowed_actions": '["users:read", "users:create"]',
            }
        )
        assert u.allowed_actions == ["users:read", "users:create"]

    def test_none_stays_none(self) -> None:
        u = User(
            id=1,
            username="alice",
            email=None,
            role=UserRole.NOC,
            enabled=True,
            auth_provider="api_key",
            api_key_hash="x",
            password_hash=None,
            created_at=self._stamp(),
            allowed_actions=None,
        )
        assert u.allowed_actions is None

    def test_useradmin_also_coerces(self) -> None:
        # UserAdmin is the API response shape — same JSONB coercion applies.
        admin = UserAdmin.model_validate(
            {
                "id": 2,
                "username": "noc-svc",
                "email": None,
                "role": "admin",
                "auth_provider": "api_key",
                "enabled": True,
                "created_at": self._stamp(),
                "last_login_at": None,
                "allowed_actions": '["users:create", "users:read"]',
            }
        )
        assert admin.allowed_actions == ["users:create", "users:read"]
