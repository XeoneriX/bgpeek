"""User model: authentication and authorisation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from bgpeek.core.scopes import validate_scope_string, warn_unknown_actions
from bgpeek.models._common import TrimmedOptStr, TrimmedStr


def _validate_scope_list(v: Any) -> list[str] | None:
    """Reject malformed scope strings; warn on unknown actions.

    ``None`` passes through (legacy role-based authz). Empty list is allowed
    semantically (deny-all) but practically meaningless — it would lock the
    user out of every protected endpoint. We accept it without comment;
    operators who set it have a reason (e.g. temporarily neutralise a key
    without deleting the row to preserve audit history).
    """
    if v is None:
        return None
    if not isinstance(v, list):
        raise ValueError("allowed_actions must be a list of strings or null")
    cleaned: list[str] = []
    for s in v:
        if not isinstance(s, str):
            raise ValueError(f"scope must be a string, got {type(s).__name__}")
        if not validate_scope_string(s):
            raise ValueError(
                f"invalid scope format: {s!r} "
                f"(expected 'resource:action' or 'resource:*' or '*'; "
                f"see core/scopes.py)"
            )
        cleaned.append(s)
    warn_unknown_actions(cleaned)
    return cleaned


# Pydantic validator that DB code can apply when reading an asyncpg JSONB
# value. asyncpg returns JSONB as `str`; this BeforeValidator parses the
# string into the Python list before the field type check runs. Models that
# only ever construct from API payloads (UserCreate, UserUpdate) skip this
# helper — ``v`` is already a list there.
def _parse_jsonb_list(v: Any) -> Any:
    if isinstance(v, str):
        import json
        return json.loads(v)
    return v


AllowedActions = Annotated[
    list[str] | None,
    BeforeValidator(_parse_jsonb_list),
]


class UserRole(StrEnum):
    """User privilege levels."""

    ADMIN = "admin"
    NOC = "noc"
    PUBLIC = "public"
    GUEST = "guest"


class UserBase(BaseModel):
    """Fields shared by create / read variants."""

    username: TrimmedStr = Field(min_length=1, max_length=255)
    email: TrimmedOptStr = None
    role: UserRole = UserRole.PUBLIC
    enabled: bool = True


class UserCreate(UserBase):
    """Payload for creating a new API-key user.

    ``api_key`` is optional: when omitted the server generates a cryptographically
    strong value and returns it once in the 201 response (show-once pattern).
    Client-supplied keys are still accepted for backward compatibility but will
    be rejected in v1.5.0 — migrate any automation to let the server generate
    and read the ``api_key`` field from the response.
    """

    # `api_key` is a shared secret — keep exactly what the caller sent, even
    # if it has incidental whitespace. Length constraint already blocks "   ".
    api_key: str | None = Field(default=None, min_length=32, max_length=128)
    allowed_actions: list[str] | None = None

    @field_validator("allowed_actions")
    @classmethod
    def _check_actions(cls, v: Any) -> list[str] | None:
        return _validate_scope_list(v)


class UserUpdate(BaseModel):
    """Payload for partial updates. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    username: TrimmedOptStr = Field(default=None, min_length=1, max_length=255)
    email: TrimmedOptStr = None
    role: UserRole | None = None
    enabled: bool | None = None
    allowed_actions: list[str] | None = None

    @field_validator("allowed_actions")
    @classmethod
    def _check_actions(cls, v: Any) -> list[str] | None:
        return _validate_scope_list(v)


class UserCreateLocal(BaseModel):
    """Payload for creating a local (username/password) user."""

    model_config = ConfigDict(extra="forbid")

    username: TrimmedStr = Field(min_length=1, max_length=255)
    # Passwords are preserved verbatim; silently stripping whitespace could
    # desynchronise the stored hash from what the user types at the login form.
    password: str = Field(min_length=8, max_length=128)
    email: TrimmedOptStr = None
    role: UserRole = UserRole.PUBLIC


class LoginRequest(BaseModel):
    """Payload for username/password login."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class User(UserBase):
    """User as stored in PostgreSQL."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    auth_provider: str
    api_key_hash: str | None = None
    password_hash: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None
    # asyncpg returns JSONB as a string — the BeforeValidator parses it once
    # so callers always see a list (or None for legacy users).
    allowed_actions: AllowedActions = None


class UserPublic(BaseModel):
    """User fields safe for public API responses — no hashes, no internals."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: UserRole
    enabled: bool


class UserAdmin(BaseModel):
    """User fields for admin API responses — includes metadata but no hashes."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None = None
    role: UserRole
    auth_provider: str
    enabled: bool
    created_at: datetime
    last_login_at: datetime | None = None
    allowed_actions: AllowedActions = None


class UserCreated(UserAdmin):
    """201 response for ``POST /api/users`` — carries the one-shot API key.

    ``api_key`` is the plaintext token. It is returned exactly once; subsequent
    reads of the user never expose it again (only the SHA-256 hash is stored).
    """

    api_key: str


class LoginResponse(BaseModel):
    """Response returned after successful login."""

    token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    user: UserPublic
