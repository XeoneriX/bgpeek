"""User model: authentication and authorisation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from bgpeek.models._common import TrimmedOptStr, TrimmedStr


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
    """Payload for creating a new API-key user."""

    # `api_key` is a shared secret — keep exactly what the caller sent, even
    # if it has incidental whitespace. Length constraint already blocks "   ".
    api_key: str = Field(min_length=32, max_length=128)


class UserUpdate(BaseModel):
    """Payload for partial updates. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    username: TrimmedOptStr = Field(default=None, min_length=1, max_length=255)
    email: TrimmedOptStr = None
    role: UserRole | None = None
    enabled: bool | None = None


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

    username: str
    password: str


class User(UserBase):
    """User as stored in PostgreSQL."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    auth_provider: str
    api_key_hash: str | None = None
    password_hash: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None


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


class LoginResponse(BaseModel):
    """Response returned after successful login."""

    token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    user: UserPublic
