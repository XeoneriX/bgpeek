"""User model: authentication and authorisation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class UserRole(StrEnum):
    """User privilege levels."""

    ADMIN = "admin"
    NOC = "noc"
    PUBLIC = "public"


class UserBase(BaseModel):
    """Fields shared by create / read variants."""

    username: str = Field(min_length=1, max_length=255)
    email: str | None = None
    role: UserRole = UserRole.PUBLIC
    enabled: bool = True


class UserCreate(UserBase):
    """Payload for creating a new API-key user."""

    api_key: str = Field(min_length=32, max_length=128)


class UserUpdate(BaseModel):
    """Payload for partial updates. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    username: str | None = Field(default=None, min_length=1, max_length=255)
    email: str | None = None
    role: UserRole | None = None
    enabled: bool | None = None


class User(UserBase):
    """User as stored in PostgreSQL."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    auth_provider: str
    api_key_hash: str | None = None
    password_hash: str | None = None
    created_at: datetime
    last_login_at: datetime | None = None
