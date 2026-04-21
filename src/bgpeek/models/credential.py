"""SSH credential model for device authentication."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from bgpeek.models._common import TrimmedOptStr, TrimmedStr


class CredentialBase(BaseModel):
    """Fields shared by create / read variants."""

    name: TrimmedStr = Field(min_length=1, max_length=255)
    description: TrimmedStr = ""
    auth_type: str = Field(default="key", pattern=r"^(key|password|key\+password)$")
    username: TrimmedStr = Field(min_length=1, max_length=255)
    key_name: TrimmedOptStr = None
    # `password` is intentionally *not* trimmed — leading/trailing whitespace
    # can legitimately be part of a stored secret; silently stripping could
    # lock an operator out of a router.
    password: str | None = None

    @field_validator("key_name")
    @classmethod
    def validate_key_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if ".." in v or "/" in v or "\\" in v or "\x00" in v:
            raise ValueError("key_name must be a plain filename without path separators")
        return v


class CredentialCreate(CredentialBase):
    """Payload for creating a credential."""


class CredentialUpdate(BaseModel):
    """Partial update payload. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    name: TrimmedOptStr = Field(default=None, min_length=1, max_length=255)
    description: TrimmedOptStr = None
    auth_type: str | None = Field(default=None, pattern=r"^(key|password|key\+password)$")
    username: TrimmedOptStr = Field(default=None, min_length=1, max_length=255)
    key_name: TrimmedOptStr = None
    # See CredentialBase.password — preserved verbatim on purpose.
    password: str | None = None

    @field_validator("key_name")
    @classmethod
    def validate_key_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if ".." in v or "/" in v or "\\" in v or "\x00" in v:
            raise ValueError("key_name must be a plain filename without path separators")
        return v


class Credential(CredentialBase):
    """Credential as stored in PostgreSQL (password masked in API responses)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    password: str | None = None
    created_at: datetime
    updated_at: datetime


class CredentialWithUsage(Credential):
    """Credential with count of devices referencing it."""

    device_count: int = 0
