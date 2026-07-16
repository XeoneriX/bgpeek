"""Audit log models: security trail for queries, auth, and admin actions."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field

IPAddress = IPv4Address | IPv6Address


class AuditAction(StrEnum):
    """High-level categories of auditable events."""

    QUERY = "query"
    PROBE = "probe"
    LOGIN = "login"
    LOGOUT = "logout"
    CREATE_DEVICE = "create_device"
    UPDATE_DEVICE = "update_device"
    DELETE_DEVICE = "delete_device"
    CREATE_USER = "create_user"
    UPDATE_USER = "update_user"
    DELETE_USER = "delete_user"
    RESET_PASSWORD = "reset_password"  # noqa: S105 — audit action label, not a password
    SCOPE_VIOLATION = "scope_violation"
    PRIVILEGE_ESCALATION_ATTEMPT = "privilege_escalation_attempt"


class AuditEntryCreate(BaseModel):
    """Payload for inserting a new audit log row."""

    model_config = ConfigDict(extra="forbid")

    action: AuditAction
    success: bool

    user_id: int | None = None
    username: str | None = Field(default=None, max_length=255)
    user_role: str | None = Field(default=None, max_length=32)

    source_ip: IPAddress | None = None
    user_agent: str | None = Field(default=None, max_length=512)

    device_id: int | None = None
    device_name: str | None = Field(default=None, max_length=255)

    query_type: str | None = Field(default=None, max_length=64)
    query_target: str | None = Field(default=None, max_length=255)

    error_message: str | None = None
    runtime_ms: int | None = Field(default=None, ge=0)
    response_bytes: int | None = Field(default=None, ge=0)


class AuditEntry(AuditEntryCreate):
    """Audit log row as stored in PostgreSQL."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
