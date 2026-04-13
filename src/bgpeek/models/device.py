"""Device model: a network element bgpeek can query."""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field

IPAddress = IPv4Address | IPv6Address


class DeviceBase(BaseModel):
    """Fields shared by create / read variants."""

    name: str = Field(min_length=1, max_length=255)
    address: IPAddress
    port: int = Field(default=22, ge=1, le=65535)
    platform: str = Field(min_length=1, max_length=64)
    description: str | None = None
    location: str | None = None
    enabled: bool = True
    restricted: bool = False
    credential_id: int | None = None
    source4: str | None = None
    source6: str | None = None


class DeviceCreate(DeviceBase):
    """Payload for creating a new device."""


class DeviceUpdate(BaseModel):
    """Payload for partial updates. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    address: IPAddress | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    platform: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = None
    location: str | None = None
    enabled: bool | None = None
    restricted: bool | None = None
    credential_id: int | None = None
    source4: str | None = None
    source6: str | None = None


class Device(DeviceBase):
    """Device as stored in PostgreSQL."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
