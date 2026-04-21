"""Device model: a network element bgpeek can query."""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field

from bgpeek.models._common import TrimmedOptStr, TrimmedStr

IPAddress = IPv4Address | IPv6Address


class DeviceBase(BaseModel):
    """Fields shared by create / read variants."""

    name: TrimmedStr = Field(min_length=1, max_length=255)
    address: IPAddress
    port: int = Field(default=22, ge=1, le=65535)
    platform: TrimmedStr = Field(min_length=1, max_length=64)
    description: TrimmedOptStr = None
    location: TrimmedOptStr = None
    region: TrimmedOptStr = None
    enabled: bool = True
    restricted: bool = False
    credential_id: int | None = None
    source4: IPv4Address | None = None
    source6: IPv6Address | None = None


class DeviceCreate(DeviceBase):
    """Payload for creating a new device."""


class DeviceUpdate(BaseModel):
    """Payload for partial updates. All fields optional."""

    model_config = ConfigDict(extra="forbid")

    name: TrimmedOptStr = Field(default=None, min_length=1, max_length=255)
    address: IPAddress | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    platform: TrimmedOptStr = Field(default=None, min_length=1, max_length=64)
    description: TrimmedOptStr = None
    location: TrimmedOptStr = None
    region: TrimmedOptStr = None
    enabled: bool | None = None
    restricted: bool | None = None
    credential_id: int | None = None
    source4: IPv4Address | None = None
    source6: IPv6Address | None = None


class Device(DeviceBase):
    """Device as stored in PostgreSQL."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
