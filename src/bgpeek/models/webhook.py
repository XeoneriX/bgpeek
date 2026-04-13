"""Webhook notification models."""

from __future__ import annotations

import socket
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WebhookEvent(StrEnum):
    """Events that can trigger a webhook."""

    QUERY = "query"
    DEVICE_CREATE = "device_create"
    DEVICE_UPDATE = "device_update"
    DEVICE_DELETE = "device_delete"
    LOGIN = "login"


class WebhookBase(BaseModel):
    """Shared fields for webhook creation and response."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=255)
    url: str = Field(max_length=2048)
    events: list[WebhookEvent] = Field(min_length=1)
    enabled: bool = True


_BLOCKED_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ip_network("100.64.0.0/10"),  # CGNAT
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]


def _check_blocked(addr_str: str) -> None:
    """Raise ValueError if *addr_str* falls inside a blocked network."""
    addr = ip_address(addr_str)
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise ValueError(
                f"webhook URL cannot target private/reserved network ({net})"
            )


class WebhookCreate(WebhookBase):
    """Payload for creating a new webhook."""

    secret: str | None = Field(default=None, max_length=255)

    @field_validator("url")
    @classmethod
    def validate_webhook_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("webhook URL must use http or https")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("webhook URL must have a hostname")
        # Check if hostname is a literal IP address
        try:
            _check_blocked(hostname)
        except ValueError as exc:
            if "cannot target" in str(exc):
                raise
            # hostname is not an IP literal — try DNS resolution
            try:
                resolved = socket.getaddrinfo(
                    hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
                )
                for info in resolved:
                    _check_blocked(info[4][0])
            except socket.gaierror:
                pass  # DNS failure — allow now, will fail on delivery
        return v


class WebhookUpdate(BaseModel):
    """Partial update payload — all fields optional."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=2048)
    events: list[WebhookEvent] | None = Field(default=None, min_length=1)
    enabled: bool | None = None
    secret: str | None = Field(default=None, max_length=255)


class Webhook(WebhookBase):
    """Webhook as stored in PostgreSQL."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    secret: str | None = None
    created_at: datetime
    updated_at: datetime

    def mask_secret(self) -> Webhook:
        """Return a copy with the secret masked for API responses."""
        if self.secret is None:
            return self
        return self.model_copy(update={"secret": "****"})


class WebhookPayload(BaseModel):
    """Payload sent to webhook URL."""

    event: WebhookEvent
    timestamp: str
    data: dict[str, Any]
