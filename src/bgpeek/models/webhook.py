"""Webhook notification models."""

from __future__ import annotations

import socket
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from bgpeek.models._common import TrimmedOptStr, TrimmedStr


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

    # `min_length=1` was missing — without it a whitespace-only name stripped
    # down to `""` would still have been accepted. Adding explicitly guards the
    # invariant we want the form to enforce.
    name: TrimmedStr = Field(min_length=1, max_length=255)
    url: TrimmedStr = Field(min_length=1, max_length=2048)
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
    from ipaddress import IPv6Address

    addr = ip_address(addr_str)
    # Handle IPv6-mapped IPv4 (e.g. ::ffff:10.0.0.1)
    if isinstance(addr, IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise ValueError(f"webhook URL cannot target private/reserved network ({net})")


def _validate_webhook_target(url: str, *, allow_unresolved_hostname: bool) -> None:
    """Validate that a webhook URL does not resolve to private/reserved targets."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("webhook URL must use http or https")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("webhook URL must have a hostname")

    # Handle literal IP hostnames first.
    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        _check_blocked(hostname)
        return

    # Hostname: resolve all addresses and validate each.
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        if allow_unresolved_hostname:
            return
        raise ValueError(f"webhook URL hostname could not be resolved ({hostname})") from None

    for info in resolved:
        _check_blocked(str(info[4][0]))


def validate_webhook_delivery_target(url: str) -> None:
    """Runtime webhook target validation used right before outbound delivery."""
    _validate_webhook_target(url, allow_unresolved_hostname=False)


def resolve_and_pin_webhook_target(url: str) -> tuple[str, str]:
    """Resolve the URL's hostname once, validate every address, pin to the first.

    Returns ``(pinned_url, original_host)`` where ``pinned_url`` has the
    hostname replaced with an IP literal. The caller sends ``Host: <original>``
    so the webhook receiver still sees the expected virtual host, and
    (for HTTPS) supplies ``sni_hostname=original`` via httpx request
    ``extensions`` so certificate verification continues to match the CN/SAN.

    Closes the DNS-rebind TOCTOU — httpx's own DNS lookup would otherwise
    race with our validator under a low-TTL rebind, and the request could
    land on 127.0.0.1 / 169.254.169.254 / an internal service.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("webhook URL must use http or https")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("webhook URL must have a hostname")

    # Literal-IP hostnames were already validated at model-create time.
    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        _check_blocked(hostname)
        return url, hostname

    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"webhook URL hostname could not be resolved ({hostname})") from exc

    # Validate every returned address; if ANY is blocked, refuse — don't let
    # the attacker's resolver return a mix of public + private and get us to
    # pick the public one.
    for info in resolved:
        _check_blocked(str(info[4][0]))

    pinned_ip = str(resolved[0][4][0])
    netloc = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    pinned = parsed._replace(netloc=netloc).geturl()
    return pinned, hostname


class WebhookCreate(WebhookBase):
    """Payload for creating a new webhook."""

    # `secret` is signing material — never stripped (see CredentialBase.password).
    secret: str | None = Field(default=None, max_length=255)

    @field_validator("url")
    @classmethod
    def validate_webhook_url(cls, v: str) -> str:
        _validate_webhook_target(v, allow_unresolved_hostname=True)
        return v


class WebhookUpdate(BaseModel):
    """Partial update payload — all fields optional."""

    model_config = ConfigDict(extra="forbid")

    name: TrimmedOptStr = Field(default=None, min_length=1, max_length=255)
    url: TrimmedOptStr = Field(default=None, min_length=1, max_length=2048)
    events: list[WebhookEvent] | None = Field(default=None, min_length=1)
    enabled: bool | None = None
    secret: str | None = Field(default=None, max_length=255)

    @field_validator("url")
    @classmethod
    def validate_webhook_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return WebhookCreate.validate_webhook_url(v)


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
