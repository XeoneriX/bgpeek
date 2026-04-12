"""Request/response models for network queries."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class QueryType(StrEnum):
    """Supported query types."""

    BGP_ROUTE = "bgp_route"
    PING = "ping"
    TRACEROUTE = "traceroute"


class QueryRequest(BaseModel):
    """Incoming query from user or API."""

    model_config = ConfigDict(extra="forbid")

    device_name: str = Field(min_length=1, max_length=255)
    query_type: QueryType
    target: str = Field(min_length=1, max_length=255)


class BGPRoute(BaseModel):
    """Single parsed BGP route entry."""

    prefix: str
    next_hop: str | None = None
    as_path: str | None = None
    origin: str | None = None  # IGP, EGP, Incomplete
    med: int | None = None
    local_pref: int | None = None
    communities: list[str] = Field(default_factory=list)
    best: bool = False


class QueryResponse(BaseModel):
    """Result of a successful query."""

    device_name: str
    query_type: QueryType
    target: str
    command: str
    raw_output: str
    filtered_output: str
    runtime_ms: int
    cached: bool = False
    parsed_routes: list[BGPRoute] = Field(default_factory=list)


class QueryError(BaseModel):
    """Structured error from a failed query."""

    detail: str
    target: str | None = None
    device_name: str | None = None
