"""Request/response models for network queries."""

from __future__ import annotations

import uuid
from datetime import datetime
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
    metric2: int | None = None  # Junos IGP metric to next-hop
    local_pref: int | None = None
    age: str | None = None  # raw string, e.g. "4d 10:03:27", "2w3d"
    communities: list[str] = Field(default_factory=list)
    best: bool = False
    rpki_status: str | None = None


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
    resolved_target: str | None = None
    result_id: str | None = None


class StoredResult(BaseModel):
    """Query result as stored in PostgreSQL."""

    id: uuid.UUID
    user_id: int | None = None
    username: str | None = None
    device_name: str
    query_type: QueryType
    target: str
    command: str | None = None
    raw_output: str | None = None
    filtered_output: str | None = None
    parsed_routes: list[BGPRoute] = Field(default_factory=list)
    runtime_ms: int | None = None
    cached: bool = False
    created_at: datetime
    expires_at: datetime


class QueryError(BaseModel):
    """Structured error from a failed query."""

    detail: str
    target: str | None = None
    device_name: str | None = None


class MultiQueryRequest(BaseModel):
    """Query targeting multiple devices in parallel."""

    model_config = ConfigDict(extra="forbid")

    device_names: list[str] = Field(min_length=1, max_length=10)
    query_type: QueryType
    target: str = Field(min_length=1, max_length=255)


class MultiQueryResponse(BaseModel):
    """Results from parallel queries across multiple devices."""

    results: list[QueryResponse] = Field(default_factory=list)
    errors: list[QueryError] = Field(default_factory=list)
    total_runtime_ms: int
    device_count: int
