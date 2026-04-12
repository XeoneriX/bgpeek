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


class QueryError(BaseModel):
    """Structured error from a failed query."""

    detail: str
    target: str | None = None
    device_name: str | None = None
