"""Community-label mapping models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class MatchType(StrEnum):
    """How ``pattern`` is compared against a community string."""

    EXACT = "exact"
    PREFIX = "prefix"


ALLOWED_COLORS: frozenset[str] = frozenset({
    "amber", "emerald", "rose", "sky", "violet", "slate", "red", "orange",
    "cyan", "pink", "yellow", "lime", "teal", "indigo", "fuchsia", "blue", "green",
})


class CommunityLabelBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern: str = Field(min_length=1, max_length=64)
    match_type: MatchType = MatchType.EXACT
    label: str = Field(min_length=1, max_length=255)
    color: str | None = Field(default=None, max_length=16)


class CommunityLabelCreate(CommunityLabelBase):
    pass


class CommunityLabelUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern: str | None = Field(default=None, min_length=1, max_length=64)
    match_type: MatchType | None = None
    label: str | None = Field(default=None, min_length=1, max_length=255)
    color: str | None = Field(default=None, max_length=16)


class CommunityLabel(CommunityLabelBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
