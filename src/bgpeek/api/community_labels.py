"""HTTP handlers for /api/community-labels."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from bgpeek.core.auth import require_role, scoped_endpoint
from bgpeek.core.community_labels import refresh_cache
from bgpeek.db import community_labels as crud
from bgpeek.db.pool import get_pool
from bgpeek.models.community_label import (
    CommunityLabel,
    CommunityLabelCreate,
    CommunityLabelUpdate,
)
from bgpeek.models.user import User, UserRole

router = APIRouter(prefix="/api/community-labels", tags=["community-labels"])

_admin = require_role(UserRole.ADMIN)


@router.get("", response_model=list[CommunityLabel])
async def list_labels() -> list[CommunityLabel]:
    """List all community labels (public — labels are not sensitive)."""
    return await crud.list_labels(get_pool())


@router.post("", response_model=CommunityLabel, status_code=status.HTTP_201_CREATED)
@scoped_endpoint("community_labels:write")
async def create_label(
    payload: CommunityLabelCreate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> CommunityLabel:
    """Create a community label (admin only)."""
    try:
        row = await crud.create_label(get_pool(), payload)
    except Exception as exc:
        msg = str(exc).lower()
        if "unique" in msg or "duplicate" in msg:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail="label with this pattern and match_type already exists",
            ) from exc
        raise
    await refresh_cache()
    return row


@router.patch("/{label_id}", response_model=CommunityLabel)
@scoped_endpoint("community_labels:write")
async def update_label(
    label_id: int,
    payload: CommunityLabelUpdate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> CommunityLabel:
    """Partially update a community label (admin only)."""
    row = await crud.update_label(get_pool(), label_id, payload)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="community label not found")
    await refresh_cache()
    return row


@router.delete("/{label_id}", status_code=status.HTTP_204_NO_CONTENT)
@scoped_endpoint("community_labels:write")
async def delete_label(
    label_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> None:
    """Delete a community label (admin only)."""
    deleted = await crud.delete_label(get_pool(), label_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="community label not found")
    await refresh_cache()
