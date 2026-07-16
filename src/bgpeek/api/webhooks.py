"""HTTP handlers for /api/webhooks."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from bgpeek.core.auth import require_role, scoped_endpoint
from bgpeek.core.webhooks import send_test_payload
from bgpeek.db import webhooks as crud
from bgpeek.db.pool import get_pool
from bgpeek.models.user import User, UserRole
from bgpeek.models.webhook import Webhook, WebhookCreate, WebhookUpdate

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

_admin = require_role(UserRole.ADMIN)


@router.get("", response_model=list[Webhook])
@scoped_endpoint("webhooks:read")
async def list_webhooks(
    _caller: User = Depends(_admin),  # noqa: B008
) -> list[Webhook]:
    """List all webhooks (admin only)."""
    hooks = await crud.list_webhooks(get_pool())
    return [h.mask_secret() for h in hooks]


@router.get("/{webhook_id}", response_model=Webhook)
@scoped_endpoint("webhooks:read")
async def get_webhook(
    webhook_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> Webhook:
    """Get a single webhook by id (admin only)."""
    hook = await crud.get_webhook(get_pool(), webhook_id)
    if hook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="webhook not found")
    return hook.mask_secret()


@router.post("", response_model=Webhook, status_code=status.HTTP_201_CREATED)
@scoped_endpoint("webhooks:create")
async def create_webhook(
    payload: WebhookCreate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> Webhook:
    """Create a new webhook (admin only)."""
    hook = await crud.create_webhook(get_pool(), payload)
    return hook.mask_secret()


@router.patch("/{webhook_id}", response_model=Webhook)
@scoped_endpoint("webhooks:update")
async def update_webhook(
    webhook_id: int,
    payload: WebhookUpdate,
    _caller: User = Depends(_admin),  # noqa: B008
) -> Webhook:
    """Partially update a webhook (admin only)."""
    hook = await crud.update_webhook(get_pool(), webhook_id, payload)
    if hook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="webhook not found")
    return hook.mask_secret()


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
@scoped_endpoint("webhooks:delete")
async def delete_webhook(
    webhook_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> None:
    """Delete a webhook by id (admin only)."""
    deleted = await crud.delete_webhook(get_pool(), webhook_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="webhook not found")


@router.post("/{webhook_id}/test")
@scoped_endpoint("webhooks:read")
async def ping_webhook(
    webhook_id: int,
    _caller: User = Depends(_admin),  # noqa: B008
) -> dict[str, bool]:
    """Send a test payload to a webhook (admin only)."""
    hook = await crud.get_webhook(get_pool(), webhook_id)
    if hook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="webhook not found")
    success = await send_test_payload(hook)
    return {"success": success}
