"""JWT token creation and verification."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import jwt

from bgpeek.config import settings


def create_token(user_id: int, username: str, role: str) -> str:
    """Create a signed JWT with standard claims.

    Every token carries a random ``jti`` (JWT ID) so server-side revocation
    can target a single token without invalidating other live sessions for the
    same user. See :mod:`bgpeek.core.jwt_revoke`.
    """
    now = datetime.now(tz=UTC)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, object]:
    """Verify and decode a JWT. Raises ``jwt.InvalidTokenError`` on failure."""
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
    )
