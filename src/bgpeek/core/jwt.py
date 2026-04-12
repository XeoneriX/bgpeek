"""JWT token creation and verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt

from bgpeek.config import settings


def create_token(user_id: int, username: str, role: str) -> str:
    """Create a signed JWT with standard claims."""
    now = datetime.now(tz=UTC)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, object]:
    """Verify and decode a JWT. Raises ``jwt.InvalidTokenError`` on failure."""
    return jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
    )
