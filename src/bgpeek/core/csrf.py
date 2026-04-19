"""Reusable CSRF integration using fastapi-csrf-protect."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import Response
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from pydantic_settings import BaseSettings

from bgpeek.config import settings


class CsrfSettings(BaseSettings):
    """Configuration for fastapi-csrf-protect."""

    secret_key: str = settings.session_secret or settings.jwt_secret
    cookie_samesite: str = "lax"
    cookie_secure: bool = settings.cookie_secure
    cookie_httponly: bool = True
    token_location: str = "body"  # noqa: S105
    token_key: str = "csrf_token"  # noqa: S105


@CsrfProtect.load_config
def _load_csrf_config() -> CsrfSettings:
    return CsrfSettings()


def issue_csrf_token(csrf_protect: CsrfProtect) -> tuple[str, str]:
    """Generate a csrf token pair (raw token, signed cookie token)."""
    return csrf_protect.generate_csrf_tokens()


def set_csrf_cookie(csrf_protect: CsrfProtect, response: Response, signed_token: str) -> None:
    """Set signed CSRF cookie on response."""
    csrf_protect.set_csrf_cookie(signed_token, response)


async def validate_csrf(
    request: Request,
    csrf_protect: CsrfProtect = Depends(),  # noqa: B008
) -> None:
    """Validate CSRF token from form body against signed cookie."""
    try:
        await csrf_protect.validate_csrf(request)
    except CsrfProtectError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="invalid CSRF token") from exc
