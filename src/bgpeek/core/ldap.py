"""LDAP authentication backend."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import structlog
from ldap3 import ALL_ATTRIBUTES, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPException,
    LDAPSocketOpenError,
)

from bgpeek.config import settings
from bgpeek.models.user import UserRole

logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class LdapUserInfo:
    """User information extracted from a successful LDAP bind."""

    username: str
    email: str | None
    role: UserRole


def _parse_role_mapping(raw: str) -> dict[str, UserRole]:
    """Parse the JSON role-mapping string into {group_dn: UserRole}."""
    if not raw.strip():
        return {}
    mapping: dict[str, str] = json.loads(raw)
    return {dn.lower(): UserRole(role) for dn, role in mapping.items()}


def _resolve_role(
    member_of: list[str],
    role_mapping: dict[str, UserRole],
    default: UserRole,
) -> UserRole:
    """Pick the highest-privilege role that matches any of the user's groups."""
    priority = {UserRole.ADMIN: 0, UserRole.NOC: 1, UserRole.PUBLIC: 2}
    best = default
    for group_dn in member_of:
        role = role_mapping.get(group_dn.lower())
        if role is not None and priority.get(role, 99) < priority.get(best, 99):
            best = role
    return best


def _authenticate_sync(username: str, password: str) -> LdapUserInfo | None:
    """Blocking LDAP authenticate: search + rebind. Called via ``asyncio.to_thread``."""
    use_ssl = settings.ldap_server.startswith("ldaps://")

    tls_obj = Tls() if (settings.ldap_use_tls or use_ssl) else None
    server = Server(settings.ldap_server, use_ssl=use_ssl, tls=tls_obj, get_info=None)

    # --- Service-account bind (search) ---
    svc_conn = Connection(
        server,
        user=settings.ldap_bind_dn,
        password=settings.ldap_bind_password,
        auto_bind=False,
        raise_exceptions=True,
    )
    svc_conn.bind()

    if settings.ldap_use_tls and not use_ssl:
        svc_conn.start_tls()

    # --- Search for user entry ---
    search_filter = settings.ldap_user_filter.replace("{username}", username)
    svc_conn.search(
        search_base=settings.ldap_base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=ALL_ATTRIBUTES,
    )

    if not svc_conn.entries:
        logger.info("ldap user not found", username=username)
        svc_conn.unbind()
        return None

    entry = svc_conn.entries[0]
    user_dn: str = entry.entry_dn
    svc_conn.unbind()

    # --- User bind (authentication) ---
    user_conn = Connection(
        server,
        user=user_dn,
        password=password,
        auto_bind=False,
        raise_exceptions=True,
    )
    try:
        user_conn.bind()
    except LDAPBindError:
        logger.info("ldap bind failed (wrong password)", username=username)
        return None
    finally:
        user_conn.unbind()

    # --- Extract attributes ---
    email_attr = settings.ldap_email_attr
    email: str | None = None
    if email_attr in entry:
        raw_email = entry[email_attr].value
        email = str(raw_email) if raw_email else None

    group_attr = settings.ldap_group_attr
    member_of: list[str] = []
    if group_attr in entry:
        raw = entry[group_attr].value
        if isinstance(raw, list):
            member_of = [str(g) for g in raw]
        elif raw is not None:
            member_of = [str(raw)]

    role_mapping = _parse_role_mapping(settings.ldap_role_mapping)
    default_role = UserRole(settings.ldap_default_role)
    role = _resolve_role(member_of, role_mapping, default_role)

    return LdapUserInfo(username=username, email=email, role=role)


async def authenticate_ldap(username: str, password: str) -> LdapUserInfo | None:
    """Try to authenticate a user against LDAP. Returns user info or None."""
    if not settings.ldap_enabled:
        return None

    try:
        return await asyncio.to_thread(_authenticate_sync, username, password)
    except LDAPSocketOpenError:
        logger.error("ldap server unreachable", server=settings.ldap_server)
        return None
    except LDAPException as exc:
        logger.error("ldap error", error=str(exc))
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error("ldap unexpected error", error=str(exc))
        return None
