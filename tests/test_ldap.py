"""Tests for LDAP authentication backend and user provisioning."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import asyncpg

from bgpeek.core.ldap import LdapUserInfo, authenticate_ldap
from bgpeek.db import users as crud
from bgpeek.models.user import UserRole

# ---------------------------------------------------------------------------
# authenticate_ldap — unit tests (mock ldap3, no real server)
# ---------------------------------------------------------------------------


async def test_authenticate_ldap_disabled_returns_none() -> None:
    with patch("bgpeek.core.ldap.settings") as mock_settings:
        mock_settings.ldap_enabled = False
        result = await authenticate_ldap("alice", "password")
    assert result is None


class _FakeEntry:
    """Minimal stand-in for an ldap3 Entry with attribute access via ``in`` / ``[]``."""

    def __init__(
        self,
        dn: str,
        attrs: dict[str, object],
    ) -> None:
        self.entry_dn = dn
        self._attrs = attrs

    def __contains__(self, key: object) -> bool:
        return key in self._attrs

    def __getitem__(self, key: str) -> object:
        return self._attrs[key]


def _mock_entry(
    dn: str = "uid=alice,ou=people,dc=example,dc=com",
    mail: str = "alice@example.com",
    member_of: list[str] | None = None,
) -> _FakeEntry:
    """Build a fake ldap3 entry object."""
    attrs: dict[str, MagicMock] = {}

    mail_attr = MagicMock()
    mail_attr.value = mail
    attrs["mail"] = mail_attr

    if member_of is not None:
        group_attr = MagicMock()
        group_attr.value = member_of
        attrs["memberOf"] = group_attr

    return _FakeEntry(dn=dn, attrs=attrs)


def _ldap_settings(**overrides: object) -> MagicMock:
    """Return a mock Settings object with LDAP enabled and sensible defaults."""
    s = MagicMock()
    defaults: dict[str, object] = {
        "ldap_enabled": True,
        "ldap_server": "ldap://ldap.example.com:389",
        "ldap_bind_dn": "cn=readonly,dc=example,dc=com",
        "ldap_bind_password": "secret",
        "ldap_base_dn": "ou=people,dc=example,dc=com",
        "ldap_user_filter": "(uid={username})",
        "ldap_use_tls": False,
        "ldap_role_mapping": "",
        "ldap_default_role": "public",
        "ldap_email_attr": "mail",
        "ldap_group_attr": "memberOf",
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(s, k, v)
    return s


async def test_authenticate_ldap_success() -> None:
    entry = _mock_entry()
    svc_conn = MagicMock()
    svc_conn.entries = [entry]
    user_conn = MagicMock()

    with (
        patch("bgpeek.core.ldap.settings", _ldap_settings()),
        patch("bgpeek.core.ldap.Server"),
        patch("bgpeek.core.ldap.Connection", side_effect=[svc_conn, user_conn]),
    ):
        result = await authenticate_ldap("alice", "correct-password")

    assert result is not None
    assert result == LdapUserInfo(username="alice", email="alice@example.com", role=UserRole.PUBLIC)
    svc_conn.bind.assert_called_once()
    svc_conn.search.assert_called_once()
    svc_conn.unbind.assert_called_once()
    user_conn.bind.assert_called_once()
    user_conn.unbind.assert_called_once()


async def test_authenticate_ldap_user_not_found() -> None:
    svc_conn = MagicMock()
    svc_conn.entries = []

    with (
        patch("bgpeek.core.ldap.settings", _ldap_settings()),
        patch("bgpeek.core.ldap.Server"),
        patch("bgpeek.core.ldap.Connection", return_value=svc_conn),
    ):
        result = await authenticate_ldap("ghost", "password")

    assert result is None


async def test_authenticate_ldap_wrong_password() -> None:
    from ldap3.core.exceptions import LDAPBindError  # type: ignore[import-untyped]

    entry = _mock_entry()
    svc_conn = MagicMock()
    svc_conn.entries = [entry]

    user_conn = MagicMock()
    user_conn.bind.side_effect = LDAPBindError("invalid credentials")

    with (
        patch("bgpeek.core.ldap.settings", _ldap_settings()),
        patch("bgpeek.core.ldap.Server"),
        patch("bgpeek.core.ldap.Connection", side_effect=[svc_conn, user_conn]),
    ):
        result = await authenticate_ldap("alice", "wrong-password")

    assert result is None


async def test_authenticate_ldap_role_mapping() -> None:
    import json

    role_mapping = json.dumps(
        {
            "cn=noc,ou=groups,dc=example,dc=com": "noc",
            "cn=admin,ou=groups,dc=example,dc=com": "admin",
        }
    )

    entry = _mock_entry(member_of=["cn=noc,ou=groups,dc=example,dc=com"])
    svc_conn = MagicMock()
    svc_conn.entries = [entry]
    user_conn = MagicMock()

    with (
        patch("bgpeek.core.ldap.settings", _ldap_settings(ldap_role_mapping=role_mapping)),
        patch("bgpeek.core.ldap.Server"),
        patch("bgpeek.core.ldap.Connection", side_effect=[svc_conn, user_conn]),
    ):
        result = await authenticate_ldap("alice", "password")

    assert result is not None
    assert result.role == UserRole.NOC


async def test_authenticate_ldap_admin_role_wins_over_noc() -> None:
    import json

    role_mapping = json.dumps(
        {
            "cn=noc,ou=groups,dc=example,dc=com": "noc",
            "cn=admin,ou=groups,dc=example,dc=com": "admin",
        }
    )

    entry = _mock_entry(
        member_of=[
            "cn=noc,ou=groups,dc=example,dc=com",
            "cn=admin,ou=groups,dc=example,dc=com",
        ],
    )
    svc_conn = MagicMock()
    svc_conn.entries = [entry]
    user_conn = MagicMock()

    with (
        patch("bgpeek.core.ldap.settings", _ldap_settings(ldap_role_mapping=role_mapping)),
        patch("bgpeek.core.ldap.Server"),
        patch("bgpeek.core.ldap.Connection", side_effect=[svc_conn, user_conn]),
    ):
        result = await authenticate_ldap("alice", "password")

    assert result is not None
    assert result.role == UserRole.ADMIN


# ---------------------------------------------------------------------------
# upsert_ldap_user — integration tests (real PostgreSQL)
# ---------------------------------------------------------------------------


async def test_upsert_ldap_user_creates_new(pool: asyncpg.Pool) -> None:
    user = await crud.upsert_ldap_user(pool, "ldapuser", "ldap@example.com", UserRole.NOC)
    assert user.username == "ldapuser"
    assert user.email == "ldap@example.com"
    assert user.role == UserRole.NOC
    assert user.auth_provider == "ldap"
    assert user.enabled is True


async def test_upsert_ldap_user_updates_existing(pool: asyncpg.Pool) -> None:
    first = await crud.upsert_ldap_user(pool, "ldapuser", "old@example.com", UserRole.PUBLIC)
    assert first.email == "old@example.com"
    assert first.role == UserRole.PUBLIC

    second = await crud.upsert_ldap_user(pool, "ldapuser", "new@example.com", UserRole.NOC)
    assert second.id == first.id
    assert second.email == "new@example.com"
    assert second.role == UserRole.NOC
    assert second.last_login_at is not None
