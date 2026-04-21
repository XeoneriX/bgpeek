"""Whitespace-only input must fail validation on all admin-CRUD models.

Before the B1 fix, a whitespace-only ``name`` (or ``username`` / ``pattern``
/ ``url``) slipped through Pydantic because ``min_length=1`` was evaluated
against the un-stripped string, and the admin SSR handler would then 303-
redirect as if the create succeeded — "200-ish on bad input". Each model
below is now backed by :class:`bgpeek.models._common.TrimmedStr`, which runs
the strip as a ``BeforeValidator`` so ``min_length`` sees the real length.

Tests also assert that the fields we deliberately *didn't* trim (passwords,
api keys, webhook secrets) still preserve leading/trailing whitespace — a
regression here would desync a stored credential from what the user types.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from bgpeek.models.community_label import CommunityLabelCreate, CommunityLabelUpdate
from bgpeek.models.credential import CredentialCreate, CredentialUpdate
from bgpeek.models.device import DeviceCreate, DeviceUpdate
from bgpeek.models.user import UserCreateLocal, UserUpdate
from bgpeek.models.webhook import WebhookCreate, WebhookUpdate


class TestDeviceWhitespace:
    def test_whitespace_only_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            DeviceCreate(name="   ", address="1.2.3.4", platform="juniper_junos")  # type: ignore[arg-type]

    def test_whitespace_around_name_trimmed(self) -> None:
        d = DeviceCreate(name="  core-rtr  ", address="1.2.3.4", platform="juniper_junos")  # type: ignore[arg-type]
        assert d.name == "core-rtr"

    def test_whitespace_only_platform_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            DeviceCreate(name="x", address="1.2.3.4", platform="   ")  # type: ignore[arg-type]

    def test_update_whitespace_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            DeviceUpdate(name="   ")


class TestCredentialWhitespace:
    def test_whitespace_only_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            CredentialCreate(name="   ", username="netops")

    def test_whitespace_only_username_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            CredentialCreate(name="prod-key", username="   ")

    def test_password_whitespace_preserved(self) -> None:
        """Passwords must not be stripped — a router admin could have a password
        with leading/trailing whitespace, and silently trimming it would desync
        the stored secret from what the operator actually entered."""
        c = CredentialCreate(
            name="x",
            username="y",
            auth_type="password",
            password="  s3cret  ",
        )
        assert c.password == "  s3cret  "  # noqa: S105 — exercises whitespace-preservation invariant

    def test_update_whitespace_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            CredentialUpdate(name="   ")


class TestUserWhitespace:
    def test_whitespace_only_username_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            UserCreateLocal(username="   ", password="abcdefgh")

    def test_password_whitespace_preserved(self) -> None:
        u = UserCreateLocal(username="alice", password="  hunter2x  ")
        assert u.password == "  hunter2x  "  # noqa: S105 — exercises whitespace-preservation invariant

    def test_update_whitespace_username_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            UserUpdate(username="   ")


class TestCommunityLabelWhitespace:
    def test_whitespace_only_pattern_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            CommunityLabelCreate(pattern="   ", label="Upstream")

    def test_whitespace_only_label_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            CommunityLabelCreate(pattern="65000:100", label="   ")

    def test_update_whitespace_label_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            CommunityLabelUpdate(label="   ")


class TestWebhookWhitespace:
    def test_whitespace_only_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            WebhookCreate(
                name="   ",
                url="https://hooks.example.com/a",
                events=["query"],  # type: ignore[list-item]
            )

    def test_whitespace_only_url_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            WebhookCreate(
                name="prod",
                url="   ",
                events=["query"],  # type: ignore[list-item]
            )

    def test_secret_whitespace_preserved(self) -> None:
        w = WebhookCreate(
            name="prod",
            url="https://hooks.example.com/a",
            events=["query"],  # type: ignore[list-item]
            secret="  hmac-key  ",
        )
        assert w.secret == "  hmac-key  "  # noqa: S105 — exercises whitespace-preservation invariant

    def test_update_whitespace_name_rejected(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            WebhookUpdate(name="   ")
