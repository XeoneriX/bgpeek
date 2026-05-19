"""Tests for bgpeek.core.scopes — format validation, matching, subsumption."""

from __future__ import annotations

import pytest

from bgpeek.core.scopes import (
    Action,
    matches,
    subsumes,
    validate_scope_string,
    warn_unknown_actions,
)


class TestValidateScopeString:
    """Format validator (T3, T5 defence)."""

    @pytest.mark.parametrize(
        "scope",
        [
            "*",
            "users:create",
            "users:read",
            "users:*",
            "query:history:read",
            "query:history:*",
            "query:*",
            "users:actions:update",
            "community_labels:read",  # underscore in identifier
            "community_labels:write",
        ],
    )
    def test_well_formed_scopes_pass(self, scope: str) -> None:
        assert validate_scope_string(scope) is True

    @pytest.mark.parametrize(
        "scope",
        [
            "",  # empty string
            "users",  # bare resource — must require an action
            "users:",  # trailing colon
            ":create",  # leading colon (no resource)
            "users::create",  # empty namespace segment
            "users:create:",  # trailing colon after action
            "Users:Create",  # uppercase
            "USERS:CREATE",
            "users:create OR 1=1",  # SQL-injection-ish payload
            "users:cre ate",  # whitespace inside action
            " users:create",  # leading whitespace
            "users:create ",  # trailing whitespace
            "users:create;rm -rf",  # shell-injection-ish payload
            # Cross-resource action wildcard rejected at format layer (T5).
            # Pydantic in models/user.py adds a redundant explicit guard for
            # belt-and-suspenders, but format alone is sufficient.
            "*:create",
            "*:*",
            "1users:create",  # leading digit on resource
            "users:1create",  # leading digit on action
            "users-admin:create",  # hyphens not in alphabet
            "users.admin:create",  # dots not in alphabet
            "_users:create",  # leading underscore
        ],
    )
    def test_malformed_scopes_rejected(self, scope: str) -> None:
        assert validate_scope_string(scope) is False


class TestMatches:
    """Scope satisfaction."""

    @pytest.mark.parametrize(
        ("allowed", "required", "expected"),
        [
            # Exact matches
            (["users:create"], "users:create", True),
            (["users:create"], "users:read", False),
            # Single-level wildcard
            (["users:*"], "users:create", True),
            (["users:*"], "users:read", True),
            (["users:*"], "users:delete", True),
            (["users:*"], "devices:read", False),
            # Multi-segment wildcards (namespace prefix)
            (["query:history:*"], "query:history:read", True),
            (["query:history:*"], "query:history:write", True),
            (["query:history:*"], "query:execute", False),
            (["query:*"], "query:history:read", True),
            (["query:*"], "query:execute", True),
            # Full wildcard
            (["*"], "users:create", True),
            (["*"], "anything:at:all", True),
            # Empty allowed list = deny-all
            ([], "users:create", False),
            ([], "*", False),
            # Multiple scopes — match if any element covers
            (["users:create", "users:read"], "users:read", True),
            (["users:create", "users:read"], "users:delete", False),
            # Wildcard alongside specific
            (["users:*", "devices:read"], "devices:read", True),
            (["users:*", "devices:read"], "devices:write", False),
            # `users:*` matches deeper namespacing — documented behaviour
            (["users:*"], "users:actions:update", True),
        ],
    )
    def test_matches(self, allowed: list[str], required: str, expected: bool) -> None:
        assert matches(allowed, required) is expected


class TestSubsumes:
    """Subsumption — caller permission to grant scopes (T1, T1', T4 defence)."""

    def test_unrestricted_admin_grants_anything(self) -> None:
        assert subsumes(None, None) is True
        assert subsumes(None, ["users:create"]) is True
        assert subsumes(None, []) is True
        assert subsumes(None, ["*"]) is True

    def test_scoped_caller_cannot_grant_unrestricted(self) -> None:
        # T1: critical defence — scoped admin cannot mint a god-mode account.
        assert subsumes(["users:create"], None) is False
        assert subsumes(["*"], None) is False
        assert subsumes([], None) is False

    def test_scoped_caller_can_grant_subset_of_own_scopes(self) -> None:
        assert subsumes(["users:create"], ["users:create"]) is True
        assert subsumes(["users:create", "users:read"], ["users:create"]) is True
        assert subsumes(["users:create", "users:read"], ["users:read"]) is True
        # Subset including both
        assert (
            subsumes(
                ["users:create", "users:read", "users:update"],
                ["users:create", "users:read"],
            )
            is True
        )

    def test_wildcard_caller_grants_specific_within_namespace(self) -> None:
        assert subsumes(["users:*"], ["users:create"]) is True
        assert subsumes(["users:*"], ["users:create", "users:read"]) is True
        assert subsumes(["users:*"], ["users:*"]) is True

    def test_scoped_caller_cannot_grant_wider(self) -> None:
        # Caller has only one specific scope — cannot grant the wildcard
        # that would also include actions they don't have.
        assert subsumes(["users:create"], ["users:*"]) is False
        # Cannot grant cross-resource scope the caller doesn't hold.
        assert subsumes(["users:create"], ["devices:read"]) is False
        assert subsumes(["users:create"], ["users:create", "devices:read"]) is False

    def test_empty_caller_grants_only_empty(self) -> None:
        # Deny-all caller — cannot grant any specific scope. Empty grant
        # is vacuously subsumed (`all([])` is True), which is acceptable
        # because such a caller would already be blocked by `scope_gate`
        # on the create endpoint itself (no `users:create` scope = 403
        # before subsumption is even checked).
        assert subsumes([], ["users:create"]) is False
        assert subsumes([], []) is True

    def test_full_wildcard_caller_grants_anything_well_formed(self) -> None:
        # `*` caller is effectively unrestricted within the scope mechanism,
        # but still cannot mint an unrestricted (`None`) user — that's a
        # mode change, not a wider scope.
        assert subsumes(["*"], ["users:create"]) is True
        assert subsumes(["*"], ["devices:write", "audit:read"]) is True
        assert subsumes(["*"], None) is False  # T1 still applies


class TestWarnUnknownActions:
    """T10 — operator typo detector via structured warn-log.

    bgpeek's structlog uses ``PrintLoggerFactory`` (writes directly to stdout,
    not via stdlib ``logging``), so ``capsys`` is the correct capture fixture.
    """

    def test_known_actions_silent(self, capsys: pytest.CaptureFixture[str]) -> None:
        warn_unknown_actions([Action.USERS_CREATE.value, Action.USERS_READ.value])
        captured = capsys.readouterr()
        assert "scope_not_in_action_registry" not in captured.out

    def test_wildcards_silent(self, capsys: pytest.CaptureFixture[str]) -> None:
        # Wildcards are intentional, not typos.
        warn_unknown_actions(["*", "users:*", "query:history:*"])
        captured = capsys.readouterr()
        assert "scope_not_in_action_registry" not in captured.out

    def test_unknown_action_warns(self, capsys: pytest.CaptureFixture[str]) -> None:
        warn_unknown_actions(["users:creat"])  # typo
        captured = capsys.readouterr()
        assert "scope_not_in_action_registry" in captured.out
        assert "users:creat" in captured.out

    def test_mixed_known_and_unknown(self, capsys: pytest.CaptureFixture[str]) -> None:
        warn_unknown_actions([Action.USERS_CREATE.value, "users:creat", Action.USERS_READ.value])
        captured = capsys.readouterr()
        # Only the typo triggers — once.
        assert captured.out.count("scope_not_in_action_registry") == 1
        assert "users:creat" in captured.out


def test_action_enum_values_are_well_formed() -> None:
    """Sanity check: every Action enum value passes its own format validator."""
    for action in Action:
        assert validate_scope_string(action.value), f"{action.value!r} fails format check"
