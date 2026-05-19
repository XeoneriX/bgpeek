"""Action scopes for fine-grained API authorization.

Format: ``resource:action`` or ``resource:sub:action`` (namespacing).
Wildcards: ``resource:*``, ``resource:sub:*``, ``*`` (full).
NOT allowed (Phase 1): ``*:action``, regex, negation, mixed case, bare resource
(``users`` without an action).

Two semantic modes coexist on the ``users.allowed_actions`` column:
* ``None`` (NULL) — legacy role-based authz; the user's role grants whatever
  the existing ``require_role`` / ``require_admin`` dependencies allow.
* non-null list — explicit whitelist. Default-deny: an action that does not
  match any element is denied. An empty list grants nothing.

The known action vocabulary is enumerated by :class:`Action`. Operators may
store any well-formed scope string (typo-tolerance for forward-compat with
endpoints added in later releases), but :func:`warn_unknown_actions` flags
strings outside the registry as a likely operator typo.
"""

from __future__ import annotations

import re
from enum import StrEnum

import structlog

log = structlog.get_logger(__name__)

# Strict format. A bare resource without an action ("users") is invalid — the
# form is always `resource:action` (or deeper namespacing), with the optional
# final segment being a literal `*` for namespace wildcards. The first
# alternative covers the full wildcard `*` alone.
#
# Identifier alphabet: `[a-z][a-z0-9_]*` — lowercase letters, digits, and
# underscores. Underscores let composite resource names like
# `community_labels` read naturally without sacrificing the strict character
# class (no whitespace, hyphens, dots, or shell-meaningful characters).
#
# Verified pass/fail cases (mirrored in test_scopes.py):
#   pass: "*", "users:create", "query:history:read", "users:*",
#         "query:history:*", "community_labels:read"
#   fail: "users", "users:", ":create", "users::create", "users:create:",
#         "Users:Create", "*:create", "users:create OR 1=1", "users:cre ate",
#         "users-admin:create", "users.admin:create", ""
_SCOPE_RE: re.Pattern[str] = re.compile(
    r"^(?:\*|[a-z][a-z0-9_]*(?:(?::[a-z][a-z0-9_]*)+(?::\*)?|:\*))$"
)


class Action(StrEnum):
    """Known action identifiers used to tag protected endpoints.

    Stored scopes do not have to belong to this enum — operators can store
    any well-formed scope string for forward-compatibility — but unknown
    scopes trigger a warn-log at write time as a typo detector.
    """

    USERS_CREATE = "users:create"
    USERS_READ = "users:read"
    USERS_UPDATE = "users:update"
    USERS_DELETE = "users:delete"
    USERS_ACTIONS_UPDATE = "users:actions:update"
    USERS_RESET_PASSWORD = "users:reset_password"  # noqa: S105 — scope identifier, not a password

    DEVICES_READ = "devices:read"
    DEVICES_CREATE = "devices:create"
    DEVICES_UPDATE = "devices:update"
    DEVICES_DELETE = "devices:delete"

    CREDENTIALS_READ = "credentials:read"
    CREDENTIALS_CREATE = "credentials:create"
    CREDENTIALS_UPDATE = "credentials:update"
    CREDENTIALS_DELETE = "credentials:delete"

    WEBHOOKS_READ = "webhooks:read"
    WEBHOOKS_CREATE = "webhooks:create"
    WEBHOOKS_UPDATE = "webhooks:update"
    WEBHOOKS_DELETE = "webhooks:delete"

    COMMUNITY_LABELS_READ = "community_labels:read"
    COMMUNITY_LABELS_WRITE = "community_labels:write"

    QUERY_EXECUTE = "query:execute"
    QUERY_HISTORY_READ = "query:history:read"

    AUDIT_READ = "audit:read"

    SETTINGS_READ = "settings:read"
    SETTINGS_WRITE = "settings:write"

    ADMIN_DASHBOARD = "admin:dashboard"


def validate_scope_string(s: str) -> bool:
    """Strict format validation. Used at write time (Pydantic validator + DB CHECK)."""
    return bool(_SCOPE_RE.fullmatch(s))


def matches(allowed: list[str], required: str) -> bool:
    """Check whether ``required`` is satisfied by the ``allowed`` whitelist.

    Caller must have already established that ``allowed`` is the non-null
    whitelist semantic — a ``None`` ``allowed_actions`` means "legacy
    role-based authz" and is decided elsewhere.

    An empty list grants nothing (deny-all).

    Returns True for: exact match, ``*`` (full wildcard), or a namespace
    prefix wildcard (``resource:*`` matches ``resource:create``;
    ``query:history:*`` matches ``query:history:read``; ``query:*`` also
    matches ``query:history:read``). Does not match the cross-resource form
    ``*:action`` — that form is forbidden in Phase 1.
    """
    if not allowed:
        return False
    if "*" in allowed or required in allowed:
        return True
    parts = required.split(":")
    for i in range(1, len(parts)):
        prefix = ":".join(parts[:i]) + ":*"
        if prefix in allowed:
            return True
    return False


def subsumes(
    caller_actions: list[str] | None,
    granted_actions: list[str] | None,
) -> bool:
    """True iff ``caller`` may grant ``granted`` to another user.

    * ``caller=None`` (unrestricted admin) — may grant anything, including
      ``None`` (legacy admin promotion).
    * ``caller=non-null`` — may grant only a subset of own scopes. May NOT
      grant ``None`` (would be privilege escalation: scoped caller cannot
      mint an unrestricted user).
    * ``granted=None`` with ``caller=non-null`` — always False (T1 guard).
    * Empty ``granted`` — vacuously subsumed (deny-all is always weaker).

    Used at: ``POST /api/users``, ``PATCH /api/users/{id}`` (role/scope
    mutation), and Phase 2's ``PATCH /api/users/{id}/actions``.
    """
    if caller_actions is None:
        return True
    if granted_actions is None:
        return False
    return all(matches(caller_actions, g) for g in granted_actions)


def warn_unknown_actions(scope_strings: list[str]) -> None:
    """Emit a structured warn for any scope outside :class:`Action`.

    Wildcards are intentionally excluded — they're a deliberate operator
    choice, not a typo. Bare unknown leaves (``users:creat``) are flagged so
    operators see the mismatch in stdout instead of silently getting deny-all
    for the action they meant to grant.

    Caller invokes this AFTER format validation has already passed, so every
    scope is well-formed; this function only checks vocabulary.
    """
    known = {a.value for a in Action}
    for s in scope_strings:
        if "*" in s:
            continue
        if s not in known:
            log.warning(
                "scope_not_in_action_registry",
                scope=s,
                hint="check for typo or future-dated scope",
            )
