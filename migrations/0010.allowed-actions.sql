-- Per-key action scopes (Phase 1).
--
-- Each user row may carry an explicit action whitelist. NULL preserves the
-- legacy role-based authorisation path; a non-null array enables default-deny
-- scope enforcement against the `core/scopes.matches()` rules.
--
-- The format regex must stay in sync with `_SCOPE_RE` in `core/scopes.py`.
-- This CHECK constraint is defence-in-depth: even if the Pydantic validator
-- is bypassed (a future refactor, an out-of-band SQL write, a migration
-- that forgets to round-trip through the model), the storage layer still
-- rejects malformed scope strings.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS allowed_actions JSONB NULL;

COMMENT ON COLUMN users.allowed_actions IS
    'Per-key action whitelist. NULL = legacy role-based authz (unrestricted '
    'within role). Non-null array = explicit whitelist with default-deny. '
    'Format: ["resource:action", ...] with wildcards "*" or "resource:*". '
    'See core/scopes.py for validation rules.';

-- Idempotent CHECK constraint: drop-then-add so re-running the migration on
-- an already-migrated database is a no-op rather than `duplicate_object`.
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_allowed_actions_format;

ALTER TABLE users
    ADD CONSTRAINT users_allowed_actions_format CHECK (
        allowed_actions IS NULL
        OR (
            jsonb_typeof(allowed_actions) = 'array'
            AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(allowed_actions) AS s
                WHERE s !~ '^(\*|[a-z][a-z0-9_]*((:[a-z][a-z0-9_]*)+(:\*)?|:\*))$'
            )
        )
    );
