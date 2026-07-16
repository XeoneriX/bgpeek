-- Per-key action scopes (Phase 1).
--
-- Each user row may carry an explicit action whitelist. NULL preserves the
-- legacy role-based authorisation path; a non-null array enables default-deny
-- scope enforcement against the `core/scopes.matches()` rules.
--
-- The format regex must stay in sync with `_SCOPE_RE` in `core/scopes.py`.
-- This validation is defence-in-depth: even if the Pydantic validator is
-- bypassed (a future refactor, an out-of-band SQL write, a migration that
-- forgets to round-trip through the model), the storage layer still rejects
-- malformed scope strings.
--
-- Implementation note: PostgreSQL forbids subqueries directly in CHECK
-- expressions (`cannot use subquery in check constraint`), so the per-element
-- loop lives in an IMMUTABLE PL/pgSQL function and CHECK invokes it. The
-- function also returns `false` on a JSON-null array element (`[null]`) — the
-- equivalent inline pattern using `s !~ regex` would let nulls through
-- because `NULL !~ ...` is unknown, not true.

CREATE OR REPLACE FUNCTION validate_allowed_actions(actions jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    s text;
BEGIN
    IF actions IS NULL THEN
        RETURN true;
    END IF;
    IF jsonb_typeof(actions) != 'array' THEN
        RETURN false;
    END IF;
    FOR s IN SELECT value FROM jsonb_array_elements_text(actions) AS t(value) LOOP
        IF s IS NULL THEN
            RETURN false;
        END IF;
        IF s !~ '^(\*|[a-z][a-z0-9_]*((:[a-z][a-z0-9_]*)+(:\*)?|:\*))$' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS allowed_actions JSONB NULL;

COMMENT ON COLUMN users.allowed_actions IS
    'Per-key action whitelist. NULL = legacy role-based authz (unrestricted '
    'within role). Non-null array = explicit whitelist with default-deny. '
    'Format: ["resource:action", ...] with wildcards "*" or "resource:*". '
    'See core/scopes.py for validation rules.';

-- Idempotent CHECK: drop-then-add so re-running the migration on an
-- already-migrated database is a no-op rather than `duplicate_object`.
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_allowed_actions_format;

ALTER TABLE users
    ADD CONSTRAINT users_allowed_actions_format
    CHECK (validate_allowed_actions(allowed_actions));
