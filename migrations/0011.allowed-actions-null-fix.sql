-- Tighten the users.allowed_actions CHECK to also reject JSON null elements.
--
-- The 0010 constraint relied on `s !~ regex` to fail; in PostgreSQL,
-- `NULL !~ anything` is NULL (unknown), and `WHERE NULL` excludes the row from
-- the inner result, so `NOT EXISTS` evaluated to true and `[null]` JSONB
-- arrays slipped past the constraint via direct SQL. The Pydantic validator
-- on the API path already rejects `[None]` (only str elements pass), so the
-- column was never reached with a null element through any caller — but the
-- migration's stated purpose is defence-in-depth, and this case slipped past.
-- Adding `s IS NULL` to the WHERE makes the rejection explicit.

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_allowed_actions_format;

ALTER TABLE users
    ADD CONSTRAINT users_allowed_actions_format CHECK (
        allowed_actions IS NULL
        OR (
            jsonb_typeof(allowed_actions) = 'array'
            AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(allowed_actions) AS s
                WHERE s IS NULL
                   OR s !~ '^(\*|[a-z][a-z0-9_]*((:[a-z][a-z0-9_]*)+(:\*)?|:\*))$'
            )
        )
    );
