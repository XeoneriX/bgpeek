-- Per-user JWT invalidation timestamp.
--
-- A JWT with `iat` earlier than this column's value is rejected by the auth
-- resolver (see `core/auth.py:_resolve_jwt`). Set on admin-driven password
-- reset and on `enabled=false` so all outstanding tokens for the target user
-- become invalid in a single column flip.
--
-- This is a clean alternative to per-jti revocation (which doesn't scale to
-- "kill every live session for this user" — we'd have to track every issued
-- jti). A `timestamptz` epoch is per-user state, O(1) on the write side, and
-- already covered by the `users` row read on every authenticated request.
--
-- NULL preserves prior behaviour: tokens issued before this column existed
-- are accepted as usual until they hit the natural `exp` boundary. Sessions
-- get invalidated only when an admin action explicitly bumps the column.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS sessions_valid_after TIMESTAMPTZ NULL;

COMMENT ON COLUMN users.sessions_valid_after IS
    'JWTs with iat earlier than this timestamp are rejected by the auth '
    'resolver. Bumped on admin password reset and on enabled=false. NULL = '
    'no invalidation epoch set; tokens accepted until natural expiry.';
