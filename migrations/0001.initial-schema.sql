-- Initial schema: devices, users, audit_log
-- yoyo migration: applied via `bgpeek-migrate` or `make migrate`

CREATE TABLE devices (
    id              SERIAL          PRIMARY KEY,
    name            TEXT            NOT NULL UNIQUE,
    address         INET            NOT NULL,
    port            INTEGER         NOT NULL DEFAULT 22 CHECK (port > 0 AND port < 65536),
    platform        TEXT            NOT NULL,
    description     TEXT,
    location        TEXT,
    enabled         BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX devices_name_idx ON devices (name);
CREATE INDEX devices_enabled_idx ON devices (enabled) WHERE enabled IS TRUE;

CREATE TABLE users (
    id              SERIAL          PRIMARY KEY,
    username        TEXT            NOT NULL UNIQUE,
    email           TEXT,
    role            TEXT            NOT NULL DEFAULT 'public'
                    CHECK (role IN ('public', 'noc', 'admin')),
    auth_provider   TEXT            NOT NULL
                    CHECK (auth_provider IN ('local', 'oidc', 'ldap', 'api_key')),
    password_hash   TEXT,
    api_key_hash    TEXT,
    enabled         BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ
);

CREATE INDEX users_username_idx ON users (username);
CREATE INDEX users_api_key_hash_idx ON users (api_key_hash) WHERE api_key_hash IS NOT NULL;

CREATE TABLE audit_log (
    id              BIGSERIAL       PRIMARY KEY,
    timestamp       TIMESTAMPTZ     NOT NULL DEFAULT now(),
    user_id         INTEGER         REFERENCES users(id) ON DELETE SET NULL,
    username        TEXT,
    user_role       TEXT,
    source_ip       INET,
    user_agent      TEXT,
    action          TEXT            NOT NULL,
    device_id       INTEGER         REFERENCES devices(id) ON DELETE SET NULL,
    device_name     TEXT,
    query_type      TEXT,
    query_target    TEXT,
    success         BOOLEAN         NOT NULL,
    error_message   TEXT,
    runtime_ms      INTEGER,
    response_bytes  INTEGER
);

CREATE INDEX audit_log_timestamp_idx ON audit_log (timestamp DESC);
CREATE INDEX audit_log_user_id_idx ON audit_log (user_id);
CREATE INDEX audit_log_action_idx ON audit_log (action);
