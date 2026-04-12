-- Shareable query results with UUID permalinks and configurable TTL

CREATE TABLE query_results (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         INTEGER         REFERENCES users(id) ON DELETE SET NULL,
    username        TEXT,
    device_name     TEXT            NOT NULL,
    query_type      TEXT            NOT NULL,
    target          TEXT            NOT NULL,
    command         TEXT,
    raw_output      TEXT,
    filtered_output TEXT,
    parsed_routes   JSONB           DEFAULT '[]'::jsonb,
    runtime_ms      INTEGER,
    cached          BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ     NOT NULL DEFAULT now() + interval '7 days'
);

CREATE INDEX query_results_created_at_idx ON query_results (created_at DESC);
CREATE INDEX query_results_user_id_idx ON query_results (user_id);
CREATE INDEX query_results_expires_at_idx ON query_results (expires_at);
