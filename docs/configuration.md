# Configuration

All settings are configured via environment variables with the `BGPEEK_` prefix.
Copy `.env.example` to `.env` and adjust values for your deployment:

```bash
cp .env.example .env
```

bgpeek also reads from a `.env` file in the working directory automatically.

---

## Server

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_HOST` | `0.0.0.0` | Bind address |
| `BGPEEK_PORT` | `8000` | Listen port |
| `BGPEEK_WORKERS` | `1` | Number of Uvicorn workers |
| `BGPEEK_DEBUG` | `false` | Enable debug mode (never use in production) |

## Database

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_DATABASE_URL` | `postgresql://bgpeek:bgpeek@localhost:5432/bgpeek` | PostgreSQL connection string |
| `BGPEEK_DB_POOL_MIN` | `2` | Minimum connection pool size |
| `BGPEEK_DB_POOL_MAX` | `10` | Maximum connection pool size |
| `BGPEEK_DB_COMMAND_TIMEOUT` | `30` | SQL command timeout in seconds |
| `BGPEEK_AUTO_MIGRATE` | `true` | Run database migrations on startup |

When using Docker Compose, `BGPEEK_DATABASE_URL` is constructed automatically from `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` variables — you don't need to set it explicitly.

## Redis / Cache

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `BGPEEK_CACHE_TTL` | `60` | Query result cache TTL in seconds |

Redis is optional. If unavailable, bgpeek degrades gracefully — queries execute without caching.

## Authentication

### JWT

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_JWT_SECRET` | `change-me-in-production` | **Required.** HMAC secret for signing JWT tokens |
| `BGPEEK_JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `BGPEEK_JWT_EXPIRE_MINUTES` | `60` | Token expiration time in minutes |

Generate a strong secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Session

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_SESSION_SECRET` | `change-me-session-secret` | **Required for OIDC.** Secret for session cookie signing |
| `BGPEEK_ACCESS_MODE` | `guest` | Access mode: `closed` (login required), `guest` (anonymous with restrictions), `open` (anonymous full access) |
| `BGPEEK_PUBLIC_OUTPUT_LEVEL` | `restricted` | Output detail for public/guest users: `restricted` (hide communities/LP/MED, mask RFC1918), `standard` (all parsed fields, no raw), `full` (same as NOC) |
| `BGPEEK_MAX_PREFIX_V4` | `24` | Longest IPv4 prefix accepted at validation and kept in public output. Range 8–32. Raise to expose more-specifics (e.g. `27`) if your threat model allows it. Privileged roles bypass the output filter but input validation still applies. |
| `BGPEEK_MAX_PREFIX_V6` | `48` | Longest IPv6 prefix accepted at validation and kept in public output. Range 16–128. |

### LDAP

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_LDAP_ENABLED` | `false` | Enable LDAP authentication |
| `BGPEEK_LDAP_SERVER` | _(empty)_ | LDAP URI, e.g. `ldap://ldap.example.com:389` or `ldaps://...` |
| `BGPEEK_LDAP_BIND_DN` | _(empty)_ | Service account DN for user search |
| `BGPEEK_LDAP_BIND_PASSWORD` | _(empty)_ | Service account password |
| `BGPEEK_LDAP_BASE_DN` | _(empty)_ | Search base, e.g. `ou=people,dc=example,dc=com` |
| `BGPEEK_LDAP_USER_FILTER` | `(uid={username})` | LDAP filter; `{username}` is replaced at login |
| `BGPEEK_LDAP_USE_TLS` | `false` | Use STARTTLS on a non-SSL connection |
| `BGPEEK_LDAP_ROLE_MAPPING` | _(empty)_ | JSON mapping LDAP groups to bgpeek roles, e.g. `{"cn=noc,ou=groups,dc=ex": "noc"}` |
| `BGPEEK_LDAP_DEFAULT_ROLE` | `public` | Role assigned when no LDAP group matches |
| `BGPEEK_LDAP_EMAIL_ATTR` | `mail` | LDAP attribute containing the user's email |
| `BGPEEK_LDAP_GROUP_ATTR` | `memberOf` | LDAP attribute on user entries listing group DNs |

### OIDC

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_OIDC_ENABLED` | `false` | Enable OpenID Connect authentication |
| `BGPEEK_OIDC_CLIENT_ID` | _(empty)_ | OIDC client ID |
| `BGPEEK_OIDC_CLIENT_SECRET` | _(empty)_ | OIDC client secret |
| `BGPEEK_OIDC_SERVER_URL` | _(empty)_ | Issuer URL, e.g. `https://keycloak.example.com/realms/bgpeek` |
| `BGPEEK_OIDC_DISCOVERY_URL` | _(empty)_ | Well-known endpoint; auto-derived from `server_url` if empty |
| `BGPEEK_OIDC_SCOPES` | `openid email profile` | Space-separated list of OIDC scopes to request |
| `BGPEEK_OIDC_ROLE_CLAIM` | `realm_access.roles` | Dot-path to the roles claim in the ID token |
| `BGPEEK_OIDC_ROLE_MAPPING` | _(empty)_ | JSON mapping IdP roles to bgpeek roles, e.g. `{"bgpeek-admin": "admin", "bgpeek-noc": "noc"}` |
| `BGPEEK_OIDC_DEFAULT_ROLE` | `public` | Role assigned when no IdP role matches |

## SSH

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_SSH_USERNAME` | `looking-glass` | Default SSH username (fallback when no credential is assigned to a device) |
| `BGPEEK_KEYS_DIR` | `/etc/bgpeek/keys` | Directory containing SSH private key files |
| `BGPEEK_ENCRYPTION_KEY` | _(empty)_ | Fernet key for encrypting stored passwords in the database |
| `BGPEEK_SSH_TIMEOUT` | `30` | SSH connection and command timeout in seconds |
| `BGPEEK_SSH_TIMEOUT_TRACEROUTE` | `120` | SSH timeout for traceroute commands (they take longer) |
| `BGPEEK_SSH_KNOWN_HOSTS_POLICY` | `auto-add` | Host key policy: `auto-add` (accept new keys) or `strict` (reject unknown hosts) |

Generate an encryption key for stored credentials:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Credentials

Device credentials (SSH passwords, enable secrets) are managed via the REST API after deployment. Private keys are read from the `BGPEEK_KEYS_DIR` directory.

See the API documentation at `/docs` for the credential CRUD endpoints.

## Rate Limiting

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `BGPEEK_RATE_LIMIT_QUERY` | `30` | Max queries per minute per IP |
| `BGPEEK_RATE_LIMIT_LOGIN` | `5` | Max login attempts per minute per IP |
| `BGPEEK_RATE_LIMIT_API` | `60` | Max API calls per minute per API key |

Rate limiting requires Redis. If Redis is unavailable, rate limiting is silently disabled.

## RPKI

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_RPKI_ENABLED` | `false` | Enable RPKI validation overlay on BGP routes |
| `BGPEEK_RPKI_API_URL` | `http://routinator:8323/api/v1/validity` | Routinator RPKI validity API endpoint |
| `BGPEEK_RPKI_TIMEOUT` | `5` | API request timeout in seconds |
| `BGPEEK_RPKI_CACHE_TTL` | `3600` | Cache TTL for successful RPKI lookups (seconds) |
| `BGPEEK_RPKI_ERROR_CACHE_TTL` | `60` | Cache TTL for RPKI API errors (seconds) |

RPKI is disabled by default because bgpeek does not bundle a Routinator service.
To enable it, run Routinator and point `BGPEEK_RPKI_API_URL` to its validity endpoint.

Example:

```bash
docker run -d --name routinator \
  -p 8323:8323 \
  nlnetlabs/routinator:latest \
  server --rtr 0.0.0.0:3323 --http 0.0.0.0:8323
```

Then set:

```bash
BGPEEK_RPKI_ENABLED=true
BGPEEK_RPKI_API_URL=http://<routinator-host>:8323/api/v1/validity
```

## Circuit Breaker

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_CIRCUIT_BREAKER_ENABLED` | `true` | Enable circuit breaker for device connections |
| `BGPEEK_CIRCUIT_BREAKER_THRESHOLD` | `3` | Consecutive SSH failures before marking a device as down |
| `BGPEEK_CIRCUIT_BREAKER_COOLDOWN` | `300` | Seconds to wait before retrying a tripped device |

When the circuit breaker trips, queries to the affected device return an immediate error instead of waiting for an SSH timeout. The device is retried automatically after the cooldown period.

## Parallel Queries

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_MAX_PARALLEL_QUERIES` | `5` | Maximum concurrent SSH queries for multi-device requests |

## Device Access Control

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_DEVICE_PUBLIC_BY_DEFAULT` | `true` | If true, all devices are visible to public (unauthenticated) users unless explicitly restricted |

## Observability

### Prometheus Metrics

bgpeek exposes Prometheus-compatible metrics at `/metrics` via `prometheus-fastapi-instrumentator`. Scrape this endpoint with your Prometheus instance.

### Structured Logging

All components use `structlog` for structured JSON logging. Every request is tagged with a correlation ID propagated via the `X-Request-ID` header. If a client sends `X-Request-ID`, it is preserved; otherwise one is generated automatically.

### Health Check

`GET /api/health` returns `{"status": "ok", "version": "..."}`.

Pass `?deep=true` for a full connectivity check (PostgreSQL + Redis):

```json
{
  "status": "ok",
  "version": "1.3.1",
  "database": "ok",
  "redis": "ok"
}
```

Status is `degraded` if any backend is unreachable.

## Branding

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_PRIMARY_ASN` | _(empty)_ | Primary ASN (digits only) used for derived branding defaults and PeeringDB link generation. If unset, `site_name` falls back to `bgpeek` and the PeeringDB icon is hidden |
| `BGPEEK_BRAND_SITE_NAME` | _(empty)_ | Brand name shown in page titles and header; if empty, defaults to `AS<BGPEEK_PRIMARY_ASN> bgpeek` when `PRIMARY_ASN` is set, otherwise just `bgpeek` |
| `BGPEEK_BRAND_PAGE_TITLES` | `{}` | JSON object with per-page title suffix overrides (text after `·`) without modifying language files. Supported keys: `index`, `login`, `history`, `result_page` |
| `BGPEEK_BRAND_SITE_DESCRIPTION` | `Open-source looking glass for ISPs and IX operators` | OpenAPI/UI description text |
| `BGPEEK_BRAND_LOGO_PATH` | `/static/favicon.svg` | Logo path/URL for header and login brand icon |
| `BGPEEK_BRAND_FAVICON_PATH` | `/static/favicon.svg` | Favicon path/URL for browser tab icon |
| `BGPEEK_BRAND_THEME_STORAGE_KEY` | `bgpeek-theme` | Browser localStorage key used for dark/light preference; set a unique value per installation to isolate theme preferences between deployments |
| `BGPEEK_BRAND_FOOTER` | _(empty)_ | Optional footer HTML shown after a `·` separator; when empty, no suffix/separator is shown |
| `BGPEEK_BRAND_CUSTOM_CSS` | _(empty)_ | Optional CSS injected into the base template style block |

`BGPEEK_BRAND_PAGE_TITLES` examples:

```bash
# Override only the home page suffix:
BGPEEK_BRAND_PAGE_TITLES='{"index":"AS152183 Home"}'

# Override all supported pages:
BGPEEK_BRAND_PAGE_TITLES='{"index":"AS152183 Home","login":"sign in","history":"query history","result_page":"shared result"}'
```

## Other

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_DEFAULT_LANG` | `en` | Default UI language (must be listed in `BGPEEK_ENABLED_LANGUAGES`) |
| `BGPEEK_ENABLED_LANGUAGES` | `en,ru` | Comma-separated allow-list of language codes. Languages outside the list are ignored even if requested via `?lang=`, cookie, or `Accept-Language`. Must include `BGPEEK_DEFAULT_LANG`. Set to a single code (for example `en`) to force one language |
| `BGPEEK_LG_LINKS` | _(empty)_ | JSON array of external Looking Glass links, e.g. `[{"name": "Example LG", "url": "https://lg.example.com"}]` |
| `BGPEEK_PEERINGDB_LINK_ENABLED` | `true` | Show/hide the PeeringDB icon in the top-right header. Requires `BGPEEK_PRIMARY_ASN` to be set — if the ASN is unset, the icon is hidden regardless of this flag |
| `BGPEEK_CONFIG_DIR` | `/etc/bgpeek` | Base configuration directory |
| `BGPEEK_STATIC_DIR` | _(built-in)_ | Path to static files (override for custom themes) |
| `BGPEEK_TEMPLATES_DIR` | _(built-in)_ | Path to Jinja2 templates (override for custom UI) |
| `BGPEEK_RESULT_TTL_DAYS` | `7` | How long shared query results are kept (days) |
| `BGPEEK_AUDIT_TTL_DAYS` | `90` | Audit log retention in days; `0` keeps records forever |
| `BGPEEK_AUDIT_STDOUT` | `true` | Also emit audit entries to the structlog stream (for Loki/VictoriaLogs/Elastic ingestion). PostgreSQL row is unaffected. |

## Logging

| Variable | Default | Description |
|---|---|---|
| `BGPEEK_SERVICE_NAME` | `bgpeek` | Value used for the `service=<name>` label on every log event. Distinct per instance when multiple bgpeeks ship into one log backend; pick names like `bgpeek-fra` / `bgpeek-edge` to partition VictoriaLogs / Loki streams cleanly. |
| `BGPEEK_LOG_LEVEL` | `info` | Minimum log level: `debug`, `info`, `warning`, `error`, `critical` |
| `BGPEEK_LOG_FORMAT` | `console` | Renderer: `console` (human, colourless plain text), `json` (NDJSON, one event per line), `logfmt` (`key=value` pairs) |
| `BGPEEK_LOG_SHIP_URL` | _(empty)_ | Optional HTTP endpoint that receives batched copies of every structlog event. Empty disables shipping; `stdout` remains the always-live sink regardless |
| `BGPEEK_LOG_SHIP_FORMAT` | `ndjson` | Wire format: `ndjson` (one JSON per line), `loki` (Loki push schema), `elasticsearch` (bulk NDJSON) |
| `BGPEEK_LOG_SHIP_HEADERS` | _(empty)_ | JSON object of extra HTTP headers, e.g. `{"Authorization":"Bearer …"}` |
| `BGPEEK_LOG_SHIP_BATCH_SIZE` | `100` | Events per POST |
| `BGPEEK_LOG_SHIP_BATCH_TIMEOUT_SEC` | `2.0` | Maximum seconds an event waits in the queue before being flushed |
| `BGPEEK_LOG_SHIP_QUEUE_MAX` | `10000` | In-memory queue cap; oldest events drop first on overflow (never blocks log calls) |
| `BGPEEK_LOG_SHIP_TIMEOUT_SEC` | `5.0` | HTTP timeout for one shipping POST |
