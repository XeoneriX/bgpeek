<div align="center">

<img src="assets/logo.svg" alt="bgpeek" width="240"/>

**Open-source looking glass for ISPs and IX operators.**

Self-hosted, multi-vendor, API-first.

[![CI](https://github.com/xeonerix/bgpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/xeonerix/bgpeek/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

</div>

## Features

**Querying**
- Multi-vendor SSH — Juniper JunOS, Cisco IOS/XE/XR, Arista EOS, Huawei VRP
- BGP route, ping, and traceroute with structured BGP output parsing
- RPKI validation overlay with colored badges (valid / invalid / not-found)
- Parallel queries across multiple devices with side-by-side diff
- DNS resolution for hostname targets
- Shareable results via UUID permalinks (configurable TTL)
- Query history with pagination

**Authentication**
- API key, local password (bcrypt), LDAP, OIDC (Keycloak)
- Role-based access — admin, NOC (sees all routes), public (filtered)
- Device-level access control (restricted devices)

**Security**
- Per-role output filtering — hides /25-/32 prefixes from public users
- Fernet-encrypted SSH credential storage
- Rate limiting — per-IP, per-user, per-API-key (Redis sliding window)
- Circuit breaker for SSH connections (configurable threshold and cooldown)
- Webhook HMAC-SHA256 signatures

**Observability**
- Audit log in PostgreSQL (queries, logins, device changes)
- Prometheus metrics endpoint (`/metrics`)
- Request correlation via `X-Request-ID` header
- Deep health check endpoint (DB + Redis connectivity)
- Periodic cleanup for expired results and audit entries

**UI**
- Server-rendered HTML with HTMX + Tailwind CSS (no SPA, no npm, ~14 KB JS)
- Dark/light theme with persistent toggle
- Internationalization-ready (English; translation scaffold in place)

**Deployment**
- Single `docker compose up` to run (PostgreSQL + Redis included)
- Auto-migration on startup
- Debian slim base image, non-root container
- `.env.example` with every setting documented

## Quickstart

```bash
git clone https://github.com/xeonerix/bgpeek.git
cd bgpeek
cp .env.example .env
# Edit .env — set at minimum:
#   POSTGRES_PASSWORD
#   BGPEEK_JWT_SECRET
docker compose up -d
open http://localhost:8000
```

### Creating the first admin

bgpeek does not auto-create an admin account. Bootstrap the first admin by
inserting a row directly, then use the admin UI / API for subsequent users:

```bash
# Generate a bcrypt hash for the password you want.
docker compose exec bgpeek python -c \
  "import bcrypt, sys; print(bcrypt.hashpw(b'<your-password>', bcrypt.gensalt()).decode())"

# Insert the admin row.
docker compose exec postgres psql -U bgpeek -c \
  "INSERT INTO users (username, email, role, auth_provider, password_hash, enabled)
   VALUES ('admin', 'admin@example.com', 'admin', 'local', '<hash-from-above>', TRUE);"
```

Alternatively, configure OIDC / LDAP and map a directory group to the `admin`
role via `BGPEEK_OIDC_ROLE_MAPPING` / `BGPEEK_LDAP_ROLE_MAPPING` — the first
login from that group lands with admin privileges.

## SSH Credentials

bgpeek manages SSH credentials as first-class entities stored in PostgreSQL with Fernet encryption. Each device can be assigned its own credential, or fall back to a global default.

- Create and manage credentials via the REST API (`/api/credentials`)
- Test connectivity before assigning: `POST /api/credentials/{id}/test?device_id=N`
- SSH private keys are read from a configurable directory (`BGPEEK_KEYS_DIR`, default `/etc/bgpeek/keys`)
- A default credential is auto-created from `BGPEEK_SSH_USERNAME` on first startup

Mount your keys directory in compose.yaml (already configured as `./secrets:/etc/bgpeek/keys:ro`).

## Configuration

All settings use environment variables with the `BGPEEK_` prefix. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_PASSWORD` | *(required)* | PostgreSQL password |
| `BGPEEK_JWT_SECRET` | *(required)* | JWT signing key |
| `BGPEEK_ENCRYPTION_KEY` | | Fernet key for encrypting stored SSH passwords |
| `BGPEEK_DATABASE_URL` | `postgresql://bgpeek:…@postgres:5432/bgpeek` | PostgreSQL connection string |
| `BGPEEK_REDIS_URL` | `redis://redis:6379/0` | Redis connection string |
| `BGPEEK_CACHE_TTL` | `60` | Query cache TTL in seconds |
| `BGPEEK_RATE_LIMIT_QUERY` | `30` | Queries per minute per IP |
| `BGPEEK_RPKI_ENABLED` | `false` | Enable RPKI validation |
| `BGPEEK_DEFAULT_LANG` | `en` | Default UI language (`en`) |

See [`.env.example`](.env.example) for the complete list with descriptions.

## API

bgpeek exposes a REST API with full OpenAPI documentation.

- Interactive Swagger UI: `http://localhost:8000/api/docs`
- Endpoints: devices, credentials, queries, audit, webhooks, users
- Authentication: pass `Authorization: Bearer <jwt>` or `X-API-Key: <key>` header

## Deployment

For production, set strong values for `POSTGRES_PASSWORD`, `BGPEEK_JWT_SECRET`, `BGPEEK_SESSION_SECRET`, and `BGPEEK_ENCRYPTION_KEY`. Put a reverse proxy (nginx, Caddy) in front for TLS.

See the [Deployment Guide](docs/deployment.md) for reverse proxy, TLS, backups, and monitoring.

## Development

```bash
# install uv: https://docs.astral.sh/uv/
uv sync --extra dev
docker compose -f compose.yaml -f compose.dev.yaml up -d
uv run pytest
```

Other make targets:

```bash
make check          # lint + format-check + mypy + pytest
make test-cov       # pytest with coverage report
make secure         # pip-audit + bandit
make dev            # docker compose up -d
```

## Architecture

```
 Browser / API client
         │
    ┌────┴────────────────────────────────────┐
    │  FastAPI + Jinja2 + HTMX + Tailwind CSS │
    └────┬──────────┬──────────┬──────────────┘
         │          │          │
    ┌────┴────┐ ┌───┴───┐ ┌───┴───┐
    │ Netmiko │ │asyncpg│ │ Redis │
    └────┬────┘ └───┬───┘ └───┬───┘
         │          │          │
      Routers    PostgreSQL   Cache, Rate
   JunOS, IOS   devices       limiting,
   XR, EOS,     credentials   RPKI cache
   Huawei VRP   users, audit
                 results,
                 webhooks
```

## Documentation

- [Configuration Reference](docs/configuration.md) — all settings with defaults
- [Deployment Guide](docs/deployment.md) — production setup, proxy, TLS, backups
- [SSH Credentials](docs/credentials.md) — per-device credential management
- [REST API](docs/api.md) — endpoints, examples, authentication
- [Changelog](CHANGELOG.md)
- [Environment reference](.env.example)

## License

[Apache-2.0](LICENSE)
