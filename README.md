# bgpeek

[![CI](https://github.com/xeonerix/bgpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/xeonerix/bgpeek/actions/workflows/ci.yml)

Open-source looking glass for ISPs and IX operators.

## Features

- **Multi-vendor SSH** — Juniper JunOS, Cisco IOS/XE/XR, Arista EOS, Huawei VRP
- **BGP route, ping, traceroute** with structured BGP output parsing
- **RPKI validation** overlay with colored badges (valid/invalid/not-found)
- **Authentication** — API key, local password (bcrypt), LDAP, OIDC (Keycloak)
- **Role-based access** — admin, NOC (sees all routes), public (filtered /24+)
- **REST API** with OpenAPI/Swagger documentation
- **Per-role output filtering** — hides /25-/32 prefixes from public users
- **Audit log** in PostgreSQL (every query, login, device change)
- **Redis cache** with configurable TTL and graceful degradation
- **Parallel queries** across multiple devices with side-by-side diff
- **Shareable results** via UUID permalinks (7-day TTL)
- **Query history** with pagination
- **Rate limiting** — per-IP and per-user, Redis sliding window
- **DNS resolution** for hostname targets
- **Webhooks** — notify external systems on query/device/login events
- **Dark/light theme** with persistent toggle
- **i18n** — English and Russian
- **Server-rendered HTML** with HTMX + Tailwind (no SPA, no npm, ~14KB JS)
- **Single `docker compose up`** to run

## Quickstart

```bash
git clone https://github.com/xeonerix/bgpeek.git
cd bgpeek
docker compose up -d
open http://localhost:8000
```

## Configuration

All settings via environment variables with `BGPEEK_` prefix:

| Variable | Default | Description |
|----------|---------|-------------|
| `BGPEEK_DATABASE_URL` | `postgresql://bgpeek:bgpeek@localhost:5432/bgpeek` | PostgreSQL connection |
| `BGPEEK_REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `BGPEEK_JWT_SECRET` | `change-me-in-production` | JWT signing key |
| `BGPEEK_LDAP_ENABLED` | `false` | Enable LDAP auth |
| `BGPEEK_OIDC_ENABLED` | `false` | Enable OIDC auth |
| `BGPEEK_RPKI_ENABLED` | `true` | Enable RPKI validation |
| `BGPEEK_CACHE_TTL` | `60` | Query cache TTL (seconds) |
| `BGPEEK_RATE_LIMIT_QUERY` | `30` | Queries per minute per IP |
| `BGPEEK_DEFAULT_LANG` | `en` | Default UI language (en/ru) |

Full list: [`src/bgpeek/config.py`](src/bgpeek/config.py)

## Development

```bash
# install uv: https://docs.astral.sh/uv/
uv sync --extra dev
make check          # lint + format + mypy + pytest
make dev            # docker compose up (postgres + redis + bgpeek)
```

## Architecture

```
FastAPI + Jinja2 + HTMX + Tailwind CSS
         │
    ┌────┴────┐
    │ Netmiko │──── SSH ──── Routers (JunOS, IOS, XR, EOS, Huawei)
    └─────────┘
         │
    ┌────┴────┐
    │ asyncpg │──── PostgreSQL (devices, users, audit, results, webhooks)
    └─────────┘
         │
    ┌────┴────┐
    │  Redis  │──── Cache + Rate limiting + RPKI cache
    └─────────┘
```

## License

Apache-2.0. See [LICENSE](LICENSE).
