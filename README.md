# bgpeek

[![CI](https://github.com/xeonerix/bgpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/xeonerix/bgpeek/actions/workflows/ci.yml)

Open-source looking glass for ISPs and IX operators.

## Features

- Multi-vendor SSH (Juniper, Cisco, Arista, Huawei, FRR, BIRD, …)
- BGP route, ping, traceroute
- OIDC, LDAP, and API key authentication
- REST API with OpenAPI/Swagger
- Per-role output filtering (NOC sees everything, public sees aggregate prefixes)
- Bogon and prefix-length input validation
- Audit log in PostgreSQL
- Server-rendered HTML with HTMX (no SPA, no npm)
- Single `docker compose up` to run

## Quickstart

```bash
git clone https://github.com/xeonerix/bgpeek.git
cd bgpeek
docker compose up -d
open http://localhost:8000
```

## Development

```bash
# install uv: https://docs.astral.sh/uv/
uv sync --extra dev
uv run pytest
uv run ruff check
uv run mypy src
```

## Configuration

bgpeek reads configuration from environment variables (prefix `BGPEEK_`). See
[`src/bgpeek/config.py`](src/bgpeek/config.py) for the full list.

## License

Apache-2.0. See [LICENSE](LICENSE).
