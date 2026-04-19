# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-04-18

### Added

- First-class branding configuration for UI identity and behavior:
  - `BGPEEK_PRIMARY_ASN` (digits-only)
  - `BGPEEK_BRAND_PAGE_TITLES` for per-page title suffix overrides
  - `BGPEEK_BRAND_FOOTER` for optional footer HTML
  - `BGPEEK_BRAND_CUSTOM_CSS` for custom CSS injection
  - `BGPEEK_PEERINGDB_LINK_ENABLED` to toggle the PeeringDB header icon
- ASN-driven defaults for branding:
  - site name defaults to `AS<PRIMARY_ASN> bgpeek` when unset
  - PeeringDB URL is derived from `BGPEEK_PRIMARY_ASN`
- PeeringDB header icon link with bundled asset at `/static/peeringdb.png`.
- Unified top-bar user menu (login/logout, guest/user label, account settings visibility).
- `Continue as guest` action on `/auth/login` when `access_mode` is `guest` or `open`.
- Russian locale translations added with English-fallback merge behavior in i18n.

### Changed

- Footer branding behavior reworked:
  - `bgpeek` + version is always visible and links to source
  - optional custom footer segment appears only when configured
  - legacy configurable source label/URL behavior removed
- Page title branding moved from a single tagline to per-page suffix mapping.
- Header/navigation behavior is consistent across index, history, and shared result pages.
- Configuration docs and examples were updated for the branding and links feature set.
- Configuration docs/examples now explicitly document session/output controls:
  - `BGPEEK_ACCESS_MODE`
  - `BGPEEK_PUBLIC_OUTPUT_LEVEL`

## [1.1.1] - 2026-04-17

### Added

- Dedicated `sixwind_os` BGP parser behavior for Cisco-like output quirks:
  - ignores non-path preamble lines under `Paths:`
  - parses `Last update:` into BGP route age

### Changed

- 6WIND BGP command templates switched to prefix form:
  - `show bgp ipv4 prefix {target}`
  - `show bgp ipv6 prefix {target}`
- RPKI integration now targets Routinator validity API format directly:
  - default API URL changed to `http://routinator:8323/api/v1/validity`
  - request URL path uses `/{origin_asn}/{prefix}`
  - response parsing uses `validated_route.validity.state`
- Webhook model and signing flow tightened for safer secret handling defaults.
- Development container hardening updates in Docker/dev compose.
- Test and documentation fixtures sanitized to reserved documentation IP/ASN ranges.

### Fixed

- 6WIND BGP parsing no longer misclassifies peer advertisement preamble lines as route paths.
- 6WIND age column population for parsed BGP routes.
- RPKI status mapping for Routinator response variants (`valid`, `invalid`, `not-found`/equivalents).
- Multiple command/parser/integration tests updated to match real 6WIND command behavior and routing output structure.

## [1.1.0] - 2026-04-16

### Added

- Community label annotations from a DB-backed catalog, including optional color badges and row highlighting in BGP results.
- BGP table enhancements: Age column support, active-route highlighting for Junos, and clearer best-path marker placement.
- UI/UX refinements for result rendering, including improved light/dark theme behavior and raw output interaction updates.
- Social preview assets for the repository.

### Changed

- Query command dispatch now auto-detects IPv4/IPv6 family from target input.
- Input handling now strips and validates target values earlier in the UI/request flow.
- Internationalization scope simplified: removed Russian locale while retaining i18n scaffolding.
- Shared Jinja template wiring centralized in `core.templates`.
- CI/release workflow dependencies updated (`actions/checkout@v6`, `astral-sh/setup-uv@v7`, `softprops/action-gh-release@v3`, and dependabot metadata tooling updates).
- Dependency baseline updated (including `asyncpg`, `bandit`, `pre-commit`, and `prometheus-fastapi-instrumentator`).

### Fixed

- Junos BGP parser improvements:
  - parse active path state correctly
  - parse `Metric:` as MED
  - strip trailing AS-path annotations (e.g. originator markers)
- BGP output handling:
  - strip leading license banners more robustly
  - return explicit "Network not in table" UX state for empty route results
- DNS target validation now rejects numeric shorthand forms that may be ambiguously resolved by `getaddrinfo`.
- Query validation hardening for ping/traceroute targets: reject unspecified, broadcast, multicast, and link-local destinations.
- Multiple BGP table presentation and copy-to-clipboard usability issues.
- Ruff formatting cleanups required for CI consistency.

## [1.0.0] - 2026-04-13

Initial public release.

### Querying

- Multi-vendor SSH support (Juniper JunOS, Cisco IOS/XE/XR, Arista EOS, Huawei VRP)
- BGP route, ping, and traceroute queries
- Structured BGP output parsing (prefix, next-hop, AS path, communities, origin, MED, local-pref)
- RPKI validation overlay via Cloudflare API (valid/invalid/not-found badges)
- Parallel multi-device queries with side-by-side diff view
- DNS resolution for hostname targets
- Shareable query results via UUID permalinks (configurable TTL)
- Query history with pagination
- Per-query-type SSH timeouts (120s for traceroute, 30s default)

### SSH Credential Management

- Credentials as a first-class entity (per-device SSH authentication)
- Support for key, password, and key+password auth types
- Fernet encryption for stored SSH passwords
- Configurable keys directory (`BGPEEK_KEYS_DIR`)
- Credential resolution chain: device-level → global default → clear error
- SSH connectivity test endpoint (`POST /api/credentials/{id}/test`)
- Auto-create default credential from global config on first startup
- Configurable host key policy (auto-accept or strict)

### Authentication & Authorization

- API key, local password (bcrypt), LDAP, OIDC (Keycloak) authentication
- JWT tokens with configurable expiry
- Cookie-based auth for web UI
- Role-based access: admin, NOC (sees all routes), public (filtered)
- Per-role output filtering — hides /25-/32 prefixes from public users
- Device-level access control (restricted devices hidden from public)

### Security

- Rate limiting per-IP, per-user, per-API-key (Redis sliding window)
- Circuit breaker for SSH connections (configurable threshold and cooldown)
- Webhook notifications with HMAC-SHA256 signatures
- Audit log in PostgreSQL (queries, logins, device changes, credential changes)
- Configurable audit log retention with automatic cleanup

### Observability

- Prometheus metrics endpoint (`/metrics`)
- Request correlation via `X-Request-ID` header
- Deep health check (`GET /api/health?deep=true` — DB + Redis connectivity)
- Structured JSON logging via structlog
- Periodic cleanup for expired results and old audit entries

### API

- Full REST API with OpenAPI/Swagger documentation
- Device inventory CRUD
- Credential CRUD with usage tracking
- Webhook CRUD with test endpoint
- User management (local, LDAP, OIDC)

### UI

- Server-rendered HTML with HTMX + Tailwind CSS (no SPA, no npm, ~14 KB JS)
- Two-column sidebar + results layout
- Dark/light theme with persistent toggle
- Internationalization (English and Russian)
- Loading spinner with abort button
- DOM growth limit (capped at 20 results)

### Deployment

- Single `docker compose up` (PostgreSQL + Redis included)
- Debian slim-based Docker image, non-root container, tini init
- Auto-migration on startup
- `.env.example` with all settings documented
- SSH keys mounted as read-only volume
- Compose uses env var references (no hardcoded credentials)
- Separate `compose.dev.yaml` for development (not auto-loaded in production)

### Documentation

- Configuration reference (all 60+ settings)
- Production deployment guide (proxy, TLS, backups, monitoring)
- SSH credential management guide
- REST API reference with curl examples

[1.2.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.2.0
[1.1.1]: https://github.com/xeonerix/bgpeek/releases/tag/v1.1.1
[1.1.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.1.0
[1.0.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.0.0
