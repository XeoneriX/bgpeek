# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `BGPEEK_ACCEPT_BARE_IP_LOOKUP` (default `true`) — accept bare host addresses (e.g. `8.8.8.8`, `2001:4860:4860::8888`) as BGP query targets. The router performs longest-prefix-match and returns whichever covering prefix exists. The output filter still enforces `BGPEEK_MAX_PREFIX_V4/V6` on the response, so the prefix-length invariant holds for unprivileged roles. Set to `false` to restore pre-1.3.2 strict behaviour.
- UI hint when LPM match is hidden: if a bare-IP lookup resolves to a prefix more specific than the public cutoff, the result view now shows "Match hidden at your output level" instead of a silent empty result. Privileged roles (admin/NOC) still see the full entry.

### Fixed

- Bare IPv4 and IPv6 addresses are no longer rejected as "prefix too specific" at the input stage. This matched the behaviour of every other Looking Glass (hyperglass, alice-lg, vendor-native LGs) and blocked the common NetOps workflow of "I have an address, show me its BGP route." The security invariant — no /25+ routes visible to unprivileged roles — is preserved by the existing output filter.

## [1.3.1] - 2026-04-19

### Added

- `BGPEEK_MAX_PREFIX_V4` (default `24`, range 8–32) and `BGPEEK_MAX_PREFIX_V6` (default `48`, range 16–128) — the previously hardcoded cutoff for input validation and public output filtering is now configurable. Operators can raise the limit to expose more-specifics (e.g. `/27`) if their threat model allows it. Defaults are unchanged.

### Fixed

- `BGPEEK_PUBLIC_OUTPUT_LEVEL=restricted` now correctly hides fields from both UI and JSON responses. Previously the level stripped communities, local_pref and MED from `parsed_routes` but left them intact in `filtered_output` (the CLI text), so unprivileged users still saw them via the "Show raw" toggle in the UI and via the JSON field in the API.

## [1.3.0] - 2026-04-19

### Added

- Admin panel: web UI for managing devices, SSH credentials, users, community labels, and webhooks (CRUD for each).
- Admin panel extras:
  - per-device query stats on the devices list
  - circuit breaker status per device
  - "Query this device" quick link from the devices list
  - "Test SSH" button on the device edit form
  - community labels count on the landing page
- `AGENTS.md` — guidance file for AI coding agents and human contributors (stack, layout, hard rules, workflow, adding a vendor platform, security notes).

### Changed

- `BGPEEK_PRIMARY_ASN` is now optional. When unset, `site_name` falls back to just `bgpeek` (no `AS<N>` prefix) and the PeeringDB icon is hidden regardless of `BGPEEK_PEERINGDB_LINK_ENABLED`. Behaviour is unchanged when the ASN is set.
- Dev workflow: `compose.dev.yaml` now bundles a `tailwind` watcher container that rebuilds `static/css/tailwind.css` on template changes. No host `tailwindcss` binary required.

### Fixed

- Security: queries against devices flagged as `restricted` are no longer executed for unprivileged callers. Previously the device was correctly hidden from the dropdown and the REST device listing, but `POST /query` with a known-or-guessed name would still run the SSH command. Unprivileged callers now get the same "not found" response as for a non-existent device.

### Internal

- Device form UX: platform selector as a proper `<select>`, source v4/v6 fields stacked for readability.

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

[1.3.1]: https://github.com/xeonerix/bgpeek/releases/tag/v1.3.1
[1.3.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.3.0
[1.2.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.2.0
[1.1.1]: https://github.com/xeonerix/bgpeek/releases/tag/v1.1.1
[1.1.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.1.0
[1.0.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.0.0
