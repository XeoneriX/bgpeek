# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Admin device form: saving any device with `source4` or `source6` set returned a 500. `asyncpg` cannot bind a Pydantic `IPv4Address`/`IPv6Address` to the TEXT columns used for source IPs, so every save with a non-empty source IP failed with `invalid input for query argument ... expected str, got IPv4Address`. `create_device`/`update_device` now serialise the payload with `model_dump(mode="json")`, which coerces IP objects to strings (and is a no-op for the `INET` address column, which accepts both).
- Admin CRUD: whitespace-only values in required string fields (`name`, `username`, `pattern`, `label`, `url`) are now rejected with HTTP 400 instead of silently saved. Root cause was that `min_length=1` ran against the un-stripped value, so `"   "` (three spaces) passed validation and became a 303 redirect that looked like a successful save — the user got an invisible-named row. Affected models: `Device`, `Credential`, `User` (local password + API-key variants), `CommunityLabel`, `Webhook`. Fixed via a new `bgpeek.models._common.TrimmedStr` annotated type that strips whitespace *before* length validation. Passwords, API keys, and webhook HMAC secrets are intentionally left untrimmed — stripping a secret field would desync the stored hash from what the operator actually typed. Also: `Webhook.name` and `Webhook.url` were missing `min_length=1` entirely, which meant a fully empty webhook name was already being accepted; this fix adds the constraint alongside the strip.
- Admin devices list: the Health badge now correctly reflects a fresh probe failure. Previously, a device that had any prior successful session would keep rendering as `Healthy` even right after a visible `ssh connect timeout` in the logs, because the async reachability probe wrote the outcome to `audit_log` only — it never fed the circuit breaker. Now a failed probe calls `record_failure(device.name)` (and a successful one calls `record_success`), so the badge flips to amber `1/3` / red `Open` on the same evidence as a failed query would. On top of that, the list page fetches `audit_crud.recent_device_failures(pool, since_seconds=300)` and surfaces the concrete `error_message` from the most recent failed query or probe as a `title=` tooltip on the badge — operators can hover to read `ssh connect timeout` without cracking open the server logs. Devices that already recovered (latest event is a success) are excluded from the tooltip.
- `POST /auth/logout` now revokes the JWT server-side, not just the cookie. Previously, logout only cleared the `bgpeek_token` cookie — the JWT itself stayed valid until its natural `exp` (default 60 minutes), so anyone who captured the token before logout (XSS, stolen device, network snoop over non-TLS) could keep authenticating. Each mint now carries a random `jti` claim; logout decodes the cookie, pulls `jti` + `exp`, and writes `bgpeek:jwt_revoked:<jti>` to Redis with a TTL equal to the token's remaining lifetime. The auth resolver rejects tokens whose `jti` is on the blocklist with `401 token has been revoked`. Redis-unavailable falls open (logs a warning, does not lock operators out of the app) — same graceful-degradation stance as rate-limiter / circuit-breaker. Expired or tampered cookies during logout are a no-op (logout always succeeds).
- Admin forms: Save buttons now disable + swap their label to `Saving…` (EN) / `Сохраняем…` (RU) on submit. Before, the button had no visible press or loading state — the browser's navigation progress bar is the only feedback, which is easy to miss on fast internal networks, so operators would click twice. The second click either silently double-POSTed (creating a duplicate for create flows where the name was typed between clicks) or raced the redirect. Opt-in via `data-loading-text` attribute, so the inline `Delete` buttons in list views keep their label and their `confirm()` flow untouched. Applied to all five admin form types: devices, credentials, users, community labels, webhooks.
- Admin panel: creating, editing or deleting a device via `/admin/devices/*` no longer silently skips webhook delivery. Only the REST `/api/devices` paths fired `device_create`/`device_update`/`device_delete` events before; the SSR admin panel (which is what operators actually use) went directly through the CRUD layer. Parity restored — both surfaces now emit the same payload.
- Admin devices list: the Health column no longer shows `• Healthy` for devices that have never had a successful query or probe. A new `• Unknown` state (slate bullet) is shown until the first success is recorded, so newly-added unreachable devices are visibly distinguishable from devices that are actually working.

### Added

- Async SSH reachability probe on admin device save. Creating or editing a device via `/admin/devices/*` now fires a fire-and-forget SSH connect against the device in the background; the result is written to `audit_log` as a new `probe` action. The Health badge flips from `Unknown` to `Healthy` (or to the failure state) automatically within a few seconds of save, so operators see connectivity problems in the list view instead of discovering them at first query. Pending probes are drained on application shutdown.
- `BGPEEK_ENABLED_LANGUAGES` (default `en,ru`) — operator-level allow-list of UI language codes. Languages outside the list are ignored even if requested via `?lang=`, the `bgpeek_lang` cookie, or `Accept-Language` — so a deployment can serve a single language regardless of what the client advertises. `BGPEEK_DEFAULT_LANG` must be a member of the allow-list; a mismatch fails validation at startup. Translation files remain in the repo regardless — operators toggle visibility via env, not file deletion. The parsed list is also exposed to templates as a Jinja2 global (`enabled_languages`) so a future language switcher can auto-hide when `enabled_languages|length == 1`.
- `BGPEEK_ALLOWED_TARGET_TYPES` (default `ip,cidr,hostname`) — operator-level allow-list of accepted query-target kinds. Targets whose syntactic kind (classified in `core/dns.classify_target`) is not in the list are rejected with HTTP 400 before any DNS lookup or SSH work. Lets prod deployments drop `hostname` (to refuse DNS-name queries when a spoofed answer could send `ping`/`trace` to the wrong place) or `cidr` (to disallow prefix notation) without touching code. Unknown kinds in the env value fail startup validation. `BGPEEK_DNS_RESOLVE_ENABLED` is still honoured and layers on top — an operator who keeps `hostname` in the allow-list but sets `dns_resolve_enabled=false` will still get the existing "DNS resolution is disabled" rejection on hostname submission.
- `BGPEEK_DOCS_ENABLED` (default `true`) — single toggle that governs both the Swagger UI / OpenAPI schema endpoints and the `API` link in the main-site header. When set to `false`, `/api/docs` and `/api/openapi.json` return 404 AND the header link is hidden — the two move together so prod users never see a dead link, and the endpoints stay invisible to simple scanners. Previously the docs were gated behind `BGPEEK_DEBUG=true`, which meant no production user could discover them and no operator could choose to leave them on; this splits the concerns. Pair with an nginx 404 rule upstream for defense-in-depth on internal deployments.
- `BGPEEK_LOG_FORMAT` (default `console`) — selects the structlog renderer. Set to `json` for NDJSON (one event per line, ready for Loki / VictoriaLogs / Elasticsearch ingestion) or `logfmt` for `key=value` pairs. The shared processor chain (request-id correlation, ISO-8601 timestamp, log level) is applied regardless of renderer.
- `BGPEEK_LOG_LEVEL` (default `info`) — minimum log level. Events below the threshold are dropped before rendering.
- `BGPEEK_AUDIT_STDOUT` (default `true`) — mirrors each `audit_log` row to the structlog stream as a structured `audit` event. The PostgreSQL row remains the source of truth; stdout emission is additive, so external shippers (promtail, Vector, fluent-bit) can index audit alongside app logs without a separate pipeline. Set to `false` to silence audit on stdout if it creates noise.
- Native HTTP log shipper (`BGPEEK_LOG_SHIP_URL`) — optional second sink that batches structlog events and POSTs them to any HTTP endpoint. Three wire formats (`ndjson` for VictoriaLogs / raw Loki / custom webhook receivers, `loki` for the Loki push API, `elasticsearch` for `/_bulk`). Configurable batch size / timeout / queue cap; on overflow the oldest events are dropped (log calls never block). The shipper is additive: `stdout` remains the always-live sink regardless. Pending events are flushed on shutdown. Part B of the `feedback/2026-04-20-logging-pipeline-*.md` plan; Part C (OTLP exporter) is parked in the backlog.
- `BGPEEK_SERVICE_NAME` (default `bgpeek`) — every structlog event now carries a `service=<name>` field. Operators running multiple bgpeek instances (edge/core, per-region) or sharing a log backend with unrelated services can set a distinct name per deployment so VictoriaLogs / Loki stream labels partition cleanly.
- `log_shipper_started` and `log_shipper_shutdown` info lines — the HTTP log shipper now announces startup (url scrubbed of query string, format, batch size, queue cap) and shutdown (events flushed from the tail). Eliminates the 5-minute "did it start?" debug cycle an operator otherwise hits the first time they enable shipping.
- Audit-log coverage for auth endpoints. Previously `audit_log` only recorded `query` and `probe` actions, so `event:audit` dashboards (enabled by `BGPEEK_AUDIT_STDOUT`) showed only half of the system lifecycle despite `AuditAction` enumerating `LOGIN`, `LOGOUT`, `CREATE_USER`, `DELETE_USER`, etc. Web and REST login paths now record both success and failure; logout, create-user (API-key and local-password variants) and delete-user record success. Every entry carries `source_ip`, `user_agent`, and the acting user's id/role via the new `core/audit_helpers.py` context helpers.
- Audit-log coverage for device and admin-panel user CRUD. `POST /api/devices` and `PATCH`/`DELETE /api/devices/{id}` (REST) plus their admin-panel SSR equivalents (`POST /admin/devices`, `POST /admin/devices/{id}`, `POST /admin/devices/{id}/delete`) now record `create_device` / `update_device` / `delete_device` actions. Admin-panel user CRUD (`POST /admin/users`, `POST /admin/users/{id}`, `POST /admin/users/{id}/delete`) records `create_user` / `update_user` / `delete_user` with the target user captured in `error_message` (a dedicated target-user column is not yet in the schema). Device and user surfaces now produce identical audit trails regardless of which path the operator took.
- Prometheus metrics for the HTTP log shipper (exposed at `/metrics`, gated on `BGPEEK_METRICS_ENABLED`). Registered only when `BGPEEK_LOG_SHIP_URL` is set, so operators without shipping don't see perpetually-zero series: `bgpeek_log_ship_queue_depth` (gauge — current queue size, read at scrape time), `bgpeek_log_ship_events_total` (events accepted into the queue), `bgpeek_log_ship_dropped_total` (events dropped on queue overflow — primary "endpoint can't keep up" signal), `bgpeek_log_ship_delivered_total` and `bgpeek_log_ship_failed_total` (events whose batch POST succeeded / failed). `rate(bgpeek_log_ship_dropped_total[5m]) > 0` is the practical alert for silent event loss.
- `bgpeek_log_ship_queue_max` Prometheus gauge — static value set once at shipper install, exposes the configured `BGPEEK_LOG_SHIP_QUEUE_MAX`. Lets queue-utilization alerts stay self-contained (`bgpeek_log_ship_queue_depth / bgpeek_log_ship_queue_max > 0.8`) instead of hard-coding the capacity as a Grafana dashboard variable that silently drifts when an operator tunes the env var.
- Admin device form: platform-aware soft warning when `platform=juniper_junos` and both `source4` and `source6` are blank. Renders a yellow inline block under the Source addresses fieldset — non-blocking (Save still works), explains that Junos looking-glass setups typically need an explicit source IP or `ping`/`trace` leaves via an internal interface and gets dropped by uRPF at the upstream. Follow-up to the BGW1-SP-M9 case documented in `feedback/2026-04-20-ping-timeout-source-ip-and-rapid.md`. Platforms other than Junos are unaffected — empty source fields remain silent-optional.

### Changed

- `<select>` controls now render a consistent custom chevron positioned with a small gap from the right border, replacing the browser-default arrow which hugged the edge inconsistently across Chrome/Firefox/Safari. Applied to the home page Query type selector.
- Swagger UI and the OpenAPI schema are no longer gated behind `BGPEEK_DEBUG=true`. They're now controlled by the dedicated `BGPEEK_DOCS_ENABLED` (default `true`), so operators can keep them on without enabling other debug-only behaviour, and turn them off in prod without faking debug mode. Pre-existing deployments with `BGPEEK_DEBUG` set to anything are unaffected — `docs_enabled` starts on regardless — but operators who relied on `BGPEEK_DEBUG=false` silently hiding docs will now see them unless they explicitly set `BGPEEK_DOCS_ENABLED=false`.

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
