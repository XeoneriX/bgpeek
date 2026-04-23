# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2026-04-23

### Breaking

- **CSRF enforcement on cookie-authenticated web forms.** `/auth/login`, `/auth/logout`, `/account/settings/*`, and every `/admin/*` POST now require a `csrf_token` form field that matches a signed cookie issued on the preceding `GET`. External automation that scripted web-form logins must either switch to `POST /api/auth/login` (REST endpoint, JSON payload, cookie-less, CSRF-exempt) or perform the full `GET /auth/login → extract csrf_token → POST with token + cookie` dance. The REST API is unaffected.
- **`POST /api/users` response shape is now `UserCreated`**, not `UserAdmin`. `UserCreated` extends `UserAdmin` with an `api_key` field that carries the plaintext key exactly once — callers reading only the pre-existing fields continue to work, but clients that asserted response-model equality against `UserAdmin` will see an extra field.
- **`BGPEEK_ENCRYPTION_KEY` is now required in non-debug mode.** An unset or malformed key causes `SystemExit(1)` at startup. Previously an empty value silently fell through to plaintext storage of SSH credentials. Deployments that relied on the old fallback must set a Fernet key generated with `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'` before upgrading.

### Security

- **C1 — `BGPEEK_ENCRYPTION_KEY` startup gate.** Non-debug mode now refuses to start without a valid Fernet key; a malformed key is also a fatal validation error. (See Breaking.) Threat-model §9 stated SSH credentials are Fernet-encrypted — previously the app would silently store them in plaintext when the key was missing.
- **C2 — Identity-provider upsert is scoped to `auth_provider`.** LDAP and OIDC upserts previously resolved `ON CONFLICT (username) DO UPDATE` unconditionally, so a directory returning `role=admin` for a username already owned by another provider would silently overwrite the row's role/email. The WHERE clause now guards by provider; a cross-provider collision raises `IdentityProviderConflictError` and maps to 409 (REST) or a neutral 401 (OIDC callback). Both provider names are recorded in the audit row.
- **H1 — Result retrieval scoped to caller identity.** `/api/results/{id}` and `/result/{id}` returned any stored result by UUID. With a stolen or guessed UUID a caller could read metadata (device name, target, command) and — with `BGPEEK_PUBLIC_OUTPUT_LEVEL=full` — raw SSH output. ADMIN/NOC continue to see everything; everyone else sees only results their own `user_id` produced. Mismatch returns 404 so callers cannot enumerate other users' UUIDs by status code.
- **H2 — `device.restricted` is joined at retrieve time.** Stored results previously consulted only `public_output_level` on retrieve, so a permalink to a result produced against a restricted device leaked device name, command text, and vendor fingerprint to PUBLIC callers. `get_result` now LEFT JOINs `devices` and `_may_view_stored_result` rejects restricted devices for non-privileged callers. Flipping a device to restricted immediately hides previously-public permalinks; orphaned rows (device renamed/deleted) default to restricted.
- **H3 — `/history` guest/anonymous leak closed.** The handler fell through to `list_results(user_id=None)` for callers without a real user row, returning the most recent 25 results across every user filtered only by `public_output_level`. Anonymous / guest / `BGPEEK_ACCESS_MODE=open` callers now see an empty list; the admin-oversight path keeps its own entry point.
- **H4 — LDAP empty-password bind rejected.** Some directories accept `Connection(password="")` as an unauthenticated bind and return success. `_authenticate_sync` now guards at the door and `LoginRequest.password` carries `min_length=1`. Local bcrypt auth was unaffected.
- **H5 — LDAP StartTLS negotiated before bind.** `start_tls()` previously ran after `bind()`, so the bind DN + password crossed the socket in plaintext on `ldap://` servers with `BGPEEK_LDAP_USE_TLS=true`. Both service-account and user-bind paths now open the connection, negotiate TLS, and only then bind.
- **H6 — Webhook delivery pinned to pre-validated address.** `validate_webhook_delivery_target` resolved the hostname and checked the result, but httpx then re-resolved when it issued the POST; under a low-TTL DNS rebind the two lookups could diverge and the request would land on `127.0.0.1`, `169.254.169.254`, or an internal service. `resolve_and_pin_webhook_target` now resolves once, validates every returned address, and returns a pinned IP-literal URL. The delivery path sends to the IP, passes `Host: <original>` so virtual-hosted receivers still route correctly, and forwards `sni_hostname` via httpx request extensions so TLS cert verification keeps matching the hostname.
- **H7 — Secret redactor in shared structlog chain.** A stray `log.info(..., password=x)` or an asyncpg/netmiko traceback carrying credential arguments would reach the remote log shipper verbatim. A substring-keyed redactor replaces the value (not the key) of any field whose name contains `password`, `passwd`, `api_key`, `apikey`, `secret`, `token`, `authorization`, `auth_header`, `encryption_key`, `bind_password`, `client_secret`, `jwt_secret`, `session_secret`, or `cookie` with `***`.
- **`/auth/logout` now revokes the JWT server-side.** Each token carries a random `jti` claim; logout decodes the cookie, extracts `jti` + `exp`, and writes `bgpeek:jwt_revoked:<jti>` to Redis with a TTL equal to the remaining lifetime. The auth resolver rejects tokens whose `jti` is on the blocklist with `401 token has been revoked`. Redis-unavailable falls open (same graceful-degradation stance as rate-limiter / circuit-breaker); expired or tampered cookies during logout are a no-op.
- **CSRF protection via [`fastapi-csrf-protect`](https://pypi.org/project/fastapi-csrf-protect/).** See Breaking for the enforcement scope. Defence against an attacker who lures an authenticated operator to a hostile page that POSTs to `/admin/devices/{id}/delete` (and similar) — the missing signed-cookie pair now yields HTTP 400.
- **M1 — Server-side API-key generation.** See Deprecated. Enforces the show-once pattern and prevents two deployments from sharing the SHA-256 of a reused key.
- **M4 — Webhook SSRF blocklist widened.** `http://0/` resolves to `0.0.0.0` → delivered to `127.0.0.1` on Linux; `http://[::]/` behaves the same on IPv6. `0.0.0.0/8`, `::/128`, `224.0.0.0/4`, `240.0.0.0/4`, and `ff00::/8` added to `_BLOCKED_NETWORKS`.
- **L11 — Startup warning on `BGPEEK_COOKIE_SECURE=false` in non-debug.** Previously silent; operators behind TLS who forgot to flip the flag would ship insecure session cookies without any signal. Sits alongside the existing JWT/SESSION secret checks.
- **`Server: uvicorn` fingerprint stripped at the transport layer.** `uvicorn.run(server_header=False)` stops the header from being written in the first place. A prior middleware-only strip passed unit tests because `TestClient` bypasses the protocol layer, but real `nuclei` scans still saw `uvicorn` on the wire.
- **`Content-Security-Policy` header on every response** except `/api/docs` (Swagger UI loads its JS from a CDN and strict `script-src 'self'` would brick the docs page). Defence-in-depth against stored-XSS via `brand.custom_css` / `brand.footer` — those are `| safe`-rendered so admins can style the LG, and a compromised admin account could inject malicious markup; the CSP caps the blast radius.

### Added

- **Account settings page (`/account/settings`)** for authenticated users to self-manage email and password. Local-auth users only; OIDC/LDAP accounts see a read-only view with a provider note.
- **Branded API documentation page (`/api/docs`)** with the app's dark-mode styling, replacing the default Swagger UI layout. Gated on `BGPEEK_DOCS_ENABLED` (404 when disabled).
- **`BGPEEK_ENABLED_LANGUAGES`** (default `en,ru`) — operator-level allow-list of UI language codes. Languages outside the list are ignored even if requested via `?lang=`, the `bgpeek_lang` cookie, or `Accept-Language`. `BGPEEK_DEFAULT_LANG` must be a member of the allow-list; a mismatch fails validation at startup. Also exposed as a Jinja global (`enabled_languages`) so a future language switcher can auto-hide when the list has length 1. Translation files remain in the repo regardless — operators toggle visibility via env, not file deletion.
- **`BGPEEK_ALLOWED_TARGET_TYPES`** (default `ip,cidr,hostname`) — operator-level allow-list of accepted query-target kinds. Targets whose syntactic kind (classified in `core/dns.classify_target`) is not in the list are rejected with HTTP 400 before any DNS lookup or SSH work. Lets prod deployments drop `hostname` (to refuse DNS-name queries where a spoofed answer could send `ping`/`trace` to the wrong place) or `cidr` (to disallow prefix notation) without touching code.
- **`BGPEEK_DOCS_ENABLED`** (default `true`) — single toggle that governs both the Swagger/OpenAPI endpoints and the `API` link in the main-site header. Previously the docs were gated behind `BGPEEK_DEBUG=true`; this splits the concerns.
- **`BGPEEK_LOG_FORMAT`** (default `console`) — selects the structlog renderer (`console` / `json` / `logfmt`). The shared processor chain (request-id correlation, ISO-8601 timestamp, log level) is applied regardless of renderer.
- **`BGPEEK_LOG_LEVEL`** (default `info`) — minimum log level. Events below the threshold are dropped before rendering.
- **`BGPEEK_AUDIT_STDOUT`** (default `true`) — mirrors each `audit_log` row to the structlog stream as a structured `audit` event. The PostgreSQL row remains the source of truth; stdout emission is additive.
- **Native HTTP log shipper** (`BGPEEK_LOG_SHIP_URL`) — optional second sink that batches structlog events and POSTs them to any HTTP endpoint. Three wire formats (`ndjson` for VictoriaLogs / raw Loki / custom receivers, `loki` for the Loki push API, `elasticsearch` for `/_bulk`). Configurable batch size / timeout / queue cap; on overflow the oldest events are dropped (log calls never block). Pending events are flushed on shutdown.
- **`BGPEEK_SERVICE_NAME`** (default `bgpeek`) — every structlog event now carries a `service=<name>` field for multi-instance deployments sharing a log backend.
- **`log_shipper_started` / `log_shipper_shutdown` info lines** — the HTTP log shipper announces startup (url scrubbed of query string, format, batch size, queue cap) and shutdown (events flushed from the tail).
- **Audit-log coverage for auth endpoints** — login success/failure, logout, create-user (both API-key and local-password variants), delete-user. Every entry carries `source_ip`, `user_agent`, and the acting user's id/role via the new `core/audit_helpers.py` context helpers.
- **Audit-log coverage for device + admin-panel user CRUD** — REST and SSR paths now produce identical audit trails.
- **Prometheus metrics for the HTTP log shipper** (exposed at `/metrics`, gated on `BGPEEK_METRICS_ENABLED`). Registered only when `BGPEEK_LOG_SHIP_URL` is set: `bgpeek_log_ship_queue_depth`, `bgpeek_log_ship_events_total`, `bgpeek_log_ship_dropped_total`, `bgpeek_log_ship_delivered_total`, `bgpeek_log_ship_failed_total`. `rate(bgpeek_log_ship_dropped_total[5m]) > 0` is the practical alert for silent event loss.
- **`bgpeek_log_ship_queue_max` gauge** — static value set once at shipper install, exposes the configured `BGPEEK_LOG_SHIP_QUEUE_MAX`. Lets queue-utilisation alerts stay self-contained (`bgpeek_log_ship_queue_depth / bgpeek_log_ship_queue_max > 0.8`) instead of hard-coding the capacity as a Grafana dashboard variable.
- **Async SSH reachability probe on admin device save.** Creating or editing a device via `/admin/devices/*` fires a fire-and-forget SSH connect; the result is written to `audit_log` as a new `probe` action and feeds the circuit breaker. The Health badge flips from `Unknown` to `Healthy` (or the failure state) within a few seconds of save. Pending probes are drained on shutdown.
- **Admin device form: platform-aware soft warning** when `platform=juniper_junos` and both `source4` and `source6` are blank. Non-blocking — Save still works — but explains that Junos looking-glass setups typically need an explicit source IP or `ping`/`trace` leaves via an internal interface and gets dropped by uRPF upstream.
- **`Unknown` health state** — admin devices list. A new slate-bullet state shown until the first success is recorded, so newly-added unreachable devices are visibly distinguishable from devices that are actually working.
- **Health-badge error tooltip** — devices list. The concrete `error_message` from the most recent failed query or probe is surfaced as a `title=` tooltip on the badge. Operators hover to read `ssh connect timeout` without cracking open the server logs; recovered devices are excluded.
- **Loading state on admin Save buttons** — disable + swap label to `Saving…` / `Сохраняем…` on submit. Opt-in via `data-loading-text` attribute so inline `Delete` buttons keep their `confirm()` flow. Applied to all five admin form types.
- **Consistent centralised page navigation** via shared `partials/header.html` / `partials/user_menu.html`; fewer inline duplicates across index / history / result / admin / docs.
- **Webhook delivery from the admin panel.** SSR admin CRUD on devices previously skipped webhook events; now parity with the REST path.
- **`.github/ISSUE_TEMPLATE/config.yml`** — disables blank issues and redirects security reports to the private advisory workflow.

### Changed

- **`<select>` controls** now render a consistent custom chevron with a small gap from the right border, replacing the browser-default arrow which hugged the edge inconsistently across Chrome/Firefox/Safari.
- **Swagger UI / OpenAPI** are no longer gated behind `BGPEEK_DEBUG=true`. They are now controlled by the dedicated `BGPEEK_DOCS_ENABLED` (default `true`). Deployments that relied on the old implicit "no docs in prod" behaviour will now see them unless they explicitly set `BGPEEK_DOCS_ENABLED=false`.
- **Admin device form with `source4`/`source6` set** no longer returns 500. `asyncpg` cannot bind Pydantic `IPv4Address`/`IPv6Address` objects to the TEXT columns used for source IPs; payloads are now serialised with `model_dump(mode="json")` before insert/update.
- **README admin-bootstrap instructions** corrected — the prior wording claimed a default admin account is auto-created on first startup; the replacement describes the two real paths (direct INSERT with bcrypt hash, or OIDC/LDAP role-mapping).
- **`CONTRIBUTING.md`** — corrected compose filename (`compose.yaml`), service name (`postgres`), and port (`8000`) so new contributors can copy commands verbatim.

### Deprecated

- **Client-supplied `api_key` on `POST /api/users`.** The server now generates a cryptographically strong value by default; supplying the field remains accepted for one release cycle (logs a `deprecated_client_supplied_api_key` warning) and will be removed in v1.5.0. Migrate admin automation to read the `api_key` field from the 201 response instead of pre-generating the secret client-side.

### Fixed

- **Admin CRUD: whitespace-only values** in required string fields (`name`, `username`, `pattern`, `label`, `url`) are now rejected with HTTP 400 instead of silently saved. A new `bgpeek.models._common.TrimmedStr` annotated type strips whitespace *before* length validation. Passwords, API keys, and webhook HMAC secrets are intentionally left untrimmed — stripping a secret field would desync the stored hash from what the operator typed.
- **Admin devices list: Health badge now reflects a fresh probe failure.** Previously, a device with any prior successful session kept rendering as `Healthy` even right after a visible `ssh connect timeout` in the logs because the async probe wrote to `audit_log` only — it never fed the circuit breaker. Probe failures now call `record_failure` / `record_success`, so the badge flips to amber `1/3` / red `Open` on the same evidence as a failed query would.

### Internal

- Template chrome refactor and user-context hardening in shared template wiring (`TemplateUserMiddleware` attaches best-effort `request.state.user` for all SSR pages).
- Test coverage expanded across auth, admin UI, DB users, templates, and links — account settings, link generation, CSRF enforcement, identity-provider collision, API-key generation path, result-retrieval gating, and the security-header contract.

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

[Unreleased]: https://github.com/xeonerix/bgpeek/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.4.0
[1.3.1]: https://github.com/xeonerix/bgpeek/releases/tag/v1.3.1
[1.3.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.3.0
[1.2.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.2.0
[1.1.1]: https://github.com/xeonerix/bgpeek/releases/tag/v1.1.1
[1.1.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.1.0
[1.0.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.0.0
