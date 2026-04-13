# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-04-12

### Added

- Auto-migration on startup
- Deep health check endpoint (DB + Redis connectivity)
- Periodic cleanup for expired shared results and audit log entries
- Request correlation ID via X-Request-ID header
- Prometheus metrics endpoint (/metrics)
- Circuit breaker for SSH connections
- Device-level access control (restricted field)
- HTMX DOM growth limit to prevent memory leaks
- .env.example with all configuration settings documented

### Fixed

- SSH key path now passed to all query endpoints
- Docker image includes migrations directory
- _persist_result no longer crashes successful queries on DB error
- SSH username configurable via BGPEEK_SSH_USERNAME env var
- Per-query-type SSH timeouts (120s for traceroute)
- SSH host key auto-accept policy (configurable)
- RPKI error cache uses shorter TTL (60s instead of 1h)
- DB pool command_timeout configurable
- Webhook task tracking (prevents GC of fire-and-forget tasks) with exponential backoff
- Narrowed exception handling in HTMX endpoints

### Changed

- Docker base image from Alpine to Debian slim
- compose.override.yaml renamed to compose.dev.yaml
- compose.yaml uses env var references instead of hardcoded credentials

## [1.0.0] - 2026-04-12

### Added

- Multi-vendor SSH support (Juniper, Cisco IOS/XE/XR, Arista EOS, Huawei VRP)
- BGP route, ping, and traceroute queries
- API key + local password (bcrypt) + LDAP + JWT authentication
- OIDC authentication (Keycloak)
- REST API with OpenAPI documentation
- Per-role output filtering (hide /25-/32 routes for public users)
- Audit log stored in PostgreSQL
- Device inventory CRUD
- Redis cache with graceful degradation
- Webhook notifications with HMAC-SHA256 signatures
- Parallel multi-device queries with side-by-side diff view
- Shareable query results (UUID permalinks, configurable TTL)
- Structured BGP output parsing with RPKI validation
- Internationalization (English and Russian)
- Rate limiting (per-IP, per-user, per-API-key)
- DNS resolution for query targets
- Dark/light theme toggle
- Docker multi-stage build

[1.0.1]: https://github.com/xeonerix/bgpeek/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/xeonerix/bgpeek/releases/tag/v1.0.0
