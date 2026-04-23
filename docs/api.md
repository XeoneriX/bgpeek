# REST API

bgpeek provides a RESTful JSON API for all operations. Interactive documentation
is available at `/api/docs` (Swagger UI) and `/api/redoc` (ReDoc) when the
application is running.

## Authentication

Three authentication methods are supported. All admin and query endpoints require
at least one:

| Method       | Header / Cookie                    | Use Case             |
|--------------|------------------------------------|----------------------|
| API key      | `X-API-Key: <key>`                 | Scripts, monitoring  |
| JWT Bearer   | `Authorization: Bearer <token>`    | API clients          |
| Cookie       | `bgpeek_token` (set after login)   | Web UI               |

### Obtaining a JWT Token

```bash
curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}'
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "enabled": true,
    "auth_provider": "local",
    "created_at": "2025-01-15T10:00:00Z"
  }
}
```

The token expires after `BGPEEK_JWT_EXPIRE_MINUTES` (default: 60 minutes).

### Current User

```bash
curl -s http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

### OIDC Login

When OIDC is enabled (`BGPEEK_OIDC_ENABLED=true`), browser-based login is
available at `/auth/oidc/login`. The callback at `/auth/oidc/callback` exchanges
the authorization code, upserts the user, and sets a session cookie.

---

## Devices

Manage the device inventory. Authenticated users can list and view devices;
admin role is required for create, update, and delete.

### List Devices

```bash
curl -s http://localhost:8000/api/devices \
  -H "X-API-Key: $API_KEY"
```

Query parameter: `enabled_only=true` to filter to enabled devices only.

### Get Device

```bash
curl -s http://localhost:8000/api/devices/1 \
  -H "X-API-Key: $API_KEY"
```

### Create Device

```bash
curl -s -X POST http://localhost:8000/api/devices \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "moscow-r1",
    "address": "10.0.1.1",
    "platform": "juniper_junos",
    "port": 22,
    "location": "Moscow, M9",
    "credential_id": 1
  }'
```

### Update Device

```bash
curl -s -X PATCH http://localhost:8000/api/devices/1 \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### Delete Device

```bash
curl -s -X DELETE http://localhost:8000/api/devices/1 \
  -H "X-API-Key: $API_KEY"
```

Returns `204 No Content` on success.

---

## Credentials

Manage SSH credentials. All endpoints require admin role. See
[credentials.md](credentials.md) for the full credential management guide.

### List Credentials

```bash
curl -s http://localhost:8000/api/credentials \
  -H "X-API-Key: $API_KEY"
```

Returns credentials with a `device_count` field showing how many devices
reference each credential. Passwords are masked in the response.

### Create Credential

```bash
curl -s -X POST http://localhost:8000/api/credentials \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "juniper-prod",
    "auth_type": "key",
    "username": "looking-glass",
    "key_name": "juniper.key"
  }'
```

Validation rules:
- `auth_type` must be `key`, `password`, or `key+password`
- `key_name` is required when `auth_type` includes `key`
- `password` is required when `auth_type` includes `password`
- `name` must be unique (409 on conflict)

### Update Credential

```bash
curl -s -X PATCH http://localhost:8000/api/credentials/1 \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"password": "new-secret"}'
```

### Delete Credential

```bash
curl -s -X DELETE http://localhost:8000/api/credentials/1 \
  -H "X-API-Key: $API_KEY"
```

Returns `204 No Content` on success. Fails with `409 Conflict` if any devices
still reference this credential.

### Test Credential

```bash
curl -s -X POST "http://localhost:8000/api/credentials/1/test?device_id=3" \
  -H "X-API-Key: $API_KEY"
```

Opens an SSH connection to the specified device using this credential, then
disconnects immediately. Returns `{"success": true/false, "message": "..."}`.

---

## Queries

### Single Device Query

```bash
curl -s -X POST http://localhost:8000/api/query \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "device_name": "moscow-r1",
    "query_type": "bgp_route",
    "target": "8.8.8.0/24"
  }'
```

Supported `query_type` values: `bgp_route`, `ping`, `traceroute`.

Response:

```json
{
  "device_name": "moscow-r1",
  "query_type": "bgp_route",
  "target": "8.8.8.0/24",
  "command": "show route 8.8.8.0/24",
  "raw_output": "...",
  "filtered_output": "...",
  "runtime_ms": 1250,
  "cached": false,
  "parsed_routes": [
    {
      "prefix": "8.8.8.0/24",
      "next_hop": "10.0.0.1",
      "as_path": "15169",
      "origin": "IGP",
      "best": true,
      "rpki_status": "valid",
      "communities": ["15169:1000"]
    }
  ],
  "resolved_target": null,
  "result_id": "a1b2c3d4-..."
}
```

For BGP queries, `filtered_output` has prefixes longer than the configured
`BGPEEK_MAX_PREFIX_V4` / `BGPEEK_MAX_PREFIX_V6` removed for public users
(defaults: /24 and /48). At `BGPEEK_PUBLIC_OUTPUT_LEVEL=restricted` the
field is cleared entirely and parsed_routes have communities, local_pref,
and MED stripped. Admin and NOC roles see unfiltered output.

Hostname targets are automatically resolved to IP addresses before the query is
sent to the device. The original hostname and resolved IP are both recorded.

### Multi-Device Parallel Query

```bash
curl -s -X POST http://localhost:8000/api/query/multi \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "device_names": ["moscow-r1", "frankfurt-r1", "amsterdam-r1"],
    "query_type": "bgp_route",
    "target": "1.1.1.0/24"
  }'
```

Queries up to 10 devices concurrently (configurable via
`BGPEEK_MAX_PARALLEL_QUERIES`, default: 5 concurrent SSH sessions).

Response:

```json
{
  "results": [ ... ],
  "errors": [
    {"detail": "SSH timeout", "target": "1.1.1.0/24", "device_name": "amsterdam-r1"}
  ],
  "total_runtime_ms": 2100,
  "device_count": 3
}
```

Successful results and errors are returned separately. A partial failure does not
block other devices from returning.

---

## Results

Query results are persisted with a unique UUID for sharing via permalink.

### Get Shared Result

```bash
curl -s http://localhost:8000/api/results/a1b2c3d4-5678-90ab-cdef-1234567890ab
```

No authentication required. Results expire after `BGPEEK_RESULT_TTL_DAYS`
(default: 7 days).

### List User's Results

```bash
curl -s http://localhost:8000/api/results \
  -H "X-API-Key: $API_KEY"
```

Returns recent results for the authenticated user.

---

## Webhooks

Receive HTTP notifications for system events. All endpoints require admin role.

### Supported Events

| Event            | Trigger                    |
|------------------|----------------------------|
| `query`          | Query executed             |
| `device_create`  | New device added           |
| `device_update`  | Device configuration changed |
| `device_delete`  | Device removed             |
| `login`          | User logged in             |

### List Webhooks

```bash
curl -s http://localhost:8000/api/webhooks \
  -H "X-API-Key: $API_KEY"
```

Secrets are masked to `"****"` in responses.

### Create Webhook

```bash
curl -s -X POST http://localhost:8000/api/webhooks \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "slack-notifications",
    "url": "https://hooks.slack.com/services/T00/B00/xxx",
    "events": ["query", "login"],
    "enabled": true,
    "secret": "webhook-signing-secret"
  }'
```

### Update Webhook

```bash
curl -s -X PATCH http://localhost:8000/api/webhooks/1 \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### Delete Webhook

```bash
curl -s -X DELETE http://localhost:8000/api/webhooks/1 \
  -H "X-API-Key: $API_KEY"
```

### Test Webhook

```bash
curl -s -X POST http://localhost:8000/api/webhooks/1/test \
  -H "X-API-Key: $API_KEY"
```

Sends a test payload to the webhook URL. Returns `{"success": true/false}`.

### Payload Format

All webhook deliveries use the same envelope:

```json
{
  "event": "query",
  "timestamp": "2025-06-15T12:34:56Z",
  "data": {
    "device_name": "moscow-r1",
    "query_type": "bgp_route",
    "target": "8.8.8.0/24",
    "runtime_ms": 1250,
    "username": "admin"
  }
}
```

If a `secret` is configured, the request includes an HMAC signature header for
verification.

---

## Users

Manage user accounts. All endpoints require admin role.

### Create API-Key User

```bash
curl -s -X POST http://localhost:8000/api/users \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "monitoring",
    "api_key": "a]gNpKr2x8Wm4vBq7LfEy9Zc1DhTj5Xs",
    "role": "public"
  }'
```

API keys must be 32-128 characters.

### Create Local (Password) User

```bash
curl -s -X POST http://localhost:8000/api/users/local \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "operator",
    "password": "strong-password-here",
    "role": "noc",
    "email": "operator@example.com"
  }'
```

Passwords must be 8-128 characters and are stored as bcrypt hashes.

### List Users

```bash
curl -s http://localhost:8000/api/users \
  -H "X-API-Key: $API_KEY"
```

### Delete User

```bash
curl -s -X DELETE http://localhost:8000/api/users/42 \
  -H "X-API-Key: $API_KEY"
```

---

## Health

### Liveness Probe

```bash
curl -s http://localhost:8000/api/health
```

```json
{"status": "ok", "version": "1.4.0"}
```

### Deep Health Check

```bash
curl -s "http://localhost:8000/api/health?deep=true"
```

```json
{
  "status": "ok",
  "version": "1.4.0",
  "database": "ok",
  "redis": "ok"
}
```

Returns `"degraded"` status if either PostgreSQL or Redis is unreachable.

---

## Metrics

Prometheus-compatible metrics are exposed at `/metrics`:

```bash
curl -s http://localhost:8000/metrics
```

Includes standard HTTP request metrics (duration, count, status codes)
instrumented by `prometheus-fastapi-instrumentator`.

---

## Rate Limiting

Rate limits are enforced per-IP via Redis when `BGPEEK_RATE_LIMIT_ENABLED=true`
(default). Limits are returned in response headers.

| Scope   | Default Limit       | Config Variable             |
|---------|---------------------|-----------------------------|
| Queries | 30 per minute / IP  | `BGPEEK_RATE_LIMIT_QUERY`  |
| Login   | 5 per minute / IP   | `BGPEEK_RATE_LIMIT_LOGIN`  |
| API     | 60 per minute / key | `BGPEEK_RATE_LIMIT_API`    |

When a limit is exceeded, the API returns `429 Too Many Requests`.

If Redis is unavailable, rate limiting degrades gracefully (requests are allowed
through).

---

## Errors

All error responses use standard HTTP status codes with a JSON body:

```json
{"detail": "device not found"}
```

Query errors include additional context:

```json
{
  "detail": "SSH connection timed out",
  "target": "8.8.8.0/24",
  "device_name": "moscow-r1"
}
```

Common status codes:

| Code | Meaning                                      |
|------|----------------------------------------------|
| 400  | Invalid request (bad target, missing fields)  |
| 401  | Missing or invalid authentication             |
| 403  | Insufficient role (e.g. public calling admin endpoint) |
| 404  | Resource not found                            |
| 409  | Conflict (duplicate name, credential in use)  |
| 422  | Validation error (Pydantic)                   |
| 429  | Rate limit exceeded                           |
| 502  | Upstream error (SSH failure, device unreachable) |
