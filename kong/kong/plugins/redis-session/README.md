# redis-session — Kong Gateway Plugin

Server-side session management for Kong Gateway. Redis holds all session data; the browser receives only an AES-256-GCM encrypted, HMAC-signed session ID cookie. No session data is ever stored client-side.

---

## How it differs from cookie-session

| | `cookie-session` | `redis-session` |
|---|---|---|
| **Session data location** | Encrypted inside the cookie | Redis only |
| **Cookie contents** | Encrypted JSON payload | Encrypted + signed session ID reference |
| **Session revocation** | Not possible (stateless) | Instant — `DEL session:<id>` in Redis |
| **Horizontal scaling** | No shared state needed | Requires Redis accessible to all Kong nodes |
| **Cookie size** | Grows with payload | Fixed and small (reference only) |
| **Infrastructure** | None | Redis instance or cluster |

---

## Architecture

```
Client                    Kong (plugin)                    Redis
  |                           |                              |
  |  create_session: true     |                              |
  |-------------------------->|                              |
  |                           |--- SET session:<id> EX 3600->|
  |                           |<-- OK ------------------------|
  |<-- Set-Cookie: kong_session=<encrypted_signed_id> --------|
  |                                                           |
  |  Cookie: kong_session=<id>                                |
  |-------------------------->|                              |
  |                           |--- GET session:<id> -------->|
  |                           |<-- {id, last_used_at} -------|
  |                           |  [verify idle timeout]       |
  |                           |  [update last_used_at]       |
  |                           |--- SET session:<id> EX 3600->|
  |<-- 200 OK + refreshed Set-Cookie -------------------------|
  |                                                           |
  |  destroy_session: true + Cookie: kong_session=<id>        |
  |-------------------------->|                              |
  |                           |--- DEL session:<id> -------->|
  |<-- 200 OK  Set-Cookie: kong_session=; Max-Age=0 ----------|
```

---

## Cookie format

The browser cookie value is a single encrypted blob (no dots visible to the browser):

```
<iv_b64url>.<ciphertext_b64url>.<tag_b64url>
```

The **plaintext inside** the encryption (never visible to the client):

```
<session_id_uuid>.<hmac_sha256_b64url>
```

| Layer | What it does |
|---|---|
| HMAC-SHA256 | Binds the session ID to the signing secret — a leaked Redis key cannot produce a valid cookie |
| AES-256-GCM | Encrypts + authenticates the HMAC-signed session reference |
| GCM tag | Detects any bit-level tampering with the ciphertext |

---

## Sequence of events

### 1. Session Creation (`create_session: true`)

```
Client                          Kong                            Redis
  |                              |                               |
  | GET /api                     |                               |
  | create_session: true ------->|                               |
  |                              | 1. generate UUID session ID   |
  |                              | 2. build JSON:                |
  |                              |    {id, created_at,           |
  |                              |     last_used_at}             |
  |                              | 3. SET session:<id> EX 3600 ->|
  |                              |<-- OK ------------------------|
  |                              | 4. HMAC-sign session ID       |
  |                              | 5. AES-GCM encrypt <id>.<mac> |
  |                              | 6. strip create_session header|
  |                              |---------> upstream ----------->|
  |                              |<--------- 200 OK -------------|
  |<-- 200 OK -------------------|                               |
  |    Set-Cookie: kong_session= |                               |
  |      <iv>.<ct>.<tag>         |                               |
```

The `create_session` header is stripped before the request reaches the upstream service.

---

### 2. Subsequent Request (valid session)

```
Client                          Kong                            Redis
  |                              |                               |
  | GET /api                     |                               |
  | Cookie: kong_session=<val> ->|                               |
  |                              | 1. AES-GCM decrypt cookie     |
  |                              | 2. HMAC verify session ID     |
  |                              | 3. GET session:<id> --------->|
  |                              |<-- {id, created_at,           |
  |                              |     last_used_at} ------------|
  |                              | 4. check idle timeout:        |
  |                              |    now - last_used_at <= 3600 |
  |                              | 5. update last_used_at = now  |
  |                              | 6. SET session:<id> EX 3600 ->|
  |                              |---------> upstream ----------->|
  |                              |<--------- 200 OK -------------|
  |<-- 200 OK -------------------|                               |
  |    Set-Cookie: kong_session= |                               |
  |      <new iv>.<ct>.<tag>     |                               |
```

Every successful request resets the idle timer in Redis. The cookie is re-encrypted on each response (same session ID, fresh IV).

---

### 3. Expired Session (idle timeout or Redis TTL elapsed)

```
Client                          Kong                            Redis
  |                              |                               |
  | Cookie: kong_session=<val> ->|                               |
  |                              | 1. decrypt + verify ✓         |
  |                              | 2. GET session:<id> --------->|
  |                              |<-- nil (key expired) ---------|
  |                              |    OR                         |
  |                              |<-- {last_used_at: old} -------|
  |                              |    idle > 3600s → DEL key --->|
  |<-- 401 Unauthorized ---------|                               |
  |    Set-Cookie: kong_session= |                               |
  |      =; Max-Age=0            |                               |
  |    {"message":"Session       |                               |
  |      invalid or expired"}    |                               |
```

---

### 4. Tampered or Forged Cookie

```
Client                          Kong                            Redis
  |                              |                               |
  | Cookie: kong_session=<bad> ->|                               |
  |                              | 1. AES-GCM decrypt FAILS      |
  |                              |    (or GCM tag mismatch)      |
  |                              |    OR HMAC verify FAILS       |
  |                              |    No Redis call is made      |
  |<-- 401 Unauthorized ---------|                               |
  |    Set-Cookie: kong_session= |                               |
  |      =; Max-Age=0            |                               |
```

---

### 5. Session Destruction (`destroy_session: true`)

```
Client                          Kong                            Redis
  |                              |                               |
  | Cookie: kong_session=<val>   |                               |
  | destroy_session: true ------>|                               |
  |                              | 1. decrypt + verify cookie    |
  |                              | 2. DEL session:<id> --------->|
  |                              |<-- 1 (deleted) ---------------|
  |<-- 200 OK -------------------|                               |
  |    Set-Cookie: kong_session= |                               |
  |      =; Max-Age=0            |                               |
  |    {"message":               |                               |
  |      "Session destroyed"}    |                               |
```

---

## Configuration reference

| Field | Type | Default | Description |
|---|---|---|---|
| `cookie_name` | string | `kong_session` | Name of the session cookie |
| `encryption_secret` | string | *(see warning)* | 64-char hex string (32 bytes) for AES-256-GCM |
| `signing_secret` | string | *(see warning)* | HMAC-SHA256 signing secret, minimum 16 chars |
| `idle_timeout` | number | `3600` | Seconds of inactivity before session expires. Also the Redis TTL. |
| `redis_host` | string | `127.0.0.1` | Redis hostname |
| `redis_port` | integer | `6379` | Redis port |
| `redis_password` | string | — | Redis `AUTH` password |
| `redis_database` | integer | `0` | Redis logical database index (0–15) |
| `redis_timeout` | integer | `2000` | Socket timeout in ms |
| `redis_pool_size` | integer | `10` | Max idle connections per nginx worker |
| `redis_pool_timeout` | integer | `10000` | Pool keepalive timeout in ms |
| `session_key_prefix` | string | `session:` | Redis key prefix: `session:<uuid>` |
| `cookie_secure` | boolean | `true` | Add `Secure` flag (requires HTTPS) |
| `cookie_same_site` | string | `Strict` | `Strict`, `Lax`, or `None` |
| `cookie_path` | string | `/` | Cookie `Path` attribute |
| `cookie_max_age` | integer | `0` | `Max-Age` in seconds; `0` = session cookie |

> **Warning:** The default `encryption_secret` and `signing_secret` are publicly known placeholders. Replace them before any production use. Store them in a [Kong Vault](https://docs.konghq.com/gateway/latest/kong-enterprise/secrets-management/).

---

## Installation

### 1. Install the rock

```bash
luarocks make redis-session-1.0.0-1.rockspec
```

### 2. Register in `kong.conf`

```
plugins = bundled,redis-session
```

### 3. Reload Kong

```bash
kong reload
```

---

## Enabling the plugin

### Via Admin API

```bash
curl -X POST http://localhost:8001/routes/{route-id}/plugins \
  --data name=redis-session \
  --data config.encryption_secret=<your-64-char-hex-key> \
  --data config.signing_secret=<your-signing-secret> \
  --data config.redis_host=redis.internal \
  --data config.redis_port=6379 \
  --data config.idle_timeout=1800
```

### Via declarative YAML (deck)

```yaml
plugins:
  - name: redis-session
    config:
      cookie_name: kong_session
      encryption_secret: "{vault://aws/kong-secrets/session-enc-key}"
      signing_secret: "{vault://aws/kong-secrets/session-sign-key}"
      idle_timeout: 1800
      redis_host: redis.internal
      redis_port: 6379
      redis_password: "{vault://aws/kong-secrets/redis-password}"
      redis_database: 0
      redis_timeout: 2000
      redis_pool_size: 20
      redis_pool_timeout: 10000
      session_key_prefix: "session:"
      cookie_secure: true
      cookie_same_site: Strict
      cookie_path: /
```

---

## Testing with curl

### Create a session

```bash
curl -v -c cookies.txt \
  -H "create_session: true" \
  https://api.example.com/login

# Response headers will include:
# Set-Cookie: kong_session=<iv>.<ct>.<tag>; Path=/; HttpOnly; SameSite=Strict; Secure
```

### Use the session (valid follow-up request)

```bash
curl -v -b cookies.txt -c cookies.txt \
  https://api.example.com/api/me

# Response: HTTP 200 from upstream
# Response headers include a refreshed Set-Cookie with updated last_used_at inside
```

### Simulate an expired session

```bash
# Option A: manually delete the key in Redis
redis-cli DEL session:<your-session-uuid>

# Option B: set a very short TTL
redis-cli EXPIRE session:<your-session-uuid> 1
sleep 2

curl -v -b cookies.txt \
  https://api.example.com/api/me

# Response:
# HTTP/1.1 401 Unauthorized
# Set-Cookie: kong_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict; Secure
# {"message":"Session invalid or expired"}
```

### Destroy a session

```bash
curl -v -b cookies.txt \
  -H "destroy_session: true" \
  https://api.example.com/logout

# Response:
# HTTP/1.1 200 OK
# Set-Cookie: kong_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict; Secure
# {"message":"Session destroyed"}
```

---

## Redis key inspection

```bash
# List all active session keys
redis-cli KEYS "session:*"

# Inspect a specific session's JSON data
redis-cli GET "session:550e8400-e29b-41d4-a716-446655440000"
# Output: {"id":"550e8400-...","created_at":1711584000.0,"last_used_at":1711587600.0}

# Check remaining TTL (seconds)
redis-cli TTL "session:550e8400-e29b-41d4-a716-446655440000"
# Output: 2847  (seconds remaining before automatic expiry)

# Manually expire a session (force logout)
redis-cli DEL "session:550e8400-e29b-41d4-a716-446655440000"

# Count total active sessions
redis-cli DBSIZE

# Monitor Redis commands in real time (useful during development)
redis-cli MONITOR
```

---

## File structure

```
kong/plugins/redis-session/
├── handler.lua    — Plugin phases (access + header_filter)
├── schema.lua     — Configuration schema and field validators
├── crypto.lua     — AES-256-GCM encrypt/decrypt, HMAC-SHA256 sign/verify,
│                    cookie build/parse helpers
└── redis.lua      — Redis connect, get, set, del, release (connection pooling)

redis-session-1.0.0-1.rockspec   — LuaRocks packaging descriptor
```

---

## Security properties

| Threat | Protection |
|---|---|
| Reading session data from cookie | Cookie holds only an encrypted reference; data is in Redis |
| Forging a session ID | HMAC-SHA256 signature on the session ID inside the encryption |
| Cookie bit-flip / tampering | AES-256-GCM authentication tag |
| Timing attacks on HMAC check | Constant-time byte comparison (`ct_equal`) |
| IV reuse | Fresh 12-byte random IV per encryption call |
| Session fixation | Session ID is a UUID v4 (cryptographic entropy) |
| CSRF | `SameSite=Strict` |
| XSS cookie theft | `HttpOnly` flag |
| Network interception | `Secure` flag (HTTPS only) |
| Redis password in logs | Password replaced with `[REDACTED]` in all log output |
| Secrets in logs | `encryption_secret` and `signing_secret` never passed to `kong.log` |
| Instant revocation | `DEL session:<id>` in Redis immediately invalidates a session |
