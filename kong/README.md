# cookie-session — Kong Gateway Plugin

A stateless session management plugin for Kong Gateway. Sessions are stored entirely inside an encrypted, signed cookie — no database, Redis, or any other storage backend is required.

---

## Why this plugin?

Kong's built-in `session` plugin stores session data on the server (Redis / PostgreSQL). That works well but adds infrastructure dependencies and creates a single point of failure for session reads.

`cookie-session` moves all session state into the cookie itself:

- Every Kong node can independently verify and decode any session cookie.
- No shared storage means no extra infrastructure to provision or scale.
- Idle-timeout enforcement still works because the last-activity timestamp is carried inside the encrypted cookie.

The trade-off is that individual sessions cannot be revoked before they naturally expire. If that is a hard requirement, use a server-side session store instead.

---

## How it works — sequence of events

### 1. Session Creation

Triggered when the client sends `create_session: true` as a request header.

```
Client                          Kong (plugin)                   Upstream
  |                                  |                              |
  |-- GET /api  create_session:true->|                              |
  |                                  |-- generate UUID session ID   |
  |                                  |-- build JSON payload:        |
  |                                  |   { id, created_at,         |
  |                                  |     last_used_at }           |
  |                                  |-- AES-256-GCM encrypt        |
  |                                  |-- HMAC-SHA256 sign           |
  |                                  |-- Base64URL encode           |
  |                                  |-- strip create_session header|
  |                                  |---------- GET /api --------->|
  |                                  |<--------- 200 OK -----------|
  |<-- 200 OK + Set-Cookie ----------|                              |
       kong_session=<iv>.<ct>.<tag>.<hmac>
```

The `create_session` header is stripped before the request reaches the upstream service. The upstream never sees it.

---

### 2. Subsequent Request (valid session)

The client sends the cookie it received. The plugin validates it, checks the idle timeout, then refreshes the cookie with an updated `last_used_at` timestamp (rolling session).

```
Client                          Kong (plugin)                   Upstream
  |                                  |                              |
  |-- GET /api  Cookie:kong_session->|                              |
  |                                  |-- extract cookie value       |
  |                                  |-- verify HMAC-SHA256         |
  |                                  |-- AES-256-GCM decrypt        |
  |                                  |-- parse JSON payload         |
  |                                  |-- check idle timeout:        |
  |                                  |   now - last_used_at <= 3600 |
  |                                  |-- update last_used_at = now  |
  |                                  |-- re-encrypt + re-sign       |
  |                                  |---------- GET /api --------->|
  |                                  |<--------- 200 OK -----------|
  |<-- 200 OK + Set-Cookie ----------|                              |
       (refreshed cookie with new last_used_at)
```

Every successful request resets the idle timer, so an active user is never logged out mid-session.

---

### 3. Expired Session (idle timeout exceeded)

If the gap between `last_used_at` and the current time is greater than `idle_timeout`, the plugin rejects the request without forwarding it to the upstream.

```
Client                          Kong (plugin)                   Upstream
  |                                  |                              |
  |-- GET /api  Cookie:kong_session->|                              |
  |                                  |-- verify HMAC ✓              |
  |                                  |-- decrypt ✓                  |
  |                                  |-- idle check:                |
  |                                  |   now - last_used_at > 3600  |
  |                                  |   EXPIRED                    |
  |<-- 401 Unauthorized -------------|                              |
  |    Set-Cookie: kong_session=;    |                              |
  |      Max-Age=0 (clear cookie)    |                              |
  |    { "message": "Session         |                              |
  |       invalid or expired" }      |                              |
```

---

### 4. Tampered or Forged Cookie

Any modification to the cookie value — even a single bit flip — causes HMAC verification or GCM tag verification to fail. The request is rejected before decryption is attempted.

```
Client                          Kong (plugin)                   Upstream
  |                                  |                              |
  |-- GET /api  Cookie: <forged> --->|                              |
  |                                  |-- HMAC verify FAIL           |
  |                                  |   (no decryption attempted)  |
  |<-- 401 Unauthorized -------------|                              |
  |    Set-Cookie: kong_session=;    |                              |
  |      Max-Age=0 (clear cookie)    |                              |
```

---

### 5. Request with No Cookie (anonymous)

If no session cookie is present and `create_session: true` is not set, the request passes through untouched. Blocking anonymous access is the responsibility of other plugins (e.g. `key-auth`, `jwt`, `basic-auth`).

```
Client                          Kong (plugin)                   Upstream
  |                                  |                              |
  |-- GET /api (no cookie) --------->|                              |
  |                                  |-- no cookie found            |
  |                                  |-- pass through               |
  |                                  |---------- GET /api --------->|
  |<-------------------------------- 200 OK ----------------------->|
```

---

## Cookie format

The cookie value is a dot-separated string of four Base64URL-encoded segments:

```
<iv>.<ciphertext>.<tag>.<hmac>
```

| Segment | Size | Description |
|---|---|---|
| `iv` | 12 bytes | Random AES-GCM nonce, unique per request |
| `ciphertext` | variable | AES-256-GCM encrypted JSON payload |
| `tag` | 16 bytes | GCM authentication tag (covers IV + ciphertext) |
| `hmac` | 32 bytes | HMAC-SHA256 over `<iv>.<ciphertext>.<tag>` |

The JSON payload inside the cookie:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": 1711584000.0,
  "last_used_at": 1711587600.0
}
```

---

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `cookie_name` | string | `kong_session` | Name of the session cookie |
| `encryption_secret` | string | *(see warning)* | 64-char hex string (32 raw bytes) for AES-256-GCM |
| `signing_secret` | string | *(see warning)* | Secret for HMAC-SHA256 signing, minimum 16 chars |
| `idle_timeout` | number | `3600` | Seconds of inactivity before session expires |
| `cookie_secure` | boolean | `true` | Adds the `Secure` flag (requires HTTPS) |
| `cookie_same_site` | string | `Strict` | SameSite policy: `Strict`, `Lax`, or `None` |
| `cookie_path` | string | `/` | Cookie `Path` attribute |
| `cookie_max_age` | integer | `0` | `Max-Age` in seconds; `0` = session cookie (cleared on browser close) |

> **Warning:** The default values for `encryption_secret` and `signing_secret` are publicly known placeholders. You must replace them with secrets generated specifically for your deployment before going to production. Store them in a [Kong Vault](https://docs.konghq.com/gateway/latest/kong-enterprise/secrets-management/) rather than inline in the Admin API.

---

## Installation

```bash
# 1. Build and install the rock
luarocks make cookie-session-1.0.0-1.rockspec

# 2. Add the plugin to kong.conf
plugins = bundled,cookie-session

# 3. Reload Kong
kong reload
```

## Enabling on a route

```bash
curl -X POST http://localhost:8001/routes/{route-id}/plugins \
  --data name=cookie-session \
  --data config.encryption_secret=<your-64-char-hex-key> \
  --data config.signing_secret=<your-signing-secret> \
  --data config.idle_timeout=1800
```

---

## curl examples

**Create a session:**
```bash
curl -c cookies.txt -H "create_session: true" https://api.example.com/login
```

**Use the session:**
```bash
curl -b cookies.txt -c cookies.txt https://api.example.com/profile
```

**What an expired or invalid cookie returns:**
```bash
# HTTP 401
# Set-Cookie: kong_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict; Secure
# {"message":"Session invalid or expired"}
```

---

## Security properties

| Threat | Protection |
|---|---|
| Reading cookie contents | AES-256-GCM encryption |
| Forging or modifying a cookie | HMAC-SHA256 + GCM authentication tag |
| Timing attacks on HMAC check | Constant-time byte comparison |
| IV reuse | Fresh 12-byte random IV per encryption |
| CSRF | `SameSite=Strict` |
| XSS cookie theft | `HttpOnly` flag |
| Network interception | `Secure` flag (HTTPS only) |
| Secrets appearing in logs | Secrets are never passed to `kong.log` |

**Known limitations:**
- A stolen cookie cannot be revoked before its idle timeout expires (stateless by design).
- There is no built-in key rotation — changing a secret immediately invalidates all live sessions.

---

## File structure

```
kong/plugins/cookie-session/
├── handler.lua   — Plugin logic (access + header_filter phases)
└── schema.lua    — Configuration schema and validators

cookie-session-1.0.0-1.rockspec  — LuaRocks packaging descriptor
```
