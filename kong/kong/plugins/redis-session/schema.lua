-- kong/plugins/redis-session/schema.lua
--
-- Configuration schema for the redis-session plugin.
-- Fields marked `encrypted = true` are stored encrypted at rest in Kong's DB.
-- Fields marked `referenceable = true` can be sourced from a Kong Vault at runtime.

local typedefs = require "kong.db.schema.typedefs"

-- Validator: encryption_secret must be exactly 64 hex characters (32 raw bytes = AES-256 key).
local function validate_hex32(v)
  if #v ~= 64 then
    return nil, "encryption_secret must be exactly 64 hex characters (32 bytes for AES-256-GCM)"
  end
  if not v:match("^[0-9a-fA-F]+$") then
    return nil, "encryption_secret must contain only hexadecimal characters [0-9a-fA-F]"
  end
  return true
end

return {
  name = "redis-session",
  fields = {
    -- Plugin cannot be scoped to a consumer (server-side sessions are global)
    { consumer  = typedefs.no_consumer },
    -- Applies to HTTP and HTTPS routes only
    { protocols = typedefs.protocols_http },
    {
      config = {
        type   = "record",
        fields = {

          -- ── Cookie identity ─────────────────────────────────────────────
          {
            cookie_name = {
              type        = "string",
              default     = "kong_session",
              len_min     = 1,
              description = "Name of the session cookie sent to the browser.",
            },
          },

          -- ── Cryptographic secrets ────────────────────────────────────────
          {
            encryption_secret = {
              type             = "string",
              required         = true,
              -- WARN: default is a publicly known zero-key — CHANGE IN PRODUCTION
              default          = "0000000000000000000000000000000000000000000000000000000000000000",
              encrypted        = true,        -- stored encrypted in Kong DB
              referenceable    = true,        -- can be a Vault reference
              custom_validator = validate_hex32,
              description      = "64-character hex string (32 bytes) for AES-256-GCM cookie encryption. CHANGE IN PRODUCTION.",
            },
          },
          {
            signing_secret = {
              type          = "string",
              required      = true,
              -- WARN: default is publicly known — CHANGE IN PRODUCTION
              default       = "change-me-this-is-not-a-safe-default-secret",
              encrypted     = true,
              referenceable = true,
              len_min       = 16,
              description   = "Secret for HMAC-SHA256 cookie signing. Minimum 16 chars; 32+ recommended. CHANGE IN PRODUCTION.",
            },
          },

          -- ── Session policy ───────────────────────────────────────────────
          {
            idle_timeout = {
              type        = "number",
              default     = 3600,             -- 1 hour
              gt          = 0,
              description = "Seconds of inactivity before a session expires. Also used as the Redis key TTL.",
            },
          },

          -- ── Redis connection ─────────────────────────────────────────────
          {
            redis_host = {
              type        = "string",
              default     = "127.0.0.1",
              description = "Redis server hostname or IP address.",
            },
          },
          {
            redis_port = {
              type        = "integer",
              default     = 6379,
              between     = { 1, 65535 },
              description = "Redis server port.",
            },
          },
          {
            redis_password = {
              type          = "string",
              encrypted     = true,           -- never stored or logged in plaintext
              referenceable = true,
              description   = "Redis AUTH password. Leave empty if Redis has no password.",
            },
          },
          {
            redis_database = {
              type        = "integer",
              default     = 0,
              between     = { 0, 15 },
              description = "Redis logical database index (0–15).",
            },
          },
          {
            redis_timeout = {
              type        = "integer",
              default     = 2000,             -- 2 seconds
              gt          = 0,
              description = "Redis socket timeout in milliseconds (connect + read + write).",
            },
          },

          -- ── Connection pooling ───────────────────────────────────────────
          {
            redis_pool_size = {
              type        = "integer",
              default     = 10,
              gt          = 0,
              description = "Maximum number of idle Redis connections per nginx worker.",
            },
          },
          {
            redis_pool_timeout = {
              type        = "integer",
              default     = 10000,            -- 10 seconds
              gt          = 0,
              description = "Max idle time (ms) a connection may sit in the pool before being closed.",
            },
          },

          -- ── Redis key namespace ──────────────────────────────────────────
          {
            session_key_prefix = {
              type        = "string",
              default     = "session:",
              len_min     = 1,
              description = "Prefix for all Redis session keys. Format: <prefix><session_id>.",
            },
          },

          -- ── Cookie attributes ────────────────────────────────────────────
          {
            cookie_secure = {
              type        = "boolean",
              default     = true,
              description = "Append the Secure flag to Set-Cookie (requires HTTPS).",
            },
          },
          {
            cookie_same_site = {
              type        = "string",
              default     = "Strict",
              one_of      = { "Strict", "Lax", "None" },
              description = "SameSite cookie policy. Use 'None' only alongside cookie_secure = true.",
            },
          },
          {
            cookie_path = {
              type        = "string",
              default     = "/",
              len_min     = 1,
              description = "Cookie Path attribute.",
            },
          },
          {
            cookie_max_age = {
              type        = "integer",
              default     = 0,                -- 0 = session cookie (no Max-Age)
              between     = { 0, 2147483647 },
              description = "Max-Age in seconds. 0 means a session cookie discarded on browser close.",
            },
          },
        },
      },
    },
  },
}
