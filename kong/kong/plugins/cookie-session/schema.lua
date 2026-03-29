-- kong/plugins/cookie-session/schema.lua
--
-- Configuration schema for the cookie-session plugin.
-- Fields marked `encrypted = true` are stored encrypted at rest in Kong's DB.
-- Fields marked `referenceable = true` can be pulled from a Kong Vault at runtime.

local typedefs = require "kong.db.schema.typedefs"

-- Validator: encryption_secret must be a 64-char hex string (32 raw bytes = AES-256 key).
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
  name = "cookie-session",
  fields = {
    -- Plugin cannot be scoped to a specific consumer (stateless by design)
    { consumer  = typedefs.no_consumer },
    -- Only applies to HTTP / HTTPS routes
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
              description = "Name of the session cookie.",
            },
          },

          -- ── Cryptographic secrets ────────────────────────────────────────
          {
            encryption_secret = {
              type             = "string",
              required         = true,
              default          = "0000000000000000000000000000000000000000000000000000000000000000",
              encrypted        = true,      -- Kong stores this field encrypted at rest
              referenceable    = true,      -- Can be sourced from a Kong Vault reference
              custom_validator = validate_hex32,
              description      = "64-character hex string (32 bytes) used as the AES-256-GCM encryption key. CHANGE THIS in production.",
            },
          },
          {
            signing_secret = {
              type          = "string",
              required      = true,
              default       = "change-me-this-is-not-a-safe-default-secret",
              encrypted     = true,
              referenceable = true,
              len_min       = 16,           -- Minimum viable HMAC key length
              description   = "Secret used for HMAC-SHA256 cookie signing. At least 32 bytes recommended. CHANGE THIS in production.",
            },
          },

          -- ── Session policy ───────────────────────────────────────────────
          {
            idle_timeout = {
              type        = "number",
              default     = 3600,           -- 1 hour
              gt          = 0,
              description = "Seconds of inactivity after which the session is considered expired.",
            },
          },

          -- ── Cookie attributes ────────────────────────────────────────────
          {
            cookie_secure = {
              type        = "boolean",
              default     = true,
              description = "Append the Secure flag to the Set-Cookie header.",
            },
          },
          {
            cookie_same_site = {
              type        = "string",
              default     = "Strict",
              one_of      = { "Strict", "Lax", "None" },
              description = "SameSite policy. Use 'None' only with cookie_secure = true.",
            },
          },
          {
            cookie_path = {
              type        = "string",
              default     = "/",
              len_min     = 1,
              description = "Path attribute for the session cookie.",
            },
          },
          {
            cookie_max_age = {
              type        = "integer",
              default     = 0,             -- 0 = session cookie (browser discards on close)
              between     = { 0, 2147483647 },
              description = "Max-Age attribute in seconds. 0 means a session cookie (no Max-Age set).",
            },
          },
        },
      },
    },
  },
}
