-- kong/plugins/cookie-session/handler.lua
--
-- Stateless session management via encrypted, signed cookies.
--
-- ── Cookie value wire format ──────────────────────────────────────────────────
--
--   <iv_b64url>.<ciphertext_b64url>.<tag_b64url>.<hmac_b64url>
--
--   Segments are separated by '.' and individually Base64URL-encoded (RFC 4648 §5).
--
--   iv          — 12 random bytes (96-bit nonce, NIST recommended for GCM)
--   ciphertext  — AES-256-GCM encryption of the JSON session payload
--   tag         — 16-byte (128-bit) GCM authentication tag
--   hmac        — HMAC-SHA256 computed over the string
--                 "<iv_b64url>.<ciphertext_b64url>.<tag_b64url>"
--
--   AES-GCM provides authenticated encryption: the tag already covers the
--   ciphertext and IV. The outer HMAC adds a second, independent authenticity
--   layer with a different key, enabling key rotation and defence-in-depth.
--
-- ── Request flow ─────────────────────────────────────────────────────────────
--
--   access phase
--     ├─ Header `create_session: true` → generate new session, stash cookie
--     ├─ Cookie present               → verify HMAC → decrypt → check idle
--     │                                 timeout → roll (update last_used_at)
--     │                                 → stash updated cookie
--     └─ No cookie                    → pass through (anonymous request OK)
--
--   header_filter phase
--     └─ Stashed cookie value exists  → add Set-Cookie to outgoing response
--
-- ─────────────────────────────────────────────────────────────────────────────

local cipher_lib = require "resty.openssl.cipher"
local hmac_lib   = require "resty.openssl.hmac"
local rand_lib   = require "resty.openssl.rand"
local cjson      = require "cjson.safe"

-- LuaJIT's built-in bit library (always available in OpenResty / Kong)
local bit    = bit   -- luacheck: ignore
local kong   = kong  -- luacheck: ignore
local ngx    = ngx   -- luacheck: ignore
local string = string
local table  = table
local type   = type
local math   = math

local CookieSessionHandler = {
  VERSION  = "1.0.0",
  PRIORITY = 1000,      -- runs before most auth plugins; adjust as needed
}

-- ── Low-level helpers ─────────────────────────────────────────────────────────

-- Decode a lowercase/uppercase hex string to its binary equivalent.
-- Used to turn the 64-char hex encryption_secret into a 32-byte key.
local function hex_decode(hex)
  return (hex:gsub("..", function(h)
    return string.char(tonumber(h, 16))
  end))
end

-- Base64URL encode (RFC 4648 §5): no padding, '+' → '-', '/' → '_'
local function b64url_encode(data)
  return (ngx.encode_base64(data)
           :gsub("+", "-")
           :gsub("/", "_")
           :gsub("=+$", ""))
end

-- Base64URL decode: restore standard Base64, re-add padding, then decode.
local function b64url_decode(s)
  if not s then return nil end
  -- Restore standard Base64 alphabet
  s = s:gsub("-", "+"):gsub("_", "/")
  -- Re-add '=' padding so the length is a multiple of 4
  local rem = #s % 4
  if rem == 2 then
    s = s .. "=="
  elseif rem == 3 then
    s = s .. "="
  end
  return ngx.decode_base64(s)
end

-- Constant-time byte comparison to prevent timing oracle attacks on HMAC.
-- Both operands must be the same type (string); length difference leaks
-- only the fact that the MAC is wrong (not which byte differed).
local function ct_equal(a, b)
  if type(a) ~= "string" or type(b) ~= "string" then
    return false
  end
  -- XOR the lengths first so a length mismatch always produces acc != 0
  local acc = bit.bxor(#a, #b)
  local len = math.max(#a, #b)
  for i = 1, len do
    local ba = string.byte(a, i) or 0
    local bb = string.byte(b, i) or 0
    acc = bit.bor(acc, bit.bxor(ba, bb))
  end
  return acc == 0
end

-- ── Cryptographic primitives ──────────────────────────────────────────────────

-- Encrypt `plaintext` with AES-256-GCM using `key_bytes` (32 raw bytes).
-- Returns: iv, ciphertext, tag — all as raw binary strings.
-- Returns: nil, nil, nil, err_string on failure.
local function aes_gcm_encrypt(plaintext, key_bytes)
  -- Generate a fresh 12-byte (96-bit) IV for every encryption call.
  -- Reusing an IV with the same key is catastrophic for GCM security.
  local iv, err = rand_lib.bytes(12)
  if not iv then
    return nil, nil, nil, "rand.bytes failed: " .. tostring(err)
  end

  local c, err = cipher_lib.new("aes-256-gcm")
  if not c then
    return nil, nil, nil, "cipher.new failed: " .. tostring(err)
  end

  local ok, err = c:init(key_bytes, iv, { is_encrypt = true })
  if not ok then
    return nil, nil, nil, "cipher:init failed: " .. tostring(err)
  end

  -- update() may return an empty string for streaming block ciphers; always
  -- accumulate both parts to reconstruct the full ciphertext.
  local ct1, err = c:update(plaintext)
  if err then
    return nil, nil, nil, "cipher:update failed: " .. tostring(err)
  end

  local ct2, err = c:final()
  if err then
    return nil, nil, nil, "cipher:final failed: " .. tostring(err)
  end

  -- 16-byte (128-bit) authentication tag covers IV + ciphertext under GCM
  local tag, err = c:get_aead_tag(16)
  if not tag then
    return nil, nil, nil, "get_aead_tag failed: " .. tostring(err)
  end

  return iv, (ct1 or "") .. (ct2 or ""), tag
end

-- Decrypt `ciphertext` with AES-256-GCM.
-- GCM internally verifies the tag; final() will fail if the ciphertext or
-- tag has been tampered with, providing authenticated decryption.
-- Returns: plaintext_string or nil, err_string.
local function aes_gcm_decrypt(iv, ciphertext, tag, key_bytes)
  local c, err = cipher_lib.new("aes-256-gcm")
  if not c then
    return nil, "cipher.new failed: " .. tostring(err)
  end

  local ok, err = c:init(key_bytes, iv, { is_encrypt = false })
  if not ok then
    return nil, "cipher:init failed: " .. tostring(err)
  end

  -- Tag MUST be set before calling final() in decrypt mode
  local ok, err = c:set_aead_tag(tag)
  if not ok then
    return nil, "set_aead_tag failed: " .. tostring(err)
  end

  local pt1, err = c:update(ciphertext)
  if err then
    return nil, "cipher:update failed: " .. tostring(err)
  end

  -- If the GCM tag does not verify, final() returns an error here.
  local pt2, err = c:final()
  if err then
    return nil, "GCM authentication failed (tag mismatch or corrupt data): " .. tostring(err)
  end

  return (pt1 or "") .. (pt2 or "")
end

-- Compute HMAC-SHA256 of `data` using `key` (raw string of any length).
-- Returns: raw 32-byte digest, or nil + err_string.
local function hmac_sha256(key, data)
  local h, err = hmac_lib.new(key, "sha256")
  if not h then
    return nil, "hmac.new failed: " .. tostring(err)
  end

  local ok, err = h:update(data)
  if not ok then
    return nil, "hmac:update failed: " .. tostring(err)
  end

  local digest, err = h:final()
  if not digest then
    return nil, "hmac:final failed: " .. tostring(err)
  end

  return digest
end

-- ── Cookie encoding / decoding ────────────────────────────────────────────────

-- Build a signed, encrypted cookie value from a JSON payload string.
-- Returns: cookie_value_string or nil, err_string.
local function encode_cookie(payload_json, conf)
  -- NOTE: hex_decode is called once per request, not cached, to avoid
  -- holding the raw key in upvalue memory across requests.
  local key_bytes = hex_decode(conf.encryption_secret)

  local iv, ct, tag, err = aes_gcm_encrypt(payload_json, key_bytes)
  if not iv then
    -- Do NOT include key material in the error string
    return nil, "encryption failed: " .. tostring(err)
  end

  local iv_b64  = b64url_encode(iv)
  local ct_b64  = b64url_encode(ct)
  local tag_b64 = b64url_encode(tag)

  -- The HMAC covers all three Base64URL segments exactly as they appear in
  -- the cookie, binding the IV and tag to this specific ciphertext.
  local protected = iv_b64 .. "." .. ct_b64 .. "." .. tag_b64

  local mac, err = hmac_sha256(conf.signing_secret, protected)
  if not mac then
    return nil, "HMAC computation failed: " .. tostring(err)
  end

  return protected .. "." .. b64url_encode(mac)
end

-- Parse, verify, and decrypt a cookie value produced by encode_cookie().
-- Returns: session_table or nil, err_string.
local function decode_cookie(cookie_value, conf)
  -- ── Step 1: structural validation ───────────────────────────────────────
  -- Split on '.' to get exactly 4 Base64URL segments
  local parts = {}
  for seg in cookie_value:gmatch("[^.]+") do
    parts[#parts + 1] = seg
  end
  if #parts ~= 4 then
    return nil, "malformed cookie: expected 4 dot-separated segments, got " .. #parts
  end

  local iv_b64, ct_b64, tag_b64, mac_b64 = parts[1], parts[2], parts[3], parts[4]
  local protected = iv_b64 .. "." .. ct_b64 .. "." .. tag_b64

  -- ── Step 2: HMAC verification (constant-time) ────────────────────────────
  -- Compute the expected MAC over the protected header before touching any
  -- ciphertext. This short-circuits tampering without a decryption oracle.
  local expected_mac, err = hmac_sha256(conf.signing_secret, protected)
  if not expected_mac then
    return nil, "HMAC computation failed: " .. tostring(err)
  end

  local received_mac = b64url_decode(mac_b64)
  if not received_mac then
    return nil, "HMAC Base64URL decode failed"
  end

  -- ct_equal performs a constant-time comparison to prevent timing attacks
  if not ct_equal(expected_mac, received_mac) then
    return nil, "HMAC signature mismatch — cookie has been tampered with"
  end

  -- ── Step 3: decode binary components ────────────────────────────────────
  local iv  = b64url_decode(iv_b64)
  local ct  = b64url_decode(ct_b64)
  local tag = b64url_decode(tag_b64)

  if not iv or not ct or not tag then
    return nil, "Base64URL decode failed for one or more cookie segments"
  end

  -- ── Step 4: authenticated decryption (GCM verifies tag internally) ──────
  local key_bytes = hex_decode(conf.encryption_secret)
  local plaintext, err = aes_gcm_decrypt(iv, ct, tag, key_bytes)
  if not plaintext then
    return nil, "decryption failed: " .. tostring(err)
  end

  -- ── Step 5: JSON parse ───────────────────────────────────────────────────
  local session, err = cjson.decode(plaintext)
  if not session then
    return nil, "JSON decode failed: " .. tostring(err)
  end

  -- Sanity-check required fields
  if not session.id or not session.created_at or not session.last_used_at then
    return nil, "session payload missing required fields"
  end

  return session
end

-- ── Cookie header builders ────────────────────────────────────────────────────

-- Build a Set-Cookie header value for issuing or rolling a session.
local function build_set_cookie(value, conf)
  local parts = {
    conf.cookie_name .. "=" .. value,
    "Path=" .. conf.cookie_path,
    "HttpOnly",
    "SameSite=" .. conf.cookie_same_site,
  }
  if conf.cookie_secure then
    parts[#parts + 1] = "Secure"
  end
  -- Only emit Max-Age when explicitly configured; 0 means "session cookie"
  if conf.cookie_max_age and conf.cookie_max_age > 0 then
    parts[#parts + 1] = "Max-Age=" .. conf.cookie_max_age
  end
  return table.concat(parts, "; ")
end

-- Build a Set-Cookie header value that instructs browsers to delete the cookie.
local function build_clear_cookie(conf)
  local parts = {
    conf.cookie_name .. "=",   -- empty value
    "Max-Age=0",               -- delete immediately
    "Path=" .. conf.cookie_path,
    "HttpOnly",
    "SameSite=" .. conf.cookie_same_site,
  }
  if conf.cookie_secure then
    parts[#parts + 1] = "Secure"
  end
  return table.concat(parts, "; ")
end

-- ── Request cookie extraction ─────────────────────────────────────────────────

-- Parse the Cookie request header and return the value for `name`, or nil.
local function get_request_cookie(name)
  local header = kong.request.get_header("cookie")
  if not header then
    return nil
  end
  -- Cookies are separated by "; "; each entry is "name=value"
  for pair in header:gmatch("[^;]+") do
    local k, v = pair:match("^%s*([^=]+)%s*=%s*(.-)%s*$")
    if k == name then
      return v
    end
  end
  return nil
end

-- ── Shared rejection helper ───────────────────────────────────────────────────

-- Terminate the request with HTTP 401 and a clear-cookie directive.
-- IMPORTANT: this calls kong.response.exit(), which does NOT return to the
-- caller — Kong unwinds the coroutine after exit() is invoked.
local function reject_session(conf, reason)
  -- Log at INFO level: reason may contain partial cookie data but never keys
  kong.log.info("[cookie-session] session rejected: ", reason)

  return kong.response.exit(
    401,
    { message = "Session invalid or expired" },
    {
      ["Content-Type"] = "application/json",
      ["Set-Cookie"]   = build_clear_cookie(conf),
    }
  )
end

-- ── Plugin phases ─────────────────────────────────────────────────────────────

function CookieSessionHandler:access(conf)
  local now = ngx.now()   -- floating-point Unix timestamp

  -- ══════════════════════════════════════════════════════════════════════════
  -- Path A — Session Creation
  --
  -- Triggered when the downstream client sends:  create_session: true
  -- A new session is minted and the Set-Cookie will be added in header_filter.
  -- ══════════════════════════════════════════════════════════════════════════
  if kong.request.get_header("create_session") == "true" then
    local session_id = kong.utils.uuid()
    if not session_id then
      kong.log.err("[cookie-session] kong.utils.uuid() returned nil")
      return kong.response.exit(500, { message = "Internal server error" })
    end

    local payload = {
      id           = session_id,
      created_at   = now,
      last_used_at = now,
    }

    local payload_json, err = cjson.encode(payload)
    if not payload_json then
      kong.log.err("[cookie-session] cjson.encode failed: ", err)
      return kong.response.exit(500, { message = "Internal server error" })
    end

    local cookie_value, err = encode_cookie(payload_json, conf)
    if not cookie_value then
      -- Log the error category but never the raw secret or key material
      kong.log.err("[cookie-session] cookie encoding failed: ", err)
      return kong.response.exit(500, { message = "Internal server error" })
    end

    -- Strip the trigger header so it is never forwarded to the upstream service
    kong.service.request.clear_header("create_session")

    -- Stash cookie value; header_filter will attach it to the response
    kong.ctx.shared.cookie_session_value = cookie_value
    return   -- let the request proceed to the upstream
  end

  -- ══════════════════════════════════════════════════════════════════════════
  -- Path B — Session Validation (subsequent requests)
  --
  -- Requests without a session cookie pass through untouched (anonymous).
  -- Requests with a cookie undergo full verification and rolling update.
  -- ══════════════════════════════════════════════════════════════════════════
  local cookie_value = get_request_cookie(conf.cookie_name)
  if not cookie_value then
    -- No session cookie — anonymous request; policy enforcement (e.g.
    -- requiring authentication) is the responsibility of other plugins.
    return
  end

  -- ── 1. Signature verification + decryption ────────────────────────────────
  local session, err = decode_cookie(cookie_value, conf)
  if not session then
    return reject_session(conf, err)
  end

  -- ── 2. Idle-timeout check ─────────────────────────────────────────────────
  local idle = now - session.last_used_at
  if idle > conf.idle_timeout then
    return reject_session(conf,
      string.format("idle timeout exceeded (%.0fs > %ds)", idle, conf.idle_timeout))
  end

  -- ── 3. Rolling update — refresh last_used_at ──────────────────────────────
  session.last_used_at = now

  local updated_json, err = cjson.encode(session)
  if not updated_json then
    kong.log.err("[cookie-session] cjson.encode failed during roll: ", err)
    return reject_session(conf, "internal error during session roll")
  end

  local new_cookie_value, err = encode_cookie(updated_json, conf)
  if not new_cookie_value then
    kong.log.err("[cookie-session] cookie re-encoding failed: ", err)
    return reject_session(conf, "internal crypto error during session roll")
  end

  -- Stash the refreshed cookie; header_filter will attach it to the response
  kong.ctx.shared.cookie_session_value = new_cookie_value
end

function CookieSessionHandler:header_filter(conf)
  -- Retrieve the cookie value stashed by the access phase.
  -- This covers both the "new session" and "rolling update" cases.
  local value = kong.ctx.shared.cookie_session_value
  if not value then
    -- Nothing to add: either no session was involved, or the request was
    -- rejected (in which case exit() already set the clear-cookie header).
    return
  end

  -- Use add_header (not set_header) so upstream Set-Cookie headers are
  -- preserved. Browsers handle multiple Set-Cookie headers correctly.
  kong.response.add_header("Set-Cookie", build_set_cookie(value, conf))
end

return CookieSessionHandler
