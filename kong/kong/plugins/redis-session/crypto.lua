-- kong/plugins/redis-session/crypto.lua
--
-- Cryptographic helpers for the redis-session plugin.
--
-- Cookie wire format (the value stored in the browser cookie):
--
--   Base64URL( AES-256-GCM( "<session_id>.<hmac_b64url>" ) )
--   ↓
--   "<iv_b64url>.<ciphertext_b64url>.<tag_b64url>"
--
-- Layered security:
--   1. HMAC-SHA256 binds the session ID to a secret key so a leaked Redis
--      key cannot be turned into a valid cookie.
--   2. AES-256-GCM hides the session ID from the browser and provides
--      authenticated encryption — any bit flip in the cookie is detected.
--
-- The session ID itself (UUID v4) is stored in Redis; the cookie contains
-- only the encrypted, signed reference to that ID.

local cipher_lib = require "resty.openssl.cipher"
local hmac_lib   = require "resty.openssl.hmac"
local rand_lib   = require "resty.openssl.rand"

local bit    = bit   -- LuaJIT built-in, always available
local ngx    = ngx
local string = string
local type   = type
local math   = math

local _M = {}

-- ── Encoding helpers ──────────────────────────────────────────────────────────

-- Convert a lower/uppercase hex string to its binary equivalent.
-- Used to turn the 64-char hex encryption_secret into a 32-byte AES key.
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

-- Base64URL decode: restore standard Base64, re-add '=' padding, then decode.
local function b64url_decode(s)
  if not s then return nil end
  s = s:gsub("-", "+"):gsub("_", "/")
  local rem = #s % 4
  if rem == 2 then
    s = s .. "=="
  elseif rem == 3 then
    s = s .. "="
  end
  return ngx.decode_base64(s)
end

-- ── Constant-time comparison ──────────────────────────────────────────────────

-- Compares two strings in constant time to prevent timing-oracle attacks on
-- the HMAC check. XORs all bytes (using the longer length) and ORs the
-- length difference into the accumulator, so mismatches at any position —
-- or a length difference — always produce acc != 0.
local function ct_equal(a, b)
  if type(a) ~= "string" or type(b) ~= "string" then
    return false
  end
  local acc = bit.bxor(#a, #b)     -- non-zero if lengths differ
  local len = math.max(#a, #b)
  for i = 1, len do
    local ba = string.byte(a, i) or 0
    local bb = string.byte(b, i) or 0
    acc = bit.bor(acc, bit.bxor(ba, bb))
  end
  return acc == 0
end

-- ── AES-256-GCM ───────────────────────────────────────────────────────────────

-- Encrypt plaintext with AES-256-GCM.
-- `key_hex` is the 64-char hex encryption_secret from config.
--
-- Returns: "<iv_b64url>.<ciphertext_b64url>.<tag_b64url>" or nil, err_string.
function _M.encrypt(plaintext, key_hex)
  local key_bytes = hex_decode(key_hex)

  -- A fresh 12-byte (96-bit) IV is required per encryption call.
  -- Reusing an IV with the same GCM key is a catastrophic security failure.
  local iv, err = rand_lib.bytes(12)
  if not iv then
    return nil, "rand.bytes failed: " .. tostring(err)
  end

  local c, err = cipher_lib.new("aes-256-gcm")
  if not c then return nil, "cipher.new: " .. tostring(err) end

  local ok, err = c:init(key_bytes, iv, { is_encrypt = true })
  if not ok then return nil, "cipher:init: " .. tostring(err) end

  -- update() returns intermediate ciphertext bytes (may be empty for short inputs)
  local ct1, err = c:update(plaintext)
  if err then return nil, "cipher:update: " .. tostring(err) end

  local ct2, err = c:final()
  if err then return nil, "cipher:final: " .. tostring(err) end

  -- 16-byte (128-bit) authentication tag — covers IV + ciphertext under GCM
  local tag, err = c:get_aead_tag(16)
  if not tag then return nil, "get_aead_tag: " .. tostring(err) end

  local ciphertext = (ct1 or "") .. (ct2 or "")
  return b64url_encode(iv) .. "." .. b64url_encode(ciphertext) .. "." .. b64url_encode(tag)
end

-- Decrypt a value produced by _M.encrypt().
-- Input: "<iv_b64url>.<ciphertext_b64url>.<tag_b64url>"
--
-- Returns: plaintext_string or nil, err_string.
-- If the tag does not verify (tampered ciphertext), final() returns an error.
function _M.decrypt(encoded, key_hex)
  -- Parse the three Base64URL segments
  local parts = {}
  for seg in encoded:gmatch("[^.]+") do
    parts[#parts + 1] = seg
  end
  if #parts ~= 3 then
    return nil, "expected 3 dot-separated segments, got " .. #parts
  end

  local iv  = b64url_decode(parts[1])
  local ct  = b64url_decode(parts[2])
  local tag = b64url_decode(parts[3])
  if not iv or not ct or not tag then
    return nil, "base64url decode failed for one or more segments"
  end

  local key_bytes = hex_decode(key_hex)

  local c, err = cipher_lib.new("aes-256-gcm")
  if not c then return nil, "cipher.new: " .. tostring(err) end

  local ok, err = c:init(key_bytes, iv, { is_encrypt = false })
  if not ok then return nil, "cipher:init: " .. tostring(err) end

  -- Tag must be set before calling final() in GCM decrypt mode
  local ok, err = c:set_aead_tag(tag)
  if not ok then return nil, "set_aead_tag: " .. tostring(err) end

  local pt1, err = c:update(ct)
  if err then return nil, "cipher:update: " .. tostring(err) end

  -- final() fails here if the GCM authentication tag does not match,
  -- meaning the ciphertext or IV has been tampered with.
  local pt2, err = c:final()
  if err then
    return nil, "GCM authentication failed (tampered ciphertext or wrong key): " .. tostring(err)
  end

  return (pt1 or "") .. (pt2 or "")
end

-- ── HMAC-SHA256 ───────────────────────────────────────────────────────────────

-- Compute HMAC-SHA256 of `data` using `secret`.
-- Returns: Base64URL-encoded digest string, or nil, err_string.
function _M.sign(data, secret)
  local h, err = hmac_lib.new(secret, "sha256")
  if not h then return nil, "hmac.new: " .. tostring(err) end

  local ok, err = h:update(data)
  if not ok then return nil, "hmac:update: " .. tostring(err) end

  local digest, err = h:final()
  if not digest then return nil, "hmac:final: " .. tostring(err) end

  return b64url_encode(digest)
end

-- Verify HMAC-SHA256 of `data` against `signature_b64url` using `secret`.
-- Uses constant-time comparison to prevent timing attacks.
-- Returns: true (valid) or false.
function _M.verify(data, signature_b64url, secret)
  local h, err = hmac_lib.new(secret, "sha256")
  if not h then return false end

  local ok = h:update(data)
  if not ok then return false end

  local expected = h:final()
  if not expected then return false end

  local received = b64url_decode(signature_b64url)
  if not received then return false end

  return ct_equal(expected, received)
end

-- ── Cookie building / parsing ─────────────────────────────────────────────────

-- Build the final cookie value from a session ID:
--
--   Step 1 — HMAC-sign the session_id (UUID, no dots):
--              hmac_b64 = HMAC-SHA256( session_id, signing_secret )
--
--   Step 2 — Concatenate into a plaintext with a single dot separator:
--              plaintext = "<session_id>.<hmac_b64>"
--              (UUIDs and base64url strings both contain no literal dots,
--               so the first dot is always the delimiter)
--
--   Step 3 — AES-256-GCM encrypt the plaintext:
--              cookie_value = "<iv_b64>.<ct_b64>.<tag_b64>"
--
-- Returns: cookie_value_string or nil, err_string.
function _M.build_cookie_value(session_id, conf)
  local hmac_b64, err = _M.sign(session_id, conf.signing_secret)
  if not hmac_b64 then
    return nil, "sign failed: " .. tostring(err)
  end

  -- Plaintext before encryption: "<uuid>.<hmac_b64url>"
  local plaintext = session_id .. "." .. hmac_b64

  local cookie_value, err = _M.encrypt(plaintext, conf.encryption_secret)
  if not cookie_value then
    return nil, "encrypt failed: " .. tostring(err)
  end

  return cookie_value
end

-- Parse and verify a cookie value produced by build_cookie_value().
--
--   Step 1 — AES-256-GCM decrypt → plaintext "<session_id>.<hmac_b64>"
--   Step 2 — Split on the first '.' to recover session_id and hmac_b64
--             (safe: UUIDs and base64url both have no dots)
--   Step 3 — Constant-time HMAC verification
--   Step 4 — Return session_id
--
-- Returns: session_id_string or nil, err_string.
function _M.parse_cookie_value(cookie_str, conf)
  -- Decrypt (GCM tag verification happens here)
  local plaintext, err = _M.decrypt(cookie_str, conf.encryption_secret)
  if not plaintext then
    return nil, "decryption failed: " .. tostring(err)
  end

  -- Split on the first literal dot
  local dot_pos = plaintext:find(".", 1, true)
  if not dot_pos then
    return nil, "malformed plaintext: separator dot not found"
  end

  local session_id = plaintext:sub(1, dot_pos - 1)
  local hmac_b64   = plaintext:sub(dot_pos + 1)

  if session_id == "" or hmac_b64 == "" then
    return nil, "malformed plaintext: empty session_id or hmac segment"
  end

  -- Constant-time HMAC verification (second authentication layer)
  if not _M.verify(session_id, hmac_b64, conf.signing_secret) then
    return nil, "HMAC signature mismatch — cookie has been tampered with"
  end

  return session_id
end

return _M
