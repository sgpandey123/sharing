-- kong/plugins/redis-session/handler.lua
--
-- Server-side session management with Redis as the session store.
-- The browser cookie contains only an encrypted, signed reference to the
-- session ID — all session data lives exclusively in Redis.
--
-- ── Request flow ─────────────────────────────────────────────────────────────
--
--   access phase (all business logic lives here)
--   │
--   ├─ Header `create_session: true`
--   │    → generate UUID → store JSON in Redis (with TTL)
--   │    → build encrypted+signed cookie → stash for header_filter
--   │    → strip trigger header → pass request through to upstream
--   │
--   ├─ Header `destroy_session: true` + cookie present
--   │    → decrypt/verify cookie → DEL Redis key
--   │    → exit(200, "Session destroyed") + clear cookie
--   │
--   ├─ Cookie present (normal authenticated request)
--   │    → decrypt/verify cookie → GET Redis key
--   │    → idle-timeout check → UPDATE last_used_at + reset TTL
--   │    → stash refreshed cookie for header_filter
--   │    → pass request through to upstream
--   │
--   └─ No cookie (anonymous request) → pass through untouched
--
--   header_filter phase
--   └─ If a cookie value was stashed in access → add Set-Cookie to response
--
-- ── Error policy ─────────────────────────────────────────────────────────────
--
--   Cookie / signature / decryption failure → 401  + clear cookie
--   Redis miss (session not found)          → 401  + clear cookie
--   Idle timeout exceeded                   → 401  + clear cookie + DEL key
--   Redis connection / command error        → 503  (no cookie change)

local redis_mod  = require "kong.plugins.redis-session.redis"
local crypto_mod = require "kong.plugins.redis-session.crypto"
local cjson      = require "cjson.safe"

local kong   = kong
local ngx    = ngx
local string = string
local table  = table

local RedisSessionHandler = {
  VERSION  = "1.0.0",
  PRIORITY = 1000,    -- runs before auth plugins; adjust if needed
}

-- ── Cookie header utilities ───────────────────────────────────────────────────

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
  -- Omit Max-Age entirely when set to 0 (browser treats it as a session cookie)
  if conf.cookie_max_age and conf.cookie_max_age > 0 then
    parts[#parts + 1] = "Max-Age=" .. conf.cookie_max_age
  end
  return table.concat(parts, "; ")
end

local function build_clear_cookie(conf)
  local parts = {
    conf.cookie_name .. "=",    -- empty value
    "Max-Age=0",                 -- instruct browser to delete immediately
    "Path=" .. conf.cookie_path,
    "HttpOnly",
    "SameSite=" .. conf.cookie_same_site,
  }
  if conf.cookie_secure then
    parts[#parts + 1] = "Secure"
  end
  return table.concat(parts, "; ")
end

-- Parse the Cookie request header and return the named cookie's value, or nil.
local function get_request_cookie(name)
  local header = kong.request.get_header("cookie")
  if not header then return nil end
  for pair in header:gmatch("[^;]+") do
    local k, v = pair:match("^%s*([^=]+)%s*=%s*(.-)%s*$")
    if k == name then return v end
  end
  return nil
end

-- ── Response helpers ──────────────────────────────────────────────────────────

-- Terminate with HTTP 401. Clears the session cookie so the browser does not
-- keep sending an invalid token on every subsequent request.
local function reject_session(conf, reason)
  kong.log.info("[redis-session] rejecting: ", reason)
  return kong.response.exit(
    401,
    { message = "Session invalid or expired" },
    {
      ["Content-Type"] = "application/json",
      ["Set-Cookie"]   = build_clear_cookie(conf),
    }
  )
end

-- Terminate with HTTP 503 when Redis is unreachable or returns an unexpected
-- error. The session cookie is left unchanged so the client can retry.
local function store_error(reason)
  kong.log.err("[redis-session] Redis error: ", reason)
  return kong.response.exit(
    503,
    { message = "Session store unavailable" },
    { ["Content-Type"] = "application/json" }
  )
end

-- ── Plugin phases ─────────────────────────────────────────────────────────────

function RedisSessionHandler:access(conf)
  local now = ngx.now()

  local create_hdr  = kong.request.get_header("create_session")
  local destroy_hdr = kong.request.get_header("destroy_session")
  local cookie_val  = get_request_cookie(conf.cookie_name)

  -- ════════════════════════════════════════════════════════════════════════════
  -- Path A — Session Creation  (`create_session: true`)
  --
  -- Generates a new session, stores it in Redis, and issues an encrypted cookie.
  -- The request still proceeds to the upstream — the cookie arrives on the
  -- response via header_filter.
  -- ════════════════════════════════════════════════════════════════════════════
  if create_hdr == "true" then
    local session_id = kong.utils.uuid()
    if not session_id then
      kong.log.err("[redis-session] kong.utils.uuid() returned nil")
      return kong.response.exit(500, { message = "Internal server error" })
    end

    local session_data = {
      id           = session_id,
      created_at   = now,
      last_used_at = now,
    }

    local session_json, err = cjson.encode(session_data)
    if not session_json then
      kong.log.err("[redis-session] cjson.encode failed: ", err)
      return kong.response.exit(500, { message = "Internal server error" })
    end

    -- Store session data in Redis; key = "<prefix><uuid>", TTL = idle_timeout
    local redis_key = conf.session_key_prefix .. session_id
    local red, err  = redis_mod.connect(conf)
    if not red then
      return store_error(err)
    end

    local ok, err = redis_mod.set(red, redis_key, session_json, conf.idle_timeout)
    redis_mod.release(red, conf)  -- MUST release even if set fails

    if not ok then
      return store_error(err)
    end

    -- Build the encrypted, HMAC-signed cookie value
    local encrypted_cookie, err = crypto_mod.build_cookie_value(session_id, conf)
    if not encrypted_cookie then
      -- Do not log session_id as it could correlate to a live Redis key
      kong.log.err("[redis-session] build_cookie_value failed: ", err)
      return kong.response.exit(500, { message = "Internal server error" })
    end

    -- Remove the trigger header so the upstream service never sees it
    kong.service.request.clear_header("create_session")

    -- Stash cookie value; header_filter will attach it to the upstream response
    kong.ctx.shared.redis_session_cookie = encrypted_cookie
    return   -- let the request proceed normally
  end

  -- ════════════════════════════════════════════════════════════════════════════
  -- Path B — Session Destruction  (`destroy_session: true`)
  --
  -- Validates the cookie (to prevent CSRF-style forced logouts by a third
  -- party), deletes the Redis key, clears the cookie, and returns 200.
  -- ════════════════════════════════════════════════════════════════════════════
  if destroy_hdr == "true" then
    if cookie_val then
      local session_id, err = crypto_mod.parse_cookie_value(cookie_val, conf)
      if session_id then
        -- Best-effort Redis delete: even if Redis is down we still clear the cookie
        local red, conn_err = redis_mod.connect(conf)
        if red then
          local redis_key = conf.session_key_prefix .. session_id
          local ok, del_err = redis_mod.del(red, redis_key)
          redis_mod.release(red, conf)
          if not ok then
            kong.log.warn("[redis-session] DEL failed during destroy: ", del_err)
          end
        else
          kong.log.warn("[redis-session] Redis unavailable during destroy: ", conn_err)
        end
      else
        -- Cookie was invalid — still clear it from the browser
        kong.log.info("[redis-session] destroy with invalid cookie: ", err)
      end
    end

    -- Always return 200 (idempotent) and clear the cookie
    return kong.response.exit(
      200,
      { message = "Session destroyed" },
      {
        ["Content-Type"] = "application/json",
        ["Set-Cookie"]   = build_clear_cookie(conf),
      }
    )
  end

  -- ════════════════════════════════════════════════════════════════════════════
  -- Path C — Session Validation & Rolling Update
  --
  -- Handles every authenticated request after the initial session creation.
  -- ════════════════════════════════════════════════════════════════════════════
  if not cookie_val then
    -- Anonymous request — pass through without touching anything
    return
  end

  -- ── Step 1: Decrypt cookie and verify HMAC ───────────────────────────────
  local session_id, err = crypto_mod.parse_cookie_value(cookie_val, conf)
  if not session_id then
    return reject_session(conf, "cookie parse failed: " .. tostring(err))
  end

  -- ── Step 2: Redis lookup ─────────────────────────────────────────────────
  local redis_key = conf.session_key_prefix .. session_id
  local red, err  = redis_mod.connect(conf)
  if not red then
    return store_error(err)
  end

  local session_json, get_err = redis_mod.get(red, redis_key)
  if get_err then
    redis_mod.release(red, conf)
    return store_error(get_err)
  end

  if not session_json then
    -- Key does not exist: session expired in Redis or was explicitly deleted
    redis_mod.release(red, conf)
    return reject_session(conf, "session key not found in Redis (expired or destroyed)")
  end

  -- ── Step 3: Parse session data ───────────────────────────────────────────
  local session, err = cjson.decode(session_json)
  if not session then
    redis_mod.release(red, conf)
    return reject_session(conf, "corrupt session data in Redis: " .. tostring(err))
  end

  -- ── Step 4: Idle timeout check ───────────────────────────────────────────
  -- Redis TTL already provides a hard expiry, but we enforce an explicit
  -- idle check here to allow tighter-than-TTL expiry when desired, and to
  -- provide an immediate delete rather than waiting for TTL to lapse.
  local idle = now - (session.last_used_at or 0)
  if idle > conf.idle_timeout then
    -- Actively remove the stale key rather than waiting for TTL
    redis_mod.del(red, redis_key)
    redis_mod.release(red, conf)
    return reject_session(conf,
      string.format("idle timeout exceeded (%.0fs > %ds)", idle, conf.idle_timeout))
  end

  -- ── Step 5: Rolling update — refresh last_used_at and reset Redis TTL ────
  session.last_used_at = now

  local updated_json, err = cjson.encode(session)
  if not updated_json then
    redis_mod.release(red, conf)
    kong.log.err("[redis-session] cjson.encode failed during roll: ", err)
    -- Session was valid; don't reject — just skip the update this cycle
    return
  end

  local ok, set_err = redis_mod.set(red, redis_key, updated_json, conf.idle_timeout)
  redis_mod.release(red, conf)

  if not ok then
    -- Log the error but allow the request through — the session was valid.
    -- The TTL will slide naturally on the next successful update.
    kong.log.err("[redis-session] failed to refresh session TTL: ", set_err)
  end

  -- Re-encrypt the cookie (same session ID, fresh IV per encryption call)
  -- so each response carries a new ciphertext — makes replay-window analysis harder.
  local new_cookie, err = crypto_mod.build_cookie_value(session_id, conf)
  if not new_cookie then
    kong.log.err("[redis-session] build_cookie_value failed during roll: ", err)
    return   -- session was valid; proceed without updating the cookie
  end

  -- Stash for header_filter to attach to the upstream response
  kong.ctx.shared.redis_session_cookie = new_cookie
end

function RedisSessionHandler:header_filter(conf)
  -- Attach the Set-Cookie header to the upstream response for both the
  -- "create" path (new session) and the "validate" path (rolling update).
  local value = kong.ctx.shared.redis_session_cookie
  if not value then return end

  -- Use add_header so any upstream Set-Cookie headers are preserved alongside ours
  kong.response.add_header("Set-Cookie", build_set_cookie(value, conf))
end

return RedisSessionHandler
