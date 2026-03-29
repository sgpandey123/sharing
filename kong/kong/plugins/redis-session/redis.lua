-- kong/plugins/redis-session/redis.lua
--
-- Redis connection and operation helpers for the redis-session plugin.
--
-- Design principles:
--   • Every exported function receives either `conf` (for connect/release) or
--     an already-established `red` connection (for get/set/del).
--   • Connections are returned to an nginx connection pool via set_keepalive()
--     after every use — caller MUST call release() even on error paths to
--     avoid connection leaks.
--   • The redis_password is never logged (use [REDACTED] placeholders).
--   • All functions return (result, nil) on success or (nil, err_string) on
--     failure so callers can use the standard `if not x then return nil, err`
--     pattern.

local redis_lib = require "resty.redis"
local kong      = kong
local ngx       = ngx
local tostring  = tostring
local string    = string

local _M = {}

-- ── Connection ────────────────────────────────────────────────────────────────

-- Establish a Redis connection, authenticate, and select the logical database.
--
-- Connections from a prior request may be reused from the nginx pool
-- automatically by resty.redis when connect() is called with the same
-- host/port/options tuple — set_keepalive() is what feeds the pool.
--
-- Returns: red (connection object) or nil, err_string.
function _M.connect(conf)
  local red = redis_lib:new()

  -- Overall socket timeout (connect + send + read) in milliseconds
  red:set_timeout(conf.redis_timeout)

  local ok, err = red:connect(conf.redis_host, conf.redis_port)
  if not ok then
    return nil, string.format(
      "connect to Redis %s:%d failed: %s",
      conf.redis_host, conf.redis_port, tostring(err)
    )
  end

  -- Authenticate if a password is configured.
  -- IMPORTANT: never log conf.redis_password — use [REDACTED].
  if conf.redis_password and conf.redis_password ~= "" then
    local ok, err = red:auth(conf.redis_password)
    if not ok then
      return nil, "Redis AUTH failed: " .. tostring(err)
        .. " (password: [REDACTED])"
    end
  end

  -- Select the logical database (0 is the default and requires no SELECT).
  if conf.redis_database and conf.redis_database ~= 0 then
    local ok, err = red:select(conf.redis_database)
    if not ok then
      return nil, "Redis SELECT " .. conf.redis_database .. " failed: " .. tostring(err)
    end
  end

  return red
end

-- ── Operations ────────────────────────────────────────────────────────────────

-- GET a key from Redis.
--
-- Returns: value_string  — key exists and has a value
--          nil            — key does not exist (ngx.null → converted to nil)
--          nil, err_string — Redis command failed
function _M.get(red, key)
  local val, err = red:get(key)
  if err then
    return nil, "Redis GET [" .. key .. "] failed: " .. tostring(err)
  end
  -- resty.redis represents a Redis nil bulk reply as the Lua userdata ngx.null
  if val == ngx.null then
    return nil
  end
  return val
end

-- SET a key in Redis with a sliding TTL (EX seconds).
--
-- Equivalent Redis command:  SET <key> <value> EX <ttl>
--
-- Returns: true or nil, err_string.
function _M.set(red, key, value, ttl)
  -- Passing "EX", ttl as extra variadic args maps to the Redis SET … EX option
  local res, err = red:set(key, value, "EX", ttl)
  if not res then
    return nil, "Redis SET [" .. key .. "] failed: " .. tostring(err)
  end
  if res ~= "OK" then
    return nil, "Redis SET [" .. key .. "] unexpected response: " .. tostring(res)
  end
  return true
end

-- DEL a key from Redis.
--
-- Silently succeeds if the key does not exist (DEL returns 0).
-- Returns: true or nil, err_string.
function _M.del(red, key)
  local n, err = red:del(key)
  if err then
    return nil, "Redis DEL [" .. key .. "] failed: " .. tostring(err)
  end
  return true
end

-- ── Connection pooling ────────────────────────────────────────────────────────

-- Return the connection to the nginx keep-alive pool so it can be reused
-- by a subsequent request without paying the TCP handshake cost.
--
--   redis_pool_timeout — max idle time (ms) a connection may sit in the pool
--   redis_pool_size    — max number of idle connections per nginx worker
--
-- Must be called after EVERY Redis operation, including error paths, to
-- prevent connection leaks that would exhaust the pool.
function _M.release(red, conf)
  local ok, err = red:set_keepalive(conf.redis_pool_timeout, conf.redis_pool_size)
  if not ok then
    -- Non-fatal: log and let the connection close naturally
    kong.log.warn("[redis-session] failed to return connection to pool: ", tostring(err))
  end
end

return _M
