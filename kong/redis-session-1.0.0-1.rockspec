-- redis-session-1.0.0-1.rockspec
--
-- LuaRocks packaging descriptor for the redis-session Kong plugin.
--
-- Installation:
--   luarocks make redis-session-1.0.0-1.rockspec
--
-- After installation, register the plugin in kong.conf:
--   plugins = bundled,redis-session

package = "redis-session"
version = "1.0.0-1"

source = {
  url = "git+https://github.com/your-org/kong-plugin-redis-session.git",
  tag = "v1.0.0",
}

description = {
  summary    = "Kong plugin for server-side session management backed by Redis, with AES-256-GCM encrypted and HMAC-signed session ID cookies",
  homepage   = "https://github.com/your-org/kong-plugin-redis-session",
  license    = "Apache 2.0",
  maintainer = "your-team@example.com",
}

-- Kong runtime provides resty.redis, resty.openssl, cjson, and kong.* —
-- they are listed here for documentation purposes, not as installable rocks.
dependencies = {
  "lua >= 5.1",
}

build = {
  type    = "builtin",
  modules = {
    ["kong.plugins.redis-session.handler"] = "kong/plugins/redis-session/handler.lua",
    ["kong.plugins.redis-session.schema"]  = "kong/plugins/redis-session/schema.lua",
    ["kong.plugins.redis-session.crypto"]  = "kong/plugins/redis-session/crypto.lua",
    ["kong.plugins.redis-session.redis"]   = "kong/plugins/redis-session/redis.lua",
  },
}
