-- cookie-session-1.0.0-1.rockspec
--
-- LuaRocks packaging descriptor for the cookie-session Kong plugin.
--
-- Installation:
--   luarocks make cookie-session-1.0.0-1.rockspec
--
-- Or install directly from the rock:
--   luarocks install cookie-session
--
-- After installation, register the plugin in kong.conf:
--   plugins = bundled,cookie-session

package = "cookie-session"
version = "1.0.0-1"

source = {
  url = "git+https://github.com/your-org/kong-plugin-cookie-session.git",
  tag = "v1.0.0",
}

description = {
  summary     = "Kong plugin for stateless session management via AES-256-GCM encrypted, HMAC-signed cookies",
  homepage    = "https://github.com/your-org/kong-plugin-cookie-session",
  license     = "Apache 2.0",
  maintainer  = "your-team@example.com",
}

-- Kong and lua-resty-openssl are provided by the Kong runtime; they are
-- listed here for documentation purposes rather than as installable rocks.
dependencies = {
  "lua >= 5.1",
}

build = {
  type    = "builtin",
  modules = {
    ["kong.plugins.cookie-session.handler"] = "kong/plugins/cookie-session/handler.lua",
    ["kong.plugins.cookie-session.schema"]  = "kong/plugins/cookie-session/schema.lua",
  },
}
