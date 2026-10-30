-- Run with the OpenResty resty CLI; argv[1] is this test's directory.
-- Regex rewrites/redirects with capture groups and prefix
-- redirects that keep the path after the prefix (preserve_path).
local root = assert(arg[1], "missing httppolicy directory")
local file = assert(io.open(root .. "/engine.lua", "rb"))
local source = file:read("*a")
file:close()
local exports = "\nreturn { validate_policy = validate_policy, rule_matches = rule_matches,"
    .. " rewrite_target = rewrite_target, expand = expand, location_escape = location_escape }\n"
local engine = assert(loadstring((source:gsub("\nreturn _M\n", exports))))()
local cjson = require("cjson.safe")

local site = {
    site_id = "s", max_upload_bytes = 16, request_headers = {}, response_headers = {},
    rewrites = {
        { rule_id = "rx", priority = 1, match_kind = "regex", match_path = "^/item/([0-9]+)/(\\w+)$",
          target_path = "/items/$2/$1", preserve_query = true, preserve_cookie = true },
    },
    redirect_allowed_hosts = { "a.example" },
    redirects = {
        { rule_id = "rd", priority = 2, match_kind = "regex", match_path = "^/u/(.+)$", status = 301,
          target_url = "https://a.example/users/$1", preserve_query = false, preserve_path = false },
        { rule_id = "keep", priority = 3, match_kind = "prefix", match_path = "/docs/", status = 302,
          target_url = "https://a.example/manual/", preserve_query = true, preserve_path = true },
        { rule_id = "fixed", priority = 4, match_kind = "prefix", match_path = "/old/", status = 302,
          target_url = "https://a.example/new", preserve_query = true, preserve_path = false },
    },
    cors = cjson.null,
}
local policy = { schema_version = "cdnca.edge.http-policy/v1", policy_version = 1, sites = { site } }
local sites, reason = engine.validate_policy(policy)
assert(sites, "valid regex policy rejected: " .. tostring(reason))

-- Rewrites: captures fill the template; a non-matching path is untouched.
local hit, captures = engine.rule_matches(site.rewrites[1], "/item/42/shoes")
assert(hit and engine.rewrite_target(site.rewrites[1], "/item/42/shoes", captures) == "/items/shoes/42", "regex rewrite")
assert(not engine.rule_matches(site.rewrites[1], "/item/x/shoes"), "regex rewrite matched a non-number")

-- Regex redirect: captures are percent-encoded into the Location path.
hit, captures = engine.rule_matches(site.redirects[1], "/u/a b")
assert(hit and engine.expand("/users/$1", captures, engine.location_escape) == "/users/a%20b", "regex redirect escape")

-- preserve_path keeps the suffix; a plain prefix rule does not.
assert(engine.location_escape("guide/intro.html") == "guide/intro.html", "suffix escaped needlessly")
assert(engine.rule_matches(site.redirects[2], "/docs/guide/intro.html"), "prefix keep did not match")

-- The node refuses what control refuses.
local function refused(mutate, label)
    local copy = cjson.decode(cjson.encode(policy))
    copy.sites[1].cors = cjson.null
    mutate(copy.sites[1])
    local ok = engine.validate_policy(copy)
    assert(not ok, label .. " accepted")
end
refused(function(s) s.rewrites[1].match_path = "/item" end, "unanchored regex")
refused(function(s) s.rewrites[1].match_path = "^/(" end, "invalid regex")
refused(function(s) s.rewrites[1].target_path = "/items/$" end, "bare dollar")
refused(function(s) s.rewrites[1].target_path = "/a/../$1" end, "target traversal")
refused(function(s) s.redirects[1].preserve_path = true end, "regex preserve_path")
refused(function(s) s.redirects[2].target_url = "https://a.example/manual" end, "preserve_path file target")
refused(function(s) s.redirects[3].preserve_path = nil end, "missing preserve_path")
print("HTTP_POLICY_REGEX_PASS rewrite=1 redirect=1 keep=1 refused=7")
