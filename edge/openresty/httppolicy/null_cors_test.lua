-- Run with the OpenResty resty CLI; argv[1] is this test's directory.
-- The agent publishes a site without CORS as "cors":null (Go *CORSPolicy nil);
-- cjson decodes that to cjson.null, which the engine must treat as "no CORS".
local root = assert(arg[1], "missing httppolicy directory")
local file = assert(io.open(root .. "/engine.lua", "rb"))
local source = file:read("*a")
file:close()
local validate_policy = assert(loadstring((source:gsub("\nreturn _M\n", "\nreturn validate_policy\n"))))()
local cjson = require("cjson.safe")

-- Canonical bytes of httppolicy.CompileJSON for a site without CORS.
local canonical = '{"schema_version":"cdnca.edge.http-policy/v1","policy_version":1,"sites":[{"site_id":"s",'
    .. '"max_upload_bytes":16,"request_headers":[],"response_headers":[],"rewrites":[],'
    .. '"redirect_allowed_hosts":["a.example"],"redirects":[],"cors":null,"referer_check":null}]}'
local sites, reason = validate_policy(assert(cjson.decode(canonical)))
assert(sites, "policy without CORS rejected: " .. tostring(reason))
assert(sites.s.cors == nil, "null CORS must read as no CORS")

local absent = canonical:gsub(',"cors":null', "")
assert(validate_policy(assert(cjson.decode(absent))), "policy with CORS omitted rejected")

local invalid = canonical:gsub('"cors":null', '"cors":{}')
local rejected, invalid_reason = validate_policy(assert(cjson.decode(invalid)))
assert(not rejected and invalid_reason == "site_1_cors", "empty CORS object accepted")
-- Hotlink protection (ge-waf S8): null is no check, an empty check is refused.
assert(sites.s.referer_check == nil, "null referer_check must read as no check")
local referer = canonical:gsub('"referer_check":null', '"referer_check":{"allow_empty":true,"allow_same_domain":true,'
    .. '"allowed_domains":["*.a.example"],"denied_domains":[],"check_origin":false,"extensions":["jpg"]}')
assert(validate_policy(assert(cjson.decode(referer))), "valid referer_check rejected")
local empty_check = canonical:gsub('"referer_check":null', '"referer_check":{"allow_empty":true,"allow_same_domain":false,'
    .. '"allowed_domains":[],"denied_domains":[],"check_origin":false,"extensions":[]}')
local empty_rejected, empty_reason = validate_policy(assert(cjson.decode(empty_check)))
assert(not empty_rejected and empty_reason == "site_1_referer_check", "referer_check restricting nothing accepted")
print("HTTP_POLICY_NULL_CORS_PASS null=1 absent=1 invalid=1 referer=2")
