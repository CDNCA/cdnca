-- Run with the OpenResty LuaJIT runtime; argv[1] is this test's directory.
local cjson = require("cjson.safe")
local root = assert(arg[1], "missing l4geo directory")
local function read(path)
    local file = assert(io.open(path, "rb"))
    local value = file:read("*a")
    file:close()
    return value
end
local source = read(root .. "/engine.lua")
local compile = assert(loadstring((source:gsub("\nreturn _M\n", "\nreturn compile_config\n"))))()
local function fixture()
    return assert(cjson.decode(read(root .. "/fixtures/config-v2.json")))
end
assert(compile(fixture()), "historical V2 fixture rejected")
local value = fixture()
value.revision = 9
value.listeners[1].resource_revision = 3
value.listeners[1].geo.revision = 3
assert(compile(value), "source 9/resource 3 rejected")
value.listeners[1].geo.revision = 9
local rejected, reason = compile(value)
assert(not rejected and reason == "geo_scope_mismatch", "Geo accepted source revision as resource identity")
for _, revision in ipairs({0, -1, 1.5, 9007199254740992}) do
    value = fixture()
    value.listeners[1].resource_revision = revision
    rejected, reason = compile(value)
    assert(not rejected and reason == "geo_revision_invalid", "invalid resource revision accepted")
end
value = fixture()
value.listeners[1].resource_revision = value.revision
assert(compile(value), "explicit equal resource revision rejected")
print("L4_GEO_RESOURCE_REVISION_PASS legacy=1 independent=1 mismatched=1 invalid=4 equal=1")
