-- cdnca dynamic routing security (ADR 0009 D7, site_runtime 9): CC, ACL/WAF
-- rules, firewall action, JS challenge and HTTP policy run from the site
-- object cdnca_site selected (cdnca.edge.site/v2 "security" and
-- "http_policy"), not from per-site server{} blocks. Phase order and the
-- decisions are v7's (libs/edgeconfig security fragments, site runtime v2
-- compiler writeRuntimePolicyLocation):
--
--   server_rewrite  CC (security.cc binding of the request's public port)
--   rewrite         ACL/WAF rule plan (D6 interpreter)
--   access          firewall action -> JS challenge -> HTTP policy
--   header_filter   HTTP policy response headers
--   log             CC completed-response counters
--
-- Everything derived from an object (compiled rule program, CC entry,
-- firewall matcher, HTTP policy entry, challenge engine instance) is cached
-- per worker by the digest or identity of what it was derived from; nothing
-- needs invalidation. A missing or invalid referenced object fails the
-- request closed (503), as v7 fails a release whose files do not verify.
--
-- Telemetry variables are $cdnca_security_* (dynroute-contract §1 item 4):
-- emit, type, action, severity, rule_id, block_page. The skeleton declares
-- them in its variable location (Variables below).
local site_module = require "cdnca_site"
local rule_plan = require "cdnca_rule_plan"

local ngx = ngx
local ngx_var = ngx.var
local type, tonumber, ipairs = type, tonumber, ipairs

local _M = { _VERSION = "1" }

-- Variables the skeleton must declare (edgeskeleton.Variables).
_M.VARIABLES = {
    "cdnca_security_emit", "cdnca_security_type", "cdnca_security_action",
    "cdnca_security_severity", "cdnca_security_rule_id", "cdnca_security_block_page",
}

local config = {
    cc_state_dict = "cdnca_cc_state",
    challenge_root = false,         -- <deployment root>/challenge (policies/<id>/versions/<v>.json)
    challenge_lua = false,          -- the node's challenge Lua directory (engine.lua, crypto.lua, ip.lua)
    challenge_state_dict = "cdnca_challenge_state",
    -- per-worker caches of derived objects (compiled rule programs, CC
    -- entries, HTTP policy entries, firewall matchers); size them to the
    -- node's hot site set, like cdnca_site's lru_items.
    cache_items = 10000,
    challenges = false,             -- delivered policy versions to preload: { { id = <uuid>, revision = <n> }, ... }
    -- rule pack mounts (ADR 0009 §8.4): the agent compiles a site's mounted
    -- WAF/ACL pack rules into <rule_plan_root>/<resolved_sha256>.json and its
    -- cc_v2 / challenge pack rules into
    -- <rule_plan_root>/<resolved_sha256>.<site_id>.cc.json (tmpfs, worker
    -- group readable) after its precheck reproduced resolved_sha256.
    rule_plan_root = false,
    -- this node's ID: the CC engine picks the auto switch override naming it
    -- (CC API v8, fix-fwregion).
    node_id = "",
}

local cc, interp, firewall, httppolicy
-- the auto defense gate (overlay values for CC, ADR 0010 §7A.2); absent when
-- the skeleton renders no auto defense dictionaries
local autodefense = ngx.shared.cdnca_autodefense and require("cdnca_autodefense")
local programs, challenge_instances
local preload_challenges

-- configure (init_by_lua, in the master): opts.challenge_root is where the
-- challenge secret rollout installs policies (the agent's <deployment
-- root>/challenge); opts.challenges lists the versions to preload.
function _M.configure(opts)
    opts = opts or {}
    for key, value in pairs(opts) do
        if config[key] == nil then error("cdnca_security.configure: unknown " .. key) end
        config[key] = value
    end
    programs = require("resty.lrucache").new(config.cache_items)
    cc = require "cc"
    cc.configure({ state_dict = config.cc_state_dict, object_items = config.cache_items, node_id = config.node_id, variables = {
        block_page = "cdnca_security_block_page", type = "cdnca_security_type", action = "cdnca_security_action",
        severity = "cdnca_security_severity", rule_id = "cdnca_security_rule_id", emit = "cdnca_security_emit",
        aggregate = "cdnca_security_aggregate",
    } })
    interp = require "cdnca_rule_interp"
    -- WAF v2 decisions (challenge / ban / auto block / observe) write the
    -- same $cdnca_security_* variables as CC (ge-waf).
    require("cdnca_waf").configure({ variables = {
        block_page = "cdnca_security_block_page", type = "cdnca_security_type", action = "cdnca_security_action",
        severity = "cdnca_security_severity", rule_id = "cdnca_security_rule_id", emit = "cdnca_security_emit",
    } })
    firewall = require "firewallaction.engine"
    firewall.configure_objects(config.cache_items)
    httppolicy = require "httppolicy.engine"
    httppolicy.configure_objects(config.cache_items)
    preload_challenges(config.challenges or nil)
end

local function read_object(digest)
    return site_module.object(digest)
end

local function unavailable(what, reason)
    ngx.log(ngx.ERR, "cdnca security: ", what, " unavailable: ", tostring(reason))
    pcall(function() ngx_var.cdnca_security_block_page = "1" end)
    return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end

local function public_port()
    return tonumber(ngx_var.proxy_protocol_server_port or ngx_var.server_port)
end

-- ---------------------------------------------------------------------------
-- CC (server_rewrite). v7 renders one server_rewrite hook per listener with a
-- CC binding; here the binding is the one whose ports hold the public port.
-- ---------------------------------------------------------------------------
--
-- Rule pack mounts (ADR 0009 §8.4) with cc_v2 / challenge rules: the agent
-- writes the site's pack policy (one CC v2 policy, the pack rules in the
-- published order user -> developer -> system) as
-- <rule_plan_root>/<resolved_sha256>.<site_id>.cc.json. It runs after the
-- site's own binding, on every port: a decision of the site's policy ends
-- the request; an explicit pass of it (trusted crawler, passed challenge,
-- log rule with flow stop: ngx.ctx.ccv2_stopped) is the site's exception
-- and skips the packs as well.

-- has_cc_mounts: whether a site object mounts CC-family packs (cached by
-- the site object digest).
local function has_cc_mounts(site)
    local key = "ccmounts:" .. ngx_var.cdnca_site_digest
    local cached = programs:get(key)
    if cached ~= nil then return cached end
    local found = false
    local mounts = site.security.mounts
    if type(mounts) == "table" then
        for _, mount in ipairs(mounts) do
            if type(mount) == "table" and (mount.engine == "cc_v2" or mount.engine == "challenge") then found = true end
        end
    end
    programs:set(key, found)
    return found
end

-- mount_cc(site) -> digest, bytes of the site's CC pack policy file (the
-- engine verifies the digest; the file never changes for its name).
local function mount_cc(site)
    local resolved = site.security.resolved_sha256
    if type(resolved) ~= "string" or #resolved ~= 64 or resolved:find("[^0-9a-f]") or
        type(site.site_id) ~= "string" or not site.site_id:match("^[0-9a-f-]+$") or #site.site_id ~= 36 then
        return nil, "site object"
    end
    local key = "mountcc:" .. resolved .. ":" .. site.site_id
    local cached = programs:get(key)
    if cached then return cached[1], cached[2] end
    if not config.rule_plan_root then return nil, "no rule plan root" end
    local file = io.open(config.rule_plan_root .. "/" .. resolved .. "." .. site.site_id .. ".cc.json", "rb")
    if not file then return nil, "missing" end
    local raw = file:read("*a")
    file:close()
    local hash = require("resty.sha256"):new()
    hash:update(raw)
    local digest = require("resty.string").to_hex(hash:final())
    programs:set(key, { digest, raw })
    return digest, raw
end

function _M.cc(site)
    local security = site.security
    local bindings = security and security.cc
    local packs = type(security) == "table" and has_cc_mounts(site)
    if type(bindings) == "table" and #bindings ~= 0 then
        local port = public_port()
        for _, binding in ipairs(bindings) do
            for _, bound in ipairs(binding.ports) do
                if bound == port then
                    ngx.ctx.ccv2_more = packs or nil
                    local result = cc.access_object(binding.policy.sha256, read_object, autodefense and autodefense.overlay(site.site_id))
                    ngx.ctx.ccv2_more = nil
                    if result ~= nil or not packs or ngx.ctx.ccv2_stopped then return result end
                    break
                end
            end
        end
    end
    if not packs then return end
    local digest, raw = mount_cc(site)
    if not digest then return unavailable("rule pack CC policy " .. tostring(security.resolved_sha256), raw) end
    return cc.access_object(digest, function() return raw end, autodefense and autodefense.overlay(site.site_id))
end

-- ---------------------------------------------------------------------------
-- ACL / WAF rule plan (rewrite): the site object's bound policies as a D6
-- program (cdnca_rule_plan), the decision applied as v7 enforce() does with
-- the $cdnca_security_* variables.
-- ---------------------------------------------------------------------------

-- Compiled programs per site object digest (the rules are part of the site
-- object, so its digest names them).

local function program_for(site, digest)
    local program = programs:get(digest)
    if program then return program end
    local plan, problem = rule_plan.plan(site.security.rules, true, site.site_id)
    if not plan then return nil, problem end
    local compiled, compile_error = interp.compile(plan)
    if not compiled then return nil, compile_error end
    programs:set(digest, compiled)
    return compiled
end

-- mount_program: the compiled plan of a site's mounted packs, cached by
-- resolved_sha256 (the plan file is named by it and never changes).
local function mount_program(resolved)
    local key = "mounts:" .. resolved
    local program = programs:get(key)
    if program then return program end
    if not config.rule_plan_root then return nil, "no rule plan root" end
    local file = io.open(config.rule_plan_root .. "/" .. resolved .. ".json", "rb")
    if not file then return nil, "missing" end
    local raw = file:read("*a")
    file:close()
    local compiled, problem = interp.compile_json(raw)
    if not compiled then return nil, problem end
    programs:set(key, compiled)
    return compiled
end

local function enforce(program)
    local verdict, kind, rule_id, policy_id = interp.evaluate(program)
    if verdict == "allow" then return end
    -- the deciding segment's policy (a mounted pack: NodeRuleID(pack, "@pack")):
    -- auto defense labels the sample by it (cdnca_autodefense INTEL_LABELS).
    -- The variable exists only with telemetry (the skeleton's telemetry
    -- server block); without it the write raises, so it is guarded as
    -- cdnca_waf.evidence does and never keeps the verdict from acting.
    if policy_id then pcall(function() ngx_var.cdnca_security_policy_id = policy_id end) end
    if verdict == "block" then
        if kind then
            ngx_var.cdnca_security_emit = "1"
            ngx_var.cdnca_security_type = kind
            ngx_var.cdnca_security_action = "block"
            ngx_var.cdnca_security_block_page = "1"
            ngx_var.cdnca_security_severity = "high"
            ngx_var.cdnca_security_rule_id = rule_id
            -- attack evidence (policy, detector, fragment), as interp.enforce
            require("cdnca_waf").evidence(policy_id)
        end
        return ngx.exit(403)
    end
    ngx_var.cdnca_security_emit = "1"
    ngx_var.cdnca_security_type = kind
    ngx_var.cdnca_security_action = "log"
    ngx_var.cdnca_security_severity = "info"
    ngx_var.cdnca_security_rule_id = rule_id
end

-- rules: the site's bound policies, then its mounted rule packs (user ->
-- developer -> system, the order the control plane published).
function _M.rules(site)
    local security = site.security
    if type(security) ~= "table" then return end
    local rules = security.rules
    if type(rules) == "table" and type(rules.policies) == "table" and #rules.policies ~= 0 then
        local program, problem = program_for(site, ngx_var.cdnca_site_digest)
        if not program then return unavailable("rule plan", problem) end
        enforce(program)
    end
    local resolved = security.resolved_sha256
    if type(resolved) == "string" and #resolved == 64 and not resolved:find("[^0-9a-f]") then
        local program, problem = mount_program(resolved)
        if not program then return unavailable("rule pack mounts " .. resolved, problem) end
        enforce(program)
    end
end

-- ---------------------------------------------------------------------------
-- JS challenge (access). As in v7, every delivered policy version is loaded
-- in the master at init (configure{challenges}): the policy and its keys are
-- root-only (0700/0600, the engine refuses anything wider), so workers never
-- read them. A newly delivered version reaches the node by a skeleton change
-- (the list is skeleton input) and its reload. One engine instance per
-- (policy, version), shared by every site that binds it.
-- ---------------------------------------------------------------------------
-- load_challenge_engine: a fresh engine instance (its own policy state)
-- from <challenge_lua>/engine.lua. The engine requires its helpers by the
-- bare names "crypto" and "ip", which other node modules also use (origin
-- auth has its own "crypto"): they are bound to the challenge directory's
-- files for the load only.
local challenge_helpers

local function load_challenge_engine()
    local directory = config.challenge_lua
    if not challenge_helpers then
        local helpers = {}
        for _, name in ipairs({ "crypto", "ip" }) do
            local chunk, load_error = loadfile(directory .. "/" .. name .. ".lua")
            if not chunk then return nil, load_error end
            local ok, helper = pcall(chunk)
            if not ok or type(helper) ~= "table" then return nil, helper end
            helpers[name] = helper
        end
        challenge_helpers = helpers
    end
    local chunk, load_error = loadfile(directory .. "/engine.lua")
    if not chunk then return nil, load_error end
    local saved = { crypto = package.loaded.crypto, ip = package.loaded.ip }
    package.loaded.crypto, package.loaded.ip = challenge_helpers.crypto, challenge_helpers.ip
    local ok, module = pcall(chunk)
    package.loaded.crypto, package.loaded.ip = saved.crypto, saved.ip
    if not ok or type(module) ~= "table" then return nil, module end
    return module
end

local function challenge_key(id, revision)
    return id .. "@" .. string.format("%d", revision)
end

-- preload_challenges (configure, in the master): a version that does not
-- load is left out and logged; its sites answer 503 until a reload loads it
-- (v7 fails nginx -t instead, which would take every other site down too).
preload_challenges = function(list)
    challenge_instances = {}
    if list == nil then return end
    assert(type(list) == "table", "cdnca_security.configure: challenges must be a list")
    assert(config.challenge_root and config.challenge_lua, "cdnca_security.configure: challenges need challenge_root and challenge_lua")
    for _, ref in ipairs(list) do
        assert(type(ref) == "table" and type(ref.id) == "string" and ref.id:match("^[0-9a-f-]+$")
            and type(ref.revision) == "number" and ref.revision >= 1, "cdnca_security.configure: challenge reference")
        local module, load_error = load_challenge_engine()
        local key = challenge_key(ref.id, ref.revision)
        if module then
            local policy_path = string.format("%s/policies/%s/versions/%020d.json", config.challenge_root, ref.id, ref.revision)
            -- versions are immutable files: no point re-reading them every second
            local ok, init_error = pcall(module.init, { policy_path = policy_path, state_dict = config.challenge_state_dict,
                reload_interval = 60 })
            if ok then
                challenge_instances[key] = module
            else
                ngx.log(ngx.ERR, "cdnca security: challenge policy ", key, " not loaded: ", tostring(init_error))
            end
        else
            ngx.log(ngx.ERR, "cdnca security: challenge engine: ", tostring(load_error))
        end
    end
end

function _M.challenge(site)
    local ref = site.security and site.security.challenge
    if type(ref) ~= "table" then return end
    local engine = challenge_instances[challenge_key(ref.id, ref.revision)]
    if not engine then return unavailable("challenge policy " .. tostring(ref.id), "not loaded (delivered after the last reload?)") end
    return engine.access({ tenant_id = site.tenant_id, site_id = site.site_id })
end

-- ---------------------------------------------------------------------------
-- Phases.
-- ---------------------------------------------------------------------------
function _M.server_rewrite(site)
    return _M.cc(site)
end

function _M.rewrite(site)
    return _M.rules(site)
end

-- access: firewall action, then the JS challenge, then the HTTP policy
-- (writeRuntimePolicyLocation). Origin signing runs before them (D5) and an
-- advanced cache dispatch after them (cache task).
function _M.access(site)
    local security = site.security or {}
    local action = security.firewall_action
    if type(action) == "table" then
        firewall.handle_object(action.sha256, read_object, site.site_id)
    end
    if type(security.challenge) == "table" then
        local result = _M.challenge(site)
        if result ~= nil then return result end
    end
    local policy = site.http_policy
    if type(policy) == "table" then
        return httppolicy.access_object(policy, read_object, site.site_id)
    end
end

-- header_filter: the HTTP policy's response headers (its access phase left
-- the site entry in ngx.ctx; an ngx.exec dispatch clears it, as in v7).
function _M.header_filter(site)
    if type(site.http_policy) == "table" then httppolicy.header_filter() end
end

-- log: CC's completed-response counters (404 statistics, auto switch 5xx).
function _M.log(site)
    local security = site.security
    local bindings = security and security.cc
    if type(bindings) == "table" and #bindings ~= 0 or type(security) == "table" and has_cc_mounts(site) then cc.log() end
end

-- firewall_action_status (loopback health server, FX45): the agent POSTs the
-- running sites' firewall_action references ({ { site_id, sha256 } }) once a
-- second and mirrors the answered escalation state into nftables.
function _M.firewall_action_status()
    ngx.header["Content-Type"] = "application/json"
    if ngx.req.get_method() ~= "POST" then return ngx.exit(405) end
    ngx.req.read_body()
    local sites = require("cjson.safe").decode(ngx.req.get_body_data() or "")
    if type(sites) ~= "table" then return ngx.exit(400) end
    ngx.print(require("cjson.safe").encode(firewall.status_objects(sites, read_object)))
end

return _M
