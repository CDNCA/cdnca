local balancer = require "ngx.balancer"
local bit = require "bit"
local cjson = require "cjson.safe"
local dns_resolver = require "resty.dns.resolver"

local _M = {}
local active
local state_unavailable_until = 0
local adaptive_state_unavailable_until = 0
local STATE_MIN_FREE_BYTES = 16384
local UINT32_RANGE = 4294967296
local LN2 = math.log(2)
local PROBE_MUTATION_LOCK_TTL = 0.1
local LEASE_STATE_LOCK_TTL = 0.5
local LEASE_SCAN_LIMIT = 64
local LEASE_PROTOCOL_KEY = "__cdnca_originroute_lease_protocol_v1"
local LEASE_EPOCH_KEY = "__cdnca_originroute_lease_epoch"
local LEASE_ORDER_KEY = "__cdnca_originroute_lease_order"
local LEASE_MAX_GENERATION = 9007199254740990
local DNS_MAX_CNAME_HOPS = 8
local DNS_MAX_ANSWERS = 32
local DNS_REFRESH_BATCH = 16
local DNS_MAX_INFLIGHT = 32
local lease_epoch
local dns_due = {}
local dns_inflight = {}
local dns_inflight_count = 0
local dns_timer_started = false
local lease_protocol_seen = setmetatable({}, {__mode = "k"})
local BASELINE_ALGORITHMS = {
  round_robin = true,
  ip_hash = true,
  url_hash = true,
  least_conn = true,
  random = true,
}

local function fail(message)
  return nil, "invalid origin route policy: " .. message
end

local function is_integer(value, minimum, maximum)
  return type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum
end

local function lease_protocol_init(dictionary)
  if not dictionary then
    return nil, "origin route lease dictionary is missing"
  end
  local protocol = dictionary:get(LEASE_PROTOCOL_KEY)
  local stored_epoch = dictionary:get(LEASE_EPOCH_KEY)
  local order = dictionary:get(LEASE_ORDER_KEY)
  if protocol == nil and stored_epoch == nil and order == nil then
    if lease_protocol_seen[dictionary] then
      return nil, "origin route lease protocol unavailable"
    end
    local candidate_epoch = lease_epoch or table.concat({
      tostring(os.time()), (tostring({}):gsub("^table: ", "")),
    }, ":")
    local marker_ok, marker_err = dictionary:safe_add(
      LEASE_PROTOCOL_KEY, "initializing:" .. candidate_epoch)
    if not marker_ok then
      if marker_err == "exists" then
        return lease_protocol_init(dictionary)
      end
      return nil, marker_err
    end
    protocol = "initializing:" .. candidate_epoch
    stored_epoch = nil
    order = nil
  elseif protocol == nil then
    if type(stored_epoch) ~= "string" or stored_epoch == "" or
      not is_integer(order, 0, LEASE_MAX_GENERATION) or
      (lease_epoch and lease_epoch ~= stored_epoch) then
      return nil, "origin route lease epoch mismatch"
    end
    local marker_ok, marker_err = dictionary:safe_add(
      LEASE_PROTOCOL_KEY, "ready:" .. stored_epoch)
    if not marker_ok and marker_err ~= "exists" then
      return nil, marker_err
    end
    protocol = dictionary:get(LEASE_PROTOCOL_KEY)
  end

  local protocol_state, protocol_epoch
  if type(protocol) == "string" then
    protocol_state, protocol_epoch = protocol:match("^(%a+):(.+)$")
  end
  if (protocol_state ~= "initializing" and protocol_state ~= "ready") or
    type(protocol_epoch) ~= "string" or protocol_epoch == "" or
    (lease_epoch and lease_epoch ~= protocol_epoch) then
    return nil, "origin route lease epoch mismatch"
  end

  if protocol_state == "initializing" then
    if stored_epoch == nil then
      local epoch_ok, epoch_err = dictionary:safe_add(LEASE_EPOCH_KEY, protocol_epoch)
      if not epoch_ok and epoch_err ~= "exists" then
        return nil, epoch_err
      end
      stored_epoch = dictionary:get(LEASE_EPOCH_KEY)
    end
    if stored_epoch ~= protocol_epoch then
      return nil, "origin route lease epoch mismatch"
    end
    if order == nil then
      local order_ok, order_err = dictionary:safe_add(LEASE_ORDER_KEY, 0)
      if not order_ok and order_err ~= "exists" then
        return nil, order_err
      end
      order = dictionary:get(LEASE_ORDER_KEY)
    end
    if not is_integer(order, 0, LEASE_MAX_GENERATION) then
      return nil, "origin route lease order unavailable"
    end
    local ready_ok, ready_err = dictionary:safe_set(
      LEASE_PROTOCOL_KEY, "ready:" .. protocol_epoch)
    if not ready_ok then
      return nil, ready_err
    end
    protocol_state = "ready"
  end
  if protocol_state ~= "ready" or stored_epoch ~= protocol_epoch or
    not is_integer(order, 0, LEASE_MAX_GENERATION) then
    return nil, "origin route lease epoch mismatch"
  end
  lease_epoch = protocol_epoch
  lease_protocol_seen[dictionary] = true
  return true
end

local function is_token(value)
  return type(value) == "string" and #value >= 1 and #value <= 64 and
    value:match("^[A-Za-z0-9][A-Za-z0-9._-]*$") ~= nil
end

local function is_array(value, maximum)
  if type(value) ~= "table" or #value > maximum then
    return false
  end
  for key in pairs(value) do
    if type(key) ~= "number" or key < 1 or key > #value or key ~= math.floor(key) then
      return false
    end
  end
  return true
end

local function reject_unknown(value, allowed, label)
  if type(value) ~= "table" then
    return fail(label .. " must be an object")
  end
  for key in pairs(value) do
    if type(key) ~= "string" or not allowed[key] then
      return fail(label .. " has an unknown field")
    end
  end
  return true
end

local function split(value, separator)
  local result = {}
  local start = 1
  while true do
    local position = value:find(separator, start, true)
    if not position then
      result[#result + 1] = value:sub(start)
      return result
    end
    result[#result + 1] = value:sub(start, position - 1)
    start = position + #separator
  end
end

local function parse_ipv4(value)
  if type(value) ~= "string" or value:match("^%d+%.%d+%.%d+%.%d+$") == nil then
    return nil
  end
  local result = {}
  for part in value:gmatch("[^.]+") do
    if (#part > 1 and part:sub(1, 1) == "0") or #part > 3 then
      return nil
    end
    local number = tonumber(part, 10)
    if not number or number > 255 then
      return nil
    end
    result[#result + 1] = number
  end
  if #result ~= 4 then
    return nil
  end
  return { family = 4, bytes = result }
end

local function ipv6_groups(value)
  if value == "" then
    return {}
  end
  local result = split(value, ":")
  for _, group in ipairs(result) do
    if #group < 1 or #group > 4 or group:match("^[0-9A-Fa-f]+$") == nil then
      return nil
    end
  end
  return result
end

local function parse_ipv6(value)
  if type(value) ~= "string" or value:find("%", 1, true) or value:find(".", 1, true) then
    return nil
  end
  local marker = value:find("::", 1, true)
  local groups = {}
  if marker then
    if value:find("::", marker + 2, true) then
      return nil
    end
    local left = ipv6_groups(value:sub(1, marker - 1))
    local right = ipv6_groups(value:sub(marker + 2))
    if not left or not right or #left + #right >= 8 then
      return nil
    end
    for _, group in ipairs(left) do
      groups[#groups + 1] = group
    end
    for _ = 1, 8 - #left - #right do
      groups[#groups + 1] = "0"
    end
    for _, group in ipairs(right) do
      groups[#groups + 1] = group
    end
  else
    groups = ipv6_groups(value)
    if not groups or #groups ~= 8 then
      return nil
    end
  end
  local bytes = {}
  for _, group in ipairs(groups) do
    local number = tonumber(group, 16)
    bytes[#bytes + 1] = math.floor(number / 256)
    bytes[#bytes + 1] = number % 256
  end
  return { family = 6, bytes = bytes }
end

local function parse_ip(value)
  return parse_ipv4(value) or parse_ipv6(value)
end

local function ipv4_mapped_ipv6(address)
  if not address or address.family ~= 6 or #address.bytes ~= 16 then
    return false
  end
  for index = 1, 10 do
    if address.bytes[index] ~= 0 then
      return false
    end
  end
  return address.bytes[11] == 0xff and address.bytes[12] == 0xff
end

local function dns_address_key(address)
  local result = {tostring(address.family)}
  for _, value in ipairs(address.bytes) do
    result[#result + 1] = string.format("%02x", value)
  end
  return table.concat(result, ":")
end

local function safe_endpoint_address(address)
  if not address then
    return false
  end
  local bytes = address.bytes
  if address.family == 4 then
    return not (bytes[1] == 0 or (bytes[1] == 169 and bytes[2] == 254) or
      (bytes[1] >= 224 and bytes[1] <= 239) or
      (bytes[1] == 255 and bytes[2] == 255 and bytes[3] == 255 and bytes[4] == 255))
  end
  local all_zero = true
  for _, value in ipairs(bytes) do
    if value ~= 0 then
      all_zero = false
      break
    end
  end
  return not all_zero and not ipv4_mapped_ipv6(address) and bytes[1] ~= 0xff and
    not (bytes[1] == 0xfe and bit.band(bytes[2], 0xc0) == 0x80)
end

local function safe_resolver_address(address)
  if not address then
    return false
  end
  local bytes = address.bytes
  if address.family == 4 then
    return bytes[1] ~= 0 and not (bytes[1] >= 224 and bytes[1] <= 239) and
      not (bytes[1] == 255 and bytes[2] == 255 and bytes[3] == 255 and bytes[4] == 255)
  end
  local all_zero = true
  for _, value in ipairs(bytes) do
    if value ~= 0 then
      all_zero = false
      break
    end
  end
  return not all_zero and bytes[1] ~= 0xff
end

local function valid_dns_hostname(value)
  if type(value) ~= "string" or #value < 3 or #value > 253 or value ~= value:lower() or
    value == "localhost" or value:sub(-1) == "." or
    value:sub(-13) == ".in-addr.arpa" or value:sub(-9) == ".ip6.arpa" then
    return false
  end
  local labels = split(value, ".")
  if #labels < 2 then
    return false
  end
  for _, label in ipairs(labels) do
    if #label < 1 or #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" or
      label:match("^[a-z0-9-]+$") == nil then
      return false
    end
  end
  return labels[#labels]:match("[a-z]") ~= nil
end

local function parse_cidr(value)
  if type(value) ~= "string" then
    return nil
  end
  local slash = value:find("/", 1, true)
  if not slash or value:find("/", slash + 1, true) then
    return nil
  end
  local address = parse_ip(value:sub(1, slash - 1))
  local bits = tonumber(value:sub(slash + 1), 10)
  local maximum = address and (address.family == 4 and 32 or 128) or 0
  if not address or not is_integer(bits, 0, maximum) then
    return nil
  end
  address.bits = bits
  return address
end

local function cidr_contains(cidr, address)
  if cidr.family ~= address.family then
    return false
  end
  local full_bytes = math.floor(cidr.bits / 8)
  for index = 1, full_bytes do
    if cidr.bytes[index] ~= address.bytes[index] then
      return false
    end
  end
  local remaining = cidr.bits % 8
  if remaining == 0 then
    return true
  end
  local mask = bit.band(0xff, bit.lshift(0xff, 8 - remaining))
  return bit.band(cidr.bytes[full_bytes + 1], mask) == bit.band(address.bytes[full_bytes + 1], mask)
end

local function validate_endpoint(endpoint, pool_kind)
  local ok, err = reject_unknown(endpoint, {
    id = true, host = true, port = true, node_id = true, weight = true,
  }, "endpoint")
  if not ok then
    return nil, err
  end
  local address = parse_ip(endpoint.host)
  local hostname = not address and pool_kind == "origin" and valid_dns_hostname(endpoint.host)
  if not is_token(endpoint.id) or (not address and not hostname) or
    not is_integer(endpoint.port, 1, 65535) or not is_integer(endpoint.weight, 1, 100) then
    return fail("endpoint fields are invalid")
  end
  if (pool_kind == "l2" and not is_token(endpoint.node_id)) or
    (pool_kind == "origin" and endpoint.node_id ~= nil) then
    return fail("endpoint node identity is invalid")
  end
  return {
    id = endpoint.id, host = endpoint.host, port = endpoint.port, weight = endpoint.weight,
    node_id = endpoint.node_id, family = address and address.family or nil,
    hostname = hostname and true or false,
  }
end

local function validate_dns_policy(value, required)
  if value == nil then
    if required then
      return fail("DNS policy is required for hostname endpoints")
    end
    return nil
  end
  local ok, err = reject_unknown(value, {
    resolver = true, query_timeout_ms = true, min_ttl_seconds = true,
    max_ttl_seconds = true, stale_ttl_seconds = true,
  }, "dns")
  if not ok then
    return nil, err
  end
  local resolver_address = value.resolver ~= "" and parse_ip(value.resolver) or nil
  if type(value.resolver) ~= "string" or
    (value.resolver ~= "" and not safe_resolver_address(resolver_address)) or
    not is_integer(value.query_timeout_ms, 100, 5000) or
    not is_integer(value.min_ttl_seconds, 1, 300) or
    not is_integer(value.max_ttl_seconds, value.min_ttl_seconds, 86400) or
    not is_integer(value.stale_ttl_seconds, 1, 86400) then
    return fail("DNS resolver, timeout, or TTL bounds are invalid")
  end
  return {
    resolver = value.resolver, timeout = value.query_timeout_ms,
    min_ttl = value.min_ttl_seconds, max_ttl = value.max_ttl_seconds,
    stale_ttl = value.stale_ttl_seconds,
  }
end

local function validate_adaptive(value)
  if value == nil then
    return nil
  end
  local ok, err = reject_unknown(value, {
    version = true, mode = true, minimum_samples = true, sample_freshness_ms = true,
    peak_ewma_half_life_ms = true, exploration_percent = true,
    slow_start = true, outlier = true,
  }, "adaptive")
  if not ok then
    return nil, err
  end
  if value.version ~= 1 or (value.mode ~= "shadow" and value.mode ~= "active") or
    not is_integer(value.minimum_samples, 2, 1000) or
    not is_integer(value.sample_freshness_ms, 100, 300000) or
    not is_integer(value.peak_ewma_half_life_ms, 100, 60000) or
    not is_integer(value.exploration_percent, 1, 10) then
    return fail("adaptive version, mode, sample, EWMA, or exploration fields are invalid")
  end
  ok, err = reject_unknown(value.slow_start, {
    initial_weight_percent = true, ramp_ms = true, hard_timeout_ms = true,
  }, "adaptive slow_start")
  if not ok then
    return nil, err
  end
  if not is_integer(value.slow_start.initial_weight_percent, 1, 100) or
    not is_integer(value.slow_start.ramp_ms, 100, 300000) or
    not is_integer(value.slow_start.hard_timeout_ms, value.slow_start.ramp_ms, 600000) then
    return fail("adaptive slow-start fields are invalid")
  end
  ok, err = reject_unknown(value.outlier, {
    minimum_samples = true, consecutive_failures = true, failure_ratio_percent = true,
    max_ejection_percent = true, base_ejection_ms = true, max_ejection_ms = true,
    recovery_probe_interval_ms = true,
  }, "adaptive outlier")
  if not ok then
    return nil, err
  end
  if not is_integer(value.outlier.minimum_samples, value.minimum_samples, 1000) or
    not is_integer(value.outlier.consecutive_failures, 1, 20) or
    not is_integer(value.outlier.failure_ratio_percent, 1, 100) or
    not is_integer(value.outlier.max_ejection_percent, 1, 99) or
    not is_integer(value.outlier.base_ejection_ms, 100, 60000) or
    not is_integer(value.outlier.max_ejection_ms, value.outlier.base_ejection_ms, 600000) or
    not is_integer(value.outlier.recovery_probe_interval_ms, 100, 60000) then
    return fail("adaptive outlier fields are invalid")
  end
  local freshness = value.sample_freshness_ms / 1000
  local hard_timeout = value.slow_start.hard_timeout_ms / 1000
  local max_ejection = value.outlier.max_ejection_ms / 1000
  return {
    version = 1,
    mode = value.mode,
    minimum_samples = value.minimum_samples,
    freshness = freshness,
    half_life = value.peak_ewma_half_life_ms / 1000,
    exploration = value.exploration_percent,
    slow_initial = value.slow_start.initial_weight_percent / 100,
    slow_ramp = value.slow_start.ramp_ms / 1000,
    slow_hard_timeout = hard_timeout,
    outlier_minimum_samples = value.outlier.minimum_samples,
    consecutive_failures = value.outlier.consecutive_failures,
    failure_ratio = value.outlier.failure_ratio_percent / 100,
    max_ejection_percent = value.outlier.max_ejection_percent,
    base_ejection = value.outlier.base_ejection_ms / 1000,
    max_ejection = max_ejection,
    recovery_probe_interval = value.outlier.recovery_probe_interval_ms / 1000,
    state_ttl = math.min(1800, math.max(freshness * 4, hard_timeout * 2, max_ejection * 2)),
  }
end

local function validate_policy(policy)
  local ok, err = reject_unknown(policy, {
    schema = true, revision = true, tenant_id = true, site_id = true,
    version_id = true, node = true, listeners = true,
    pools = true, default_pool_id = true, default_fallback_pool_id = true,
    routes = true, retry = true, l2 = true, adaptive = true, dns = true,
  }, "policy")
  if not ok then
    return nil, err
  end
  if policy.schema ~= "cdnca.edge.origin-route/v1" or
    not is_integer(policy.revision, 1, 9007199254740991) or
    not is_token(policy.tenant_id) or not is_token(policy.site_id) or
    not is_token(policy.version_id) then
    return fail("schema, revision, tenant, site, or version is invalid")
  end

  ok, err = reject_unknown(policy.node, { id = true, region = true, tier = true }, "node")
  if not ok then
    return nil, err
  end
  if not is_token(policy.node.id) or not is_token(policy.node.region) or
    (policy.node.tier ~= "l1" and policy.node.tier ~= "l2") then
    return fail("node is invalid")
  end

  if not is_array(policy.listeners, 16) or #policy.listeners < 1 then
    return fail("listeners are invalid")
  end
  local listeners = {}
  for _, listener in ipairs(policy.listeners) do
    ok, err = reject_unknown(listener, {
      id = true, address = true, port = true,
      ingress_source_ipv4 = true, ingress_source_ipv6 = true,
    }, "listener")
    if not ok then
      return nil, err
    end
    local listen_address = parse_ip(listener.address)
    local source4 = listener.ingress_source_ipv4 and parse_ip(listener.ingress_source_ipv4) or nil
    local source6 = listener.ingress_source_ipv6 and parse_ip(listener.ingress_source_ipv6) or nil
    if not is_token(listener.id) or listeners[listener.id] or not listen_address or
      not is_integer(listener.port, 1, 65535) or
      (listener.ingress_source_ipv4 and (not source4 or source4.family ~= 4)) or
      (listener.ingress_source_ipv6 and (not source6 or source6.family ~= 6)) then
      return fail("listener is invalid")
    end
    listeners[listener.id] = {
      id = listener.id, source4 = listener.ingress_source_ipv4,
      source6 = listener.ingress_source_ipv6,
    }
  end

  if not is_array(policy.pools, 64) or #policy.pools < 1 then
    return fail("pools are invalid")
  end
  local pools = {}
  local dns_hostnames = {}
  for _, pool in ipairs(policy.pools) do
    ok, err = reject_unknown(pool, {
      id = true, kind = true, algorithm = true, endpoints = true,
    }, "pool")
    if not ok then
      return nil, err
    end
    local algorithm = pool.algorithm or "round_robin"
    if not is_token(pool.id) or pools[pool.id] or (pool.kind ~= "origin" and pool.kind ~= "l2") or
      not BASELINE_ALGORITHMS[algorithm] or
      not is_array(pool.endpoints, 32) or #pool.endpoints < 1 then
      return fail("pool is invalid")
    end
    local endpoints = {}
    local endpoint_ids = {}
    local total_weight = 0
    for _, endpoint in ipairs(pool.endpoints) do
      local compiled, endpoint_err = validate_endpoint(endpoint, pool.kind)
      if not compiled then
        return nil, endpoint_err
      end
      if endpoint_ids[compiled.id] then
        return fail("pool has duplicate endpoint ids")
      end
      endpoint_ids[compiled.id] = true
      if compiled.hostname then
        dns_hostnames[compiled.host] = true
      end
      endpoints[#endpoints + 1] = compiled
      total_weight = total_weight + compiled.weight
    end
    pools[pool.id] = {
      id = pool.id, kind = pool.kind, algorithm = algorithm,
      endpoints = endpoints, total_weight = total_weight,
    }
  end
  if not pools[policy.default_pool_id] then
    return fail("default pool is missing")
  end

  if not is_array(policy.routes, 256) then
    return fail("routes are invalid")
  end
  local routes = {}
  local route_ids = {}
  for _, route in ipairs(policy.routes) do
    ok, err = reject_unknown(route, {
      id = true, priority = true, path_prefix = true, node_regions = true,
      client_cidrs = true, pool_id = true, fallback_pool_id = true,
    }, "route")
    if not ok then
      return nil, err
    end
    if not is_token(route.id) or route_ids[route.id] or not is_integer(route.priority, -1000, 1000) or
      (route.path_prefix ~= nil and (type(route.path_prefix) ~= "string" or route.path_prefix:sub(1, 1) ~= "/")) or
      not is_array(route.node_regions or {}, 32) or not is_array(route.client_cidrs or {}, 32) or
      not pools[route.pool_id] then
      return fail("route is invalid")
    end
    route_ids[route.id] = true
    local regions = {}
    for _, region in ipairs(route.node_regions or {}) do
      if not is_token(region) then
        return fail("route region is invalid")
      end
      regions[region] = true
    end
    local cidrs = {}
    for _, raw_cidr in ipairs(route.client_cidrs or {}) do
      local cidr = parse_cidr(raw_cidr)
      if not cidr then
        return fail("route CIDR is invalid")
      end
      cidrs[#cidrs + 1] = cidr
    end
    local pool = pools[route.pool_id]
    local fallback = route.fallback_pool_id and pools[route.fallback_pool_id] or nil
    if (pool.kind == "l2" and (not fallback or fallback.kind ~= "origin")) or
      (pool.kind == "origin" and fallback) then
      return fail("route fallback is invalid")
    end
    routes[#routes + 1] = {
      id = route.id, path = route.path_prefix, regions = regions, cidrs = cidrs,
      pool = pool, fallback = fallback,
    }
  end

  ok, err = reject_unknown(policy.retry, {
    methods = true, max_attempts = true, connect_timeout_ms = true,
    read_timeout_ms = true, total_budget_ms = true,
  }, "retry")
  if not ok then
    return nil, err
  end
  if not is_array(policy.retry.methods, 2) or #policy.retry.methods < 1 or
    not is_integer(policy.retry.max_attempts, 1, 8) or
    not is_integer(policy.retry.connect_timeout_ms, 10, 60000) or
    not is_integer(policy.retry.read_timeout_ms, 10, 60000) or
    not is_integer(policy.retry.total_budget_ms, 20, 120000) then
    return fail("retry policy is invalid")
  end
  local retry_methods = {}
  for _, method in ipairs(policy.retry.methods) do
    if (method ~= "GET" and method ~= "HEAD") or retry_methods[method] then
      return fail("retry method is invalid")
    end
    retry_methods[method] = true
  end

  ok, err = reject_unknown(policy.l2, {
    failure_threshold = true, recovery_threshold = true,
    probe_interval_ms = true, max_hops = true,
  }, "l2")
  if not ok then
    return nil, err
  end
  if not is_integer(policy.l2.failure_threshold, 1, 10) or
    not is_integer(policy.l2.recovery_threshold, 1, 10) or
    not is_integer(policy.l2.probe_interval_ms, 100, 60000) or
    not is_integer(policy.l2.max_hops, 1, 8) then
    return fail("L2 policy is invalid")
  end

  local adaptive, adaptive_err = validate_adaptive(policy.adaptive)
  if adaptive_err then
    return nil, adaptive_err
  end
  local dns, dns_err = validate_dns_policy(policy.dns, next(dns_hostnames) ~= nil)
  if dns_err then
    return nil, dns_err
  end

  local default_pool = pools[policy.default_pool_id]
  local default_fallback = policy.default_fallback_pool_id and pools[policy.default_fallback_pool_id] or nil
  if (default_pool.kind == "l2" and (not default_fallback or default_fallback.kind ~= "origin")) or
    (default_pool.kind == "origin" and default_fallback) then
    return fail("default fallback is invalid")
  end
  local probe_seconds = policy.l2.probe_interval_ms / 1000
  local state_key = table.concat({
    "v1|tenant=", policy.tenant_id, "|site=", policy.site_id, "|version=", policy.version_id,
  })
  local dns_targets = {}
  for hostname in pairs(dns_hostnames) do
    dns_targets[#dns_targets + 1] = {
      hostname = hostname,
      key = table.concat({"d1:", state_key, ":", policy.revision, ":", hostname}),
    }
  end
  table.sort(dns_targets, function(left, right) return left.hostname < right.hostname end)
  local dns_keys = {}
  for _, target in ipairs(dns_targets) do
    dns_keys[target.hostname] = target.key
  end
  for _, pool in pairs(pools) do
    for _, endpoint in ipairs(pool.endpoints) do
      if endpoint.hostname then
        endpoint.dns_key = dns_keys[endpoint.host]
      end
    end
  end
  return {
    tenant_id = policy.tenant_id, site_id = policy.site_id,
    version_id = policy.version_id, revision = policy.revision, state_key = state_key,
    node_region = policy.node.region,
    listeners = listeners, pools = pools, routes = routes,
    default_pool = default_pool, default_fallback = default_fallback,
    retry = {
      methods = retry_methods, max_attempts = policy.retry.max_attempts,
      connect = policy.retry.connect_timeout_ms / 1000,
      read = policy.retry.read_timeout_ms / 1000,
      budget = policy.retry.total_budget_ms / 1000,
    },
    l2 = policy.l2,
    adaptive = adaptive,
    dns = dns, dns_targets = dns_targets,
    state_ttl = math.min(300, math.max(1, probe_seconds * 10)),
    state_cooldown = math.min(10, math.max(1, probe_seconds)),
  }
end

local dns_nameserver_cache
local dns_nameserver_cache_until = 0

local function dns_nameservers(now)
  if active.dns.resolver ~= "" then
    return {active.dns.resolver}
  end
  if dns_nameserver_cache and now < dns_nameserver_cache_until then
    return dns_nameserver_cache
  end
  local file = io.open("/etc/resolv.conf", "rb")
  if not file then
    return nil, "dns_resolver_unavailable"
  end
  local values = {}
  local seen = {}
  for line in file:lines() do
    local value = line:match("^%s*nameserver%s+([^%s#]+)")
    local address = value and parse_ip(value) or nil
    if safe_resolver_address(address) then
      local key = dns_address_key(address)
      if not seen[key] then
        seen[key] = true
        values[#values + 1] = value
        if #values == 3 then
          break
        end
      end
    end
  end
  file:close()
  if #values == 0 then
    return nil, "dns_resolver_unavailable"
  end
  dns_nameserver_cache = values
  dns_nameserver_cache_until = now + 60
  return values
end

local function dns_query_reason(answers, err)
  if not answers then
    if tostring(err):lower():find("timeout", 1, true) then
      return "dns_timeout"
    end
    return "dns_query_failed"
  end
  if answers.errcode == 3 then
    return "dns_nxdomain"
  elseif answers.errcode then
    return "dns_query_failed"
  end
  return nil
end

local function normalize_dns_name(value)
  if type(value) ~= "string" then
    return nil
  end
  return value:lower():gsub("%.$", "")
end

local function dns_query_type(resolver, hostname, qtype, depth, visited, answer_count)
  if depth > DNS_MAX_CNAME_HOPS then
    return nil, nil, "dns_cname_limit", answer_count
  end
  if visited[hostname] then
    return nil, nil, "dns_cname_loop", answer_count
  end
  visited[hostname] = true
  local answers, query_err = resolver:query(hostname, {qtype = qtype})
  local reason = dns_query_reason(answers, query_err)
  if reason then
    return nil, nil, reason, answer_count
  end
  answer_count = answer_count + #answers
  if answer_count > DNS_MAX_ANSWERS then
    return nil, nil, "dns_too_many_answers", answer_count
  end
  local addresses = {}
  local minimum_ttl
  local cname
  for _, answer in ipairs(answers) do
    if answer.type == dns_resolver.TYPE_A or answer.type == dns_resolver.TYPE_AAAA or
      answer.type == dns_resolver.TYPE_CNAME then
      if normalize_dns_name(answer.name) ~= hostname then
        return nil, nil, "dns_owner_mismatch", answer_count
      end
    end
    if answer.type == qtype and answer.address then
      local address = parse_ip(answer.address)
      if not safe_endpoint_address(address) or
        not is_integer(answer.ttl, 0, 2147483647) then
        return nil, nil, "dns_invalid_answer", answer_count
      end
      addresses[#addresses + 1] = {
        host = answer.address:lower(), family = address.family,
        key = dns_address_key(address),
      }
      minimum_ttl = minimum_ttl and math.min(minimum_ttl, answer.ttl) or answer.ttl
    elseif answer.type == dns_resolver.TYPE_CNAME and answer.cname then
      local target = answer.cname:lower():gsub("%.$", "")
      if not valid_dns_hostname(target) or
        (cname and cname ~= target) or not is_integer(answer.ttl, 0, 2147483647) then
        return nil, nil, "dns_cname_chain", answer_count
      end
      cname = target
      minimum_ttl = minimum_ttl and math.min(minimum_ttl, answer.ttl) or answer.ttl
    end
  end
  if #addresses > 0 then
    return addresses, minimum_ttl, nil, answer_count
  end
  if cname then
    local resolved, ttl, cname_err, count = dns_query_type(
      resolver, cname, qtype, depth + 1, visited, answer_count)
    if ttl and minimum_ttl then
      ttl = math.min(ttl, minimum_ttl)
    end
    return resolved, ttl, cname_err, count
  end
  return nil, nil, "dns_no_answer", answer_count
end

local DNS_HARD_FAILURE = {
  dns_cname_limit = true,
  dns_cname_loop = true,
  dns_cname_chain = true,
  dns_invalid_answer = true,
  dns_owner_mismatch = true,
  dns_too_many_answers = true,
}
local DNS_STORED_REASONS = {
  dns_fresh = true,
  dns_timeout = true,
  dns_query_failed = true,
  dns_nxdomain = true,
  dns_cname_limit = true,
  dns_cname_loop = true,
  dns_cname_chain = true,
  dns_invalid_answer = true,
  dns_owner_mismatch = true,
  dns_too_many_answers = true,
  dns_no_answer = true,
  dns_resolver_unavailable = true,
  dns_unresolved = true,
}

local function dns_resolve_target(target, now)
  local nameservers, nameserver_err = dns_nameservers(now)
  if not nameservers then
    return nil, nil, nameserver_err
  end
  local resolver, resolver_err = dns_resolver:new({
    nameservers = nameservers, retrans = 2, timeout = active.dns.timeout,
  })
  if not resolver then
    ngx.log(ngx.ERR, "origin route DNS resolver initialization failed: ", resolver_err or "unknown")
    return nil, nil, "dns_resolver_unavailable"
  end
  local addresses4, ttl4, err4, count = dns_query_type(
    resolver, target.hostname, dns_resolver.TYPE_A, 0, {}, 0)
  if DNS_HARD_FAILURE[err4] then
    return nil, nil, err4
  end
  local addresses6, ttl6, err6
  addresses6, ttl6, err6, count = dns_query_type(
    resolver, target.hostname, dns_resolver.TYPE_AAAA, 0, {}, count)
  if DNS_HARD_FAILURE[err6] then
    return nil, nil, err6
  end
  local deduplicated = {}
  local by_key = {}
  for _, values in ipairs({addresses4 or {}, addresses6 or {}}) do
    for _, address in ipairs(values) do
      if not by_key[address.key] then
        by_key[address.key] = true
        deduplicated[#deduplicated + 1] = address
      end
    end
  end
  if #deduplicated == 0 then
    if err4 == "dns_timeout" or err6 == "dns_timeout" then
      return nil, nil, "dns_timeout"
    end
    if err4 == "dns_nxdomain" and err6 == "dns_nxdomain" then
      return nil, nil, "dns_nxdomain"
    end
    return nil, nil, err4 or err6 or "dns_no_answer"
  end
  if #deduplicated > DNS_MAX_ANSWERS then
    return nil, nil, "dns_too_many_answers"
  end
  table.sort(deduplicated, function(left, right) return left.key < right.key end)
  local ttl = ttl4 and ttl6 and math.min(ttl4, ttl6) or ttl4 or ttl6
  if not ttl then
    return nil, nil, "dns_invalid_answer"
  end
  ttl = math.max(active.dns.min_ttl, math.min(active.dns.max_ttl, ttl))
  return deduplicated, ttl
end

local function dns_decode_state(raw)
  if type(raw) ~= "string" or #raw > 8192 then
    return nil
  end
  local value = cjson.decode(raw)
  if type(value) ~= "table" or value.version ~= 1 or
    type(value.fresh_until) ~= "number" or type(value.stale_until) ~= "number" or
    type(value.reason) ~= "string" or not DNS_STORED_REASONS[value.reason] or
    not is_array(value.addresses, DNS_MAX_ANSWERS) then
    return nil
  end
  for _, item in ipairs(value.addresses) do
    local address = type(item) == "table" and parse_ip(item.host) or nil
    if not safe_endpoint_address(address) or item.family ~= address.family or
      item.key ~= dns_address_key(address) then
      return nil
    end
  end
  return value
end

local function dns_read_state(dictionary, key)
  return dns_decode_state(dictionary:get(key))
end

local function dns_write_state(dictionary, key, value, ttl)
  local raw, encode_err = cjson.encode(value)
  if not raw then
    return nil, encode_err
  end
  local ok, err, forcible = dictionary:set(key, raw, math.max(1, ttl))
  if not ok or forcible then
    if forcible then
      dictionary:delete(key)
    end
    return nil, forcible and "dns shared state eviction" or err
  end
  return true
end

local function dns_refresh_target(target)
  local dictionary = ngx.shared.cdnca_originroute_dns_state
  if not dictionary then
    return active.dns.min_ttl, "dns_state_unavailable"
  end
  local now = ngx.now()
  local addresses, ttl, reason = dns_resolve_target(target, now)
  local current = dns_read_state(dictionary, target.key)
  local next_delay = active.dns.min_ttl
  local value
  local state_ttl
  if addresses then
    value = {
      version = 1, addresses = addresses, fresh_until = now + ttl,
      stale_until = now + ttl + active.dns.stale_ttl, reason = "dns_fresh",
    }
    next_delay = ttl
    state_ttl = ttl + active.dns.stale_ttl
  elseif current and #current.addresses > 0 and now <= current.stale_until then
    current.reason = reason or "dns_query_failed"
    value = current
    state_ttl = current.stale_until - now
  else
    value = {
      version = 1, addresses = {}, fresh_until = 0, stale_until = 0,
      reason = reason or "dns_unresolved",
    }
    state_ttl = active.dns.min_ttl * 2
  end
  local written, write_err = dns_write_state(dictionary, target.key, value, state_ttl)
  if not written then
    ngx.log(ngx.ERR, "origin route DNS state write failed: ", write_err or "unknown")
  end
  return next_delay, reason
end

local function dns_refresh_tick(premature)
  if premature or not active or not active.dns then
    return
  end
  if dns_inflight_count >= DNS_MAX_INFLIGHT then
    return
  end
  local now = ngx.now()
  local selected = {}
  for _, target in ipairs(active.dns_targets) do
    if not dns_inflight[target.key] and (dns_due[target.key] or 0) <= now then
      dns_due[target.key] = now + 1
      dns_inflight[target.key] = true
      dns_inflight_count = dns_inflight_count + 1
      selected[#selected + 1] = target
      if #selected == DNS_REFRESH_BATCH or dns_inflight_count == DNS_MAX_INFLIGHT then
        break
      end
    end
  end
  local threads = {}
  for _, target in ipairs(selected) do
    local spawned, thread = pcall(ngx.thread.spawn, dns_refresh_target, target)
    if spawned and thread then
      threads[#threads + 1] = {target = target, thread = thread}
    else
      dns_inflight[target.key] = nil
      dns_inflight_count = math.max(0, dns_inflight_count - 1)
      dns_due[target.key] = ngx.now() + active.dns.min_ttl
      ngx.log(ngx.ERR, "origin route DNS refresh spawn failed")
    end
  end
  for _, pending in ipairs(threads) do
    local ok, next_delay, reason = ngx.thread.wait(pending.thread)
    dns_inflight[pending.target.key] = nil
    dns_inflight_count = math.max(0, dns_inflight_count - 1)
    dns_due[pending.target.key] = ngx.now() + (ok and next_delay or active.dns.min_ttl)
    if not ok then
      ngx.log(ngx.ERR, "origin route DNS refresh failed: ", reason or "unknown")
    end
  end
end

function _M.start_dns()
  if not active or not active.dns or #active.dns_targets == 0 or dns_timer_started then
    return true
  end
  if ngx.worker.id() ~= 0 then
    return true
  end
  local ok, err = ngx.timer.every(1, dns_refresh_tick)
  if not ok then
    return nil, "start origin route DNS refresh: " .. tostring(err)
  end
  local initial_ok, initial_err = ngx.timer.at(0, dns_refresh_tick)
  if not initial_ok then
    return nil, "start initial origin route DNS refresh: " .. tostring(initial_err)
  end
  dns_timer_started = true
  return true
end

function _M.health(version_id)
  local healthy = true
  local reason = "ready"
  if not active or active.version_id ~= version_id then
    healthy = false
    reason = "origin_revision_mismatch"
  elseif active.dns and #active.dns_targets > 0 then
    local dictionary = ngx.shared.cdnca_originroute_dns_state
    if not dictionary then
      healthy = false
      reason = "dns_state_unavailable"
    else
      local now = ngx.now()
      for _, target in ipairs(active.dns_targets) do
        local expected_key = table.concat({"d1:", active.state_key, ":", active.revision, ":", target.hostname})
        local state = target.key == expected_key and dns_read_state(dictionary, expected_key) or nil
        if not state or #state.addresses == 0 or state.reason ~= "dns_fresh" or now > state.stale_until then
          healthy = false
          reason = state and state.reason or "dns_unresolved"
          break
        end
      end
    end
  end
  ngx.status = healthy and ngx.HTTP_OK or ngx.HTTP_SERVICE_UNAVAILABLE
  ngx.header.content_type = "text/plain"
  ngx.say((healthy and "ok:" or "not_ready:") .. tostring(version_id) .. ":" .. reason)
end

local function dns_select_address(endpoint, now)
  local dictionary = ngx.shared.cdnca_originroute_dns_state
  local state = dictionary and dns_read_state(dictionary, endpoint.dns_key) or nil
  if not state then
    return nil, "unavailable", "dns_unresolved"
  end
  if #state.addresses == 0 then
    return nil, "unavailable", state.reason
  end
  if now > state.stale_until then
    return nil, "expired", "dns_stale_expired"
  end
  local seed = table.concat({
    ngx.var.request_id or "", ngx.var.remote_addr or "", endpoint.id,
  }, ":")
  local address = state.addresses[(ngx.crc32_short(seed) % #state.addresses) + 1]
  if now <= state.fresh_until then
    return address, "fresh", "dns_fresh"
  end
  return address, "stale", state.reason ~= "dns_fresh" and state.reason or "dns_refresh_pending"
end

function _M.init_file(path)
  if type(path) ~= "string" or #path < 1 or #path > 4096 or path:find("\0", 1, true) then
    return fail("policy path is invalid")
  end
  local file, open_err = io.open(path, "rb")
  if not file then
    return nil, "open origin route policy: " .. tostring(open_err)
  end
  local raw = file:read(1048577)
  file:close()
  if not raw or #raw < 1 or #raw > 1048576 then
    return fail("policy size is invalid")
  end
  local decoded, decode_err = cjson.decode(raw)
  if not decoded then
    return nil, "decode origin route policy: " .. tostring(decode_err)
  end
  local compiled, validation_err = validate_policy(decoded)
  if not compiled then
    return nil, validation_err
  end
  local lease_ok, lease_err = lease_protocol_init(ngx.shared.cdnca_originroute_state)
  if not lease_ok then
    return nil, lease_err
  end
  if compiled.adaptive then
    lease_ok, lease_err = lease_protocol_init(ngx.shared.cdnca_originroute_adaptive_state)
    if not lease_ok then
      return nil, lease_err
    end
  end
  active = compiled
  return true
end

local function path_matches(prefix, path)
  if prefix == nil or prefix == "" or prefix == "/" then
    return true
  end
  return path == prefix or (path:sub(1, #prefix) == prefix and path:sub(#prefix + 1, #prefix + 1) == "/")
end

local function route_matches(route, path, client)
  if not path_matches(route.path, path) then
    return false
  end
  if next(route.regions) and not route.regions[active.node_region] then
    return false
  end
  if #route.cidrs > 0 then
    for _, cidr in ipairs(route.cidrs) do
      if cidr_contains(cidr, client) then
        return true
      end
    end
    return false
  end
  return true
end

local function circuit_key(pool, suffix)
  return "c1:" .. active.state_key .. ":" .. active.revision .. ":" .. pool.id .. ":" .. suffix
end

local function probe_operation_token(now)
  return table.concat({
    tostring(ngx.worker.pid()), ngx.var.connection or "0",
    ngx.var.connection_requests or "0", ngx.var.request_id or "", string.format("%.6f", now),
  }, ":")
end

local function probe_lock_acquire(dictionary, key)
  local token = probe_operation_token(ngx.now())
  local lock_key = key .. ":mutation-lock"
  local counter_key = key .. ":mutation-lock-counter"
  local previous_count = dictionary:get(counter_key)
  local count, err, forcible = dictionary:incr(
    counter_key, 1, 0, PROBE_MUTATION_LOCK_TTL)

  local function rollback(expected)
    local value, rollback_err, rollback_forcible = dictionary:incr(counter_key, -1)
    return value == expected and not rollback_forcible, rollback_err, rollback_forcible
  end

  if not count or forcible or not is_integer(count, 1, LEASE_MAX_GENERATION) or count ~= 1 then
    if is_integer(count, 1, LEASE_MAX_GENERATION) then
      local rolled_back, rollback_err, rollback_forcible = rollback(count - 1)
      if not rolled_back then
        return nil, rollback_forcible and "shared dict eviction" or rollback_err or
          "origin route mutation lock rollback unavailable"
      end
    end
    return nil, forcible and "shared dict eviction" or err or
      (count and "exists" or "origin route mutation lock unavailable")
  end

  local existing = dictionary:get(lock_key)
  if previous_count == nil and existing ~= nil then
    local legacy_ttl = dictionary:ttl(lock_key)
    if type(legacy_ttl) == "number" and legacy_ttl > 0 then
      dictionary:expire(counter_key, math.min(PROBE_MUTATION_LOCK_TTL, legacy_ttl))
    end
    return nil, "exists"
  end
  local expiry_ok, expiry_err = dictionary:expire(counter_key, PROBE_MUTATION_LOCK_TTL)
  local counter_ttl = expiry_ok and dictionary:ttl(counter_key) or nil
  if not expiry_ok or type(counter_ttl) ~= "number" or counter_ttl <= 0 then
    local rolled_back, rollback_err, rollback_forcible = rollback(0)
    if not rolled_back then
      return nil, rollback_forcible and "shared dict eviction" or rollback_err or
        "origin route mutation lock rollback unavailable"
    end
    return nil, expiry_err or "origin route mutation lock expiry unavailable"
  end
  local ok, set_err = dictionary:safe_set(lock_key, token, counter_ttl)
  if not ok or dictionary:get(lock_key) ~= token then
    local rolled_back, rollback_err, rollback_forcible = rollback(0)
    if not rolled_back then
      return nil, rollback_forcible and "shared dict eviction" or rollback_err or
        "origin route mutation lock rollback unavailable"
    end
    return nil, set_err or "origin route mutation lock owner unavailable"
  end
  local owned = dictionary:get(counter_key)
  if dictionary:get(lock_key) == token and
    is_integer(owned, 1, LEASE_MAX_GENERATION) then
    return token
  end
  local rolled_back, rollback_err, rollback_forcible = rollback(
    is_integer(owned, 1, LEASE_MAX_GENERATION) and owned - 1 or 0)
  if not rolled_back then
    return nil, rollback_forcible and "shared dict eviction" or rollback_err or
      "origin route mutation lock rollback unavailable"
  end
  return nil, "origin route mutation lock ownership unavailable"
end

local function probe_lock_release(dictionary, key, lock_token)
  local lock_key = key .. ":mutation-lock"
  local counter_key = key .. ":mutation-lock-counter"
  if dictionary:get(lock_key) == lock_token and dictionary:get(counter_key) == nil then
    local legacy_ttl = dictionary:ttl(lock_key)
    if type(legacy_ttl) ~= "number" or legacy_ttl <= 0 then
      legacy_ttl = PROBE_MUTATION_LOCK_TTL
    end
    local adopted, adopt_err, adopt_forcible = dictionary:incr(
      counter_key, 1, 0, math.min(PROBE_MUTATION_LOCK_TTL, legacy_ttl))
    if adopted ~= 1 or adopt_forcible then
      if is_integer(adopted, 1, LEASE_MAX_GENERATION) then
        dictionary:incr(counter_key, -1)
      end
      return false, adopt_forcible and "shared dict eviction" or adopt_err or
        "origin route mutation lock adoption unavailable"
    end
  end
  local count = dictionary:get(counter_key)
  local owned = dictionary:get(lock_key) == lock_token and
    is_integer(count, 1, LEASE_MAX_GENERATION)
  -- CDNCA_TEST_PROBE_LOCK_RELEASE_BARRIER
  if not owned or dictionary:get(lock_key) ~= lock_token then
    return false
  end
  local counter_ttl = dictionary:ttl(counter_key)
  if type(counter_ttl) ~= "number" or counter_ttl <= 0 then
    return false, "origin route mutation lock expiry unavailable"
  end
  local claimed, claim_err = dictionary:safe_add(
    key .. ":mutation-lock-release-claim:" .. lock_token, true, counter_ttl)
  if not claimed then
    return false, claim_err
  end
  count = dictionary:get(counter_key)
  if dictionary:get(lock_key) ~= lock_token or
    not is_integer(count, 1, LEASE_MAX_GENERATION) then
    return false
  end
  local remaining, err, forcible = dictionary:incr(counter_key, -1)
  if is_integer(remaining, 0, LEASE_MAX_GENERATION) and not forcible then
    return true
  end
  if is_integer(remaining, -LEASE_MAX_GENERATION, LEASE_MAX_GENERATION) then
    local restored, restore_err, restore_forcible = dictionary:incr(counter_key, 1)
    if restored ~= remaining + 1 or restore_forcible then
      return false, restore_forcible and "shared dict eviction" or restore_err or
        "origin route mutation lock rollback unavailable"
    end
  end
  return false, forcible and "shared dict eviction" or err
end

local function lease_generation_key(key)
  return key .. ":generation"
end

local function lease_generation_epoch_key(key)
  return key .. ":generation-epoch"
end

local function lease_generation_state_key(key)
  return key .. ":generation-state"
end

local function lease_generation_state_value(phase)
  return "state:" .. phase .. ":" .. lease_epoch
end

local function lease_fallback_key(key, generation)
  return key .. ":fallback:" .. generation
end

local function lease_metadata_ttl(history_ttl)
  return history_ttl + math.max(0.1, math.min(history_ttl, 1))
end

local function probe_owner_key(key, generation, slot_token)
  return key .. ":owner:" .. generation .. ":" .. slot_token
end

local function probe_slot_key(key, generation)
  return key .. ":slot:" .. generation
end

local function lease_commit_key(key, generation)
  return key .. ":commit:" .. generation
end

local function probe_release_key(key, generation, slot_token)
  return key .. ":released:" .. generation .. ":" .. slot_token
end

local function lease_pack(slot_token, value)
  return slot_token .. "\0" .. value
end

local function lease_unpack(raw)
  if type(raw) ~= "string" then
    return nil
  end
  local separator = raw:find("\0", 1, true)
  if not separator then
    return nil
  end
  return raw:sub(1, separator - 1), raw:sub(separator + 1)
end

local function lease_order_next(dictionary)
  if not lease_epoch or dictionary:get(LEASE_EPOCH_KEY) ~= lease_epoch then
    return nil, "origin route lease epoch mismatch"
  end
  local previous = dictionary:get(LEASE_ORDER_KEY)
  if not is_integer(previous, 0, LEASE_MAX_GENERATION - 1) then
    return nil, "origin route lease order unavailable"
  end
  local order, err, forcible = dictionary:incr(LEASE_ORDER_KEY, 1)
  if not is_integer(order, previous + 1, LEASE_MAX_GENERATION) or forcible or
    dictionary:get(LEASE_EPOCH_KEY) ~= lease_epoch then
    return nil, forcible and "shared dict eviction" or err or "origin route lease order exhausted"
  end
  return order
end

local function lease_generation_current(dictionary, key)
  if not lease_epoch or dictionary:get(LEASE_EPOCH_KEY) ~= lease_epoch then
    return nil, "origin route lease epoch mismatch"
  end
  local generation_state = dictionary:get(lease_generation_state_key(key))
  local generation_epoch = dictionary:get(lease_generation_epoch_key(key))
  local generation = dictionary:get(lease_generation_key(key))
  if generation_state == nil and generation_epoch == nil and generation == nil then
    return 0
  end
  if generation_state == nil and generation_epoch == lease_epoch and
    is_integer(generation, 0, LEASE_MAX_GENERATION) then
    return generation
  end
  if generation_state ~= lease_generation_state_value("R") or generation_epoch ~= lease_epoch or
    not is_integer(generation, 0, LEASE_MAX_GENERATION) then
    return nil, "origin route lease generation unavailable"
  end
  return generation
end

local function lease_generation_refresh(dictionary, key, metadata_ttl)
  for _, metadata_key in ipairs({
    lease_generation_state_key(key), lease_generation_epoch_key(key), lease_generation_key(key),
  }) do
    local ok, err = dictionary:expire(metadata_key, metadata_ttl)
    if not ok then
      return nil, err or "origin route lease generation unavailable"
    end
  end
  return true
end

local function lease_generation_init(dictionary, key, history_ttl)
  local metadata_ttl = lease_metadata_ttl(history_ttl)
  local state_key = lease_generation_state_key(key)
  local epoch_key = lease_generation_epoch_key(key)
  local counter_key = lease_generation_key(key)
  local generation_state = dictionary:get(state_key)
  local generation_epoch = dictionary:get(epoch_key)
  local generation = dictionary:get(counter_key)
  if generation_state == nil and generation_epoch == lease_epoch and
    is_integer(generation, 0, LEASE_MAX_GENERATION) then
    local migrated, migrate_err = dictionary:safe_add(
      state_key, lease_generation_state_value("R"), metadata_ttl)
    if not migrated and migrate_err ~= "exists" then
      return nil, migrate_err
    end
    generation_state = dictionary:get(state_key)
  elseif generation_state == nil and generation_epoch == nil and generation == nil then
    local initialized, init_err = dictionary:safe_add(
      state_key, lease_generation_state_value("I"), metadata_ttl)
    if not initialized and init_err ~= "exists" then
      return nil, init_err
    end
    generation_state = dictionary:get(state_key)
  end

  if generation_state == lease_generation_state_value("I") then
    generation_epoch = dictionary:get(epoch_key)
    generation = dictionary:get(counter_key)
    if generation_epoch == nil and generation ~= nil then
      return nil, "origin route lease generation unavailable"
    end
    if generation_epoch == nil then
      local epoch_ok, epoch_err = dictionary:safe_add(epoch_key, lease_epoch, metadata_ttl)
      if not epoch_ok and epoch_err ~= "exists" then
        return nil, epoch_err
      end
      generation_epoch = dictionary:get(epoch_key)
    end
    if generation_epoch ~= lease_epoch then
      return nil, "origin route lease generation unavailable"
    end
    if generation == nil then
      local counter_ok, counter_err = dictionary:safe_add(counter_key, 0, metadata_ttl)
      if not counter_ok and counter_err ~= "exists" then
        return nil, counter_err
      end
      generation = dictionary:get(counter_key)
    end
    if not is_integer(generation, 0, LEASE_MAX_GENERATION) then
      return nil, "origin route lease generation unavailable"
    end
    local ready_ok, ready_err = dictionary:safe_set(
      state_key, lease_generation_state_value("R"), metadata_ttl)
    if not ready_ok then
      return nil, ready_err
    end
    generation_state = lease_generation_state_value("R")
  end

  if generation_state == lease_generation_state_value("X") then
    if generation_epoch ~= lease_epoch or
      not is_integer(generation, 1, LEASE_MAX_GENERATION) then
      return nil, "origin route lease generation unavailable"
    end
    local fallback_raw = dictionary:get(lease_fallback_key(key, generation - 1))
    if fallback_raw == nil then
      local candidate = generation - 1
      local minimum = math.max(1, generation - LEASE_SCAN_LIMIT)
      while candidate >= minimum do
        local slot_token = dictionary:get(probe_slot_key(key, candidate))
        if slot_token and dictionary:get(lease_commit_key(key, candidate)) == slot_token then
          fallback_raw = lease_pack(slot_token, tostring(candidate))
          break
        end
        candidate = candidate - 1
      end
    end
    fallback_raw = fallback_raw or "none"
    local fallback_ok, fallback_err = dictionary:safe_add(
      lease_fallback_key(key, generation), fallback_raw, metadata_ttl)
    if not fallback_ok and
      (fallback_err ~= "exists" or
        dictionary:get(lease_fallback_key(key, generation)) ~= fallback_raw) then
      return nil, fallback_err
    end
    local ready_ok, ready_err = dictionary:safe_set(
      state_key, lease_generation_state_value("R"), metadata_ttl)
    if not ready_ok then
      return nil, ready_err
    end
    generation_state = lease_generation_state_value("R")
  end

  if generation_state ~= lease_generation_state_value("R") or generation_epoch ~= lease_epoch or
    not is_integer(generation, 0, LEASE_MAX_GENERATION) then
    return nil, "origin route lease generation unavailable"
  end
  local refreshed, refresh_err = lease_generation_refresh(dictionary, key, metadata_ttl)
  if not refreshed then
    return nil, refresh_err
  end
  return generation
end

local function lease_generation_retire(dictionary, key, generation)
  if not generation or generation < 1 then
    return
  end
  local slot_token = dictionary:get(probe_slot_key(key, generation))
  dictionary:delete(lease_commit_key(key, generation))
  if slot_token then
    dictionary:delete(probe_owner_key(key, generation, slot_token))
    dictionary:delete(probe_release_key(key, generation, slot_token))
    dictionary:delete(key .. ":value:" .. generation .. ":" .. slot_token)
  end
  dictionary:delete(probe_slot_key(key, generation))
end

local function lease_fallback_write(dictionary, key, generation, fallback, metadata_ttl)
  local raw = "none"
  if fallback then
    raw = lease_pack(fallback.slot_token, tostring(fallback.generation))
  end
  local ok, err = dictionary:safe_add(lease_fallback_key(key, generation), raw, metadata_ttl)
  if not ok and err == "exists" and dictionary:get(lease_fallback_key(key, generation)) == raw then
    return true
  end
  return ok, err
end

local function lease_fallback_read(dictionary, key, generation)
  local raw = dictionary:get(lease_fallback_key(key, generation))
  if raw == nil or raw == "none" then
    return nil
  end
  local slot_token, fallback_generation = lease_unpack(raw)
  fallback_generation = tonumber(fallback_generation)
  if not slot_token or not is_integer(fallback_generation, 1, generation - 1) then
    return nil, "origin route lease fallback mismatch"
  end
  local current_slot = dictionary:get(probe_slot_key(key, fallback_generation))
  local committed_slot = dictionary:get(lease_commit_key(key, fallback_generation))
  if current_slot == nil and committed_slot == nil then
    return nil
  end
  if current_slot ~= slot_token or committed_slot ~= slot_token then
    return nil, "origin route lease fallback mismatch"
  end
  return {generation = fallback_generation, slot_token = slot_token}
end

local function lease_committed_generations(dictionary, key)
  local generation, generation_err = lease_generation_current(dictionary, key)
  if generation == nil then
    return nil, generation_err
  end
  local result = {}
  local seen = {}
  local minimum = math.max(1, generation - LEASE_SCAN_LIMIT + 1)
  local current_generation = generation
  while generation >= minimum do
    local expected_slot = dictionary:get(probe_slot_key(key, generation))
    local committed_slot = dictionary:get(lease_commit_key(key, generation))
    if committed_slot and committed_slot ~= expected_slot then
      return nil, "origin route lease commit mismatch"
    end
    if committed_slot then
      result[#result + 1] = {generation = generation, slot_token = expected_slot}
      seen[generation] = true
    end
    generation = generation - 1
  end
  local fallback, fallback_err = lease_fallback_read(dictionary, key, current_generation)
  if fallback_err then
    return nil, fallback_err
  end
  if fallback and not seen[fallback.generation] then
    result[#result + 1] = fallback
  end
  return result
end

local function probe_generation_next(dictionary, key, history_ttl)
  local previous, previous_err = lease_generation_init(dictionary, key, history_ttl)
  if previous == nil then
    return nil, nil, nil, previous_err
  end
  if previous >= LEASE_MAX_GENERATION then
    return nil, nil, nil, "origin route lease generation exhausted"
  end
  local prior_committed, committed_err = lease_committed_generations(dictionary, key)
  if not prior_committed then
    return nil, nil, nil, committed_err
  end
  local generation, generation_err, generation_forcible = dictionary:incr(
    lease_generation_key(key), 1)
  if not is_integer(generation, previous + 1, LEASE_MAX_GENERATION) or generation_forcible or
    dictionary:get(lease_generation_epoch_key(key)) ~= lease_epoch then
    return nil, nil, nil, generation_forcible and "shared dict eviction" or
      generation_err or "origin route lease generation exhausted"
  end
  local metadata_ttl = lease_metadata_ttl(history_ttl)
  local fallback_ok, fallback_err = lease_fallback_write(
    dictionary, key, generation, prior_committed[1], metadata_ttl)
  if not fallback_ok then
    dictionary:safe_set(
      lease_generation_state_key(key), lease_generation_state_value("X"), metadata_ttl)
    return nil, nil, nil, fallback_err or "origin route lease fallback unavailable"
  end
  local order, order_err = lease_order_next(dictionary)
  if not order then
    return nil, nil, nil, order_err
  end
  local slot_token = probe_operation_token(ngx.now()) .. ":" .. order
  local slot_ok, slot_err = dictionary:safe_add(
    probe_slot_key(key, generation), slot_token, history_ttl)
  if not slot_ok then
    return nil, nil, nil, slot_err or "origin route lease slot unavailable"
  end
  local refreshed, refresh_err = lease_generation_refresh(dictionary, key, metadata_ttl)
  if not refreshed then
    lease_generation_retire(dictionary, key, generation)
    return nil, nil, nil, refresh_err
  end
  if generation > 1 then
    dictionary:delete(lease_fallback_key(key, generation - 1))
  end
  return generation, slot_token, order
end

local function lease_slot_current(dictionary, key, generation, slot_token)
  local current = lease_generation_current(dictionary, key)
  return current and current >= generation and
    dictionary:get(probe_slot_key(key, generation)) == slot_token
end

local function lease_commit_current(dictionary, key, generation, slot_token)
  return lease_slot_current(dictionary, key, generation, slot_token) and
    dictionary:get(lease_commit_key(key, generation)) == slot_token
end

local function lease_cleanup_history(dictionary, key, generation, slot_token, cleanup)
  local committed, committed_err = lease_committed_generations(dictionary, key)
  if not committed then
    return false, committed_err
  end
  local captured = {}
  for _, prior in ipairs(committed) do
    if prior.generation < generation then
      captured[#captured + 1] = prior
    end
  end
  if not lease_commit_current(dictionary, key, generation, slot_token) then
    return false
  end
  -- CDNCA_TEST_LEASE_CLEANUP_CAPTURE_BARRIER
  for _, prior in ipairs(captured) do
    cleanup(prior.generation, prior.slot_token)
    lease_generation_retire(dictionary, key, prior.generation)
  end
  return true
end

local function lease_trim_history(dictionary, key, generation, cleanup)
  local boundary = generation - LEASE_SCAN_LIMIT
  if boundary < 1 then
    return true
  end
  local fallback, fallback_err = lease_fallback_read(dictionary, key, generation)
  if fallback_err then
    return false, fallback_err
  end
  local function retire(prior)
    local expected_slot = dictionary:get(probe_slot_key(key, prior))
    local committed_slot = dictionary:get(lease_commit_key(key, prior))
    if committed_slot and committed_slot ~= expected_slot then
      return false, "origin route lease commit mismatch"
    end
    if committed_slot then
      cleanup(prior, committed_slot)
    end
    lease_generation_retire(dictionary, key, prior)
    dictionary:delete(lease_fallback_key(key, prior))
    return true
  end
  local retired, retire_err = retire(boundary)
  if not retired then
    return false, retire_err
  end
  if fallback and fallback.generation <= boundary and fallback.generation ~= boundary then
    retired, retire_err = retire(fallback.generation)
    if not retired then
      return false, retire_err
    end
  end
  return true
end

local function probe_current(dictionary, key)
  local committed, committed_err = lease_committed_generations(dictionary, key)
  if not committed then
    return nil, nil, nil, nil, committed_err
  end
  for _, candidate in ipairs(committed) do
    local generation, expected_slot = candidate.generation, candidate.slot_token
    local raw = dictionary:get(probe_owner_key(key, generation, expected_slot))
    if raw then
      local slot_token, owner = lease_unpack(raw)
      if slot_token and expected_slot == slot_token then
        if dictionary:get(probe_release_key(key, generation, slot_token)) then
          return nil
        end
        local order = tonumber(slot_token:match(":(%d+)$"))
        if not is_integer(order, 1, LEASE_MAX_GENERATION) then
          return nil, nil, nil, nil, "committed probe order mismatch"
        end
        return owner, generation, slot_token, order
      end
      return nil, nil, nil, nil, "committed probe owner mismatch"
    else
      return nil
    end
  end
  return nil
end

local function probe_write(dictionary, key, value, ttl, replace, history_ttl, skip_cleanup)
  history_ttl = math.max(ttl, history_ttl or ttl)
  local lock_token, lock_err = probe_lock_acquire(dictionary, key)
  if not lock_token then
    return nil, lock_err == "exists" and "mutation locked" or lock_err
  end
  -- CDNCA_TEST_PROBE_AFTER_MUTATION_ACQUIRE_BARRIER
  local previous, _, _, _, previous_err = probe_current(dictionary, key)
  if previous_err then
    probe_lock_release(dictionary, key, lock_token)
    return nil, previous_err
  end
  if not replace and previous then
    probe_lock_release(dictionary, key, lock_token)
    return nil, "exists"
  end
  local generation, slot_token, order, generation_err =
    probe_generation_next(dictionary, key, history_ttl)
  if not generation then
    probe_lock_release(dictionary, key, lock_token)
    return nil, generation_err or "origin route lease generation unavailable"
  end
  if dictionary:get(key .. ":mutation-lock") ~= lock_token then
    lease_generation_retire(dictionary, key, generation)
    return nil, "mutation lock lost"
  end
  -- CDNCA_TEST_PROBE_BEFORE_OWNER_PUBLICATION_BARRIER
  local owner_key = probe_owner_key(key, generation, slot_token)
  local ok, err, forcible = dictionary:add(owner_key, lease_pack(slot_token, value), ttl)
  if not ok or forcible then
    lease_generation_retire(dictionary, key, generation)
    probe_lock_release(dictionary, key, lock_token)
    return nil, forcible and "shared dict eviction" or err or
      "origin route probe owner unavailable", forcible
  end
  -- CDNCA_TEST_PROBE_WRITE_BARRIER
  if not lease_slot_current(dictionary, key, generation, slot_token) or
    dictionary:get(key .. ":mutation-lock") ~= lock_token then
    lease_generation_retire(dictionary, key, generation)
    return nil, "publication fence lost"
  end
  local committed, commit_err = dictionary:safe_add(
    lease_commit_key(key, generation), slot_token, history_ttl)
  if not committed then
    lease_generation_retire(dictionary, key, generation)
    return nil, commit_err or "origin route probe commit unavailable"
  end
  -- CDNCA_TEST_LEASE_AFTER_COMMIT_BARRIER
  if not probe_lock_release(dictionary, key, lock_token) then
    return nil, "mutation lock lost"
  end
  if skip_cleanup then
    local trimmed, trim_err = lease_trim_history(
      dictionary, key, generation, function(prior, prior_slot)
        dictionary:delete(probe_owner_key(key, prior, prior_slot))
        dictionary:delete(probe_release_key(key, prior, prior_slot))
      end)
    if not trimmed then
      return nil, trim_err
    end
    dictionary:delete(lease_fallback_key(key, generation))
    return ok, err, forcible, generation, slot_token, order
  end
  lease_cleanup_history(dictionary, key, generation, slot_token, function(prior, prior_slot)
    dictionary:delete(probe_owner_key(key, prior, prior_slot))
    dictionary:delete(probe_release_key(key, prior, prior_slot))
  end)
  dictionary:delete(lease_fallback_key(key, generation))
  return ok, err, forcible, generation, slot_token, order
end

local function probe_owned_delete(dictionary, key, owner_token, before_delete)
  if not owner_token then
    return false
  end
  local current, generation, slot_token, _, read_err = probe_current(dictionary, key)
  if read_err then
    return false, read_err
  end
  if not current and not generation then
    return false, "expired"
  end
  if current ~= owner_token or not generation then
    return false, "replaced"
  end
  -- CDNCA_TEST_PROBE_RELEASE_BARRIER
  if before_delete then
    before_delete()
  end
  local ttl = dictionary:ttl(probe_owner_key(key, generation, slot_token))
  if not ttl or ttl < 0 then
    ttl = active and active.retry and active.retry.budget + 1 or 1
  end
  local release_ttl = ttl == 0 and 0 or math.max(0.001, ttl)
  local ok, err, forcible = dictionary:set(
    probe_release_key(key, generation, slot_token), true, release_ttl)
  if not ok or forcible then
    return false, forcible and "shared dict eviction" or err
  end
  return true, nil, generation
end

local function lease_state_value_key(base_key, generation, slot_token)
  return base_key .. ":value:" .. generation .. ":" .. slot_token
end

local function lease_state_read(dictionary, base_key)
  local committed, committed_err = lease_committed_generations(dictionary, base_key)
  if not committed then
    return nil, nil, nil, committed_err
  end
  for _, candidate in ipairs(committed) do
    local generation, expected_slot = candidate.generation, candidate.slot_token
    local raw = dictionary:get(lease_state_value_key(base_key, generation, expected_slot))
    if raw then
      local slot_token, value = lease_unpack(raw)
      if slot_token and expected_slot == slot_token then
        local order = tonumber(slot_token:match(":(%d+)$"))
        if not is_integer(order, 1, LEASE_MAX_GENERATION) then
          return nil, nil, nil, "committed lease order mismatch"
        end
        return value, generation, order
      end
      return nil, nil, nil, "committed lease value mismatch"
    else
      return nil, nil, nil, "committed lease value unavailable"
    end
  end
  return nil
end

local function lease_dependency_current(dictionary, dependency)
  local owner, generation, slot_token, order = probe_current(dictionary, dependency.key)
  return owner == dependency.owner and generation == dependency.generation and
    slot_token == dependency.slot_token and order == dependency.order
end

local function lease_state_write(dictionary, base_key, raw, ttl, dependencies, skip_cleanup)
  local generation, slot_token, _, generation_err =
    probe_generation_next(dictionary, base_key, ttl)
  if not generation then
    return false, generation_err or "origin route lease generation unavailable"
  end
  for _, dependency in ipairs(dependencies or {}) do
    if not lease_dependency_current(dictionary, dependency) then
      lease_generation_retire(dictionary, base_key, generation)
      return false, "lease lost"
    end
  end
  -- CDNCA_TEST_LEASE_STATE_WRITE_BARRIER
  local value_key = lease_state_value_key(base_key, generation, slot_token)
  local ok, err, forcible = dictionary:add(
    value_key, lease_pack(slot_token, raw), ttl)
  if not ok or forcible then
    lease_generation_retire(dictionary, base_key, generation)
    return false, forcible and "shared dict eviction" or err or
      "origin route lease value unavailable"
  end
  -- CDNCA_TEST_LEASE_STATE_AFTER_ADD_BARRIER
  for _, dependency in ipairs(dependencies or {}) do
    if not lease_dependency_current(dictionary, dependency) then
      lease_generation_retire(dictionary, base_key, generation)
      return false, "lease lost"
    end
  end
  if not lease_slot_current(dictionary, base_key, generation, slot_token) then
    lease_generation_retire(dictionary, base_key, generation)
    return false, "publication fence lost"
  end
  local committed, commit_err = dictionary:safe_add(
    lease_commit_key(base_key, generation), slot_token, ttl)
  if not committed then
    lease_generation_retire(dictionary, base_key, generation)
    return false, commit_err or "origin route lease commit unavailable"
  end
  -- CDNCA_TEST_LEASE_AFTER_COMMIT_BARRIER
  if skip_cleanup then
    local trimmed, trim_err = lease_trim_history(
      dictionary, base_key, generation, function(prior, prior_slot)
        dictionary:delete(lease_state_value_key(base_key, prior, prior_slot))
      end)
    if not trimmed then
      return false, trim_err, generation
    end
    dictionary:delete(lease_fallback_key(base_key, generation))
    return true, nil, generation
  end
  lease_cleanup_history(dictionary, base_key, generation, slot_token, function(prior, prior_slot)
    dictionary:delete(lease_state_value_key(base_key, prior, prior_slot))
  end)
  dictionary:delete(lease_fallback_key(base_key, generation))
  return true, nil, generation
end

local function lease_acquire(dictionary, key, lease_ttl, history_ttl)
  local token = probe_operation_token(ngx.now())
  local ok, err, forcible, generation, slot_token, order = probe_write(
    dictionary, key, token, lease_ttl, false, history_ttl)
  if not ok or forcible then
    return nil, nil, forcible and "shared dict eviction" or err or
      "origin route lease acquisition unavailable"
  end
  return token, {
    key = key, owner = token, generation = generation,
    slot_token = slot_token, order = order,
  }
end

local function mark_state_unavailable(reason)
  local now = ngx.now()
  if now >= state_unavailable_until then
    ngx.log(ngx.ERR, "origin route circuit state unavailable: ", reason or "unknown")
  end
  state_unavailable_until = math.max(state_unavailable_until, now + active.state_cooldown)
  return false
end

local function state_write_ok(ok, err, forcible)
  if ok and not forcible then
    return true
  end
  return mark_state_unavailable(forcible and "shared dict eviction" or err)
end

local function state_capacity_available(dictionary)
  local free = dictionary:free_space()
  if type(free) ~= "number" then
    return false
  end
  local batches = 32
  while free < STATE_MIN_FREE_BYTES and batches > 0 do
    local flushed = dictionary:flush_expired(64)
    free = dictionary:free_space()
    if type(free) ~= "number" or not flushed or flushed == 0 then
      break
    end
    batches = batches - 1
  end
  return type(free) == "number" and free >= STATE_MIN_FREE_BYTES
end

local function state_ready(dictionary, pool)
  if ngx.now() < state_unavailable_until then
    return false
  end
  if not state_capacity_available(dictionary) then
    return mark_state_unavailable("shared dict capacity pressure")
  end
  local ok, err, forcible = dictionary:set(circuit_key(pool, "guard"), true, active.state_ttl)
  return state_write_ok(ok, err, forcible)
end

local function circuit_state_snapshot_key(pool)
  return circuit_key(pool, "circuit-snapshot")
end

local function circuit_state_decode(raw)
  if type(raw) ~= "string" or #raw > 128 then
    return nil
  end
  local version, failures, successes, open_until, marker =
    raw:match("^(%d+),(%d+),(%d+),([%d%.]+),(%d+)$")
  version, failures, successes, open_until, marker =
    tonumber(version), tonumber(failures), tonumber(successes), tonumber(open_until), tonumber(marker)
  if version ~= 1 or not failures or not successes or not open_until or not marker then
    return nil
  end
  return {failures = failures, successes = successes, open_until = open_until, marker = marker}
end

local function circuit_state_read(dictionary, pool)
  local raw, _, _, read_err = lease_state_read(dictionary, circuit_state_snapshot_key(pool))
  if read_err then
    return nil, read_err
  end
  if raw then
    local state = circuit_state_decode(raw)
    if state then
      return state
    end
    return nil, "invalid circuit snapshot"
  end
  return {
    failures = tonumber(dictionary:get(circuit_key(pool, "failures"))) or 0,
    successes = tonumber(dictionary:get(circuit_key(pool, "successes"))) or 0,
    open_until = tonumber(dictionary:get(circuit_key(pool, "open"))) or 0,
    marker = 0,
  }
end

local function circuit_state_write(dictionary, pool, state, dependencies)
  local raw = string.format("1,%d,%d,%.6f,%d",
    state.failures, state.successes, state.open_until, state.marker or 0)
  local ok, err, generation = lease_state_write(
    dictionary, circuit_state_snapshot_key(pool), raw, active.state_ttl, dependencies)
  if ok then
    dictionary:delete(circuit_key(pool, "failures"))
    dictionary:delete(circuit_key(pool, "successes"))
    dictionary:delete(circuit_key(pool, "open"))
  end
  return ok, err, generation
end

local function circuit_allow(pool)
  local dictionary = ngx.shared.cdnca_originroute_state
  if not state_ready(dictionary, pool) then
    return false, nil, false
  end
  local now = ngx.now()
  local probe_key = circuit_key(pool, "probe")
  local probe_owner, _, _, _, probe_err = probe_current(dictionary, probe_key)
  if probe_err then
    mark_state_unavailable(probe_err)
    return false, nil, false
  end
  if probe_owner then
    return false, nil, true
  end
  local state = circuit_state_read(dictionary, pool)
  if not state then
    return false, nil, false
  end
  local open_until = state.open_until
  if open_until <= 0 then
    return true, nil, true
  end
  if open_until > now then
    return false, nil, true
  end
  return true, nil, true
end

local function circuit_acquire_attempt(pool)
  local dictionary = ngx.shared.cdnca_originroute_state
  if not state_ready(dictionary, pool) then
    return false, nil, false
  end
  local now = ngx.now()
  local probe_key = circuit_key(pool, "probe")
  local state = circuit_state_read(dictionary, pool)
  if not state then
    return false, nil, false
  end
  local open_until = state.open_until
  if open_until <= 0 then
    return true, nil, true
  end
  local probe_owner, _, _, _, probe_err = probe_current(dictionary, probe_key)
  if probe_err then
    mark_state_unavailable(probe_err)
    return false, nil, false
  end
  if open_until > now or probe_owner then
    return false, nil, true
  end
  local probe_token = table.concat({
    tostring(ngx.worker.pid()), ngx.var.connection or "0",
    ngx.var.connection_requests or "0", ngx.var.request_id or "", string.format("%.6f", now),
  }, ":")
  local admitted, err, forcible = probe_write(
    dictionary, probe_key, probe_token, active.retry.budget + 1, false, active.state_ttl)
  if admitted and not forcible then
    return true, probe_token, true
  end
  if err == "exists" then
    return false, nil, true
  end
  mark_state_unavailable(forcible and "shared dict eviction" or err)
  return false, nil, false
end

local function circuit_release_probe(dictionary, probe_key, probe_token)
  local _, err = probe_owned_delete(dictionary, probe_key, probe_token)
  if err and err ~= "expired" then
    return mark_state_unavailable(err)
  end
  return true
end

local function circuit_observe(pool, probe_token, success)
  local dictionary = ngx.shared.cdnca_originroute_state
  local probe_key = circuit_key(pool, "probe")
  local dependencies = {}
  if probe_token then
    local owner, generation, slot_token, order, probe_err = probe_current(dictionary, probe_key)
    if probe_err then
      return mark_state_unavailable(probe_err)
    end
    if owner ~= probe_token then
      return true
    end
    dependencies[#dependencies + 1] = {
      key = probe_key, owner = owner, generation = generation,
      slot_token = slot_token, order = order,
    }
  end
  local state_lock_key = circuit_key(pool, "state-lock")
  local state_lock_token, state_dependency, lock_err = lease_acquire(
    dictionary, state_lock_key, LEASE_STATE_LOCK_TTL, active.state_ttl)
  if not state_lock_token then
    if probe_token then
      circuit_release_probe(dictionary, probe_key, probe_token)
    end
    if lock_err == "exists" or lock_err == "mutation locked" then
      return true
    end
    return mark_state_unavailable(lock_err or "state lock acquisition unavailable")
  end
  dependencies[#dependencies + 1] = state_dependency
  local state, state_err = circuit_state_read(dictionary, pool)
  if not state then
    probe_owned_delete(dictionary, state_lock_key, state_lock_token)
    if probe_token then
      circuit_release_probe(dictionary, probe_key, probe_token)
    end
    return mark_state_unavailable(state_err or "circuit state unavailable")
  end
  if success then
    state.failures = 0
    if probe_token then
      state.successes = math.min(1000000, state.successes + 1)
      if state.successes >= active.l2.recovery_threshold then
        state.successes = 0
        state.open_until = 0
      else
        state.open_until = ngx.now()
      end
    end
  else
    state.successes = 0
    state.failures = math.min(1000000, state.failures + 1)
    if probe_token or state.failures >= active.l2.failure_threshold then
      state.open_until = ngx.now() + active.l2.probe_interval_ms / 1000
    end
  end
  local written, write_err = circuit_state_write(dictionary, pool, state, dependencies)
  local state_released, state_release_err = probe_owned_delete(
    dictionary, state_lock_key, state_lock_token)
  local probe_released = not probe_token or circuit_release_probe(dictionary, probe_key, probe_token)
  if not written then
    if write_err == "lease lost" or write_err == "publication fence lost" then
      return true
    end
    return mark_state_unavailable(write_err)
  end
  if not state_released and state_release_err ~= "expired" then
    return mark_state_unavailable(state_release_err or "state lock ownership lost")
  end
  return probe_released
end

local function algorithm_state_key(pool, endpoint, suffix)
  local key = "b1:" .. active.state_key .. ":" .. active.revision .. ":" .. pool.id
  if endpoint then
    key = key .. ":" .. endpoint.id
  end
  return key .. ":" .. suffix
end

local function weighted_slot_sequence(pool, slot)
  if not is_integer(slot, 1, pool.total_weight) then
    return nil, "weighted slot is invalid"
  end
  local first = 1
  local cursor = 0
  for index, endpoint in ipairs(pool.endpoints) do
    cursor = cursor + endpoint.weight
    if slot <= cursor then
      first = index
      break
    end
  end
  local result = {}
  for offset = 0, #pool.endpoints - 1 do
    local index = ((first + offset - 1) % #pool.endpoints) + 1
    result[#result + 1] = {
      endpoint = pool.endpoints[index], pool = pool, kind = pool.kind,
    }
  end
  return result
end

local function hashed_sequence(pool, seed)
  if type(seed) ~= "string" or seed == "" then
    return nil, "algorithm seed is unavailable"
  end
  return weighted_slot_sequence(pool, (ngx.crc32_short(seed) % pool.total_weight) + 1)
end

local function round_robin_sequence(pool)
  local dictionary = ngx.shared.cdnca_originroute_state
  if not dictionary or not state_ready(dictionary, pool) then
    return nil, "round-robin state is unavailable"
  end
  local cursor, err, forcible = dictionary:incr(
    algorithm_state_key(pool, nil, "round-robin"), 1, 0, active.state_ttl)
  if not cursor or forcible or not is_integer(cursor, 1, LEASE_MAX_GENERATION) then
    if cursor and forcible then
      dictionary:incr(algorithm_state_key(pool, nil, "round-robin"), -1)
    end
    mark_state_unavailable(forcible and "shared dict eviction" or err or "round-robin cursor invalid")
    return nil, "round-robin state is unavailable"
  end
  return weighted_slot_sequence(pool, ((cursor - 1) % pool.total_weight) + 1)
end

local function canonical_client_ip(client)
  if type(client) ~= "table" or (client.family ~= 4 and client.family ~= 6) or
    type(client.bytes) ~= "table" then
    return nil
  end
  local result = {tostring(client.family)}
  for _, value in ipairs(client.bytes) do
    result[#result + 1] = string.format("%02x", value)
  end
  return table.concat(result, ":")
end

local function ip_hash_sequence(pool, client)
  local client_key = canonical_client_ip(client)
  if not client_key then
    return nil, "normalized client IP is unavailable"
  end
  return hashed_sequence(pool, "ip:" .. client_key)
end

local function url_hash_sequence(pool, request_uri)
  if type(request_uri) ~= "string" or request_uri == "" or #request_uri > 16384 or
    request_uri:find("\0", 1, true) then
    return nil, "normalized request URI is unavailable"
  end
  return hashed_sequence(pool, "uri:" .. request_uri)
end

local function request_random_seed()
  local test_seed = ngx.ctx.cdnca_origin_test_seed
  if test_seed ~= nil then
    test_seed = tostring(test_seed)
    if test_seed ~= "" and #test_seed <= 256 then
      return "test:" .. test_seed
    end
    return nil
  end
  local request_id = ngx.var.request_id
  if type(request_id) ~= "string" or #request_id < 16 or #request_id > 128 or
    not request_id:match("^[0-9A-Fa-f]+$") then
    return nil
  end
  return table.concat({
    request_id, tostring(ngx.worker.pid()), ngx.var.connection or "0",
    ngx.var.connection_requests or "0", string.format("%.6f", ngx.now()),
  }, ":")
end

local function random_sequence(pool)
  local seed = request_random_seed()
  if not seed then
    return nil, "request random seed is unavailable"
  end
  return hashed_sequence(pool, "random:" .. seed)
end

local function least_conn_sequence(pool, seed)
  local dictionary = ngx.shared.cdnca_originroute_state
  if not dictionary or not state_ready(dictionary, pool) then
    return nil, "least-conn state is unavailable"
  end
  local result = {}
  for _, endpoint in ipairs(pool.endpoints) do
    local raw = dictionary:get(algorithm_state_key(pool, endpoint, "inflight"))
    local inflight = raw == nil and 0 or tonumber(raw)
    if not is_integer(inflight, 0, LEASE_MAX_GENERATION) then
      mark_state_unavailable("least-conn inflight state is invalid")
      return nil, "least-conn state is unavailable"
    end
    result[#result + 1] = {
      endpoint = endpoint, pool = pool, kind = pool.kind,
      baseline_score = (inflight + 1) / endpoint.weight,
      baseline_tie = ngx.crc32_short(seed .. ":" .. endpoint.id),
    }
  end
  table.sort(result, function(left, right)
    if left.baseline_score ~= right.baseline_score then
      return left.baseline_score < right.baseline_score
    end
    if left.baseline_tie ~= right.baseline_tie then
      return left.baseline_tie < right.baseline_tie
    end
    return left.endpoint.id < right.endpoint.id
  end)
  return result
end

local function algorithm_sequence(pool, request)
  if pool.algorithm == "round_robin" then
    return round_robin_sequence(pool)
  elseif pool.algorithm == "ip_hash" then
    return ip_hash_sequence(pool, request.client)
  elseif pool.algorithm == "url_hash" then
    return url_hash_sequence(pool, request.request_uri)
  elseif pool.algorithm == "least_conn" then
    return least_conn_sequence(pool, request.seed)
  elseif pool.algorithm == "random" then
    return random_sequence(pool)
  end
  return nil, "unknown origin route algorithm"
end

local function baseline_inflight(candidate, delta)
  if candidate.pool.algorithm ~= "least_conn" then
    return true
  end
  local dictionary = ngx.shared.cdnca_originroute_state
  if not dictionary or not state_ready(dictionary, candidate.pool) then
    return nil
  end
  local key = algorithm_state_key(candidate.pool, candidate.endpoint, "inflight")
  local value, err, forcible = dictionary:incr(key, delta, 0, active.state_ttl)
  if not value or forcible or not is_integer(value, 0, LEASE_MAX_GENERATION) then
    if value and forcible then
      dictionary:incr(key, -delta)
    end
    mark_state_unavailable(forcible and "shared dict eviction" or err or "least-conn inflight invalid")
    return nil
  end
  return true
end

local function adaptive_key(pool, endpoint, suffix)
  local key = "a1:" .. active.state_key .. ":" .. active.revision .. ":" .. pool.id
  if endpoint then
    key = key .. ":" .. endpoint.id
  end
  return key .. ":" .. suffix
end

local function adaptive_probe_token(now)
  return probe_operation_token(now)
end

local mark_adaptive_state_unavailable

local function adaptive_release_probe(dictionary, candidate)
  if not candidate.adaptive_probe_token then
    return true
  end
  local key = adaptive_key(candidate.pool, candidate.endpoint, "probe")
  local _, err = probe_owned_delete(dictionary, key, candidate.adaptive_probe_token)
  candidate.adaptive_probe_token = nil
  if err and err ~= "expired" then
    return mark_adaptive_state_unavailable(err)
  end
  return true
end

local function adaptive_cooldown_active(dictionary, key)
  local value, _, _, read_err = lease_state_read(dictionary, key)
  if read_err then
    mark_adaptive_state_unavailable(read_err)
    return true, read_err
  end
  return value ~= nil or dictionary:get(key) ~= nil
end

local function adaptive_probe_active(dictionary, key)
  local owner, _, _, _, read_err = probe_current(dictionary, key)
  if read_err then
    mark_adaptive_state_unavailable(read_err)
    return true, read_err
  end
  return owner ~= nil
end

mark_adaptive_state_unavailable = function(reason)
  local now = ngx.now()
  if now >= adaptive_state_unavailable_until then
    ngx.log(ngx.ERR, "origin route adaptive state unavailable: ", reason or "unknown")
  end
  adaptive_state_unavailable_until = math.max(adaptive_state_unavailable_until, now + 1)
  return false
end

local function adaptive_dictionary_ready()
  if not active.adaptive or ngx.now() < adaptive_state_unavailable_until then
    return nil
  end
  local dictionary = ngx.shared.cdnca_originroute_adaptive_state
  if not dictionary then
    mark_adaptive_state_unavailable("shared dict is missing")
    return nil
  end
  if not state_capacity_available(dictionary) then
    mark_adaptive_state_unavailable("shared dict capacity pressure")
    return nil
  end
  return dictionary
end

local function adaptive_finite(value)
  return type(value) == "number" and value == value and value ~= math.huge and value ~= -math.huge
end

local function adaptive_decode_state(raw, now)
  if type(raw) ~= "string" or #raw > 256 then
    return nil
  end
  local _, separators = raw:gsub(",", "")
  if separators ~= 9 or raw:sub(1, 1) == "," or raw:sub(-1) == "," or
    raw:find(",,", 1, true) then
    return nil
  end
  local values = {}
  for part in raw:gmatch("[^,]+") do
    values[#values + 1] = tonumber(part)
  end
  if #values ~= 10 or values[1] ~= 1 then
    return nil
  end
  for index = 2, 10 do
    if not adaptive_finite(values[index]) or values[index] < 0 then
      return nil
    end
  end
  if values[2] ~= math.floor(values[2]) or values[2] > 1000000 or
    values[5] > 1 or values[6] ~= math.floor(values[6]) or values[6] > 1000000 or
    values[10] ~= math.floor(values[10]) or values[10] > 16 or
    values[3] > 120 or values[4] > 120 or
    values[7] > now or values[8] > now or values[9] > now + active.adaptive.max_ejection then
    return nil
  end
  return {
    samples = values[2], ewma = values[3], peak = values[4], failure = values[5],
    consecutive = values[6], last = values[7], warm = values[8],
    ejected = values[9], ejections = values[10],
  }
end

local function adaptive_encode_state(state)
  return string.format("1,%d,%.6f,%.6f,%.6f,%d,%.6f,%.6f,%.6f,%d",
    state.samples, state.ewma, state.peak, state.failure, state.consecutive,
    math.floor(state.last * 1000000) / 1000000,
    math.floor(state.warm * 1000000) / 1000000,
    math.floor(state.ejected * 1000000) / 1000000,
    state.ejections)
end

local function adaptive_read_state(dictionary, pool, endpoint, now)
  local base_key = adaptive_key(pool, endpoint, "state")
  local raw, _, _, read_err = lease_state_read(dictionary, base_key)
  if read_err then
    mark_adaptive_state_unavailable(read_err)
    return nil, "unavailable"
  end
  if raw == nil then
    raw = dictionary:get(base_key)
  end
  if raw == nil then
    return nil, "missing"
  end
  local state = adaptive_decode_state(raw, now or ngx.now())
  if not state then
    mark_adaptive_state_unavailable("invalid endpoint state")
    return nil, "invalid"
  end
  return state
end

local function adaptive_write_state(dictionary, pool, endpoint, state, dependencies)
  local ok, err = lease_state_write(dictionary, adaptive_key(pool, endpoint, "state"),
    adaptive_encode_state(state), active.adaptive.state_ttl, dependencies)
  if not ok then
    if err == "lease lost" or err == "publication fence lost" then
      return false
    end
    return mark_adaptive_state_unavailable(err)
  end
  dictionary:delete(adaptive_key(pool, endpoint, "state"))
  return true
end

local ADAPTIVE_LOCK_TTL = 0.5

local function adaptive_lock(dictionary, key)
  local token, dependency, err = lease_acquire(
    dictionary, key, ADAPTIVE_LOCK_TTL, active.adaptive.state_ttl)
  if token then
    return token, dependency
  end
  if err ~= "exists" and err ~= "mutation locked" then
    mark_adaptive_state_unavailable(err)
  end
  return false
end

local function adaptive_unlock(dictionary, key, token)
  local released, err = probe_owned_delete(dictionary, key, token)
  if not released then
    if err == "expired" then
      return true
    end
    mark_adaptive_state_unavailable(err or "adaptive lock ownership lost")
    return false
  end
  return true
end

local function adaptive_publish_locked(dictionary, dependency, publish)
  if not lease_dependency_current(dictionary, dependency) then
    return false, "busy"
  end
  local ok = publish()
  if not lease_dependency_current(dictionary, dependency) then
    return false, "busy"
  end
  return ok, ok and nil or "error"
end

local function adaptive_inflight(dictionary, pool, endpoint, delta)
  local key = adaptive_key(pool, endpoint, "inflight")
  local value, err, forcible = dictionary:incr(key, delta, 0, active.adaptive.state_ttl)
  if not value or forcible then
    if value and forcible then
      dictionary:incr(key, -delta)
    end
    mark_adaptive_state_unavailable(forcible and "shared dict eviction" or err)
    return nil
  end
  if value < 0 then
    dictionary:set(key, 0, active.adaptive.state_ttl)
    return 0
  end
  return value
end

local function adaptive_max_ejected(pool)
  local maximum = math.floor(#pool.endpoints * active.adaptive.max_ejection_percent / 100)
  return math.max(0, math.min(#pool.endpoints - 1, maximum))
end

local function adaptive_try_eject(dictionary, pool, endpoint, state, now, endpoint_dependency)
  if #pool.endpoints < 2 then
    return false, "single"
  end
  local lock_key = adaptive_key(pool, nil, "ejection-lock")
  local lock_token, lock_dependency = adaptive_lock(dictionary, lock_key)
  if not lock_token then
    return false, "busy"
  end
  local ejected = 0
  for _, other in ipairs(pool.endpoints) do
    if other.id ~= endpoint.id then
      local other_state = adaptive_read_state(dictionary, pool, other, now)
      if not other_state then
        adaptive_unlock(dictionary, lock_key, lock_token)
        return false, "unknown"
      elseif other_state.ejected > now then
        ejected = ejected + 1
      end
    end
  end
  if ejected >= adaptive_max_ejected(pool) then
    local published, publish_err = adaptive_publish_locked(dictionary, lock_dependency, function()
      if not adaptive_write_state(
        dictionary, pool, endpoint, state, {endpoint_dependency, lock_dependency}) then
        return false
      end
      local ok, err = lease_state_write(dictionary, adaptive_key(pool, nil, "cap"), "1",
        active.adaptive.recovery_probe_interval, {lock_dependency})
      if not ok then
        if err ~= "lease lost" and err ~= "publication fence lost" then
          mark_adaptive_state_unavailable(err)
        end
        return false
      end
      dictionary:delete(adaptive_key(pool, nil, "cap"))
      return true
    end)
    if not published then
      if publish_err ~= "busy" then
        adaptive_unlock(dictionary, lock_key, lock_token)
      end
      return false, publish_err
    end
    if not adaptive_unlock(dictionary, lock_key, lock_token) then
      return false, "error"
    end
    return true, "cap"
  end
  local previous_ejections = state.ejections
  local previous_ejected = state.ejected
  state.ejections = math.min(16, state.ejections + 1)
  local duration = active.adaptive.base_ejection
  for _ = 2, state.ejections do
    duration = math.min(active.adaptive.max_ejection, duration * 2)
  end
  state.ejected = now + math.min(active.adaptive.max_ejection, duration)
  -- CDNCA_TEST_EJECTION_BARRIER
  local published, publish_err = adaptive_publish_locked(dictionary, lock_dependency, function()
    return adaptive_write_state(
      dictionary, pool, endpoint, state, {endpoint_dependency, lock_dependency})
  end)
  if not published then
    state.ejections = previous_ejections
    state.ejected = previous_ejected
    if publish_err ~= "busy" then
      adaptive_unlock(dictionary, lock_key, lock_token)
    end
    return false, publish_err
  end
  if not adaptive_unlock(dictionary, lock_key, lock_token) then
    return false, "error"
  end
  return true, "ejected"
end

local function adaptive_observe(context, candidate, success, now)
  if not active.adaptive or candidate.adaptive_observed then
    return
  end
  candidate.adaptive_observed = true
  local raw_dictionary = ngx.shared.cdnca_originroute_adaptive_state
  if candidate.adaptive_inflight_recorded and raw_dictionary then
    if not adaptive_inflight(raw_dictionary, candidate.pool, candidate.endpoint, -1) then
      context.adaptive_disabled = true
      context.adaptive_reason = "telemetry_stale_fallback"
    end
    candidate.adaptive_inflight_recorded = false
  end
  if context.adaptive_disabled then
    if raw_dictionary then
      adaptive_release_probe(raw_dictionary, candidate)
    end
    return
  end
  local dictionary = adaptive_dictionary_ready()
  if not dictionary then
    if raw_dictionary then
      adaptive_release_probe(raw_dictionary, candidate)
    end
    context.adaptive_disabled = true
    context.adaptive_reason = "telemetry_stale_fallback"
    return
  end
  local lock_key = adaptive_key(candidate.pool, candidate.endpoint, "lock")
  local lock_token, lock_dependency = adaptive_lock(dictionary, lock_key)
  if not lock_token then
    adaptive_release_probe(dictionary, candidate)
    context.adaptive_disabled = true
    context.adaptive_reason = "telemetry_stale_fallback"
    return
  end
  local state, state_err = adaptive_read_state(dictionary, candidate.pool, candidate.endpoint, now)
  local latency = math.max(0.001, now - (candidate.started or now))
  if not state then
    if state_err ~= "missing" then
      adaptive_release_probe(dictionary, candidate)
      adaptive_unlock(dictionary, lock_key, lock_token)
      context.adaptive_disabled = true
      context.adaptive_reason = "telemetry_stale_fallback"
      return
    end
    state = {
      samples = 0, ewma = latency, peak = latency, failure = 0,
      consecutive = 0, last = now, warm = now, ejected = 0, ejections = 0,
    }
  elseif now < state.last or now < state.warm then
    context.adaptive_reason = "telemetry_stale_fallback"
    context.adaptive_disabled = true
    adaptive_release_probe(dictionary, candidate)
    adaptive_unlock(dictionary, lock_key, lock_token)
    mark_adaptive_state_unavailable("clock moved backwards")
    return
  end
  local decay = math.exp(-math.max(0, now - state.last) * LN2 / active.adaptive.half_life)
  local sample_alpha = 2 / (math.min(20, state.samples + 1) + 1)
  local failure_alpha = 2 / (math.min(20, math.max(active.adaptive.minimum_samples, state.samples + 1)) + 1)
  state.ewma = state.samples == 0 and latency or state.ewma + sample_alpha * (latency - state.ewma)
  state.peak = math.max(latency, state.peak * decay)
  state.failure = state.failure + failure_alpha * ((success and 0 or 1) - state.failure)
  state.samples = math.min(1000000, state.samples + 1)
  state.last = now
  local state_published = false
  local state_publish_blocked = false
  local result
  if success then
    state.consecutive = 0
    if candidate.adaptive_probe then
      state.ejected = 0
      state.failure = 0
      state.warm = now
    end
  else
    state.consecutive = math.min(1000000, state.consecutive + 1)
    if state.samples >= active.adaptive.outlier_minimum_samples and
      (state.consecutive >= active.adaptive.consecutive_failures or
        state.failure >= active.adaptive.failure_ratio) then
      state_published, result = adaptive_try_eject(
        dictionary, candidate.pool, candidate.endpoint, state, now, lock_dependency)
      state_publish_blocked = result == "busy"
      if result == "cap" then
        context.adaptive_reason = "ejection_cap_reached"
      elseif result == "error" or result == "unknown" then
        context.adaptive_disabled = true
        context.adaptive_reason = "telemetry_stale_fallback"
      end
    end
  end
  if not state_published and not state_publish_blocked then
    local published = adaptive_publish_locked(dictionary, lock_dependency, function()
      return adaptive_write_state(
        dictionary, candidate.pool, candidate.endpoint, state, {lock_dependency})
    end)
    if not published then
      context.adaptive_disabled = true
      context.adaptive_reason = "telemetry_stale_fallback"
    end
  end
  if not adaptive_release_probe(dictionary, candidate) then
    context.adaptive_disabled = true
    context.adaptive_reason = "telemetry_stale_fallback"
  end
  if not adaptive_unlock(dictionary, lock_key, lock_token) then
    context.adaptive_disabled = true
    context.adaptive_reason = "telemetry_stale_fallback"
  end
end

local function adaptive_weight(state, endpoint, now)
  if now < state.warm then
    return nil
  end
  local elapsed = now - state.warm
  if elapsed >= active.adaptive.slow_hard_timeout or elapsed >= active.adaptive.slow_ramp then
    return endpoint.weight, false
  end
  local factor = active.adaptive.slow_initial +
    (1 - active.adaptive.slow_initial) * math.max(0, elapsed / active.adaptive.slow_ramp)
  return endpoint.weight * factor, factor < 1
end

local function adaptive_pick(candidates, seed, salt, excluded)
  local total = 0
  for _, candidate in ipairs(candidates) do
    if candidate ~= excluded then
      total = total + candidate.adaptive_weight
    end
  end
  if total <= 0 then
    return nil
  end
  local slot = (ngx.crc32_short(seed .. ":" .. salt) / UINT32_RANGE) * total
  local cursor = 0
  for _, candidate in ipairs(candidates) do
    if candidate ~= excluded then
      cursor = cursor + candidate.adaptive_weight
      if slot < cursor then
        return candidate
      end
    end
  end
  return candidates[#candidates]
end

local function adaptive_score(candidate, now)
  local peak = candidate.adaptive_state.peak *
    math.exp(-math.max(0, now - candidate.adaptive_state.last) * LN2 / active.adaptive.half_life)
  return math.max(candidate.adaptive_state.ewma, peak) *
    (candidate.adaptive_inflight + 1) / math.max(0.000001, candidate.adaptive_weight)
end

local function adaptive_prefer(first, second, now)
  if first.adaptive_state.failure ~= second.adaptive_state.failure then
    return first.adaptive_state.failure < second.adaptive_state.failure and first or second
  end
  return adaptive_score(first, now) <= adaptive_score(second, now) and first or second
end

local function adaptive_tag_sequence(sequence, pool, reason, eligible, ejected, explored, slow)
  for _, candidate in ipairs(sequence) do
    candidate.adaptive_reason = reason
    candidate.adaptive_diagnostic = string.format("p=%s;c=%s;n=%d;e=%d;explore=%d;s=%d",
      pool.id, candidate.endpoint.id, eligible, ejected, explored and 1 or 0, slow and 1 or 0)
  end
  return sequence, reason, sequence[1] and sequence[1].adaptive_diagnostic or "p=none;c=none;n=0;e=0;explore=0;s=0"
end

local function copy_candidate_sequence(source)
  local result = {}
  for _, candidate in ipairs(source) do
    result[#result + 1] = {
      endpoint = candidate.endpoint, pool = candidate.pool, kind = candidate.kind,
    }
  end
  return result
end

local function adaptive_sequence(pool, seed, now, baseline_sequence)
  local baseline = baseline_sequence
  if not baseline then
    baseline = hashed_sequence(pool, seed)
  end
  baseline = copy_candidate_sequence(baseline)
  if #pool.endpoints == 1 then
    return adaptive_tag_sequence(baseline, pool, "single_candidate_fallback", 1, 0, false, false)
  end
  local dictionary = adaptive_dictionary_ready()
  if not dictionary then
    return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, 0, false, false)
  end
  local eligible = {}
  local eligible_ids = {}
  local ejected = 0
  local slow = false
  local recovery
  for _, endpoint in ipairs(pool.endpoints) do
    local state, state_err = adaptive_read_state(dictionary, pool, endpoint, now)
    if not state then
      if state_err == "missing" then
        return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, 0, false, false)
      end
      return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, 0, false, false)
    end
    if now < state.last then
      return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, 0, false, false)
    end
    local probe = false
    local excluded = false
    if state.ejected > now then
      ejected = ejected + 1
      excluded = true
    elseif state.ejected > 0 then
      local probe_key = adaptive_key(pool, endpoint, "probe")
      local cooldown_key = adaptive_key(pool, endpoint, "probe-cooldown")
      local cooldown, cooldown_err = adaptive_cooldown_active(dictionary, cooldown_key)
      local probe_active, probe_err = adaptive_probe_active(dictionary, probe_key)
      if cooldown_err or probe_err then
        return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, 0, false, false)
      end
      if cooldown or probe_active then
        ejected = ejected + 1
        excluded = true
      else
        probe = true
      end
    elseif state.samples < active.adaptive.minimum_samples or now - state.last > active.adaptive.freshness then
      return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, 0, false, false)
    end
    if not excluded then
      local weight, warming = adaptive_weight(state, endpoint, now)
      if not weight then
        return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, 0, false, false)
      end
      local inflight = tonumber(dictionary:get(adaptive_key(pool, endpoint, "inflight"))) or 0
      local candidate = {
        endpoint = endpoint, pool = pool, kind = pool.kind,
        adaptive_state = state, adaptive_weight = weight,
        adaptive_inflight = math.max(0, inflight), adaptive_recovery = probe,
      }
      eligible[#eligible + 1] = candidate
      eligible_ids[endpoint.id] = candidate
      slow = slow or warming
      if probe and not recovery then
        recovery = candidate
      end
    end
  end
  if #eligible == 0 then
    return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, ejected, false, false)
  end
  local selected = recovery
  local explored = false
  if not selected and #eligible == 1 then
    selected = eligible[1]
  elseif not selected then
    explored = ngx.crc32_short(seed .. ":explore") % 100 < active.adaptive.exploration
    local first = adaptive_pick(eligible, seed, explored and "explore" or "first")
    if explored then
      selected = first
    else
      local second = adaptive_pick(eligible, seed, "second")
      selected = adaptive_prefer(first, second, now)
    end
  end
  local result = { selected }
  for _, candidate in ipairs(baseline) do
    local eligible_candidate = eligible_ids[candidate.endpoint.id]
    if eligible_candidate and eligible_candidate.endpoint.id ~= selected.endpoint.id then
      result[#result + 1] = eligible_candidate
    end
  end
  local reason = "p2c_ewma_selected"
  if #eligible == 1 then
    reason = "single_candidate_fallback"
  elseif selected.adaptive_recovery or ejected > 0 then
    reason = "endpoint_ejected"
  elseif selected.adaptive_weight < selected.endpoint.weight then
    reason = "slow_start_active"
  end
  local cap_key = adaptive_key(pool, nil, "cap")
  local cap, _, _, cap_err = lease_state_read(dictionary, cap_key)
  if cap_err then
    mark_adaptive_state_unavailable(cap_err)
    return adaptive_tag_sequence(baseline, pool, "telemetry_stale_fallback", 0, 0, false, false)
  end
  if cap or dictionary:get(cap_key) then
    reason = "ejection_cap_reached"
  end
  return adaptive_tag_sequence(result, pool, reason, #eligible, ejected, explored, slow)
end

local function adaptive_acquire_probe(dictionary, candidate)
  if not candidate.adaptive_recovery then
    return true
  end
  local probe_key = adaptive_key(candidate.pool, candidate.endpoint, "probe")
  local cooldown_key = adaptive_key(candidate.pool, candidate.endpoint, "probe-cooldown")
  local cooldown, cooldown_err = adaptive_cooldown_active(dictionary, cooldown_key)
  local probe_active, probe_err = adaptive_probe_active(dictionary, probe_key)
  if cooldown_err or probe_err then
    return false, "unavailable"
  end
  if cooldown or probe_active then
    return false, "busy"
  end
  local token = adaptive_probe_token(ngx.now())
  local admitted, err, forcible, generation, slot_token, order = probe_write(
    dictionary, probe_key, token, active.retry.budget + 1, false, active.adaptive.state_ttl)
  if not admitted or forcible then
    if err == "exists" or err == "mutation locked" then
      return false, "busy"
    end
    mark_adaptive_state_unavailable(forcible and "shared dict eviction" or err)
    return false, "unavailable"
  end
  local dependency = {
    key = probe_key, owner = token, generation = generation,
    slot_token = slot_token, order = order,
  }
  local cooldown_ok, cooldown_err = lease_state_write(
    dictionary, cooldown_key, "1", active.adaptive.recovery_probe_interval, {dependency})
  if not cooldown_ok then
    probe_owned_delete(dictionary, probe_key, token)
    if cooldown_err ~= "lease lost" and cooldown_err ~= "publication fence lost" then
      mark_adaptive_state_unavailable(cooldown_err)
    end
    return false, "unavailable"
  end
  dictionary:delete(cooldown_key)
  candidate.adaptive_probe = true
  candidate.adaptive_probe_token = token
  return true
end

local function append_sequence(target, pool, request)
  if not pool then
    return true, nil, {}
  end
  local sequence, err = algorithm_sequence(pool, request)
  if not sequence then
    return nil, err
  end
  for _, candidate in ipairs(sequence) do
    target[#target + 1] = candidate
  end
  return true, nil, sequence
end

local function append_adaptive_sequence(target, pool, seed, now, baseline)
  if not pool then
    return nil, nil
  end
  local sequence, reason, diagnostic = adaptive_sequence(
    pool, seed .. ":" .. pool.id, now, baseline)
  for _, candidate in ipairs(sequence) do
    target[#target + 1] = candidate
  end
  return reason, diagnostic
end

local function request_has_body()
  local content_length = tonumber(ngx.var.http_content_length or "0") or 0
  return content_length > 0 or (ngx.var.http_transfer_encoding or "") ~= ""
end

function _M.access(listener_id)
  if not active then
    return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
  end
  local listener = active.listeners[listener_id]
  local client = parse_ip(ngx.var.remote_addr)
  if not listener or not client then
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
  end
  local path = ngx.var.uri or "/"
  local selected
  for _, route in ipairs(active.routes) do
    if route_matches(route, path, client) then
      selected = route
      break
    end
  end
  local pool = selected and selected.pool or active.default_pool
  local fallback = selected and selected.fallback or active.default_fallback
  local event = "selected"
  local state_available = true
  if pool.kind == "l2" then
    local allowed, ignored_probe
    allowed, ignored_probe, state_available = circuit_allow(pool)
    if not allowed then
      pool, fallback, event = fallback, nil,
        state_available and "circuit_open" or "circuit_state_unavailable"
    end
  end
  if not pool then
    return ngx.exit(ngx.HTTP_BAD_GATEWAY)
  end
  ngx.var.cdnca_origin_hop = pool.kind == "l2" and "1" or "0"

  local seed = (ngx.ctx.cdnca_origin_test_seed or ngx.var.request_id or "") ..
    ":" .. (ngx.var.remote_addr or "") .. ":" .. path
  local algorithm_request = {
    client = client,
    request_uri = ngx.var.request_uri,
    seed = seed,
  }
  local sequence = {}
  local baseline_sequence = {}
  local baseline_ok, baseline_err, primary_baseline =
    append_sequence(baseline_sequence, pool, algorithm_request)
  local fallback_baseline = {}
  if baseline_ok then
    baseline_ok, baseline_err, fallback_baseline =
      append_sequence(baseline_sequence, fallback, algorithm_request)
  end
  if not baseline_ok then
    ngx.log(ngx.ERR, "origin route baseline algorithm unavailable: ", baseline_err or "unknown")
    ngx.var.cdnca_origin_event = "algorithm_state_unavailable"
    return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
  end
  local adaptive_shadow = {}
  if active.adaptive then
    local adaptive_sequence_values = {}
    append_adaptive_sequence(adaptive_sequence_values, pool, seed, ngx.now(), primary_baseline)
    append_adaptive_sequence(adaptive_sequence_values, fallback, seed, ngx.now(), fallback_baseline)
    if active.adaptive.mode == "active" then
      sequence = adaptive_sequence_values
    else
      for _, candidate in ipairs(adaptive_sequence_values) do
        adaptive_shadow[candidate.pool.id .. ":" .. candidate.endpoint.id] = candidate.adaptive_reason
      end
      sequence = baseline_sequence
      for _, candidate in ipairs(sequence) do
        candidate.adaptive_reason = "baseline_weighted_selected"
        candidate.adaptive_diagnostic = string.format(
          "p=%s;c=%s;n=%d;e=0;explore=0;s=0", candidate.pool.id, candidate.endpoint.id, #candidate.pool.endpoints)
      end
    end
  else
    sequence = baseline_sequence
  end
  local retry_allowed = active.retry.methods[ngx.req.get_method()] == true and not request_has_body()
  local available_attempts = math.max(#sequence, #baseline_sequence)
  local max_attempts = retry_allowed and math.min(active.retry.max_attempts, available_attempts) or 1
  ngx.ctx.cdnca_originroute = {
    sequence = sequence, index = 0, attempt = 0, max_attempts = max_attempts,
    started = ngx.now(), retry_allowed = retry_allowed, listener = listener,
    route = selected and selected.id or "default", event = event,
    initial_pool = pool, state_unavailable = not state_available,
    circuit_denied = {}, adaptive_shadow = adaptive_shadow,
    baseline_sequence = baseline_sequence, attempted = {},
    using_adaptive = active.adaptive and active.adaptive.mode == "active" or false,
  }
  ngx.var.cdnca_origin_route = selected and selected.id or "default"
  ngx.var.cdnca_origin_event = event
  if active.adaptive then
    ngx.var.cdnca_origin_reason = ""
    ngx.var.cdnca_origin_shadow_reason = ""
    ngx.var.cdnca_origin_diagnostic = ""
  end
end

local function retryable_last_failure(state, status)
  if state == "failed" or state == "timeout" then
    return true
  end
  return status == 502 or status == 503 or status == 504
end

local function next_candidate(context)
  while context.index < #context.sequence do
    context.index = context.index + 1
    local candidate = context.sequence[context.index]
    if candidate.kind ~= "l2" then
      return candidate
    end
    if context.state_unavailable or context.circuit_denied[candidate.pool.id] then
      -- Circuit state is required before any L2 attempt; continue to the direct fallback.
    else
      local open_until = ngx.shared.cdnca_originroute_state:get(circuit_key(candidate.pool, "open"))
      if not open_until or open_until <= ngx.now() then
        return candidate
      end
    end
  end
  return nil
end

local function adaptive_candidate_key(candidate)
  return candidate.pool.id .. ":" .. candidate.endpoint.id
end

local function fallback_to_baseline(context)
  local remaining = {}
  for _, candidate in ipairs(context.baseline_sequence or {}) do
    if not context.attempted[adaptive_candidate_key(candidate)] then
      remaining[#remaining + 1] = candidate
    end
  end
  context.sequence = remaining
  context.index = 0
  context.using_adaptive = false
  context.adaptive_disabled = true
  context.adaptive_reason = "telemetry_stale_fallback"
  for _, candidate in ipairs(remaining) do
    candidate.adaptive_reason = "telemetry_stale_fallback"
    candidate.adaptive_diagnostic = string.format(
      "p=%s;c=%s;n=0;e=0;explore=0;s=0", candidate.pool.id, candidate.endpoint.id)
  end
end

local function baseline_observe(context, candidate)
  if not candidate.baseline_inflight_recorded then
    return true
  end
  if not baseline_inflight(candidate, -1) then
    context.algorithm_unavailable = true
    ngx.var.cdnca_origin_event = "algorithm_state_unavailable"
    return false
  end
  candidate.baseline_inflight_recorded = false
  return true
end

local function abandon_candidate(context, candidate)
  candidate.attempt_abandoned = true
  candidate.adaptive_observed = true
  baseline_observe(context, candidate)
  local adaptive_dictionary = ngx.shared.cdnca_originroute_adaptive_state
  if candidate.adaptive_inflight_recorded and adaptive_dictionary then
    adaptive_inflight(adaptive_dictionary, candidate.pool, candidate.endpoint, -1)
    candidate.adaptive_inflight_recorded = false
  end
  if candidate.adaptive_probe_token and adaptive_dictionary then
    adaptive_release_probe(adaptive_dictionary, candidate)
  end
  if candidate.circuit_probe_token then
    circuit_release_probe(ngx.shared.cdnca_originroute_state,
      circuit_key(candidate.pool, "probe"), candidate.circuit_probe_token)
    candidate.circuit_probe_token = nil
  end
end

local function prepare_candidate(context, candidate)
  if candidate.kind == "l2" then
    local allowed, probe_token, state_available = circuit_acquire_attempt(candidate.pool)
    if not allowed then
      context.circuit_denied[candidate.pool.id] = true
      if not state_available then
        context.state_unavailable = true
        ngx.var.cdnca_origin_event = "circuit_state_unavailable"
      end
      return false
    end
    candidate.circuit_probe_token = probe_token
  end
  if candidate.pool.algorithm == "least_conn" then
    if not baseline_inflight(candidate, 1) then
      context.algorithm_unavailable = true
      ngx.var.cdnca_origin_event = "algorithm_state_unavailable"
      abandon_candidate(context, candidate)
      return false
    end
    candidate.baseline_inflight_recorded = true
  end
  if not active.adaptive then
    return true
  end
  local dictionary = adaptive_dictionary_ready()
  if not dictionary then
    if context.using_adaptive then
      abandon_candidate(context, candidate)
      fallback_to_baseline(context)
      return false
    end
    context.adaptive_disabled = true
    context.adaptive_reason = "telemetry_stale_fallback"
    return true
  end
  local admitted, probe_err = adaptive_acquire_probe(dictionary, candidate)
  if not admitted then
    abandon_candidate(context, candidate)
    if probe_err == "unavailable" and context.using_adaptive then
      fallback_to_baseline(context)
    end
    return false
  end
  if not adaptive_inflight(dictionary, candidate.pool, candidate.endpoint, 1) then
    abandon_candidate(context, candidate)
    if context.using_adaptive then
      fallback_to_baseline(context)
    else
      context.adaptive_disabled = true
      context.adaptive_reason = "telemetry_stale_fallback"
    end
    return false
  end
  candidate.adaptive_inflight_recorded = true
  return true
end

local function select_candidate(context)
  while true do
    local candidate = next_candidate(context)
    if not candidate then
      return nil
    end
    if prepare_candidate(context, candidate) then
      return candidate
    end
    if context.algorithm_unavailable then
      return nil
    end
  end
end

local function publish_candidate_diagnostic(context, candidate)
  if not active.adaptive then
    return
  end
  -- Retry observations can promote a selection reason to a request-level outcome.
  local reason = context.adaptive_reason or candidate.adaptive_reason or "telemetry_stale_fallback"
  context.adaptive_reason = reason
  ngx.var.cdnca_origin_reason = reason
  ngx.var.cdnca_origin_shadow_reason = context.adaptive_shadow[adaptive_candidate_key(candidate)] or ""
  ngx.var.cdnca_origin_diagnostic = candidate.adaptive_diagnostic or string.format(
    "p=%s;c=%s;n=0;e=0;explore=0;s=0", candidate.pool.id, candidate.endpoint.id)
end

local function publish_dns_status(dns_state, dns_reason)
  if not active.dns then
    return
  end
  ngx.var.cdnca_origin_dns_state = dns_state
  ngx.var.cdnca_origin_dns_reason = dns_reason
end

function _M.balance()
  local context = ngx.ctx.cdnca_originroute
  if not context then
    return ngx.ERROR
  end
  local state, status = balancer.get_last_failure()
  if context.previous then
    local baseline_state_ok = baseline_observe(context, context.previous)
    local retryable = retryable_last_failure(state, status)
    if context.previous.kind == "l2" then
      if not circuit_observe(context.previous.pool, context.previous.circuit_probe_token, not retryable) then
        context.state_unavailable = true
        ngx.var.cdnca_origin_event = "circuit_state_unavailable"
      end
      context.previous.circuit_probe_token = nil
      context.previous_observed = true
    end
    adaptive_observe(context, context.previous, not retryable, ngx.now())
    if active.adaptive and context.adaptive_reason then
      ngx.var.cdnca_origin_reason = context.adaptive_reason
    end
    if not baseline_state_ok then
      return ngx.ERROR
    end
    if not context.retry_allowed or not retryable then
      return ngx.ERROR
    end
  end
  if context.adaptive_disabled and context.using_adaptive then
    fallback_to_baseline(context)
  end
  if context.attempt >= context.max_attempts or ngx.now() - context.started >= active.retry.budget then
    ngx.var.cdnca_origin_event = "budget_exhausted"
    return ngx.ERROR
  end
  local candidate
  local peer_address
  while true do
    candidate = select_candidate(context)
    if not candidate then
      break
    end
    local dns_state, dns_reason
    if candidate.endpoint.hostname then
      peer_address, dns_state, dns_reason = dns_select_address(candidate.endpoint, ngx.now())
    else
      peer_address = {host = candidate.endpoint.host, family = candidate.endpoint.family}
      dns_state, dns_reason = "literal", "ip_literal"
    end
    publish_dns_status(dns_state, dns_reason)
    if peer_address then
      break
    end
    context.dns_unavailable = true
    context.attempted[adaptive_candidate_key(candidate)] = true
    abandon_candidate(context, candidate)
  end
  if not candidate then
    ngx.var.cdnca_origin_event = context.algorithm_unavailable and
      "algorithm_state_unavailable" or (context.dns_unavailable and "dns_unavailable" or "attempts_exhausted")
    return ngx.ERROR
  end
  context.attempt = context.attempt + 1
  context.previous = candidate
  context.previous_observed = false
  context.attempted[adaptive_candidate_key(candidate)] = true
  publish_candidate_diagnostic(context, candidate)
  if context.attempt > 1 then
    ngx.var.cdnca_origin_event = candidate.kind == "origin" and "direct_fallback" or "retry"
  end
  candidate.started = ngx.now()
  local hop = candidate.kind == "l2" and "1" or "0"
  if ngx.var.cdnca_origin_hop ~= hop then
    ngx.var.cdnca_origin_hop = hop
    local request_ok, request_err = balancer.recreate_request()
    if not request_ok then
      ngx.log(ngx.ERR, "origin route request header rebuild failed: ", request_err)
      abandon_candidate(context, candidate)
      return ngx.ERROR
    end
  end
  local remaining = active.retry.budget - (ngx.now() - context.started)
  if remaining <= 0 then
    abandon_candidate(context, candidate)
    return ngx.ERROR
  end
  local timeout_ok, timeout_err = balancer.set_timeouts(
    math.min(active.retry.connect, remaining), remaining, math.min(active.retry.read, remaining)
  )
  if not timeout_ok then
    ngx.log(ngx.ERR, "origin route timeout setup failed: ", timeout_err)
    abandon_candidate(context, candidate)
    return ngx.ERROR
  end
  if context.attempt == 1 then
    local _, tries_err = balancer.set_more_tries(context.max_attempts - 1)
    if tries_err then
      ngx.log(ngx.WARN, "origin route retry cap: ", tries_err)
    end
  end
  local peer_host = peer_address.family == 6 and ("[" .. peer_address.host .. "]") or peer_address.host
  local ok, peer_err = balancer.set_current_peer(peer_host, candidate.endpoint.port)
  if not ok then
    ngx.log(ngx.ERR, "origin route peer setup failed: ", peer_err)
    abandon_candidate(context, candidate)
    return ngx.ERROR
  end
  -- Ingress-IP origin: bind this peer's connection to the source of its
  -- family. proxy_bind is evaluated before the balancer runs, so a variable
  -- set here never applied (FX30); the balancer API binds this attempt.
  local source
  if peer_address.family == 4 then
    source = context.listener.source4
  elseif peer_address.family == 6 then
    source = context.listener.source6
  end
  if source ~= nil and source ~= "" then
    local bound, bind_err = balancer.bind_to_local_addr(source)
    if not bound then
      ngx.log(ngx.ERR, "origin route source bind failed: ", bind_err)
      abandon_candidate(context, candidate)
      return ngx.ERROR
    end
  end
end

function _M.log_result()
  local context = ngx.ctx.cdnca_originroute
  if not context or not context.previous or context.previous.attempt_abandoned then
    return
  end
  local raw_status = ngx.var.upstream_status or ""
  local status = tonumber(raw_status:match("(%d%d%d)%s*$")) or 0
  local success = status > 0 and status ~= 502 and status ~= 503 and status ~= 504
  baseline_observe(context, context.previous)
  adaptive_observe(context, context.previous, success, ngx.now())
  if active.adaptive and context.adaptive_reason then
    ngx.var.cdnca_origin_reason = context.adaptive_reason
  end
  if context.previous.kind ~= "l2" or context.previous_observed then
    return
  end
  if not circuit_observe(context.previous.pool, context.previous.circuit_probe_token, success) then
    ngx.var.cdnca_origin_event = "circuit_state_unavailable"
  end
  context.previous.circuit_probe_token = nil
end

if os.getenv("CDNCA_ORIGINROUTE_SMOKE") == "1" then
  function _M.test_probe_clear(dictionary_name, key)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil, "test dictionary is missing"
    end
    local owner_prefix = key .. ":owner:"
    local release_prefix = key .. ":released:"
    local slot_prefix = key .. ":slot:"
    local commit_prefix = key .. ":commit:"
    local fallback_prefix = key .. ":fallback:"
    for _, candidate in ipairs(dictionary:get_keys(0)) do
      if candidate:sub(1, #owner_prefix) == owner_prefix or
        candidate:sub(1, #release_prefix) == release_prefix or
        candidate:sub(1, #slot_prefix) == slot_prefix or
        candidate:sub(1, #commit_prefix) == commit_prefix or
        candidate:sub(1, #fallback_prefix) == fallback_prefix then
        dictionary:delete(candidate)
      end
    end
    dictionary:delete(lease_generation_state_key(key))
    dictionary:delete(lease_generation_epoch_key(key))
    dictionary:delete(lease_generation_key(key))
    local test_mutation_lock = key .. ":mutation-" .. "lock"
    dictionary:delete(test_mutation_lock)
    dictionary:delete(key .. ":test-read")
    dictionary:delete(key .. ":test-write")
    dictionary:delete(key .. ":test-post-add")
    dictionary:delete(key .. ":test-cleanup-capture")
    dictionary:delete(key .. ":test-cleanup-generation")
    return true
  end

  local function test_wait_mutation_lock_expired(dictionary, key)
    local lock_key = key .. ":mutation-lock"
    dictionary:expire(lock_key, 0.001)
    local deadline = ngx.now() + 0.1
    repeat
      if not dictionary:get(lock_key) then
        return true
      end
      ngx.sleep(0.001)
    until ngx.now() >= deadline
    return not dictionary:get(lock_key)
  end

  function _M.test_lease_state_clear(dictionary_name, base_key)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil, "test dictionary is missing"
    end
    local slot_prefix = base_key .. ":slot:"
    local value_prefix = base_key .. ":value:"
    local commit_prefix = base_key .. ":commit:"
    local fallback_prefix = base_key .. ":fallback:"
    for _, candidate in ipairs(dictionary:get_keys(0)) do
      if candidate:sub(1, #slot_prefix) == slot_prefix or
        candidate:sub(1, #value_prefix) == value_prefix or
        candidate:sub(1, #commit_prefix) == commit_prefix or
        candidate:sub(1, #fallback_prefix) == fallback_prefix then
        dictionary:delete(candidate)
      end
    end
    dictionary:delete(lease_generation_state_key(base_key))
    dictionary:delete(lease_generation_epoch_key(base_key))
    dictionary:delete(lease_generation_key(base_key))
    return true
  end

  function _M.test_lease_key_counts(dictionary_name, key)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(key) ~= "string" or #key < 1 or #key > 4096 then
      return nil, "invalid lease count test"
    end
    local owner_prefix = key .. ":owner:"
    local slot_prefix = key .. ":slot:"
    local release_prefix = key .. ":released:"
    local value_prefix = key .. ":value:"
    local commit_prefix = key .. ":commit:"
    local owners, slots, releases, values, commits = 0, 0, 0, 0, 0
    for _, candidate in ipairs(dictionary:get_keys(0)) do
      if candidate:sub(1, #owner_prefix) == owner_prefix then
        owners = owners + 1
      elseif candidate:sub(1, #slot_prefix) == slot_prefix then
        slots = slots + 1
      elseif candidate:sub(1, #release_prefix) == release_prefix then
        releases = releases + 1
      elseif candidate:sub(1, #value_prefix) == value_prefix then
        values = values + 1
      elseif candidate:sub(1, #commit_prefix) == commit_prefix then
        commits = commits + 1
      end
    end
    return owners, slots, releases, values, commits
  end

  function _M.test_probe_history_bound(dictionary_name, key, iterations)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(key) ~= "string" or #key < 1 or #key > 4096 or
      not is_integer(iterations, LEASE_SCAN_LIMIT + 1, LEASE_SCAN_LIMIT * 2) then
      return nil, "invalid probe history test"
    end
    _M.test_probe_clear(dictionary_name, key)
    for index = 1, iterations do
      local owner = "history-owner-" .. index
      local ok, write_err = probe_write(dictionary, key, owner, 60, true, 60)
      if not ok then
        return nil, write_err
      end
      local released, release_err = probe_owned_delete(dictionary, key, owner)
      if not released then
        return nil, release_err or "history release failed"
      end
      if not test_wait_mutation_lock_expired(dictionary, key) then
        return nil, "mutation lock timeout"
      end
    end
    return true
  end

  function _M.test_lease_state_history_bound(dictionary_name, base_key, iterations)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(base_key) ~= "string" or #base_key < 1 or #base_key > 4096 or
      not is_integer(iterations, LEASE_SCAN_LIMIT + 1, LEASE_SCAN_LIMIT * 2) then
      return nil, "invalid state history test"
    end
    _M.test_lease_state_clear(dictionary_name, base_key)
    for index = 1, iterations do
      local ok, write_err = lease_state_write(
        dictionary, base_key, "history-value-" .. index, 60)
      if not ok then
        return nil, write_err
      end
    end
    return true
  end

  function _M.test_probe_interrupted_history(dictionary_name, key, iterations)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(key) ~= "string" or #key < 1 or #key > 4096 or
      not is_integer(iterations, LEASE_SCAN_LIMIT + 1, LEASE_SCAN_LIMIT * 2) then
      return nil, "invalid interrupted probe history test"
    end
    _M.test_probe_clear(dictionary_name, key)
    for index = 1, iterations do
      local owner = "interrupted-owner-" .. index
      local ok, write_err = probe_write(dictionary, key, owner, 60, true, 60, true)
      if not ok then
        return nil, write_err
      end
      local released, release_err = probe_owned_delete(dictionary, key, owner)
      if not released then
        return nil, release_err or "interrupted history release failed"
      end
      if not test_wait_mutation_lock_expired(dictionary, key) then
        return nil, "mutation lock timeout"
      end
    end
    return true
  end

  function _M.test_lease_state_interrupted_history(dictionary_name, base_key, iterations)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(base_key) ~= "string" or #base_key < 1 or #base_key > 4096 or
      not is_integer(iterations, LEASE_SCAN_LIMIT + 1, LEASE_SCAN_LIMIT * 2) then
      return nil, "invalid interrupted state history test"
    end
    _M.test_lease_state_clear(dictionary_name, base_key)
    for index = 1, iterations do
      local ok, write_err = lease_state_write(
        dictionary, base_key, "interrupted-value-" .. index, 60, nil, true)
      if not ok then
        return nil, write_err
      end
    end
    return true
  end

  function _M.test_lease_protocol_fault(dictionary_name, key, kind)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(key) ~= "string" or #key < 1 or #key > 4096 then
      return nil, "invalid lease fault test"
    end
    _M.test_probe_clear(dictionary_name, key)
    local seeded, seed_err = probe_write(dictionary, key, "fault-seed", 60, true, 60)
    if not seeded then
      return nil, seed_err
    end
    if not test_wait_mutation_lock_expired(dictionary, key) then
      return nil, "mutation lock timeout"
    end
    local saved_order
    if kind == "counter-missing" then
      dictionary:delete(lease_generation_key(key))
    elseif kind == "overflow" then
      dictionary:set(lease_generation_key(key), LEASE_MAX_GENERATION)
    elseif kind == "restart-mismatch" then
      dictionary:set(lease_generation_epoch_key(key), "wrong-process-epoch")
    elseif kind == "order-missing" then
      saved_order = dictionary:get(LEASE_ORDER_KEY)
      dictionary:delete(LEASE_ORDER_KEY)
    else
      return nil, "invalid lease fault kind"
    end
    local ok, err = probe_write(dictionary, key, "must-fail", 60, true, 60)
    if kind == "order-missing" then
      local restored, restore_err = dictionary:safe_set(LEASE_ORDER_KEY, saved_order)
      if not restored then
        return nil, restore_err or "origin route lease order restore failed"
      end
    end
    return not ok, err
  end

  function _M.test_lease_precommit_failures(dictionary_name, base_key, failures)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(base_key) ~= "string" or #base_key < 1 or #base_key > 4096 or
      not is_integer(failures, LEASE_SCAN_LIMIT + 1, LEASE_SCAN_LIMIT * 2) then
      return nil, "invalid precommit failure test"
    end
    local seeded, seed_err = lease_state_write(dictionary, base_key, "round8-seed", 60)
    if not seeded then
      return nil, seed_err
    end
    for _ = 1, failures do
      local generation, _, _, generation_err = probe_generation_next(dictionary, base_key, 60)
      if not generation then
        return nil, generation_err
      end
      lease_generation_retire(dictionary, base_key, generation)
    end
    local value, _, _, read_err = lease_state_read(dictionary, base_key)
    if read_err or value ~= "round8-seed" then
      return nil, read_err or "committed state was retired"
    end
    return true, nil, value
  end

  local function lease_test_metadata_count(dictionary, prefix)
    local suffix = ":generation-state"
    local count = 0
    for _, candidate in ipairs(dictionary:get_keys(0)) do
      if candidate:sub(1, #prefix) == prefix and
        candidate:sub(-#suffix) == suffix then
        count = count + 1
      end
    end
    return count
  end

  function _M.test_lease_metadata_reclaim(dictionary_name, prefix, revisions)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(prefix) ~= "string" or #prefix < 1 or #prefix > 256 or
      not is_integer(revisions, LEASE_SCAN_LIMIT + 1, LEASE_SCAN_LIMIT * 2) then
      return nil, "invalid metadata reclaim test"
    end
    for revision = 1, revisions do
      local ok, err = lease_state_write(
        dictionary, prefix .. revision, "round8", 0.05)
      if not ok then
        return nil, err
      end
    end
    local before = lease_test_metadata_count(dictionary, prefix)
    ngx.sleep(0.2)
    dictionary:flush_expired(0)
    local after = lease_test_metadata_count(dictionary, prefix)
    if before ~= revisions or after ~= 0 then
      return nil, "lease metadata was not reclaimed"
    end
    return true, nil, before, after
  end

  function _M.test_lease_round8_fault(dictionary_name, key, kind)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(key) ~= "string" or #key < 1 or #key > 4096 then
      return nil, "invalid Round-8 lease fault test"
    end
    local state_key = lease_generation_state_key(key)
    local epoch_key = lease_generation_epoch_key(key)
    local counter_key = lease_generation_key(key)
    if kind == "half-init" then
      dictionary:delete(state_key)
      dictionary:delete(epoch_key)
      dictionary:delete(counter_key)
      local state_ok, state_err = dictionary:safe_add(
        state_key, lease_generation_state_value("I"), 2)
      if not state_ok then
        return nil, state_err
      end
      local epoch_ok, epoch_err = dictionary:safe_add(epoch_key, lease_epoch, 2)
      if not epoch_ok then
        return nil, epoch_err
      end
      local generation, generation_err = lease_generation_init(dictionary, key, 1)
      if generation ~= 0 then
        return nil, generation_err or "half initialization did not recover"
      end
      return true, nil, "recovered"
    elseif kind == "allocation-pressure" then
      local pressure_prefix = key .. ":pressure:"
      for index = 1, 4096 do
        local ok = dictionary:safe_add(pressure_prefix .. index, string.rep("x", 64), 2)
        if not ok then
          break
        end
      end
      local pressure_key = key .. ":allocation"
      local first = lease_generation_init(dictionary, pressure_key, 1)
      for _, candidate in ipairs(dictionary:get_keys(0)) do
        if candidate:sub(1, #pressure_prefix) == pressure_prefix then
          dictionary:delete(candidate)
        end
      end
      dictionary:flush_expired(0)
      local recovered, recover_err = lease_generation_init(dictionary, pressure_key, 1)
      if first ~= nil or recovered ~= 0 then
        return nil, recover_err or "allocation pressure did not fail and recover"
      end
      return true, nil, "recovered"
    elseif kind == "fallback-pressure" then
      local pressure_key = key .. ":fallback-allocation"
      local seeded, seed_err = lease_state_write(dictionary, pressure_key, "round8-seed", 2)
      if not seeded then
        return nil, seed_err
      end
      local pressure_prefix = key .. ":fallback-pressure:"
      for index = 1, 4096 do
        local ok = dictionary:safe_add(pressure_prefix .. index, string.rep("x", 64), 2)
        if not ok then
          break
        end
      end
      local failed = probe_generation_next(dictionary, pressure_key, 2)
      for _, candidate in ipairs(dictionary:get_keys(0)) do
        if candidate:sub(1, #pressure_prefix) == pressure_prefix then
          dictionary:delete(candidate)
        end
      end
      dictionary:flush_expired(0)
      local recovered, _, _, recover_err = probe_generation_next(dictionary, pressure_key, 2)
      if failed ~= nil or not recovered then
        return nil, recover_err or "fallback allocation did not fail and recover"
      end
      lease_generation_retire(dictionary, pressure_key, recovered)
      local value, _, _, read_err = lease_state_read(dictionary, pressure_key)
      if read_err or value ~= "round8-seed" then
        return nil, read_err or "fallback recovery lost committed state"
      end
      return true, nil, "recovered"
    elseif kind == "global-loss" then
      local protocol = dictionary:get(LEASE_PROTOCOL_KEY)
      local stored_epoch = dictionary:get(LEASE_EPOCH_KEY)
      local order = dictionary:get(LEASE_ORDER_KEY)
      dictionary:delete(LEASE_EPOCH_KEY)
      dictionary:delete(LEASE_ORDER_KEY)
      local accepted = lease_protocol_init(dictionary)
      local epoch_ok, epoch_err = dictionary:safe_set(LEASE_EPOCH_KEY, stored_epoch)
      local order_ok, order_err = dictionary:safe_set(LEASE_ORDER_KEY, order)
      local marker_ok, marker_err = dictionary:safe_set(LEASE_PROTOCOL_KEY, protocol)
      if not epoch_ok or not order_ok or not marker_ok then
        return nil, epoch_err or order_err or marker_err
      end
      local restored, restore_err = lease_protocol_init(dictionary)
      if accepted or not restored then
        return nil, restore_err or "global lease metadata loss was accepted"
      end
      return true, nil, "rejected"
    elseif kind == "local-restart" then
      lease_epoch = nil
      local restarted, restart_err = lease_protocol_init(dictionary)
      if not restarted then
        return nil, restart_err
      end
      return true, nil, "restarted"
    end
    return nil, "invalid Round-8 lease fault kind"
  end

  function _M.test_lease_state_replace(dictionary_name, base_key, raw, ttl)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(base_key) ~= "string" or #base_key < 1 or #base_key > 4096 or
      type(raw) ~= "string" or #raw < 1 or #raw > 128 or
      type(ttl) ~= "number" or ttl < 1 or ttl > 120 then
      return nil, "invalid lease state replacement test"
    end
    return lease_state_write(dictionary, base_key, raw, ttl)
  end

  function _M.test_lease_state_value(dictionary_name, base_key)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil
    end
    return lease_state_read(dictionary, base_key)
  end

  function _M.test_mutation_lock_seed(dictionary_name, key, token, ttl)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary or type(key) ~= "string" or #key < 1 or #key > 4096 or
      type(token) ~= "string" or #token < 1 or #token > 128 or
      type(ttl) ~= "number" or ttl < 0.001 or ttl > 2 then
      return nil, "invalid mutation lock seed"
    end
    return dictionary:set(key .. ":mutation-lock", token, ttl)
  end

  function _M.test_mutation_lock_release(dictionary_name, key, token)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil, "test dictionary is missing"
    end
    return probe_lock_release(dictionary, key, token)
  end

  function _M.test_mutation_lock_value(dictionary_name, key)
    local dictionary = ngx.shared[dictionary_name]
    return dictionary and dictionary:get(key .. ":mutation-lock") or nil
  end

  function _M.test_probe_seed(dictionary_name, key, owner_token, ttl)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil, "test dictionary is missing"
    end
    _M.test_probe_clear(dictionary_name, key)
    local deadline = ngx.now() + 1
    repeat
      local ok, err, forcible, generation, slot_token, order =
        probe_write(dictionary, key, owner_token, ttl, true)
      if ok or err ~= "mutation locked" then
        return ok, err, forcible, generation, slot_token, order
      end
      ngx.sleep(0.005)
    until ngx.now() >= deadline
    return nil, "mutation lock timeout"
  end

  function _M.test_probe_value(dictionary_name, key)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil
    end
    return probe_current(dictionary, key)
  end

  function _M.test_probe_release(dictionary_name, key, owner_token)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil, "test dictionary is missing"
    end
    local released, err = probe_owned_delete(dictionary, key, owner_token, function()
      dictionary:set(key .. ":test-read", tostring(ngx.worker.pid()), 2)
      ngx.sleep(0.2)
    end)
    return released, err or tostring(ngx.worker.pid())
  end

  function _M.test_probe_replace(dictionary_name, key, replacement_token, ttl)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil, "test dictionary is missing"
    end
    local deadline = ngx.now() + 1
    while ngx.now() < deadline do
      local ok, err, _, generation = probe_write(dictionary, key, replacement_token, ttl, true)
      if ok then
        return true, tostring(ngx.worker.pid()), generation
      end
      if err ~= "mutation locked" then
        return nil, err
      end
      ngx.sleep(0.005)
    end
    return nil, "mutation lock timeout"
  end

  function _M.test_circuit_state_write(pool_id, marker, open_until)
    local dictionary = ngx.shared.cdnca_originroute_state
    local pool = active and active.pools[pool_id]
    if not dictionary or not pool or not is_integer(marker, 0, 1000000) then
      return nil, "invalid circuit test state"
    end
    local started_at = ngx.now()
    local lock_key = circuit_key(pool, "state-lock")
    local token, dependency, lock_err
    local deadline = ngx.now() + LEASE_STATE_LOCK_TTL + PROBE_MUTATION_LOCK_TTL
    repeat
      token, dependency, lock_err = lease_acquire(
        dictionary, lock_key, LEASE_STATE_LOCK_TTL, active.state_ttl)
      if token or (lock_err ~= "mutation locked" and lock_err ~= "exists") then
        break
      end
      ngx.sleep(0.005)
    until ngx.now() >= deadline
    if not token then
      return nil, lock_err
    end
    local state, state_err = circuit_state_read(dictionary, pool)
    if not state then
      probe_owned_delete(dictionary, lock_key, token)
      return nil, state_err
    end
    state.marker = marker
    if open_until ~= nil then
      if type(open_until) ~= "number" or open_until < 0 then
        probe_owned_delete(dictionary, lock_key, token)
        return nil, "invalid circuit test open time"
      end
      state.open_until = open_until
    end
    local ok, write_err, generation = circuit_state_write(dictionary, pool, state, {dependency})
    local released, release_err = probe_owned_delete(dictionary, lock_key, token)
    if not ok then
      return nil, write_err, generation
    end
    if not released then
      return nil, release_err or string.format(
        "state lock ownership lost after %.3f", ngx.now() - started_at), generation
    end
    return true, nil, generation
  end

  function _M.test_circuit_state_value(pool_id)
    local dictionary = ngx.shared.cdnca_originroute_state
    local pool = active and active.pools[pool_id]
    if not dictionary or not pool then
      return nil
    end
    local state = circuit_state_read(dictionary, pool)
    return state and state.marker or nil
  end

  function _M.test_decode_state(raw)
    return adaptive_decode_state(raw, ngx.now()) == nil
  end

  function _M.test_reset_state_cooldown()
    adaptive_state_unavailable_until = 0
    return true
  end

  function _M.test_adaptive_prefer(
    first_failure, first_latency, first_weight, first_inflight,
    second_failure, second_latency, second_weight, second_inflight)
    local values = {
      first_failure, first_latency, first_weight, first_inflight,
      second_failure, second_latency, second_weight, second_inflight,
    }
    for _, value in ipairs(values) do
      if not adaptive_finite(value) or value < 0 then
        return nil, "invalid comparator input"
      end
    end
    if first_failure > 1 or second_failure > 1 or first_weight <= 0 or second_weight <= 0 then
      return nil, "invalid comparator input"
    end
    local now = ngx.now()
    local first = {
      adaptive_state = {failure = first_failure, ewma = first_latency, peak = first_latency, last = now},
      adaptive_weight = first_weight, adaptive_inflight = first_inflight,
    }
    local second = {
      adaptive_state = {failure = second_failure, ewma = second_latency, peak = second_latency, last = now},
      adaptive_weight = second_weight, adaptive_inflight = second_inflight,
    }
    return adaptive_prefer(first, second, now) == first and "first" or "second"
  end

  function _M.test_adaptive_lock_crash(dictionary_name, key)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil, "test dictionary is missing"
    end
    local token = adaptive_lock(dictionary, key)
    if not token then
      return nil, "busy"
    end
    return true
  end

  function _M.test_adaptive_lock_takeover(dictionary_name, key)
    local dictionary = ngx.shared[dictionary_name]
    if not dictionary then
      return nil, "test dictionary is missing"
    end
    local token = adaptive_lock(dictionary, key)
    if not token then
      return nil, "busy"
    end
    if not adaptive_unlock(dictionary, key, token) then
      return nil, "unlock failed"
    end
    return true
  end

  local function test_adaptive_lease_keys(pool, endpoint, kind)
    if not pool or not endpoint then
      return nil
    end
    if kind == "ordinary" or kind == "ejection" then
      return adaptive_key(pool, endpoint, "state"), adaptive_key(pool, endpoint, "lock")
    elseif kind == "cap" then
      return adaptive_key(pool, nil, "cap"), adaptive_key(pool, nil, "ejection-lock")
    elseif kind == "cooldown" then
      return adaptive_key(pool, endpoint, "probe-cooldown"), adaptive_key(pool, endpoint, "probe")
    end
    return nil
  end

  function _M.test_adaptive_lease_reset(pool_id, endpoint_id, kind)
    local dictionary = ngx.shared.cdnca_originroute_adaptive_state
    local pool = active and active.pools[pool_id]
    local endpoint
    if pool then
      for _, candidate in ipairs(pool.endpoints) do
        if candidate.id == endpoint_id then
          endpoint = candidate
          break
        end
      end
    end
    local base_key, lock_key = test_adaptive_lease_keys(pool, endpoint, kind)
    if not dictionary or not pool or not endpoint or not base_key then
      return nil, "invalid adaptive lease test"
    end
    _M.test_lease_state_clear("cdnca_originroute_adaptive_state", base_key)
    _M.test_probe_clear("cdnca_originroute_adaptive_state", lock_key)
    dictionary:delete("__cdnca_test_round5_" .. kind .. "_post_add")
    return true
  end

  function _M.test_adaptive_lease_write(pool_id, endpoint_id, kind, marker)
    local dictionary = ngx.shared.cdnca_originroute_adaptive_state
    local pool = active and active.pools[pool_id]
    local endpoint
    if pool then
      for _, candidate in ipairs(pool.endpoints) do
        if candidate.id == endpoint_id then
          endpoint = candidate
          break
        end
      end
    end
    local base_key, lock_key = test_adaptive_lease_keys(pool, endpoint, kind)
    if not dictionary or not pool or not endpoint or not base_key or
      type(marker) ~= "string" or #marker > 64 then
      return nil, "invalid adaptive lease test"
    end
    local token, dependency, lock_err = lease_acquire(
      dictionary, lock_key, ADAPTIVE_LOCK_TTL, active.adaptive.state_ttl)
    if not token then
      return nil, lock_err
    end
    local ok, write_err, generation = lease_state_write(
      dictionary, base_key, marker, active.adaptive.state_ttl, {dependency})
    local released = probe_owned_delete(dictionary, lock_key, token)
    return ok and released, write_err or (released and nil or "unlock failed"), generation
  end

  function _M.test_adaptive_lease_value(pool_id, endpoint_id, kind)
    local dictionary = ngx.shared.cdnca_originroute_adaptive_state
    local pool = active and active.pools[pool_id]
    local endpoint
    if pool then
      for _, candidate in ipairs(pool.endpoints) do
        if candidate.id == endpoint_id then
          endpoint = candidate
          break
        end
      end
    end
    local base_key = test_adaptive_lease_keys(pool, endpoint, kind)
    if not dictionary or not pool or not endpoint or not base_key then
      return nil, "invalid adaptive lease test"
    end
    return lease_state_read(dictionary, base_key)
  end

  function _M.test_adaptive_state_write(pool_id, endpoint_id, marker)
    local dictionary = ngx.shared.cdnca_originroute_adaptive_state
    local pool = active and active.pools[pool_id]
    local endpoint
    if pool then
      for _, candidate in ipairs(pool.endpoints) do
        if candidate.id == endpoint_id then
          endpoint = candidate
          break
        end
      end
    end
    if not dictionary or not endpoint or not is_integer(marker, 1, 1000000) then
      return nil, "invalid adaptive test state"
    end
    local lock_key = adaptive_key(pool, endpoint, "lock")
    local token, dependency = adaptive_lock(dictionary, lock_key)
    if not token then
      return nil, "busy"
    end
    local now = ngx.now()
    local state = {
      samples = marker, ewma = 0.001, peak = 0.001, failure = 0,
      consecutive = 0, last = now, warm = now, ejected = 0, ejections = 0,
    }
    local ok, write_err = adaptive_publish_locked(dictionary, dependency, function()
      return adaptive_write_state(dictionary, pool, endpoint, state, {dependency})
    end)
    local released = adaptive_unlock(dictionary, lock_key, token)
    return ok and released, write_err or (released and nil or "unlock failed")
  end

  function _M.test_adaptive_state_value(pool_id, endpoint_id)
    local dictionary = ngx.shared.cdnca_originroute_adaptive_state
    local pool = active and active.pools[pool_id]
    local endpoint
    if pool then
      for _, candidate in ipairs(pool.endpoints) do
        if candidate.id == endpoint_id then
          endpoint = candidate
          break
        end
      end
    end
    if not dictionary or not endpoint then
      return nil
    end
    local state = adaptive_read_state(dictionary, pool, endpoint, ngx.now())
    return state and adaptive_encode_state(state) or nil
  end

  function _M.test_benchmark(pool_id, iterations)
    if not active or not active.adaptive or not is_integer(iterations, 1, 100000) then
      return nil, "adaptive benchmark is unavailable"
    end
    local pool = active.pools[pool_id]
    if not pool then
      return nil, "benchmark pool is missing"
    end
    collectgarbage("collect")
    local baseline_memory = collectgarbage("count")
    ngx.update_time()
    local baseline_started = ngx.now()
    for index = 1, iterations do
      hashed_sequence(pool, "benchmark:" .. index)
    end
    ngx.update_time()
    local baseline_elapsed = ngx.now() - baseline_started
    local baseline_allocated = math.max(0, collectgarbage("count") - baseline_memory)

    collectgarbage("collect")
    local adaptive_memory = collectgarbage("count")
    ngx.update_time()
    local adaptive_started = ngx.now()
    for index = 1, iterations do
      adaptive_sequence(pool, "benchmark:" .. index, ngx.now())
    end
    ngx.update_time()
    local adaptive_elapsed = ngx.now() - adaptive_started
    local adaptive_allocated = math.max(0, collectgarbage("count") - adaptive_memory)
    return {
      iterations = iterations,
      baseline_elapsed_ms = baseline_elapsed * 1000,
      adaptive_elapsed_ms = adaptive_elapsed * 1000,
      baseline_heap_kb = baseline_allocated,
      adaptive_heap_kb = adaptive_allocated,
    }
  end
end

return _M
