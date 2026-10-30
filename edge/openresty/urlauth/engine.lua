local bit = require("bit")
local cjson = require("cjson.safe")
local ffi = require("ffi")
local resty_sha256 = require("resty.sha256")
local resty_string = require("resty.string")

-- The public port. A composed node dispatches plaintext and TLS that share one
-- port through internal unix sockets, where $server_port is empty; those
-- listeners alone accept PROXY protocol, which carries the public port.
local function public_server_port()
    return ngx.var.proxy_protocol_server_port or ngx.var.server_port
end

ffi.cdef([[
int open(const char *pathname, int flags, ...);
long read(int fd, void *buf, unsigned long count);
int close(int fd);
int statx(int dirfd, const char *pathname, int flags, unsigned int mask, void *statxbuf);
struct cdnca_statx_timestamp {
    long long tv_sec;
    unsigned int tv_nsec;
    int reserved;
};
struct cdnca_statx {
    unsigned int stx_mask;
    unsigned int stx_blksize;
    unsigned long long stx_attributes;
    unsigned int stx_nlink;
    unsigned int stx_uid;
    unsigned int stx_gid;
    unsigned short stx_mode;
    unsigned short spare0;
    unsigned long long stx_ino;
    unsigned long long stx_size;
    unsigned long long stx_blocks;
    unsigned long long stx_attributes_mask;
    struct cdnca_statx_timestamp stx_atime;
    struct cdnca_statx_timestamp stx_btime;
    struct cdnca_statx_timestamp stx_ctime;
    struct cdnca_statx_timestamp stx_mtime;
    unsigned int stx_rdev_major;
    unsigned int stx_rdev_minor;
    unsigned int stx_dev_major;
    unsigned int stx_dev_minor;
    unsigned long long spare2[14];
};
]])

local _M = {}

local SCHEMA_VERSION = "cdnca.edge.urlauth/v1"
local ALGORITHM = "hmac-sha256"
local MAX_POLICY_BYTES = 1024 * 1024
local MAX_POLICY_VERSION = 9007199254740991
local MAX_IDENTIFIER_BYTES = 128
local MAX_PARAMETER_BYTES = 64
local MAX_EXCLUDED_PARAMETERS = 32
local MAX_PROXY_CIDRS = 64
local MAX_KEY_ID_BYTES = 64
local MAX_KEY_FILE_BYTES = 4096
local MIN_KEY_BYTES = 32
local MAX_KEY_BYTES = 128
local MAX_CLOCK_SKEW_SECONDS = 300
local MAX_VALIDITY_SECONDS = 86400
local MAX_SIGNATURE_USES = 1000000
local MAX_URI_BYTES = 4096
local MAX_PATH_BYTES = 2048
local MAX_QUERY_BYTES = 2048
local MAX_QUERY_PARAMETERS = 64
local MAX_QUERY_VALUE_BYTES = 1024
local MAX_XFF_BYTES = 2048
local MAX_XFF_HOPS = 32
local DUMMY_KEY = string.rep("\0", 32)
local O_RDONLY = 0
local O_CLOEXEC = 0x80000
local O_NOFOLLOW = 0x20000
local AT_EMPTY_PATH = 0x1000
local AT_SYMLINK_NOFOLLOW = 0x100
local STATX_BASIC_STATS = 0x7ff
local MODE_TYPE_MASK = 0xf000
local MODE_REGULAR = 0x8000
local MODE_PERMISSIONS = 0x1ff

local state_dict_name
local reload_interval = 1
local binding_specs
local binding_states = {}
local legacy_state

local function integer(value, minimum, maximum)
    return type(value) == "number" and value == math.floor(value) and value >= minimum and value <= maximum
end

local function identifier(value, maximum)
    return type(value) == "string" and #value >= 1 and #value <= maximum
        and value:match("^[A-Za-z0-9._:-]+$") ~= nil
end

local function parameter_name(value)
    return type(value) == "string" and #value >= 1 and #value <= MAX_PARAMETER_BYTES
        and value:match("^[A-Za-z0-9_.~-]+$") ~= nil
end

local function has_only(value, allowed)
    if type(value) ~= "table" then
        return false
    end
    for key in pairs(value) do
        if not allowed[key] then
            return false
        end
    end
    return true
end

local function array_length(value, maximum)
    if type(value) ~= "table" then
        return nil
    end
    local length = #value
    if length > maximum then
        return nil
    end
    for key in pairs(value) do
        if type(key) ~= "number" or key < 1 or key > length or key ~= math.floor(key) then
            return nil
        end
    end
    return length
end

local function contains_control(value)
    return type(value) ~= "string" or value:find("[%z\1-\31\127]") ~= nil
end

local cidr_fields = { family = true, network = true, prefix_length = true }

local function validate_cidr(cidr)
    if not has_only(cidr, cidr_fields) or (cidr.family ~= 4 and cidr.family ~= 6) then
        return false
    end
    local byte_count = cidr.family == 4 and 4 or 16
    if array_length(cidr.network, byte_count) ~= byte_count then
        return false
    end
    for _, value in ipairs(cidr.network) do
        if not integer(value, 0, 255) then
            return false
        end
    end
	if not integer(cidr.prefix_length, 0, cidr.family == 4 and 32 or 128) then
		return false
	end
	local full_bytes = math.floor(cidr.prefix_length / 8)
	local remaining = cidr.prefix_length % 8
	if remaining > 0 and bit.band(cidr.network[full_bytes + 1], bit.lshift(1, 8 - remaining) - 1) ~= 0 then
		return false
	end
	local first_host_byte = full_bytes + (remaining > 0 and 2 or 1)
	for index = first_host_byte, #cidr.network do
		if cidr.network[index] ~= 0 then
			return false
		end
	end
	return true
end

local function cidr_sort_key(cidr)
    return cidr.family .. "/" .. string.format("%03d", cidr.prefix_length) .. "/"
        .. table.concat(cidr.network, ".")
end

local function validate_cidrs(value)
    local length = array_length(value, MAX_PROXY_CIDRS)
    if not length then
        return false
    end
	local seen = {}
    for index = 1, length do
        if not validate_cidr(value[index]) then
            return false
        end
        local key = cidr_sort_key(value[index])
		if seen[key] then
            return false
        end
		seen[key] = true
    end
    return true
end

local key_fields = { key_id = true, key_file = true, key_sha256 = true }

local function validate_key(value)
    if not has_only(value, key_fields) or not identifier(value.key_id, MAX_KEY_ID_BYTES)
        or type(value.key_file) ~= "string" or #value.key_file < 2 or #value.key_file > MAX_KEY_FILE_BYTES
        or value.key_file:sub(1, 1) ~= "/" or contains_control(value.key_file)
		or value.key_file:find("//", 1, true) or value.key_file:find("/%.%.?/")
        or type(value.key_sha256) ~= "string" or #value.key_sha256 ~= 64
        or value.key_sha256:match("^[0-9a-f]+$") == nil then
        return false
    end
	for segment in value.key_file:gmatch("[^/]+") do
		if segment == "." or segment == ".." then
			return false
		end
	end
    return true
end

local policy_fields = {
    schema_version = true, policy_version = true, tenant_id = true, site_id = true, algorithm = true,
    signature_parameter = true, expiration_parameter = true, key_id_parameter = true,
    bind_client_ip = true, max_clock_skew_seconds = true, max_validity_seconds = true,
    max_signature_uses = true, excluded_query_parameters = true, trusted_proxies = true,
    current_key = true, previous_key = true,
}

local function validate_policy(value)
    if not has_only(value, policy_fields) or value.schema_version ~= SCHEMA_VERSION
        or not integer(value.policy_version, 1, MAX_POLICY_VERSION)
        or not identifier(value.tenant_id, MAX_IDENTIFIER_BYTES) or not identifier(value.site_id, MAX_IDENTIFIER_BYTES)
        or value.algorithm ~= ALGORITHM or type(value.bind_client_ip) ~= "boolean"
        or not integer(value.max_clock_skew_seconds, 0, MAX_CLOCK_SKEW_SECONDS)
        or not integer(value.max_validity_seconds, 1, MAX_VALIDITY_SECONDS)
        or not integer(value.max_signature_uses, 0, MAX_SIGNATURE_USES)
        or not validate_cidrs(value.trusted_proxies) or not validate_key(value.current_key) then
        return nil, "invalid_envelope"
    end
    local names = {}
    for _, name in ipairs({ value.signature_parameter, value.expiration_parameter, value.key_id_parameter }) do
        if not parameter_name(name) or names[name] then
            return nil, "invalid_auth_parameters"
        end
        names[name] = true
    end
    local excluded_length = array_length(value.excluded_query_parameters, MAX_EXCLUDED_PARAMETERS)
    if not excluded_length then
        return nil, "invalid_exclusions"
    end
    local previous_name
    for index = 1, excluded_length do
        local name = value.excluded_query_parameters[index]
        if not parameter_name(name) or names[name] or (previous_name and name <= previous_name) then
            return nil, "invalid_exclusions"
        end
        names[name] = true
        previous_name = name
    end
    if value.previous_key ~= nil then
        if not validate_key(value.previous_key) or value.previous_key.key_id == value.current_key.key_id
            or value.previous_key.key_file == value.current_key.key_file
            or value.previous_key.key_sha256 == value.current_key.key_sha256 then
            return nil, "invalid_rotation"
        end
    end
    return value
end

local function sha256_binary(value)
    local digest = resty_sha256:new()
    if not digest then
        return nil
    end
    local ok = digest:update(value)
    if not ok then
        return nil
    end
    return digest:final()
end

local function sha256_hex(value)
    local digest = sha256_binary(value)
    return digest and resty_string.to_hex(digest) or nil
end

local function constant_time_equal(left, right)
    left = type(left) == "string" and left or ""
    right = type(right) == "string" and right or ""
    local difference = bit.bxor(#left, #right)
	for index = 1, 64 do
        difference = bit.bor(difference, bit.bxor(left:byte(index) or 0, right:byte(index) or 0))
    end
    return difference == 0
end

local function fd_stat(fd)
    local info = ffi.new("struct cdnca_statx[1]")
    if ffi.C.statx(fd, "", bit.bor(AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW), STATX_BASIC_STATS, info) ~= 0 then
        return nil
    end
    return info[0]
end

local function secure_read_key(path)
    local fd = ffi.C.open(path, bit.bor(O_RDONLY, O_CLOEXEC, O_NOFOLLOW))
    if fd < 0 then
        return nil, "key_open_failed"
    end
    local info = fd_stat(fd)
    if not info or bit.band(tonumber(info.stx_mode), MODE_TYPE_MASK) ~= MODE_REGULAR
        or bit.band(tonumber(info.stx_mode), MODE_PERMISSIONS) ~= 384 or tonumber(info.stx_nlink) ~= 1
        or tonumber(info.stx_size) < MIN_KEY_BYTES or tonumber(info.stx_size) > MAX_KEY_BYTES then
        ffi.C.close(fd)
        return nil, "key_metadata_invalid"
    end
    local buffer = ffi.new("unsigned char[?]", MAX_KEY_BYTES + 1)
	local chunks = {}
	local length = 0
	while length <= MAX_KEY_BYTES do
		local read_length = ffi.C.read(fd, buffer, MAX_KEY_BYTES + 1 - length)
		if read_length < 0 then
			ffi.C.close(fd)
			return nil, "key_read_failed"
		end
		if read_length == 0 then
			break
		end
		chunks[#chunks + 1] = ffi.string(buffer, read_length)
		length = length + read_length
	end
    ffi.C.close(fd)
    if length < MIN_KEY_BYTES or length > MAX_KEY_BYTES or length ~= tonumber(info.stx_size) then
        return nil, "key_read_failed"
    end
	return table.concat(chunks)
end

local function read_key(key)
    local secret, read_error = secure_read_key(key.key_file)
    if not secret then
        return nil, read_error
    end
    local digest = sha256_hex(secret)
    if not digest or not constant_time_equal(digest, key.key_sha256) then
        return nil, "key_digest_mismatch"
    end
    return secret
end

local function read_candidate(state)
    local file = io.open(state.policy_path, "rb")
    if not file then
        return nil, "policy_open_failed"
    end
    local raw = file:read(MAX_POLICY_BYTES + 1)
    file:close()
    if not raw or #raw == 0 or #raw > MAX_POLICY_BYTES then
        return nil, "policy_size_invalid"
    end
    local raw_digest = sha256_hex(raw)
    local decoded = cjson.decode(raw)
    if not decoded then
        return nil, "policy_decode_failed", raw_digest
    end
    local candidate, validation_error = validate_policy(decoded)
    if not candidate then
        return nil, validation_error, raw_digest
    end
    if state.tenant_id and (candidate.tenant_id ~= state.tenant_id or candidate.site_id ~= state.site_id) then
        return nil, "policy_binding_mismatch", raw_digest
    end
    local current_secret, current_error = read_key(candidate.current_key)
    if not current_secret then
        return nil, current_error, raw_digest
    end
    candidate.current_key.secret = current_secret
    candidate.key_by_id = { [candidate.current_key.key_id] = candidate.current_key }
    if candidate.previous_key then
        local previous_secret, previous_error = read_key(candidate.previous_key)
        if not previous_secret then
            return nil, previous_error, raw_digest
        end
        candidate.previous_key.secret = previous_secret
        candidate.key_by_id[candidate.previous_key.key_id] = candidate.previous_key
    end
    return candidate, nil, raw_digest
end

local function mark_rejected(state, code, digest)
    local rejection = code .. ":" .. (digest or "unavailable")
    if state.current_policy and state.last_rejection ~= rejection then
        state.policy_event = "policy_rejected"
        local dict = ngx.shared[state_dict_name]
        if dict then
            dict:incr("urlauth:m:reload_rejected", 1, 0)
        end
    end
    state.last_rejection = rejection
end

local function reload(state, force)
    local now = ngx.now()
    if not force and now < state.next_reload_at then
        return true
    end
    state.next_reload_at = now + reload_interval
    local candidate, candidate_error, candidate_digest = read_candidate(state)
    if not candidate then
        mark_rejected(state, candidate_error, candidate_digest)
        return false, candidate_error
    end
    if state.current_policy and candidate.policy_version < state.current_policy.policy_version then
        mark_rejected(state, "policy_version_regressed", candidate_digest)
        return false, "policy_version_regressed"
    end
    if state.current_policy and candidate.policy_version == state.current_policy.policy_version and candidate_digest ~= state.current_digest then
        mark_rejected(state, "same_version_changed", candidate_digest)
        return false, "same_version_changed"
    end
    if not state.current_policy or candidate.policy_version > state.current_policy.policy_version then
        state.current_policy = candidate
        state.current_digest = candidate_digest
    end
    state.last_rejection = nil
    return true
end

local function parse_ipv4(value)
    if type(value) ~= "string" or #value == 0 or #value > 15 then
        return nil
    end
    local bytes = {}
    for part in (value .. "."):gmatch("(.-)%.") do
        if part == "" or part:find("[^0-9]") or (#part > 1 and part:sub(1, 1) == "0") then
            return nil
        end
        local byte = tonumber(part)
        if not byte or byte > 255 then
            return nil
        end
        bytes[#bytes + 1] = byte
    end
    if #bytes ~= 4 then
        return nil
    end
    return { family = 4, bytes = bytes, display = value, canonical = "4:" .. value }
end

local function ipv6_side(value)
    local words = {}
    if value == "" then
        return words
    end
    if value:sub(1, 1) == ":" or value:sub(-1) == ":" or value:find("::", 1, true) then
        return nil
    end
    for part in value:gmatch("[^:]+") do
        if #part > 4 or not part:match("^[0-9A-Fa-f]+$") then
            return nil
        end
        words[#words + 1] = tonumber(part, 16)
    end
    return words
end

local function parse_ipv6(value)
    if type(value) ~= "string" or #value < 2 or #value > 45 or value:find("[%%%.]") then
        return nil
    end
    local marker = value:find("::", 1, true)
    if marker and value:find("::", marker + 2, true) then
        return nil
    end
    local left = ipv6_side(marker and value:sub(1, marker - 1) or value)
    local right = ipv6_side(marker and value:sub(marker + 2) or "")
    if not left or not right then
        return nil
    end
    local missing = 8 - #left - #right
    if (marker and missing < 1) or (not marker and missing ~= 0) then
        return nil
    end
    local words = {}
    for _, word in ipairs(left) do words[#words + 1] = word end
    for _ = 1, missing do words[#words + 1] = 0 end
    for _, word in ipairs(right) do words[#words + 1] = word end
    if #words ~= 8 then
        return nil
    end
    local bytes = {}
    local hexadecimal = {}
    for _, word in ipairs(words) do
        local high = math.floor(word / 256)
        local low = word % 256
        bytes[#bytes + 1] = high
        bytes[#bytes + 1] = low
        hexadecimal[#hexadecimal + 1] = string.format("%02x%02x", high, low)
    end
    return { family = 6, bytes = bytes, display = string.lower(value), canonical = "6:" .. table.concat(hexadecimal) }
end

local function parse_ip(value)
    if type(value) ~= "string" or #value > 64 or value:find("[%c%s]") then
        return nil
    end
    return value:find(":", 1, true) and parse_ipv6(value) or parse_ipv4(value)
end

local function cidr_contains(cidr, address)
    if cidr.family ~= address.family then
        return false
    end
    local full_bytes = math.floor(cidr.prefix_length / 8)
    for index = 1, full_bytes do
        if cidr.network[index] ~= address.bytes[index] then
            return false
        end
    end
    local remaining = cidr.prefix_length % 8
    if remaining == 0 then
        return true
    end
    local mask = bit.band(bit.lshift(255, 8 - remaining), 255)
    return bit.band(cidr.network[full_bytes + 1], mask) == bit.band(address.bytes[full_bytes + 1], mask)
end

local function in_cidrs(address, cidrs)
    for _, cidr in ipairs(cidrs) do
        if cidr_contains(cidr, address) then
            return true
        end
    end
    return false
end

local function client_address(policy)
    local peer = parse_ip(ngx.var.remote_addr)
    if not peer then
        return nil, "peer_invalid"
    end
    local forwarded = ngx.var.http_x_forwarded_for
    if not forwarded or not in_cidrs(peer, policy.trusted_proxies) then
        return peer
    end
    if #forwarded == 0 or #forwarded > MAX_XFF_BYTES or contains_control(forwarded) then
        return nil, "forwarded_invalid"
    end
    local chain = {}
    for part in (forwarded .. ","):gmatch("(.-),") do
        part = part:match("^[ \t]*(.-)[ \t]*$")
        local address = parse_ip(part)
        if not address or #chain >= MAX_XFF_HOPS then
            return nil, "forwarded_invalid"
        end
        chain[#chain + 1] = address
    end
    if #chain == 0 then
        return nil, "forwarded_empty"
    end
    chain[#chain + 1] = peer
    for index = #chain - 1, 1, -1 do
        if not in_cidrs(chain[index], policy.trusted_proxies) then
            return chain[index]
        end
    end
    return chain[1]
end

local function percent_decode(value)
    local output = {}
    local index = 1
    while index <= #value do
        local character = value:sub(index, index)
        if character == "+" then
            output[#output + 1] = " "
            index = index + 1
        elseif character == "%" then
            local encoded = value:sub(index + 1, index + 2)
            if #encoded ~= 2 or not encoded:match("^[0-9A-Fa-f][0-9A-Fa-f]$") then
                return nil
            end
            output[#output + 1] = string.char(tonumber(encoded, 16))
            index = index + 3
        else
            output[#output + 1] = character
            index = index + 1
        end
    end
    return table.concat(output)
end

local function percent_encode(value)
    local output = {}
    for index = 1, #value do
        local character = value:byte(index)
        if (character >= 65 and character <= 90) or (character >= 97 and character <= 122)
            or (character >= 48 and character <= 57) or character == 45 or character == 46
            or character == 95 or character == 126 then
            output[#output + 1] = string.char(character)
        else
            output[#output + 1] = string.format("%%%02X", character)
        end
    end
    return table.concat(output)
end

local function parse_query(raw)
    if type(raw) ~= "string" or #raw == 0 or #raw > MAX_QUERY_BYTES then
        return nil, "query_size_invalid"
    end
    local pairs = {}
    local values = {}
    for part in (raw .. "&"):gmatch("(.-)&") do
        if part == "" or #pairs >= MAX_QUERY_PARAMETERS then
            return nil, "query_structure_invalid"
        end
        local equals = part:find("=", 1, true)
        local raw_name = equals and part:sub(1, equals - 1) or part
        local raw_value = equals and part:sub(equals + 1) or ""
        local name = percent_decode(raw_name)
        local value = percent_decode(raw_value)
        if not parameter_name(name) or not value or #value > MAX_QUERY_VALUE_BYTES or contains_control(value)
            or values[name] ~= nil then
            return nil, "query_parameter_invalid"
        end
        local pair = { name = name, value = value }
        pairs[#pairs + 1] = pair
        values[name] = value
    end
    return pairs, nil, values
end

local function validate_path(path)
    if type(path) ~= "string" or #path == 0 or #path > MAX_PATH_BYTES or path:sub(1, 1) ~= "/"
        or contains_control(path) or path:find("[^\1-\127]") or path:find("[\\%%?#]")
        or path:find("//", 1, true) then
        return false
    end
    for segment in path:gmatch("[^/]+") do
        if segment == "." or segment == ".." then
            return false
        end
    end
    return true
end

local function request_parts()
    local request_uri = ngx.var.request_uri
    if type(request_uri) ~= "string" or #request_uri == 0 or #request_uri > MAX_URI_BYTES or contains_control(request_uri) then
        return nil, "uri_invalid"
    end
    local question = request_uri:find("?", 1, true)
    local path = question and request_uri:sub(1, question - 1) or request_uri
    local query = question and request_uri:sub(question + 1) or nil
    if not validate_path(path) or path ~= ngx.var.uri then
        return nil, "path_ambiguous"
    end
    local pairs, query_error, values = parse_query(query)
    if not pairs then
        return nil, query_error
    end
    return { path = path, pairs = pairs, values = values }
end

local function encode_pairs(pairs)
    local output = {}
    for _, pair in ipairs(pairs) do
        output[#output + 1] = percent_encode(pair.name) .. "=" .. percent_encode(pair.value)
    end
    return table.concat(output, "&")
end

local function canonical_request(policy, request, method, expiration, key_id, client_ip)
    local excluded = {
        [policy.signature_parameter] = true,
        [policy.expiration_parameter] = true,
        [policy.key_id_parameter] = true,
    }
    for _, name in ipairs(policy.excluded_query_parameters) do
        excluded[name] = true
    end
    local pairs = {}
    for _, pair in ipairs(request.pairs) do
        if not excluded[pair.name] then
            pairs[#pairs + 1] = pair
        end
    end
    table.sort(pairs, function(left, right)
        return left.name < right.name or (left.name == right.name and left.value < right.value)
    end)
    return "CDNCA-URL-AUTH/1\n"
        .. "tenant_id=" .. percent_encode(policy.tenant_id) .. "\n"
        .. "site_id=" .. percent_encode(policy.site_id) .. "\n"
        .. "method=" .. method .. "\n"
        .. "path=" .. percent_encode(request.path) .. "\n"
        .. "query=" .. encode_pairs(pairs) .. "\n"
        .. "expires=" .. expiration .. "\n"
        .. "key_id=" .. percent_encode(key_id) .. "\n"
        .. "client_ip=" .. percent_encode(client_ip) .. "\n"
end

local function hmac_sha256_hex(secret, message)
    if #secret > 64 then
        secret = sha256_binary(secret)
    end
    if not secret then
        return nil
    end
    secret = secret .. string.rep("\0", 64 - #secret)
    local inner_pad = {}
    local outer_pad = {}
    for index = 1, 64 do
        local character = secret:byte(index)
        inner_pad[index] = string.char(bit.bxor(character, 0x36))
        outer_pad[index] = string.char(bit.bxor(character, 0x5c))
    end
    local inner = sha256_binary(table.concat(inner_pad) .. message)
    if not inner then
        return nil
    end
    return sha256_hex(table.concat(outer_pad) .. inner)
end

local function valid_traceparent(value)
    if type(value) ~= "string" or #value ~= 55 then
        return ""
    end
    local version, trace_id, parent_id, flags = value:match(
        "^([0-9a-f][0-9a-f])%-([0-9a-f]+)%-([0-9a-f]+)%-([0-9a-f][0-9a-f])$")
    if not version or #trace_id ~= 32 or #parent_id ~= 16 or version ~= "00"
        or trace_id == string.rep("0", 32) or parent_id == string.rep("0", 16) or not flags then
        return ""
    end
    return value
end

local function set_variable(name, value)
    pcall(function()
        ngx.var[name] = value
    end)
end

local metric_reasons = {
    signature_valid = true, context_unavailable = true, listen_port_mismatch = true,
    client_address_invalid = true, auth_parameters_invalid = true, time_window_invalid = true,
    method_invalid = true, signature_invalid = true, replay_state_unavailable = true,
    signature_use_limit = true, request_uri_invalid = true, path_invalid = true,
    query_invalid = true,
}

local function emit(state, action, reason, status, policy_version)
    local policy_event = ""
    if state then
        policy_event = state.policy_event or ""
        state.policy_event = nil
    end
    set_variable("cdnca_urlauth_trace_id", valid_traceparent(ngx.var.http_traceparent))
    set_variable("cdnca_urlauth_action", action)
    set_variable("cdnca_urlauth_reason", reason)
    set_variable("cdnca_urlauth_status", tostring(status))
    set_variable("cdnca_urlauth_policy_version", tostring(policy_version or 0))
    set_variable("cdnca_urlauth_policy_event", policy_event)
    set_variable("cdnca_urlauth_emit", "1")
    local dict = ngx.shared[state_dict_name]
    if dict then
        local category = action == "allow" and "allow" or action == "block" and "block" or "error"
        dict:incr("urlauth:m:" .. category, 1, 0)
        local stable_reason = metric_reasons[reason] and reason or "other"
        dict:incr("urlauth:m:reason:" .. stable_reason, 1, 0)
    end
end

local function reject(state, status, code, policy_version)
    emit(state, status == ngx.HTTP_SERVICE_UNAVAILABLE and "error" or "block", code, status, policy_version)
    ngx.ctx.cdnca_url_auth_reject_code = code
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "text/plain; charset=utf-8"
    ngx.status = status
    ngx.say(status == ngx.HTTP_FORBIDDEN and "Forbidden" or "Service Unavailable")
    return ngx.exit(status)
end

local function consume_signature(policy, key_id, signature, expiration, now)
    if policy.max_signature_uses == 0 then
        return true
    end
    local dict = ngx.shared[state_dict_name]
    local digest = sha256_hex(key_id .. ":" .. signature)
    if not digest then
        return nil
    end
    local key = "urlauth:t:" .. policy.tenant_id .. ":s:" .. policy.site_id
        .. ":sig:" .. digest
    local ttl = math.max(1, expiration + policy.max_clock_skew_seconds - now + 1)
    local count, increment_error, forcible = dict:incr(key, 1, 0, ttl)
    if not count or increment_error or forcible then
        return nil
    end
    return count <= policy.max_signature_uses
end

local function valid_policy_path(path)
    return type(path) == "string" and #path >= 2 and #path <= 4096 and path:sub(1, 1) == "/"
        and not contains_control(path) and not path:find("//", 1, true) and not path:find("/%.%.?/")
        and path:sub(-2) ~= "/." and path:sub(-3) ~= "/.."
end

local function binding_key(tenant_id, site_id, listen_port)
	return tenant_id .. "\0" .. site_id .. "\0" .. listen_port
end

local function new_state(binding)
    return {
		tenant_id = binding.tenant_id,
		site_id = binding.site_id,
		listen_port = binding.listen_port,
		policy_path = binding.policy_path,
        next_reload_at = 0,
    }
end

function _M.init(options)
    if type(options) ~= "table" or type(options.state_dict) ~= "string" or not ngx.shared[options.state_dict] then
        error("invalid URL auth engine options")
    end
    if options.reload_interval ~= nil and (type(options.reload_interval) ~= "number"
        or options.reload_interval < 0.05 or options.reload_interval > 60) then
        error("invalid URL auth reload interval")
    end
    state_dict_name = options.state_dict
    reload_interval = options.reload_interval or 1
    if options.bindings ~= nil then
        local count = array_length(options.bindings, 1000)
        if not count or count == 0 or options.policy_path ~= nil then
            error("invalid URL auth bindings")
        end
        local seen, paths = {}, {}
        local specs = {}
		for index = 1, count do
			local binding = options.bindings[index]
			if type(binding) ~= "table" or not identifier(binding.tenant_id, MAX_IDENTIFIER_BYTES)
				or not identifier(binding.site_id, MAX_IDENTIFIER_BYTES)
				or not integer(binding.listen_port, 1, 65535) or not valid_policy_path(binding.policy_path) then
				error("invalid URL auth binding")
			end
			local key = binding_key(binding.tenant_id, binding.site_id, binding.listen_port)
			local identity = binding.tenant_id .. "\0" .. binding.site_id
			if seen[key] or paths[binding.policy_path] and paths[binding.policy_path] ~= identity then
				error("conflicting URL auth binding")
			end
			seen[key] = true
			paths[binding.policy_path] = identity
			specs[index] = {
				tenant_id = binding.tenant_id,
				site_id = binding.site_id,
				listen_port = binding.listen_port,
				policy_path = binding.policy_path,
            }
        end
        binding_specs = specs
        binding_states = {}
        legacy_state = nil
        return 0
    end
    if not valid_policy_path(options.policy_path) then
        error("invalid URL auth engine options")
    end
    binding_specs = nil
    binding_states = {}
    legacy_state = new_state({ policy_path = options.policy_path })
    local ok, load_error = reload(legacy_state, true)
    if not ok or not legacy_state.current_policy then
        error("no valid URL auth policy code=" .. tostring(load_error))
    end
    return legacy_state.current_policy.policy_version
end

function _M.init_worker()
    if not binding_specs then
        return legacy_state and legacy_state.current_policy and legacy_state.current_policy.policy_version or 0
    end
    local states = {}
    for _, binding in ipairs(binding_specs) do
        local state = new_state(binding)
        local ok, load_error = reload(state, true)
        if not ok or not state.current_policy then
            error("no valid URL auth policy code=" .. tostring(load_error))
        end
		states[binding_key(binding.tenant_id, binding.site_id, binding.listen_port)] = state
    end
    binding_states = states
    return true
end

local function default_state()
    if legacy_state then
        return legacy_state
    end
    local found
    for _, state in pairs(binding_states) do
        if found then
            return nil
        end
        found = state
    end
    return found
end

function _M.policy_version()
    local state = default_state()
    if not state then
        return 0
    end
    reload(state, false)
    return state.current_policy and state.current_policy.policy_version or 0
end

function _M.resolve_client_ip()
    local state = default_state()
    if not state then
        return nil
    end
    reload(state, false)
    if not state.current_policy then
        return nil
    end
    local address = client_address(state.current_policy)
    return address and address.display or nil
end

function _M.metrics()
    local dict = ngx.shared[state_dict_name]
    if not dict then
        return { allow = 0, block = 0, error = 0, reload_rejected = 0 }
    end
    local result = {
        allow = dict:get("urlauth:m:allow") or 0,
        block = dict:get("urlauth:m:block") or 0,
        error = dict:get("urlauth:m:error") or 0,
        reload_rejected = dict:get("urlauth:m:reload_rejected") or 0,
    }
    result.reasons = {}
    for reason in pairs(metric_reasons) do
        result.reasons[reason] = dict:get("urlauth:m:reason:" .. reason) or 0
    end
    result.reasons.other = dict:get("urlauth:m:reason:other") or 0
    return result
end

function _M.access(context)
	local state = legacy_state
	if not state and type(context) == "table" and type(context.tenant_id) == "string"
		and type(context.site_id) == "string" and integer(context.listen_port, 1, 65535) then
		state = binding_states[binding_key(context.tenant_id, context.site_id, context.listen_port)]
    end
    if not state then
        return reject(nil, ngx.HTTP_SERVICE_UNAVAILABLE, "context_unavailable", 0)
    end
    reload(state, false)
    local policy = state.current_policy
	if not policy or type(context) ~= "table" or context.tenant_id ~= policy.tenant_id or context.site_id ~= policy.site_id then
		return reject(state, ngx.HTTP_SERVICE_UNAVAILABLE, "context_unavailable", policy and policy.policy_version or 0)
	end
	if state.listen_port and public_server_port() ~= tostring(state.listen_port) then
		return reject(state, ngx.HTTP_FORBIDDEN, "listen_port_mismatch", policy.policy_version)
	end
    local address = client_address(policy)
    if not address then
        return reject(state, ngx.HTTP_FORBIDDEN, "client_address_invalid", policy.policy_version)
    end
    local request, request_error = request_parts()
    if not request then
        return reject(state, ngx.HTTP_FORBIDDEN, request_error, policy.policy_version)
    end
    local signature = request.values[policy.signature_parameter]
    local expiration_text = request.values[policy.expiration_parameter]
    local key_id = request.values[policy.key_id_parameter]
    if not signature or not expiration_text or not key_id or #expiration_text > 16
        or expiration_text:match("^[1-9][0-9]*$") == nil or not identifier(key_id, MAX_KEY_ID_BYTES) then
        return reject(state, ngx.HTTP_FORBIDDEN, "auth_parameters_invalid", policy.policy_version)
    end
    local expiration = tonumber(expiration_text)
    local now = ngx.time()
    if not integer(expiration, 1, MAX_POLICY_VERSION) or now > expiration + policy.max_clock_skew_seconds
        or expiration > now + policy.max_validity_seconds + policy.max_clock_skew_seconds then
        return reject(state, ngx.HTTP_FORBIDDEN, "time_window_invalid", policy.policy_version)
    end
    local method = ngx.req.get_method()
    if type(method) ~= "string" or method ~= string.upper(method) or #method == 0 or #method > 32
        or method:find("[^!#$&'*+.%^_`|~A-Z0-9-]") then
        return reject(state, ngx.HTTP_FORBIDDEN, "method_invalid", policy.policy_version)
    end
    local key = policy.key_by_id[key_id]
    local known_key = key ~= nil
    local secret = known_key and key.secret or DUMMY_KEY
    local canonical_ip = policy.bind_client_ip and address.canonical or ""
    local canonical = canonical_request(policy, request, method, expiration_text, key_id, canonical_ip)
    local expected = hmac_sha256_hex(secret, canonical)
    local signature_format = #signature == 64 and signature:match("^[0-9a-f]+$") ~= nil
	local signature_matches = constant_time_equal(signature, expected or string.rep("0", 64))
    if not expected or not known_key or not signature_format or not signature_matches then
        return reject(state, ngx.HTTP_FORBIDDEN, "signature_invalid", policy.policy_version)
    end
    local use_allowed = consume_signature(policy, key_id, signature, expiration, now)
    if use_allowed == nil then
        return reject(state, ngx.HTTP_SERVICE_UNAVAILABLE, "replay_state_unavailable", policy.policy_version)
    end
    if not use_allowed then
        return reject(state, ngx.HTTP_FORBIDDEN, "signature_use_limit", policy.policy_version)
    end
    ngx.ctx.cdnca_url_auth_client_ip = address.display
    ngx.ctx.cdnca_url_auth_policy_version = policy.policy_version
    emit(state, "allow", "signature_valid", 0, policy.policy_version)
end

return _M
