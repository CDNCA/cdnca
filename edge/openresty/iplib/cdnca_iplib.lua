-- cdnca_iplib: node lookup in the signed IP intelligence library (G3-c).
--
-- The library (docs/architecture/ip-intel-artifact.md, format v2 "CDNIPI01")
-- is mapped read-only with mmap(MAP_SHARED) and searched in place through
-- LuaJIT FFI: the range tables are never expanded into Lua tables. The agent
-- installs it as <deployment_root>/ip-intel/current.ipi and replaces it only
-- by rename, so an existing mapping always sees one complete file.
--
-- Reload: each Lua VM (every http and stream worker) re-reads the 64-byte
-- header of current.ipi at most once per wall-clock second, on the second
-- boundary, and switches when the revision or size changed. Every worker
-- therefore switches within one second of the rename and a request is always
-- answered from one whole table. The old mapping is unmapped right after the
-- switch: lookups are synchronous and copy what they return, nothing keeps a
-- pointer into a mapping across a yield.
--
-- Missing library: lookup returns nil, "not_ready" and match() is false for
-- every condition (negated ones included), so a rule neither blocks by
-- mistake nor silently allows; the state is logged once per change.
--
-- The same module serves the http and the stream subsystem (L4 rules).

local ffi = require("ffi")
local bit = require("bit")

local band, bor, bxor, rshift, lshift, bswap = bit.band, bit.bor, bit.bxor, bit.rshift, bit.lshift, bit.bswap
local byte, sub, find, gmatch, tonumber = string.byte, string.sub, string.find, string.gmatch, tonumber
local floor = math.floor

ffi.cdef [[
int cdnca_iplib_open(const char *path, int flags) __asm__("open");
int cdnca_iplib_close(int fd) __asm__("close");
int64_t cdnca_iplib_lseek(int fd, int64_t offset, int whence) __asm__("lseek");
int64_t cdnca_iplib_pread(int fd, void *buf, size_t count, int64_t offset) __asm__("pread");
void *cdnca_iplib_mmap(void *addr, size_t length, int prot, int flags, int fd, int64_t offset) __asm__("mmap");
int cdnca_iplib_munmap(void *addr, size_t length) __asm__("munmap");
int cdnca_iplib_memcmp(const void *a, const void *b, size_t n) __asm__("memcmp");
]]

local C = ffi.C
local new_table = require("table.new")
local u8p = ffi.typeof("const uint8_t *")
local u32p = ffi.typeof("const uint32_t *")
local header_buf = ffi.new("uint8_t[64]")
local MAP_FAILED = ffi.cast("void *", -1)

-- Linux values, identical on x86_64 and aarch64.
local O_RDONLY, O_CLOEXEC = 0, 0x80000
local PROT_READ, MAP_SHARED = 1, 1
local SEEK_END = 2

local MAGIC = "CDNIPI01"
local FORMAT_VERSION = 2
local HEADER_SIZE = 64
local ATTR_SIZE = 24
local V4_RECORD = 12
local V6_RECORD = 36
local MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
local MAX_RANGES = 4000000
local CACHE_LIMIT = 8192
local MAX_SPEC_VALUES = 64

-- Little-endian fields are read through aligned uint32 loads (every section
-- starts 8-aligned and records are 4-aligned in a page-aligned mapping).
assert(ffi.abi("le"), "cdnca_iplib needs a little-endian host")

local _M = { _VERSION = "1" }

local DEFAULT_PATH = "/var/lib/cdnca-edge/ip-intel/current.ipi"
local path = DEFAULT_PATH
local current -- loaded table, or nil
local next_check = 0
local last_problem -- last logged load problem, logged once per change
local cache, cache_size = new_table(0, 8192), 0
local MISS = false -- cached "address not in the library"
local last_addr, last_attrs
local specs = {}
local searches = 0 -- binary searches since the library was loaded (cache misses)

local function log(level, message)
    if ngx and ngx.log then
        ngx.log(level, "cdnca_iplib: ", message)
    end
end

local function problem(message)
    if message ~= last_problem then
        last_problem = message
        if message then
            log(ngx and ngx.WARN or 4, message)
        end
    end
end

local function le16(p, offset)
    return p[offset] + p[offset + 1] * 256
end

local function le32(p, offset)
    return p[offset] + p[offset + 1] * 256 + p[offset + 2] * 65536 + p[offset + 3] * 16777216
end

local function le64(p, offset)
    return le32(p, offset) + le32(p, offset + 4) * 4294967296
end

local function align8(value)
    return floor((value + 7) / 8) * 8
end

-- parse_header validates the layout the way libs/entitlement/ipintel Open
-- does (sizes, offsets, alignment, reserved bytes) for a file of size bytes.
-- Range ordering and digests were verified by the agent before the rename.
local function parse_header(p, size)
    if size < HEADER_SIZE or size > MAX_ARTIFACT_BYTES or ffi.string(p, 8) ~= MAGIC
        or le16(p, 8) ~= FORMAT_VERSION or le16(p, 10) ~= HEADER_SIZE then
        return nil, "invalid header"
    end
    for offset = 52, 63 do
        if p[offset] ~= 0 then return nil, "invalid header" end
    end
    local attr_count, v4_count, v6_count = le32(p, 12), le32(p, 16), le32(p, 20)
    local attr_off, v4_off, v6_off = le32(p, 32), le32(p, 36), le32(p, 40)
    local meta_off, meta_len = le32(p, 44), le32(p, 48)
    if attr_count == 0 or attr_count > MAX_RANGES or v4_count + v6_count == 0 or v4_count + v6_count > MAX_RANGES
        or attr_off ~= HEADER_SIZE or v4_off ~= attr_off + attr_count * ATTR_SIZE
        or v6_off ~= v4_off + align8(v4_count * V4_RECORD) or meta_off ~= v6_off + align8(v6_count * V6_RECORD)
        or meta_len == 0 or meta_off + meta_len ~= size then
        return nil, "invalid layout"
    end
    return {
        revision = le64(p, 24), size = size, attr_count = attr_count,
        v4_count = v4_count, v6_count = v6_count, attr_off = attr_off, v4_off = v4_off, v6_off = v6_off,
    }
end

-- probe reads current.ipi's header and size without mapping it.
local function probe()
    local fd = C.cdnca_iplib_open(path, bor(O_RDONLY, O_CLOEXEC))
    if fd < 0 then return nil, "library missing" end
    local size = tonumber(C.cdnca_iplib_lseek(fd, 0, SEEK_END))
    local read = tonumber(C.cdnca_iplib_pread(fd, header_buf, HEADER_SIZE, 0))
    C.cdnca_iplib_close(fd)
    if read ~= HEADER_SIZE then return nil, "invalid header" end
    return parse_header(header_buf, size)
end

-- load maps current.ipi and validates the mapping itself (the file may have
-- been replaced again since probe).
local function load()
    local fd = C.cdnca_iplib_open(path, bor(O_RDONLY, O_CLOEXEC))
    if fd < 0 then return nil, "library missing" end
    local size = tonumber(C.cdnca_iplib_lseek(fd, 0, SEEK_END))
    if size < HEADER_SIZE or size > MAX_ARTIFACT_BYTES then
        C.cdnca_iplib_close(fd)
        return nil, "invalid size"
    end
    local base = C.cdnca_iplib_mmap(nil, size, PROT_READ, MAP_SHARED, fd, 0)
    C.cdnca_iplib_close(fd)
    if base == MAP_FAILED or base == nil then return nil, "mmap failed" end
    local p = ffi.cast(u8p, base)
    local table_, err = parse_header(p, size)
    if not table_ then
        C.cdnca_iplib_munmap(base, size)
        return nil, err
    end
    table_.base, table_.p = base, p
    table_.attrs = ffi.cast(u32p, p + table_.attr_off)
    table_.v4, table_.v6 = ffi.cast(u32p, p + table_.v4_off), p + table_.v6_off
    return table_
end

local function clock()
    if ngx and ngx.now then return ngx.now() end
    return os.time()
end

local function switch(table_)
    local old = current
    current = table_
    cache, cache_size, last_addr, last_attrs, searches = new_table(0, CACHE_LIMIT), 0, nil, nil, 0
    if old then C.cdnca_iplib_munmap(old.base, old.size) end
end

local function refresh(now)
    next_check = floor(now) + 1
    local head, err = probe()
    if not head then
        problem(current and (err .. ", keeping revision " .. current.revision) or err)
        return
    end
    if current and head.revision == current.revision and head.size == current.size then
        last_problem = nil
        return
    end
    local table_, load_err = load()
    if not table_ then
        problem("revision " .. head.revision .. ": " .. load_err .. (current and (", keeping revision " .. current.revision) or ""))
        return
    end
    switch(table_)
    last_problem = nil
    log(ngx and ngx.NOTICE or 6, "loaded revision " .. table_.revision .. " (" .. table_.v4_count .. " IPv4 and "
        .. table_.v6_count .. " IPv6 ranges)")
end

local function decode(table_, index)
    local w = table_.attrs + index * 6
    local country = w[3] % 65536
    return {
        tags_lo = w[0], tags_hi = w[1], asn = w[2],
        country = country ~= 0 and string.char(country % 256, rshift(country, 8)) or nil,
        province = w[4], city = w[5],
    }
end

-- Big-endian start / last words become order-preserving signed 32-bit
-- numbers: byte swap, then flip the sign bit.
local function ordered(word)
    return bxor(bswap(word), 0x80000000)
end

-- Last record whose start <= key (docs/architecture/ip-intel-artifact.md §4).
-- key is the address as an ordered() number.
local function search_v4(table_, key)
    local w = table_.v4
    local low, high = 0, table_.v4_count
    while low < high do
        local middle = rshift(low + high, 1)
        if ordered(w[middle * 3]) > key then high = middle else low = middle + 1 end
    end
    if low == 0 then return nil end
    local record = (low - 1) * 3
    if key > ordered(w[record + 1]) then return nil end
    local index = w[record + 2]
    if index >= table_.attr_count then return nil end
    return decode(table_, index)
end

local function search_v6(table_, key)
    local p = table_.v6
    local low, high = 0, table_.v6_count
    while low < high do
        local middle = rshift(low + high, 1)
        if C.cdnca_iplib_memcmp(p + middle * V6_RECORD, key, 16) > 0 then high = middle else low = middle + 1 end
    end
    if low == 0 then return nil end
    local record = p + (low - 1) * V6_RECORD
    if C.cdnca_iplib_memcmp(record + 16, key, 16) < 0 then return nil end
    local index = ffi.cast(u32p, record)[8]
    if index >= table_.attr_count then return nil end
    return decode(table_, index)
end

local function v4_key(addr, first)
    local b1, b2, b3, b4 = byte(addr, first, first + 3)
    return bxor(bor(lshift(b1, 24), lshift(b2, 16), lshift(b3, 8), b4), 0x80000000)
end

local function search(table_, addr)
    local length = #addr
    if length == 4 then
        return search_v4(table_, v4_key(addr, 1))
    end
    if length ~= 16 then return nil end
    local b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12 = byte(addr, 1, 12)
    if b1 == 0 and b2 == 0 and b3 == 0 and b4 == 0 and b5 == 0 and b6 == 0 and b7 == 0 and b8 == 0
        and b9 == 0 and b10 == 0 and b11 == 255 and b12 == 255 then
        -- IPv4-mapped IPv6 (::ffff:a.b.c.d) is looked up in the IPv4 table.
        return search_v4(table_, v4_key(addr, 13))
    end
    return search_v6(table_, addr)
end

-- lookup returns the attributes of addr (4 or 16 byte network order, as
-- ngx.var.binary_remote_addr): a table {tags_lo, tags_hi, asn, country,
-- province, city}, false when the library has no range for addr, or nil,
-- "not_ready" when no library was ever loaded. Results are cached per
-- address (a keepalive / HTTP/2 connection is looked up once).
function _M.lookup(addr)
    local now = clock()
    if now >= next_check then refresh(now) end
    if not current then return nil, "not_ready" end
    if addr == last_addr then return last_attrs end
    local attrs = cache[addr]
    if attrs == nil then
        attrs = search(current, addr) or MISS
        searches = searches + 1
        if cache_size >= CACHE_LIMIT then cache, cache_size = new_table(0, CACHE_LIMIT), 0 end
        cache[addr] = attrs
        cache_size = cache_size + 1
    end
    last_addr, last_attrs = addr, attrs
    return attrs
end

-- lookup_client looks up the connection's client address
-- ($binary_remote_addr, after realip / PROXY protocol), in http and stream.
function _M.lookup_client()
    return _M.lookup(ngx.var.binary_remote_addr)
end

-- Condition specs are rendered by libs/edgeconfig (RenderWAFIPIntelCondition):
--   tag=<16 hex digits>   any of the mask's tag bits is set
--   asn=13335,4134        country=CN,US   province=440000   city=440300
-- "!=" negates. Values are validated and canonical; a spec is compiled once
-- per VM.
local KIND_TAG, KIND_ASN, KIND_COUNTRY, KIND_PROVINCE, KIND_CITY = 1, 2, 3, 4, 5
local KINDS = { tag = KIND_TAG, asn = KIND_ASN, country = KIND_COUNTRY, province = KIND_PROVINCE, city = KIND_CITY }

local function compile(spec)
    if type(spec) ~= "string" or #spec > 1024 then return nil end
    local field, negate, list = spec:match("^(%l+)(!?)=([%w,]+)$")
    local kind = KINDS[field]
    if not kind then return nil end
    local compiled = { kind = kind, negate = negate == "!" }
    if kind == KIND_TAG then
        if not find(list, "^%x+$") or #list ~= 16 then return nil end
        compiled.hi, compiled.lo = tonumber(sub(list, 1, 8), 16), tonumber(sub(list, 9, 16), 16)
        if compiled.hi == 0 and compiled.lo == 0 then return nil end
        return compiled
    end
    local set, count = {}, 0
    for value in gmatch(list, "[^,]+") do
        count = count + 1
        if count > MAX_SPEC_VALUES then return nil end
        if kind == KIND_COUNTRY then
            if not find(value, "^%u%u$") then return nil end
            set[value] = true
        else
            if not find(value, "^[1-9]%d*$") or #value > 10 then return nil end
            local number = tonumber(value)
            if number > 4294967295 or kind ~= KIND_ASN and (#value ~= 6 or kind == KIND_PROVINCE and number % 10000 ~= 0) then
                return nil
            end
            set[number] = true
        end
    end
    if count == 0 then return nil end
    compiled.set = set
    return compiled
end

local function hit(compiled, attrs)
    local kind = compiled.kind
    if kind == KIND_TAG then
        return band(attrs.tags_lo, compiled.lo) ~= 0 or band(attrs.tags_hi, compiled.hi) ~= 0
    elseif kind == KIND_ASN then
        return compiled.set[attrs.asn] == true
    elseif kind == KIND_COUNTRY then
        return attrs.country ~= nil and compiled.set[attrs.country] == true
    elseif kind == KIND_PROVINCE then
        return compiled.set[attrs.province] == true
    end
    return compiled.set[attrs.city] == true
end

-- test evaluates one condition spec against lookup()'s result. Not ready
-- (nil) never matches, negated or not; an address the library does not know
-- (false) has no tags, ASN or region: "=" is false and "!=" is true.
function _M.test(attrs, spec)
    if attrs == nil then return false end
    local compiled = specs[spec]
    if compiled == nil then
        compiled = compile(spec) or false
        specs[spec] = compiled
        if not compiled then log(ngx and ngx.ERR or 3, "invalid condition " .. tostring(spec)) end
    end
    if not compiled then return false end
    if attrs == false then return compiled.negate end
    return hit(compiled, attrs) ~= compiled.negate
end

-- match is test() for the request's / connection's client address. WAF
-- rules render one match() per condition; the lookup itself runs once per
-- address (cache) and never when a site has no such rule.
function _M.match(spec)
    return _M.test(_M.lookup(ngx.var.binary_remote_addr), spec)
end

-- status reports the loaded library (for logs and tests).
function _M.status()
    if not current then return { ready = false, path = path, problem = last_problem } end
    return { ready = true, path = path, revision = current.revision, size = current.size,
        ipv4_ranges = current.v4_count, ipv6_ranges = current.v6_count, searches = searches, problem = last_problem }
end

-- configure points the module at another library file (tests) and forgets
-- the loaded one.
function _M.configure(options)
    path = options and options.path or DEFAULT_PATH
    if current then switch(nil) end
    next_check, last_problem, specs = 0, nil, {}
end

return _M
