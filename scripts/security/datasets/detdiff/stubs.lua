-- 用 ngx 桩加载 cdnca_waf，按 cmd 检测器的各个阶段分别计时
ngx = setmetatable({ shared = {}, var = {}, ctx = {}, re = { find = function() return nil end },
  config = { subsystem = "http" }, worker = { id = function() return 0 end }, null = nil,
  log = function() end, WARN = 0, ERR = 0, INFO = 0, NOTICE = 0, DEBUG = 0, now = os.time, time = os.time,
  decode_base64 = function() return nil end, encode_base64 = function(s) return s end, md5 = function(s) return s end,
  unescape_uri = function(s) return s end, escape_uri = function(s) return s end, crc32_short = function() return 0 end,
  hmac_sha1 = function() return "" end, sha1_bin = function() return "" end }, { __index = function() return function() end end })
package.preload["cjson.safe"] = function() return { decode = function() return nil end, encode = function() return "" end, new = function() return { decode = function() end, encode = function() return "" end } end } end
package.preload["cjson"] = package.preload["cjson.safe"]
local stub = function() return setmetatable({}, { __index = function() return function() end end }) end
for _, m in ipairs({ "resty.lock", "resty.core", "ngx.re", "ngx.ssl", "resty.string", "resty.sha256", "resty.random", "resty.lrucache", "ngx.base64", "ngx.process", "resty.aes", "resty.hmac", "resty.md5" }) do package.preload[m] = stub end
package.path = "/l/?.lua;" .. package.path
