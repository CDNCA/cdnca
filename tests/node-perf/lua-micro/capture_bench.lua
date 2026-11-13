-- capture 站点 log 阶段（cdnca_telemetry.log，内含 run_capture）每请求微基准。
-- 站点 stub：capture 开启、无头/体白名单（最常见的 capture 配置），emit=0（普通请求）。
-- 需要 NP_SERVER_EXTRA 声明 log() 会写的变量（见 capture_bench.sh）。
local site = { telemetry = { capture = { enabled = true } } }
package.loaded["cdnca_site"] = { current = function() return site end }
local telemetry = require "cdnca_telemetry"
local N = tonumber(os.getenv("NP_ITERS")) or 200000
ngx.update_time()
for _ = 1, 20000 do telemetry.log() end
local clock = os.clock
local t0 = clock()
for _ = 1, N do telemetry.log() end
local ns = (clock() - t0) / N * 1e9
print(string.format("[bench] capture log() emit=0 %8.0f ns/次 json=%d bytes", ns, #ngx.var.cdnca_access_telemetry_json))
