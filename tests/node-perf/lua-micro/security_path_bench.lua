-- cdnca_telemetry.security_path 每请求微基准（log 阶段对每个请求都跑）。
-- 用法（节点运行时镜像里）：
--   resty -I <lua根>/dynroute -I <lua根> security_path_bench.lua [迭代次数]
-- 输出每种查询串形态的 ns/次；改前改后各跑一次对比。
package.loaded["cdnca_site"] = {}
local telemetry = require "cdnca_telemetry"

local N = tonumber(os.getenv("NP_ITERS")) or 1000000
local cases = {
    { "无查询串", "/index.html", nil },
    { "空查询串", "/index.html", "" },
    { "2个常见参数", "/search", "q=hello&page=2" },
    { "6个常见参数(utm)", "/landing", "utm_source=google&utm_medium=cpc&utm_campaign=spring&id=12345&lang=zh&ref=home" },
    { "含敏感参数", "/login", "user=bob&token=abcdef&next=%2Fhome" },
    { "含非ASCII", "/s", "q=%E4%BD%A0%E5%A5%BD&x=1" },
}

local clock = os.clock
for _, c in ipairs(cases) do
    local name, uri, query = c[1], c[2], c[3]
    local result
    for _ = 1, 20000 do result = telemetry.security_path(uri, query) end -- 预热
    local t0 = clock()
    for _ = 1, N do result = telemetry.security_path(uri, query) end
    local ns = (clock() - t0) / N * 1e9
    print(string.format("[bench] %-20s %8.0f ns/次  => %s", name, ns, result))
end
