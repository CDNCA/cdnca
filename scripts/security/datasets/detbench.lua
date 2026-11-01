-- defense-perf 检测器耗时基准：逐行 "<类>\t<值>" 对每个检测器计时（ngx.now 精度不够，用 os.clock 按批累计），
-- 输出每个检测器的总耗时、每值平均 ns、命中数，以及单值最慢的 5 条（值截 120 字节）。
-- 由 detscan.sh 同样的方式在节点运行时镜像里跑：DETSCAN_FILES / DETSCAN_NAMES；DETBENCH_LIMIT 每文件最多行数（默认 200000）。
local waf = require("cdnca_waf")
local detectors = waf._detect
local clock = os.clock
local names = {}
for name in (os.getenv("DETSCAN_NAMES") or "sqli,xss,ssti,java_deser,php_deser,ssrf,cmd,crlf,redirect,format,nosql,ldap,xxe,proto"):gmatch("[^,]+") do
    names[#names + 1] = name
end
local limit = tonumber(os.getenv("DETBENCH_LIMIT") or "") or 200000
for spec in (os.getenv("DETSCAN_FILES") or ""):gmatch("[^,]+") do
    local kind, path = spec:match("^(%a+):(.+)$")
    local values, bytes = {}, 0
    for line in io.lines(path) do
        local value = line:match("^[^\t]*\t(.*)$")
        if value then
            value = value:gsub("\\r", "\r"):gsub("\\n", "\n")
            values[#values + 1] = value
            bytes = bytes + #value
            if #values >= limit then break end
        end
    end
    local grand = 0
    for _, name in ipairs(names) do
        local detector = detectors[name]
        local hits, slow = 0, {}
        -- warm the JIT and the regex caches
        for i = 1, math.min(#values, 2000) do pcall(detector, values[i]) end
        local started = clock()
        for i = 1, #values do
            local value = values[i]
            local t0 = clock()
            local ok, hit = pcall(detector, value)
            local spent = clock() - t0
            if ok and hit then hits = hits + 1 end
            if #slow < 5 or spent > slow[#slow][1] then
                slow[#slow + 1] = { spent, value }
                table.sort(slow, function(a, b) return a[1] > b[1] end)
                if #slow > 5 then slow[6] = nil end
            end
        end
        local total = clock() - started
        grand = grand + total
        print(string.format("DETBENCH %s %s values=%d bytes=%d total_ms=%.1f avg_ns=%.0f hits=%d",
            kind, name, #values, bytes, total * 1000, total * 1e9 / math.max(#values, 1), hits))
        for _, item in ipairs(slow) do
            print(string.format("DETSLOW %s %s us=%.0f len=%d %s", kind, name, item[1] * 1e6, #item[2],
                (item[2]:sub(1, 120):gsub("[%c]", "."))))
        end
    end
    print(string.format("DETBENCH %s ALL values=%d total_ms=%.1f avg_ns_per_value=%.0f", kind, #values, grand * 1000,
        grand * 1e9 / math.max(#values, 1)))
end
