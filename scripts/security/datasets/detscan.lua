-- waf-gap4 离线检测器扫描：逐行 "<类>\t<值>" 跑 cdnca_waf 的检测器，
-- 输出每个检测器在每类上的命中数，并打印正常集命中样例（每检测器 ≤ 20 条）。
-- 在节点运行时镜像里由 detscan.sh 以 init_worker 定时器调用（镜像无 resty 用的 perl）。
-- 环境：DETSCAN_FILES（逗号分隔，"benign:/path" 或 "attack:/path"）、DETSCAN_NAMES（检测器名）
local waf = require("cdnca_waf")
local detectors = waf._detect
local names = {}
for name in (os.getenv("DETSCAN_NAMES") or "crlf,redirect,format,nosql,ldap"):gmatch("[^,]+") do names[#names + 1] = name end
for spec in (os.getenv("DETSCAN_FILES") or ""):gmatch("[^,]+") do
    local kind, path = spec:match("^(%a+):(.+)$")
    local hits, totals, examples = {}, {}, {}
    for line in io.lines(path) do
        local class, value = line:match("^([^\t]*)\t(.*)$")
        if class then
            value = value:gsub("\\r", "\r"):gsub("\\n", "\n")
            totals[class] = (totals[class] or 0) + 1
            for _, name in ipairs(names) do
                local ok, hit = pcall(detectors[name], value)
                if not ok then print("ERROR " .. name .. " " .. tostring(hit) .. " value=" .. value:sub(1, 200)) end
                if ok and hit then
                    local key = name .. "@" .. class
                    hits[key] = (hits[key] or 0) + 1
                    examples[name] = examples[name] or {}
                    if kind == "benign" and #examples[name] < 20 then
                        examples[name][#examples[name] + 1] = class .. " " .. value:sub(1, 160)
                    end
                end
            end
        end
    end
    for class, total in pairs(totals) do
        local row = {}
        for _, name in ipairs(names) do row[#row + 1] = name .. "=" .. (hits[name .. "@" .. class] or 0) end
        print(string.format("SCAN %s class=%s total=%d %s", kind, class, total, table.concat(row, " ")))
    end
    for name, list in pairs(examples) do
        for _, example in ipairs(list) do print("FP " .. name .. " " .. example) end
    end
end
