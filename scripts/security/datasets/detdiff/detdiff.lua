-- 两版 cdnca_waf.lua 的检测器逐值差分 + 耗时（纯 LuaJIT，ngx 桩），由 detdiff.sh 调用
dofile("/s/stubs.lua")
local function load(dir)
  package.loaded.cdnca_waf = nil
  package.path = dir .. "/?.lua;/l/?.lua;" .. package.path
  local m = require("cdnca_waf"); package.loaded.cdnca_waf = nil
  return m._detect
end
local A = load("/base"); local B = load("/new")
local names = {}
for name in (os.getenv("DETDIFF_NAMES") or "cmd"):gmatch("[^,]+") do names[#names + 1] = name end
local files = {}
for f in (os.getenv("DETDIFF_FILES") or ""):gmatch("[^,]+") do files[#files + 1] = "/data/" .. f end
local ta, tb, n, diff = 0, 0, 0, 0
for _, f in ipairs(files) do
  for line in io.lines(f) do
    local v = line:match("^[^\t]*\t(.*)$")
    if v then
      v = v:gsub("\\r", "\r"):gsub("\\n", "\n")
      if #v > 8192 then v = v:sub(1, 8192) end -- inspect's value bound
      for _, name in ipairs(names) do
        local c = os.clock(); local _, ra = pcall(A[name], v); ta = ta + os.clock() - c
        c = os.clock(); local _, rb = pcall(B[name], v); tb = tb + os.clock() - c
        n = n + 1
        if (not ra) ~= (not rb) then diff = diff + 1; if diff <= 10 then print("DIFF", name, f, ra, rb, (v:sub(1, 120):gsub("%c", "."))) end end
      end
    end
  end
end
print(string.format("RESULT checks=%d diffs=%d base_ms=%.0f new_ms=%.0f", n, diff, ta * 1000, tb * 1000))
