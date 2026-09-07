-- ============================================================================
-- OBF 5.1vm.lua · 静态破解重构源码
-- 与反编译器机械输出 full_decomp.txt 逐条对应（proto0 全部 1250 条指令 + 13 个子 proto）。
-- 全程仅静态分析，目标文件从未被执行。
-- ============================================================================

-- ── [FUNC 1] 变参透传 ────────────────────────────────────────────────────────
local function identity(...)
  return ...
end

-- ── [FUNC 2] 函数应用：f(...) ───────────────────────────────────────────────
local function apply(f, ...)
  return f(...)
end

-- ── [FUNC 3 / FUNC 4] 累加器工厂（有状态闭包） ──────────────────────────────
local function make_accumulator(x)
  return function(y)
    x = x + y
    return x
  end
end

-- ── [FUNC 5 / 6 / 7] 三层闭包工厂：x 被最内层捕获 ───────────────────────────
local function make_closure3(x)
  return function()
    return function(y)
      return x + y
    end
  end
end

-- ── [FUNC 8] 乘 2 ───────────────────────────────────────────────────────────
local function twice(x)
  return x * 2
end

-- ── [FUNC 9] 全运算演示：一次返回 6 个值 ────────────────────────────────────
local function ops(a, b)
  return a / b, a % b, a ^ b, not a, a and b, a or b
end

-- ── [FUNC 11] “盒子”对象的方法（以 obj.add(obj, v) 形式调用） ───────────────
local function box_add(self, v)
  self.value = self.value + v
  return self.value
end

-- ── [FUNC 12 / 13] 元表：__add 与 __tostring（uv0 = MT 自身） ───────────────
local MT
MT = {
  __add = function(a, b)
    local t = {}
    t.value = a.value + b.value
    return setmetatable(t, MT)
  end,
  __tostring = function(a)
    return "box:" .. a.value
  end,
}

-- ============================================================================
-- 主脚本（proto 0）
-- ============================================================================

-- 1) 累加器：10 → +2 → 12 → -5 → 7
local v2 = make_accumulator
local acc = v2(10)                    -- v3 = FUNC[3](10)
assert(acc(2) == 12)
assert(acc(-5) == 7)

-- 2) 三层闭包：9 被最内层捕获，4 由最外传入 → 13
local v4 = make_closure3              -- FUNC[5]
assert(v4(9)()(4) == 13)

-- 3) 变参透传 + 多返回值
local a, b, c = identity(1, nil, 3)   -- v0 = FUNC[1]
assert(a == 1 and b == nil and c == 3)

-- 4) 函数应用：apply(twice, 9) == 18
assert(apply(twice, 9) == 18)         -- v1 = FUNC[2], twice = FUNC[8]

-- 5) 全运算：8/3, 8%3, 8^3, not 8, 8 and 3, 8 or 3
local r1, r2, r3, r4, r5, r6 = ops(8, 3)   -- v8 = FUNC[9]
assert(r1 == 8 / 3 and r2 == 2 and r3 == 512)
assert(r4 == false and r5 == 3 and r6 == 8)

-- 6) 闭包读捕获值 + 条件 + 短路求值
local get_value                       -- v15 (box15)
local ok = true                       -- v16 (box16)
local n = 5                           -- v17 (box17)
get_value = function() return n end   -- v15 = FUNC[10]，uv0 = box17（活盒）
if ok then ok = (get_value() == 5) end          -- n 此刻 == 5 → ok = true
assert(ok and (get_value() == 5))               -- 短路：ok 为 true 才会再调 get_value()
n = 16                                -- box17 改写为 16（此后 get_value() 若再调用将返回 16）
assert(n == 16)

-- 7) 一元/关系/逻辑/连接运算断言链
assert(2 == 2 and 32 == 32)
assert((-n == -16) and (not false) and (#"abcd" == 4))
assert("a" .. "b" .. 3 == "ab3")
assert((1 < 2) and (2 <= 2) and (not (3 == 4)) and (4 == 4))

-- 8) 方法调用：obj:add(6) → value 4+6 == 10
local obj = { value = 4 }
obj.add = box_add
assert(obj:add(6) == 10)

-- 9) 数值 for / for-in（ipairs）/ while / repeat-until
local sum = 0                         -- v19
for i = 1, 5, 1 do sum = sum + i end         -- 15
for i = 5, 1, -2 do sum = sum + i end        -- +5 +3 +1 = 24
for _, v in ipairs({ 2, 4, 6 }) do sum = sum + v end  -- +12 = 36
assert(sum == 36)

local cnt = 0                         -- v20
while cnt < 3 do cnt = cnt + 1 end
repeat cnt = cnt - 1 until cnt == 0

-- 10) 大表字面量（编译器拆成两个 SPWRITE 段写入）
local big = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
              21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
              41,42,43,44,45,46,47,48,49,50,
              51,52,53,54,55 }        -- tbl31
assert(big[55] == 55)

-- 11) 元表 OOP：setmetatable({value=2}) + setmetatable({value=8})
--     → __add 生成新盒 value=10 → __tostring → "box:10"
local x = setmetatable({ value = 2 }, MT)
local y = setmetatable({ value = 8 }, MT)
local z = x + y
assert(tostring(z) == "box:10")

-- 12) 全局探针（_G 读写）
_G.__obf_vm_probe = 41
_G.__obf_vm_probe = _G.__obf_vm_probe + 1
assert(_G.__obf_vm_probe == 42)
_G.__obf_vm_probe = nil

-- 13) 完成标记
print("vm:lua51:ok")
return
