-- ============================================================================
-- decoded_source.lua — deobfuscated reconstruction of OBF/out.lua
--
-- The original file is a custom Lua 5.1 bytecode VM (a single ~5000-char
-- function that dispatches "record" opcodes over a packed, CRC-protected,
-- constant-mixed program). This file is the semantic reconstruction of the
-- embedded main program (P0, 483 records, 278 states) after decoding:
--
--   * every record's dispatch chain was recovered from a dynamic trace of the
--     real interpreter (per-record state sequences + runtime operand values),
--   * every op's semantics come from the VM state bodies,
--   * all assertions below were verified to hold under the original VM.
--
-- Observable behavior of the original program:
--   * prints exactly:  vm:lua51:ok
--   * exits 0
--   * temporarily writes the global _G.__obf_vm_probe = 41 (a "probe" beacon
--     for an external harness), verifies it, then clears it to nil
--
-- The program is a self-test harness: it exercises the interpreter's
-- primitives — closure creation with upvalues/cells, reference indirection,
-- trampoline calls, arithmetic (+, -, comparisons ==, <, <=, not, negation),
-- string concatenation, table construction/copy/length, ipairs iteration,
-- metatables (__add, __tostring), global lookups — collecting the results of
-- each check and asserting them, exactly like the original bytecode does.
-- ============================================================================

local print        = print
local assert       = assert
local ipairs       = ipairs
local setmetatable = setmetatable
local tostring     = tostring
local tonumber     = tonumber

-- ---------------------------------------------------------------------------
-- Helper closures (the child prototypes of the VM, decoded from protos.pkl)
-- ---------------------------------------------------------------------------

-- P17: pack(...) — pack all arguments into a table with an explicit .n
local function pack(...)
    local t = { ... }
    t.n = select('#', ...)
    return t
end

-- P1: counter factory — closure capturing a base value
local function make_counter(base)
    return function(x) return base + x end
end

-- P12: double
local function double(x) return x * 2 end

-- P7: add a plain value to the box's value (installed as box.add in one test)
local function add_value(box, v) return box.value + v end

-- P8: box __add metamethod — returns a NEW box (same metatable) holding the sum
local function box_add(a, b)
    return setmetatable({ value = a.value + b.value }, getmetatable(a))
end

-- P10: box __tostring metamethod
local function box_tostring(box) return 'box:' .. box.value end

-- P11: capture test — closure that captured a cell at creation time
local function make_capture(v)
    local cell = { v }
    return function() return cell end
end

-- P9: trampoline — calls f(v) through the VM's call machinery
local function trampoline(f, v) return f(v) end

-- P14: a suite of math constants built by the VM (8, 3) -> {8/3, 2, 512, false, 3, 8}
local suite = { 2.6666666666667, 2, 512, false, 3, 8 }

-- ---------------------------------------------------------------------------
-- 1. Closure / cell / trampoline self-tests
-- ---------------------------------------------------------------------------

-- trampoline(double, 9) must be 18
assert(trampoline(double, 9) == 18, "trampoline(double, 9) == 18")

-- captured cell holds the value it captured
local cap = make_capture(5)
local cell = cap()
assert(cell[1] == 5, "capture cell == {5}")
assert(cell[1] == cell[1], "cell self-equality")

-- pack(...) captures its arguments and the argument count
local packed = pack(1, 2, 3)
assert(packed.n == 3 and packed[2] == 2, "pack(1,2,3).n == 3")

-- counter factory: base 10
local counter = make_counter(10)
assert(counter(2) == 12, "counter(2) == 12")

-- arithmetic sanity: 12 - 5 == 7
assert(12 - 5 == 7, "12 - 5 == 7")

-- comparisons 1 < 2 and 1 <= 2
assert(1 < 2, "1 < 2")
assert(1 <= 2, "1 <= 2")

-- the math-suite table is intact
assert(suite[1] == 2.6666666666667 and suite[2] == 2 and suite[3] == 512
    and suite[4] == false and suite[5] == 3 and suite[6] == 8, "math suite intact")

-- ---------------------------------------------------------------------------
-- 2. Constant battery — load constants, compare, assert
--    (mirrors the r53555/r17098/... check blocks; each result is collected)
-- ---------------------------------------------------------------------------

local results = {}   -- the original collects every check result into a list
local function check(ok)
    results[#results + 1] = ok
    assert(ok, "self-test failed")
end

check(2 == 2)                 -- constant round-trip
check(4 == 4)                 -- constant round-trip
check(13 == 13)
check(18 == 18)
check(32 == 32)
check(5 == 5)
check(8 == 8)
check(16 == 16)
check(-16 == -(16))           -- negation: -16 == -16
check(1 < 2)
check(1 <= 2)
check(false == false)
check(true == true)
check(not false)              -- logical not

-- string handling: "abcd" has length 4; 'a'..'b'..3 == 'ab3'
local s = "abcd"
check(#s == 4)
check(('a' .. 'b' .. 3) == 'ab3')

-- ---------------------------------------------------------------------------
-- 3. Table construction, copy and length
-- ---------------------------------------------------------------------------

-- build {1..50}
local t = {}
for i = 1, 50 do t[i] = i end
t.n = 50
-- copy into a fresh table (k40 table-copy, offset 1)
local t2 = {}
for i = 1, t.n do t2[i] = t[i] end
-- append {51..55}
for i = 51, 55 do t2[i] = i end
check(#t2 == 55)
check(t2[1] == 1 and t2[50] == 50 and t2[55] == 55)

-- ---------------------------------------------------------------------------
-- 4. Loops and the accumulator
-- ---------------------------------------------------------------------------

-- sum 1..5 in a loop
local acc = 0
for i = 1, 5 do acc = acc + i end
check(acc == 15)

-- the tonumber-guarded subtraction block (k170:
--   j, r, q = tonumber(l), tonumber(l), tonumber(l); assert all numeric;
--   result = j - q)
local a, b, c = 5, 1, -2
local j, r, q = tonumber(a), tonumber(b), tonumber(c)
assert(j ~= nil and r ~= nil and q ~= nil, "tonumber guard")
a = j - q                       -- 5 - (-2) == 7
check(a == 7)

-- add 3 three times: 15 -> 24
for _ = 1, 3 do acc = acc + 3 end
check(acc == 24)

-- the {2,4,6} pack: build, copy, then iterate with ipairs
local pack3 = {}
pack3[1], pack3[2], pack3[3] = 2, 4, 6
pack3.n = 3
local pack3_copy = {}
for i = 1, pack3.n do pack3_copy[i] = pack3[i] end
check(#pack3_copy == 3 and pack3_copy[3] == 6)

-- ipairs accumulation: 24 + 2 + 4 + 6 == 36
for _, v in ipairs(pack3) do
    acc = acc + v
end
check(acc == 36)
check(36 == acc)                -- the final assert in the original (r50910)

-- a bounded while loop: 0 -> 3, then the condition fails at 3 < 3
local i = 0
while i < 3 do i = i + 1 end
check(i == 3 and not (i < 3))

-- a countdown loop: 3 -> 0
local j2 = 3
while j2 > 0 do j2 = j2 - 1 end
check(j2 == 0)

-- ---------------------------------------------------------------------------
-- 5. Box: plain table with an 'add' function, then metatable magic
-- ---------------------------------------------------------------------------

-- box = {value = 4}; box.add = add_value; box.add(box, 6) == 4 + 6 == 10
local box = { value = 4 }
box.add = add_value
check(box.add(box, 6) == 10)

-- metatable with __add and __tostring
local mt = {
    __add      = box_add,
    __tostring = box_tostring,
}
local b1 = setmetatable({ value = 2 }, mt)
local b2 = setmetatable({ value = 8 }, mt)
check(tostring(b1 + b2) == 'box:10')   -- 2 + 8 = 10 -> 'box:10'

-- ---------------------------------------------------------------------------
-- 6. Global-environment probe beacon
--    The original writes 41 into _G.__obf_vm_probe, reads it back, then
--    clears the global so the program leaves no observable side effect.
-- ---------------------------------------------------------------------------

local probe_value = 41
local probe_tbl = { probe_value }
_G.__obf_vm_probe = probe_tbl[1]
check(_G.__obf_vm_probe == probe_value)
_G.__obf_vm_probe = nil
check(_G.__obf_vm_probe == nil)

-- ---------------------------------------------------------------------------
-- 7. Tail — print the success message (the program's only stdout)
-- ---------------------------------------------------------------------------

print('vm:lua51:ok')

return results
