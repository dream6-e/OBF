-- Regression sample for the custom mixed stack/register VM ISA.
local function make_counter(seed)
  local current = seed
  local label = "counter"
  return function(step)
    current = current + step
    return label, current
  end
end

local label, n = make_counter(10)(2)
assert(label == "counter" and n == 12)

local function pack(...)
  return select("#", ...), ...
end
local count, a, b, c = pack("x", nil, 7)
assert(count == 3 and a == "x" and b == nil and c == 7)

local function values()
  return "v", nil, 9
end
local function receive(...)
  return select("#", ...), ...
end
local value_count, v1, v2, v3 = receive(values())
assert(value_count == 3 and v1 == "v" and v2 == nil and v3 == 9)
local expanded_list = {values()}
assert(expanded_list[1] == "v" and expanded_list[2] == nil and expanded_list[3] == 9)

local t = {2, 3, 5}
t[2] = t[2] + 4
function t:sum(extra)
  return self[1] + self[2] + self[3] + extra
end
assert(t:sum(1) == 15)
assert(#t == 3)

local total = 0
for i = 1, 5 do
  if i % 2 == 0 then total = total + i else total = total + 1 end
end
assert(total == 9)

local map = {a = 1, b = 2, c = 3}
local seen = 0
for _, value in pairs(map) do seen = seen + value end
assert(seen == 6)

local x = false
local y = true
assert((x or y) and not x)
assert((5 > 3) and (3 <= 3) and (2 ~= 4))

local function relay(...)
  return pack(...)
end
local rc, rx, ry = relay(21, 22)
assert(rc == 2 and rx == 21 and ry == 22)

local function factory()
  local nested_total = 1
  local function middle()
    return function(delta)
      nested_total = nested_total + delta
      return nested_total
    end
  end
  return middle()
end
local nested = factory()
assert(nested(2) == 3 and nested(5) == 8)

local closed
local closed_value = 41
do
  local captured = closed_value
  closed = function() return captured end
end
assert(closed() == 41)

local break_closure
for i = 1, 5 do
  local captured_i = i
  break_closure = function() return captured_i end
  if i == 2 then break end
end
assert(break_closure() == 2)

local values = {}
for i = 1, 60 do values[i] = i end
local sum = 0
for i = 60, 1, -1 do sum = sum + values[i] end
assert(sum == 1830)

local dense = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60}
assert(#dense == 60 and dense[50] == 50 and dense[51] == 51 and dense[60] == 60)

local concat_mt = {__concat = function(left, right)
  local function show(value)
    if type(value) == "table" then return value.tag end
    return tostring(value)
  end
  return "(" .. show(left) .. ">" .. show(right) .. ")"
end}
local ca = setmetatable({tag = "a"}, concat_mt)
local cb = setmetatable({tag = "b"}, concat_mt)
local cc = setmetatable({tag = "c"}, concat_mt)
local concatenated = ca .. cb .. cc
assert(concatenated == "(a>(b>c))")

local function multi()
  return nil, "middle", 9
end
local nil_value, text, last = multi()
assert(nil_value == nil and text == "middle" and last == 9)

local choice = false
if choice then choice = "bad" else choice = "good" end
assert(choice == "good")

print("VM_ISA_OK", n, t:sum(1), total, seen, rc)
print("VM_ISA_EXT_OK", nested(1), closed(), sum, text, last, choice)
print("VM_ISA_CONCAT_OK", concatenated)
