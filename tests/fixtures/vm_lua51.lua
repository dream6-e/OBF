-- VM coverage fixture for Lua 5.1.5.
local function multi(...)
    return ...
end

local function tail(fn, ...)
    return fn(...)
end

local function makeCounter(start)
    local value = start
    return function(delta)
        value = value + delta
        return value
    end
end

local counter = makeCounter(10)
assert(counter(2) == 12)
assert(counter(-5) == 7)
local function nested(value)
    return function()
        return function(delta)
            return value + delta
        end
    end
end
assert(nested(9)()(4) == 13)

local a, b, c = multi(1, nil, 3)
assert(a == 1 and b == nil and c == 3)
assert(tail(function(x) return x * 2 end, 9) == 18)

local arithmetic = ((7 + 5) * 3 - 4) / 2
assert(arithmetic == 16)
assert(17 % 5 == 2 and 2 ^ 5 == 32)
assert(-arithmetic == -16 and not false and #"abcd" == 4)
assert("a" .. "b" .. 3 == "ab3")
assert(1 < 2 and 2 <= 2 and 3 ~= 4 and 4 == 4)

local object = {value = 4}
function object:add(amount)
    self.value = self.value + amount
    return self.value
end
assert(object:add(6) == 10)

local sum = 0
for i = 1, 5 do
    sum = sum + i
end
for i = 5, 1, -2 do
    sum = sum + i
end
for _, value in ipairs({2, 4, 6}) do
    sum = sum + value
end
assert(sum == 36)

local n = 0
while n < 3 do
    n = n + 1
end
repeat
    n = n - 1
until n == 0

local large = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55,
}
assert(large[55] == 55)

local mt
mt = {
    __add = function(left, right)
        return setmetatable({value = left.value + right.value}, mt)
    end,
    __tostring = function(self)
        return "box:" .. self.value
    end,
}
local box = setmetatable({value = 2}, mt) + setmetatable({value = 8}, mt)
assert(tostring(box) == "box:10")

_G.__obf_vm_probe = 41
__obf_vm_probe = __obf_vm_probe + 1
assert(_G.__obf_vm_probe == 42)
_G.__obf_vm_probe = nil

print("vm:lua51:ok")
