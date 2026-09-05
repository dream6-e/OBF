-- VM coverage fixture for Luau 0.735 / Roblox-compatible bytecode.
export type Box<T> = {value: T}

type Pair<T> = {left: T, right: T}

local function multi(...: number)
    return ...
end

local function choose<T>(pair: Pair<T>, left: boolean): T
    return if left then pair.left else pair.right
end

local function makeCounter(start: number): (number) -> number
    local value = start
    return function(delta: number): number
        value += delta
        return value
    end
end

local counter = makeCounter(5)
assert(counter(3) == 8)
assert(counter(-2) == 6)
local function nested(value: number)
    return function()
        return function(delta: number)
            return value + delta
        end
    end
end
assert(nested(9)()(4) == 13)
local a, b, c = multi(1, 2, 3)
assert(a == 1 and b == 2 and c == 3)
assert(choose({left = "yes", right = "no"}, true) == "yes")

local x = 0b1100_0000
x //= 3
x += 2
x *= 2
x -= 4
x /= 2
assert(x == 64)
assert(17 // 5 == 3 and 17 % 5 == 2 and 2 ^ 5 == 32)
local floorBoxMt = {
    __idiv = function(left, right)
        return left.value // right.value
    end,
}
assert(setmetatable({value = 17}, floorBoxMt) // setmetatable({value = 5}, floorBoxMt) == 3)
assert(false or nil == nil)
assert(nil or false == false)
assert(true and 9 == 9)

local object = {value = 10}
function object:add(amount: number): number
    self.value += amount
    return self.value
end
assert(object:add(5) == 15)

local array = table.create(4)
table.insert(array, 2)
table.insert(array, 4)
table.insert(array, 6)
local sum = 0
for index, value in ipairs(array) do
    if index == 2 then
        continue
    end
    sum += value
end
assert(sum == 8)

local direct = {alpha = 3, beta = 7}
local directSum = 0
for _, value in direct do
    directSum += value
end
assert(directSum == 10)

for i = 1, 5 do
    sum += i
end
for i = 5, 1, -2 do
    sum += i
end
assert(sum == 32)

local loops = 0
while loops < 3 do
    loops += 1
end
repeat
    loops -= 1
until loops == 0

local frozenTemplate = {kind = "template", count = 2}
local first = {kind = "template", count = 2}
local second = {kind = "template", count = 2}
assert(first ~= second and first.kind == frozenTemplate.kind)

local ok, result = pcall(function()
    return string.format("%s:%d", "value", x)
end)
assert(ok and result == "value:64")
assert(type(result) == "string")
assert(`vm:luau:{x}` == "vm:luau:64")

-- GETIMPORT must observe a table field after the environment is made unsafe.
__obf_luau_import_probe = {value = 1}
assert(__obf_luau_import_probe.value == 1)
__obf_luau_import_probe.value = 2
assert(__obf_luau_import_probe.value == 2)
__obf_luau_import_probe = nil

local originalString = string
string = {format = function()
    return "changed"
end}
assert(string.format("ignored") == "changed")
string = originalString

print("vm:luau:ok")
