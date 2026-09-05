-- Focused Lua 5.1 AST corpus: declarations, calls, loops, tables and operators.
local function pack(...)
    return {n = select("#", ...), ...}
end

local object = {value = 2}
function object:add(amount)
    self.value = self.value + amount
    return self
end

local total = 0
for index, value in ipairs(pack(3, 4, 5)) do
    if type(index) == "number" and index <= 3 then
        total = total + value
    end
end

local cursor = 0
while cursor < 2 do
    cursor = cursor + 1
end
repeat
    total = total - 1
until total < 12

do
    local computed = {[object.value] = total, label = "ok", 7}
    object:add(computed[1])
end

local function sink(value)
    return value
end
sink "short-call"
sink {true, false, nil}

assert(-2 ^ 2 == -4)
assert(object.value == 9 and cursor == 2 and total == 11)
print("ast:lua51:" .. object.value .. ":" .. total)
