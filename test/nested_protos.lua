local function make_counter(start)
    local value = start
    local function add(delta)
        value = value + delta
        local saved = delta * 3
        return function(multiplier)
            value = value + multiplier
            return value, saved
        end
    end
    local function sibling(x)
        return x * 2 + start
    end
    return add, sibling
end

local add, sibling = make_counter(5)
local first = add(2)
local second = add(4)
local a, b = first(1)
local c, d = second(3)
print(a, b, c, d, sibling(7))

local function nest(depth, seed)
    if depth == 0 then
        return function(n)
            return seed + n
        end
    end
    local child = nest(depth - 1, seed + depth)
    return function(n)
        return child(n + depth)
    end
end

local deep = nest(5, 10)
print(deep(7))
