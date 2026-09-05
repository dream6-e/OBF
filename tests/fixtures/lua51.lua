-- Lua 5.1 compatibility fixture: comments, long strings, closures and varargs.
local banner = [=[
OBF
matrix]=]

local function fold(seed, ...)
    local values = {...}
    local total = seed
    for index, value in ipairs(values) do
        if index % 2 == 0 then
            total = total - value
        else
            total = total + value
        end
    end
    return total
end

local object = setmetatable({value = fold(10, 4, 3, 2)}, {
    __tostring = function(self)
        return banner .. ":" .. self.value
    end,
})

assert(fold(10, 4, 3, 2) == 13)
print(tostring(object))
