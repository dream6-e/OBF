local function getTime()
    return os.clock()
end

local function formatTime(seconds)
    if seconds < 1e-6 then
        return string.format("%.2f ns", seconds * 1e9)
    elseif seconds < 1e-3 then
        return string.format("%.2f us", seconds * 1e6)
    elseif seconds < 1 then
        return string.format("%.2f ms", seconds * 1e3)
    else
        return string.format("%.4f s", seconds)
    end
end

local function measure(name, func, innerN, args)
    innerN = innerN or 10000
    args = args or {}
    for i = 1, 20 do
        func(unpack(args))
    end
    local minT = math.huge
    local totalT = 0
    local rounds = 20
    for r = 1, rounds do
        local t0 = getTime()
        for i = 1, innerN do
            func(unpack(args))
        end
        local dt = (getTime() - t0) / innerN
        if dt < minT then minT = dt end
        totalT = totalT + dt
    end
    local avgT = totalT / rounds
    print(string.format("%-16s min=%-12s avg=%-12s n=%d",
        name, formatTime(minT), formatTime(avgT), innerN))
    return minT
end

local cases = {}

cases.arith = {
    name = "arith",
    func = function()
        local a, b, c = 1, 2, 3
        for i = 1, 100 do
            a = a + b * c - (a % 7)
        end
        return a
    end,
    innerN = 10000,
    check = function(r) return type(r) == "number" end
}

cases.table_ops = {
    name = "table_ops",
    func = function()
        local t = {}
        for i = 1, 50 do
            t[i] = i
        end
        local s = 0
        for i = 1, 50 do
            s = s + t[i]
        end
        return s
    end,
    innerN = 10000,
    check = function(r) return type(r) == "number" end
}

cases.calls = {
    name = "calls",
    func = function()
        local f = function(x) return x + 1 end
        local s = 0
        for i = 1, 100 do
            s = f(s)
        end
        return s
    end,
    innerN = 10000,
    check = function(r) return type(r) == "number" end
}

cases.string_ops = {
    name = "string_ops",
    func = function()
        local parts = {}
        for i = 1, 50 do
            parts[i] = "x"
        end
        return table.concat(parts)
    end,
    innerN = 10000,
    check = function(r) return type(r) == "string" end
}

cases.closure = {
    name = "closure",
    func = function()
        local x = 0
        local function inc() x = x + 1 end
        for i = 1, 100 do
            inc()
        end
        return x
    end,
    innerN = 10000,
    check = function(r) return type(r) == "number" end
}

cases.fib = {
    name = "fib(20)",
    func = function()
        local function fib(n)
            if n < 2 then return n end
            return fib(n - 1) + fib(n - 2)
        end
        return fib(20)
    end,
    innerN = 100,
    check = function(r) return r == 6765 end
}

local order = { "arith", "table_ops", "calls", "string_ops", "closure", "fib" }

local function runAll(label)
    print("=== " .. label .. " ===")
    local results = {}
    for _, key in ipairs(order) do
        local c = cases[key]
        local r = c.func()
        if c.check and not c.check(r) then
            print(string.format("%-16s CHECK FAILED (result=%s)", c.name, tostring(r)))
        end
        results[key] = measure(c.name, c.func, c.innerN)
    end
    print("")
    return results
end

local base = runAll("baseline")
