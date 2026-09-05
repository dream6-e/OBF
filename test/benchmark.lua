local Kryvex = {
    Iterations = 100000,
    Results = {}
}

local function benchmark(name, func)
    local start = os.clock()
    func()
    local elapsed = os.clock() - start
    Kryvex.Results[name] = elapsed
    print(string.format("%-20s: %.4fs", name, elapsed))
end

print("=== Kryvex Benchmark Tool ===")
print("Iterations: " .. Kryvex.Iterations)

local total_start = os.clock()

benchmark("CLOSURE", function()
    for i = 1, Kryvex.Iterations do
        (function()
            if (not true) then print('Hey gamer.') end
        end)()
    end
end)

local T = {}
benchmark("SETTABLE", function()
    for i = 1, Kryvex.Iterations do
        T[tostring(i)] = "EPIC GAMER " .. i
    end
end)

benchmark("GETTABLE", function()
    for i = 1, Kryvex.Iterations do
        T[1] = T[tostring(i)]
    end
end)

print(string.format("%-20s: %.4fs", "Total Time", os.clock() - total_start))
