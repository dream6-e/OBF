-- Luau exposes debug function names rather than Lua 5.1 local inspection.
local function retainedFunctionName()
    return debug.info(1, "n")
end
assert(retainedFunctionName() == "retainedFunctionName")
local retainedValueName = 42
local dynamicEnvironmentAlias = getfenv(0)
assert(dynamicEnvironmentAlias.print == print and retainedValueName == 42)
assert(assert(loadstring("return 40 + 2"))() == 42)
print("reflection:luau:ok")
