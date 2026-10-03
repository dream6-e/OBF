-- Verify that decoded global names use each VM frame's current environment.
local base_env = getfenv and getfenv(1) or _ENV or _G
local top_env = setmetatable({ DynamicGlobalProbe = "top" }, { __index = base_env })

setfenv(1, top_env)
assert(DynamicGlobalProbe == "top")
DynamicGlobalProbe = "top-updated"
assert(top_env.DynamicGlobalProbe == "top-updated")
setfenv(1, base_env)

local closure_env = setmetatable({ DynamicGlobalProbe = "closure" }, { __index = base_env })
local function read_closure_global()
    local before = DynamicGlobalProbe
    DynamicGlobalProbe = "closure-updated"
    return before, DynamicGlobalProbe
end
setfenv(read_closure_global, closure_env)

local before, after = read_closure_global()
assert(before == "closure")
assert(after == "closure-updated")
assert(closure_env.DynamicGlobalProbe == "closure-updated")
print("top-updated,closure,closure-updated")
