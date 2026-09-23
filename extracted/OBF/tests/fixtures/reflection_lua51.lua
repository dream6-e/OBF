-- The default safe minifier must retain all names in reflective chunks.
local retainedLocalName = 42
local localObserverAlias = debug["get" .. "local"]
local function inspectCallerName()
    for observerIndex = 1, 100 do
        local observedName, observedValue = localObserverAlias(2, observerIndex)
        if observedName == nil then break end
        if observedName == "retainedLocalName" then
            assert(observedValue == 42)
            return observedName
        end
    end
end
assert(inspectCallerName() == "retainedLocalName")
local retainedUpvalueName = 19
local function capturedFunctionName() return retainedUpvalueName end
local upvalueName, upvalueValue = debug.getupvalue(capturedFunctionName, 1)
assert(upvalueName == "retainedUpvalueName" and upvalueValue == 19)
assert(retainedLocalName == 42 and getfenv(0).print == print)
assert(assert(loadstring("return 40 + 2"))() == 42)
print("reflection:lua51:ok")
