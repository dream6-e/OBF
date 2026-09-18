-- Safe compression: binding identity, not identifier text replacement.
a, b = 101, 202
local safeCompressionMarker = 5
local initializerValue = 19
local initializerValue, siblingValue = initializerValue + 1, initializerValue
assert(initializerValue == 20 and siblingValue == 19)

fallbackFunction = 44
local fallbackFunction = function()
    return fallbackFunction -- the GLOBAL: the new local is not in scope yet
end
assert(fallbackFunction() == 44)

local retainedClosure
local shadowedValue = 10
do
    local shadowedValue = shadowedValue + 1
    retainedClosure = function(delta)
        shadowedValue = shadowedValue + delta
        return function() return shadowedValue end
    end
end
local nestedClosure = retainedClosure(3)
assert(nestedClosure() == 14 and shadowedValue == 10)
local shadowedValue = 99
assert(nestedClosure() == 14 and shadowedValue == 99)

do
    local siblingLocal = 3
    assert(siblingLocal == 3)
end
do
    local siblingLocal = 4
    assert(siblingLocal == 4)
end

local function factorialLongName(numberValue)
    if numberValue <= 1 then return 1 end
    return numberValue * factorialLongName(numberValue - 1)
end
assert(factorialLongName(5) == 120)
local reassignedFunction
function reassignedFunction(argumentValue)
    return argumentValue + safeCompressionMarker
end
assert(reassignedFunction(3) == 8)

local loopVariable = 3
local loopClosures = {}
for loopVariable = loopVariable, loopVariable + 2 do
    loopClosures[#loopClosures + 1] = function() return loopVariable end
end
assert(loopVariable == 3)
assert(loopClosures[1]() == 3 and loopClosures[3]() == 5)
local iteratorValue = {7, 8, 9}
local iterationTotal = 0
for iteratorIndex, iteratorValue in ipairs(iteratorValue) do
    iterationTotal = iterationTotal + iteratorIndex * iteratorValue
end
assert(iterationTotal == 50 and iteratorValue[1] == 7)
local repeatTotal = 0
repeat
    local repeatLimit = repeatTotal + 1
    repeatTotal = repeatLimit
until repeatLimit == 3
assert(repeatTotal == 3 and repeatLimit == nil)
while repeatTotal > 0 do
    local repeatTotal = repeatTotal - 1
    assert(repeatTotal >= 0)
    break
end
assert(repeatTotal == 3)

local self = {value = -100}
local objectLongName = {value = 2, branch = {}}
function objectLongName:increase(amountValue)
    self.value = self.value + amountValue
    return function() return self.value end
end
function objectLongName:explicit(self)
    return self
end
function objectLongName.branch.calculate(inputValue)
    return inputValue * 2
end
assert(objectLongName:increase(3)() == 5 and self.value == -100)
assert(objectLongName:explicit(77) == 77)
assert(objectLongName.branch.calculate(4) == 8)

local function legacyArguments(prefixValue, ...)
    return prefixValue, arg.n, arg[1], arg[3]
end
local prefixResult, argumentCount, firstArgument, lastArgument = legacyArguments("p", 1, nil, 3)
assert(prefixResult == "p" and argumentCount == 3 and firstArgument == 1 and lastArgument == 3)
local function capturedLegacyArguments(...)
    local function readArgument() return arg[1] end
    return readArgument()
end
assert(capturedLegacyArguments(71) == 71)
local function packValues(...)
    return {n = select("#", ...), ...}
end
local function multipleReturns(argumentValue, ...)
    return argumentValue, ...
end
local packedValues = packValues(multipleReturns(1, nil, 3, nil))
assert(packedValues.n == 4 and packedValues[1] == 1 and packedValues[3] == 3)

local orderingTrace = ""
local function nextValue(labelValue, numberValue)
    orderingTrace = orderingTrace .. labelValue
    return numberValue
end
local metaValue = setmetatable({value = 4}, {
    __add = function(leftValue, rightValue)
        orderingTrace = orderingTrace .. "M"
        return leftValue.value + rightValue
    end,
})
assert(metaValue + nextValue("A", 2) == 6 and orderingTrace == "AM")
local keyedValue = {longFieldName = safeCompressionMarker, ["safeCompressionMarker"] = "safeCompressionMarker"}
assert(keyedValue.longFieldName == 5 and keyedValue["safeCompressionMarker"] == "safeCompressionMarker")
assert(a == 101 and b == 202)
assert("\q\z" == "qz")
print("scope:lua51:ok")
