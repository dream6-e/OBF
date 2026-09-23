-- Safe compression across Luau value scopes, types and interpolation.
a, b = 101, 202
local safeCompressionMarker = 5
local initializerValue = 19
local initializerValue, siblingValue = initializerValue + 1, initializerValue
assert(initializerValue == 20 and siblingValue == 19)

local typedValue = 8
type typedValue = number
local typedCopy: typedValue = typedValue
local function typedFunction(typedValue: typeof(typedValue)): typeof(typedValue)
    return typedValue + typedCopy
end
assert(typedFunction(2) == 10)

type PairType<T, U = T> = {left: T, right: U}
type PackType<T...> = (T...) -> T...
type function IdentityType(typeArgument)
    local preservedTypeLocal = typeArgument
    return preservedTypeLocal
end

@[checked]
export function exportedFunctionLongName<T>(parameterValue: T): T
    return parameterValue
end
export const exportedConstantLongName = 7
const constantLocalValue = 3
assert(exportedFunctionLongName<<number>>(exportedConstantLongName) == 7)

local rootCapturedValue = 10
local firstClosure = function()
    return function(deltaValue)
        rootCapturedValue += deltaValue
        return rootCapturedValue
    end
end
local secondClosure = firstClosure()
do
    local rootCapturedValue = rootCapturedValue + 2
    assert(rootCapturedValue == 12)
end
assert(secondClosure(4) == 14 and rootCapturedValue == 14)

local function recursiveFunction(numberValue: number): number
    return if numberValue <= 1 then 1 else numberValue * recursiveFunction(numberValue - 1)
end
assert(recursiveFunction(5) == 120)
local assignedFunction
function assignedFunction(argumentValue: number): number
    return argumentValue + safeCompressionMarker
end
assert(assignedFunction(2) == 7)

local totalValue = 0
local iteratorValue = {2, 3, 4}
for iteratorIndex, iteratorValue in iteratorValue do
    if iteratorIndex == 2 then continue end
    totalValue += iteratorValue
end
assert(totalValue == 6 and iteratorValue[2] == 3)
local loopVariable = 3
local loopClosures = {}
for loopVariable = loopVariable, loopVariable + 2 do
    table.insert(loopClosures, function() return loopVariable end)
end
assert(loopVariable == 3 and loopClosures[1]() == 3 and loopClosures[3]() == 5)
repeat
    local conditionValue = totalValue - 1
    totalValue = conditionValue
until conditionValue == 3
assert(totalValue == 3 and conditionValue == nil)

local self = {value = -100}
local objectLongName = {value = 2, branch = {}}
function objectLongName:increase(amountValue: number)
    self.value += amountValue
    return function() return self.value end
end
function objectLongName:explicit(self)
    return self
end
function objectLongName.branch.calculate(inputValue: number): number
    return inputValue * 2
end
assert(objectLongName:increase(3)() == 5 and self.value == -100)
assert(objectLongName:explicit(77) == 77)
assert(objectLongName.branch.calculate(4) == 8)

local function packValues(...: number)
    return {n = select("#", ...), ...}
end
local function multipleReturns(argumentValue: number, ...: number)
    return argumentValue, ...
end
local packedValues = packValues(multipleReturns(1, nil, 3, nil))
assert(packedValues.n == 4 and packedValues[3] == 3)

local interpolatedResult = `\{outer={
    (function(innerValue: number)
        local textValue = `v={innerValue + safeCompressionMarker}`
        -- Braces and backticks in a comment: } ` {
        return textValue
    end)(2)
}; percent=100%; escaped=\`}`
assert(interpolatedResult == "{outer=v=7; percent=100%; escaped=`}")
local tableInterpolation = `value={ {field = safeCompressionMarker} }`
assert(string.sub(tableInterpolation, 1, 12) == "value=table:")
local escapedNewline = `first\
second`
assert(escapedNewline == "first\nsecond")
local skippedWhitespace = `a\z
    b`
assert(skippedWhitespace == "ab")
local longString = [=[
first
second]=]
assert(longString == "first\nsecond")
assert(`\x7b\x60\q` == "{`q")
local keyedValue = {longFieldName = safeCompressionMarker, ["safeCompressionMarker"] = "safeCompressionMarker"}
assert(keyedValue.longFieldName == 5 and keyedValue["safeCompressionMarker"] == "safeCompressionMarker")
assert(a == 101 and b == 202 and constantLocalValue == 3)
print("scope:luau:ok")
