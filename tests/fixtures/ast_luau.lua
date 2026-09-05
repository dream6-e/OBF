-- Focused Luau 0.735 AST corpus: types, attributes, exports and interpolation.
export type Pair<T> = {
    read left: T,
    write right: T,
}

type Mapper<T, U...> = (value: T, U...) -> (T, U...)
type function Identity(kind)
    return kind
end

@[checked]
export function choose<T>(pair: Pair<T>, takeLeft: boolean): T
    return if takeLeft then pair.left elseif pair.right ~= nil then pair.right else pair.left
end

@native
local function increment(value: number): number
    return value + 1
end

export const seed: number = 0b1010
const offset: number = 0x_2
local value = choose<<number>>({left = seed, right = 0}, true)
value += offset
value //= 2

local sum = 0
for index = 1, 5 do
    if index % 2 == 0 then
        continue
    end
    sum += index
end

local nested = `value={value}; inner={`sum={sum}`}`
assert(increment(value) == 7)
assert(sum == 9)
print(`ast:luau:{nested}`)
