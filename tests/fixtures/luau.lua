-- Luau 0.735 compatibility fixture: types, binary numbers and compound assignment.
export type Pair<T> = {
    left: T,
    right: T,
}

local function choose<T>(pair: Pair<T>, takeLeft: boolean): T
    return if takeLeft then pair.left else pair.right
end

local value: number = 0b1010_0011
value += 2
local selected = choose({left = value, right = 0}, true)
assert(selected == 165)
print(`OBF:luau:{selected}`)
