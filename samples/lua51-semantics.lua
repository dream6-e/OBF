-- Differential regression corpus for Lua 5.1 VM semantics.
local function pack(...)
    return { n = select('#', ...), ... }
end

local function pass(...)
    return ...
end

local packed = pack(pass('a', nil, 'c', false))
assert(packed.n == 4 and packed[1] == 'a' and packed[2] == nil)
assert(packed[3] == 'c' and packed[4] == false)

local nested = pack(pass(pass(7, nil, 9)))
assert(nested.n == 3 and nested[1] == 7 and nested[2] == nil and nested[3] == 9)

local function arity(...)
    return select('#', ...), ...
end
local arity_result = pack(arity(pass('x', nil, 'z')))
assert(arity_result.n == 4 and arity_result[1] == 3)
assert(arity_result[2] == 'x' and arity_result[3] == nil and arity_result[4] == 'z')

local list = { 1, pass(2, nil, 4) }
assert(list[1] == 1 and list[2] == 2 and list[3] == nil and list[4] == 4)
local tail_result
local function tail(...)
    return pass(...)
end
tail_result = pack(tail(5, nil, 8))
assert(tail_result.n == 3 and tail_result[1] == 5 and tail_result[2] == nil)
assert(tail_result[3] == 8)

local fixed_a, fixed_b, fixed_c = pass('fixed', nil, 'last')
assert(fixed_a == 'fixed' and fixed_b == nil and fixed_c == 'last')

local function iterator(state, control)
    local next_index = control + 1
    if next_index <= #state then
        return next_index, state[next_index]
    end
end
local iter_sum = 0
for index, value in iterator, { 2, 3, 4 }, 0 do
    iter_sum = iter_sum + index + value
end
assert(iter_sum == 15)

local positive_sum = 0
for value = '1', '4', '1' do
    positive_sum = positive_sum + value
end
local negative_sum = 0
for value = '3', '1', '-1' do
    negative_sum = negative_sum + value
end
assert(positive_sum == 10 and negative_sum == 6)

local coercion_side_effect = 0
local invalid_for_value = setmetatable({}, {
    __add = function()
        coercion_side_effect = coercion_side_effect + 1
        return 0
    end,
})
local valid_for = pcall(function()
    for value = invalid_for_value, 1, 1 do
    end
end)
assert(not valid_for and coercion_side_effect == 0)

local lookup_log = {}
local proxy = setmetatable({}, {
    __index = function(_, key)
        lookup_log[#lookup_log + 1] = 'i' .. key
        return 40
    end,
    __newindex = function(_, key, value)
        lookup_log[#lookup_log + 1] = 'n' .. key .. value
    end,
    __add = function()
        return 12
    end,
    __concat = function(_, right)
        return 'meta:' .. right
    end,
})
assert(proxy.answer == 40)
proxy.saved = 3
assert(proxy + 1 == 12)
assert((proxy .. 'x') == 'meta:x')
assert(lookup_log[1] == 'ianswer' and lookup_log[2] == 'nsaved3')

local function make_counter()
    local value = 0
    local function increment(by)
        value = value + (by or 1)
        return value
    end
    local function read()
        return value
    end
    return increment, read
end
local increment, read = make_counter()
assert(increment() == 1 and increment(4) == 5 and read() == 5)

local main_env = getfenv(1)
local env_a = setmetatable({ env_value = 21 }, { __index = main_env })
local env_b = setmetatable({ env_value = 34 }, { __index = main_env })
local function read_env_value()
    return env_value
end
assert(setfenv(read_env_value, env_a) == read_env_value)
assert(read_env_value() == 21 and getfenv(read_env_value) == env_a)
setfenv(read_env_value, env_b)
assert(read_env_value() == 34 and getfenv(read_env_value) == env_b)

local function child_envs()
    return getfenv(1), getfenv(2)
end
local function parent_envs()
    local own, parent = child_envs()
    return own, parent
end
setfenv(child_envs, env_b)
setfenv(parent_envs, env_a)
local child_env, parent_env = parent_envs()
assert(child_env == env_b and parent_env == env_a)

local function switch_own_environment()
    setfenv(1, env_b)
    return env_value, getfenv(1)
end
setfenv(switch_own_environment, env_a)
local switched_value, switched_env = switch_own_environment()
assert(switched_value == 34 and switched_env == env_b)
assert(getfenv(switch_own_environment) == env_b)

local function set_parent_environment()
    setfenv(2, env_b)
    return getfenv(2)
end
local function parent_environment_target()
    local reported = set_parent_environment()
    return reported, getfenv(1)
end
setfenv(set_parent_environment, env_a)
setfenv(parent_environment_target, env_a)
local changed_parent, changed_caller = parent_environment_target()
assert(changed_parent == env_b and changed_caller == env_b)

local function create_with_current_environment()
    setfenv(1, env_a)
    local function inherited_environment()
        return env_value
    end
    return inherited_environment
end
setfenv(create_with_current_environment, env_b)
local inherited_environment = create_with_current_environment()
assert(inherited_environment() == 21)
setfenv(inherited_environment, env_b)
assert(inherited_environment() == 34)

local original_getgenv = main_env.getgenv
main_env.getgenv = function()
    return main_env
end
main_env.only_in_main_environment = 'private'
local isolated_environment = {}
local function isolated_lookup()
    return only_in_main_environment
end
setfenv(isolated_lookup, isolated_environment)
assert(isolated_lookup() == nil)
main_env.getgenv = original_getgenv
main_env.only_in_main_environment = nil

local saved_assert = assert
local saved_type, saved_pairs = type, pairs
local saved_tonumber, saved_error = tonumber, error
type, pairs, tonumber, error = nil, nil, nil, nil
local function make_internal_state()
    local value = 1
    return function()
        value = value + 1
        return value
    end
end
local internal_counter = make_internal_state()
saved_assert(internal_counter() == 2)
local string_for_sum = 0
for value = '1', '2', '1' do
    string_for_sum = string_for_sum + value
end
saved_assert(string_for_sum == 3)
local still_errors = pcall(function()
    for value = invalid_for_value, 1, 1 do
    end
end)
saved_assert(not still_errors and coercion_side_effect == 0)
type, pairs, tonumber, error = saved_type, saved_pairs, saved_tonumber, saved_error

print('LUA51_SEMANTICS_OK', packed.n, list[2], list[4], iter_sum,
      positive_sum, negative_sum, switched_value, increment(), read())
