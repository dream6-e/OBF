-- vararg 透传夹具：壳必须对脚本的 `...` 完全透明（宿主传几个就看见几个）。
-- 旧形态只透传第一个（`local L = ...` 后传 L），本夹具会把那种退化直接测出来。
local a, b, c, d = ...
print("head4", a, b, c, d)
print("count", select('#', ...))
print("pack", #{...})

-- 二次转发：`f(...)` 应当把全部实参原样带下去
local function f(...)
    return select('#', ...), ...
end
print("fwd", f(...))

-- 表打包后按下标取
local t = {...}
print("t", t[1], t[2], t[3], #t)

-- 嵌套闭包里用 upvalue 再转发一次
local function outer(...)
    local function inner(...)
        return select('#', ...)
    end
    return inner(...)
end
print("nested", outer(...))

-- 空 vararg 的边界：count 必须是 0，不能是 1（那会把 nil 当实参）
local function zero(...)
    return select('#', ...)
end
print("zero", zero())
