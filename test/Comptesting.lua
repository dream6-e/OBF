local TOTAL = 0

local function assert_eq(a,b)
    if a ~= b then
        error(
            "assert failed\nExpected: "
            .. tostring(b)
            .. "\nActual: "
            .. tostring(a)
        )
    end
end

local function test(name,fn)
    TOTAL = TOTAL + 1

    local ok,err = pcall(fn)

    if not ok then
        error(
            "\n[FAILED] "
            .. name
            .. "\n"
            .. tostring(err)
        )
    end

    print("[PASS] "..name)
end

--------------------------------------------------
-- BASIC
--------------------------------------------------

test("Arithmetic",function()
    assert_eq(1+2,3)
    assert_eq(10-5,5)
    assert_eq(3*4,12)
    assert_eq(8/2,4)
end)

test("Scope",function()
    local a=1

    do
        local a=2
        assert_eq(a,2)
    end

    assert_eq(a,1)
end)

--------------------------------------------------
-- CLOSURE
--------------------------------------------------

test("Closure_Capture",function()
    local x=10

    local function f()
        return x
    end

    assert_eq(f(),10)
end)

test("Closure_Mutation",function()
    local x=0

    local function inc()
        x=x+1
    end

    inc()
    inc()

    assert_eq(x,2)
end)

test("Nested_Upvalue",function()
    local x=123

    local function a()
        local function b()
            return x
        end

        return b
    end

    assert_eq(a()(),123)
end)

test("Shared_Upvalue",function()
    local x=0

    local function inc()
        x=x+1
    end

    local function get()
        return x
    end

    inc()
    inc()

    assert_eq(get(),2)
end)

test("IndependentClosures",function()

    local function make()
        local x=0

        return function()
            x=x+1
            return x
        end
    end

    local a=make()
    local b=make()

    assert_eq(a(),1)
    assert_eq(a(),2)

    assert_eq(b(),1)
end)

--------------------------------------------------
-- RETURN
--------------------------------------------------

test("MultiReturn",function()

    local function f()
        return 1,2,3
    end

    local a,b,c=f()

    assert_eq(a,1)
    assert_eq(b,2)
    assert_eq(c,3)
end)

test("MultiReturnPropagation",function()

    local function f()
        return 1,2,3
    end

    local function g()
        return f()
    end

    local a,b,c=g()

    assert_eq(a,1)
    assert_eq(b,2)
    assert_eq(c,3)
end)

--------------------------------------------------
-- VARARG
--------------------------------------------------

test("Vararg",function()

    local function f(...)
        return ...
    end

    local a,b,c=f(1,2,3)

    assert_eq(a,1)
    assert_eq(b,2)
    assert_eq(c,3)
end)

test("VarargClosure",function()

    local function outer(...)
        local x=select(1,...)

        return function()
            return x
        end
    end

    assert_eq(outer(99)(),99)
end)

--------------------------------------------------
-- TABLE
--------------------------------------------------

test("Table",function()

    local t={
        a=1,
        b=2
    }

    assert_eq(t.a,1)
    assert_eq(t.b,2)
end)

test("LargeTable",function()

    local t={}

    for i=1,200 do
        t[i]=i
    end

    local s=0

    for i=1,200 do
        s=s+t[i]
    end

    assert_eq(s,20100)
end)

--------------------------------------------------
-- RECURSION
--------------------------------------------------

test("Recursion",function()

    local function fact(n)

        if n==0 then
            return 1
        end

        return n*fact(n-1)
    end

    assert_eq(fact(5),120)
end)

test("DeepRecursion",function()

    local function f(n)

        if n==0 then
            return 1
        end

        return f(n-1)
    end

    assert_eq(f(500),1)
end)

--------------------------------------------------
-- TAILCALL
--------------------------------------------------

test("TailCall",function()

    local function f(n)

        if n==0 then
            return 123
        end

        return f(n-1)
    end

    assert_eq(f(300),123)
end)

test("TailCallMultiReturn",function()

    local function a()
        return 1,2,3
    end

    local function b()
        return a()
    end

    local x,y,z=b()

    assert_eq(x,1)
    assert_eq(y,2)
    assert_eq(z,3)
end)

--------------------------------------------------
-- LOGIC
--------------------------------------------------

test("ShortCircuitAnd",function()

    local called=false

    local function boom()
        called=true
        return true
    end

    local _=false and boom()

    assert_eq(called,false)
end)

test("ShortCircuitOr",function()

    local called=false

    local function boom()
        called=true
        return true
    end

    local _=true or boom()

    assert_eq(called,false)
end)

--------------------------------------------------
-- FOR
--------------------------------------------------

test("ForStep",function()

    local s=0

    for i=1,10,2 do
        s=s+i
    end

    assert_eq(s,25)
end)

test("While",function()

    local i=0

    while i<5 do
        i=i+1
    end

    assert_eq(i,5)
end)

test("RepeatUntil",function()

    local i=0

    repeat
        i=i+1
    until i==5

    assert_eq(i,5)
end)

--------------------------------------------------
-- GENERIC FOR
--------------------------------------------------

test("Pairs",function()

    local t={a=1,b=2,c=3}

    local s=0

    for _,v in pairs(t) do
        s=s+v
    end

    assert_eq(s,6)
end)

test("Ipairs",function()

    local t={1,2,3,4}

    local s=0

    for _,v in ipairs(t) do
        s=s+v
    end

    assert_eq(s,10)
end)

test("Next",function()

    local t={a=1,b=2,c=3}

    local s=0

    for _,v in next,t,nil do
        s=s+v
    end

    assert_eq(s,6)
end)

--------------------------------------------------
-- SELF
--------------------------------------------------

test("Self",function()

    local t={}

    function t:add(v)
        return v+1
    end

    assert_eq(t:add(5),6)
end)

--------------------------------------------------
-- METATABLE
--------------------------------------------------

test("__index",function()

    local mt={
        __index=function()
            return 123
        end
    }

    local t=setmetatable({},mt)

    assert_eq(t.x,123)
end)

test("__newindex",function()

    local hit=false

    local mt={
        __newindex=function()
            hit=true
        end
    }

    local t=setmetatable({},mt)

    t.x=1

    assert_eq(hit,true)
end)

test("__call",function()

    local mt={
        __call=function()
            return 555
        end
    }

    local t=setmetatable({},mt)

    assert_eq(t(),555)
end)

test("__add",function()

    local mt={
        __add=function()
            return 777
        end
    }

    local t=setmetatable({},mt)

    assert_eq(t+t,777)
end)

test("__concat",function()

    local mt={
        __concat=function()
            return "ok"
        end
    }

    local t=setmetatable({},mt)

    assert_eq(t..t,"ok")
end)

--------------------------------------------------
-- ERROR
--------------------------------------------------

test("pcall",function()

    local ok=pcall(function()
        error("x")
    end)

    assert_eq(ok,false)
end)

test("xpcall",function()

    local ok=xpcall(
        function()
            error("x")
        end,
        function()
            return true
        end
    )

    assert_eq(ok,false)
end)

--------------------------------------------------
-- COROUTINE
--------------------------------------------------

test("Coroutine",function()

    local co=coroutine.create(function()
        return 10
    end)

    local ok,v=coroutine.resume(co)

    assert_eq(ok,true)
    assert_eq(v,10)
end)

test("CoroutineYield",function()

    local co=coroutine.create(function()

        coroutine.yield(1)
        coroutine.yield(2)

        return 3
    end)

    local _,a=coroutine.resume(co)
    local _,b=coroutine.resume(co)
    local _,c=coroutine.resume(co)

    assert_eq(a,1)
    assert_eq(b,2)
    assert_eq(c,3)
end)

--------------------------------------------------
-- RESULT
--------------------------------------------------

print("")
print("================================")
print(" TOTAL TESTS : "..TOTAL)
print(" ALL TESTS PASSED SUCCESSFULLY ")
print("================================")