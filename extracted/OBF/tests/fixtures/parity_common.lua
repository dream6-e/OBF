-- Deterministic application-like corpus: parsing, data processing, closures,
-- error objects, callback replacement, methods and an explicit coroutine queue.
local function evaluate(text, variables)
    local at=1
    local function skip() local _,last=string.find(text,'^%s*',at) at=(last or at-1)+1 end
    local expression,term,atom
    atom=function()
        skip()
        local ch=string.sub(text,at,at)
        if ch=='(' then at=at+1 local value=expression() skip() assert(string.sub(text,at,at)==')') at=at+1 return value end
        if ch=='-' then at=at+1 return -atom() end
        local first,last=string.find(text,'^%d+',at)
        if first then local value=tonumber(string.sub(text,first,last)) at=last+1 return value end
        first,last=string.find(text,'^%a+',at)
        assert(first,'operand') local name=string.sub(text,first,last) at=last+1
        return assert(variables[name],name)
    end
    term=function()
        local value=atom()
        while true do skip() local op=string.sub(text,at,at)
            if op~='*' and op~='/' then break end
            at=at+1 local right=atom() if op=='*' then value=value*right else value=value/right end
        end
        return value
    end
    expression=function()
        local value=term()
        while true do skip() local op=string.sub(text,at,at)
            if op~='+' and op~='-' then break end
            at=at+1 local right=term() if op=='+' then value=value+right else value=value-right end
        end
        return value
    end
    local value=expression() skip() assert(at>#text) return value
end
print('parse',evaluate(' (alpha + 3) * (beta - 2) - -4 ',{alpha=7,beta=8}))

local records={}
for word in string.gmatch('pear apple pear orange apple pear','%a+') do records[word]=(records[word] or 0)+1 end
local keys={} for key in pairs(records) do keys[#keys+1]=key end table.sort(keys)
local fields={} for _,key in ipairs(keys) do fields[#fields+1]=key..'='..records[key] end
print('words',table.concat(fields,','))

local Account={}
Account.__index=Account
function Account:new(value)return setmetatable({value=value,history={}},self)end
function Account:change(delta)self.value=self.value+delta self.history[#self.history+1]=delta return self end
function Account:report()return self.value,table.concat(self.history,',')end
local first=Account:new(10) local second=Account:new(100)
local pending={}
for index=1,5 do
    local amount=index*2
    pending[index]=function()first:change(amount) second:change(-amount)end
end
for _,apply in ipairs(pending) do apply() end
print('accounts',first:report()) print('transfer',second:report())

local listeners={}
local function subscribe(callback)
    local active=true listeners[#listeners+1]=function(...)if active then return callback(...) end end
    return function()active=false end
end
local events={}
local disconnect=subscribe(function(a,b)events[#events+1]=a..':'..tostring(b)end)
local function fire(...)for _,listener in ipairs(listeners)do listener(...)end end
fire('one',nil) fire('two',3) disconnect() fire('ignored',7)
print('events',table.concat(events,','))

local object={tag='error-object'}
local function fail()error(object)end
local ok,result=xpcall(fail,function(value)return {original=value,tag=value.tag}end)
assert(not ok and result.original==object) print('protected',ok,result.tag)
local function packed(...)return {n=select('#',...),...}end
local thread=coroutine.create(function(start)
    for index=1,3 do start=coroutine.yield(index,start,nil)end
    return 'done',start,nil
end)
for index=1,4 do local values=packed(coroutine.resume(thread,index*10)) print('queue',values.n,values[1],values[2],values[3],values[4])end
print('status',coroutine.status(thread))

local function pipeline(value,...)
    local arguments=packed(...)
    return function(callback)return callback(value,unpack(arguments,1,arguments.n))end
end
local invoke=pipeline(5,nil,7,nil)
invoke(function(...)local p=packed(...)assert(p.n==4 and p[2]==nil and p[4]==nil)print('pack',p.n,p[1],p[3])end)
print('parity:common:ok')
