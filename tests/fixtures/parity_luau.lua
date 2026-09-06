-- Typed event/data pipeline; output ordering is explicit, never pairs order.
type Event<T> ={name:string,value:T}
type function Identity(kind)return kind end
local events:{Event<number>}={}
@native
local function push<T>(value:T):T return value end
for index=1,8 do
    if index%2==0 then continue end
    events[#events+1]={name=`event-{index}`,value=push<<number>>(index*3)}
end
local total=0 local labels={}
for index,event in events do
    total+=event.value//2
    labels[index]=`{event.name}:{if event.value>10 then 'high' else 'low'}`
end
print('typed',total,table.concat(labels,','))

local Counted={}
Counted.__index=Counted
function Counted:read<T>(value:T):T self.calls+=1 return value end
local object=setmetatable({calls=0},Counted)
print('generic-method',object:read<<number>>(42),object.calls)

local callable=setmetatable({count=0},{__call=function(self,state,control)
    self.count+=1
    if self.count<=3 then return self.count,state*self.count,nil end
end})
local sum=0 for key,value,empty in callable,7 do assert(empty==nil)sum+=key+value end
print('callable-iterator',sum,callable.count)

local disabled=false local n=0
repeat
    n+=1
    if disabled or 2<1 then continue end
    local ready=n>=3
until ready
print('reachability',n)

local function factory(value)
    local function identity()return 23 end
    return function()
        type Erased=typeof(value)
        if false then return value end
        return identity()
    end
end
local a,b=factory('one'),factory('two')
print('closure-identity',a==b,a(),b())
local integerValue=9007199254740993i
print('integer',tostring(integer.add(integerValue,2i)))
print('parity:luau:ok')
