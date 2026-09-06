//! Native differential acceptance suite. These are deterministic supported
//! programs, not an assertion of universal Lua/executor compatibility.
mod support;
use obf::{bytecode::custom as bc, ir, vm, Target};
use std::fs;
use support::{compile, compile_and_run, Workspace};

fn differential(source: &str, target: Target) {
    let work = Workspace::new();
    let path = work.0.join("subject.lua");
    fs::write(&path, source).unwrap();
    let expected = compile_and_run(target, &path);
    let bytes = vm::custom::compile(source, target).unwrap();
    let program = bc::decode(&bytes, target).unwrap();
    assert_eq!(bc::serialize(&program).unwrap(), bytes);
    assert_eq!(program.isa_version, bc::ISA_VERSION);
    for seed in [0, 735, u64::MAX] {
        let output = vm::custom::emit(&bytes, target, seed).unwrap();
        assert_eq!(output, vm::custom::emit(&bytes, target, seed).unwrap());
        assert!(!output.contains(['\n', '\r']));
        fs::write(&path, output).unwrap();
        let actual = compile_and_run(target, &path);
        assert_eq!(
            String::from_utf8_lossy(&actual),
            String::from_utf8_lossy(&expected),
            "{target}, seed {seed}\n{source}"
        );
        assert_eq!(actual, expected, "compare bytes, not only lossy UTF-8");
    }
}

fn cases(items: &[(String, String)]) -> String {
    let mut source = String::new();
    for (index, (label, body)) in items.iter().enumerate() {
        // Each case has its own scope and reports status without comparing
        // implementation-specific source locations in host error strings.
        source.push_str(&format!("do local function probe()\n{body}\nend print('case:{index}:{label}');local ok=pcall(probe);print('ok',ok)end\n"));
    }
    source
}

#[test]
fn application_style_parsing_events_data_processing_and_coroutines() {
    for target in [Target::Lua51, Target::Luau] {
        differential(include_str!("fixtures/parity_common.lua"), target);
    }
    differential(include_str!("fixtures/parity_luau.lua"), Target::Luau);
}

#[test]
fn target_closure_identity_including_recursion_constants_and_loop_captures() {
    let source = r#"
        local root=7
        local function empty()return function()return 1 end end
        local function top()return function()return root end end
        local function parameter(v)return function()return v end end
        local function constant()local value='constant' return function()return value end end
        local function chain()local function first()return 2 end return function()return first()end end
        local function recursive()local function self(n)if n>0 then return self(n-1)end return 3 end return self end
        local factories={empty,top,parameter,constant,chain,recursive}
        for _,make in ipairs(factories)do local a,b=make(4),make(4)print(a==b,rawequal(a,b),a(2),b(3))end
        local mutable=1 local function make()return function(delta)mutable=mutable+delta return mutable end end
        local a,b=make(),make()print(a==b,a(1),b(2))
        local closures={} for i=1,3 do closures[i]=function()return i end end
        print(closures[1]==closures[2],closures[1](),closures[2](),closures[3]())
        local function grouped()local identity=(function()return 5 end) return function()return identity()end end
        print(grouped()==grouped())
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target);
    }
}

#[test]
fn erased_types_dead_branches_and_transitive_captures_use_runtime_bindings_only() {
    let source = r#"
        local function factory(parameter)
            return function()
                type First=typeof(parameter)
                return function()
                    type Second=typeof(parameter)
                    if false then return parameter end
                    return if true then 7 else parameter
                end
            end
        end
        local a,b=factory(1),factory(2)
        local c,d=a(),b()
        print(a==b,c==d,c(),d())
        local function live(parameter)
            return function()return function(delta)parameter+=delta return parameter end end
        end
        local first,second=live(1)(),live(10)()
        print(first==second,first(2),second(3),first(4))
    "#;
    differential(source, Target::Luau);
    let module = ir::compile(source, Target::Luau).unwrap();
    // Factory and its two nested closures no longer capture type-only values.
    assert!(module.functions[2].captures.is_empty());
    assert!(module.functions[3].captures.is_empty());
    assert!(module.functions.iter().any(|f| !f.captures.is_empty()));
}

#[test]
fn luau_iterators_use_raw_metamethods_callable_fallback_and_exact_arity() {
    differential(
        r#"
        local count=0 local callable=setmetatable({}, {__call=function(self,state,control)
            count+=1 if count<=3 then return count,state+count,nil end end})
        local total=0 for key,value,empty in callable,10 do assert(empty==nil)total+=key+value end
        print(count,total)
        local meta=setmetatable({}, {__index=function()error('metamethod lookup must be raw')end})
        local total=0 for key,value in setmetatable({11,22},meta)do total+=key+value end print(total)
        local proxy=newproxy(true) local index=0
        getmetatable(proxy).__call=function(self,state,control)index+=1 if index<3 then return index,state end end
        for key,value in proxy,'state' do print(key,value)end
        local iter=setmetatable({}, {__call=function(_,t)return ipairs(t)end})
        for key,value in setmetatable({3,4},{__iter=iter,__call=function()error('wrong fallback')end})do print(key,value)end
        for _,method in ipairs({false,7})do
            local ok=pcall(function()for key,value in setmetatable({1},{__iter=method})do error('unexpected body')end end)
            print(ok)
        end
        local ok=pcall(function()for key in setmetatable({},{__iter=function()return nil end})do end end)print(ok)
        local function booleanKeys(_,control)if control==nil then return false,2 elseif control==false then return true,3 end end
        for key,value in booleanKeys do print(key,value)end
    "#,
        Target::Luau,
    );
}

#[test]
fn luau_repeat_continue_prunes_only_proven_dead_paths_and_still_rejects_skips() {
    for condition in ["false", "not true", "1==2", "nil", "never", "never or 2<1"] {
        differential(&format!("local never=false local n=0 repeat n+=1 if {condition} then continue end local x=n until x>=3 print(n)"),Target::Luau);
    }
    differential(
        r#"
        local n=0 repeat n+=1 if true then break end local x=99 until x>3 print(n)
        local function choose(x)
            if x then return 1 else return 2 end
            local dead=99 while true do dead+=1 end
        end
        print(choose(true),choose(false))
        local touched=0 local function effect()touched+=1 return false end
        repeat touched+=1 if false and effect() then continue end local x=touched until x==3
        if true or effect()then print(touched)end
    "#,
        Target::Luau,
    );
    let work = Workspace::new();
    let path = work.0.join("invalid.luau");
    for condition in ["true", "0", "''"] {
        let source = format!("repeat if {condition} then continue end local x=1 until x==1");
        fs::write(&path, &source).unwrap();
        assert!(!compile(Target::Luau, &path).status.success());
        assert!(vm::custom::compile(&source, Target::Luau)
            .unwrap_err()
            .message
            .contains("skip a local initialization"));
    }
}

#[test]
fn generated_operator_assignment_and_loop_evaluation_order_matrix() {
    let mut items = Vec::new();
    for op in [
        "+", "-", "*", "/", "%", "^", "<", "<=", ">", ">=", "==", "~=", "..",
    ] {
        for left in ["x", "(x)", "t[k]", "t.x", "get()"] {
            items.push((
                format!("operand-{op}-{left}"),
                format!(
                    r#"
                local x=2 local k=1 local t={{[1]=2,x=2}} local function get()return x end
                local function mutate()x=7 k=2 t[1]=9 t.x=9 return 3 end
                print({left} {op} mutate(),x,k,t[1],t.x)
            "#
                ),
            ));
        }
    }
    for lhs in [
        "x,y",
        "y,x",
        "t.x,x",
        "x,t.x",
        "t[k],k",
        "k,t[k]",
        "t[k],t.x",
        "x,t[k],y",
        "t[x],x,t[y],y",
        "x,x,t[x]",
        "t[x],t[x],x",
        "t,t.x",
    ] {
        for values in [
            "mutate(),read(),x,y",
            "1,mutate(),read(),x",
            "x,mutate(),read(),y",
            "1,(function()return x,y end)()",
        ] {
            items.push((format!("assignment-{lhs}"),format!(r#"
                local x,y,k=1,2,1 local t={{x=3}} local old=t
                local function mutate()x=4 y=5 k=2 return 7,8,9,10 end local function read()return x end
                {lhs}={values}
                print(x,y,k,type(t),old.x,old[1],old[2],old[4],old[5])
            "#)));
        }
    }
    for (index, spec) in [
        "'1','3','1'",
        "1,3,0",
        "1,3,0/0",
        "3,1,0/0",
        "0/0,3,1",
        "1,0/0,1",
        "-1/0,1/0,1/0",
        "-0,0,0",
    ]
    .iter()
    .enumerate()
    {
        items.push((
            format!("numeric-for-{index}"),
            format!(
                "local n=0 for i={spec} do n=n+1 print(i,1/i) if n==3 then break end end print(n)"
            ),
        ));
    }
    assert_eq!(items.len(), 121);
    for target in [Target::Lua51, Target::Luau] {
        differential(&cases(&items), target);
    }
}

#[test]
fn luau_compound_assignment_evaluates_base_key_and_rhs_at_target_times() {
    let mut items = Vec::new();
    for left in ["x", "t.x", "t[k]"] {
        for op in ["+=", "-=", "*=", "/=", "%=", "^=", "..=", "//="] {
            items.push((format!("compound-{left}-{op}"),format!("local x=4 local k=1 local t={{[1]=8,x=8}} local function mutate()x=10 k=2 t[1]=16 t.x=16 return 2 end {left}{op}mutate() print(x,k,t[1],t[2],t.x)")));
        }
    }
    assert_eq!(items.len(), 24);
    differential(&cases(&items), Target::Luau);
}

#[test]
fn multret_nil_holes_large_packs_and_callback_results_preserve_arity() {
    let source = r#"
        local function pack(...)return {n=select('#',...),...}end
        local function many()return 1,nil,3,nil end
        local function none()end
        local function show(...)local p=pack(...)print(p.n,p[1],p[2],p[3],p[4],p[5])end
        show(none()) show(many()) show((many())) show(7,many()) show(many(),7)
        show(true and many()) show(false or many())
        local a,b,c,d,e=many() show(a,b,c,d,e)
        local data={} for i=1,1000 do if i%2==1 then data[i]=i end end
        local function relay(...)return select('#',...),select(999,...)end
        print(relay(unpack(data,1,1000)))
        local callback=function(...)return many(),... end show(callback(7,nil,8))
        local a={1,many()} print(a[1],a[2],a[3],a[4],a[5])
        local marker={} local ok,value=pcall(function()error(marker)end)print(ok,value==marker)
        show(pcall(function()return many()end))
        print(pcall(error,'exact user message',0))
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target);
    }
}

#[test]
fn arithmetic_comparison_concat_index_and_tostring_metamethod_effects_match() {
    let source = r#"
        local trace='' local function record(s)trace=trace..s..';'end
        local mt={}
        mt.__tostring=function(a)return a.name end
        mt.__add=function(a,b)record('add:'..tostring(a)..':'..tostring(b))return a.value+b.value end
        mt.__lt=function(a,b)record('lt:'..tostring(a)..':'..tostring(b))return a.value<b.value end
        mt.__le=function(a,b)record('le:'..tostring(a)..':'..tostring(b))return a.value<=b.value end
        mt.__eq=function(a,b)record('eq')return a.value==b.value end
        mt.__concat=function(a,b)record('concat:'..tostring(a)..':'..tostring(b))return '('..tostring(a)..tostring(b)..')'end
        local a=setmetatable({name='A',value=1},mt) local b=setmetatable({name='B',value=2},mt)
        print(a+b,a<b,a<=b,a>b,a>=b,a==b,a~=b,a..b..'x'..3)
        print(trace)
        local writes={} local proxy=setmetatable({},{__newindex=function(_,k,v)writes[#writes+1]=k..'='..v end,
            __index=function(_,k)return 'value:'..k end})
        proxy.one,proxy.two=1,2 print(proxy.key,table.concat(writes,','))
        local x='a' local change=setmetatable({},{__concat=function()x='z' return 'c'end})
        print(x..change..change,x)
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target);
    }
}

#[test]
fn module_return_values_live_exports_and_external_calls_match() {
    for target in [Target::Lua51, Target::Luau] {
        let work = Workspace::new();
        let module = work.0.join("subject.lua");
        let main = work.0.join("main.lua");
        let source="local state=0 return {step=function(delta)state=state+delta return state,nil,7 end,read=function()return state end}";
        let loader = if target == Target::Lua51 {
            format!("assert(loadfile({:?}))()", module.to_str().unwrap())
        } else {
            "require('./subject')".to_string()
        };
        fs::write(
            &main,
            format!("local m={loader} print(m.step(2)) print(m.step(3)) print(m.read())"),
        )
        .unwrap();
        fs::write(&module, source).unwrap();
        let expected = compile_and_run(target, &main);
        for seed in [0, 735] {
            fs::write(
                &module,
                vm::custom::virtualize(source, target, seed).unwrap(),
            )
            .unwrap();
            assert_eq!(compile_and_run(target, &main), expected);
        }
    }
    let work = Workspace::new();
    let module = work.0.join("subject.luau");
    let main = work.0.join("main.luau");
    let source="export local total=1 total+=2 export function read()return total,nil,9 end export function write(v)total=v end";
    fs::write(&main,"local m=require('./subject') print(table.isfrozen(m),m.total) print(m.read()) local ok=pcall(m.write,7)print(ok,m.total)").unwrap();
    fs::write(&module, source).unwrap();
    let expected = compile_and_run(Target::Luau, &main);
    fs::write(
        &module,
        vm::custom::virtualize(source, Target::Luau, 735).unwrap(),
    )
    .unwrap();
    assert_eq!(compile_and_run(Target::Luau, &main), expected);
}

#[test]
fn legacy_isa1_bytecode_still_executes_and_cli_reports_the_actual_revision() {
    use std::process::Command;
    let work = Workspace::new();
    for target in [Target::Lua51, Target::Luau] {
        let data =
            vm::custom::compile("local function f(x)return x+1 end print(f(2))", target).unwrap();
        let mut program = bc::decode(&data, target).unwrap();
        program.isa_version = 1;
        for p in &mut program.prototypes {
            p.flags &= 7;
        }
        let legacy = bc::serialize(&program).unwrap();
        let file = work.0.join("legacy.obf");
        fs::write(&file, &legacy).unwrap();
        let inspection = Command::new(env!("CARGO_BIN_EXE_obf"))
            .args(["inspect-bytecode", "--target", &target.to_string()])
            .arg(&file)
            .output()
            .unwrap();
        assert!(inspection.status.success());
        assert!(String::from_utf8(inspection.stdout)
            .unwrap()
            .contains("isa-version: 1\n"));
        let path = work.0.join("legacy.lua");
        fs::write(&path, vm::custom::emit(&legacy, target, 735).unwrap()).unwrap();
        assert_eq!(compile_and_run(target, &path), b"3\n");
    }
}

#[test]
fn constant_analysis_preserves_signed_zero_truthiness_and_integer_runtime_errors() {
    let source = r#"
        local function a()local n=-0 print(1/n,1/0,1/-0)end
        local function b()local n=0 print(1/n,1/-0,1/0)end
        local function c()local n=1-1 print(1/n,1/-0)end
        local function d()local n=-(1-1) print(1/n,1/0)end
        a() b() c() d()
        local values={false,0,'',3}
        for _,value in ipairs(values)do print(not value,value and 'yes' or 'no')end
        local counter=0 local function effect()counter=counter+1 return false end
        local a=false and effect() local b=true or effect() local c=effect()and false
        print(a,b,c,counter)
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target);
    }
    differential(
        r#"
        local i=1i local ok=pcall(function()return -i end)print(ok,tostring(-1i))
        local function make()local i=1i return function()return i end end
        print(make()==make())
        local function branch()local no=false return function(parameter)return if no then parameter else 7 end end
        local a,b=branch(),branch() print(a==b,a(1),b(2))
    "#,
        Target::Luau,
    );
}

#[test]
fn luau_constant_capture_policy_matches_arithmetic_strings_if_expressions_and_integers() {
    let mut source = String::new();
    for (index, expr) in [
        "0/0",
        "1/0",
        "'a'..'b'",
        "1+2*3",
        "'a'<'b'",
        "#'hello'",
        "if true then 7 else 8",
        "false or 17",
        "math.abs(-7)",
        "1i",
        "-1i",
    ]
    .iter()
    .enumerate()
    {
        source.push_str(&format!("do local function make()local value={expr} return function()return value end end local a,b=make(),make()print({index},a==b,a(),b())end\n"));
    }
    differential(&source, Target::Luau);
}
