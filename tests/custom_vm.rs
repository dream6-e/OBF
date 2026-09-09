mod support;
use obf::{vm, Target};
use std::fs;
use support::{compile_and_run, Workspace};

fn differential(source: &str, target: Target) {
    let workspace = Workspace::new();
    let path = workspace.0.join("run.lua");
    fs::write(&path, source).unwrap();
    let expected = compile_and_run(target, &path);
    let ir = obf::ir::compile(source, target).unwrap();
    let bytes = obf::bytecode::custom::encode(&ir).unwrap();
    let decoded = obf::bytecode::custom::decode(&bytes, target).unwrap();
    assert_eq!(obf::bytecode::custom::serialize(&decoded).unwrap(), bytes);
    for seed in [0, 735, u64::MAX] {
        let generated = vm::custom::emit(&bytes, target, seed).unwrap();
        assert!(!generated.contains(['\r', '\n']));
        fs::write(&path, &generated).unwrap();
        assert_eq!(
            expected,
            compile_and_run(target, &path),
            "{target} seed={seed}\n{source}"
        );
    }
}

#[test]
fn basic_ast_ir_bytecode_register_vm_executes_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        differential(
            "local x=1 local y=2 local function add(a,b)return a+b end print(add(x,y))",
            target,
        );
    }
}

#[test]
fn register_abi_preserves_cells_captures_callbacks_loops_and_tailcalls() {
    let common = r#"
        local function make(seed)
            local cell=seed
            return function(delta,callback)
                local before=cell
                cell=cell+delta
                return callback(before,cell)
            end
        end
        local function callback(a,b)return a*100+b end
        local function tailcall(fn,value,cb)return fn(value,cb)end
        local fn=make(10)
        local total=0
        for i=1,5 do total=total+i end
        do local cleared1,cleared2,cleared3=1,2,3 total=total+cleared1+cleared2+cleared3 end
        print(tailcall(fn,2,callback),tailcall(fn,3,callback),total)
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(common, target);
    }
    differential(
        r#"
        local function legacy(a,...)
            local first,n=arg[1],arg.n
            return function()return a,first,n end
        end
        local read=legacy(9,'x',nil,'z') print(read())
        "#,
        Target::Lua51,
    );
    differential(
        r#"
        local function modern(a,...)
            local rest={...} local n=select('#',...)
            return function()return a,rest[1],n end
        end
        local read=modern(9,'x',nil,'z') print(read())
        "#,
        Target::Luau,
    );
}

#[test]
fn fused_dataflow_preserves_nil_false_aliasing_metamethods_and_errors() {
    let source = r#"
        local function truth(v)
            local first=v
            local second=not first
            local third=not second
            return first,second,third
        end
        local a,b,c=truth(nil) print('nil',a,b,c)
        local d,e,f=truth(false) print('false',d,e,f)

        local tableValue={value=4}
        local alias=tableValue
        alias.value=alias.value+3
        local copied=alias
        print('alias',tableValue.value,copied==tableValue)

        local events=''
        local mt={}
        mt.__add=function(left,right)
            events=events..left.value..':'..right.value..';'
            return setmetatable({value=left.value+right.value},mt)
        end
        local left=setmetatable({value=2},mt)
        local middle=left+setmetatable({value=3},mt)
        local result=middle+setmetatable({value=5},mt)
        print('meta',result.value,events)

        local state=10
        local function bump()state=state+1 return state end
        local ordered=state+bump()
        print('order',ordered,state)

        local function capture(value)
            return function(nextValue)
                local before=value
                value=nextValue
                return before,not value
            end
        end
        local closure=capture(false)
        print('cell',closure(nil))
        print('cell',closure(false))

        local ok=pcall(function()
            local bad=nil
            local forwarded=bad
            return forwarded+1
        end)
        print('error',ok)
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target);
    }
}

#[test]
fn existing_full_vm_corpora_execute_without_native_compilation() {
    differential(include_str!("fixtures/vm_lua51.lua"), Target::Lua51);
    differential(include_str!("fixtures/vm_luau.lua"), Target::Luau);
}

#[test]
fn ast_and_scope_corpora_run_through_ir_including_legacy_arg_and_luau_types() {
    for (source, target) in [
        (include_str!("fixtures/lua51.lua"), Target::Lua51),
        (include_str!("fixtures/luau.lua"), Target::Luau),
        (include_str!("fixtures/ast_lua51.lua"), Target::Lua51),
        (include_str!("fixtures/ast_luau.lua"), Target::Luau),
        (include_str!("fixtures/scope_lua51.lua"), Target::Lua51),
        (include_str!("fixtures/scope_luau.lua"), Target::Luau),
    ] {
        differential(source, target);
    }
}

#[test]
fn assignment_conflicts_operand_lifetimes_and_method_lookup_match_each_target() {
    let source = r#"
    local x=0 x,x=1,2 print('duplicate',x)
    local t={} local k=1 k,t[k]=2,5 print('conflict',t[1],t[2])
    t={} k=1 t[k],k=5,2 print('reverse',t[1],t[2])
    t={} local saved=t t,t.x={},5 print('base',saved.x,t.x)
    t={} saved=t t.x,t=5,{} print('base-reverse',saved.x,t.x)
    local first={v=1} local second={v=2} local object=first
    local function change()object=second return 5 end
    object.v=change() print('late-base',first.v,second.v)
    t={} k=1 local function key()k=2 return 5 end
    t[k]=key() print('late-key',t[1],t[2])
    x=1 local function mutate()x=10 return 2 end
    print('binary',x+mutate())
    x=1 local function read()return x end
    local y x,y=4,read() print('early-local',x,y)
    x=1 x,y=4,(function()return x end)() print('syntactic',x,y)
    local methodObject={m=function()return 1 end}
    local function replaceMethod()methodObject.m=function()return 2 end return nil end
    print('method',methodObject:m(replaceMethod()))
    local other={m=function(self)return self.value end,value=99}
    methodObject={m=function()return 1 end}
    local function replaceObject()methodObject=other return nil end
    print('receiver',methodObject:m(replaceObject()))
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target);
    }
    differential(
        r#"
        local a={x=1} local b={x=2} local t=a
        local function move()t=b return 5 end
        t.x+=move() print(a.x,b.x)
        local n=1 local function change()n=10 return 2 end n+=change() print(n)
    "#,
        Target::Luau,
    );
}

#[test]
fn mixed_table_flush_order_and_multret_nil_holes_match_reference() {
    let lists = (1..=105)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        r#"
        local function many()return 7,nil,9,nil end
        local a={{1,[1]=100}} local b={{[1]=100,1}}
        local large={{{lists},[50]=-50,[100]=-100,many()}}
        print(a[1],b[1],large[50],large[100],large[106],large[107],large[108],large[109])
        local function count(...)return select('#',...),... end
        local x,y,z,w=count(many()) print(x,y,z,w)
        print(count((many()))) print(count(1,many()))
        local t={{many()}} print(t[1],t[3],t[4])
        local effects='' local function one(s)effects=effects..s return s end
        local item=one('a'),one('b'),one('c') print(item,effects)
    "#
    );
    for target in [Target::Lua51, Target::Luau] {
        differential(&source, target);
    }
}

#[test]
fn lua51_hexadecimal_double_rounding_and_ieee_edges_are_preserved() {
    differential(
        r#"
        local function show(n)print(string.format('%.17g',n),1/n)end
        show(0x1000000000000081) show(0x1000000000000080) show(0x1000000000000180)
        show(4.9406564584124654e-324) show(2.4703282292062327e-324)
        show(1.7976931348623157e308) show(0x1p1024)
        show(0x0p999999999) show(0x1p1023)
        show(0x100000000000000001) show(0x100000000000000081)
        show(-0) show(5e-324) show(1e309)
        local function truth_only()if 0 then return 1/-0 end end
        local function first_negative()return 1/-0,1/0 end
        local function folded_positive()local zero=1-1 return zero,1/-0 end
        print(truth_only()) print(first_negative()) print(folded_positive())
    "#,
        Target::Lua51,
    );
}

#[test]
fn luau_integer_constants_are_exact_and_not_float_coercions() {
    differential(
        r#"
        local values={0i,1i,-1i,9007199254740993i,9223372036854775807i,
            0xffffffffffffffffi,0x8000000000000000i,0b101010i}
        for _,v in ipairs(values)do print(typeof(v),tostring(v))end
        print(integer.add(values[4],1i),integer.neg(values[2]))
        print(pcall(function()local v=values[2] return -v end))
    "#
        .replace(
            "print(pcall(function()local v=values[2] return -v end))",
            "local ok=pcall(function()local v=values[2] return -v end) print(ok)",
        )
        .as_str(),
        Target::Luau,
    );
    assert!(vm::custom::compile("return 9223372036854775808i", Target::Luau).is_err());
}

#[test]
fn escaping_loop_cells_break_continue_and_repeat_condition_remain_live() {
    let common = r#"
        local closures={} local total=0
        for i=1,4 do
            local held=i*10
            closures[i]=function(delta) held=held+delta return i,held end
            if i==3 then break end
        end
        for i=1,3 do print(closures[i](1)) end
        local n=0
        repeat
            local held=n+1
            n=held
            closures[n]=function()return held end
        until held==3
        print(closures[1](),closures[2](),closures[3](),held==nil)
        local iterator=function(state,control)
            if control==nil then return false,2 elseif control==false then return true,3 end
        end
        for control,value in iterator do total=total+value print(control,value)end
        for i='3','1','-1' do total=total+i end
        for i=1,3,0 do error('zero step should not enter') end
        print(total)
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(common, target);
    }
    differential(
        r#"
        local saved={} local n=0
        repeat
            n+=1 local held=n
            if n<3 then
                local inner=held*10
                saved[n]=function()return held,inner end
                continue
            end
        until held>=3
        print(saved[1](),saved[2](),n,held==nil)
        local total=0
        for i=1,6 do if i%2==0 then continue end total+=i end
        while n>0 do n-=1 if n>0 then continue end total+=10 end
        repeat n+=1 if n==1 then continue end local unused=7 until n>=2
        print(total,n)
    "#,
        Target::Luau,
    );
    let bad = "repeat if true then continue end local x=1 until x==1";
    let error = vm::custom::compile(bad, Target::Luau).unwrap_err();
    assert!(error.message.contains("skip a local initialization"));
}

#[test]
fn tail_calls_do_not_consume_interpreter_frames() {
    let source = r#"
        local odd,even
        even=function(n,total)if n==0 then return total,nil,9 end return odd(n-1,total+1)end
        odd=function(n,total)if n==0 then return total,nil,9 end return even(n-1,total+1)end
        local value,empty,last=even(20000,0)
        assert(value==20000 and empty==nil and last==9)
        print('tail:ok')
    "#;
    differential(source, Target::Lua51);
    // Luau does not promise native proper-tail-call elimination. The custom
    // ISA explicitly does; compare with an iterative oracle on that target.
    let workspace = Workspace::new();
    let path = workspace.0.join("tail.luau");
    let output = vm::custom::virtualize(source, Target::Luau, 735).unwrap();
    fs::write(&path, output).unwrap();
    assert_eq!(compile_and_run(Target::Luau, &path), b"tail:ok\n");
}

#[test]
fn native_callbacks_coroutines_callable_tables_and_error_objects_work() {
    let source = r#"
        local marker={} local ok,result=pcall(function()error(marker)end)
        assert(not ok and result==marker)
        local callable=setmetatable({offset=5},{__call=function(self,n)return self.offset+n,nil,7 end})
        print(callable(3))
        local co=coroutine.create(function(start)
            local resumed=coroutine.yield(start+1,nil,3)
            return resumed*2,nil,5
        end)
        local ok,a,b,c=coroutine.resume(co,10) print(ok,a,b,c)
        ok,a,b,c=coroutine.resume(co,7) print(ok,a,b,c,coroutine.status(co))
        local values={4,1,3,2} table.sort(values,function(a,b)return a<b end)
        print(table.concat(values,','))
    "#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target);
    }
}

#[test]
fn luau_generalized_iterators_interpolation_order_and_userdata_namecall() {
    differential(
        r#"
        local iterable=setmetatable({10,20},{__iter=function(t)
            local index=0
            return function()index+=1 if t[index]~=nil then return index,t[index],index*2 end end
        end})
        local total=0 for i,v,extra in iterable do total+=i+v+extra end print(total)
        local trace='' local meta={__tostring=function()trace..='T' return 'x' end}
        local function value()trace..='V' return setmetatable({},meta)end
        local result=`a{value()}b{value()}` print(result,trace)
        local saved=tostring tostring=function()return 'wrong'end
        local interpolation=`{42}` tostring=saved print(interpolation)
        local proxy=newproxy(true)
        getmetatable(proxy).__namecall=function(self,first,...)
            assert(self==proxy) return first,select('#',...),...
        end
        print(proxy:probe(7,nil,9))
    "#,
        Target::Luau,
    );
}

#[test]
fn exported_modules_are_frozen_and_preserve_live_binding_reads() {
    for source in [
        "export local value=1 value=2 export const constant=9 export function read()return value,constant end",
        "export type Answer=number",
        "export type Answer=number return {value=7}",
    ]{
        let workspace=Workspace::new();let module=workspace.0.join("subject.luau");
        let main=workspace.0.join("main.luau");
        fs::write(&main,r#"
            local m=require('./subject')
            print(type(m),table.isfrozen(m),m.value,m.constant)
            if m.read then print(m.read())end
            local ok=pcall(function()m.value=33 end) print(ok)
        "#).unwrap();
        fs::write(&module,source).unwrap();let expected=compile_and_run(Target::Luau,&main);
        fs::write(&module,vm::custom::virtualize(source,Target::Luau,735).unwrap()).unwrap();
        assert_eq!(compile_and_run(Target::Luau,&main),expected);
    }
}

#[test]
fn closed_cells_and_recursive_function_descriptors_do_not_pin_gc_objects() {
    differential(
        r#"
        local finalized=0
        do
            local proxy=newproxy(true)
            getmetatable(proxy).__gc=function()finalized=finalized+1 end
        end
        collectgarbage('collect') collectgarbage('collect')
        assert(finalized==1)
        local weak=setmetatable({},{__mode='v'})
        do local function recursive(n)if n>0 then return recursive(n-1)end end weak[1]=recursive end
        collectgarbage('collect') collectgarbage('collect')
        print(finalized,weak[1]==nil)
    "#,
        Target::Lua51,
    );
}

#[test]
fn generated_programs_preserve_shadowing_assignments_and_control_flow() {
    for target in [Target::Lua51, Target::Luau] {
        for n in 0..16 {
            let source = format!(
                r#"
                local x={n} local y=3 local tableValue={{}}
                local function bump(v) x=x+v return x,nil,v end
                local function reader()return x end
                do local x=x+2 tableValue[1]=function()return x end end
                x,y=y,x
                tableValue[x],x=y,x+1
                local a,b,c=bump(2)
                local total=0 for i=1,5 do if i%2==0 then total=total+i else total=total-i end end
                print(x,y,tableValue[1](),a,b,c,total,reader())
            "#
            );
            // Preserve the original closure key when the generated assignment
            // happens to address it; all n share the same deterministic shape.
            let source = source
                .replace("tableValue[1]=function()", "tableValue.closure=function()")
                .replace("tableValue[1]()", "tableValue.closure()");
            differential(&source, target);
        }
    }
}

#[test]
fn obvious_reflection_is_a_diagnostic_not_silent_native_fallback() {
    for target in [Target::Lua51, Target::Luau] {
        for source in [
            "return getfenv(1)",
            "return debug.getinfo(1)",
            "return loadstring('return 1')()",
        ] {
            let error = vm::custom::compile(source, target).unwrap_err();
            assert!(error.message.contains("reflective operation"));
        }
    }
}

#[test]
fn encrypted_payload_probes_fail_closed_on_tampered_environments() {
    use std::process::Command;
    for target in [Target::Lua51, Target::Luau] {
        let bytes = obf::bytecode::custom::encode(
            &obf::ir::compile("print('MUST_NOT_RUN')", target).unwrap(),
        )
        .unwrap();
        let generated = vm::custom::emit(&bytes, target, 735).unwrap();
        let workspace = Workspace::new();
        let vm_path = workspace.0.join("guarded.lua");
        fs::write(&vm_path, &generated).unwrap();
        let runner = support::root()
            .join("toolchains/bin")
            .join(if target.is_luau() { "luau" } else { "lua5.1" });
        // Environment probes, behavior-equivalent native wrappers, wrong
        // source witnesses and generated ChaCha helper tampering must all fail
        // closed before user output.
        let (tampered, wrong_witness, native_hook, control) = if target.is_luau() {
            let mut level = 1;
            while generated.contains(&format!("]{}]", "=".repeat(level))) {
                level += 1;
            }
            let fence = "=".repeat(level);
            let inline = format!("[{fence}[{generated}]{fence}]");
            (
                format!(
                    "local e=setmetatable({{}},{{__index=_G}}) e.loadstring=function()end \
                     local f=assert(loadstring({inline})) setfenv(f,e) f() print('SHOULD_NOT_RUN')"
                ),
                format!(
                    "local oi=debug.info local n=0 local d={{}} for k,v in pairs(debug)do d[k]=v end \
                     d.info=function(...)n=n+1 local v=oi(...)if n<=3 then return '[HOOK]'end return v end \
                     local e=setmetatable({{debug=d}},{{__index=_G}}) local f=assert(loadstring({inline})) \
                     setfenv(f,e) f() print('SHOULD_NOT_RUN')"
                ),
                format!(
                    "local ob=string.byte local st={{}} for k,v in pairs(string)do st[k]=v end \
                     st.byte=function(...)return ob(...)end local e=setmetatable({{string=st}},{{__index=_G}}) \
                     local f=assert(loadstring({inline})) setfenv(f,e) f() print('SHOULD_NOT_RUN')"
                ),
                format!("local f=assert(loadstring({inline})) f()"),
            )
        } else {
            let path = vm_path.to_str().unwrap();
            (
                format!(
                    "loadstring=function()end local f=assert(loadfile('{path}')) f() print('SHOULD_NOT_RUN')"
                ),
                format!(
                    "local oi=debug.getinfo local n=0 local d={{}} for k,v in pairs(debug)do d[k]=v end \
                     d.getinfo=function(...)n=n+1 local v=oi(...)if n<=3 then local c={{}} \
                     for k,x in pairs(v)do c[k]=x end c.source='=[HOOK]' return c end return v end \
                     local e=setmetatable({{debug=d}},{{__index=_G}}) local f=assert(loadfile('{path}')) \
                     setfenv(f,e) f() print('SHOULD_NOT_RUN')"
                ),
                format!(
                    "local ob=string.byte local st={{}} for k,v in pairs(string)do st[k]=v end \
                     st.byte=function(...)return ob(...)end local e=setmetatable({{string=st}},{{__index=_G}}) \
                     local f=assert(loadfile('{path}')) setfenv(f,e) f() print('SHOULD_NOT_RUN')"
                ),
                format!("local f=assert(loadfile('{path}')) f()"),
            )
        };
        // Change the generated ChaCha constant itself. The helper still has
        // plausible source metadata, but the anti-hook known-answer test must
        // reject it before either payload decrypt can expose bytes.
        let helper_tamper = generated.replacen("1634760805", "1634760806", 1);
        assert_ne!(helper_tamper, generated);
        // K7 shuffles the attestation fold terms and respells its modulus,
        // so the tamper targets the KAT comparison instead of a fixed fold
        // shape; flipping the expected word still fails the attestation.
        let wrong_attestation = generated.replacen("~=1123945486", "~=1123945487", 1);
        assert_ne!(wrong_attestation, generated);
        for (name, source, expect_success) in [
            ("control", control, true),
            ("loadstring-hook", tampered, false),
            ("wrong-witness", wrong_witness, false),
            ("native-byte-hook", native_hook, false),
            ("chacha-helper-tamper", helper_tamper, false),
            ("wrong-attestation", wrong_attestation, false),
        ] {
            let path = workspace.0.join(format!("{name}.lua"));
            fs::write(&path, source).unwrap();
            let output = Command::new(&runner).arg(&path).output().unwrap();
            assert_eq!(output.status.success(), expect_success, "{target} {name}");
            if expect_success {
                assert_eq!(output.stdout, b"MUST_NOT_RUN\n");
            } else {
                assert!(output.stdout.is_empty(), "{target} {name}");
            }
        }
    }
}

// K9a segment locators shared by the watermark and encrypted-frame
// corruption tests. Spans come from the lexer's own string tokens and are
// filtered on DECODED bytes (segments carry `\"`/`\\`/`\ddd` escapes);
// callers either identify the watermark carrier by decoding or keep the
// three longest spans, which are the payload segments.
fn segment_spans(source: &str, target: Target, seed: u64) -> Vec<(usize, usize)> {
    let alphabet = vm::custom::base86_image_alphabet(seed);
    let mut member = [false; 256];
    for &byte in &alphabet {
        member[byte as usize] = true;
    }
    let mut spans = Vec::new();
    for token in obf::lexer::lex(source, target).unwrap() {
        if token.kind != obf::lexer::TokenKind::String {
            continue;
        }
        // Segments are always `"..."`-quoted; anything else is skipped so
        // the inner-span arithmetic below stays exact.
        if !token.text(source).starts_with('"') {
            continue;
        }
        let decoded = obf::minify::literal_bytes(token.text(source), target).unwrap();
        if decoded.len() >= 12 && decoded.iter().all(|&byte| member[byte as usize]) {
            spans.push((token.span.start + 1, token.span.end - 1));
        }
    }
    spans
}

/// Decoded bytes of a raw inner span (re-adds the quotes for the parser).
fn span_bytes(source: &str, target: Target, span: (usize, usize)) -> Vec<u8> {
    obf::minify::literal_bytes(&source[span.0 - 1..span.1 + 1], target).unwrap()
}

/// Raw start offset of every decoded char: walks `\"`/`\\` (2 raw
/// chars) and `\ddd` (up to 3 digits); everything else is 1:1.
fn raw_char_map(inner: &str) -> Vec<usize> {
    let bytes = inner.as_bytes();
    let mut map = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        map.push(index);
        if bytes[index] == b'\\' {
            index += 1;
            let mut digits = 0;
            while digits < 3 && index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
                digits += 1;
            }
            if digits == 0 {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    map
}

/// Nearest image-alphabet member after `byte` (cyclic) that survives raw
/// in a literal: never 34/92/<32, so mutants stay valid Lua.
fn adjacent_plain(byte: u8, alphabet: &[u8; 86]) -> u8 {
    let pos = alphabet.iter().position(|&value| value == byte).unwrap();
    for step in 1..=86 {
        let candidate = alphabet[(pos + step) % 86];
        if candidate != 34 && candidate != 92 && candidate >= 32 {
            return candidate;
        }
    }
    unreachable!("image alphabet without plain members");
}

#[test]
fn watermark_mismatch_aborts_silently_before_any_execution() {
    use std::process::Command;
    for target in [Target::Lua51, Target::Luau] {
        let bytes = obf::bytecode::custom::encode(
            &obf::ir::compile("print('MUST_NOT_RUN')", target).unwrap(),
        )
        .unwrap();
        let generated = vm::custom::emit(&bytes, target, 735).unwrap();
        assert!(!generated.contains("XXS:"));
        // Flip the first digit of the stream-first segment's first body
        // group (decoded char 4, right after the length prefix), keeping
        // pv % 3 so the chained widths -- and every downstream byte --
        // stay identical. Only the watermark bytes change (verified by
        // re-decoding in-test), so any abort proves the watermark check
        // itself fired.
        let alphabet = vm::custom::base86_image_alphabet(735);
        let plain: Vec<u8> = alphabet
            .iter()
            .copied()
            .filter(|&byte| byte != 34 && byte != 92 && byte >= 32)
            .collect();
        let mut tampered = generated.clone();
        let mut flipped = false;
        for (start, end) in segment_spans(&generated, target, 735) {
            let text = String::from_utf8(span_bytes(&generated, target, (start, end))).unwrap();
            let Ok(decoded) = vm::custom::base86_decode_mixed(&text, &alphabet) else {
                continue;
            };
            if !decoded.starts_with(b"XXS:") {
                continue;
            }
            let map = raw_char_map(&generated[start..end]);
            let raw_at = start + map[4];
            let raw_len = map[5] - map[4];
            let original = text.as_bytes()[4];
            for &candidate in &plain {
                if candidate == original {
                    continue;
                }
                let mut probe = text.clone().into_bytes();
                probe[4] = candidate;
                let probe_text = String::from_utf8(probe).unwrap();
                let Ok(probe_decoded) = vm::custom::base86_decode_mixed(&probe_text, &alphabet)
                else {
                    continue;
                };
                if probe_decoded.starts_with(b"XXS:") || probe_decoded[4..] != decoded[4..] {
                    continue;
                }
                tampered.replace_range(raw_at..raw_at + raw_len, &(candidate as char).to_string());
                flipped = true;
                break;
            }
            assert!(flipped, "{target}: no watermark flip preserved the chain");
            break;
        }
        assert!(
            flipped,
            "{target}: stream-first watermark segment not found"
        );
        let workspace = Workspace::new();
        let runner = support::root()
            .join("toolchains/bin")
            .join(if target.is_luau() { "luau" } else { "lua5.1" });
        for (name, source, expect_success) in [
            ("control", generated.as_str(), true),
            ("watermark", tampered.as_str(), false),
        ] {
            let path = workspace.0.join(format!("wm-{name}.lua"));
            fs::write(&path, source).unwrap();
            let output = Command::new(&runner).arg(&path).output().unwrap();
            assert_eq!(output.status.success(), expect_success, "{target} {name}");
            if expect_success {
                assert_eq!(output.stdout, b"MUST_NOT_RUN\n");
            } else {
                assert!(output.stdout.is_empty(), "{target} {name}");
            }
        }
    }
}

#[test]
fn chacha8_transport_ciphertext_corruption_fails_closed_on_both_targets() {
    use std::collections::BTreeSet;
    use std::process::Command;

    for target in [Target::Lua51, Target::Luau] {
        let bytes = obf::bytecode::custom::encode(
            &obf::ir::compile("print('MUST_NOT_RUN')", target).unwrap(),
        )
        .unwrap();
        let generated = vm::custom::emit(&bytes, target, 735).unwrap();
        let alphabet = vm::custom::base86_image_alphabet(735);
        let mut spans = segment_spans(&generated, target, 735);
        spans.sort_by_key(|&(start, end)| std::cmp::Reverse(end - start));
        spans.truncate(3);
        assert_eq!(spans.len(), 3, "{target}: payload segment count");

        let stream_first = spans
            .iter()
            .position(|&span| {
                let text = String::from_utf8(span_bytes(&generated, target, span)).unwrap();
                vm::custom::base86_decode_mixed(&text, &alphabet)
                    .is_ok_and(|bytes| bytes.starts_with(b"XXS:"))
            })
            .unwrap_or_else(|| panic!("{target}: stream-first segment missing"));
        let mut mutation_offsets = BTreeSet::new();
        for (index, &(start, end)) in spans.iter().enumerate() {
            // Spread raw offsets across the literal, snapped to plain
            // (non-escape) chars so every mutant stays valid Lua. Any flip
            // desyncs the chained widths or corrupts ciphertext, and some
            // gate (transport, watermark, frame, LZW, Adler) fires. The
            // watermark carrier (decoded chars 0..10: 4-char prefix plus a
            // first body group of at most 6) is skipped with margin on the
            // stream-first segment so these mutants exercise the layers
            // past the watermark.
            let inner = &generated[start..end];
            let map = raw_char_map(inner);
            let skip = if index == stream_first { 12 } else { 0 };
            let mut usable = Vec::new();
            for decoded_at in skip..map.len() {
                let raw_end = if decoded_at + 1 < map.len() {
                    map[decoded_at + 1]
                } else {
                    inner.len()
                };
                if raw_end - map[decoded_at] == 1 {
                    let byte = inner.as_bytes()[map[decoded_at]];
                    if byte != 34 && byte != 92 && byte >= 32 {
                        usable.push(start + map[decoded_at]);
                    }
                }
            }
            assert!(!usable.is_empty(), "{target}: no plain mutant offsets");
            mutation_offsets.insert(usable[0]);
            mutation_offsets.insert(usable[usable.len() / 2]);
            mutation_offsets.insert(usable[usable.len() - 1]);
        }

        let workspace = Workspace::new();
        let runner = support::root()
            .join("toolchains/bin")
            .join(if target.is_luau() { "luau" } else { "lua5.1" });
        let control_path = workspace.0.join("chacha-control.lua");
        fs::write(&control_path, &generated).unwrap();
        let control = Command::new(&runner).arg(&control_path).output().unwrap();
        assert!(control.status.success(), "{target}: control failed");
        assert_eq!(control.stdout, b"MUST_NOT_RUN\n");

        for (case, offset) in mutation_offsets.into_iter().enumerate() {
            let mut damaged = generated.clone();
            let replacement = adjacent_plain(generated.as_bytes()[offset], &alphabet);
            damaged.replace_range(offset..offset + 1, &(replacement as char).to_string());
            let path = workspace.0.join(format!("chacha-corrupt-{case}.lua"));
            fs::write(&path, damaged).unwrap();
            let output = Command::new(&runner).arg(&path).output().unwrap();
            assert!(
                !output.status.success(),
                "{target}: ciphertext corruption {case} ran"
            );
            assert!(
                output.stdout.is_empty(),
                "{target}: ciphertext corruption {case} leaked output"
            );
        }
    }
}
