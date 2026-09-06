//! Binding identity, actual name reuse and native execution are separate
//! assertions. A parse-only test or global set of names is not sufficient.

mod support;

use obf::scope::{self, Analysis};
use obf::{MinifyOptions, Target};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use support::{compile_and_run, Workspace};

const SEEDS: &[u64] = &[0, 1, 2, 42, 735, u64::MAX];

fn verify(before: &Analysis, after: &Analysis) {
    assert_eq!(before.globals, after.globals);
    assert_eq!(before.scopes.len(), after.scopes.len());
    for (old, new) in before.scopes.iter().zip(&after.scopes) {
        assert_eq!(old.parent, new.parent);
        assert_eq!(old.kind, new.kind);
        assert_eq!(old.function, new.function);
        assert_eq!(old.name_scope, new.name_scope);
        assert_eq!(old.bindings, new.bindings);
        assert_eq!(old.upvalues, new.upvalues);
    }
    assert_eq!(before.bindings.len(), after.bindings.len());
    let mut names = BTreeMap::new();
    for (id, (old, new)) in before.bindings.iter().zip(&after.bindings).enumerate() {
        assert_eq!(old.scope, new.scope);
        assert_eq!(old.kind, new.kind);
        assert_eq!(old.references, new.references);
        assert_eq!(old.captured, new.captured);
        assert_eq!(old.is_const, new.is_const);
        if old.preserve.is_some() || !before.rename_barriers.is_empty() {
            assert_eq!(old.name, new.name);
        } else {
            assert_ne!(old.name, new.name);
            assert!((1..=2).contains(&new.name.len()));
            assert!(new.name.bytes().all(|byte| byte.is_ascii_lowercase()));
        }
        if let Some(previous) = names.insert((after.scopes[new.scope].name_scope, &new.name), id) {
            assert_eq!(
                before.bindings[previous].name,
                after.bindings[previous].name
            );
            assert_eq!(old.name, new.name, "new same-scope conflict");
        }
    }
    assert_eq!(before.references.len(), after.references.len());
    for (old, new) in before.references.iter().zip(&after.references) {
        assert_eq!(old.scope, new.scope);
        assert_eq!(old.binding, new.binding);
        assert_eq!(old.is_write, new.is_write);
        if old.binding.is_none() {
            assert_eq!(old.name, new.name);
        }
    }
}

fn differential(
    source: &str,
    target: Target,
    seeds: &[u64],
    inspect: impl Fn(&Analysis, &Analysis),
) {
    let workspace = Workspace::new();
    let path = workspace.0.join("program.lua");
    fs::write(&path, source).unwrap();
    let expected = compile_and_run(target, &path);
    let before = scope::analyze(source, target).unwrap();
    let lexical = obf::minify_with_options(source, target, MinifyOptions::lexical()).unwrap();
    fs::write(&path, lexical).unwrap();
    assert_eq!(compile_and_run(target, &path), expected);
    for &seed in seeds {
        let options = MinifyOptions::seeded(seed);
        let output = obf::minify_with_options(source, target, options).unwrap();
        assert_eq!(
            output,
            obf::minify_with_options(source, target, options).unwrap()
        );
        assert!(!output.contains(['\n', '\r']));
        let after = scope::analyze(&output, target).unwrap();
        verify(&before, &after);
        inspect(&before, &after);
        fs::write(&path, &output).unwrap();
        assert_eq!(
            compile_and_run(target, &path),
            expected,
            "{target}, seed={seed}: {output}"
        );
    }
}

fn renamed<'a>(before: &Analysis, after: &'a Analysis, original: &str) -> &'a str {
    let id = before
        .bindings
        .iter()
        .position(|binding| binding.name == original)
        .unwrap();
    &after.bindings[id].name
}

#[test]
fn function_if_while_for_repeat_and_do_scopes_actually_reuse_short_names() {
    let source = r#"
local output={}
do local first=11 output[#output+1]=first end
if true then local second=22 output[#output+1]=second
else local alternate=0 output[#output+1]=alternate end
while #output<3 do local third=33 output[#output+1]=third end
for numeric=4,4 do local fourth=numeric*11 output[#output+1]=fourth end
for ignored,element in ipairs({55}) do local fifth=element output[#output+1]=fifth end
repeat local sixth=66 output[#output+1]=sixth until sixth==66
local function firstFunction(parameter) local firstValue=parameter*11 return firstValue end
local function secondFunction(otherParameter) local secondValue=otherParameter*11 return secondValue end
output[7]=firstFunction(7) output[8]=secondFunction(8)
assert(table.concat(output,',')=='11,22,33,44,55,66,77,88')
print('scope-reuse:ok')
"#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target, SEEDS, |before, after| {
            let name = |original| renamed(before, after, original);
            assert_eq!(name("first"), name("second"));
            assert_eq!(name("first"), name("third"));
            assert_eq!(name("parameter"), name("otherParameter"));
            assert_eq!(name("firstValue"), name("secondValue"));
            assert_ne!(name("parameter"), name("firstValue"));
            assert_ne!(name("numeric"), name("fourth"));
            assert_ne!(name("ignored"), name("element"));
            assert_ne!(name("element"), name("fifth"));
        });
    }
}

#[test]
fn escaped_and_transitive_closures_keep_reads_writes_and_shadowed_bindings() {
    let source = r#"
local boxes={} local capturedTotal=100
for index=1,3 do
    local snapshot=index
    boxes[index]=function(delta)
        capturedTotal=capturedTotal+delta snapshot=snapshot+delta
        return capturedTotal,snapshot
    end
end
do
    local shadow=5 boxes[4]=function()return shadow end
    local shadow=50 boxes[5]=function()return shadow end
    local innerValue=7 boxes[6]=function()return capturedTotal+innerValue end
end
local function nesting(mid)
    local retained=mid
    return function(step)
        return function()
            local increment=1 capturedTotal=capturedTotal+step+increment retained=retained+1
            return capturedTotal,retained
        end
    end
end
local total,value=boxes[1](10) assert(total==110 and value==11)
total,value=boxes[2](20) assert(total==130 and value==22)
total,value=boxes[1](1) assert(total==131 and value==12)
assert(boxes[4]()==5 and boxes[5]()==50 and boxes[6]()==138)
total,value=nesting(30)(2)() assert(total==134 and value==31)
print(total,value)
"#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target, SEEDS, |before, after| {
            let shadows: Vec<_> = before
                .bindings
                .iter()
                .enumerate()
                .filter(|(_, binding)| binding.name == "shadow")
                .map(|(id, _)| id)
                .collect();
            assert_ne!(
                after.bindings[shadows[0]].name,
                after.bindings[shadows[1]].name
            );
            let name = |original| renamed(before, after, original);
            assert_ne!(name("capturedTotal"), "capturedTotal");
            for captured in [
                "snapshot",
                "delta",
                "innerValue",
                "retained",
                "step",
                "increment",
            ] {
                assert_ne!(
                    name("capturedTotal"),
                    name(captured),
                    "capture through {captured}"
                );
            }
        });
    }
}

#[test]
fn declaration_activation_permits_initializers_but_not_recursive_function_capture() {
    let source = r#"
local outer=17
do local alias=outer+1 assert(alias==18) end
do local child=function()return outer end assert(child()==17) end
do
    local function recursive(depth)
        if depth==0 then return outer end
        return recursive(depth-1)
    end
    assert(recursive(3)==17)
end
for counter=outer,outer do local copy=counter assert(copy==17) end
print(outer)
"#;
    for target in [Target::Lua51, Target::Luau] {
        differential(source, target, SEEDS, |before, after| {
            let name = |original| renamed(before, after, original);
            assert_eq!(name("outer"), name("alias"));
            assert_eq!(name("outer"), name("child"));
            assert_eq!(name("outer"), name("counter"));
            assert_ne!(name("outer"), name("recursive"));
            assert_ne!(name("outer"), name("depth"));
        });
    }
}

#[test]
fn repeat_until_and_loop_control_keep_the_same_binding_visibility() {
    let common = r#"
local total=0
repeat local step=total+1 total=step until step==3
local items={4,5}
for key,item in ipairs(items) do local amount=key+item total=total+amount end
while total<20 do local amount=1 total=total+amount if total==19 then break end end
assert(total==19)
"#;
    for target in [Target::Lua51, Target::Luau] {
        let mut source = common.to_owned();
        if target == Target::Luau {
            source.push_str("while total<22 do total+=1 local doubled=total*2 if doubled==40 then continue end assert(doubled>40) end assert(total==22) ");
        }
        source.push_str("print(total)");
        differential(&source, target, SEEDS, |before, after| {
            assert_ne!(
                renamed(before, after, "total"),
                renamed(before, after, "step")
            );
        });
    }
}

#[test]
fn luau_signatures_method_types_and_interpolation_participate_in_interference() {
    let source = r#"
local outside=9
local object={}
function object:identity<T>(value:T):T return value end
do local initialized:typeof(outside)=outside assert(initialized==9) end
do
    local blocker=1
    type Evidence=typeof(outside)
    local result=object:identity<<typeof(outside)>>(blocker)
    assert(result==1)
    assert(`{outside}:{blocker}`=='9:1')
end
do
    local function outside(parameter:typeof(outside)):typeof(outside)
        return parameter
    end
    assert(outside(7)==7)
end
type function Identity(kind) return kind end
print(outside)
"#;
    differential(source, Target::Luau, SEEDS, |before, after| {
        let name = |original| renamed(before, after, original);
        assert_eq!(name("outside"), name("initialized"));
        assert_ne!(name("outside"), name("blocker"));
        assert_eq!(name("kind"), "kind", "type functions remain protected");
    });
}

#[test]
fn ten_thousand_sibling_bindings_do_not_exhaust_the_global_alphabet() {
    let mut source = String::from("local z=0 ");
    for value in 0..10_000 {
        source.push_str(&format!("do local a={value} z=z+a end "));
    }
    source.push_str("assert(z==49995000) print('many-scopes:ok')");
    for target in [Target::Lua51, Target::Luau] {
        differential(&source, target, &[0, 735, u64::MAX], |_, after| {
            assert_eq!(after.bindings.len(), 10_001);
            let names: BTreeSet<_> = after.bindings.iter().map(|binding| &binding.name).collect();
            assert_eq!(names.len(), 2);
            assert!(names.iter().all(|name| name.len() == 1));
        });
    }
}

#[test]
fn generated_shadowing_and_initializer_programs_run_identically() {
    let originals = ["a", "b", "ab", "longVariable"];
    for (left, outer) in originals.iter().enumerate() {
        for (right, inner) in originals.iter().enumerate() {
            let programs = [
                format!("local {outer}=1 do local {inner}={outer}+1 print({inner}) end print({outer})"),
                format!("local {outer}=1 do local {inner}=function()return {outer} end print({inner}()) end print({outer})"),
                format!("local {outer}=1 do local function {inner}(depth) if depth==0 then return {outer} end return {inner}(depth-1) end print(type({inner}(2))) end print({outer})"),
                format!("local {outer}=1 repeat local {inner}={outer}+1 print({inner}) until {inner}==2 print({outer})"),
                format!("local {outer}=1 for {inner}={outer},{outer} do print({inner}) end print({outer})"),
                format!("local {outer}=1 do local saved={outer} local {inner}=2 print(saved,{inner}) end print({outer})"),
            ];
            for target in [Target::Lua51, Target::Luau] {
                for (shape, source) in programs.iter().enumerate() {
                    let seed = (left * 24 + right * 6 + shape) as u64;
                    differential(source, target, &[seed, u64::MAX - seed], |_, _| {});
                }
            }
        }
    }
}
