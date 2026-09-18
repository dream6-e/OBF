//! Compare accepted/rejected syntax against the committed target compilers.
//! This is an audit corpus, not a proof of equivalence for every possible input.

mod support;

use obf::ast::{ExpressionKind, StatementKind, UnaryOperator};
use obf::{MinifyOptions, Target};
use std::fs;
use support::{compile, compile_and_run, Workspace};

fn case(source: &str, target: Target, accepted: bool) {
    let workspace = Workspace::new();
    let path = workspace.0.join("input.lua");
    fs::write(&path, source).unwrap();
    let reference = compile(target, &path);
    assert_eq!(
        reference.status.success(),
        accepted,
        "reference changed: {target}: {source}\n{}",
        String::from_utf8_lossy(&reference.stderr)
    );
    let parsed = obf::parse(source, target);
    assert_eq!(parsed.is_ok(), accepted, "{target}: {source}\n{parsed:?}");
    for options in [
        MinifyOptions::lexical(),
        MinifyOptions::seeded(0),
        MinifyOptions::seeded(u64::MAX),
    ] {
        let output = obf::minify_with_options(source, target, options);
        assert_eq!(output.is_ok(), accepted, "{target}: {source}\n{output:?}");
        if let Ok(output) = output {
            assert!(!output.contains(['\r', '\n']));
            fs::write(&path, &output).unwrap();
            let compiled = compile(target, &path);
            assert!(
                compiled.status.success(),
                "{target}: {output}\n{}",
                String::from_utf8_lossy(&compiled.stderr)
            );
        }
    }
}

#[test]
fn contextual_continue_is_a_name_except_in_luau_control_flow() {
    for target in [Target::Lua51, Target::Luau] {
        for source in [
            "local continue=function() return 42 end; continue()",
            "local continue=1; continue=continue+1; return continue",
            "local x={continue=1}; return x.continue",
            "function continue() end; continue()",
            "while false do local continue=function() end; continue(); break end",
            "while false do continue=1 end",
            "local o={} function o:continue(continue) return continue end return o:continue(1)",
            "for continue=1,3 do print(continue) end",
        ] {
            case(source, target, true);
        }
        case(
            "while false do continue end",
            target,
            target == Target::Luau,
        );
        case("continue", target, false);
        case(
            "while false do local f=function() continue end end",
            target,
            false,
        );
    }
}

#[test]
fn suffixes_require_names_or_parenthesized_prefix_expressions() {
    for target in [Target::Lua51, Target::Luau] {
        for base in [
            "1",
            "nil",
            "true",
            "false",
            "\"text\"",
            "function() end",
            "...",
            "{}",
        ] {
            for suffix in ["()", "[1]", ":method()"] {
                case(&format!("return {base}{suffix}"), target, false);
                case(&format!("return ({base}){suffix}"), target, true);
            }
        }
        for source in [
            "return f().field[1]",
            "return (function() return 1 end)()",
            "return (nil).field",
        ] {
            case(source, target, true);
        }
    }
    case("return @native function() end()", Target::Luau, false);
    case("return (@native function() end)()", Target::Luau, true);
    case("local result=f`text`", Target::Luau, false);
    case("local result=f(`text`)", Target::Luau, true);
}

#[test]
fn newlines_before_parenthesized_call_arguments_are_not_silently_repaired() {
    for target in [Target::Lua51, Target::Luau] {
        for gap in [
            "\n",
            "\r\n",
            "\r",
            "-- comment\n",
            "-- comment\r",
            "--[[\ncomment]]",
        ] {
            for callee in ["f", "f()", "(function() end)", "obj:method"] {
                case(
                    &format!("return {callee}{gap}(1)"),
                    target,
                    target == Target::Luau && !gap.contains('\n'),
                );
            }
        }
        for source in [
            "return f(\n1\n)",
            "return f--[[ inline ]] (1)",
            "return f\n{}",
            "return f\n\"text\"",
            "return f[[multi\nline]](1)",
            "return f[[multi\nline]]\n(1)",
        ] {
            case(source, target, !source.ends_with("]]\n(1)"));
        }
        case("f();\n(g)()", target, true);
        case("f()\n(g)()", target, false);
    }
}

#[test]
fn nested_blocks_preserve_terminal_loop_and_vararg_contexts() {
    for target in [Target::Lua51, Target::Luau] {
        for source in [
            "while true do if true then break end end",
            "for i=1,2 do for j=1,2 do break end break end",
            "repeat local x=1 if false then break end until x==1",
            "local function f(...) do if true then return ... end end end",
            "if true then local x=1 elseif false then local x=2 else local x=3 end",
        ] {
            case(source, target, true);
        }
        for source in [
            "while true do local function f() break end end",
            "local function f(...) return function() return ... end end",
            "if true then break end",
            "while true do break print(1) end",
            "repeat local x=1 end",
            "if true then else elseif true then end",
            "for i=1,2,3,4 do end",
            "function f(...,x) end",
            "local x=1;;",
            "return;;",
            "(a)=1",
            "f()=1",
        ] {
            case(source, target, false);
        }
    }
}

#[test]
fn luau_assertions_and_explicit_method_types_match_the_pinned_grammar() {
    for source in [
        "local x=(1::any)::number",
        "return -x::number + y::number",
        "return f<<number>>",
        "return f<<\nnumber\n>>(1)",
        "return o:m<<number>>(1)",
        "return o:m<<typeof(x)>>()",
        "return o:m<<number>>{}",
        "return o:m<<>>()",
    ] {
        case(source, Target::Luau, true);
    }
    for source in [
        "local x=1::any::number",
        "return o:m<<number>>",
        "return o:m<<\nnumber\n>>(1)",
        "return x::number()",
    ] {
        case(source, Target::Luau, false);
    }
    let chunk = obf::parse("return -value::number", Target::Luau).unwrap();
    let StatementKind::Return(values) = &chunk.block.statements[0].kind else {
        panic!()
    };
    let ExpressionKind::Unary {
        operator: UnaryOperator::Negate,
        expression,
    } = &values[0].kind
    else {
        panic!()
    };
    assert!(matches!(
        expression.kind,
        ExpressionKind::TypeAssertion { .. }
    ));
    let chunk = obf::parse(
        "return receiver:method<<typeof(value)>>(value)",
        Target::Luau,
    )
    .unwrap();
    let StatementKind::Return(values) = &chunk.block.statements[0].kind else {
        panic!()
    };
    let ExpressionKind::Call {
        method: Some(method),
        type_arguments,
        ..
    } = &values[0].kind
    else {
        panic!()
    };
    assert_eq!(method.value, "method");
    assert_eq!(type_arguments.len(), 1);
}

#[test]
fn luau_const_and_module_exports_obey_binding_and_function_boundaries() {
    for source in [
        "const x=1 do local x=2 x+=1 end",
        "const x=1 local f=function(x) x=2 return x end",
        "const t={} t.x=2 t[1]=1 function t.f() end",
        "const a,b=f()",
        "const a,b=...",
        "const a,b=1,2",
        "export const x=1; local function f() do return x end end",
        "export local x=1; x=2",
        "export const x=1 local x=2",
    ] {
        case(source, Target::Luau, true);
    }
    for source in [
        "const a,b=1",
        "const a=1,2",
        "const a,b=(f())",
        "const x",
        "const x=1; x=2",
        "const x=1; x+=2",
        "const x=1; local f=function() x=2 end",
        "const function f() f=1 end",
        "const f=1; function f() end",
        "export function f() end; f=1",
        "export const x=1; do return 2 end",
        "do return 2 end; export const x=1",
        "export const x=1; if true then return 2 end",
        "while false do return end; export const x=1",
        "do export const x=1 end",
        "local text=`{(function() const x=1; x=2; return x end)()}`",
    ] {
        case(source, Target::Luau, false);
    }
}

#[test]
fn type_functions_cannot_capture_runtime_locals_even_in_signatures() {
    for source in [
        "type function Identity(kind) return kind end",
        "type function F(kind) local function g() return kind end return g() end",
        "type function F() return globalValue end local globalValue=1",
        "type function F(p:typeof((function(q) return q end)(1))) return p end",
    ] {
        case(source, Target::Luau, true);
    }
    for source in [
        "local a=1 type function F() return a end",
        "local a=1 type function F(p:typeof(a)) return p end",
        "local a=1 type function F() return function() return a end end",
    ] {
        case(source, Target::Luau, false);
    }
}

#[test]
fn generated_operator_corpus_round_trips_through_both_compilers() {
    for target in [Target::Lua51, Target::Luau] {
        for operator in ["or", "and", "<", "==", "..", "+", "-", "*", "/", "%", "^"] {
            for unary in ["", "not ", "-", "#"] {
                for atom in ["a", "(a+b)", "f()", "{a,field=b}"] {
                    case(&format!("local a,b,f=1,2,function()return 3 end; return {unary}{atom} {operator} b"), target, true);
                }
            }
        }
    }
}

#[test]
fn audited_namecall_and_contextual_names_execute_identically() {
    let workspace = Workspace::new();
    for (target, source) in [
        (Target::Lua51, "local continue=function(x)return x+1 end; print(continue(41))"),
        (Target::Luau, "local continue=function(x)return x+1 end; local object={} function object:method<T>(x:T):T return x end print(object:method<<number>>(continue(41)))"),
    ] {
        for options in [MinifyOptions::lexical(), MinifyOptions::seeded(0), MinifyOptions::seeded(u64::MAX)] {
            let path = workspace.0.join("runtime.lua");
            fs::write(&path, obf::minify_with_options(source, target, options).unwrap()).unwrap();
            assert_eq!(compile_and_run(target, &path), b"42\n");
        }
    }
}

#[test]
fn binding_validation_distinguishes_reassignment_from_table_mutation() {
    let source = "const object={} object.field=1 object[2]=3 function object:method(value) return value end local mutable=0 mutable=1 function mutable() return 0 end return object:method<<typeof(mutable)>>(mutable)";
    case(source, Target::Luau, true);
    let graph = obf::scope::analyze(source, Target::Luau).unwrap();
    assert!(
        graph
            .bindings
            .iter()
            .find(|binding| binding.name == "object")
            .unwrap()
            .is_const
    );
    assert!(
        !graph
            .bindings
            .iter()
            .find(|binding| binding.name == "mutable")
            .unwrap()
            .is_const
    );
    let object: Vec<_> = graph
        .references
        .iter()
        .filter(|reference| reference.name == "object")
        .collect();
    assert_eq!(object.len(), 4);
    assert!(object.iter().all(|reference| !reference.is_write));
    let mutable: Vec<_> = graph
        .references
        .iter()
        .filter(|reference| reference.name == "mutable")
        .collect();
    assert_eq!(
        mutable.len(),
        4,
        "explicit method type arguments must be traversed"
    );
    assert_eq!(
        mutable
            .iter()
            .filter(|reference| reference.is_write)
            .count(),
        2
    );
}

#[test]
fn syntax_check_does_not_claim_compiler_dataflow_validation() {
    let source = "repeat if true then continue end local x=1 until x==1";
    // The reference PARSER accepts this; its compiler subsequently rejects
    // the continue that skips initialization of a local read by `until`.
    assert!(obf::check(source, Target::Luau).is_ok());
    let workspace = Workspace::new();
    let path = workspace.0.join("dataflow.lua");
    fs::write(&path, source).unwrap();
    let output = compile(Target::Luau, &path);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("CompileError"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SyntaxError"));
    // A purely lexical rule would incorrectly reject these valid programs.
    case(
        "repeat if false then continue end local x=1 until x==1",
        Target::Luau,
        true,
    );
    case(
        "repeat if true then continue end local x=1 until (function() return x end)()",
        Target::Luau,
        true,
    );
}
