//! Statement-aware delimiters must preserve native syntax/runtime semantics.
//! A semicolon is not general whitespace: literals, headers, operators and
//! genuine expression suffixes must never be split by this formatting pass.
mod support;

use obf::{MinifyOptions, Target};
use std::fs;
use std::process::Command;
use support::{compile, compile_and_run, Workspace};

fn lexical(source: &str, target: Target) -> String {
    obf::minify_with_options(source, target, MinifyOptions::lexical()).unwrap()
}

fn differential(source: &str, target: Target) -> String {
    let work = Workspace::new();
    let path = work.0.join("run.lua");
    fs::write(&path, source).unwrap();
    let expected = compile_and_run(target, &path);
    let compact = lexical(source, target);
    assert_eq!(
        lexical(&compact, target),
        compact,
        "formatting is idempotent"
    );
    let tokens = obf::lexer::lex(source, target).unwrap();
    assert_eq!(
        obf::minify::minify(source, &tokens, target).unwrap(),
        compact
    );
    for output in
        std::iter::once(compact.clone()).chain([0, 735, u64::MAX].map(|seed| {
            obf::minify_with_options(source, target, MinifyOptions::seeded(seed)).unwrap()
        }))
    {
        assert!(!output.contains(['\n', '\r']));
        fs::write(&path, &output).unwrap();
        assert_eq!(
            compile_and_run(target, &path),
            expected,
            "{target}: {output}"
        );
    }
    compact
}

#[test]
fn statements_and_nonempty_block_closers_use_semicolons_not_spaces() {
    for target in [Target::Lua51, Target::Luau] {
        let output = differential(
            "local a=1 local b=2 a=a+b print(a) do local held=a print(held) end",
            target,
        );
        assert_eq!(
            output,
            "local a=1;local b=2;a=a+b;print(a);do local held=a;print(held);end"
        );
        let output = differential(
            "local function choose(x) if x then return x else return 0 end end print(choose(3))",
            target,
        );
        assert_eq!(
            output,
            "local function choose(x)if x then return x;else return 0;end;end;print(choose(3))"
        );
        let output = differential(
            "local x=2 while x>0 do x=x-1 end repeat x=x+1 until x==2 if x==1 then print('a') elseif x==2 then print('b') else print('c') end print(x)",
            target,
        );
        assert!(output.contains("x=x-1;end;repeat"));
        assert!(output.contains("x=x+1;until x==2;if"));
        assert!(output.contains("print(\"a\");elseif"));
        assert!(output.contains("print(\"b\");else"));
        assert!(output.ends_with("print(\"c\");end;print(x)"));
    }
}

#[test]
fn required_spaces_operators_arguments_and_table_fields_are_not_replaced() {
    for target in [Target::Lua51, Target::Luau] {
        let output = differential(
            r#"
                local function values(a,b,...)
                    local fields={a,b;flag=true}
                    return not a and b or - -1, #fields, select('#',...)
                end
                local function tokens()return 1 .. .5, 3 - -2 end
                for index,value in ipairs({1,2})do print(index,value)end
                for index=1,2 do print(index)end
                print(values(false,7,'x')) print(tokens())
            "#,
            target,
        );
        for kept in [
            "local function values(a,b,...)",
            "return not a and b or- -1",
            "return 1 .. .5,3- -2",
            "for index,value in ipairs",
            "for index=1,2 do",
            "local fields={a,b;flag=true}",
        ] {
            assert!(output.contains(kept), "{target}: missing {kept}: {output}");
        }
        for bad in ["local;", "for;", "then;", "do;", "-;-", "a;b;flag"] {
            assert!(!output.contains(bad), "{target}: {output}");
        }
    }
}

#[test]
fn closures_suffix_calls_methods_and_terminal_statements_remain_intact() {
    let source = r#"
        local factory=(function()
            local held=3
            return function(value)held=held+value return held end
        end)()
        local function curried()
            return function(value)return value*2 end
        end
        local object={value=1,read=function(self)return self.value end}
        function object:add(value)self.value=self.value+value return self end
        local function empty()return end
        local count=0 while true do count=count+1 if count==2 then break end end
        print(factory(4),curried()(5),object:add(3):read(),count)
        empty();(function()print('standalone')end)()
    "#;
    for target in [Target::Lua51, Target::Luau] {
        let output = differential(source, target);
        assert!(output.contains("return held;end;end)()"));
        assert!(output.contains("object:add(3):read()"));
        assert!(output.contains("empty()return;end"));
        assert!(output.contains("break;end;end;print"));
        assert!(output.contains("empty();(function()"));
        assert!(!output.contains("end;)("));
    }
    let output = differential(
        "local n=0 for i=1,4 do if i%2==0 then continue end n+=i end print(n)",
        Target::Luau,
    );
    assert!(output.contains("continue;end;n+=i;end;print"));
}

#[test]
fn nested_interpolation_typeof_and_type_function_bodies_get_real_boundaries() {
    let source = r#"
        type NumberKind=typeof((function()local typedLocal=1 return typedLocal end)())
        type function Identity(kind)local held=kind return held end
        @native
        local function identity<T>(value:T):T local alias=value return alias end
        local object={}
        function object:typed<T>(value:T):T return value end
        local label='a b; c'
        local text=`left space; {(function()
            local first=identity<<number>>(3)
            local nested=`inner {(function()local second=first+2 return second end)()}`
            return nested
        end)()} right {label}`
        assert(text=='left space; inner 5 right a b; c')
        local tab=`table={ {value=1} }`
        assert(string.sub(tab,1,12)=='table=table:')
        print(text,object:typed<<number>>(4))
    "#;
    let output = differential(source, Target::Luau);
    for expected in [
        "local typedLocal=1;return typedLocal;end)());type function",
        "local held=kind;return held;end;@native",
        "local alias=value;return alias;end;local object",
        "local second=first+2;return second;end)()",
        "`;return nested;end)()",
        "object:typed<<number>>(4)",
        "`table={ {value=1}}`",
        "left space; ",
        " right {label}",
    ] {
        assert!(output.contains(expected), "missing {expected}: {output}");
    }
}

#[test]
fn quoted_long_and_binary_strings_keep_their_bytes_and_spaces() {
    let source = r#"
        local quoted="a b ; -- then end\000\255"
        local long=[=[literal space ; local a=1 return a
next line]=]
        assert(quoted==string.char(97,32,98,32,59,32,45,45,32,116,104,101,110,32,101,110,100,0,255))
        assert(long=="literal space ; local a=1 return a\nnext line")
        local bytes={string.byte(quoted,1,#quoted)}
        print(table.concat(bytes,','),long)
    "#;
    for target in [Target::Lua51, Target::Luau] {
        let output = differential(source, target);
        assert!(output.contains("a b ; -- then end\\000\\255"));
        assert!(output.contains("literal space ; local a=1 return a\\nnext line"));
    }
}

#[test]
fn existing_semicolons_empty_blocks_and_invalid_newline_calls_are_not_rewritten() {
    for target in [Target::Lua51, Target::Luau] {
        for (source, expected) in [
            ("", ""),
            ("-- only a comment\n", ""),
            ("do end", "do end"),
            ("if false then else end", "if false then else end"),
            ("local function f() end f()", "local function f()end;f()"),
            (
                "local a=1;local b=2;return a+b;",
                "local a=1;local b=2;return a+b;",
            ),
            (
                "#! /usr/bin/env lua\nlocal x=1 -- between statements\nprint(x)",
                "local x=1;print(x)",
            ),
        ] {
            assert_eq!(differential(source, target), expected);
        }
        let work = Workspace::new();
        let path = work.0.join("invalid.lua");
        for source in ["local x=1;;local y=2", "do;end", "f()\n(g)()"] {
            fs::write(&path, source).unwrap();
            assert!(!compile(target, &path).status.success());
            assert!(obf::minify_with_options(source, target, MinifyOptions::lexical()).is_err());
        }
        let source = "local x=1 print(x)";
        let mut tokens = obf::lexer::lex(source, target).unwrap();
        tokens[0].kind = obf::lexer::TokenKind::Identifier;
        assert!(obf::minify::minify(source, &tokens, target).is_err());
    }
}

#[test]
fn cli_and_both_vm_backends_share_the_new_delimiters() {
    let work = Workspace::new();
    let input = work.0.join("input.lua");
    let source = "local function outer(v) local function inner(x) return x+v end return inner end print(outer(3)(4))";
    fs::write(&input, source).unwrap();
    for target in [Target::Lua51, Target::Luau] {
        let result = Command::new(env!("CARGO_BIN_EXE_obf"))
            .args(["minify", "--target", &target.to_string(), "--no-rename"])
            .arg(&input)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, lexical(source, target).as_bytes());
        for native in [false, true] {
            let output = if native {
                obf::vm::virtualize_native(
                    source.as_bytes(),
                    target,
                    obf::vm::Options { seed: 735 },
                )
            } else {
                obf::vm::virtualize(source.as_bytes(), target, obf::vm::Options { seed: 735 })
            }
            .unwrap();
            assert!(!output.contains("end end"));
            assert!(!output.contains("end local"));
            assert!(!output.contains("end return"));
            assert!(output.contains(";end;"));
            let path = work.0.join("vm.lua");
            fs::write(&path, output).unwrap();
            assert_eq!(compile_and_run(target, &path), b"7\n");
        }
    }
}
