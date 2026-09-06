//! Native differential tests: parsing/binding assertions alone cannot prove
//! that a rewritten program has the same Lua/Luau runtime behavior.

use obf::{MinifyOptions, Target};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_WORKSPACE: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "obf-safe-minify-{}-{}",
            std::process::id(),
            NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn success(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn compile_and_run(target: Target, path: &Path) -> Vec<u8> {
    let (compiler, runtime) = match target {
        Target::Lua51 => ("luac5.1", "lua5.1"),
        Target::Luau => ("luau-compile", "luau"),
    };
    let mut compiler = Command::new(root().join("toolchains/bin").join(compiler));
    if target == Target::Lua51 {
        compiler.arg("-p");
    }
    success(compiler.arg(path));
    success(Command::new(root().join("toolchains/bin").join(runtime)).arg(path)).stdout
}

fn differential(source: &str, target: Target) -> (String, String) {
    let workspace = Workspace::new();
    // Used by the module-prefix/exports regression; harmless for other cases.
    fs::write(
        workspace.0.join("type_module.luau"),
        "export type Value=number export const answer=42",
    )
    .unwrap();
    let compact = obf::minify(source, target).unwrap();
    let lexical = obf::minify_with_options(
        source,
        target,
        MinifyOptions {
            rename_locals: false,
        },
    )
    .unwrap();
    assert!(!compact.contains(['\n', '\r']));
    assert!(!lexical.contains(['\n', '\r']));
    assert!(compact.len() <= lexical.len());
    assert_eq!(compact, obf::minify(source, target).unwrap());
    let original_path = workspace.0.join("original.lua");
    let compact_path = workspace.0.join("compact.lua");
    let lexical_path = workspace.0.join("lexical.lua");
    fs::write(&original_path, source).unwrap();
    fs::write(&compact_path, &compact).unwrap();
    fs::write(&lexical_path, &lexical).unwrap();
    let expected = compile_and_run(target, &original_path);
    assert_eq!(
        expected,
        compile_and_run(target, &compact_path),
        "{target}: {compact}"
    );
    assert_eq!(expected, compile_and_run(target, &lexical_path));
    (compact, lexical)
}

#[test]
fn lua51_scope_fixture_runs_identically_after_safe_compression() {
    let (compact, lexical) = differential(include_str!("fixtures/scope_lua51.lua"), Target::Lua51);
    assert!(compact.len() < lexical.len());
    assert!(!compact.contains("local safeCompressionMarker"));
}

#[test]
fn luau_scope_fixture_runs_identically_after_safe_compression() {
    let (compact, lexical) = differential(include_str!("fixtures/scope_luau.lua"), Target::Luau);
    assert!(compact.len() < lexical.len());
    assert!(!compact.contains("local safeCompressionMarker"));
    assert!(compact.contains("exportedFunctionLongName"));
    assert!(compact.contains("preservedTypeLocal"));
}

#[test]
fn lua51_reflection_observes_original_local_and_upvalue_names() {
    let (compact, lexical) =
        differential(include_str!("fixtures/reflection_lua51.lua"), Target::Lua51);
    assert_eq!(compact, lexical);
}

#[test]
fn luau_reflection_observes_original_function_names() {
    let (compact, lexical) =
        differential(include_str!("fixtures/reflection_luau.lua"), Target::Luau);
    assert_eq!(compact, lexical);
}

#[test]
fn luau_required_type_prefix_is_renamed_but_exported_api_is_not() {
    let (compact, _) = differential(
        r#"
            local moduleNamespace = require("./type_module")
            type Imported = moduleNamespace.Value
            local resultValue: Imported = moduleNamespace.answer
            local typedValue: typeof(moduleNamespace.answer) = resultValue
            assert(typedValue == 42)
            print("qualified-types:ok")
        "#,
        Target::Luau,
    );
    assert!(!compact.contains("moduleNamespace"));
    assert!(compact.contains(".Value") && compact.contains(".answer"));
}

#[test]
fn shadowing_initializers_duplicate_parameters_and_metatable_order_are_preserved() {
    let cases = [
        r#"
            local longName=7
            local longName,longName=longName+1,longName+2
            local function duplicateParameters(parameterName,parameterName)
                return parameterName+longName
            end
            assert(duplicateParameters(1,3)==12)
            print("duplicates:ok")
        "#,
        r#"
            local outerName=3
            local savedFunction
            do
                local outerName=outerName+1
                savedFunction=function() return outerName end
                local outerName=99
                assert(outerName==99)
            end
            assert(savedFunction()==4 and outerName==3)
            print("shadowing:ok")
        "#,
        r#"
            a=9
            local b=2
            local longName=3
            local function outerFunction(longName)
                return function() return a,b,longName end
            end
            local firstValue,secondValue,thirdValue=outerFunction(7)()
            assert(firstValue==9 and secondValue==2 and thirdValue==7 and longName==3)
            print("capture:ok")
        "#,
        r#"
            local traceValue=""
            local proxyValue=setmetatable({}, {
                __index=function(_,keyValue)
                    traceValue=traceValue..keyValue
                    return function(argumentValue) traceValue=traceValue..argumentValue end
                end,
            })
            local function argumentFunction() traceValue=traceValue.."A" return "V" end
            proxyValue.K(argumentFunction())
            assert(traceValue=="KAV")
            print("metatable-order:ok")
        "#,
        r#"
            local countValue=0
            repeat
                local repeatLocal=countValue+1
                countValue=repeatLocal
            until (function() return repeatLocal==3 end)()
            assert(countValue==3)
            print("repeat-closure:ok")
        "#,
    ];
    for target in [Target::Lua51, Target::Luau] {
        for source in cases {
            differential(source, target);
        }
    }
}

#[test]
fn lua51_legacy_arg_shadowing_and_luau_arg_visibility_match_reference_runtimes() {
    differential(
        r#"
            local arg={99}
            local function arguments(arg,...)
                return arg[1]
            end
            assert(arguments({71},42)==42 and arg[1]==99)
            print("legacy-arg:ok")
        "#,
        Target::Lua51,
    );
    differential(
        r#"
            local arg={99}
            local function arguments(arg,...)
                return arg[1],...
            end
            local firstValue,secondValue=arguments({71},42)
            assert(firstValue==71 and secondValue==42 and arg[1]==99)
            print("luau-arg:ok")
        "#,
        Target::Luau,
    );
}

#[test]
fn interpolated_literals_preserve_bytes_and_evaluate_embedded_functions_in_place() {
    differential(
        "local stringValue='v' local resultValue=`百分比100%; escaped=\\123\\x60; quoted=\\\"{\n(function(parameterValue) return `inside={parameterValue}` end)(stringValue)}` print(resultValue)",
        Target::Luau,
    );
}

#[test]
fn command_line_supports_no_rename_and_rejects_it_for_other_commands() {
    let workspace = Workspace::new();
    let input = workspace.0.join("input.lua");
    fs::write(&input, "local longerName=1 return longerName").unwrap();
    let binary = env!("CARGO_BIN_EXE_obf");
    for target in ["lua51", "luau"] {
        let compact = success(
            Command::new(binary)
                .args(["minify", "--target", target])
                .arg(&input),
        );
        let lexical = success(
            Command::new(binary)
                .args(["minify", "--no-rename", "--target", target])
                .arg(&input),
        );
        assert_eq!(compact.stdout, b"local a=1 return a");
        assert_eq!(lexical.stdout, b"local longerName=1 return longerName");
        for command in ["check", "virtualize", "inspect-bytecode"] {
            let output = Command::new(binary)
                .args([command, "--no-rename", "--target", target])
                .arg(&input)
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("--no-rename is only valid"));
        }
    }
}
