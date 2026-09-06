//! Native differential tests: parsing/binding assertions alone cannot prove
//! that a rewritten program has the same Lua/Luau runtime behavior.

mod support;

use obf::{MinifyOptions, Target};
use std::fs;
use std::process::Command;
use support::{compile_and_run, root, success, Workspace};

fn differential(source: &str, target: Target) -> (String, String) {
    let workspace = Workspace::new();
    // Used by the module-prefix/exports regression; harmless for other cases.
    fs::write(
        workspace.0.join("type_module.luau"),
        "export type Value=number export const answer=42",
    )
    .unwrap();
    let compact = obf::minify_with_options(source, target, MinifyOptions::seeded(735)).unwrap();
    let lexical = obf::minify_with_options(source, target, MinifyOptions::lexical()).unwrap();
    assert!(!compact.contains(['\n', '\r']));
    assert!(!lexical.contains(['\n', '\r']));
    assert_eq!(
        compact,
        obf::minify_with_options(source, target, MinifyOptions::seeded(735)).unwrap()
    );
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
    for seed in [0, 1, 0x735, u64::MAX] {
        let variant =
            obf::minify_with_options(source, target, MinifyOptions::seeded(seed)).unwrap();
        fs::write(&compact_path, &variant).unwrap();
        assert_eq!(
            expected,
            compile_and_run(target, &compact_path),
            "{target}, seed={seed}: {variant}"
        );
    }
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
                .args(["minify", "--target", target, "--seed", "735"])
                .arg(&input),
        );
        let lexical = success(
            Command::new(binary)
                .args(["minify", "--no-rename", "--target", target])
                .arg(&input),
        );
        let target_kind = if target == "lua51" {
            Target::Lua51
        } else {
            Target::Luau
        };
        assert_eq!(
            compact.stdout,
            obf::minify_with_options(
                "local longerName=1 return longerName",
                target_kind,
                MinifyOptions::seeded(735)
            )
            .unwrap()
            .as_bytes()
        );
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

#[test]
fn hundreds_of_sibling_short_locals_reuse_names_without_global_pool_growth() {
    let mut source = String::from("local z=0 ");
    for index in 0..650 {
        source.push_str(&format!("do local a={index} z=z+a end "));
    }
    source.push_str("assert(z==210925) print('short-names:ok')");
    for target in [Target::Lua51, Target::Luau] {
        let (compact, lexical) = differential(&source, target);
        assert!(
            compact.len() <= lexical.len(),
            "independent sibling scopes should reuse one-letter names"
        );
    }
}

#[test]
fn full_virtual_machines_compile_and_run_across_edge_seeds() {
    let workspace = Workspace::new();
    for (target, fixture) in [
        (Target::Lua51, "vm_lua51.lua"),
        (Target::Luau, "vm_luau.lua"),
    ] {
        let input = root().join("tests/fixtures").join(fixture);
        let source = fs::read(&input).unwrap();
        let expected = compile_and_run(target, &input);
        let path = workspace.0.join(fixture);
        for seed in [0, 1, 0x735, u64::MAX] {
            let output = obf::vm::virtualize(&source, target, obf::vm::Options { seed }).unwrap();
            assert!(!output.contains(['\n', '\r']));
            let analysis = obf::scope::analyze(&output, target).unwrap();
            let mut names = std::collections::BTreeSet::new();
            for binding in analysis
                .bindings
                .iter()
                .filter(|binding| binding.declaration.is_some())
            {
                assert!((1..=2).contains(&binding.name.len()));
                assert!(binding.name.bytes().all(|byte| byte.is_ascii_lowercase()));
                assert!(names.insert((analysis.scopes[binding.scope].name_scope, &binding.name)));
            }
            fs::write(&path, &output).unwrap();
            assert_eq!(
                expected,
                compile_and_run(target, &path),
                "{target}, seed={seed}"
            );
        }
    }
}

#[test]
fn cli_default_seed_is_reported_reproducible_and_does_not_pollute_scripts() {
    let workspace = Workspace::new();
    let input = workspace.0.join("input.lua");
    let output_path = workspace.0.join("output.lua");
    let mut source = String::new();
    for index in 0..40 {
        source.push_str(&format!("local originalValue{index}={index} "));
    }
    source.push_str("print(originalValue39)");
    fs::write(&input, source).unwrap();
    let binary = env!("CARGO_BIN_EXE_obf");
    for target in [Target::Lua51, Target::Luau] {
        for command in ["minify", "virtualize"] {
            let mut seeds = std::collections::BTreeSet::new();
            let mut outputs = std::collections::BTreeSet::new();
            for _ in 0..2 {
                let generated = success(
                    Command::new(binary)
                        .args([command, "--target", target.name()])
                        .arg(&input),
                );
                let report = String::from_utf8(generated.stderr).unwrap();
                let seed: u64 = report
                    .trim()
                    .strip_prefix("seed: ")
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(seeds.insert(seed));
                let repeated = success(
                    Command::new(binary)
                        .args([
                            command,
                            "--target",
                            target.name(),
                            "--seed",
                            &seed.to_string(),
                        ])
                        .arg(&input),
                );
                assert!(repeated.stderr.is_empty());
                assert_eq!(generated.stdout, repeated.stdout);
                assert!(!generated.stdout.contains(&b'\n') && !generated.stdout.contains(&b'\r'));
                fs::write(&output_path, &generated.stdout).unwrap();
                assert_eq!(compile_and_run(target, &output_path), b"39\n");
                assert!(outputs.insert(generated.stdout));
            }
            let decimal = success(
                Command::new(binary)
                    .args([command, "--target", target.name(), "--seed", "1845"])
                    .arg(&input),
            );
            let hex = success(
                Command::new(binary)
                    .args([command, "--target", target.name(), "--seed=0x735"])
                    .arg(&input),
            );
            assert_eq!(decimal.stdout, hex.stdout);
            assert!(decimal.stderr.is_empty() && hex.stderr.is_empty());
            fs::write(&output_path, &hex.stdout).unwrap();
            assert_eq!(compile_and_run(target, &output_path), b"39\n");
        }
    }
}

#[test]
fn cli_rejects_invalid_seed_options_and_never_writes_partial_results() {
    let workspace = Workspace::new();
    let input = workspace.0.join("input.lua");
    let output_path = workspace.0.join("output.lua");
    let binary = env!("CARGO_BIN_EXE_obf");
    fs::write(&input, "local originalValue=1 return originalValue").unwrap();
    for target in ["lua51", "luau"] {
        for args in [
            vec!["minify", "--seed", "0", "--no-rename"],
            vec!["minify", "--seed", "-1"],
            vec!["minify", "--seed", "18446744073709551616"],
            vec!["minify", "--seed=0x10000000000000000"],
            vec!["virtualize", "--seed", "not-a-seed"],
            vec!["check", "--seed", "0"],
            vec!["inspect-bytecode", "--seed", "0"],
        ] {
            let result = Command::new(binary)
                .args(args)
                .args(["--target", target])
                .arg(&input)
                .output()
                .unwrap();
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
            assert!(String::from_utf8_lossy(&result.stderr).contains("seed"));
        }
    }
    let mut source = String::new();
    // Exhaust the palette with globals in a natively compilable program;
    // 703 siblings are now safe to reuse, while 703 same-scope locals would
    // test the compiler's own resource limit instead of the name allocator.
    for first in b'a'..=b'z' {
        let mut names = vec![char::from(first).to_string()];
        names.extend(
            (b'a'..=b'z').map(|second| format!("{}{}", char::from(first), char::from(second))),
        );
        for name in names {
            if !matches!(name.as_str(), "do" | "if" | "in" | "or") {
                source.push_str(&format!("{name}=0 "));
            }
        }
    }
    source.push_str("local originalValue=1");
    fs::write(&input, source).unwrap();
    for target in [Target::Lua51, Target::Luau] {
        for existing in [false, true] {
            let _ = fs::remove_file(&output_path);
            if existing {
                fs::write(&output_path, "previous successful output").unwrap();
            }
            let result = Command::new(binary)
                .args(["minify", "--target", target.name(), "--seed", "0", "-o"])
                .arg(&output_path)
                .arg(&input)
                .output()
                .unwrap();
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
            assert!(String::from_utf8_lossy(&result.stderr).contains("pool exhausted"));
            if existing {
                assert_eq!(
                    fs::read_to_string(&output_path).unwrap(),
                    "previous successful output"
                );
            } else {
                assert!(!output_path.exists());
            }
        }
        let lexical = success(
            Command::new(binary)
                .args(["minify", "--target", target.name(), "--no-rename"])
                .arg(&input),
        );
        assert!(lexical.stderr.is_empty());
        fs::write(&output_path, &lexical.stdout).unwrap();
        assert!(compile_and_run(target, &output_path).is_empty());
    }
}
