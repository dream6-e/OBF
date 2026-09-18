mod support;
use obf::{bytecode, Target};
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use support::{compile_and_run, success, Workspace};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_obf"))
}

#[test]
fn default_compile_dump_wrap_and_virtualize_work_with_missing_native_compilers() {
    for target in [Target::Lua51, Target::Luau] {
        let work = Workspace::new();
        let input = work.0.join("input.lua");
        let blob = work.0.join("program.obf");
        let script = work.0.join("program.lua");
        fs::write(
            &input,
            "local x=7 local function add(v)if v>0 then x=x+v end return x end print(add(3))",
        )
        .unwrap();
        let expected = compile_and_run(target, &input);
        let target_name = target.to_string();
        let missing = || {
            let mut c = command();
            c.env("OBF_LUAC51", work.0.join("missing-luac"))
                .env("OBF_LUAU_COMPILE", work.0.join("missing-luau-compile"));
            c
        };
        let compiled = success(
            missing()
                .args(["compile", "--target", &target_name])
                .arg(&input),
        );
        assert!(compiled.stderr.is_empty());
        assert!(compiled.stdout.starts_with(b"OBF\x02"));
        fs::write(&blob, &compiled.stdout).unwrap();
        assert!(bytecode::inspect(&compiled.stdout, target).is_ok());
        let dump = success(
            missing()
                .args(["dump-ir", "--target", &target_name])
                .arg(&input),
        );
        let dump = String::from_utf8(dump.stdout).unwrap();
        assert!(dump.contains("Module"));
        assert!(dump.contains("Branch"));
        assert!(dump.contains("NewCell"));
        assert!(dump.contains("captures:"));
        let direct = success(
            missing()
                .args(["virtualize", "--target", &target_name, "--seed", "735"])
                .arg(&input),
        );
        let explicit = success(
            missing()
                .args([
                    "virtualize",
                    "--backend=ast",
                    "--target",
                    &target_name,
                    "--seed",
                    "735",
                ])
                .arg(&input),
        );
        let wrapped = success(
            missing()
                .args(["wrap-bytecode", "--target", &target_name, "--seed", "735"])
                .arg(&blob),
        );
        assert_eq!(direct.stdout, explicit.stdout);
        assert_eq!(direct.stdout, wrapped.stdout);
        fs::write(&script, &direct.stdout).unwrap();
        assert_eq!(compile_and_run(target, &script), expected);
        let inspect = success(
            command()
                .args(["inspect-bytecode", "--target", &target_name])
                .arg(&blob),
        );
        let inspect = String::from_utf8(inspect.stdout).unwrap();
        assert!(inspect.contains("format: OBF v2"));
        assert!(inspect.contains("instruction-size: 0"));
        assert!(inspect.contains("header-size: 32"));
        let native = missing()
            .args([
                "virtualize",
                "--backend",
                "native",
                "--target",
                &target_name,
                "--seed",
                "1",
            ])
            .arg(&input)
            .output()
            .unwrap();
        assert!(!native.status.success());
        assert!(native.stdout.is_empty());
        assert!(String::from_utf8_lossy(&native.stderr).contains("missing tool"));
    }
}

#[test]
fn explicit_legacy_backend_still_compiles_and_runs() {
    let work = Workspace::new();
    let input = work.0.join("source.lua");
    let output = work.0.join("vm.lua");
    fs::write(
        &input,
        "local function add(x,y)return x+y end print(add(2,3))",
    )
    .unwrap();
    for target in [Target::Lua51, Target::Luau] {
        let expected = compile_and_run(target, &input);
        success(
            command()
                .args([
                    "virtualize",
                    "--backend",
                    "native",
                    "--target",
                    &target.to_string(),
                    "--seed",
                    "735",
                    "-o",
                ])
                .arg(&output)
                .arg(&input),
        );
        assert_eq!(compile_and_run(target, &output), expected);
    }
}

#[test]
fn invalid_options_or_inputs_never_overwrite_existing_output() {
    let work = Workspace::new();
    let input = work.0.join("source.lua");
    let output = work.0.join("sentinel");
    fs::write(&input, "return 7").unwrap();
    fs::write(&output, "keep").unwrap();
    for args in [
        vec!["compile", "--seed", "1"],
        vec!["dump-ir", "--seed", "1"],
        vec!["compile", "--backend", "native"],
        vec!["wrap-bytecode", "--no-rename"],
        vec!["virtualize", "--backend", "mystery"],
        vec!["wrap-bytecode", "--seed", "1"],
    ] {
        let result = command()
            .args(args)
            .args(["--target", "lua51", "-o"])
            .arg(&output)
            .arg(&input)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(fs::read_to_string(&output).unwrap(), "keep");
    }
    fs::write(&input, "local =").unwrap();
    for cmd in ["compile", "dump-ir", "virtualize"] {
        let result = command()
            .args([cmd, "--target", "lua51", "-o"])
            .arg(&output)
            .arg(&input)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(fs::read_to_string(&output).unwrap(), "keep");
    }
    let bytes = obf::vm::custom::compile("return 7", Target::Lua51).unwrap();
    fs::write(&input, bytes).unwrap();
    let result = command()
        .args(["wrap-bytecode", "--target", "luau", "--seed", "1", "-o"])
        .arg(&output)
        .arg(&input)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read_to_string(&output).unwrap(), "keep");
}

#[test]
fn binary_stdin_and_default_seed_reporting_are_reproducible() {
    for target in [Target::Lua51, Target::Luau] {
        let bytes = obf::vm::custom::compile("local x=7 print(x)", target).unwrap();
        let invoke = |seed: Option<&str>| {
            let mut command = command();
            command.args(["wrap-bytecode", "--target", &target.to_string()]);
            if let Some(seed) = seed {
                command.args(["--seed", seed]);
            }
            let mut child = command
                .arg("-")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&bytes).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            output
        };
        let output = invoke(None);
        let stderr = String::from_utf8(output.stderr).unwrap();
        let seed = stderr.trim().strip_prefix("seed: ").unwrap();
        assert_eq!(invoke(Some(seed)).stdout, output.stdout);
        assert!(!output.stdout.contains(&b'\n'));
        let first = invoke(Some("735"));
        let second = invoke(Some("736"));
        assert_ne!(first.stdout, second.stdout);
    }
}
