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

/// M3 batch gate: the one-step obfuscator mode `obf input.lua --luau|--lua51
/// [--MB]` must feed a source through the full pipeline (virtualize, and with
/// --MB the compressed self-expanding shell on top), print a reproducible
/// seed to stderr, stay backwards-rejective on every neighbouring surface,
/// and keep the classic subcommands untouched.
#[test]
fn one_step_obfuscator_mode_virtualizes_and_shells_with_reproducible_runs() {
    let work = Workspace::new();
    let input = work.0.join("obfme.lua");
    fs::write(&input, "local x=1 for i=1,3 do x=x+i end print(\"ok:\"..x)").unwrap();
    let default_out = work.0.join("obfuscated.lua");
    for (flag, target) in [("--luau", Target::Luau), ("--lua51", Target::Lua51)] {
        let run_in_work = |args: &[&str]| {
            let mut cmd = command();
            cmd.current_dir(&work.0).arg(&input).args(args);
            let output = success(&mut cmd);
            assert!(
                output.stdout.is_empty(),
                "{flag} {args:?}: one-step mode writes files, never stdout"
            );
            output
        };
        // Plain mode without -o: obfuscated.lua appears in the current
        // directory, and a fresh seed is reported on stderr.
        let _ = fs::remove_file(&default_out);
        let plain = run_in_work(&[flag]);
        let plain_bytes =
            fs::read(&default_out).expect("one-step mode must write ./obfuscated.lua");
        let stderr = String::from_utf8(plain.stderr).unwrap();
        let seed_line = stderr
            .lines()
            .find(|line| line.starts_with("seed: "))
            .expect("obfuscate mode must report its seed");
        let seed = seed_line.trim_start_matches("seed: ");
        assert!(stderr.contains("output: obfuscated.lua"), "{stderr}");
        // Replaying the reported seed rewrites the same file byte-identically.
        run_in_work(&[flag, "--seed", seed]);
        assert_eq!(
            fs::read(&default_out).unwrap(),
            plain_bytes,
            "{flag}: seed replay diverging"
        );
        let stdout = compile_and_run(target, &default_out);
        assert_eq!(&stdout, b"ok:7\n");
        // An explicit -o overrides the default name and yields the same bytes.
        let explicit_out = work.0.join(format!("explicit-{target}.lua"));
        let explicit_name = explicit_out.to_str().unwrap().to_string();
        run_in_work(&[flag, "--seed", seed, "-o", &explicit_name]);
        assert_eq!(
            fs::read(&explicit_out).unwrap(),
            plain_bytes,
            "{flag}: -o output diverging from the default-name run"
        );
        // --MB: the compressed self-expanding wrapper; also native-run.
        run_in_work(&[flag, "--seed", seed, "--MB"]);
        let wrapped_bytes = fs::read(&default_out).unwrap();
        assert_ne!(wrapped_bytes, plain_bytes, "{flag}: --MB must wrap the VM");
        let stdout = compile_and_run(target, &default_out);
        assert_eq!(&stdout, b"ok:7\n");
    }
}

#[test]
fn one_step_obfuscator_mode_accepts_bare_backend_words_and_option_separator() {
    let work = Workspace::new();
    let input = work.0.join("bare.lua");
    fs::write(&input, "local x=2 print('n:'..x*3)").unwrap();
    let default_out = work.0.join("obfuscated.lua");
    for (word, flag, target) in [
        ("luau", "--luau", Target::Luau),
        ("lua51", "--lua51", Target::Lua51),
    ] {
        // A bare backend word selects byte-identical output to the dashed flag.
        let dashed_out = work.0.join(format!("dashed-{word}.lua"));
        let dashed_name = dashed_out.to_str().unwrap().to_string();
        success(
            command()
                .arg(&input)
                .args([flag, "--seed", "97", "-o", &dashed_name]),
        );
        let mut separated = command();
        separated
            .current_dir(&work.0)
            .arg(&input)
            .arg("--")
            .args([word, "--seed", "97"]);
        success(&mut separated);
        assert_eq!(
            fs::read(&default_out).unwrap(),
            fs::read(&dashed_out).unwrap(),
            "{word}: bare word must select the same backend as {flag}"
        );
        // The `--` separator does not swallow later flags, --MB included, and
        // the written script still runs in the native interpreter.
        let mut wrapped = command();
        wrapped
            .current_dir(&work.0)
            .arg(&input)
            .args([word, "--", "--MB", "--seed", "97"]);
        let wrapped = success(&mut wrapped);
        assert!(String::from_utf8(wrapped.stderr)
            .unwrap()
            .contains("ratio="));
        let stdout = compile_and_run(target, &default_out);
        assert_eq!(&stdout, b"n:6\n");
    }
    // Mixing spellings still counts as two backend choices.
    let mixed = command()
        .arg(&input)
        .args(["--luau", "lua51"])
        .output()
        .unwrap();
    assert!(!mixed.status.success());
    assert!(String::from_utf8(mixed.stderr)
        .unwrap()
        .contains("choose exactly one"));
    let two_bare = command()
        .arg(&input)
        .args(["lua51", "luau"])
        .output()
        .unwrap();
    assert!(!two_bare.status.success());
    assert!(String::from_utf8(two_bare.stderr)
        .unwrap()
        .contains("choose exactly one"));
    // --target and a bare backend word stay mutually exclusive.
    let with_target = command()
        .arg(&input)
        .args(["--target", "luau", "lua51"])
        .output()
        .unwrap();
    assert!(!with_target.status.success());
    assert!(String::from_utf8(with_target.stderr)
        .unwrap()
        .contains("--target cannot be combined"));
    // Classic subcommands keep the strict surface: no separator sugar there.
    let classic = command()
        .args(["virtualize", "--target", "luau", "--", "--seed", "1"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(!classic.status.success());
    assert!(String::from_utf8(classic.stderr)
        .unwrap()
        .contains("unknown option '--'"));
}

#[test]
fn one_step_obfuscator_mode_rejects_every_abuse_of_its_flags() {
    let work = Workspace::new();
    let input = work.0.join("reject.lua");
    fs::write(&input, "print('x')").unwrap();
    // Two backend choices at once.
    let both = command()
        .arg(&input)
        .args(["--luau", "--lua51"])
        .output()
        .unwrap();
    assert!(!both.status.success());
    assert!(String::from_utf8(both.stderr)
        .unwrap()
        .contains("choose exactly one"));
    // No backend flag at all.
    let none = command().arg(&input).output().unwrap();
    assert!(!none.status.success());
    assert!(String::from_utf8(none.stderr)
        .unwrap()
        .contains("--luau or --lua51"));
    // --MB on a classic subcommand must not silently change behaviour.
    let classic = command()
        .args(["shell", "--target", "luau", "--MB"])
        .arg(&input)
        .output()
        .unwrap();
    assert!(!classic.status.success());
    assert!(String::from_utf8(classic.stderr)
        .unwrap()
        .contains("one-step obfuscator mode"));
    // An unknown word that is neither a command nor a .lua input.
    let unknown = command().arg("frobnicate").output().unwrap();
    assert!(!unknown.status.success());
    assert!(String::from_utf8(unknown.stderr)
        .unwrap()
        .contains("pass a .lua input first"));
}
