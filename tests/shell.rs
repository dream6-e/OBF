//! XXS 压缩外壳的集成门：真机跑通、静态面、以及"改一个字符必须死"。
//!
//! 输入用仓库里的两份 golden（`vm_lua51.out.lua` / `vm_luau.out.lua`），所以这里测的是
//! **成品**被再包一层之后的行为，不是合成的样例。

mod support;

use obf::shell;
use obf::Target;
use std::fs;
use std::process::Command;

const GOLDENS: [(Target, &str, &str, u64, &str); 2] = [
    (
        Target::Lua51,
        "vm_lua51.out.lua",
        "vm:lua51:ok",
        7001,
        "lua5.1",
    ),
    (Target::Luau, "vm_luau.out.lua", "vm:luau:ok", 7351, "luau"),
];

fn read_golden(name: &str) -> String {
    fs::read_to_string(support::root().join(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn runner(binary: &str) -> std::path::PathBuf {
    support::root().join("toolchains/bin").join(binary)
}

fn run(path: &std::path::Path, binary: &str) -> std::process::Output {
    Command::new(runner(binary))
        .arg(path)
        .output()
        .unwrap_or_else(|error| panic!("failed to launch {binary}: {error}"))
}

/// 外壳必须原样跑出与 golden 相同的结果——两个目标、多个种子。
#[test]
fn shell_runs_the_wrapped_golden_identically_on_both_targets() {
    for (target, name, expect, seed, binary) in GOLDENS {
        let source = read_golden(name);
        for case_seed in [seed, seed + 1, 0, u64::MAX] {
            let wrapped = shell::wrap(&source, target, case_seed)
                .unwrap_or_else(|error| panic!("{target} seed {case_seed}: {error}"));
            assert_eq!(
                wrapped.script.lines().last(),
                Some("end)(...);"),
                "{target} seed {case_seed}: shell is not the mirrored loader shape"
            );
            let workspace = support::Workspace::new();
            let path = workspace.0.join(format!("shell-{case_seed}.lua"));
            fs::write(&path, &wrapped.script).unwrap();
            let output = run(&path, binary);
            assert!(
                output.status.success(),
                "{target} seed {case_seed}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&output.stdout).trim(),
                expect,
                "{target} seed {case_seed}: wrapped output differs"
            );
            // 尺寸账：负载 = 压缩流 base85 后 + 固定外壳；比例按实测钉住（只许变小，不许变大）。
            let ratio = wrapped.ratio();
            let limit = if target == Target::Lua51 { 0.66 } else { 0.69 };
            assert!(
                ratio <= limit,
                "{target} seed {case_seed}: ratio {ratio:.3} over the recorded {limit}"
            );
        }
    }
}

/// 同一份输入 + 同一种子必须逐字节一致（外壳自己也要是可复现的产物）。
#[test]
fn shell_is_reproducible_and_seed_dependent() {
    let source = read_golden("vm_lua51.out.lua");
    let one = shell::wrap(&source, Target::Lua51, 7001).unwrap();
    let same = shell::wrap(&source, Target::Lua51, 7001).unwrap();
    let other = shell::wrap(&source, Target::Lua51, 7002).unwrap();
    assert_eq!(
        one.script, same.script,
        "wrapper output is not deterministic"
    );
    assert_ne!(one.script, other.script, "seed did not reach the wrapper");
}

/// 静态面：`XXS` 改名到位、不依赖 5.1 没有的东西、也不把原脚本留在明文里。
#[test]
fn shell_static_surface_is_portable_and_renamed() {
    for (target, name, _, seed, _) in GOLDENS {
        let source = read_golden(name);
        let wrapped = shell::wrap(&source, target, seed).unwrap();
        let script = &wrapped.script;
        assert!(
            !script.contains("Luraph"),
            "{target}: the old marker survived"
        );
        assert!(
            script.contains("\"XXS\" .. string.rep(\" \", 4)"),
            "{target}: XXS chunkname is missing"
        );
        assert!(
            script.contains("XXS decompression error:"),
            "{target}: XXS assert message is missing"
        );
        for forbidden in [
            "string.pack",
            "string.unpack",
            "bit.",
            "bit32.",
            "buffer.",
            "loadstring(",
        ] {
            assert!(
                !script.contains(forbidden),
                "{target}: shell depends on {forbidden}, which one of the targets lacks"
            );
        }
        // 原脚本不得以可读形式残留在外壳里（负载必须是 base85 之后的 token 流）。
        let probe = source.lines().next().unwrap_or("");
        let head: String = probe.chars().take(64).collect();
        assert!(!head.is_empty());
        assert!(
            !script.contains(&head),
            "{target}: payload leaked in the clear"
        );
    }
}

/// 改一个字符必须死在 `loadstring` 之前，且不得留下任何输出。
#[test]
fn shell_tampering_dies_before_user_code_runs() {
    for (target, name, _, seed, binary) in GOLDENS {
        let source = read_golden(name);
        let wrapped = shell::wrap(&source, target, seed).unwrap();
        let payload_at = wrapped
            .script
            .find("local E = [=[")
            .expect("payload literal")
            + "local E = =[".len()
            + 1;
        let cases: Vec<(&str, String)> = vec![
            (
                // 一个 base85 符号换成同长度表里的另一个 => 解码出的字节变了。
                "symbol",
                {
                    let mut text = wrapped.script.clone();
                    let original = text.as_bytes()[payload_at];
                    let replacement = if original == b'0' { b'1' } else { b'0' };
                    text.replace_range(
                        payload_at..payload_at + 1,
                        &char::from(replacement).to_string(),
                    );
                    text
                },
            ),
            (
                "digit table",
                wrapped
                    .script
                    .replacen("local D = [=[", "local D = [=[X", 1),
            ),
            ("truncated", wrapped.script[..payload_at + 400].to_owned()),
        ];
        let workspace = support::Workspace::new();
        for (case, text) in cases {
            let path = workspace.0.join(format!("tamper-{case}.lua"));
            fs::write(&path, format!("{text}\n")).unwrap();
            let output = run(&path, binary);
            assert!(
                !output.status.success(),
                "{target}: {case} tampering still ran"
            );
            assert!(
                output.stdout.is_empty(),
                "{target}: {case} tampering leaked output"
            );
        }
    }
}

/// 没有收益就不包：小脚本 / 近随机的输入必须被明确拒绝，而不是悄悄变大。
#[test]
fn shell_refuses_inputs_it_cannot_shrink() {
    let tiny = "print(1)\n".repeat(8);
    let error = shell::wrap(&tiny, Target::Lua51, 1).unwrap_err();
    assert!(
        error.message.contains("no gain"),
        "unexpected refusal: {error}"
    );
}
