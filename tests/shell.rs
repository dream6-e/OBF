//! XXS 压缩外壳的集成门：真机跑通、成品形状、以及"改一个字符必须死"。
//!
//! 输入用仓库里的两份 golden（`vm_lua51.out.lua` / `vm_luau.out.lua`），所以这里测的是
//! **成品**被再包一层、并过完 finalizer 之后的行为，不是合成的样例。

mod support;

use obf::shell;
use obf::Target;
use std::fs;
use std::path::Path;
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

fn run(path: &Path, binary: &str) -> std::process::Output {
    Command::new(runner(binary))
        .arg(path)
        .output()
        .unwrap_or_else(|error| panic!("failed to launch {binary}: {error}"))
}

/// 最终成品里的显式 `local` 名称必须全被换成 1-2 个小写字母（与 golden 同一策略），
/// 并且不得把原名字留着不改。这里按内容扫，不依赖任何发射端局部名（改名会把名字类断言证伪）。
fn assert_every_local_is_a_random_short_name(script: &str) {
    let bytes = script.as_bytes();
    let mut offenders: Vec<String> = Vec::new();
    let mut index = 0usize;
    while let Some(found) = script[index..].find("local ") {
        let start = index + found + "local ".len();
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        // `local a, b = ...`：逐个名字看过去，直到 `=` 或行尾。
        let mut cursor = start;
        loop {
            let mut stop = cursor;
            while stop < bytes.len() && (bytes[stop].is_ascii_alphanumeric() || bytes[stop] == b'_')
            {
                stop += 1;
            }
            let name = &script[cursor..stop];
            let short =
                (1..=2).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_lowercase());
            if !short {
                offenders.push(name.to_owned());
            }
            if stop < bytes.len() && script[stop..].starts_with(", ") {
                cursor = stop + 2;
            } else {
                break;
            }
        }
        index = end.max(start);
    }
    assert!(
        offenders.is_empty(),
        "shell kept non-short or non-lowercase local names: {offers:?}",
        offers = offenders
    );
}

/// 外壳必须原样跑出与 golden 相同的结果——两个目标、多种子。
#[test]
fn shell_runs_the_wrapped_golden_identically_on_both_targets() {
    for (target, name, expect, seed, binary) in GOLDENS {
        let source = read_golden(name);
        for case_seed in [seed, seed + 1, 0, u64::MAX] {
            let wrapped = shell::wrap(&source, target, case_seed)
                .unwrap_or_else(|error| panic!("{target} seed {case_seed}: {error}"));
            let script = &wrapped.script;
            // 与两份 golden 同一套 finalizer 的结果形状：单物理行、无缩进 tab、
            // 首语句是 VM 的固定环境捕获、结尾是 `end)(...);`。
            assert_eq!(
                script.lines().count(),
                1,
                "{target} seed {case_seed}: the shell is not one physical line"
            );
            assert!(
                !script.contains('\t'),
                "{target} seed {case_seed}: indentation survived the lexical pass"
            );
            assert!(
                script.starts_with("local ") && script.contains("(getfenv and getfenv(1))or _G"),
                "{target} seed {case_seed}: the audited environment capture is missing"
            );
            // 与 golden 同一条尾部约定：没有结尾换行（`cmp`/`wc -l` 都按这个口径）。
            assert!(
                script.ends_with("end)(...);") && !script.ends_with("\n"),
                "{target} seed {case_seed}: the wrapper tail changed"
            );
            assert_every_local_is_a_random_short_name(script);
            let workspace = support::Workspace::new();
            let path = workspace.0.join(format!("shell-{case_seed}.lua"));
            fs::write(&path, script).unwrap();
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
            // 比率门。2026-09-13 随「外壳也过 finalizer」一起**收紧**（不是放宽）：
            // 单行化 + 短名实测 Lua51 最坏 0.652、Luau 最坏 0.676（四个被采样种子），
            // 旧的 0.66 / 0.69 是套壳前的宽松上界。留 0.003 余量，回退必须显式重测。
            let ratio = wrapped.ratio();
            let limit = if target == Target::Lua51 {
                0.655
            } else {
                0.679
            };
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

/// 静态面：`XXS` 改名到位、反射名不成明文、不依赖 5.1 没有的东西、也不把原脚本留在明文里。
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
            script.contains("\"XXS\".."),
            "{target}: the XXS chunkname prefix is missing"
        );
        assert!(
            script.contains("string.rep(\" \",4)"),
            "{target}: the XXS chunkname padding is missing"
        );
        assert!(
            script.contains("XXS decompression error:"),
            "{target}: XXS assert message is missing"
        );
        // loader 是运行期拼出来的，所以这些词在成品里必须一个都不出现。
        for forbidden in [
            "string.pack",
            "string.unpack",
            "bit.",
            "bit32.",
            "buffer.",
            "loadstring",
            "load(",
            "getfenv(0)",
            "debug.",
        ] {
            assert!(
                !script.contains(forbidden),
                "{target}: shell spells {forbidden}, which is either unportable or a reflection anchor"
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

/// 所有双引号字面量的内部区间（成品里没有转义引号，可以直接扫）。
fn quoted_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            if let Some(offset) = bytes[index + 1..].iter().position(|&byte| byte == b'"') {
                spans.push((index + 1, index + 1 + offset));
                index = index + 2 + offset;
                continue;
            }
        }
        index += 1;
    }
    spans
}

/// 改一个字符必须死在 `loadstring` 之前，且不得留下任何输出。
#[test]
fn shell_tampering_dies_before_user_code_runs() {
    for (target, name, _, seed, binary) in GOLDENS {
        let source = read_golden(name);
        let wrapped = shell::wrap(&source, target, seed).unwrap();
        let alphabet = shell::base85_alphabet(seed);
        let spans = quoted_spans(&wrapped.script);
        // 最长的那段字面量就是 base85 负载；85 字符那段是置换过的数字表。
        let payload = spans
            .iter()
            .copied()
            .max_by_key(|(start, stop)| stop - start)
            .expect("payload literal");
        let digits = *spans
            .iter()
            .find(|(start, stop)| stop - start == 85)
            .expect("digit table literal");
        let cases: Vec<(&str, String)> = vec![
            (
                // 同长度表里换一个符号：长度不变，解出来的值变 => 折叠/长度必死。
                "symbol",
                {
                    let mut text = wrapped.script.clone();
                    let at = payload.0 + 1024;
                    let original = text.as_bytes()[at];
                    let replacement = if original == alphabet[0] {
                        alphabet[1]
                    } else {
                        alphabet[0]
                    };
                    text.replace_range(at..at + 1, &char::from(replacement).to_string());
                    text
                },
            ),
            (
                // 数字表整体旋转一格：每个符号的值都变了。
                "digit table",
                {
                    let text = &wrapped.script[digits.0..digits.1];
                    let mut rotated = String::from(&text[1..]);
                    rotated.push(text.as_bytes()[0] as char);
                    wrapped.script.replacen(text, &rotated, 1)
                },
            ),
            ("truncated", wrapped.script[..payload.0 + 400].to_owned()),
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

/// 入库的两份压缩产物必须就是「当前实现 + 固定种子 + 对应 golden」的产物：
/// 交付时上传的是它们，不是临时文件，所以过期必须红灯（与 golden 的 `cmp` 同一口径）。
#[test]
fn checked_in_shell_artifacts_are_the_golden_regeneration() {
    for (target, golden, shell_name, seed) in [
        (
            Target::Lua51,
            "vm_lua51.out.lua",
            "vm_lua51.shell.out.lua",
            7001u64,
        ),
        (
            Target::Luau,
            "vm_luau.out.lua",
            "vm_luau.shell.out.lua",
            7351u64,
        ),
    ] {
        let source = read_golden(golden);
        let expected = shell::wrap(&source, target, seed)
            .unwrap_or_else(|error| panic!("{target}: {error}"))
            .script;
        let path = support::root().join(shell_name);
        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{shell_name} is not checked in: {error}"));
        assert_eq!(
            committed.as_bytes(),
            expected.as_bytes(),
            "{shell_name} is stale; rebuild with `obf shell --target {target} --seed {seed}` (§10.2)"
        );
        // 入库产物的形状：单物理行，首语句是 VM 的固定捕获，尾是 `end)(...);`。
        assert_eq!(committed.lines().count(), 1, "{shell_name}: not one line");
        assert_eq!(
            committed.bytes().filter(|byte| *byte == b'\n').count(),
            0,
            "{shell_name}: a single line must not carry any newline byte"
        );
        assert!(
            committed.starts_with("local ") && committed.ends_with("end)(...);"),
            "{shell_name}: unexpected head/tail"
        );
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
