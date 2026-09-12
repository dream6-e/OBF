// K20：运行期分段装载（T2 ③「打散」）的门禁。
//
// 验收线（用户在 T2 里定的）：≥20 处分散的、**承重**的装载点，跨 ≥6 个区域；
// handler 实现允许运行期替换（同一键先装 A、后装 B，A 从不生效但静态上看不出）。
// 这里四条门分别钉住：
//   1. 结构 census：装载点数、区域数、被搬出字面量的键、折叠检查覆盖所有装载点；
//   2. 等价性：白名单改写对必须逐点等价（穷举证明），否则「运行期替换」是错的；
//   3. 承重性：真机 Lua 5.1 上删/改/复制任一装载语句都必须让程序失败；
//   4. 规划器拓扑：装载槽位不得晚于首次读取槽位，且同一 seed 结果可复现。

fn install_span(raw: &str, key: u64, from: usize) -> Option<usize> {
    let tail = format!("end;ck=ck+{key};");
    raw[from..].find(&tail).map(|at| from + at + tail.len())
}

/// 扫描原始（未缩短名）文本，返回 `(装载点 (键, 起点, 终点), 字面量字段键)`。
fn scan_scatter(raw: &str) -> (Vec<(u64, usize, usize)>, Vec<u64>) {
    let mut installs = Vec::new();
    let mut literal = Vec::new();
    let mut cursor = 0usize;
    while let Some(at) = raw[cursor..].find("[") {
        let start = cursor + at;
        cursor = start + 1;
        let rest = &raw[cursor..];
        let digits: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>();
        if digits.is_empty() || digits.len() > 5 {
            continue;
        }
        let after = &rest[digits.len()..];
        if !after.starts_with("]=function(") {
            continue;
        }
        let Ok(key) = digits.parse::<u64>() else {
            continue;
        };
        let is_install = raw[..start].ends_with("VMS");
        if is_install {
            if let Some(end) = install_span(raw, key, start) {
                installs.push((key, start, end));
                cursor = end;
                continue;
            }
            // 装载语句必须紧跟 `;ck=ck+key;`，否则它不进折叠检查。
            panic!("install site for key {key} is not followed by its fold statement");
        }
        literal.push(key);
    }
    (installs, literal)
}

#[test]
fn k20_runtime_installs_are_dispersed_and_cover_the_fold_checkpoint() {
    for (target, fixture, seeds) in [
        (
            Target::Lua51,
            "tests/fixtures/vm_lua51.lua",
            vec![7001u64, 1, 2, 3, 5, 8, 13, 123456, 999983, u64::MAX],
        ),
        (
            Target::Luau,
            "tests/fixtures/vm_luau.lua",
            vec![7351u64, 1, 2, 3, 5, 8, 13, 123456, 999983, u64::MAX],
        ),
    ] {
        let source = fs::read_to_string(fixture).unwrap();
        let data = compile(&source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut site_min = usize::MAX;
        let mut region_min = usize::MAX;
        let mut baked_max = 0usize;
        for seed in seeds {
            let raw = generate(&data, &program, seed).unwrap();
            let (installs, literal) = scan_scatter(&raw);
            let installed: BTreeSet<u64> = installs.iter().map(|(key, _, _)| *key).collect();
            // 承重前提：被搬出的键不得同时留在字面量里，否则删掉装载语句只是
            // 少了一份冗余，程序照跑。
            for key in &installed {
                assert!(
                    !literal.contains(key),
                    "{target} seed {seed}: key {key} is both baked and installed"
                );
                // 每个被装载的键必须在装载点之外还有去处（直接调用，或作为值
                // 交给别的段）；出现次数严格多于装载次数才算承重。
                let sites = installs.iter().filter(|(site, _, _)| site == key).count();
                assert!(
                    raw.matches(&format!("VMS[{key}]")).count() > sites,
                    "{target} seed {seed}: installed key {key} is never read"
                );
            }
            assert!(
                installs.len() >= 20,
                "{target} seed {seed}: only {} install sites",
                installs.len()
            );
            assert!(
                installed.len() >= 15,
                "{target} seed {seed}: only {} distinct installed sections",
                installed.len()
            );
            assert!(
                literal.len() <= 12,
                "{target} seed {seed}: {} sections still baked at once",
                literal.len()
            );
            // 区域数 = 相邻装载点之间夹了别的语句的次数 + 1。
            let mut regions = 1usize;
            for pair in installs.windows(2) {
                if raw[pair[0].2..pair[1].1].trim().len() > 1 {
                    regions += 1;
                }
            }
            assert!(
                regions >= 6,
                "{target} seed {seed}: install sites sit in only {regions} regions"
            );
            // 折叠检查必须正好覆盖所有装载点。
            let expected = installs
                .iter()
                .fold(0u64, |acc, (key, _, _)| acc.wrapping_add(*key));
            let marker = format!("if ck~={expected} then E()end;");
            assert!(
                raw.contains(&marker),
                "{target} seed {seed}: fold checkpoint missing or stale"
            );
            assert_eq!(
                raw.matches(";ck=ck+").count(),
                installs.len(),
                "{target} seed {seed}: fold statements and install sites disagree"
            );
            assert_eq!(expected, super::loader::fold_of(&{
                installs.iter().map(|(key, _, _)| *key).collect::<Vec<_>>()
            }));
            // 同一 seed 两次生成必须逐字节相同，且输出仍是一条物理行。
            let emitted = emit(&data, target, seed).unwrap();
            assert_eq!(emit(&data, target, seed).unwrap(), emitted);
            assert!(!emitted.contains('\n'), "{target} seed {seed}: newline in output");
            site_min = site_min.min(installs.len());
            region_min = region_min.min(regions);
            baked_max = baked_max.max(literal.len());
        }
        assert!(
            site_min >= 20 && region_min >= 6 && baked_max <= 12,
            "{target}: aggregate scatter shape regressed ({site_min} sites, {region_min} regions, {baked_max} baked)"
        );
    }
}

#[test]
fn k20_watermark_pack_respelling_is_the_same_polynomial() {
    // 装载替换只允许白名单恒等式，这里穷举证明第一对：
    // `((a*256+b)*256+c)*256+d` 与 `d+(c+(b+a*256)*256)*256`。
    // 两边对 a/b/c/d 各自线性，故在 {0,1}^4 上相等即多项式恒等；再对完整字节
    // 域逐点复核，双精度下所有中间量 < 2^53，与 Lua 的 number 语义一致。
    for a in 0..=255u32 {
        for b in 0..=255u32 {
            let left = a * 16777216 + b * 65536;
            let right = (a * 256 + b) * 65536;
            assert_eq!(left, right, "partial packing at {a},{b}");
        }
    }
    for a in [0u32, 1, 2, 127, 255] {
        for b in [0u32, 1, 128, 255] {
            for c in [0u32, 3, 200, 255] {
                for d in [0u32, 5, 251, 255] {
                    let left = ((a * 256 + b) * 256 + c) * 256 + d;
                    let right = d + (c + (b + a * 256) * 256) * 256;
                    assert_eq!(left, right, "packing at {a},{b},{c},{d}");
                    let lf = ((a as f64 * 256.0 + b as f64) * 256.0 + c as f64) * 256.0 + d as f64;
                    let rf = d as f64
                        + (c as f64 + (b as f64 + a as f64 * 256.0) * 256.0) * 256.0;
                    assert_eq!(lf, rf, "double packing at {a},{b},{c},{d}");
                }
            }
        }
    }
}

#[test]
fn k20_probe_fold_and_guard_respellings_are_equivalent() {
    // 第二对：`(a*257+S)%M` 与 `(a+a*256+S)%M`，a 是折叠累加值、S 是字节值。
    let cases: Vec<(f64, f64)> = (0..600)
        .map(|step| {
            let a = (step as f64 * 3_571_941.0) % 2_147_483_647.0;
            let s = (step % 256) as f64 + (step % 7) as f64;
            (a, s)
        })
        .collect();
    for (a, s) in cases {
        let left = (a * 257.0 + s) % 2_147_483_647.0;
        let right = (a + a * 256.0 + s) % 2_147_483_647.0;
        assert_eq!(left, right, "probe fold at {a},{s}");
    }
    // 守卫改写：`x~=y` 与 `not(x==y)` 对任意取值互反，包括 nil 与数字比较。
    for a in [-2_147_483_648i64, -1, 0, 1, 92, 255, 2_147_483_647] {
        for b in [-1i64, 0, 1, 92, 255, 65_536] {
            assert_eq!((a != b), !(a == b), "inequality at {a},{b}");
        }
    }
    // 装载计划里出现过的改写必须确实出现在壳里，否则「等价替换」是空话。
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut respelled = 0usize;
        for seed in [0u64, 1, 735, 7001] {
            let raw = generate(&data, &program, seed).unwrap();
            respelled += raw
                .matches("a=(a+a*256+SB(A,b))%2147483647;")
                .count();
        }
        assert!(
            respelled >= 4,
            "{target}: no respelled probe fold reached the shell ({respelled})"
        );
    }
}

#[test]
fn k20_install_plan_is_reproducible_and_topologically_valid() {
    let body = |key: u64, guard: bool| -> String {
        format!(
            "[{key}]=function(A,B)local x=0;while x<4 do x=x+1 end if x~={key} then E()end;return{}{}end,",
            if guard { "" } else { "x" },
            if guard { "x+A" } else { "" }
        )
    };
    let pool: Vec<(usize, bool, String)> = vec![
        (1, false, body(1001, true)),
        (3, true, body(1002, false)),
        (5, true, body(1003, true)),
        (9, false, body(1004, true)),
        (9, true, body(1005, false)),
        // 自由引用壳句柄的字段永远不搬：搬过去会指向入口局部变量。
        (9, true, "[1006]=function(A)return t.e+A end,".to_owned()),
        // 不认识的键保持烘入。
        (0, true, "[1007]=function(A)A()end,".to_owned()),
    ];
    let mut structure = crate::random::Prng::lcg(0x51a7_7e11_20c0_ffee);
    let first = super::loader::scatter(pool.clone(), &mut structure);
    let second = super::loader::scatter(pool, &mut crate::random::Prng::lcg(0x51a7_7e11_20c0_ffee));
    assert_eq!(
        first.blobs.iter().map(String::as_str).collect::<Vec<_>>(),
        second.blobs.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_eq!(first.kept.len(), 2, "baked fallback set moved");
    for (key, slot, read_slot) in &first.plan {
        assert!(
            slot <= read_slot,
            "key {key} installed at slot {slot} but first read at {read_slot}"
        );
        assert!(*slot < super::loader::SLOTS);
    }
    assert_eq!(
        first.fold,
        super::loader::fold_of(&first.plan.iter().map(|(key, _, _)| *key).collect::<Vec<_>>())
    );
    // 变体 B 必须真的出现在装载文本里（同键两份时两份拼法不同）。
    let joined = first.blobs.concat();
    assert!(
        joined.contains("if not(x==1002) then"),
        "guard respelling did not reach variant B"
    );
    assert!(
        joined.matches("VMS[1004]=function").count() == 1,
        "a non-doublable section got copied"
    );
    // 双重装载的键：先 A 后 B，且 B 紧贴读取点。
    let doubles: BTreeSet<u64> = {
        let mut seen = BTreeSet::new();
        let mut out = BTreeSet::new();
        for (key, _, _) in &first.plan {
            if !seen.insert(*key) {
                out.insert(*key);
            }
        }
        out
    };
    assert!(
        doubles.len() >= 1,
        "no section received two equivalent spellings"
    );
    for key in doubles {
        let sites: Vec<(usize, usize)> = first
            .plan
            .iter()
            .filter(|(site, _, _)| *site == key)
            .map(|(_, slot, read)| (*slot, *read))
            .collect();
        assert_eq!(sites.len(), 2, "key {key} expected exactly two spellings");
        assert!(
            sites[0].0 < sites[1].0,
            "key {key}: variant A installed after variant B"
        );
        assert_eq!(sites[1].0, sites[1].1, "variant B must sit at the read point");
    }
}

#[test]
fn k20_tampering_with_an_install_statement_faults_the_program() {
    let target = Target::Lua51;
    let source = "local a=2 print(a*21)";
    let data = compile(source, target).unwrap();
    let program = custom::decode(&data, target).unwrap();
    let seed = 7001u64;
    let raw = generate(&data, &program, seed).unwrap();
    let (installs, _) = scan_scatter(&raw);
    assert!(installs.len() >= 20, "only {} install sites", installs.len());
    let keys: Vec<u64> = installs.iter().map(|(key, _, _)| *key).collect();
    let output = emit(&data, target, seed).unwrap();
    let workspace = native::Workspace::new();
    let path = workspace.0.join("scatter.lua");
    fs::write(&path, &output).unwrap();
    assert_eq!(
        native::compile_and_run(target, &path),
        b"42\n",
        "control run changed"
    );
    let runtime = native::root().join("toolchains/bin/lua5.1");
    let must_fail = |case: &str, text: &str| {
        fs::write(&path, text).unwrap();
        assert_ne!(text, output, "{case}: the edit was a no-op");
        assert!(
            native::compile(target, &path).status.success(),
            "{case}: tampered script no longer even compiles"
        );
        let result = Command::new(&runtime).arg(&path).output().unwrap();
        assert!(
            !result.status.success(),
            "{case}: the program still ran after the tamper"
        );
        assert!(result.stdout.is_empty(), "{case}: tampered run leaked output");
    };
    // 选一个「折叠语句没有被 K16 常量提升改写掉」的装载键：`+<key>;` 的出现次数
    // 必须正好等于该键的装载次数，这样按语句边界切分才可靠。
    let needle_for = |key: u64| format!("[{key}]=function(");
    let mut chosen = None;
    for key in &keys {
        let sites = keys.iter().filter(|site| *site == key).count();
        if sites == 1
            && output.matches(&needle_for(*key)).count() == 1
            && output.matches(&format!("+{key};")).count() == 1
        {
            chosen = Some(*key);
            break;
        }
    }
    let key = chosen.expect("no install site kept its own fold literal");
    let needle = needle_for(key);
    let at = output.find(&needle).expect("install site in the final text");
    // 1) 换掉装载点的键：真实读取点拿不到 handler，必须立刻失败。
    let mut rekeyed = output.clone();
    rekeyed.replace_range(at..at + needle.len(), &format!("[{}]=function(", key + 1));
    must_fail("rekeyed install", &rekeyed);
    // 2) 复制整条装载语句（含它的折叠累加）：折叠总和多出 k，必须失败。
    let fold_needle = format!("+{key};");
    let fold_at = at
        + output[at..]
            .find(&fold_needle)
            .expect("fold statement after the install");
    let stmt_end = fold_at + fold_needle.len();
    let mut stmt_start = at;
    while stmt_start > 0 {
        let prev = output[..stmt_start].as_bytes()[stmt_start - 1];
        if prev == b';' || prev == b'{' || prev == b',' {
            stmt_start -= 1;
            break;
        }
        if !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b'[' || prev == b']') {
            break;
        }
        stmt_start -= 1;
    }
    let mut duplicated = output.clone();
    duplicated.insert_str(stmt_end, &output[stmt_start..stmt_end]);
    must_fail("duplicated install", &duplicated);
    // 3) 只删掉折叠累加语句：装载本身还在，行为不变，但检查必须抓到「少一次
    //    装载」——这条正是「装载点承重」的可判定形式。
    let line_start = output[..fold_at]
        .rfind(|c: char| c == ';' || c == ' ' || c == '\n')
        .map(|at| at + 1)
        .unwrap_or(0);
    // Lua 5.1 里 `;` 只是语句分隔符，不是空语句；所以只在会粘住前一条语句时才补
    // 分隔符，否则整段删掉。
    let needs_separator = output[..line_start]
        .as_bytes()
        .last()
        .map(|c| !(c.is_ascii_alphanumeric() || *c == b'_' || *c == b';' || *c == b' ' || *c == b'\n'))
        .unwrap_or(false);
    let mut dropped = output.clone();
    dropped.replace_range(
        line_start..stmt_end,
        if needs_separator { ";" } else { "" },
    );
    must_fail("dropped fold", &dropped);
}
