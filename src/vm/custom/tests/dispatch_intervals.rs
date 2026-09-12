// K21：opcode 分派改由**数字区间**判定。
//
// 语义解释器原先的两级分派是「`value % groups == 余数` 选子链 + 子链内一条扁平
// `if/elseif` 等值扫描」。本批把两级都换成区间判断：桶边界是区间测试，桶内是一棵
// 按边界值二分的区间树（`structure::grouped_interval_chain`）。文档里 T2 的验收线
// 只说「分派形状多样化」，所以这里钉的是**可判定**的三件事：
//
//   1. 结构 census（原始发射文本，重命名前）：取模选择器确实从 `rid`/`sid` 上消失；
//      区间节点数达到下限；每一枚边界既不是该链任何 handler 的等值测试值、也不是
//      审计漂亮常数 ⇒ 「读边界就能读出 opcode 集合」这条路被关掉；恒等守卫的回退值
//      同样不许是漂亮常数；拓扑随种子变化。
//   2. 拼写等价性（真机 Lua 5.1 上跑）：区间测试的所有拼法（含 `(v<=v and v or K)`
//      守卫形）对 v 必须是**单调**的、且跳变点恰好落在边界 B 上——也就是它们逐个
//      等价于 `v<=B` 或 `v>B`。这一步不靠 Rust 侧镜像自证。
//   3. 承重性（真机 Lua 5.1 上跑整份脚本）：把某枚边界挪到它上方最近的臂值——区间树里
//      唯一可能有语义的挪法（挪进 gap 中间本来就是语义 no-op，测了等于没测）——脚本要么
//      装载期致死，要么输出逐字节不变；**绝不允许跑出另一种结果**，那意味着边界上换了 handler。
//
// 扫描读 `generate()` 的原始文本：`finalize_vm` 会把局部改名成一到两个字母，
// 结构断言在最终文本上无从下手（K20 已经踩过一次）。

/// 审计漂亮常数：分派区的任意标签都不许拼出这些值（K9a 口径，与
/// `wrapper_keys`/`state_values` 一致）。
const INTERVAL_NICE: [u64; 4] = [86, 256, 7225, 7396];

/// 一个数值 token 的值（十进制、`0x` 十六进制、Luau 的 `0b1_0011` 分组二进制）。
fn interval_token_value(text: &str) -> Option<u64> {
    let (radix, digits) = if let Some(rest) = text.strip_prefix("0x") {
        (16, rest)
    } else if let Some(rest) = text.strip_prefix("0b") {
        (2, rest)
    } else {
        (10, text)
    };
    u64::from_str_radix(&digits.replace('_', ""), radix).ok()
}

/// 扫出某个分派变量上的 `(等值测试值集合, 区间边界序列)`。
///
/// 认得的形状与发射侧一一对应：等值 `v==N`/`N==v`/`not(v~=N)`/`v-N==0`；区间
/// `v<=N`/`N>=v`/`not(v>N)`/`v-N<=0`/`N-v>=0`，以及把变量藏进恒等式的
/// `(v<=v and v or K)<=N`、`not((v<=v and v or K)>N)`、`(v<=v and v or K)-N<=0`。
/// 赋值（`sid=288`）、声明与实参都不是比较，直接跳过。
pub(super) fn scan_dispatch_chain(
    raw: &str,
    target: Target,
    var: &str,
) -> (BTreeSet<u64>, BTreeSet<u64>, Vec<u64>) {
    let tokens = crate::lexer::lex(raw, target).unwrap();
    let text = |index: usize| -> &str {
        tokens
            .get(index)
            .map(|token| token.text(raw))
            .unwrap_or_default()
    };
    let is = |index: usize, word: &str| text(index) == word;
    let value = |index: usize| -> Option<u64> {
        tokens
            .get(index)
            .filter(|token| token.kind == crate::lexer::TokenKind::Number)
            .and_then(|token| interval_token_value(token.text(raw)))
    };
    let mut equality = BTreeSet::new();
    let mut bounds = BTreeSet::new();
    let mut order = Vec::new();
    for index in 0..tokens.len() {
        if !is(index, var) {
            continue;
        }
        // v <op> N
        if is(index + 1, "==") || is(index + 1, "~=") {
            if let Some(value) = value(index + 2) {
                equality.insert(value);
            }
            continue;
        }
        if is(index + 1, "<=") || is(index + 1, ">") {
            if let Some(value) = value(index + 2) {
                bounds.insert(value);
                order.push(value);
            }
            continue;
        }
        if is(index + 1, "-") {
            if let Some(value) = value(index + 2) {
                if is(index + 3, "==") {
                    equality.insert(value);
                } else if is(index + 3, "<=") || is(index + 3, ">") {
                    bounds.insert(value);
                    order.push(value);
                }
            }
            continue;
        }
        // `(v<=v and v or K)` 之后接比较符：守卫形。第三个 v 后面是 `or`。
        if is(index + 1, "or") {
            if is(index + 4, "<=") || is(index + 4, ">") {
                if let Some(value) = value(index + 5) {
                    bounds.insert(value);
                    order.push(value);
                }
            } else if is(index + 4, "-") {
                if let Some(value) = value(index + 5) {
                    bounds.insert(value);
                    order.push(value);
                }
            }
            continue;
        }
        if index < 3 {
            continue;
        }
        // N <op> v
        if is(index - 1, "==") {
            if let Some(value) = value(index - 2) {
                equality.insert(value);
            }
            continue;
        }
        if is(index - 1, ">=") || is(index - 1, "<") {
            if let Some(value) = value(index - 2) {
                bounds.insert(value);
                order.push(value);
            }
            continue;
        }
        // `N-v>=0` / `N-v<0`
        if is(index - 1, "-") {
            if let Some(value) = value(index - 2) {
                if is(index + 1, ">=") || is(index + 1, "<") {
                    bounds.insert(value);
                    order.push(value);
                }
            }
        }
    }
    (equality, bounds, order)
}

#[test]
fn k21_opcode_dispatch_partitions_by_numeric_intervals() {
    for (target, fixture, seeds) in [
        (
            Target::Lua51,
            "tests/fixtures/vm_lua51.lua",
            [7001u64, 7002, 7003, 7004, 7005, 1, 2, 7, 4242, u64::MAX],
        ),
        (
            Target::Luau,
            "tests/fixtures/vm_luau.lua",
            [7351u64, 7352, 7353, 7354, 7355, 1, 2, 7, 4242, u64::MAX],
        ),
    ] {
        let source = fs::read_to_string(fixture).unwrap();
        let data = compile(&source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut topologies: BTreeSet<Vec<u64>> = BTreeSet::new();
        let mut node_min = usize::MAX;
        let mut arm_min = usize::MAX;
        for seed in seeds {
            let raw = generate(&data, &program, seed).unwrap();
            // 同一 seed 两次生成必须逐字节相同，且整份脚本仍是一条物理行。
            let emitted = emit(&data, target, seed).unwrap();
            assert_eq!(emit(&data, target, seed).unwrap(), emitted);
            assert!(!emitted.contains('\n'), "{target} seed {seed}: newline in output");
            let mut chain_nodes = 0usize;
            for var in ["rid", "sid"] {
                assert!(
                    !raw.contains(&format!("{var}%")),
                    "{target} seed {seed}: {var} still carries the residue selector"
                );
                let (equality, bounds, order) = scan_dispatch_chain(&raw, target, var);
                assert!(
                    equality.len() >= 8,
                    "{target} seed {seed}: {var} only equality-tests {} values",
                    equality.len()
                );
                assert!(
                    bounds.len() >= 4,
                    "{target} seed {seed}: {var} has only {} interval nodes",
                    bounds.len()
                );
                arm_min = arm_min.min(equality.len());
                node_min = node_min.min(bounds.len());
                chain_nodes += bounds.len();
                for bound in &bounds {
                    assert!(
                        !equality.contains(bound),
                        "{target} seed {seed}: {var} bound {bound} is also an arm value"
                    );
                    assert!(
                        !INTERVAL_NICE.contains(bound),
                        "{target} seed {seed}: {var} bound {bound} is an audit-nice value"
                    );
                }
                topologies.insert(order);
            }
            // 每枚边界都必须真的把链上的值切开：左边有 handler，右边也有。
            for var in ["rid", "sid"] {
                let (equality, bounds, _) = scan_dispatch_chain(&raw, target, var);
                for bound in &bounds {
                    assert!(
                        equality.iter().any(|value| value <= bound)
                            && equality.iter().any(|value| value > bound),
                        "{target} seed {seed}: {var} bound {bound} splits no handler"
                    );
                }
            }
            assert!(
                chain_nodes >= 8,
                "{target} seed {seed}: only {chain_nodes} interval nodes across both chains"
            );
        }
        assert!(
            node_min >= 4 && arm_min >= 8,
            "{target}: smallest draw had {node_min} nodes over {arm_min} arms"
        );
        assert!(
            topologies.len() >= 2,
            "{target}: the interval topology is seed-independent"
        );
    }
}

#[test]
fn k21_guard_noise_values_never_spell_an_audit_nice_value() {
    // 守卫 `(v<=v and v or K)` 的回退值 K 是凭空多出来的字面量，它进入常数海洋
    // 之前必须先过漂亮常数筛子；同时 K 不得选中任何 handler——叶子仍带自己的
    // 等值测试，所以这里查的是「K 不是该链的等值测试值」这一条构造性保证。
    for (target, fixture) in [
        (
            Target::Lua51,
            "tests/fixtures/vm_lua51.lua",
        ),
        (Target::Luau, "tests/fixtures/vm_luau.lua"),
    ] {
        let source = fs::read_to_string(fixture).unwrap();
        let data = compile(&source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [7001u64, 7351, 3] {
            let raw = generate(&data, &program, seed).unwrap();
            let mut guard_noises = Vec::new();
            let mut cursor = 0usize;
            for var in ["rid", "sid"] {
                let marker = format!("and {var} or ");
                while let Some(offset) = raw[cursor..].find(&marker) {
                    let at = cursor + offset + marker.len();
                    cursor = at;
                    let digits: String = raw[at..]
                        .chars()
                        .take_while(|c| c.is_ascii_hexdigit() || *c == 'x' || *c == '_')
                        .collect();
                    if let Some(value) = interval_token_value(&digits) {
                        guard_noises.push(value);
                    }
                }
            }
            assert!(
                guard_noises.len() >= 4,
                "{target} seed {seed}: only {} guard forms",
                guard_noises.len()
            );
            for noise in &guard_noises {
                assert!(
                    !INTERVAL_NICE.contains(noise),
                    "{target} seed {seed}: guard fallback {noise} is an audit-nice value"
                );
            }
        }
    }
}

#[test]
fn k21_every_interval_spelling_is_a_monotone_cut_at_its_bound() {
    // 不靠 Rust 侧镜像：把每种拼法在真机 Lua 5.1 上对 v=0,B-2,B-1,B,B+1,B+2,65535
    // 逐个求值，要求真值向量恰好是 `v<=B`（TTTTFFF）或 `v>B`（FFFFTTT）。单调 +
    // 跳变点在 B 上，就证明这一枚测试确实是区间判断而不是别的谓词。
    let mut random = crate::random::Prng::lcg(0x2157);
    let mut forms: Vec<(bool, u64, String)> = Vec::new();
    for _trial in 0..400 {
        // Bounds stay inside [2, 65530] so the seven probe points below are all
        // distinct and straddle the cut.
        let bound = 2 + random.index(65529) as u64;
        let noise = (1 + random.index(999)) as u16;
        for below in [true, false] {
            let text = random.interval_condition("v", bound as u16, noise, below);
            if !forms.iter().any(|(_, _, seen)| seen == &text) {
                forms.push((below, bound, text));
            }
        }
        if forms.len() >= 16 {
            break;
        }
    }
    assert!(
        forms.len() >= 12,
        "only {} distinct interval spellings across 400 draws",
        forms.len()
    );
    let mut script = String::new();
    let mut expectations = Vec::new();
    for (below, bound, text) in forms.iter() {
        // 每个形状就用自己的那枚边界，逐点求值后打印一行 0/1。
        let mut line = String::new();
        for point in [0u64, bound - 2, bound - 1, *bound, bound + 1, bound + 2, 65535] {
            let condition = text.replace('v', &point.to_string());
            line.push_str(&format!(
                "if ({condition}) then io.write(1) else io.write(0) end "
            ));
        }
        expectations.push((*below, line));
    }
    for (below, line) in &expectations {
        script.push_str(line);
        script.push('\n');
    }
    script.push_str("print()");
    let workspace = native::Workspace::new();
    let path = workspace.0.join("interval_forms.lua");
    fs::write(&path, &script).unwrap();
    let runtime = native::root().join("toolchains/bin/lua5.1");
    let output = Command::new(&runtime).arg(&path).output().unwrap();
    assert!(
        output.status.success(),
        "form probe did not run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bits = String::from_utf8(output.stdout).unwrap();
    let bits = bits.trim();
    assert_eq!(
        bits.len(),
        expectations.len() * 7,
        "form probe printed {bits:?}, expected one row of 7 bits per form"
    );
    let low = "1111000";
    let high = "0000111";
    for (index, (below, _)) in expectations.iter().enumerate() {
        let row = &bits[index * 7..index * 7 + 7];
        let want = if *below { low } else { high };
        assert_eq!(
            row, want,
            "interval spelling {:?} is not an exact cut at its bound",
            forms[index].2
        );
    }
}

#[test]
fn k21_moving_an_interval_bound_cannot_swap_a_handler() {
    // 把一枚边界挪 1：它必然把某个 handler 的等值测试推到另一侧，于是那条路径
    // 落到 `else E()`；如果这条链上的这个 handler 本轮没被执行，脚本输出必须
    // 逐字节不变。出现「跑通但输出不同」就是区间划分改变了语义，直接红。
    let target = Target::Lua51;
    let source = fs::read_to_string("tests/fixtures/vm_lua51.lua").unwrap();
    let data = compile(&source, target).unwrap();
    let program = custom::decode(&data, target).unwrap();
    let seed = 7001u64;
    let raw = generate(&data, &program, seed).unwrap();
    // 每枚边界配上「它上面最近的那个 handler 值」：把边界挪到那一枚上，这个值就被
    // 划进左子树，而左子树的叶子不再测它 ⇒ 必须落到 `else E()`。挪 +1 在宽间隙里
    // 本来就是等价的（那正是区间划分的特点），所以不能拿它当承重证据。
    let mut moves: Vec<(u64, u64)> = Vec::new();
    for var in ["rid", "sid"] {
        let (equality, _, order) = scan_dispatch_chain(&raw, target, var);
        for bound in order {
            let Some(&next) = equality.iter().find(|value| **value > bound) else {
                continue;
            };
            if !moves.contains(&(bound, next)) {
                moves.push((bound, next));
            }
        }
    }
    assert!(
        moves.len() >= 8,
        "only {} bounds have a handler above them to move",
        moves.len()
    );
    let output = emit(&data, target, seed).unwrap();
    let workspace = native::Workspace::new();
    let path = workspace.0.join("interval_bound.lua");
    fs::write(&path, &output).unwrap();
    let control = native::compile_and_run(target, &path);
    assert!(!control.is_empty(), "the control run produced nothing");
    let runtime = native::root().join("toolchains/bin/lua5.1");
    let mut failures = 0usize;
    let mut checked = 0usize;
    for (bound, next) in moves.into_iter().take(40) {
        // 只在最终文本里唯一出现时才挪它，否则替换会打到别处（K20 同类教训）。
        let needle = format!("{bound}");
        if output.matches(&needle).count() != 1 {
            continue;
        }
        let at = output.find(&needle).unwrap();
        let mut tampered = output.clone();
        tampered.replace_range(at..at + needle.len(), &next.to_string());
        assert_ne!(tampered, output);
        fs::write(&path, &tampered).unwrap();
        checked += 1;
        let compiled = native::compile(target, &path);
        if !compiled.status.success() {
            failures += 1;
            continue;
        }
        let result = Command::new(&runtime).arg(&path).output().unwrap();
        if !result.status.success() || result.stderr.iter().any(|byte| *byte != 0) {
            failures += 1;
            continue;
        }
        assert_eq!(
            result.stdout, control,
            "bound {bound} -> {next} silently changed the program's output"
        );
    }
    assert!(
        checked >= 6,
        "only {checked} bounds were locatable in the final text"
    );
    assert!(
        failures >= 1,
        "no interval bound is load-bearing: {checked} bound moves all ran clean"
    );
}
