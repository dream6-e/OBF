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


/// Goal 6 (part 3): an operand is no longer always a literal. The dispatcher
/// and interval spellings hand their value to `opaque_literal`, i.e. a
/// parenthesised `(<guard>and<arm>or<arm>)` whose two arms are exact constant
/// reconstructions of the value. This evaluates the arm after the top-level
/// `and` -- which is constant-only by construction -- so the scanner keeps
/// reading the *value* a chain tests whatever spelling the site drew. Returns
/// `(value, tokens_consumed)`. The arm is parsed with a hard token budget, so a
/// parenthesised *expression* can never be mistaken for an operand.
pub(super) fn opaque_operand_value(
    tokens: &[crate::lexer::Token],
    raw: &str,
    index: usize,
) -> Option<(u64, usize)> {
    let text = |index: usize| -> &str {
        tokens
            .get(index)
            .map(|token| token.text(raw))
            .unwrap_or_default()
    };
    if text(index) != "(" {
        return None;
    }
    // Find the group's `and` at depth 0, then evaluate the arm after it.
    let mut depth = 0i32;
    let mut at = index;
    while at < tokens.len() {
        match text(at) {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth == 0 {
                    return None;
                }
            }
            "and" if depth == 1 => break,
            _ => {}
        }
        at += 1;
    }
    if at >= tokens.len() {
        return None;
    }
    let (value, used) = constant_expr_value(tokens, raw, at + 1)?;
    if text(at + 1 + used) != "or" {
        return None;
    }
    // Walk the second arm to this group's closing paren: the operand is the
    // whole `(<guard>and<a>or<b>)`, so the caller gets the token run it spans.
    let mut depth = 0i32;
    let mut cursor = at + 1 + used;
    while cursor < tokens.len() {
        match text(cursor) {
            "(" => depth += 1,
            ")" => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
        cursor += 1;
    }
    if cursor >= tokens.len() {
        return None;
    }
    Some((value, cursor + 1 - index))
}

/// Longest constant run an opaque arm may occupy: the byte-fold family is the
/// widest at fifteen tokens, so this leaves room and still refuses a whole
/// parenthesised expression.
const ARM_TOKENS: usize = 24;

/// A constant integer expression over number tokens: the arithmetic subset the
/// opaque arms are built from (`+ - * / \ ^ %` and parentheses). `None` as
/// soon as anything that is not a number, an operator or a paren shows up, or
/// as soon as the run passes [`ARM_TOKENS`].
pub(super) fn constant_expr_value(
    tokens: &[crate::lexer::Token],
    raw: &str,
    index: usize,
) -> Option<(u64, usize)> {
    fn text<'a>(tokens: &'a [crate::lexer::Token], raw: &'a str, index: usize) -> &'a str {
        tokens
            .get(index)
            .map(|token| token.text(raw))
            .unwrap_or_default()
    }
    fn primary(
        tokens: &[crate::lexer::Token],
        raw: &str,
        mut index: usize,
        limit: usize,
    ) -> Option<(f64, usize)> {
        let mut sign = 1f64;
        while index < limit && text(tokens, raw, index) == "-" {
            sign = -sign;
            index += 1;
        }
        if index >= limit {
            return None;
        }
        if text(tokens, raw, index) == "(" {
            let (value, used) = expr(tokens, raw, index + 1, limit)?;
            if index + 1 + used >= limit || text(tokens, raw, index + 1 + used) != ")" {
                return None;
            }
            return Some((sign * value, used + 2));
        }
        let value = tokens
            .get(index)
            .filter(|token| token.kind == crate::lexer::TokenKind::Number)
            .and_then(|token| interval_token_value(token.text(raw)))? as f64;
        Some((sign * value, 1))
    }
    fn power(
        tokens: &[crate::lexer::Token],
        raw: &str,
        index: usize,
        limit: usize,
    ) -> Option<(f64, usize)> {
        let (base, used) = primary(tokens, raw, index, limit)?;
        if index + used >= limit || text(tokens, raw, index + used) != "^" {
            return Some((base, used));
        }
        let (exponent, used2) = power(tokens, raw, index + used + 1, limit)?;
        if exponent < 0f64 || exponent.fract() != 0f64 {
            return None;
        }
        Some((base.powf(exponent), used + 1 + used2))
    }
    fn term(
        tokens: &[crate::lexer::Token],
        raw: &str,
        index: usize,
        limit: usize,
    ) -> Option<(f64, usize)> {
        let (mut value, used) = power(tokens, raw, index, limit)?;
        let mut used_total = used;
        loop {
            let op = text(tokens, raw, index + used_total).to_owned();
            if !matches!(op.as_str(), "*" | "/" | "//" | "%" | "\\") {
                return Some((value, used_total));
            }
            let (right, used2) = power(tokens, raw, index + used_total + 1, limit)?;
            used_total += 1 + used2;
            value = match op.as_str() {
                "*" => value * right,
                "/" => value / right,
                "//" => (value / right).floor(),
                "%" => value - (value / right).floor() * right,
                _ => (value / right).floor(),
            };
        }
    }
    fn expr(
        tokens: &[crate::lexer::Token],
        raw: &str,
        index: usize,
        limit: usize,
    ) -> Option<(f64, usize)> {
        let (mut value, used) = term(tokens, raw, index, limit)?;
        let mut used_total = used;
        loop {
            let op = text(tokens, raw, index + used_total).to_owned();
            if !matches!(op.as_str(), "+" | "-") {
                return Some((value, used_total));
            }
            let (right, used2) = term(tokens, raw, index + used_total + 1, limit)?;
            used_total += 1 + used2;
            value = if op == "+" { value + right } else { value - right };
        }
    }
    let limit = (index + ARM_TOKENS).min(tokens.len());
    let (value, used) = expr(tokens, raw, index, limit)?;
    if !value.is_finite() || value.fract() != 0f64 || value < 0f64 || value > 9e15 {
        return None;
    }
    Some((value as u64, used))
}

/// One chain operand: either a plain literal or an opaque reconstruction.
pub(super) fn chain_operand_value(
    tokens: &[crate::lexer::Token],
    raw: &str,
    index: usize,
) -> Option<(u64, usize)> {
    if let Some(token) = tokens.get(index) {
        if token.kind == crate::lexer::TokenKind::Number {
            return interval_token_value(token.text(raw)).map(|value| (value, 1));
        }
    }
    opaque_operand_value(tokens, raw, index)
}

/// 真·残余选择器（`v%N==K`）的除数表。
///
/// 旧的检查是文本子串 `v%`，但 Goal 6 的不透明谓词会在守卫里写
/// `(v%2==v%2)` —— 变量和自己的取模结果比较，永远为真，**不是**选择器。所以
/// 这里按 token 看：`%` 的右端是常量操作数、后面紧跟 `==`/`~=`，右端又是常量
/// 操作数，才算「用余数切子链」。
pub(super) fn residue_selector_moduli(raw: &str, target: Target, var: &str) -> Vec<u64> {
    let tokens = crate::lexer::lex(raw, target).unwrap();
    let text = |index: usize| -> &str {
        tokens
            .get(index)
            .map(|token| token.text(raw))
            .unwrap_or_default()
    };
    let compared = |at: usize| matches!(text(at), "==" | "~=" | "<=" | ">" | "<" | ">=");
    // 取模之后可以直接比，也可以先减一枚常量再和常量比（`o%2-1==0`）：两种都是
    // 同一个「按余数切子链」的形状。
    let tail_is_test = |after: usize| -> bool {
        if compared(after) && chain_operand_value(&tokens, raw, after + 1).is_some() {
            return true;
        }
        if !matches!(text(after), "+" | "-") {
            return false;
        }
        let Some((_, used)) = chain_operand_value(&tokens, raw, after + 1) else {
            return false;
        };
        let next = after + 1 + used;
        compared(next) && chain_operand_value(&tokens, raw, next + 1).is_some()
    };
    let mut moduli = Vec::new();
    for index in 0..tokens.len() {
        if text(index) != var || text(index + 1) != "%" {
            continue;
        }
        let Some((modulus, used)) = chain_operand_value(&tokens, raw, index + 2) else {
            continue;
        };
        let after = index + 2 + used;
        // `o%N == K` (and its arithmetic variants), or `K == o%N`.
        // `K == o%N`: the constant has to be a genuine left operand, not the
        // modulus `o%2 == o%2` just compared with itself.
        let left_form = compared(index.wrapping_sub(1))
            && (0..ARM_TOKENS)
                .filter(|back| *back + 1 <= index)
                .any(|back| {
                    let start = index - back - 1;
                    start > 0
                        && text(start - 1) != "%"
                        && chain_operand_value(&tokens, raw, start)
                            .is_some_and(|(_, span)| start + span == index - 1)
                });
        if tail_is_test(after) || left_form {
            moduli.push(modulus);
        }
    }
    moduli
}

/// [`residue_selector_moduli`] 的命中数。
pub(super) fn residue_selectors(raw: &str, target: Target, var: &str) -> usize {
    residue_selector_moduli(raw, target, var).len()
}

/// 扫出某个分派变量上的 `(等值测试值集合, 区间边界序列)`。
///
/// 认得的形状与发射侧一一对应：等值 `v==N`/`N==v`/`not(v~=N)`/`v-N==0`；区间
/// `v<=N`/`N>=v`/`not(v>N)`/`v-N<=0`/`N-v>=0`，以及把变量藏进恒等式的
/// `(v<=v and v or K)<=N`、`not((v<=v and v or K)>N)`、`(v<=v and v or K)-N<=0`。
/// 赋值（`sid=288`）、声明与实参都不是比较，直接跳过。
///
/// Goal 6 (part 3) 之后 `N` 既可能是十进制字面量，也可能是**不透明字面量**
/// `(<guard>and<a>or<b>)`；两种都由 [`chain_operand_value`] 折成同一个数值。
pub(super) fn scan_dispatch_chain(
    raw: &str,
    target: Target,
    var: &str,
) -> (BTreeSet<u64>, BTreeSet<u64>, Vec<u64>) {
    let (equality, bounds, order, _) = scan_dispatch_chain_spans(raw, target, var);
    (equality, bounds, order)
}

/// 同 [`scan_dispatch_chain`]，另外把每枚边界的**字节区间**报出来：挪边界那条
/// 承重门要在最终文本里替换那一段操作数，而边界值本身已经不再以十进制出现。
pub(super) fn scan_dispatch_chain_spans(
    raw: &str,
    target: Target,
    var: &str,
) -> (BTreeSet<u64>, BTreeSet<u64>, Vec<u64>, Vec<(u64, usize, usize)>) {
    let tokens = crate::lexer::lex(raw, target).unwrap();
    let text = |index: usize| -> &str {
        tokens
            .get(index)
            .map(|token| token.text(raw))
            .unwrap_or_default()
    };
    let is = |index: usize, word: &str| text(index) == word;
    let operand = |index: usize| -> Option<(u64, usize)> {
        chain_operand_value(&tokens, raw, index)
    };
    let span = |index: usize| -> (usize, usize) {
        tokens
            .get(index)
            .map(|token| (token.span.start, token.span.end))
            .unwrap_or((0, 0))
    };
    let mut equality = BTreeSet::new();
    let mut bounds = BTreeSet::new();
    let mut order = Vec::new();
    let mut spans: Vec<(u64, usize, usize)> = Vec::new();
    let mut bound = |value: u64, from: usize, to: usize, bounds: &mut BTreeSet<u64>, order: &mut Vec<u64>, spans: &mut Vec<(u64, usize, usize)>| {
        bounds.insert(value);
        order.push(value);
        spans.push((value, from, to));
    };
    for index in 0..tokens.len() {
        if !is(index, var) {
            continue;
        }
        // v <op> N
        if let Some((value, used)) = operand(index + 2) {
            let after = index + 2 + used;
            if is(index + 1, "==") || is(index + 1, "~=") {
                equality.insert(value);
                continue;
            }
            if is(index + 1, "<=") || is(index + 1, ">") {
                bound(value, span(index + 2).0, span(after - 1).1, &mut bounds, &mut order, &mut spans);
                continue;
            }
            if is(index + 1, "-") {
                if is(after, "==") {
                    equality.insert(value);
                } else if is(after, "<=") || is(after, ">") {
                    bound(value, span(index + 2).0, span(after - 1).1, &mut bounds, &mut order, &mut spans);
                }
                continue;
            }
        }
        // `(v<=v and v or K)` 之后接比较符：守卫形。第三个 v 后面是 `or`。
        if is(index + 1, "or") && (is(index + 4, "<=") || is(index + 4, ">") || is(index + 4, "-")) {
            if let Some((value, used)) = operand(index + 5) {
                let after = index + 5 + used;
                if is(index + 4, "<=") || is(index + 4, ">") || is(after, "<=") || is(after, ">") {
                    bound(value, span(index + 5).0, span(after - 1).1, &mut bounds, &mut order, &mut spans);
                }
            }
        }
    }
    // 操作数在前的拼法：`N<op>v` 与 `N-v<op>0`。不透明字面量没法从变量往回读，
    // 所以这里从它自己的起点往前扫。
    for start in 0..tokens.len() {
        let Some((value, used)) = operand(start) else {
            continue;
        };
        let after = start + used;
        if is(after, "==") && is(after + 1, var) {
            equality.insert(value);
        } else if (is(after, ">=") || is(after, "<")) && is(after + 1, var) {
            bound(value, span(start).0, span(after - 1).1, &mut bounds, &mut order, &mut spans);
        } else if is(after, "-")
            && is(after + 1, var)
            && (is(after + 2, ">=") || is(after + 2, "<"))
        {
            bound(value, span(start).0, span(after - 1).1, &mut bounds, &mut order, &mut spans);
        }
    }
    (equality, bounds, order, spans)
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
                assert_eq!(
                    residue_selectors(&raw, target, var),
                    0,
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
    //
    // Goal 6 (part 3) 之后边界不再拼出十进制：它是一枚**不透明字面量**，所以
    // 「哪一段字节是这枚边界」由 [`scan_dispatch_chain_spans`] 报出来，替换的
    // 是整段操作数（换成挪过的那枚 handler 值的十进制写法，语法上仍是常量）。
    let target = Target::Lua51;
    let source = fs::read_to_string("tests/fixtures/vm_lua51.lua").unwrap();
    let data = compile(&source, target).unwrap();
    let program = custom::decode(&data, target).unwrap();
    let seed = 7001u64;
    let raw = generate(&data, &program, seed).unwrap();
    // 每枚边界配上「它上面最近的那个 handler 值」：把边界挪到那一枚上，这个值就被
    // 划进左子树，而左子树的叶子不再测它 ⇒ 必须落到 `else E()`。挪 +1 在宽间隙里
    // 本来就是等价的（那正是区间划分的特点），所以不能拿它当承重证据。
    //
    // 原始文本不是可运行形态（分节函数在装载期才接上），所以先过一遍 layout，
    // 再按重排后的文本重新定位边界区间，最后用生产同款的 `shorten` + `finalize_vm`
    // 收尾 —— 挪动发生在最终交给运行时的同一份文本上。
    let laid = crate::vm::custom::layout::restructure(&raw, target, seed).expect("layout accepts");
    let mut located: Vec<(u64, u64, usize, usize)> = Vec::new();
    for var in ["rid", "sid"] {
        let (equality, _, _, spans) = scan_dispatch_chain_spans(&laid, target, var);
        for (bound, from, to) in spans {
            let Some(&next) = equality.iter().find(|value| **value > bound) else {
                continue;
            };
            if !located.iter().any(|(seen, up, _, _)| *seen == bound && *up == next) {
                located.push((bound, next, from, to));
            }
        }
    }
    assert!(
        located.len() >= 6,
        "only {} bounds survived the layout pass",
        located.len()
    );
    let workspace = native::Workspace::new();
    let path = workspace.0.join("interval_bound.lua");
    let shorten = |text: &str| -> String {
        let short = crate::vm::fields::shorten(text, target, seed).expect("shorten accepts");
        crate::minify::finalize_vm(&short, target, seed).expect("finalize accepts")
    };
    let control_text = shorten(&laid);
    fs::write(&path, &control_text).unwrap();
    let control = native::compile_and_run(target, &path);
    assert!(!control.is_empty(), "the control run produced nothing");
    let runtime = native::root().join("toolchains/bin/lua5.1");
    let mut failures = 0usize;
    let mut checked = 0usize;
    for (bound, next, from, to) in located.iter().take(40) {
        let mut edited = laid.clone();
        edited.replace_range(*from..*to, &next.to_string());
        assert_ne!(edited, laid);
        let tampered = shorten(&edited);
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

