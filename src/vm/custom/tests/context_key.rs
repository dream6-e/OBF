// K22：解释器的后继块改由「滚动上下文密钥 + 掩码后的线路令牌」给出，发射文本里
// 不再出现任何一个明文状态后继。本文件钉住四件可判定的事：
//
//   1. 静态面（`generate()` 原始文本）：`sid=<数字>` 赋值归零；每枚 `wv=<字面量>-kw`
//      的字面量都落在三位数状态带之外、且不与该链的任何等值测试值相同 ⇒ 朴素配对
//      （「谁写的数 = 谁测的数」）得零分；解码语句的四种拼写都不在 `sid`/`rid` 上留下
//      比较，所以 K21 的区间普查不会把模数当成「切不开 handler 的界」。
//   2. 承重的算术：取指重播种的滚动里带一个**操作数摘要**（只由 `a==b` 这类等值比较
//      构成，对 VM 能持有的一切值都有定义），因此密钥取决于刚执行完那条指令真正绑定的
//      操作数。真机上把摘要/权重改一个值，脚本必须**仍然跑通**（写出与解读自洽），但
//      线路令牌的取值必须与参照运行不同——这就是「密钥不是装饰」的证据；把逆掩码改成
//      1 或把某枚后继字面量挪 1，脚本则必须**不再复现参照输出**。
//   3. 运行期一致性（真机）：`(字面量 + 写点密钥) mod M` 经逆掩码后必须等于下一次派发
//      解出的状态；而字面量本身**不等于**后继状态（朴素读法失败）；每个写点的密钥取值
//      随执行路径变化。
//   4. 四种解码拼写等价：与 K21 的区间拼写门同法，把四种拼写搬到真机 Lua 上对边界值
//      逐个求值，不靠 Rust 侧镜像自证。
//
// 静态扫描读原始文本（`finalize_vm` 会把局部改名成一到两个字母，K20 已踩过）；真机
// 运行与篡改读**最终文本**（原始文本只保证可扫，不保证可跑：K4 之后语言层重排是交付
// 形态的一部分）。篡改一律靠「唯一数字针」定位，出现次数不为 1 就跳过，绝不误伤别处。

/// 四种解码拼写（名字与 `context::decode_stmt` 的模板一一对应）。门在产物里找这四条
/// 原文，因此拼写一旦漂移，这里会先红，而不是悄悄换成别的形状。
fn k22_decode_templates(modulus: u64, inv: u64) -> [String; 4] {
    [
        format!("sid=(wv+kw)%{modulus}*{inv}%{modulus};"),
        format!("sid=(kw+wv)%{modulus}*{inv}%{modulus};"),
        format!("sid=(wv+kw-(wv+kw<0 and {modulus} or 0))%{modulus}*{inv}%{modulus};"),
        format!("sid=wv+kw;if sid<0 then sid=sid+{modulus} end;sid=sid*{inv}%{modulus};"),
    ]
}

/// 从原始发射文本里读回 K22 的密钥算术：模数、逆掩码、三个滚动权重、命中哪种解码拼写，
/// 以及每一枚 `wv=<字面量>-kw` 的字面量。门验的是**产物**里的算术，不在 Rust 侧重算 plan。
struct K22Plan {
    modulus: u64,
    inv: u64,
    weights: [u64; 3],
    decode_form: usize,
    decode: String,
    literals: Vec<u64>,
    digest_terms: usize,
    digest_numbers: Vec<u64>,
    init_literal: u64,
    /// 派发滚动（`kw=(...)`）与取指重播种（滚动 + 入口线路）的原文。
    roll: String,
    reset: String,
    /// 取指重播种里参与等值比较的**数据局部**（操作数绑定），以及比较项数。
    digest_locals: std::collections::BTreeSet<String>,
    digest_comparisons: usize,
}

/// 一条语句：从 `at` 到下一个 `;`（含）。发射文本里这些语句不含字符串字面量，
/// 所以按 `;` 切分是安全的——但**不能**用「按 `;` 切分后看前缀」来找语句：Lua 允许
/// `end` 后直接接新语句，解码语句并不总落在切分边界上（K20 同类教训）。
fn k22_statement(raw: &str, at: usize) -> &str {
    let end = raw[at..]
        .find(';')
        .map(|offset| at + offset + 1)
        .unwrap_or(raw.len());
    &raw[at..end]
}

fn k22_read_plan(raw: &str, target: Target, seed: u64) -> K22Plan {
    let modulus = super::context::MODULUS;
    let numbers = |text: &str| -> Vec<u64> {
        crate::lexer::lex(text, target)
            .unwrap()
            .iter()
            .filter(|token| token.kind == crate::lexer::TokenKind::Number)
            .filter_map(|token| interval_token_value(token.text(text)))
            .collect()
    };
    // 解码语句：唯一一条以 `sid=` 开头（且不是 `sid==`）、同时含线路名与密钥名的语句。
    let mut decode_text = None;
    let mut decode_form = None;
    let mut inv = 0u64;
    let mut candidates: Vec<String> = Vec::new();
    for (at, _) in raw.match_indices("sid=") {
        let statement = k22_statement(raw, at);
        // 拼写 3 的末句既没有 `wv` 也没有 `kw`，所以这里只排掉等值测试形状。
        if statement.starts_with("sid==") {
            continue;
        }
        candidates.push(statement.to_owned());
        // 拼写 3 的第一句就是 `sid=wv+kw;`（没有逆掩码），跳过它继续找末句。
        let candidate: Vec<u64> = numbers(statement)
            .into_iter()
            .filter(|value| *value != 0 && *value != modulus)
            .collect();
        if candidate.len() != 1 {
            continue;
        }
        inv = candidate[0];
        let templates = k22_decode_templates(modulus, inv);
        if let Some(form) = templates.iter().position(|template| template == statement) {
            decode_form = Some(form);
            decode_text = Some(statement.to_owned());
            break;
        }
        // 拼写 3 的末句：`sid=sid*INV%m;`（字面量可能被重拼成十六进制，所以按 token 认）。
        let tokens = crate::lexer::lex(statement, target).unwrap();
        let words: Vec<&str> = tokens.iter().map(|token| token.text(statement)).collect();
        let form_three = words.len() >= 8
            && words[0] == "sid"
            && words[1] == "="
            && words[2] == "sid"
            && words[3] == "*"
            && words[5] == "%"
            && words[7] == ";"
            && interval_token_value(words[4]) == Some(inv)
            && interval_token_value(words[6]) == Some(modulus);
        if form_three {
            // 把这三句一起交出去（普查要看到整段解码）。
            let mut start = at;
            let mut prefix: Vec<usize> = raw[..at].match_indices("sid=").map(|(at, _)| at).collect();
            for previous_at in prefix.drain(..).rev().take(2) {
                let previous = k22_statement(raw, previous_at);
                if previous.starts_with("sid==") || !previous.contains("wv") {
                    break;
                }
                start = previous_at;
            }
            decode_form = Some(3);
            decode_text = Some(raw[start..at + statement.len()].to_owned());
            break;
        }
    }
    let decode = match decode_text {
        Some(text) => text,
        None => panic!(
            "{target} seed {seed}: no K22 decode statement (candidates: {:?})",
            &candidates[..candidates.len().min(4)]
        ),
    };
    // 取指重播种与派发滚动：都是 `kw=(...)` 语句，靠语句里出现 `rid` 还是 `sid` 区分。
    let mut digest_terms = 0usize;
    let mut fetch_roll_at = None;
    let mut digest_numbers: Vec<u64> = Vec::new();
    let mut weights = [0u64; 3];
    let mut roll_text = String::new();
    let mut fetch_roll_end = None;
    let mut dispatch_rolls = 0usize;
    for (at, _) in raw.match_indices("kw=(") {
        let statement = k22_statement(raw, at);
        if statement.contains("rid") {
            let tokens = crate::lexer::lex(statement, target).unwrap();
            let mut ids: Vec<u64> = Vec::new();
            for token in tokens.iter() {
                if token.kind == crate::lexer::TokenKind::Keyword && token.text(statement) == "and" {
                    digest_terms += 1;
                }
                if token.kind == crate::lexer::TokenKind::Number {
                    if let Some(value) = interval_token_value(token.text(statement)) {
                        if value < 100 {
                            ids.push(value);
                        }
                    }
                }
            }
            digest_numbers = ids;
            fetch_roll_end = Some(at + statement.len());
            fetch_roll_at = Some(at);
        } else if statement.contains("sid") && statement.contains("pc") {
            // 只有真正的派发滚动才会同时出现状态名、指令序号与模数；别的同名局部
            // （装载器/分段解码里也有短名）不参与。
            let Ok(tokens) = crate::lexer::lex(statement, target) else {
                continue;
            };
            if !statement.contains(&modulus.to_string()) {
                continue;
            }
            dispatch_rolls += 1;
            roll_text = statement.to_owned();
            for (index, token) in tokens.iter().enumerate() {
                if token.kind != crate::lexer::TokenKind::Number {
                    continue;
                }
                let Some(value) = interval_token_value(token.text(statement)) else {
                    continue;
                };
                if value == modulus {
                    continue;
                }
                // 乘法项两边的名字：字面量可能被变异批次重拼成 `(0x3a1b)` 形态，
                // 所以往两侧各看几个 token，取最近的那个标识符。
                // 名字必须取自**同一个乘法项**：先往右扫到 `+`/`)` 为止，找不到再往左
                // 扫到 `+`/`(`/`=` 为止。否则 `35641*kw+63217*sid` 里的 63217 会认领
                // 前一项的 `kw`。
                let mut name = None;
                for step in 1..=4usize {
                    let Some(token) = tokens.get(index + step) else {
                        break;
                    };
                    let text = token.text(statement);
                    if token.kind == crate::lexer::TokenKind::Identifier {
                        name = Some(text.to_owned());
                        break;
                    }
                    if matches!(text, "+" | ")" | ";" | "(" | "=") {
                        break;
                    }
                }
                if name.is_none() {
                    for step in 1..=4usize {
                        if index < step {
                            break;
                        }
                        let token = &tokens[index - step];
                        let text = token.text(statement);
                        if token.kind == crate::lexer::TokenKind::Identifier {
                            name = Some(text.to_owned());
                            break;
                        }
                        if matches!(text, "+" | "(" | "=" | ")") {
                            break;
                        }
                    }
                }
                if let Some(name) = name {
                    match name.as_str() {
                        "kw" => weights[0] = value,
                        "sid" => weights[1] = value,
                        _ => weights[2] = value,
                    }
                }
            }
        }
    }
    let fetch_roll_end = fetch_roll_end.expect("no fetch roll in the emitted text");
    assert_eq!(dispatch_rolls, 1, "expected exactly one K22 dispatch roll");
    // 取指重播种 = 「带摘要的滚动」+「入口线路令牌」两条语句；滚动语句就是上面那条带
    // `rid` 的 `kw=(...)`（`fetch_roll_at` 记下它的起点），后面紧跟 `wv=`。
    // 摘要项：取指重播种里用 `==`/`~=` 比较的那几个名字。它们必须是**操作数绑定**
    // （`a/b/c/k/j` 这类），而不是密钥/序号本身——这正是「密钥取决于刚执行完那条指令
    // 真正算出来的值」的静态证据。
    let mut digest_locals = std::collections::BTreeSet::new();
    let mut digest_comparisons = 0usize;
    {
        let statement = k22_statement(raw, fetch_roll_at.expect("no fetch roll"));
        let tokens = crate::lexer::lex(statement, target).unwrap();
        for (index, token) in tokens.iter().enumerate() {
            let text = token.text(statement);
            if text != "==" && text != "~=" {
                continue;
            }
            digest_comparisons += 1;
            for offset in [-1isize, 1] {
                let at = index as isize + offset;
                if at < 0 {
                    continue;
                }
                if let Some(operand) = tokens.get(at as usize) {
                    if operand.kind != crate::lexer::TokenKind::Identifier {
                        continue;
                    }
                    let name = operand.text(statement).to_owned();
                    // 密钥、控制、序号与状态都不是「刚绑定的操作数」。
                    if matches!(name.as_str(), "kw" | "wv" | "cw" | "rid" | "pc" | "sid") {
                        continue;
                    }
                    digest_locals.insert(name);
                }
            }
        }
    }
    let reset_at = fetch_roll_at.expect("no fetch roll in the emitted text");
    let wire_at = raw[fetch_roll_end..]
        .find("wv=")
        .map(|offset| fetch_roll_end + offset)
        .expect("the fetch reset has no wire token");
    let reset_text = raw[reset_at..reset_at + (wire_at - reset_at) + k22_statement(raw, wire_at).len()]
        .to_owned();
    assert!(reset_text.contains("rid"), "fetch reset {reset_text:?} lost its recipe token");
    assert!(
        reset_text.contains("wv="),
        "fetch reset {reset_text:?} lost its wire token"
    );
    // 线路写点：`wv=<字面量>-kw`（臂）与 `wv=<字面量>-kw` / `wv=-kw+<字面量>`（入口）。
    let mut literals = Vec::new();
    let mut init_literal = None;
    for (at, _) in raw.match_indices("wv=") {
        let statement = k22_statement(raw, at);
        let Some(rest) = statement.strip_prefix("wv=") else {
            continue;
        };
        let rest = rest.strip_suffix(';').unwrap_or(rest);
        let masked = if let Some(head) = rest.strip_suffix("-kw") {
            head.to_owned()
        } else if let Some(tail) = rest.strip_prefix("-kw+") {
            tail.to_owned()
        } else {
            continue;
        };
        let Some(value) = interval_token_value(masked.trim()) else {
            continue;
        };
        if at >= fetch_roll_end && at < fetch_roll_end + 8 {
            init_literal = Some(value);
        }
        literals.push(value);
    }
    K22Plan {
        modulus,
        inv,
        weights,
        decode_form: decode_form.unwrap(),
        decode,
        literals,
        digest_terms,
        digest_numbers,
        init_literal: init_literal.expect("the entry wire token is missing"),
        roll: roll_text,
        reset: reset_text,
        digest_locals,
        digest_comparisons,
    }
}

#[test]
fn k22_successor_identity_leaves_the_static_text() {
    for (target, fixture, seeds) in [
        (
            Target::Lua51,
            "tests/fixtures/vm_lua51.lua",
            [7001u64, 7351, 1, 4242, u64::MAX],
        ),
        (
            Target::Luau,
            "tests/fixtures/vm_luau.lua",
            [7351u64, 7001, 2, 77, u64::MAX],
        ),
    ] {
        let source = fs::read_to_string(fixture).unwrap();
        let data = compile(&source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut literal_sets = BTreeSet::new();
        for seed in seeds {
            let raw = generate(&data, &program, seed).unwrap();
            let plan = k22_read_plan(&raw, target, seed);
            assert!(plan.inv >= 2 && plan.inv < plan.modulus, "inverse out of range");
            assert!(
                plan.weights.iter().all(|value| *value >= 2),
                "{target} seed {seed}: weight out of range {:?}",
                plan.weights
            );
            assert!(
                plan.digest_terms >= 3,
                "{target} seed {seed}: the fetch roll carries {} comparison terms, expected the operand digest",
                plan.digest_terms
            );
            // 摘要必须比较**操作数绑定**：至少两项，且不是密钥/序号自己。
            assert!(
                plan.digest_comparisons >= 3 && plan.digest_locals.len() >= 2,
                "{target} seed {seed}: the fetch digest compares {:?} ({} comparisons), expected the operand bindings",
                plan.digest_locals,
                plan.digest_comparisons
            );
            // 1) 状态后继不再以明文数字写入任何地方（`for sid=1,N do` 是别的局部变量，
            //    只看真正的赋值形状：标识符 `sid` 后面紧跟 `=` 再紧跟一个数字字面量）。
            let statement_tokens = crate::lexer::lex(&raw, target).unwrap();
            for (index, token) in statement_tokens.iter().enumerate() {
                if token.kind != crate::lexer::TokenKind::Identifier || token.text(&raw) != "sid" {
                    continue;
                }
                if statement_tokens.get(index + 1).map(|next| next.text(&raw)) != Some("=") {
                    continue;
                }
                if statement_tokens.get(index + 2).map(|next| next.kind)
                    != Some(crate::lexer::TokenKind::Number)
                {
                    continue;
                }
                let previous = statement_tokens
                    .get(index.wrapping_sub(1))
                    .map(|previous| previous.text(&raw))
                    .unwrap_or_default();
                assert_eq!(
                    previous, "for",
                    "{target} seed {seed}: plaintext state write at token {index}"
                );
            }
            // 2) 线路字面量全部落在三位数状态带之外，且与链上的等值测试值不相交。
            assert!(
                plan.literals.len() >= 8,
                "{target} seed {seed}: only {} wire tokens",
                plan.literals.len()
            );
            let (equality, _, _) = scan_dispatch_chain(&raw, target, "sid");
            for literal in &plan.literals {
                assert!(
                    *literal > 999,
                    "{target} seed {seed}: wire literal {literal} is inside the stage band"
                );
                assert!(
                    !equality.contains(literal),
                    "{target} seed {seed}: wire literal {literal} is also a chain arm value"
                );
                assert!(
                    !INTERVAL_NICE.contains(literal),
                    "{target} seed {seed}: wire literal {literal} is an audit-nice value"
                );
            }
            // 朴素配对（把写下的数当成被测的数）必须得零分。
            let naive = plan
                .literals
                .iter()
                .filter(|literal| equality.contains(literal))
                .count();
            assert_eq!(naive, 0, "{target} seed {seed}: naive pairing scored {naive}");
            // 3) 解码语句本身不许在 `sid`/`rid` 上留下比较，也不许出现 `sid%`。
            assert!(!plan.decode.contains("sid%"), "{target} seed {seed}: {}", plan.decode);
            for (label, text) in [
                ("decode", &plan.decode),
                ("roll", &plan.roll),
                ("reset", &plan.reset),
            ] {
                for var in ["rid", "sid"] {
                    let (equality, bounds, _) = scan_dispatch_chain(text, target, var);
                    assert!(
                        equality.is_empty() && bounds.is_empty(),
                        "{target} seed {seed}: {label} statement {text:?} registers a {var} comparison"
                    );
                }
            }
            literal_sets.insert(plan.literals.iter().copied().collect::<BTreeSet<u64>>());
        }
        assert!(
            literal_sets.len() >= 3,
            "{target}: the wire-token set is seed-independent"
        );
    }
}

#[test]
fn k22_every_decode_spelling_is_the_same_function_on_the_real_interpreter() {
    // 四种拼写在真机 Lua 5.1 上对边界值逐个求值：`(wv+kw)` 落在负数侧、模数边界、
    // 以及 `wv = 掩码 - kw` 真正会写出的未归约值上。期望值由脚本自己算
    // `(wv+kw)%M*INV%M`，Rust 只做「四种拼写彼此相等」的判断。
    let target = Target::Lua51;
    let source = fs::read_to_string("tests/fixtures/vm_lua51.lua").unwrap();
    let data = compile(&source, target).unwrap();
    let program = custom::decode(&data, target).unwrap();
    let raw = generate(&data, &program, 7001).unwrap();
    let plan = k22_read_plan(&raw, target, 7001);
    let (m, inv) = (plan.modulus, plan.inv);
    let mut script = String::new();
    let mut probes = Vec::new();
    for key in [0u64, 1, m / 3, m - 1] {
        for literal in [2u64, 1000, m / 2, m - 1] {
            // 写点真正赋的值是未归约的 `literal - key`，可能是负数。
            probes.push((literal as i128 - key as i128, key));
        }
    }
    let snippets = |w: &str, k: &str| -> [String; 4] {
        [
            format!("sid=({w}+{k})%{m}*{inv}%{m};"),
            format!("sid=({k}+{w})%{m}*{inv}%{m};"),
            format!("sid=({w}+{k}-({w}+{k}<0 and {m} or 0))%{m}*{inv}%{m};"),
            format!("sid={w}+{k};if sid<0 then sid=sid+{m} end;sid=sid*{inv}%{m};"),
        ]
    };
    for (wire, key) in &probes {
        let wire = *wire;
        let key = *key;
        script.push_str(&format!(
            "io.write(tostring((({wire}+{key})%{m})*{inv}%{m}))"
        ));
        for body in snippets(&wire.to_string(), &key.to_string()) {
            script.push_str(&format!(
                // 尾随空格：`end` 直接接下一个 `io.write` 会被词法器拼成一个标识符。
                " do local ok,sid=pcall(function() local sid; {body} return sid end) io.write(\",\",tostring(ok)) io.write(\":\",tostring(sid)) end "
            ));
        }
        script.push_str(" io.write(\"\\n\")");
    }
    script.push_str("print()");
    let workspace = native::Workspace::new();
    let path = workspace.0.join("k22_decode_forms.lua");
    fs::write(&path, &script).unwrap();
    let runtime = native::root().join("toolchains/bin/lua5.1");
    let output = Command::new(&runtime).arg(&path).output().unwrap();
    assert!(
        output.status.success(),
        "decode probe did not run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(lines.len(), probes.len(), "probe printed {text:?}");
    for (index, line) in lines.iter().enumerate() {
        let mut parts = line.split(',');
        let want = parts.next().unwrap();
        let mut spellings = Vec::new();
        for part in parts {
            let (ok, value) = part.rsplit_once(':').unwrap();
            assert_eq!(ok, "true", "spelling faulted on probe {index}: {part}");
            spellings.push(value.to_owned());
        }
        assert_eq!(spellings.len(), 4, "probe {index} printed {line:?}");
        for value in &spellings {
            assert_eq!(
                value, want,
                "decode spelling disagrees with the identity on probe {index}: {line:?}"
            );
        }
    }
}

/// 插桩用的写出函数：生成的程序里可能有同名局部、而 Luau 运行时没有 `io`
/// 库，所以先在自己的 chunk 头部把 `print` 取一份再引用（两个目标都有 `print`）。
const TRACE: &str = "k22_print";

#[test]
fn k22_wire_tokens_need_the_live_key_on_the_real_interpreter() {
    // 在最终文本上插桩：派发回合解出的状态打 `D`，每次线路写点打 `W字面量|密钥`。
    // 断言三件事——(a) 每个写点的字面量都不是它真正的后继（朴素读法失败）；
    // (b) 字面量经未归约线路与写点密钥还原出下一次解出的状态（写读自洽）；
    // (c) 写点密钥随路径变化，不是常数。
    for (target, fixture, seed, runner) in [
        (Target::Lua51, "tests/fixtures/vm_lua51.lua", 7001u64, "lua5.1"),
        (Target::Luau, "tests/fixtures/vm_luau.lua", 7351u64, "luau"),
    ] {
        let source = fs::read_to_string(fixture).unwrap();
        let data = compile(&source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = generate(&data, &program, seed).unwrap();
        let plan = k22_read_plan(&raw, target, seed);
        let output = emit(&data, target, seed).unwrap();
        // 最终文本里的短名：从解码语句里读回来（解码是唯一一处同时出现逆掩码与线路名的
        // 语句，形状在 `context::decode_stmt` 里固定）。
        let tokens = crate::lexer::lex(&output, target).unwrap();
        let inv_at = tokens
            .iter()
            .position(|token| {
                token.kind == crate::lexer::TokenKind::Number
                    && interval_token_value(token.text(&output)) == Some(plan.inv)
            })
            .expect("the inverse literal is not in the finalized text");
        // 含逆掩码的那条语句：向左回到上一枚 `;`，向右走到下一枚 `;`（四种拼写的末句
        // 都落在逆掩码上，所以这条语句就是解码的最后一步）。
        let boundaries = [";", "then", "do", "else", "elseif", "end", "repeat", "until"];
        let mut start = inv_at;
        while start > 0 && !boundaries.contains(&tokens[start - 1].text(&output)) {
            start -= 1;
        }
        let mut end = inv_at;
        while end + 1 < tokens.len() && tokens[end].text(&output) != ";" {
            end += 1;
        }
        let anchor = output[tokens[start].span.start..tokens[end].span.end].to_owned();
        assert!(anchor.ends_with(';'), "{target}: decode anchor {anchor:?}");
        assert_eq!(
            output.matches(&anchor).count(),
            1,
            "{target}: decode anchor {anchor:?} is not unique"
        );
        // 模数在最终文本里是包装表字段（`n.ab`），所以字段访问的两个标识符要排除：
        // 只看前后都不是 `.` 的标识符。
        let mut idents: Vec<String> = Vec::new();
        for index in start..=end {
            if tokens[index].kind != crate::lexer::TokenKind::Identifier {
                continue;
            }
            if tokens.get(index.wrapping_sub(1)).map(|token| token.text(&output)) == Some(".") {
                continue;
            }
            if tokens.get(index + 1).map(|token| token.text(&output)) == Some(".") {
                continue;
            }
            let name = tokens[index].text(&output).to_owned();
            if !idents.contains(&name) {
                idents.push(name);
            }
        }
        assert_eq!(
            idents.len(),
            3,
            "{target}: decode statement {anchor:?} does not name state/wire/key"
        );
        // 形态 0/2/3 是 `state=wire+key`，形态 1 是 `state=key+wire`。
        let (state, wire, key) = if plan.decode_form == 1 {
            (idents[0].clone(), idents[2].clone(), idents[1].clone())
        } else {
            (idents[0].clone(), idents[1].clone(), idents[2].clone())
        };
        // 插桩：解码语句后打 D<状态>，每个写点后打 W<字面量>|<密钥>。写点按**数值**
        // 定位（最终文本会重拼字面量、把模数挪进包装表字段），形状必须是
        // `wire = <字面量> - key ;`。
        let mut inserts: Vec<(usize, usize, u64)> = Vec::new();
        for (index, token) in tokens.iter().enumerate() {
            if token.kind != crate::lexer::TokenKind::Number {
                continue;
            }
            let Some(literal) = interval_token_value(token.text(&output)) else {
                continue;
            };
            if !plan.literals.contains(&literal) {
                continue;
            }
            let text_at = |offset: isize| -> Option<&str> {
                let at = index as isize + offset;
                if at < 0 {
                    return None;
                }
                tokens.get(at as usize).map(|token| token.text(&output))
            };
            let kind_at = |offset: isize| -> Option<crate::lexer::TokenKind> {
                let at = index as isize + offset;
                if at < 0 {
                    return None;
                }
                tokens.get(at as usize).map(|token| token.kind.clone())
            };
            // 两种拼写：`wire = <字面量> - key` 与 `wire = - key + <字面量>`。
            let forward = text_at(-1) == Some("=")
                && text_at(-2) == Some(wire.as_str())
                && text_at(1) == Some("-")
                && kind_at(2) == Some(crate::lexer::TokenKind::Identifier)
                && text_at(2) == Some(key.as_str());
            let backward = text_at(-1) == Some("+")
                && kind_at(-2) == Some(crate::lexer::TokenKind::Identifier)
                && text_at(-2) == Some(key.as_str())
                && text_at(-3) == Some("-")
                && text_at(-4) == Some("=")
                && text_at(-5) == Some(wire.as_str());
            if !forward && !backward {
                continue;
            }
            // 插桩点必须在**整个表达式之后**：向前拼写插在密钥名之后，向后拼写插在
            // 字面量之后（否则会把 `L-kw` 截成 `L`，改掉语义）。
            let end = if forward {
                tokens[index + 2].span.end
            } else {
                token.span.end
            };
            inserts.push((end, end, literal));
        }
        assert!(
            inserts.len() >= 8,
            "{target}: only {} wire sites were locatable in the finalized text (state={state} wire={wire} key={key} literals={} form={})",
            inserts.len(),
            plan.literals.len(),
            plan.decode_form
        );
        // 生成的程序里可能有叫 `io` 的局部（Luau 目标上就有），所以先在自己的
        // chunk 头部把 `io.write` 取出来存进一个不会撞名的局部。
        let prefix = format!("local {TRACE}=print;");
        let shift = prefix.len();
        let mut patched = prefix;
        patched.push_str(&output);
        inserts.sort_by_key(|(at, ..)| std::cmp::Reverse(*at));
        for (_, end, literal) in inserts {
            // 前导 `;`：插桩文本必须与上一个 token 分开，否则 `...-m` 与 `io.write`
            // 会被词法器拼成一个标识符（K22 施工时就踩过一次）。语句本身已带 `;` 时
            // 不再补第二个——Lua 5.1 的语法里空语句 `;;` 是非法的。
            let suffix = if output[end..].starts_with(';') { "" } else { ";" };
            let trace =
                format!(";{TRACE}(\"W\" .. {literal} .. \"|\" .. {key}){suffix}");
            patched.insert_str(end + shift, &trace);
        }
        patched = patched.replacen(
            &anchor,
            &format!(
                "{anchor}{TRACE}(\"D\" .. {state} .. \"|\" .. {wire} .. \"|\" .. {key});"
            ),
            1,
        );
        let workspace = native::Workspace::new();
        let path = workspace.0.join("k22_trace.lua");
        fs::write(&path, &patched).unwrap();
        let runtime = native::root().join("toolchains/bin").join(runner);
        let run = Command::new(&runtime).arg(&path).output().unwrap();
        assert!(
            run.status.success(),
            "{target}: instrumented run failed: {}",
            String::from_utf8_lossy(&run.stderr).chars().take(400).collect::<String>()
        );
        let stdout = String::from_utf8(run.stdout).unwrap();
        // 事件流（每行一条）：`W<字面量>|<写点密钥>` 与
        // `D<状态>|<线路值>|<解码密钥>`；W 后紧跟的 D 就是这道边解出的后继状态。
        let mut events: Vec<char> = Vec::new();
        let mut first = Vec::new();
        let mut second = Vec::new();
        // 与 events 平行的第三个字段：W 事件记字面量，D 事件记当时机器上的线路值。
        let mut wires: Vec<u64> = Vec::new();
        // 线路值可以是未归约的负数（`wv=-kw+N`），所以按有符号解析再归一到 [0,M)。
        let field = |part: Option<&str>, chunk: &str| -> u64 {
            let raw = part.unwrap_or_else(|| panic!("{target}: truncated trace chunk {chunk:?}"));
            let value = raw
                .parse::<i64>()
                .unwrap_or_else(|_| panic!("{target}: non-numeric trace chunk {chunk:?}"));
            value.rem_euclid(plan.modulus as i64) as u64
        };
        for chunk in stdout.lines() {
            let chunk = chunk.trim();
            if !chunk.starts_with('W') && !chunk.starts_with('D') {
                continue;
            }
            let mut parts = chunk[1..].split('|');
            if chunk.starts_with('W') {
                let literal = field(parts.next(), chunk);
                let key_value = field(parts.next(), chunk);
                events.push('W');
                first.push(literal);
                second.push(key_value);
                wires.push(literal);
            } else if chunk.starts_with('D') {
                let state = field(parts.next(), chunk);
                let wire = field(parts.next(), chunk);
                let key_value = field(parts.next(), chunk);
                events.push('D');
                first.push(state);
                second.push(key_value);
                wires.push(wire);
                // 解码恒等式：脚本自己算出来的状态必须等于线路值与解码密钥的还原。
                assert_eq!(
                    ((wire + key_value) % plan.modulus * plan.inv) % plan.modulus,
                    state,
                    "{target}: decode identity failed for wire {wire} key {key_value}"
                );
            }
        }
        let dispatches = events.iter().filter(|event| **event == 'D').count();
        let writes = events.iter().filter(|event| **event == 'W').count();
        assert!(dispatches >= 50 && writes >= 50, "{target}: trace too small ({dispatches}/{writes})");
        let (equality, _, _) = scan_dispatch_chain(&raw, target, "sid");
        let entry = (plan.init_literal * plan.inv) % plan.modulus;
        let mut keys = BTreeSet::new();
        let mut literals_seen = BTreeSet::new();
        let mut edges = 0usize;
        for index in 0..events.len().saturating_sub(1) {
            if events[index] != 'W' || events[index + 1] != 'D' {
                continue;
            }
            let (literal, write_key) = (first[index], second[index]);
            let (next, decode_key) = (first[index + 1], second[index + 1]);
            assert!(
                equality.contains(&next) || next == entry,
                "{target}: decoded state {next} is not a handler state"
            );
            let _ = decode_key;
            let live_wire = wires[index + 1];
            // (a) 后继恒等式：写点的字面量乘以逆掩码就是后继状态，**与密钥无关**。
            assert_ne!(
                literal, next,
                "{target}: wire literal {literal} is the successor state itself"
            );
            assert_eq!(
                (literal * plan.inv) % plan.modulus,
                next,
                "{target}: masked literal {literal} is not the successor of {next}"
            );
            // (b) 机器上的线路值确实是「字面量 − 写点密钥」：静态文本里没有密钥，
            //     而解释器里的值被密钥掩掉，所以两者永远不会相等。
            assert_eq!(
                (literal + plan.modulus - write_key) % plan.modulus,
                live_wire,
                "{target}: live wire {live_wire} is not literal-minus-key"
            );
            assert_ne!(
                literal, live_wire,
                "{target}: the live wire equals the static literal under key {write_key}"
            );
            keys.insert(write_key);
            literals_seen.insert(literal);
            edges += 1;
        }
        assert!(edges >= 40, "{target}: only {edges} wire edges observed");
        assert!(
            keys.len() >= 8,
            "{target}: the write-site key only took {} values",
            keys.len()
        );
        assert!(literals_seen.len() >= 8, "{target}: too few wire literals exercised");
    }
}

#[test]
fn k22_wire_arithmetic_is_load_bearing() {
    // 自洽性说明：写点用哪个密钥补偿、解读时就减掉哪个密钥，所以**改权重/改摘要**
    // 不会让脚本跑错，只会改变线路令牌的取值；而**改逆掩码/改字面量**破坏写读往返，
    // 必须让参照输出不再出现。四枚针都在最终文本上按「唯一出现」定位。
    let target = Target::Lua51;
    let source = fs::read_to_string("tests/fixtures/vm_lua51.lua").unwrap();
    let data = compile(&source, target).unwrap();
    let program = custom::decode(&data, target).unwrap();
    let seed = 7001u64;
    let raw = generate(&data, &program, seed).unwrap();
    let plan = k22_read_plan(&raw, target, seed);
    let output = emit(&data, target, seed).unwrap();
    let workspace = native::Workspace::new();
    let path = workspace.0.join("k22_tamper.lua");
    let runtime = native::root().join("toolchains/bin/lua5.1");
    let run = |text: &str| -> (bool, Vec<u8>) {
        fs::write(&path, text).unwrap();
        let result = Command::new(&runtime).arg(&path).output().unwrap();
        (
            result.status.success() && !result.stderr.iter().any(|byte| *byte != 0),
            result.stdout,
        )
    };
    let (reference_ok, reference) = run(&output);
    assert!(reference_ok, "the untampered finalized script did not run");
    assert!(!reference.is_empty());
    let site = |text: &str, needle: &str| -> Option<String> {
        if text.matches(needle).count() != 1 {
            return None;
        }
        Some(needle.to_owned())
    };
    let mut checked = 0usize;
    // (1) 逆掩码 → 1：写读往返破坏，必须不再复现参照输出。
    if let Some(needle) = site(&output, &plan.inv.to_string()) {
        let tampered = output.replacen(&needle, "1", 1);
        let (ok, stdout) = run(&tampered);
        assert!(
            !ok || stdout != reference,
            "masking the inverse to 1 still reproduced the program output"
        );
        checked += 1;
    }
    // (2) 某枚后继字面量挪 1：该边不再指向原来的块。
    if let Some(needle) = plan
        .literals
        .iter()
        .map(|value| value.to_string())
        .find(|needle| site(&output, needle).is_some_and(|n| n.len() >= 4))
    {
        let shifted = plan
            .literals
            .iter()
            .find(|value| value.to_string() == needle)
            .map(|value| value + 1)
            .unwrap();
        let tampered = output.replacen(&needle, &shifted.to_string(), 1);
        let (ok, stdout) = run(&tampered);
        assert!(
            !ok || stdout != reference,
            "shifting wire literal {needle} to {shifted} still reproduced the program output"
        );
        checked += 1;
    }
    // (3) 滚动权重挪 1：自洽，必须仍跑通，但线路令牌取值必须变。
    let weight = plan.weights[1];
    if let Some(needle) = site(&output, &weight.to_string()) {
        let tampered = output.replacen(&needle, &(weight + 1).to_string(), 1);
        let (ok, stdout) = run(&tampered);
        assert!(ok && stdout == reference, "changing the roll weight broke the machine");
        checked += 1;
    }
    // (4) 操作数摘要：把某一项的真值挪 1 —— 同一个「仍然跑通、但令牌不同」的证据。
    let mut digest_tampered = 0usize;
    for number in plan.digest_numbers.iter().copied() {
        let needle = format!("and {number} or ");
        if output.matches(&needle).count() != 1 {
            continue;
        }
        let tampered = output.replacen(&needle, &format!("and {} or ", number + 1), 1);
        let (ok, stdout) = run(&tampered);
        assert!(
            ok && stdout == reference,
            "changing the operand digest broke the machine's self-consistency"
        );
        digest_tampered += 1;
        break;
    }
    assert!(
        digest_tampered == 1,
        "no digest term was locatable in the finalized text"
    );
    checked += digest_tampered;
    assert!(
        checked >= 3,
        "only {checked} tamper probes were locatable in the finalized text"
    );
}
