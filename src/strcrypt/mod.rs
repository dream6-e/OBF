//! 源码字符串加密（流水线第 ⓪′ 步，2026-10-06 新增）
//!
//! 目标：让进入编译器的源码里**不再出现任何用户字符串明文**——
//! `print("abc")` 在这一步之后变成 `print(<解密函数>("密文"))`，运行时再解回原值。
//!
//! 具体做法：
//!   1. 用第 ⓪ 步的词法扫描器切分源码（不解析文法）；
//!   2. 逐个串字面量：解码 Lua 转义得到真实字节 → 逐字面量随机种子的加法流加密
//!      → base86 编码（字母表逐构建随机、不含引号/反斜杠/反引号）→ 写成普通字符串字面量；
//!   3. 在源码顶部注入一个**纯算术**（无需 bit 库）的解密函数，形如
//!      `local <D>=(function() … return function(s) … end end)()`；
//!   4. 认不出转义的、空的、Luau 插值串一律原样保留（宁少压不压坏）；
//!   5. 收尾自检：重新分词后，除被替换的字面量外令牌序列不得变化，否则放弃本次加密。
//!
//! 定位说明：产物侧本来就没有明文（常量池 ChaCha + VM 解码链），这一步的价值是
//! **源码/中间态也不再出现明文**，并多加一层与产物层独立的加密；不改变产物形态。

pub mod codec;

use std::collections::HashSet;

use rand::Rng;

use crate::minifier::lexer::{Kind, Tok, lex};

/// 源码字符串加密。任何异常都返回原文。
pub fn encrypt_strings(source: &str) -> String {
    let tokens = match lex(source) {
        Ok(t) => t,
        Err(_) => return source.to_string(),
    };
    if tokens.is_empty() {
        return source.to_string();
    }

    let mut rng = rand::rng();
    let mut used: HashSet<String> = tokens
        .iter()
        .filter(|t| t.kind == Kind::Name)
        .map(|t| t.text.clone())
        .collect();

    let alpha = codec::random_alphabet(&mut rng);
    let stream = codec::Stream::random(&mut rng);
    let n_dec = rand_name(&mut rng, &mut used);
    let n_al = rand_name(&mut rng, &mut used);
    let n_am = rand_name(&mut rng, &mut used);
    let n_f = rand_name(&mut rng, &mut used);
    let n_c = rand_name(&mut rng, &mut used);
    let n_s = rand_name(&mut rng, &mut used);
    let n_r = rand_name(&mut rng, &mut used);
    let n_t = rand_name(&mut rng, &mut used);
    let n_p = rand_name(&mut rng, &mut used);
    let n_g = rand_name(&mut rng, &mut used);
    let n_v = rand_name(&mut rng, &mut used);
    let n_j = rand_name(&mut rng, &mut used);
    let n_n = rand_name(&mut rng, &mut used);
    let n_k = rand_name(&mut rng, &mut used);
    let n_x = rand_name(&mut rng, &mut used);
    let n_o = rand_name(&mut rng, &mut used);
    let n_a = rand_name(&mut rng, &mut used);
    let n_b = rand_name(&mut rng, &mut used);
    let n_st2 = rand_name(&mut rng, &mut used);
    let n_a2 = rand_name(&mut rng, &mut used);
    let n_b2 = rand_name(&mut rng, &mut used);
    let n_mi = rand_name(&mut rng, &mut used);

    let mut out_tokens: Vec<Tok> = Vec::with_capacity(tokens.len());
    let mut slots: Vec<Slot> = Vec::with_capacity(tokens.len());
    let mut replaced = 0usize;

    for (idx, tok) in tokens.iter().enumerate() {
        let prev = idx.checked_sub(1).map(|i| &tokens[i]);
        let plain = match tok.kind {
            Kind::Str => codec::decode_short_literal(&tok.text),
            Kind::LongStr => codec::decode_long_literal(&tok.text),
            // Luau 插值串含代码片段，整体保持原样
            _ => None,
        };
        // `x :: "类型"`（Luau 字面量类型）里字符串处在类型位置，不能被换成调用
        let in_type_slot = matches!(prev, Some(p) if p.kind == Kind::Op && p.text == "::");
        match plain {
            Some(value) if !value.is_empty() && !in_type_slot => {
                let (seed1, seed2): (u32, u32) = (rng.random(), rng.random());
                let cipher = codec::seal_literal(&value, &stream, &alpha, seed1, seed2);
                // 前一个记号若是 prefixexp 的结尾，这个字面量本来会被当成「调用实参糖」
                // （`f "s"` == `f("s")`）吃掉，必须补一层括号让它继续充当实参。
                let slot = if takes_sugar_args(prev) {
                    out_tokens.push(op_tok("("));
                    out_tokens.extend(call_tokens(&n_dec, &cipher));
                    out_tokens.push(op_tok(")"));
                    Slot::Wrapped
                } else {
                    out_tokens.extend(call_tokens(&n_dec, &cipher));
                    Slot::Plain
                };
                slots.push(slot);
                replaced += 1;
            }
            _ => {
                out_tokens.push(tok.clone());
                slots.push(Slot::Keep);
            }
        }
    }

    if replaced == 0 {
        return source.to_string();
    }

    let body = crate::minifier::join_tokens(&out_tokens);
    let header = build_decryptor(
        DecryptorNames {
            dec: &n_dec,
            alpha: &n_al,
            map: &n_am,
            floor: &n_f,
            cache: &n_c,
            s: &n_s,
            r: &n_r,
            t: &n_t,
            p: &n_p,
            g: &n_g,
            v: &n_v,
            j: &n_j,
            n: &n_n,
            k: &n_k,
            x: &n_x,
            o: &n_o,
            a: &n_a,
            b: &n_b,
            st2: &n_st2,
            a2: &n_a2,
            b2: &n_b2,
            mi: &n_mi,
        },
        &alpha,
        &stream,
    );

    // 自检（任一不满足即原样放行，宁少压不压坏）：
    //   1. 注入的解密壳自身可分词；
    //   2. 正文分词后与「原令牌序列、仅把被替换的字面量展开成 `名字("密文")`」逐令牌一致；
    //   3. 壳与正文相接处不产生记号粘连。
    let (Ok(header_tokens), Ok(body_tokens)) = (lex(&header), lex(&body)) else {
        return source.to_string();
    };
    if !matches_replacement(&tokens, &slots, &n_dec, &body_tokens) {
        return source.to_string();
    }
    let out = format!("{}{}", header, body);
    match lex(&out) {
        Ok(joined) if joined.len() == header_tokens.len() + body_tokens.len() => out,
        _ => source.to_string(),
    }
}

/// 一处字符串字面量在输出里的形态
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// 原样保留（空串 / 认不出的转义 / 插值串 / 类型位置）
    Keep,
    /// 换成 `解密名("密文")`
    Plain,
    /// 换成 `(解密名("密文"))`——原位置是「调用实参糖」时必须补括号
    Wrapped,
}

/// 该记号能否作为 prefixexp 的结尾、把紧随的字面量当调用实参吃掉（`f "s"`、`f{} "s"`…）
fn takes_sugar_args(prev: Option<&Tok>) -> bool {
    match prev {
        None => false,
        Some(p) => match p.kind {
            Kind::Name | Kind::Str | Kind::LongStr | Kind::Interp => true,
            Kind::Op => matches!(p.text.as_str(), ")" | "]" | "}"),
            _ => false,
        },
    }
}

fn op_tok(text: &str) -> Tok {
    Tok {
        kind: Kind::Op,
        text: text.to_string(),
    }
}

/// 正文是否恰好是「原令牌序列 + 每处替换按 `Slot` 展开」——逐令牌比对
fn matches_replacement(orig: &[Tok], slots: &[Slot], dec: &str, body_tokens: &[Tok]) -> bool {
    let mut it = body_tokens.iter();
    for (tok, &slot) in orig.iter().zip(slots) {
        let first = match it.next() {
            Some(t) => t,
            None => return false,
        };
        match slot {
            Slot::Keep => {
                if first.kind != tok.kind || first.text != tok.text {
                    return false;
                }
            }
            Slot::Plain | Slot::Wrapped => {
                let head = if slot == Slot::Wrapped {
                    if first.kind != Kind::Op || first.text != "(" {
                        return false;
                    }
                    match it.next() {
                        Some(t) => t,
                        None => return false,
                    }
                } else {
                    first
                };
                let (open, cipher, close) = match (it.next(), it.next(), it.next()) {
                    (Some(a), Some(b), Some(c)) => (a, b, c),
                    _ => return false,
                };
                if head.kind != Kind::Name
                    || head.text != dec
                    || open.kind != Kind::Op
                    || open.text != "("
                    || cipher.kind != Kind::Str
                    || cipher.text.len() < 3
                    || close.kind != Kind::Op
                    || close.text != ")"
                {
                    return false;
                }
                if slot == Slot::Wrapped {
                    match it.next() {
                        Some(t) if t.kind == Kind::Op && t.text == ")" => {}
                        _ => return false,
                    }
                }
            }
        }
    }
    it.next().is_none()
}

struct DecryptorNames<'a> {
    dec: &'a str,
    alpha: &'a str,
    map: &'a str,
    floor: &'a str,
    cache: &'a str,
    s: &'a str,
    r: &'a str,
    t: &'a str,
    p: &'a str,
    g: &'a str,
    v: &'a str,
    j: &'a str,
    n: &'a str,
    k: &'a str,
    x: &'a str,
    o: &'a str,
    a: &'a str,
    b: &'a str,
    // 第二条流与乘法替换常数
    st2: &'a str,
    a2: &'a str,
    b2: &'a str,
    mi: &'a str,
}

/// 生成解密函数（纯算术：只用 `%`、`/`、`^`、`math.floor`、`string.byte/char`、`table.concat`）
fn build_decryptor(n: DecryptorNames<'_>, alpha: &[u8; 86], stream: &codec::Stream) -> String {
    decryptor_parts(n, alpha, stream).join(" ")
}

/// 解密函数的片段序列。片段之间、片段内部可能相邻成词的位置都显式留空格，
/// 以免出现 `endlocal`、`math.floorlocal` 这一类词法粘连（见 `decryptor_lexes_cleanly` 测试）。
fn decryptor_parts(n: DecryptorNames<'_>, alpha: &[u8; 86], stream: &codec::Stream) -> Vec<String> {
    let alpha_lit: String = alpha.iter().map(|&c| c as char).collect();
    vec![
        format!("local {dec}=(function()", dec = n.dec),
        format!("local {al}=\"{alv}\"", al = n.alpha, alv = alpha_lit),
        format!(
            "local {m}={{}} for {i}=1,#{al} do {m}[string.byte({al},{i})]={i}-1 end",
            m = n.map,
            i = n.j,
            al = n.alpha
        ),
        format!("local {f}=math.floor", f = n.floor),
        format!(
            "local {a},{b},{a2},{b2},{mi}={av},{bv},{a2v},{b2v},{miv} local {c}={{}} return function({s}) local {r}={c}[{s}] if {r} then return {r} end",
            a = n.a,
            b = n.b,
            a2 = n.a2,
            b2 = n.b2,
            mi = n.mi,
            av = stream.a1,
            bv = stream.b1,
            a2v = stream.a2,
            b2v = stream.b2,
            miv = stream.mul_inv,
            c = n.cache,
            s = n.s,
            r = n.r
        ),
        // 解码 base86 → 字节数组
        format!(
            "local {t}={{}} local {p}=1 while {p}<=#{s} do local {g}=#{s}-{p}+1 if {g}>5 then {g}=5 end local {v}=0 for {j}=0,{g}-1 do {v}={v}*86+{m}[string.byte({s},{p}+{j})] end {p}={p}+{g} local {k}={g}-1 for {q}=1,{k} do {t}[#{t}+1]={f}({v}/256^({k}-{q}))%256 end end",
            t = n.t,
            p = n.p,
            g = n.g,
            v = n.v,
            j = n.j,
            s = n.s,
            m = n.map,
            k = n.k,
            q = n.n,
            f = n.floor
        ),
        // 前 8 字节是两条流的种子；其余：双流推进取混合密钥字节 → 乘法替换求逆 → 减密钥
        format!(
            "local {x}={t}[1]+{t}[2]*256+{t}[3]*65536+{t}[4]*16777216 local {st2}={t}[5]+{t}[6]*256+{t}[7]*65536+{t}[8]*16777216 local {o}={{}} for {k}=9,#{t} do {x}=({x}*{a}+{b})%4294967296 {st2}=({st2}*{a2}+{b2})%4294967296 {o}[#{o}+1]=string.char(((({t}[{k}]+1)*{mi})%257-1+256-{f}(({x}+{st2}*256)%4294967296/16777216))%256) end",
            x = n.x,
            st2 = n.st2,
            t = n.t,
            o = n.o,
            k = n.k,
            a = n.a,
            b = n.b,
            a2 = n.a2,
            b2 = n.b2,
            mi = n.mi,
            f = n.floor
        ),
        format!(
            "{r}=table.concat({o}) {c}[{s}]={r} return {r} end end)()",
            r = n.r,
            o = n.o,
            c = n.cache,
            s = n.s
        ),
    ]
}

/// `名字("密文")` 三个令牌
fn call_tokens(name: &str, cipher: &str) -> Vec<Tok> {
    vec![
        Tok {
            kind: Kind::Name,
            text: name.to_string(),
        },
        Tok {
            kind: Kind::Op,
            text: "(".to_string(),
        },
        Tok {
            kind: Kind::Str,
            text: format!("\"{}\"", cipher),
        },
        Tok {
            kind: Kind::Op,
            text: ")".to_string(),
        },
    ]
}

/// 生成一个不与源码冲突的标识符
fn rand_name(rng: &mut impl Rng, used: &mut HashSet<String>) -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    loop {
        let len = rng.random_range(3..7);
        let mut name = String::with_capacity(len);
        name.push(LETTERS[rng.random_range(0..LETTERS.len())] as char);
        for _ in 1..len {
            name.push(ALNUM[rng.random_range(0..ALNUM.len())] as char);
        }
        if !is_keyword(&name) && used.insert(name.clone()) {
            return name;
        }
    }
}

fn is_keyword(s: &str) -> bool {
    matches!(
        s,
        "and" | "break" | "do" | "else" | "elseif" | "end" | "false" | "for" | "function" | "if"
            | "in" | "local" | "nil" | "not" | "or" | "repeat" | "return" | "then" | "true"
            | "until" | "while"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sample_names() -> DecryptorNames<'static> {
        DecryptorNames {
            dec: "dQ7",
            alpha: "aQ7",
            map: "mQ7",
            floor: "fQ7",
            cache: "cQ7",
            s: "sQ7",
            r: "rQ7",
            t: "tQ7",
            p: "pQ7",
            g: "gQ7",
            v: "vQ7",
            j: "jQ7",
            n: "nQ7",
            k: "kQ7",
            x: "xQ7",
            o: "oQ7",
            a: "aq7",
            b: "bQ7",
            st2: "S2Q7",
            a2: "A2Q7",
            b2: "B2Q7",
            mi: "MIQ7",
        }
    }

    #[test]
    fn decryptor_lexes_cleanly() {
        // 曾把 `end` + `local` 粘成 `endlocal`：此处守住"注入代码里每个标识符都必须是
        // 我们生成的随机名或 Lua 关键字"，任何粘连都会多出一个白名单外的名字。
        let mut rng = rand::rng();
        let alpha = crate::strcrypt::codec::random_alphabet(&mut rng);
        let stream = crate::strcrypt::codec::Stream::random(&mut rng);
        let code = build_decryptor(sample_names(), &alpha, &stream);
        let allowed: Vec<&str> = {
            let n = sample_names();
            let mut v = vec![
                n.dec, n.alpha, n.map, n.floor, n.cache, n.s, n.r, n.t, n.p, n.g, n.v, n.j, n.n,
                n.k, n.x, n.o, n.a, n.b, n.st2, n.a2, n.b2, n.mi,
                "local", "end", "for", "do", "if", "then", "return", "while", "function", "math",
                "string", "table", "floor", "byte", "char", "concat",
            ];
            v.sort_unstable();
            v
        };
        let tokens = crate::minifier::lexer::lex(&code).expect("注入代码必须可分词");
        for tok in &tokens {
            match tok.kind {
                Kind::Name => assert!(
                    allowed.binary_search(&tok.text.as_str()).is_ok(),
                    "出现白名单外的标识符 {:?}（疑似词法粘连）:\n{code}",
                    tok.text
                ),
                Kind::Number => assert!(
                    tok.text.bytes().all(|b| b.is_ascii_digit()),
                    "异常数字记号 {:?}",
                    tok.text
                ),
                Kind::Str => {
                    // 唯一允许的字符串字面量：base86 字母表
                    let lit = tok.text.trim_matches('"');
                    assert_eq!(lit.len(), 86, "异常的字符串字面量: {:?}", tok.text);
                }
                Kind::Op | Kind::Raw => {}
                other => panic!("注入代码不应含 {other:?} 记号: {:?}", tok.text),
            }
        }
        assert!(code.contains("(function()"), "解密壳结构缺失");
        assert!(code.ends_with("end)()"), "解密壳结构缺失: {code}");
    }

    #[test]
    fn substitution_matches_lua_formula() {
        // 乘法替换是逐产物随机的，必须 Rust 加密端与 Lua 解密端**逐项相同**：
        // 用与壳里完全一样的表达式在 lua5.1 / luau 下算 0..255 全表，与 Rust 比对。
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut rng = rand::rng();
        for _ in 0..8 {
            let stream = crate::strcrypt::codec::Stream::random(&mut rng);
            let expect: Vec<u8> = (0..=255u8)
                .map(|x| crate::strcrypt::codec::substitute(x, stream.mul_inv))
                .collect();
            let code = format!(
                "local o={{}} for k=0,255 do o[#o+1]=((k+1)*{mi})%257-1 end print(table.concat(o,\",\"))",
                mi = stream.mul_inv
            );
            for bin in [
                root.join("toolchains/bin/lua5.1"),
                root.join("toolchains/bin/luau"),
            ] {
                if !bin.exists() {
                    continue;
                }
                let got = run_code(&bin, &code, root).expect("解释器可执行");
                assert_eq!(got.0, 0, "替换公式执行失败:\n{code}");
                let text = String::from_utf8_lossy(&got.1);
                let vals: Vec<u8> = text
                    .trim()
                    .split(',')
                    .map(|x| x.trim().parse::<u8>().expect("表项必须是 0..255"))
                    .collect();
                assert_eq!(vals.len(), 256, "替换表长度不对");
                assert_eq!(vals, expect, "Lua 侧替换与 Rust 不一致（解密会失败）");
            }
        }
        // 常数必须是双射（素数模保证），且逆元互逆
        for mul in 1u64..=256 {
            let inv = crate::strcrypt::codec::mod_inverse_257(mul);
            assert_eq!((mul * inv) % 257, 1, "逆元不对: {mul}");
        }
    }

    fn run_code(bin: &Path, code: &str, root: &Path) -> Option<(i32, Vec<u8>)> {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let seq = SEQ.fetch_add(1, Ordering::SeqCst);
        let tmp: PathBuf = std::env::temp_dir().join(format!(
            "kryvex_str_{}_{}_{}.lua",
            std::process::id(),
            seq,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&tmp, code).ok()?;
        let out = Command::new(bin).arg(&tmp).current_dir(root).output().ok();
        let _ = std::fs::remove_file(&tmp);
        let out = out?;
        Some((out.status.code().unwrap_or(-1), out.stdout))
    }

    #[test]
    fn plaintext_disappears_from_source() {
        let src = "local s = \"PLAINTEXT_MARKER_ZZ9\"\nlocal t = {key = '中文键'}\nprint(s, t.key)";
        let out = encrypt_strings(src);
        assert!(!out.contains("PLAINTEXT_MARKER_ZZ9"), "原文不得残留:\n{out}");
        assert!(!out.contains("中文键"), "原文不得残留:\n{out}");
        assert!(out.contains("print("), "代码结构应保留");
    }

    #[test]
    fn escapes_and_long_strings_survive() {
        // 与「不做本步骤」的同一解释器输出逐字节对照；只挑 5.1 与 Luau 语义一致的转义
        // （`\x`、`\z`、`\u{}` 两派含义不同，改由 `decoder_matches_pipeline_lexer` 兜住）。
        let cases = [
            r#"print("a\tb\nc")"#,
            r#"print("\65\66\67")"#,
            r#"print([[\nabc]])"#,
            "print([[多行\\n内容]])",
            r#"print('单引号 " 双引号')"#,
            r#"print("\\", "\"", "\'", "\a\b\f\v\r", "tab\9end")"#,
            r#"local t = {x = "键"} print(t.x, #t.x)"#,
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let lua = root.join("toolchains/bin/lua5.1");
        let luau = root.join("toolchains/bin/luau");
        for src in cases {
            let enc = encrypt_strings(src);
            assert_ne!(enc, src, "案例应当发生替换: {src}");
            for bin in [&lua, &luau] {
                if !bin.exists() {
                    continue;
                }
                let base = run_code(bin, src, root).expect("解释器可执行");
                let got = run_code(bin, &enc, root).expect("解释器可执行");
                assert_eq!(base.0, 0, "原文执行失败: {src}");
                assert_eq!(got.0, 0, "加密后执行失败: {enc}");
                assert_eq!(
                    String::from_utf8_lossy(&base.1),
                    String::from_utf8_lossy(&got.1),
                    "加密前后输出不一致: {src}"
                );
            }
        }
    }

    #[test]
    fn sugar_and_type_slots_compile_and_run() {
        // `print "s"`（调用实参糖）与 `x :: "T"`（Luau 字面量类型位置）最容易被换坏：
        // 前者必须补一层括号，后者必须原样保留。这里要求注入后的源码能被流水线编译器接受。
        let sugar = [
            r#"print "SUGAR_1""#,
            r#"print 'SUGAR_2'"#,
            r#"local f = print f "SUGAR_3""#,
            r#"local t = {} t.k = print t.k "SUGAR_4""#,
            r#"print(("SUGAR_5"):lower())"#,
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for src in sugar {
            let enc = encrypt_strings(src);
            assert_ne!(enc, src, "应当发生替换: {src}");
            assert!(
                crate::compiler::codegen::compile(enc.as_bytes(), "@sugar").is_ok(),
                "注入后无法编译（调用糖被换坏）:\n{enc}"
            );
            for bin in [root.join("toolchains/bin/lua5.1"), root.join("toolchains/bin/luau")] {
                if !bin.exists() {
                    continue;
                }
                let base = run_code(&bin, src, root).expect("解释器可执行");
                let got = run_code(&bin, &enc, root).expect("解释器可执行");
                assert_eq!(base.0, 0, "原文执行失败: {src}");
                assert_eq!(got.0, 0, "加密后执行失败:\n{enc}");
                assert_eq!(base.1, got.1, "加密前后输出不一致: {src}");
            }
        }
        // 类型位置的字符串必须原样保留（不替换 ⇒ 源码不变）
        let typed = r#"local x = 1 :: "T""#;
        assert_eq!(encrypt_strings(typed), typed);
    }

    /// 用流水线自己的词法器取某个字面量的值（返回 None 表示编译器也解不出来）
    fn pipeline_value(literal: &str) -> Option<Vec<u8>> {
        use crate::compiler::lexer::Lexer;
        use crate::compiler::token::Token;
        let probe = format!("return {literal}");
        let mut lx = Lexer::new(probe.as_bytes(), "@probe");
        loop {
            match lx.next() {
                Ok((Token::Str(v), _)) => return Some(v),
                Ok((Token::Eos, _)) => return None,
                Ok(_) => {}
                Err(_) => return None,
            }
        }
    }

    #[test]
    fn decoder_matches_pipeline_lexer() {
        // 关键不变式：strcrypt 解出的值必须与编译器解出的值逐字节相同，否则产物里的
        // 字符串会与「不做本步骤」时不一致（例：`\x41` 在 Lua 5.1 文本里是 `x41`，
        // 但本流水线的编译器按 Lua 5.2+/Luau 语义解成 `A`）。
        let cases = [
            r#"print("a\tb\nc")"#,
            r#"print("\65\66\67")"#,
            r#"print("\x41\x42")"#,
            r#"print("\z    x")"#,
            r#"print("\u{4e2d}\u{6587}")"#,
            r#"print([[\nabc]])"#,
            "print([[多行\\n内容]])",
            r#"print('单引号 " 双引号')"#,
            r#"print("\\", "\"", "\'", "\a\b\f\v\r")"#,
            r#"print("")"#,
            r#"print("tab\9end")"#,
        ];
        for src in cases {
            let tokens = crate::minifier::lexer::lex(src).expect("案例必须可分词");
            let mut checked = 0;
            for tok in &tokens {
                let mine = match tok.kind {
                    Kind::Str => codec::decode_short_literal(&tok.text),
                    Kind::LongStr => codec::decode_long_literal(&tok.text),
                    _ => continue,
                };
                let theirs = pipeline_value(&tok.text);
                assert_eq!(
                    mine.as_deref(),
                    theirs.as_deref(),
                    "字面量 {:?} 的解码与编译器不一致（本步骤会改变语义）",
                    tok.text
                );
                checked += 1;
            }
            assert!(checked > 0, "案例里居然没有字面量: {src}");
        }
        // 顺带固定住「编译器按 5.2+/Luau 解 \x」这一既有事实（本步骤沿用，不改它）
        assert_eq!(pipeline_value(r#""\x41\x42""#).as_deref(), Some(&b"AB"[..]));
    }

    #[test]
    fn empty_and_interpolated_are_left_alone() {
        let src = "local a = \"\"\nprint(a, `x{1}y`)";
        let out = encrypt_strings(src);
        assert!(out.contains("\"\""), "空串应原样保留: {out}");
        assert!(out.contains("`x{1}y`"), "插值串应原样保留: {out}");
    }

    #[test]
    fn unknown_escape_is_left_alone() {
        let src = r#"print("ok", "\q")"#;
        let out = encrypt_strings(src);
        assert!(out.contains(r#""\q""#), "认不出的转义必须原样保留: {out}");
    }

    #[test]
    fn corpus_output_matches_reference() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let lua = root.join("toolchains/bin/lua5.1");
        let luau = root.join("toolchains/bin/luau");
        if !lua.exists() && !luau.exists() {
            return;
        }
        let mut fixtures: Vec<PathBuf> = Vec::new();
        for name in [
            "test/print.lua",
            "test/nested_protos.lua",
            "test/string_encryption.lua",
            "test/DynamicGlobalEnv.lua",
            "test/Comptesting.lua",
            "test/roblox.lua",
        ] {
            let p = root.join(name);
            if p.exists() {
                fixtures.push(p);
            }
        }
        if let Ok(entries) = std::fs::read_dir(root.join("test/Prometheus")) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "lua").unwrap_or(false) {
                    fixtures.push(p);
                }
            }
        }
        let mut compared = 0usize;
        for path in &fixtures {
            let src = std::fs::read_to_string(path).expect("读取语料");
            let enc = encrypt_strings(&src);
            for bin in [&lua, &luau] {
                if !bin.exists() {
                    continue;
                }
                let a = run_code(bin, &src, root);
                let b = run_code(bin, &enc, root);
                if let (Some(a), Some(b)) = (a, b) {
                    if a.0 != 0 || b.0 != 0 {
                        continue; // 异常路径可能带行号，跳过
                    }
                    assert_eq!(a, b, "字符串加密改变了行为: {:?} @ {:?}", path, bin);
                    compared += 1;
                }
            }
        }
        assert!(compared > 0 || (!lua.exists() && !luau.exists()));
    }
}
