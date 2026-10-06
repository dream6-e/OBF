//! 源码字符串加密的底层编解码（2026-10-06）
//!
//! 三件事，全部要求「Lua 5.1 与 Luau 都能在纯算术下执行」：
//!   1. 字面量字节的转义解码（`\n`/`\ddd`/`\xNN`/`\z`/`\u{…}`/长串首行丢弃）；
//!   2. 密文的 base86 表示（4 字节 → 5 字符，字母表逐构建随机且不含引号/反斜杠）；
//!   3. 逐字面量独立种子的加法流（LCG：`s = (s*A+B) mod 2^32`，只做模运算，无需位运算库）。
//!
//! 安全性定位（与实现一致，不夸大）：这一层是**源码级第二层**，产物侧的强加密（ChaCha
//! 常量池 + VM 解码链）仍在。乘法取 `A < 2^20` 是为了保证 `s*A+B < 2^53`，在 Lua 里
//! 用 double 也能精确表示，因此 Rust 与 Lua 两侧逐位一致。

use rand::Rng;

/// 字母表：从可见 ASCII 里剔除引号/反斜杠/反引号后随机取 86 个。
pub fn random_alphabet(rng: &mut impl Rng) -> [u8; 86] {
    let mut pool: Vec<u8> = (33u8..=126u8)
        .filter(|&c| c != b'"' && c != b'\'' && c != b'\\' && c != b'`' && c != b'$')
        .collect();
    // Fisher–Yates
    for i in (1..pool.len()).rev() {
        let j = rng.random_range(0..=i);
        pool.swap(i, j);
    }
    let mut alpha = [0u8; 86];
    alpha.copy_from_slice(&pool[..86]);
    alpha
}

/// 字母表 → 字符值表（Lua 侧解码用，这里只用于测试与自检）
pub fn alphabet_lookup(alpha: &[u8; 86]) -> [i16; 256] {
    let mut m = [-1i16; 256];
    for (i, &c) in alpha.iter().enumerate() {
        m[c as usize] = i as i16;
    }
    m
}

/// base86 编码：4 字节 → 5 字符，余 3/2/1 字节分别 → 4/3/2 字符。
/// 与 `src/VM/packer.rs` 的 base86 同规格，便于解码逻辑互证。
pub fn base86_encode(input: &[u8], alpha: &[u8; 86]) -> String {
    let mut out = String::with_capacity(input.len() / 4 * 5 + 5);
    let chunks = input.len() / 4;
    for i in 0..chunks {
        let v = ((input[i * 4] as u64) << 24)
            | ((input[i * 4 + 1] as u64) << 16)
            | ((input[i * 4 + 2] as u64) << 8)
            | (input[i * 4 + 3] as u64);
        let c1 = v / 54700816;
        let r1 = v % 54700816;
        let c2 = r1 / 636056;
        let r2 = r1 % 636056;
        let c3 = r2 / 7396;
        let r3 = r2 % 7396;
        let c4 = r3 / 86;
        let c5 = r3 % 86;
        for c in [c1, c2, c3, c4, c5] {
            out.push(alpha[c as usize] as char);
        }
    }
    let rem = input.len() % 4;
    let tail: &[u8] = &input[chunks * 4..];
    let digits: Vec<u64> = match rem {
        3 => {
            let v = ((tail[0] as u64) << 16) | ((tail[1] as u64) << 8) | (tail[2] as u64);
            vec![v / 636056, (v % 636056) / 7396, (v % 7396) / 86, v % 86]
        }
        2 => {
            let v = ((tail[0] as u64) << 8) | (tail[1] as u64);
            vec![v / 7396, (v % 7396) / 86, v % 86]
        }
        1 => {
            let v = tail[0] as u64;
            vec![v / 86, v % 86]
        }
        _ => Vec::new(),
    };
    for d in digits {
        out.push(alpha[d as usize] as char);
    }
    out
}

/// 加法流：`s = (s*A + B) mod 2^32`，取 `floor(s / 2^16) mod 256` 作为一个密钥字节。
#[derive(Clone, Copy, Debug)]
pub struct Stream {
    pub a: u64,
    pub b: u64,
}

impl Stream {
    pub fn random(rng: &mut impl Rng) -> Self {
        // A 取奇数且 < 2^20：保证 s*A+B < 2^53（Lua double 精确），且周期满长。
        let a = (rng.random_range(1u64 << 16..1u64 << 20)) | 1;
        let b = rng.random_range(1u64..(1u64 << 32));
        Self { a, b }
    }

    fn next(&self, state: &mut u64) -> u8 {
        *state = state.wrapping_mul(self.a).wrapping_add(self.b) & 0xFFFF_FFFF;
        ((*state >> 16) & 0xFF) as u8
    }
}

/// 加密一个字面量的值：载荷 = 4 字节小端种子 ‖ 密文；再整体 base86。
pub fn seal_literal(value: &[u8], stream: &Stream, alpha: &[u8; 86], seed: u32) -> String {
    let mut payload = Vec::with_capacity(value.len() + 4);
    payload.extend_from_slice(&seed.to_le_bytes());
    let mut state = seed as u64;
    for &b in value {
        let k = stream.next(&mut state);
        payload.push(b.wrapping_add(k));
    }
    base86_encode(&payload, alpha)
}

// ─────────────────────── 字面量转义解码 ───────────────────────

/// 短字符串字面量（含引号）→ 真实字节值；遇到不认识的转义返回 None（调用方原样保留该字面量）。
pub fn decode_short_literal(token: &str) -> Option<Vec<u8>> {
    let bytes = token.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let quote = bytes[0];
    if bytes[bytes.len() - 1] != quote {
        return None;
    }
    let inner = &token[1..token.len() - 1];
    let b = inner.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            return None;
        }
        let e = b[i];
        match e {
            b'a' => {
                out.push(7);
                i += 1;
            }
            b'b' => {
                out.push(8);
                i += 1;
            }
            b'f' => {
                out.push(12);
                i += 1;
            }
            b'n' => {
                out.push(10);
                i += 1;
            }
            b'r' => {
                out.push(13);
                i += 1;
            }
            b't' => {
                out.push(9);
                i += 1;
            }
            b'v' => {
                out.push(11);
                i += 1;
            }
            b'\\' => {
                out.push(b'\\');
                i += 1;
            }
            b'"' => {
                out.push(b'"');
                i += 1;
            }
            b'\'' => {
                out.push(b'\'');
                i += 1;
            }
            b'\n' => {
                out.push(b'\n');
                i += 1;
            }
            b'\r' => {
                // `\r\n` 计作一个换行
                out.push(b'\n');
                i += 1;
                if i < b.len() && b[i] == b'\n' {
                    i += 1;
                }
            }
            b'x' | b'X' => {
                // \xNN（Lua 5.2+/Luau）
                let mut j = i + 1;
                let mut v: u32 = 0;
                let mut n = 0;
                while j < b.len() && n < 2 && b[j].is_ascii_hexdigit() {
                    v = v * 16 + (b[j] as char).to_digit(16)?;
                    j += 1;
                    n += 1;
                }
                if n == 0 {
                    return None;
                }
                out.push(v as u8);
                i = j;
            }
            b'z' => {
                // \z 跳过后续空白（Lua 5.2+/Luau）
                i += 1;
                while i < b.len() && (b[i] as char).is_ascii_whitespace() {
                    i += 1;
                }
            }
            b'u' => {
                // \u{XXX}（Lua 5.3/Luau）
                if i + 1 >= b.len() || b[i + 1] != b'{' {
                    return None;
                }
                let mut j = i + 2;
                let mut v: u32 = 0;
                let mut n = 0;
                while j < b.len() && b[j] != b'}' {
                    v = v * 16 + (b[j] as char).to_digit(16)?;
                    j += 1;
                    n += 1;
                }
                if n == 0 || j >= b.len() {
                    return None;
                }
                let ch = char::from_u32(v)?;
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                i = j + 1;
            }
            b'0'..=b'9' => {
                // \ddd（最多三位十进制，值 ≤ 255）
                let mut j = i;
                let mut v: u32 = 0;
                let mut n = 0;
                while j < b.len() && n < 3 && b[j].is_ascii_digit() {
                    v = v * 10 + (b[j] - b'0') as u32;
                    j += 1;
                    n += 1;
                }
                if v > 255 {
                    return None;
                }
                out.push(v as u8);
                i = j;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// 长括号串（含定界符）→ 真实字节值（Lua 语义：紧跟在开括号后的首个换行被丢弃）。
pub fn decode_long_literal(token: &str) -> Option<Vec<u8>> {
    let b = token.as_bytes();
    if b.len() < 4 || b[0] != b'[' {
        return None;
    }
    let mut k = 1;
    while k < b.len() && b[k] == b'=' {
        k += 1;
    }
    if k >= b.len() || b[k] != b'[' {
        return None;
    }
    let eqs = k - 1;
    let close_len = eqs + 2;
    if b.len() < k + 1 + close_len {
        return None;
    }
    let body = &b[k + 1..b.len() - close_len];
    let body = if body.first() == Some(&b'\n') {
        &body[1..]
    } else if body.starts_with(b"\r\n") {
        &body[2..]
    } else {
        body
    };
    Some(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;

    #[test]
    fn escape_decoding_matches_lua_semantics() {
        assert_eq!(decode_short_literal(r#""a\tb""#).unwrap(), b"a\tb");
        assert_eq!(decode_short_literal(r#""\65\66\67""#).unwrap(), b"ABC");
        assert_eq!(decode_short_literal(r#""\x41\x42""#).unwrap(), b"AB");
        assert_eq!(decode_short_literal("\"a\\z  \n  b\"").unwrap(), b"ab");
        assert_eq!(decode_short_literal(r#""\u{4E2D}""#).unwrap(), "中".as_bytes());
        assert_eq!(decode_short_literal("'\\''").unwrap(), b"'");
        assert_eq!(decode_short_literal(r#""\\""#).unwrap(), b"\\");
        assert_eq!(decode_short_literal(r#""\q""#), None, "未知转义必须放弃");
        assert_eq!(decode_short_literal(r#""\300""#), None, "超过 255 的十进制转义必须放弃");
    }

    #[test]
    fn long_string_decoding() {
        assert_eq!(decode_long_literal("[[abc]]").unwrap(), b"abc");
        assert_eq!(decode_long_literal("[[\nabc]]").unwrap(), b"abc", "首个换行应丢弃");
        assert_eq!(decode_long_literal("[==[x]=]y]==]").unwrap(), b"x]=]y");
    }

    #[test]
    fn base86_roundtrip_under_lua_rules() {
        // Rust 侧自检：解码（按 Lua 侧同一算法）必须还原
        let mut r = rng();
        let alpha = random_alphabet(&mut r);
        let mut m = alphabet_lookup(&alpha);
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) % 256) as u8).collect();
            let enc = base86_encode(&data, &alpha);
            let enc_b = enc.as_bytes();
            let mut out: Vec<u8> = Vec::new();
            let mut i = 0usize;
            while i < enc_b.len() {
                let mut g = enc_b.len() - i;
                if g > 5 {
                    g = 5;
                }
                let mut v: u64 = 0;
                for j in 0..g {
                    let idx = m[enc_b[i + j] as usize];
                    assert!(idx >= 0, "编码字符必须在字母表内");
                    v = v * 86 + idx as u64;
                }
                i += g;
                let nb = g - 1; // 5→4, 4→3, 3→2, 2→1
                for k in (0..nb).rev() {
                    out.push(((v >> (8 * k)) & 0xFF) as u8);
                }
            }
            let _ = &mut m;
            assert_eq!(out, data, "len={} 往返不一致", len);
        }
    }

    #[test]
    fn stream_matches_lua_arithmetic() {
        // 关键约束：s*A+B 必须落在 double 精确范围（< 2^53）
        let mut r = rng();
        for _ in 0..200 {
            let s = Stream::random(&mut r);
            assert!(s.a < (1u64 << 20));
            assert!(s.a % 2 == 1);
            let max = (0xFFFF_FFFFu64) * s.a + s.b;
            assert!(max < (1u64 << 53), "乘法溢出 double 精确范围");
        }
    }

    #[test]
    fn seal_then_decode_roundtrip() {
        let mut r = rng();
        let alpha = random_alphabet(&mut r);
        let stream = Stream::random(&mut r);
        let value = "print 中文 🚀 \t mixed".as_bytes().to_vec();
        let enc = seal_literal(&value, &stream, &alpha, 0x1234_5678);
        assert!(!enc.contains('"') && !enc.contains('\\'), "密文必须能安全放进双引号字面量");
        // 用与 Lua 侧一致的解码 + 解密流程还原
        let m = alphabet_lookup(&alpha);
        let eb = enc.as_bytes();
        let mut bytes: Vec<u8> = Vec::new();
        let mut i = 0usize;
        while i < eb.len() {
            let mut g = eb.len() - i;
            if g > 5 {
                g = 5;
            }
            let mut v: u64 = 0;
            for j in 0..g {
                v = v * 86 + m[eb[i + j] as usize] as u64;
            }
            i += g;
            for k in (0..g - 1).rev() {
                bytes.push(((v >> (8 * k)) & 0xFF) as u8);
            }
        }
        let seed = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut state = seed as u64;
        let mut out = Vec::new();
        for &c in &bytes[4..] {
            state = (state * stream.a + stream.b) & 0xFFFF_FFFF;
            let k = ((state >> 16) & 0xFF) as u8;
            out.push(c.wrapping_sub(k));
        }
        assert_eq!(out, value);
    }
}
