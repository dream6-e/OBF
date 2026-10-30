use super::token::{Token, TokenType};

pub struct Packer;

/// 短字符串字面量的等价重编码（结构对齐 luraph14.9）。
///
/// luraph 的 19 个短串全部用转义混排写过（`"r\e\z\x61\zd\102\0544"`），于是
/// "grep 关键字 / 格式名 / API 名"这条路直接失效。这里做同一件事，但**只用
/// Lua 5.1 就有的十进制转义 `\ddd`**：
///
/// * `\xHH`（Lua 5.2+ / Luau）、`\z`（Luau）、`\u{…}`（Luau）在 5.1 上要么是
///   语法错误、要么被当成普通字符（实测 `"\x41"` 在 5.1 上等于 `"x41"`），
///   所以一律不产出；
/// * 长字符串（`[=[ … ]=]`，也就是载荷）原样保留 —— 它本来就是不可读的大块；
/// * 解码 → 再编码是逐字节往返，**值不变**，只改写法。产物仍然同时过
///   lua5.1 与 Luau，且 `RadixSieve` 依赖的"字符串区间"扫描不受影响
///   （encode 出来的串里不会出现裸引号，见 `encode_literal`）。
pub fn reencode_short_string(lit: &str) -> String {
    let bytes = lit.as_bytes();
    if bytes.len() < 2 {
        return lit.to_string();
    }
    let quote = bytes[0];
    if quote != b'"' && quote != b'\'' {
        // `[==[ … ]==]` 长串：不动。
        return lit.to_string();
    }
    if bytes[bytes.len() - 1] != quote {
        return lit.to_string();
    }
    let Some(raw) = decode_literal(&bytes[1..bytes.len() - 1]) else {
        return lit.to_string(); // 认不出的转义 ⇒ 原样放回（fail-open）
    };
    encode_literal(&raw, lit)
}

/// 按 Lua 5.1 的词法把字面量正文解成原始字节；遇到无法无损解释的写法返回 None。
fn decode_literal(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0usize;
    while i < body.len() {
        let c = body[i];
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i >= body.len() {
            return None;
        }
        let e = body[i];
        i += 1;
        match e {
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(10),
            b'r' => out.push(13),
            b't' => out.push(9),
            b'v' => out.push(11),
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'\'' => out.push(b'\''),
            b'\n' | b'\r' => out.push(b'\n'),
            b'x' => {
                // Lua 5.2+/Luau 写法：两位十六进制。
                if i + 1 >= body.len() {
                    return None;
                }
                let hi = hex_val(body[i])?;
                let lo = hex_val(body[i + 1])?;
                out.push(hi * 16 + lo);
                i += 2;
            }
            b'z' => {
                // Luau 的 `\z`：吞掉后续空白。
                while i < body.len() && (body[i] as char).is_ascii_whitespace() {
                    i += 1;
                }
            }
            b'u' => return None, // `\u{…}`：UTF-8 编码语义，交给原文（不做猜测）
            b'0'..=b'9' => {
                let mut v: u32 = (e - b'0') as u32;
                let mut n = 1;
                while n < 3 && i < body.len() && body[i].is_ascii_digit() {
                    v = v * 10 + (body[i] - b'0') as u32;
                    i += 1;
                    n += 1;
                }
                if v > 255 {
                    return None;
                }
                out.push(v as u8);
            }
            _ => return None,
        }
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// 老一套"看起来像明文"的判定：直接给人读得懂的串才重编码。
fn looks_plain(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| (0x20..=0x7E).contains(&b))
}

/// 用 `\ddd` 与原字符混排重新写出来。
///
/// 保留哪些字符由一个按字面量内容播种的小 LCG 决定：同一份输入永远得到同一份
/// 输出（可复现），但对不同的串给出不同的转义位置，避免出现"整串全转义"这种
/// 同样可辨的统一形状。
fn encode_literal(bytes: &[u8], seed_src: &str) -> String {
    if bytes.is_empty() {
        return "\"\"".to_string();
    }
    let plain = looks_plain(bytes);
    let mut h: u32 = 0x811C_9DC5;
    for b in seed_src.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    let mut out = String::with_capacity(bytes.len() + 8);
    out.push('"');
    for (idx, &b) in bytes.iter().enumerate() {
        h ^= b as u32 ^ (idx as u32).wrapping_mul(0x9E37_79B1);
        h = h.wrapping_mul(0x0100_0193);
        let keep = b.is_ascii_alphanumeric()
            && b != b'"'
            && b != b'\\'
            && plain
            && (h >> 11) % 100 >= 55;
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\{:03}", b));
        }
    }
    out.push('"');
    out
}

impl Packer {
    pub fn pack(tokens: Vec<Token>) -> String {
        let mut output = String::new();
        let mut prev_token: Option<&Token> = None;

        for token in &tokens {
            if let Some(prev) = prev_token {
                let needs_space = match (&prev.token_type, &token.token_type) {
                    (TokenType::Keyword, TokenType::Keyword) => true,
                    (TokenType::Keyword, TokenType::Identifier) => true,
                    (TokenType::Keyword, TokenType::Number) => true,
                    (TokenType::Identifier, TokenType::Keyword) => true,
                    (TokenType::Identifier, TokenType::Identifier) => true,
                    (TokenType::Identifier, TokenType::Number) => true,
                    (TokenType::Number, TokenType::Keyword) => true,
                    (TokenType::Number, TokenType::Identifier) => true,
                    (TokenType::Number, TokenType::Number) => true,
                    _ => false,
                };

                if needs_space {
                    let prev_can_end = match &prev.token_type {
                        TokenType::Identifier | TokenType::Number => true,
                        TokenType::Keyword => {
                            prev.text == "end"
                                || prev.text == "break"
                                || prev.text == "true"
                                || prev.text == "false"
                                || prev.text == "nil"
                        }
                        _ => false,
                    };

                    let next_can_start = match &token.token_type {
                        TokenType::Keyword => {
                            token.text == "local"
                                || token.text == "if"
                                || token.text == "while"
                                || token.text == "for"
                                || token.text == "function"
                                || token.text == "repeat"
                                || token.text == "break"
                                || token.text == "return"
                                || token.text == "goto"
                                || token.text == "end"
                        }
                        _ => false,
                    };

                    let can_use_semi = if prev.text == "return" {
                        token.text == "end"
                    } else {
                        prev_can_end && next_can_start
                    };

                    if can_use_semi {
                        output.push(';');
                    } else {
                        output.push(' ');
                    }
                } else if prev.text == "-" && token.text == "-" {
                    output.push(' ');
                } else if prev.text.ends_with('.') && token.text.starts_with('.') {
                    output.push(' ');
                } else if matches!(prev.token_type, TokenType::Number) && token.text.starts_with('.') {
                    output.push(' ');
                }
            }
            if token.token_type == TokenType::StringLiteral {
                output.push_str(&reencode_short_string(&token.text));
            } else {
                output.push_str(&token.text);
            }
            prev_token = Some(token);
        }

        output
    }
}
