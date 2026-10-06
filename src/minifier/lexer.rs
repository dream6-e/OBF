//! 源码词法扫描器（最小化器专用）
//!
//! 与压缩器的 `compressor/lexer.rs` 不同，这里**不建语法树、不做任何改写**：
//! 目标只是把源码切成一串「原样保留字节」的令牌，供最小化器做空白/注释重排。
//!
//! 覆盖范围（Lua 5.1 + Luau 词法全集）：
//!   * 行注释 `--…`、长注释 `--[=*[…]=*]`
//!   * 短字符串（含 `\` 转义、`\` 续行）、长括号串 `[=*[…]=*]`
//!   * Luau 反引号插值串 `` `文本 {表达式} 文本` ``（表达式内可嵌套字符串/注释/更深插值）
//!   * 数字：十进制/`0x` 十六进制/`0b` 二进制/小数/`e`·`p` 指数/Luau 数字分隔符 `_`
//!   * 运算符（含 Luau 的 `+= -= *= /= %= ^= ..= // //= -> ::`）
//!   * 其余字节：可打印 ASCII 记单字节运算符；非 ASCII 按整字符记为 `Raw`
//!
//! 安全策略：**任何拿不准的输入一律返回错误**，由调用方原样放行源码。宁可少压，
//! 不允许压坏。

/// 令牌种类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 标识符 / 关键字
    Name,
    /// 数字字面量
    Number,
    /// 短引号字符串（含引号）
    Str,
    /// 长括号字符串（含定界符）
    LongStr,
    /// Luau 反引号插值串（含反引号）
    Interp,
    /// 运算符 / 标点
    Op,
    /// 其它字节（非 ASCII 整字符等）
    Raw,
}

/// 一个令牌：字节区间与原文
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tok {
    pub kind: Kind,
    pub text: String,
}

/// 扫描失败（调用方应原样放行源码）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LexError(pub &'static str);

const ERR_UTF8: LexError = LexError("非 UTF-8 字节");
const ERR_NUL: LexError = LexError("源码含 NUL 字节");
const ERR_SHORT: LexError = LexError("短字符串未闭合");
const ERR_SHORT_NL: LexError = LexError("短字符串内出现裸换行");
const ERR_LONG: LexError = LexError("长括号串/长注释未闭合");
const ERR_INTERP: LexError = LexError("反引号插值串未闭合");

/// 运算符按长度从长到短排列，用于最长匹配。
const OPERATORS: &[&[u8]] = &[
    b"...", b"..=", b"<<=", b">>=", b"//=", b"..", b"::", b"==", b"~=", b"<=", b">=", b"+=",
    b"-=", b"*=", b"/=", b"%=", b"^=", b"->", b"//", b"<<", b">>", b"&=", b"|=", b"&&", b"||",
    b".", b":", b",", b";", b"(", b")", b"{", b"}", b"[", b"]", b"+", b"-", b"*", b"/", b"%",
    b"^", b"#", b"=", b"<", b">", b"~", b"&", b"|", b"?", b"@", b"!",
];

/// 扫描源码为令牌序列；注释被丢弃，空白不入令牌。
pub fn lex(src: &str) -> Result<Vec<Tok>, LexError> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out: Vec<Tok> = Vec::new();
    let mut i = 0usize;

    while i < n {
        let c = b[i];

        // ── 空白（Lua 的 isspace：空格 \t \n \v \f \r）
        if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C) {
            i += 1;
            continue;
        }
        if c == 0 {
            return Err(ERR_NUL);
        }

        // ── 注释
        if c == b'-' && i + 1 < n && b[i + 1] == b'-' {
            match long_bracket_close(b, i + 2)? {
                Some(end) => i = end,
                None => {
                    while i < n && b[i] != b'\n' {
                        i += 1;
                    }
                }
            }
            continue;
        }

        // ── 长括号串
        if c == b'[' {
            if let Some(end) = long_bracket_close(b, i)? {
                out.push(slice(src, i, end, Kind::LongStr)?);
                i = end;
                continue;
            }
        }

        // ── 短字符串
        if c == b'"' || c == b'\'' {
            let end = short_string_end(b, i)?;
            out.push(slice(src, i, end, Kind::Str)?);
            i = end;
            continue;
        }

        // ── Luau 反引号插值串
        if c == b'`' {
            let end = interp_end(b, i)?;
            out.push(slice(src, i, end, Kind::Interp)?);
            i = end;
            continue;
        }

        // ── 数字
        if c.is_ascii_digit() || (c == b'.' && i + 1 < n && b[i + 1].is_ascii_digit()) {
            let end = number_end(b, i);
            out.push(slice(src, i, end, Kind::Number)?);
            i = end;
            continue;
        }

        // ── 标识符 / 关键字
        if c == b'_' || c.is_ascii_alphabetic() {
            let mut j = i + 1;
            while j < n && (b[j] == b'_' || b[j].is_ascii_alphanumeric()) {
                j += 1;
            }
            out.push(slice(src, i, j, Kind::Name)?);
            i = j;
            continue;
        }

        // ── 运算符（最长匹配）
        if let Some(op) = OPERATORS.iter().find(|op| b[i..].starts_with(op)) {
            let end = i + op.len();
            out.push(slice(src, i, end, Kind::Op)?);
            i = end;
            continue;
        }

        // ── 其它：非 ASCII 按整字符记号（绝不切开多字节字符）
        let ch = src[i..].chars().next().ok_or(ERR_UTF8)?;
        let end = i + ch.len_utf8();
        out.push(slice(src, i, end, Kind::Raw)?);
        i = end;
    }

    Ok(out)
}

fn slice(src: &str, a: usize, z: usize, kind: Kind) -> Result<Tok, LexError> {
    let text = src.get(a..z).ok_or(ERR_UTF8)?;
    Ok(Tok {
        kind,
        text: text.to_string(),
    })
}

/// 若 `i` 处是长括号开头 `[=*[`，返回其配对结束位置（含结束定界符）；否则 None。
/// 未闭合时报错（不允许猜测）。
fn long_bracket_close(b: &[u8], i: usize) -> Result<Option<usize>, LexError> {
    let n = b.len();
    if i >= n || b[i] != b'[' {
        return Ok(None);
    }
    let mut k = i + 1;
    let mut eq = 0usize;
    while k < n && b[k] == b'=' {
        eq += 1;
        k += 1;
    }
    if k >= n || b[k] != b'[' {
        return Ok(None);
    }
    // 结束定界符 = `]` + eq 个 `=` + `]`
    let content = k + 1;
    let mut j = content;
    while j < n {
        if b[j] == b']' {
            let mut m = j + 1;
            let mut e2 = 0usize;
            while m < n && b[m] == b'=' {
                e2 += 1;
                m += 1;
            }
            if e2 == eq && m < n && b[m] == b']' {
                return Ok(Some(m + 1));
            }
        }
        j += 1;
    }
    Err(ERR_LONG)
}

/// 短字符串结束位置（含引号）
fn short_string_end(b: &[u8], i: usize) -> Result<usize, LexError> {
    let n = b.len();
    let q = b[i];
    let mut j = i + 1;
    while j < n {
        let d = b[j];
        if d == b'\\' {
            if j + 1 >= n {
                return Err(ERR_SHORT);
            }
            j += 2;
            continue;
        }
        if d == q {
            return Ok(j + 1);
        }
        if d == b'\n' || d == b'\r' {
            return Err(ERR_SHORT_NL);
        }
        j += 1;
    }
    Err(ERR_SHORT)
}

/// 反引号插值串结束位置（含收尾反引号）
fn interp_end(b: &[u8], i: usize) -> Result<usize, LexError> {
    let n = b.len();
    let mut j = i + 1;
    while j < n {
        match b[j] {
            b'\\' => {
                if j + 1 >= n {
                    return Err(ERR_INTERP);
                }
                j += 2;
            }
            b'`' => return Ok(j + 1),
            b'{' => j = interp_expr_end(b, j + 1)?,
            _ => j += 1,
        }
    }
    Err(ERR_INTERP)
}

/// 插值表达式 `{ … }` 的结束位置（返回 `}` 之后）；内部可嵌套字符串/注释/长括号/更深插值。
fn interp_expr_end(b: &[u8], i: usize) -> Result<usize, LexError> {
    let n = b.len();
    let mut j = i;
    let mut depth = 1usize;
    while j < n {
        let c = b[j];
        match c {
            b'{' => {
                depth += 1;
                j += 1;
            }
            b'}' => {
                depth -= 1;
                j += 1;
                if depth == 0 {
                    return Ok(j);
                }
            }
            b'"' | b'\'' => j = short_string_end(b, j)?,
            b'`' => j = interp_end(b, j)?,
            b'[' => {
                if let Some(end) = long_bracket_close(b, j)? {
                    j = end;
                } else {
                    j += 1;
                }
            }
            b'-' if j + 1 < n && b[j + 1] == b'-' => match long_bracket_close(b, j + 2)? {
                Some(end) => j = end,
                None => {
                    while j < n && b[j] != b'\n' {
                        j += 1;
                    }
                }
            },
            _ => j += 1,
        }
    }
    Err(ERR_INTERP)
}

/// 数字字面量结束位置
fn number_end(b: &[u8], i: usize) -> usize {
    let n = b.len();
    let mut j = i;
    let mut hex = false;

    if b[j] == b'0' && j + 1 < n && (b[j + 1] | 32) == b'x' {
        hex = true;
        j += 2;
        while j < n && (b[j].is_ascii_hexdigit() || b[j] == b'_') {
            j += 1;
        }
    } else if b[j] == b'0' && j + 1 < n && (b[j + 1] | 32) == b'b' {
        j += 2;
        while j < n && (b[j] == b'0' || b[j] == b'1' || b[j] == b'_') {
            j += 1;
        }
    } else {
        while j < n && (b[j].is_ascii_digit() || b[j] == b'_') {
            j += 1;
        }
    }
    // 小数点：`1..2` 里的点不吃（后一个还是点）
    if j < n && b[j] == b'.' && !(j + 1 < n && b[j + 1] == b'.') {
        j += 1;
        while j < n
            && ((hex && b[j].is_ascii_hexdigit()) || (!hex && b[j].is_ascii_digit()) || b[j] == b'_')
        {
            j += 1;
        }
    }
    // 指数：十进制 e/E，十六进制 p/P
    if j < n {
        let e = b[j] | 32;
        if (hex && e == b'p') || (!hex && e == b'e') {
            let mut k = j + 1;
            if k < n && (b[k] == b'+' || b[k] == b'-') {
                k += 1;
            }
            let d0 = k < n
                && ((hex && b[k].is_ascii_hexdigit()) || (!hex && b[k].is_ascii_digit()));
            if d0 {
                j = k;
                while j < n
                    && ((hex && b[j].is_ascii_hexdigit())
                        || (!hex && b[j].is_ascii_digit())
                        || b[j] == b'_')
                {
                    j += 1;
                }
            }
        }
    }
    j
}
