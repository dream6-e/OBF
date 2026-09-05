use crate::lexer::{Token, TokenKind};
use crate::{Diagnostic, Target};

/// Emit a comment-free, whitespace-minimal single-line chunk.
pub fn minify(source: &str, tokens: &[Token], target: Target) -> Result<String, Diagnostic> {
    let mut output = String::with_capacity(source.len());
    let mut previous: Option<(TokenKind, String)> = None;

    for token in tokens.iter().filter(|token| token.kind != TokenKind::Eof) {
        let raw = token.text(source);
        let text = if token.kind == TokenKind::String {
            normalize_string(raw, target).map_err(|error| {
                Diagnostic::at(error, token.span.start, token.line, token.column)
            })?
        } else {
            raw.to_owned()
        };

        if let Some((previous_kind, previous_text)) = &previous {
            if needs_separator(*previous_kind, previous_text, token.kind, &text) {
                output.push(' ');
            }
        }
        output.push_str(&text);
        previous = Some((token.kind, text));
    }

    debug_assert!(!output.contains('\n') && !output.contains('\r'));
    Ok(output)
}

fn normalize_string(raw: &str, target: Target) -> Result<String, String> {
    let bytes = raw.as_bytes();
    if bytes.first() == Some(&b'`') {
        if raw.contains(['\n', '\r']) {
            return Err("multiline interpolated strings cannot yet be emitted on one line".into());
        }
        return Ok(raw.to_owned());
    }

    let decoded = if matches!(bytes.first(), Some(b'\'' | b'"')) {
        decode_quoted(bytes, target)?
    } else {
        decode_long(bytes)?
    };
    Ok(encode_quoted(&decoded))
}

fn decode_long(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.first() != Some(&b'[') {
        return Err("invalid long string".into());
    }
    let mut opening_end = 1usize;
    while raw.get(opening_end) == Some(&b'=') {
        opening_end += 1;
    }
    if raw.get(opening_end) != Some(&b'[') {
        return Err("invalid long string delimiter".into());
    }
    let delimiter_len = opening_end + 1;
    if raw.len() < delimiter_len * 2 {
        return Err("truncated long string".into());
    }
    let mut content = &raw[delimiter_len..raw.len() - delimiter_len];
    // Lua discards exactly one initial newline in a long string.
    if content.starts_with(b"\r\n") || content.starts_with(b"\n\r") {
        content = &content[2..];
    } else if matches!(content.first(), Some(b'\r' | b'\n')) {
        content = &content[1..];
    }

    // The reference lexers normalize every source newline sequence to '\n'
    // while collecting a long string. Preserve that behavior before turning
    // the value into a quoted one-line literal.
    let mut normalized = Vec::with_capacity(content.len());
    let mut cursor = 0usize;
    while cursor < content.len() {
        match content[cursor] {
            b'\r' | b'\n' => {
                let first = content[cursor];
                cursor += 1;
                if cursor < content.len()
                    && matches!((first, content[cursor]), (b'\r', b'\n') | (b'\n', b'\r'))
                {
                    cursor += 1;
                }
                normalized.push(b'\n');
            }
            byte => {
                normalized.push(byte);
                cursor += 1;
            }
        }
    }
    Ok(normalized)
}

fn decode_quoted(raw: &[u8], target: Target) -> Result<Vec<u8>, String> {
    if raw.len() < 2 {
        return Err("truncated quoted string".into());
    }
    let quote = raw[0];
    let mut cursor = 1usize;
    let end = raw.len() - 1;
    let mut output = Vec::with_capacity(raw.len());

    while cursor < end {
        let byte = raw[cursor];
        cursor += 1;
        if byte != b'\\' {
            output.push(byte);
            continue;
        }
        let escaped = *raw
            .get(cursor)
            .ok_or_else(|| "truncated escape sequence".to_owned())?;
        cursor += 1;
        match escaped {
            b'a' => output.push(7),
            b'b' => output.push(8),
            b'f' => output.push(12),
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b't' => output.push(b'\t'),
            b'v' => output.push(11),
            b'\\' => output.push(b'\\'),
            b'\'' => output.push(b'\''),
            b'"' => output.push(b'"'),
            b'\n' => output.push(b'\n'),
            b'\r' => {
                if raw.get(cursor) == Some(&b'\n') {
                    cursor += 1;
                }
                output.push(b'\n');
            }
            b'0'..=b'9' => {
                let mut value = u16::from(escaped - b'0');
                let mut count = 1;
                while count < 3 {
                    let Some(next @ b'0'..=b'9') = raw.get(cursor).copied() else {
                        break;
                    };
                    value = value * 10 + u16::from(next - b'0');
                    cursor += 1;
                    count += 1;
                }
                if value > 255 {
                    return Err("decimal escape exceeds 255".into());
                }
                output.push(value as u8);
            }
            b'x' if target.is_luau() => {
                let high = hex(*raw.get(cursor).ok_or("truncated hexadecimal escape")?)?;
                let low = hex(*raw.get(cursor + 1).ok_or("truncated hexadecimal escape")?)?;
                cursor += 2;
                output.push(high * 16 + low);
            }
            b'u' if target.is_luau() => {
                if raw.get(cursor) != Some(&b'{') {
                    return Err("invalid Unicode escape".into());
                }
                cursor += 1;
                let start = cursor;
                while raw.get(cursor).is_some_and(|byte| byte.is_ascii_hexdigit()) {
                    cursor += 1;
                }
                if cursor == start || raw.get(cursor) != Some(&b'}') {
                    return Err("invalid Unicode escape".into());
                }
                let digits = std::str::from_utf8(&raw[start..cursor])
                    .map_err(|_| "invalid Unicode escape")?;
                let value = u32::from_str_radix(digits, 16)
                    .map_err(|_| "Unicode escape is out of range")?;
                let character = char::from_u32(value)
                    .ok_or_else(|| "Unicode escape is not a scalar value".to_owned())?;
                let mut buffer = [0u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                cursor += 1;
            }
            b'z' if target.is_luau() => {
                while cursor < end && raw[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
            }
            _ => return Err(format!("invalid escape sequence \\{}", escaped as char)),
        }
    }
    if raw[end] != quote {
        return Err("mismatched quote".into());
    }
    Ok(output)
}

fn encode_quoted(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() + 2);
    output.push('"');
    for &byte in bytes {
        match byte {
            b'"' => output.push_str("\\\""),
            b'\\' => output.push_str("\\\\"),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'\t' => output.push_str("\\t"),
            7 => output.push_str("\\a"),
            8 => output.push_str("\\b"),
            11 => output.push_str("\\v"),
            12 => output.push_str("\\f"),
            32..=126 => output.push(byte as char),
            _ => output.push_str(&format!("\\{byte:03}")),
        }
    }
    output.push('"');
    output
}

fn hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hexadecimal escape".into()),
    }
}

fn needs_separator(
    previous_kind: TokenKind,
    previous: &str,
    current_kind: TokenKind,
    current: &str,
) -> bool {
    let previous_word = matches!(
        previous_kind,
        TokenKind::Identifier | TokenKind::Keyword | TokenKind::Number
    );
    let current_word = matches!(
        current_kind,
        TokenKind::Identifier | TokenKind::Keyword | TokenKind::Number
    );
    if previous_word && current_word {
        return true;
    }

    let Some(left) = previous.as_bytes().last().copied() else {
        return false;
    };
    let Some(right) = current.as_bytes().first().copied() else {
        return false;
    };

    if left == b'-' && right == b'-' {
        return true; // would start a comment
    }
    if left == b'.' && (right == b'.' || right.is_ascii_digit()) {
        return true;
    }
    if previous_kind == TokenKind::Number && right == b'.' {
        return true;
    }

    matches!(
        (left, right),
        (b'=', b'=')
            | (b'~', b'=')
            | (b'<', b'=')
            | (b'>', b'=')
            | (b':', b':')
            | (b'-', b'>')
            | (b'+', b'=')
            | (b'-', b'=')
            | (b'*', b'=')
            | (b'/', b'=')
            | (b'/', b'/')
            | (b'%', b'=')
            | (b'^', b'=')
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;

    fn compact(source: &str, target: Target) -> String {
        let tokens = lexer::lex(source, target).unwrap();
        minify(source, &tokens, target).unwrap()
    }

    #[test]
    fn removes_comments_without_merging_tokens() {
        assert_eq!(
            compact("local a = 1 -- x\nlocal b = a - -2", Target::Lua51),
            "local a=1 local b=a- -2"
        );
    }

    #[test]
    fn rewrites_multiline_strings() {
        assert_eq!(
            compact("return [=[\nhello\nworld]=]", Target::Lua51),
            "return\"hello\\nworld\""
        );
        assert_eq!(
            compact("return [=[\r\nfirst\r\nsecond\rthird]=]", Target::Lua51),
            "return\"first\\nsecond\\nthird\""
        );
    }

    #[test]
    fn decodes_luau_escapes() {
        assert_eq!(
            compact(r#"return "\x41\u{42}""#, Target::Luau),
            "return\"AB\""
        );
    }
}
