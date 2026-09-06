use crate::lexer::{self, Token, TokenKind};
use crate::{parser, scope, Diagnostic, Target};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    /// Randomly rename safe locals; known reflection/environment access in
    /// user source disables this automatically. Opaque host reflection should
    /// use `Options::lexical()` instead.
    pub rename_locals: bool,
    /// Controls final 1-2 letter variable names. Defaults to a fresh seed.
    pub seed: u64,
}

impl Options {
    pub const fn seeded(seed: u64) -> Self {
        Self {
            rename_locals: true,
            seed,
        }
    }

    pub const fn lexical() -> Self {
        Self {
            rename_locals: false,
            seed: 0,
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self::seeded(crate::random::fresh_seed())
    }
}

pub(crate) fn with_options(
    source: &str,
    target: Target,
    options: Options,
) -> Result<String, Diagnostic> {
    finalize(source, target, options, false)
}

/// Called only by `vm::virtualize` after all crate-owned VM source has been
/// assembled. The checked generated-VM policy is NOT available to user source.
pub(crate) fn finalize_vm(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    finalize(source, target, Options::seeded(seed), true)
}

fn finalize(
    source: &str,
    target: Target,
    options: Options,
    generated_vm: bool,
) -> Result<String, Diagnostic> {
    let tokens = lexer::lex(source, target)?;
    let (chunk, statement_ends) = parser::parse_lexed_with_statement_ends(source, &tokens, target)?;
    let analysis = if options.rename_locals {
        Some(scope::analyze_chunk(&chunk)?)
    } else {
        None
    };
    let plan = analysis
        .as_ref()
        .map(|analysis| {
            if generated_vm {
                analysis.generated_vm_plan(&chunk, options.seed)
            } else {
                analysis.rename_plan(target, options.seed)
            }
        })
        .transpose()?;
    let renamed = match (&analysis, &plan) {
        (Some(analysis), Some(plan)) => plan.apply(source, analysis)?,
        _ => None,
    };
    let output = if let Some(renamed) = renamed {
        let tokens = lexer::lex(&renamed, target)?;
        // Renaming changes byte offsets. Never apply the original sidecar
        // to the newly spelled source, including its interpolation fragments.
        let (_, statement_ends) =
            parser::parse_lexed_with_statement_ends(&renamed, &tokens, target)?;
        emit_tokens(&renamed, &tokens, target, &statement_ends, 0)?
    } else {
        emit_tokens(source, &tokens, target, &statement_ends, 0)?
    };
    // Fail closed: reparse the final, normalized source and verify that every
    // reference still resolves to exactly the same binding (or global).
    let compact = parser::parse_source(&output, target)?;
    if let (Some(analysis), Some(plan)) = (analysis, plan) {
        let compact_analysis = scope::analyze_chunk(&compact)?;
        analysis.verify_renamed(&compact_analysis, &plan)?;
        if generated_vm
            && analysis
                .bindings
                .iter()
                .zip(&compact_analysis.bindings)
                .any(|(original, binding)| {
                    binding.declaration.is_some()
                        && (original.name == binding.name
                            || !(1..=2).contains(&binding.name.len())
                            || !binding.name.bytes().all(|byte| byte.is_ascii_lowercase()))
                })
        {
            return Err(Diagnostic::new(
                "generated VM retained a non-random or oversized local name",
            ));
        }
    }
    Ok(output)
}

/// Lexical-only compatibility entry point for an externally supplied token
/// array. For default safe local renaming, use `obf::minify` instead.
pub fn minify(source: &str, tokens: &[Token], target: Target) -> Result<String, Diagnostic> {
    let (_, statement_ends) = parser::parse_with_statement_ends(source, tokens, target)?;
    let output = emit_tokens(source, tokens, target, &statement_ends, 0)?;
    parser::parse_source(&output, target)?;
    Ok(output)
}

fn emit_tokens(
    source: &str,
    tokens: &[Token],
    target: Target,
    statement_ends: &[usize],
    depth: usize,
) -> Result<String, Diagnostic> {
    if depth > 64 {
        return Err(Diagnostic::new(
            "minifier interpolation nesting exceeds safety limit",
        ));
    }
    let mut output = String::new();
    let mut previous: Option<(TokenKind, String, usize)> = None;

    for token in tokens.iter().filter(|token| token.kind != TokenKind::Eof) {
        let raw = token.text(source);
        let text = if token.kind == TokenKind::String && raw.starts_with('`') {
            emit_interpolated(source, token, target, statement_ends, depth + 1)?
        } else if token.kind == TokenKind::String {
            normalize_string(raw, target).map_err(|error| {
                Diagnostic::at(error, token.span.start, token.line, token.column)
            })?
        } else {
            raw.to_owned()
        };

        if let Some((previous_kind, previous_text, previous_end)) = &previous {
            if text != ";" && statement_ends.binary_search(previous_end).is_ok() {
                // A semicolon is a statement terminator, NOT general trivia.
                // Prefer it at every proven statement boundary, even when
                // the old emitter could concatenate the tokens without space.
                // Existing ';' tokens are retained; never introduce ';;'.
                output.push(';');
            } else if needs_separator(*previous_kind, previous_text, token.kind, &text) {
                output.push(' ');
            }
        }
        output.push_str(&text);
        previous = Some((token.kind, text, token.span.end));
    }

    if output.contains(['\n', '\r']) {
        return Err(Diagnostic::new(
            "minifier failed to produce a single physical line",
        ));
    }
    Ok(output)
}

fn emit_interpolated(
    source: &str,
    token: &Token,
    target: Target,
    statement_ends: &[usize],
    depth: usize,
) -> Result<String, Diagnostic> {
    let ranges = lexer::interpolated_expression_ranges(source, token.span.clone(), target)?;
    let mut output = String::from("`");
    let mut start = token.span.start + 1;
    for range in ranges {
        emit_segment(source, start, range.start - 1, target, &mut output)?;
        output.push('{');
        let tokens = lexer::lex_fragment(source, range.clone(), target)?;
        let expression = emit_tokens(source, &tokens, target, statement_ends, depth)?;
        // `{{` is not a valid interpolation opener in Luau. A table literal
        // as the first expression token needs this otherwise-unnecessary gap.
        if expression.starts_with('{') {
            output.push(' ');
        }
        output.push_str(&expression);
        output.push('}');
        start = range.end + 1;
    }
    emit_segment(source, start, token.span.end - 1, target, &mut output)?;
    output.push('`');
    Ok(output)
}

fn emit_segment(
    source: &str,
    start: usize,
    end: usize,
    target: Target,
    output: &mut String,
) -> Result<(), Diagnostic> {
    let raw = source
        .get(start..end)
        .ok_or_else(|| Diagnostic::byte("invalid interpolation segment", start))?;
    let decoded = literal_bytes(&format!("`{raw}`"), target)
        .map_err(|error| Diagnostic::byte(error, start))?;
    encode_content(&decoded, b'`', true, output);
    Ok(())
}

fn normalize_string(raw: &str, target: Target) -> Result<String, String> {
    Ok(encode_quoted(&literal_bytes(raw, target)?))
}

/// Shared with scope analysis to recognize statically spelled reflective
/// field keys, including escaped and long-quoted names. Backticks here are
/// literal interpolation segments only, never unevaluated expressions.
pub(crate) fn literal_bytes(raw: &str, target: Target) -> Result<Vec<u8>, String> {
    let bytes = raw.as_bytes();
    if matches!(bytes.first(), Some(b'\'' | b'"' | b'`')) {
        decode_quoted(bytes, target)
    } else {
        decode_long(bytes)
    }
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
            // Both pinned lexers retain the escaped byte for otherwise
            // unknown escapes (`\q` -> `q`, including `\{` / `\`` in Luau).
            _ => output.push(escaped),
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
    encode_content(bytes, b'"', false, &mut output);
    output.push('"');
    output
}

fn encode_content(bytes: &[u8], quote: u8, interpolation: bool, output: &mut String) {
    for &byte in bytes {
        if byte == quote || (interpolation && byte == b'{') {
            output.push('\\');
            output.push(byte as char);
            continue;
        }
        match byte {
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
            "local a=1;local b=a- -2"
        );
    }

    #[test]
    fn every_statement_on_all_corpora_is_delimited_even_after_offset_changing_renames() {
        for (target, sources) in [
            (
                Target::Lua51,
                [
                    include_str!("../tests/fixtures/lua51.lua"),
                    include_str!("../tests/fixtures/ast_lua51.lua"),
                    include_str!("../tests/fixtures/scope_lua51.lua"),
                    include_str!("../tests/fixtures/reflection_lua51.lua"),
                    include_str!("../tests/fixtures/vm_lua51.lua"),
                ],
            ),
            (
                Target::Luau,
                [
                    include_str!("../tests/fixtures/luau.lua"),
                    include_str!("../tests/fixtures/ast_luau.lua"),
                    include_str!("../tests/fixtures/scope_luau.lua"),
                    include_str!("../tests/fixtures/reflection_luau.lua"),
                    include_str!("../tests/fixtures/vm_luau.lua"),
                ],
            ),
        ] {
            for source in sources {
                for options in [
                    Options::lexical(),
                    Options::seeded(0),
                    Options::seeded(u64::MAX),
                ] {
                    let output = with_options(source, target, options).unwrap();
                    let tokens = lexer::lex(&output, target).unwrap();
                    let (_, ends) =
                        parser::parse_lexed_with_statement_ends(&output, &tokens, target).unwrap();
                    for end in ends {
                        // Includes statements nested in function expressions,
                        // type syntax and interpolation, using GLOBAL offsets.
                        assert!(
                            end == output.len() || output.as_bytes()[end] == b';',
                            "{target}: {output}"
                        );
                    }
                    assert_eq!(compact(&output, target), output);
                }
            }
        }
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

#[cfg(test)]
mod generated_tests {
    use super::*;

    #[test]
    fn vm_exception_only_allows_the_audited_environment_capture() {
        let prefix = "local G=(getfenv and getfenv(0))or _G;";
        for target in [Target::Lua51, Target::Luau] {
            let source = format!("{prefix}local privateValue=1;return privateValue,G");
            let output = finalize_vm(&source, target, 42).unwrap();
            assert!(!output.contains("privateValue"));
            assert!(output.contains("getfenv(0)"));
            for invalid in [
                "local G=getfenv(1);local privateValue=1;return privateValue",
                "local G=(getfenv and getfenv(1))or _G;return G",
                "local G=(getfenv and getfenv(0,1))or _G;return G",
                "local G,H=(getfenv and getfenv(0))or _G,1;return G,H",
                "local _G={};local G=(getfenv and getfenv(0))or _G;return G",
                "local G=(getfenv and getfenv(0))or _G;return _G",
                "local G=(getfenv and getfenv(0))or _G;return observer.getfenv",
                "local G=(getfenv and getfenv(0))or _G;return observer[\"get\"..\"local\"]",
                "local G=(getfenv and getfenv(0))or _G;return debug",
                "local getfenv=function() return {} end;local G=(getfenv and getfenv(0))or _G;return G",
                "local G=(getfenv and getfenv(0))or _G;local G=(getfenv and getfenv(0))or _G;return G",
                "local G=(getfenv and getfenv(0))or _G;local self=1;return G,self",
                "local privateValue=1;return privateValue",
            ] {
                assert!(finalize_vm(invalid, target, 42).is_err(), "{target}: {invalid}");
            }
        }
    }
}
