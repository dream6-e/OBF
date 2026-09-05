use crate::{Diagnostic, Target};
use std::ops::Range;

pub(crate) const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_TOKENS: usize = 1_000_000;
const MAX_INTERPOLATION_NESTING: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Identifier,
    Keyword,
    Number,
    String,
    Symbol,
    Eof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Range<usize>,
    pub line: usize,
    pub column: usize,
}

impl Token {
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        &source[self.span.clone()]
    }
}

pub fn lex(source: &str, target: Target) -> Result<Vec<Token>, Diagnostic> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Diagnostic::new("source exceeds lexer safety limit"));
    }
    Lexer::new(source, target, true).run()
}

/// Lex a range while retaining byte spans and source positions from the
/// containing source. This is used for expressions inside interpolated
/// strings; unlike a chunk, a fragment never recognizes a shebang.
pub(crate) fn lex_fragment(
    source: &str,
    range: Range<usize>,
    target: Target,
) -> Result<Vec<Token>, Diagnostic> {
    if range.start > range.end
        || range.end > source.len()
        || !source.is_char_boundary(range.start)
        || !source.is_char_boundary(range.end)
    {
        return Err(Diagnostic::new("invalid source fragment span"));
    }
    let fragment = &source[range.clone()];
    let (base_line, base_column) = location_at(source, range.start);
    let mut tokens = Lexer::new(fragment, target, false).run()?;
    for token in &mut tokens {
        token.span.start += range.start;
        token.span.end += range.start;
        if token.line == 1 {
            token.column += base_column - 1;
        }
        token.line += base_line - 1;
    }
    Ok(tokens)
}

/// Return the half-open expression ranges embedded in an interpolated string.
pub(crate) fn interpolated_expression_ranges(
    source: &str,
    span: Range<usize>,
    target: Target,
) -> Result<Vec<Range<usize>>, Diagnostic> {
    if !target.is_luau()
        || span.start >= span.end
        || span.end > source.len()
        || !source.is_char_boundary(span.start)
        || !source.is_char_boundary(span.end)
        || source.as_bytes().get(span.start) != Some(&b'`')
    {
        return Err(Diagnostic::new("invalid interpolated string span"));
    }
    let mut lexer = Lexer::new(source, target, false);
    lexer.offset = span.start;
    (lexer.line, lexer.column) = location_at(source, span.start);
    let ranges = lexer.interpolated_string()?;
    if lexer.offset != span.end {
        return Err(lexer.error("interpolated string span ends at the wrong delimiter"));
    }
    Ok(ranges)
}

fn location_at(source: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    while cursor < offset {
        let byte = bytes[cursor];
        cursor += 1;
        if byte == b'\n' {
            line += 1;
            column = 1;
        } else if byte == b'\r' {
            if bytes.get(cursor) != Some(&b'\n') {
                line += 1;
                column = 1;
            }
        } else {
            column += 1;
        }
    }
    (line, column)
}

struct Lexer<'a> {
    source: &'a str,
    bytes: &'a [u8],
    target: Target,
    offset: usize,
    line: usize,
    column: usize,
    interpolation_depth: usize,
    allow_shebang: bool,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str, target: Target, allow_shebang: bool) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            target,
            offset: 0,
            line: 1,
            column: 1,
            interpolation_depth: 0,
            allow_shebang,
        }
    }

    fn run(mut self) -> Result<Vec<Token>, Diagnostic> {
        let mut tokens = Vec::new();

        // Both reference command-line programs accept a Unix shebang at the
        // beginning of a file even though '#' is not part of either grammar.
        if self.allow_shebang && self.offset == 0 && self.bytes.first() == Some(&b'#') {
            self.skip_line();
        }

        loop {
            self.skip_trivia()?;
            if self.offset == self.bytes.len() {
                if tokens.len() >= MAX_TOKENS {
                    return Err(self.error("token count exceeds lexer safety limit"));
                }
                tokens.push(Token {
                    kind: TokenKind::Eof,
                    span: self.offset..self.offset,
                    line: self.line,
                    column: self.column,
                });
                return Ok(tokens);
            }

            let start = self.offset;
            let line = self.line;
            let column = self.column;
            let byte = self.bytes[self.offset];

            let kind = if is_ident_start(byte) {
                self.bump();
                while self.peek().is_some_and(is_ident_continue) {
                    self.bump();
                }
                if is_keyword(&self.source[start..self.offset], self.target) {
                    TokenKind::Keyword
                } else {
                    TokenKind::Identifier
                }
            } else if byte.is_ascii_digit()
                || (byte == b'.'
                    && self
                        .bytes
                        .get(self.offset + 1)
                        .is_some_and(|byte| byte.is_ascii_digit()))
            {
                self.number()?;
                TokenKind::Number
            } else if byte == b'\'' || byte == b'"' {
                self.quoted_string(byte)?;
                TokenKind::String
            } else if byte == b'[' && self.long_bracket_level(self.offset).is_some() {
                self.long_string()?;
                TokenKind::String
            } else if byte == b'`' {
                if !self.target.is_luau() {
                    return Err(self.error("interpolated strings are only valid for Luau"));
                }
                self.interpolated_string()?;
                TokenKind::String
            } else {
                self.symbol()?;
                TokenKind::Symbol
            };

            if tokens.len() + 1 >= MAX_TOKENS {
                return Err(self.error("token count exceeds lexer safety limit"));
            }
            tokens.push(Token {
                kind,
                span: start..self.offset,
                line,
                column,
            });
        }
    }

    fn skip_trivia(&mut self) -> Result<(), Diagnostic> {
        loop {
            while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
                self.bump();
            }

            if !self.rest().starts_with(b"--") {
                return Ok(());
            }

            self.bump();
            self.bump();
            if self.peek() == Some(b'[') && self.long_bracket_level(self.offset).is_some() {
                self.long_comment()?;
            } else {
                self.skip_line();
            }
        }
    }

    fn long_bracket_level(&self, at: usize) -> Option<usize> {
        if self.bytes.get(at) != Some(&b'[') {
            return None;
        }
        let mut cursor = at + 1;
        while self.bytes.get(cursor) == Some(&b'=') {
            cursor += 1;
        }
        (self.bytes.get(cursor) == Some(&b'[')).then_some(cursor - at - 1)
    }

    fn consume_long_body(&mut self, level: usize, what: &str) -> Result<(), Diagnostic> {
        self.bump();
        for _ in 0..level {
            self.bump();
        }
        self.bump();

        loop {
            match self.peek() {
                None => return Err(self.error(format!("unfinished {what}"))),
                Some(b']') => {
                    let mut cursor = self.offset + 1;
                    let mut equals = 0;
                    while self.bytes.get(cursor) == Some(&b'=') {
                        equals += 1;
                        cursor += 1;
                    }
                    if equals == level && self.bytes.get(cursor) == Some(&b']') {
                        while self.offset <= cursor {
                            self.bump();
                        }
                        return Ok(());
                    }
                    self.bump();
                }
                Some(_) => {
                    self.bump();
                }
            }
        }
    }

    fn long_comment(&mut self) -> Result<(), Diagnostic> {
        let level = self
            .long_bracket_level(self.offset)
            .expect("caller checked long bracket");
        self.consume_long_body(level, "long comment")
    }

    fn long_string(&mut self) -> Result<(), Diagnostic> {
        let level = self
            .long_bracket_level(self.offset)
            .expect("caller checked long bracket");
        self.consume_long_body(level, "long string")
    }

    fn quoted_string(&mut self, quote: u8) -> Result<(), Diagnostic> {
        self.bump();
        loop {
            match self.peek() {
                None => return Err(self.error("unfinished string")),
                Some(byte) if byte == quote => {
                    self.bump();
                    return Ok(());
                }
                Some(b'\n' | b'\r') => {
                    return Err(self.error("unescaped newline in quoted string"));
                }
                Some(b'\\') => {
                    self.bump();
                    self.escape_sequence()?;
                }
                Some(_) => {
                    self.bump();
                }
            }
        }
    }

    fn escape_sequence(&mut self) -> Result<(), Diagnostic> {
        let Some(byte) = self.peek() else {
            return Err(self.error("unfinished escape sequence"));
        };

        match byte {
            b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v' | b'\\' | b'\'' | b'"' => {
                self.bump();
            }
            b'\n' => {
                self.bump();
            }
            b'\r' => {
                self.bump();
                if self.peek() == Some(b'\n') {
                    self.bump();
                }
            }
            b'0'..=b'9' => {
                let mut value = 0u16;
                for _ in 0..3 {
                    if let Some(byte) = self.peek().filter(|byte| byte.is_ascii_digit()) {
                        value = value * 10 + u16::from(byte - b'0');
                        self.bump();
                    } else {
                        break;
                    }
                }
                if value > 255 {
                    return Err(self.error("decimal escape sequence is greater than 255"));
                }
            }
            b'x' if self.target.is_luau() => {
                self.bump();
                self.require_hex_digit("hexadecimal escape")?;
                self.require_hex_digit("hexadecimal escape")?;
            }
            b'u' if self.target.is_luau() => {
                self.bump();
                if self.peek() != Some(b'{') {
                    return Err(self.error("expected '{' after \\u"));
                }
                self.bump();
                let start = self.offset;
                while self.peek().is_some_and(|b| b.is_ascii_hexdigit()) {
                    self.bump();
                }
                let digits = &self.source[start..self.offset];
                let scalar = u32::from_str_radix(digits, 16).ok();
                if digits.is_empty()
                    || self.peek() != Some(b'}')
                    || scalar.is_none_or(|value| value > 0x10ffff)
                {
                    return Err(self.error("invalid Unicode escape"));
                }
                self.bump();
            }
            b'z' if self.target.is_luau() => {
                self.bump();
                while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
                    self.bump();
                }
            }
            // Both Lua 5.1 and Luau accept a backslash before an otherwise
            // unrecognized character and retain the character itself.
            _ => {
                self.bump();
            }
        }
        Ok(())
    }

    fn interpolated_string(&mut self) -> Result<Vec<Range<usize>>, Diagnostic> {
        if self.interpolation_depth >= MAX_INTERPOLATION_NESTING {
            return Err(self.error("interpolated string nesting exceeds safety limit"));
        }
        self.interpolation_depth += 1;
        let result = self.interpolated_string_inner();
        self.interpolation_depth -= 1;
        result
    }

    fn interpolated_string_inner(&mut self) -> Result<Vec<Range<usize>>, Diagnostic> {
        debug_assert_eq!(self.peek(), Some(b'`'));
        self.bump();
        let mut expressions = Vec::new();
        loop {
            match self.peek() {
                None => return Err(self.error("unfinished interpolated string")),
                Some(b'`') => {
                    self.bump();
                    return Ok(expressions);
                }
                Some(b'\n' | b'\r') => {
                    return Err(self.error("unescaped newline in interpolated string"));
                }
                Some(b'\\') => {
                    self.bump();
                    self.escape_sequence()?;
                }
                Some(b'{') => {
                    if self.bytes.get(self.offset + 1) == Some(&b'{') {
                        return Err(self.error("double '{{' is invalid in an interpolated string"));
                    }
                    if expressions.len() >= MAX_TOKENS {
                        return Err(
                            self.error("interpolated expression count exceeds safety limit")
                        );
                    }
                    self.bump();
                    expressions.push(self.interpolated_expression()?);
                }
                // A lone closing brace is ordinary text in Luau; only an
                // opening brace begins an embedded expression.
                Some(b'}') => {
                    self.bump();
                }
                Some(_) => {
                    self.bump();
                }
            }
        }
    }

    fn interpolated_expression(&mut self) -> Result<Range<usize>, Diagnostic> {
        let start = self.offset;
        let mut brace_depth = 0usize;
        let mut saw_token = false;
        loop {
            self.skip_trivia()?;
            match self.peek() {
                None => return Err(self.error("unfinished interpolated expression")),
                Some(b'}') if brace_depth == 0 => {
                    if !saw_token {
                        return Err(self.error("interpolated expression cannot be empty"));
                    }
                    let end = self.offset;
                    self.bump();
                    return Ok(start..end);
                }
                Some(b'`') => {
                    saw_token = true;
                    self.interpolated_string()?;
                }
                Some(b'\'' | b'\"') => {
                    saw_token = true;
                    let quote = self.peek().unwrap_or_default();
                    self.quoted_string(quote)?;
                }
                Some(b'[') if self.long_bracket_level(self.offset).is_some() => {
                    saw_token = true;
                    self.long_string()?;
                }
                Some(byte) if is_ident_start(byte) => {
                    saw_token = true;
                    self.bump();
                    while self.peek().is_some_and(is_ident_continue) {
                        self.bump();
                    }
                }
                Some(byte)
                    if byte.is_ascii_digit()
                        || (byte == b'.'
                            && self
                                .bytes
                                .get(self.offset + 1)
                                .is_some_and(|byte| byte.is_ascii_digit())) =>
                {
                    saw_token = true;
                    self.number()?;
                }
                Some(b'{') => {
                    saw_token = true;
                    brace_depth += 1;
                    self.bump();
                }
                Some(b'}') => {
                    saw_token = true;
                    brace_depth -= 1;
                    self.bump();
                }
                Some(_) => {
                    saw_token = true;
                    self.symbol()?;
                }
            }
        }
    }

    fn number(&mut self) -> Result<(), Diagnostic> {
        let start = self.offset;

        // Match the reference lexers first, including their deliberately broad
        // number-like token. Validation happens after the complete candidate
        // has been consumed, preventing `1..2` from becoming three valid
        // tokens when both reference parsers report a malformed number.
        if self.peek() == Some(b'.') {
            self.bump();
        }
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_digit() || byte == b'.' || byte == b'_')
        {
            self.bump();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
        }
        while self
            .peek()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            self.bump();
        }

        let raw = &self.source[start..self.offset];
        if valid_numeric_literal(raw, self.target) {
            Ok(())
        } else {
            Err(self.error("malformed numeric literal"))
        }
    }

    fn require_hex_digit(&mut self, description: &str) -> Result<(), Diagnostic> {
        if self.peek().is_some_and(|byte| byte.is_ascii_hexdigit()) {
            self.bump();
            Ok(())
        } else {
            Err(self.error(format!("invalid {description}")))
        }
    }

    fn symbol(&mut self) -> Result<(), Diagnostic> {
        const LUAU_MULTI: &[&[u8]] = &[
            b"...", b"..=", b"//=", b"==", b"~=", b"<=", b">=", b"..", b"::", b"->", b"+=", b"-=",
            b"*=", b"/=", b"%=", b"^=", b"//",
        ];
        const LUA51_MULTI: &[&[u8]] = &[b"...", b"==", b"~=", b"<=", b">=", b".."];
        let choices = if self.target.is_luau() {
            LUAU_MULTI
        } else {
            LUA51_MULTI
        };

        for symbol in choices {
            if self.rest().starts_with(symbol) {
                for _ in 0..symbol.len() {
                    self.bump();
                }
                return Ok(());
            }
        }

        let byte = self.peek().expect("symbol called before eof");
        let allowed = b"+-*/%^#=<>;:,(){}[].";
        let luau_extra = b"&|?~@";
        if allowed.contains(&byte) || (self.target.is_luau() && luau_extra.contains(&byte)) {
            self.bump();
            Ok(())
        } else if byte >= 0x80 {
            Err(self.error("non-ASCII characters are only allowed inside strings and comments"))
        } else {
            Err(self.error(format!("unexpected character '{}'", byte as char)))
        }
    }

    fn skip_line(&mut self) {
        while let Some(byte) = self.peek() {
            self.bump();
            if byte == b'\n' || byte == b'\r' {
                break;
            }
        }
    }

    fn rest(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn bump(&mut self) {
        let byte = self.bytes[self.offset];
        self.offset += 1;
        if byte == b'\n' {
            self.line += 1;
            self.column = 1;
        } else if byte == b'\r' {
            if self.peek() != Some(b'\n') {
                self.line += 1;
                self.column = 1;
            }
        } else {
            self.column += 1;
        }
    }

    fn error(&self, message: impl Into<String>) -> Diagnostic {
        Diagnostic::at(message, self.offset, self.line, self.column)
    }
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit()
}

fn valid_numeric_literal(raw: &str, target: Target) -> bool {
    if raw.is_empty() || (!target.is_luau() && raw.contains('_')) {
        return false;
    }
    let normalized = if target.is_luau() {
        raw.replace('_', "")
    } else {
        raw.to_owned()
    };
    if normalized.is_empty() {
        return false;
    }

    let (number, integer) = if target.is_luau() {
        normalized
            .strip_suffix('i')
            .map_or((normalized.as_str(), false), |value| (value, true))
    } else {
        (normalized.as_str(), false)
    };

    if let Some(digits) = number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
    {
        if integer {
            return !digits.is_empty() && u64::from_str_radix(digits, 16).is_ok();
        }
        if target.is_luau() {
            return !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit());
        }
        if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return true;
        }
        // Lua 5.1 delegates conversion to the host C library after scanning;
        // glibc accepts hexadecimal floats whose exponent has no sign here.
        return digits
            .split_once(['p', 'P'])
            .is_some_and(|(mantissa, exponent)| {
                !mantissa.is_empty()
                    && mantissa.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && !exponent.is_empty()
                    && exponent.bytes().all(|byte| byte.is_ascii_digit())
            });
    }
    if let Some(digits) = number
        .strip_prefix("0b")
        .or_else(|| number.strip_prefix("0B"))
    {
        return target.is_luau()
            && !digits.is_empty()
            && if integer {
                u64::from_str_radix(digits, 2).is_ok()
            } else {
                digits.bytes().all(|byte| matches!(byte, b'0' | b'1'))
            };
    }
    if integer {
        return number.parse::<i64>().is_ok();
    }
    valid_decimal_literal(number)
}

fn valid_decimal_literal(value: &str) -> bool {
    let (mantissa, exponent) = match value.find(['e', 'E']) {
        Some(index) => (&value[..index], Some(&value[index + 1..])),
        None => (value, None),
    };
    if mantissa.matches('.').count() > 1
        || !mantissa
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !mantissa.bytes().any(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    exponent.is_none_or(|exponent| {
        let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn is_keyword(value: &str, target: Target) -> bool {
    const LUA51: &[&str] = &[
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in",
        "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
    ];
    // `type` and `export` are contextual in Luau and must remain usable as
    // ordinary identifiers (notably the built-in `type` function).
    LUA51.contains(&value) || (target.is_luau() && value == "continue")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_long_strings() {
        let source = "-- comment\nlocal x=[==[a\nb]==] --[=[ hidden ]=]\nreturn x";
        let tokens = lex(source, Target::Lua51).unwrap();
        let text: Vec<_> = tokens
            .iter()
            .filter(|t| t.kind != TokenKind::Eof)
            .map(|t| t.text(source))
            .collect();
        assert_eq!(text, ["local", "x", "=", "[==[a\nb]==]", "return", "x"]);
    }

    #[test]
    fn target_specific_numbers() {
        assert!(lex("return 0b1010_0011", Target::Luau).is_ok());
        assert!(lex("return 0b10", Target::Lua51).is_err());
        assert!(lex("return 1..2", Target::Lua51).is_err());
        assert!(lex("return 1e+", Target::Lua51).is_err());
        assert!(lex("return 0x1p2", Target::Lua51).is_ok());
        assert!(lex("return 1__0 + 0x_FF + 1i", Target::Luau).is_ok());
        assert!(lex("return 0b2", Target::Luau).is_err());
    }

    #[test]
    fn reports_unfinished_constructs() {
        assert!(lex("return 'x", Target::Lua51).is_err());
        assert!(lex("--[=[ x", Target::Luau).is_err());
    }
}
