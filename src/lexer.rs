use crate::{Diagnostic, Target};
use std::ops::Range;

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
    Lexer::new(source, target).run()
}

struct Lexer<'a> {
    source: &'a str,
    bytes: &'a [u8],
    target: Target,
    offset: usize,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str, target: Target) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            target,
            offset: 0,
            line: 1,
            column: 1,
        }
    }

    fn run(mut self) -> Result<Vec<Token>, Diagnostic> {
        let mut tokens = Vec::new();

        if self.bytes.starts_with(b"\xef\xbb\xbf") {
            self.offset = 3;
            self.column = 2;
        }

        // Both reference command-line programs accept a Unix shebang at the
        // beginning of a file even though '#' is not part of either grammar.
        if self.offset == 0 && self.bytes.first() == Some(&b'#') {
            self.skip_line();
        }

        loop {
            self.skip_trivia()?;
            if self.offset == self.bytes.len() {
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
                for _ in 0..3 {
                    if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                        self.bump();
                    } else {
                        break;
                    }
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
                if self.offset == start || self.peek() != Some(b'}') {
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
            _ => {
                return Err(self.error(format!(
                    "unsupported escape sequence \\{} for {}",
                    byte as char, self.target
                )));
            }
        }
        Ok(())
    }

    fn interpolated_string(&mut self) -> Result<(), Diagnostic> {
        // Interpolated strings are retained as one token in the first parser
        // stage. Their nested expressions are validated by the pinned Luau
        // compiler in the compatibility matrix.
        self.bump();
        loop {
            match self.peek() {
                None => return Err(self.error("unfinished interpolated string")),
                Some(b'`') => {
                    self.bump();
                    return Ok(());
                }
                Some(b'\\') => {
                    self.bump();
                    if self.peek().is_none() {
                        return Err(self.error("unfinished interpolated string escape"));
                    }
                    self.bump();
                }
                Some(_) => {
                    self.bump();
                }
            }
        }
    }

    fn number(&mut self) -> Result<(), Diagnostic> {
        if self.rest().starts_with(b"0x") || self.rest().starts_with(b"0X") {
            self.bump();
            self.bump();
            self.digits(16, self.target.is_luau(), "hexadecimal literal")?;
        } else if self.rest().starts_with(b"0b") || self.rest().starts_with(b"0B") {
            if !self.target.is_luau() {
                return Err(self.error("binary numeric literals are not valid in Lua 5.1"));
            }
            self.bump();
            self.bump();
            self.digits(2, true, "binary literal")?;
        } else {
            if self.peek() == Some(b'.') {
                self.bump();
                self.digits(10, self.target.is_luau(), "fraction")?;
            } else {
                self.digits(10, self.target.is_luau(), "decimal literal")?;
                if self.peek() == Some(b'.') && self.bytes.get(self.offset + 1) != Some(&b'.') {
                    self.bump();
                    if self.peek().is_some_and(|b| digit_value(b, 10).is_some()) {
                        self.digits(10, self.target.is_luau(), "fraction")?;
                    }
                }
            }

            if matches!(self.peek(), Some(b'e' | b'E')) {
                self.bump();
                if matches!(self.peek(), Some(b'+' | b'-')) {
                    self.bump();
                }
                self.digits(10, self.target.is_luau(), "exponent")?;
            }
        }

        if self.peek().is_some_and(is_ident_start) {
            return Err(self.error("malformed numeric literal"));
        }
        Ok(())
    }

    fn digits(
        &mut self,
        radix: u8,
        underscores: bool,
        description: &str,
    ) -> Result<(), Diagnostic> {
        let mut count = 0usize;
        let mut previous_underscore = false;
        loop {
            match self.peek() {
                Some(byte) if digit_value(byte, radix).is_some() => {
                    count += 1;
                    previous_underscore = false;
                    self.bump();
                }
                Some(b'_') if underscores && count > 0 && !previous_underscore => {
                    previous_underscore = true;
                    self.bump();
                }
                _ => break,
            }
        }
        if count == 0 || previous_underscore {
            return Err(self.error(format!("invalid {description}")));
        }
        Ok(())
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
        let luau_extra = b"&|?~";
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

fn digit_value(byte: u8, radix: u8) -> Option<u8> {
    let value = match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => return None,
    };
    (value < radix).then_some(value)
}

fn is_keyword(value: &str, target: Target) -> bool {
    const LUA51: &[&str] = &[
        "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in",
        "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
    ];
    LUA51.contains(&value) || (target.is_luau() && matches!(value, "continue" | "export" | "type"))
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
        assert!(lex("return 1..2", Target::Lua51).is_ok());
        assert!(lex("return 1e+", Target::Lua51).is_err());
    }

    #[test]
    fn reports_unfinished_constructs() {
        assert!(lex("return 'x", Target::Lua51).is_err());
        assert!(lex("--[=[ x", Target::Luau).is_err());
    }
}
