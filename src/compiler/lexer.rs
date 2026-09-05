use crate::compiler::error::{LuaError, LuaResult, SyntaxError};
use super::token::{Span, Token, lookup_keyword};

type ReaderFn<'a> = Box<dyn FnMut() -> Result<Option<Vec<u8>>, LuaError> + 'a>;

pub struct Lexer<'a> {
    source: Vec<u8>,
    pos: usize,
    line: u32,
    column: u32,
    source_name: String,
    lookahead: Option<(Token, Span)>,
    last_token_text: String,
    reader: Option<ReaderFn<'a>>,
    reader_error: Option<LuaError>,
    reader_exhausted: bool,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &[u8], name: &str) -> Self {
        let (start, start_line) = if source.starts_with(b"#") {
            let end = source
                .iter()
                .position(|&b| b == b'\n' || b == b'\r')
                .map_or(source.len(), |p| p + 1);
            (end, 2)
        } else {
            (0, 1)
        };
        Self {
            source: source.to_vec(),
            pos: start,
            line: start_line,
            column: 1,
            source_name: name.to_string(),
            lookahead: None,
            last_token_text: String::new(),
            reader: None,
            reader_error: None,
            reader_exhausted: false,
        }
    }

    pub fn from_reader(
        first_chunk: Vec<u8>,
        reader: impl FnMut() -> Result<Option<Vec<u8>>, LuaError> + 'a,
        name: &str,
    ) -> Self {
        Self {
            source: first_chunk,
            pos: 0,
            line: 1,
            column: 1,
            source_name: name.to_string(),
            lookahead: None,
            last_token_text: String::new(),
            reader: Some(Box::new(reader)),
            reader_error: None,
            reader_exhausted: false,
        }
    }

    #[must_use]
    pub fn line(&self) -> u32 {
        self.line
    }

    #[must_use]
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    #[must_use]
    pub fn last_token_text(&self) -> &str {
        &self.last_token_text
    }

    fn refill(&mut self) -> bool {
        if self.reader_exhausted {
            return false;
        }
        let Some(reader) = self.reader.as_mut() else {
            return false;
        };
        match reader() {
            Ok(Some(data)) => {
                if data.is_empty() {
                    self.reader_exhausted = true;
                    false
                } else {
                    self.source.extend_from_slice(&data);
                    true
                }
            }
            Ok(None) => {
                self.reader_exhausted = true;
                false
            }
            Err(e) => {
                self.reader_error = Some(e);
                self.reader_exhausted = true;
                false
            }
        }
    }

    fn ensure_available(&mut self, needed: usize) -> bool {
        while self.pos + needed > self.source.len() {
            if !self.refill() {
                return false;
            }
        }
        true
    }

    #[inline]
    fn peek(&mut self) -> Option<u8> {
        if self.pos < self.source.len() {
            return Some(self.source[self.pos]);
        }
        if self.refill() && self.pos < self.source.len() {
            Some(self.source[self.pos])
        } else {
            None
        }
    }

    fn peek_ahead(&mut self, offset: usize) -> Option<u8> {
        let target = self.pos + offset;
        if target < self.source.len() {
            return Some(self.source[target]);
        }
        if self.ensure_available(offset + 1) {
            Some(self.source[self.pos + offset])
        } else {
            None
        }
    }

    #[inline]
    fn advance(&mut self) -> Option<u8> {
        if self.pos >= self.source.len() && !self.refill() {
            return None;
        }
        let ch = self.source[self.pos];
        self.pos += 1;
        if ch != b'\n' && ch != b'\r' {
            self.column += 1;
        }
        if self.reader.is_some() && self.pos >= self.source.len() {
            self.refill();
        }
        Some(ch)
    }

    fn inc_line(&mut self) {
        let old = self.peek();
        self.pos += 1;
        if let Some(next) = self.peek() {
            if (next == b'\n' || next == b'\r') && next != old.unwrap_or(0) {
                self.pos += 1;
            }
        }
        self.line += 1;
        self.column = 1;
    }

    fn current_span(&self) -> Span {
        Span::new(self.line, self.column)
    }

    fn syntax_error(&self, msg: &str) -> LuaError {
        LuaError::Syntax(SyntaxError {
            message: msg.to_string(),
            source: self.source_name.clone(),
            line: self.line,
            raw_message: None,
        })
    }

    fn syntax_error_near(&self, msg: &str, near: &str) -> LuaError {
        LuaError::Syntax(SyntaxError {
            message: format!("{} near '{}'", msg, near),
            source: self.source_name.clone(),
            line: self.line,
            raw_message: None,
        })
    }

    pub fn next(&mut self) -> LuaResult<(Token, Span)> {
        if let Some(la) = self.lookahead.take() {
            return Ok(la);
        }
        self.scan()
    }

    pub fn lookahead(&mut self) -> LuaResult<&Token> {
        if self.lookahead.is_none() {
            self.lookahead = Some(self.scan()?);
        }
        Ok(&self
            .lookahead
            .as_ref()
            .ok_or_else(|| self.syntax_error("unexpected error"))?
            .0)
    }

    fn scan(&mut self) -> LuaResult<(Token, Span)> {
        loop {
            if let Some(err) = self.reader_error.take() {
                return Err(err);
            }
            self.skip_whitespace();
            if let Some(err) = self.reader_error.take() {
                return Err(err);
            }
            let span = self.current_span();
            let token_start = self.pos;
            let Some(ch) = self.peek() else {
                if let Some(err) = self.reader_error.take() {
                    return Err(err);
                }
                return Ok((Token::Eos, span));
            };
            match ch {
                b'\n' | b'\r' => {
                    self.inc_line();
                }
                b'+' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::PlusEq, span));
                    }
                    return Ok((Token::Char(b'+'), span));
                }
                b'-' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::MinusEq, span));
                    }
                    if self.peek() == Some(b'>') {
                        self.advance();
                        return Ok((Token::Arrow, span));
                    }
                    if self.peek() != Some(b'-') {
                        return Ok((Token::Char(b'-'), span));
                    }
                    self.advance();
                    if self.peek() == Some(b'[') {
                        let sep = self.count_sep();
                        if sep >= 0 {
                            self.read_long_string(sep, true)?;
                            continue;
                        }
                    }
                    while let Some(c) = self.peek() {
                        if c == b'\n' || c == b'\r' {
                            break;
                        }
                        self.advance();
                    }
                }
                b'*' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::MulEq, span));
                    }
                    return Ok((Token::Char(b'*'), span));
                }
                b'/' => {
                    self.advance();
                    if self.peek() == Some(b'/') {
                        self.advance();
                        if self.peek() == Some(b'=') {
                            self.advance();
                            return Ok((Token::FloorDivEq, span));
                        }
                        return Ok((Token::FloorDiv, span));
                    }
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::DivEq, span));
                    }
                    return Ok((Token::Char(b'/'), span));
                }
                b'%' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::ModEq, span));
                    }
                    return Ok((Token::Char(b'%'), span));
                }
                b'^' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::PowEq, span));
                    }
                    return Ok((Token::Char(b'^'), span));
                }
                b'[' => {
                    let sep = self.count_sep();
                    if sep >= 0 {
                        let s = self.read_long_string(sep, false)?;
                        self.last_token_text =
                            String::from_utf8_lossy(&self.source[token_start..self.pos]).into();
                        return Ok((Token::Str(s), span));
                    }
                    if sep == -1 {
                        return Err(self.syntax_error_near("invalid long string delimiter", "["));
                    }
                    self.advance();
                    return Ok((Token::Char(b'['), span));
                }
                b'=' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::Eq, span));
                    }
                    return Ok((Token::Char(b'='), span));
                }
                b'<' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::Le, span));
                    }
                    if self.peek() == Some(b'<') {
                        self.advance();
                        return Ok((Token::Shl, span));
                    }
                    return Ok((Token::Char(b'<'), span));
                }
                b'>' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::Ge, span));
                    }
                    if self.peek() == Some(b'>') {
                        self.advance();
                        return Ok((Token::Shr, span));
                    }
                    return Ok((Token::Char(b'>'), span));
                }
                b'~' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        return Ok((Token::Ne, span));
                    }
                    return Ok((Token::BXor, span));
                }
                b'&' => {
                    self.advance();
                    return Ok((Token::BAnd, span));
                }
                b'|' => {
                    self.advance();
                    return Ok((Token::BOr, span));
                }
                b':' => {
                    self.advance();
                    if self.peek() == Some(b':') {
                        self.advance();
                        return Ok((Token::ColonColon, span));
                    }
                    return Ok((Token::Char(b':'), span));
                }
                b'.' => {
                    self.advance();
                    if self.peek() == Some(b'.') {
                        self.advance();
                        if self.peek() == Some(b'.') {
                            self.advance();
                            return Ok((Token::Dots, span));
                        }
                        if self.peek() == Some(b'=') {
                            self.advance();
                            return Ok((Token::ConcatEq, span));
                        }
                        return Ok((Token::Concat, span));
                    }
                    if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                        let num = self.read_number(b'.')?;
                        return Ok((Token::Number(num), span));
                    }
                    return Ok((Token::Char(b'.'), span));
                }
                b'"' | b'\'' | b'`' => {
                    let s = self.read_short_string(ch)?;
                    self.last_token_text =
                        String::from_utf8_lossy(&self.source[token_start..self.pos]).into();
                    return Ok((Token::Str(s), span));
                }
                _ if ch.is_ascii_digit() => {
                    let num = self.read_number(ch)?;
                    return Ok((Token::Number(num), span));
                }
                _ if ch.is_ascii_alphabetic() || ch == b'_' => {
                    let (start, end) = self.scan_name_extent();
                    let name_bytes = &self.source[start..end];
                    if let Some(kw) = lookup_keyword(name_bytes) {
                        return Ok((kw, span));
                    }
                    let name = String::from_utf8(name_bytes.to_vec())
                        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
                    return Ok((Token::Name(name), span));
                }
                _ => {
                    self.advance();
                    return Ok((Token::Char(ch), span));
                }
            }
        }
    }

    #[inline]
    fn skip_whitespace(&mut self) {
        if self.reader.is_none() {
            let src = &self.source;
            let mut p = self.pos;
            while p < src.len() {
                let c = src[p];
                if c == b' ' || c == b'\t' || c == 0x0C || c == 0x0B {
                    p += 1;
                } else {
                    break;
                }
            }
            let skipped = p - self.pos;
            self.column += skipped as u32;
            self.pos = p;
            return;
        }
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' || c == 0x0C || c == 0x0B {
                self.advance();
            } else {
                break;
            }
        }
    }

    #[inline]
    fn scan_name_extent(&mut self) -> (usize, usize) {
        let start = self.pos;
        if self.reader.is_none() {
            let src = &self.source;
            let mut p = self.pos;
            while p < src.len() {
                let c = src[p];
                if c.is_ascii_alphanumeric() || c == b'_' {
                    p += 1;
                } else {
                    break;
                }
            }
            let len = p - self.pos;
            self.column += len as u32;
            self.pos = p;
            return (start, p);
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        (start, self.pos)
    }

    fn read_number(&mut self, first: u8) -> LuaResult<f64> {
        let start = if first == b'.' {
            self.pos - 1
        } else {
            self.pos
        };

        let mut is_hex = false;
        let mut is_bin = false;

        if first == b'0' {
            self.advance();
            if let Some(c) = self.peek() {
                if c == b'x' || c == b'X' {
                    is_hex = true;
                    self.advance();
                } else if c == b'b' || c == b'B' {
                    is_bin = true;
                    self.advance();
                }
            }
        } else if first != b'.' {
            self.advance();
        }

        while let Some(c) = self.peek() {
            if is_hex {
                if c.is_ascii_hexdigit() || c == b'_' || c == b'.' || c == b'p' || c == b'P' {
                    self.advance();
                    if c == b'p' || c == b'P' {
                        if let Some(n) = self.peek() {
                            if n == b'+' || n == b'-' {
                                self.advance();
                            }
                        }
                    }
                } else {
                    break;
                }
            } else if is_bin {
                if c == b'0' || c == b'1' || c == b'_' {
                    self.advance();
                } else {
                    break;
                }
            } else {
                if c.is_ascii_digit() || c == b'.' || c == b'_' || c == b'e' || c == b'E' {
                    self.advance();
                    if c == b'e' || c == b'E' {
                        if let Some(n) = self.peek() {
                            if n == b'+' || n == b'-' {
                                self.advance();
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        }

        while self.peek().is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_') {
            self.advance();
        }

        let num_bytes = &self.source[start..self.pos];
        let num_str = String::from_utf8_lossy(num_bytes).into_owned();
        self.last_token_text = num_str.clone();

        let clean_str = num_str.replace('_', "");

        if is_hex {
            let hex_body = &clean_str[2..];
            if hex_body.is_empty() {
                return Err(self.syntax_error_near("malformed number", &num_str));
            }
            return match u64::from_str_radix(hex_body, 16) {
                Ok(v) => Ok(v as f64),
                Err(_) => Err(self.syntax_error_near("malformed number", &num_str)),
            };
        } else if is_bin {
            let bin_body = &clean_str[2..];
            if bin_body.is_empty() {
                return Err(self.syntax_error_near("malformed number", &num_str));
            }
            return match u64::from_str_radix(bin_body, 2) {
                Ok(v) => Ok(v as f64),
                Err(_) => Err(self.syntax_error_near("malformed number", &num_str)),
            };
        } else {
            return match clean_str.parse::<f64>() {
                Ok(val) => Ok(val),
                Err(_) => Err(self.syntax_error_near("malformed number", &num_str)),
            };
        }
    }

    fn read_short_string(&mut self, delimiter: u8) -> LuaResult<Vec<u8>> {
        self.advance();
        let mut buf = Vec::new();
        loop {
            match self.peek() {
                None => {
                    return Err(self.syntax_error_near("unfinished string", "<eof>"));
                }
                Some(b'\n') | Some(b'\r') => {
                    return Err(self.syntax_error_near("unfinished string", "<string>"));
                }
                Some(c) if c == delimiter => {
                    self.advance();
                    break;
                }
                Some(b'\\') => {
                    self.advance();
                    match self.peek() {
                        Some(b'a') => {
                            self.advance();
                            buf.push(0x07);
                        }
                        Some(b'b') => {
                            self.advance();
                            buf.push(0x08);
                        }
                        Some(b'f') => {
                            self.advance();
                            buf.push(0x0C);
                        }
                        Some(b'n') => {
                            self.advance();
                            buf.push(b'\n');
                        }
                        Some(b'r') => {
                            self.advance();
                            buf.push(b'\r');
                        }
                        Some(b't') => {
                            self.advance();
                            buf.push(b'\t');
                        }
                        Some(b'v') => {
                            self.advance();
                            buf.push(0x0B);
                        }
                        Some(b'\\') => {
                            self.advance();
                            buf.push(b'\\');
                        }
                        Some(b'"') => {
                            self.advance();
                            buf.push(b'"');
                        }
                        Some(b'\'') => {
                            self.advance();
                            buf.push(b'\'');
                        }
                        Some(b'`') => {
                            self.advance();
                            buf.push(b'`');
                        }
                        Some(b'\n') | Some(b'\r') => {
                            self.inc_line();
                            buf.push(b'\n');
                        }
                        Some(b'z') => {
                            self.advance();
                            while let Some(w) = self.peek() {
                                if w.is_ascii_whitespace() {
                                    if w == b'\n' || w == b'\r' {
                                        self.inc_line();
                                    } else {
                                        self.advance();
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                        Some(b'u') => {
                            self.advance();
                            if self.peek() != Some(b'{') {
                                return Err(self.syntax_error_near("missing '{' in \\u escape", "<string>"));
                            }
                            self.advance();
                            let mut val = 0u32;
                            let mut has_digits = false;
                            while let Some(c) = self.peek() {
                                if c == b'}' {
                                    self.advance();
                                    break;
                                }
                                if c.is_ascii_hexdigit() {
                                    has_digits = true;
                                    let v = if c >= b'0' && c <= b'9' { c - b'0' }
                                            else if c >= b'a' && c <= b'f' { c - b'a' + 10 }
                                            else { c - b'A' + 10 };
                                    val = val * 16 + v as u32;
                                    self.advance();
                                } else {
                                    return Err(self.syntax_error_near("invalid unicode escape", "<string>"));
                                }
                            }
                            if !has_digits || val > 0x10FFFF {
                                return Err(self.syntax_error_near("invalid unicode escape", "<string>"));
                            }
                            if let Some(ch) = char::from_u32(val) {
                                let mut b_buf = [0; 4];
                                buf.extend_from_slice(ch.encode_utf8(&mut b_buf).as_bytes());
                            } else {
                                return Err(self.syntax_error_near("invalid unicode scalar", "<string>"));
                            }
                        }
                        Some(b'x') => {
                            self.advance();
                            let mut val = 0u8;
                            for _ in 0..2 {
                                if let Some(c) = self.peek() {
                                    if c.is_ascii_hexdigit() {
                                        let v = if c >= b'0' && c <= b'9' { c - b'0' }
                                                else if c >= b'a' && c <= b'f' { c - b'a' + 10 }
                                                else { c - b'A' + 10 };
                                        val = val * 16 + v;
                                        self.advance();
                                    } else {
                                        return Err(self.syntax_error_near("invalid hex escape", "<string>"));
                                    }
                                } else {
                                    return Err(self.syntax_error_near("unfinished string", "<eof>"));
                                }
                            }
                            buf.push(val);
                        }
                        Some(c) if c.is_ascii_digit() => {
                            let mut val: u32 = 0;
                            for _ in 0..3 {
                                if let Some(d) = self.peek() {
                                    if d.is_ascii_digit() {
                                        val = val * 10 + u32::from(d - b'0');
                                        self.advance();
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            if val > 255 {
                                return Err(
                                    self.syntax_error_near("escape sequence too large", "<string>")
                                );
                            }
                            buf.push(val as u8);
                        }
                        Some(c) => {
                            return Err(self.syntax_error_near(
                                &format!("invalid escape sequence '\\{}'", char::from(c)),
                                "<string>",
                            ));
                        }
                        None => {
                            return Err(self.syntax_error_near("unfinished string", "<eof>"));
                        }
                    }
                }
                Some(c) => {
                    self.advance();
                    buf.push(c);
                }
            }
        }
        Ok(buf)
    }

    fn count_sep(&mut self) -> i32 {
        debug_assert_eq!(self.source.get(self.pos).copied(), Some(b'['));
        let mut i = 1;
        let mut count = 0;
        while self.peek_ahead(i) == Some(b'=') {
            count += 1;
            i += 1;
        }
        if self.peek_ahead(i) == Some(b'[') {
            count
        } else if count > 0 {
            -1
        } else {
            -2
        }
    }

    fn read_long_string(&mut self, sep: i32, is_comment: bool) -> LuaResult<Vec<u8>> {
        let count = 2 + sep as usize;
        for _ in 0..count {
            self.pos += 1;
            self.column += 1;
        }
        if let Some(c) = self.peek() {
            if c == b'\n' || c == b'\r' {
                self.inc_line();
            }
        }
        let mut buf = Vec::new();
        loop {
            match self.peek() {
                None => {
                    let what = if is_comment { "comment" } else { "string" };
                    return Err(self.syntax_error_near(&format!("unfinished long {}", what), "<eof>"));
                }
                Some(b'\n') | Some(b'\r') => {
                    buf.push(b'\n');
                    self.inc_line();
                }
                Some(b']') => {
                    if self.check_closing_long_bracket(sep) {
                        let close_count = 2 + sep as usize;
                        for _ in 0..close_count {
                            self.pos += 1;
                            self.column += 1;
                        }
                        if is_comment {
                            return Ok(Vec::new());
                        }
                        return Ok(buf);
                    }
                    self.advance();
                    if !is_comment {
                        buf.push(b']');
                    }
                }
                Some(c) => {
                    self.advance();
                    if !is_comment {
                        buf.push(c);
                    }
                }
            }
        }
    }

    fn check_closing_long_bracket(&mut self, sep: i32) -> bool {
        if self.peek() != Some(b']') {
            return false;
        }
        let mut i = 1;
        for _ in 0..sep {
            if self.peek_ahead(i) != Some(b'=') {
                return false;
            }
            i += 1;
        }
        self.peek_ahead(i) == Some(b']')
    }
}