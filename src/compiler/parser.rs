use crate::compiler::error::{LuaError, LuaResult, SyntaxError, SemanticError, chunkid};
use crate::compiler::instructions::{LUAI_MAXUPVALUES, LUAI_MAXVARS};
use super::ast::{BinOp, Block, Expr, FuncBody, FuncName, Stat, TableField, UnOp};
use super::lexer::Lexer;
use super::token::{Span, Token};

struct FuncScope {
    line_defined: u32,
    local_count: u32,
    local_names: Vec<String>,
    upvalue_names: Vec<String>,
}

pub struct Parser<'a> {
    lexer: Lexer<'a>,
    current: Token,
    span: Span,
    lastline: u32,
    loop_depth: u32,
    syntax_depth: u32,
    func_scopes: Vec<FuncScope>,
    errors: Vec<LuaError>,
    source: &'a [u8],
    source_name: String,
    line_offset: u32,
}

const MAX_SYNTAX_LEVELS: u32 = 500;

impl<'a> Parser<'a> {
    pub fn new(source: &'a [u8], name: &str) -> LuaResult<Self> {
        let lexer = Lexer::new(source, name);
        let mut p = Self::from_lexer(lexer)?;
        p.source = source;
        p.source_name = name.to_string();
        Ok(p)
    }

    pub fn from_lexer(mut lexer: Lexer<'a>) -> LuaResult<Self> {
        let (current, span) = lexer.next()?;
        Ok(Self {
            lexer,
            current,
            span,
            lastline: 1,
            loop_depth: 0,
            syntax_depth: 0,
            func_scopes: vec![FuncScope {
                line_defined: 0,
                local_count: 0,
                local_names: Vec::new(),
                upvalue_names: Vec::new(),
            }],
            errors: Vec::new(),
            source: &[],
            source_name: String::new(),
            line_offset: 0,
        })
    }

    fn skip_luau_type(&mut self) -> LuaResult<()> {
        let mut brace_depth = 0;
        let mut paren_depth = 0;
        let mut bracket_depth = 0;
        let mut angle_depth = 0;

        loop {
            match &self.current {
                Token::Char(b'{') => {
                    brace_depth += 1;
                    self.advance()?;
                }
                Token::Char(b'}') => {
                    if brace_depth == 0 { break; }
                    brace_depth -= 1;
                    self.advance()?;
                    if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 {
                        break;
                    }
                }
                Token::Char(b'(') => {
                    paren_depth += 1;
                    self.advance()?;
                }
                Token::Char(b')') => {
                    if paren_depth == 0 { break; }
                    paren_depth -= 1;
                    self.advance()?;
                }
                Token::Char(b'[') => {
                    bracket_depth += 1;
                    self.advance()?;
                }
                Token::Char(b']') => {
                    if bracket_depth == 0 { break; }
                    bracket_depth -= 1;
                    self.advance()?;
                }
                Token::Char(b'<') => {
                    angle_depth += 1;
                    self.advance()?;
                }
                Token::Char(b'>') => {
                    if angle_depth > 0 {
                        angle_depth -= 1;
                        self.advance()?;
                    } else {
                        break;
                    }
                }
                Token::Char(b',') | Token::Char(b':') | Token::Char(b'=') | Token::Char(b'|') | Token::Char(b'&') | Token::Char(b'?') | Token::Arrow => {
                    if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 {
                        break;
                    }
                    self.advance()?;
                }
                Token::Name(n) if n == "typeof" => {
                    self.advance()?;
                    if self.check_char(b'(') {
                        let mut d = 0;
                        loop {
                            match self.current {
                                Token::Char(b'(') => { d += 1; self.advance()?; }
                                Token::Char(b')') => {
                                    d -= 1;
                                    self.advance()?;
                                    if d == 0 { break; }
                                }
                                Token::Eos => break,
                                _ => { self.advance()?; }
                            }
                        }
                    }
                }
                Token::Name(_) | Token::Number(_) | Token::Str(_) | Token::Nil | Token::True | Token::False | Token::Dots => {
                    self.advance()?;
                }
                _ => break,
            }
            if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 {
                match &self.current {
                    Token::Char(b'|') | Token::Char(b'&') | Token::Char(b'?') | Token::Arrow => {}
                    _ => break,
                }
            }
        }
        Ok(())
    }

    fn enter_level(&mut self) -> LuaResult<()> {
        self.syntax_depth += 1;
        if self.syntax_depth > MAX_SYNTAX_LEVELS {
            return Err(self.semantic_error("chunk has too many syntax levels", None));
        }
        Ok(())
    }

    fn leave_level(&mut self) {
        self.syntax_depth -= 1;
    }

    fn register_locals(&mut self, count: u32) -> LuaResult<()> {
        if let Some(scope) = self.func_scopes.last_mut() {
            if scope.local_count + count > LUAI_MAXVARS {
                let msg = format!(
                    "function at line {} has more than {} local variables",
                    scope.line_defined, LUAI_MAXVARS
                );
                return Err(self.semantic_error(&msg, None));
            }
            scope.local_count += count;
        }
        Ok(())
    }

    fn register_locals_named(&mut self, names: &[String]) -> LuaResult<()> {
        self.register_locals(names.len() as u32)?;
        if let Some(scope) = self.func_scopes.last_mut() {
            scope.local_names.extend(names.iter().cloned());
        }
        Ok(())
    }

    fn check_name_upvalue(&mut self, name: &str) -> LuaResult<()> {
        let n_scopes = self.func_scopes.len();
        if n_scopes < 2 {
            return Ok(());
        }
        let current = n_scopes - 1;
        if self.func_scopes[current].local_names.contains(&name.to_string()) {
            return Ok(());
        }
        if self.func_scopes[current].upvalue_names.contains(&name.to_string()) {
            return Ok(());
        }
        let mut found_at = None;
        for i in (0..current).rev() {
            if self.func_scopes[i].local_names.contains(&name.to_string())
                || self.func_scopes[i].upvalue_names.contains(&name.to_string())
            {
                found_at = Some(i);
                break;
            }
        }
        let Some(found_level) = found_at else {
            return Ok(());
        };
        let name_owned = name.to_string();
        for i in (found_level + 1)..=current {
            if !self.func_scopes[i].upvalue_names.contains(&name_owned) {
                let scope = &self.func_scopes[i];
                if scope.upvalue_names.len() >= LUAI_MAXUPVALUES as usize {
                    let msg = format!(
                        "function at line {} has more than {} upvalues",
                        scope.line_defined, LUAI_MAXUPVALUES
                    );
                    return Err(self.semantic_error(&msg, None));
                }
                self.func_scopes[i].upvalue_names.push(name_owned.clone());
            }
        }
        Ok(())
    }

    fn advance(&mut self) -> LuaResult<(Token, Span)> {
        let prev_token = std::mem::replace(&mut self.current, Token::Eos);
        let mut prev_span = self.span;
        self.lastline = prev_span.line;
        let (tok, mut span) = self.lexer.next()?;
        span.line += self.line_offset;
        self.current = tok;
        self.span = span;
        Ok((prev_token, prev_span))
    }

    fn advance_recovery(&mut self) {
        let prev_token = std::mem::replace(&mut self.current, Token::Eos);
        let prev_span = self.span;
        self.lastline = prev_span.line;
        match self.lexer.next() {
            Ok((tok, mut span)) => {
                span.line += self.line_offset;
                self.current = tok;
                self.span = span;
            }
            Err(e) => {
                self.errors.push(e);
                if !self.source.is_empty() {
                    let next_line = prev_span.line + 1;
                    let offset = find_line_start_offset(self.source, next_line);
                    if offset < self.source.len() {
                        self.line_offset = next_line - 1;
                        self.lexer = Lexer::new(&self.source[offset..], &self.source_name);
                        match self.lexer.next() {
                            Ok((tok, mut span)) => {
                                span.line += self.line_offset;
                                self.current = tok;
                                self.span = span;
                            }
                            Err(e2) => {
                                self.errors.push(e2);
                                self.current = Token::Eos;
                            }
                        }
                    } else {
                        self.current = Token::Eos;
                    }
                } else {
                    self.current = Token::Eos;
                }
            }
        }
    }

    fn check(&self, expected: &Token) -> bool {
        self.current == *expected
    }

    fn check_char(&self, ch: u8) -> bool {
        self.current == Token::Char(ch)
    }

    fn test_next(&mut self, expected: &Token) -> LuaResult<bool> {
        if self.check(expected) {
            self.advance()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn test_next_char(&mut self, ch: u8) -> LuaResult<bool> {
        self.test_next(&Token::Char(ch))
    }

    fn expect(&mut self, expected: &Token) -> LuaResult<Span> {
        if self.check(expected) {
            let span = self.span;
            self.advance()?;
            Ok(span)
        } else {
            Err(self.error_expected(&expected.token2str()))
        }
    }

    fn expect_char(&mut self, ch: u8) -> LuaResult<Span> {
        self.expect(&Token::Char(ch))
    }

    fn expect_name(&mut self) -> LuaResult<(String, Span)> {
        let span = self.span;
        match &self.current {
            Token::Name(_) => {
                let (tok, _) = self.advance()?;
                if let Token::Name(name) = tok {
                    Ok((name, span))
                } else {
                    Err(self.error_expected("<name>"))
                }
            }
            _ => Err(self.error_expected("<name>")),
        }
    }

    fn check_match(&mut self, close: &Token, open: &Token, open_line: u32) -> LuaResult<()> {
        if !self.check(close) {
            if open_line == self.lexer.line() + self.line_offset {
                return Err(self.error_expected(&close.token2str()));
            }
            return Err(self.syntax_error_near(&format!(
                "'{}' expected (to close '{}' at line {})",
                close.token2str(),
                open.token2str(),
                open_line
            )));
        }
        self.advance()?;
        Ok(())
    }

    fn syntax_error(&self, msg: &str) -> LuaError {
        LuaError::Syntax(SyntaxError {
            message: msg.to_string(),
            source: self.lexer.source_name().to_string(),
            line: self.span.line,
            raw_message: None,
        })
    }

    fn semantic_error(&self, msg: &str, token: Option<String>) -> LuaError {
        LuaError::Semantic(SemanticError {
            message: msg.to_string(),
            source: self.lexer.source_name().to_string(),
            line: self.span.line,
            token,
        })
    }

    fn syntax_error_near(&self, msg: &str) -> LuaError {
        let near = match self.current {
            Token::Number(_) | Token::Str(_) => {
                let text = self.lexer.last_token_text();
                format!("'{text}'")
            }
            _ => self.current.txt_token(),
        };
        let raw_message = if let Token::Char(b) = self.current {
            if b.is_ascii() {
                None
            } else {
                let source = chunkid(self.lexer.source_name());
                let mut raw = Vec::new();
                raw.extend_from_slice(source.as_bytes());
                raw.push(b':');
                raw.extend_from_slice(self.span.line.to_string().as_bytes());
                raw.extend_from_slice(b": ");
                raw.extend_from_slice(msg.as_bytes());
                raw.extend_from_slice(b" near '");
                raw.push(b);
                raw.push(b'\'');
                Some(raw)
            }
        } else {
            None
        };
        LuaError::Syntax(SyntaxError {
            message: format!("{msg} near {near}"),
            source: self.lexer.source_name().to_string(),
            line: self.span.line,
            raw_message,
        })
    }

    fn error_expected(&self, what: &str) -> LuaError {
        self.syntax_error_near(&format!("'{what}' expected"))
    }

    fn recover(&mut self) {
        loop {
            match &self.current {
                Token::Eos => break,
                Token::Local | Token::Function | Token::If | Token::For | Token::While | Token::Repeat | Token::Do | Token::Return | Token::Break => break,
                Token::Char(b';') => {
                    self.advance_recovery();
                    break;
                }
                tok if tok.is_block_follow() => break,
                _ => {
                    if self.current.is_block_follow() {
                        break;
                    }
                    self.advance_recovery();
                }
            }
        }
    }

    pub fn parse_chunk(&mut self) -> LuaResult<Block> {
        let block = match self.parse_block() {
            Ok(b) => b,
            Err(e) => {
                self.errors.push(e);
                Vec::new()
            }
        };
        if !self.check(&Token::Eos) {
            let err = self.error_expected("<eof>");
            self.errors.push(err);
        }
        if !self.errors.is_empty() {
            return Err(LuaError::Multiple(std::mem::take(&mut self.errors)));
        }
        Ok(block)
    }

    fn parse_block(&mut self) -> LuaResult<Block> {
        self.enter_level()?;
        let saved_locals = self.func_scopes.last().map(|s| (s.local_count, s.local_names.len()));
        let mut stmts = Vec::new();
        loop {
            if self.current.is_block_follow() {
                break;
            }
            match self.parse_stat() {
                Ok(stmt) => {
                    let is_last = matches!(stmt, Stat::Return { .. } | Stat::Break { .. });
                    stmts.push(stmt);
                    if self.check_char(b';') {
                        self.advance_recovery();
                    }
                    if is_last {
                        break;
                    }
                }
                Err(e) => {
                    self.errors.push(e);
                    self.recover();
                }
            }
        }
        if let Some((count, names_len)) = saved_locals {
            if let Some(scope) = self.func_scopes.last_mut() {
                scope.local_count = count;
                scope.local_names.truncate(names_len);
            }
        }
        self.leave_level();
        Ok(stmts)
    }

    fn parse_stat(&mut self) -> LuaResult<Stat> {
        let span = self.span;

        if let Token::Name(ref n) = self.current {
            if n == "export" {
                if let Ok(Token::Name(nxt)) = self.lexer.lookahead() {
                    if nxt == "type" {
                        self.advance()?;
                        self.advance()?;
                        self.expect_name()?;
                        if self.check_char(b'<') { self.skip_luau_type()?; }
                        self.expect_char(b'=')?;
                        self.skip_luau_type()?;
                        return Ok(Stat::Do { body: vec![], span, end_line: span.line });
                    }
                }
            }
            if n == "type" {
                if let Ok(Token::Name(_)) = self.lexer.lookahead() {
                    self.advance()?;
                    self.expect_name()?;
                    if self.check_char(b'<') { self.skip_luau_type()?; }
                    self.expect_char(b'=')?;
                    self.skip_luau_type()?;
                    return Ok(Stat::Do { body: vec![], span, end_line: span.line });
                }
            }
            if n == "Continue" {
                self.advance()?;
                if self.loop_depth == 0 {
                    return Err(self.semantic_error("Continue outside loop", Some("Continue".to_string())));
                }
                return Ok(Stat::Do { body: vec![], span, end_line: span.line });
            }
        }

        match &self.current {
            Token::If => self.parse_if(span),
            Token::While => self.parse_while(span),
            Token::Do => self.parse_do(span),
            Token::For => self.parse_for(span),
            Token::Repeat => self.parse_repeat(span),
            Token::Function => self.parse_func_decl(span),
            Token::Local => self.parse_local(span),
            Token::Return => self.parse_return(span),
            Token::Break => self.parse_break(span),
            Token::Continue => self.parse_Continue(span),
            _ => self.parse_expr_stat(span),
        }
    }

    fn parse_if(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        let open_line = span.line;
        let mut conditions = Vec::new();
        let mut bodies = Vec::new();
        conditions.push(self.parse_expr()?);
        self.expect(&Token::Then)?;
        bodies.push(self.parse_block()?);
        while self.check(&Token::ElseIf) {
            self.advance()?;
            conditions.push(self.parse_expr()?);
            self.expect(&Token::Then)?;
            bodies.push(self.parse_block()?);
        }
        let else_body = if self.test_next(&Token::Else)? {
            Some(self.parse_block()?)
        } else {
            None
        };
        let end_line = self.span.line;
        self.check_match(&Token::End, &Token::If, open_line)?;
        Ok(Stat::If {
            conditions,
            bodies,
            else_body,
            span,
            end_line,
        })
    }

    fn parse_while(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        let open_line = span.line;
        let condition = self.parse_expr()?;
        self.expect(&Token::Do)?;
        self.loop_depth += 1;
        let body = self.parse_block()?;
        self.loop_depth -= 1;
        let end_line = self.span.line;
        self.check_match(&Token::End, &Token::While, open_line)?;
        Ok(Stat::While {
            condition,
            body,
            span,
            end_line,
        })
    }

    fn parse_do(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        let open_line = span.line;
        let body = self.parse_block()?;
        let end_line = self.span.line;
        self.check_match(&Token::End, &Token::Do, open_line)?;
        Ok(Stat::Do {
            body,
            span,
            end_line,
        })
    }

    fn parse_for(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        let open_line = span.line;
        let (name, _) = self.expect_name()?;
        match &self.current {
            Token::Char(b'=') => self.parse_numeric_for(name, open_line, span),
            Token::Char(b',') | Token::In | Token::Char(b':') => self.parse_generic_for(name, open_line, span),
            _ => Err(self.syntax_error_near("'=' or 'in' expected")),
        }
    }

    fn parse_numeric_for(&mut self, name: String, open_line: u32, span: Span) -> LuaResult<Stat> {
        self.register_locals(3)?;
        self.register_locals_named(std::slice::from_ref(&name))?;
        self.expect_char(b'=')?;
        let start = self.parse_expr()?;
        self.expect_char(b',')?;
        let stop = self.parse_expr()?;
        let step = if self.test_next_char(b',')? {
            Some(self.parse_expr()?)
        } else {
            None
        };
        self.expect(&Token::Do)?;
        self.loop_depth += 1;
        let body = self.parse_block()?;
        self.loop_depth -= 1;
        let end_line = self.span.line;
        self.check_match(&Token::End, &Token::For, open_line)?;
        Ok(Stat::NumericFor {
            name,
            start,
            stop,
            step,
            body,
            span,
            end_line,
        })
    }

    fn parse_generic_for(&mut self, first_name: String, open_line: u32, span: Span) -> LuaResult<Stat> {
        if self.check_char(b':') {
            self.advance()?;
            self.skip_luau_type()?;
        }
        let mut names = vec![first_name];
        while self.test_next_char(b',')? {
            let (name, _) = self.expect_name()?;
            if self.check_char(b':') {
                self.advance()?;
                self.skip_luau_type()?;
            }
            names.push(name);
        }
        self.register_locals(3)?;
        self.register_locals_named(&names)?;
        self.expect(&Token::In)?;
        let iter_line = self.span.line;
        let iterators = self.parse_expr_list()?;
        self.expect(&Token::Do)?;
        self.loop_depth += 1;
        let body = self.parse_block()?;
        self.loop_depth -= 1;
        let end_line = self.span.line;
        self.check_match(&Token::End, &Token::For, open_line)?;
        Ok(Stat::GenericFor {
            names,
            iterators,
            body,
            iter_line,
            end_line,
            span,
        })
    }

    fn parse_repeat(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        let open_line = span.line;
        self.loop_depth += 1;
        let body = self.parse_block()?;
        self.check_match(&Token::Until, &Token::Repeat, open_line)?;
        let condition = self.parse_expr()?;
        self.loop_depth -= 1;
        Ok(Stat::Repeat {
            body,
            condition,
            span,
        })
    }

    fn parse_func_decl(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        let name = self.parse_func_name()?;
        let body = self.parse_func_body(span)?;
        Ok(Stat::FuncDecl { name, body, span })
    }

    fn parse_func_name(&mut self) -> LuaResult<FuncName> {
        let span = self.span;
        let (first, _) = self.expect_name()?;
        let mut parts = vec![first];
        while self.test_next_char(b'.')? {
            let (name, _) = self.expect_name()?;
            parts.push(name);
        }
        let method = if self.test_next_char(b':')? {
            let (name, _) = self.expect_name()?;
            Some(name)
        } else {
            None
        };
        if self.check_char(b'<') {
            self.skip_luau_type()?;
        }
        Ok(FuncName {
            parts,
            method,
            span,
        })
    }

    fn parse_local(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        if self.test_next(&Token::Function)? {
            let (name, _) = self.expect_name()?;
            if self.check_char(b'<') { self.skip_luau_type()?; }
            self.register_locals_named(std::slice::from_ref(&name))?;
            let body = self.parse_func_body(span)?;
            return Ok(Stat::LocalFunc { name, body, span });
        }
        let (first_name, _) = self.expect_name()?;
        if self.check_char(b':') {
            self.advance()?;
            self.skip_luau_type()?;
        }
        let mut names = vec![first_name];
        while self.test_next_char(b',')? {
            let (name, _) = self.expect_name()?;
            if self.check_char(b':') {
                self.advance()?;
                self.skip_luau_type()?;
            }
            names.push(name);
        }
        self.register_locals_named(&names)?;
        let values = if self.test_next_char(b'=')? {
            self.parse_expr_list()?
        } else {
            Vec::new()
        };
        Ok(Stat::LocalDecl {
            names,
            values,
            span,
        })
    }

    fn parse_return(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        let values = if self.current.is_block_follow() || self.check_char(b';') {
            Vec::new()
        } else {
            self.parse_expr_list()?
        };
        Ok(Stat::Return { values, span })
    }

    fn parse_break(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        if self.loop_depth == 0 {
            return Err(self.semantic_error("break outside loop", Some("break".to_string())));
        }
        Ok(Stat::Break { span })
    }

    fn parse_Continue(&mut self, span: Span) -> LuaResult<Stat> {
        self.advance()?;
        if self.loop_depth == 0 {
            return Err(self.semantic_error("Continue outside loop", Some("Continue".to_string())));
        }
        Ok(Stat::Continue { span })
    }

    fn parse_expr_stat(&mut self, span: Span) -> LuaResult<Stat> {
        let expr = self.parse_suffixed_expr()?;
        match &self.current {
            Token::Char(b'=') | Token::Char(b',') => {
                let mut targets = vec![expr];
                while self.test_next_char(b',')? {
                    targets.push(self.parse_suffixed_expr()?);
                }
                self.expect_char(b'=')?;
                let values = self.parse_expr_list()?;
                Ok(Stat::Assign {
                    targets,
                    values,
                    span,
                })
            }
            Token::PlusEq | Token::MinusEq | Token::MulEq | Token::DivEq | Token::ModEq | Token::PowEq | Token::ConcatEq | Token::FloorDivEq => {
                let op_tok = self.current.clone();
                self.advance()?;
                let val_expr = self.parse_expr()?;
                let bin_op = match op_tok {
                    Token::PlusEq => BinOp::Add,
                    Token::MinusEq => BinOp::Sub,
                    Token::MulEq => BinOp::Mul,
                    Token::DivEq => BinOp::Div,
                    Token::ModEq => BinOp::Mod,
                    Token::PowEq => BinOp::Pow,
                    Token::ConcatEq => BinOp::Concat,
                    Token::FloorDivEq => BinOp::Div,
                    _ => unreachable!(),
                };
                let cloned_target = expr.clone();
                let mut right_expr = Expr::BinOp {
                    op: bin_op,
                    left: Box::new(cloned_target),
                    right: Box::new(val_expr),
                    span,
                };
                if op_tok == Token::FloorDivEq {
                    right_expr = Expr::Call {
                        func: Box::new(Expr::Field {
                            table: Box::new(Expr::Name("math".to_string(), span)),
                            field: "floor".to_string(),
                            span,
                        }),
                        args: vec![right_expr],
                        span,
                    };
                }
                Ok(Stat::Assign {
                    targets: vec![expr],
                    values: vec![right_expr],
                    span,
                })
            }
            _ => {
                match &expr {
                    super::ast::Expr::Call { .. } | super::ast::Expr::MethodCall { .. } => {
                        Ok(Stat::ExprStat { expr, span })
                    }
                    _ => Err(self.error_expected("=")),
                }
            }
        }
    }

    fn parse_expr_list(&mut self) -> LuaResult<Vec<Expr>> {
        let mut exprs = vec![self.parse_expr()?];
        while self.test_next_char(b',')? {
            exprs.push(self.parse_expr()?);
        }
        Ok(exprs)
    }

    pub(crate) fn parse_expr(&mut self) -> LuaResult<Expr> {
        self.parse_sub_expr(0)
    }

    fn get_binary_op_info(&self) -> Option<(BinOp, bool)> {
        match &self.current {
            Token::Char(b'+') => Some((BinOp::Add, false)),
            Token::Char(b'-') => Some((BinOp::Sub, false)),
            Token::Char(b'*') => Some((BinOp::Mul, false)),
            Token::Char(b'/') => Some((BinOp::Div, false)),
            Token::FloorDiv => Some((BinOp::Div, true)),
            Token::Char(b'%') => Some((BinOp::Mod, false)),
            Token::Char(b'^') => Some((BinOp::Pow, false)),
            Token::Concat => Some((BinOp::Concat, false)),
            Token::Ne => Some((BinOp::Ne, false)),
            Token::Eq => Some((BinOp::Eq, false)),
            Token::Char(b'<') => Some((BinOp::Lt, false)),
            Token::Le => Some((BinOp::Le, false)),
            Token::Char(b'>') => Some((BinOp::Gt, false)),
            Token::Ge => Some((BinOp::Ge, false)),
            Token::And => Some((BinOp::And, false)),
            Token::Or => Some((BinOp::Or, false)),
            _ => None,
        }
    }

    fn parse_sub_expr(&mut self, limit: u8) -> LuaResult<Expr> {
        self.enter_level()?;
        let span = self.span;
        let mut expr = if let Some(op) = self.get_unary_op() {
            self.advance()?;
            let operand = self.parse_sub_expr(UNARY_PRIORITY)?;
            Expr::UnOp {
                op,
                operand: Box::new(operand),
                span,
            }
        } else {
            self.parse_simple_expr()?
        };

        while let Some((op, is_floor)) = self.get_binary_op_info() {
            let (left_prio, right_prio) = binary_priority(op);
            if left_prio <= limit {
                break;
            }
            self.advance()?;
            let right = self.parse_sub_expr(right_prio)?;
            let new_span = span;
            expr = Expr::BinOp {
                op,
                left: Box::new(expr),
                right: Box::new(right),
                span: new_span,
            };
            if is_floor {
                expr = Expr::Call {
                    func: Box::new(Expr::Field {
                        table: Box::new(Expr::Name("math".to_string(), new_span)),
                        field: "floor".to_string(),
                        span: new_span,
                    }),
                    args: vec![expr],
                    span: new_span,
                };
            }
        }
        self.leave_level();
        Ok(expr)
    }

    fn parse_simple_expr(&mut self) -> LuaResult<Expr> {
        let span = self.span;
        match &self.current {
            Token::If => {
                let if_span = span;
                self.advance()?;
                let cond = self.parse_expr()?;
                self.expect(&Token::Then)?;
                let true_val = self.parse_expr()?;
                let mut elseif_blocks = Vec::new();
                while self.check(&Token::ElseIf) {
                    self.advance()?;
                    let elseif_cond = self.parse_expr()?;
                    self.expect(&Token::Then)?;
                    let elseif_val = self.parse_expr()?;
                    elseif_blocks.push((elseif_cond, elseif_val));
                }
                self.expect(&Token::Else)?;
                let false_val = self.parse_expr()?;
                let mut bodies = vec![vec![Stat::Return { values: vec![true_val], span: if_span }]];
                let mut conditions = vec![cond];
                for (c, v) in elseif_blocks {
                    conditions.push(c);
                    bodies.push(vec![Stat::Return { values: vec![v], span: if_span }]);
                }
                let else_body = Some(vec![Stat::Return { values: vec![false_val], span: if_span }]);
                let if_stat = Stat::If {
                    conditions,
                    bodies,
                    else_body,
                    span: if_span,
                    end_line: self.span.line,
                };
                let func_body = FuncBody {
                    params: vec![],
                    has_varargs: false,
                    body: vec![if_stat],
                    span: if_span,
                    end_line: self.span.line,
                };
                let func_expr = Expr::FuncDef { body: func_body, span: if_span };
                let paren_func = Expr::Paren(Box::new(func_expr), if_span);
                Ok(Expr::Call {
                    func: Box::new(paren_func),
                    args: vec![],
                    span: if_span,
                })
            }
            Token::Number(_) => {
                let (tok, _) = self.advance()?;
                if let Token::Number(n) = tok {
                    Ok(Expr::Number(n, span))
                } else {
                    Err(self.syntax_error("unexpected token"))
                }
            }
            Token::Str(_) => {
                let (tok, _) = self.advance()?;
                if let Token::Str(s) = tok {
                    Ok(Expr::Str(s, span))
                } else {
                    Err(self.syntax_error("unexpected token"))
                }
            }
            Token::Nil => {
                self.advance()?;
                Ok(Expr::Nil(span))
            }
            Token::True => {
                self.advance()?;
                Ok(Expr::True(span))
            }
            Token::False => {
                self.advance()?;
                Ok(Expr::False(span))
            }
            Token::Dots => {
                self.advance()?;
                Ok(Expr::VarArg(span))
            }
            Token::Function => {
                self.advance()?;
                let body = self.parse_func_body(span)?;
                Ok(Expr::FuncDef { body, span })
            }
            Token::Char(b'{') => self.parse_table_ctor(),
            _ => self.parse_suffixed_expr(),
        }
    }

    fn parse_suffixed_expr(&mut self) -> LuaResult<Expr> {
        let mut expr = self.parse_primary_expr()?;
        loop {
            match &self.current {
                Token::ColonColon => {
                    self.advance()?;
                    self.skip_luau_type()?;
                }
                Token::Char(b'.') => {
                    self.advance()?;
                    let (field, _) = self.expect_name()?;
                    let span = expr.span();
                    expr = Expr::Field {
                        table: Box::new(expr),
                        field,
                        span,
                    };
                }
                Token::Char(b'[') => {
                    let span = expr.span();
                    self.advance()?;
                    let key = self.parse_expr()?;
                    self.expect_char(b']')?;
                    expr = Expr::Index {
                        table: Box::new(expr),
                        key: Box::new(key),
                        span,
                    };
                }
                Token::Char(b':') => {
                    let span = expr.span();
                    self.advance()?;
                    let (method, _) = self.expect_name()?;
                    if self.check_char(b'<') { self.skip_luau_type()?; }
                    let args = self.parse_func_args()?;
                    expr = Expr::MethodCall {
                        table: Box::new(expr),
                        method,
                        args,
                        span,
                    };
                }
                Token::Char(b'(') | Token::Str(_) | Token::Char(b'{') => {
                    let span = expr.span();
                    let args = self.parse_func_args()?;
                    expr = Expr::Call {
                        func: Box::new(expr),
                        args,
                        span,
                    };
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    fn parse_primary_expr(&mut self) -> LuaResult<Expr> {
        let span = self.span;
        match &self.current {
            Token::Name(_) => {
                let (tok, _) = self.advance()?;
                if let Token::Name(name) = tok {
                    self.check_name_upvalue(&name)?;
                    Ok(Expr::Name(name, span))
                } else {
                    Err(self.syntax_error("unexpected token"))
                }
            }
            Token::Char(b'(') => {
                let paren_span = self.span;
                self.advance()?;
                let expr = self.parse_expr()?;
                self.expect_char(b')')?;
                Ok(Expr::Paren(Box::new(expr), paren_span))
            }
            _ => Err(self.syntax_error_near("unexpected symbol")),
        }
    }

    fn parse_func_args(&mut self) -> LuaResult<Vec<Expr>> {
        match &self.current {
            Token::Char(b'(') => {
                if self.span.line != self.lastline {
                    return Err(
                        self.syntax_error_near("ambiguous syntax (function call x new statement)")
                    );
                }
                let open_line = self.span.line;
                self.advance()?;
                let args = if self.check_char(b')') {
                    Vec::new()
                } else {
                    self.parse_expr_list()?
                };
                self.check_match(&Token::Char(b')'), &Token::Char(b'('), open_line)?;
                Ok(args)
            }
            Token::Char(b'{') => {
                let table = self.parse_table_ctor()?;
                Ok(vec![table])
            }
            Token::Str(_) => {
                let span = self.span;
                let (tok, _) = self.advance()?;
                if let Token::Str(s) = tok {
                    Ok(vec![Expr::Str(s, span)])
                } else {
                    Err(self.syntax_error("unexpected token"))
                }
            }
            _ => Err(self.syntax_error_near("function arguments expected")),
        }
    }

    fn parse_func_body(&mut self, def_span: Span) -> LuaResult<FuncBody> {
        let open_line = self.span.line;
        if self.check_char(b'<') {
            self.skip_luau_type()?;
        }
        self.expect_char(b'(')?;
        let mut params = Vec::new();
        let mut has_varargs = false;
        if !self.check_char(b')') {
            loop {
                match &self.current {
                    Token::Name(_) => {
                        let (name, _) = self.expect_name()?;
                        if self.check_char(b':') {
                            self.advance()?;
                            self.skip_luau_type()?;
                        }
                        params.push(name);
                    }
                    Token::Dots => {
                        self.advance()?;
                        if self.check_char(b':') {
                            self.advance()?;
                            self.skip_luau_type()?;
                        }
                        has_varargs = true;
                        break;
                    }
                    _ => {
                        return Err(self.syntax_error_near("<name> or '...' expected"));
                    }
                }
                if !self.test_next_char(b',')? {
                    break;
                }
            }
        }
        self.expect_char(b')')?;
        if self.check_char(b':') || self.check(&Token::Arrow) {
            self.advance()?;
            self.skip_luau_type()?;
        }
        self.func_scopes.push(FuncScope {
            line_defined: def_span.line,
            local_count: 0,
            local_names: Vec::new(),
            upvalue_names: Vec::new(),
        });
        self.register_locals_named(&params)?;
        let saved_loop_depth = self.loop_depth;
        self.loop_depth = 0;
        let body = self.parse_block()?;
        self.loop_depth = saved_loop_depth;
        self.func_scopes.pop();
        let end_line = self.span.line;
        self.check_match(&Token::End, &Token::Function, open_line)?;
        Ok(FuncBody {
            params,
            has_varargs,
            body,
            span: def_span,
            end_line,
        })
    }

    fn parse_table_ctor(&mut self) -> LuaResult<Expr> {
        let span = self.span;
        let open_line = span.line;
        self.expect_char(b'{')?;
        let mut fields = Vec::new();
        while !self.check_char(b'}') {
            let field = self.parse_field()?;
            fields.push(field);
            if !self.test_next_char(b',')? && !self.test_next_char(b';')? {
                break;
            }
        }
        self.check_match(&Token::Char(b'}'), &Token::Char(b'{'), open_line)?;
        Ok(Expr::TableCtor { fields, span })
    }

    fn parse_field(&mut self) -> LuaResult<TableField> {
        let span = self.span;
        match &self.current {
            Token::Char(b'[') => {
                self.advance()?;
                let key = self.parse_expr()?;
                self.expect_char(b']')?;
                self.expect_char(b'=')?;
                let value = self.parse_expr()?;
                Ok(TableField::IndexField { key, value, span })
            }
            Token::Name(_) if self.lexer.lookahead()? == &Token::Char(b'=') => {
                let (name, _) = self.expect_name()?;
                self.expect_char(b'=')?;
                let value = self.parse_expr()?;
                Ok(TableField::NameField { name, value, span })
            }
            _ => {
                let value = self.parse_expr()?;
                Ok(TableField::ValueField { value, span })
            }
        }
    }

    fn get_unary_op(&self) -> Option<UnOp> {
        match &self.current {
            Token::Not => Some(UnOp::Not),
            Token::Char(b'-') => Some(UnOp::Neg),
            Token::Char(b'#') => Some(UnOp::Len),
            _ => None,
        }
    }
}

const UNARY_PRIORITY: u8 = 8;

fn binary_priority(op: BinOp) -> (u8, u8) {
    match op {
        BinOp::Or => (1, 1),
        BinOp::And => (2, 2),
        BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge | BinOp::Ne | BinOp::Eq => (3, 3),
        BinOp::Concat => (5, 4),
        BinOp::Add | BinOp::Sub => (6, 6),
        BinOp::Mul | BinOp::Div | BinOp::Mod => (7, 7),
        BinOp::Pow => (10, 9),
    }
}

fn find_line_start_offset(source: &[u8], target_line: u32) -> usize {
    if target_line <= 1 {
        return 0;
    }
    let mut current_line = 1;
    for (i, &b) in source.iter().enumerate() {
        if b == b'\n' {
            current_line += 1;
            if current_line == target_line {
                return i + 1;
            }
        }
    }
    source.len()
}

pub fn parse(source: &[u8], name: &str) -> LuaResult<Block> {
    let mut parser = Parser::new(source, name)?;
    parser.parse_chunk()
}

pub fn parse_with_lexer(lexer: Lexer<'_>) -> LuaResult<Block> {
    let mut parser = Parser::from_lexer(lexer)?;
    parser.parse_chunk()
}