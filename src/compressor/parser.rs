use crate::compiler::error::{LuaError, LuaResult, SyntaxError, SemanticError};
use super::token::{Token, TokenType};
use super::ast::{Block, LastStmt, Stmt, Expr, PrefixExpr, Var, Call, LocalVar, TableField, VarId};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    errors: Vec<LuaError>,
    loop_depth: u32,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            errors: Vec::new(),
            loop_depth: 0,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn peek_at(&self, offset: usize) -> Option<&Token> {
        self.tokens.get(self.pos + offset)
    }

    fn advance(&mut self) -> Option<&Token> {
        if self.pos < self.tokens.len() {
            let t = &self.tokens[self.pos];
            self.pos += 1;
            Some(t)
        } else {
            None
        }
    }

    fn current_line(&self) -> u32 {
        1
    }

    fn add_error(&mut self, err: LuaError) {
        match err {
            LuaError::Multiple(errs) => {
                self.errors.extend(errs);
            }
            other => {
                self.errors.push(other);
            }
        }
    }

    fn syntax_error(&self, msg: &str, line: u32) -> LuaError {
        let start = self.pos.saturating_sub(6);
        let end = (self.pos + 6).min(self.tokens.len());
        let mut context = String::new();
        for i in start..end {
            if i == self.pos {
                context.push_str(" >> ");
            }
            context.push_str(&self.tokens[i].text);
            if i == self.pos {
                context.push_str(" << ");
            }
            context.push(' ');
        }
        let full_msg = format!("{} [解析器上下文: {}]", msg, context.trim());
        LuaError::Syntax(SyntaxError {
            message: full_msg,
            source: "compressor_parser".to_string(),
            line,
            raw_message: None,
        })
    }

    fn semantic_error(&self, msg: &str, line: u32, token: Option<String>) -> LuaError {
        let start = self.pos.saturating_sub(6);
        let end = (self.pos + 6).min(self.tokens.len());
        let mut context = String::new();
        for i in start..end {
            if i == self.pos {
                context.push_str(" >> ");
            }
            context.push_str(&self.tokens[i].text);
            if i == self.pos {
                context.push_str(" << ");
            }
            context.push(' ');
        }
        let full_msg = format!("{} [解析器上下文: {}]", msg, context.trim());
        LuaError::Semantic(SemanticError {
            message: full_msg,
            source: "compressor_parser".to_string(),
            line,
            token,
        })
    }

    fn consume(&mut self, text: &str) -> LuaResult<()> {
        let line = self.current_line();
        match self.peek() {
            Some(t) if t.text == text => {
                self.advance();
                Ok(())
            }
            Some(t) => Err(self.syntax_error(&format!("Expected '{}', got '{}'", text, t.text), line)),
            None => Err(self.syntax_error(&format!("Expected '{}', got EOF", text), line)),
        }
    }

    fn consume_type(&mut self, t_type: TokenType) -> LuaResult<Token> {
        let line = self.current_line();
        match self.peek() {
            Some(t) if t.token_type == t_type => {
                Ok(self.advance().unwrap().clone())
            }
            Some(t) => Err(self.syntax_error(&format!("Expected token of type {:?}, got '{}'", t_type, t.text), line)),
            None => Err(self.syntax_error(&format!("Expected token of type {:?}, got EOF", t_type), line)),
        }
    }

    fn recover(&mut self) {
        loop {
            match self.peek().map(|t| t.text.as_str()) {
                None => break,
                Some("local") | Some("function") | Some("if") | Some("for") | Some("while") | Some("repeat") | Some("do") | Some("return") | Some("break") => break,
                Some(";") => {
                    self.advance();
                    break;
                }
                Some("end") | Some("elseif") | Some("else") | Some("until") => break,
                _ => {
                    self.advance();
                }
            }
        }
    }

    fn get_op_precedence(op: &str) -> Option<(u8, u8)> {
        match op {
            "or" => Some((1, 2)),
            "and" => Some((3, 4)),
            "<" | ">" | "<=" | ">=" | "~=" | "==" => Some((5, 6)),
            ".." => Some((8, 7)),
            "+" | "-" => Some((9, 10)),
            "*" | "/" | "%" => Some((11, 12)),
            "^" => Some((14, 13)),
            _ => None,
        }
    }

    pub fn parse_expr_bp(&mut self, min_bp: u8) -> LuaResult<Expr> {
        let mut lhs = self.parse_prefix_or_primary_expr()?;
        loop {
            let op_opt = match self.peek() {
                Some(t) if t.token_type == TokenType::Symbol || t.token_type == TokenType::Keyword => Some(t.text.clone()),
                _ => None,
            };
            if let Some(op) = op_opt {
                if let Some((l_bp, r_bp)) = Self::get_op_precedence(&op) {
                    if l_bp < min_bp {
                        break;
                    }
                    self.advance();
                    let rhs = self.parse_expr_bp(r_bp)?;
                    lhs = Expr::BinOp(op, Box::new(lhs), Box::new(rhs));
                    continue;
                }
            }
            break;
        }
        Ok(lhs)
    }

    fn parse_prefix_or_primary_expr(&mut self) -> LuaResult<Expr> {
        let line = self.current_line();
        let t = match self.peek() {
            Some(t) => t,
            None => return Err(self.syntax_error("Unexpected EOF", line)),
        };

        if t.token_type == TokenType::Keyword {
            match t.text.as_str() {
                "nil" => {
                    self.advance();
                    return Ok(Expr::Nil);
                }
                "true" => {
                    self.advance();
                    return Ok(Expr::Boolean(true));
                }
                "false" => {
                    self.advance();
                    return Ok(Expr::Boolean(false));
                }
                "function" => {
                    self.advance();
                    return self.parse_function_def();
                }
                "not" => {
                    self.advance();
                    let expr = self.parse_expr_bp(13)?;
                    return Ok(Expr::UnOp("not".to_string(), Box::new(expr)));
                }
                _ => {}
            }
        } else if t.token_type == TokenType::Number {
            let num = self.advance().unwrap().text.clone();
            return Ok(Expr::Number(num));
        } else if t.token_type == TokenType::StringLiteral {
            let s = self.advance().unwrap().text.clone();
            return Ok(Expr::String(s));
        } else if t.token_type == TokenType::Symbol {
            match t.text.as_str() {
                "..." => {
                    self.advance();
                    return Ok(Expr::Vararg);
                }
                "{" => {
                    return self.parse_table_ctor();
                }
                "-" => {
                    self.advance();
                    let expr = self.parse_expr_bp(13)?;
                    return Ok(Expr::UnOp("-".to_string(), Box::new(expr)));
                }
                "#" => {
                    self.advance();
                    let expr = self.parse_expr_bp(13)?;
                    return Ok(Expr::UnOp("#".to_string(), Box::new(expr)));
                }
                _ => {}
            }
        }

        let prefix = self.parse_prefix_expr()?;
        Ok(Expr::Prefix(Box::new(prefix)))
    }

    fn parse_function_def(&mut self) -> LuaResult<Expr> {
        self.consume("(")?;
        let mut params = Vec::new();
        let mut is_vararg = false;
        if self.peek().map(|t| t.text.as_str()) != Some(")") {
            loop {
                if self.peek().map(|t| t.text.as_str()) == Some("...") {
                    self.advance();
                    is_vararg = true;
                    break;
                }
                let param = self.consume_type(TokenType::Identifier)?.text;
                params.push(LocalVar { name: param, id: VarId(0) });
                if self.peek().map(|t| t.text.as_str()) == Some(",") {
                    self.advance();
                } else {
                    break;
                }
            }
        }
        self.consume(")")?;
        let block = self.parse_block()?;
        self.consume("end")?;
        Ok(Expr::FuncDef(params, is_vararg, Box::new(block)))
    }

    fn parse_table_ctor(&mut self) -> LuaResult<Expr> {
        self.consume("{")?;
        let mut fields = Vec::new();
        while self.peek().map(|t| t.text.as_str()) != Some("}") {
            if self.peek().map(|t| t.text.as_str()) == Some("[") {
                self.advance();
                let key = self.parse_expr_bp(0)?;
                self.consume("]")?;
                self.consume("=")?;
                let value = self.parse_expr_bp(0)?;
                fields.push(TableField::Rec(key, value));
            } else if self.peek().map(|t| t.token_type) == Some(TokenType::Identifier)
                && self.peek_at(1).map(|t| t.text.as_str()) == Some("=")
            {
                let key_name = self.advance().unwrap().text.clone();
                self.consume("=")?;
                let value = self.parse_expr_bp(0)?;
                fields.push(TableField::Rec(Expr::String(key_name), value));
            } else {
                let value = self.parse_expr_bp(0)?;
                fields.push(TableField::List(value));
            }

            if let Some(t) = self.peek() {
                if t.text == "," || t.text == ";" {
                    self.advance();
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        self.consume("}")?;
        Ok(Expr::Table(fields))
    }

    fn parse_prefix_expr(&mut self) -> LuaResult<PrefixExpr> {
        let mut prefix = if self.peek().map(|t| t.text.as_str()) == Some("(") {
            self.advance();
            let expr = self.parse_expr_bp(0)?;
            self.consume(")")?;
            PrefixExpr::Paren(Box::new(expr))
        } else {
            let name = self.consume_type(TokenType::Identifier)?.text;
            PrefixExpr::Var(Var::Name(name, VarId(0)))
        };

        loop {
            match self.peek().map(|t| t.text.as_str()) {
                Some("[") => {
                    self.advance();
                    let expr = self.parse_expr_bp(0)?;
                    self.consume("]")?;
                    prefix = PrefixExpr::Var(Var::Index(Box::new(prefix), Box::new(expr)));
                }
                Some(".") => {
                    self.advance();
                    let member = self.consume_type(TokenType::Identifier)?.text;
                    prefix = PrefixExpr::Var(Var::Member(Box::new(prefix), member));
                }
                Some(":") => {
                    self.advance();
                    let method = self.consume_type(TokenType::Identifier)?.text;
                    let args = self.parse_args()?;
                    prefix = PrefixExpr::Call(Call::Method(Box::new(prefix), method, args));
                }
                Some("(") | Some("{") => {
                    let args = self.parse_args()?;
                    prefix = PrefixExpr::Call(Call::Normal(Box::new(prefix), args));
                }
                _ => break,
            }
        }
        Ok(prefix)
    }

    fn parse_args(&mut self) -> LuaResult<Vec<Expr>> {
        let line = self.current_line();
        let t = self.peek().ok_or_else(|| self.syntax_error("Expected call arguments, got EOF", line))?;
        if t.text == "(" {
            self.advance();
            let mut args = Vec::new();
            if self.peek().map(|tok| tok.text.as_str()) != Some(")") {
                loop {
                    args.push(self.parse_expr_bp(0)?);
                    if self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                        self.advance();
                    } else {
                        break;
                    }
                }
            }
            self.consume(")")?;
            Ok(args)
        } else if t.text == "{" {
            let expr = self.parse_table_ctor()?;
            Ok(vec![expr])
        } else if t.token_type == TokenType::StringLiteral {
            let s = self.advance().unwrap().text.clone();
            Ok(vec![Expr::String(s)])
        } else {
            Err(self.syntax_error(&format!("Unexpected token in function call args: '{}'", t.text), line))
        }
    }

    pub fn parse_stmt(&mut self) -> LuaResult<Stmt> {
        let line = self.current_line();
        let t = self.peek().ok_or_else(|| self.syntax_error("Expected statement, got EOF", line))?;
        match t.text.as_str() {
            "local" => {
                self.advance();
                if self.peek().map(|tok| tok.text.as_str()) == Some("function") {
                    self.advance();
                    let name = self.consume_type(TokenType::Identifier)?.text;
                    let var = LocalVar { name, id: VarId(0) };
                    self.consume("(")?;
                    let mut params = Vec::new();
                    let mut is_vararg = false;
                    if self.peek().map(|tok| tok.text.as_str()) != Some(")") {
                        loop {
                            if self.peek().map(|tok| tok.text.as_str()) == Some("...") {
                                self.advance();
                                is_vararg = true;
                                break;
                            }
                            let param = self.consume_type(TokenType::Identifier)?.text;
                            params.push(LocalVar { name: param, id: VarId(0) });
                            if self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    self.consume(")")?;
                    let block = self.parse_block()?;
                    self.consume("end")?;
                    Ok(Stmt::LocalFunction { var, params, is_vararg, block: Box::new(block) })
                } else {
                    let mut vars = Vec::new();
                    loop {
                        let name = self.consume_type(TokenType::Identifier)?.text;
                        vars.push(LocalVar { name, id: VarId(0) });
                        if self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let mut exprs = Vec::new();
                    if self.peek().map(|tok| tok.text.as_str()) == Some("=") {
                        self.advance();
                        loop {
                            exprs.push(self.parse_expr_bp(0)?);
                            if self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    Ok(Stmt::LocalAssign(vars, exprs))
                }
            }
            "function" => {
                self.advance();
                let mut path = vec![self.consume_type(TokenType::Identifier)?.text];
                while self.peek().map(|tok| tok.text.as_str()) == Some(".") {
                    self.advance();
                    path.push(self.consume_type(TokenType::Identifier)?.text);
                }
                let mut method = None;
                if self.peek().map(|tok| tok.text.as_str()) == Some(":") {
                    self.advance();
                    method = Some(self.consume_type(TokenType::Identifier)?.text);
                }
                self.consume("(")?;
                let mut params = Vec::new();
                let mut is_vararg = false;
                if self.peek().map(|tok| tok.text.as_str()) != Some(")") {
                    loop {
                        if self.peek().map(|tok| tok.text.as_str()) == Some("...") {
                            self.advance();
                            is_vararg = true;
                            break;
                        }
                        let param = self.consume_type(TokenType::Identifier)?.text;
                        params.push(LocalVar { name: param, id: VarId(0) });
                        if self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                }
                self.consume(")")?;
                let block = self.parse_block()?;
                self.consume("end")?;
                Ok(Stmt::Function { path, method, params, is_vararg, block: Box::new(block) })
            }
            "do" => {
                self.advance();
                let block = self.parse_block()?;
                self.consume("end")?;
                Ok(Stmt::Do(Box::new(block)))
            }
            "while" => {
                self.advance();
                let cond = self.parse_expr_bp(0)?;
                self.consume("do")?;
                self.loop_depth += 1;
                let block = self.parse_block()?;
                self.loop_depth -= 1;
                self.consume("end")?;
                Ok(Stmt::While(Box::new(cond), Box::new(block)))
            }
            "repeat" => {
                self.advance();
                self.loop_depth += 1;
                let block = self.parse_block()?;
                self.loop_depth -= 1;
                self.consume("until")?;
                let cond = self.parse_expr_bp(0)?;
                Ok(Stmt::Repeat(Box::new(block), Box::new(cond)))
            }
            "if" => {
                self.advance();
                let cond = self.parse_expr_bp(0)?;
                self.consume("then")?;
                let then_block = self.parse_block()?;
                let mut else_ifs = Vec::new();
                while self.peek().map(|tok| tok.text.as_str()) == Some("elseif") {
                    self.advance();
                    let cond = self.parse_expr_bp(0)?;
                    self.consume("then")?;
                    let block = self.parse_block()?;
                    else_ifs.push((cond, block));
                }
                let mut else_block = None;
                if self.peek().map(|tok| tok.text.as_str()) == Some("else") {
                    self.advance();
                    else_block = Some(Box::new(self.parse_block()?));
                }
                self.consume("end")?;
                Ok(Stmt::If { cond: Box::new(cond), then_block: Box::new(then_block), else_ifs, else_block })
            }
            "for" => {
                self.advance();
                let first_name = self.consume_type(TokenType::Identifier)?.text;
                if self.peek().map(|tok| tok.text.as_str()) == Some("=") {
                    self.advance();
                    let init = self.parse_expr_bp(0)?;
                    self.consume(",")?;
                    let limit = self.parse_expr_bp(0)?;
                    let mut step = None;
                    if self.peek().map(|tok| tok.text.as_str()) == Some("") {
                        self.advance();
                        step = Some(Box::new(self.parse_expr_bp(0)?));
                    }
                    self.consume("do")?;
                    self.loop_depth += 1;
                    let block = self.parse_block()?;
                    self.loop_depth -= 1;
                    self.consume("end")?;
                    Ok(Stmt::For {
                        var: LocalVar { name: first_name, id: VarId(0) },
                        init: Box::new(init),
                        limit: Box::new(limit),
                        step,
                        block: Box::new(block),
                    })
                } else {
                    let mut vars = vec![LocalVar { name: first_name, id: VarId(0) }];
                    while self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                        self.advance();
                        let name = self.consume_type(TokenType::Identifier)?.text;
                        vars.push(LocalVar { name, id: VarId(0) });
                    }
                    self.consume("in")?;
                    let mut exprs = Vec::new();
                    loop {
                        exprs.push(self.parse_expr_bp(0)?);
                        if self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    self.consume("do")?;
                    self.loop_depth += 1;
                    let block = self.parse_block()?;
                    self.loop_depth -= 1;
                    self.consume("end")?;
                    Ok(Stmt::ForIn { vars, exprs, block: Box::new(block) })
                }
            }
            _ => {
                let prefix = self.parse_prefix_expr()?;
                match prefix {
                    PrefixExpr::Call(call) => {
                        Ok(Stmt::Call(call))
                    }
                    PrefixExpr::Var(var) => {
                        let mut vars = vec![var];
                        while self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                            self.advance();
                            let next_prefix = self.parse_prefix_expr()?;
                            if let PrefixExpr::Var(v) = next_prefix {
                                vars.push(v);
                            } else {
                                return Err(self.syntax_error("Expected variable in assignment left-hand side", line));
                            }
                        }
                        self.consume("=")?;
                        let mut exprs = Vec::new();
                        loop {
                            exprs.push(self.parse_expr_bp(0)?);
                            if self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                        Ok(Stmt::Assign(vars, exprs))
                    }
                    PrefixExpr::Paren(_) => {
                        Err(self.syntax_error("Parenthesized expression cannot be a standalone statement", line))
                    }
                }
            }
        }
    }

    pub fn parse_block(&mut self) -> Result<Block, LuaError> {
        let mut stmts = Vec::new();
        let mut last_stmt = None;
        loop {
            if let Some(t) = self.peek() {
                let text = t.text.as_str();
                if text == "end" || text == "elseif" || text == "else" || text == "until" {
                    break;
                }
                if text == "return" {
                    self.advance();
                    let mut exprs = Vec::new();
                    if self.peek().is_some() {
                        let t_next = self.peek().unwrap().text.as_str();
                        if t_next != "end" && t_next != "elseif" && t_next != "else" && t_next != "until" && t_next != ";" {
                            loop {
                                match self.parse_expr_bp(0) {
                                    Ok(expr) => exprs.push(expr),
                                    Err(e) => {
                                        self.add_error(e);
                                        self.recover();
                                        break;
                                    }
                                }
                                if self.peek().map(|tok| tok.text.as_str()) == Some(",") {
                                    self.advance();
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    if self.peek().map(|tok| tok.text.as_str()) == Some(";") {
                        self.advance();
                    }
                    last_stmt = Some(LastStmt::Return(exprs));
                    break;
                }
                if text == "break" {
                    let line = self.current_line();
                    self.advance();
                    if self.loop_depth == 0 {
                        self.add_error(self.semantic_error("break outside loop", line, Some("break".to_string())));
                    }
                    if self.peek().map(|tok| tok.text.as_str()) == Some(";") {
                        self.advance();
                    }
                    last_stmt = Some(LastStmt::Break);
                    break;
                }
                if text == ";" {
                    self.advance();
                    continue;
                }
                match self.parse_stmt() {
                    Ok(stmt) => stmts.push(stmt),
                    Err(e) => {
                        self.add_error(e);
                        self.recover();
                    }
                }
            } else {
                break;
            }
        }
        if !self.errors.is_empty() {
            return Err(LuaError::Multiple(std::mem::take(&mut self.errors)));
        }
        Ok(Block { stmts, last_stmt })
    }
}