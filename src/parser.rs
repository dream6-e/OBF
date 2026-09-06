use crate::ast::*;
use crate::lexer::{self, Token, TokenKind};
use crate::{Diagnostic, Target};
use std::collections::HashSet;

const MAX_TOKENS: usize = 1_000_000;
const MAX_NODES: usize = 1_000_000;
// Kept deliberately conservative: parser frames contain owned AST builders,
// and Rust test/runtime threads can have a stack as small as 2 MiB.
const MAX_NESTING: usize = 64;

/// Parse an already-tokenized source chunk into an owned AST.
///
/// Token arrays are validated before parsing so this public entry point also
/// fails safely when called with tokens that did not originate in the lexer.
pub fn parse(source: &str, tokens: &[Token], target: Target) -> Result<Chunk, Diagnostic> {
    validate_external_tokens(source, tokens, target)?;
    parse_lexed(source, tokens, target)
}

fn validate_external_tokens(
    source: &str,
    tokens: &[Token],
    target: Target,
) -> Result<(), Diagnostic> {
    validate_tokens(source, tokens, source.len())?;
    let expected = lexer::lex(source, target)?;
    if tokens != expected {
        return Err(Diagnostic::new(
            "token stream does not match the source and selected target",
        ));
    }
    Ok(())
}

/// The public token-array minifier must retain the same validation as parse.
pub(crate) fn parse_with_statement_ends(
    source: &str,
    tokens: &[Token],
    target: Target,
) -> Result<(Chunk, Vec<usize>), Diagnostic> {
    validate_external_tokens(source, tokens, target)?;
    parse_lexed_with_statement_ends(source, tokens, target)
}

pub(crate) fn parse_lexed(
    source: &str,
    tokens: &[Token],
    target: Target,
) -> Result<Chunk, Diagnostic> {
    parse_lexed_inner(source, tokens, target, false).map(|(chunk, _)| chunk)
}

/// Private formatting sidecar: global source byte offsets immediately after
/// complete statements, BEFORE an optional existing semicolon. Recording in
/// the grammar covers function bodies in expressions, types and interpolation
/// without a second, potentially incomplete AST walker. Parsing is unchanged.
pub(crate) fn parse_lexed_with_statement_ends(
    source: &str,
    tokens: &[Token],
    target: Target,
) -> Result<(Chunk, Vec<usize>), Diagnostic> {
    parse_lexed_inner(source, tokens, target, true)
}

fn parse_lexed_inner(
    source: &str,
    tokens: &[Token],
    target: Target,
    collect_statement_ends: bool,
) -> Result<(Chunk, Vec<usize>), Diagnostic> {
    if source.len() > lexer::MAX_SOURCE_BYTES {
        return Err(Diagnostic::new("source exceeds parser safety limit"));
    }
    validate_tokens(source, tokens, source.len())?;
    let mut parser = Parser {
        source,
        tokens,
        target,
        cursor: 0,
        nesting: 0,
        nodes: 0,
        loop_depth: 0,
        function_depth: 0,
        block_depth: 0,
        vararg_allowed: true,
        exported_values: HashSet::new(),
        has_value_exports: false,
        has_module_return: false,
        needs_binding_validation: false,
        statement_ends: collect_statement_ends.then(Vec::new),
    };
    let block = parser.block(&[])?;
    parser.expect_eof()?;
    let chunk = Chunk {
        target,
        block,
        span: Span::new(0, source.len()),
    };
    // Reuse the lexical resolver for Luau's binding-dependent syntax rules.
    // This does not reenter the parser and is unnecessary for ordinary chunks.
    if parser.needs_binding_validation {
        crate::scope::analyze_chunk(&chunk)?;
    }
    Ok((chunk, parser.statement_ends.unwrap_or_default()))
}

/// Lex and parse source in one bounded operation.
pub fn parse_source(source: &str, target: Target) -> Result<Chunk, Diagnostic> {
    let tokens = lexer::lex(source, target)?;
    parse_lexed(source, &tokens, target)
}

fn validate_tokens(source: &str, tokens: &[Token], expected_eof: usize) -> Result<(), Diagnostic> {
    if tokens.is_empty() {
        return Err(Diagnostic::new("token stream is empty"));
    }
    if tokens.len() > MAX_TOKENS {
        return Err(Diagnostic::new("token stream exceeds parser safety limit"));
    }
    if tokens.last().map(|token| token.kind) != Some(TokenKind::Eof) {
        return Err(Diagnostic::new("token stream is missing EOF"));
    }
    if expected_eof > source.len()
        || tokens
            .last()
            .is_none_or(|token| token.span != (expected_eof..expected_eof))
    {
        return Err(Diagnostic::new("EOF token is at the wrong source offset"));
    }

    let mut previous_end = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        if token.span.start > token.span.end
            || token.span.end > source.len()
            || !source.is_char_boundary(token.span.start)
            || !source.is_char_boundary(token.span.end)
        {
            return Err(Diagnostic::new(format!(
                "token {index} has an invalid UTF-8 span"
            )));
        }
        if token.span.start < previous_end {
            return Err(Diagnostic::new(format!(
                "token {index} overlaps the previous token"
            )));
        }
        if (token.kind == TokenKind::Eof && token.span.start != token.span.end)
            || (token.kind != TokenKind::Eof && token.span.start == token.span.end)
        {
            return Err(Diagnostic::new(format!(
                "token {index} has an invalid empty/non-empty span"
            )));
        }
        if token.line == 0 || token.column == 0 {
            return Err(Diagnostic::new(format!(
                "token {index} has an invalid source position"
            )));
        }
        if token.kind == TokenKind::Eof && index + 1 != tokens.len() {
            return Err(Diagnostic::new("EOF must be the final token"));
        }
        previous_end = token.span.end;
    }
    Ok(())
}

struct Parser<'a> {
    source: &'a str,
    tokens: &'a [Token],
    target: Target,
    cursor: usize,
    nesting: usize,
    nodes: usize,
    loop_depth: usize,
    function_depth: usize,
    block_depth: usize,
    vararg_allowed: bool,
    exported_values: HashSet<String>,
    has_value_exports: bool,
    has_module_return: bool,
    needs_binding_validation: bool,
    statement_ends: Option<Vec<usize>>,
}

impl<'a> Parser<'a> {
    fn block(&mut self, terminators: &[&str]) -> Result<Block, Diagnostic> {
        self.enter("block")?;
        self.block_depth += 1;
        let result = self.block_inner(terminators);
        self.block_depth -= 1;
        self.leave();
        result
    }

    fn block_inner(&mut self, terminators: &[&str]) -> Result<Block, Diagnostic> {
        let start = self.current().span.start;
        let mut statements = Vec::new();
        while !self.at_eof() && !terminators.iter().any(|word| self.at(word)) {
            let mut statement = self.statement()?;
            if let Some(ends) = &mut self.statement_ends {
                if ends.len() >= MAX_NODES {
                    return Err(Diagnostic::byte(
                        "statement boundary count exceeds safety limit",
                        statement.span.end,
                    ));
                }
                // Nested bodies finish before their containing statement.
                // Keep a sorted, unique sidecar for bounded emitter lookups.
                if ends.last().is_some_and(|&end| end >= statement.span.end) {
                    return Err(Diagnostic::byte(
                        "unordered statement boundary",
                        statement.span.end,
                    ));
                }
                ends.push(statement.span.end);
            }
            if self.consume(";") {
                statement.span.end = self.previous_end();
            }
            let terminal = matches!(
                statement.kind,
                StatementKind::Return(_) | StatementKind::Break | StatementKind::Continue
            );
            statements.push(statement);
            if terminal && !self.at_eof() && !terminators.iter().any(|word| self.at(word)) {
                return Err(
                    self.error_current("statement is not allowed after a terminal statement")
                );
            }
        }
        self.bump_node()?;
        Ok(Block {
            statements,
            span: Span::new(start, self.current().span.start),
        })
    }

    fn statement(&mut self) -> Result<Statement, Diagnostic> {
        let start = self.current().span.start;
        let kind = if self.starts_luau_declaration() {
            self.luau_declaration_statement()?
        } else if self.at("if") {
            self.if_statement()?
        } else if self.at("while") {
            self.while_statement()?
        } else if self.at("repeat") {
            self.repeat_statement()?
        } else if self.at("for") {
            self.for_statement()?
        } else if self.at("do") {
            self.advance();
            let body = self.block(&["end"])?;
            self.expect("end")?;
            StatementKind::Do(body)
        } else if self.at("function") {
            self.function_statement()?
        } else if self.at("local") {
            self.local_statement()?
        } else if self.at("return") {
            self.return_statement()?
        } else if self.at("break") {
            if self.loop_depth == 0 {
                return Err(self.error_current("'break' used outside a loop"));
            }
            self.advance();
            StatementKind::Break
        } else if self.starts_type_declaration() {
            self.type_declaration()?
        } else {
            self.assignment_or_call()?
        };
        self.bump_node()?;
        Ok(Statement {
            kind,
            span: Span::new(start, self.previous_end()),
        })
    }

    fn starts_luau_declaration(&self) -> bool {
        if !self.target.is_luau() {
            return false;
        }
        self.at("@")
            || (self.at("type")
                && (self.peek_kind(1) == Some(TokenKind::Identifier)
                    || self.peek_text(1) == "function"))
            || (self.at("const")
                && (self.peek_kind(1) == Some(TokenKind::Identifier)
                    || self.peek_text(1) == "function"))
            || (self.at("export")
                && matches!(self.peek_text(1), "local" | "const" | "function" | "type"))
    }

    fn luau_declaration_statement(&mut self) -> Result<StatementKind, Diagnostic> {
        let attributes = if self.at("@") {
            self.attributes()?
        } else {
            Vec::new()
        };
        let exported = self.consume("export");
        if exported && (self.function_depth != 0 || self.block_depth != 1) {
            return Err(self.error_current("'export' is only valid at the top level"));
        }

        if self.consume("type") {
            if !attributes.is_empty() {
                return Err(self.error_current("attributes require a value function declaration"));
            }
            if self.consume("function") {
                self.needs_binding_validation = true;
                let name = self.name("expected type function name")?;
                let body = self.function_body(Vec::new())?;
                return Ok(StatementKind::TypeFunction {
                    exported,
                    name,
                    body,
                });
            }
            return self.type_declaration_after_keyword(exported);
        }

        if self.consume("local") {
            if exported && self.at("function") {
                return Err(
                    self.error_current("'export local function' is invalid; use 'export function'")
                );
            }
            return self.local_declaration(false, exported, attributes);
        }
        if self.consume("const") {
            return self.local_declaration(true, exported, attributes);
        }
        if self.consume("function") {
            if exported {
                self.needs_binding_validation = true;
                let name = self.name("expected exported function name")?;
                self.record_value_export(&name)?;
                let body = self.function_body(attributes)?;
                return Ok(StatementKind::LocalFunction {
                    name,
                    body,
                    is_const: true,
                    exported: true,
                });
            }
            return self.function_declaration_after_keyword(attributes);
        }

        Err(self.error_current("attributes or 'export' must precede a declaration"))
    }

    fn starts_type_declaration(&self) -> bool {
        self.target.is_luau()
            && ((self.at("type") && self.peek_kind(1) == Some(TokenKind::Identifier))
                || (self.at("export") && self.peek_text(1) == "type"))
    }

    fn if_statement(&mut self) -> Result<StatementKind, Diagnostic> {
        self.expect("if")?;
        let mut branches = Vec::new();
        loop {
            let branch_start = self.current().span.start;
            let condition = self.expression(0)?;
            self.expect("then")?;
            let body = self.block(&["elseif", "else", "end"])?;
            let span = Span::new(branch_start, body.span.end);
            branches.push(ConditionalBlock {
                condition,
                body,
                span,
            });
            if !self.consume("elseif") {
                break;
            }
        }
        let else_block = if self.consume("else") {
            Some(self.block(&["end"])?)
        } else {
            None
        };
        self.expect("end")?;
        Ok(StatementKind::If {
            branches,
            else_block,
        })
    }

    fn while_statement(&mut self) -> Result<StatementKind, Diagnostic> {
        self.expect("while")?;
        let condition = self.expression(0)?;
        self.expect("do")?;
        self.loop_depth += 1;
        let body = self.block(&["end"]);
        self.loop_depth -= 1;
        let body = body?;
        self.expect("end")?;
        Ok(StatementKind::While { condition, body })
    }

    fn repeat_statement(&mut self) -> Result<StatementKind, Diagnostic> {
        self.expect("repeat")?;
        self.loop_depth += 1;
        let body = self.block(&["until"]);
        self.loop_depth -= 1;
        let body = body?;
        self.expect("until")?;
        let condition = self.expression(0)?;
        Ok(StatementKind::Repeat { body, condition })
    }

    fn for_statement(&mut self) -> Result<StatementKind, Diagnostic> {
        self.expect("for")?;
        let first = self.binding(&[",", "=", "in"])?;
        if self.consume("=") {
            let initial = self.expression(0)?;
            self.expect(",")?;
            let limit = self.expression(0)?;
            let step = if self.consume(",") {
                Some(self.expression(0)?)
            } else {
                None
            };
            self.expect("do")?;
            self.loop_depth += 1;
            let body = self.block(&["end"]);
            self.loop_depth -= 1;
            let body = body?;
            self.expect("end")?;
            Ok(StatementKind::NumericFor {
                binding: first,
                initial,
                limit,
                step,
                body,
            })
        } else {
            let mut bindings = vec![first];
            while self.consume(",") {
                bindings.push(self.binding(&[",", "in"])?);
            }
            self.expect("in")?;
            let values = self.expression_list()?;
            self.expect("do")?;
            self.loop_depth += 1;
            let body = self.block(&["end"]);
            self.loop_depth -= 1;
            let body = body?;
            self.expect("end")?;
            Ok(StatementKind::GenericFor {
                bindings,
                values,
                body,
            })
        }
    }

    fn function_statement(&mut self) -> Result<StatementKind, Diagnostic> {
        self.expect("function")?;
        self.function_declaration_after_keyword(Vec::new())
    }

    fn function_declaration_after_keyword(
        &mut self,
        attributes: Vec<Attribute>,
    ) -> Result<StatementKind, Diagnostic> {
        let start = self.current().span.start;
        let mut path = vec![self.name("expected function name")?];
        while self.consume(".") {
            path.push(self.name("expected field name after '.'")?);
        }
        let method = if self.consume(":") {
            Some(self.name("expected method name after ':'")?)
        } else {
            None
        };
        let name_end = self.previous_end();
        let body = self.function_body(attributes)?;
        Ok(StatementKind::Function {
            name: FunctionName {
                path,
                method,
                span: Span::new(start, name_end),
            },
            body,
        })
    }

    fn local_statement(&mut self) -> Result<StatementKind, Diagnostic> {
        self.expect("local")?;
        self.local_declaration(false, false, Vec::new())
    }

    fn local_declaration(
        &mut self,
        is_const: bool,
        exported: bool,
        attributes: Vec<Attribute>,
    ) -> Result<StatementKind, Diagnostic> {
        self.needs_binding_validation |= is_const;
        if self.consume("function") {
            let name = self.name("expected local function name")?;
            if exported {
                self.record_value_export(&name)?;
            }
            let body = self.function_body(attributes)?;
            return Ok(StatementKind::LocalFunction {
                name,
                body,
                is_const,
                exported,
            });
        }
        if !attributes.is_empty() {
            return Err(self.error_current("attributes on local values require 'function'"));
        }

        let mut bindings = vec![self.binding(&[",", "="])?];
        while self.consume(",") {
            bindings.push(self.binding(&[",", "="])?);
        }
        let values = if self.consume("=") {
            self.expression_list()?
        } else {
            Vec::new()
        };
        if is_const
            && values.len() != bindings.len()
            && !values.last().is_some_and(|value| {
                matches!(
                    value.kind,
                    ExpressionKind::Call { .. } | ExpressionKind::Vararg
                )
            })
        {
            return Err(self.error_current(
                "const initializer count must match bindings, unless the last value is a call or vararg",
            ));
        }
        if exported {
            for binding in &bindings {
                self.record_value_export(&binding.name)?;
            }
        }
        Ok(StatementKind::Local {
            bindings,
            values,
            is_const,
            exported,
        })
    }

    fn return_statement(&mut self) -> Result<StatementKind, Diagnostic> {
        if self.target.is_luau() && self.function_depth == 0 {
            if self.has_value_exports {
                return Err(
                    self.error_current("top-level return is incompatible with exported values")
                );
            }
            // A return in a top-level if/do/loop still returns from the module.
            self.has_module_return = true;
        }
        self.expect("return")?;
        let values =
            if self.at_eof() || matches!(self.text(), "end" | "else" | "elseif" | "until" | ";") {
                Vec::new()
            } else {
                self.expression_list()?
            };
        Ok(StatementKind::Return(values))
    }

    fn assignment_or_call(&mut self) -> Result<StatementKind, Diagnostic> {
        let first = self.expression(0)?;
        if self.target.is_luau() {
            if let Some(operator) = compound_operator(self.text()) {
                if !first.is_assignable() {
                    return Err(
                        self.error_current("left side of compound assignment is not assignable")
                    );
                }
                self.advance();
                let value = self.expression(0)?;
                return Ok(StatementKind::CompoundAssignment {
                    target: first,
                    operator,
                    value,
                });
            }
        }

        if self.at(",") || self.at("=") {
            if !first.is_assignable() {
                return Err(self.error_current("left side of assignment is not assignable"));
            }
            let mut targets = vec![first];
            while self.consume(",") {
                let expression = self.expression(0)?;
                if !expression.is_assignable() {
                    return Err(self.error_current("left side of assignment is not assignable"));
                }
                targets.push(expression);
            }
            self.expect("=")?;
            let values = self.expression_list()?;
            Ok(StatementKind::Assignment { targets, values })
        } else if first.is_call() {
            Ok(StatementKind::Call(first))
        } else if self.target.is_luau()
            && matches!(&first.kind, ExpressionKind::Name(name) if name.value == "continue")
        {
            if self.loop_depth == 0 {
                return Err(self.error_current("'continue' used outside a loop"));
            }
            Ok(StatementKind::Continue)
        } else {
            Err(self.error_current("expected assignment or function call statement"))
        }
    }

    fn expression_list(&mut self) -> Result<Vec<Expression>, Diagnostic> {
        let mut values = vec![self.expression(0)?];
        while self.consume(",") {
            values.push(self.expression(0)?);
        }
        Ok(values)
    }

    fn expression(&mut self, minimum: u8) -> Result<Expression, Diagnostic> {
        self.enter("expression")?;
        let result = self.expression_inner(minimum);
        self.leave();
        result
    }

    fn expression_inner(&mut self, minimum: u8) -> Result<Expression, Diagnostic> {
        let mut expression = if let Some(operator) = unary_operator(self.text(), self.target) {
            let start = self.current().span.start;
            self.advance();
            let value = self.expression(7)?;
            self.make_expression(
                ExpressionKind::Unary {
                    operator,
                    expression: Box::new(value),
                },
                start,
                self.previous_end(),
            )?
        } else {
            let primary = self.primary()?;
            // Luau: assertion binds to a simple expression, at most once.
            // Repeated assertions need parentheses; unary/binary precedence
            // must not accidentally turn `-x::T` into `(-x)::T`.
            if self.target.is_luau() && self.consume("::") {
                let start = primary.span.start;
                let asserted = self.type_expression()?;
                self.make_expression(
                    ExpressionKind::TypeAssertion {
                        expression: Box::new(primary),
                        asserted,
                    },
                    start,
                    self.previous_end(),
                )?
            } else {
                primary
            }
        };

        let mut chain = 0usize;
        loop {
            let Some((operator, left, right)) = infix_operator(self.text(), self.target) else {
                break;
            };
            if left < minimum {
                break;
            }
            self.extend_chain(&mut chain, "expression")?;
            self.advance();
            let rhs = self.expression(right)?;
            let start = expression.span.start;
            let end = rhs.span.end;
            expression = self.make_expression(
                ExpressionKind::Binary {
                    operator,
                    left: Box::new(expression),
                    right: Box::new(rhs),
                },
                start,
                end,
            )?;
        }
        Ok(expression)
    }

    fn primary(&mut self) -> Result<Expression, Diagnostic> {
        let start = self.current().span.start;
        let kind = if self.consume("nil") {
            ExpressionKind::Nil
        } else if self.consume("false") {
            ExpressionKind::Boolean(false)
        } else if self.consume("true") {
            ExpressionKind::Boolean(true)
        } else if self.at("...") {
            if !self.vararg_allowed {
                return Err(self.error_current("cannot use '...' outside a variadic function"));
            }
            self.advance();
            ExpressionKind::Vararg
        } else if self.kind() == TokenKind::Number {
            let value = self.text().to_owned();
            self.advance();
            ExpressionKind::Number(value)
        } else if self.kind() == TokenKind::String && self.text().starts_with('`') {
            return self.interpolated_string_expression();
        } else if self.kind() == TokenKind::String {
            let value = self.text().to_owned();
            self.advance();
            ExpressionKind::String(value)
        } else if self.at("@") && self.target.is_luau() {
            let attributes = self.attributes()?;
            self.expect("function")?;
            ExpressionKind::Function(self.function_body(attributes)?)
        } else if self.consume("function") {
            ExpressionKind::Function(self.function_body(Vec::new())?)
        } else if self.at("{") {
            return self.table_constructor();
        } else if self.at("if") && self.target.is_luau() {
            return self.if_expression();
        } else if self.kind() == TokenKind::Identifier {
            ExpressionKind::Name(self.name("expected name")?)
        } else if self.consume("(") {
            let value = self.expression(0)?;
            self.expect(")")?;
            ExpressionKind::Group(Box::new(value))
        } else {
            return Err(self.error_current("expected expression"));
        };

        let prefix = matches!(kind, ExpressionKind::Name(_) | ExpressionKind::Group(_));
        let expression = self.make_expression(kind, start, self.previous_end())?;
        if prefix {
            self.suffixes(expression)
        } else {
            Ok(expression)
        }
    }

    fn suffixes(&mut self, mut expression: Expression) -> Result<Expression, Diagnostic> {
        let mut chain = 0usize;
        loop {
            let start = expression.span.start;
            if self.target.is_luau() && self.at("<") && self.peek_text(1) == "<" {
                self.extend_chain(&mut chain, "expression suffix")?;
                let arguments = self.explicit_type_arguments()?;
                let end = self.previous_end();
                expression = self.make_expression(
                    ExpressionKind::TypeInstantiation {
                        expression: Box::new(expression),
                        arguments,
                    },
                    start,
                    end,
                )?;
            } else if self.consume(".") {
                self.extend_chain(&mut chain, "expression suffix")?;
                let field = self.name("expected field name after '.'")?;
                let end = field.span.end;
                expression = self.make_expression(
                    ExpressionKind::Field {
                        table: Box::new(expression),
                        field,
                    },
                    start,
                    end,
                )?;
            } else if self.consume("[") {
                self.extend_chain(&mut chain, "expression suffix")?;
                let index = self.expression(0)?;
                self.expect("]")?;
                let end = self.previous_end();
                expression = self.make_expression(
                    ExpressionKind::Index {
                        table: Box::new(expression),
                        index: Box::new(index),
                    },
                    start,
                    end,
                )?;
            } else if self.consume(":") {
                self.extend_chain(&mut chain, "expression suffix")?;
                let method = self.name("expected method name after ':'")?;
                let type_arguments =
                    if self.target.is_luau() && self.at("<") && self.peek_text(1) == "<" {
                        self.explicit_type_arguments()?
                    } else {
                        Vec::new()
                    };
                // The reference parser compares '(' with the method name,
                // even when explicit type arguments occur between them.
                self.check_call_line(method.span.end)?;
                let arguments = self.call_arguments()?;
                let end = self.previous_end();
                expression = self.make_expression(
                    ExpressionKind::Call {
                        function: Box::new(expression),
                        method: Some(method),
                        type_arguments,
                        arguments,
                    },
                    start,
                    end,
                )?;
            } else if self.starts_call_arguments() {
                self.extend_chain(&mut chain, "expression suffix")?;
                self.check_call_line(expression.span.end)?;
                let arguments = self.call_arguments()?;
                let end = self.previous_end();
                expression = self.make_expression(
                    ExpressionKind::Call {
                        function: Box::new(expression),
                        method: None,
                        type_arguments: Vec::new(),
                        arguments,
                    },
                    start,
                    end,
                )?;
            } else {
                break;
            }
        }
        Ok(expression)
    }

    fn explicit_type_arguments(&mut self) -> Result<Vec<TypeArgument>, Diagnostic> {
        self.expect("<")?;
        self.expect("<")?;
        let mut arguments = Vec::new();
        if !(self.at(">") && self.peek_text(1) == ">") {
            loop {
                arguments.push(type_argument(self.type_expression_allow_pack()?));
                if !self.consume(",") {
                    break;
                }
            }
        }
        self.expect(">")?;
        self.expect(">")?;
        Ok(arguments)
    }

    fn check_call_line(&self, callee_end: usize) -> Result<(), Diagnostic> {
        // Luau's reference lexer counts only LF as a source line break;
        // Lua 5.1 also counts a bare CR. Inspect the gap after the callee's
        // END so multiline strings/type arguments do not cause false errors.
        let gap = &self.source[callee_end..self.current().span.start];
        if self.at("(")
            && gap
                .bytes()
                .any(|byte| byte == b'\n' || (byte == b'\r' && !self.target.is_luau()))
        {
            return Err(self.error_current(
                "ambiguous call across a newline; use a semicolon between statements",
            ));
        }
        Ok(())
    }

    fn interpolated_string_expression(&mut self) -> Result<Expression, Diagnostic> {
        let token_span = self.current().span.clone();
        let ranges =
            lexer::interpolated_expression_ranges(self.source, token_span.clone(), self.target)?;
        self.advance();

        let mut strings = Vec::with_capacity(ranges.len() + 1);
        let mut expressions = Vec::with_capacity(ranges.len());
        let mut string_start = token_span.start + 1;
        for range in ranges {
            let string_end = range
                .start
                .checked_sub(1)
                .ok_or_else(|| self.error_current("invalid interpolated expression span"))?;
            let value = self
                .source
                .get(string_start..string_end)
                .ok_or_else(|| self.error_current("invalid interpolated string segment"))?
                .to_owned();
            strings.push(InterpolatedSegment {
                value,
                span: Span::new(string_start, string_end),
            });
            expressions.push(self.expression_fragment(range.clone())?);
            string_start = range
                .end
                .checked_add(1)
                .ok_or_else(|| self.error_current("interpolated string span overflow"))?;
        }
        let string_end = token_span.end - 1;
        let value = self
            .source
            .get(string_start..string_end)
            .ok_or_else(|| self.error_current("invalid final interpolated string segment"))?
            .to_owned();
        strings.push(InterpolatedSegment {
            value,
            span: Span::new(string_start, string_end),
        });
        self.make_expression(
            ExpressionKind::InterpolatedString {
                strings,
                expressions,
            },
            token_span.start,
            token_span.end,
        )
    }

    fn expression_fragment(
        &mut self,
        range: std::ops::Range<usize>,
    ) -> Result<Expression, Diagnostic> {
        let expected_eof = range.end;
        let tokens = lexer::lex_fragment(self.source, range, self.target)?;
        validate_tokens(self.source, &tokens, expected_eof)?;
        let mut child = Parser {
            source: self.source,
            tokens: &tokens,
            target: self.target,
            cursor: 0,
            nesting: self.nesting,
            nodes: 0,
            loop_depth: self.loop_depth,
            function_depth: self.function_depth,
            block_depth: self.block_depth,
            vararg_allowed: self.vararg_allowed,
            exported_values: HashSet::new(),
            has_value_exports: false,
            has_module_return: false,
            needs_binding_validation: false,
            // Move the shared sidecar through fragment parsers. Do not clone
            // or repeatedly append all nested boundaries at each depth.
            statement_ends: self.statement_ends.take(),
        };
        let expression = child.expression(0)?;
        child.expect_eof()?;
        self.needs_binding_validation |= child.needs_binding_validation;
        self.statement_ends = child.statement_ends;
        self.nodes = self
            .nodes
            .checked_add(child.nodes)
            .ok_or_else(|| self.error_current("AST node count overflow"))?;
        if self.nodes > MAX_NODES {
            return Err(self.error_current("AST node count exceeds safety limit"));
        }
        Ok(expression)
    }

    fn if_expression(&mut self) -> Result<Expression, Diagnostic> {
        let start = self.current().span.start;
        self.expect("if")?;
        let mut branches = Vec::new();
        loop {
            let branch_start = self.current().span.start;
            let condition = self.expression(0)?;
            self.expect("then")?;
            let value = self.expression(0)?;
            let end = value.span.end;
            branches.push(ConditionalExpression {
                condition,
                value,
                span: Span::new(branch_start, end),
            });
            if !self.consume("elseif") {
                break;
            }
        }
        self.expect("else")?;
        let else_expression = self.expression(0)?;
        let end = else_expression.span.end;
        self.make_expression(
            ExpressionKind::IfExpression {
                branches,
                else_expression: Box::new(else_expression),
            },
            start,
            end,
        )
    }

    fn call_arguments(&mut self) -> Result<Vec<Expression>, Diagnostic> {
        if self.consume("(") {
            if self.consume(")") {
                Ok(Vec::new())
            } else {
                let arguments = self.expression_list()?;
                self.expect(")")?;
                Ok(arguments)
            }
        } else if self.at("{") {
            Ok(vec![self.table_constructor()?])
        } else if self.kind() == TokenKind::String && !self.text().starts_with('`') {
            let start = self.current().span.start;
            let raw = self.text().to_owned();
            self.advance();
            let end = self.previous_end();
            Ok(vec![self.make_expression(
                ExpressionKind::String(raw),
                start,
                end,
            )?])
        } else {
            Err(self.error_current("expected function call arguments"))
        }
    }

    fn starts_call_arguments(&self) -> bool {
        self.at("(")
            || self.at("{")
            || (self.kind() == TokenKind::String && !self.text().starts_with('`'))
    }

    fn table_constructor(&mut self) -> Result<Expression, Diagnostic> {
        let start = self.current().span.start;
        self.expect("{")?;
        let mut fields = Vec::new();
        if !self.consume("}") {
            loop {
                if self.consume("[") {
                    let field_start = self.previous_start();
                    let key = self.expression(0)?;
                    self.expect("]")?;
                    self.expect("=")?;
                    let value = self.expression(0)?;
                    let span = Span::new(field_start, value.span.end);
                    fields.push(TableField::Computed { key, value, span });
                } else if self.kind() == TokenKind::Identifier && self.peek_text(1) == "=" {
                    let name = self.name("expected table field")?;
                    let field_start = name.span.start;
                    self.expect("=")?;
                    let value = self.expression(0)?;
                    let span = Span::new(field_start, value.span.end);
                    fields.push(TableField::Record { name, value, span });
                } else {
                    fields.push(TableField::List(self.expression(0)?));
                }

                if self.consume(",") || self.consume(";") {
                    if self.consume("}") {
                        break;
                    }
                } else {
                    self.expect("}")?;
                    break;
                }
            }
        }
        self.make_expression(ExpressionKind::Table(fields), start, self.previous_end())
    }

    fn attributes(&mut self) -> Result<Vec<Attribute>, Diagnostic> {
        let mut attributes = Vec::new();
        while self.consume("@") {
            let at_start = self.previous_start();
            if self.consume("[") {
                if self.at("]") {
                    return Err(self.error_current("attribute list cannot be empty"));
                }
                loop {
                    let name = self.name("expected attribute name")?;
                    let arguments = if self.starts_call_arguments() {
                        self.call_arguments()?
                    } else {
                        Vec::new()
                    };
                    self.push_attribute(&mut attributes, name, arguments, at_start)?;
                    if !self.consume(",") {
                        break;
                    }
                }
                self.expect("]")?;
            } else {
                let name = self.name("expected attribute name after '@'")?;
                self.push_attribute(&mut attributes, name, Vec::new(), at_start)?;
            }
        }
        Ok(attributes)
    }

    fn push_attribute(
        &mut self,
        attributes: &mut Vec<Attribute>,
        name: Name,
        arguments: Vec<Expression>,
        start: usize,
    ) -> Result<(), Diagnostic> {
        if !matches!(name.value.as_str(), "checked" | "native" | "deprecated") {
            return Err(self.error_current(format!("invalid attribute '@{}'", name.value)));
        }
        if attributes
            .iter()
            .any(|attribute| attribute.name.value == name.value)
        {
            return Err(self.error_current(format!("duplicate attribute '@{}'", name.value)));
        }
        if name.value != "deprecated" && !arguments.is_empty() {
            return Err(self.error_current(format!(
                "attribute '@{}' does not accept arguments",
                name.value
            )));
        }
        if name.value == "deprecated" && arguments.len() > 1 {
            return Err(self.error_current("attribute '@deprecated' accepts at most one argument"));
        }
        if name.value == "deprecated"
            && arguments
                .first()
                .is_some_and(|argument| !valid_deprecated_attribute(argument))
        {
            return Err(self.error_current(
                "'@deprecated' only accepts a table with string 'use'/'reason' fields",
            ));
        }
        self.bump_node()?;
        attributes.push(Attribute {
            name,
            arguments,
            span: Span::new(start, self.previous_end()),
        });
        Ok(())
    }

    fn function_body(&mut self, attributes: Vec<Attribute>) -> Result<FunctionBody, Diagnostic> {
        self.enter("function")?;
        self.function_depth += 1;
        let result = self.function_body_inner(attributes);
        self.function_depth -= 1;
        self.leave();
        result
    }

    fn function_body_inner(
        &mut self,
        attributes: Vec<Attribute>,
    ) -> Result<FunctionBody, Diagnostic> {
        let start = self.current().span.start;
        let generics = if self.target.is_luau() && self.at("<") {
            self.generic_parameter_list(false)?
        } else {
            Vec::new()
        };
        self.expect("(")?;
        let mut parameters = Vec::new();
        let mut vararg = None;
        let mut has_vararg = false;
        if !self.consume(")") {
            loop {
                if self.consume("...") {
                    has_vararg = true;
                    vararg = self.optional_type_pack_annotation()?;
                    self.expect(")")?;
                    break;
                }
                parameters.push(self.binding(&[",", ")"])?);
                if self.consume(")") {
                    break;
                }
                self.expect(",")?;
            }
        }
        let return_type = if self.target.is_luau() && self.consume(":") {
            Some(self.type_expression_allow_pack()?)
        } else {
            None
        };

        let saved_loop_depth = self.loop_depth;
        let saved_vararg = self.vararg_allowed;
        self.loop_depth = 0;
        self.vararg_allowed = has_vararg;
        let body = self.block(&["end"]);
        self.loop_depth = saved_loop_depth;
        self.vararg_allowed = saved_vararg;
        let body = body?;
        self.expect("end")?;
        self.bump_node()?;
        Ok(FunctionBody {
            attributes,
            generics,
            parameters,
            has_vararg,
            vararg,
            return_type,
            body,
            span: Span::new(start, self.previous_end()),
        })
    }

    fn binding(&mut self, _stops: &[&str]) -> Result<Binding, Diagnostic> {
        let name = self.name("expected binding name")?;
        let start = name.span.start;
        let annotation = self.optional_type_annotation()?;
        let end = annotation
            .as_ref()
            .map_or(name.span.end, |annotation| annotation.span.end);
        self.bump_node()?;
        Ok(Binding {
            name,
            annotation,
            span: Span::new(start, end),
        })
    }

    fn optional_type_annotation(&mut self) -> Result<Option<TypeExpression>, Diagnostic> {
        if self.consume(":") {
            if !self.target.is_luau() {
                return Err(self.error_current("type annotations are only valid for Luau"));
            }
            Ok(Some(self.type_expression()?))
        } else {
            Ok(None)
        }
    }

    fn optional_type_pack_annotation(&mut self) -> Result<Option<TypeExpression>, Diagnostic> {
        if self.consume(":") {
            if !self.target.is_luau() {
                return Err(self.error_current("type annotations are only valid for Luau"));
            }
            Ok(Some(self.type_expression_allow_pack()?))
        } else {
            Ok(None)
        }
    }

    fn generic_parameter_list(
        &mut self,
        allow_defaults: bool,
    ) -> Result<Vec<GenericParameter>, Diagnostic> {
        self.expect("<")?;
        let mut parameters = Vec::new();
        let mut saw_pack = false;
        let mut saw_default = false;
        loop {
            let start = self.current().span.start;
            let name = self.name("expected generic parameter")?;
            let is_pack = self.consume("...");
            if saw_pack && !is_pack {
                return Err(
                    self.error_current("generic types must appear before generic type packs")
                );
            }
            saw_pack |= is_pack;
            let default = if self.consume("=") {
                if !allow_defaults {
                    return Err(
                        self.error_current("generic defaults are only valid on type aliases")
                    );
                }
                saw_default = true;
                Some(if is_pack {
                    self.type_expression_allow_pack()?
                } else {
                    self.type_expression()?
                })
            } else {
                if saw_default {
                    return Err(
                        self.error_current("generic parameters after a default also need defaults")
                    );
                }
                None
            };
            self.bump_node()?;
            parameters.push(GenericParameter {
                name,
                is_pack,
                default,
                span: Span::new(start, self.previous_end()),
            });
            if self.consume(">") {
                return Ok(parameters);
            }
            self.expect(",")?;
        }
    }

    fn type_declaration(&mut self) -> Result<StatementKind, Diagnostic> {
        let exported = self.consume("export");
        self.expect("type")?;
        self.type_declaration_after_keyword(exported)
    }

    fn type_declaration_after_keyword(
        &mut self,
        exported: bool,
    ) -> Result<StatementKind, Diagnostic> {
        let name = self.name("expected type alias name")?;
        let generics = if self.at("<") {
            self.generic_parameter_list(true)?
        } else {
            Vec::new()
        };
        self.expect("=")?;
        let value = self.type_expression()?;
        Ok(StatementKind::TypeAlias {
            exported,
            name,
            generics,
            value,
        })
    }

    fn type_expression(&mut self) -> Result<TypeExpression, Diagnostic> {
        self.type_expression_mode(false)
    }

    fn type_expression_allow_pack(&mut self) -> Result<TypeExpression, Diagnostic> {
        self.type_expression_mode(true)
    }

    fn type_expression_mode(&mut self, allow_pack: bool) -> Result<TypeExpression, Diagnostic> {
        self.enter("type annotation")?;
        let result = self.type_union();
        self.leave();
        let result = result?;
        if !allow_pack && is_type_pack(&result) {
            Err(self.error_current("a type pack is not valid in this type position"))
        } else {
            Ok(result)
        }
    }

    fn type_union(&mut self) -> Result<TypeExpression, Diagnostic> {
        let start = self.current().span.start;
        let leading = self.consume("|");
        let first = self.type_intersection()?;
        let mut has_separator = self.consume("|");
        if !leading && !has_separator {
            return Ok(first);
        }
        if is_type_pack(&first) {
            return Err(self.error_current("type packs cannot be union members"));
        }
        if matches!(&first.kind, TypeKind::Intersection(_)) {
            return Err(
                self.error_current("mixing union and intersection types requires parentheses")
            );
        }
        let mut members = vec![first];
        while has_separator {
            let member = self.type_intersection()?;
            if is_type_pack(&member) {
                return Err(self.error_current("type packs cannot be union members"));
            }
            if matches!(&member.kind, TypeKind::Intersection(_)) {
                return Err(
                    self.error_current("mixing union and intersection types requires parentheses")
                );
            }
            members.push(member);
            has_separator = self.consume("|");
        }
        let end = members.last().map_or(start, |member| member.span.end);
        self.make_type(TypeKind::Union(members), start, end)
    }

    fn type_intersection(&mut self) -> Result<TypeExpression, Diagnostic> {
        let start = self.current().span.start;
        let leading = self.consume("&");
        let first = self.type_postfix()?;
        let mut has_separator = self.consume("&");
        if !leading && !has_separator {
            return Ok(first);
        }
        if is_type_pack(&first) {
            return Err(self.error_current("type packs cannot be intersection members"));
        }
        if matches!(&first.kind, TypeKind::Union(_) | TypeKind::Optional(_)) {
            return Err(
                self.error_current("mixing union and intersection types requires parentheses")
            );
        }
        let mut members = vec![first];
        while has_separator {
            let member = self.type_postfix()?;
            if is_type_pack(&member) {
                return Err(self.error_current("type packs cannot be intersection members"));
            }
            if matches!(&member.kind, TypeKind::Union(_) | TypeKind::Optional(_)) {
                return Err(
                    self.error_current("mixing union and intersection types requires parentheses")
                );
            }
            members.push(member);
            has_separator = self.consume("&");
        }
        let end = members.last().map_or(start, |member| member.span.end);
        self.make_type(TypeKind::Intersection(members), start, end)
    }

    fn type_postfix(&mut self) -> Result<TypeExpression, Diagnostic> {
        let mut value = self.type_atom()?;
        let mut chain = 0usize;
        while self.consume("?") {
            self.extend_chain(&mut chain, "type suffix")?;
            if is_type_pack(&value) {
                return Err(self.error_current("type packs cannot be optional"));
            }
            let start = value.span.start;
            let end = self.previous_end();
            value = self.make_type(TypeKind::Optional(Box::new(value)), start, end)?;
        }
        Ok(value)
    }

    fn type_atom(&mut self) -> Result<TypeExpression, Diagnostic> {
        let start = self.current().span.start;
        if self.consume("...") {
            let value = self.type_expression()?;
            let end = value.span.end;
            return self.make_type(TypeKind::Variadic(Box::new(value)), start, end);
        }
        if self.at("typeof") {
            self.advance();
            self.expect("(")?;
            let expression = self.expression(0)?;
            self.expect(")")?;
            return self.make_type(
                TypeKind::Typeof(Box::new(expression)),
                start,
                self.previous_end(),
            );
        }
        if self.consume("nil") {
            return self.make_type(TypeKind::Nil, start, self.previous_end());
        }
        if self.consume("true") {
            return self.make_type(TypeKind::BooleanSingleton(true), start, self.previous_end());
        }
        if self.consume("false") {
            return self.make_type(
                TypeKind::BooleanSingleton(false),
                start,
                self.previous_end(),
            );
        }
        if self.kind() == TokenKind::String {
            if self.text().starts_with('`') {
                return Err(
                    self.error_current("interpolated strings cannot be used as singleton types")
                );
            }
            let value = self.text().to_owned();
            self.advance();
            return self.make_type(TypeKind::StringSingleton(value), start, self.previous_end());
        }
        if self.kind() == TokenKind::Identifier {
            let mut path = vec![self.name("expected type name")?];
            while self.consume(".") {
                path.push(self.name("expected type name after '.'")?);
            }
            if self.consume("...") {
                if path.len() != 1 {
                    return Err(self.error_current("qualified names cannot be generic type packs"));
                }
                return self.make_type(
                    TypeKind::GenericPack(path.remove(0)),
                    start,
                    self.previous_end(),
                );
            }
            let arguments = if self.consume("<") {
                let mut arguments = Vec::new();
                if !self.consume(">") {
                    loop {
                        let value = self.type_expression_allow_pack()?;
                        arguments.push(type_argument(value));
                        if self.consume(">") {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                arguments
            } else {
                Vec::new()
            };
            return self.make_type(
                TypeKind::Named { path, arguments },
                start,
                self.previous_end(),
            );
        }
        if self.at("{") {
            return self.table_type();
        }
        if self.consume("(") {
            return self.parenthesized_type(start, Vec::new());
        }
        if self.at("<") {
            let generics = self.generic_parameter_list(false)?;
            self.expect("(")?;
            return self.parenthesized_type(start, generics);
        }
        Err(self.error_current("expected type expression"))
    }

    fn parenthesized_type(
        &mut self,
        start: usize,
        generics: Vec<GenericParameter>,
    ) -> Result<TypeExpression, Diagnostic> {
        let mut parameters = Vec::new();
        if !self.consume(")") {
            loop {
                let parameter_start = self.current().span.start;
                let name = if self.kind() == TokenKind::Identifier && self.peek_text(1) == ":" {
                    let name = self.name("expected type parameter name")?;
                    self.expect(":")?;
                    Some(name)
                } else {
                    None
                };
                let value = self.type_expression_allow_pack()?;
                let is_pack = is_type_pack(&value);
                let end = value.span.end;
                parameters.push(TypeParameter {
                    name,
                    value,
                    span: Span::new(parameter_start, end),
                });
                if self.consume(")") {
                    break;
                }
                if is_pack {
                    return Err(
                        self.error_current("a type pack must be the final function parameter")
                    );
                }
                self.expect(",")?;
            }
        }
        if self.consume("->") {
            let returns = self.type_expression_allow_pack()?;
            let end = returns.span.end;
            self.make_type(
                TypeKind::Function {
                    generics,
                    parameters,
                    returns: Box::new(returns),
                },
                start,
                end,
            )
        } else {
            if !generics.is_empty() {
                return Err(
                    self.error_current("generic type parameter list requires a function type")
                );
            }
            let mut values: Vec<_> = parameters
                .into_iter()
                .map(|parameter| parameter.value)
                .collect();
            let end = self.previous_end();
            if values.len() == 1 {
                self.make_type(TypeKind::Group(Box::new(values.remove(0))), start, end)
            } else {
                self.make_type(TypeKind::Tuple(values), start, end)
            }
        }
    }

    fn table_type(&mut self) -> Result<TypeExpression, Diagnostic> {
        let start = self.current().span.start;
        self.expect("{")?;
        let mut fields = Vec::new();
        let mut has_indexer = false;
        if !self.consume("}") {
            loop {
                let field_start = self.current().span.start;
                let access = if self.kind() == TokenKind::Identifier
                    && self.text() == "read"
                    && self.peek_text(1) != ":"
                {
                    self.advance();
                    TypeAccess::Read
                } else if self.kind() == TokenKind::Identifier
                    && self.text() == "write"
                    && self.peek_text(1) != ":"
                {
                    self.advance();
                    TypeAccess::Write
                } else {
                    TypeAccess::ReadWrite
                };

                if self.consume("[") {
                    if self.kind() == TokenKind::String
                        && !self.text().starts_with('`')
                        && self.peek_text(1) == "]"
                    {
                        let literal = self.text().to_owned();
                        self.advance();
                        self.expect("]")?;
                        self.expect(":")?;
                        let value = self.type_expression()?;
                        let span = Span::new(field_start, value.span.end);
                        fields.push(TypeField::StringProperty {
                            literal,
                            value,
                            access,
                            span,
                        });
                    } else {
                        if has_indexer {
                            return Err(self.error_current(
                                "table types cannot contain more than one indexer",
                            ));
                        }
                        has_indexer = true;
                        let key = self.type_expression()?;
                        self.expect("]")?;
                        self.expect(":")?;
                        let value = self.type_expression()?;
                        let span = Span::new(field_start, value.span.end);
                        fields.push(TypeField::Indexer {
                            key,
                            value,
                            access,
                            span,
                        });
                    }
                } else if self.kind() == TokenKind::Identifier && self.peek_text(1) == ":" {
                    let name = self.name("expected table type property")?;
                    self.expect(":")?;
                    let value = self.type_expression()?;
                    let span = Span::new(field_start, value.span.end);
                    fields.push(TypeField::Property {
                        name,
                        value,
                        access,
                        span,
                    });
                } else if fields.is_empty() {
                    let value = self.type_expression()?;
                    let span = Span::new(field_start, value.span.end);
                    fields.push(TypeField::Array {
                        value,
                        access,
                        span,
                    });
                    self.expect("}")?;
                    break;
                } else {
                    return Err(self.error_current("expected table type field"));
                }

                if self.consume(",") || self.consume(";") {
                    if self.consume("}") {
                        break;
                    }
                } else {
                    self.expect("}")?;
                    break;
                }
            }
        }
        self.make_type(TypeKind::Table(fields), start, self.previous_end())
    }

    fn record_value_export(&mut self, name: &Name) -> Result<(), Diagnostic> {
        if self.has_module_return {
            return Err(self.error_current("exported values are incompatible with a module return"));
        }
        self.has_value_exports = true;
        if self.exported_values.insert(name.value.clone()) {
            Ok(())
        } else {
            let token = self
                .tokens
                .iter()
                .find(|token| token.span.start == name.span.start)
                .unwrap_or(self.current());
            Err(Diagnostic::at(
                format!("duplicate exported identifier '{}'", name.value),
                name.span.start,
                token.line,
                token.column,
            ))
        }
    }

    fn make_expression(
        &mut self,
        kind: ExpressionKind,
        start: usize,
        end: usize,
    ) -> Result<Expression, Diagnostic> {
        self.bump_node()?;
        Ok(Expression {
            kind,
            span: Span::new(start, end),
        })
    }

    fn make_type(
        &mut self,
        kind: TypeKind,
        start: usize,
        end: usize,
    ) -> Result<TypeExpression, Diagnostic> {
        self.bump_node()?;
        Ok(TypeExpression {
            kind,
            span: Span::new(start, end),
        })
    }

    fn name(&mut self, message: &str) -> Result<Name, Diagnostic> {
        if self.kind() != TokenKind::Identifier {
            return Err(self.error_current(message));
        }
        let token = self.current();
        let name = Name {
            value: token.text(self.source).to_owned(),
            span: Span::new(token.span.start, token.span.end),
        };
        self.advance();
        self.bump_node()?;
        Ok(name)
    }

    fn bump_node(&mut self) -> Result<(), Diagnostic> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or_else(|| self.error_current("AST node count overflow"))?;
        if self.nodes > MAX_NODES {
            Err(self.error_current("AST node count exceeds safety limit"))
        } else {
            Ok(())
        }
    }

    // Iteratively parsed operator/suffix chains still produce recursively
    // owned ASTs. Bound them before construction so dropping even a rejected
    // source cannot overflow the native stack (recursion limits alone do not
    // protect a 100,000-term left-associated expression).
    fn extend_chain(&self, length: &mut usize, what: &str) -> Result<(), Diagnostic> {
        if *length >= MAX_NESTING {
            return Err(self.error_current(format!("{what} chain exceeds safety limit")));
        }
        *length += 1;
        Ok(())
    }

    fn enter(&mut self, what: &str) -> Result<(), Diagnostic> {
        if self.nesting >= MAX_NESTING {
            return Err(self.error_current(format!("{what} nesting exceeds safety limit")));
        }
        self.nesting += 1;
        Ok(())
    }

    fn leave(&mut self) {
        self.nesting -= 1;
    }

    fn at(&self, text: &str) -> bool {
        self.text() == text
    }

    fn consume(&mut self, text: &str) -> bool {
        if self.at(text) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, text: &str) -> Result<(), Diagnostic> {
        if self.consume(text) {
            Ok(())
        } else {
            Err(self.error_current(format!("expected '{text}', found '{}'", self.text())))
        }
    }

    fn expect_eof(&self) -> Result<(), Diagnostic> {
        if self.at_eof() {
            Ok(())
        } else {
            Err(self.error_current(format!("unexpected token '{}'", self.text())))
        }
    }

    fn at_eof(&self) -> bool {
        self.kind() == TokenKind::Eof
    }

    fn advance(&mut self) {
        if !self.at_eof() {
            self.cursor += 1;
        }
    }

    fn current(&self) -> &Token {
        &self.tokens[self.cursor]
    }

    fn kind(&self) -> TokenKind {
        self.current().kind
    }

    fn text(&self) -> &str {
        self.current().text(self.source)
    }

    fn peek_text(&self, distance: usize) -> &str {
        self.cursor
            .checked_add(distance)
            .and_then(|index| self.tokens.get(index))
            .map(|token| token.text(self.source))
            .unwrap_or("")
    }

    fn peek_kind(&self, distance: usize) -> Option<TokenKind> {
        self.cursor
            .checked_add(distance)
            .and_then(|index| self.tokens.get(index))
            .map(|token| token.kind)
    }

    fn previous_end(&self) -> usize {
        self.cursor
            .checked_sub(1)
            .and_then(|index| self.tokens.get(index))
            .map_or(self.current().span.start, |token| token.span.end)
    }

    fn previous_start(&self) -> usize {
        self.cursor
            .checked_sub(1)
            .and_then(|index| self.tokens.get(index))
            .map_or(self.current().span.start, |token| token.span.start)
    }

    fn error_current(&self, message: impl Into<String>) -> Diagnostic {
        let token = self.current();
        Diagnostic::at(message, token.span.start, token.line, token.column)
    }
}

fn valid_deprecated_attribute(argument: &Expression) -> bool {
    let ExpressionKind::Table(fields) = &argument.kind else {
        return false;
    };
    fields.iter().all(|field| {
        let TableField::Record { name, value, .. } = field else {
            return false;
        };
        if !matches!(name.value.as_str(), "use" | "reason") {
            return false;
        }
        matches!(&value.kind, ExpressionKind::String(_))
            || matches!(
                &value.kind,
                ExpressionKind::InterpolatedString { expressions, .. } if expressions.is_empty()
            )
    })
}

fn is_type_pack(value: &TypeExpression) -> bool {
    match &value.kind {
        TypeKind::Tuple(_) | TypeKind::GenericPack(_) | TypeKind::Variadic(_) => true,
        TypeKind::Group(inner) => is_type_pack(inner),
        _ => false,
    }
}

fn type_argument(value: TypeExpression) -> TypeArgument {
    if matches!(
        &value.kind,
        TypeKind::GenericPack(_) | TypeKind::Variadic(_)
    ) {
        TypeArgument::Pack(value)
    } else {
        TypeArgument::Type(value)
    }
}

fn unary_operator(text: &str, _target: Target) -> Option<UnaryOperator> {
    match text {
        "not" => Some(UnaryOperator::Not),
        "-" => Some(UnaryOperator::Negate),
        "#" => Some(UnaryOperator::Length),
        _ => None,
    }
}

fn compound_operator(text: &str) -> Option<BinaryOperator> {
    match text {
        "+=" => Some(BinaryOperator::Add),
        "-=" => Some(BinaryOperator::Subtract),
        "*=" => Some(BinaryOperator::Multiply),
        "/=" => Some(BinaryOperator::Divide),
        "//=" => Some(BinaryOperator::FloorDivide),
        "%=" => Some(BinaryOperator::Modulo),
        "^=" => Some(BinaryOperator::Power),
        "..=" => Some(BinaryOperator::Concat),
        _ => None,
    }
}

fn infix_operator(text: &str, target: Target) -> Option<(BinaryOperator, u8, u8)> {
    let (operator, precedence, right_associative) = match text {
        "or" => (BinaryOperator::Or, 1, false),
        "and" => (BinaryOperator::And, 2, false),
        "<" => (BinaryOperator::Less, 3, false),
        ">" => (BinaryOperator::Greater, 3, false),
        "<=" => (BinaryOperator::LessEqual, 3, false),
        ">=" => (BinaryOperator::GreaterEqual, 3, false),
        "~=" => (BinaryOperator::NotEqual, 3, false),
        "==" => (BinaryOperator::Equal, 3, false),
        ".." => (BinaryOperator::Concat, 4, true),
        "+" => (BinaryOperator::Add, 5, false),
        "-" => (BinaryOperator::Subtract, 5, false),
        "*" => (BinaryOperator::Multiply, 6, false),
        "/" => (BinaryOperator::Divide, 6, false),
        "%" => (BinaryOperator::Modulo, 6, false),
        "//" if target.is_luau() => (BinaryOperator::FloorDivide, 6, false),
        "^" => (BinaryOperator::Power, 8, true),
        _ => return None,
    };
    Some(if right_associative {
        (operator, precedence, precedence)
    } else {
        (operator, precedence, precedence + 1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(source: &str, target: Target) -> Result<Chunk, Diagnostic> {
        parse_source(source, target)
    }

    #[test]
    fn builds_lua51_ast_with_precedence_and_control_flow() {
        let source = r#"
            local function sum(t)
                local n = 0
                for i, v in ipairs(t) do
                    if i % 2 == 0 then n = n + v else n = n - v end
                end
                return n
            end
            print(sum({1, 2, 3}))
        "#;
        let chunk = parsed(source, Target::Lua51).unwrap();
        assert_eq!(chunk.block.statements.len(), 2);
        assert!(matches!(
            chunk.block.statements[0].kind,
            StatementKind::LocalFunction { .. }
        ));
        assert!(matches!(
            chunk.block.statements[1].kind,
            StatementKind::Call(_)
        ));
    }

    #[test]
    fn builds_luau_type_and_extension_nodes() {
        let source = r#"
            export type Pair<T> = {read left: T, right: T}
            local function pick<T>(pair: Pair<T>, yes: boolean): T
                local result: T = if yes then pair.left else pair.right
                return result
            end
            local n = 0b1010_0011
            n += 1
            print(pick({left=n, right=0}, true))
        "#;
        let chunk = parsed(source, Target::Luau).unwrap();
        assert_eq!(chunk.block.statements.len(), 5);
        assert!(matches!(
            chunk.block.statements[0].kind,
            StatementKind::TypeAlias { exported: true, .. }
        ));
        assert!(matches!(
            chunk.block.statements[3].kind,
            StatementKind::CompoundAssignment { .. }
        ));
        assert!(parsed("type(1);type=type;export=2;print(type)", Target::Luau).is_ok());
        assert!(parsed("type=type;print(type)", Target::Lua51).is_ok());
    }

    #[test]
    fn preserves_expression_and_interpolation_spans() {
        let source = "local result = 1 + 2 * 3\nlocal text = `a{result + 1}b{`n{result}`}`";
        let chunk = parsed(source, Target::Luau).unwrap();
        let StatementKind::Local { values, .. } = &chunk.block.statements[0].kind else {
            panic!("expected local declaration");
        };
        let ExpressionKind::Binary {
            operator: BinaryOperator::Add,
            right,
            ..
        } = &values[0].kind
        else {
            panic!("expected addition expression");
        };
        assert!(matches!(
            right.kind,
            ExpressionKind::Binary {
                operator: BinaryOperator::Multiply,
                ..
            }
        ));
        assert_eq!(
            &source[values[0].span.start..values[0].span.end],
            "1 + 2 * 3"
        );

        let StatementKind::Local { values, .. } = &chunk.block.statements[1].kind else {
            panic!("expected interpolated local declaration");
        };
        let ExpressionKind::InterpolatedString {
            strings,
            expressions,
        } = &values[0].kind
        else {
            panic!("expected interpolated string");
        };
        assert_eq!(
            strings
                .iter()
                .map(|part| part.value.as_str())
                .collect::<Vec<_>>(),
            ["a", "b", ""]
        );
        assert_eq!(expressions.len(), 2);
        assert_eq!(
            &source[expressions[0].span.start..expressions[0].span.end],
            "result + 1"
        );
        assert!(matches!(
            expressions[1].kind,
            ExpressionKind::InterpolatedString { .. }
        ));
    }

    #[test]
    fn parses_extended_luau_declarations_and_type_packs() {
        let source = r#"
            @[checked] export function id<T>(value: T): T return value end
            export const answer: number = 0x_2
            type Pack<T...> = (T...) -> T...
            type function Identity(kind) return kind end
            local value = id<<number>>(if answer > 0 then answer elseif answer < 0 then -answer else 0)
        "#;
        let chunk = parsed(source, Target::Luau).unwrap();
        assert_eq!(chunk.block.statements.len(), 5);
        assert!(matches!(
            chunk.block.statements[0].kind,
            StatementKind::LocalFunction {
                is_const: true,
                exported: true,
                ..
            }
        ));
        assert!(matches!(
            chunk.block.statements[3].kind,
            StatementKind::TypeFunction { .. }
        ));
        assert!(parsed("const missing", Target::Luau).is_err());
        assert!(parsed("type Invalid = (number, string)", Target::Luau).is_err());
        assert!(parsed("type Invalid = number & string?", Target::Luau).is_err());
    }

    #[test]
    fn rejects_invalid_context_and_incomplete_blocks() {
        assert!(parsed("if true then print(1)", Target::Lua51).is_err());
        assert!(parsed("local x =", Target::Luau).is_err());
        assert!(parsed("break", Target::Lua51).is_err());
        assert!(parsed("local function f() return ... end", Target::Lua51).is_err());
        assert!(parsed("return 1 print(2)", Target::Lua51).is_err());
        assert!(parsed("; local x = 1", Target::Lua51).is_err());
        assert!(parsed("local x = 1;; local y = 2", Target::Luau).is_err());
        assert!(parsed("local x: number = 1", Target::Lua51).is_err());
        assert!(parsed("local x = 0b10", Target::Lua51).is_err());
        assert!(parsed("continue", Target::Lua51).is_err());
        assert!(parsed("return ~1", Target::Luau).is_err());
        assert!(parsed("local x = `value {}`", Target::Luau).is_err());
    }

    #[test]
    fn rejects_malformed_external_token_streams_without_panicking() {
        assert!(parse("", &[], Target::Lua51).is_err());
        let bad = vec![Token {
            kind: TokenKind::Eof,
            span: 1..2,
            line: 1,
            column: 1,
        }];
        assert!(parse("", &bad, Target::Luau).is_err());
        let omitted = vec![Token {
            kind: TokenKind::Eof,
            span: 4..4,
            line: 1,
            column: 5,
        }];
        assert!(parse("name", &omitted, Target::Lua51).is_err());

        let source = "name";
        for start in 0..=source.len() + 1 {
            for end in 0..=source.len() + 1 {
                let tokens = vec![
                    Token {
                        kind: TokenKind::Identifier,
                        span: start..end,
                        line: 1,
                        column: 1,
                    },
                    Token {
                        kind: TokenKind::Eof,
                        span: source.len()..source.len(),
                        line: 1,
                        column: source.len() + 1,
                    },
                ];
                let result = std::panic::catch_unwind(|| parse(source, &tokens, Target::Lua51));
                assert!(result.is_ok(), "malformed token stream panicked");
            }
        }
    }

    #[test]
    fn enforces_nesting_limit() {
        let source = format!("return {}1{}", "(".repeat(300), ")".repeat(300));
        let result = parsed(&source, Target::Lua51);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("nesting"));

        let nested_interpolation = format!("local x = {}1{}", "`{".repeat(100), "}`".repeat(100));
        let result = parsed(&nested_interpolation, Target::Luau);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("nesting"));
    }
}

#[cfg(test)]
mod formatting_tests {
    use super::*;

    #[test]
    fn statement_sidecar_keeps_the_same_ast_and_global_offsets_in_fragments() {
        let lua51 = "local f=(function()local x=1;return x end)();print(f)";
        let luau = concat!(
            "local text=`{(function()local x=1 ",
            "return `inner {(function()return x end)()}` end)()}`;print(text)"
        );
        for (source, target, count) in [(lua51, Target::Lua51, 4), (luau, Target::Luau, 5)] {
            let tokens = lexer::lex(source, target).unwrap();
            let (chunk, ends) = parse_with_statement_ends(source, &tokens, target).unwrap();
            assert_eq!(chunk, parse(source, &tokens, target).unwrap());
            assert_eq!(ends.len(), count);
            assert!(ends.windows(2).all(|w| w[0] < w[1]));
            assert_eq!(ends.last(), Some(&source.len()));
            for &end in &ends {
                assert!(source.is_char_boundary(end));
                assert_ne!(source.as_bytes()[end - 1], b';');
            }
            assert!(parse_lexed_inner(source, &tokens, target, false)
                .unwrap()
                .1
                .is_empty());
        }
    }

    #[test]
    fn many_sibling_statements_keep_a_bounded_sorted_sidecar() {
        let source = "do local value=1 end ".repeat(10_000);
        let tokens = lexer::lex(&source, Target::Lua51).unwrap();
        let (_, ends) = parse_lexed_with_statement_ends(&source, &tokens, Target::Lua51).unwrap();
        assert_eq!(ends.len(), 20_000);
        assert!(ends.windows(2).all(|w| w[0] < w[1]));
    }
}
