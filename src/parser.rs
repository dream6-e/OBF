use crate::lexer::{Token, TokenKind};
use crate::{Diagnostic, Target};

pub fn parse(source: &str, tokens: &[Token], target: Target) -> Result<(), Diagnostic> {
    let mut parser = Parser {
        source,
        tokens,
        target,
        cursor: 0,
        function_depth: 0,
        loop_depth: 0,
    };
    parser.block(&[])?;
    parser.expect_eof()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExprClass {
    Value,
    Assignable,
    Call,
}

struct Parser<'a> {
    source: &'a str,
    tokens: &'a [Token],
    target: Target,
    cursor: usize,
    function_depth: usize,
    loop_depth: usize,
}

impl<'a> Parser<'a> {
    fn block(&mut self, terminators: &[&str]) -> Result<(), Diagnostic> {
        while !self.at_eof() && !terminators.iter().any(|word| self.at(word)) {
            self.statement()?;
        }
        Ok(())
    }

    fn statement(&mut self) -> Result<(), Diagnostic> {
        if self.consume(";") {
            return Ok(());
        }
        if self.at("if") {
            return self.if_statement();
        }
        if self.at("while") {
            return self.while_statement();
        }
        if self.at("repeat") {
            return self.repeat_statement();
        }
        if self.at("for") {
            return self.for_statement();
        }
        if self.at("do") {
            self.advance();
            self.block(&["end"])?;
            return self.expect("end");
        }
        if self.at("function") {
            return self.function_statement();
        }
        if self.at("local") {
            return self.local_statement();
        }
        if self.at("return") {
            return self.return_statement();
        }
        if self.at("break") {
            if self.loop_depth == 0 {
                return Err(self.error_current("'break' used outside a loop"));
            }
            self.advance();
            self.consume(";");
            return Ok(());
        }
        if self.at("continue") {
            if !self.target.is_luau() {
                return Err(self.error_current("'continue' is only valid for Luau"));
            }
            if self.loop_depth == 0 {
                return Err(self.error_current("'continue' used outside a loop"));
            }
            self.advance();
            self.consume(";");
            return Ok(());
        }
        if self.at("type") || self.at("export") {
            return self.type_declaration();
        }

        self.assignment_or_call()
    }

    fn if_statement(&mut self) -> Result<(), Diagnostic> {
        self.expect("if")?;
        self.expression(0)?;
        self.expect("then")?;
        self.block(&["elseif", "else", "end"])?;
        while self.consume("elseif") {
            self.expression(0)?;
            self.expect("then")?;
            self.block(&["elseif", "else", "end"])?;
        }
        if self.consume("else") {
            self.block(&["end"])?;
        }
        self.expect("end")
    }

    fn while_statement(&mut self) -> Result<(), Diagnostic> {
        self.expect("while")?;
        self.expression(0)?;
        self.expect("do")?;
        self.loop_depth += 1;
        let result = self.block(&["end"]);
        self.loop_depth -= 1;
        result?;
        self.expect("end")
    }

    fn repeat_statement(&mut self) -> Result<(), Diagnostic> {
        self.expect("repeat")?;
        self.loop_depth += 1;
        let result = self.block(&["until"]);
        self.loop_depth -= 1;
        result?;
        self.expect("until")?;
        self.expression(0).map(|_| ())
    }

    fn for_statement(&mut self) -> Result<(), Diagnostic> {
        self.expect("for")?;
        self.expect_identifier("expected loop variable after 'for'")?;
        self.optional_type_annotation(&[",", "=", "in"])?;

        if self.consume("=") {
            self.expression(0)?;
            self.expect(",")?;
            self.expression(0)?;
            if self.consume(",") {
                self.expression(0)?;
            }
        } else {
            while self.consume(",") {
                self.expect_identifier("expected loop variable after ','")?;
                self.optional_type_annotation(&[",", "in"])?;
            }
            self.expect("in")?;
            self.expression_list()?;
        }

        self.expect("do")?;
        self.loop_depth += 1;
        let result = self.block(&["end"]);
        self.loop_depth -= 1;
        result?;
        self.expect("end")
    }

    fn function_statement(&mut self) -> Result<(), Diagnostic> {
        self.expect("function")?;
        self.expect_identifier("expected function name")?;
        while self.consume(".") {
            self.expect_identifier("expected field name after '.'")?;
        }
        if self.consume(":") {
            self.expect_identifier("expected method name after ':'")?;
        }
        self.function_body()
    }

    fn local_statement(&mut self) -> Result<(), Diagnostic> {
        self.expect("local")?;
        if self.consume("function") {
            self.expect_identifier("expected local function name")?;
            return self.function_body();
        }

        self.expect_identifier("expected local variable name")?;
        self.optional_type_annotation(&[",", "="])?;
        while self.consume(",") {
            self.expect_identifier("expected local variable name after ','")?;
            self.optional_type_annotation(&[",", "="])?;
        }
        if self.consume("=") {
            self.expression_list()?;
        }
        Ok(())
    }

    fn return_statement(&mut self) -> Result<(), Diagnostic> {
        self.expect("return")?;
        if !self.at_eof() && !matches!(self.text(), "end" | "else" | "elseif" | "until" | ";") {
            self.expression_list()?;
        }
        self.consume(";");
        Ok(())
    }

    fn assignment_or_call(&mut self) -> Result<(), Diagnostic> {
        let first = self.expression(0)?;
        let compound = self.target.is_luau()
            && matches!(
                self.text(),
                "+=" | "-=" | "*=" | "/=" | "//=" | "%=" | "^=" | "..="
            );

        if compound {
            if first != ExprClass::Assignable {
                return Err(
                    self.error_current("left side of compound assignment is not assignable")
                );
            }
            self.advance();
            self.expression(0)?;
            return Ok(());
        }

        if self.at(",") || self.at("=") {
            if first != ExprClass::Assignable {
                return Err(self.error_current("left side of assignment is not assignable"));
            }
            while self.consume(",") {
                let class = self.expression(0)?;
                if class != ExprClass::Assignable {
                    return Err(self.error_current("left side of assignment is not assignable"));
                }
            }
            self.expect("=")?;
            self.expression_list()?;
            Ok(())
        } else if first == ExprClass::Call {
            Ok(())
        } else {
            Err(self.error_current("expected assignment or function call statement"))
        }
    }

    fn expression_list(&mut self) -> Result<(), Diagnostic> {
        self.expression(0)?;
        while self.consume(",") {
            self.expression(0)?;
        }
        Ok(())
    }

    fn expression(&mut self, min_binding_power: u8) -> Result<ExprClass, Diagnostic> {
        let mut class = if matches!(self.text(), "not" | "-" | "#" | "~") {
            if self.at("~") && !self.target.is_luau() {
                return Err(self.error_current("bitwise '~' is only valid for Luau"));
            }
            self.advance();
            self.expression(7)?;
            ExprClass::Value
        } else {
            self.primary()?
        };

        loop {
            if self.target.is_luau() && self.consume("::") {
                self.type_expression()?;
                class = ExprClass::Value;
                continue;
            }

            let Some((left, right)) = infix_binding_power(self.text(), self.target) else {
                break;
            };
            if left < min_binding_power {
                break;
            }
            self.advance();
            self.expression(right)?;
            class = ExprClass::Value;
        }
        Ok(class)
    }

    fn primary(&mut self) -> Result<ExprClass, Diagnostic> {
        if matches!(self.text(), "nil" | "false" | "true" | "...")
            || matches!(self.kind(), TokenKind::Number | TokenKind::String)
        {
            self.advance();
            return Ok(ExprClass::Value);
        }
        if self.consume("function") {
            self.function_body()?;
            return Ok(ExprClass::Value);
        }
        if self.at("{") {
            self.table_constructor()?;
            return Ok(ExprClass::Value);
        }
        if self.at("if") && self.target.is_luau() {
            return self.if_expression();
        }

        let mut class = if self.kind() == TokenKind::Identifier {
            self.advance();
            ExprClass::Assignable
        } else if self.consume("(") {
            self.expression(0)?;
            self.expect(")")?;
            ExprClass::Value
        } else {
            return Err(self.error_current("expected expression"));
        };

        loop {
            if self.consume(".") {
                self.expect_identifier("expected field name after '.'")?;
                class = ExprClass::Assignable;
            } else if self.consume("[") {
                self.expression(0)?;
                self.expect("]")?;
                class = ExprClass::Assignable;
            } else if self.consume(":") {
                self.expect_identifier("expected method name after ':'")?;
                self.call_arguments()?;
                class = ExprClass::Call;
            } else if self.starts_call_arguments() {
                self.call_arguments()?;
                class = ExprClass::Call;
            } else {
                break;
            }
        }
        Ok(class)
    }

    fn if_expression(&mut self) -> Result<ExprClass, Diagnostic> {
        self.expect("if")?;
        self.expression(0)?;
        self.expect("then")?;
        self.expression(0)?;
        self.expect("else")?;
        if self.at("if") {
            self.if_expression()?;
        } else {
            self.expression(0)?;
        }
        Ok(ExprClass::Value)
    }

    fn call_arguments(&mut self) -> Result<(), Diagnostic> {
        if self.consume("(") {
            if !self.consume(")") {
                self.expression_list()?;
                self.expect(")")?;
            }
            Ok(())
        } else if self.at("{") {
            self.table_constructor()
        } else if self.kind() == TokenKind::String {
            self.advance();
            Ok(())
        } else {
            Err(self.error_current("expected function call arguments"))
        }
    }

    fn starts_call_arguments(&self) -> bool {
        self.at("(") || self.at("{") || self.kind() == TokenKind::String
    }

    fn table_constructor(&mut self) -> Result<(), Diagnostic> {
        self.expect("{")?;
        if self.consume("}") {
            return Ok(());
        }
        loop {
            if self.consume("[") {
                self.expression(0)?;
                self.expect("]")?;
                self.expect("=")?;
                self.expression(0)?;
            } else if self.kind() == TokenKind::Identifier && self.peek_text(1) == "=" {
                self.advance();
                self.expect("=")?;
                self.expression(0)?;
            } else {
                self.expression(0)?;
            }

            if self.consume(",") || self.consume(";") {
                if self.consume("}") {
                    return Ok(());
                }
            } else {
                return self.expect("}");
            }
        }
    }

    fn function_body(&mut self) -> Result<(), Diagnostic> {
        if self.target.is_luau() && self.at("<") {
            self.generic_parameter_list()?;
        }
        self.expect("(")?;
        if !self.consume(")") {
            loop {
                if self.consume("...") {
                    self.optional_type_annotation(&[","])?;
                    self.expect(")")?;
                    break;
                }
                self.expect_identifier("expected parameter name")?;
                self.optional_type_annotation(&[",", ")"])?;
                if self.consume(")") {
                    break;
                }
                self.expect(",")?;
            }
        }
        if self.target.is_luau() && self.consume(":") {
            self.type_expression()?;
        }

        self.function_depth += 1;
        let saved_loop_depth = self.loop_depth;
        self.loop_depth = 0;
        let result = self.block(&["end"]);
        self.loop_depth = saved_loop_depth;
        self.function_depth -= 1;
        result?;
        self.expect("end")
    }

    fn generic_parameter_list(&mut self) -> Result<(), Diagnostic> {
        self.expect("<")?;
        loop {
            self.expect_identifier("expected generic parameter")?;
            self.consume("...");
            if self.consume("=") {
                self.type_expression()?;
            }
            if self.consume(">") {
                return Ok(());
            }
            self.expect(",")?;
        }
    }

    fn optional_type_annotation(&mut self, _stops: &[&str]) -> Result<(), Diagnostic> {
        if self.consume(":") {
            if !self.target.is_luau() {
                return Err(self.error_current("type annotations are only valid for Luau"));
            }
            self.type_expression()?;
        }
        Ok(())
    }

    fn type_declaration(&mut self) -> Result<(), Diagnostic> {
        if !self.target.is_luau() {
            return Err(self.error_current("type declarations are only valid for Luau"));
        }
        if self.consume("export") {
            self.expect("type")?;
        } else {
            self.expect("type")?;
        }
        self.expect_identifier("expected type alias name")?;
        if self.at("<") {
            self.generic_parameter_list()?;
        }
        self.expect("=")?;
        self.type_expression()
    }

    fn type_expression(&mut self) -> Result<(), Diagnostic> {
        self.type_union()
    }

    fn type_union(&mut self) -> Result<(), Diagnostic> {
        self.type_intersection()?;
        while self.consume("|") {
            self.type_intersection()?;
        }
        Ok(())
    }

    fn type_intersection(&mut self) -> Result<(), Diagnostic> {
        self.type_postfix()?;
        while self.consume("&") {
            self.type_postfix()?;
        }
        Ok(())
    }

    fn type_postfix(&mut self) -> Result<(), Diagnostic> {
        self.type_atom()?;
        while self.consume("?") {}
        Ok(())
    }

    fn type_atom(&mut self) -> Result<(), Diagnostic> {
        if self.consume("typeof") {
            self.expect("(")?;
            self.expression(0)?;
            return self.expect(")");
        }
        if self.kind() == TokenKind::Identifier
            || matches!(self.text(), "nil" | "true" | "false")
            || self.kind() == TokenKind::String
        {
            self.advance();
            while self.consume(".") {
                self.expect_identifier("expected type name after '.'")?;
            }
            if self.consume("<") {
                loop {
                    self.type_expression()?;
                    self.consume("...");
                    if self.consume(">") {
                        break;
                    }
                    self.expect(",")?;
                }
            }
            return Ok(());
        }
        if self.consume("{") {
            if self.consume("}") {
                return Ok(());
            }
            loop {
                if self.consume("[") {
                    self.type_expression()?;
                    self.expect("]")?;
                    self.expect(":")?;
                    self.type_expression()?;
                } else if self.kind() == TokenKind::Identifier && self.peek_text(1) == ":" {
                    self.advance();
                    self.expect(":")?;
                    self.type_expression()?;
                } else {
                    self.type_expression()?;
                }
                if self.consume("}") {
                    return Ok(());
                }
                if !(self.consume(",") || self.consume(";")) {
                    return Err(self.error_current("expected ',', ';', or '}' in table type"));
                }
                if self.consume("}") {
                    return Ok(());
                }
            }
        }
        if self.consume("(") {
            if !self.consume(")") {
                loop {
                    if self.kind() == TokenKind::Identifier && self.peek_text(1) == ":" {
                        self.advance();
                        self.expect(":")?;
                    }
                    self.type_expression()?;
                    self.consume("...");
                    if self.consume(")") {
                        break;
                    }
                    self.expect(",")?;
                }
            }
            if self.consume("->") {
                self.type_expression()?;
            }
            return Ok(());
        }
        Err(self.error_current("expected type expression"))
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

    fn expect_identifier(&mut self, message: &str) -> Result<(), Diagnostic> {
        if self.kind() == TokenKind::Identifier {
            self.advance();
            Ok(())
        } else {
            Err(self.error_current(message))
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
        // The lexer always appends EOF. Gracefully use the last token if a
        // caller supplies a malformed token array.
        self.tokens
            .get(self.cursor)
            .unwrap_or_else(|| self.tokens.last().expect("parser requires at least EOF"))
    }

    fn kind(&self) -> TokenKind {
        self.current().kind
    }

    fn text(&self) -> &str {
        self.current().text(self.source)
    }

    fn peek_text(&self, distance: usize) -> &str {
        self.tokens
            .get(self.cursor + distance)
            .map(|token| token.text(self.source))
            .unwrap_or("")
    }

    fn error_current(&self, message: impl Into<String>) -> Diagnostic {
        let token = self.current();
        Diagnostic::at(message, token.span.start, token.line, token.column)
    }
}

fn infix_binding_power(operator: &str, target: Target) -> Option<(u8, u8)> {
    let precedence = match operator {
        "or" => (1, false),
        "and" => (2, false),
        "<" | ">" | "<=" | ">=" | "~=" | "==" => (3, false),
        ".." => (4, true),
        "+" | "-" => (5, false),
        "*" | "/" | "%" => (6, false),
        "//" if target.is_luau() => (6, false),
        "^" => (8, true),
        _ => return None,
    };
    let (power, right_associative) = precedence;
    Some(if right_associative {
        (power, power)
    } else {
        (power, power + 1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer;

    fn parses(source: &str, target: Target) -> bool {
        let tokens = lexer::lex(source, target).unwrap();
        parse(source, &tokens, target).is_ok()
    }

    #[test]
    fn parses_lua51_control_flow() {
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
        assert!(parses(source, Target::Lua51));
    }

    #[test]
    fn parses_luau_types_and_extensions() {
        let source = r#"
            export type Pair<T> = {left: T, right: T}
            local function pick<T>(pair: Pair<T>, yes: boolean): T
                local result: T = if yes then pair.left else pair.right
                return result
            end
            local n = 0b1010_0011
            n += 1
            print(pick({left=n, right=0}, true))
        "#;
        assert!(parses(source, Target::Luau));
    }

    #[test]
    fn rejects_incomplete_blocks() {
        assert!(!parses("if true then print(1)", Target::Lua51));
        assert!(!parses("local x =", Target::Luau));
    }
}
