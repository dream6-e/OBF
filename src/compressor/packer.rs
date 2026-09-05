use super::token::{Token, TokenType};

pub struct Packer;

impl Packer {
    pub fn pack(tokens: Vec<Token>) -> String {
        let mut output = String::new();
        let mut prev_token: Option<&Token> = None;

        for token in &tokens {
            if let Some(prev) = prev_token {
                let needs_space = match (&prev.token_type, &token.token_type) {
                    (TokenType::Keyword, TokenType::Keyword) => true,
                    (TokenType::Keyword, TokenType::Identifier) => true,
                    (TokenType::Keyword, TokenType::Number) => true,
                    (TokenType::Identifier, TokenType::Keyword) => true,
                    (TokenType::Identifier, TokenType::Identifier) => true,
                    (TokenType::Identifier, TokenType::Number) => true,
                    (TokenType::Number, TokenType::Keyword) => true,
                    (TokenType::Number, TokenType::Identifier) => true,
                    (TokenType::Number, TokenType::Number) => true,
                    _ => false,
                };

                if needs_space {
                    let prev_can_end = match &prev.token_type {
                        TokenType::Identifier | TokenType::Number => true,
                        TokenType::Keyword => {
                            prev.text == "end"
                                || prev.text == "break"
                                || prev.text == "true"
                                || prev.text == "false"
                                || prev.text == "nil"
                        }
                        _ => false,
                    };

                    let next_can_start = match &token.token_type {
                        TokenType::Keyword => {
                            token.text == "local"
                                || token.text == "if"
                                || token.text == "while"
                                || token.text == "for"
                                || token.text == "function"
                                || token.text == "repeat"
                                || token.text == "break"
                                || token.text == "return"
                                || token.text == "goto"
                                || token.text == "end"
                        }
                        _ => false,
                    };

                    let can_use_semi = if prev.text == "return" {
                        token.text == "end"
                    } else {
                        prev_can_end && next_can_start
                    };

                    if can_use_semi {
                        output.push(';');
                    } else {
                        output.push(' ');
                    }
                } else if prev.text == "-" && token.text == "-" {
                    output.push(' ');
                } else if prev.text.ends_with('.') && token.text.starts_with('.') {
                    output.push(' ');
                } else if matches!(prev.token_type, TokenType::Number) && token.text.starts_with('.') {
                    output.push(' ');
                }
            }
            output.push_str(&token.text);
            prev_token = Some(token);
        }

        output
    }
}