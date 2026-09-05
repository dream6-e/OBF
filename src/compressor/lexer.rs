use std::collections::HashSet;
use super::token::{Token, TokenType};

pub struct Lexer<'a> {
    input: &'a str,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input }
    }

    pub fn tokenize(&self) -> Vec<Token> {
        let chars: Vec<char> = self.input.chars().collect();
        let mut tokens = Vec::new();
        let mut i = 0;
        let len = chars.len();

        let keywords: HashSet<&str> = [
            "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
            "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
            "true", "until", "while",
        ]
        .iter()
        .cloned()
        .collect();

        while i < len {
            if chars[i].is_whitespace() {
                i += 1;
                continue;
            }

            if i + 1 < len && chars[i] == '-' && chars[i + 1] == '-' {
                i += 2;
                if i + 1 < len && chars[i] == '[' && (chars[i + 1] == '[' || chars[i + 1] == '=') {
                    let mut sep_len = 0;
                    let mut j = i + 1;
                    while j < len && chars[j] == '=' {
                        sep_len += 1;
                        j += 1;
                    }
                    if j < len && chars[j] == '[' {
                        i = j + 1;
                        loop {
                            if i + sep_len + 1 >= len {
                                i = len;
                                break;
                            }
                            if chars[i] == ']' {
                                let mut match_eq = true;
                                for k in 0..sep_len {
                                    if chars[i + 1 + k] != '=' {
                                        match_eq = false;
                                        break;
                                    }
                                }
                                if match_eq && chars[i + 1 + sep_len] == ']' {
                                    i += sep_len + 2;
                                    break;
                                }
                            }
                            i += 1;
                        }
                        continue;
                    }
                }
                while i < len && chars[i] != '\n' && chars[i] != '\r' {
                    i += 1;
                }
                continue;
            }

            if chars[i] == '"' || chars[i] == '\'' {
                let quote = chars[i];
                let start = i;
                i += 1;
                while i < len && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < len {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < len {
                    i += 1;
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::StringLiteral,
                });
                continue;
            }

            if chars[i] == '[' && i + 1 < len && (chars[i + 1] == '[' || chars[i + 1] == '=') {
                let mut sep_len = 0;
                let mut j = i + 1;
                while j < len && chars[j] == '=' {
                    sep_len += 1;
                    j += 1;
                }
                if j < len && chars[j] == '[' {
                    let start = i;
                    i = j + 1;
                    loop {
                        if i + sep_len + 1 >= len {
                            i = len;
                            break;
                        }
                        if chars[i] == ']' {
                            let mut match_eq = true;
                            for k in 0..sep_len {
                                if chars[i + 1 + k] != '=' {
                                    match_eq = false;
                                    break;
                                }
                            }
                            if match_eq && chars[i + 1 + sep_len] == ']' {
                                i += sep_len + 2;
                                break;
                            }
                        }
                        i += 1;
                    }
                    tokens.push(Token {
                        text: chars[start..i].iter().collect(),
                        token_type: TokenType::StringLiteral,
                    });
                    continue;
                }
            }

            if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
                let start = i;
                while i < len && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if keywords.contains(word.as_str()) {
                    tokens.push(Token {
                        text: word,
                        token_type: TokenType::Keyword,
                    });
                } else {
                    tokens.push(Token {
                        text: word,
                        token_type: TokenType::Identifier,
                    });
                }
                continue;
            }

            if chars[i].is_ascii_digit()
                || (chars[i] == '.' && i + 1 < len && chars[i + 1].is_ascii_digit())
            {
                let start = i;
                if chars[i] == '0' && i + 1 < len && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
                    i += 2;
                    while i < len && chars[i].is_ascii_hexdigit() {
                        i += 1;
                    }
                } else {
                    while i < len && (chars[i].is_ascii_digit() || chars[i] == '.') {
                        i += 1;
                    }
                    if i < len && (chars[i] == 'e' || chars[i] == 'E') {
                        i += 1;
                        if i + 1 < len && (chars[i] == '+' || chars[i] == '-') {
                            i += 1;
                        }
                        while i < len && chars[i].is_ascii_digit() {
                            i += 1;
                        }
                    }
                }
                tokens.push(Token {
                    text: chars[start..i].iter().collect(),
                    token_type: TokenType::Number,
                });
                continue;
            }

            let start = i;
            if i + 2 < len && chars[start..start + 3] == ['.', '.', '.'] {
                i += 3;
            } else if i + 1 < len
                && (chars[start..start + 2] == ['.', '.']
                    || chars[start..start + 2] == ['=', '=']
                    || chars[start..start + 2] == ['~', '=']
                    || chars[start..start + 2] == ['<', '=']
                    || chars[start..start + 2] == ['>', '='])
            {
                i += 2;
            } else {
                i += 1;
            }
            tokens.push(Token {
                text: chars[start..i].iter().collect(),
                token_type: TokenType::Symbol,
            });
        }

        tokens
    }
}