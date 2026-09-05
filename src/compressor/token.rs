#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Keyword,
    Identifier,
    Number,
    StringLiteral,
    Symbol,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub text: String,
    pub token_type: TokenType,
}