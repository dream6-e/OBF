use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: u32,
    pub column: u32,
}

impl Span {
    #[must_use]
    pub fn new(line: u32, column: u32) -> Self {
        Self { line, column }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    And,
    Break,
    Continue,
    Do,
    Else,
    ElseIf,
    End,
    False,
    For,
    Function,
    If,
    In,
    Local,
    Nil,
    Not,
    Or,
    Repeat,
    Return,
    Then,
    True,
    Until,
    While,
    Concat,
    Dots,
    Eq,
    Ge,
    Le,
    Ne,
    PlusEq,
    MinusEq,
    MulEq,
    DivEq,
    ModEq,
    PowEq,
    ConcatEq,
    FloorDiv,
    FloorDivEq,
    ColonColon,
    Arrow,
    BAnd,
    BOr,
    BXor,
    Shl,
    Shr,
    Number(f64),
    Name(String),
    Str(Vec<u8>),
    Char(u8),
    Eos,
}

#[inline]
pub(crate) fn lookup_keyword(bytes: &[u8]) -> Option<Token> {
    let &first = bytes.first()?;
    match (bytes.len(), first) {
        (2, b'd') if bytes == b"do" => Some(Token::Do),
        (2, b'i') => {
            if bytes[1] == b'f' {
                Some(Token::If)
            } else if bytes[1] == b'n' {
                Some(Token::In)
            } else {
                None
            }
        }
        (2, b'o') if bytes[1] == b'r' => Some(Token::Or),
        (3, b'a') if bytes == b"and" => Some(Token::And),
        (3, b'e') if bytes == b"end" => Some(Token::End),
        (3, b'f') if bytes == b"for" => Some(Token::For),
        (3, b'n') => {
            if bytes == b"nil" {
                Some(Token::Nil)
            } else if bytes == b"not" {
                Some(Token::Not)
            } else {
                None
            }
        }
        (4, b'e') if bytes == b"else" => Some(Token::Else),
        (4, b't') => {
            if bytes == b"then" {
                Some(Token::Then)
            } else if bytes == b"true" {
                Some(Token::True)
            } else {
                None
            }
        }
        (5, b'b') if bytes == b"break" => Some(Token::Break),
        (5, b'f') if bytes == b"false" => Some(Token::False),
        (5, b'l') if bytes == b"local" => Some(Token::Local),
        (5, b'u') if bytes == b"until" => Some(Token::Until),
        (5, b'w') if bytes == b"while" => Some(Token::While),
        (6, b'e') if bytes == b"elseif" => Some(Token::ElseIf),
        (6, b'r') => {
            if bytes == b"repeat" {
                Some(Token::Repeat)
            } else if bytes == b"return" {
                Some(Token::Return)
            } else {
                None
            }
        }
        (8, b'c') if bytes == b"continue" => Some(Token::Continue),
        (8, b'f') if bytes == b"function" => Some(Token::Function),
        _ => None,
    }
}

impl Token {
    #[must_use]
    pub fn token2str(&self) -> String {
        match self {
            Self::And => "and".into(),
            Self::Break => "break".into(),
            Self::Continue => "continue".into(),
            Self::Do => "do".into(),
            Self::Else => "else".into(),
            Self::ElseIf => "elseif".into(),
            Self::End => "end".into(),
            Self::False => "false".into(),
            Self::For => "for".into(),
            Self::Function => "function".into(),
            Self::If => "if".into(),
            Self::In => "in".into(),
            Self::Local => "local".into(),
            Self::Nil => "nil".into(),
            Self::Not => "not".into(),
            Self::Or => "or".into(),
            Self::Repeat => "repeat".into(),
            Self::Return => "return".into(),
            Self::Then => "then".into(),
            Self::True => "true".into(),
            Self::Until => "until".into(),
            Self::While => "while".into(),
            Self::Concat => "..".into(),
            Self::Dots => "...".into(),
            Self::Eq => "==".into(),
            Self::Ge => ">=".into(),
            Self::Le => "<=".into(),
            Self::Ne => "~=".into(),
            Self::PlusEq => "+=".into(),
            Self::MinusEq => "-=".into(),
            Self::MulEq => "*=".into(),
            Self::DivEq => "/=".into(),
            Self::ModEq => "%=".into(),
            Self::PowEq => "^=".into(),
            Self::ConcatEq => "..=".into(),
            Self::FloorDiv => "//".into(),
            Self::FloorDivEq => "//=".into(),
            Self::ColonColon => "::".into(),
            Self::Arrow => "->".into(),
            Self::BAnd => "&".into(),
            Self::BOr => "|".into(),
            Self::BXor => "~".into(),
            Self::Shl => "<<".into(),
            Self::Shr => ">>".into(),
            Self::Number(_) => "<number>".into(),
            Self::Name(_) => "<name>".into(),
            Self::Str(_) => "<string>".into(),
            Self::Char(c) if c.is_ascii_control() => format!("char({c})"),
            Self::Char(c) => format!("{}", char::from(*c)),
            Self::Eos => "<eof>".into(),
        }
    }

    #[must_use]
    pub fn display_name(&self) -> String {
        format!("'{}'", self.token2str())
    }

    #[must_use]
    pub fn txt_token(&self) -> String {
        match self {
            Self::Name(s) => format!("'{s}'"),
            Self::Number(n) => format!("'{n}'"),
            Self::Str(s) => {
                let text = String::from_utf8_lossy(s);
                format!("'{text}'")
            }
            _ => format!("'{}'", self.token2str()),
        }
    }

    #[must_use]
    pub fn is_block_follow(&self) -> bool {
        matches!(
            self,
            Self::Else | Self::ElseIf | Self::End | Self::Until | Self::Eos
        )
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.token2str())
    }
}