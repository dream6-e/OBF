use std::error::Error;
use std::fmt;

/// A user-facing error with an optional byte/line/column location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub message: String,
    pub offset: Option<usize>,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl Diagnostic {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            offset: None,
            line: None,
            column: None,
        }
    }

    pub fn at(message: impl Into<String>, offset: usize, line: usize, column: usize) -> Self {
        Self {
            message: message.into(),
            offset: Some(offset),
            line: Some(line),
            column: Some(column),
        }
    }

    pub fn byte(message: impl Into<String>, offset: usize) -> Self {
        Self {
            message: message.into(),
            offset: Some(offset),
            line: None,
            column: None,
        }
    }

    pub fn context(mut self, context: impl AsRef<str>) -> Self {
        self.message = format!("{}: {}", context.as_ref(), self.message);
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line, self.column, self.offset) {
            (Some(line), Some(column), _) => {
                write!(f, "{line}:{column}: {}", self.message)
            }
            (_, _, Some(offset)) => write!(f, "byte {offset}: {}", self.message),
            _ => f.write_str(&self.message),
        }
    }
}

impl Error for Diagnostic {}
