use super::token::Span;

pub type Block = Vec<Stat>;

#[derive(Debug, Clone)]
pub enum Stat {
    Assign {
        targets: Vec<Expr>,
        values: Vec<Expr>,
        span: Span,
    },
    LocalDecl {
        names: Vec<String>,
        values: Vec<Expr>,
        span: Span,
    },
    Do {
        body: Block,
        span: Span,
        end_line: u32,
    },
    While {
        condition: Expr,
        body: Block,
        span: Span,
        end_line: u32,
    },
    Repeat {
        body: Block,
        condition: Expr,
        span: Span,
    },
    If {
        conditions: Vec<Expr>,
        bodies: Vec<Block>,
        else_body: Option<Block>,
        span: Span,
        end_line: u32,
    },
    NumericFor {
        name: String,
        start: Expr,
        stop: Expr,
        step: Option<Expr>,
        body: Block,
        span: Span,
        end_line: u32,
    },
    GenericFor {
        names: Vec<String>,
        iterators: Vec<Expr>,
        body: Block,
        iter_line: u32,
        span: Span,
        end_line: u32,
    },
    FuncDecl {
        name: FuncName,
        body: FuncBody,
        span: Span,
    },
    LocalFunc {
        name: String,
        body: FuncBody,
        span: Span,
    },
    Return { values: Vec<Expr>, span: Span },
    Break { span: Span },
    Continue { span: Span },
    ExprStat { expr: Expr, span: Span },
}

#[derive(Debug, Clone)]
pub enum Expr {
    Nil(Span),
    True(Span),
    False(Span),
    Number(f64, Span),
    Str(Vec<u8>, Span),
    VarArg(Span),
    Name(String, Span),
    BinOp {
        op: BinOp,
        left: Box<Self>,
        right: Box<Self>,
        span: Span,
    },
    UnOp {
        op: UnOp,
        operand: Box<Self>,
        span: Span,
    },
    Index {
        table: Box<Self>,
        key: Box<Self>,
        span: Span,
    },
    Field {
        table: Box<Self>,
        field: String,
        span: Span,
    },
    MethodCall {
        table: Box<Self>,
        method: String,
        args: Vec<Self>,
        span: Span,
    },
    Call {
        func: Box<Self>,
        args: Vec<Self>,
        span: Span,
    },
    FuncDef { body: FuncBody, span: Span },
    TableCtor { fields: Vec<TableField>, span: Span },
    Paren(Box<Self>, Span),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Concat,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    Len,
}

#[derive(Debug, Clone)]
pub enum TableField {
    IndexField { key: Expr, value: Expr, span: Span },
    NameField {
        name: String,
        value: Expr,
        span: Span,
    },
    ValueField { value: Expr, span: Span },
}

#[derive(Debug, Clone)]
pub struct FuncBody {
    pub params: Vec<String>,
    pub has_varargs: bool,
    pub body: Block,
    pub span: Span,
    pub end_line: u32,
}

#[derive(Debug, Clone)]
pub struct FuncName {
    pub parts: Vec<String>,
    pub method: Option<String>,
    pub span: Span,
}

impl Stat {
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::Assign { span, .. }
            | Self::LocalDecl { span, .. }
            | Self::Do { span, .. }
            | Self::While { span, .. }
            | Self::Repeat { span, .. }
            | Self::If { span, .. }
            | Self::NumericFor { span, .. }
            | Self::GenericFor { span, .. }
            | Self::FuncDecl { span, .. }
            | Self::LocalFunc { span, .. }
            | Self::Return { span, .. }
            | Self::Break { span, .. }
            | Self::Continue { span, .. }
            | Self::ExprStat { span, .. } => *span,
        }
    }
}

impl Expr {
    #[must_use]
    pub fn span(&self) -> Span {
        match self {
            Self::Nil(span)
            | Self::True(span)
            | Self::False(span)
            | Self::Number(_, span)
            | Self::Str(_, span)
            | Self::VarArg(span)
            | Self::Name(_, span)
            | Self::BinOp { span, .. }
            | Self::UnOp { span, .. }
            | Self::Index { span, .. }
            | Self::Field { span, .. }
            | Self::MethodCall { span, .. }
            | Self::Call { span, .. }
            | Self::FuncDef { span, .. }
            | Self::TableCtor { span, .. }
            | Self::Paren(_, span) => *span,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_span() {
        let s = Stat::Break {
            span: Span::new(5, 1),
        };
        assert_eq!(s.span(), Span::new(5, 1));
    }

    #[test]
    fn stat_continue_span() {
        let s = Stat::Continue {
            span: Span::new(5, 1),
        };
        assert_eq!(s.span(), Span::new(5, 1));
    }

    #[test]
    fn expr_span() {
        let e = Expr::Number(42.0, Span::new(1, 1));
        assert_eq!(e.span(), Span::new(1, 1));
    }

    #[test]
    fn expr_nil_span() {
        let e = Expr::Nil(Span::new(3, 10));
        assert_eq!(e.span(), Span::new(3, 10));
    }

    #[test]
    fn binop_expr_span() {
        let e = Expr::BinOp {
            op: BinOp::Add,
            left: Box::new(Expr::Number(1.0, Span::new(1, 1))),
            right: Box::new(Expr::Number(2.0, Span::new(1, 5))),
            span: Span::new(1, 1),
        };
        assert_eq!(e.span(), Span::new(1, 1));
    }

    #[test]
    fn unop_expr_span() {
        let e = Expr::UnOp {
            op: UnOp::Neg,
            operand: Box::new(Expr::Number(1.0, Span::new(1, 2))),
            span: Span::new(1, 1),
        };
        assert_eq!(e.span(), Span::new(1, 1));
    }

    #[test]
    fn func_name_simple() {
        let name = FuncName {
            parts: vec!["foo".into()],
            method: None,
            span: Span::new(1, 1),
        };
        assert_eq!(name.parts.len(), 1);
        assert!(name.method.is_none());
    }

    #[test]
    fn func_name_dotted_with_method() {
        let name = FuncName {
            parts: vec!["a".into(), "b".into()],
            method: Some("c".into()),
            span: Span::new(1, 1),
        };
        assert_eq!(name.parts.len(), 2);
        assert_eq!(name.method.as_deref(), Some("c"));
    }

    #[test]
    fn func_body_construction() {
        let body = FuncBody {
            params: vec!["x".into(), "y".into()],
            has_varargs: true,
            body: vec![],
            span: Span::new(1, 1),
            end_line: 5,
        };
        assert_eq!(body.params.len(), 2);
        assert!(body.has_varargs);
    }

    #[test]
    fn table_field_variants() {
        let _idx = TableField::IndexField {
            key: Expr::Number(1.0, Span::new(1, 2)),
            value: Expr::Str(b"a".to_vec(), Span::new(1, 7)),
            span: Span::new(1, 1),
        };
        let _name = TableField::NameField {
            name: "x".into(),
            value: Expr::Number(1.0, Span::new(1, 5)),
            span: Span::new(1, 1),
        };
        let _val = TableField::ValueField {
            value: Expr::Number(1.0, Span::new(1, 1)),
            span: Span::new(1, 1),
        };
    }

    #[test]
    fn call_expr() {
        let e = Expr::Call {
            func: Box::new(Expr::Name("print".into(), Span::new(1, 1))),
            args: vec![Expr::Str(b"hello".to_vec(), Span::new(1, 7))],
            span: Span::new(1, 1),
        };
        assert_eq!(e.span(), Span::new(1, 1));
    }
}