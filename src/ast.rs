use crate::Target;

/// Half-open UTF-8 byte range in the original source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub const fn join(self, other: Self) -> Self {
        Self {
            start: self.start,
            end: other.end,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Chunk {
    pub target: Target,
    pub block: Block,
    pub span: Span,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Block {
    pub statements: Vec<Statement>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Name {
    pub value: String,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Statement {
    pub kind: StatementKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StatementKind {
    Empty,
    Assignment {
        targets: Vec<Expression>,
        values: Vec<Expression>,
    },
    CompoundAssignment {
        target: Expression,
        operator: BinaryOperator,
        value: Expression,
    },
    Call(Expression),
    Local {
        bindings: Vec<Binding>,
        values: Vec<Expression>,
        is_const: bool,
        exported: bool,
    },
    LocalFunction {
        name: Name,
        body: FunctionBody,
        is_const: bool,
        exported: bool,
    },
    Function {
        name: FunctionName,
        body: FunctionBody,
    },
    Do(Block),
    While {
        condition: Expression,
        body: Block,
    },
    Repeat {
        body: Block,
        condition: Expression,
    },
    If {
        branches: Vec<ConditionalBlock>,
        else_block: Option<Block>,
    },
    NumericFor {
        binding: Binding,
        initial: Expression,
        limit: Expression,
        step: Option<Expression>,
        body: Block,
    },
    GenericFor {
        bindings: Vec<Binding>,
        values: Vec<Expression>,
        body: Block,
    },
    Return(Vec<Expression>),
    Break,
    Continue,
    TypeAlias {
        exported: bool,
        name: Name,
        generics: Vec<GenericParameter>,
        value: TypeExpression,
    },
    TypeFunction {
        exported: bool,
        name: Name,
        body: FunctionBody,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConditionalBlock {
    pub condition: Expression,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Binding {
    pub name: Name,
    pub annotation: Option<TypeExpression>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FunctionName {
    pub path: Vec<Name>,
    pub method: Option<Name>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FunctionBody {
    pub attributes: Vec<Attribute>,
    pub generics: Vec<GenericParameter>,
    pub parameters: Vec<Binding>,
    pub vararg: Option<TypeExpression>,
    pub return_type: Option<TypeExpression>,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    pub name: Name,
    pub arguments: Vec<Expression>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GenericParameter {
    pub name: Name,
    pub is_pack: bool,
    pub default: Option<TypeExpression>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Expression {
    pub kind: ExpressionKind,
    pub span: Span,
}

impl Expression {
    pub fn is_assignable(&self) -> bool {
        matches!(
            self.kind,
            ExpressionKind::Name(_) | ExpressionKind::Field { .. } | ExpressionKind::Index { .. }
        )
    }

    pub fn is_call(&self) -> bool {
        matches!(self.kind, ExpressionKind::Call { .. })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExpressionKind {
    Nil,
    Boolean(bool),
    Number(String),
    String(String),
    InterpolatedString {
        strings: Vec<InterpolatedSegment>,
        expressions: Vec<Expression>,
    },
    Vararg,
    Name(Name),
    Function(FunctionBody),
    Table(Vec<TableField>),
    IfExpression {
        branches: Vec<ConditionalExpression>,
        else_expression: Box<Expression>,
    },
    Unary {
        operator: UnaryOperator,
        expression: Box<Expression>,
    },
    Binary {
        operator: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    TypeAssertion {
        expression: Box<Expression>,
        asserted: TypeExpression,
    },
    TypeInstantiation {
        expression: Box<Expression>,
        arguments: Vec<TypeArgument>,
    },
    Group(Box<Expression>),
    Field {
        table: Box<Expression>,
        field: Name,
    },
    Index {
        table: Box<Expression>,
        index: Box<Expression>,
    },
    Call {
        function: Box<Expression>,
        method: Option<Name>,
        arguments: Vec<Expression>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConditionalExpression {
    pub condition: Expression,
    pub value: Expression,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InterpolatedSegment {
    /// Raw source text between interpolation delimiters.
    pub value: String,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryOperator {
    Not,
    Negate,
    Length,
    BitNot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryOperator {
    Or,
    And,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Concat,
    Add,
    Subtract,
    Multiply,
    Divide,
    FloorDivide,
    Modulo,
    Power,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TableField {
    List(Expression),
    Record {
        name: Name,
        value: Expression,
        span: Span,
    },
    Computed {
        key: Expression,
        value: Expression,
        span: Span,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct TypeExpression {
    pub kind: TypeKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeKind {
    Nil,
    BooleanSingleton(bool),
    StringSingleton(String),
    Named {
        path: Vec<Name>,
        arguments: Vec<TypeArgument>,
    },
    Typeof(Box<Expression>),
    Table(Vec<TypeField>),
    Function {
        generics: Vec<GenericParameter>,
        parameters: Vec<TypeParameter>,
        returns: Box<TypeExpression>,
    },
    Group(Box<TypeExpression>),
    Tuple(Vec<TypeExpression>),
    Union(Vec<TypeExpression>),
    Intersection(Vec<TypeExpression>),
    Optional(Box<TypeExpression>),
    Variadic(Box<TypeExpression>),
    GenericPack(Name),
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeArgument {
    Type(TypeExpression),
    Pack(TypeExpression),
}

#[derive(Clone, Debug, PartialEq)]
pub struct TypeParameter {
    pub name: Option<Name>,
    pub value: TypeExpression,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeAccess {
    ReadWrite,
    Read,
    Write,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeField {
    Property {
        name: Name,
        value: TypeExpression,
        access: TypeAccess,
        span: Span,
    },
    StringProperty {
        literal: String,
        value: TypeExpression,
        access: TypeAccess,
        span: Span,
    },
    Indexer {
        key: TypeExpression,
        value: TypeExpression,
        access: TypeAccess,
        span: Span,
    },
    Array {
        value: TypeExpression,
        access: TypeAccess,
        span: Span,
    },
}
