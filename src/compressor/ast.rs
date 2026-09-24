#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarId(pub usize);

#[derive(Debug, Clone)]
pub struct LocalVar {
    pub name: String,
    pub id: VarId,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub last_stmt: Option<LastStmt>,
}

#[derive(Debug, Clone)]
pub enum LastStmt {
    Return(Vec<Expr>),
    Break,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Assign(Vec<Var>, Vec<Expr>),
    Call(Call),
    Do(Box<Block>),
    While(Box<Expr>, Box<Block>),
    Repeat(Box<Block>, Box<Expr>),
    If {
        cond: Box<Expr>,
        then_block: Box<Block>,
        else_ifs: Vec<(Expr, Block)>,
        else_block: Option<Box<Block>>,
    },
    For {
        var: LocalVar,
        init: Box<Expr>,
        limit: Box<Expr>,
        step: Option<Box<Expr>>,
        block: Box<Block>,
    },
    ForIn {
        vars: Vec<LocalVar>,
        exprs: Vec<Expr>,
        block: Box<Block>,
    },
    Function {
        path: Vec<String>,
        method: Option<String>,
        params: Vec<LocalVar>,
        is_vararg: bool,
        block: Box<Block>,
    },
    LocalFunction {
        var: LocalVar,
        params: Vec<LocalVar>,
        is_vararg: bool,
        block: Box<Block>,
    },
    LocalAssign(Vec<LocalVar>, Vec<Expr>),
}

#[derive(Debug, Clone)]
pub enum Expr {
    Nil,
    Boolean(bool),
    Number(String),
    String(String),
    Vararg,
    FuncDef(Vec<LocalVar>, bool, Box<Block>),
    Table(Vec<TableField>),
    BinOp(String, Box<Expr>, Box<Expr>),
    UnOp(String, Box<Expr>),
    Prefix(Box<PrefixExpr>),
}

#[derive(Debug, Clone)]
pub enum PrefixExpr {
    Var(Var),
    Call(Call),
    Paren(Box<Expr>),
}

#[derive(Debug, Clone)]
pub enum Var {
    Name(String, VarId),
    Index(Box<PrefixExpr>, Box<Expr>),
    Member(Box<PrefixExpr>, String),
}

#[derive(Debug, Clone)]
pub enum Call {
    Normal(Box<PrefixExpr>, Vec<Expr>),
    Method(Box<PrefixExpr>, String, Vec<Expr>),
}

#[derive(Debug, Clone)]
pub enum TableField {
    List(Expr),
    Rec(Expr, Expr),
}