//! Target-aware register IR produced directly from the owned source AST.
//! No native Lua/Luau instruction words or external compiler are involved.
//! Blocks have symbolic successors; byte offsets/opcode packing belong solely
//! to `bytecode::custom`. Locals are explicit heap cells, so closures survive
//! register reuse and each loop iteration can allocate a fresh binding.

mod lower;

use crate::{ast, Diagnostic, Target};

pub type Register = u16;
pub type BlockId = usize;
pub type FunctionId = usize;
pub type ConstantId = usize;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Constant {
    Nil,
    Boolean(bool),
    /// IEEE-754 binary64 bits, preserving negative zero and NaN payloads.
    Number(u64),
    String(Vec<u8>),
    /// Luau's signed 64-bit integer value, NOT an f64 approximation.
    Integer(i64),
    /// A statically known method identifier, also a string at runtime.
    Method(String),
}

impl Constant {
    pub fn number(value: f64) -> Self {
        Self::Number(value.to_bits())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capture {
    Local(Register),
    Upvalue(u16),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Instruction {
    Constant(Register, ConstantId),
    Nil(Register),
    Move(Register, Register),
    NewCell(Register, Register),
    ReadCell(Register, Register),
    WriteCell(Register, Register),
    ReadUpvalue(Register, u16),
    WriteUpvalue(u16, Register),
    ReadGlobal(Register, ConstantId),
    WriteGlobal(ConstantId, Register),
    NewTable(Register),
    GetTable(Register, Register, Register),
    SetTable(Register, Register, Register),
    Method(Register, Register, Register),
    NewPack(Register),
    Push(Register, Register),
    Extend(Register, Register),
    Extract(Register, Register, u16),
    Varargs(Register),
    Call(Register, Register, Register),
    Closure(Register, FunctionId),
    Clear(Register, Register),
    Binary(ast::BinaryOperator, Register, Register, Register),
    Unary(ast::UnaryOperator, Register, Register),
    NumberPrepare(Register),
    NumberStep(Register),
    NumberTest(Register, Register),
    IteratorPrepare(Register),
    IteratorNext(Register, Register),
    SetList(Register, Register, Register),
    ToString(Register, Register),
    /// Link an existing local cell to an exported table field (live binding).
    Export(Register, Register, Register),
    Freeze(Register),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Terminator {
    Jump(BlockId),
    Branch {
        condition: Register,
        then_block: BlockId,
        else_block: BlockId,
    },
    Return(Register),
    TailCall {
        function: Register,
        arguments: Register,
    },
    /// Builder-only state; the bytecode encoder rejects unfinished blocks.
    Unreachable,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub instructions: Vec<Instruction>,
    pub terminator: Terminator,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Function {
    pub parent: Option<FunctionId>,
    pub parameters: u16,
    pub variadic: bool,
    pub legacy_arg_slot: bool,
    pub legacy_arg_table: bool,
    pub registers: u16,
    pub captures: Vec<Capture>,
    pub constants: Vec<Constant>,
    pub blocks: Vec<Block>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Module {
    pub target: Target,
    pub entry: FunctionId,
    pub functions: Vec<Function>,
}

/// AST -> typed register IR. Binding resolution and binding-dependent parser
/// checks are reused, not reimplemented with spelling-based substitutions.
pub fn lower(chunk: &ast::Chunk) -> Result<Module, Diagnostic> {
    lower::lower(chunk)
}

pub fn compile(source: &str, target: Target) -> Result<Module, Diagnostic> {
    lower(&crate::parse(source, target)?)
}
