use crate::BytecodeCompiler::ir::instruction::Instruction;

#[derive(Debug, Clone, PartialEq)]
pub enum Constant {
    Nil,
    Boolean(bool),
    Number(f64),
    String(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Local {
    pub name: String,
    pub start_pc: i32,
    pub end_pc: i32,
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub name: String,
    pub line_defined: i32,
    pub last_line_defined: i32,
    pub upvalue_count: u8,
    pub param_count: u8,
    pub is_vararg: u8,
    pub max_stack: u8,
    pub instructions: Vec<Instruction>,
    pub constants: Vec<Constant>,
    pub protos: Vec<Chunk>,
    pub lines: Vec<i32>,
    pub locals: Vec<Local>,
    pub upvalues: Vec<String>,
}