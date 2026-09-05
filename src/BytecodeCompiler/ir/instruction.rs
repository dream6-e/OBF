use crate::BytecodeCompiler::ir::opcode::Opcode;
use crate::BytecodeCompiler::virtualizer::vopcode::VOpcode;

#[derive(Debug, Clone)]
pub struct Instruction {
    pub data: u32,
    pub opcode: Opcode,
    pub a: u8,
    pub b: i32,
    pub c: i32,
    pub line: i32,
    pub v_opcode: Option<VOpcode>,
    pub is_junk: bool,
}