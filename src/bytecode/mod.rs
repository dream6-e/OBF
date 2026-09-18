pub mod custom;
pub mod lua51;
pub mod luau;

use crate::{Diagnostic, Target};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeReport {
    pub target: Target,
    pub version: u8,
    pub type_version: Option<u8>,
    pub strings: usize,
    pub prototypes: usize,
    pub instructions: usize,
    pub constants: usize,
    pub main_prototype: usize,
}

pub fn inspect(data: &[u8], target: Target) -> Result<BytecodeReport, Diagnostic> {
    if data.starts_with(b"OBF") {
        return custom::decode(data, target).map(|program| program.report());
    }
    match target {
        Target::Lua51 => lua51::inspect(data),
        Target::Luau => luau::inspect(data),
    }
}
