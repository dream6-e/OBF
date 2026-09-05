mod binary;
pub mod compiler;
mod lua51;
mod luau;
mod opcode;
mod prng;

use crate::{Diagnostic, Target};

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub seed: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self { seed: 0x0bf0_0001 }
    }
}

/// Compile source through the pinned target compiler and lower it into a
/// randomized private instruction format interpreted by generated source.
pub fn virtualize(source: &[u8], target: Target, options: Options) -> Result<String, Diagnostic> {
    let bytecode = compiler::compile(source, target)?;
    match target {
        Target::Lua51 => lua51::virtualize(&bytecode, options.seed),
        Target::Luau => luau::virtualize(&bytecode, options.seed),
    }
}
