//! Executable VM for AST-produced OBF v2 bytecode. The file encodes every
//! instruction as an opcode byte plus 7-bit varint operands; the generated
//! decoder validates them and expands the stream back into the fixed
//! 4-byte-per-instruction string that the fetch loop then executes. Only
//! handlers in the program are emitted; all opcode definitions exist in the
//! two target subfolders. `seed` affects final local/private-field names
//! only, never bytecode.

mod cipher;
mod emit;
mod structure;
#[cfg(test)]
mod tests;
mod transport;

use crate::bytecode::custom::{self, Opcode, Program};
use crate::{Diagnostic, Target};

pub(crate) use cipher::*;
pub(crate) use emit::generate;
pub(crate) use structure::*;
pub(crate) use transport::*;
pub use transport::{decrypt_embedded, extract_embedded};

pub fn compile(source: &str, target: Target) -> Result<Vec<u8>, Diagnostic> {
    custom::encode(&crate::ir::compile(source, target)?)
}

pub fn virtualize(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    let bytecode = compile(source, target)?;
    emit(&bytecode, target, seed)
}

/// Validate externally supplied custom bytecode before generating a runtime.
pub fn emit(bytecode: &[u8], target: Target, seed: u64) -> Result<String, Diagnostic> {
    let program = custom::decode(bytecode, target)?;
    let raw = generate(bytecode, &program, seed)?;
    finalize(&raw, target, seed)
}

// All source (including static host method adapters) is complete before
// shortening private fields and then applying the existing final local pass.
fn finalize(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    let source = super::fields::shorten(source, target, seed)?;
    crate::minify::finalize_vm(&source, target, seed)
}
