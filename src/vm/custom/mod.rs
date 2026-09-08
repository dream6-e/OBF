//! Executable VM for AST-produced OBF v2 bytecode. Public `.obf` files keep
//! the canonical opcode-plus-varint ISA2 format, but generated scripts lower
//! that program into a private seed-specific ISA12 image: straight-line words
//! become recipe superoperators, use sites carry operands plus random graph
//! labels, three-stage successor tokens, and five-stage recipe tokens (not
//! plaintext successors/opcodes/recipe ids). Reachable neutral bundles split
//! every real entry and sampled CFG edges. Live dictionary descriptors are
//! validation-equivalent camouflage; actual semantics are split into random-id
//! 1..2-primitive fragments and globally shuffled. Each prototype code image is
//! additionally split into a masked two-node id/owner/next chain; every node is
//! shuffled through one cross-prototype pool and fully validated before user
//! execution. Records/sibling prototypes are shuffled, an unreachable synthetic
//! subtree changes topology, and persistent code records retain only tokens.
//! The semantic image is then losslessly compressed by bounded LZW, protected
//! by an inner ChaCha8 domain, sealed in strict transport frame v2, and
//! protected again by a disjoint outer ChaCha8 domain. Word-XOR/rotate,
//! quarter-round, block, stream/KDF and anti-hook code are independent shuffled
//! fields. ISA12 retains ISA11's live source-witness key schedule and
//! fail-closed runtime attestation, then adds a per-prototype heterogeneous
//! operand ABI: decoded operands use one of four physical record layouts,
//! independently rotated and placed in a sparse lane, while fragment bindings
//! vary and no actual-opcode marker is emitted. Share parity also selects one
//! of two fetch/dispatch state pairs before masking their concrete representation.
//! Primitive semantics still live in the two target opcode subfolders. The
//! seed never changes public `.obf` bytes, but it does change the embedded
//! semantic image as well as transport, layout, local, and private-field
//! randomization.

mod chacha;
mod cipher;
mod compress;
mod emit;
mod lowering;
mod semantic;
mod structure;
#[cfg(test)]
mod tests;
mod transport;

use crate::bytecode::custom::{self, Opcode, Program};
use crate::{Diagnostic, Target};

pub(crate) use chacha::*;
pub(crate) use cipher::*;
pub(crate) use compress::*;
pub(crate) use emit::generate;
pub(crate) use lowering::*;
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
