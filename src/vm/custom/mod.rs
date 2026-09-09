//! Executable VM for AST-produced OBF v2 bytecode. Public `.obf` files keep
//! the canonical opcode-plus-varint ISA2 format, but generated scripts lower
//! that program into a private seed-specific ISA13 image: straight-line words
//! become recipe superoperators, use sites carry operands plus random graph
//! labels, three-stage successor tokens, and five-stage recipe tokens (not
//! plaintext successors/opcodes/recipe ids). Reachable neutral bundles split
//! every real entry and sampled CFG edges. Live dictionary descriptors are
//! validation-equivalent camouflage; actual semantics are split into random-id
//! 1..2-primitive fragments and globally shuffled. ISA12-C permits a 2-op
//! fragment only when token analysis can turn it into a real carried-value
//! dataflow pair: the first result is evaluated once and every safe read in the
//! second primitive goes through a frame-family forwarding closure. Unsupported
//! or control pairs remain single fragments rather than concatenated handlers.
//! Each prototype code image is additionally split into a masked two-node
//! id/owner/next chain; every node is
//! shuffled through one cross-prototype pool and fully validated before user
//! execution. Records/sibling prototypes are shuffled, an unreachable synthetic
//! subtree changes topology, and persistent code records retain only tokens.
//! The semantic image is then losslessly compressed by bounded LZW, protected
//! by an inner ChaCha8 domain, sealed in strict transport frame v2, and
//! protected again by a disjoint outer ChaCha8 domain. Word-XOR/rotate,
//! quarter-round, block, stream/KDF and anti-hook code are independent shuffled
//! fields. ISA13 retains ISA11's live source-witness key schedule and
//! fail-closed runtime attestation, the ISA12 per-prototype heterogeneous
//! operand ABI (four physical record layouts, rotation, sparse lane, varied
//! fragment bindings, no actual-opcode marker), the ISA12-B register ABI
//! (four 257-key bank shapes, no complete permutation table) and the ISA12-C
//! carried-value fusion plus six-state entry graph. ISA13 additionally
//! de-documents parser field order: record headers use a per-prototype
//! factorial slot permutation, segment tokens a per-segment one, while
//! dictionary, metadata and tuple orders are per-image permutations baked
//! into the generated parser. All inverses and graph dependencies remain
//! client-visible and reversible. Share parity also selects
//! one of two fetch/dispatch state pairs before masking their representation.
//! Primitive semantics still live in the two target opcode subfolders. The
//! seed never changes public `.obf` bytes, but it does change the embedded
//! semantic image as well as transport, layout, local, and private-field
//! randomization.

mod chacha;
mod cipher;
mod compress;
mod emit;
mod lowering;
mod seed;
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
pub(crate) use seed::*;
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
