use super::*;
use crate::ir::{self, Instruction as I, Terminator as T};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

mod native {
    use crate as obf;
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/mod.rs"));
}

// Keep this test module physically split: the project enforces an 80 KiB
// source-file ceiling while `include!` preserves the existing module scope.
include!("tests/runtime.rs");
include!("tests/semantic_corruption.rs");
include!("tests/transport.rs");
include!("tests/transport_fragments.rs");
include!("tests/semantic.rs");
include!("tests/transport_chain.rs");
include!("tests/transport_k19.rs");
include!("tests/seed_v1.rs");
include!("tests/seed_arms.rs");
include!("tests/heuristic_audit.rs");
include!("tests/opaque_bits.rs");
include!("tests/opaque_bounds.rs");
include!("tests/opaque_shapes.rs");
include!("tests/stream_audit.rs");
include!("tests/bitops.rs");
include!("tests/lane.rs");
include!("tests/scatter.rs");
include!("tests/dispatch_intervals.rs");
include!("tests/anchor_floor.rs");
include!("tests/operand_fields.rs");
include!("tests/depooled_recipe.rs");
include!("tests/segment_alphabets.rs");
include!("tests/layout.rs");
include!("tests/context_key.rs");
include!("tests/mba.rs");
include!("tests/rolling.rs");
include!("tests/k4.rs");
