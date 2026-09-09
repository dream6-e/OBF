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
include!("tests/transport.rs");
include!("tests/semantic.rs");
include!("tests/seed_v1.rs");
include!("tests/heuristic_audit.rs");
include!("tests/stream_audit.rs");
