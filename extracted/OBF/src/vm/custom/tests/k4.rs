// K4 step 2 (user-program IR function-structure transform): the permanent
// gates. The transform -- strict single-block inlining plus deterministic
// sibling reorder plus fail-closed invariant validation -- runs inside
// `ir::compile`, i.e. before public `.obf` encoding, so the seed-independent
// public artifact and the per-seed wire image both carry the transformed IR.
// The unit-level behavior of the inliner and the reorder is pinned in
// `src/ir/transform.rs`; what belongs here is the pipeline-level contract.

// The transform has to be *live* in the public `.obf` -- if it ever stops
// changing the public bytes it has silently stopped doing its job -- and it
// has to be deterministic: the public `.obf` is documented seed-independent,
// and the transform is seed-free by construction (a seeded variant would leak
// the seed into the shared artifact). Measured at re-recording: the Lua 5.1
// fixture inlines its one single-use callee (14 -> 13 prototypes), the Luau
// fixture's forest only reorders (14 prototypes, same prototype set).
#[test]
fn k4_transform_is_live_and_deterministic_in_the_public_obf() {
    for (target, file) in [
        (Target::Lua51, "tests/fixtures/vm_lua51.lua"),
        (Target::Luau, "tests/fixtures/vm_luau.lua"),
    ] {
        let source =
            fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file))
                .unwrap();
        let plain = crate::ir::lower(&crate::parse(&source, target).unwrap()).unwrap();
        let plain_bytes = crate::bytecode::custom::encode(&plain).unwrap();
        let first = crate::ir::compile(&source, target).unwrap();
        let second = crate::ir::compile(&source, target).unwrap();
        let first_bytes = crate::bytecode::custom::encode(&first).unwrap();
        let second_bytes = crate::bytecode::custom::encode(&second).unwrap();
        assert_eq!(
            first_bytes, second_bytes,
            "{target}: the K4 transform is not deterministic -- the public .obf would \
             stop being a stable shared artifact"
        );
        assert_ne!(
            plain_bytes, first_bytes,
            "{target}: the K4 transform left the public .obf unchanged -- either the \
             hook in `ir::compile` dropped out or the transform stopped matching this \
             fixture; re-measure before touching this gate"
        );
        assert!(
            crate::bytecode::custom::decode(&first_bytes, target).is_ok(),
            "{target}: the transformed public .obf no longer decodes"
        );
    }
}

// The dual-target semantic gate: the fully virtualized script (K4 on) must
// run to exactly the fixture's native stdout on both toolchains. Two golden
// seeds plus one off-golden seed, so the gate does not merely pin the golden
// recordings. The output comparison is byte-exact stdout, the same standard
// the runtime gates use.
#[test]
fn k4_virtualized_output_is_semantically_identical_on_both_targets() {
    for (target, file) in [
        (Target::Lua51, "tests/fixtures/vm_lua51.lua"),
        (Target::Luau, "tests/fixtures/vm_luau.lua"),
    ] {
        let source =
            fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file))
                .unwrap();
        let data = compile(&source, target).unwrap();
        let workspace = native::Workspace::new();
        let path = workspace.0.join("k4_gate.lua");
        fs::write(&path, &source).unwrap();
        let expected = native::compile_and_run(target, &path);
        for seed in [7001u64, 7351, 424242] {
            fs::write(&path, emit(&data, target, seed).unwrap()).unwrap();
            assert_eq!(
                native::compile_and_run(target, &path),
                expected,
                "{target} seed {seed}: the K4-transformed program changed observable \
                 behavior -- the inline/reorder pass broke the single-use or \
                 parent-before-child invariant on this fixture"
            );
        }
    }
}
