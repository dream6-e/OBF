// K9/K12 operand-lane tests: the per-record affine lane keys, the ISA16
// chain recurrence that feeds decoded record state into them, and the private
// wire version pin. Split out of `tests/semantic.rs` for the 81,920 B source
// ceiling; `include!` keeps the shared test module scope.

#[test]
fn k9_affine_lanes_round_trip_for_all_forms_and_contexts() {
    let bytes = compile("return 1", Target::Lua51).unwrap();
    let program = custom::decode(&bytes, Target::Lua51).unwrap();
    let image = super::semantic::encode(&program, 0x9_0009).unwrap();
    let multipliers = [1u32, 3, 5, 7, 9, 11, 13, 15];
    for token in [0u16, 1, 257, 65535] {
        for prototype in [0u16, 1, 31, 4095] {
            for lane in 0..3u32 {
                let index = super::semantic::k9_index(token, prototype, lane, image.mask_salt);
                assert_eq!(multipliers[index] % 2, 1);
                for value in [0usize, 1, 127, 128, 255] {
                    for chain in [0u32, 1, 4095, super::semantic::K9_CHAIN_MOD - 1] {
                        let wire = super::semantic::k9_affine(
                            value, token, prototype, lane, &image, chain, 256,
                        );
                        let inverse = [1u32, 171, 205, 183, 57, 163, 197, 239][index];
                        let add =
                            super::semantic::k9_add(token, prototype, lane, image.mask_add, chain, 256);
                        assert_eq!(((wire + 256 - add) % 256) * inverse % 256, value as u32);
                    }
                }
            }
        }
    }
}

#[test]
fn wire_isa_version_is_16() {
    assert_eq!(
        super::semantic::WIRE_ISA_VERSION,
        16,
        "chained per-record operand lanes (K12/T1) require ISA16"
    );
}

// K12/T1: the operand lane key must eat the decoded record prefix, so the
// recovery of record r is not expressible without records 0..r-1. These gates
// pin (a) the recurrence is order-sensitive and never collapses, (b) the
// doubles stay inside the exact-integer bound the emitted toolbox assumes, and
// (c) the Lua parser replays exactly the Rust constants -- drift between the
// two sides is the failure mode, not the arithmetic itself.
#[test]
fn operand_lane_chain_is_order_dependent_and_double_exact() {
    use super::semantic::{
        k9_chain_init, k9_chain_next, K9_CHAIN_MOD, K9_CHAIN_MUL, K9_CHAIN_STEP_MUL,
        K9_CHAIN_TOKEN_MUL, K9_INIT_PROTO_MUL, K9_INIT_ROUTE_MUL, K9_INIT_START_MUL,
    };
    // Same tokens, different order => different tail states (non-commutative).
    let run = |salt: u16, tokens: &[u16]| -> Vec<u32> {
        let mut st = k9_chain_init(3, 7, 11, salt);
        tokens
            .iter()
            .enumerate()
            .map(|(at, &t)| {
                st = k9_chain_next(st, t, at as u32, salt);
                st
            })
            .collect()
    };
    let tokens = [1u16, 7, 4099, 65_535, 2, 3];
    let mut swapped = tokens;
    swapped.swap(1, 4);
    let a = run(9, &tokens);
    let b = run(9, &swapped);
    assert_ne!(a, b, "lane chain must depend on record order");
    assert!(
        a.windows(2).all(|w| w[0] != w[1]) && a.iter().all(|&v| v < K9_CHAIN_MOD),
        "lane chain collapsed: {a:?}"
    );
    // Salt and prototype/route/start seeds all move the chain.
    assert_ne!(a, run(10, &tokens), "salt must enter the chain");
    assert_ne!(
        k9_chain_init(0, 7, 11, 9),
        k9_chain_init(1, 7, 11, 9),
        "prototype id must seed the chain"
    );
    assert_ne!(
        k9_chain_init(0, 8, 11, 9),
        k9_chain_init(0, 7, 11, 9),
        "route count must seed the chain"
    );
    assert_ne!(
        k9_chain_init(0, 7, 12, 9),
        k9_chain_init(0, 7, 11, 9),
        "entry label must seed the chain"
    );
    // Exact-integer bound: the emitted Lua computes the same recurrence with
    // doubles, so the largest intermediate must stay below 2^53.
    let worst = u64::from(K9_CHAIN_MOD - 1) * u64::from(K9_CHAIN_MUL)
        + u64::from(u16::MAX) * u64::from(K9_CHAIN_TOKEN_MUL)
        + 1_048_576 * u64::from(K9_CHAIN_STEP_MUL)
        + u64::from(u16::MAX);
    assert!(worst < 1 << 53, "lane chain exceeds the double exact range: {worst}");
    assert_eq!(K9_CHAIN_MOD % 2, 1, "modulus must be odd");
}

// Drift lock: every constant in the emitted recurrence has to equal the Rust
// constant, and the operand decode has to feed the chain state to AK.

#[test]
fn emitted_runtime_replays_the_operand_lane_chain() {
    use super::semantic::{
        K9_CHAIN_MUL, K9_CHAIN_STEP_MUL, K9_CHAIN_TOKEN_MUL, K9_INIT_PROTO_MUL, K9_INIT_ROUTE_MUL,
        K9_INIT_START_MUL,
    };
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("local t={} for i=1,4 do t[i]=i*3 end print(#t,t[4])", target).unwrap();
        let output = emit(&data, target, 7001).unwrap();
        // The finalizer renames every safe local (stL/AK included) and drops
        // optional semicolons, so the lock uses the numeric shape only: each
        // multiplier has exactly one site unless the recurrence drifted.
        for (fragment, count) in [
            (format!("*{K9_INIT_PROTO_MUL}+"), 1usize),
            (format!("*{K9_INIT_ROUTE_MUL}+"), 1),
            (format!("*{K9_INIT_START_MUL}+"), 1),
            (format!("*{K9_CHAIN_MUL}+"), 1),
            (format!("*{K9_CHAIN_TOKEN_MUL}+"), 1),
            (format!("*{K9_CHAIN_STEP_MUL}+"), 1),
        ] {
            assert_eq!(
                output.matches(fragment.as_str()).count(),
                count,
                "{target}: lane chain shape drifted at {fragment:?}"
            );
        }
        // AK must consume the chain state: its additive term has to close over
        // a reduction (`+<salt>+<state>%<mod>)`) before the parenthesis. Without
        // the fold the window ends immediately with no `%` at all.
        let ak = output.find("*193+").expect("AK lane multiplier term");
        let window = &output[ak..ak + 40];
        let upto = window.find(')').unwrap_or(window.len());
        assert!(
            window[..upto].contains('%'),
            "{target}: AK no longer folds the operand lane chain state"
        );
    }
}
