// M2 batch gates: the new opaque-predicate families are *exact*, the wrapper
// draws stay inside their licensed scopes, and the mixed random use requested
// by the user actually means every family appears under the sweep. Scope
// discipline (the M1 lesson): these wrappers land only where the validator
// destructures its captures (bits=true), so the R/D state machines and every
// raw condition path keep their pre-M2 spellings draw-for-draw.

#[test]
fn boolean_wrappers_are_exact_identities() {
    use crate::random::tests::OvParser;
    let mut rng = Prng::lcg(0x626f_6f6c_7772_6170);
    for c in ["X==17", "X-567==0", "(X%2==X%2)", "17>=X", "not(X~=90)"] {
        for _ in 0..64 {
            for forbid in [&[17u64][..], &[90, 567][..]] {
                let wrapped = rng.bool_wrap(c, forbid);
                assert!(wrapped.starts_with("(not("), "{wrapped}");
                let dw = wrapped.clone();
                let dc = c.to_string();
                for source in [0i64, 1, 17, 56, 90, 255, 567] {
                    assert_eq!(
                        OvParser::truthy(&dw, source),
                        OvParser::truthy(&dc, source),
                        "{dw} diverged from {dc} at o={source}"
                    );
                }
            }
        }
    }
}

#[test]
fn rotate_dressed_dispatch_keys_match_exactly_their_value() {
    use crate::random::tests::OvParser;
    let mut rng = Prng::sfc(0x726f_6c5f_6b65_7973);
    for luau in [false, true] {
        for value in [1u16, 7, 255, 256, 4096, 65_535] {
            for _ in 0..24 {
                let text = rng.rol_dispatch_condition("X", value, luau);
                // The bound's digits must never ride inside the rotated key.
                assert!(text.contains("4294967296"), "{text}");
                for probe in [0i64, i64::from(value), i64::from(value) + 1, 1024, 65_536] {
                    assert_eq!(
                        OvParser::truthy(&text, probe),
                        probe == i64::from(value),
                        "{text} at o={probe}, want {value}"
                    );
                }
            }
        }
    }
}

#[test]
fn zero_dwarf_arms_are_exact_and_never_spell_the_value() {
    use crate::random::tests::OvParser;
    let mut rng = Prng::lcg(0x6477_6172_665f);
    for value in [0u64, 3, 17, 86, 255, 1234, 56789] {
        for _ in 0..24 {
            let base = format!("({}-23)", value + 23);
            let arm = rng.zero_dwarf_arm(base, value);
            assert_eq!(OvParser::parse(&arm, 0), value as i64, "{arm}");
            assert!(
                !Prng::spells_value(value, &arm),
                "{arm} still spells {value}"
            );
        }
    }
}

#[test]
fn all_families_show_up_under_the_mixed_draw() {
    // Sweep through the licensed scope the same way the emitter does and count
    // every M2 surface mark; a probability collapse on any of them would
    // silently shrink the predicate surface the user asked to see mixed.
    let mut rng = Prng::lcg(0x6d32_6661_6d73_2141);
    let (mut dwarf, mut masked, mut wrapped, mut rotated) = (0usize, 0usize, 0usize, 0usize);
    for bound in (1u16..=512).step_by(37) {
        for _ in 0..8 {
            let text = rng.boundary_condition_opaque("o", bound, true, true, true, "o");
            if text.starts_with("(not(") && text.ends_with("~=0))") {
                wrapped += 1;
            }
            let text = rng.dispatch_condition_opaque("o", bound, true, true, "o");
            if text.contains("4294967296") {
                rotated += 1;
            }
            let text = rng.opaque_literal_scoped(u64::from(bound), true, true, "o");
            if contains_self_cancelling_group(&text) {
                dwarf += 1;
            }
            if text.contains("4294967295") {
                masked += 1;
            }
        }
    }
    assert!(wrapped > 8, "boolean wraps faded in bits scope: {wrapped}");
    assert!(rotated > 8, "rotate-dressed dispatch keys faded: {rotated}");
    assert!(dwarf > 0, "zero-dwarf arms faded: {dwarf}");
    assert!(masked > 0, "all-ones masked arms faded: {masked}");
}

/// True when the text contains an `(N-N)` group with N the same digit run on
/// both sides -- the zero-dwarf signature the sweep counts.
fn contains_self_cancelling_group(text: &str) -> bool {
    let bytes = text.as_bytes();
    for start in 0..bytes.len() {
        if bytes[start] != b'(' {
            continue;
        }
        let mut at = start + 1;
        let digits_start = at;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
        }
        if at == digits_start || at >= bytes.len() || bytes[at] != b'-' {
            continue;
        }
        let first = &text[digits_start..at];
        let tail = &text[at + 1..];
        if tail.starts_with(first) && tail[first.len()..].starts_with(')') {
            return true;
        }
    }
    false
}

#[test]
fn non_bits_scopes_never_carry_m2_surface_marks() {
    // The bit-capture licence is the hard boundary of the batch: raw dispatch
    // chains, R/D state machines and every Lua-5.1 path pass `bits=false` and
    // must keep their classic surface -- otherwise the wire-image and
    // state-decoding gates would be decoding M2 text without knowing.
    let mut rng = Prng::lcg(0x7072_6532_2d6d_3261);
    for luau in [false, true] {
        for bound in (1u16..=512).step_by(31) {
            let dispatch = rng.dispatch_condition_opaque("o", bound, luau, false, "o");
            let below = rng.boundary_condition_opaque("o", bound, true, luau, false, "o");
            let above = rng.interval_condition_opaque("o", bound, 7, true, luau, false, "o");
            for text in [dispatch, below, above] {
                assert!(!text.contains("4294967296"), "{text}");
                assert!(!text.contains("4294967295"), "{text}");
                assert!(!contains_self_cancelling_group(&text), "{text}");
                // The boolean-wrapper fingerprint is a trailing `~=0)` on a
                // wrapped outer `not`; classic `not(...)` shapes end with `)`.
                if text.starts_with("(not(") {
                    assert!(!text.ends_with("~=0))"), "{text}");
                }
            }
        }
    }
}
