// M1 batch gates: opaque predicates composed through the captured bit names
// (BX/BA/BO/BN/LR/SHL). These spellings are allowed only at opt-in
// reconstruction sites -- currently the loader validation dispatch chain and
// its decoys on the Luau path -- and the gates below pin the properties the
// design promises, so a future edit cannot silently weaken the batch:
//
// * every bit-composed arm keeps the exact value under u32 bit semantics (the
//   exactness is what lets the validator accept real bytecode while the shape
//   still resists direct evaluation);
// * no arm spells its own value with a digit run;
// * no operand inside a bit-composed arm is the value itself or an audit-nice
//   literal -- the census must get nothing to point inside;
// * every family the pool offers actually shows up under the sweep;
// * the shipped Luau artifact contains the bit-condensed constants (any
//   accidental revert of the emit-site opt-in drains the fingerprint to 0);
// * the shipped Lua 5.1 artifact remains byte-identical in this family -- its
//   fingerprint count stays exactly 0 (plus the agent-verified full-byte cmp
//   recorded against the previous export).

#[test]
fn opaque_bit_families_are_exact_and_never_plain() {
    let mut random = Prng::lcg(0x6269_7473_5f66_616d);
    let mut values: Vec<u64> = vec![0, 1, 2, 3, 86, 255, 256, 4096, 65_535, 12_345];
    values.extend(0..64);
    for &value in &values {
        for _ in 0..40 {
            let text = random.opaque_literal_scoped(value, true, true, "X");
            assert!(
                !Prng::spells_value(value, &text),
                "bit-composed text {text} still spells {value}"
            );
            // The existing arm splitter already understands the guard and the
            // two candidate spellings; both must fold back to the same value
            // under the crate's now-bit-aware evaluator.
            let (guard, first, second) = crate::random::tests::opaque_parts(&text);
            assert!(
                crate::random::tests::OvParser::truthy(guard, 7),
                "guard {guard}"
            );
            for arm in [first.clone(), second.clone()] {
                assert_eq!(
                    crate::random::tests::OvParser::parse(arm, 7),
                    value as i64,
                    "{text}: arm {arm} folded != {value}"
                );
            }
            assert_eq!(
                crate::random::tests::OvParser::parse(&text, 7),
                value as i64,
                "whole {text} folded != {value}"
            );
        }
    }
}

#[test]
fn opaque_bit_operands_are_never_the_value_never_audit_nice() {
    let mut random = Prng::sfc(0x6f70_6572_616e_6473);
    let mut saw = [0usize; 4];
    for value in [3u64, 7, 32, 86, 255, 1_337, 123_456] {
        for _ in 0..30 {
            let text = random.opaque_literal_scoped(value, true, true, "X");
            for (slot, pat) in ["(BX(", "(BA(", "(LR(", "BA(BX("].iter().enumerate() {
                if text.contains(pat) {
                    saw[slot] += 1;
                }
            }
            // Every digit group *inside a bit-composed arm* is checked against
            // the audit-nice table and the value: an operand like 86 or 256
            // inside `BX(...)` would hand the auditor a pointer into the
            // composed text. (The neighbouring arithmetic arms follow their
            // own, older invariants and keep their K9A-legit small operands.)
            let (guard, first, second) = crate::random::tests::opaque_parts(&text);
            for arm in [first, second] {
                if arm.contains("BX(") || arm.contains("BA(") || arm.contains("LR(") {
                    for group in digit_groups(arm) {
                        // The all-ones mask and the rotate frame (2^32) are
                        // M1/M2 family *structure*, per-seed constants of the
                        // wrapper itself -- not operands. The random-drawn
                        // operands still must never equal the value or an
                        // audit-nice anchor.
                        if group == 4294967295 || group == 4294967296 {
                            continue;
                        }
                        assert!(
                            group != value,
                            "operand {group} inside bit arm of {text} is the value"
                        );
                        // Audit-nice anchors are all four digits or shorter; on
                        // shorter operands the K9A split forms legitimately use
                        // them, so the census check targets the five-digit-plus
                        // lane where these families actually draw.
                        if group >= 10_000 {
                            assert!(
                                !Prng::audit_nice(group),
                                "operand {group} inside bit arm of {text} is audit-nice"
                            );
                        }
                    }
                }
            }
            let _ = guard;
        }
    }
    // The sweep must exercise every family the pool offers; a seed path that
    // never lands one family would silently halve the cross-family diversity.
    let [fxor, fband, frot, fchain] = saw;
    assert!(
        fxor > 0 && fband > 0 && frot > 0 && fchain > 0,
        "bit families not all exercised: {saw:?}"
    );
}

/// Digit runs of the text as numeric groups -- the census looks at digit runs,
/// so the gate does too.
fn digit_groups(text: &str) -> Vec<u64> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().unwrap())
        .collect()
}

/// The structural fingerprint of a bit-composed constant after minification:
/// a short renamed selector `uv(UUUUU,VVVVV)` with both operands five digits
/// or longer. Plain arithmetic arms never produce that shape -- their texts
/// are `((n+k))`-style, and the capture selectors never take two large
/// constants at once anywhere else in the pipeline.
fn bit_call_fingerprints(text: &str) -> usize {
    let bytes = text.as_bytes();
    let is_lower = |b: u8| b.is_ascii_lowercase();
    let digit_len = |mut at: usize| {
        let start = at;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
        }
        at - start
    };
    let mut count = 0usize;
    let mut at = 0usize;
    while at < bytes.len() {
        if is_lower(bytes[at]) {
            let name_start = at;
            while at < bytes.len() && is_lower(bytes[at]) {
                at += 1;
            }
            let name_len = at - name_start;
            if (1..=2).contains(&name_len) && at < bytes.len() && bytes[at] == b'(' {
                let first = digit_len(at + 1);
                let comma = at + 1 + first;
                if first >= 5 && comma < bytes.len() && bytes[comma] == b',' {
                    let second = digit_len(comma + 1);
                    let close = comma + 1 + second;
                    if second >= 5 && close < bytes.len() && bytes[close] == b')' {
                        count += 1;
                        at = close;
                        continue;
                    }
                }
            }
            continue;
        }
        at += 1;
    }
    count
}

#[test]
fn shipped_luau_artifact_carries_bit_composed_constants() {
    // Seed 7351's export: the opt-in sites (loader validation dispatch, its
    // boundary levels and its decoys) must all exercise the bit pool; at the
    // time of pinning the families together printed 48 fingerprints, so a
    // factor-two floor keeps future healthy growth from tripping the gate
    // while a silent revert (bits=false at all sites) would still read 0.
    let script = include_str!("../../../../vm_luau.out.lua");
    let count = bit_call_fingerprints(script);
    assert!(
        count >= 24,
        "loader validation bit-composed constants faded to {count}"
    );
}

#[test]
fn shipped_lua51_artifact_never_carries_bit_composed_constants() {
    // The bit families are Luau-only (the Lua 5.1 chain has no bit32 to
    // capture). Any fingerprint here would mean the opt-in guard leaked.
    let script = include_str!("../../../../vm_lua51.out.lua");
    assert_eq!(
        bit_call_fingerprints(script),
        0,
        "lua51 export picked up bit-composed constants"
    );
}
