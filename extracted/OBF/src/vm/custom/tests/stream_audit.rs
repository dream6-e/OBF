// K5 position-dependent keystream gate: check 8 of the core-techniques
// audit on REAL word streams. The outer ChaCha8 input is already pinned by
// T1-M6 ((pairs, gcd) = (0, 0) on both audit configs); this file pins the
// inner ChaCha8 input (`extract_embedded`): repeated u32 words must show no
// periodic structure, i.e. the keystream depends on position (counter mode),
// so "same plaintext -> same ciphertext" cannot happen and the repeat-gap
// gcd self-check bit stays dead. Reuses T1's probe and gcd helper (shared
// module scope); any residual position-independent XOR layer would surface
// here as gcd > 1 or a nonzero pair count drift.
fn stream_word_stats(bytes: &[u8]) -> (usize, usize, u32) {
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    let mut pairs = 0usize;
    let mut gcd = 0u32;
    for (i, &word) in words.iter().enumerate() {
        for (j, &other) in words.iter().enumerate().skip(i + 1) {
            if word == other {
                pairs += 1;
                gcd = audit_gcd(gcd, (j - i) as u32);
            }
        }
    }
    (bytes.len(), pairs, gcd)
}

#[test]
fn inner_ciphertext_words_have_no_periodic_repeats() {
    // Word counts re-recorded for ISA16 (K12 chains the operand lane keys over
    // the decoded record prefix, which changes varint lengths slightly). The
    // security-relevant halves stay at zero: no repeated word, no common
    // divisor among repeat distances.
    // Re-recorded 2026-09-11 for K13c step 2 (ISA17): the constant pool payloads
    // are keyed, so the inner plaintext stream differs and the number of 4-byte
    // words in it moved (lua51 975 -> 997, luau 778 -> 799). The security-relevant halves are
    // pinned at zero and stay zero: no repeated word, no common divisor among
    // repeat distances.
    // Re-recorded 2026-09-11 for K18: the sampler became bias-free (multiply-shift
    // instead of a remainder) and the domains split across three mixing families,
    // so keyed varint lengths shift again (lua51 997 -> 978, luau 799 -> below).
    // Word *count* is a length artifact; both zero halves are unchanged, and
    // `stream_word_stats` still sees no repeat.
    // Re-recorded 2026-09-12 for K3-FULL (ISA18): every recipe slot gained a second
    // byte (the operand form rides in the image instead of being looked up in a form
    // table the script builds), so the inner plaintext stream is longer and the word
    // count moves with it (lua51 978 -> 1093, luau 982 -> 1094). Both zero halves stay
    // zero: still no repeated 4-byte word and no common divisor among repeat
    // distances -- the added byte is a 3-bit value per slot, which is exactly the kind
    // of structure a repeat census would catch, and it does not produce one.
    // Re-recorded 2026-09-15 for goal 5 (ISA19): the constants moved out of the
    // pool section into each prototype's code-region tail and are keyed with the
    // same `pool_key_fold` chain, so the inner plaintext stream changes length
    // again (lua51 1093 -> 1072, luau 1094 -> 1076 -- the block is shorter than
    // the per-record pool encoding it replaced, by a different amount per
    // target). Both zero halves stay zero: still no repeated 4-byte word and no
    // common divisor among repeat distances -- the newly added keyed bytes and
    // the u32 block lengths are exactly what this census would catch as
    // structure, and they do not produce one.
    for (target, seed, expected) in [
        (Target::Lua51, 7001u64, (1063usize, 0usize, 0u32)),
        // Goal 6 (2026-09-16): re-keying the payload bytes moves one byte of the
        // decoded stream on this config (1076 -> 1077) while lua51 stays at 1072 --
        // a length artifact of the transport's LZW framing, not of the constants.
        // Both zero halves stay zero: still no repeated 4-byte word and no common
        // divisor among repeat distances, which is what says the rolling keystream
        // introduced no periodic structure of its own.
        (Target::Luau, 7351u64, (1075usize, 0usize, 0u32)),
    ] {
        let data = compile(AUDIT_PROBE, target).unwrap();
        let output = emit(&data, target, seed).unwrap();
        let inner = transport::extract_embedded(&output, target, seed).unwrap();
        assert!(!inner.is_empty(), "{target} seed {seed}: empty inner layer");
        let actual = stream_word_stats(&inner);
        assert_eq!(actual, expected, "{target} seed {seed}: inner keystream repeats");
    }
}
