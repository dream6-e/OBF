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
    for (target, seed, expected) in [
        (Target::Lua51, 7001u64, (848usize, 0usize, 0u32)),
        (Target::Luau, 7351u64, (676usize, 0usize, 0u32)),
    ] {
        let data = compile(AUDIT_PROBE, target).unwrap();
        let output = emit(&data, target, seed).unwrap();
        let inner = transport::extract_embedded(&output, target, seed).unwrap();
        assert!(!inner.is_empty(), "{target} seed {seed}: empty inner layer");
        let actual = stream_word_stats(&inner);
        assert_eq!(actual, expected, "{target} seed {seed}: inner keystream repeats");
    }
}
