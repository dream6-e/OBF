// K19 segmented-key inverse tests split out of `transport.rs` for the
// permanent 80 KiB source-file gate (same `include!` scope, logic unchanged).

#[test]
fn k19_digit_rotation_is_an_exact_inverse_at_every_rotation() {
    // The encoder writes digit d at alphabet slot (d - ro) mod 86 and the
    // decoder reads slot j as digit (j + ro) mod 86, so the two must be exact
    // inverses at every rotation: otherwise a segment would decode against a
    // different table than the one it was written with. A rotation must also
    // be size-neutral -- it re-keys the text, it does not lengthen it.
    let alphabet = base86_image_alphabet(7001);
    for seed in [0u64, 1, 2, 7, 999_983] {
        let bytes: Vec<u8> = (0..4096u32)
            .map(|index| index.wrapping_mul(2_654_435_761 >> 13) as u8)
            .collect();
        for rotation in 0..86u64 {
            let text = base86_encode_mixed_ro(&bytes, &alphabet, &mut crate::random::Prng::sfc(seed), rotation);
            assert_eq!(
                base86_decode_mixed_ro(&text, &alphabet, rotation).unwrap(),
                bytes,
                "seed {seed} rotation {rotation}"
            );
        }
        let plain = base86_encode_mixed_ro(&bytes, &alphabet, &mut crate::random::Prng::sfc(seed), 0);
        let turned = base86_encode_mixed_ro(&bytes, &alphabet, &mut crate::random::Prng::sfc(seed), 5);
        assert_eq!(plain.len(), turned.len(), "rotation changed the footprint");
        assert_ne!(plain, turned, "rotation is cosmetic");
        match base86_decode_mixed_ro(&turned, &alphabet, 0) {
            Ok(_) => panic!("seed {seed}: a stale rotation still decoded the whole segment"),
            Err(_) => {}
        }
    }
}

#[test]
fn k19_segment_key_fold_loads_every_byte_and_the_length() {
    // The fold is the only thing a later segment keys on, so it must stay in
    // range, react to every sampled byte and to the length. That the emitted
    // Lua computes the same value is proven elsewhere: the chained-segment
    // harness gate executes the real field against Rust-mirror bytes, so any
    // drift between this loop and the generated `RO=(RO+bb)*MM%r` fails there.
    let base: Vec<u8> = (0..512u32).map(|index| (index % 251) as u8).collect();
    let anchor = segment_key_fold(&base);
    assert!(anchor < 86, "fold left the table range");
    for index in [0usize, 1, 7, 63, 255, 383, 511] {
        let mut edited = base.clone();
        edited[index] = edited[index].wrapping_add(1);
        assert!(segment_key_fold(&edited) < 86);
        assert_ne!(segment_key_fold(&edited), anchor, "byte {index} is inert");
    }
    assert_ne!(
        segment_key_fold(&base[..base.len() - 1]),
        anchor,
        "the folded length is inert"
    );
    let mut swapped = base.clone();
    swapped.swap(11, 260);
    assert_ne!(
        segment_key_fold(&swapped),
        anchor,
        "a transposition inside the segment is invisible"
    );
}
