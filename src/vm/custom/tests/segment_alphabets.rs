// Split out of `tests/transport.rs` (2026-09-13, K3-FULL 第二步) while that file was at
// its 81,920 B source ceiling; `include!` keeps the shared module scope.
#[test]
fn k9a_image_alphabet_is_seeded_noncontiguous() {
    // K3-FULL 第二步: every property is stated per logical segment table, and
    // the three tables must be genuinely different sets -- that is the whole
    // point of the batch ("one table recovered => all three readable" dies).
    for seed in [7001u64, 7351] {
        let mut sorted_sets = [[0u8; 86]; 3];
        for part in 0..3 {
            let a = base86_segment_alphabet(seed, part);
            assert_eq!(a, base86_segment_alphabet(seed, part));
            let mut sorted = a;
            sorted.sort_unstable();
            sorted_sets[part] = sorted;
            assert_eq!((sorted[0], sorted[85]), (28, 126), "span must be exactly 99");
            let mut deduped = sorted.to_vec();
            deduped.dedup();
            assert_eq!(deduped.len(), 86);
            assert!(a.iter().all(|&byte| (28..=126).contains(&byte)));
            // Order is permuted, not sorted (1/86! to fluke; pinned by seed).
            assert_ne!(a.to_vec(), sorted.to_vec());
        }
        assert_ne!(base86_segment_alphabet(seed, 0), base86_segment_alphabet(seed, 1));
        assert_ne!(base86_segment_alphabet(seed, 1), base86_segment_alphabet(seed, 2));
        assert_ne!(base86_segment_alphabet(seed, 0), base86_segment_alphabet(seed, 2));
        // Distinct as *sets*, not just as orders: two 86/99 draws share 73..86
        // symbols but never all 86 (13 dropped per table, seeded independently).
        for x in 0..3 {
            for y in x + 1..3 {
                assert_ne!(sorted_sets[x], sorted_sets[y], "seed {seed}: parts {x}/{y} drew the same set");
                let shared = sorted_sets[x].iter().filter(|b| sorted_sets[y].contains(b)).count();
                assert!((73..86).contains(&shared), "seed {seed}: parts {x}/{y} share {shared} symbols");
            }
        }
    }
    // Part 0 stays the alias the rest of the suite states codec properties over.
    assert_eq!(base86_image_alphabet(7001), base86_segment_alphabet(7001, 0));
    assert_ne!(base86_image_alphabet(7001), base86_image_alphabet(7351));
}

/// K3-FULL 第二步 (成品级去池证据): each segment bakes **its own** digit table, so
/// no 86-character table text is pasted more than once in the finished script.
/// Before this batch the emitter built one `alpha_literal` outside the segment
/// loop and pasted it three times -- recovering any segment handed over the table
/// for all three (only the K19 fold differed, and that fold is a rotation of the
/// same set). Identifier names are shuffled per seed, so the gate matches the
/// *baked table text* rather than a name.
#[test]
fn k3s2_baked_alpha_tables_are_per_segment_in_the_script() {
    /// Exactly the emitter's fragment packing: 11 characters per quoted piece,
    /// `..` between them, decimal escapes only.
    fn baked(alpha: &[u8; 86]) -> String {
        let mut lit = String::new();
        for (index, frag) in alpha.chunks(11).enumerate() {
            if index > 0 {
                lit.push_str("..");
            }
            lit.push('"');
            lit.push_str(&lua_escape_string(frag));
            lit.push('"');
        }
        lit
    }
    for target in [Target::Lua51, Target::Luau] {
        for seed in [0u64, 1, 3, 7001, 7351, 999983, u64::MAX] {
            let data = compile("return 7", target).unwrap();
            let output = emit(&data, target, seed).unwrap();
            let mut lits = Vec::new();
            for part in 0..3 {
                let alpha = base86_segment_alphabet(seed, part);
                let lit = baked(&alpha);
                assert_eq!(
                    output.matches(lit.as_str()).count(),
                    1,
                    "{target} seed {seed}: segment {part}'s table appears {} times",
                    output.matches(lit.as_str()).count()
                );
                // Sub-12 fragments: the table must never qualify as a segment
                // candidate for the audit's "longest three literals" filter.
                for piece in lit.split("..") {
                    let decoded = crate::minify::literal_bytes(piece, target).unwrap();
                    assert!(
                        decoded.len() < 12,
                        "{target} seed {seed}: a baked ALPHA fragment reaches {}",
                        decoded.len()
                    );
                }
                lits.push(lit);
            }
            for x in 0..3 {
                for y in x + 1..3 {
                    assert_ne!(
                        lits[x], lits[y],
                        "{target} seed {seed}: segments {x}/{y} baked the same table"
                    );
                }
            }
        }
    }
}
