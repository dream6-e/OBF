// K19 chain-replay gates for the transport layer, physically split out of
// `tests/transport.rs` (that file had reached the 81,920 B implementation-source ceiling;
// `include!` keeps the shared module scope, so the helpers above stay in view). These
// gates read the *emitted* segment text, so they anchor the alphabet pool the decoder
// builds -- which is why the K3-FULL notes about the shared `ALPHA` belong here as well
// (see 项目交接总结.md, "K3-FULL 施工单").

#[test]
fn k19_an_edit_inside_the_head_segment_never_yields_a_different_accepted_stream() {
    // The security claim in one gate: single-symbol edits anywhere in the chain
    // root either stay invisible (byte-identical stream) or die -- either at the
    // chain-order search itself (`chained_segment_orders` finds no candidate:
    // the mutated rotation desynchronizes the following segments) or, when the
    // mod-86 fold happens to collide, at the *full* acceptance path
    // (`accept_segment_streams`: outer/inner ChaCha8 domains, frame v2
    // authentication, strict LZW and the semantic Adler gate). Never a
    // different-but-accepted stream.
    //
    // Goal 5 attribution: until 2026-09-15 this gate used "the chain search
    // resolved a candidate whose decoded parts equal the baseline" as its
    // definition of "accepted", which is weaker than the requirement it
    // encodes -- the fold is an 86-valued checksum, so a collision lets a
    // mutated head segment resolve and the promise then rested on a proxy
    // instead of on the acceptance path. The goal-5 payload reshuffle moved
    // the emitted bytes and surfaced the weaker proxy (8 of ~74 samples per
    // target collided); the fix is to state the claim over the real path.
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("local function f(x)return x+1 end print(f(41))", target).unwrap();
        let output = emit(&data, target, 7001).unwrap();
        let alphabet = base86_image_alphabet(7001);
        let mut segments = segment_literals(&output, target, 7001).unwrap();
        let orders = chained_segment_orders(
            &segments,
            &base86_segment_alphabets(7001),
        );
        assert_eq!(orders.len(), 1, "{target}: baseline chain not unique");
        let baseline = orders[0].1.clone();
        // Sanity: the acceptance path does accept the untouched chain, so the
        // rejection below cannot be an always-Err helper.
        assert!(
            accept_segment_streams(&segments, target, 7001).is_ok(),
            "{target}: the baseline chain must be accepted"
        );
        let head = orders[0].0[0];
        let original = segments[head].clone();
        let mut fatal = 0usize;
        let mut invisible = 0usize;
        let mut relayed = 0usize;
        let mut sampled = 0usize;
        for position in (0..original.len()).step_by((original.len() / 64).max(1)) {
            let slot = alphabet
                .iter()
                .position(|&byte| byte == original[position])
                .expect("segment symbols come from the alphabet");
            let mut bad = original.clone();
            bad[position] = alphabet[(slot + 1) % 86];
            segments[head] = bad;
            sampled += 1;
            match chained_segment_orders(
            &segments,
            &base86_segment_alphabets(7001),
        ) {
                found if found.is_empty() => fatal += 1,
                found => {
                    assert_eq!(found.len(), 1, "{target} position {position}: an edit created a second order");
                    if found[0].1 == baseline {
                        // Invisible: the fold is unchanged, so every following
                        // segment re-decodes to the identical stream.
                        invisible += 1;
                    } else {
                        relayed += 1;
                        assert!(
                            accept_segment_streams(&segments, target, 7001).is_err(),
                            "{target} position {position}: an edit was accepted as a different stream"
                        );
                    }
                }
            }
        }
        segments[head] = original;
        assert!(sampled >= 64, "{target}: only {sampled} sampled positions");
        assert_eq!(
            fatal + invisible + relayed,
            sampled,
            "{target}: edit census does not add up"
        );
    }
}
