// K19 chain-replay gates for the transport layer, physically split out of
// `tests/transport.rs` (that file had reached the 81,920 B implementation-source ceiling;
// `include!` keeps the shared module scope, so the helpers above stay in view). These
// gates read the *emitted* segment text, so they anchor the alphabet pool the decoder
// builds -- which is why the K3-FULL notes about the shared `ALPHA` belong here as well
// (see 项目交接总结.md, "K3-FULL 施工单").

#[test]
fn k19_an_edit_inside_the_head_segment_never_yields_a_different_accepted_stream() {
    // The security claim in one gate: single-symbol edits anywhere in the chain
    // root either stay invisible (they cannot, here) or kill the whole chain --
    // never re-key it into a different payload that still passes. Sampled
    // positions across the segment; the fail-closed half is the hard part.
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("local function f(x)return x+1 end print(f(41))", target).unwrap();
        let output = emit(&data, target, 7001).unwrap();
        let alphabet = base86_image_alphabet(7001);
        let mut segments = segment_literals(&output, target, 7001).unwrap();
        let orders = chained_segment_orders(&segments, &alphabet);
        assert_eq!(orders.len(), 1, "{target}: baseline chain not unique");
        let baseline = orders[0].1.clone();
        let head = orders[0].0[0];
        let original = segments[head].clone();
        let mut fatal = 0usize;
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
            match chained_segment_orders(&segments, &alphabet) {
                found if found.is_empty() => fatal += 1,
                found => {
                    assert_eq!(found.len(), 1, "{target}: an edit created a second order");
                    assert_eq!(
                        found[0].1, baseline,
                        "{target} position {position}: an edit changed the accepted stream"
                    );
                }
            }
        }
        assert_eq!(
            fatal, sampled,
            "{target}: {}/{} sampled edits silently decoded to the same stream",
            fatal, sampled
        );
    }
}
