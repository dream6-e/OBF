#[test]
fn goal7_transport_has_no_complete_segment_literal() {
    for (target, seed) in [
        (Target::Lua51, 7001u64),
        (Target::Luau, 7351u64),
        (Target::Lua51, u64::MAX),
    ] {
        let data = compile("local x='fragment-audit' print(x,#x)", target).unwrap();
        let output = emit(&data, target, seed).unwrap();
        let segments = segment_literals(&output, target, seed).unwrap();
        assert_eq!(segments.len(), 3);

        let alphabets = base86_segment_alphabets(seed);
        let mut union = [false; 256];
        for alphabet in &alphabets {
            for &byte in alphabet {
                union[byte as usize] = true;
            }
        }
        let fragments: Vec<Vec<u8>> = crate::lexer::lex(&output, target)
            .unwrap()
            .into_iter()
            .filter(|token| token.kind == crate::lexer::TokenKind::String)
            .map(|token| crate::minify::literal_bytes(token.text(&output), target).unwrap())
            .filter(|value| value.len() >= 12 && value.iter().all(|byte| union[*byte as usize]))
            .collect();

        assert!(
            fragments.len() >= 24,
            "{target} seed {seed}: only {} transport fragments",
            fragments.len()
        );
        for segment in &segments {
            assert!(
                !fragments.iter().any(|fragment| fragment == segment),
                "{target} seed {seed}: a complete transport segment remains a string token"
            );
        }
        let longest_fragment = fragments.iter().map(Vec::len).max().unwrap();
        let shortest_segment = segments.iter().map(Vec::len).min().unwrap();
        assert!(
            longest_fragment < shortest_segment,
            "{target} seed {seed}: fragmentation did not shorten the static literal surface"
        );
    }
}
