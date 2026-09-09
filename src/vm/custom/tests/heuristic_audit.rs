// T1 heuristic-surface audit: pins the detector-visible facts of the final
// blob for two fixed configs, so later T-zone work cannot silently shift
// what YARA-style heuristics key on. Number metrics count VALUES (parsed
// through every spelling the respeller emits), never spellings — so the
// whole audit is immune to respell changes by construction, including the
// T6 paren forms.
const AUDIT_PROBE: &str = "local function f(x)return x+3 end print(f(4),f(9))";
const AUDIT_CONFIGS: [(Target, u64); 2] = [(Target::Lua51, 7001), (Target::Luau, 7351)];

// KAT words: suspicious-API substrings a heuristic would flag on sight.
// Counts are pinned as observed (the compat shim references getfenv);
// any new hit means a newly exposed API surface.
const AUDIT_KAT_WORDS: [&str; 10] = [
    "loadstring",
    "getfenv",
    "setfenv",
    "dofile",
    "loadlib",
    "require",
    "os.",
    "io.",
    "debug.",
    "dump",
];

type AuditPins = (
    usize,                 // M1: distinct alphabet bytes across the stream
    (usize, usize, usize, usize), // M2: stream len + residues mod 3/4/5
    [usize; 10],           // M3a: KAT-word hit counts
    (usize, u64, u64),     // M3b: literals >= 1e6 (count, sum, max)
    [(u64, usize); 12],    // M4: top-12 literal values by (count desc, value asc)
    usize,                 // M4b: non-integer number tokens skipped
    (usize, usize),        // M5: long strings (singleton count, raw bytes sum)
    (usize, u32),          // M6: u32 repeats in outer ciphertext (pairs, gap gcd)
    ([usize; 5], usize),   // M7: top-5 string lens + 3rd/4th gap
);

// Pins observed 2026-09-09 (K9a mixed transport). Any drift means the
// detector-visible surface moved and must be justified in the batch.
// K9a deltas: M2 total/residues (mixed widths + prefixes, arbitrary by
// design); M3b/M4 (opaque M24/MM/C1C2 splits + downstream rng-stream
// shift incl. label hygiene); M4b luau (spelling lottery over the shifted
// stream); M5/M7 raw lengths (escapes + longer segments). Stable: M1 = 86
// distinct bytes, KAT words, M6 = (0, 0), M5 count = 5 (ALPHA frags stay
// sub-64 raw), M7 gap stays in the hundreds.
const PINS_LUA51_7001: AuditPins = (
    86,
    (1189, 1, 1, 4),
    [0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
    (253, 4503942668733487, 4503599627370496),
    [
        (1, 443),
        (0, 385),
        (2, 216),
        (256, 172),
        (3, 160),
        (4, 124),
        (65536, 102),
        (20, 95),
        (5, 82),
        (8, 69),
        (94, 69),
        (41, 67),
    ],
    0,
    (5, 1676),
    (0, 0),
    ([473, 473, 462, 134, 134], 328),
);
const PINS_LUAU_7351: AuditPins = (
    86,
    (950, 2, 2, 0),
    [0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
    (254, 4503936625916531, 4503599627370496),
    [
        (1, 442),
        (0, 382),
        (2, 219),
        (4, 165),
        (256, 148),
        (3, 145),
        (65536, 94),
        (13, 92),
        (5, 76),
        (23, 69),
        (7, 52),
        (30, 52),
    ],
    32,
    (5, 1360),
    (0, 0),
    ([369, 363, 360, 134, 134], 226),
);

/// Value of an integer number token in any spelling the emitter produces
/// (decimal, `0x` hex, trailing-zero scientific). Anything else (floats,
/// overflows, exotic forms) returns `None` and is counted, never parsed.
fn audit_number_value(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if text.bytes().any(|byte| byte == b'.') {
        return None;
    }
    if let Some(exp_at) = text.find('e').or_else(|| text.find('E')) {
        let mantissa: u64 = text[..exp_at].parse().ok()?;
        let exp: u32 = text[exp_at + 1..].parse().ok()?;
        return mantissa.checked_mul(10u64.checked_pow(exp)?);
    }
    text.parse::<u64>().ok()
}

fn audit_gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn audit_metrics(target: Target, seed: u64) -> AuditPins {
    let data = compile(AUDIT_PROBE, target).unwrap();
    let output = emit(&data, target, seed).unwrap();
    let tokens = crate::lexer::lex(&output, target).unwrap();

    // M1/M2: the base86 stream (transport surface, template-independent).
    let segments = transport::segment_literals(&output, target, seed).unwrap();
    let image_alphabet = transport::base86_image_alphabet(seed);
    let mut member = [false; 256];
    for &byte in &image_alphabet {
        member[byte as usize] = true;
    }
    assert_eq!(segments.len(), 3, "{target} seed {seed}: segment count moved");
    let mut distinct = [false; 256];
    let mut stream_len = 0usize;
    for segment in &segments {
        stream_len += segment.len();
        for &byte in segment {
            assert!(
                member[byte as usize],
                "{target} seed {seed}: stream byte {byte} outside the image alphabet"
            );
            distinct[byte as usize] = true;
        }
    }
    let m1 = distinct.iter().filter(|&&seen| seen).count();
    let m2 = (stream_len, stream_len % 3, stream_len % 4, stream_len % 5);

    // M3a: KAT-word hits over the raw text (parens are not words: T6-immune).
    let mut kat = [0usize; 10];
    for (slot, word) in kat.iter_mut().zip(AUDIT_KAT_WORDS) {
        *slot = output.matches(word).count();
    }

    // M3b/M4: value-based number census (spellings canonicalize away).
    let mut counts: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    let mut skipped = 0usize;
    for token in &tokens {
        if token.kind != crate::lexer::TokenKind::Number {
            continue;
        }
        match audit_number_value(token.text(&output)) {
            Some(value) => *counts.entry(value).or_insert(0) += 1,
            None => skipped += 1,
        }
    }
    let mut big_count = 0usize;
    let mut big_sum = 0u64;
    let mut big_max = 0u64;
    for (&value, &count) in &counts {
        if value >= 1_000_000 {
            big_count += count;
            big_sum += value * count as u64;
            big_max = big_max.max(value);
        }
    }
    let mut by_freq: Vec<(u64, usize)> = counts.into_iter().map(|(v, c)| (v, c)).collect();
    by_freq.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    assert!(
        by_freq.len() >= 12,
        "{target} seed {seed}: only {} distinct literal values",
        by_freq.len()
    );
    let mut top12 = [(0u64, 0usize); 12];
    top12.copy_from_slice(&by_freq[..12]);

    // M5/M7: raw string-literal lengths (strings never respell: T6-immune).
    let mut string_lens: Vec<usize> = Vec::new();
    let mut string_groups: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for token in &tokens {
        if token.kind != crate::lexer::TokenKind::String {
            continue;
        }
        let text = token.text(&output);
        string_lens.push(text.len());
        *string_groups.entry(text).or_insert(0) += 1;
    }
    let mut singleton_count = 0usize;
    let mut singleton_bytes = 0usize;
    for (text, count) in &string_groups {
        if *count == 1 && text.len() >= 64 {
            singleton_count += 1;
            singleton_bytes += text.len();
        }
    }
    string_lens.sort_unstable_by(|a, b| b.cmp(a));
    assert!(
        string_lens.len() >= 5,
        "{target} seed {seed}: only {} string literals",
        string_lens.len()
    );
    let mut top5 = [0usize; 5];
    top5.copy_from_slice(&string_lens[..5]);
    let gap = top5[2] - top5[3];

    // M6: repeated u32 words in the outer ciphertext (ECB-style tell).
    let outer = transport::embedded_outer_ciphertext(&output, target, seed).unwrap();
    let words: Vec<u32> = outer
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

    (
        m1,
        m2,
        kat,
        (big_count, big_sum, big_max),
        top12,
        skipped,
        (singleton_count, singleton_bytes),
        (pairs, gcd),
        (top5, gap),
    )
}

#[test]
fn heuristic_surface_pins_hold_on_both_audit_configs() {
    for (target, seed) in AUDIT_CONFIGS {
        let actual = audit_metrics(target, seed);
        let expected = if target.is_luau() {
            PINS_LUAU_7351
        } else {
            PINS_LUA51_7001
        };
        assert_eq!(actual, expected, "{target} seed {seed}: heuristic surface moved");
    }
}
