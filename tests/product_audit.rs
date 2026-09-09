//! K0 product-text audit: section 3 of the core-techniques doc, adapted to
//! OBF's output shape. The 9 static-leak checks run against the checked-in
//! goldens; the FAIL counts are pinned. Each K-batch tightens its checks
//! toward zero (a FAIL means that build can be pushed one step statically).
//! Check 8 on REAL word streams lives unit-side (`stream_audit.rs`, where the
//! transport accessors are reachable); here check 8 runs the literal fallback.

use obf::lexer::{self, TokenKind};
use obf::Target;
use std::collections::{BTreeMap, BTreeSet};

const GOLDEN_LUA51: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/vm_lua51.out.lua");
const GOLDEN_LUAU: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/vm_luau.out.lua");

// Doc [1] set {85^k} + {2^32-1, 2^32, 2^32+1, 2^31, 2^16-1, 65536, 256},
// extended with OBF's own radix family (86^k), the witness-hash modulus
// 2^31-1 and the byte-split weight 2^24.
const NICE: [u64; 17] = [
    85, 7225, 614125, 52200625, 86, 7396, 636056, 54700816, 256, 65535, 65536, 16777216,
    2147483648, 2147483647, 4294967295, 4294967296, 4294967297,
];

#[derive(Debug, PartialEq)]
struct AuditPins {
    check1_nice_fails: Vec<(u64, usize)>,
    check2_alphabet: (usize, usize, bool), // (distinct, span, fail)
    check3_noise_pairs: usize,
    check4_thresholds: (usize, u64, bool), // (distinct, max, fail)
    check5_templates: (usize, Vec<(String, usize)>), // (fail_count, top8)
    check6_alias_prologues: usize,
    check7_dead_tables: Vec<String>,
    check8_literal_gcd: (u64, usize),    // (gcd, pairs)
    check9_stream: (usize, usize, bool), // (total_len, rem5, fail)
}

// Pins observed 2026-09-09 (K9a mixed transport). K-batches tighten.
// K9a: [2] -> (86, 99, clean), [9] -> clean under the new rule; [1] drops
// the 85/4294967295 anchors and sheds 86/256 hits (opaque splits, VAL
// table, label hygiene: slot keys avoid 85/86, states avoid 256, wrapper
// keys avoid 256/7225/7396); remaining 86s are forms/decoy code (K9b's).
// [5] grows (3 self-contained decoders triple shapes; shape diversity is
// K7's scope); [6] flips on layout-shuffle artifacts (pre-existing text,
// position luck); [8] re-indexes on the fresh M24 addends. [3]/[4]/[7]
// stable; 16777216/2147483647/4294967296 untouched (M24 split adds zero).
fn pins_lua51() -> AuditPins {
    AuditPins {
        check1_nice_fails: vec![
            (86, 4),
            (256, 156),
            (65536, 96),
            (16777216, 8),
            (2147483647, 27),
            (4294967296, 29),
        ],
        check2_alphabet: (86, 99, false),
        check3_noise_pairs: 0,
        check4_thresholds: (2, 65535, false),
        check5_templates: (
            12,
            vec![
                ("X=N*X%N".to_string(), 21),
                ("X[N]=N".to_string(), 19),
                ("X[N]=X[N]+X[N]*X[N]X[N]=X[N]*X[N]X".to_string(), 18),
                ("X[N]=X[N][X[N]]XX[N]==XXX()X".to_string(), 18),
                ("X[N]=N+N".to_string(), 9),
                (
                    "X[N]=NXX=N,NXX[N]=X(X[N],X[N]+X-N)XX[N]==XXX()X".to_string(),
                    9,
                ),
                ("X=(X+X+(N*N+N))%N".to_string(), 8),
                ("X=NXXXXXXX=(X*N+X+X+X+X+(N*N+N))%N".to_string(), 8),
            ],
        ),
        check6_alias_prologues: 0,
        check7_dead_tables: Vec::new(),
        check8_literal_gcd: (1, 85),
        check9_stream: (15536, 1, false),
    }
}

fn pins_luau() -> AuditPins {
    AuditPins {
        check1_nice_fails: vec![
            (86, 4),
            (256, 161),
            (65536, 98),
            (16777216, 8),
            (2147483647, 22),
            (4294967296, 29),
        ],
        check2_alphabet: (86, 99, false),
        check3_noise_pairs: 0,
        check4_thresholds: (2, 65535, false),
        check5_templates: (
            11,
            vec![
                ("X[N]=N".to_string(), 19),
                ("X[N]=X[N]+X[N]*X[N]X[N]=X[N]*X[N]X".to_string(), 18),
                ("X[N]=X[N][X[N]]XX[N]==XXX()X".to_string(), 18),
                ("X=N*X%N".to_string(), 16),
                ("X[N]=N+N".to_string(), 9),
                (
                    "X[N]=NXX=N,NXX[N]=X(X[N],X[N]+X-N)XX[N]==XXX()X".to_string(),
                    9,
                ),
                ("X=(X+X+(N*N+N))%N".to_string(), 8),
                (
                    "X[N]=NXX=N,X[N]XX[N]=X(X[N],X[N]+X-N)XX[N]==XXX()X".to_string(),
                    6,
                ),
            ],
        ),
        check6_alias_prologues: 1,
        check7_dead_tables: Vec::new(),
        check8_literal_gcd: (1, 90),
        check9_stream: (20687, 2, false),
    }
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Count decimal occurrences of `value` with identifier/float boundaries
/// (neither side may be `[A-Za-z0-9_.]`).
fn count_decimal(body: &str, value: u64) -> usize {
    let bytes = body.as_bytes();
    let digits = value.to_string();
    let needle = digits.as_bytes();
    let mut count = 0;
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let left_ok = i == 0 || (!is_word_byte(bytes[i - 1]) && bytes[i - 1] != b'.');
            let right_at = i + needle.len();
            let right_ok = right_at >= bytes.len()
                || (!is_word_byte(bytes[right_at]) && bytes[right_at] != b'.');
            if left_ok && right_ok {
                count += 1;
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

fn audit_gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Decoded bytes of every string token: K9a payload segments carry `\"` /
/// `\\` / `\ddd` escapes (non-contiguous alphabet), so filters match on
/// post-escape bytes through the real literal parser. Spans still delimit
/// the raw source ranges for masking.
fn string_inners(body: &str, target: Target) -> Vec<(usize, usize, Vec<u8>)> {
    let mut out = Vec::new();
    for token in lexer::lex(body, target).unwrap() {
        if token.kind != TokenKind::String {
            continue;
        }
        let decoded = obf::minify::literal_bytes(token.text(body), target)
            .unwrap_or_else(|error| panic!("audit: bad string literal: {error}"));
        out.push((token.span.start, token.span.end, decoded));
    }
    out
}

/// The three payload segment literals (same filters as `segment_literals`:
/// decoded length, image-alphabet membership, longest three win; mixed
/// groups make divisibility meaningless).
fn segments(inners: &[(usize, usize, Vec<u8>)], seed: u64) -> Vec<Vec<u8>> {
    let alphabet = obf::vm::custom::base86_image_alphabet(seed);
    let mut member = [false; 256];
    for &byte in &alphabet {
        member[byte as usize] = true;
    }
    let mut candidates: Vec<Vec<u8>> = inners
        .iter()
        .map(|(_, _, bytes)| bytes.clone())
        .filter(|value| value.len() >= 12 && value.iter().all(|&byte| member[byte as usize]))
        .collect();
    assert!(
        candidates.len() >= 3,
        "audit: golden lost its three payload segments"
    );
    candidates.sort_by_key(|literal| std::cmp::Reverse(literal.len()));
    candidates.truncate(3);
    candidates
}

/// Body with every string span replaced by `S` (keeps statement shapes small
/// and `;`-splitting sound: masking is span-based, so payload escapes and
/// `;` bytes inside segments cannot leak into shapes).
fn masked_body(body: &str, inners: &[(usize, usize, Vec<u8>)]) -> String {
    let mut out = String::with_capacity(body.len() / 4);
    let mut prev = 0;
    for (start, end, _) in inners {
        out.push_str(&body[prev..*start]);
        out.push('S');
        prev = *end;
    }
    out.push_str(&body[prev..]);
    out
}

/// Normalize a `;`-separated statement: identifiers -> X, digit runs -> N,
// whitespace dropped, structure kept.
fn normalize_shape(fragment: &str) -> String {
    let bytes = fragment.as_bytes();
    let mut shape = String::with_capacity(fragment.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            while i < bytes.len() && is_word_byte(bytes[i]) {
                i += 1;
            }
            shape.push('X');
        } else if c.is_ascii_digit() {
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            shape.push('N');
        } else if c.is_ascii_whitespace() {
            i += 1;
        } else {
            shape.push(c as char);
            i += 1;
        }
    }
    shape
}

fn audit_golden(path: &str, target: Target, seed: u64) -> AuditPins {
    let body = std::fs::read_to_string(path).unwrap();
    assert!(!body.is_empty(), "audit: golden {path} missing");

    // [1] pretty constants: any nice value occurring >2 times is an anchor.
    let mut check1 = Vec::new();
    for value in NICE {
        let count = count_decimal(&body, value);
        if count > 2 {
            check1.push((value, count));
        }
    }

    // [2]/[9] segment stream over DECODED bytes: alphabet contiguity +
    // length divisibility. K9a kills both clean rules (non-contiguous
    // 86-subset alphabet, mixed group widths), so [9] now fires only on
    // the everything-multiple-of-5 pathology (P ~ 0.16% for healthy
    // output; a hit means reseed the golden and investigate).
    let inners = string_inners(&body, target);
    let segs = segments(&inners, seed);
    let mut distinct = BTreeSet::new();
    let mut total = 0usize;
    for seg in &segs {
        total += seg.len();
        distinct.extend(seg.iter().copied());
    }
    let span = *distinct.last().unwrap() as usize - *distinct.first().unwrap() as usize + 1;
    let check2 = (distinct.len(), span, span - distinct.len() <= 12);
    let check9 = (
        total,
        total % 5,
        total % 5 == 0 && segs.iter().all(|seg| seg.len() % 5 == 0),
    );

    // [3] noise pairs summing to 2^32 (adapted: any literal pair around a
    // 2^32-1 site that cancels unconditionally).
    let mut check3 = 0usize;
    let max_marker = "4294967295";
    let mut search = 0;
    while let Some(hit) = body[search..].find(max_marker) {
        let at = search + hit;
        let before = &body[..at];
        let after = &body[at + max_marker.len()..];
        let back: Vec<u64> = before
            .rsplit(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty() && s.len() <= 10)
            .filter_map(|s| s.parse().ok())
            .take(1)
            .collect();
        let fwd: Vec<u64> = after
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty() && s.len() <= 10)
            .filter_map(|s| s.parse().ok())
            .take(1)
            .collect();
        if let (Some(&a), Some(&b)) = (back.first(), fwd.first()) {
            if a.wrapping_add(b) & (u64::from(u32::MAX)) == 0 && (a, b) != (0, 0) {
                check3 += 1;
            }
        }
        search = at + 1;
    }

    // [4] comparison-threshold density.
    let mut thresholds: Vec<u64> = Vec::new();
    let mut rest = body.as_str();
    while let Some(hit) = rest.find("<=") {
        let after = rest[hit + 2..].trim_start();
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            thresholds.push(digits.parse().unwrap());
        }
        rest = &rest[hit + 2..];
    }
    let distinct_th: BTreeSet<u64> = thresholds.iter().copied().collect();
    let check4 = if distinct_th.is_empty() {
        (0, 0, false)
    } else {
        let max = *distinct_th.last().unwrap();
        (distinct_th.len(), max, max < 3 * distinct_th.len() as u64)
    };

    // [5]/[6] statement shapes + alias prologues over `;`-split statements.
    let masked = masked_body(&body, &inners);
    let mut shapes: BTreeMap<String, usize> = BTreeMap::new();
    let mut check6 = 0usize;
    for fragment in masked.split(';') {
        let shape = normalize_shape(fragment);
        if shape.is_empty() {
            continue;
        }
        *shapes.entry(shape.clone()).or_insert(0) += 1;
        if fragment.trim_start().starts_with("local ") {
            let mut slots = 0;
            let bytes = fragment.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'[' {
                    let mut j = i + 1;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                    if j > i + 1 && j < bytes.len() && bytes[j] == b']' {
                        slots += 1;
                        i = j + 1;
                        continue;
                    }
                }
                i += 1;
            }
            if slots >= 6 {
                check6 += 1;
            }
        }
    }
    let mut fails: Vec<(String, usize)> = shapes
        .into_iter()
        .filter(|(_, c)| *c > 4)
        .map(|(s, c)| (s, c))
        .collect();
    fails.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let check5 = (fails.len(), fails.into_iter().take(8).collect());

    // [7] dead tables: 2+ six-digit literals inside braces, name used <=once.
    let mut check7 = BTreeSet::new();
    let bytes = body.as_bytes();
    let mut stack: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => stack.push(i),
            b'}' => {
                if let Some(open) = stack.pop() {
                    let inner = &body[open + 1..i];
                    if !inner.contains(['{', '}']) {
                        let big = inner
                            .split(|c: char| !c.is_ascii_digit())
                            .filter(|s| s.len() >= 6)
                            .count();
                        if big >= 2 {
                            let head = body[..open].trim_end();
                            if let Some(eq) = head.rfind('=') {
                                if !matches!(
                                    head.as_bytes().get(eq.wrapping_sub(1)),
                                    Some(b'=' | b'~' | b'<' | b'>')
                                ) {
                                    let name: String = head[..eq]
                                        .trim_end()
                                        .chars()
                                        .rev()
                                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                                        .collect::<String>()
                                        .chars()
                                        .rev()
                                        .collect();
                                    if !name.is_empty() && name != "local" {
                                        let refs = body
                                            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                                            .filter(|w| *w == name)
                                            .count();
                                        if refs <= 1 {
                                            check7.insert(name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    // [8] literal fallback: gcd of gaps between repeated 6+ digit literals.
    let mut positions: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut index = 0usize;
    let mut k = 0;
    while k < bytes.len() {
        if bytes[k].is_ascii_digit()
            && (k == 0 || !is_word_byte(bytes[k - 1]) && bytes[k - 1] != b'.')
        {
            let mut j = k;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j - k >= 6 && (j >= bytes.len() || !is_word_byte(bytes[j]) && bytes[j] != b'.') {
                positions.entry(&body[k..j]).or_default().push(index);
                index += 1;
                k = j;
                continue;
            }
        }
        k += 1;
    }
    let mut gcd = 0u64;
    let mut pairs = 0usize;
    for pos in positions.values() {
        for window in pos.windows(2) {
            gcd = audit_gcd(gcd, (window[1] - window[0]) as u64);
            pairs += 1;
        }
    }
    let check8 = (gcd, pairs);

    AuditPins {
        check1_nice_fails: check1,
        check2_alphabet: check2,
        check3_noise_pairs: check3,
        check4_thresholds: check4,
        check5_templates: check5,
        check6_alias_prologues: check6,
        check7_dead_tables: check7.into_iter().collect(),
        check8_literal_gcd: check8,
        check9_stream: check9,
    }
}

#[test]
fn product_text_audit_pins_hold_on_both_goldens() {
    for (path, target, seed, pins) in [
        (GOLDEN_LUA51, Target::Lua51, 7001u64, pins_lua51()),
        (GOLDEN_LUAU, Target::Luau, 7351u64, pins_luau()),
    ] {
        let actual = audit_golden(path, target, seed);
        assert_eq!(actual, pins, "{path}: product surface moved");
    }
}
