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

// Pins observed 2026-09-10 (re-recorded after the keyed dual-lane frame tag
// and the pool-assembled Luau probe transcript). Any drift means the
// detector-visible surface moved and must be justified in the batch.
// The previous pins dated from K9a, so two batches of change are absorbed at
// once. K8/K9 added emitted constant sites: the +18 `256` values in M4 are
// theirs, not the tag's -- verified by counting the goldens kept in git (the
// same growth was already present in the commit preceding the tag). The tag
// itself replaced the position-independent Adler fold with two mod-65521
// lanes, which moves M2 total/residues, the M3b count/sum, the 65536 and
// 4294967296 entries of M4, and M5/M7 lengths (longer tag helper text, and a
// shifted downstream rng stream). The Luau probe-transcript fix shifts M3b/M4/
// M5 once more (the pool-joined transcript local adds name-assembly index
// runs; the probes gain one parameter) without introducing a new value class.
// Stable on both targets: M1 = 86 distinct stream bytes, KAT words
// [0,2,0,...] (only the audited getfenv capture), M6 = (0, 0), M5 count = 5
// (ALPHA frags stay sub-64 raw), M7 gaps stay in the hundreds.
// 2026-09-10 ISA16 (K12/T1) re-record: the parser now carries one chained
// recurrence per prototype and every operand lane folds the chain state, which
// moves the value census totals (M2), the M3b count/sum, the M5 literal run and
// the M7 gap lengths; the Luau `23` residue drops by one. Stable and still
// required to stay: M1 = 86 distinct stream bytes, the KAT word vector
// [0,2,0,...] (only the audited getfenv capture), M6 = (0, 0), M5 count = 5,
// and the whole M4 residue table on Lua 5.1 -- i.e. the chain introduces no new
// value class and no new static surface.
// 2026-09-11 K13c step 1 (constant-pool records become byte coordinates)
// re-record: the pool mirror now stores {tag, off, len} and the value is written
// straight into the owning prototype, so exactly three emitted sites change --
// the slice-state gate gains `tg~=0` and `rec[3]` and loses two `==1` tests,
// `val=val==1` moves into the pool loop, and `local KBase,KLen=1,0` is added.
// Literal census of that diff: class 0 +2 (one in the gate, one in the new
// declaration), class 3 +1 (`rec[3]`), class 1 net 0 (+1 pool coercion, +1
// declaration, -2 dropped `==1` comparisons), class 2 net 0 (`rec[2]` existed
// before and still does). Observed: Lua 5.1 0 410->412 and 3 158->159, every
// other class byte-identical. M1=86, M2, the KAT word vector, M3b, M5, M6,
// M7's top5/gap pair are all unchanged -- no new repeated block, no new value
// class, no new capability. Luau moves identically (0 401->403, 3 143->144) and
// its tag4 branch adds no literal, which is the cross-check that the attribution
// above is the whole story rather than a plausible story.
// 2026-09-11 K14 (validator dispatch becomes a seeded binary search tree)
// re-record: every arm keeps its own equality test, but the tree's internal
// nodes carry boundary literals and the flat `elseif` runs shorten, so the M4
// residue census redistributes -- Lua 5.1 class 1 461 -> 469, class 0 396 ->
// 410, class 20 104 -> 74 with class 9 leaving the top table and 41 entering at
// 68; Luau class 1 460 -> 492, class 0 394 -> 401, class 23 -> 16, and the
// skipped-literal count 32 -> 39. Required to stay unchanged and still stable:
// M1 = 86 distinct stream bytes, M2 = (1366/1111, 1, 2, 1), the KAT word vector
// [0,2,0,...], M3b, M5 count = 5, M6 = (0, 0) and the M7 top5/gap pair -- i.e.
// the restructuring adds no new repeated text block, no new value class and no
// new suspicious-API surface; it only trades a linear scan for log2 routing.
// 2026-09-11 T4 K13b (idle re-lock) re-record: one frame activation now charges
// a per-prototype counter and the last exit hands the raw chained bytes back,
// which costs exactly six `1` tokens (`o==1`, `o-1`, `+1` and three `[-1]`
// handle uses) plus one `0` (`or 0`) and one shifted pool index on each target:
// Lua 5.1 M4 class 1 455 -> 461 and class 0 395 -> 396, Luau 454 -> 460 and
// 393 -> 394. Everything else -- M1, M2, KAT, M3b, M5, M6, M7 and the other ten
// M4 classes -- is byte-for-byte unchanged, so the re-lock adds no new value
// class and no new static surface.
// K16 (2026-09-11) -- both pins were re-recorded once more for the constant-field
// pass, which replaces the script's repeated round constants with reads of a field
// on the wrapper table. Every moved number is explained by that substitution and
// nothing else changed:
//   M3b 256 -> 228 (lua51)     28 big literals gone: 19 spellings of 4294967296
//                              and 9 of 16777216. big_sum drops by exactly
//                              19*4294967296 + 9*16777216 = 81,755,373,568, so no
//                              other >=1e6 value moved; big_max is still the pool
//                              constant 4503599627370496, which the pass leaves
//                              spelled out because it is used too rarely to pay for
//                              a field of its own.
//   M4 (65536,100) -> absent    all 100 uses became reads of one field; the freed
//                              twelfth slot refills as (8,62). No other class
//                              changed count, so nothing new entered the script --
//                              the 1-2 digit literals (the alphabet, the opcode
//                              ids) are untouched by design: a 3-byte spelling is
//                              exactly as long as the read that would replace it.
//   Luau M3b 259 -> 244         15 spellings of 4294967296, big_sum down by
//                              exactly 15*4294967296 = 64,424,509,440; M4 loses
//                              (65536,91) and gains (8,58).
//   M1, M2, M3a, M4b, M5, M6, M7 unchanged on both targets: the pass rewrites code
//                              tokens only, so the image blob, the string census
//                              and the outer-ciphertext statistics cannot move --
//                              which is also the check that no payload byte did.
// 2026-09-11 K18 (bias-free sampler + per-family streams + respelled validator
// guards) -- re-recorded from the measured surface, with the attribution the
// header asks for:
//   M1 stays 86: the transport alphabet is still exactly 86 symbols, and M1 is
//      the one measure that would notice a radix or pool change.
//   M2 (1413, 0, 1, 3) -> (1372, 1, 0, 2): the *stream* is 41 bytes shorter
//      because the private image shrank (see the k7 image-length pin in
//      tests/bitops.rs: 1,141 -> 1,118); the three residues are what an
//      analyst would use to guess a fixed block size, and no residue became 0
//      that was not already free to be - one zero moved from mod 3 to mod 4.
//   M3a stays [0, 2, 0, ...]: still only the audited getfenv capture.
//   M3b (228, ..., 4503599627370496) -> (233, ...): five more big literals,
//      from the guard respellings that spell a difference (`n()-66~=0`) and
//      from the LCG-routed structure stream picking new folded forms; max is
//      unchanged, i.e. no new magnitude.
//   M4 top-12 census moves with the same two causes (the `97`/`6` entries
//      leave the top 12, `15`/`28` enter), and M4b stays 0 on this target: no
//      non-integer number token appeared.
//   M5 (5, 1842) -> (5, 1794) and M7 [527,525,522,..]/388 -> [512,508,506,..]/372
//      are the image shrinking, exactly as K17's entry described: embedding and
//      length, not new payload. The 134/134 pair is untouched, so no literal
//      became long.
//   M6 stays (0, 0): no repeated u32 word in the outer ciphertext, which is the
//      one thing a re-keyed stream could have broken.
// K19 (2026-09-12, segment key feedback: the digit table is rotated by a fold
// of the previous segment) -- measured diff, all five load-bearing invariants
// held: M1 stays 86 (alphabet radix), M2 stays (1372,1,0,2), M3a stays
// [0,2,0,...] (only the audited getfenv capture), M3b stays (233, ...,
// 4503599627370496) (no new big literal, no new magnitude), M4b stays 0 (the
// fold adds no non-integer token, i.e. it stays exact integer arithmetic on this
// target), M6 stays (0,0) (no repeated u32 word in the outer ciphertext -- the
// one thing a re-keyed stream could have broken).
// What moved, and why:
//   M4 top-12 census: `1` 502 -> 504 is exactly the two `for j=1,#PR` fold loops
//      (the accumulator reuses the segment's existing `B` slot, so no extra `0`
//      is spelled and `0` stays 436 -- that reuse is also why the payload table's
//      field census stayed inside 25..=27 instead of being widened); `5` 78 -> 81
//      is the re-keyed alphabet moving symbol runs, everything else is untouched.
//      Tried first and rolled back: a dedicated `RO` local added two more `0`s,
//      the constant pool lifted one more number, and the field census hit 28.
//   M5 (5, 1794) -> (5, 1782) and M7 [512,508,506,134,134]/372 ->
//      [507,506,501,134,134]/367: the rotated alphabet permutes symbol runs, so
//      some long strings got 3-12 bytes shorter while the whole script grew by
//      158 B (101,391 -> 101,549: the two fold loops and the extra parameter).
//      The 134/134 pair is untouched, so no literal crossed into "long".
// K20 (2026-09-12, 运行期分段装载：payload 段函数改由入口阶段分多次装载，同一键
// 可以先装 A 再装等价的 B) -- re-recorded from the measured surface. Invariants
// that held: M1 stays 86 (alphabet radix), M2 stays (1372,1,0,2), M3a stays
// [0,2,0,...] (still only the audited getfenv capture), M4b stays 0 (the装载折叠
// keeps integer arithmetic exact, no float token), M5/M7 stay (5,1782) and
// ([507,506,501,134,134],367) (no literal grew longer, no long run moved), M6
// stays (0,0).
// What moved, and why:
//   M3b 233 -> 234 distinct big literals is exactly one new number: the fold
//     checkpoint's expected sum (`if ck~=156346 then`), placed before the run
//     stage's first handler call. The maximum is untouched -- no new magnitude.
//   M4 top-12: 256 205 -> 211 is the respelled bodies reaching the shell (the
//     probe fold `a*257` -> `a+a*256` on each installed probe, plus W1's second
//     packing order); 1/0/2/4/5 gain a handful because relocated sections carry
//     their own small constants, while 3 154 -> 149 and 15 86 -> 72 drop the
//     same way; 42 and 8 enter the top 12 and 11 leaves it. No audit-nice value
//     (86/7225/65536/16777216/...) enters the census, so K16's invariant -- the
//     shell exposes no new nice-value literal -- still holds.
// 2026-09-12 K21 re-record（只动 M4 一张表）：opcode 边界从「对每个 handler 做一次相等
// 比较」换成「按数字区间二分」。实测差异与归因——
//   `1` 505->503、`2` 238->236、`4` 142->128、`5` 90->81：链上的取模选择器消失（整份
//     脚本文本里 `%3`/`%4` 各 3 枚、`%2` 22->20，都是 `rid%g`/`sid%g`/`o%g` 那类），
//     以及链之后被每个节点抽样挪动的 structure 流把下游槽位键/临时键重抽；
//   `42` 55->63、`17`(57) 顶掉 `8`(54)：同一批重抽的尾部噪声；
//   新引入的 44 枚区间边界全落在 2..=65535 且互不相同，进不了 top-12。
// M1=86、M2、KAT 字向量、M3b (234, 9007493881568240, 4503599627370496)、M4b=0、
// M5/M6/M7 一字未动 ⇒ 区间层没有带来新的数量级，也没有新的静态面。
const PINS_LUA51_7001: AuditPins = (
    86,
    (1372, 1, 0, 2),
    [0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
    (234, 9007493881568240, 4503599627370496),
    [
        (1, 503),
        (0, 438),
        (2, 236),
        (256, 211),
        (3, 149),
        (4, 128),
        (5, 81),
        (15, 72),
        (28, 71),
        (7, 64),
        (42, 63),
        (17, 57),
    ],
    0,
    (5, 1782),
    (0, 0),
    ([507, 506, 501, 134, 134], 367),
);

// K17 (2026-09-11, decimal-escape minimality + quote-hostile alphabet bytes) --
// the only lua51 moves are the two measures that count *spelling*:
//   M5 (5, 1914) -> (5, 1842)    the three blob source spans together lose 72 B;
//                                the 134/134 pair is untouched, so nothing new
//                                became long -- this is embedding, not payload.
//   M7 [557,549,540,134,134] gap 406 -> [527,525,522,134,134] gap 388
//                                decimal escapes dropped their zero padding
//                                (`\028` -> `\28`) and the alphabet can no longer
//                                hold `"`, `'` or `\`, so the blobs need no
//                                two-character escape at all.
// M1 (alphabet 86 / span 99), M2, the KAT, M3b (228 big literals, sum and max),
// M4's whole top-12 census, M4b and M6 (no repeated u32 word) are byte-for-byte
// unchanged: A2 only permutes which symbol stands for which value and A1 only
// re-spells bytes, so neither can add payload, pretty constants or repeats --
// and a fresh image-length or entropy measure here would have moved M5's count.
// K13c step 2 (2026-09-11, ISA17) -- literal-by-literal census of the lua51 move:
//   M1 86 -> 86                 alphabet unchanged (no new character classes).
//   M2 1366 -> 1413 (+47)       stream length: the re-keyed image blob is spelled
//                               with a different escape density; residues 0/1/3
//                               follow arithmetically from +47.
//   M3a [0,2,0...] unchanged   no KAT word entered the stream.
//   M3b 250 -> 256 big literals  the six new >=1e6 spellings are the prelude
//                               `NU` decoder (1048576 twice, 4294967296,
//                               4503599627370496) plus the baked pool modulus
//                               429496729x and the pool mask in the pool walk.
//                               big_max is unchanged: none of them exceeds the
//                               existing 4503599627370496.
//   M4 tail churn              the cipher helpers add small integer literals
//                               (119, 257, 1023, 2048, 256, 4, 5, 8) which
//                               reshuffle the count-tied tail (97/11/14/6 in,
//                               20/8/94/41 out); no class gained a large value.
//   M4b skipped 0 -> 0          still no non-integer number tokens on 5.1, where
//                               the blob is written as \ddd escapes.
//   M6 (0, 0) -> (0, 0)         outer ciphertext still has no repeated u32 word.
//   M5 1846 -> 1914 (+68)       long-string source span only: the image byte
//                               count is pinned unchanged by
//                               k7_wire_image_bytes_are_pinned, so this is
//                               spelling, not new payload.
//   M7 534/526/518 -> 557/549/540, gap 384 -> 406   same escape-density churn on
//                               the three blobs; the two short entries (134/134)
//                               are untouched, i.e. nothing new became long.
// The Luau config moved the same way for the same reasons: M2 1111 -> 1134,
// M3b 253 -> 259 (the six new spellings again, max unchanged), M5 1575 -> 1523
// -- *down*, which is only possible for a spelling measure, not for added
// payload -- and M7 439/438/430 -> 419/418/418 with the 134/134 pair intact.
// M4b 39 -> 42 needs one more word: that counter skips number-looking tokens it
// cannot parse as u64, and on Luau the embedded blob is printable text, so the
// counter samples the ciphertext itself. Re-keying the constant pool rewrites
// that ciphertext, so three such tokens disappeared/appeared. It moved only on
// Luau and stayed 0 on 5.1, which is the check that it is blob noise rather than
// new emitted numeric syntax (5.1 gained no token either).
// K17 (2026-09-11) luau config: M5 (5, 1523) -> (5, 1509) and M7
// [419,418,418,134,134] gap 284 -> [419,412,410,134,134] gap 276. Same two
// measures as above, same reason: shorter decimal escapes plus an alphabet that
// can no longer contain `"`, `'` or `\`. M7's first entry stays 419 while the
// other two drop -- the segments lose escapes unevenly because the escape count
// per blob is payload-driven (the padded control bytes 28/29 remain in the
// alphabet by design), which is exactly what a spelling measure should track.
// M4b stays 42 and M3b stays (244, 9007484541350310, 4503599627370496), so no
// digit-run census moved: the alphabet permutation did not create or destroy any
// number-looking token on this target either.
// 2026-09-11 K18 luau config, measured: M1 stays 86 and M6 stays (0, 0); M2
// (1134, 0, 2, 4) -> (1390, 1, 2, 0) is the same layout shift as on lua51 but in
// the other direction (the keyed pool records got longer here), and the zero
// residue moved from mod 3 to mod 5 - M2 pins the three residues, it is not the
// divisibility gate, which lives in product_audit check9 (`fail` stays false).
// M3b's count falls 244 -> 225 with max unchanged, M4's census reorders, M4b
// 42 -> 39 non-integer tokens, and M5/M7 follow the long-string spans
// (1509 -> 1809 bytes across 5 singletons; M7 top-5 419/412/410 -> 514/514/513
// with the 134/134 pair untouched, so no literal crossed into "long").
// K19 (same change, Luau side): M1/M2/M3a/M3b/M6 all unchanged (225 big
// literals with the same maximum, no repeated u32 word, only the audited
// capture), M4b stays 39 non-integer tokens -- the fold loop adds no new float
// spelling here either; those 39 are the pre-existing `/` forms. M4's census
// gains exactly the two `for j=1,#PR` loops (`1` 542 -> 544) plus one `2`, and
// `0` is untouched at 418 because the accumulator reuses the segment's own `B`
// slot; `89` 64 -> 70 is the re-keyed alphabet moving symbol runs, which also
// reorders the top 12 (`89` now precedes `8`). M5 (5, 1809) -> (5, 1840) and
// M7 [514,514,513,134,134]/379 -> [532,526,514,134,134]/380: the script grew
// 268 B (110,877 -> 111,145) and the long-string spans moved with the re-keyed
// stream; the 134/134 pair is untouched, so nothing crossed the length class.
// K20 (2026-09-12, 运行期分段装载) -- same construction, Luau side. Held: M1 86,
// M2 (1390,1,2,0), M3a [0,2,0,...], M5 (5,1840), M6 (0,0), M7
// ([532,526,514,134,134],380) -- the section text moved between regions but no
// literal grew and no repeated u32 word appeared in the outer ciphertext.
// Moved: M3b 225 -> 226 distinct big literals (the one new checkpoint constant) and
// M4 census 256 200 -> 206 / 3 172 -> 175 / 4 167 -> 164 (respelled bodies),
// M4b 39 -> 40. M4b's single extra token is the same new checkpoint number: it is
// not a float spelling (the count of `.`/`e`-spelled number tokens is unchanged at
// 299 -> 299, measured), i.e. the audit declines to read that one spelling as a
// plain decimal integer; no non-integer *value* enters the shell.
// 2026-09-12 K21 re-record（同样只动 M4）：Luau 侧 M3b 与 M4b=40 一字未动，说明区间
// 边界没有带来新的数量级、也没有把整数码改成别的拼写；top-12 里 `1`/`2`/`3`/`4` 各掉
// 1-4 枚是取模选择器消失＋链后 structure 流重抽，`82`(68) 与 `42` 53->65 顶掉 `19`(55)
// 是同一批重抽的尾部噪声。
const PINS_LUAU_7351: AuditPins = (
    86,
    (1390, 1, 2, 0),
    [0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
    (226, 9007479735086075, 4503599627370496),
    [
        (1, 543),
        (0, 418),
        (2, 247),
        (256, 206),
        (3, 171),
        (4, 160),
        (5, 81),
        (89, 70),
        (82, 68),
        (8, 65),
        (42, 65),
        (18, 58),
    ],
    40,
    (5, 1840),
    (0, 0),
    ([532, 526, 514, 134, 134], 380),
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
