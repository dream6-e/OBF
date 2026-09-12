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

// Pins observed 2026-09-10 (ISA16 / K12 chained operand lanes). K-batches tighten.
// K12 attribution: `2147483647` +2 is exactly the two chain recurrence sites
// (per-prototype seed + per-record step), check8 picks up two more same-class
// literals (gcd stays 1 = clean), check9 grows with the image; check1 `86`,
// check2/check3/check4/check5/check6/check7 are untouched, i.e. the chain adds
// no new residue class, no new template family and no new static surface.
// K9a: [2] -> (86, 99, clean), [9] -> clean under the new rule; [1] drops
// the 85/4294967295 anchors and sheds 86/256 hits (opaque splits, VAL
// table, label hygiene: slot keys avoid 85/86, states avoid 256, wrapper
// keys avoid 256/7225/7396); remaining 86s are forms/decoy code (K9b's).
// [5] grows (3 self-contained decoders triple shapes; shape diversity is
// K7's scope); [6] flips on layout-shuffle artifacts (pre-existing text,
// position luck); [8] re-indexes on the fresh M24 addends. [3]/[4]/[7]
// stable; 16777216/2147483647/4294967296 untouched (M24 split adds zero).
//
// Re-recorded 2026-09-10 (frame tag + pool-assembled Luau probe transcript),
// attributed against the goldens in git rather than guessed:
//   * `256` 181 -> 199 happened *before* 89dcc91 (that commit's golden already
//     had 199), i.e. in the K8/K9 batches that grew the script 93k -> 98.6k;
//     it is extra base-256 word-packing spellings, not a new capability -
//     [2]/[3]/[4]/[5] and the KAT-word counts stay exactly pinned.
//   * `65536` 102 -> 99 and `4294967296` 18 -> 20 are the keyed dual-lane tag
//     (verified by diffing 89dcc91 -> 7106908: those two move, `256` does not).
//   * the probe-transcript fix moves no lua51 bytes at all (golden is
//     byte-identical) and on Luau leaves every check1 value unchanged; it only
//     replaces three 36-byte name literals with one pool-joined local.
//   * [9] total_len tracks the transport widths (the tag's frame rng shifts the
//     downstream draws); rem5 leaving 0 moves *away* from the multiple-of-5
//     pathology this check exists to catch, and fail stays false.
// 2026-09-11 K14 (validator dispatch tree) re-record, all values diffed against
// the pre-batch golden:
//   * `256` 199 -> 210 and `65536` 99 -> 102 -- the tree's internal nodes carry
//     the bucket split points as literals, which is the same opcode-value space
//     the flat `o == K` arms already lived in; every other check1 class, check2
//     (86 distinct chars, span 99), check3, check4 (`<=` threshold census),
//     check7, check8 (gcd 1) and check9 are untouched, and no `fail` flag flips.
//   * check5 gains one over-repeated shape class (11 -> 12): `if <cmp> then if`
//     is a new statement shape by construction. No existing class grows -- the
//     largest class is still 21 fragments and the top-8 set only swaps its 8th
//     entry -- so the price of the tree is one more countable shape, not a new
//     anchor a scanner could key the validator on (which was the point).
//   * check6 falls back 1 -> 0: the validator's first `;` now closes after the
//     first tree node instead of after the whole bucket, so the K7-attributed
//     script-head fragment (13 digit-index slots) is cut shorter and no longer
//     trips the `local `-prefixed dense-slot heuristic.
// 2026-09-11 K13c step 2 (ISA17, keyed constant-pool payloads), lua51 pin.
// Measured drift, field by field, before the pin moved:
//   check1 `256` 210 -> 208 and `65536` 102 -> 99  (fewer round constants: the
//      pool walk lost its per-type decode arms, which used to reuse those
//      spellings) while `4294967296` 20 -> 21 is the new prelude `NU` decoder.
//      Fewer round literals is the good direction for this census.
//   check5 12 -> 11 distinct templates: the rare class
//      "X=NXXXXXXX=(X*N+X+X+X+X+(N*N+N))%N" (7 uses) folded into the existing
//      "X=(X+X+(N*N+N))%N" family once the pool loop became a length skip, so
//      the top-8 list lost its tail entry. This is the one mildly negative
//      number in the batch and it is a *count of shapes*, not a threshold:
//      check4 (max repetition 2 / span 65535) and every `fail` flag stay as
//      pinned, and check3/check6/check7 are untouched.
//   check8 gcd stays 1 (no common divisor among literal values); the second
//      entry 78 -> 83 is the literal census size, up because of the new cipher
//      constants (119, 257, 1023, 2048, 1048576, the baked mask/modulus).
//   check9 18426 -> 18777 (+351 B) is the stream itself growing by the new
//      primitives; the repeat residue 1 -> 2 with fail=false, i.e. still no
//      periodic structure.
// The Luau config moved in the same shape but with the round-literal census
// going *up* instead of down -- `86` 5 -> 6, `256` 187 -> 196, `65536` 91 -> 93,
// `4294967296` 15 -> 16 -- because only Luau ships the extra 64-bit integer
// arm, and it buys those literals with `take(8)`-style skips on both the parser
// and the `DC` side. check5 there is 12 -> 11 as well, check8 72 -> 78 and
// check9 23896 -> 24126 with residue 1 -> 1 and fail=false. check2/3/4/6/7 and
// every flag are unchanged on both targets.
// 2026-09-11 K16 (repeated round constants become fields of the wrapper table),
// lua51 golden 102,261 -> 101,908 B. Every moved number is the constants leaving
// the text, never payload arriving:
//   check1  65536 99 -> 3, 16777216 10 -> 1, 4294967296 21 -> 2. The last
//               occurrence in each class is the table write itself, so
//               16777216/4294967296 fall to or under one and stop being anchors at
//               all (check1 lists only values spelled more than twice); 97 of the
//               99 `65536` spellings became reads and the 2 left are out of reach
//               (a nearer binding of the wrapper name, or the shell's own
//               constructor, which evaluates before the entry assigns the field).
//               `256` (208) is untouched by choice: a 3-byte literal costs exactly
//               what the `t.k` read would, so the write can never be paid for.
//               `2147483647` (29) is untouched by reach: only 2 of its spellings
//               sit where the wrapper is visible (the prelude and validator regions
//               re-bind the name), below the six uses the pass needs.
//   check5   11 classes still, same counts; one family simply renames itself
//               (`...(N*N+N))%N` -> `...(N*N+N))%X.X`) because a decoy modulus is
//               now `<name>.<field>` and the normalizer writes that as `X.X`.
//   check8   83 -> 49 pairs, gcd still 1: fewer literal pairs to grep, no new
//               arithmetic regularity.
//   check2/3/4/6/7/9 and every flag unchanged -- including check9, the string/blob
//               stream -- so the image bytes did not move at all.
// 2026-09-11 K17 (A1: decimal escapes spelled as shortly as their follower
// allows; A2: `"`, `'` and `\` dropped from the base86 pool) -- measured lua51
// diff, exactly one field:
//   check4   (2, 65535, false) -> (3, 65535, false). A2 changes which symbol
//              each group value stands for, so `base86_padded` takes the
//              "padding fits" branch a different number of times and the shared
//              transport RNG advances differently -- downstream per-seed labels
//              move with it, and one more distinct `<= N` boundary is all that
//              comes out of it on this config. The guarded property still holds
//              (max 65,535 over 3 distinct thresholds: the density bound
//              `max < 3 * distinct` does not come close to firing, `fail` false).
//   check1/2/3/5/6/7/8 unchanged to the digit. Notably check2 still reads
//              (86 distinct, span 99) -- the radix and the contiguity margin are
//              intact -- and check9's blob stream is identical, so the payload
//              bytes did not move: A1/A2 re-spell the embedding, nothing else.
// 2026-09-11 K18 (bias-free sampler + three mixing families + respelled validator
// guards) -- measured lua51 diff, five fields, every `fail` flag still false:
//   check1   (256, 208) -> (256, 212) and (2147483647, 29) -> (24, ...), plus a
//              new entry (4294967296, 3). This census counts raw *text* occurrences
//              of the audit's nice values, not tokens: the guard respellings of ①
//              (`79-n()~=0`) and the LCG-routed fold choices move which spellings
//              a fold keeps as a literal, and `2^32` crossed the ">2 occurrences"
//              listing by one. It is the same 2^32 the IEEE-754 read-back arms
//              already needed (K16 recorded that folding those into a field read
//              does not pay for itself), so no *new* constant class entered the script.
//   check4   (3, 65535, false) -> (2, 16777215, false): two distinct thresholds
//              instead of three, the larger one now in the 2^24 class. The check
//              guards threshold *density* (`max < 3 * distinct` would leak a state
//              count); the ratio here is 8.4M:1, so the bound is nowhere close.
//   check5   still 11 classes. The top-8 list reorders and one family changes
//              identity: `X=N*X%N` 21 -> 17 while a new `X[N]=NXX[N]==NXX[N]=N`
//              (7) appears. That is ① working as intended - the normalizer maps the
//              respelled `not(a==b)` / `a-b~=0` guards into different template
//              families, i.e. the head block no longer collapses onto one shape.
//   check8   gcd stays 1 with 49 -> 51 pairs: fewer than 52 arithmetic pairs, no
//              new regularity.
//   check9   (18777, 2, false) -> (19017, 2, false): +240 bytes in the long-string
//              stream, because the private image re-layouted (see the
//              k7 image-length pin: 1,141 -> 1,118 on this config). Length, not
//              structure: check2 still reads (86 distinct, span 99).
fn pins_lua51() -> AuditPins {
    AuditPins {
        // K19（分段密钥回灌）实测：`86` 由 4 降到 3 —— 旋转后的数字表用 `%r`，
        // 而 r 是 c1+c2 的和式，代码区少了一处裸 86；`256` 保持 212，因为折叠累加器
        // 复用了段内已有的 `B` 槽位，常数池没有被逼着再提升一个数字（先前用独立
        // `RO` 局部时 `256` 涨到 220、字段数 27->28，已按「收紧生成器优先」回退）。
        // check5 的 `X[N]=N` 19 -> 17：两处赋值被折叠语句改写成形，模板类数仍是 11；
        // check2/3/4/6/7/8/9 一字未动。
        // K20 (runtime segment loading) -- measured Lua51 diff:
        //   check1 `256` 212 -> 218.  The six added occurrences are the respelled
        //     digit-accumulate loops: the equivalent spelling writes `a*257` as
        //     `a+a*256`, and each respelled field exists twice (A then B), so the
        //     literal count moves with the number of respelled loop bodies and
        //     nothing else.  `86`, `65536`, `2147483647` and `4294967296` hold.
        //   check5 class count 11 (unchanged); `X=X+N` enters the top-8 with 29 --
        //     the fold statements each loader carries -- which pushes the previous
        //     8th entry (`X[N]=NXX[N]==NXX[N]=N`, 7) below the cut.  No template
        //     class appeared or disappeared.
        //   check8 pairs 51 -> 52, gcd still 1: duplicating a body made one
        //     previously unique 6+ digit literal repeat, so a new adjacent pair
        //     exists; the gcd staying 1 says no periodic structure was introduced.
        //   check7 dead-table list stays EMPTY -- every loader is read, and
        //   check2/3/4/6/9 are untouched.
        // K9b (audit anchors as wrapper fields) -- measured Lua51 diff:
        //   check1 `256` 218 -> 4.  The byte-assembly weight is now a field of the
        //     wrapper table, so 214 of the 218 spellings became `t.<key>` reads.  The
        //     four that remain are the single write that materialises the field plus
        //     the three sites this pass is not allowed to touch (the payload-table
        //     constructor, which evaluates before the entry runs, and `[N]=` key
        //     positions).  `86`/`65536`/`4294967296` hold at 3 and `2147483647` at
        //     24 -- K16 measured 27 of its 29 spellings as out of reach, so that one
        //     stays a documented residual anchor.  Every anchor now sits at the
        //     write-plus-protected-sites floor; none of them is a grep handle.
        //   check5 class count 11 (unchanged), one top-8 entry respells:
        //     `X=(X+X+(N*N+N))%X.X` -> `X=(X+X+(N*X.X+N))%X.X`, count 8 -- the fold
        //     accumulator's `*256` reads the field, which the normalizer maps to
        //     `X.N`.  No template class appeared or disappeared.
        //   check8 pairs 52 and check2/3/4/6/7/9 byte-for-byte unchanged: the pass
        //     spends no RNG, so the streams are identical.
        // Cost: +21 B on this golden (102,939 -> 102,960).  `256` is price neutral
        // per use (literal and read are both three bytes) and pays only its write; the
        // extra is the anchor taking the first one-character key, which slides the last
        // field to a two-character key (+1 B per use of that field).
        check1_nice_fails: vec![
            (86, 3),
            (256, 4),
            (65536, 3),
            (2147483647, 24),
            (4294967296, 3),
        ],
        check2_alphabet: (86, 99, false),
        check3_noise_pairs: 0,
        // K21 (interval opcode dispatch) -- measured Lua51 diff, the only move:
        //   check4 (2, 16777215, false) -> (12, 16777215, false). The dispatch chains
        //     now carry 44 range tests; 10 of them spell `x<=B`/`(v)<=B` with a
        //     distinct bound each, 7 spell `x-B<=0` (threshold 0) and the rest use
        //     `>=`/`not(x>B)`, which this census does not look at. max stays the
        //     pre-existing 0xffffff mask constant, the density fail flag stays false,
        //     and check1/2/3/5/6/7/8/9 are byte-for-byte unchanged -- no new constant
        //     class reached the shell, and the threshold census got *more* varied.
        check4_thresholds: (12, 16777215, false),
        check5_templates: (
            11,
            vec![
                ("X=X+N".to_string(), 29),
                ("X[N]=X[N]+X[N]*X[N]X[N]=X[N]*X[N]X".to_string(), 18),
                ("X[N]=X[N][X[N]]XX[N]==XXX()X".to_string(), 18),
                ("X=N*X%N".to_string(), 17),
                ("X[N]=N".to_string(), 17),
                ("X[N]=N+N".to_string(), 9),
                (
                    "X[N]=NXX=N,NXX[N]=X(X[N],X[N]+X-N)XX[N]==XXX()X".to_string(),
                    9,
                ),
                ("X=(X+X+(N*X.X+N))%X.X".to_string(), 8),
            ],
        ),
        check6_alias_prologues: 0,
        check7_dead_tables: Vec::new(),
        check8_literal_gcd: (1, 52),
        check9_stream: (19017, 2, false),
    }
}

// 2026-09-11 K18 (bias-free sampler + three families + respelled guards) --
// measured Luau diff, every `fail` flag still false:
//   check1   (256, 196) -> (256, 201) and (2147483647, 24) -> (27): raw-text
//              occurrences of the audit's nice values move with the fold choices
//              the LCG-routed structure stream makes; no new value enters the list.
//   check4   (2, 65535, false) -> (1, 65535, false). One distinct *literal*
//              threshold survives the census because ① respelled part of the head
//              block into side-by-side forms (`not(a==b)`, `a-b~=0`) that carry no
//              bound literal at all - the tree still splits, it just stopped
//              spelling every split as `< literal`. The guarded property is density
//              (`max < 3 * distinct`), nowhere near firing: max is 65,535.
//   check5   11 -> 12 template classes with `X=N*X%N` 16 -> 17: the normalizer now
//              separates a family it used to merge. That is ① landing - the head
//              block is measurably less uniform than before.
//   check8   (1, 57) -> (1, 59): gcd still 1, no new arithmetic regularity.
//   check9   (24126, 1, false) -> (23738, 3, false): the long-string stream is
//              388 B shorter (the Luau private image re-layouted, 870 -> 1,126 in
//              tests/bitops.rs) and its mod-5 residue moved 1 -> 3, so the
//              divisibility lint still sees a length that is not a multiple of 5.
// 2026-09-11 K14 (validator dispatch tree), Luau pin: `86` 7 -> 5 and `256`
// 177 -> 187 are the bucket split points moving out of the radix class and into
// the byte class; check5 already sat at 12 classes and its top-8 counts are
// unchanged (19/18/18/16/9/9/8/6), check2/3/4/7/8/9 and every `fail` flag are
// untouched. check6 rises 0 -> 1: on this seed the validator's first `;` lands
// *later* than the old first bucket did, so one `local`-prefixed fragment picks
// up a sixth digit-index slot -- the mirror image of the Lua 5.1 direction above.
//
// 2026-09-11 K16, Luau golden 112,605 -> 112,336 B: the same substitution on
// Luau's literal mix. check1 `65536` 93 -> 3 (91 reads, one write, one use inside a
// scope that re-binds the wrapper name) and `4294967296` 16 -> 2, which leaves the
// anchor list; `16777216` keeps its four uses (fewer than the pass requires to pay
// for a field), `2147483647` keeps its 24 because only 2 of them are in reach, and
// `86`/`256` hold exactly.
// The `0b1011_1010`-style spellings are never candidates: only canonical decimals
// are, so digit-grouped binary survives untouched as it must. check5 stays at 11 classes
// with the same counts and renames one family the same way, check8 drops 78 -> 57
// pairs with gcd still 1, and check9 (24,126, residue 1, no fail) proves the
// Luau blob did not move either.
fn pins_luau() -> AuditPins {
    AuditPins {
        // K9b (audit anchors as wrapper fields) -- measured Luau diff: check1 `256`
        // 207 -> 4 (one field write plus the three sites the pass may not touch) and
        // check5's fold template respells to `X=(X+X+(N*X.X+N))%X.X`, count 8; the
        // class count stays 12.  `86`/`65536`/`16777216`/`2147483647` and checks 2/3/
        // 4/6/7/8/9 are byte-for-byte unchanged.  Cost +28 B (112,969 -> 112,997):
        // same cause as Lua51 -- the anchor takes a one-character key and the last
        // field slides to two characters.
        // K19（分段密钥回灌）实测：`86` 由 6 降到 3 处中的 4 处（Luau 侧同样少两处
        // 裸 86：数字表旋转改成 `(x-1+B)%r`，r 是 c1+c2 的和式），其余 nice 值计数
        // 一字未动；check5 的 `X[N]=N` 19 -> 17 与 lua51 同因（两处赋值被折叠语句
        // 改写成形），模板类数仍是 12；check2/3/4/6/7/8/9 全部原样，`fail` 仍为 false。
        // K20 (runtime segment loading) -- measured Luau diff, same three causes as
        // Lua51 and nothing else: `256` 201 -> 207 (the respelled digit loops write
        // `a*257` as `a+a*256`, once per surviving spelling), `X=X+N` 0 -> 29 enters
        // the top-8 and pushes the 6-count entry below the cut (template class count
        // stays 12), check8 59 -> 60 pairs with gcd still 1 because A/B duplication
        // repeated one previously unique long literal.  check2/3/4/6/7/9 -- including
        // every `fail` flag and the empty dead-table list -- hold untouched, i.e. the
        // loaders did not widen the alphabet, add a threshold, or leave a table
        // installed but never read.
        check1_nice_fails: vec![
            (86, 4),
            (256, 4),
            (65536, 3),
            (16777216, 4),
            (2147483647, 27),
        ],
        check2_alphabet: (86, 99, false),
        check3_noise_pairs: 0,
        // K21 (interval opcode dispatch) -- measured Luau diff, two moves, and no
        // `fail` flag is affected:
        //   check4 (1, 65535, false) -> (14, 65535, false): the chains now carry 44
        //     range tests; the `x<=B`/`(v)<=B` spellings contribute 10 distinct bounds
        //     and `x-B<=0` contributes the 0, while the `>=`/`not(x>B)` spellings are
        //     outside what this census reads.
        //   check6 0 -> 1: one *head* statement (the slot-alias prologue `local j=..
        //     x=.. i=..`) now carries a sixth digit-index slot, because the structure
        //     stream downstream of the chain re-draws where that block's first `end;`
        //     falls. Same seed-accident direction K14 recorded in mirror image (Lua
        //     5.1 fell 1 -> 0 there); the prologue already had five slots, so no new
        //     construct appears. check1/2/3/5/7/8/9 are byte-for-byte unchanged.
        check4_thresholds: (14, 65535, false),
        check5_templates: (
            12,
            vec![
                ("X=X+N".to_string(), 29),
                ("X[N]=X[N]+X[N]*X[N]X[N]=X[N]*X[N]X".to_string(), 18),
                ("X[N]=X[N][X[N]]XX[N]==XXX()X".to_string(), 18),
                ("X=N*X%N".to_string(), 17),
                ("X[N]=N".to_string(), 17),
                ("X[N]=N+N".to_string(), 9),
                (
                    "X[N]=NXX=N,NXX[N]=X(X[N],X[N]+X-N)XX[N]==XXX()X".to_string(),
                    9,
                ),
                ("X=(X+X+(N*X.X+N))%X.X".to_string(), 8),
            ],
        ),
        check6_alias_prologues: 1,
        check7_dead_tables: Vec::new(),
        check8_literal_gcd: (1, 60),
        check9_stream: (23738, 3, false),
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
