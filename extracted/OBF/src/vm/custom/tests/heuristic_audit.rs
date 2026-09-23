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
// 2026-09-12 K9b re-record（只动 M4 一张表）：`256` 从普查里掉出去（211 -> 4，已在
// 前十之外）——byte 组装权重成了包装表的一个字段，代码区那 211 处明文换成 211 处
// `t.k` 读数，「常见数字」这一栏里它不再是锚点；空出的第十二位由 `8`(54) 回填，其余
// 十一项与 K21 逐字节相同。M1、M2、KAT、M3b (234, 9007493881568240,
// 4503599627370496)、M4b=0、M5/M6/M7 一字未动 ⇒ 这一批只搬位置：没有新的数量级、
// 没有新的字面量类、也没有新的静态面（提升段不消耗随机流，故 M2/M5/M7 必然原样）。
// 2026-09-12 K3-FULL re-record（M2/M4/M5/M7 四项，逐条归因；M1=86、KAT、M3b、M4b=0、
// M6=(0,0) 一字未动）：
//   M2 (1372,1,0,2) -> (1523,2,3,3)：内嵌字流长 1372 -> 1523（+151 B）。私有镜像本身
//     1,118 -> 1,264 B（+146 B = 73 个 recipe 槽各多一枚「操作数形状」字节，见
//     `k7_wire_image_bytes_are_pinned`），加上描述子替代两条打包串后的净差；三个残数
//     跟着换格是长度变化的算术后果，不是新的结构周期。
//   M3b (234, 9007493881568240, 4503599627370496) **未动** ⇒ 去池没有把任何大常数带进
//     壳里；这是本批「只搬表示、不新增数量级」的直接证据。
//   M4 top-12：`1` 503->501、`2` 236->232、`3` 149->147、`7` 64->59 掉，`0` 438->442、
//     `4` 128->136、`5` 81->89、`8` 58、`15` 72->73 涨。成因都可指到文本：形状表与
//     重排表被删（那段 `%86`/`+1`/`(b-35-rot)` 算术不再出现），换成一枚六符号描述子的
//     下标 `d[1]..d[6]`（1..6 各多几处）与读者里 `sf==1..5` 五次形状测试（第二形是显式
//     拼出的，未知形状落到 `E()`，所以 `5` 比 `1`/`2` 多一处：90）；`0` 增 4 来自
//     读者入口那串零初始化（`local kk=0`/`local a,b,c,j,k2,w=0,...`）；`42`(63)、`17`(57)
//     跌出十二名、`37`(75)、`70`(52) 进来，是槽位键与状态号随换流重抽的尾部噪声（与 K21
//     记录过的同类）。`256` 仍在普查表之外（4 处），K9b 的下界没有被这批吃掉。
//   M5 (5,1782) -> (4,1812)：孤例字面量少一枚、总字节多 30 —— 两条打包串（49 与 128
//     字符）换成一条 7 字符描述子，短串数 -1，而段内 blob 随镜像变长。
//   第二批改形（读者的临时量从槽位改回普通 local，见 `dec` 字段注释）后再测一次：
//     `0` 442->433、`4` 136->127、`7` 59->63、`8` 58->56、`5` 90->93、`1` 501->502、
//     `2` 232->231、`70` 52->53，`37`(75) 出、`73`(50) 进。方向可指到文本：槽位写
//     （`g[71]=AK(...)`，键随种子散在 1..99）变成同名 local 后，小数字的分布回到
//     「形状号 + 描述子下标」这一族，`0` 少了 9 处正是那批零初始化被删掉；`7`/`8` 的
//     几处来回是槽键重抽的尾部噪声。M2/M3b/M4b/M5/M6/M7 与第一批记录一致 ⇒
//     改形没有再动流长或字面量种类。
//   M7 [507,506,501,134,134] gap 367 -> [573,560,545,134,17] gap 411：三枚段 blob 各涨
//     66..72 B（镜像 +146 B 的分摊）；`134` 那一对是打包串的旧长度，如今只剩 `17`
//     （描述子串含 `\127` 前缀与引号的源长）——**打包串这一类静态锚点整体消失**，这正是
//     本批要买的静态面，不是退化。
// K3-FULL 第二步 (2026-09-13, per-segment digit tables) -- lua51 moves two cells:
//   M1 86 -> 96. M1 counts distinct stream bytes and had been pinned at 86 on both
//     targets since K9a *because* the whole stream was written in one 86-symbol
//     alphabet. Three segments now use three tables, so their union covers 96 of
//     the 99 printable pool bytes. The pin direction is reversed on purpose:
//     >= 87 is the evidence of the split, and a fall back to exactly 86 would mean
//     the tables silently collapsed onto one another again.
//   M7 top-5 [573,560,545,134,17] gap 411 -> [568,560,550,134,17] gap 416. Only the
//     two redrawn segments move: the tables for parts 1/2 got new permutations, so
//     the density of the four forced-low symbols (each costs a 3-char decimal escape
//     in source) changed; part 0 keeps the pre-K3s2 table (identity salt) and is
//     byte-identical at 560, which is what makes the diff attributable per segment.
//     M2's decoded stream (1523 B) is untouched -> no payload grew, this is escape
//     expansion only. M3b, the KAT words, M4's census, M4b, M5 (4,1812) and M6 all
//     stayed byte-for-byte: a per-segment permutation cannot add a value class, a
//     pretty constant or a repeated word.
// K22 (2026-09-14, rolling context chain: keyed wire tokens + operand digest) --
// measured Lua51 diff: the *only* moved cells are inside the M4a literal census.
// `0` 436 -> 440 and `70` 53 -> 54, with the previous 12th entry `73`/50 falling
// below the cut and `6`/50 entering: the batch adds one 0 (the conditional-add
// spelling's `or 0`), and its 5-digit wire literals plus the digest weights make the
// small-value classes marginally more common. M1 (96, per-segment tables), M2's
// decoded stream (1523 B), M3b/KAT words, M4's big-value census, M4b (0 skipped),
// M5 (4, 1812), M6 (0 pairs) and M7 ([568, 560, 550, 134, 17] gap 416) are
// byte-for-byte unchanged -> no new API word, no new pretty constant, no repeated
// ciphertext word: the chain buys its static surface with literals already in class.
// P7 (2026-09-14, goal-3 micro-op MBA layer) -- measured Lua51 diff: the moved
// cells are exactly the large-literal census and the counts of the small values it
// shares terms with. M3b count 234 -> 390 and its sum grows by ~1.2e11: every drawn
// coefficient pair and modulus spelling (`1000003..301000002`, `100003..999982`) is
// a new literal >= 1e6, which is the point of the layer -- an analyst reading the
// template no longer sees `sl+vo`, `ip+1`, `#q~=3` or `vo~=0`, and the price is
// algebra that carries its own coefficients. M4a counts rise correspondingly (`1`
// 502 -> 545, `0` 440 -> 478, `2` 231 -> 248), and the 12th entry is unchanged
// (`6`/50, so no value class enters or leaves the top 12). M1 = 96, M2's decoded
// stream (1523 B), the KAT words (only the audited getfenv capture), M4b (0
// skipped), M5 (4, 1812), M6 (0 pairs) and M7 ([568, 560, 550, 134, 17], gap 416)
// are byte-for-byte unchanged -> no new API word, no new pretty constant, no
// repeated ciphertext word, no new string class.
// P7 final draw shape (same batch, 2026-09-14) -- the layer's two literal draws were
// re-specified after the anchor census and the measured diff is M3b/M4a only:
//   M3b (390, 9007611512925197, 2^52) -> (378, 9007550309607896, 2^52). Coefficients
//     are now drawn from 1e6..1.2e6 instead of 1e6..3.01e8 (`mba::coefficient_pair`),
//     because the packed-reference field sites fold operands that reach ~9e6 and
//     `9e6 * 1.2e6 < 2^53` keeps every product exact; 12 spellings fall below the 1e6
//     gate and the sum follows (the payload's 2^52 max is untouched).
//   M4a `2` 248 -> 330, `15` 73 -> 88, `8` 56 -> 68, `16`/73 enters the top-12 and
//     `6`/50 leaves; `1` 545 -> 531. Two spelling sources move the small-value census:
//     the poly form now carries 7-digit coefficients, and the modulus/half sum forms
//     delegate to the shared `transport::opaque_split` (its parts are drawn under
//     `is_nice_part` rejection, which is the same predicate the anchor floor uses, so
//     the two layers can no longer disagree about what an anchor is) -- those parts are
//     often small. `0` (478), `3`, `4`, `5`, `28`, `7`, `70` are unchanged, so no new
//     value class, no new API word: M1 = 96, M2's decoded stream, the KAT words, M4b,
//     M5, M6 and M7 are byte-for-byte identical.
// Goal 5 (2026-09-15, ISA19) -- the constant-pool section became each
// prototype's keyed code-region tail, so every length-sensitive measure moves
// while the *shape* measures do not:
//   M1 96 (unchanged)            the symbol census is the three transport
//                                alphabets' union; the payload reshuffle cannot
//                                change which bytes appear.
//   M2 (1523,2,3,3) -> (1503,0,3,3)  the stream is 20 B shorter and its length
//                                now lands on a different residue pair -- a pure
//                                length artifact (M6/M3a stay put, so nothing
//                                structural moved).
//   M3b (378, ...) -> (377, ...)  one fewer big literal: the pool's per-record
//                                coordinates held a `>= 1e6` mask constant that
//                                the block length + key fold replaced.
//   M4 top-12 census              the small-literal order reshuffles with the
//                                payload (31 -> 15, 70 -> 75, one value
//                                exchanged at the tail); the K9b floor for `256`
//                                (4 sites) is unchanged.
//   M5 (4,1812) -> (4,1779)       four long blobs still, 33 B less text.
//   M7 gap 416 -> 408             the top string lengths moved by a few bytes.
//   M3a / M4b / M6 (all zeros)    untouched: no KAT word, no skipped number,
//                                no repeated u32 in the outer ciphertext.
// Goal 6 (2026-09-16) -- same re-record, one cause: `UK` gained the rolling step
// (`local k=(acc+119)%256; ... k=(k*MUL+b*MIX+ADD)%256`) and the walker gained the
// lazy cursor (`ST[1],ST[2],ST[3]` plus the commit state), so the emitted text is
// different text with a different small-literal mix:
//   M2 (1503, 0, 3, 3) -> (1501, 1, 1, 1)   two fewer integer tokens, one hex
//       spelling, one scientific spelling, one "unparsed" token (all four counters
//       move together because the respeller has to place the same literals in
//       different forms); the total is 2 B smaller.
//   M3b 377 -> 379, big-sum 9007550309001824 -> 9007554604575187: three more
//       6+ digit literals appear (the rolling coefficients are three extra numeric
//       tokens) and the sum follows them. max is the K9b 2^52 anchor, unchanged.
//   M4 top-12 re-orders (1, 522) -> (1, 526), (0, 491) -> (0, 506), 15: 117 -> 100,
//       5: 95 -> 82, 8: 65 -> 67: the `0`/`1` census is where the new `ST[1]`-style
//       field reads and the `%256` in the rolling step land. The four-cell `256`
//       floor is unchanged (K9b) and no new nice class appears.
//   M5 (4, 1779) -> (4, 1787)      four long blobs, 8 B more text.
//   M7 gap 408 -> 399              same strings, top-5 order re-measured.
//   M1 (96), M3a, M6 (0, 0)        untouched.
// Goal 7 transport fragmentation (2026-09-18): the three complete payload
// literals are replaced by 8..16 source-shuffled pieces each. M5/M7 lose the
// 500-byte-class blobs; their new 64..79-byte entries are payload fragments,
// not new monoliths. A dedicated fragment RNG leaves M1/M2/KAT/M3b/M4b/M6 and
// downstream draws fixed; only the joiner's 0/1/2 token counts enter M4.
// K6 step 2 (2026-09-23) -- same re-record, one cause: the 87-checksum field
// now carries its three `*87` respellings and is doubled (A + B spellings at
// two install sites), so its `2147483646` modulus literal appears one more
// time; the new literal pairs (`b=1+b`, `p+n>N`, `k2=(j-a)/256`, ...
// `a<F.__obf_proto_m-2`) re-shuffle the small-literal census. Net:
//   M3b 388 -> 389, big-sum +2147483646 (the doubled modulus), max unchanged.
//   M4 top-12: the 0/1/2/3/5/53/8/15/6 cells absorb the moved literals;
//     4 (154) and 23 (56) are untouched. No new nice class appears.
//   M1/M2/KAT/M5/M6/M7 untouched.
const PINS_LUA51_7001: AuditPins = (
    96,
    (1495, 1, 3, 0),
    [0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
            (389, 9007550084155834, 4503599627370496),
    [
        (0, 637),
        (1, 633),
        (2, 461),
        (3, 190),
        (4, 154),
        (5, 83),
        (53, 77),
        (16, 72),
        (8, 70),
        (15, 67),
        (6, 60),
        (23, 56),
    ],
    0,
    (12, 980),
    (0, 0),
    ([134, 98, 92, 83, 78], 9),
);

// L1 (2026-09-19, escape-spelled plaintext strings) -- only the two *text*
// measures move, in the direction the batch intends:
//   lua51: M5 (singleton plaintext runs) (9, 707) -> (12, 980); M7 top5
//          [134, 78, 75, 73, 70] gap 2 -> [134, 98, 92, 83, 78] gap 9.
//   luau:  M5 (5, 399) -> (6, 506); M7 [134, 71, 65, 65, 64] gap 0 ->
//          [134, 107, 71, 65, 65] gap 6.
// respelling splits readable words into pieces and lengthens the surviving
// literal text with `\ddd`/`\xHH` escapes; image/KAT/ECB/lane pins unchanged.
// M2 (2026-09-20, user-requested new opaque-predicate families mixed in:
// zero-dwarf self-cancelling arms, all-ones bit masks, boolean-xor/equivalence
// wrappers and rotate-dressed dispatch keys; scope-gated to bits=true so the
// Lua 5.1 config stays byte-identical -- this config alone moves) --
//   M3b (399 big) -> (395): pow2 structural constants (2^S / 2^(32-S) / 2^32
//          / 0xFFFFFFFF) replace part of the random u32 spells.
//   top12 re-ordered with (25,*) and (82,*) entering (wrapper/dwarf noise).
//   M5 singleton window 4->6 and (6, 506) back up: the boolean-wrapper tails
//          (`N~=0)`) are runnable unique substrings.
//   M7 top5 restored to [134, 107, 71, 65, 65] (80-char second leg refilled
//          by the same tail text), gap stays 6.
// M1 (2026-09-19, bit-composed constant spellings in the loader validation
// chain on Luau; the Lua 5.1 config stays byte-identical) -- the surfaces move
// as literal text moves, everything semantic holds:
//   M3b (340 big literals) -> (399): the bit families spell u32 operands as
//          ten-digit decimals, which the big-literal census counts; sum rises
//          by exactly the new operands, max (2^53 ceiling artifact) unchanged.
//   top12 histogram re-ordered by the same population shift.
//   M5 singletons (6, 506) -> (6, 479); M7 top5 second entry 107 -> 80 (the
//          longest plaintext runs got shorter, i.e. the intended direction).
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
// 2026-09-12 K9b re-record（同样只动 M4）：`256` 206 -> 4 掉出前十，第十二位由
// `19`(55) 回填，其余十一项逐字节不变；M3b (226, 9007479735086075,
// 4503599627370496) 与 M4b=40、M1/M2/KAT/M5/M6/M7 一字未动 ⇒ Luau 侧同样只是把
// 已经收集到的常数搬进包装表字段，大常数的种类与浮点拼写计数都没变。
// 2026-09-12 K3-FULL re-record（与 Lua51 同因，逐项归因；M1=86、KAT、M6=(0,0) 未动）：
//   M2 1390 -> 1550（+160 B：Luau 侧私有镜像随「每槽多一枚形状字节」变长，段 blob 的
//     源长跟着涨，残数是长度的算术后果）；
//   M3b (226, 9007479735086075, 4503599627370496) **一字未动** ⇒ 与 Lua51 同一结论：
//     去池没有引入任何新的大常数；
//   M4 top-12 里 `1` 543->521、`0` 418->419、`2` 247->244、`3` 171->169、`4` 160->158、
//     `5` 81->78（第五形显式拼出，多一处）、`8` 65->69、`18` 58->59、`89` 70 保持，`42` 65->95 涨，`82`(68)、
//     `19`(55) 掉出、`54`(46)、`7`(46) 进来：小数字的变化同上（描述子下标 1..6、五次
//     形状测试、零初始化，以及被删掉的 `%86`/`(b-35-rot)` 算术），`42`/`54`/`7` 这一档
//     是槽位键与状态号重抽的尾部噪声（K21/K20 记录过同一现象）；
//   M4b 40 -> 38（第二批：读者改回普通 local 后是 38，第一批测到 34）：区间边界与噪声的
//     重抽把若干枚改成了别的拼写（`M4b` 数的是被审计读成
//     非规范十进制的拼写数，值域与形状都没变）；
//   M5 (5,1840) -> (4,1821)、M7 [532,526,514,134,134]/380 -> [576,569,542,134,15]/408：
//     两条打包串塌成一条 7 字符描述子 ⇒ 孤例少一枚；段 blob 各涨 40..44 B（镜像变长的
//     分摊），`134` 那一类打包串长度只剩 `15`。
// K3-FULL 第二步 (2026-09-13, per-segment digit tables) -- luau, same three cells as
// lua51 and the same attribution: M1 86 -> 96 (union of the three per-segment tables
// over the stream; >= 87 is now the requirement, 86 would mean the tables collapsed).
// M5 (4,1821) -> (4,1781) and M7 [576,569,542,134,15] gap 408 ->
// [567,542,538,134,15] gap 404: the two *redrawn* segment bodies lost 40 B of source
// (their new permutations put the four forced-low symbols -- one decimal escape each
// -- in slightly less crowded positions), while 542 survives unchanged because it is
// part 0's body, whose table this batch deliberately left alone. M2's decoded stream
// (1550 B), M3b, the KAT words, M4's whole census, M4b (38) and M6 are byte-for-byte
// unchanged -> no new literal class, no new pretty constant, no repeated word.
// K22 (2026-09-14, rolling context chain) -- measured Luau diff, same attribution as
// Lua51: M4a `0` 407 -> 410 only (the 12th entry `6`/50 is byte-identical on both
// targets, so the two goldens moved for the same reason), M1/M2/M3b/M4b/M5/M6/M7
// unchanged. M7's top-5 already sat at gap 404 after K3s2 and does not move here.
// P7 (2026-09-14, goal-3 micro-op MBA layer) -- measured Luau diff, same
// attribution as Lua51: M3b count 226 -> 330 with the drawn coefficient literals,
// M4a `1` 520 -> 558, `0` 410 -> 448, `2` 241 -> 254, `3` 168 -> 174, `4` 162 -> 163,
// `5` 80 -> 82, `8` 67 -> 68 (the bit-family spellings share the same coefficient
// pool, so the class mix is the Lua51 one), 12th entry `6`/50 byte-identical. M1/M2
// (1550 B)/KAT words/M4b (38)/M5 (4, 1781)/M6/M7 ([567, 542, 538, 134, 15], gap 404)
// unchanged.
// P7 final draw shape (same batch, 2026-09-14) -- Luau moves for exactly the Lua51
// reasons (narrower coefficient draws, `opaque_split`-drawn modulus sums) and on the
// same two cells: M3b (330, 9007583562583119, 2^52) -> (318, 9007524907854693, 2^52),
// and M4a `2` 254 -> 322, `8` 68 -> 78, `16`/60 enters the top-12 while `6`/50 leaves,
// `1` 558 -> 550. The bit-family spellings share the same coefficient pool on this
// target, so the class mix tracks Lua51's (there `2`/330 and `16`/73). `0` (448), `3`,
// `4`, `5`, `42`, `89`, `18`, `22` and M1/M2 (1550 B)/KAT words/M4b (38)/M5
// (4, 1781)/M6/M7 ([567, 542, 538, 134, 15], gap 404) are byte-for-byte unchanged.
// Goal 6 (2026-09-16) -- the Luau re-record, same cause as the lua51 block above
// (rolling `UK` + the walker's lazy cursor/commit state). It moves more cells than
// lua51 because the Luau text carries the extra bit-helpers and one more convert arm:
//   M2 (1493, 2, 1, 3) -> (1501, 1, 1, 1): the counter total *rises* by 8 here (the
//       cursor reads plus the rolling coefficients outweigh the removed positional
//       step), while the spelling split collapses onto the same shape lua51 has.
//   M3b (318, 9007524907854693) -> (319, 9007529202821988): one more 6+ digit
//       literal; the sum follows it; max stays the 2^52 anchor.
//   M4 order and counts re-measured (1: 547, 0: 472, 2: 313, 3: 171, 4: 155, 8: 89,
//       5: 82, 18: 60, 16: 57, 36: 50, 42: 50, 6: 46) -- still exactly four `256`
//       sites, the K9b floor, and no new nice class.
//   M4b skipped 38, M5 (4, 1760), M7 ([550, 541, 535, 134, 15], 401), M3a/M6 zeros:
//       re-measured with the same text.
//   M1 (96) unchanged.
// Goal 7 buffer-backed opaque entry transitions (2026-09-18): M1/M2/KAT,
// the fragmented M5/M7 transport surface and M6 ciphertext repeat gate stay
// fixed. M3b/M4/M4b move because five transitions now carry independently
// permuted byte fragments, bit32 masks, typed reads and erase/checkpoint code;
// the counts are measured, not relaxed (M3a still has only two env captures).
// K6 step 2 (2026-09-23) -- same re-record, three causes, all measured:
//   M3b 395 -> 396, big-sum +2147483646: the 87-checksum field is doubled
//       (its A/B install pair carries the modulus literal twice), max
//       unchanged at the 2^52 anchor.
//   M4 top-12 re-measured: the new literal pairs (`b=1+b`, `p+n>N`,
//       `k2=(j-a)/256`, `a<F.__obf_proto_m-2`, ...) move counts between the
//       0/1/2/3/4/5/6/7/8/9/16 cells; the 82/25 tie is broken by value.
//   M4b skipped 6 -> 3 and M5 (6, 506) -> (6, 479) / M7 second-longest
//       107 -> 80: K6's group draws (group count, per-group slot cursors and
//       fold forms) advance the structure PRNG, so the downstream string
//       respeller re-escapes 73 strings. Unescaped content is byte-identical
//       (verified against the K4-only script: only escape spelling differs);
//       the source length of the spellings is what M5/M7 measure.
//   M1/M2/KAT/M6 untouched.
const PINS_LUAU_7351: AuditPins = (
    96,
    (1503, 0, 3, 3),
    [0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
            (396, 9007642612970580, 4503599627370496),
    [
        (1, 743),
        (2, 644),
        (0, 597),
        (3, 298),
        (4, 208),
        (6, 167),
        (5, 146),
        (8, 106),
        (7, 104),
        (9, 87),
        (16, 85),
        (25, 76),
    ],
    3,
    (6, 479),
    (0, 0),
    ([134, 80, 71, 65, 65], 6),
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
    let segments = segment_literals(&output, target, seed).unwrap();
    // K3-FULL 第二步: `segment_literals` admits the union of the three
    // per-segment tables, and M1 re-derives that filter, so it unions too. The
    // "exactly one table can write this segment" claim is pinned in
    // `segment_alphabets.rs`/`transport.rs`, not here.
    let mut member = [false; 256];
    for part in 0..3 {
        for byte in transport::base86_segment_alphabet(seed, part) {
            member[byte as usize] = true;
        }
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
