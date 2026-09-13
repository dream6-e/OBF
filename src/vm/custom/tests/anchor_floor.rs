// K9b (audit anchors at the wrapper-field floor). `tests/product_audit.rs` check1
// treats any value of `transport::NICE_FULL` that is spelled more than twice in the
// emitted text as an anchor an analyst can grep for, and the wrapper-field pass is
// allowed to buy such anchors with the single write that populates the field. This
// gate pins the floor that is actually reachable: one write, plus the spellings the
// pass is not allowed to touch. The census behind those numbers is in the module
// header of `constant_fields` -- after K9b the untouchable sites are shadowed
// scopes (a nearer binder of the wrapper name), not the payload-table constructor
// and not `[N]=` key positions, which measured zero occurrences. It is a one-way
// ratchet: a count may fall as reach grows, and it may not creep back up. The exact
// per-value counts for every other surface live in the product-audit pins; what
// belongs here is the cap, because the cap is the property K9b is about.

/// Spellings of `value` as a standalone canonical decimal integer: not glued to a
/// letter, digit, `_` or `.` on either side, so `0x1256`, `256.0`, `1e256` and
/// `t256` never count. Same adjacency rule the audit itself uses, which is what
/// keeps this gate and those pins from disagreeing.
fn decimal_spells(text: &str, value: u64) -> usize {
    let needle = value.to_string();
    let bytes = text.as_bytes();
    let glued = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.';
    let mut count = 0usize;
    let mut from = 0usize;
    while let Some(found) = text[from..].find(needle.as_str()) {
        let start = from + found;
        let end = start + needle.len();
        let free_before = start == 0 || !glued(bytes[start - 1]);
        let free_after = end == text.len() || !glued(bytes[end]);
        if free_before && free_after {
            count += 1;
        }
        from = start + 1;
    }
    count
}

/// What check1 counts as "not an anchor": a nice value spelled twice or less is
/// noise, the third spelling is what an analyst would pattern on.
const CHECK1_FREE: usize = 2;

/// Per-value maxima on the Lua 5.1 golden, measured after K3-FULL. Three values are
/// still above check1's threshold and each is at its floor: `256` (one field write
/// plus the three shadowed-scope spellings K9b measured), `4294967296` (write plus two
/// shadowed) and `2147483647` (K16's residual -- 23 of its 29 spellings sit under a
/// binder that re-shadows the wrapper name). **Every other nice value must stay at or
/// below [`CHECK1_FREE`]**, which is what this batch tightened: before K3-FULL, `86`
/// (3) and `65536` (3) also needed table entries, because the form/renumbering field
/// spelled both radix constants while rebuilding the tables; with the tables gone, both
/// fall under the threshold. A count may fall further; it may not rise, and adding a row
/// here requires the measurement and the per-site reason in the commit message.
const SPELLING_MAXIMA_LUA51: [(u64, usize); 3] =
    [(256, 4), (4294967296, 3), (2147483647, 24)];

/// Same census on the Luau golden. `16777216` keeps its four spellings because four uses
/// is under `MIN_USES`, so a wrapper field would lose bytes there (K16's curve), and
/// `4294967296` sits at two because Luau's pool has one fewer out-of-reach spelling.
/// `86` needs a row here where the Lua 5.1 golden does not: three spellings survive on
/// this target, all of them inside the transport's own radix machinery (the count has
/// moved between 2 and 4 across K19/K3 as the stream re-drew, so it is recorded as a cap,
/// and it is one spelling above check1's threshold -- the smallest possible anchor.
const SPELLING_MAXIMA_LUAU: [(u64, usize); 4] = [
    (86, 3),
    (256, 4),
    (16777216, 4),
    (2147483647, 27),
];

/// The two `256` floors K9b measured are the *only* nice-value anchor the byte-assembly
/// weight still has; K3-FULL re-checked that the shape no longer re-enters through the
/// reader, hence this exact-equality half of the gate below.
const ANCHOR_FLOOR_256: usize = 4;

#[test]
fn every_audit_anchor_sits_at_the_wrapper_field_floor_in_the_goldens() {
    for (target, path, maxima) in [
        (
            Target::Lua51,
            concat!(env!("CARGO_MANIFEST_DIR"), "/vm_lua51.out.lua"),
            &SPELLING_MAXIMA_LUA51[..],
        ),
        (
            Target::Luau,
            concat!(env!("CARGO_MANIFEST_DIR"), "/vm_luau.out.lua"),
            &SPELLING_MAXIMA_LUAU[..],
        ),
    ] {
        let body =
            fs::read_to_string(path).unwrap_or_else(|why| panic!("{path}: no golden ({why})"));
        for value in transport::NICE_FULL {
            let count = decimal_spells(&body, value);
            let cap = maxima
                .iter()
                .find(|(spelled, _)| *spelled == value)
                .map_or(CHECK1_FREE, |(_, cap)| *cap);
            assert!(
                count <= cap,
                "{target:?} golden spells `{value}` {count} times, above the recorded cap {cap}: that constant is drifting back towards being a grep handle. Either the wrapper-field pass lost it (see `plan`'s audit exception and the reach rules in `constant_fields`) or a new emitter started spelling it inline. A lower count is a win and belongs in this table with the diff in the commit message; a higher one is never fixed by raising a cap."
            );
        }
        // The value K9b was about: it used to be spelled a couple of hundred times
        // (218 on Lua 5.1, 207 on Luau) because every digit loop assembles bytes with
        // it. Exactly four survive -- the field write and the three sites the pass is
        // not allowed to rewrite -- on both targets.
        assert_eq!(
            decimal_spells(&body, 256),
            ANCHOR_FLOOR_256,
            "{target:?}: `256` moved off the measured floor -- re-run the census, put the per-site attribution next to this assertion, and re-record it from the numbers"
        );
    }
}

#[test]
fn decimal_spelling_census_ignores_glued_and_nondecimal_forms() {
    // Guards the census itself: a respelled or adjacent digit run is not an anchor.
    let text = "x=256 y=0x1256 z=256.0 w=t256 v=(1e256) u=[256]=1 s=\"256\"";
    // Three count: the standalone one, a `[256]=` key, and digits inside a string --
    // the census is textual, exactly as check1 runs it, which is why the field-write
    // floor of four is measured the same way in both places.
    assert_eq!(decimal_spells(text, 256), 3);
    assert_eq!(decimal_spells("return 65536+65536", 65536), 2);
    assert_eq!(decimal_spells("2561 655360", 256), 0);
}

/// K9b's own size ratchet, at the level the exception actually operates on: the
/// whole wrapper-field pass (arithmetic candidates *and* the audit exception) has
/// to leave the shipped file smaller than the same file with the pass switched off.
/// The exception is allowed to spend the one write that populates a field -- that
/// is its whole price -- but it is never allowed to turn the table into a cost.
/// Measured saving on the two golden configs: 376 B (Lua 5.1) and 322 B (Luau);
/// the assertion only demands 64 B, so a batch that trades a little of that for a
/// legitimate reason still passes while a size sink fails loudly.
#[test]
fn the_wrapper_field_pass_never_costs_the_shipped_script_bytes() {
    for (target, fixture, seed) in [
        (
            Target::Lua51,
            include_str!("../../../../tests/fixtures/vm_lua51.lua"),
            7001u64,
        ),
        (
            Target::Luau,
            include_str!("../../../../tests/fixtures/vm_luau.lua"),
            7351u64,
        ),
    ] {
        let data = crate::vm::custom::compile(fixture, target).unwrap();
        let without = super::emit_unlifted(&data, target, seed).unwrap();
        let with = super::emit(&data, target, seed).unwrap();
        assert!(
            with.len() + 64 <= without.len(),
            "{target} seed {seed}: the constant-field pass grew the script ({} -> {} B). Admitting a spelling to the wrapper table is only allowed for the one audit-anchor case, and only while every use stays price neutral -- re-measure `plan`/`admits` before touching this bound, and never by relaxing the `text.len() >= read` side of the exception.",
            without.len(),
            with.len()
        );
    }
}
