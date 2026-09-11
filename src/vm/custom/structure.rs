use super::*;
use std::fmt::Write as _;

/// Random non-keyword single-letter name for the wrapper's entry method. No
/// Lua 5.1 or Luau keyword is a single letter. Drawn from a dedicated seeded
/// stream: the same seed reproduces the whole script while bytecode, final
/// local names and private fields stay on their own existing streams.
pub(crate) fn wrapper_method(target: Target, seed: u64) -> String {
    let mut random = crate::random::Prng::new(seed ^ 0x6d65_7468_6f64_3276);
    let mut pool: Vec<char> = (b'a'..=b'z').map(char::from).collect();
    random.shuffle(&mut pool);
    let name = pool[0].to_string();
    debug_assert!(!crate::lexer::is_keyword(&name, target));
    name
}

/// Distinct random numeric keys for every payload-table section, including
/// seed-variable LZW fields and five split ChaCha8/anti-hook fields. Separate
/// seeded stream; same reproducibility guarantees as the method name.
pub(crate) fn wrapper_keys(seed: u64) -> Vec<u64> {
    let mut random = crate::random::Prng::new(seed ^ 0x6b65_7973_3276_6d35);
    let mut used = std::collections::BTreeSet::new();
    let mut keys = Vec::new();
    while keys.len() < 29 {
        let key = 100 + random.next_u64() % 9900;
        // K9a label hygiene: arbitrary labels must never emit audit-nice
        // values (a YARA rule for 86 must not hit a table key).
        if key == 256 || key == 7225 || key == 7396 {
            continue;
        }
        if used.insert(key) {
            keys.push(key);
        }
    }
    keys
}

/// M7 opaque branch predicates: constant integer tautologies and their
/// matched contradictions. Same shape, flipped truth value; no NaN, no
/// metamethods, no floats -- the truth value is fixed at generation time.
pub(crate) fn opaque_pair(structure: &mut crate::random::Prng) -> (String, String) {
    const TAUTOLOGIES: [(&str, &str); 4] = [
        ("48271%2==1", "48271%2==0"),
        ("2147483647>2147483646", "2147483647>2147483647"),
        ("65536%256==0", "65536%256==1"),
        ("16777216%2==0", "16777216%2==1"),
    ];
    let index = (structure.next_u64() % TAUTOLOGIES.len() as u64) as usize;
    let (truthy, falsy) = TAUTOLOGIES[index];
    (truthy.to_owned(), falsy.to_owned())
}

/// M7 unreachable decoy arms for the F3/F5 dispatch chains: `elseif o==K`
/// (in the chain's current comparison spelling) with byte values drawn
/// from outside the per-seed opcode image. The expanded instruction
/// stream only ever carries renumbered values of real opcodes, so these
/// arms are dead by construction while carrying real, plausible
/// instructions.
pub(crate) fn decoy_arms(
    structure: &mut crate::random::Prng,
    count: usize,
    luau: bool,
    bodies: &[&str],
    image: &std::collections::BTreeSet<u8>,
) -> Vec<(u8, String)> {
    let mut used = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    while used.len() < count {
        let opcode = loop {
            let value = (structure.next_u64() % 256) as u8;
            if !image.contains(&value) && used.insert(value) {
                break value;
            }
        };
        let body = bodies[(structure.next_u64() % bodies.len() as u64) as usize];
        let condition = structure.dispatch_condition(u16::from(opcode), luau);
        out.push((opcode, format!("{condition} then {body}")));
    }
    out
}

/// Two-level dispatch split with a binary search tree inside each bucket: the
/// arms of a dispatch chain are partitioned into a seeded number of sub-chains
/// selected by `value_var % groups`, and each sub-chain's arms are then looked
/// up through a seeded, possibly unbalanced **binary search tree** over the
/// arm values instead of one flat `if/elseif` scan. Every arm still sits behind
/// exactly its own equality test (`structure.dispatch_condition` spelling), so
/// evaluating the tree means evaluating at most one arm body -- the same
/// observable behaviour as the flat chain, with `log2` comparisons instead of a
/// scan. Leaves keep a short linear run (seeded size) so the topology has both
/// tree and chain shapes; every leaf and every empty residue class closes with
/// its own fail-closed `else E()end;`, and a residue class no arm carries stays
/// dead by construction (the selector can only be reached by validated
/// renumbered opcodes) and simply aborts.
pub(crate) fn grouped_tree(
    structure: &mut crate::random::Prng,
    mut arms: Vec<(u8, String)>,
    groups: u8,
    value_var: &str,
    luau: bool,
) -> String {
    structure.shuffle(&mut arms);
    let leaf_max = 2 + (structure.next_u64() % 3) as usize;
    let mut text = String::new();
    for group in 0..groups {
        let condition = selector_condition(structure, value_var, groups, group);
        write!(
            text,
            "{} {condition} then ",
            if group == 0 { "if" } else { "elseif" }
        )
        .unwrap();
        let mut members: Vec<(u8, String)> = arms
            .iter()
            .filter(|(value, _)| value % groups == group)
            .map(|(value, arm)| (*value, arm.clone()))
            .collect();
        if members.is_empty() {
            text.push_str("E();");
            continue;
        }
        // A value-partitioning tree needs distinct keys: equal values have to
        // stay in one leaf so the first matching arm wins, exactly like the
        // flat chain. The validator's callers guarantee this (renumbered
        // opcodes are a permutation and decoy values are drawn outside the
        // image), so a collision is a builder bug rather than a runtime case.
        members.sort_by_key(|(value, _)| *value);
        debug_assert!(members
            .as_slice()
            .windows(2)
            .all(|pair| pair[0].0 != pair[1].0));
        search_tree(structure, &members, value_var, luau, leaf_max, &mut text);
    }
    text.push_str(" else E()end;");
    text
}

/// One bucket's search tree. `members` must be sorted by value and hold
/// distinct values. Internal nodes only compare `value_var` against an existing
/// arm value (`below` picks `<`/`>=`), so each recursive call gets exactly the
/// arms on that side of the bound; small runs collapse into the original
/// `if/elseif ... else E()end` chain.
fn search_tree(
    structure: &mut crate::random::Prng,
    members: &[(u8, String)],
    value_var: &str,
    luau: bool,
    leaf_max: usize,
    out: &mut String,
) {
    if members.len() <= leaf_max {
        for (index, (_, arm)) in members.iter().enumerate() {
            write!(out, "{} {arm}", if index == 0 { "if" } else { "elseif" }).unwrap();
        }
        out.push_str(" else E()end;");
        return;
    }
    let split = 1 + (structure.next_u64() % (members.len() as u64 - 1)) as usize;
    let (left, right) = members.split_at(split);
    let bound = right[0].0;
    // The comparator and the branch order both vary per seed; the two forms
    // are exact complements, so the partition is the same tree either way.
    let below = structure.next_u64() % 2 == 0;
    let condition = structure.boundary_condition(value_var, u16::from(bound), below, luau);
    // Exactly one side runs: `below` asks `<` and keeps the low half in the
    // then-branch, otherwise the same partition rides as `>=` with the halves
    // swapped. Both spellings are complements, so no value can reach both.
    let (first, second) = if below { (left, right) } else { (right, left) };
    write!(out, "if {condition} then ").unwrap();
    search_tree(structure, first, value_var, luau, leaf_max, out);
    out.push_str(" else ");
    search_tree(structure, second, value_var, luau, leaf_max, out);
    out.push_str(" end;");
}

/// Wide-id form used by semantic superoperators. Recipe identifiers occupy
/// the full nonzero u16 range rather than the byte-sized opcode image.
pub(crate) fn grouped_recipe_chain(
    structure: &mut crate::random::Prng,
    mut arms: Vec<(u16, String)>,
    groups: u8,
    value_var: &str,
) -> String {
    structure.shuffle(&mut arms);
    let mut text = String::new();
    for group in 0..groups {
        let condition = selector_condition(structure, value_var, groups, group);
        write!(
            text,
            "{} {condition} then ",
            if group == 0 { "if" } else { "elseif" }
        )
        .unwrap();
        let members: Vec<&String> = arms
            .iter()
            .filter(|(value, _)| value % u16::from(groups) == u16::from(group))
            .map(|(_, arm)| arm)
            .collect();
        if members.is_empty() {
            text.push_str("E();");
        } else {
            for (index, arm) in members.iter().enumerate() {
                write!(text, "{} {arm}", if index == 0 { "if" } else { "elseif" }).unwrap();
            }
            text.push_str(" else E()end;");
        }
    }
    text.push_str(" else E()end;");
    text
}

/// Sub-chain selector condition, one of four exactly equivalent spellings
/// of `value % modulus == group` (raw integer arithmetic, no metamethods).
pub(crate) fn selector_condition(
    structure: &mut crate::random::Prng,
    value_var: &str,
    modulus: u8,
    group: u8,
) -> String {
    match structure.next_u64() % 4 {
        0 => format!("{value_var}%{modulus}=={group}"),
        1 => format!("{group}=={value_var}%{modulus}"),
        2 => format!("not({value_var}%{modulus}~={group})"),
        _ => format!("{value_var}%{modulus}-{group}==0"),
    }
}

/// Scratch-table slots: rewrite the given local variables of a field's
/// body into reads/writes of `g[key]` -- one fixed random key per variable
/// (drawn from the structure stream, so the mapping varies per seed), the
/// value constantly changing, `local` declarations for slots stripped
/// (assignments target the table). The caller prepends `local g={};` and,
/// where the field's lifetime ends, clears the table (`g=nil`) before
/// returning. Function names, parameters and for-loop controls must not be
/// listed; the scanner matches whole words only, so field-access prefixes
/// and string contents are never touched.
fn flush_word(word: &mut String, out: &mut String, keys: &std::collections::BTreeMap<&str, u64>) {
    if !word.is_empty() {
        match keys.get(word.as_str()) {
            Some(key) => write!(out, "g[{key}]").unwrap(),
            None => out.push_str(word),
        }
        word.clear();
    }
}

pub(crate) fn slot_rewrite(
    structure: &mut crate::random::Prng,
    text: &str,
    vars: &[&str],
) -> String {
    let mut keys: std::collections::BTreeMap<&str, u64> = Default::default();
    let mut used = std::collections::BTreeSet::new();
    for name in vars {
        loop {
            let key = 1 + structure.next_u64() % 99;
            // K9a label hygiene: slot keys are arbitrary labels, so 85/86
            // are rejected (they would read as radix constants).
            if key == 85 || key == 86 {
                continue;
            }
            if used.insert(key) {
                keys.insert(name, key);
                break;
            }
        }
    }
    let mut out = String::with_capacity(text.len() + 16);
    let mut word = String::new();
    // String literals are copied verbatim: packed payloads and tags must
    // never be mistaken for variable words. The scan is escape-aware: a
    // backslash inside a literal protects the next character, so K9a
    // `\"`/`\\`/`\ddd` escapes can never desynchronize the quote tracker
    // (behavior-preserving on escape-free bodies, which cover all
    // pre-K9a templates).
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in text.chars() {
        if let Some(marker) = quote {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == marker {
                quote = None;
            }
            continue;
        }
        if c == '"' || c == '\'' {
            flush_word(&mut word, &mut out, &keys);
            out.push(c);
            quote = Some(c);
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            flush_word(&mut word, &mut out, &keys);
            out.push(c);
        }
    }
    flush_word(&mut word, &mut out, &keys);
    // Slot declarations lose `local ` (they are table assignments now).
    out.replace("local g[", "g[")
}

/// Control-flow flattening: distinct per-seed state numbers for one
/// machine (three digits keeps them visually indistinct from operands).
pub(crate) fn state_values(structure: &mut crate::random::Prng, count: usize) -> Vec<u16> {
    let mut used = std::collections::BTreeSet::new();
    while used.len() < count {
        let value = (100 + structure.next_u64() % 900) as u16;
        // K9a label hygiene: state numbers are arbitrary labels, so the
        // byte width 256 is rejected.
        if value == 256 {
            continue;
        }
        used.insert(value);
    }
    used.into_iter().collect()
}

/// State-test condition, one of four exactly equivalent spellings of
/// `var == value` (raw integer comparison, no metamethods).
pub(crate) fn state_condition(
    structure: &mut crate::random::Prng,
    var: &str,
    value: u16,
) -> String {
    match structure.next_u64() % 4 {
        0 => format!("{var}=={value}"),
        1 => format!("{value}=={var}"),
        2 => format!("not({var}~={value})"),
        _ => format!("{var}-{value}==0"),
    }
}

/// Runtime-masked state representation used where a static state number must
/// not be enough to resolve a control-flow edge. Both assignment and every
/// comparison retain the mask expression; there is no removable one-time
/// guard in front of an otherwise ordinary state machine.
pub(crate) fn masked_state_value(value: u16, mask: &str) -> String {
    format!("({value}+{mask})%65521")
}

pub(crate) fn masked_state_condition(
    structure: &mut crate::random::Prng,
    var: &str,
    mask: &str,
    value: u16,
) -> String {
    let represented = masked_state_value(value, mask);
    match structure.next_u64() % 4 {
        0 => format!("{var}=={represented}"),
        1 => format!("{represented}=={var}"),
        2 => format!("not({var}~={represented})"),
        _ => format!("{var}-{represented}==0"),
    }
}

/// Select one of two disjoint physical state pairs from a runtime mask bit.
/// This makes the concrete transition -- not merely a common translation of
/// an otherwise static state -- depend on the reconstructed probe shares.
pub(crate) fn selected_masked_state_value(first: u16, second: u16, mask: &str) -> String {
    format!(
        "({mask}%2==0 and {} or {})",
        masked_state_value(first, mask),
        masked_state_value(second, mask)
    )
}

pub(crate) fn selected_masked_state_condition(
    structure: &mut crate::random::Prng,
    var: &str,
    mask: &str,
    first: u16,
    second: u16,
) -> String {
    let first = masked_state_condition(structure, var, mask, first);
    let second = masked_state_condition(structure, var, mask, second);
    format!("(({mask}%2==0 and {first})or({mask}%2~=0 and {second}))")
}

/// A flattened state machine: `while true do if <c1> then B1 elseif <c2>
/// then B2 ... else E()end end;` with the branch bodies supplied by the
/// caller and both the textual branch order and every condition spelling
/// drawn from the structure stream. The caller declares and initializes
/// the state variable before the machine.
pub(crate) fn state_machine(
    structure: &mut crate::random::Prng,
    var: &str,
    mut branches: Vec<(u16, String)>,
) -> String {
    structure.shuffle(&mut branches);
    let mut text = String::from("while true do ");
    for (index, (value, body)) in branches.iter().enumerate() {
        let condition = state_condition(structure, var, *value);
        write!(
            text,
            "{} {condition} then {body}",
            if index == 0 { "if" } else { "elseif" }
        )
        .unwrap();
    }
    text.push_str(" else E()end;end;");
    text
}

fn u16_expression(value: u16) -> String {
    format!("({}*256+{})", value / 256, value % 256)
}

fn token_opaque_pair(structure: &mut crate::random::Prng) -> (String, String) {
    let salt = u16_expression((17 + structure.next_u64() % 4_079) as u16);
    match structure.next_u64() % 5 {
        0 => ("v<=v and l<=l".to_owned(), "v<v or l<l".to_owned()),
        1 => (
            format!("(n+{salt})-{salt}==n"),
            format!("(n+{salt})-{salt}~=n"),
        ),
        2 => ("s%1==0 and f%1==0".to_owned(), "s%1==1 or f<0".to_owned()),
        3 => ("(v-l)==(v-l)".to_owned(), "(v-l)~=(v-l)".to_owned()),
        _ => (
            "(v<=v and v or 0)==v".to_owned(),
            "(v<=v and v or 0)~=v".to_owned(),
        ),
    }
}

fn nested_token_guard(
    structure: &mut crate::random::Prng,
    mut live: String,
    depth: usize,
    decoy_states: &[u16],
) -> String {
    for _ in 0..depth {
        let (truthy, falsy) = token_opaque_pair(structure);
        let odd = 3 + 2 * (structure.next_u64() % 31);
        let salt = u16_expression((101 + structure.next_u64() % 65_000) as u16);
        let state = decoy_states[structure.next_u64() as usize % decoy_states.len()];
        let dead = format!("repeat v=(v*{odd}+l+n+s+f+{salt})%65536;q={state};break until false;");
        live = if structure.next_u64() % 2 == 0 {
            format!("if {truthy} then {live}else {dead}end;")
        } else {
            format!("if {falsy} then {dead}else {live}end;")
        };
    }
    live
}

/// Five-stage context-dependent recipe-token decoder. The real inverse stages
/// are routed through a shuffled state machine and each is buried under four
/// or five nested dynamic tautologies. Five additional state arms contain
/// plausible one-iteration arithmetic loops but have no incoming transition
/// from the live chain. The same function is used while validating the wire
/// and on every interpreter fetch, so a record never exposes a stable recipe
/// id before these runtime stages have completed.
pub(crate) fn layered_recipe_decoder(
    structure: &mut crate::random::Prng,
    layers: &[semantic::RecipeTokenLayer; semantic::RECIPE_TOKEN_STAGES],
) -> String {
    const DECOY_STATES: usize = 5;
    let mut states = state_values(structure, semantic::RECIPE_TOKEN_STAGES + 1 + DECOY_STATES);
    structure.shuffle(&mut states);
    let live_states = &states[..=semantic::RECIPE_TOKEN_STAGES];
    let decoy_states = &states[semantic::RECIPE_TOKEN_STAGES + 1..];
    let mut branches = Vec::new();
    for (stage, layer) in layers.iter().rev().enumerate() {
        let terms = [
            u16_expression(layer.add),
            format!("l*{}", u16_expression(layer.label)),
            format!("n*{}", u16_expression(layer.next)),
            format!("s*{}", u16_expression(layer.skip)),
            format!("f*{}", u16_expression(layer.prototype)),
            format!("((l*n+s*f)%65536)*{}", u16_expression(layer.cross)),
        ];
        let mut terms = terms.to_vec();
        structure.shuffle(&mut terms);
        let context = terms.join("+");
        let body = format!(
            "v=((v-({context})%65536)*{})%65536;q={};",
            u16_expression(layer.inverse),
            live_states[stage + 1]
        );
        let depth = 4 + (structure.next_u64() % 2) as usize;
        branches.push((
            live_states[stage],
            nested_token_guard(structure, body, depth, decoy_states),
        ));
    }
    branches.push((
        live_states[semantic::RECIPE_TOKEN_STAGES],
        "return v;".to_owned(),
    ));
    for (index, &state) in decoy_states.iter().enumerate() {
        let next = decoy_states[(index + 1) % decoy_states.len()];
        let odd = 3 + 2 * (structure.next_u64() % 61);
        let salt = u16_expression((1 + structure.next_u64() % 65_535) as u16);
        branches.push((
            state,
            format!(
                "repeat v=(v*{odd}+l*n+s*f+{salt})%65536;n=(n+v+{salt})%65536;q={next};break until false;"
            ),
        ));
    }
    format!(
        "local RD=function(v,l,n,s,f)local q={};{}end;",
        live_states[0],
        state_machine(structure, "q", branches)
    )
}

fn edge_opaque_pair(structure: &mut crate::random::Prng) -> (String, String) {
    let salt = u16_expression((23 + structure.next_u64() % 4_057) as u16);
    match structure.next_u64() % 4 {
        0 => ("v<=v and l<=l".to_owned(), "v<v or l<l".to_owned()),
        1 => (
            format!("(f+{salt})-{salt}==f"),
            format!("(f+{salt})-{salt}~=f"),
        ),
        2 => ("ek%1==0 and f>=0".to_owned(), "ek%1==1 or f<0".to_owned()),
        _ => ("(v-l)==(v-l)".to_owned(), "(v-l)~=(v-l)".to_owned()),
    }
}

fn nested_edge_guard(
    structure: &mut crate::random::Prng,
    mut live: String,
    depth: usize,
    decoy_states: &[u16],
) -> String {
    for _ in 0..depth {
        let (truthy, falsy) = edge_opaque_pair(structure);
        let odd = 3 + 2 * (structure.next_u64() % 29);
        let salt = u16_expression((1 + structure.next_u64() % 65_535) as u16);
        let state = decoy_states[structure.next_u64() as usize % decoy_states.len()];
        let dead = format!("repeat v=(v*{odd}+l+f+ek+{salt})%65536;q={state};break until false;");
        live = if structure.next_u64() % 2 == 0 {
            format!("if {truthy} then {live}else {dead}end;")
        } else {
            format!("if {falsy} then {dead}else {live}end;")
        };
    }
    live
}

/// Three-stage decoder for encoded CFG successors. Raw `next`/`skip` labels
/// exist only as short-lived locals during validation/fetch; the persistent
/// code table retains edge tokens. A second shuffled state machine and its
/// dead arithmetic states prevent the recipe decoder from being the sole
/// control-flow gate.
pub(crate) fn layered_edge_decoder(
    structure: &mut crate::random::Prng,
    layers: &[semantic::EdgeTokenLayer; semantic::EDGE_TOKEN_STAGES],
) -> String {
    const DECOY_STATES: usize = 3;
    let mut states = state_values(structure, semantic::EDGE_TOKEN_STAGES + 1 + DECOY_STATES);
    structure.shuffle(&mut states);
    let live_states = &states[..=semantic::EDGE_TOKEN_STAGES];
    let decoy_states = &states[semantic::EDGE_TOKEN_STAGES + 1..];
    let mut branches = Vec::new();
    for (stage, layer) in layers.iter().rev().enumerate() {
        let terms = [
            u16_expression(layer.add),
            format!("l*{}", u16_expression(layer.source)),
            format!("f*{}", u16_expression(layer.prototype)),
            format!("ek*{}", u16_expression(layer.kind)),
            format!("(((l+ek)*(f+1))%65536)*{}", u16_expression(layer.cross)),
        ];
        let mut terms = terms.to_vec();
        structure.shuffle(&mut terms);
        let context = terms.join("+");
        let body = format!(
            "v=((v-({context})%65536)*{})%65536;q={};",
            u16_expression(layer.inverse),
            live_states[stage + 1]
        );
        let depth = 2 + (structure.next_u64() % 2) as usize;
        branches.push((
            live_states[stage],
            nested_edge_guard(structure, body, depth, decoy_states),
        ));
    }
    branches.push((
        live_states[semantic::EDGE_TOKEN_STAGES],
        "return v;".to_owned(),
    ));
    for (index, &state) in decoy_states.iter().enumerate() {
        let next = decoy_states[(index + 1) % decoy_states.len()];
        let odd = 3 + 2 * (structure.next_u64() % 47);
        let salt = u16_expression((1 + structure.next_u64() % 65_535) as u16);
        branches.push((
            state,
            format!(
                "repeat v=(v*{odd}+l*(f+1)+ek+{salt})%65536;f=(f+v+{salt})%65536;q={next};break until false;"
            ),
        ));
    }
    format!(
        "local ED=function(v,l,f,ek)local q={};{}end;",
        live_states[0],
        state_machine(structure, "q", branches)
    )
}

/// Per-seed opcode renumbering: an injective map from the 64 canonical ISA
/// slots to byte values 0..=255, drawn by rejection sampling from a
/// seed-salted stream. Both sides derive it identically: the generator
/// renumbers every dispatch/bounds arm and the termination check, the
/// target rebuilds the table from the packed base86 string (two chars per
/// slot, see the forms field) and rewrites each opcode byte while
/// expanding the validated varint stream.
pub(crate) fn opcode_permutation(seed: u64, slots: u8) -> Vec<u8> {
    let mut random = crate::random::Prng::new(seed ^ 0x6f70_636f_6465_7333);
    let mut taken = std::collections::BTreeSet::new();
    (0..slots)
        .map(|_| loop {
            let value = (random.next_u64() % 256) as u8;
            if taken.insert(value) {
                return value;
            }
        })
        .collect()
}

/// One base86 digit (0..=85) as the backslash-free printable char shared
/// by the packed strings of the forms field.
pub(crate) fn pack86(digit: u8) -> char {
    let mut byte = 35 + digit;
    if byte >= 92 {
        byte += 1;
    }
    byte as char
}

/// M7 structural variant: one of three exactly equivalent integer bound
/// checks. The operands are always integers decoded from 7-bit varints, so
/// `x>K`, `K<x` and `not(x<=K)` are interchangeable -- NaN cannot occur and
/// raw numeric comparison has no metamethod dispatch. Only the spelling of
/// the emitted check changes; behavior and rejection behavior are identical.
pub(crate) fn gt(structure: &mut crate::random::Prng, value: &str, bound: &str) -> String {
    match structure.next_u64() % 3 {
        0 => format!("{value}>{bound}"),
        1 => format!("{bound}<{value}"),
        _ => format!("not({value}<={bound})"),
    }
}
