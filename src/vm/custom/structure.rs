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

/// Thirteen distinct random numeric keys for the section functions of the
/// payload table (five sections, three key-share probes, three base86
/// payload segments, two split watermark-check functions). Separate seeded
/// stream; same reproducibility guarantees as the method name.
pub(crate) fn wrapper_keys(seed: u64) -> Vec<u64> {
    let mut random = crate::random::Prng::new(seed ^ 0x6b65_7973_3276_6d35);
    let mut used = std::collections::BTreeSet::new();
    let mut keys = Vec::new();
    while keys.len() < 21 {
        let key = 100 + random.next_u64() % 9900;
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

/// Two-level dispatch split: the arms of a dispatch chain are partitioned
/// into a seeded number of sub-chains selected by `value_var % groups`, so
/// the chain topology and the per-chain lengths vary per seed. Every arm
/// lands in the sub-chain of its value's residue; each sub-chain keeps its
/// own fail-closed `else E()end`, and a residue class no arm carries is
/// dead by construction (the selector can only be reached by validated
/// renumbered opcodes) and simply aborts.
pub(crate) fn grouped_chain(
    structure: &mut crate::random::Prng,
    mut arms: Vec<(u8, String)>,
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
            .filter(|(value, _)| value % groups == group)
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
            if used.insert(key) {
                keys.insert(name, key);
                break;
            }
        }
    }
    let mut out = String::with_capacity(text.len() + 16);
    let mut word = String::new();
    // String literals are copied verbatim: packed payloads and tags must
    // never be mistaken for variable words.
    let mut quote: Option<char> = None;
    for c in text.chars() {
        if let Some(marker) = quote {
            out.push(c);
            if c == marker {
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
        used.insert((100 + structure.next_u64() % 900) as u16);
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
