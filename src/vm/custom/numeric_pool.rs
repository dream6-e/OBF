//! K15: pooled numeric literals.
//!
//! The generated VM repeats the same integer spellings hundreds of times: `256`
//! appears about 200 times and `65536` about 100 times in a shipped script,
//! because every mask, radix, shift and range check spells its modulus out.
//! This pass replaces the most frequent ones with chunk-level locals and
//! rewrites every occurrence to read the local instead, which is a pure size
//! win (one declaration, then one or two characters per use after the name pass
//! shortens it) and changes no arithmetic: the substituted text is the *same*
//! Lua number, so masks, folds and bounds checks stay bit-identical.
//!
//! Two properties are load-bearing and are the reason this runs on the
//! assembled script instead of inside the field builders:
//!
//! * Only tokens this module can prove are standalone decimal integers are
//!   touched. The scanner walks the source the way the Lua lexer does --
//!   skipping long-bracket and quoted strings (with escapes) and both comment
//!   forms -- so the embedded image blob, the escape-encoded payloads and any
//!   digit run that lives inside text are never rewritten. A number adjacent
//!   to `.`/`e`/`x`/a letter is also left alone, so `1e5`, `0x10`, `256.` and
//!   `1..2` keep their original meaning.
//!   Pooled spellings must additionally be canonical (`text == value` in
//!   decimal), which rules out zero-padded forms like `0256`.
//!
//! * The declarations are inserted immediately before the first real token of
//!   the chunk, so they sit in the outermost scope and every stage arm, field
//!   body and adapter captures the same local. Candidate names are checked
//!   against every identifier in the script, so nothing is shadowed and no
//!   global read changes meaning. The slot count is capped, which keeps the
//!   chunk's local/upvalue totals far below the Lua and Luau limits.
//!
//! The pass is a pure function of the emitted text: no RNG is consumed, so
//! output stays deterministic per (source, target, config, seed) and a program
//! whose literals are already rare simply comes back unchanged.

use crate::{Diagnostic, Target};
use std::collections::BTreeMap;

/// Pooled spellings per script. Enough to capture the whole plateau of the
/// measured benefit curve (the top slots carry ~2 KiB of the ~3.4 KiB total);
/// kept small so the outermost scope never grows near a VM limit.
const MAX_SLOTS: usize = 14;
/// A spelling must be this long before pooling it can pay for the declaration
/// at all (single-digit literals are already one byte).
const MIN_CHARS: usize = 2;
/// Minimum uses for a spelling to be worth a slot.
const MIN_USES: usize = 6;

/// One pooled literal: the exact decimal text it replaces and its local name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) text: String,
    pub(crate) name: String,
}

/// True when the literal at `start..end` is a table key -- `[9820]=function`
/// in the payload constructor or `i[76]=` in an assignment. Those spellings
/// carry two attested properties: the private fields are *numerically* keyed
/// (the layout the seed shuffles) and `X[N]=N` is one of the decoy shapes the
/// heuristic audit counts. Binding them would buy a few bytes and cost both,
/// so the pass skips them; `[N]==x` is a comparison and stays eligible.
fn is_key_position(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    let mut before = start;
    while before > 0 && bytes[before - 1].is_ascii_whitespace() {
        before -= 1;
    }
    if before == 0 || bytes[before - 1] != b'[' {
        return false;
    }
    let mut after = end;
    while after < bytes.len() && bytes[after].is_ascii_whitespace() {
        after += 1;
    }
    if after == bytes.len() || bytes[after] != b']' {
        return false;
    }
    after += 1;
    while after < bytes.len() && bytes[after].is_ascii_whitespace() {
        after += 1;
    }
    bytes.get(after) == Some(&b'=') && bytes.get(after + 1) != Some(&b'=')
}

/// Census over the positions this pass may bind: [`census`] minus the table
/// keys. Selection and the faithfulness check use these counts, so a literal
/// that only ever occurs as a key is never pooled at all.
fn usable_counts(source: &str) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (start, end) in number_spans(source) {
        let Some(text) = canonical(source, start, end) else {
            continue;
        };
        if is_key_position(source, start, end) {
            continue;
        }
        *counts.entry(text.to_owned()).or_insert(0) += 1;
    }
    counts
}

/// The literal at `start..end` if this pass may treat it as a standalone
/// canonical decimal integer: long enough to matter, and round-tripping
/// through `u64` so that zero-padded spellings (`0256`, which Lua 5.1 reads as
/// octal 174) and overflowing digit runs stay exactly as emitted. The span list
/// itself is already maximal and never reaches inside a string or comment, so
/// `1e5`, `0x10` and `256.` cannot reach here at all.
fn canonical(source: &str, start: usize, end: usize) -> Option<&str> {
    let text = &source[start..end];
    if text.len() < MIN_CHARS || text.starts_with('0') {
        return None;
    }
    let value = text.parse::<u64>().ok()?;
    if value.to_string() != text {
        return None;
    }
    Some(text)
}

/// Census over a script: every poolable decimal integer with its count,
/// ignoring where it sits. Test-only view -- the product path uses
/// [`usable_counts`], which additionally skips table-key positions -- but the
/// shape is worth asserting directly, which is why it stays.
#[cfg(test)]
pub(crate) fn census(source: &str) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (start, end) in number_spans(source) {
        if let Some(text) = canonical(source, start, end) {
            *counts.entry(text.to_owned()).or_insert(0) += 1;
        }
    }
    counts
}

fn net_gain(text: &str, uses: usize) -> i64 {
    // A use costs about one byte less than the literal once the name pass has
    // shortened the pooled local, so the gain is roughly `len - 1` per use
    // against a shared declaration of one name and one value per spelling; the
    // estimate charges one extra byte per use as safety margin, so a use of a
    // two-character literal never pays for itself.
    let len = text.len() as i64;
    (uses as i64) * (len - 2) - (len + 7)
}

/// Decide which spellings become locals. Sorted by gain, then by the literal
/// text, so ties never depend on hash order. Test-only view of the selection
/// rule; the product path reaches the same logic through [`pool`].
#[cfg(test)]
pub(crate) fn plan(source: &str) -> Vec<Entry> {
    plan_with_counts(source).0
}

/// [`plan`] plus the usable census it was derived from, so the caller can
/// verify the rewrite without re-scanning for selection.
fn plan_with_counts(source: &str) -> (Vec<Entry>, BTreeMap<String, usize>) {
    let counts = usable_counts(source);
    let taken = identifiers(source);
    let mut ranked: Vec<(i64, &String)> = counts
        .iter()
        .filter(|(text, uses)| **uses >= MIN_USES && net_gain(text, **uses) > 0)
        .map(|(text, uses)| (net_gain(text, *uses), text))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
    let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut next = 0u32;
    let mut out = Vec::new();
    for (_, text) in ranked.into_iter().take(MAX_SLOTS * 3) {
        if out.len() >= MAX_SLOTS {
            break;
        }
        let Some(name) = free_name(&mut next, &taken, &used) else {
            break;
        };
        used.insert(name.clone());
        out.push(Entry {
            text: text.clone(),
            name,
        });
    }
    (out, counts)
}

fn free_name(
    next: &mut u32,
    taken: &std::collections::BTreeSet<String>,
    used: &std::collections::BTreeSet<String>,
) -> Option<String> {
    while *next < 400 {
        let index = *next;
        *next += 1;
        let name = format!("ZQ{index}");
        if !taken.contains(&name) && !used.contains(&name) {
            return Some(name);
        }
    }
    None
}

/// How many times `name` appears as a whole identifier in `source`.
fn identifier_uses(source: &str, name: &str) -> usize {
    let bytes = source.as_bytes();
    let mut out = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'-' if bytes.get(i + 1) == Some(&b'-') => i = skip_comment(source, i),
            b'"' | b'\'' => i = skip_quoted(bytes, i),
            b'[' if long_open(bytes, i).is_some() => i = skip_long(bytes, i).unwrap_or(i + 1),
            c if is_ident_start(c) => {
                let start = i;
                while i < bytes.len() && is_ident(bytes[i]) {
                    i += 1;
                }
                if &source[start..i] == name {
                    out += 1;
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// The script with the numeric pool undone: the chunk-level declaration
/// [`pool`] inserted is dropped and every name it bound is spelled back as its
/// literal.
///
/// Test-only, and only sound on a script no other binding shares a pooled name
/// with -- after the name pass, a one-letter pool name is indistinguishable
/// from an unrelated local in a sibling scope, so inlining would corrupt the
/// text. It exists to prove this module's own rewrite is value-faithful; the
/// library's structural censuses use `emit_unpooled` instead.
#[cfg(test)]
pub(crate) fn unpool(source: &str) -> String {
    let bytes = source.as_bytes();
    let start = first_token(source);
    if !source[start..].starts_with("local ") {
        return source.to_string();
    }
    let mut i = start + "local ".len();
    let mut names: Vec<(usize, usize)> = Vec::new();
    loop {
        while bytes.get(i) == Some(&b' ') || bytes.get(i) == Some(&b'\t') {
            i += 1;
        }
        let word = i;
        while i < bytes.len() && is_ident_start(bytes[i]) {
            i += 1;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
        }
        if word == i {
            return source.to_string();
        }
        names.push((word, i));
        if bytes.get(i) == Some(&b',') {
            i += 1;
            continue;
        }
        break;
    }
    if bytes.get(i) != Some(&b'=') || names.is_empty() {
        return source.to_string();
    }
    i += 1;
    let mut values: Vec<(usize, usize)> = Vec::new();
    loop {
        let digit = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if digit == i {
            return source.to_string();
        }
        values.push((digit, i));
        if bytes.get(i) == Some(&b',') {
            i += 1;
            continue;
        }
        break;
    }
    if values.len() != names.len() {
        return source.to_string();
    }
    // Only canonical decimal literals belong to this pass.
    for (from, to) in &values {
        let text = &source[*from..*to];
        if text.parse::<u64>().is_err() || text.parse::<u64>().unwrap().to_string() != text {
            return source.to_string();
        }
    }
    let bound: BTreeMap<&str, &str> = names
        .iter()
        .zip(values.iter())
        .map(|((name_from, name_to), (value_from, value_to))| {
            (
                &source[*name_from..*name_to],
                &source[*value_from..*value_to],
            )
        })
        .collect();
    if bytes.get(i) == Some(&b';') {
        i += 1;
    }
    let mut out = String::from(&source[..start]);
    let mut flush = i;
    while i < bytes.len() {
        match bytes[i] {
            b'-' if bytes.get(i + 1) == Some(&b'-') => i = skip_comment(source, i),
            b'"' | b'\'' => i = skip_quoted(bytes, i),
            b'[' if long_open(bytes, i).is_some() => i = skip_long(bytes, i).unwrap_or(i + 1),
            c if is_ident_start(c) => {
                let word = i;
                while i < bytes.len() && is_ident(bytes[i]) {
                    i += 1;
                }
                if let Some(value) = bound.get(&source[word..i]) {
                    out.push_str(&source[flush..word]);
                    // The name pass is allowed to close a `x .. y` gap once the
                    // operand is an identifier, so an inlined literal has to
                    // re-open it: `65536..2` would be a malformed number.
                    if word > flush && bytes[word - 1] == b'.' {
                        out.push(' ');
                    }
                    out.push_str(value);
                    if bytes.get(i) == Some(&b'.') {
                        out.push(' ');
                    }
                    flush = i;
                }
            }
            _ => i += 1,
        }
    }
    out.push_str(&source[flush..]);
    out
}

fn is_ident_start(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphabetic()
}

fn is_ident(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// All identifiers in the script (comments and strings excluded by the scan
/// below), used to avoid shadowing anything.
fn identifiers(source: &str) -> std::collections::BTreeSet<String> {
    let bytes = source.as_bytes();
    let mut out = std::collections::BTreeSet::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i = skip_comment(source, i);
            }
            b'"' | b'\'' => {
                i = skip_quoted(bytes, i);
            }
            b'[' if long_open(bytes, i).is_some() => {
                i = skip_long(bytes, i).unwrap_or(i + 1);
            }
            c if is_ident_start(c) => {
                let start = i;
                while i < bytes.len() && is_ident(bytes[i]) {
                    i += 1;
                }
                out.insert(source[start..i].to_string());
            }
            _ => i += 1,
        }
    }
    out
}

/// Byte spans of standalone decimal integer runs: maximal digit runs that are
/// not glued to a letter, `_` or `.`, and that live outside strings/comments.
fn number_spans(source: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i = skip_comment(source, i);
            }
            b'"' | b'\'' => {
                i = skip_quoted(bytes, i);
            }
            b'[' if long_open(bytes, i).is_some() => {
                i = skip_long(bytes, i).unwrap_or(i + 1);
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let glued_before = start > 0 && is_ident(bytes[start - 1]);
                let glued_after = i < bytes.len() && (is_ident(bytes[i]) || bytes[i] == b'.');
                if !glued_before && !glued_after {
                    out.push((start, i));
                }
            }
            _ => i += 1,
        }
    }
    out
}

fn skip_comment(source: &str, at: usize) -> usize {
    let bytes = source.as_bytes();
    let mut i = at + 2;
    if let Some(close) = long_open(bytes, i) {
        if let Some(end) = skip_long_from(bytes, i, close) {
            return end;
        }
    }
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

/// `[[`, `[=[`, ... -> the closing bracket length to look for.
fn long_open(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'[') {
        return None;
    }
    let mut level = 0usize;
    let mut i = at + 1;
    while bytes.get(i) == Some(&b'=') {
        level += 1;
        i += 1;
    }
    if bytes.get(i) == Some(&b'[') {
        Some(level)
    } else {
        None
    }
}

fn skip_long(bytes: &[u8], at: usize) -> Option<usize> {
    let level = long_open(bytes, at)?;
    skip_long_from(bytes, at, level)
}

fn skip_long_from(bytes: &[u8], at: usize, level: usize) -> Option<usize> {
    let close: Vec<u8> = format!("]{}]", "=".repeat(level)).into_bytes();
    let start = at + 2 + level;
    let mut i = start;
    while i + close.len() <= bytes.len() {
        if &bytes[i..i + close.len()] == close.as_slice() {
            return Some(i + close.len());
        }
        i += 1;
    }
    None
}

fn skip_quoted(bytes: &[u8], at: usize) -> usize {
    let quote = bytes[at];
    let mut i = at + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            c if c == quote => return i + 1,
            _ => {}
        }
        i += 1;
    }
    i
}

/// Byte index of the first real token: declarations inserted here land in the
/// chunk's outermost scope, ahead of everything that uses them, while any
/// leading comment keeps its position.
fn first_token(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            c if c.is_ascii_whitespace() => i += 1,
            b'-' if bytes.get(i + 1) == Some(&b'-') => i = skip_comment(source, i),
            _ => return i,
        }
    }
    i
}

/// Rewrite `source`, pooling its most frequent decimal literals. Returns the
/// source untouched when nothing qualifies.
pub(crate) fn pool(source: &str, target: Target) -> Result<String, Diagnostic> {
    let (entries, counts) = plan_with_counts(source);
    if entries.is_empty() {
        return Ok(source.to_string());
    }
    let spans = number_spans(source);
    let replaced: usize = spans
        .iter()
        .filter(|(start, end)| {
            !is_key_position(source, *start, *end)
                && entries
                    .iter()
                    .any(|e| &source[*start..*end] == e.text.as_str())
        })
        .count();
    let lookup: BTreeMap<&str, &str> = entries
        .iter()
        .map(|e| (e.text.as_str(), e.name.as_str()))
        .collect();
    // One `local` with a name list and a value list: `local a=1,b=2` is not even
    // legal Lua, so names and literals must be grouped rather than interleaved
    // -- which is also the cheapest spelling, one keyword for the whole pool.
    let mut declaration = String::from("local ");
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            declaration.push(',');
        }
        declaration.push_str(&entry.name);
    }
    declaration.push('=');
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            declaration.push(',');
        }
        declaration.push_str(&entry.text);
    }
    declaration.push(';');

    // Spans refer to the original text, so the literal-for-name rewrite runs
    // first and the declaration is spliced in afterwards.
    let split = first_token(source);
    let mut body = String::with_capacity(source.len());
    let mut last = 0usize;
    for (start, end) in number_spans(source) {
        if is_key_position(source, start, end) {
            continue;
        }
        let text = &source[start..end];
        let Some(name) = lookup.get(text) else {
            continue;
        };
        body.push_str(&source[last..start]);
        body.push_str(name);
        last = end;
    }
    body.push_str(&source[last..]);
    let mut out = String::with_capacity(declaration.len() + body.len());
    out.push_str(&source[..split]);
    out.push_str(&declaration);
    out.push_str(&body[split..]);
    // Faithfulness check, arithmetic rather than token counts: after pooling,
    // the only decimal literals left in the script are the ones in the new
    // declaration, and every pooled name appears once per literal it replaced
    // plus once in the declaration.
    let expected_spans = spans.len() - replaced + entries.len();
    let actual_spans = number_spans(&out).len();
    if actual_spans != expected_spans {
        return Err(Diagnostic::new(format!(
            "numeric pooling left {actual_spans} decimal literals, expected {expected_spans}"
        )));
    }
    for entry in &entries {
        let uses = *counts
            .get(&entry.text)
            .ok_or_else(|| Diagnostic::new("numeric pooling lost a census entry"))?;
        let seen = identifier_uses(&out, &entry.name);
        if seen != uses + 1 {
            return Err(Diagnostic::new(format!(
                "numeric pooling bound {} to {} uses, expected {}",
                entry.name,
                seen,
                uses + 1
            )));
        }
    }
    crate::lexer::lex(&out, target)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pools_repeated_decimal_literals_once_each() {
        let source = "local m=256;local a=x%256;local b=y%256;local c=z%256;local d=w%256;local e=v%256;local f=w%256;local g=v%256;local h=x%256;local i=y%256;local j=z%256;local k=w%256;";
        let counts = census(source);
        assert_eq!(counts.get("256"), Some(&12));
        let out = pool(source, Target::Lua51).unwrap();
        assert_eq!(out.matches("local ZQ0=256;").count(), 1, "{out}");
        // `local a=1,b=2` is not legal Lua: a multi-value pool groups the names
        // and the values into two lists.
        let mut two = String::new();
        for _ in 0..12 {
            two.push_str("t=t%65536;");
        }
        for _ in 0..12 {
            two.push_str("u=u%256;");
        }
        let two = pool(&two, Target::Lua51).unwrap();
        // The better-paying literal is bound first, so ZQ0 is the long one.
        assert!(two.starts_with("local ZQ0,ZQ1=65536,256;"), "{two}");
        assert_eq!(
            out.matches("256").count(),
            1,
            "every use must become a read"
        );
    }

    #[test]
    fn table_key_spellings_stay_numeric_and_unpool_inverts_the_binding() {
        // `[N]=` carries the numeric-keyed layout, so those occurrences are
        // never rewritten; the arithmetic uses of the same literal still pay.
        let mut source = String::from("local t={};");
        for _ in 0..6 {
            source.push_str("t[65536]=1;");
        }
        for _ in 0..8 {
            source.push_str("u=u+65536;");
        }
        let out = pool(&source, Target::Lua51).unwrap();
        assert!(out.starts_with("local ZQ0=65536;"), "{out}");
        assert_eq!(out.matches("t[65536]=1;").count(), 6, "{out}");
        assert!(!out.contains("u=u+65536;"), "{out}");
        assert_eq!(out.matches("65536").count(), 7, "{out}");
        let back = unpool(&out);
        assert_eq!(back, source, "unpool must invert the binding exactly");
    }

    #[test]
    fn zero_padded_and_long_digit_runs_are_never_pooled() {
        // `0256` is octal 174 in Lua 5.1, and a digit run that overflows u64
        // is a float: rebinding either spelling would change a value.
        let mut source = String::new();
        for _ in 0..20 {
            source.push_str("t=t+0256;");
        }
        for _ in 0..20 {
            source.push_str("u=u+99999999999999999999999;");
        }
        assert!(census(&source).is_empty(), "{:?}", census(&source));
        assert_eq!(pool(&source, Target::Lua51).unwrap(), source);
    }

    #[test]
    fn leaves_strings_comments_and_glued_numbers_alone() {
        let source = "local s=\"x%256y\"; -- 256\nlocal a=[[256]];\nlocal b=1e5;local c=0x10;local d=256.;local e=256;local f=256;local g=256;local h=256;local i=256;local j=256;";
        let counts = census(source);
        assert_eq!(counts.get("256"), Some(&6), "{counts:?}");
        assert!(!counts.contains_key("1e5") && !counts.contains_key("10"));
        let out = pool(source, Target::Lua51).unwrap();
        assert!(out.contains("\"x%256y\""), "{out}");
        assert!(out.contains("-- 256"), "{out}");
        assert!(out.contains("[[256]]"), "{out}");
        assert!(out.contains("1e5") && out.contains("0x10") && out.contains("256."));
    }

    #[test]
    fn rare_or_short_literals_are_not_pooled() {
        let source = "local a=256;local b=7;local c=99999999;";
        assert!(pool(source, Target::Lua51).unwrap() == source);
    }

    #[test]
    fn plan_is_capped_and_deterministic() {
        let mut source = String::from("local t={};");
        for value in 100..260u32 {
            for _ in 0..30 {
                source.push_str(&format!("t=t+{};", value));
            }
        }
        for round in 0..2 {
            let plan = plan(&source);
            assert!(!plan.is_empty() && plan.len() <= MAX_SLOTS, "round {round}");
            let names: Vec<&str> = plan.iter().map(|e| e.name.as_str()).collect();
            let mut unique = names.clone();
            unique.sort();
            unique.dedup();
            assert_eq!(unique.len(), names.len(), "names must be distinct");
            assert_eq!(plan, super::plan(&source), "round {round} must repeat");
        }
    }
}
