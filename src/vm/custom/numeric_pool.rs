//! K15: pooled numeric literals, inside the shell.
//!
//! The generated VM repeats the same integer spellings hundreds of times: `256`
//! appears about 200 times and `65536` about 100 times in a shipped script,
//! because every mask, radix, shift and range check spells its modulus out.
//! This pass binds the most frequent ones to locals and rewrites every
//! occurrence to read the local instead -- a pure size win (one declaration,
//! then one or two characters per use once the name pass has shortened it) that
//! changes no arithmetic: the substituted text is the *same* Lua number, so
//! masks, folds and bounds checks stay bit-identical.
//!
//! The declarations are deliberately not placed in the chunk head. A shipped
//! script is `local <t>={} return setmetatable({<sections>},<t>):<m>(...)`, that
//! two-statement shape is attested by the tests, and a leading `local` line would
//! also collect every mask, radix and bound on one greppable line at the top of
//! the file. Instead the payload table is handed over by a function of the
//! script's own -- `setmetatable((function() local <pool> return {<sections>}
//! end)(),<t>)` -- so the pool sits inside the shell, one scope above every
//! section function, which reaches the constants as upvalues exactly as it would
//! if they had been chunk locals.
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
//! * The scope is the payload table's own byte range -- a balanced expression
//!   that contains every stage arm, field body and adapter -- and the
//!   declaration is spliced immediately in front of it, inside the wrapper. Each
//!   use is therefore bound where it can be seen, and nothing outside the table
//!   is touched. Candidate names are checked against every identifier in the
//!   script, so nothing is shadowed and no global read changes meaning. The slot
//!   count is capped, which keeps the wrapper's local total and every entry's
//!   upvalue total far below the Lua and Luau limits.
//!
//! The pass is a pure function of the emitted text: no RNG is consumed, so
//! output stays deterministic per (source, target, config, seed). A program
//! whose literals are already rare comes back unchanged, and so does any text
//! without a payload table to wrap -- this is an optimization, not a validator,
//! so an unrecognized shape costs bytes rather than failing the build.

use crate::{Diagnostic, Target};
use std::collections::BTreeMap;
use std::ops::Range;

/// Pooled spellings per host function. Enough to capture the plateau of the
/// measured benefit curve; deliberately small, because the host is already the
/// script's densest function and Lua counts both locals per function and the
/// upvalues each nested closure inherits from it.
pub(crate) const MAX_SLOTS: usize = 14;
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

/// Census over the positions this pass may bind inside `region`: [`census`]
/// minus table keys and minus everything outside the pooled scope. Selection and
/// the faithfulness check use these counts, so a literal that only occurs as a
/// key, or only outside the payload table, is never pooled at all -- a name
/// bound inside the wrapper cannot be read from the chunk head, and a literal
/// bound in one scope while still being spelled out in another buys nothing.
fn usable_counts(source: &str, region: &Range<usize>) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (start, end) in number_spans(source) {
        if start < region.start || end > region.end {
            continue;
        }
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
    plan_with_counts(source, &(0..source.len())).0
}

/// [`plan`] for one host scope, plus the census it was derived from, so the
/// caller can verify the rewrite without re-scanning for selection.
fn plan_with_counts(source: &str, region: &Range<usize>) -> (Vec<Entry>, BTreeMap<String, usize>) {
    let counts = usable_counts(source, region);
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
#[cfg(test)]
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
/// Pool the script's commonest literals inside the shell, not in front of it.
///
/// A generated script is `local <t>={} return setmetatable({<sections>},<t>):<m>(...)`.
/// The pool is *not* placed in the chunk head -- that would both change the
/// attested two-statement shape and hand whoever opens the file one line listing
/// every mask, radix and bound. Instead the payload table is produced by a
/// function of its own, `setmetatable((function() local <pool> return {<sections>}
/// end)(),<t>)`, so the declarations sit inside the shell and every section
/// function -- the entry, the decoders, the prelude toolbox -- closes over them
/// like any other upvalue. Text without a payload table to wrap comes back alone:
/// the pass is a size optimization, so a shape it does not recognise skips it
/// rather than failing a build.
pub(crate) fn pool(source: &str, target: Target) -> Result<String, Diagnostic> {
    let Some(table) = payload_table(source, target)? else {
        return Ok(source.to_string());
    };
    let (entries, counts) = plan_with_counts(source, &table);
    if entries.is_empty() {
        return Ok(source.to_string());
    }
    let declaration = declaration(&entries);
    if number_spans(&declaration).len() != entries.len() {
        return Err(Diagnostic::new(
            "numeric pooling declaration does not hold one literal per slot",
        ));
    }
    let (body, table) = pool_text(source, &entries, &counts, &table)?;
    let mut out = String::with_capacity(body.len() + declaration.len() + 24);
    out.push_str(&body[..table.start]);
    out.push_str("(function()");
    out.push_str(&declaration);
    out.push_str("return ");
    out.push_str(&body[table.start..table.end]);
    out.push_str(" end)()");
    out.push_str(&body[table.end..]);
    crate::lexer::lex(&out, target)?;
    Ok(out)
}

/// One `local` with a name list and a value list: `local a=1,b=2` is not legal
/// Lua, so names and literals are grouped rather than interleaved -- which is
/// also the cheapest spelling, one keyword for the whole pool.
fn declaration(entries: &[Entry]) -> String {
    let mut out = String::from("local ");
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str(&entry.name);
    }
    out.push('=');
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        out.push_str(&entry.text);
    }
    out.push(';');
    out
}

/// [`pool`] applied to a snippet whose whole text is the scope being pooled, so
/// the selection and rewrite rules can be tested without a generated script.
#[cfg(test)]
pub(crate) fn pool_at(
    source: &str,
    target: Target,
    region: &Range<usize>,
) -> Result<String, Diagnostic> {
    let (entries, counts) = plan_with_counts(source, region);
    if entries.is_empty() {
        return Ok(source.to_string());
    }
    let declaration = declaration(&entries);
    let (body, _) = pool_text(source, &entries, &counts, region)?;
    let mut out = String::with_capacity(body.len() + declaration.len());
    out.push_str(&body[..region.start]);
    out.push_str(&declaration);
    out.push_str(&body[region.start..]);
    crate::lexer::lex(&out, target)?;
    Ok(out)
}

/// The rewritten region's own extent in that text is returned with it: every
/// byte of the substitution is inside the region, so the region's end moves by
/// exactly the amount the script shrank (or grew), and callers must not index
/// the new text with an offset taken from the old one.

/// Rewrite the literals of `region` into the pooled names, returning the whole
/// script with that region replaced (no declaration yet -- each caller splices
/// its own), and verify afterwards that the substitution closed.
///
/// The check is global arithmetic, which needs no offset bookkeeping: one
/// literal is removed per replacement and one added per slot by the caller, and
/// a name can neither start nor continue a digit run (`ZQ0`'s trailing zero
/// belongs to the identifier, which the scanner treats as glued), so no
/// occurrence can be lost or invented. Each bound name must then appear exactly
/// as often as the literals it replaced -- a use that fell outside the region
/// would read a sibling scope's same-named local, or `nil`, and that is the
/// failure worth refusing output over.
fn pool_text(
    source: &str,
    entries: &[Entry],
    counts: &BTreeMap<String, usize>,
    region: &Range<usize>,
) -> Result<(String, Range<usize>), Diagnostic> {
    let spans = number_spans(source);
    let in_region = |start: &usize, end: &usize| *start >= region.start && *end <= region.end;
    let lookup: BTreeMap<&str, &str> = entries
        .iter()
        .map(|e| (e.text.as_str(), e.name.as_str()))
        .collect();
    let mut replaced = 0usize;
    let mut out = String::with_capacity(source.len());
    out.push_str(&source[..region.start]);
    let mut last = region.start;
    for (start, end) in spans.iter().filter(|(s, e)| in_region(s, e)) {
        if is_key_position(source, *start, *end) {
            continue;
        }
        let Some(name) = lookup.get(&source[*start..*end]) else {
            continue;
        };
        replaced += 1;
        out.push_str(&source[last..*start]);
        out.push_str(name);
        last = *end;
    }
    out.push_str(&source[last..]);
    let mapped = region.start..region.end - (source.len() - out.len());
    let expected = spans.len() - replaced;
    let remaining = number_spans(&out).len();
    if remaining != expected {
        let region_spans = spans.iter().filter(|(s, e)| in_region(s, e)).count();
        return Err(Diagnostic::new(format!(
            "numeric pooling left {remaining} decimal literals in the script, expected {expected} ({region_spans} in the host scope, {replaced} replaced)"
        )));
    }
    for entry in entries {
        let uses = *counts
            .get(&entry.text)
            .ok_or_else(|| Diagnostic::new("numeric pooling lost a census entry"))?;
        let seen = identifier_uses(&out, &entry.name);
        if seen != uses {
            return Err(Diagnostic::new(format!(
                "numeric pooling bound {} to {} uses, expected {}",
                entry.name, seen, uses
            )));
        }
    }
    Ok((out, mapped))
}

/// The payload table of a generated script: the byte range of the first balanced
/// `{...}` expression after the chunk's `return setmetatable(`. Everything the VM
/// executes sits inside that constructor, so pooling there reaches the entry
/// function, the section decoders and the prelude toolbox at once while the
/// chunk keeps its two statements. All the caller needs for soundness is that
/// the range is a balanced expression: the declaration lands immediately before
/// it, so every use inside can see the name and nothing outside is touched.
/// Strings, comments and long brackets are single tokens, so no brace inside the
/// image blob can throw the walk off.
fn payload_table(source: &str, target: Target) -> Result<Option<Range<usize>>, Diagnostic> {
    let tokens = crate::lexer::lex(source, target)?;
    for index in 0..tokens.len() {
        let is_return = tokens[index].kind == crate::lexer::TokenKind::Keyword
            && tokens[index].text(source) == "return";
        let callee = tokens
            .get(index + 1)
            .is_some_and(|token| token.text(source) == "setmetatable");
        if !is_return
            || !callee
            || tokens
                .get(index + 2)
                .map_or(true, |t| t.text(source) != "(")
        {
            continue;
        }
        let Some(open) = (index + 3..tokens.len()).find(|&i| tokens[i].text(source) == "{") else {
            return Ok(None);
        };
        let mut depth = 0usize;
        for walk in open..tokens.len() {
            match tokens[walk].text(source) {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(Some(tokens[open].span.start..tokens[walk].span.end));
                    }
                }
                _ => {}
            }
        }
        return Ok(None);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pool a snippet as if the whole snippet were one host scope. `pool`
    /// itself first has to find a host inside a generated script, and that part
    /// has its own test; these are about the selection and rewrite rules.
    fn pooled(source: impl AsRef<str>) -> String {
        let source = source.as_ref();
        pool_at(source, Target::Lua51, &(0..source.len())).unwrap()
    }

    #[test]
    fn pools_repeated_decimal_literals_once_each() {
        let source = "local m=256;local a=x%256;local b=y%256;local c=z%256;local d=w%256;local e=v%256;local f=w%256;local g=v%256;local h=x%256;local i=y%256;local j=z%256;local k=w%256;";
        let counts = census(source);
        assert_eq!(counts.get("256"), Some(&12));
        let out = pooled(&source);
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
        let two = pooled(&two);
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
        let out = pooled(&source);
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
        assert_eq!(pooled(&source), source);
    }

    #[test]
    fn leaves_strings_comments_and_glued_numbers_alone() {
        let source = "local s=\"x%256y\"; -- 256\nlocal a=[[256]];\nlocal b=1e5;local c=0x10;local d=256.;local e=256;local f=256;local g=256;local h=256;local i=256;local j=256;";
        let counts = census(source);
        assert_eq!(counts.get("256"), Some(&6), "{counts:?}");
        assert!(!counts.contains_key("1e5") && !counts.contains_key("10"));
        let out = pooled(&source);
        assert!(out.contains("\"x%256y\""), "{out}");
        assert!(out.contains("-- 256"), "{out}");
        assert!(out.contains("[[256]]"), "{out}");
        assert!(out.contains("1e5") && out.contains("0x10") && out.contains("256."));
    }

    #[test]
    fn rare_or_short_literals_are_not_pooled() {
        let source = "local a=256;local b=7;local c=99999999;";
        assert!(pooled(&source) == source);
    }

    #[test]
    fn the_pool_is_output_by_a_function_inside_the_shell() {
        // A generated script is `local u={} return setmetatable({...},u):m()`.
        // The payload table is handed over by a function of its own, so the
        // pool is inside the shell (the chunk keeps its two statements) and
        // every section entry reads the same locals through its closure.
        let host = "local g={};g[1]=65536;g[2]=65536;g[3]=65536;g[4]=65536;g[5]=65536;g[6]=65536;g[7]=65536;g[8]=65536;";
        let sibling = "local e={};e[1]=65536;e[2]=65536;e[3]=65536;return e ";
        let source = format!(
            "local u={{}}return setmetatable({{[1]=function(a,b){host}end,[2]=function(c){sibling}end}},u):k()"
        );
        let out = pool(&source, Target::Lua51).unwrap();
        assert!(
            out.starts_with(
                "local u={}return setmetatable((function()local ZQ0=65536;return {[1]=function(a,b)local g={};g[1]=ZQ0;"
            ),
            "{out}"
        );
        assert!(
            out.ends_with("e[3]=ZQ0;return e end} end)(),u):k()"),
            "{out}"
        );
        crate::parser::parse_source(&out, Target::Lua51).unwrap();
    }

    #[test]
    fn text_without_a_payload_table_is_left_alone() {
        for source in [
            "return 1+256 ",
            "local a=256 print(a)",
            "local u={} return setmetatable(u.x,u):k()",
        ] {
            assert_eq!(pool(source, Target::Lua51).unwrap(), source, "{source}");
        }
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
