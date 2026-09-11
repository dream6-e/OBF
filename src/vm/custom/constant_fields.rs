//! K16: the script's repeated round constants live in a table.
//!
//! The emitted VM spells the same moduli out over and over: in the emitted Lua 5.1
//! script `65536` is written out 97 times, `4294967296` 20 times and `65521` 19,
//! because every mask, radix, shift and range check repeats the constant. This pass
//! stores each
//! chosen constant once, as a field of the wrapper table the script already
//! creates, and rewrites the repetitions to read it back:
//!
//! ```text
//! local f={} return setmetatable({p=function(k,...) f.q=256 print(f.q) end},f):p()
//! ```
//!
//! The wrapper table is the one handle every part of the script can reach: it is
//! a chunk-level local, so the entry function, all the sibling section fields and
//! the prelude toolbox read it as an upvalue -- unlike the payload table, which
//! only the entry receives (as `self`), because every other field is called with
//! an explicit argument list. That is why the values go there and why the single
//! write lives inside the entry body: the emitted chunk keeps its shape exactly
//! (`local <f>={} return setmetatable({<fields>},<f>):<m>(...)`, still two
//! statements, still one physical line, no extra chunk-level local in front of
//! the shell), and the constructor's own field layout -- the numeric keys the
//! seed shuffles, the one string key, the `X[N]=N` decoys -- is untouched.
//!
//! Four checks make the rewrite mean what it says:
//!
//! * **The script is the emitted shell or nothing happens.** Two statements, the
//!   first an empty wrapper table, the second `return setmetatable(<payload>,
//!   <wrapper>):<entry>(...)`, and `<entry>` must be the one field whose value is
//!   a function of a single parameter plus `...`. Anything that merely resembles
//!   that shape -- a user program with its own `setmetatable` call -- is left
//!   completely alone rather than guessed at.
//! * **A read is only inserted where the write has already run.** Rewriting is
//!   confined to the bodies of the payload table's function fields: the table
//!   constructor itself and the arguments of the call that builds it evaluate
//!   *before* the entry runs, so a field read there would be `nil`.
//! * **Nothing shadows the wrapper name.** Every binder of that name is found from
//!   the AST -- parameters, `local` lists, `for` variables, function names -- and
//!   each one governs the rest of the block that declares it, so exactly those
//!   ranges are excluded. (The later name pass is what keeps this safe in the
//!   shipped file too: it refuses same-name allocations that would intercept an
//!   outer reference, which is precisely the pattern these new reads create.)
//! * **Only standalone decimal integers are touched.** The scanner walks the
//!   source the way the Lua lexer does -- skipping long-bracket and quoted
//!   strings with escapes and both comment forms -- so the embedded image blob
//!   and any digit run inside text are invisible to it; a number adjacent to
//!   `.`/`e`/`x`/a letter is left alone (`1e5`, `0x10`, `256.`, `1..2` keep their
//!   meaning), a spelling must round-trip through `u64` without a leading zero
//!   (Lua 5.1 reads `0256` as octal 174, so rewriting it would change its value),
//!   and table-key positions are never rewritten.
//!
//! Field names are taken from outside the script's identifier set and outside
//! every key the wrapper is already indexed with, so nothing existing is
//! overwritten and the census below is exact. The script already uses nearly every
//! single letter as a name, so only the first few fields get a one-character key
//! and the rest get two -- and the price is charged per key, which is what keeps a
//! four-character spelling like `2000` (17 uses) out of the table while a
//! ten-character one gets in. On the two goldens the pass ends up with five fields
//! (Lua 5.1) and four (Luau), worth 353 and 269 bytes.
//! Reach is the other half of the story: a use only counts where the wrapper is
//! actually visible, and 27 of the 29 spellings of `2147483647` are not -- their
//! scope re-binds the wrapper name, or they sit in the constructor that builds the
//! shell. That constant therefore stays spelled out, while `65536`, with two such
//! places, is lifted 97 times. The pass is a pure function of the
//! emitted text: it consumes no RNG, so output stays deterministic per
//! (source, target, config, seed), and a program whose literals are already rare
//! simply comes back unchanged.

use crate::ast::{Block, Expression, ExpressionKind, FunctionBody, StatementKind, TableField};
use crate::lexer::is_keyword;
use crate::{Diagnostic, Target};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

/// At most this many constants move into the table. The measured benefit curve
/// plateaus well before this, and a bounded count keeps the entry's statement and
/// the wrapper's field set small.
const MAX_FIELDS: usize = 14;
/// A spelling must be this long before a field read pays for itself at all
/// (single-digit literals are already one byte).
const MIN_CHARS: usize = 2;
/// A spelling must appear this often before it is worth a field. The curve is flat
/// here: at 4 the goldens come out the same size on Lua 5.1 and 6 bytes smaller on
/// Luau, at 3 both grow again. Six is kept because every field is one more wrapper
/// key an analyst can enumerate and one more write to sit in the entry, which is
/// not worth six bytes.
const MIN_USES: usize = 6;
/// One lifted constant: the decimal text it replaces and the field it moves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) text: String,
    pub(crate) key: String,
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

/// Where the values go: the wrapper table's name, the offset its single write is
/// inserted at (the top of the entry function's body -- the first code the script
/// runs), the function bodies that may be rewritten, the ranges where some other
/// binding has claimed the wrapper name, and the names no field may take.
struct Host {
    wrapper: String,
    insert: usize,
    /// Bodies of the payload table's function fields: the only code that runs
    /// after the write above.
    regions: Vec<Range<usize>>,
    shadowed: Vec<Range<usize>>,
    taken: BTreeSet<String>,
}

/// An offset may be rewritten when it sits in a body that runs after the write
/// and is not captured by a nearer binding of the wrapper name.
fn eligible(host: &Host, offset: usize) -> bool {
    host.regions.iter().any(|range| range.contains(&offset))
        && !host.shadowed.iter().any(|range| range.contains(&offset))
}

/// Census over the literals this pass may lift: standalone canonical decimals
/// that are not table keys and do not sit inside a shadowed scope. Selection and
/// the faithfulness check both use these counts, so a spelling is never traded
/// for a read that cannot see the field.
pub(crate) fn usable_counts(
    source: &str,
    allow: &dyn Fn(usize) -> bool,
) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (start, end) in number_spans(source) {
        if !allow(start) {
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

/// Net bytes a spelling saves, priced as the text actually costs: every use trades
/// its literal for a `<wrapper>.<key>` read of `read` bytes, and the entry's share
/// of the single write statement is `<wrapper>.<key>=<literal>,`, i.e. `read`
/// again plus the value and a separator -- hence the fixed `read + len + 2`.
fn cost(text: &str, uses: usize, read: usize) -> i64 {
    let len = text.len() as i64;
    (uses as i64) * (len - read as i64) - (read as i64 + len + 2)
}

/// Bytes one `<wrapper>.<key>` read costs.
fn read_of(wrapper_len: usize, key_len: usize) -> usize {
    wrapper_len + 1 + key_len
}

#[cfg(test)]
fn gain(text: &str, uses: usize, wrapper_len: usize, key_len: usize) -> i64 {
    cost(text, uses, read_of(wrapper_len, key_len))
}

/// The field names this pass may still hand out, in the order it hands them out:
/// one character at a time -- because every read and the write itself pay for the
/// key -- then two. A name must not be an identifier the script already uses (that
/// keeps the census checks exact) and must not be a keyword.
fn free_names(taken: &BTreeSet<String>, target: Target, want: usize) -> Vec<String> {
    let mut names = Vec::with_capacity(want);
    for candidate in
        (b'a'..=b'z')
            .map(|byte| (byte as char).to_string())
            .chain((b'a'..=b'z').flat_map(|first| {
                (b'a'..=b'z').map(move |second| format!("{}{}", first as char, second as char))
            }))
    {
        if names.len() == want {
            break;
        }
        if !taken.contains(&candidate) && !is_keyword(&candidate, target) {
            names.push(candidate);
        }
    }
    names
}

fn plan(
    counts: &BTreeMap<String, usize>,
    taken: &mut BTreeSet<String>,
    target: Target,
    wrapper_len: usize,
) -> Vec<Entry> {
    let one = read_of(wrapper_len, 1);
    let mut scored: Vec<(i64, usize, String)> = counts
        .iter()
        .filter_map(|(text, uses)| {
            (*uses >= MIN_USES && cost(text, *uses, one) > 0).then_some((
                cost(text, *uses, one),
                *uses,
                text.clone(),
            ))
        })
        .collect();
    // 收益高的先入表；同分按使用数、再按拼写定序，与哈希迭代顺序无关。
    scored.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then(right.1.cmp(&left.1))
            .then(left.2.cmp(&right.2))
    });
    let names = free_names(taken, target, MAX_FIELDS);
    let mut entries = Vec::new();
    for (_, uses, text) in scored {
        let Some(key) = names.get(entries.len()) else {
            break;
        };
        // 名字发到双字母后，读写各贵一字节：按实际键长再算一次，付不起的就留着
        // 原样拼写，而且它不占名字——后面的候选不受牵连。
        if cost(&text, uses, read_of(wrapper_len, key.len())) <= 0 {
            continue;
        }
        entries.push(Entry {
            text,
            key: key.clone(),
        });
    }
    for entry in &entries {
        taken.insert(entry.key.clone());
    }
    entries
}

/// Locate the shell this pass understands and everything it needs from it. The
/// shape is the emitted chunk exactly: two statements -- an empty wrapper table,
/// then `return setmetatable(<payload table>, <wrapper>):<entry>(...)` -- where
/// `<entry>` is the one field whose value is a function of a single parameter
/// plus `...`. Nothing else is accepted, because the pass is only sound when the
/// write it inserts is the first code that runs: a program that merely happens to
/// contain a `setmetatable` call could otherwise read back fields that were never
/// assigned. An unrecognised script lifts nothing.
fn host(source: &str, target: Target) -> Result<Option<Host>, Diagnostic> {
    let chunk = crate::parser::parse_source(source, target)?;
    let [head, tail] = chunk.block.statements.as_slice() else {
        return Ok(None);
    };
    let StatementKind::Local {
        bindings, values, ..
    } = &head.kind
    else {
        return Ok(None);
    };
    if bindings.len() != 1 || values.len() != 1 {
        return Ok(None);
    }
    if !matches!(&values[0].kind, ExpressionKind::Table(fields) if fields.is_empty()) {
        return Ok(None);
    }
    let wrapper = bindings[0].name.value.clone();
    let StatementKind::Return(returned) = &tail.kind else {
        return Ok(None);
    };
    let [outer] = returned.as_slice() else {
        return Ok(None);
    };
    let ExpressionKind::Call {
        function: shell,
        method: Some(method),
        type_arguments: method_types,
        ..
    } = &outer.kind
    else {
        return Ok(None);
    };
    let ExpressionKind::Call {
        function: callee,
        method: None,
        type_arguments,
        arguments,
    } = &shell.kind
    else {
        return Ok(None);
    };
    if !method_types.is_empty()
        || !type_arguments.is_empty()
        || arguments.len() != 2
        || !matches!(&callee.kind, ExpressionKind::Name(name) if name.value == "setmetatable")
        || !matches!(&arguments[1].kind, ExpressionKind::Name(name) if name.value == wrapper)
    {
        return Ok(None);
    }
    let ExpressionKind::Table(fields) = &arguments[0].kind else {
        return Ok(None);
    };
    // 只有函数值字段可以承载读取：构造式自身（含 `:m(args)` 的实参）在入口之前
    // 求值，那里的字面量改成读字段就会读到 nil。方法名必须正好是入口字段的键。
    let mut regions: Vec<Range<usize>> = Vec::new();
    let mut insert = None;
    let mut candidates = 0usize;
    for field in fields {
        let (key, value) = match field {
            TableField::Record { name, value, .. } => (Some(name.value.clone()), value),
            TableField::Computed { key, value, .. } => (string_key(key), value),
            TableField::List(value) => (None, value),
        };
        let ExpressionKind::Function(body) = &value.kind else {
            continue;
        };
        regions.push(body.body.span.start..body.body.span.end);
        if body.parameters.len() == 1
            && body.has_vararg
            && key.as_deref() == Some(method.value.as_str())
        {
            candidates += 1;
            insert = Some(body.body.span.start);
        }
    }
    let Some(insert) = insert else {
        return Ok(None);
    };
    if candidates != 1 {
        return Ok(None);
    }

    // 字段名要躲开脚本里出现过的每个标识符（表键、形参、方法名都算），以及包装表
    // 已经在用的字段名，否则既是悄悄覆盖，也让下面的计数自检失去意义。
    let mut taken = identifiers(source);
    let mut offset = 0usize;
    while let Some(found) = source[offset..].find(&wrapper).map(|at| offset + at) {
        offset = found + wrapper.len();
        let head = source[..found].as_bytes();
        if found != 0 && head[head.len() - 1].is_ascii_alphanumeric() {
            continue;
        }
        let Some(rest) = source.get(offset..) else {
            continue;
        };
        let Some(dot) = rest.find(|char: char| char != ' ' && char != '\t') else {
            continue;
        };
        if !rest[dot..].starts_with('.') {
            continue;
        }
        let start = dot + 1;
        let mut walk = start;
        while rest[walk..]
            .chars()
            .next()
            .is_some_and(|char| char.is_ascii_alphabetic() || char == '_')
        {
            walk += 1;
        }
        if walk > start {
            taken.insert(rest[start..walk].to_string());
        }
    }

    // 遮蔽了包装名的作用域保持原拼写：那里的 `<w>.q` 会读到别的表。
    let mut shadowed: Vec<Range<usize>> = Vec::new();
    shadow_ranges(
        &chunk.block,
        &wrapper,
        bindings[0].name.span.start,
        &mut shadowed,
    );
    let host = Host {
        wrapper,
        insert,
        regions,
        shadowed,
        taken,
    };
    if !eligible(&host, insert) {
        return Ok(None);
    }
    Ok(Some(host))
}

/// The name a table key denotes when it is written as a plain quoted string
/// (`["p"]`); `p=function` is handled as a `Record`. Anything else -- a computed
/// numeric key, an escaped or long-bracket string -- is not a name this pass can
/// tie to the method the chunk calls, so the script is left alone.
fn string_key(key: &Expression) -> Option<String> {
    let ExpressionKind::String(text) = &key.kind else {
        return None;
    };
    let bytes = text.as_bytes();
    if bytes.len() < 2 || bytes.first() != bytes.last() || !matches!(bytes[0], b'"' | b'\'') {
        return None;
    }
    let inner = &text[1..text.len() - 1];
    (!inner.contains('\\')).then(|| inner.to_owned())
}

/// Ranges where some *other* binding claims `name`, so a read of it there would
/// not reach the chunk-level table. Lua scoping makes these extents exact rather
/// than guessed: a `local` governs the rest of its own block, a `for` variable
/// and a parameter govern their body, and `skip` (the declaration the pass is
/// building on) is not a shadow of itself.
fn shadow_ranges(block: &Block, name: &str, skip: usize, out: &mut Vec<Range<usize>>) {
    let tail = block.span.end;
    for statement in &block.statements {
        match &statement.kind {
            StatementKind::Local {
                bindings, values, ..
            } => {
                for binding in bindings {
                    hide(
                        binding.name.span.start,
                        &binding.name.value,
                        name,
                        skip,
                        tail,
                        out,
                    );
                }
                for value in values {
                    scan_expression(value, name, skip, out);
                }
            }
            StatementKind::LocalFunction {
                name: binding,
                body,
                ..
            } => {
                hide(binding.span.start, &binding.value, name, skip, tail, out);
                scan_function(body, name, skip, out);
            }
            StatementKind::Function { body, .. } => scan_function(body, name, skip, out),
            StatementKind::Do(inner) => shadow_ranges(inner, name, skip, out),
            StatementKind::While { condition, body } => {
                scan_expression(condition, name, skip, out);
                shadow_ranges(body, name, skip, out);
            }
            StatementKind::Repeat { body, condition } => {
                shadow_ranges(body, name, skip, out);
                scan_expression(condition, name, skip, out);
            }
            StatementKind::If {
                branches,
                else_block,
            } => {
                for branch in branches {
                    scan_expression(&branch.condition, name, skip, out);
                    shadow_ranges(&branch.body, name, skip, out);
                }
                if let Some(inner) = else_block {
                    shadow_ranges(inner, name, skip, out);
                }
            }
            StatementKind::NumericFor {
                binding,
                initial,
                limit,
                step,
                body,
            } => {
                hide(
                    binding.name.span.start,
                    &binding.name.value,
                    name,
                    skip,
                    body.span.end,
                    out,
                );
                scan_expression(initial, name, skip, out);
                scan_expression(limit, name, skip, out);
                if let Some(step) = step {
                    scan_expression(step, name, skip, out);
                }
                shadow_ranges(body, name, skip, out);
            }
            StatementKind::GenericFor {
                bindings,
                values,
                body,
            } => {
                for binding in bindings {
                    hide(
                        binding.name.span.start,
                        &binding.name.value,
                        name,
                        skip,
                        body.span.end,
                        out,
                    );
                }
                for value in values {
                    scan_expression(value, name, skip, out);
                }
                shadow_ranges(body, name, skip, out);
            }
            StatementKind::Assignment { targets, values } => {
                for target in targets {
                    scan_expression(target, name, skip, out);
                }
                for value in values {
                    scan_expression(value, name, skip, out);
                }
            }
            StatementKind::CompoundAssignment { target, value, .. } => {
                scan_expression(target, name, skip, out);
                scan_expression(value, name, skip, out);
            }
            StatementKind::Call(callee) => scan_expression(callee, name, skip, out),
            StatementKind::Return(values) => {
                for value in values {
                    scan_expression(value, name, skip, out);
                }
            }
            // 类型层的名字不占用值命名空间，也没有运行时代码。
            StatementKind::Empty
            | StatementKind::Break
            | StatementKind::Continue
            | StatementKind::TypeAlias { .. }
            | StatementKind::TypeFunction { .. } => {}
        }
    }
}

fn hide(
    start: usize,
    found: &str,
    name: &str,
    skip: usize,
    tail: usize,
    out: &mut Vec<Range<usize>>,
) {
    if found == name && start != skip && !out.iter().any(|range| range.start == start) {
        out.push(start..tail);
    }
}

fn scan_function(body: &FunctionBody, name: &str, skip: usize, out: &mut Vec<Range<usize>>) {
    for parameter in &body.parameters {
        hide(
            parameter.name.span.start,
            &parameter.name.value,
            name,
            skip,
            body.body.span.end,
            out,
        );
    }
    shadow_ranges(&body.body, name, skip, out);
}

fn scan_expression(expression: &Expression, name: &str, skip: usize, out: &mut Vec<Range<usize>>) {
    match &expression.kind {
        ExpressionKind::Function(body) => scan_function(body, name, skip, out),
        ExpressionKind::Table(fields) => {
            for field in fields {
                match field {
                    TableField::List(value) | TableField::Computed { value, .. } => {
                        scan_expression(value, name, skip, out)
                    }
                    TableField::Record { value, .. } => scan_expression(value, name, skip, out),
                }
            }
        }
        ExpressionKind::IfExpression {
            branches,
            else_expression,
        } => {
            for branch in branches {
                scan_expression(&branch.condition, name, skip, out);
                scan_expression(&branch.value, name, skip, out);
            }
            scan_expression(else_expression, name, skip, out);
        }
        ExpressionKind::Unary { expression, .. } => scan_expression(expression, name, skip, out),
        ExpressionKind::Binary { left, right, .. } => {
            scan_expression(left, name, skip, out);
            scan_expression(right, name, skip, out);
        }
        ExpressionKind::TypeAssertion { expression, .. }
        | ExpressionKind::TypeInstantiation { expression, .. } => {
            scan_expression(expression, name, skip, out)
        }
        ExpressionKind::Group(inner) => scan_expression(inner, name, skip, out),
        ExpressionKind::Field { table, .. } => scan_expression(table, name, skip, out),
        ExpressionKind::Index { table, index } => {
            scan_expression(table, name, skip, out);
            scan_expression(index, name, skip, out);
        }
        ExpressionKind::Call {
            function,
            arguments,
            ..
        } => {
            scan_expression(function, name, skip, out);
            for argument in arguments {
                scan_expression(argument, name, skip, out);
            }
        }
        ExpressionKind::InterpolatedString { expressions, .. } => {
            for nested in expressions {
                scan_expression(nested, name, skip, out);
            }
        }
        ExpressionKind::Nil
        | ExpressionKind::Boolean(_)
        | ExpressionKind::Number(_)
        | ExpressionKind::String(_)
        | ExpressionKind::Vararg
        | ExpressionKind::Name(_) => {}
    }
}

/// Store the chosen constants on the wrapper table and read them everywhere the
/// wrapper is visible.
pub(crate) fn lift(source: &str, target: Target) -> Result<String, Diagnostic> {
    let Some(host) = host(source, target)? else {
        return Ok(source.to_string());
    };
    let counts = usable_counts(source, &|offset| eligible(&host, offset));
    let mut taken = host.taken.clone();
    taken.insert(host.wrapper.clone());
    let entries = plan(&counts, &mut taken, target, host.wrapper.len());
    if entries.is_empty() {
        return Ok(source.to_string());
    }
    let lookup: BTreeMap<&str, &str> = entries
        .iter()
        .map(|entry| (entry.text.as_str(), entry.key.as_str()))
        .collect();
    // 一次收集所有编辑：每个被改写的字面量替换成 `<wrapper>.<key>`，另外在入口
    // 体首插一条多字段赋值。编辑按源文本顺序拼装，插入点与改写点谁先谁后都不影响。
    let mut write = String::new();
    for (index, entry) in entries.iter().enumerate() {
        write.push_str(if index == 0 { "" } else { "," });
        write.push_str(&host.wrapper);
        write.push('.');
        write.push_str(&entry.key);
    }
    write.push('=');
    for (index, entry) in entries.iter().enumerate() {
        write.push_str(if index == 0 { "" } else { "," });
        write.push_str(&entry.text);
    }
    write.push(';');

    let mut edits: Vec<(usize, usize, String)> = vec![(host.insert, host.insert, write.clone())];
    let spans = number_spans(source);
    for (start, end) in spans
        .iter()
        .filter(|(start, end)| eligible(&host, *start) && !is_key_position(source, *start, *end))
    {
        if let Some(key) = lookup.get(&source[*start..*end]) {
            edits.push((*start, *end, format!("{}.{}", host.wrapper, key)));
        }
    }
    let replaced = edits.len() - 1;
    edits.sort_by_key(|(start, _, _)| *start);
    let mut out = String::with_capacity(source.len() + 32 + entries.len() * 16);
    let mut last = 0usize;
    for (start, end, text) in &edits {
        out.push_str(&source[last..*start]);
        out.push_str(text);
        last = *end;
    }
    out.push_str(&source[last..]);
    if out.matches(&write).count() != 1 {
        return Err(Diagnostic::new(
            "numeric constants assignment did not land once in the entry body",
        ));
    }

    // Faithfulness, by arithmetic rather than hope: the script must have lost one
    // literal per rewrite and gained one per field; the wrapper must be named one
    // extra time per read and per written field; and every key must appear once
    // for each read plus its own assignment. A name never starts or continues a
    // digit run, so the substitution can neither lose nor invent an occurrence.
    let expected = spans.len() - replaced + entries.len();
    let remaining = number_spans(&out).len();
    if remaining != expected {
        return Err(Diagnostic::new(format!(
            "numeric constants left {remaining} decimal literals in the script, expected {expected} ({replaced} rewritten into {} fields)",
            entries.len()
        )));
    }
    let seen = identifier_uses(&out, &host.wrapper);
    let wanted = identifier_uses(source, &host.wrapper) + replaced + entries.len();
    if seen != wanted {
        return Err(Diagnostic::new(format!(
            "numeric constants bound {seen} reads of the wrapper, expected {wanted}"
        )));
    }
    for entry in &entries {
        let uses = *counts
            .get(&entry.text)
            .ok_or_else(|| Diagnostic::new("numeric constants lost a census entry"))?;
        let seen = identifier_uses(&out, &entry.key);
        if seen != uses + 1 {
            return Err(Diagnostic::new(format!(
                "numeric constants field {} was read {seen} times, expected {}",
                entry.key,
                uses + 1
            )));
        }
    }
    crate::lexer::lex(&out, target)?;
    crate::parser::parse_source(&out, target)?;
    Ok(out)
}

#[cfg(test)]
pub(crate) fn census(source: &str) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (start, end) in number_spans(source) {
        let Some(text) = canonical(source, start, end) else {
            continue;
        };
        *counts.entry(text.to_owned()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry field: the one function of a single parameter plus `...` whose
    /// key is the method the chunk calls.
    fn entry_field(statements: &str) -> String {
        format!("[\"p\"]=function(k,...) {statements} end,")
    }

    /// A script in exactly the shape the pass accepts: an empty wrapper table,
    /// then the `setmetatable` shell. `fields` are the payload table's fields.
    fn shell(fields: &str) -> String {
        format!("local w={{}} return setmetatable({{{fields}}},w):p(1)")
    }

    fn six(text: &str) -> String {
        vec![text; 6].join(",")
    }

    /// 十个 `65536`：入口体八处、兄弟字段两处，都改写；只剩写入处保留字面量。
    fn ten() -> String {
        format!(
            "local s=0 for i=1,65536 do s=s+65536%7 end return s,{}",
            six("65536")
        )
    }

    /// The key of the first `<wrapper>.<key>=<value>` write in `out`.
    fn written_key(out: &str, wrapper: &str) -> String {
        let marker = format!("{wrapper}.");
        let mut offset = 0usize;
        while let Some(found) = out[offset..].find(&marker).map(|at| offset + at) {
            offset = found + marker.len();
            let mut walk = offset;
            while out[walk..]
                .chars()
                .next()
                .is_some_and(|char| char.is_ascii_alphabetic() || char == '_')
            {
                walk += 1;
            }
            if out[walk..].trim_start().starts_with('=') {
                return out[offset..walk].to_string();
            }
        }
        panic!("输出里没有写入语句");
    }

    fn parses(source: &str) {
        crate::parser::parse_source(source, Target::Lua51).unwrap();
    }

    /// 与 [`shell`] 同构，但按给定 target 校验。
    fn shell_on(fields: &str, target: Target) -> String {
        let source = shell(fields);
        crate::parser::parse_source(&source, target).unwrap();
        source
    }

    #[test]
    fn a_repeated_round_constant_becomes_a_wrapper_field_read_everywhere() {
        let source = shell(&format!(
            "[1]=function(a,b) return 65536+65536 end,{}",
            entry_field(&ten())
        ));
        parses(&source);
        let out = lift(&source, Target::Lua51).unwrap();
        let key = written_key(&out, "w");
        assert_eq!(out.matches("65536").count(), 1);
        assert_eq!(out.matches(&format!("w.{key}")).count(), 11);
        // 写入是入口体的第一条语句；兄弟字段照样读得到（包装表是它的上值）。
        assert!(out.contains(&format!("(k,...) w.{key}=65536;local s=0")));
        assert!(out.contains(&format!("return w.{key}+w.{key}")));
        // 脚本格式一字未动：还是那两条语句、还是空包装表、还是一行。
        assert!(out.starts_with("local w={} return setmetatable({"));
        assert!(!out.contains('\n'));
        parses(&out);
        assert_eq!(
            crate::parser::parse_source(&out, Target::Lua51)
                .unwrap()
                .block
                .statements
                .len(),
            2
        );
        // 再跑一遍无事可做：写入里那个字面量只出现一次，不值得第二个字段。
        assert_eq!(lift(&out, Target::Lua51).unwrap(), out);
    }

    #[test]
    fn a_closer_binding_of_the_wrapper_name_keeps_its_literals() {
        // 这个兄弟字段的形参就叫 `w`：它体内的读数会落到形参上，整段不参与改写，
        // 剩下入口里的六处仍在门槛之上，照样成立。
        let source = shell(&format!(
            "[1]=function(w) return w,{} end,{}",
            six("65536"),
            entry_field(&format!("return {}", six("65536")))
        ));
        parses(&source);
        let out = lift(&source, Target::Lua51).unwrap();
        assert_eq!(written_key(&out, "w").len(), 1);
        // 六处留在被遮蔽的体内，一处是写入本身。
        assert_eq!(out.matches("65536").count(), 7);
        assert_eq!(out.matches("w.").count(), 7);
        parses(&out);
    }

    #[test]
    fn a_number_outside_any_field_body_is_not_liftable() {
        // 构造式自身在入口之前求值，那里的字面量改成读字段就会读到 nil。
        let source = shell(&format!("{},{}", six("65536"), entry_field("return 1")));
        parses(&source);
        assert_eq!(lift(&source, Target::Lua51).unwrap(), source);
    }

    #[test]
    fn a_table_key_is_never_rewritten() {
        // `[65536]=1` 是键；入口里的六处才是可改写的读取。
        let source = shell(&format!(
            "[1]=function(t) return t end,{}",
            entry_field(&format!("local t={{[65536]=1}} return {}", six("65536")))
        ));
        parses(&source);
        let out = lift(&source, Target::Lua51).unwrap();
        assert_eq!(out.matches("65536").count(), 2);
        assert_eq!(out.matches("w.").count(), 7);
        assert!(out.contains("[65536]=1"));
        parses(&out);
    }

    #[test]
    fn only_canonical_decimal_spellings_are_bound() {
        // 每个拼写都出现六次，够门槛：没被绑定，只能是因为它不是规范十进制。
        // 前导零在 5.1 里是八进制，`0x`/`1e5`/`65536.0` 各自是另一种值或浮点。
        for (text, target) in [
            ("065536", Target::Lua51),
            ("0x10000", Target::Lua51),
            ("1e5", Target::Lua51),
            ("65536.0", Target::Lua51),
            // 5.1 读不懂数字下划线，这是 Luau 的写法：同样不做候选。
            ("6_5_5_3_6", Target::Luau),
        ] {
            let source = shell_on(&entry_field(&format!("return {}", six(text))), target);
            assert_eq!(lift(&source, target).unwrap(), source, "{text}");
        }
    }

    #[test]
    fn a_spelling_too_short_or_too_rare_to_pay_is_left_spelled() {
        // `256` 与 `w.k` 一样长，加上写入自身的花费必然亏本。
        let source = shell(&entry_field(&format!(
            "return {}",
            vec!["256"; 60].join(",")
        )));
        parses(&source);
        assert_eq!(lift(&source, Target::Lua51).unwrap(), source);
        // 五次使用：省下的字节还不够付写入。
        let source = shell(&entry_field("return 65536,65536,65536,65536,65536"));
        parses(&source);
        assert_eq!(lift(&source, Target::Lua51).unwrap(), source);
        assert_eq!(gain("256", 200, 1, 1), -8);
        assert_eq!(gain("65536", 10, 1, 1), 10);
        assert_eq!(gain("65536", 5, 1, 1), 0);
        // 双字母键把读价抬到 4 字节：同样十次使用的 65536 就已经不划算了。
        assert_eq!(gain("65536", 10, 1, 2), -1);
        assert_eq!(gain("4294967296", 20, 1, 1), 125);
    }

    #[test]
    fn field_names_dodge_every_name_the_script_uses() {
        let dense = ('a'..='z')
            .map(|char| char.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let values = vec!["0"; 26].join(",");
        let source = format!(
            "local Q={{}} return setmetatable({{[\"p\"]=function(k,...) local {dense}={values} return {} end}},Q):p()",
            six("4294967296")
        );
        parses(&source);
        let out = lift(&source, Target::Lua51).unwrap();
        let key = written_key(&out, "Q");
        // 双字母键把一次读价抬到 4 字节：只有 10 字节的拼写还划算。
        assert_eq!(key.len(), 2, "{key} 应该退到双字母");
        assert!(!is_keyword(&key, Target::Lua51));
        assert!(!dense.contains(key.as_str()), "{key} 已被脚本占用");
        assert_eq!(out.matches(&format!("Q.{key}")).count(), 7);
        assert_eq!(out.matches("4294967296").count(), 1);
        parses(&out);
    }

    #[test]
    fn any_other_program_is_left_alone() {
        let body = six("65536");
        let entry = entry_field(&format!("return {body}"));
        for source in [
            // 包装表不是空的。
            format!("local w={{n=1}} return setmetatable({{{entry}}},w):p()"),
            // chunk 里多了一条语句。
            format!("local w={{}} local n=1 return setmetatable({{{entry}}},w):p()"),
            // 第二个实参不是那张包装表。
            format!("local w={{}} return setmetatable({{{entry}}},{{n=1}}):p()"),
            // 被调用的方法不是那个「一形参 + ...」字段。
            format!("local w={{}} return setmetatable({{{entry}}},w):q()"),
            // 用户程序里一个碰巧像壳的片段（K16 的回归现场：coverage 探针）。
            format!("local Probe={{}} function Probe.run(self,...) return {body} end return setmetatable({{}},Probe):run()"),
        ] {
            parses(&source);
            assert_eq!(lift(&source, Target::Lua51).unwrap(), source, "{source}");
        }
    }
}
