//! K4 — function-level layout of the *generated script*: provably safe
//! inlining, outlining and declaration reordering.
//!
//! The image, the container and the ISA are untouched by design: this pass only
//! ever rewrites the Lua text the emitter produced, so the encrypted semantic
//! image stays byte-identical while the script that loads it stops having one
//! canonical shape. It also invents no runtime step: every edit is a refactor of
//! code the emitter already wrote, gated on a safety predicate that is checked
//! per call site, not per seed.
//!
//! Three transforms run as sequential passes over the same text, each one
//! re-analysing what the previous pass produced:
//!
//! * `inline` — a call to an eligible helper is replaced by the helper's own
//!   text. In statement position the copy goes into a `do ... end` block whose
//!   locals are exactly the helper's parameters, so the closure boundary is
//!   reproduced scope for scope and error paths still unwind the same way; in
//!   expression position only bodies of the shape `return <one expression>`
//!   qualify, and there each parameter is substituted by its argument text.
//! * `outline` — an expression that repeats verbatim at several sites is hoisted
//!   into one freshly declared helper, and every site becomes a call with the
//!   free names threaded through as parameters.
//! * `reorder` — runs of consecutive independent helper declarations are
//!   permuted, so neither definition order nor the local/upvalue slot order is
//!   fixed by construction any more.
//!
//! Why the predicates look the way they do. A spliced copy of text resolves
//! *every* name it contains at its new position, so the pass may only move text
//! whose names cannot mean something else there. That is enforced per site, by
//! resolving the name lexically at both places and demanding the same binding:
//! `resolves_the_same` walks the site's scope chain the way Lua would and
//! compares bindings (name, declaration span, scope). A whole-script
//! "this spelling is unique" rule would have been simpler and is *wrong* here —
//! the emitted script re-declares the same short names inside each of its five
//! entry bodies, so uniqueness rejects every candidate and the pass is a no-op
//! that looks like a success.
//!
//! * For `inline`, each free name of the body must resolve at the site to the
//!   very binding the body would have read, no name involved may be a reflection
//!   barrier, and varargs, an argument-count mismatch, multiple return values, a
//!   nested `return`/`break`, a nested function literal, or a write to a binding
//!   outside the moved text all disqualify a candidate. Substituting an argument
//!   into the body's expression also moves that argument across whatever the
//!   body does, so either every argument is pure or the body cannot run code.
//! * For `outline`, every free spelling is threaded through as a parameter, so
//!   the hoisted copy reads the *site's* value and no resolution at the new
//!   definition point matters. The one remaining hazard is time, not scope: a
//!   call inside the fragment could assign a local the fragment also reads, and
//!   the copy would read the pre-call value. A fragment that calls anything
//!   therefore may only read bindings the script never assigns.
//! * For `reorder`, only runs of `local f = function...` declarations that cannot
//!   mention each other are permuted, and the permutation is checked against
//!   every declaration-then-use edge inside the run.
//!
//! Two invariants hold for all three passes. Every rule is a rejection, never a
//! repair: an ineligible candidate is left exactly as the emitter wrote it. And
//! no splice may glue word characters to a neighbour (Lua's lexer would read
//! `end` `end` as one token) nor leave a stray `;`, which is a syntax error in
//! 5.1 because the language has no empty statement.
//!
//! What "provably safe" claims, and what it does not. Everything the script can
//! observe from Lua — stdout, the values computed, whether a guard aborts, the
//! exit status — is unchanged, and `tests/layout.rs` proves it by running the
//! laid-out and the untouched script side by side on the real interpreters. The
//! one documented exception is the *position prefix* the interpreter puts on an
//! unsupplied `error(msg)` message: inlining moves the raising statement to a
//! different line, so a fail-closed diagnostic can name another line. The raised
//! value, the fact that it raises, and the code inside the message are the
//! audited part, and there is a gate for exactly that boundary.
//!
//! The pass is deterministic in `(source, target, seed)` and returns its input
//! unchanged when the seed selects no edits, so `--seed` stays the only knob. It
//! runs before `constant_fields::lift` and before the private-field shortening,
//! so both still see their markers; the delivery size gate is measured on the
//! compressed wrapper (`tools/bench-vm.sh`), not on this text.

use crate::ast::{Block, Expression, ExpressionKind, FunctionBody, Span, Statement, StatementKind};
use crate::random::Prng;
use crate::scope::{self, Analysis, BindingId};
use crate::{Diagnostic, Target};
use std::collections::{BTreeMap, BTreeSet};

/// Ceiling on how much text one inlined helper body may carry, in bytes.
const MAX_INLINE_BODY: usize = 150;
/// Ceiling on how many statements an inlinable body may hold.
const MAX_INLINE_STATEMENTS: usize = 4;
/// Total growth the inline pass may add to the script before it stops.
const MAX_INLINE_GROWTH: i64 = 24 << 10;
/// Lua caps the locals live in one function at 200, and each spliced block adds
/// a parameter local, so the pass leaves the emitter's own headroom alone.
const MAX_FUNCTION_LOCALS: usize = 180;
/// Per-candidate probability buckets, in tenths of a percent. The zero bucket is
/// deliberate: a seed may leave a helper entirely alone, and that mix of shared
/// calls and expanded text inside one script is the point of the pass.
const INLINE_PROBABILITIES: [u16; 4] = [0, 350, 650, 900];
/// Outlining only considers expressions inside this textual size window.
const MIN_OUTLINE_LEN: usize = 44;
const MAX_OUTLINE_LEN: usize = 210;
/// How many identical copies make a repeat worth a helper.
const MIN_OUTLINE_REPEAT: usize = 3;
const MAX_OUTLINE_HELPERS: usize = 6;
/// Declaration runs shorter than this are not worth permuting.
const MIN_REORDER_RUN: usize = 3;
/// Whole-script drift the three passes may cause: inlining may add up to its own
/// budget, outlining may only ever pay a little back.
const MAX_TOTAL_SHRINK: i64 = 24 << 10;
const MAX_TOTAL_GROWTH: i64 = (24 << 10) + 4096;
/// Guard rails against pathological input; the emitted script stays far below
/// all of them.
const MAX_WALK_WORK: usize = 8_000_000;
const MAX_SITES: usize = 60_000;
const MAX_EXPRESSIONS: usize = 400_000;
/// Seed domain, so the layout stream cannot alias the emitter's or the
/// finalizer's.
const LAYOUT_DOMAIN: u64 = 0x4b34_9e37_79b9_7f4d;

fn error(message: impl AsRef<str>) -> Diagnostic {
    Diagnostic::new(format!("XXS layout: {}", message.as_ref()))
}

/// Spellings the layout pass must never duplicate, hoist or reorder: the
/// reflection and loader names whose capture the naming pass audits verbatim,
/// plus the protected-call spellings whose semantics depend on how many Lua
/// frames sit between the call and its caller.
const PROTECTED_SPELLINGS: [&str; 8] = [
    "getfenv",
    "setfenv",
    "loadstring",
    "getinfo",
    "_ENV",
    "_G",
    "debug",
    "pcall",
];

/// Calls to one of these names with a number of arguments other than one are
/// refused inside moved text, because the extra argument is a frame level.
const LEVEL_SENSITIVE: [&str; 6] = ["error", "E", "assert", "pcall", "xpcall", "PC"];

/// A function-valued declaration the inline pass may act on.
struct Decl<'a> {
    binding: Option<BindingId>,
    /// The `function(...)...end` literal: the region inside which a reference
    /// counts as bound by the helper itself.
    literal: Span,
    body: &'a Block,
    parameters: Vec<(String, Option<BindingId>)>,
    varargs: bool,
}

/// A call to a name. A global callee is recorded too, so the pass can see that a
/// helper calls out through a name it cannot reason about.
struct Site<'a> {
    call: &'a Expression,
    args: Vec<&'a Expression>,
    binding: Option<BindingId>,
    /// The call expression is the whole of a call statement.
    statement: bool,
}

struct Scan<'a> {
    decls: Vec<Decl<'a>>,
    sites: Vec<Site<'a>>,
}

enum Step<'a> {
    Block(&'a Block),
    Statement(&'a Statement),
    Expression(&'a Expression),
}

impl<'a> Scan<'a> {
    /// Collect declarations and call sites with an explicit work stack: the
    /// generated script nests long left-associated expressions, and a recursive
    /// walk here would be a stack overflow with a nicer error message.
    fn walk(block: &'a Block, ctx: &Ctx<'_>) -> Result<Scan<'a>, Diagnostic> {
        let mut scan = Scan {
            decls: Vec::new(),
            sites: Vec::new(),
        };
        let mut work = 0usize;
        let mut stack: Vec<Step<'a>> = vec![Step::Block(block)];
        while let Some(step) = stack.pop() {
            work = work
                .checked_add(1)
                .ok_or_else(|| error("walk work overflow"))?;
            if work > MAX_WALK_WORK {
                return Err(error("walk work budget exceeded"));
            }
            match step {
                Step::Block(block) => {
                    for statement in block.statements.iter().rev() {
                        stack.push(Step::Statement(statement));
                    }
                }
                Step::Statement(statement) => {
                    if let Some(decl) = declaration_of(statement, ctx) {
                        scan.decls.push(decl);
                    }
                    // A call statement's whole text *is* the call expression,
                    // and that is what makes a `do ... end` splice a
                    // statement-for-statement swap rather than a restructure of
                    // the statement around it.
                    if let StatementKind::Call(inner) = &statement.kind {
                        if let Some(site) = site_of(inner, ctx, true) {
                            scan.sites.push(site);
                        }
                    }
                    let (expressions, blocks) = statement_parts(statement);
                    for expression in expressions {
                        stack.push(Step::Expression(expression));
                    }
                    for inner in blocks {
                        stack.push(Step::Block(inner));
                    }
                }
                Step::Expression(expression) => {
                    if let Some(site) = site_of(expression, ctx, false) {
                        scan.sites.push(site);
                    }
                    let (children, blocks) = expression_parts(expression);
                    for child in children {
                        stack.push(Step::Expression(child));
                    }
                    for inner in blocks {
                        stack.push(Step::Block(inner));
                    }
                }
            }
        }
        if scan.sites.len() > MAX_SITES {
            return Err(error("script has more call sites than the layout budget"));
        }
        Ok(scan)
    }
}

/// The helper a statement declares, when it declares exactly one function.
fn declaration_of<'a>(statement: &'a Statement, ctx: &Ctx<'_>) -> Option<Decl<'a>> {
    let (name, name_span, literal, body) = match &statement.kind {
        StatementKind::Local {
            bindings, values, ..
        } if bindings.len() == 1 && values.len() == 1 => match &values[0].kind {
            ExpressionKind::Function(body) => (
                &bindings[0].name.value,
                bindings[0].name.span,
                values[0].span,
                body as &'a FunctionBody,
            ),
            _ => return None,
        },
        StatementKind::LocalFunction { name, body, .. } => {
            (&name.value, name.span, body.span, body as &'a FunctionBody)
        }
        _ => return None,
    };
    Some(Decl {
        binding: ctx.binder(name_span),
        literal,
        body: &body.body,
        parameters: body
            .parameters
            .iter()
            .map(|parameter| {
                (
                    parameter.name.value.clone(),
                    ctx.binder(parameter.name.span),
                )
            })
            .collect(),
        varargs: body.has_vararg,
    })
}

/// The call an expression represents, if it is a named direct call. A method
/// call reads its method name off a table the pass cannot reason about, so it is
/// walked but never becomes a target.
fn site_of<'a>(expression: &'a Expression, ctx: &Ctx<'_>, statement: bool) -> Option<Site<'a>> {
    let ExpressionKind::Call {
        function,
        method: None,
        arguments,
        ..
    } = &expression.kind
    else {
        return None;
    };
    let ExpressionKind::Name(name) = &function.kind else {
        return None;
    };
    Some(Site {
        call: expression,
        args: arguments.iter().collect(),
        binding: ctx.resolve(name.span),
        statement,
    })
}

/// A statement's sub-expressions and nested blocks, in one place so all three
/// passes walk the tree the same way. The match is exhaustive on purpose: a new
/// statement kind has to be accounted for here before the layout pass can see
/// the expressions it hides.
fn statement_parts<'a>(statement: &'a Statement) -> (Vec<&'a Expression>, Vec<&'a Block>) {
    let mut expressions: Vec<&'a Expression> = Vec::new();
    let mut blocks: Vec<&'a Block> = Vec::new();
    match &statement.kind {
        StatementKind::Empty
        | StatementKind::Break
        | StatementKind::Continue
        | StatementKind::TypeAlias { .. } => {}
        StatementKind::Call(inner) => expressions.push(inner),
        StatementKind::Return(values) | StatementKind::Local { values, .. } => {
            expressions.extend(values.iter());
        }
        StatementKind::Assignment { targets, values } => {
            expressions.extend(values.iter());
            expressions.extend(targets.iter());
        }
        StatementKind::CompoundAssignment { target, value, .. } => {
            expressions.push(value);
            expressions.push(target);
        }
        StatementKind::LocalFunction { body, .. }
        | StatementKind::Function { body, .. }
        | StatementKind::TypeFunction { body, .. } => blocks.push(&body.body),
        StatementKind::Do(inner) => blocks.push(inner),
        StatementKind::While { condition, body } => {
            expressions.push(condition);
            blocks.push(body);
        }
        StatementKind::Repeat { body, condition } => {
            expressions.push(condition);
            blocks.push(body);
        }
        StatementKind::If {
            branches,
            else_block,
        } => {
            for branch in branches {
                expressions.push(&branch.condition);
                blocks.push(&branch.body);
            }
            if let Some(else_block) = else_block {
                blocks.push(else_block);
            }
        }
        StatementKind::NumericFor {
            initial,
            limit,
            step,
            body,
            ..
        } => {
            expressions.push(initial);
            expressions.push(limit);
            expressions.extend(step.iter());
            blocks.push(body);
        }
        StatementKind::GenericFor { values, body, .. } => {
            expressions.extend(values.iter());
            blocks.push(body);
        }
    }
    (expressions, blocks)
}

/// An expression's sub-expressions and any function body it carries.
fn expression_parts<'a>(expression: &'a Expression) -> (Vec<&'a Expression>, Vec<&'a Block>) {
    let mut children: Vec<&'a Expression> = Vec::new();
    let mut blocks: Vec<&'a Block> = Vec::new();
    match &expression.kind {
        ExpressionKind::Nil
        | ExpressionKind::Boolean(_)
        | ExpressionKind::Number(_)
        | ExpressionKind::String(_)
        | ExpressionKind::Vararg
        | ExpressionKind::Name(_) => {}
        ExpressionKind::Call {
            function,
            arguments,
            ..
        } => {
            children.push(function);
            children.extend(arguments.iter());
        }
        ExpressionKind::Function(body) => blocks.push(&body.body),
        ExpressionKind::Index { table, index } => {
            children.push(table);
            children.push(index);
        }
        ExpressionKind::Field { table, .. } => children.push(table),
        ExpressionKind::Unary { expression, .. } => children.push(expression),
        ExpressionKind::Binary { left, right, .. } => {
            children.push(left);
            children.push(right);
        }
        ExpressionKind::Group(inner) => children.push(inner),
        ExpressionKind::Table(fields) => {
            for field in fields {
                match field {
                    crate::ast::TableField::List(value) => children.push(value),
                    crate::ast::TableField::Record { value, .. } => children.push(value),
                    crate::ast::TableField::Computed { key, value, .. } => {
                        children.push(key);
                        children.push(value);
                    }
                }
            }
        }
        ExpressionKind::IfExpression {
            branches,
            else_expression,
        } => {
            children.push(else_expression);
            for branch in branches {
                children.push(&branch.condition);
                children.push(&branch.value);
            }
        }
        ExpressionKind::InterpolatedString { expressions, .. } => {
            children.extend(expressions.iter());
        }
        ExpressionKind::TypeAssertion { expression, .. }
        | ExpressionKind::TypeInstantiation { expression, .. } => children.push(expression),
    }
    (children, blocks)
}

/// Analysis the passes share, plus the two indexes their rules lean on: how many
/// bindings use a spelling, and which reference resolved to what.
struct Ctx<'a> {
    source: &'a str,
    analysis: &'a Analysis,
    spellings: BTreeMap<&'a str, usize>,
    /// Name-occurrence span -> the binding it resolves to. A global value
    /// reference maps to `Some(None)`; a span that is not a value reference at
    /// all (a field name, a type name) is absent.
    resolved: BTreeMap<(usize, usize), Option<BindingId>>,
    /// A declaration occurrence is not a value reference, so the passes that
    /// need "which binding does this name *declare*" keep their own index.
    declared: BTreeMap<(usize, usize), BindingId>,
    /// `true` when any reference to the binding assigns to it.
    written: BTreeSet<BindingId>,
}

impl<'a> Ctx<'a> {
    fn new(source: &'a str, analysis: &'a Analysis) -> Self {
        let mut spellings: BTreeMap<&str, usize> = BTreeMap::new();
        for binding in &analysis.bindings {
            *spellings.entry(binding.name.as_str()).or_default() += 1;
        }
        let mut resolved = BTreeMap::new();
        let mut declared = BTreeMap::new();
        let mut written = BTreeSet::new();
        for (id, binding) in analysis.bindings.iter().enumerate() {
            if let Some(span) = binding.declaration {
                declared.insert((span.start, span.end), id);
            }
        }
        for reference in &analysis.references {
            resolved.insert(
                (reference.span.start, reference.span.end),
                reference.binding,
            );
            if let Some(binding) = reference.binding {
                if reference.is_write {
                    written.insert(binding);
                }
            }
        }
        Ctx {
            source,
            analysis,
            spellings,
            resolved,
            declared,
            written,
        }
    }

    fn resolve(&self, span: Span) -> Option<BindingId> {
        self.resolved
            .get(&(span.start, span.end))
            .copied()
            .flatten()
    }

    /// The binding a name occurrence *declares*, falling back to the binding it
    /// reads. A declaration token is not a value reference, so a helper's own
    /// name and its parameter names only resolve through this second index.
    fn binder(&self, span: Span) -> Option<BindingId> {
        self.resolve(span)
            .or_else(|| self.declared.get(&(span.start, span.end)).copied())
    }

    /// Name occurrences inside `span`, in source order.
    fn references_in(&self, span: Span) -> Vec<&'a scope::Reference> {
        self.analysis
            .references
            .iter()
            .filter(|reference| {
                reference.span.start >= span.start && reference.span.end <= span.end
            })
            .collect()
    }

    fn binding(&self, id: BindingId) -> &'a scope::LocalBinding {
        &self.analysis.bindings[id]
    }

    fn text_of(&self, span: Span) -> &'a str {
        self.source.get(span.start..span.end).unwrap_or_default()
    }

    /// `true` when `identifier` occurs as a word inside the text of `span`.
    /// Deliberately conservative: a swap is refused rather than working out
    /// which of two same-spelled bindings a mention would have hit.
    fn mentions(&self, span: Span, identifier: &str) -> bool {
        contains_word(self.text_of(span), identifier)
    }
}

/// Word-boundary substring search, so `bp` does not mention `bpf`.
fn contains_word(text: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(offset) = text[from..].find(identifier).map(|found| found + from) {
        let free_before = offset
            .checked_sub(1)
            .is_none_or(|index| !is_identifier_byte(bytes[index]));
        let free_after = bytes
            .get(offset + identifier.len())
            .is_none_or(|byte| !is_identifier_byte(*byte));
        if free_before && free_after {
            return true;
        }
        from = offset + identifier.len();
    }
    false
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn contains(outer: Span, span: Span) -> bool {
    outer.start <= span.start && span.end <= outer.end
}

/// `true` when the byte in front of `offset` is an identifier byte, i.e. a word
/// would fuse with text inserted there.
fn word_before(source: &str, offset: usize) -> bool {
    source
        .as_bytes()
        .get(offset.wrapping_sub(1))
        .is_some_and(|byte| is_identifier_byte(*byte))
}

/// `true` when the first non-space byte at or after `offset` is a `;`.
///
/// Lua 5.1 does not have an empty statement: `;` may only *follow* a statement,
/// so a splice that lands next to a `;` the script already wrote would leave a
/// stray `;` and fail to parse. Guards have to know about that.
fn semi_ahead(source: &str, offset: usize) -> bool {
    source.as_bytes()[offset.min(source.len())..]
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b';')
}

/// Padding for a splice whose neighbour is a word: two touching words are one
/// word, and unlike `;` a space is legal everywhere.
fn pad_before(source: &str, offset: usize) -> &'static str {
    if word_before(source, offset) {
        " "
    } else {
        ""
    }
}

fn pad_after(source: &str, offset: usize) -> &'static str {
    if word_after(source, offset) {
        " "
    } else {
        ""
    }
}

/// The same on the trailing side of `span`.
fn word_after(source: &str, offset: usize) -> bool {
    source
        .as_bytes()
        .get(offset)
        .is_some_and(|byte| is_identifier_byte(*byte))
}

fn disjoint(a: Span, b: Span) -> bool {
    a.end <= b.start || b.end <= a.start
}

/// Splices sorted by start offset and applied in one pass. Nothing may be
/// dropped: a replacement whose call was rewritten but whose declaration was
/// not would leave a script that calls a helper nobody declared, so a collision
/// is an error rather than a silent skip.
struct Edits {
    planned: Vec<(usize, usize, String)>,
    growth: i64,
    /// Replacements that landed, i.e. non-zero-width edits.
    accepted: usize,
    /// Declarations that landed, i.e. zero-width insertions.
    inserts: usize,
    /// Regions already claimed by an accepted helper, declaration included.
    reserved: Vec<Span>,
}

impl Edits {
    fn new() -> Self {
        Edits {
            planned: Vec::new(),
            growth: 0,
            accepted: 0,
            inserts: 0,
            reserved: Vec::new(),
        }
    }

    fn push(&mut self, span: Span, text: String) {
        self.growth += text.len() as i64 - (span.end - span.start) as i64;
        self.planned.push((span.start, span.end, text));
    }

    fn insert(&mut self, offset: usize, text: String) {
        self.push(Span::new(offset, offset), text);
    }

    fn is_empty(&self) -> bool {
        self.planned.is_empty()
    }

    /// `true` when the region collides with an accepted helper's reservation.
    fn collides(&self, region: Span) -> bool {
        self.reserved.iter().any(|used| !disjoint(*used, region))
    }

    fn reserve(&mut self, region: Span) {
        self.reserved.push(region);
    }

    fn apply(&mut self, source: &str) -> Result<String, Diagnostic> {
        if self.is_empty() {
            return Ok(source.to_string());
        }
        let mut planned = self.planned.clone();
        // Zero-width insertions first at an equal offset, so a declaration
        // inserted at the start of a block lands before a site there.
        planned.sort_by_key(|(start, end, _)| (*start, *end));
        let room = self.growth.max(0) as usize;
        let mut out = String::with_capacity(source.len().saturating_add(room));
        let mut cursor = 0usize;
        for (start, end, text) in &planned {
            if *start < cursor || *end < *start || *end > source.len() {
                return Err(error("two layout edits collided inside one pass"));
            }
            if !source.is_char_boundary(*start) || !source.is_char_boundary(*end) {
                return Err(error("a layout edit would split a UTF-8 sequence"));
            }
            out.push_str(&source[cursor..*start]);
            out.push_str(text);
            cursor = *end;
            if start == end {
                self.inserts += 1;
            } else {
                self.accepted += 1;
            }
        }
        if self.accepted + self.inserts != planned.len() {
            return Err(error("a layout edit was dropped while applying"));
        }
        out.push_str(&source[cursor..]);
        Ok(out)
    }
}

/// `pure` here means: evaluating the expression again, or moving it, cannot be
/// observed. Calls, varargs and global reads are all out, because the pass
/// cannot see through a metatable or the environment table. Iterative, because
/// the generated script chains thousands of terms left-associated.
fn pure(expression: &Expression, ctx: &Ctx<'_>) -> bool {
    let mut stack = vec![expression];
    let mut work = 0usize;
    while let Some(current) = stack.pop() {
        work += 1;
        if work > MAX_WALK_WORK {
            return false;
        }
        match &current.kind {
            ExpressionKind::Nil | ExpressionKind::Boolean(_) | ExpressionKind::Number(_) => {}
            ExpressionKind::String(_) => {}
            ExpressionKind::Name(name) => {
                if ctx.resolve(name.span).is_none() {
                    return false;
                }
            }
            ExpressionKind::Unary { expression, .. } | ExpressionKind::Group(expression) => {
                stack.push(expression);
            }
            ExpressionKind::Binary { left, right, .. } => {
                stack.push(left);
                stack.push(right);
            }
            _ => return false,
        }
    }
    true
}

enum Walk<'a> {
    Expression(&'a Expression),
    Block(&'a Block),
}

/// `true` when the expression calls anything, directly or through a nested
/// sub-expression. It decides whether a hoisted fragment has to worry about a
/// callee assigning one of the caller's locals in the middle of the read.
fn has_any_call(expression: &Expression) -> bool {
    let mut stack = vec![expression];
    let mut work = 0usize;
    while let Some(current) = stack.pop() {
        work += 1;
        if work > MAX_WALK_WORK {
            return true;
        }
        if matches!(current.kind, ExpressionKind::Call { .. }) {
            return true;
        }
        let (children, _) = expression_parts(current);
        stack.extend(children);
    }
    false
}

/// `true` when anything under `block` raises or protects with a frame-relative
/// level, including inside a nested closure: that closure still runs one frame
/// deeper than its enclosing helper, so a splice moves the level too.
fn has_level_sensitive_call(block: &Block) -> bool {
    level_walk(vec![Walk::Block(block)])
}

/// The same question for one expression, used where the pass holds a fragment
/// rather than a statement list.
fn expression_has_level_call(expression: &Expression) -> bool {
    level_walk(vec![Walk::Expression(expression)])
}

fn level_walk(seeds: Vec<Walk<'_>>) -> bool {
    let mut stack = seeds;
    let mut work = 0usize;
    while let Some(item) = stack.pop() {
        work += 1;
        // An unbounded walk is a pathological input, not a proof of safety, so
        // it answers "sensitive" and the text stays where it is.
        if work > MAX_WALK_WORK {
            return true;
        }
        match item {
            Walk::Block(block) => {
                for statement in &block.statements {
                    let (expressions, blocks) = statement_parts(statement);
                    stack.extend(expressions.into_iter().map(Walk::Expression));
                    stack.extend(blocks.into_iter().map(Walk::Block));
                }
            }
            Walk::Expression(expression) => {
                if let ExpressionKind::Call {
                    function,
                    method,
                    arguments,
                    ..
                } = &expression.kind
                {
                    if method.is_none() {
                        if let ExpressionKind::Name(name) = &function.kind {
                            if LEVEL_SENSITIVE.contains(&name.value.as_str())
                                && arguments.len() != 1
                            {
                                return true;
                            }
                        }
                    }
                }
                let (children, blocks) = expression_parts(expression);
                stack.extend(children.into_iter().map(Walk::Expression));
                stack.extend(blocks.into_iter().map(Walk::Block));
            }
        }
    }
    false
}

/// The body slice a statement-position splice copies, plus the trailing call a
/// dropped `return` has to keep as a statement. `None` disqualifies the helper.
fn block_plan(ctx: &Ctx<'_>, decl: &Decl<'_>) -> Option<(Span, Option<Span>)> {
    let statements = &decl.body.statements;
    if statements.is_empty() || statements.len() > MAX_INLINE_STATEMENTS {
        return None;
    }
    let last = statements.len() - 1;
    for (index, statement) in statements.iter().enumerate() {
        match &statement.kind {
            // A top-level `break`/`continue` would bind to a loop the copy does
            // not bring along, and a return anywhere but last would return from
            // the caller instead of from the helper.
            StatementKind::Break | StatementKind::Continue => return None,
            StatementKind::Return(_) if index != last => return None,
            _ => {}
        }
    }
    let tail_statement = statements.get(last)?;
    let mut tail = None;
    let end = match &tail_statement.kind {
        // `return <pure>` can go: nothing observes its value. `return <call>`
        // has to keep its evaluation, so the call becomes the last statement of
        // the copy instead. Anything else is refused.
        StatementKind::Return(values) => {
            let [single] = values.as_slice() else {
                return None;
            };
            if single.is_call() {
                tail = Some(single.span);
            } else if !pure(single, ctx) {
                return None;
            }
            tail_statement.span.start
        }
        _ => tail_statement.span.end,
    };
    let kept = Span::new(statements.first()?.span.start, end);
    let text = ctx.text_of(kept);
    if text.len() > MAX_INLINE_BODY || text.trim().is_empty() {
        return None;
    }
    Some((kept, tail))
}

/// The expression a value-position splice substitutes into, when the whole body
/// is one `return <expr>` and copying it cannot duplicate or drop an argument's
/// effect.
fn substitute_plan<'a>(ctx: &Ctx<'a>, decl: &Decl<'a>) -> Option<&'a Expression> {
    let [statement] = decl.body.statements.as_slice() else {
        return None;
    };
    let StatementKind::Return(values) = &statement.kind else {
        return None;
    };
    let [value] = values.as_slice() else {
        return None;
    };
    // A parameter used twice would evaluate its argument twice, and one used not
    // at all would drop it: both are refused. The uses also have to follow the
    // argument order, so substituting them cannot reorder evaluation.
    let references = ctx.references_in(value.span);
    let mut last_use = 0usize;
    for (index, (_, binding)) in decl.parameters.iter().enumerate() {
        let uses: Vec<usize> = references
            .iter()
            .filter(|reference| matches!(binding, Some(id) if reference.binding == Some(*id)))
            .map(|reference| reference.span.start)
            .collect();
        if uses.len() > 1 {
            return None;
        }
        if let Some(where_) = uses.first() {
            if *where_ < last_use {
                return None;
            }
            last_use = *where_;
            let _ = index;
        }
    }
    Some(value)
}

/// The helper's free names: every name occurrence in the literal that the helper
/// does not bind itself. Each has to pass the visibility check at every site, so
/// they are collected once here.
fn free_names<'a>(ctx: &Ctx<'a>, decl: &Decl<'_>) -> Vec<&'a scope::Reference> {
    ctx.references_in(decl.literal)
        .into_iter()
        .filter(|reference| {
            !reference.binding.is_some_and(|id| {
                ctx.binding(id)
                    .declaration
                    .is_some_and(|span| contains(decl.literal, span))
            })
        })
        .collect()
}

/// Would the copied text still mean the same thing at `site`?
///
/// The body's name occurrence is resolved by walking the scope chain at the
/// *site*, exactly as the front end resolved it at the definition: the first
/// active binding with that spelling wins. If the winner is the same binding
/// (or there is none on both sides, i.e. a global read), the splice is a
/// refactor. A shadowing local declared between the definition and the site, or
/// a global that the site happens to have bound locally, is a refusal.
fn resolves_the_same(ctx: &Ctx<'_>, reference: &scope::Reference, site: Span) -> bool {
    let mut current = innermost_scope(ctx, site);
    while let Some(id) = current {
        let scope = &ctx.analysis.scopes[id];
        if !contains(scope.span, site) {
            return false;
        }
        for binding in &scope.bindings {
            let binding = &ctx.analysis.bindings[*binding];
            if binding.name != reference.name {
                continue;
            }
            let active = binding
                .declaration
                .is_some_and(|span| span.start < site.start);
            if active {
                return reference.binding == Some(binding_index(ctx, binding));
            }
        }
        current = scope.parent;
    }
    reference.binding.is_none()
}

/// The index of `binding` in `Analysis::bindings`. The scope tables hand out
/// indices, and the comparison above needs the identity, so this is the one
/// place that has to look a binding up by its own address.
fn binding_index(ctx: &Ctx<'_>, binding: &scope::LocalBinding) -> BindingId {
    ctx.analysis
        .bindings
        .iter()
        .position(|candidate| {
            candidate.name == binding.name
                && candidate.declaration == binding.declaration
                && candidate.scope == binding.scope
        })
        .unwrap_or(usize::MAX)
}

/// The tightest scope that still contains `span`.
fn innermost_scope(ctx: &Ctx<'_>, span: Span) -> Option<scope::ScopeId> {
    let mut best: Option<(usize, scope::ScopeId)> = None;
    for (id, scope) in ctx.analysis.scopes.iter().enumerate() {
        if !contains(scope.span, span) {
            continue;
        }
        let width = scope.span.end.saturating_sub(scope.span.start);
        match best {
            Some((current, _)) if current <= width => {}
            _ => best = Some((width, id)),
        }
    }
    best.map(|(_, id)| id)
}

/// Can evaluating `value` run code the pass cannot see through? A call, an index
/// or a field read can all hit a metamethod, and `pure` argument text that is
/// substituted into the middle of one of those would evaluate in a different
/// order than it did as an argument.
fn can_run_code(expression: &Expression) -> bool {
    let mut stack = vec![expression];
    let mut work = 0usize;
    while let Some(current) = stack.pop() {
        work += 1;
        if work > MAX_WALK_WORK {
            return true;
        }
        if matches!(
            current.kind,
            ExpressionKind::Call { .. }
                | ExpressionKind::Index { .. }
                | ExpressionKind::Field { .. }
        ) {
            return true;
        }
        let (children, _) = expression_parts(current);
        stack.extend(children);
    }
    false
}

/// Would splicing `extra` parameter locals into the function enclosing `span`
/// push it past Lua's 200-live-locals cap?
fn locals_fit(ctx: &Ctx<'_>, span: Span, extra: usize) -> bool {
    let mut home: Option<Span> = None;
    for scope in &ctx.analysis.scopes {
        if scope.kind != scope::ScopeKind::Function || !contains(scope.span, span) {
            continue;
        }
        match home {
            Some(current) if current.end - current.start <= scope.span.end - scope.span.start => {}
            _ => home = Some(scope.span),
        }
    }
    let Some(home) = home else {
        return true;
    };
    let live = ctx
        .analysis
        .bindings
        .iter()
        .filter(|binding| {
            binding
                .declaration
                .is_some_and(|declaration| contains(home, declaration))
        })
        .count();
    live + extra <= MAX_FUNCTION_LOCALS
}

/// One block, with what the outline and reorder passes need from it.
struct BlockInfo<'a> {
    /// The block's statement region: first statement start to last statement
    /// end, so containment can be tested without trusting any keyword-inclusive
    /// span the front end happens to record.
    extent: Span,
    /// Where a new local of this block can go: the start of its first statement.
    /// `None` for an empty block, which cannot host a helper.
    insert: Option<usize>,
    members: Vec<Member<'a>>,
}

struct Member<'a> {
    span: Span,
    /// Spelling, binding and body of the local this statement declares, when it
    /// declares exactly one function.
    declaration: Option<(String, Option<BindingId>, &'a Block)>,
}

impl Member<'_> {
    /// A declaration whose own text touches a reflection barrier is left where it
    /// is: the naming pass audits that text at a fixed position.
    fn movable(&self, ctx: &Ctx<'_>) -> bool {
        self.declaration.is_some()
            && !PROTECTED_SPELLINGS
                .iter()
                .any(|name| ctx.text_of(self.span).contains(name))
    }
}

/// Snapshot of every block, for the passes that work on statement regions rather
/// than on calls. The walk follows expressions too, because in the generated
/// script the entry functions are table fields: a walk that only follows
/// statement nesting would never see the bodies where the helpers live.
fn collect_blocks<'a>(root: &'a Block, ctx: &Ctx<'a>) -> Vec<BlockInfo<'a>> {
    let mut blocks: Vec<BlockInfo<'a>> = Vec::new();
    let mut stack: Vec<Step<'a>> = vec![Step::Block(root)];
    let mut work = 0usize;
    while let Some(step) = stack.pop() {
        work += 1;
        if work > MAX_WALK_WORK {
            break;
        }
        match step {
            Step::Block(block) => {
                let members = block
                    .statements
                    .iter()
                    .map(|statement| {
                        let declaration = match &statement.kind {
                            StatementKind::Local {
                                bindings, values, ..
                            } if bindings.len() == 1 && values.len() == 1 => {
                                match &values[0].kind {
                                    ExpressionKind::Function(body) => Some((
                                        bindings[0].name.value.clone(),
                                        ctx.binder(bindings[0].name.span),
                                        &body.body as &'a Block,
                                    )),
                                    _ => None,
                                }
                            }
                            StatementKind::LocalFunction { name, body, .. } => {
                                Some((name.value.clone(), ctx.binder(name.span), &body.body))
                            }
                            _ => None,
                        };
                        Member {
                            span: statement.span,
                            declaration,
                        }
                    })
                    .collect();
                let extent = match (block.statements.first(), block.statements.last()) {
                    (Some(first), Some(last)) => Span::new(first.span.start, last.span.end),
                    _ => block.span,
                };
                let insert = block
                    .statements
                    .first()
                    .map(|statement| statement.span.start);
                blocks.push(BlockInfo {
                    extent,
                    insert,
                    members,
                });
                for statement in block.statements.iter() {
                    stack.push(Step::Statement(statement));
                }
            }
            Step::Statement(statement) => {
                let (expressions, nested) = statement_parts(statement);
                stack.extend(expressions.into_iter().map(Step::Expression));
                for inner in nested {
                    stack.push(Step::Block(inner));
                }
            }
            Step::Expression(expression) => {
                let (children, nested) = expression_parts(expression);
                stack.extend(children.into_iter().map(Step::Expression));
                for inner in nested {
                    stack.push(Step::Block(inner));
                }
            }
        }
    }
    blocks.sort_by_key(|info| (info.extent.start, info.extent.end));
    blocks
}

/// The inline pass: expand a seeded subset of the eligible call sites.
fn inline_pass(
    source: &str,
    target: Target,
    rng: &mut Prng,
    forced: Option<usize>,
) -> Result<(String, usize), Diagnostic> {
    let chunk = crate::parser::parse_source(source, target)?;
    let analysis = crate::scope::analyze_chunk(&chunk)?;
    let ctx = Ctx::new(source, &analysis);
    let scan = Scan::walk(&chunk.block, &ctx)?;
    let mut edits = Edits::new();
    let mut decls: Vec<&Decl<'_>> = scan.decls.iter().collect();
    decls.sort_by_key(|decl| decl.literal.start);
    for decl in decls {
        // A literal with no binding has no call site to retarget, varargs cannot
        // be reproduced by parameter locals, and a helper whose own spelling is
        // not unique would resolve differently at each site.
        let Some(binding) = decl.binding else {
            continue;
        };
        if decl.varargs {
            continue;
        }
        let literal = ctx.text_of(decl.literal);
        if literal.contains("...") {
            continue;
        }
        // Nothing the naming pass audits as a reflection barrier may be
        // duplicated, and no level-sensitive call may move: both change what a
        // probe, or an `error` level, observes.
        if PROTECTED_SPELLINGS
            .iter()
            .any(|name| literal.contains(name))
        {
            continue;
        }
        if LEVEL_SENSITIVE.iter().any(|name| literal.contains(name))
            && has_level_sensitive_call(decl.body)
        {
            continue;
        }
        let block = block_plan(&ctx, decl);
        let substitute = substitute_plan(&ctx, decl);
        if block.is_none() && substitute.is_none() {
            continue;
        }
        // A nested function literal would make the copy create a closure per
        // site and change how many helpers the script declares: refused.
        let nested_literal = block
            .map(|(kept, _)| ctx.text_of(kept).contains("function"))
            .unwrap_or(false)
            || substitute.is_some_and(|value| ctx.text_of(value.span).contains("function"));
        if nested_literal {
            continue;
        }
        let free = free_names(&ctx, decl);
        if free
            .iter()
            .any(|reference| PROTECTED_SPELLINGS.contains(&reference.name.as_str()))
        {
            continue;
        }
        let mut sites: Vec<&Site<'_>> = scan
            .sites
            .iter()
            .filter(|site| {
                site.binding == Some(binding) && site.args.len() == decl.parameters.len()
            })
            .collect();
        sites.sort_by_key(|site| site.call.span.start);
        // Never inline a helper into its own body: the copy would re-enter the
        // very definition it was expanded from.
        sites.retain(|site| !contains(decl.literal, site.call.span));
        // A helper used at a single site is a rename, not a layout choice, so
        // the pass asks for at least two and lets the seed take a subset.
        if sites.len() < 2 {
            continue;
        }
        let bucket = forced.unwrap_or_else(|| rng.index(INLINE_PROBABILITIES.len()));
        let probability = usize::from(INLINE_PROBABILITIES[bucket]);
        if probability == 0 {
            continue;
        }
        for site in sites {
            if rng.index(1000) >= probability {
                continue;
            }
            if edits.growth > MAX_INLINE_GROWTH {
                break;
            }
            if free
                .iter()
                .any(|reference| !resolves_the_same(&ctx, reference, site.call.span))
            {
                continue;
            }
            if !locals_fit(&ctx, site.call.span, decl.parameters.len()) {
                continue;
            }
            let Some(text) = splice_text(&ctx, decl, site, &block, &substitute) else {
                continue;
            };
            if edits.collides(site.call.span) {
                continue;
            }
            edits.reserve(site.call.span);
            edits.push(site.call.span, text);
        }
    }
    let out = edits.apply(source)?;
    Ok((out, edits.accepted))
}

/// The text that replaces one call site, or `None` when the site's position and
/// the helper's shape do not pair up.
fn splice_text(
    ctx: &Ctx<'_>,
    decl: &Decl<'_>,
    site: &Site<'_>,
    block: &Option<(Span, Option<Span>)>,
    substitute: &Option<&Expression>,
) -> Option<String> {
    if site.statement {
        let (kept, tail) = *block.as_ref()?;
        let mut out = String::from("do ");
        for (index, (name, _)) in decl.parameters.iter().enumerate() {
            out.push_str("local ");
            out.push_str(name);
            out.push_str("=(");
            out.push_str(ctx.text_of(site.args[index].span));
            out.push_str(");");
        }
        let body = ctx.text_of(kept);
        out.push_str(body);
        if !body.ends_with(';') {
            out.push(';');
        }
        if let Some(tail) = tail {
            out.push_str(ctx.text_of(tail));
            if !out.ends_with(';') && !semi_ahead(ctx.source, site.call.span.end) {
                out.push(';');
            }
        }
        out.push_str(" end");
        // `then seedfail(6)end` turns into `then do ... end` followed by the
        // original `end`: two words touching are one word, so a splice that ends
        // where a word begins has to be padded. A space always works; a `;`
        // would be a syntax error right after `then`.
        if word_after(ctx.source, site.call.span.end) {
            out.push(' ');
        }
        if word_before(ctx.source, site.call.span.start) {
            out.insert(0, ' ');
        }
        return Some(out);
    }
    let value = *substitute.as_ref()?;
    // Expression-shaped text cannot carry a separator, so a neighbour that would
    // fuse with it (`name` in front of `(` reads as a call) refuses the site.
    if word_before(ctx.source, site.call.span.start) || word_after(ctx.source, site.call.span.end) {
        return None;
    }
    // Substituting an argument into the body's expression moves it across
    // whatever the body itself does, so either the argument cannot observe
    // anything (pure) or the body cannot (no call, no index, no field read).
    let args_pure = site.args.iter().all(|argument| pure(argument, ctx));
    if !args_pure && can_run_code(value) {
        return None;
    }
    let mut splices: Vec<(usize, usize, String)> = Vec::new();
    for reference in ctx.references_in(value.span) {
        let Some(id) = reference.binding else {
            continue;
        };
        let Some(index) = decl
            .parameters
            .iter()
            .position(|(_, binding)| *binding == Some(id))
        else {
            continue;
        };
        splices.push((
            reference.span.start,
            reference.span.end,
            format!("({})", ctx.text_of(site.args[index].span)),
        ));
    }
    splices.sort_by_key(|(start, _, _)| *start);
    let mut out = String::from("(");
    let mut cursor = value.span.start;
    for (start, end, text) in splices {
        if start < cursor {
            return None;
        }
        out.push_str(&ctx.source[cursor..start]);
        out.push_str(&text);
        cursor = end;
    }
    out.push_str(&ctx.source[cursor..value.span.end]);
    out.push(')');
    Some(out)
}

/// One verbatim repeat: the first node found stands in for all of them, since
/// the text is identical, and the spans are the sites to rewrite.
struct Group<'a> {
    node: &'a Expression,
    spans: Vec<Span>,
}

/// Where a hoisted helper lives, and which names it threads as parameters.
struct OutlinePlan {
    insert: usize,
    parameters: Vec<String>,
}

/// The outline pass: hoist repeated expressions into seeded helpers.
fn outline_pass(
    source: &str,
    target: Target,
    rng: &mut Prng,
) -> Result<(String, usize), Diagnostic> {
    let chunk = crate::parser::parse_source(source, target)?;
    let analysis = crate::scope::analyze_chunk(&chunk)?;
    let ctx = Ctx::new(source, &analysis);
    let blocks = collect_blocks(&chunk.block, &ctx);
    // Group every in-window expression by its verbatim text. A BTreeMap keeps the
    // grouping independent of the walk order.
    let mut groups: BTreeMap<&str, Group<'_>> = BTreeMap::new();
    let mut stack: Vec<Step<'_>> = vec![Step::Block(&chunk.block)];
    let mut work = 0usize;
    let mut seen = 0usize;
    while let Some(step) = stack.pop() {
        work += 1;
        if work > MAX_WALK_WORK {
            return Err(error("outline walk budget exceeded"));
        }
        match step {
            Step::Block(block) => {
                for statement in block.statements.iter().rev() {
                    stack.push(Step::Statement(statement));
                }
            }
            Step::Statement(statement) => {
                let (expressions, nested) = statement_parts(statement);
                stack.extend(expressions.into_iter().map(Step::Expression));
                stack.extend(nested.into_iter().map(Step::Block));
            }
            Step::Expression(expression) => {
                seen += 1;
                if seen > MAX_EXPRESSIONS {
                    return Err(error("script has more expressions than the layout budget"));
                }
                let span = expression.span;
                let length = span.end.saturating_sub(span.start);
                // A call node is refused because replacing one in a multi-value
                // position could change how many values the caller sees, and a
                // bare vararg has no local spelling to thread at all.
                if (MIN_OUTLINE_LEN..=MAX_OUTLINE_LEN).contains(&length)
                    && !matches!(
                        expression.kind,
                        ExpressionKind::Call { .. } | ExpressionKind::Vararg
                    )
                {
                    let entry = groups.entry(ctx.text_of(span)).or_insert(Group {
                        node: expression,
                        spans: Vec::new(),
                    });
                    entry.spans.push(span);
                }
                let (children, nested) = expression_parts(expression);
                stack.extend(children.into_iter().map(Step::Expression));
                stack.extend(nested.into_iter().map(Step::Block));
            }
        }
    }
    let mut candidates: Vec<(&str, Group<'_>)> = groups
        .into_iter()
        .filter(|(_, group)| group.spans.len() >= MIN_OUTLINE_REPEAT)
        .map(|(text, mut group)| {
            group.spans.sort_by_key(|span| span.start);
            (text, group)
        })
        .collect();
    // A group whose copies nest inside each other is refused outright: the
    // replacement would rewrite a fragment that is part of another fragment.
    candidates.retain(|(_, group)| {
        let mut end = 0usize;
        group.spans.iter().all(|span| {
            let free = span.start >= end;
            end = span.end;
            free
        })
    });
    rng.shuffle(&mut candidates);
    let mut edits = Edits::new();
    for (text, group) in candidates {
        if edits.inserts >= MAX_OUTLINE_HELPERS {
            break;
        }
        let Some(plan) = outline_plan(&ctx, &blocks, group.node, text, &group.spans) else {
            continue;
        };
        // The declaration goes at the head of the block the sites share, so the
        // region a helper owns runs from there to its last site, and nothing else
        // may be planned inside it.
        let last = group
            .spans
            .last()
            .map(|span| span.end)
            .unwrap_or(plan.insert);
        let region = Span::new(plan.insert, last);
        if edits.collides(region) {
            continue;
        }
        let name = fresh_name(&ctx, rng);
        let parameters = plan.parameters.join(",");
        let mut declaration = format!("local {name}=function({parameters}) return ({text}) end;");
        let call = format!("({name}({parameters}))");
        // Only hoist when the shared helper pays for its own declaration.
        if declaration.len() + call.len() * group.spans.len() >= text.len() * group.spans.len() {
            continue;
        }
        if spans_fuse(&ctx.source[..], &group.spans) {
            continue;
        }
        if word_before(ctx.source, plan.insert) {
            declaration.push(' ');
        }
        edits.reserve(region);
        edits.insert(plan.insert, declaration);
        for span in &group.spans {
            edits.push(*span, call.clone());
        }
    }
    let mut edits = edits;
    let out = edits.apply(source)?;
    Ok((out, edits.inserts))
}

fn outline_plan(
    ctx: &Ctx<'_>,
    blocks: &[BlockInfo<'_>],
    node: &Expression,
    text: &str,
    spans: &[Span],
) -> Option<OutlinePlan> {
    let fragment = node.span;
    // The copy is spliced verbatim, so it may not hide a vararg or a closure:
    // the first would need the caller's varargs, the second would make the
    // hoisted helper share one function value where each site had its own.
    if ctx.text_of(fragment) != text || text.contains("...") || text.contains("function") {
        return None;
    }
    if expression_has_level_call(node) {
        return None;
    }
    // The deepest block whose statement region holds every site.
    let mut home: Option<&BlockInfo<'_>> = None;
    for info in blocks {
        if info.insert.is_none() || !spans.iter().all(|span| contains(info.extent, *span)) {
            continue;
        }
        match home {
            Some(current)
                if current.extent.end - current.extent.start
                    <= info.extent.end - info.extent.start => {}
            _ => home = Some(info),
        }
    }
    let home = home?;
    let insert = home.insert?;
    if !spans.iter().all(|span| span.start >= insert) {
        return None;
    }
    // Every free spelling becomes a parameter, so the copy resolves its names at
    // the site that called it instead of at this new definition point. That is
    // what makes the hoist a refactor even for the many names this script
    // re-declares inside each entry body.
    let fragment_calls = has_any_call(node);
    let mut parameters: Vec<String> = Vec::new();
    for reference in ctx.references_in(fragment) {
        let internal = reference.binding.is_some_and(|id| {
            ctx.binding(id)
                .declaration
                .is_some_and(|span| contains(fragment, span))
        });
        if internal {
            continue;
        }
        // The audited capture spellings stay where the emitter put them.
        if PROTECTED_SPELLINGS.contains(&reference.name.as_str()) {
            return None;
        }
        // An argument is just a name read, so its value is whatever the site
        // would have read. The one exception: if the fragment calls something,
        // that call could assign one of the locals the fragment also reads, and
        // the copy would then read the value from before the call. A binding the
        // script never assigns cannot do that.
        if fragment_calls {
            let Some(id) = reference.binding else {
                continue;
            };
            if ctx.written.contains(&id) {
                return None;
            }
            let binding = ctx.binding(id);
            if !matches!(
                binding.kind,
                scope::BindingKind::Local
                    | scope::BindingKind::Parameter
                    | scope::BindingKind::LocalFunction
            ) {
                return None;
            }
        }
        if !parameters.contains(&reference.name) {
            parameters.push(reference.name.clone());
        }
    }
    Some(OutlinePlan { insert, parameters })
}

/// `true` when any site touches a word on either side: the hoisted text is an
/// expression, so it cannot carry a separator and the group is refused.
fn spans_fuse(source: &str, spans: &[Span]) -> bool {
    spans
        .iter()
        .any(|span| word_before(source, span.start) || word_after(source, span.end))
}

/// A spelling the script never uses, so a hoisted helper is shadowed by nothing
/// and shadows nothing the fragment cared about.
fn fresh_name(ctx: &Ctx<'_>, rng: &mut Prng) -> String {
    let whole = Span::new(0, ctx.source.len());
    for _ in 0..96 {
        let lead = (b'a' + rng.index(26) as u8) as char;
        let candidate = format!("{lead}{}", rng.index(90_000) + 100);
        if !ctx.mentions(whole, &candidate) && !ctx.spellings.contains_key(candidate.as_str()) {
            return candidate;
        }
    }
    for index in 0..9_000usize {
        let candidate = format!("q{}", 1_000 + index);
        if !ctx.mentions(whole, &candidate) {
            return candidate;
        }
    }
    "zz99999".to_string()
}

/// The reorder pass: permute runs of independent helper declarations.
fn reorder_pass(
    source: &str,
    target: Target,
    rng: &mut Prng,
) -> Result<(String, usize), Diagnostic> {
    let chunk = crate::parser::parse_source(source, target)?;
    let analysis = crate::scope::analyze_chunk(&chunk)?;
    let ctx = Ctx::new(source, &analysis);
    let blocks = collect_blocks(&chunk.block, &ctx);
    let mut edits = Edits::new();
    for info in &blocks {
        let mut index = 0usize;
        while index < info.members.len() {
            if !info.members[index].movable(&ctx) {
                index += 1;
                continue;
            }
            let mut end = index;
            while end + 1 < info.members.len() && info.members[end + 1].movable(&ctx) {
                // Only whitespace and `;` may sit between two members of a run:
                // anything else is a statement the move would drag along.
                let gap = Span::new(info.members[end].span.end, info.members[end + 1].span.start);
                let text = ctx.text_of(gap);
                if text.is_empty()
                    || !text
                        .bytes()
                        .all(|byte| byte == b';' || byte.is_ascii_whitespace())
                {
                    break;
                }
                end += 1;
            }
            if end - index + 1 >= MIN_REORDER_RUN && rng.coin() {
                let run = &info.members[index..=end];
                if let Some((region, replacement)) = permute_run(&ctx, rng, run) {
                    if !edits.collides(region) {
                        edits.reserve(region);
                        edits.push(region, replacement);
                    }
                }
            }
            index = end + 1;
        }
    }
    let mut edits = edits;
    let out = edits.apply(source)?;
    Ok((out, edits.accepted))
}

/// A seeded order for one run that keeps every constrained pair in its original
/// relative order. `None` when the run cannot move at all.
fn permute_run(ctx: &Ctx<'_>, rng: &mut Prng, run: &[Member<'_>]) -> Option<(Span, String)> {
    let mut names: Vec<String> = Vec::with_capacity(run.len());
    for member in run {
        names.push(member.declaration.as_ref()?.0.clone());
    }
    // `before[j]` holds the members that have to stay ahead of `j`: any mention
    // of the other's spelling means the original order is the only one the pass
    // can prove resolves to the same binding, in either direction.
    let mut before: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); run.len()];
    for first in 0..run.len() {
        for second in first + 1..run.len() {
            if ctx.mentions(run[first].span, &names[second])
                || ctx.mentions(run[second].span, &names[first])
            {
                before[second].insert(first);
            }
        }
    }
    let mut remaining: BTreeSet<usize> = (0..run.len()).collect();
    let mut order: Vec<usize> = Vec::with_capacity(run.len());
    while !remaining.is_empty() {
        let ready: Vec<usize> = remaining
            .iter()
            .filter(|index| {
                before[**index]
                    .iter()
                    .all(|needed| !remaining.contains(needed))
            })
            .copied()
            .collect();
        if ready.is_empty() {
            return None;
        }
        let pick = ready[rng.index(ready.len())];
        remaining.remove(&pick);
        order.push(pick);
    }
    if order.iter().enumerate().all(|(index, pick)| index == *pick) {
        return None;
    }
    let first = run.first()?;
    let last = run.last()?;
    let region = Span::new(first.span.start, last.span.end);
    let mut replacement = String::new();
    for pick in &order {
        // The statement text already carries the `;` the emitter wrote, and a
        // second one would be a stray empty statement, which Lua 5.1 rejects.
        if !replacement.is_empty() && !replacement.ends_with(';') {
            replacement.push(';');
        }
        replacement.push_str(ctx.text_of(run[*pick].span));
    }
    if !replacement.ends_with(';') && !semi_ahead(ctx.source, region.end) {
        replacement.push(';');
    }
    replacement.push_str(pad_after(ctx.source, region.end));
    replacement.insert_str(0, pad_before(ctx.source, region.start));
    Some((region, replacement))
}

/// Verify the rewrite is a refactor rather than a rewrite of the runtime: it
/// parses, no protected spelling moved, the script gained exactly as many
/// helpers as the outline pass declared, and the size stayed inside the
/// documented window.
fn verify(after: &str, before: &str, target: Target, helpers: usize) -> Result<(), Diagnostic> {
    crate::parser::parse_source(after, target)?;
    for name in PROTECTED_SPELLINGS {
        let (a, b) = (after.matches(name).count(), before.matches(name).count());
        if a != b {
            return Err(error(format!(
                "the protected spelling `{name}` changed count ({b} -> {a})"
            )));
        }
    }
    let gained = after
        .matches("function(")
        .count()
        .checked_sub(before.matches("function(").count())
        .ok_or_else(|| error("the script lost function definitions"))?;
    if gained != helpers {
        return Err(error(format!(
            "declared {helpers} helpers but the script gained {gained}"
        )));
    }
    let delta = after.len() as i64 - before.len() as i64;
    if delta > MAX_TOTAL_GROWTH || delta < -MAX_TOTAL_SHRINK {
        return Err(error(format!(
            "layout moved the script size by {delta} bytes, outside the -{MAX_TOTAL_SHRINK}/+{MAX_TOTAL_GROWTH} window"
        )));
    }
    Ok(())
}

/// Entry point: rewrite the generated script, or hand it back untouched when the
/// seed selects no edits at all.
pub(crate) fn restructure(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    let mut rng = Prng::sfc(seed ^ LAYOUT_DOMAIN);
    let (text, _inlined) = inline_pass(source, target, &mut rng, None)?;
    let (text, helpers) = outline_pass(&text, target, &mut rng)?;
    let (text, _moved) = reorder_pass(&text, target, &mut rng)?;
    verify(&text, source, target, helpers)?;
    Ok(text)
}

/// What one seed's run did — `(inlined, outlined, reordered)` and the sizes
/// before and after — for the gates that assert the pass is doing work rather
/// than hiding behind a no-op.
#[cfg(test)]
pub(crate) fn tally(
    source: &str,
    target: Target,
    seed: u64,
) -> Result<([usize; 3], usize, usize), Diagnostic> {
    let mut rng = Prng::sfc(seed ^ LAYOUT_DOMAIN);
    let (text, inlined) = inline_pass(source, target, &mut rng, None)?;
    let (text, helpers) = outline_pass(&text, target, &mut rng)?;
    let (text, moved) = reorder_pass(&text, target, &mut rng)?;
    verify(&text, source, target, helpers)?;
    Ok(([inlined, helpers, moved], source.len(), text.len()))
}

/// The same three passes with the inline probability bucket pinned, so the
/// refusal gates can assert "no seed may move this text" without depending on a
/// coin flip. Test-only: production always draws from the seed.
#[cfg(test)]
pub(crate) fn restructure_probe(
    source: &str,
    target: Target,
    seed: u64,
    bucket: usize,
) -> Result<(String, [usize; 3]), Diagnostic> {
    let mut rng = Prng::sfc(seed ^ LAYOUT_DOMAIN);
    let (text, inlined) = inline_pass(source, target, &mut rng, Some(bucket))?;
    let (text, helpers) = outline_pass(&text, target, &mut rng)?;
    let (text, moved) = reorder_pass(&text, target, &mut rng)?;
    verify(&text, source, target, helpers)?;
    Ok((text, [inlined, helpers, moved]))
}
