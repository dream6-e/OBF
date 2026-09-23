//! Micro-op MBA layer: mixed boolean-arithmetic spellings for the integer
//! primitives the emitted machine performs on *itself*.
//!
//! Goal 3 asked for the VM's direct micro-op primitives to stop reading as
//! `w+q` / `w//q` / `w==q`. The value-operand primitives (the ALU arm bodies
//! `r=x+y`, `r=(x==y)`, ...) cannot be replaced by any unconditional MBA
//! identity: they run on arbitrary Lua values, so string coercion,
//! `__add`/`__idiv` metamethods, IEEE-754 exactness and the raised-error text
//! must all survive, and each of those is pinned by `tests/fixtures/vm_lua51.lua`
//! / `vm_luau.lua` and `tests/vm_parity.rs`. This module therefore obfuscates
//! the layer that *is* integer by construction: the micro-op selector
//! (`oi5==k` / `op==k` / `kind==k`), the operand-reference unpacking, the
//! site/temp lane arithmetic, loop and target counters, arity and bounds
//! guards, and the runtime token/key arithmetic of the dispatch and context
//! layers. The value arms stay raw and a gate pins that they do.
//!
//! Two legal spelling families are drawn per use site:
//!
//! * `bit` variants -- the textbook mixed boolean-arithmetic identities
//!   `a+b = (a^b) + 2*(a&b)` and its siblings. Luau has the K7 native
//!   `bit32` captures in scope (`BX`/`BA`/`BO`/`BN`), so this family is drawn
//!   there. Lua 5.1 has no bit library and emulating one per micro-op was
//!   measured out of the timing budget, so that target draws only the
//!   arithmetic family (the same "Lua 5.1 goes pure arithmetic" rule the K7
//!   toolbox follows).
//! * `poly` variants -- non-reducible arithmetic polynomials with per-site
//!   coefficients. `x*(p+1) - x*p == x` exactly, so a sum can be written
//!   without ever writing the sum of its operands; masked and "depth 2"
//!   variants wrap the terms in opaquely spelled moduli or in a second exact
//!   polynomial, and the order predicates use the modular-order identity
//!   `x > c <=> ((c-x) % 2^32) > 2^31`.
//!
//! Anchor hygiene: the two drawn literal sources (`coefficient_pair` /
//! `wrap_pair` and the `modulus`/`half` spellings) reject every value in
//! [`super::transport::is_nice_part`] -- the very predicate the anchor-floor
//! gate uses -- and the modulus/split spellings never carry a canonical
//! decimal at all (`2^32`, `(2^16*2^16)`, or a nice-free two-term sum drawn
//! through `transport::opaque_split`). Without that, a drawn coefficient
//! could spell `65536` or `16777216` and the anchor-floor gate would blame
//! the wrapper-field pass for a literal this layer produced.
//!
//! Precision contract (enforced by unit tests in `tests/mba.rs` and the
//! template lint in `seed_deform`): every intermediate stays below 2^53, every
//! squared difference stays below 2^53, every coefficient product stays below
//! 2^53 for the documented operand bound (`< 2^21`), divisions only ever by a
//! literal that divides its dividend exactly or through the floor helper, and
//! the modular-order predicates only ever see operands whose difference
//! magnitude stays below 2^31.

use super::*;

/// The u32 modulus the masked variants use.
pub(crate) const MOD: u64 = 4_294_967_296;
/// Its half: the split point of the modular-order predicates.
pub(crate) const HALF: u64 = 2_147_483_648;
/// Largest literal a squared-difference predicate may use (`|x-c| < 2^26`).
pub(crate) const SQUARE_MAX: u64 = 1 << 26;

/// The K7 bit-capture aliases in scope where the renderers run. The interpreter
/// section receives them as parameters on Luau (see `emit.rs`), so a rendered
/// `BX(a,b)` is a local call there and never a global lookup.
#[derive(Clone, Copy)]
pub(crate) struct Bit3 {
    pub bxor: &'static str,
    pub band: &'static str,
    pub bor: &'static str,
    pub bnot: &'static str,
}

impl Bit3 {
    /// Luau only: the captures live in the same wrapper scope as `H`/`SEED`.
    pub(crate) fn for_target(target: Target) -> Option<Self> {
        target.is_luau().then(|| Bit3 {
            bxor: "BX",
            band: "BA",
            bor: "BO",
            bnot: "BN",
        })
    }
}

/// Floor spelling: Lua 5.1 has no `//` operator, Luau has no `MF` helper --
/// the same per-target split the K7 toolbox and the template gate enforce.
#[derive(Clone, Copy)]
pub(crate) enum Floor {
    /// `MF(x)`
    Call(&'static str),
    /// `x//1`
    Op(&'static str),
}

impl Floor {
    fn render(&self, x: &str) -> String {
        match self {
            Floor::Call(name) => format!("{name}({x})"),
            Floor::Op(op) => format!("{x}{op}1"),
        }
    }
}

/// Renderer name bindings.
#[derive(Clone, Copy)]
pub(crate) struct MbaNames {
    pub floor: Floor,
    pub bits: Option<Bit3>,
}

impl MbaNames {
    pub(crate) fn emit(target: Target) -> Self {
        MbaNames {
            floor: if target.is_luau() {
                Floor::Op("//")
            } else {
                Floor::Call("MF")
            },
            bits: Bit3::for_target(target),
        }
    }

    /// The same bindings with the bit family withdrawn. Sites whose operands
    /// are *not* proven integers -- the packed-reference fields, which `refd`
    /// only type-checks -- draw from this set: `bit32` errors on a
    /// non-integer argument, while the chain is specified to carry any number
    /// through to the trap that rejects it.
    pub(crate) fn plain(target: Target) -> Self {
        MbaNames {
            bits: None,
            ..Self::emit(target)
        }
    }
}

/// Comparison operators the guard rewriter understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cmp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

impl Cmp {
    /// Parse the longest operator at the head of `rest`.
    fn parse(rest: &str) -> Option<(Cmp, usize)> {
        for (text, op) in [
            ("==", Cmp::Eq),
            ("~=", Cmp::Ne),
            (">=", Cmp::Ge),
            ("<=", Cmp::Le),
            (">", Cmp::Gt),
            ("<", Cmp::Lt),
        ] {
            if rest.starts_with(text) {
                return Some((op, text.len()));
            }
        }
        None
    }
}

/// Draw `p` in `[lo, lo+span)` with **both** spelled factors (`p` and `p+1`)
/// outside the audit's nice set. The rejection predicate is the shared
/// `transport::is_nice_part`, so the layer that *admits* an anchor and the
/// layer that draws coefficients can never disagree about what an anchor is.
/// Without it a draw could spell `16777216` or the byte-assembly weight by
/// accident, and the anchor-floor gate would blame the wrapper-field pass.
fn nice_free(rng: &mut crate::random::Prng, lo: u64, span: usize) -> u64 {
    loop {
        let value = lo + rng.index(span) as u64;
        if !super::transport::is_nice_part(value) && !super::transport::is_nice_part(value + 1) {
            return value;
        }
    }
}

/// A drawn coefficient pair `(p, p+1)`: `x*(p+1) - x*p == x` exactly while
/// `x` stays under 2^21 (products below 6.5e14). The span is drawn narrow on
/// purpose: the packed-reference fields are folded through these pairs too,
/// and their operands reach 9e6 (a `refd` record is bounded by
/// `kind<=8, vi,vo<1000`), so `9e6 * 1.2e6 < 2^53` keeps every product exact
/// even for the fractional `vo` the differential's fractional-reference
/// vector carries.
fn coefficient_pair(rng: &mut crate::random::Prng) -> (u64, u64) {
    let p = nice_free(rng, 1_000_003, 200_000);
    (p, p + 1)
}

/// Small coefficient pair for wrapping an already-derived quantity: the
/// wrapped value is below 2^32, so the coefficients stay under 1e6 to keep
/// `value * p < 4.3e15 < 2^53`.
fn wrap_pair(rng: &mut crate::random::Prng) -> (u64, u64) {
    let p = nice_free(rng, 100_003, 899_980);
    (p, p + 1)
}

/// `(text)*(p+1) - (text)*p` -- an exact identity polynomial in one already
/// written sub-expression. Doubles the written depth without changing the
/// value or the precision envelope.
fn depth_wrap(rng: &mut crate::random::Prng, text: &str) -> String {
    let (p, pu) = wrap_pair(rng);
    format!("(({text})*{pu}-({text})*{p})")
}

/// Opaque spelling of `2^32`: a power form, a product of power-of-two
/// factors, or a two-term sum whose parts are drawn outside the audit's nice
/// set. Every variant is exactly the same double, and -- this is the property
/// the anchor-floor gate checks -- **no variant spells a canonical decimal
/// from that set**: the mask must not hand an analyst `4294967296`, `65536`
/// or `4294967295` as a grep handle. Hex and `2^k` spellings carry no decimal
/// digit run at all, and the sums go through the shared nice-part rejection.
pub(crate) fn modulus(rng: &mut crate::random::Prng) -> String {
    match rng.index(5) {
        0 => "2^32".to_owned(),
        1 => "(2^16*2^16)".to_owned(),
        2 => "(2^15*2^17)".to_owned(),
        3 => "(2^8*2^24)".to_owned(),
        _ => {
            let (a, b) = super::transport::opaque_split(rng, MOD);
            format!("({a}+{b})")
        }
    }
}

/// Opaque spelling of `2^31` (the modular-order split point), same rules.
pub(crate) fn half(rng: &mut crate::random::Prng) -> String {
    match rng.index(5) {
        0 => "2^31".to_owned(),
        1 => "(2^16*2^15)".to_owned(),
        2 => "(2^30*2)".to_owned(),
        3 => "(2^20*2^11)".to_owned(),
        _ => {
            let (a, b) = super::transport::opaque_split(rng, HALF);
            format!("({a}+{b})")
        }
    }
}

/// `a + b` for non-negative integers with `a + b < 2^32` and both operands
/// below `COEFF_OPERAND_MAX`.
pub(crate) fn add(rng: &mut crate::random::Prng, n: &MbaNames, a: &str, b: &str) -> String {
    let bit_forms = if n.bits.is_some() { 3 } else { 0 };
    let core = match rng.index(3 + bit_forms) {
        // poly: neither operand is ever added to the other directly.
        0 => {
            let (p, pu) = coefficient_pair(rng);
            let (q, qu) = coefficient_pair(rng);
            format!("({a}*{pu}-{a}*{p})+({b}*{qu}-{b}*{q})")
        }
        1 => {
            let (p, pu) = coefficient_pair(rng);
            let (q, qu) = coefficient_pair(rng);
            format!("({b}*{qu}-{b}*{q})+({a}*{pu}-{a}*{p})")
        }
        2 => {
            let (p, pu) = coefficient_pair(rng);
            let (q, qu) = coefficient_pair(rng);
            format!("({a}*{pu}-{a}*{p}+{b}*{qu}-{b}*{q})%{}", modulus(rng))
        }
        _ => {
            let bits = n.bits.as_ref().expect("bit forms need a bit library");
            match rng.index(3) {
                0 => format!("{}({a},{b})+2*{}({a},{b})", bits.bxor, bits.band),
                1 => format!("2*{}({a},{b})-{}({a},{b})", bits.bor, bits.bxor),
                _ => format!(
                    "{}({a},{b})+({}({a},{b})+{}({a},{b}))",
                    bits.bxor, bits.band, bits.band
                ),
            }
        }
    };
    let core = if rng.index(4) == 0 {
        depth_wrap(rng, &core)
    } else {
        core
    };
    mask_or_plain(rng, &core)
}

/// Wrap an exact identity polynomial in an opaquely spelled modulus when the
/// caller's value is known to sit below it. The rendered value is unchanged
/// (`0 <= v < 2^32`), and the modulus spelling never repeats the same form.
fn mask_or_plain(rng: &mut crate::random::Prng, text: &str) -> String {
    if rng.index(2) == 0 {
        text.to_owned()
    } else {
        format!("({})%{}", text, modulus(rng))
    }
}

/// `x + c` with a literal constant (folded into the polynomial so the literal
/// never sits next to `x`).
pub(crate) fn add_const(rng: &mut crate::random::Prng, n: &MbaNames, x: &str, c: u64) -> String {
    assert!(c < 1_000_000, "MBA: add_const constant out of range");
    add(rng, n, x, &c.to_string())
}

/// `a - b` for `0 <= b <= a` and `a < 2^21` (a non-negative difference, so
/// the masked forms may wrap without changing the sign).
pub(crate) fn sub_nonneg(rng: &mut crate::random::Prng, n: &MbaNames, a: &str, b: &str) -> String {
    let bit_forms = if n.bits.is_some() { 1 } else { 0 };
    let core = match rng.index(3 + bit_forms) {
        // poly: `a + (k - b) - k == a - b`, so the subtrahend only ever
        // appears negated against a drawn constant and then removed again.
        0 => {
            let (p, pu) = coefficient_pair(rng);
            let (q, qu) = coefficient_pair(rng);
            let k = nice_free(rng, 3_000_000, 900_000_000);
            format!("(({a}*{pu}-{a}*{p})+({k}-({b}*{qu}-{b}*{q}))-{k})")
        }
        1 => {
            let (p, pu) = coefficient_pair(rng);
            let (q, qu) = coefficient_pair(rng);
            let k = nice_free(rng, 3_000_000, 900_000_000);
            format!("((({k}-({b}*{qu}-{b}*{q}))+{a}*{pu}-{a}*{p})-{k})")
        }
        2 => {
            // a + (M - b) taken modulo M: a non-negative difference wraps back
            // to itself, and `M - b` is written through an exact polynomial.
            let (p, pu) = coefficient_pair(rng);
            let (q, qu) = coefficient_pair(rng);
            format!(
                "(({a}*{pu}-{a}*{p})+({}-({b}*{qu}-{b}*{q})))%{}",
                modulus(rng),
                modulus(rng)
            )
        }
        _ => {
            let bits = n.bits.as_ref().expect("bit forms need a bit library");
            format!(
                "{}({a},{b})-2*{}({}({a}),{b})",
                bits.bxor, bits.band, bits.bnot
            )
        }
    };
    mask_or_plain(rng, &core)
}

/// `x op c` for an integer `x` bounded by `bound` and a literal `c`.
///
/// * `==` / `~=` never compare the operand against the literal: the modular
///   difference (`<1` / `>0`), the squared difference while `|x-c| < 2^26`,
///   or the native xor on targets that have one.
/// * `<` / `>` use the modular-order identity around `M = 2^32`, `H = 2^31`,
///   valid while `|x-c| < 2^31`; `<=` / `>=` are the negations of those, which
///   keeps them exact for fractional operands as well.
pub(crate) fn compare(
    rng: &mut crate::random::Prng,
    n: &MbaNames,
    x: &str,
    bound: u64,
    op: Cmp,
    c: u64,
) -> String {
    assert!(c < HALF, "MBA: comparison constant out of range");
    assert!(
        bound < HALF,
        "MBA: comparison operand bound out of range: {bound}"
    );
    if matches!(op, Cmp::Eq | Cmp::Ne) {
        let square_ok = c <= SQUARE_MAX && bound + c < SQUARE_MAX;
        let xor = n.bits.as_ref().map(|b| b.bxor);
        let forms = 1 + usize::from(square_ok) + usize::from(xor.is_some());
        // `~=` is the non-zero test: the modular difference and the squared
        // difference are both exact for *every* number in the window, and the
        // xor form is exact for the integer-only names the bit family is
        // restricted to. `==` is its negation -- a `<1` tail would accept a
        // fractional `x` (`0.5 < 1`), which is exactly the fractional-word
        // case the direct differential carries.
        let core = match rng.index(forms) {
            0 => format!("(({x}-{c})%{})", modulus(rng)),
            1 if square_ok => format!("(({x}-{c})*({x}-{c}))"),
            _ => {
                let bits = xor.expect("xor form needs a bit library");
                format!("({}({x},{c}))", bits)
            }
        };
        let ne = format!("({core}>0)");
        return if op == Cmp::Ne {
            ne
        } else {
            format!("(not {ne})")
        };
    }
    // Order predicates: a difference taken modulo 2^32 against the split.
    let order = |rng: &mut crate::random::Prng, a: &str, b: &str| -> String {
        match rng.index(3) {
            0 => format!("((({a})-({b}))%{}>{})", modulus(rng), half(rng)),
            1 => format!(
                "((({a})-({b})+{})%{}>{})",
                modulus(rng),
                modulus(rng),
                half(rng)
            ),
            // Second spelling of the same predicate. `((a-b) mod M) > H`
            // and `((a-b) mod M) >= H` agree on the domain (`|a-b| < H`:
            // the modular value is either `a-b` or `M-(b-a)`, and equality
            // maps to zero, which neither form accepts), so the split is
            // drawn without moving the answer.
            _ => format!("((({a})-({b}))%{})>={}", modulus(rng), half(rng)),
        }
    };
    match op {
        // x > c  <=>  ((c - x) % M) > H
        Cmp::Gt => order(rng, &c.to_string(), x),
        // x < c  <=>  ((x - c) % M) > H
        Cmp::Lt => order(rng, x, &c.to_string()),
        // The non-strict orders are the negations of the strict ones: `x >= c
        // <=> not (x < c)`, `x <= c <=> not (x > c)`. Shifting the literal by
        // one (`x > c-1`) is only the same predicate for an *integer* `x`,
        // and the guarded fields carry fractional words through to the trap
        // (the direct differential's `78-frac-ref` vector is exactly that
        // case), so the layer keeps the reals exact here too.
        Cmp::Ge => format!("(not ({}))", order(rng, x, &c.to_string())),
        Cmp::Le => format!("(not ({}))", order(rng, &c.to_string(), x)),
        _ => unreachable!("equality handled above"),
    }
}

/// `x % 1 ~= 0` -- true when `x` is *not* an integer (the integrality
/// guards fire on a true), exact for every finite `x`.
pub(crate) fn non_integral(rng: &mut crate::random::Prng, n: &MbaNames, x: &str) -> String {
    let floor = n.floor.render(x);
    match rng.index(3) {
        0 => format!("({floor}<{x} or {x}<{floor})"),
        1 => format!("(({x}-{floor})>0 or ({floor}-{x})>0)"),
        _ => format!("({floor}-{x}~=0)"),
    }
}

/// `x % k` for `0 < k <= 1_000_000`, `x < 2^26`: the operand-reference field
/// extraction. The divisor is drawn per site from exactly equivalent
/// spellings, so the decoded value is identical while the literal no longer
/// reads as the ISA packing constant. `n` supplies the floor spelling, so the
/// drawn form stays dual-target clean (`MF(x/k)` on Lua 5.1, `x/k//1` on Luau
/// -- the same split the template gate enforces).
pub(crate) fn modulo_field(rng: &mut crate::random::Prng, n: &MbaNames, x: &str, k: u64) -> String {
    assert!(k > 0 && k <= 1_000_000, "MBA: modulus out of range");
    match rng.index(5) {
        0 => format!("{x}%{k}"),
        1 => {
            let factor = (2..=k).find(|d| k % d == 0).unwrap_or(0);
            if factor == 0 {
                format!("{x}%{k}")
            } else {
                format!("{x}%({factor}*{})", k / factor)
            }
        }
        2 => {
            let off = k / 3;
            format!("{x}%({}+{})", k - off, off)
        }
        3 => format!("{x}%({k}*1)"),
        // `x - floor(x/k)*k == x % k` for a non-negative integer `x` whose
        // quotient stays exactly representable (< 2^26 with the divisors this
        // layer uses). The operator itself stops reading as a field mask.
        _ => {
            let floor = n.floor.render(&format!("{x}/{k}"));
            format!("({x}-{floor}*{k})")
        }
    }
}

/// Identifiers the guard rewriter may touch, with the operand bound each one
/// is *provably* inside.
///
/// The bound is a soundness precondition, not a hint. The modular identities
/// below are equivalences only while the operand's distance to the literal
/// stays under `2^31` (`((x-c) mod 2^32) > 2^31` flips its answer once
/// `x-c` reaches the split), and the squared-difference forms need the
/// operand to be an exact integer. Every entry is therefore a quantity the
/// VM computed for itself:
///
/// * `vi` / `vo` / `oi5` / `oo5` / `ok5` -- fields unpacked by `refd`, which
///   rejects a non-integer or out-of-range record before any caller sees
///   them, so they are bounded integers;
/// * `ip` -- seeded at 1, only ever assigned a `tgtc`-validated target or
///   itself plus one, so it stays a small non-negative integer;
/// * `i` / `n` -- the arity loop counter and the execution budget, both
///   small integers by construction;
/// * `q` / `prog` -- only reached through `#`, and the decoder bounds a record
///   to its arity, so the lengths are small integers.
///
/// Image *fields* the VM has not validated yet -- `op`, `re`, `t1`, `kind`,
/// `nargs`, `t`, `m`, `a`, `sl`, ... -- are deliberately absent: their
/// comparisons are the validation traps themselves, and a modular rewrite
/// would stop firing for adversarial values inside the wrap window. A gate in
/// `tests/mba.rs` pins that those traps keep their literal form. `x%1 ~= 0`
/// is the one family that is safe for an unvalidated operand (the rewrite is
/// exact for every finite number) but it is still restricted to this table so
/// the rewrite surface stays reviewable.
pub(crate) const GUARD_IDENTS: &[(&str, u64)] = &[
    ("vi", 1_000),
    ("vo", 1_000),
    ("oi5", 16),
    ("oo5", 16),
    ("ok5", 16),
    ("ip", 1_000_000),
    ("i", 1_000_000),
    ("n", 1_000_000),
    ("q", 1_000),
    ("prog", 1_000_000),
];

/// The subset of [`GUARD_IDENTS`] the *bit* family may spell.
///
/// The bit family is exact for integers and raises a raw Luau error for
/// anything else, and on Luau the trap itself is often the only thing standing
/// between a fractional word and the rest of the chain (`if vi>15 or vo~=0
/// then seedfail(...)` evaluates `vi` first, so a `bit32` call on a fractional
/// `vi` would replace the fail-closed `seedfail` with an argument error, and
/// the differential fixture's fractional-reference vector pins that it does
/// not). The guarded *fields* therefore draw the arithmetic family only --
/// they are integer because the trap says so, not before it. The names listed
/// here are integral before their guard runs: a table length (`#q`, `#prog`),
/// the instruction pointer (only ever assigned a `tgtc`-validated target or
/// itself plus one) and the two loop counters.
pub(crate) const GUARD_BIT_IDENTS: &[&str] = &["q", "prog", "ip", "i", "n"];

/// Rewrite every integer guard of the shape `<ident> <cmp> <literal>`,
/// `<#ident> <cmp> <literal>` and `<ident>%1 <cmp> 0` in `text`, drawing an
/// independent MBA spelling per occurrence. Text inside string literals is
/// never touched, and identifiers outside [`GUARD_IDENTS`] are left alone, so
/// the value-operand comparisons and table reads keep their exact Lua
/// semantics (including the raised errors). Returns the number of rewrites.
pub(crate) fn rewrite_guards(
    text: &str,
    rng: &mut crate::random::Prng,
    names: &MbaNames,
) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len() + 512);
    let mut rewrites = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            // Copy the whole literal verbatim (escape-aware).
            let quote = c;
            out.push(c as char);
            i += 1;
            while i < bytes.len() {
                let d = bytes[i];
                out.push(d as char);
                i += 1;
                if d == b'\\' && i < bytes.len() {
                    out.push(bytes[i] as char);
                    i += 1;
                } else if d == quote {
                    break;
                }
            }
            continue;
        }
        // Try a guard starting here, but never inside a longer word.
        let at_word_start = i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric()
                || bytes[i - 1] == b'_'
                || bytes[i - 1] == b'#'
                || bytes[i - 1] == b'.');
        if at_word_start {
            if let Some((consumed, rendered)) = match_guard(&text[i..], rng, names) {
                out.push_str(&rendered);
                i += consumed;
                rewrites += 1;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    (out, rewrites)
}

/// Try to match one guard at the head of `rest`. `#`-prefixed length reads and
/// the `%1~=0` integrality form are recognised before the plain form.
fn match_guard(
    rest: &str,
    rng: &mut crate::random::Prng,
    names: &MbaNames,
) -> Option<(usize, String)> {
    let bytes = rest.as_bytes();
    let mut at = 0usize;
    let hash = bytes.first() == Some(&b'#');
    if hash {
        at += 1;
    }
    let ident_start = at;
    while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
        at += 1;
    }
    if at == ident_start {
        return None;
    }
    let ident = &rest[ident_start..at];
    let bound = GUARD_IDENTS
        .iter()
        .find(|(name, _)| *name == ident)
        .map(|(_, bound)| *bound)?;
    // Boundary check: the identifier must not be the tail of a longer word.
    // (`#q` puts the identifier one byte in; the caller already proved the
    // whole match starts on a word boundary.)
    if ident_start > usize::from(hash) {
        return None;
    }
    let lhs = &rest[..at];
    // Family choice: only the names that are integral *before* their guard
    // runs may be spelled with the bit family (see [`GUARD_BIT_IDENTS`]); the
    // guarded fields use the arithmetic family, which is exact for the
    // fractional words the trap is about to reject.
    let names = if GUARD_BIT_IDENTS.contains(&ident) {
        *names
    } else {
        MbaNames {
            bits: None,
            ..*names
        }
    };
    // Integrality form first: `<lhs>%1~=0` / `<lhs>%1==0`.
    if !hash {
        if let Some(tail) = rest[at..].strip_prefix("%1") {
            if let Some((op, op_len)) = Cmp::parse(tail) {
                let lit_end = tail[op_len..]
                    .find(|ch: char| !ch.is_ascii_digit())
                    .unwrap_or(tail.len() - op_len);
                let literal = &tail[op_len..op_len + lit_end];
                if literal == "0" {
                    let rendered = match op {
                        Cmp::Ne => non_integral(rng, &names, lhs),
                        Cmp::Eq => format!("(not {})", non_integral(rng, &names, lhs)),
                        _ => return None,
                    };
                    return Some((at + 2 + op_len + 1, rendered));
                }
            }
        }
    }
    let (op, op_len) = Cmp::parse(&rest[at..])?;
    let literal_start = at + op_len;
    let mut literal_end = literal_start;
    while literal_end < bytes.len() && bytes[literal_end].is_ascii_digit() {
        literal_end += 1;
    }
    if literal_end == literal_start {
        return None;
    }
    // A literal that continues into a bigger number (`0xFF`, `1e6`, `3.5`)
    // or into an operator is not the guard's right-hand side: the pass runs on
    // text whose neighbouring sites may already hold a drawn expression, and
    // reading the leading `2` of `2*BO(nargs,5)` as the literal would cut the
    // expression in half (that exact shape was a construction-time bug).
    if let Some(next) = bytes.get(literal_end) {
        if next.is_ascii_alphanumeric()
            || matches!(
                *next,
                b'.' | b'_'
                    | b'+'
                    | b'-'
                    | b'*'
                    | b'/'
                    | b'%'
                    | b'^'
                    | b'~'
                    | b'<'
                    | b'>'
                    | b'='
                    | b':'
            )
        {
            return None;
        }
    }
    let c: u64 = rest[literal_start..literal_end].parse().ok()?;
    if c >= HALF || bound >= HALF {
        return None;
    }
    let rendered = compare(rng, &names, lhs, bound, op, c);
    Some((literal_end, rendered))
}
