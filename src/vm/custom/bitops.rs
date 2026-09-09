//! K7 per-target polymorphic word toolbox.
//!
//! Lua 5.1 has no bit library, so its toolbox is pure arithmetic (three
//! structural variants per operation, drawn per image, dual closures per
//! image for the hot xor/rotate pair). Luau runs the same operations on
//! `bit32` + `buffer` captures (also three variants each: direct library
//! calls, buffer-table composition, De Morgan recomposition). Library and
//! method names always arrive through the hidden-name pool, never spelled.
//!
//! Every u32 modulus spelling is also drawn per use site (bare literal,
//! subtraction sandwich `((a+b)-c)`, or explicit double modulus with a
//! literal outer), and every modular sum
//! shuffles its terms: addition commutes exactly in doubles, so the shapes
//! multiply while the values stay bit-identical on both targets.
//!
//! Precision contract (the T7 emitter lint, enforced by unit tests plus a
//! real-interpreter vector harness): every division in every variant body
//! is by a power of two (exact binary-point shift), and every intermediate
//! stays below 2^53. The only sums that approach it are the KDF folds at
//! < 8 x 2^32 < 2^35.

use super::*;

pub(crate) const U32_MODULUS: u64 = 4_294_967_296;
const U32_DOUBLE_MODULUS: u64 = 8_589_934_592;

/// Helper names in scope where toolbox bodies render. The emit path and the
/// vector harness share one name set; the harness binds them to the real
/// prelude values (`math.floor`, real `bit32`/`buffer` refs).
pub(crate) struct BitNames {
    pub mf: &'static str,
    pub x8: &'static str,
    pub x8c: &'static str,
    pub bxor: &'static str,
    pub band: &'static str,
    pub bor: &'static str,
    pub bnot: &'static str,
    pub rotl: &'static str,
    pub shl: &'static str,
    pub shr: &'static str,
    pub buf_new: &'static str,
    pub buf_w8: &'static str,
    pub buf_r8: &'static str,
    pub buf_fromstr: &'static str,
    pub buf_r32: &'static str,
    pub x4t: &'static str,
}

impl BitNames {
    pub(crate) fn emit() -> Self {
        BitNames {
            mf: "MF",
            x8: "X8",
            x8c: "X8C",
            bxor: "BX",
            band: "BA",
            bor: "BO",
            bnot: "BN",
            rotl: "LR",
            shl: "SHL",
            shr: "RS",
            buf_new: "BNE",
            buf_w8: "BW8",
            buf_r8: "BR8",
            buf_fromstr: "BFS",
            buf_r32: "BR3",
            x4t: "X4T",
        }
    }
}

/// Two DISTINCT variant indexes in 0..3 (within-image multiplicity: the hot
/// xor/rotate closures always differ structurally).
pub(crate) fn draw_dual(rng: &mut crate::random::Prng) -> (usize, usize) {
    let first = rng.index(3);
    let second = (first + 1 + rng.index(2)) % 3;
    (first, second)
}

/// Byte-xor bodies over `(a, b)` in 0..=255. Returns (prefix, declaration):
/// the Luau table variant needs its build statements emitted first under the
/// shared prelude table name (at most one of the two X8 closures takes that
/// variant, since the pair is always distinct).
pub(crate) fn render_x8(
    target: Target,
    variant: usize,
    decl: &str,
    n: &BitNames,
) -> (String, String) {
    assert!(variant < 3, "K7: x8 variant out of range");
    let mf = n.mf;
    if target.is_luau() {
        let (bxor, band, bor, bnot) = (n.bxor, n.band, n.bor, n.bnot);
        let (buf_new, buf_w8, buf_r8, x4t) = (n.buf_new, n.buf_w8, n.buf_r8, n.x4t);
        match variant {
            0 => (
                String::new(),
                format!("local {decl}=function(a,b)return {bxor}(a,b) end;"),
            ),
            1 => (
                format!(
                    "local {x4t}={buf_new}(256);for i=0,255 do {buf_w8}({x4t},i,{bxor}({mf}(i/16),i%16))end;",
                ),
                format!(
                    "local {decl}=function(a,b)return {buf_r8}({x4t},(a%16)*16+b%16)+{buf_r8}({x4t},{mf}(a/16)*16+{mf}(b/16))*16 end;",
                ),
            ),
            _ => (
                String::new(),
                format!("local {decl}=function(a,b)return {band}({bor}(a,b),{bnot}({band}(a,b))) end;"),
            ),
        }
    } else {
        match variant {
            0 => (
                String::new(),
                format!(
                    "local {decl}=function(a,b)local r=0;for j=0,7 do r=r+(a+b)%2*2^j;a={mf}(a/2);b={mf}(b/2)end;return r end;",
                ),
            ),
            1 => (
                String::new(),
                format!(
                    "local {decl}=function(a,b)local r=0;for j=0,1 do local x={mf}(a/16^j)%16;local y={mf}(b/16^j)%16;local z=0;local p=1;for k=0,3 do z=z+(x+y)%2*p;x={mf}(x/2);y={mf}(y/2);p=p*2 end;r=r+z*16^j end;return r end;",
                ),
            ),
            _ => (
                String::new(),
                format!(
                    "local {decl}=function(a,b)local r=0;local p=1;local x,y=a,b;for j=0,7 do if x%2==1 and y%2==1 then r=r+p end;x={mf}(x/2);y={mf}(y/2);p=p*2 end;return a+b-2*r end;",
                ),
            ),
        }
    }
}

/// 32-bit xor bodies over `(a, b)` below 2^32. `tag` suffixes closure-local
/// table names so both dual closures stay self-contained. Callers pass the
/// image rng for the opaque-weight variant.
pub(crate) fn render_x32(
    target: Target,
    variant: usize,
    decl: &str,
    tag: &str,
    n: &BitNames,
    rng: &mut crate::random::Prng,
) -> (String, String) {
    assert!(variant < 3, "K7: x32 variant out of range");
    let mf = n.mf;
    if target.is_luau() {
        let (bxor, band, bor, bnot) = (n.bxor, n.band, n.bor, n.bnot);
        let (buf_new, buf_w8, buf_r8) = (n.buf_new, n.buf_w8, n.buf_r8);
        match variant {
            0 => (
                String::new(),
                format!("local {decl}=function(a,b)return {bxor}(a,b) end;"),
            ),
            1 => (
                format!(
                    "local XT{tag}={buf_new}(256);for i=0,255 do {buf_w8}(XT{tag},i,{bxor}({mf}(i/16),i%16))end;",
                ),
                format!(
                    "local {decl}=function(a,b)local r=0;local m=1;for j=0,7 do local na={mf}(a/m)%16;local nb={mf}(b/m)%16;r=r+{buf_r8}(XT{tag},na*16+nb)*m;m=m*16 end;return r end;",
                ),
            ),
            _ => (
                String::new(),
                format!("local {decl}=function(a,b)return {band}({bor}(a,b),{bnot}({band}(a,b))) end;"),
            ),
        }
    } else {
        let x8 = n.x8;
        let x8c = n.x8c;
        match variant {
            0 => (
                String::new(),
                format!(
                    "local T{tag}={{}};for a=0,15 do for b=0,15 do T{tag}[a*16+b]={x8c}(a,b)end end;local B{tag}=function(a,b)return T{tag}[a%16*16+b%16]+T{tag}[{mf}(a/16)*16+{mf}(b/16)]*16 end;local {decl}=function(a,b)return B{tag}(a%256,b%256)+B{tag}({mf}(a/256)%256,{mf}(b/256)%256)*256+B{tag}({mf}(a/65536)%256,{mf}(b/65536)%256)*65536+B{tag}({mf}(a/16777216),{mf}(b/16777216))*16777216 end;",
                ),
            ),
            1 => (
                String::new(),
                format!(
                    "local {decl}=function(a,b)return {x8}(a%256,b%256)+{x8}({mf}(a/256)%256,{mf}(b/256)%256)*256+{x8}({mf}(a/65536)%256,{mf}(b/65536)%256)*65536+{x8}({mf}(a/16777216),{mf}(b/16777216))*16777216 end;",
                ),
            ),
            _ => {
                let (w1a, w1b) = opaque_split(rng, 256);
                let (w2a, w2b) = opaque_split(rng, 256);
                let (w3a, w3b) = opaque_split(rng, 16777216);
                (
                    String::new(),
                    format!(
                        "local {decl}=function(a,b)local h0={x8}(a%256,b%256);local h1={x8}({mf}(a/256)%256,{mf}(b/256)%256);local h2={x8}({mf}(a/65536)%256,{mf}(b/65536)%256);local h3={x8}({mf}(a/16777216),{mf}(b/16777216));return h3*({w3a}+{w3b})+(h2*({w1a}+{w1b})+h1)*({w2a}+{w2b})+h0 end;",
                    ),
                )
            }
        }
    }
}

/// Rotate-left bodies over `(x, n)` with x below 2^32 and 1 <= n <= 31.
pub(crate) fn render_rot(
    target: Target,
    variant: usize,
    decl: &str,
    n: &BitNames,
    rng: &mut crate::random::Prng,
) -> String {
    assert!(variant < 3, "K7: rot variant out of range");
    let mf = n.mf;
    if target.is_luau() {
        let (band, bor, bnot) = (n.band, n.bor, n.bnot);
        let (rotl, shl, shr) = (n.rotl, n.shl, n.shr);
        match variant {
            0 => format!("local {decl}=function(x,n)return {rotl}(x,n) end;"),
            1 => format!("local {decl}=function(x,n)return {bor}({shl}(x,n),{shr}(x,32-n)) end;"),
            _ => format!(
                "local {decl}=function(x,n)return {bnot}({band}({bnot}({shl}(x,n)),{bnot}({shr}(x,32-n)))) end;",
            ),
        }
    } else {
        match variant {
            0 => format!("local {decl}=function(x,n)local p=2^(32-n);return x%p*2^n+{mf}(x/p)end;"),
            1 => format!(
                "local {decl}=function(x,n)local P=2^(32-n);local hi={mf}(x/P);local lo=x-hi*P;return lo*2^n+hi end;",
            ),
            _ => {
                let modulus = render_addmod(rng, &format!("{mf}(x/p)+x%p*2^n"));
                format!("local {decl}=function(x,n)local p=2^(32-n);return {modulus} end;")
            }
        }
    }
}

/// Little-endian u32 loads over `(S, p)`. The Luau buffer variant reads
/// through a transient buffer (verified little-endian on the reference
/// runner); all call sites hold at least four bytes past `p`.
pub(crate) fn render_l32(
    target: Target,
    variant: usize,
    decl: &str,
    n: &BitNames,
    rng: &mut crate::random::Prng,
) -> String {
    assert!(variant < 3, "K7: l32 variant out of range");
    if target.is_luau() {
        let (bor, shl) = (n.bor, n.shl);
        let (buf_fromstr, buf_r32) = (n.buf_fromstr, n.buf_r32);
        match variant {
            0 => format!(
                "local {decl}=function(S,p)return {bor}(SB(S,p),{bor}({shl}(SB(S,p+1),8),{bor}({shl}(SB(S,p+2),16),{shl}(SB(S,p+3),24)))) end;",
            ),
            1 => format!(
                "local {decl}=function(S,p)local b0,b1,b2,b3=SB(S,p),SB(S,p+1),SB(S,p+2),SB(S,p+3);return {bor}({bor}({shl}(b3,24),{shl}(b2,16)),{bor}({shl}(b1,8),b0)) end;",
            ),
            _ => format!("local {decl}=function(S,p)return {buf_r32}({buf_fromstr}(S),p-1) end;"),
        }
    } else {
        match variant {
            0 => format!(
                "local {decl}=function(S,p)return SB(S,p)+SB(S,p+1)*256+SB(S,p+2)*65536+SB(S,p+3)*16777216 end;",
            ),
            1 => format!(
                "local {decl}=function(S,p)local b3=SB(S,p+3);local b2=SB(S,p+2);local b1=SB(S,p+1);return b3*16777216+(b2*256+b1)*256+SB(S,p) end;",
            ),
            _ => {
                let (w1a, w1b) = opaque_split(rng, 256);
                let (w2a, w2b) = opaque_split(rng, 65536);
                let (w3a, w3b) = opaque_split(rng, 16777216);
                format!(
                    "local {decl}=function(S,p)return SB(S,p)+SB(S,p+1)*({w1a}+{w1b})+SB(S,p+2)*({w2a}+{w2b})+SB(S,p+3)*({w3a}+{w3b}) end;",
                )
            }
        }
    }
}

/// An opaque 2^32 with no literal pair summing to 2^32: draws `c` in
/// `[2^20, 2^31)` plus an opaque split of `2^32 + c`, rejecting the
/// measure-zero draws where a cross pair lands on 2^32 or two parts collide.
/// `a + b - c == 2^32` always, and `a + b == 2^32 + c` never equals 2^32, so
/// the sandwich `((a+b)-c)` is the only subtraction spelling a mod-2^32 site
/// can use without changing the cipher value.
pub(crate) fn draw_u32_sandwich(rng: &mut crate::random::Prng) -> (u64, u64, u64) {
    loop {
        let c = (1 << 20) + rng.index((1 << 31) - (1 << 20)) as u64;
        if is_nice_part(c) {
            continue;
        }
        let (a, b) = opaque_split(rng, U32_MODULUS + c);
        if a == b || a == c || b == c || a + c == U32_MODULUS || b + c == U32_MODULUS {
            continue;
        }
        return (a, b, c);
    }
}

/// One modular-sum spelling draw over three exactly-equal forms: the bare
/// literal, a subtraction sandwich `((a+b)-c)`, or an explicit double
/// modulus `((sum) % (2^33 split)) % 2^32` with a literal outer modulus. No
/// emitted pair sums to 2^32: the sandwich pairs sum to `2^32 + c` or dodge
/// it by rejection, and the double-modulus inner pair sums to 2^33. `sum`
/// is already the full `+`-joined text.
pub(crate) fn render_addmod(rng: &mut crate::random::Prng, sum: &str) -> String {
    match rng.index(3) {
        0 => format!("({sum})%{U32_MODULUS}"),
        1 => {
            let (a, b, c) = draw_u32_sandwich(rng);
            format!("({sum})%(({a}+{b})-{c})")
        }
        _ => {
            let (c, d) = opaque_split(rng, U32_DOUBLE_MODULUS);
            format!("(({sum})%({c}+{d}))%{U32_MODULUS}")
        }
    }
}

/// The same draw for a bare 2^32 bound/factor (comparison guards and the
/// double-reconstruction multiplier spell it without `%`).
pub(crate) fn render_u32_atom(rng: &mut crate::random::Prng) -> String {
    if rng.index(2) == 0 {
        U32_MODULUS.to_string()
    } else {
        let (a, b, c) = draw_u32_sandwich(rng);
        format!("(({a}+{b})-{c})")
    }
}

/// Shuffled modular sum in one call (single borrow at use sites).
pub(crate) fn render_sum(rng: &mut crate::random::Prng, terms: &[&str]) -> String {
    assert!(terms.len() >= 2, "K7: modular sums need two terms");
    let mut order: Vec<&str> = terms.to_vec();
    rng.shuffle(&mut order);
    order.join("+")
}

/// Shuffled modular sum in one call (avoids nested `&mut` borrows).
pub(crate) fn render_modsum(rng: &mut crate::random::Prng, terms: &[&str]) -> String {
    let sum = render_sum(rng, terms);
    render_addmod(rng, &sum)
}

/// The word-operations payload field: dual xor closures (two distinct
/// variants) plus dual rotate closures, all self-contained. The Lua 5.1
/// section takes `(MF,X8,X8C)`; Luau additionally takes the twelve
/// bit32/buffer method captures.
pub(crate) fn render_word_section(
    target: Target,
    key: u64,
    rng: &mut crate::random::Prng,
) -> String {
    let n = BitNames::emit();
    let (xa, xb) = draw_dual(rng);
    let (ra, rb) = draw_dual(rng);
    let (pre_a, decl_a) = render_x32(target, xa, "Xa", "a", &n, rng);
    let (pre_b, decl_b) = render_x32(target, xb, "Xb", "b", &n, rng);
    let decl_ra = render_rot(target, ra, "Ra", &n, rng);
    let decl_rb = render_rot(target, rb, "Rb", &n, rng);
    let params = if target.is_luau() {
        "MF,X8,X8C,BX,BA,BO,BN,LR,SHL,RS,BNE,BW8,BR8,BFS,BR3"
    } else {
        "MF,X8,X8C"
    };
    format!(
        "[{key}]=function({params}){pre_a}{pre_b}{decl_a}{decl_b}{decl_ra}{decl_rb}return Xa,Xb,Ra,Rb end,"
    )
}
