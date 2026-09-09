//! P1 per-seed deformation of the seed-loop template (split from `seed.rs`
//! under the permanent 80 KiB source-file ceiling; generated output is
//! unchanged by the split).

use super::seed::{
    KIND_HELPER, KIND_OPVAL, KIND_PSEUDO, KIND_REG, KIND_SCONST, KIND_TMP, OP_BR, OP_CALL, OP_RET,
};
use crate::bytecode::custom::Opcode;
use crate::random::Prng;

// ---- P1 per-seed template deformation -----------------------------------
// Every image seed gets a textually distinct but semantically identical
// seed loop: mutually-exclusive if/elseif branches commute freely (exactly
// one condition can hold, no fallthrough, no side effects in conditions),
// so branch ORDER is a per-seed cosmetic choice. Six structural passes
// plus a number respeller draw from independent sub-streams of the image
// seed (`seed ^ DOMAIN ^ region`), so regions never share draws and the
// same seed always yields byte-identical output.
//
// Fail-closed: every pass asserts exact anchor counts/shapes, so any drift
// of the audited template panics here instead of emitting a silently
// half-deformed loop. Audit surface stays decimal-canonical (see below).
const P1_DOMAIN_TEMPLATE: u64 = 0x5031_544D_504C_4154;

fn p1_stream(seed: u64, region: u64) -> Prng {
    Prng::new(seed ^ P1_DOMAIN_TEMPLATE ^ region)
}

/// Split one branch line (`if`/`elseif` + condition + `then` + optional body).
fn p1_branch(line: &str) -> (String, String) {
    let rest = line
        .strip_prefix("if ")
        .or_else(|| line.strip_prefix("elseif "))
        .unwrap_or_else(|| panic!("P1: branch lost its if/elseif prefix: {line}"));
    if let Some((cond, body)) = rest.split_once(" then ") {
        (cond.to_owned(), body.to_owned())
    } else if let Some(cond) = rest.strip_suffix(" then") {
        (cond.to_owned(), String::new())
    } else {
        panic!("P1: branch lost its 'then': {line}");
    }
}

fn p1_emit(first: bool, cond: &str, body: &str) -> String {
    let head = if first { "if" } else { "elseif" };
    if body.is_empty() {
        format!("{head} {cond} then")
    } else {
        format!("{head} {cond} then {body}")
    }
}

/// Region 1: permute the 12 op arms as (condition, body-line) units. The
/// `else seedfail(4)end;` tail stays put; conditions travel with bodies.
fn p1_deform_op_chain(lines: &mut Vec<String>, rng: &mut Prng) {
    let head = lines
        .iter()
        .position(|l| l == "if op==1 then")
        .expect("P1: op-chain head gone");
    let tail = lines
        .iter()
        .position(|l| l == "else seedfail(4)end;")
        .expect("P1: op-chain tail gone");
    assert!(tail > head + 1, "P1: op-chain tail before head");
    let mut starts = vec![head];
    for i in head + 1..tail {
        if lines[i].starts_with("elseif op==") && lines[i].ends_with(" then") {
            starts.push(i);
        }
    }
    assert_eq!(
        starts.len(),
        12,
        "P1: op-chain must hold exactly 12 arms, found {}",
        starts.len()
    );
    assert_eq!(
        lines.iter().filter(|l| l.contains("elseif op==")).count(),
        11,
        "P1: stray op-chain delimiter outside the chain"
    );
    let mut arms = Vec::with_capacity(12);
    for (k, &s) in starts.iter().enumerate() {
        let e = if k + 1 < starts.len() {
            starts[k + 1]
        } else {
            tail
        };
        let (cond, head_body) = p1_branch(&lines[s]);
        assert!(
            head_body.is_empty(),
            "P1: op-chain head carries a body: {}",
            lines[s]
        );
        let op: u32 = cond
            .strip_prefix("op==")
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("P1: bad op condition: {cond}"));
        assert!((1..=12).contains(&op), "P1: op out of range: {cond}");
        arms.push((op, cond, lines[s + 1..e].to_vec()));
    }
    let mut ops: Vec<u32> = arms.iter().map(|a| a.0).collect();
    ops.sort_unstable();
    ops.dedup();
    assert_eq!(ops.len(), 12, "P1: duplicated op arm");
    rng.shuffle(&mut arms);
    let mut out = Vec::with_capacity(tail - head);
    for (i, (_, cond, body)) in arms.iter().enumerate() {
        out.push(p1_emit(i == 0, cond, ""));
        out.extend(body.iter().cloned());
    }
    lines.splice(head..tail, out);
}

/// Regions 2-3: permute a run of single-line branches (`head_line` .. the
/// line before `tail_line`); the else-tail stays put.
fn p1_deform_branch_run(
    lines: &mut Vec<String>,
    head_line: &str,
    tail_line: &str,
    elseif_prefix: &str,
    expected: usize,
    rng: &mut Prng,
) {
    let head = lines
        .iter()
        .position(|l| l == head_line)
        .unwrap_or_else(|| panic!("P1: branch head gone: {head_line}"));
    let tail = lines
        .iter()
        .position(|l| l == tail_line)
        .unwrap_or_else(|| panic!("P1: branch tail gone: {tail_line}"));
    assert_eq!(
        tail - head,
        expected,
        "P1: branch run holds {}, want {expected}: {head_line}",
        tail - head
    );
    for line in &lines[head + 1..tail] {
        assert!(
            line.starts_with(elseif_prefix),
            "P1: branch run drifted: {line}"
        );
    }
    let mut branches: Vec<(String, String)> =
        lines[head..tail].iter().map(|l| p1_branch(l)).collect();
    rng.shuffle(&mut branches);
    for (i, (cond, body)) in branches.iter().enumerate() {
        lines[head + i] = p1_emit(i == 0, cond, body);
    }
}

const P1_RET_MEMBERS: [&str; 3] = [
    "if #q==2 then if a~=0 then seedfail(5)end;return nil,0;",
    "elseif #q==3 then if a==0 or a==3 then seedfail(5)end;return rv(q[3]),a;",
    "elseif #q==5 then if a~=3 then seedfail(5)end;return rv(q[3]),rv(q[4]),rv(q[5]),a;",
];

const P1_BR_MEMBERS: [&str; 2] = [
    "if #q==2 then ip=tgtc(q[2]);",
    "elseif #q==3 then local cv,t=dstc(q[2]),tgtc(q[3]);if tmp[cv] then ip=t else ip=ip+1 end;",
];

/// Regions 4a-4b: permute a set of full-line branches found by exact match.
/// Full lines disambiguate the two `#q==2` arms (RET vs BR).
fn p1_deform_line_set(lines: &mut Vec<String>, members: &[&str], rng: &mut Prng) {
    let mut pos = Vec::with_capacity(members.len());
    for m in members {
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l == m)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1, "P1: anchor must occur exactly once: {m}");
        pos.push(hits[0]);
    }
    pos.sort_unstable();
    for w in pos.windows(2) {
        assert_eq!(w[1], w[0] + 1, "P1: branch set is no longer contiguous");
    }
    let mut branches: Vec<(String, String)> = pos.iter().map(|&i| p1_branch(&lines[i])).collect();
    rng.shuffle(&mut branches);
    for (k, &i) in pos.iter().enumerate() {
        let (cond, body) = &branches[k];
        lines[i] = p1_emit(k == 0, cond, body);
    }
}

const P1_EXPECT_FORMS: [&str; 3] = [
    "expect=expect or 0;if expect~=9 and a~=expect then E()end;",
    "expect=expect or 0;if expect~=9 then if a~=expect then E()end end;",
    "expect=expect or 0;if a~=expect and expect~=9 then E()end;",
];

/// Region 4c: spell the expect check in one of three equivalent forms (the
/// `and` operands are pure, so nesting and order are cosmetic).
fn p1_deform_expect(lines: &mut Vec<String>, rng: &mut Prng) {
    assert_eq!(
        lines.iter().filter(|l| l.contains("expect~=9")).count(),
        1,
        "P1: expect anchor drifted"
    );
    let at = lines
        .iter()
        .position(|l| l == P1_EXPECT_FORMS[0])
        .expect("P1: expect line reshaped");
    lines[at] = P1_EXPECT_FORMS[rng.index(3)].to_owned();
}

fn p1_word_byte(c: u8) -> bool {
    matches!(c, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'.')
}

fn p1_number_value(form: &str) -> u64 {
    if let Some(hex) = form.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).expect("P1 respell: bad hex")
    } else if let Some(e) = form.find('e') {
        let mantissa: u64 = form[..e].parse().expect("P1 respell: bad sci");
        let exp: u32 = form[e + 1..].parse().expect("P1 respell: bad sci exp");
        mantissa * 10u64.pow(exp)
    } else {
        form.parse().expect("P1 respell: bad decimal")
    }
}

/// Choose one spelling for a decimal literal: itself, lowercase/uppercase
/// hex, or exact trailing-zero scientific forms. A form is eligible only
/// when it costs at most 2 extra bytes, and the picked form must parse
/// back to the identical value.
pub(crate) fn p1_number_form(dec: &str, rng: &mut Prng) -> String {
    // Audit surface stays decimal-canonical: only 3+ digit literals respell
    // (every seedfail code, op number and small bound keeps its spelling),
    // and the fuel budget is exempt so the capacity audit keeps grepping.
    if dec.len() < 3 {
        return dec.to_owned();
    }
    let value: u64 = dec.parse().expect("P1 respell: bad literal");
    assert!(value < (1 << 53), "P1 respell: literal exceeds 2^53");
    if value == 100_000 {
        return dec.to_owned();
    }
    let mut forms = vec![dec.to_owned()];
    for hex in [format!("0x{value:x}"), format!("0x{value:X}")] {
        if hex.len() <= dec.len() + 2 && !forms.contains(&hex) {
            forms.push(hex);
        }
    }
    if value > 0 {
        let mut scale = 10u64;
        let mut exp = 1u32;
        while exp < 19 && value % scale == 0 {
            let sci = format!("{}e{exp}", value / scale);
            if sci.len() <= dec.len() + 2 && !forms.contains(&sci) {
                forms.push(sci);
            }
            scale *= 10;
            exp += 1;
        }
    }
    let picked = forms[rng.index(forms.len())].clone();
    assert_eq!(
        p1_number_value(&picked),
        value,
        "P1 respell changed a value"
    );
    picked
}

/// Region 5: respell eligible integer literals (3+ digits, budget exempt).
/// String contents are skipped; a literal must sit between two non-word
/// bytes so identifiers, floats and concat runs are never touched.
fn p1_respell_numbers(src: &str, rng: &mut Prng) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len() + 128);
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            out.push(c as char);
            if c == b'\\' {
                i += 1;
                if i < bytes.len() {
                    out.push(bytes[i] as char);
                }
            } else if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let dec = &src[start..i];
            let left_ok = start == 0 || !p1_word_byte(bytes[start - 1]);
            let right_ok = i >= bytes.len() || !p1_word_byte(bytes[i]);
            if left_ok && right_ok {
                out.push_str(&p1_number_form(dec, rng));
            } else {
                out.push_str(dec);
            }
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    assert!(!in_string, "P1 respell: unterminated string literal");
    assert!(
        out.len() <= src.len() + 128,
        "P1 respell grew the template by {}B",
        out.len().saturating_sub(src.len())
    );
    out
}

pub(crate) fn p1_deform_template(body: &str, seed: u64) -> String {
    let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();
    let line_count = lines.len();
    p1_deform_op_chain(&mut lines, &mut p1_stream(seed, 1));
    p1_deform_branch_run(
        &mut lines,
        "if oi5==0 then r=x+y;",
        "else r=#x;end;",
        "elseif oi5==",
        13,
        &mut p1_stream(seed, 2),
    );
    p1_deform_branch_run(
        &mut lines,
        "if kind==0 then if vi>15 or vo~=0 then seedfail(9)end;return tmp[vi];",
        "else if vi>=9 or vo~=0 then seedfail(20)end;return site[vi+1];end end;",
        "elseif kind==",
        8,
        &mut p1_stream(seed, 3),
    );
    {
        let mut region = p1_stream(seed, 4);
        p1_deform_line_set(&mut lines, &P1_RET_MEMBERS, &mut region);
        p1_deform_line_set(&mut lines, &P1_BR_MEMBERS, &mut region);
        p1_deform_expect(&mut lines, &mut region);
    }
    assert_eq!(
        lines.len(),
        line_count,
        "P1: structural pass changed the line count"
    );
    p4_alu_forms(&mut lines, &mut p1_stream(seed, 6));
    p4_chain_perms(&mut lines, &mut p1_stream(seed, 7));
    let inserted = p4_dead_temps(&mut lines, &mut p1_stream(seed, 8));
    p5_arm_forms(&mut lines, &mut p1_stream(seed, 9));
    assert_eq!(
        lines.len(),
        line_count + inserted,
        "P1: line-count accounting drifted"
    );
    let joined = lines.join("\n");
    p1_respell_numbers(&joined, &mut p1_stream(seed, 5))
}

// ---- P1 Batch-3: helper + reader-group emission variants ----------------
// Pure per-seed mechanisms: CV/SV
// branch flips, Lookup method-chain order, and the six byte-reader
// definitions in seeded topological order. Fresh domain-separated streams
// keep every other seeded choice byte-identical.
const P3_DOMAIN_HELPER: u64 = 0x5031_4845_4C50_4552;
const P3_DOMAIN_POOLS: u64 = 0x5031_504F_4F4C_5353;

const P3_CV_FORMS: [&str; 2] = [
    "local CV=function(cell)if cell[2]then return cell[2][cell[3]]else return cell[1]end end;",
    "local CV=function(cell)if not cell[2]then return cell[1]else return cell[2][cell[3]]end end;",
];

const P3_SV_FORMS: [&str; 2] = [
    "local SV=function(cell,value)if cell[2]then cell[2][cell[3]]=value else cell[1]=value end end;",
    "local SV=function(cell,value)if not cell[2]then cell[1]=value else cell[2][cell[3]]=value end end;",
];

/// Cell-value read in one of two branch orders (exact `not`-negation:
/// same conditions, same read sequence on every path, no eval reorder).
pub(crate) fn p3_cv_lua(seed: u64) -> &'static str {
    let pick = Prng::new(seed ^ P3_DOMAIN_HELPER ^ 1).next_u64() % 2;
    P3_CV_FORMS[pick as usize]
}

/// Cell-value write in one of two branch orders (same argument as CV).
pub(crate) fn p3_sv_lua(seed: u64) -> &'static str {
    let pick = Prng::new(seed ^ P3_DOMAIN_HELPER ^ 2).next_u64() % 2;
    P3_SV_FORMS[pick as usize]
}

/// Seeded order of the Lookup method chain. Methods are distinct keys so
/// the equality arms are mutually exclusive and commute freely.
pub(crate) fn p3_lookup_order(n: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..n).collect();
    Prng::new(seed ^ P3_DOMAIN_HELPER ^ 3).shuffle(&mut order);
    order
}

const P3_READER_HEAD: &str = "local bp=1;";
const P3_READERS: [&str; 6] = [
    "local b8=function()local v=SB(B,bp);if v==nil then E()end;bp=bp+1;return v end;",
    "local b16=function()local a,b=b8(),b8();return a+b*256 end;",
    "local b32=function()local a,b,c,d=b8(),b8(),b8(),b8();return a+b*256+c*65536+d*16777216 end;",
    "local take=function(n)if n>#B-bp+1 then E()end;local v=SS(B,bp,bp+n-1);bp=bp+n;return v end;",
    "local str=function()return take(b32())end;",
    "local pos=function()return bp end;",
];

// Intra-group upvalue dependencies by reader index (b8=0, b16=1, b32=2,
// take=3, str=4, pos=5): a definition must follow the readers it calls.
const P3_READER_DEPS: [&[usize]; 6] = [&[], &[0], &[0], &[], &[2, 3], &[]];

/// The six byte-reader definitions in seeded topological order (Kahn's
/// algorithm with seeded choice among ready nodes): every order keeps each
/// definition behind the readers it closes over, so upvalue scope is exact.
pub(crate) fn p3_reader_group_lua(seed: u64) -> String {
    let mut rng = Prng::new(seed ^ P3_DOMAIN_POOLS ^ 1);
    let mut emitted = [false; 6];
    let mut out = String::from(P3_READER_HEAD);
    for _ in 0..6 {
        let mut ready = Vec::new();
        for (i, deps) in P3_READER_DEPS.iter().enumerate() {
            if !emitted[i] && deps.iter().all(|d| emitted[*d]) {
                ready.push(i);
            }
        }
        assert!(!ready.is_empty(), "P3: reader dependency cycle");
        let pick = ready[rng.index(ready.len())];
        emitted[pick] = true;
        out.push('\n');
        out.push_str(P3_READERS[pick]);
    }
    out
}

// ---- P1 Batch-4: ALU forms + chain perms + dead temps -------------------

/// One ALU binary site: canonical body plus temp-split spelling. Split
/// preserves left-to-right evaluation of locals (unobservable, hence safe
/// even under metamethods: the operator sees identical argument values).
struct P4AluSite {
    oi5: u32,
    plain: &'static str,
    split: &'static str,
    /// Comparison duality (`<` <-> `>`, `<=` <-> `>=`): exact by language
    /// definition (`a>b` IS `b<a`, including metamethod dispatch).
    /// Arithmetic/`==` swaps are excluded (`__add`/`__eq` dispatch order).
    dual: Option<(&'static str, &'static str)>,
}

const P4_ALU_SITES: [P4AluSite; 10] = [
    P4AluSite {
        oi5: 0,
        plain: "r=x+y;",
        split: "local u1=x;r=u1+y;",
        dual: None,
    },
    P4AluSite {
        oi5: 1,
        plain: "r=x-y;",
        split: "local u2=x;r=u2-y;",
        dual: None,
    },
    P4AluSite {
        oi5: 2,
        plain: "r=x*y;",
        split: "local u3=x;r=u3*y;",
        dual: None,
    },
    P4AluSite {
        oi5: 3,
        plain: "r=x/y;",
        split: "local u4=x;r=u4/y;",
        dual: None,
    },
    P4AluSite {
        oi5: 4,
        plain: "r=x%y;",
        split: "local u5=x;r=u5%y;",
        dual: None,
    },
    P4AluSite {
        oi5: 5,
        plain: "r=x^y;",
        split: "local u6=x;r=u6^y;",
        dual: None,
    },
    P4AluSite {
        oi5: 8,
        plain: "r=(x==y);",
        split: "local u7=x;r=(u7==y);",
        dual: None,
    },
    P4AluSite {
        oi5: 9,
        plain: "r=x..y;",
        split: "local u8=x;r=u8..y;",
        dual: None,
    },
    P4AluSite {
        oi5: 10,
        plain: "r=x<y;",
        split: "local u9=x;r=u9<y;",
        dual: Some(("r=y>x;", "local u9=y;r=u9>x;")),
    },
    P4AluSite {
        oi5: 11,
        plain: "r=x<=y;",
        split: "local u10=x;r=u10<=y;",
        dual: Some(("r=y>=x;", "local u10=y;r=u10>=x;")),
    },
];

/// P4: spell each ALU binary line in one of its equivalent forms. Runs
/// after branch permutation on exact canonical bodies (position-free).
fn p4_alu_forms(lines: &mut Vec<String>, rng: &mut Prng) {
    for site in P4_ALU_SITES {
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                l.contains(&format!("oi5=={} then ", site.oi5)) && l.ends_with(site.plain)
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "P4: ALU site lost its canonical line: oi5=={}",
            site.oi5
        );
        let at = hits[0];
        let (cond, body) = p1_branch(&lines[at]);
        assert_eq!(
            body, site.plain,
            "P4: ALU site body drifted: oi5=={}",
            site.oi5
        );
        let first = lines[at].starts_with("if ");
        let drawn = match site.dual {
            None => [site.plain, site.split][rng.index(2)],
            Some((dual, dual_split)) => [site.plain, site.split, dual, dual_split][rng.index(4)],
        };
        lines[at] = p1_emit(first, &cond, drawn);
    }
}

/// Pure and/or operand chains. A chain is permutable only when every
/// operand is total (`==`/`~=` never fault) or provably numeric at that
/// point (refd outputs, arithmetic results, SEED-internal `ip`). Chains
/// whose later operands fault on mistyped input (nargs/tgtc: `%`/`<` on
/// arbitrary `rv()` values) pin their type check first and permute only
/// the narrowed suffix (40-vector gate caught the unpinned form: raw
/// arithmetic error instead of seedfail). Guards with no freedom after
/// pinning (refd head, stix) are excluded; the expect-check is Batch-1.
pub(crate) struct P4Chain {
    pub open: &'static str,
    pub inner: &'static str,
    pub close: &'static str,
    pub sep: &'static str,
    pub pinned: usize,
    /// Stable witness for gates (survives B4b permutation, P5 spans, respell).
    pub witness: &'static str,
}

pub(crate) const P4_CHAINS: [P4Chain; 20] = [
    P4Chain {
        open: "if ",
        inner: "ip<1 or ip>#prog",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(2)",
    },
    P4Chain {
        open: "if ",
        inner: "vi>15 or vo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(9)",
    },
    P4Chain {
        open: "if ",
        inner: "vi>2 or vo>255 or vo%1~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(10)",
    },
    P4Chain {
        open: "if ",
        inner: "vi~=3 or vo>255 or vo%1~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(12)",
    },
    P4Chain {
        open: "if ",
        inner: "vi>999999 or vo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(14)",
    },
    P4Chain {
        open: "if ",
        inner: "vi==0 or vi==1",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(15)",
    },
    P4Chain {
        open: "if ",
        inner: "vi>9 or vo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(16)",
    },
    P4Chain {
        open: "if ",
        inner: "vi>=SN or vo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(17)",
    },
    P4Chain {
        open: "if ",
        inner: "vi~=0 or vo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(18)",
    },
    P4Chain {
        open: "if ",
        inner: "vi>=HN or vo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(19)",
    },
    P4Chain {
        open: "if ",
        inner: "vi>=9 or vo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(20)",
    },
    P4Chain {
        open: "if ",
        inner: "kind~=0 or vi>15 or vo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(8)",
    },
    P4Chain {
        open: "if ",
        inner: "kind<0 or kind>8 or kind%1~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(7)",
    },
    P4Chain {
        open: "if ",
        inner: "ok5~=3 or oi5>13 or oo5~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(22)",
    },
    P4Chain {
        open: "if ",
        inner: "TY(nargs)~=TNUM or nargs<0 or nargs>8 or nargs%1~=0",
        close: " then",
        sep: " or ",
        pinned: 1,
        witness: "seedfail(25)",
    },
    P4Chain {
        open: "if ",
        inner: "mk~=3 or mv>2 or mo~=0",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "seedfail(27)",
    },
    P4Chain {
        open: "if ",
        inner: "TY(t)~=TNUM or t<1 or t>#prog or t%1~=0",
        close: " then",
        sep: " or ",
        pinned: 1,
        witness: "seedfail(32)",
    },
    P4Chain {
        open: "if ",
        inner: "a~=0 and a~=1 and a~=2 and a~=3",
        close: " then",
        sep: " and ",
        pinned: 0,
        witness: "seedfail(34)",
    },
    P4Chain {
        open: "if ",
        inner: "a==0 or a==3",
        close: " then",
        sep: " or ",
        pinned: 0,
        witness: "a==0",
    },
    P4Chain {
        open: "(",
        inner: "v~=nil and v~=false",
        close: ")",
        sep: " and ",
        pinned: 0,
        witness: "local v=rv(q[3]);",
    },
];

/// P4: permute each chain's free suffix (pinned type checks stay first).
/// `P4_CHAINS` is the single source of truth (the lock gate reads it).
fn p4_chain_perms(lines: &mut Vec<String>, rng: &mut Prng) {
    for chain in P4_CHAINS {
        let needle = format!("{}{}{}", chain.open, chain.inner, chain.close);
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains(&needle))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1, "P4: chain anchor drifted: {needle}");
        let operands: Vec<&str> = chain.inner.split(chain.sep).collect();
        assert!(operands.len() >= 2, "P4: chain too short: {needle}");
        assert!(
            chain.pinned < operands.len(),
            "P4: chain over-pinned: {needle}"
        );
        let (head, mut tail) = operands.split_at(chain.pinned);
        let mut tail = tail.to_vec();
        rng.shuffle(&mut tail);
        let mut reordered = head.to_vec();
        reordered.extend(tail);
        let rebuilt = format!("{}{}{}", chain.open, reordered.join(chain.sep), chain.close);
        for op in operands {
            assert!(rebuilt.contains(op), "P4: chain lost an operand: {op}");
        }
        lines[hits[0]] = lines[hits[0]].replacen(&needle, &rebuilt, 1);
    }
}
/// Dead-temporary insertion points: (exact anchor line, seeded name). All
/// names are asserted absent before insertion (fail-closed vs drift).
const P4_DEAD_POINTS: [(&str, &str); 6] = [
    (
        "local TNUM,TFUN,TTAB,SN,HN,tmp=TY(0),TY(E),TY(STAB),#STAB,#SEEDH,{};",
        "q1",
    ),
    ("return kind,vi,vo end;", "q2"),
    ("return vi end;", "q3"),
    ("local op=q[1];", "q4"),
    ("tmp[dstc(q[2])]=rv(q[3]);ip=ip+1;", "q5"),
    ("E();ip=ip+1;", "q6"),
];

/// P4: insert `local qN=<digit>;` after fixed anchors (pure literal, never
/// read; single digit so the respeller draws nothing). Returns the count.
fn p4_dead_temps(lines: &mut Vec<String>, rng: &mut Prng) -> usize {
    for (_, name) in P4_DEAD_POINTS {
        assert!(
            !lines.iter().any(|l| l.contains(name)),
            "P4: dead-temp name collides: {name}"
        );
    }
    let mut inserted = 0;
    for (anchor, name) in P4_DEAD_POINTS {
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| *l == anchor)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits.len(), 1, "P4: dead-temp anchor drifted: {anchor}");
        if rng.index(2) == 1 {
            let value = rng.index(10);
            lines.insert(hits[0] + 1, format!("local {name}={value};"));
            inserted += 1;
        }
    }
    inserted
}

/// P5 (Batch-5) arm-body deformation table: one entry per span operation.
/// Matching runs on post-B1..B4 text: `line` (plus optional `prev` arm-header
/// substring) locates exactly one line, then `canon` must occur exactly once
/// in it. Duals apply before splits; all spans are disjoint by construction
/// (checked at runtime: no variant may contain any canon span).
pub(crate) struct P5Site {
    pub(crate) prev: Option<&'static str>,
    pub(crate) line: &'static str,
    pub(crate) canon: &'static str,
    pub(crate) variant: &'static str,
    pub(crate) temp: Option<&'static str>,
}

pub(crate) const P5_SITES: &[P5Site] = &[
    // Size-check duals (2-line needles: identical text across arms).
    P5Site {
        prev: Some("op==1 then"),
        line: "if #q~=3 then seedfail(5)end;",
        canon: "#q~=3",
        variant: "3~=#q",
        temp: None,
    },
    P5Site {
        prev: Some("op==2 then"),
        line: "if #q~=3 then seedfail(5)end;",
        canon: "#q~=3",
        variant: "3~=#q",
        temp: None,
    },
    P5Site {
        prev: Some("op==3 then"),
        line: "if #q~=3 then seedfail(5)end;",
        canon: "#q~=3",
        variant: "3~=#q",
        temp: None,
    },
    P5Site {
        prev: Some("op==8 then"),
        line: "if #q~=3 then seedfail(5)end;",
        canon: "#q~=3",
        variant: "3~=#q",
        temp: None,
    },
    P5Site {
        prev: Some("op==9 then"),
        line: "if #q~=3 then seedfail(5)end;",
        canon: "#q~=3",
        variant: "3~=#q",
        temp: None,
    },
    P5Site {
        prev: Some("op==10 then"),
        line: "if #q~=4 then seedfail(5)end;",
        canon: "#q~=4",
        variant: "4~=#q",
        temp: None,
    },
    P5Site {
        prev: Some("op==11 then"),
        line: "if #q~=4 then seedfail(5)end;",
        canon: "#q~=4",
        variant: "4~=#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "if #q~=5 then seedfail(5)end;",
        canon: "#q~=5",
        variant: "5~=#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "if #q~=5+nargs then seedfail(5)end;",
        canon: "#q~=5+nargs",
        variant: "5+nargs~=#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "if #q~=1 then seedfail(5)end;",
        canon: "#q~=1",
        variant: "1~=#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "#q==2 then ip=tgtc(q[2]);",
        canon: "#q==2",
        variant: "2==#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "#q==3 then local cv,t=",
        canon: "#q==3",
        variant: "3==#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "#q==2 then if a~=0 then seedfail(5)end;return nil,0;",
        canon: "#q==2",
        variant: "2==#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "if a~=0 then seedfail(5)end;return nil,0;",
        canon: "if a~=0 then",
        variant: "if 0~=a then",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "#q==3 then if a",
        canon: "#q==3",
        variant: "3==#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "#q==5 then if a~=3 then seedfail(5)end;return rv(q[3]),rv(q[4]),rv(q[5]),a;",
        canon: "#q==5",
        variant: "5==#q",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "if a~=3 then seedfail(5)end;return rv(q[3]),rv(q[4]),rv(q[5]),a;",
        canon: "if a~=3 then",
        variant: "if 3~=a then",
        temp: None,
    },
    // ip-step duals (standalone op4/op5 lines take prev-line context).
    P5Site {
        prev: None,
        line: "tmp[dstc(q[2])]=rv(q[3]);ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "local v=rv(q[3]);tmp[dstc(q[2])]=",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "tmp[dstc(q[2])]={};ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: Some("tmp[dstc(q[2])]=r;"),
        line: "ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: Some("else tmp[dv]=f(Z(U(ag,1,nargs)));end;"),
        line: "ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "local si=rv(q[2]);R[RX(stix(si))]=rv(q[3]);ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "local li=rv(q[3]);tmp[dstc(q[2])]=R[RX(stix(li))];ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "tmp[dstc(q[2])]=rv(q[3])[rv(q[4])];ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "rv(q[2])[rv(q[3])]=rv(q[4]);ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "E();ip=ip+1;",
        canon: "ip=ip+1;",
        variant: "ip=1+ip;",
        temp: None,
    },
    // Guard duals (B4b-chain interiors excluded: already permuted).
    P5Site {
        prev: None,
        line: "if TY(l)~=TNUM then seedfail(21)end;",
        canon: "TY(l)~=TNUM",
        variant: "TNUM~=TY(l)",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "local f=rv(q[3]);if TY(f)~=TFUN then seedfail(26)end;",
        canon: "TY(f)~=TFUN",
        variant: "TFUN~=TY(f)",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "if nargs~=1 then seedfail(29)end;",
        canon: "nargs~=1",
        variant: "1~=nargs",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "local t=ag[1];if TY(t)~=TTAB then seedfail(30)end;",
        canon: "TY(t)~=TTAB",
        variant: "TTAB~=TY(t)",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "local m=t.n;if m==nil then m=#t end;",
        canon: "m==nil",
        variant: "nil==m",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "if m>8 then seedfail(31)end;",
        canon: "m>8",
        variant: "8<m",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "expect~=9",
        canon: "expect~=9",
        variant: "9~=expect",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "a~=expect",
        canon: "a~=expect",
        variant: "expect~=a",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "if tmp[cv] then ip=t else ip=ip+1 end;",
        canon: "if tmp[cv] then ip=t else ip=ip+1 end;",
        variant: "if not tmp[cv] then ip=ip+1 else ip=t end;",
        temp: None,
    },
    // Temp-splits (within-line, key-side-first per dual-target probe).
    P5Site {
        prev: None,
        line: "tmp[dstc(q[2])]=rv(q[3]);",
        canon: "tmp[dstc(q[2])]=rv(q[3]);",
        variant: "local w1=dstc(q[2]);tmp[w1]=rv(q[3]);",
        temp: Some("w1"),
    },
    P5Site {
        prev: None,
        line: "local v=rv(q[3]);tmp[dstc(q[2])]=",
        canon: "local v=rv(q[3]);tmp[dstc(q[2])]=",
        variant: "local v=rv(q[3]);local w2=dstc(q[2]);tmp[w2]=",
        temp: Some("w2"),
    },
    P5Site {
        prev: None,
        line: "tmp[dstc(q[2])]={};",
        canon: "tmp[dstc(q[2])]={};",
        variant: "local w3=dstc(q[2]);tmp[w3]={};",
        temp: Some("w3"),
    },
    P5Site {
        prev: None,
        line: "tmp[dv]=f(U(ag,1,nargs));",
        canon: "tmp[dv]=f(U(ag,1,nargs));",
        variant: "local w4=f(U(ag,1,nargs));tmp[dv]=w4;",
        temp: Some("w4"),
    },
    P5Site {
        prev: None,
        line: "tmp[dv]=f(U(t,1,m));",
        canon: "tmp[dv]=f(U(t,1,m));",
        variant: "local w5=f(U(t,1,m));tmp[dv]=w5;",
        temp: Some("w5"),
    },
    P5Site {
        prev: None,
        line: "tmp[dv]=f(Z(U(ag,1,nargs)));",
        canon: "tmp[dv]=f(Z(U(ag,1,nargs)));",
        variant: "local w6=f(Z(U(ag,1,nargs)));tmp[dv]=w6;",
        temp: Some("w6"),
    },
    P5Site {
        prev: None,
        line: "for i=1,nargs do ag[i]=rv(q[5+i])end;",
        canon: "ag[i]=rv(q[5+i])",
        variant: "local w7=rv(q[5+i]);ag[i]=w7;",
        temp: Some("w7"),
    },
    P5Site {
        prev: None,
        line: "then ip=tgtc(q[2]);",
        canon: "ip=tgtc(q[2]);",
        variant: "local w8=tgtc(q[2]);ip=w8;",
        temp: Some("w8"),
    },
    P5Site {
        prev: None,
        line: "local cv,t=dstc(q[2]),tgtc(q[3]);",
        canon: "local cv,t=dstc(q[2]),tgtc(q[3]);",
        variant: "local cv=dstc(q[2]);local t=tgtc(q[3]);",
        temp: None,
    },
    P5Site {
        prev: None,
        line: "expect=expect or 0;",
        canon: "expect=expect or 0;",
        variant: "local w9=expect or 0;expect=w9;",
        temp: Some("w9"),
    },
    P5Site {
        prev: None,
        line: "return rv(q[3]),a;",
        canon: "return rv(q[3]),a;",
        variant: "local w10=rv(q[3]);return w10,a;",
        temp: Some("w10"),
    },
    P5Site {
        prev: None,
        line: "return rv(q[3]),rv(q[4]),rv(q[5]),a;",
        canon: "return rv(q[3]),rv(q[4]),rv(q[5]),a;",
        variant: "local w11=rv(q[3]);return w11,rv(q[4]),rv(q[5]),a;",
        temp: Some("w11"),
    },
    P5Site {
        prev: None,
        line: "R[RX(stix(si))]=rv(q[3]);",
        canon: "R[RX(stix(si))]=rv(q[3]);",
        variant: "local w12=RX(stix(si));R[w12]=rv(q[3]);",
        temp: Some("w12"),
    },
    P5Site {
        prev: None,
        line: "tmp[dstc(q[2])]=R[RX(stix(li))];",
        canon: "tmp[dstc(q[2])]=R[RX(stix(li))];",
        variant: "local w13=dstc(q[2]);tmp[w13]=R[RX(stix(li))];",
        temp: Some("w13"),
    },
    P5Site {
        prev: None,
        line: "tmp[dstc(q[2])]=rv(q[3])[rv(q[4])];",
        canon: "tmp[dstc(q[2])]=rv(q[3])[rv(q[4])];",
        variant: "local w14=dstc(q[2]);tmp[w14]=rv(q[3])[rv(q[4])];",
        temp: Some("w14"),
    },
    P5Site {
        prev: None,
        line: "rv(q[2])[rv(q[3])]=rv(q[4]);",
        canon: "rv(q[2])[rv(q[3])]=rv(q[4]);",
        variant: "local w15=rv(q[2]);w15[rv(q[3])]=rv(q[4]);",
        temp: Some("w15"),
    },
];

/// P5 (Batch-5): arm-body duals/splits as line-neutral within-line span
/// replaces. Table order is application order (all duals precede all splits);
/// every needle is fail-closed (`count == 1` or panic). Split safety rests on
/// the dual-target probe: stores evaluate key-side first, multi-assign and
/// indexing left-to-right, so hoisting the first-evaluated call preserves
/// failure precedence exactly. B4b-chain interiors are excluded (they already
/// permute); `expect or 0` has no Lua dual; op12's body is unreachable.
fn p5_arm_forms(lines: &mut Vec<String>, rng: &mut Prng) {
    for site in P5_SITES {
        if let Some(temp) = site.temp {
            let def = format!("local {temp}=");
            assert!(
                !lines.iter().any(|l| l.contains(&def)),
                "P5: temp collides: {temp}"
            );
        }
    }
    for a in P5_SITES {
        for b in P5_SITES {
            assert!(
                !a.variant.contains(b.canon),
                "P5: variant cannibalizes canon: {} in {}",
                b.canon,
                a.variant
            );
        }
    }
    for site in P5_SITES {
        let mut hits = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(site.line) {
                continue;
            }
            if let Some(prev) = site.prev {
                if i == 0 || !lines[i - 1].contains(prev) {
                    continue;
                }
            }
            hits.push(i);
        }
        assert_eq!(hits.len(), 1, "P5: needle drifted: {}", site.line);
        let at = hits[0];
        assert_eq!(
            lines[at].matches(site.canon).count(),
            1,
            "P5: canon drifted: {}",
            site.canon
        );
        if rng.index(2) == 1 {
            lines[at] = lines[at].replacen(site.canon, site.variant, 1);
        }
    }
}
// ---- P6 per-seed lane remapping -----------------------------------------
// Routine DATA (not template text) is remapped per image seed: tmp slots,
// site lanes, STAB/SEEDH indices are permuted, and every packed operand ref
// follows. Offsets (`vo`), K-const layout, int values, nil, op numbers and
// the five positional specials (RET action, CALL mk/nargs, ALU oi5 pack,
// BR target) are never touched. Out-of-domain words pass through, so every
// corruption probe keeps failing; the template is byte-identical, so all
// P1-P5 gates are unaffected.
//
// Fail-closed: every perm asserts bijection + template-derived pins at
// build time; map/unmap partition the word space (in-domain vs kept), so
// unmap(map(w)) == w for all words (verified by the inverse lock).
const P6_DOMAIN_TMP: u64 = 0x5036_544D_505F_4C4E;
const P6_DOMAIN_SITE: u64 = 0x5036_5354_455F_4C4E;
const P6_DOMAIN_STAB: u64 = 0x5036_5354_4142_5F4E;
const P6_DOMAIN_SEEDH: u64 = 0x5036_5344_4848_5F4E;

fn p6_shuffled(seed: u64, domain: u64, n: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..n).collect();
    Prng::new(seed ^ domain).shuffle(&mut order);
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..n).collect::<Vec<_>>(), "P6: perm not bijective");
    order
}

/// tmp perm over slots 0..16 (unconstrained: template checks `vi>15` only).
pub(crate) fn p6_tmp_perm(seed: u64) -> [usize; 16] {
    let order = p6_shuffled(seed, P6_DOMAIN_TMP, 16);
    let mut out = [0usize; 16];
    out.copy_from_slice(&order);
    out
}

/// Site perm over 1-based lanes 1..=w with template-derived pins: lane 1 is
/// fixed (kind-4 rejects vi<2, kind-1 rejects vi>2, forcing it), lane 4 is
/// fixed (konst reads `site[4]` hardcoded), lanes {2,3} swap freely
/// (kind-1 range), lanes 5..=w permute freely. Widths in use: 1,2,3,4,7,8,9.
pub(crate) fn p6_site_perm(seed: u64, w: usize) -> Vec<usize> {
    assert!((1..=9).contains(&w), "P6: site width out of range: {w}");
    let mut rng = Prng::new(seed ^ P6_DOMAIN_SITE ^ w as u64);
    let mut lanes: Vec<usize> = (1..=w).collect();
    if w >= 3 && rng.index(2) == 1 {
        lanes.swap(1, 2);
    }
    if w >= 6 {
        rng.shuffle(&mut lanes[4..]);
    }
    assert_eq!(lanes[0], 1, "P6: lane 1 must stay fixed");
    if w >= 4 {
        assert_eq!(lanes[3], 4, "P6: k-lane 4 must stay fixed");
    }
    if w >= 3 {
        assert!(
            (lanes[1] == 2 && lanes[2] == 3) || (lanes[1] == 3 && lanes[2] == 2),
            "P6: lanes 2..3 must stay closed"
        );
    }
    let mut sorted = lanes.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        (1..=w).collect::<Vec<_>>(),
        "P6: site perm not bijective"
    );
    lanes
}

/// STAB/SEEDH perms over indices 0..n (unconstrained range checks).
pub(crate) fn p6_stab_perm(seed: u64, n: usize) -> Vec<usize> {
    p6_shuffled(seed, P6_DOMAIN_STAB, n)
}
pub(crate) fn p6_seedh_perm(seed: u64, n: usize) -> Vec<usize> {
    p6_shuffled(seed, P6_DOMAIN_SEEDH, n)
}

/// Trimmed site width per op (mirrors `seed_arm_lua_for`; asserted equal
/// there, so the two can never drift apart silently).
pub(crate) fn p6_site_width(op: Opcode) -> usize {
    use Opcode::*;
    match op {
        Nil | NewTable | NewPack | NumberPrepare | NumberStep | IteratorPrepare | Return
        | Freeze => 1,
        Move | NewCell | ReadCell | WriteCell | Push | Extend | Clear | Not | Negate | Length
        | NumberTest | IteratorNext | ToString | TailCall => 2,
        GetTable | SetTable | Method | Extract | Call | Add | Subtract | Multiply | Divide
        | FloorDivide | Modulo | Power | Concat | Equal | Less | LessEqual | SetList | Export => 3,
        Constant | ReadGlobal | WriteGlobal => 4,
        Test | Jump => 7,
        ReadUpvalue | WriteUpvalue | Closure => 8,
        Varargs => 9,
    }
}

/// Permute a `{e1,..,ew}` site literal through the width-w site perm.
pub(crate) fn p6_permute_site(site: &str, seed: u64) -> String {
    let inner = site
        .strip_prefix('{')
        .and_then(|t| t.strip_suffix('}'))
        .unwrap_or_else(|| panic!("P6: site literal reshaped: {site}"));
    let elems: Vec<&str> = inner.split(',').collect();
    let perm = p6_site_perm(seed, elems.len());
    // new[i] = old[pinv(i)]: content follows its lane.
    let mut out = Vec::with_capacity(elems.len());
    let mut inv = vec![0usize; elems.len()];
    for (i, slot) in perm.iter().enumerate() {
        inv[slot - 1] = i;
    }
    for i in 0..elems.len() {
        out.push(elems[inv[i]]);
    }
    format!("{{{}}}", out.join(","))
}

/// Canonical-to-image lane mapper (perms built once, applied per word).
pub(crate) struct P6Mapper {
    tmp: [usize; 16],
    tmp_inv: [usize; 16],
    site: Vec<usize>,
    site_inv: Vec<usize>,
    stab: Vec<usize>,
    stab_inv: Vec<usize>,
    seedh: Vec<usize>,
    seedh_inv: Vec<usize>,
    site_w: usize,
    stab_n: usize,
    seedh_n: usize,
}

fn p6_invert(perm: &[usize]) -> Vec<usize> {
    let mut inv = vec![0usize; perm.len()];
    for (i, slot) in perm.iter().enumerate() {
        inv[slot - 1] = i + 1;
    }
    inv
}

impl P6Mapper {
    pub(crate) fn new(seed: u64, site_w: usize, stab_n: usize, seedh_n: usize) -> Self {
        let tmp = p6_tmp_perm(seed);
        let mut tmp_inv = [0usize; 16];
        for (i, slot) in tmp.iter().enumerate() {
            tmp_inv[*slot] = i;
        }
        let site = p6_site_perm(seed, site_w);
        let site_inv = p6_invert(&site);
        let stab = p6_stab_perm(seed, stab_n);
        let seedh = p6_seedh_perm(seed, seedh_n);
        let mut stab_inv = vec![0usize; stab_n];
        for (i, slot) in stab.iter().enumerate() {
            stab_inv[*slot] = i;
        }
        let mut seedh_inv = vec![0usize; seedh_n];
        for (i, slot) in seedh.iter().enumerate() {
            seedh_inv[*slot] = i;
        }
        Self {
            tmp,
            tmp_inv,
            site,
            site_inv,
            stab,
            stab_inv,
            seedh,
            seedh_inv,
            site_w,
            stab_n,
            seedh_n,
        }
    }

    /// Raw (non-ref) positions, transcribed 0-based from the template:
    /// RET action `a=q[2]`; CALL `nargs=q[5]`; BR target `tgtc(q[2])` on
    /// 2-word rows, `tgtc(q[3])` on 3-word rows (cond `dstc(q[2])` maps).
    /// ALU oi5 / CALL mk are kind-3 ints, excluded by kind, never by skip.
    fn skip(row_op: u32, row_len: usize, pos: usize) -> bool {
        match (row_op, row_len, pos) {
            (OP_RET, _, 1) => true,
            (OP_CALL, _, 4) => true,
            (OP_BR, 2, 1) => true,
            (OP_BR, 3, 2) => true,
            _ => false,
        }
    }

    /// Map one word canonical -> image. Out-of-domain words pass through.
    pub(crate) fn map(&self, row_op: u32, row_len: usize, pos: usize, word: u32) -> u32 {
        if pos == 0 || Self::skip(row_op, row_len, pos) {
            return word;
        }
        let kind = word / 1_000_000;
        let vi = word / 1000 % 1000;
        let vo = word % 1000;
        let mapped_vi = if kind == KIND_TMP && vi < 16 {
            Some(self.tmp[vi as usize] as u32)
        } else if kind == KIND_REG && (1..=(self.site_w as u32)).contains(&(vi + 1)) {
            Some((self.site[vi as usize] - 1) as u32)
        } else if kind == KIND_PSEUDO && (2..=(self.site_w as u32)).contains(&vi) {
            Some(self.site[(vi - 1) as usize] as u32)
        } else if kind == KIND_SCONST && vi < self.stab_n as u32 {
            Some(self.stab[vi as usize] as u32)
        } else if kind == KIND_HELPER && vi < self.seedh_n as u32 {
            Some(self.seedh[vi as usize] as u32)
        } else if kind == KIND_OPVAL && (1..=(self.site_w as u32)).contains(&(vi + 1)) {
            Some((self.site[vi as usize] - 1) as u32)
        } else {
            None
        };
        match mapped_vi {
            Some(vi) => kind * 1_000_000 + vi * 1000 + vo,
            None => word,
        }
    }

    /// Map one word image -> canonical (exact inverse of [`Self::map`]).
    pub(crate) fn unmap(&self, row_op: u32, row_len: usize, pos: usize, word: u32) -> u32 {
        if pos == 0 || Self::skip(row_op, row_len, pos) {
            return word;
        }
        let kind = word / 1_000_000;
        let vi = word / 1000 % 1000;
        let vo = word % 1000;
        let mapped_vi = if kind == KIND_TMP && vi < 16 {
            Some(self.tmp_inv[vi as usize] as u32)
        } else if kind == KIND_REG && (1..=(self.site_w as u32)).contains(&(vi + 1)) {
            Some((self.site_inv[vi as usize] - 1) as u32)
        } else if kind == KIND_PSEUDO && (2..=(self.site_w as u32)).contains(&vi) {
            Some(self.site_inv[(vi - 1) as usize] as u32)
        } else if kind == KIND_SCONST && vi < self.stab_n as u32 {
            Some(self.stab_inv[vi as usize] as u32)
        } else if kind == KIND_HELPER && vi < self.seedh_n as u32 {
            Some(self.seedh_inv[vi as usize] as u32)
        } else if kind == KIND_OPVAL && (1..=(self.site_w as u32)).contains(&(vi + 1)) {
            Some((self.site_inv[vi as usize] - 1) as u32)
        } else {
            None
        };
        match mapped_vi {
            Some(vi) => kind * 1_000_000 + vi * 1000 + vo,
            None => word,
        }
    }
}
