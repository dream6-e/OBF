//! P1 per-seed deformation of the seed-loop template (split from `seed.rs`
//! under the permanent 80 KiB source-file ceiling; generated output is
//! unchanged by the split).

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
