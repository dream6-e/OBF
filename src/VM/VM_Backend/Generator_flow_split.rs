//! Semantics-preserving relay dispatch for VM instruction cases.
//!
//! The frame setup remains in `execute`; opcode cases are independent functions and
//! each returns its next PC to the iterative driver. To keep the payload from being a
//! single scriptable shape ("one routes table + one cases table + one call site"),
//! every structural choice below is re-randomized per build:
//!
//! * case handlers are sharded into 2–3 bucket tables, each bucket using one of
//!   several storage shapes (plain closure, aliased parameter permutation, named
//!   function reference, single-element array box);
//! * route tables are sharded per bucket and built from shuffled constructor
//!   literals plus scattered assignment statements;
//! * the dispatch expression is picked among several equivalent templates;
//! * case bodies get randomized keyword wraps (`do`/single-iteration `while`/
//!   `repeat`) and the fallthrough return arity is trimmed to the flags the body
//!   actually touches;
//! * decoy tables live inside `if false` / zero-trip `for` blocks;
//! * the entry/exit protocol relay is split across two state tables.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LoopForm {
    While,
    Repeat,
}

const RELAY_SETUP_OPEN: &str = "\u{1}ARENA_RELAY_SETUP_OPEN\u{2}";
const RELAY_SETUP_CLOSE: &str = "\u{3}ARENA_RELAY_SETUP_CLOSE\u{4}";

/// Tiny splitmix64 stream so dispatch shaping never touches the generator's RNG.
struct TinyRng(u64);

impl TinyRng {
    fn new(seed: u64) -> Self {
        TinyRng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn coin(&mut self) -> bool {
        self.next() & 1 == 0
    }
    fn shuffle<T>(&mut self, xs: &mut [T]) {
        for i in (1..xs.len()).rev() {
            let j = self.range((i + 1) as u64) as usize;
            xs.swap(i, j);
        }
    }
    /// Random identifier: fixed prefix + 8 low-case letters/digits (letter first).
    fn name(&mut self, prefix: &str) -> String {
        let mut out = String::with_capacity(prefix.len() + 9);
        out.push_str(prefix);
        out.push('_');
        let letters = b"abcdefghijklmnopqrstuvwxyz";
        out.push(letters[(self.next() % 26) as usize] as char);
        for _ in 0..7 {
            let c = self.next() % 36;
            out.push(if c < 26 {
                letters[c as usize] as char
            } else {
                (b'0' + (c - 26) as u8) as char
            });
        }
        out
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CaseShape {
    Plain,
    Aliased,
    Named,
    Boxed,
}

/// Build the sharded protocol lookup and one independent function per distinct case.
/// The setup block is hoisted by `wrap_dispatcher` before the iterative driver is emitted.
pub(super) fn build_relay_dispatch(
    entries: &[(u32, String)],
    pc: &str,
    top: &str,
    r1: &str,
    r2: &str,
    r3: &str,
    route_op: &str,
    bias: &str,
    execute_name: &str,
    vm_seed: u64,
) -> String {
    let _ = top;
    let mut rng = TinyRng::new(
        vm_seed
            ^ (entries.len() as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9)
            ^ (execute_name.len() as u64).wrapping_mul(0x94D0_49BB_1331_11EB),
    );
    let tag = rng.name(&format!("{}_dx", execute_name));

    // Deduplicate identical handler bodies behind shared protocol codes.
    let mut unique: Vec<(u32, String)> = Vec::new();
    let mut used_codes = Vec::new();
    let mut route_entries: Vec<(u32, u32)> = Vec::with_capacity(entries.len());
    for (index, (opcode, body)) in entries.iter().enumerate() {
        let protocol = if let Some((protocol, _)) = unique.iter().find(|(_, old)| old == body) {
            *protocol
        } else {
            let mut code = protocol_code(vm_seed, *opcode, index);
            while used_codes.contains(&code) {
                code = code.wrapping_add(0x9E37_79B9);
            }
            used_codes.push(code);
            unique.push((code, body.clone()));
            code
        };
        route_entries.push((*opcode, protocol));
    }

    // Shard protocols across 2–3 bucket tables (one bucket for a single protocol).
    let bucket_count = if unique.len() <= 1 {
        1
    } else {
        let want = 2 + rng.range(2) as usize;
        want.min(unique.len())
    };
    let mut proto_order: Vec<usize> = (0..unique.len()).collect();
    rng.shuffle(&mut proto_order);
    let mut proto_bucket = vec![0usize; unique.len()];
    for (slot, proto_idx) in proto_order.iter().enumerate() {
        proto_bucket[*proto_idx] = slot % bucket_count;
    }

    // Distinct storage shapes, shuffled across buckets. The Named shape declares one
    // local function per case in the enclosing scope, so keep it away from the
    // 200-locals-per-function limit when the handler set is large.
    let mut shapes: Vec<CaseShape> = vec![CaseShape::Plain, CaseShape::Aliased, CaseShape::Named, CaseShape::Boxed];
    if unique.len() > 140 {
        shapes.retain(|s| *s != CaseShape::Named);
    }
    rng.shuffle(&mut shapes);
    let bucket_shapes: Vec<CaseShape> = (0..bucket_count).map(|i| shapes[i % shapes.len()]).collect();
    // Parameter style per bucket: canonical names or a permuted signature that is
    // aliased back inside the handler (bodies keep referring to the canonical names).
    let bucket_aliased: Vec<bool> = (0..bucket_count)
        .map(|i| bucket_shapes[i] == CaseShape::Aliased || (bucket_shapes[i] != CaseShape::Plain && rng.coin()))
        .collect();
    let bucket_names: Vec<(String, String)> = (0..bucket_count)
        .map(|_| (rng.name(&tag), rng.name(&tag)))
        .collect();
    let fallback = rng.name(&tag);
    let junk: Vec<(String, String)> = (0..bucket_count).map(|_| (rng.name(&tag), rng.name(&tag))).collect();

    // ---- emit case handlers -------------------------------------------------
    let mut named_defs: Vec<String> = Vec::new();
    let mut inline_entries: Vec<Vec<String>> = vec![Vec::new(); bucket_count];
    let mut scattered: Vec<String> = Vec::new();
    let mut route_stmts: Vec<(usize, String)> = Vec::new();

    for (proto_idx, (protocol, body)) in unique.iter().enumerate() {
        let b = proto_bucket[proto_idx];
        let (cases_b, _routes_b) = &bucket_names[b];
        let (j1, j2) = &junk[b];
        let (params, alias_stmt) = handler_params(&mut rng, bucket_aliased[b]);
        let trimmed = trimmed_flags(body, &[r1, r2, r3]);
        let wrapped = wrap_case_body(&mut rng, body);
        let fallthrough = if ends_with_return_statement(body) {
            String::new()
        } else {
            // Lua 5.1 has no empty statement: only add a separator when the wrapped
            // text does not already end with one.
            let separator = if wrapped.trim().is_empty() || wrapped.trim_end().ends_with(';') { "" } else { ";" };
            let mut ret = format!("return {}", pc);
            for flag in &trimmed {
                ret.push(',');
                ret.push_str(flag);
            }
            format!("{separator}{ret};", separator = separator, ret = ret)
        };
        let inner = format!(
            "{alias}local {j1},{j2};local {r1},{r2},{r3};{wrapped}{fallthrough}",
            alias = alias_stmt,
            j1 = j1,
            j2 = j2,
            r1 = r1,
            r2 = r2,
            r3 = r3,
            wrapped = wrapped,
            fallthrough = fallthrough,
        );
        let fn_expr = format!("function({params}) {inner} end", params = params, inner = inner);
        match bucket_shapes[b] {
            CaseShape::Named => {
                let hname = rng.name(&tag);
                named_defs.push(format!("local function {hname}({params}) {inner} end;", hname = hname, params = params, inner = inner));
                if rng.coin() {
                    inline_entries[b].push(format!("[0X{protocol:08X}]={hname}", protocol = protocol, hname = hname));
                } else {
                    scattered.push(format!("{cases_b}[0X{protocol:08X}]={hname};", cases_b = cases_b, protocol = protocol, hname = hname));
                }
            }
            CaseShape::Boxed => {
                let stmt = format!("{cases_b}[0X{protocol:08X}]={{{fne}}};", cases_b = cases_b, protocol = protocol, fne = fn_expr);
                if inline_entries[b].is_empty() && rng.coin() {
                    inline_entries[b].push(format!("[0X{protocol:08X}]={{{fne}}}", protocol = protocol, fne = fn_expr));
                } else {
                    scattered.push(stmt);
                }
            }
            _ => {
                if inline_entries[b].len() < 3 && rng.coin() {
                    inline_entries[b].push(format!("[0X{protocol:08X}]={fne}", protocol = protocol, fne = fn_expr));
                } else {
                    scattered.push(format!("{cases_b}[0X{protocol:08X}]={fne};", cases_b = cases_b, protocol = protocol, fne = fn_expr));
                }
            }
        }
    }

    // ---- route statements (per bucket) --------------------------------------
    for (opcode, protocol) in &route_entries {
        let b = proto_bucket[unique.iter().position(|(p, _)| p == protocol).unwrap()];
        let stmt = format!(
            "{routes}[0X{opcode:X}]=0X{protocol:08X};",
            routes = bucket_names[b].1,
            opcode = opcode,
            protocol = protocol,
        );
        route_stmts.push((b, stmt));
    }
    rng.shuffle(&mut route_stmts);
    rng.shuffle(&mut scattered);

    // ---- assemble the setup block -------------------------------------------
    let mut setup = String::new();
    for def in &named_defs {
        setup.push_str(def);
    }
    for b in 0..bucket_count {
        let (cases_b, routes_b) = &bucket_names[b];
        if inline_entries[b].is_empty() {
            setup.push_str(&format!("local {cases_b},{routes_b}={{}},{{}};", cases_b = cases_b, routes_b = routes_b));
        } else {
            setup.push_str(&format!(
                "local {cases_b},{routes_b}={{{entries}}},{{}};",
                cases_b = cases_b,
                routes_b = routes_b,
                entries = inline_entries[b].join(","),
            ));
        }
    }
    // Interleave scattered case assignments and route assignments.
    let mut si = 0usize;
    let mut ri = 0usize;
    while si < scattered.len() || ri < route_stmts.len() {
        let take_route = if si >= scattered.len() {
            true
        } else if ri >= route_stmts.len() {
            false
        } else {
            rng.coin()
        };
        if take_route {
            setup.push_str(&route_stmts[ri].1);
            ri += 1;
        } else {
            setup.push_str(&scattered[si]);
            si += 1;
        }
    }
    // Fallback in one of several equivalent shapes.
    setup.push_str(&match rng.range(3) {
        0 => format!("local {fallback}=function() return {pc},nil,nil,nil end;", fallback = fallback, pc = pc),
        1 => format!("local function {fallback}() do return {pc},nil,nil,nil end end;", fallback = fallback, pc = pc),
        _ => format!("local {fallback}=function() local {j}; return {pc},nil,nil,nil end;", fallback = fallback, pc = pc, j = rng.name(&tag)),
    });
    // Decoy tables inside dead code: plausible number→function maps that no lookup
    // ever reaches, to poison generic table-dumping scripts.
    setup.push_str(&decoy_block(&mut rng, &tag, &format!("{}_d", tag)));

    // ---- dispatch expression (several equivalent templates) ------------------
    let mut order: Vec<usize> = (0..bucket_count).collect();
    rng.shuffle(&mut order);
    let ov = format!("{}-{}", route_op, bias);
    let rtchain = order
        .iter()
        .map(|b| format!("{}[{}]", bucket_names[*b].1, ov))
        .collect::<Vec<_>>()
        .join(" or ");
    let k = rng.name(&tag);
    let f = rng.name(&tag);
    let g = rng.name(&tag);
    let np = rng.name(&tag);
    let (ra, rb, rc) = (rng.name(&tag), rng.name(&tag), rng.name(&tag));
    let unwrap = |b: usize, key: &str| match bucket_shapes[b] {
        CaseShape::Boxed => format!("({t}[{key}] and {t}[{key}][1])", t = bucket_names[b].0, key = key),
        _ => format!("{}[{}]", bucket_names[b].0, key),
    };
    let hchain = order
        .iter()
        .map(|b| unwrap(*b, &k))
        .collect::<Vec<_>>()
        .join(" or ");
    let call = format!("{np},{ra},{rb},{rc}={f}(op,inst_A,inst_B,inst_C);", np = np, ra = ra, rb = rb, rc = rc, f = f);
    let tail = format!(
        "if {np}==true then {r1}=true else {pc}={np};{r1},{r2},{r3}={ra},{rb},{rc} end;",
        np = np, pc = pc, r1 = r1, r2 = r2, r3 = r3, ra = ra, rb = rb, rc = rc,
    );
    let dispatch = match rng.range(3) {
        0 => format!("local {k}={rtchain};local {f}={hchain} or {fallback};{call}{tail}", k = k, rtchain = rtchain, f = f, hchain = hchain, fallback = fallback, call = call, tail = tail),
        1 => format!(
            "local {k}={rtchain};local {f}={fallback};do local {g}={hchain};if {g} then {f}={g} end end;{call}{tail}",
            k = k, rtchain = rtchain, f = f, fallback = fallback, g = g, hchain = hchain, call = call, tail = tail,
        ),
        _ => {
            // Per-bucket temporaries, then an or-chain over the temporaries.
            let ks: Vec<String> = (0..order.len()).map(|i| format!("{}_{}", k, i)).collect();
            let hs: Vec<String> = (0..order.len()).map(|i| format!("{}_{}", g, i)).collect();
            let kvs: Vec<String> = order.iter().map(|b| format!("{}[{}]", bucket_names[*b].1, ov)).collect();
            let hvs: Vec<String> = order.iter().zip(ks.iter()).map(|(b, kn)| unwrap(*b, kn)).collect();
            format!(
                "local {ks}={kvs};local {hs}={hvs};local {f}={chain} or {fallback};{call}{tail}",
                ks = ks.join(","),
                kvs = kvs.join(","),
                hs = hs.join(","),
                hvs = hvs.join(","),
                f = f,
                chain = hs.join(" or "),
                fallback = fallback,
                call = call,
                tail = tail,
            )
        }
    };

    format!("{open}{setup}{close}{dispatch}", open = RELAY_SETUP_OPEN, setup = setup, close = RELAY_SETUP_CLOSE, dispatch = dispatch)
}

/// Parameter list for one handler. Aliased buckets use random parameter names and
/// re-bind the canonical names inside, so handler bodies never need rewriting.
fn handler_params(rng: &mut TinyRng, aliased: bool) -> (String, String) {
    if !aliased {
        return ("op,inst_A,inst_B,inst_C".to_string(), String::new());
    }
    let pnames: Vec<String> = (0..4).map(|_| rng.name("p")).collect();
    let alias = format!(
        "local op,inst_A,inst_B,inst_C={},{},{},{};",
        pnames[0], pnames[1], pnames[2], pnames[3],
    );
    (pnames.join(","), alias)
}

/// Random keyword wrap around a case body (single-iteration forms only, so the
/// observable behavior is identical). Loop wraps are skipped for bodies containing
/// a `break` token to avoid re-targeting it.
fn wrap_case_body(rng: &mut TinyRng, body: &str) -> String {
    let has_break = body.split(|c: char| !c.is_ascii_alphanumeric() && c != '_').any(|w| w == "break");
    let style = rng.range(4);
    match (style, has_break) {
        (1, _) => format!("do {} end;", body),
        (2, false) => {
            let once = rng.name("o");
            format!("local {once}=true;while {once} do {once}=false;{body} end;", once = once, body = body)
        }
        (3, false) => format!("repeat {} until true;", body),
        _ => body.to_string(),
    }
}

/// Drop trailing flags the body never mentions, so fallthrough returns the minimal
/// arity (missing values read as nil at the driver's 4-wide assignment).
fn trimmed_flags(body: &str, flags: &[&str; 3]) -> Vec<String> {
    let mentions = |name: &str| {
        let mut chars = body.char_indices().peekable();
        while let Some((start, ch)) = chars.next() {
            if !name.starts_with(ch) {
                continue;
            }
            let end = start + name.len();
            let tail = &body[end.min(body.len())..];
            let before_ok = start == 0
                || body[..start]
                    .chars()
                    .last()
                    .map(|c| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(true);
            let after_ok = tail
                .chars()
                .next()
                .map(|c| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(true);
            if before_ok && after_ok && body[start..].starts_with(name) {
                return true;
            }
        }
        false
    };
    let used: Vec<bool> = flags.iter().map(|f| mentions(f)).collect();
    let mut keep = 3usize;
    while keep > 0 && !used[keep - 1] {
        keep -= 1;
    }
    flags.iter().take(keep).map(|s| s.to_string()).collect()
}

/// Dead-code decoys: tables shaped like case/route maps, referenced nowhere live.
fn decoy_block(rng: &mut TinyRng, tag: &str, dtag: &str) -> String {
    let df = rng.name(dtag);
    let dt = rng.name(dtag);
    let dr = rng.name(dtag);
    let d1 = rng.next() as u32;
    let d2 = rng.next() as u32;
    let inner = format!(
        "local {df}=function(op,a,b,c) local x=(op+a)%(b+1);local y=x*c;return y end;\
         local {dt}={{}};{dt}[0X{d1:08X}]={df};{dt}[0X{d2:08X}]={df};\
         local {dr}={{}};{dr}[0X{d1:08X}]=0X{d2:08X};",
        df = df, dt = dt, dr = dr, d1 = d1, d2 = d2,
    );
    if rng.coin() {
        format!("if false then {} end;", inner)
    } else {
        format!("for {}=1,0 do {} end;", rng.name(tag), inner)
    }
}

fn protocol_code(seed: u64, opcode: u32, index: usize) -> u32 {
    let mut value = (seed as u32)
        ^ opcode.rotate_left((index as u32) & 31)
        ^ (index as u32 + 1).wrapping_mul(0x9E37_79B9);
    value ^= value >> 16;
    value = value.wrapping_mul(0x7FEB_352D);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846C_A68B);
    value ^= value >> 16;
    value
}

fn ends_with_return_statement(body: &str) -> bool {
    let trimmed = body.trim().trim_end_matches(';').trim_end();
    let Some(position) = trimmed.rfind("return") else {
        return false;
    };
    !trimmed[position + "return".len()..]
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|word| word == "end")
}

fn extract_relay_setup(body: &str) -> (String, String) {
    let Some(open) = body.find(RELAY_SETUP_OPEN) else {
        return (String::new(), body.to_string());
    };
    let setup_start = open + RELAY_SETUP_OPEN.len();
    let Some(close) = body[setup_start..].find(RELAY_SETUP_CLOSE).map(|n| setup_start + n) else {
        return (String::new(), body.to_string());
    };
    let setup = body[setup_start..close].to_string();
    let rest_start = close + RELAY_SETUP_CLOSE.len();
    let mut rest = String::with_capacity(body.len() - (rest_start - open));
    rest.push_str(&body[..open]);
    rest.push_str(&body[rest_start..]);
    (setup, rest)
}

/// Build a per-output flow shape without consuming the generator's existing RNG stream.
pub(super) fn wrap_for_build(
    setup: &str,
    body: &str,
    has_handlers: bool,
    chunk_name: &str,
    execute_name: &str,
    vm_seed: u64,
    handler_count: usize,
) -> String {
    let style_seed = vm_seed ^ (handler_count as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    // No fixed suffixes: every relay identifier gets its own random tail so the
    // scaffolding cannot be located by string search.
    let mut rng = TinyRng::new(style_seed.wrapping_mul(0x94D0_49BB_1331_11EB));
    let suffix = |rng: &mut TinyRng, name: &str| format!("{}_{}", execute_name, rng.name(name));
    wrap_dispatcher(
        setup,
        body,
        has_handlers,
        if style_seed & 1 == 0 {
            LoopForm::Repeat
        } else {
            LoopForm::While
        },
        chunk_name,
        &suffix(&mut rng, "core"),
        &suffix(&mut rng, "route"),
        &suffix(&mut rng, "gate"),
        &suffix(&mut rng, "index"),
        style_seed & 2 != 0,
        style_seed,
    )
}

/// Emit the inner dispatcher and its return-preserving route inside `execute`.
/// `body` is the original instruction-loop body; it is not reordered or rewritten.
pub(super) fn wrap_dispatcher(
    setup: &str,
    body: &str,
    has_handlers: bool,
    loop_form: LoopForm,
    chunk_name: &str,
    core_name: &str,
    route_name: &str,
    gate_name: &str,
    index_name: &str,
    invert_route: bool,
    flow_seed: u64,
) -> String {
    let mut rng = TinyRng::new(flow_seed.wrapping_mul(0xBF58_476D_1CE4_E5B9));
    let step_name = rng.name(core_name);
    let exit_a = rng.name(route_name);
    let exit_b = rng.name(route_name);
    let state_name = rng.name(route_name);
    let (relay_setup, body) = extract_relay_setup(body);
    let base = (flow_seed as u32) & 0x3FFF_FF00;

    // Eight distinct randomized state codes.
    let mut offsets: Vec<u32> = (0..256).step_by(1).collect::<Vec<u32>>();
    rng.shuffle(&mut offsets);
    let states: Vec<String> = offsets[..8].iter().map(|o| format!("0X{:X}", base + o * 0x100 + 0x11)).collect();
    let (s0, s1, s2, s3, s4, s5, s6, s7) = (
        states[0].clone(),
        states[1].clone(),
        states[2].clone(),
        states[3].clone(),
        states[4].clone(),
        states[5].clone(),
        states[6].clone(),
        states[7].clone(),
    );

    // Keep setup in its original position; the nested step closure captures its locals.
    let loop_body = if !has_handlers {
        // Preserve the previous empty-tree behavior: enter once, break, and return no values.
        "while true do break end".to_string()
    } else {
        let (open, close) = match loop_form {
            LoopForm::While => ("while not ((true or false)==false) do ", " end;"),
            LoopForm::Repeat => ("repeat ", " until (false and not true) or false;"),
        };
        format!("{}{}{}", open, body, close)
    };
    let core_body = format!(
        "{setup}{relay_setup}local function {step}(...) {loop_body} end; return {step}(...);",
        setup = setup,
        relay_setup = relay_setup,
        step = step_name,
        loop_body = loop_body,
    );

    // Each route node is a function returning the next randomized protocol code.
    let start_test = if invert_route {
        format!("not {}", gate_name)
    } else {
        gate_name.to_string()
    };
    let route_form = match loop_form {
        LoopForm::While => LoopForm::Repeat,
        LoopForm::Repeat => LoopForm::While,
    };
    // State relay split across two tables; lookup goes through an or-chain.
    let relay_a = format!("{}_{}", route_name, rng.name("sa"));
    let relay_b = format!("{}_{}", route_name, rng.name("sb"));
    let pick_relay = format!("({a}[{st}] or {b}[{st}])", a = relay_a, b = relay_b, st = state_name);
    let route_step = format!("{state}={pick_relay}({gate},...);", state = state_name, pick_relay = pick_relay, gate = gate_name);
    let route_loop = match route_form {
        LoopForm::While => format!(
            "while not ((true or false)==false) and {st}~={s6} and {st}~={s7} do {step} end;",
            st = state_name, s6 = s6, s7 = s7, step = route_step,
        ),
        LoopForm::Repeat => format!(
            "repeat {step} until {st}=={s6} or {st}=={s7};",
            step = route_step, st = state_name, s6 = s6, s7 = s7,
        ),
    };

    // Randomly shard the eight state handlers across the two relay tables.
    let state_bodies: Vec<String> = vec![
        format!("function({gate},...) if {gate} and not (false or false) then return {s2} end return {s3} end", gate = gate_name, s2 = s2, s3 = s3),
        format!("function({gate},...) if not {gate} or (false and {gate}) then return {s5} end return {s4} end", gate = gate_name, s5 = s5, s4 = s4),
        format!("function({gate},...) local {index}; repeat {index}={s6} until (false and not {gate}) or true; return {index} end", gate = gate_name, index = index_name, s6 = s6),
        format!("function(...) return {} end", s7),
        format!("function(...) return {} end", s6),
        format!(
            "function({gate},...) local {index},{next_state}; for {index}=0X1,0X1 do if not {gate} or (false and {gate}) then {next_state}={s7} end; if {gate} and (true or false) then {next_state}={s6} end; break end; return {next_state} or {s7} end",
            gate = gate_name, index = index_name, next_state = format!("{}_next", state_name), s7 = s7, s6 = s6,
        ),
        format!("function({gate},...) return {exit_a}(...) end", gate = gate_name, exit_a = exit_a),
        format!("function({gate},...) return {exit_b}(...) end", gate = gate_name, exit_b = exit_b),
    ];
    let mut relay_defs = String::new();
    for (i, sb) in state_bodies.iter().enumerate() {
        let table = if i == 0 {
            &relay_a
        } else if i == 1 {
            &relay_b
        } else if rng.coin() {
            &relay_a
        } else {
            &relay_b
        };
        relay_defs.push_str(&format!("{table}[{state}]={body};", table = table, state = states[i], body = sb));
    }

    format!(
        r#"local function {core}(...) {core_body} end;
local function {exit_a}(...) return {core}(...) end;
local function {exit_b}(...) return {core}(...) end;
local {relay_a},{relay_b}={{}},{{}};
{relay_defs}
local function {route}(...)
  local {gate}=({chunk}~=nil and true) or false;
  local {state}={start} and {s0} or {s1};
  {route_loop}
  return ({ra}[{state}] or {rb}[{state}])({gate},...)
end;
return {route}(...);"#,
        core = core_name,
        core_body = core_body,
        exit_a = exit_a,
        exit_b = exit_b,
        relay_a = relay_a,
        relay_b = relay_b,
        relay_defs = relay_defs,
        route = route_name,
        gate = gate_name,
        chunk = chunk_name,
        state = state_name,
        start = start_test,
        s0 = s0,
        s1 = s1,
        route_loop = route_loop,
        ra = relay_a,
        rb = relay_b,
    )
}

#[cfg(test)]
mod tests {
    use super::{LoopForm, build_relay_dispatch, wrap_dispatcher};
    use crate::compressor::Compressor;
    use std::process::Command;

    fn run_lua(lua: &std::path::Path, code: &str, name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("kryvex_flow_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(name);
        std::fs::write(&path, code).expect("write flow test");
        let output = Command::new(lua).arg(&path).output().expect("run Lua 5.1");
        assert!(
            output.status.success(),
            "Lua 5.1 failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            code
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn split_dispatcher_preserves_order_break_and_multiple_returns() {
        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }

        for form in [LoopForm::While, LoopForm::Repeat] {
            for invert in [false, true] {
                let setup = "local flow_bias=0;";
                let loop_body = "local total=flow_bias; for i=1,4 do total=total+i; if i==2 then break end end; if chunk and chunk.stop then break end; if chunk then return total,chunk.label,nil,... else return total,\"none\",nil,... end;";
                let core = "flow_core";
                let route = "flow_route";
                let gate = "flow_gate";
                let index = "flow_index";
                let flow_seed = (u64::from(invert) << 1) | u64::from(form == LoopForm::Repeat);
                let wrapped = wrap_dispatcher(
                    setup, loop_body, true, form, "chunk", core, route, gate, index, invert,
                    flow_seed,
                );
                assert!(wrapped.matches("local function").count() >= 5);
                for keyword in [
                    "while", "repeat", "for ", "break", "not", "and", "or", "return",
                ] {
                    assert!(wrapped.contains(keyword), "missing Lua keyword: {keyword}");
                }
                assert!(wrapped.contains("]=function("), "state relay must stay table-based");
                assert!(!wrapped.contains("elseif"), "route states must use function relays, not a switch chain");
                assert!(!wrapped.contains("_protocols"), "relay table names must not be a fixed grep-able suffix");
                let source = format!(
                    "local function original(chunk, ...) local flow_bias=0; while true do {body} end end; \
                     local function transformed(chunk, ...) {wrapped} end; \
                     local a,b,c,d,e,f=original({{stop=false,label='ok'}},'x',nil,'z'); \
                     local x,y,z,u,v,w=transformed({{stop=false,label='ok'}},'x',nil,'z'); \
                     assert(a==x and b==y and c==z and d==u and e==v and f==w); \
                     local g,h,j=original({{stop=true,label='early'}}); \
                     local m,n,o=transformed({{stop=true,label='early'}}); \
                     assert(g==m and h==n and j==o); \
                     local p,q,r=original(nil); local s,t,u=transformed(nil); \
                     assert(p==s and q==t and r==u); io.write('FLOW_OK')",
                    body = loop_body,
                    wrapped = wrapped,
                );
                let compressed = Compressor::compress(&source)
                    .expect("compressor should accept split dispatcher syntax");
                assert_eq!(
                    run_lua(&lua, &source, "source.lua"),
                    "FLOW_OK",
                    "untransformed source should preserve the reference behavior"
                );
                assert_eq!(
                    run_lua(&lua, &compressed, "compressed.lua"),
                    "FLOW_OK",
                    "compressed split dispatcher must preserve all return values and breaks"
                );
            }
        }
    }

    #[test]
    fn protocol_cases_return_pc_and_preserve_fallthrough() {
        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }
        let first = "value=value+inst_A;pc=pc+inst_A;top=top+1;".to_string();
        let entries = vec![
            (0x101, first.clone()),
            (0x202, "value=value+inst_B;pc=pc+inst_B;top=top+2;".to_string()),
            (0x303, "return true;".to_string()),
            (0x404, first),
            (0x505, "if inst_A>0 then r1=true;r2=value;r3=inst_A end".to_string()),
        ];
        for seed in [0x1234u64, 0xBEEF, 0x0F0F_0F0F, 0xDEAD_BEEF] {
            let dispatch = build_relay_dispatch(
                &entries, "pc", "top", "r1", "r2", "r3", "route_op", "bias", "relay_test", seed,
            );
            let body = format!(
                "pc=pc+1;local route_op=op+bias;local rk1,rk2;local r1,r2,r3;{dispatch}return pc,top,value,r1,r2,r3;"
            );
            let setup = "local pc=10;local top=0;local value=0;local bias=7;local op,inst_A,inst_B,inst_C=...;";
            let wrapped = wrap_dispatcher(
                setup, &body, true, LoopForm::While, "chunk", "relay_core", "relay_route",
                "relay_gate", "relay_index", false, 0x5678 + seed,
            );
            assert!(!wrapped.contains("if op=="), "opcode dispatch must not be a comparison tree");
            for fixed in ["_relay_cases", "_relay_routes", "_relay_fallback"] {
                assert!(!wrapped.contains(fixed), "fixed relay suffix leaked: {fixed}");
            }
            assert!(
                wrapped.matches("local function").count() + wrapped.matches("=function(").count() >= 5,
                "cases must remain independent functions"
            );
            let source = format!(
                "local chunk={{}};local function run(...) {wrapped} end; \
                 local a,b,c,d=run(0x101,3,0,0);assert(a==14 and b==1 and c==3 and d==nil); \
                 local e,f,g,h=run(0x202,0,4,0);assert(e==15 and f==2 and g==4 and h==nil); \
                 local i,j,k,l=run(0x303,0,0,0);assert(i==11 and j==0 and k==0 and l==true); \
                 local m,n,o,p=run(0x999,0,0,0);assert(m==11 and n==0 and o==0 and p==nil); \
                 local q,r,s,t,u,v=run(0x505,9,0,0);assert(q==11 and s==0 and t==true and u==0 and v==9);io.write('RELAY_OK')",
                wrapped = wrapped,
            );
            let compressed = Compressor::compress(&source).expect("compress relay code");
            assert_eq!(run_lua(&lua, &source, "relay_source.lua"), "RELAY_OK");
            assert_eq!(run_lua(&lua, &compressed, "relay_compressed.lua"), "RELAY_OK");
        }
    }
}
