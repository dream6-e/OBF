//! Semantics-preserving relay dispatch for VM instruction cases.
//!
//! The frame setup remains in `execute`; opcode cases are independent functions and
//! each returns its next PC to the iterative driver. The opcode→handler wiring is
//! hidden rather than merely shuffled:
//!
//! * handlers live in a shuffled registry array; bodies keep randomized keyword
//!   wraps (`do`/single-iteration `while`/`repeat`), aliased parameter
//!   permutations, and fallthrough returns trimmed to the flags actually used;
//! * the route/case mapping never appears as keyed assignments. Wires are a flat,
//!   shuffled numeric blob (opcode, masked slot index pairs + trailing garbage)
//!   that reads like ordinary data, and one or two empty "front" tables resolve
//!   lookups through an `__index` metamethod that scans the wires and caches hits;
//! * burn-after-use: once every wire pair has been resolved once, the resolver
//!   refills the cache, nils the wire blob and drops the metatable, so a later
//!   dump finds no wiring; until then the cache is periodically wiped;
//! * the dispatch expression is picked among several equivalent templates;
//! * decoy maps live inside `if false` / zero-trip `for` blocks;
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

/// Split a handler body into micro-steps:
/// 1) Explicit `/*MICRO_SEP*/` markers emitted by custom/builtin opcodes;
/// 2) Cold-handler wrappers ending with the two `pc=vm[k_pc];top=vm[k_top];` slot restores,
///    normalized so all cold handlers share a single post-sync micro-handler.
fn split_micro_steps(
    raw_body: &str,
    u0: &str,
    u1: &str,
    u2: &str,
    pc: &str,
    top: &str,
) -> Vec<String> {
    let body = raw_body
        .replace("{U0}", u0)
        .replace("{U1}", u1)
        .replace("{U2}", u2);
    if body.contains("/*MICRO_SEP*/") {
        let steps: Vec<String> = body
            .split("/*MICRO_SEP*/")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !steps.is_empty() {
            return steps;
        }
    }
    if !body.contains(" end") && !body.contains("return ") {
        let parts: Vec<&str> = body
            .split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() >= 3 {
            let last1 = parts[parts.len() - 2];
            let last2 = parts[parts.len() - 1];
            let pc_prefix = format!("{}=", pc);
            let top_prefix = format!("{}=", top);
            let is_pc_top = last1.starts_with(&pc_prefix)
                && last1.contains('[')
                && last2.starts_with(&top_prefix)
                && last2.contains('[');
            let is_top_pc = last1.starts_with(&top_prefix)
                && last1.contains('[')
                && last2.starts_with(&pc_prefix)
                && last2.contains('[');
            if is_pc_top || is_top_pc {
                let (pc_stmt, top_stmt) = if is_pc_top {
                    (last1, last2)
                } else {
                    (last2, last1)
                };
                let step0 = format!("{};", parts[..parts.len() - 2].join(";"));
                let step1 = format!("{};{};", pc_stmt, top_stmt);
                return vec![step0, step1];
            }
        }
    }
    vec![body]
}

struct IntervalHash {
    p: u64,
    m: u64,
    a: u64,
    style: u64,
    p1: u64,
    order: Vec<usize>,
    thresholds: Vec<u64>,
}

/// Find a collision-free modular affine hash `(op * M + A) % P` that maps each branch's
/// `base_op` set into a strictly disjoint contiguous interval on `[0, P - 1]`.
fn find_interval_hash(
    rng: &mut TinyRng,
    branch_ops: &[Vec<u32>],
    max_iters: usize,
) -> Option<IntervalHash> {
    let k = branch_ops.len();
    if k < 2 {
        return None;
    }
    let total_ops: usize = branch_ops.iter().map(|v| v.len()).sum();
    let mut pts: Vec<(u64, usize)> = Vec::with_capacity(total_ops);
    let mut trans: Vec<usize> = Vec::with_capacity(k + 1);
    for _ in 0..max_iters {
        let style = rng.range(3);
        let p1 = 0x8001 + rng.range(0x7FE0);
        let p = 251 + rng.range(3800);
        let m = (0x101 + rng.range(0x7FE00)) | 1;
        pts.clear();
        for (b_idx, ops) in branch_ops.iter().enumerate() {
            for &op in ops {
                let x = if style == 2 { (op as u64) % p1 } else { op as u64 };
                let z = (x * m) % p;
                pts.push((z, b_idx));
            }
        }
        pts.sort_unstable_by_key(|&(z, _)| z);
        if pts.windows(2).any(|w| w[0].0 == w[1].0) {
            continue;
        }
        trans.clear();
        for i in 0..pts.len() {
            let next = (i + 1) % pts.len();
            if pts[i].1 != pts[next].1 {
                trans.push(i);
            }
        }
        if trans.len() != k {
            continue;
        }
        let cut_idx = trans[rng.range(trans.len() as u64) as usize];
        let start_idx = (cut_idx + 1) % pts.len();
        let z_end = pts[cut_idx].0;
        let z_start = pts[start_idx].0;
        let gap = (z_start + p - z_end) % p;
        if gap == 0 {
            continue;
        }
        let delta = rng.range(gap);
        let a_mod = (p - z_start + delta) % p;
        let a_full = a_mod + (1 + rng.range(0x3FFF)) * p;
        let eval = |op: u32| -> u64 {
            let x = if style == 2 { (op as u64) % p1 } else { op as u64 };
            (x * m + a_full) % p
        };
        let mut bounds: Vec<(usize, u64, u64)> = Vec::with_capacity(k);
        for (b_idx, ops) in branch_ops.iter().enumerate() {
            let mut lo = u64::MAX;
            let mut hi = 0u64;
            for &op in ops {
                let h = eval(op);
                if h < lo {
                    lo = h;
                }
                if h > hi {
                    hi = h;
                }
            }
            bounds.push((b_idx, lo, hi));
        }
        bounds.sort_unstable_by_key(|&(_, lo, _)| lo);
        if bounds.windows(2).any(|w| w[0].2 >= w[1].1) {
            continue;
        }
        let mut order = Vec::with_capacity(k);
        let mut thresholds = Vec::with_capacity(k - 1);
        for j in 0..k {
            order.push(bounds[j].0);
            if j + 1 < k {
                let hi = bounds[j].2;
                let next_lo = bounds[j + 1].1;
                thresholds.push(hi + rng.range(next_lo - hi));
            }
        }
        return Some(IntervalHash {
            p,
            m,
            a: a_full,
            style,
            p1,
            order,
            thresholds,
        });
    }
    None
}

fn build_fused_body(
    rng: &mut TinyRng,
    tag: &str,
    pc: &str,
    ih: &IntervalHash,
    branch_bodies: &[String],
) -> String {
    let dv = rng.name(tag);
    let hash_expr = match ih.style {
        0 => format!("(op*0X{m:X}+0X{a:X})%0X{p:X}", m = ih.m, a = ih.a, p = ih.p),
        1 => format!("(0X{a:X}+op*0X{m:X})%0X{p:X}", a = ih.a, m = ih.m, p = ih.p),
        _ => format!(
            "((op%0X{p1:X})*0X{m:X}+0X{a:X})%0X{p:X}",
            p1 = ih.p1,
            m = ih.m,
            a = ih.a,
            p = ih.p
        ),
    };
    let clean = |idx: usize| -> String {
        let raw = &branch_bodies[ih.order[idx]];
        let t = raw.trim().trim_end_matches(';').trim();
        if t.is_empty() {
            format!("{pc}={pc}", pc = pc)
        } else {
            t.to_string()
        }
    };
    let k = ih.order.len();
    let t = &ih.thresholds;
    match k {
        2 => {
            let (b0, b1) = (clean(0), clean(1));
            if rng.coin() {
                format!(
                    "local {dv}={h};if {dv}<=0X{t0:X} then {b0} else {b1} end;",
                    dv = dv,
                    h = hash_expr,
                    t0 = t[0],
                    b0 = b0,
                    b1 = b1
                )
            } else {
                format!(
                    "local {dv}={h};if {dv}>0X{t0:X} then {b1} else {b0} end;",
                    dv = dv,
                    h = hash_expr,
                    t0 = t[0],
                    b0 = b0,
                    b1 = b1
                )
            }
        }
        3 => {
            let (b0, b1, b2) = (clean(0), clean(1), clean(2));
            match rng.range(3) {
                0 => format!(
                    "local {dv}={h};if {dv}<=0X{t0:X} then {b0} elseif {dv}<=0X{t1:X} then {b1} else {b2} end;",
                    dv = dv, h = hash_expr, t0 = t[0], t1 = t[1], b0 = b0, b1 = b1, b2 = b2
                ),
                1 => format!(
                    "local {dv}={h};if {dv}>0X{t1:X} then {b2} elseif {dv}>0X{t0:X} then {b1} else {b0} end;",
                    dv = dv, h = hash_expr, t0 = t[0], t1 = t[1], b0 = b0, b1 = b1, b2 = b2
                ),
                _ => format!(
                    "local {dv}={h};if {dv}<=0X{t1:X} then if {dv}<=0X{t0:X} then {b0} else {b1} end else {b2} end;",
                    dv = dv, h = hash_expr, t0 = t[0], t1 = t[1], b0 = b0, b1 = b1, b2 = b2
                ),
            }
        }
        4 => {
            let (b0, b1, b2, b3) = (clean(0), clean(1), clean(2), clean(3));
            match rng.range(3) {
                0 => format!(
                    "local {dv}={h};if {dv}<=0X{t1:X} then if {dv}<=0X{t0:X} then {b0} else {b1} end else if {dv}<=0X{t2:X} then {b2} else {b3} end end;",
                    dv = dv, h = hash_expr, t0 = t[0], t1 = t[1], t2 = t[2], b0 = b0, b1 = b1, b2 = b2, b3 = b3
                ),
                1 => format!(
                    "local {dv}={h};if {dv}<=0X{t0:X} then {b0} elseif {dv}<=0X{t1:X} then {b1} elseif {dv}<=0X{t2:X} then {b2} else {b3} end;",
                    dv = dv, h = hash_expr, t0 = t[0], t1 = t[1], t2 = t[2], b0 = b0, b1 = b1, b2 = b2, b3 = b3
                ),
                _ => format!(
                    "local {dv}={h};if {dv}>0X{t2:X} then {b3} elseif {dv}>0X{t1:X} then {b2} elseif {dv}>0X{t0:X} then {b1} else {b0} end;",
                    dv = dv, h = hash_expr, t0 = t[0], t1 = t[1], t2 = t[2], b0 = b0, b1 = b1, b2 = b2, b3 = b3
                ),
            }
        }
        _ => clean(0),
    }
}

/// Build the hidden opcode→handler wiring (flat wire blobs resolved through
/// `__index` fronts) and one independent function per distinct case. The setup
/// block is hoisted by `wrap_dispatcher` before the iterative driver is emitted.
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
    setmetatable: &str,
    rawset: &str,
) -> String {
    let mut rng = TinyRng::new(
        vm_seed
            ^ (entries.len() as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9)
            ^ (execute_name.len() as u64).wrapping_mul(0x94D0_49BB_1331_11EB),
    );
    let tag = rng.name(&format!("{}_dx", execute_name));
    let (u0, u1, u2) = (rng.name(&tag), rng.name(&tag), rng.name(&tag));
    let sub_op = rng.name(&tag);

    let mut base_ops: Vec<u32> = entries.iter().map(|(op, _)| *op).collect();
    base_ops.sort_unstable();
    base_ops.dedup();
    let (delta_1, delta_2) = loop {
        let d1 = 0x0001_0000 + (rng.range(0x0FFE_0000) as u32);
        let d2 = 0x1000_0000 + (rng.range(0x0FFE_0000) as u32);
        let mut seen = std::collections::HashSet::with_capacity(base_ops.len() * 3);
        for &op in &base_ops {
            seen.insert(op);
        }
        let mut ok = true;
        for &op in &base_ops {
            match (op.checked_add(d1), op.checked_add(d2)) {
                (Some(k1), Some(k2)) => {
                    if !seen.insert(k1) || !seen.insert(k2) {
                        ok = false;
                        break;
                    }
                }
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            break (d1, d2);
        }
    };

    // Expand multi-stage handlers into micro-step entries (Scheme 2: sub_op micro-step ring
    // + cross-instruction shared pre-step / post-step deduplication).
    let mut origin_bodies: Vec<&str> = Vec::new();
    let mut expanded_entries: Vec<(u32, String)> = Vec::with_capacity(entries.len() * 2);
    let mut expanded_meta: Vec<(u32, usize)> = Vec::with_capacity(entries.len() * 2);
    for (opcode, raw_body) in entries.iter() {
        let origin_id = if let Some(pos) = origin_bodies.iter().position(|&b| b == raw_body.as_str()) {
            pos
        } else {
            origin_bodies.push(raw_body.as_str());
            origin_bodies.len() - 1
        };
        let steps = split_micro_steps(raw_body, &u0, &u1, &u2, pc, top);
        if steps.len() <= 1 {
            let b = steps.into_iter().next().unwrap_or_default();
            expanded_entries.push((*opcode, b));
            expanded_meta.push((*opcode, origin_id));
        } else if steps.len() == 2 {
            let s0 = steps[0].trim().trim_end_matches(';');
            let b0 = format!("{s0};{sub}=op+0X{d1:X};", s0 = s0, sub = sub_op, d1 = delta_1);
            expanded_entries.push((*opcode, b0));
            expanded_meta.push((*opcode, origin_id));
            expanded_entries.push((opcode.wrapping_add(delta_1), steps[1].clone()));
            expanded_meta.push((*opcode, origin_id));
        } else {
            let s0 = steps[0].trim().trim_end_matches(';');
            let b0 = format!("{s0};{sub}=op+0X{d1:X};", s0 = s0, sub = sub_op, d1 = delta_1);
            let s1 = steps[1].trim().trim_end_matches(';');
            let b1 = format!("{s1};{sub}=op+0X{d2:X};", s1 = s1, sub = sub_op, d2 = delta_2);
            expanded_entries.push((*opcode, b0));
            expanded_meta.push((*opcode, origin_id));
            expanded_entries.push((opcode.wrapping_add(delta_1), b1));
            expanded_meta.push((*opcode, origin_id));
            expanded_entries.push((opcode.wrapping_add(delta_2), steps[2].clone()));
            expanded_meta.push((*opcode, origin_id));
        }
    }

    // Deduplicate identical handler bodies first.
    let mut raw_unique: Vec<String> = Vec::new();
    let mut raw_e_indices: Vec<Vec<usize>> = Vec::new();
    let mut raw_origins: Vec<Vec<usize>> = Vec::new();
    for (e_i, (_opcode, body)) in expanded_entries.iter().enumerate() {
        let (_, origin_id) = expanded_meta[e_i];
        let idx = if let Some(pos) = raw_unique.iter().position(|old| old == body) {
            pos
        } else {
            raw_unique.push(body.clone());
            raw_e_indices.push(Vec::new());
            raw_origins.push(Vec::new());
            raw_unique.len() - 1
        };
        raw_e_indices[idx].push(e_i);
        if !raw_origins[idx].contains(&origin_id) {
            raw_origins[idx].push(origin_id);
        }
    }

    // Scheme 1: Fuse unshared leaf / terminal micro-handlers into 3~4 way heterogeneous
    // parameterized handlers dispatched by a modular affine hash `(op * M + A) % P`,
    // eliminating 1-line single-operator (`+`, `-`, `*`, `<`, `[]`, etc.) handler fingerprints.
    struct FuseSlice {
        u_idx: usize,
        e_indices: Vec<usize>,
        base_ops: Vec<u32>,
    }
    let mut unique: Vec<String> = Vec::new();
    let mut handler_of: Vec<usize> = vec![0usize; expanded_entries.len()];
    let mut pool: Vec<FuseSlice> = Vec::new();
    for u_idx in 0..raw_unique.len() {
        let body = &raw_unique[u_idx];
        let is_fusable = raw_origins[u_idx].len() <= 2
            && !ends_with_return_statement(body)
            && trimmed_flags(body, &[r1, r2, r3]).is_empty();
        if !is_fusable {
            let new_idx = unique.len();
            unique.push(body.clone());
            for &e_i in &raw_e_indices[u_idx] {
                handler_of[e_i] = new_idx;
            }
            continue;
        }
        let e_list = &raw_e_indices[u_idx];
        let max_slice = if body.len() <= 110 {
            2
        } else if e_list.len() <= 4 {
            4
        } else {
            3
        };
        for chunk in e_list.chunks(max_slice) {
            let mut b_ops: Vec<u32> = chunk.iter().map(|&e_i| expanded_meta[e_i].0).collect();
            b_ops.sort_unstable();
            b_ops.dedup();
            pool.push(FuseSlice {
                u_idx,
                e_indices: chunk.to_vec(),
                base_ops: b_ops,
            });
        }
    }
    rng.shuffle(&mut pool);

    let mut fused_groups: Vec<(IntervalHash, Vec<FuseSlice>)> = Vec::new();
    while !pool.is_empty() {
        if pool.len() == 1 {
            let mut rem_opt = Some(pool.pop().unwrap());
            for (ih_slot, grp) in fused_groups.iter_mut() {
                let rem = rem_opt.as_ref().unwrap();
                if grp.len() < 4
                    && grp.iter().all(|g| g.u_idx != rem.u_idx)
                    && grp
                        .iter()
                        .all(|g| g.base_ops.iter().all(|op| !rem.base_ops.contains(op)))
                {
                    let mut test_ops: Vec<Vec<u32>> =
                        grp.iter().map(|g| g.base_ops.clone()).collect();
                    test_ops.push(rem.base_ops.clone());
                    if let Some(new_ih) = find_interval_hash(&mut rng, &test_ops, 1500) {
                        grp.push(rem_opt.take().unwrap());
                        *ih_slot = new_ih;
                        break;
                    }
                }
            }
            if let Some(rem) = rem_opt {
                let new_idx = unique.len();
                unique.push(raw_unique[rem.u_idx].clone());
                for e_i in rem.e_indices {
                    handler_of[e_i] = new_idx;
                }
            }
            break;
        }
        let target_k = match pool.len() {
            2 => 2,
            3 => 3,
            4 => 4,
            5 => 3,
            _ => {
                if rng.coin() {
                    4
                } else {
                    3
                }
            }
        };
        // Pick first slice from the u_idx with the highest remaining slice count in pool.
        let mut best_pos = 0usize;
        let mut best_cnt = 0usize;
        for (i, s) in pool.iter().enumerate() {
            let cnt = pool.iter().filter(|x| x.u_idx == s.u_idx).count();
            if cnt > best_cnt {
                best_cnt = cnt;
                best_pos = i;
            }
        }
        let mut grp = vec![pool.remove(best_pos)];
        while grp.len() < target_k {
            let cur_ops: usize = grp.iter().map(|g| g.base_ops.len()).sum();
            let mut found = None;
            for (i, cand) in pool.iter().enumerate() {
                if grp.iter().all(|g| g.u_idx != cand.u_idx)
                    && grp
                        .iter()
                        .all(|g| g.base_ops.iter().all(|op| !cand.base_ops.contains(op)))
                    && (cur_ops + cand.base_ops.len() <= 9 || grp.len() == 1)
                {
                    found = Some(i);
                    break;
                }
            }
            if let Some(i) = found {
                grp.push(pool.remove(i));
            } else {
                break;
            }
        }
        loop {
            if grp.len() < 2 {
                let only = grp.pop().unwrap();
                let new_idx = unique.len();
                unique.push(raw_unique[only.u_idx].clone());
                for e_i in only.e_indices {
                    handler_of[e_i] = new_idx;
                }
                break;
            }
            let branch_ops: Vec<Vec<u32>> = grp.iter().map(|g| g.base_ops.clone()).collect();
            if let Some(ih) = find_interval_hash(&mut rng, &branch_ops, 1500) {
                fused_groups.push((ih, grp));
                break;
            }
            let popped = grp.pop().unwrap();
            pool.push(popped);
        }
    }

    for (ih, grp) in fused_groups {
        let branch_bodies: Vec<String> =
            grp.iter().map(|g| raw_unique[g.u_idx].clone()).collect();
        let fused_body = build_fused_body(&mut rng, &tag, pc, &ih, &branch_bodies);
        let new_idx = unique.len();
        unique.push(fused_body);
        for slice in grp {
            for e_i in slice.e_indices {
                handler_of[e_i] = new_idx;
            }
        }
    }

    // Handler registry order is shuffled; slot_of maps original index -> slot.
    let mut order: Vec<usize> = (0..unique.len()).collect();
    rng.shuffle(&mut order);
    let mut slot_of = vec![0usize; unique.len()];
    for (slot, orig) in order.iter().enumerate() {
        slot_of[*orig] = slot;
    }

    let handlers_name = rng.name(&tag);
    let fallback = rng.name(&tag);
    let mask = 1 + rng.range(0x00FF_FFFF) as u32;

    // ---- emit handlers (mix of named defs and inline closures) --------------
    let mut setup = format!(
        "local rk1,rk2,{u0},{u1},{u2},{sub_op};",
        u0 = u0,
        u1 = u1,
        u2 = u2,
        sub_op = sub_op,
    );
    let mut h_entries: Vec<String> = vec![String::new(); unique.len()];
    for (slot, orig) in order.iter().enumerate() {
        let body = &unique[*orig];
        let aliased = rng.coin();
        let (params, alias_stmt) = handler_params(&mut rng, aliased);
        let (j1, j2) = (rng.name(&tag), rng.name(&tag));
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
        if rng.coin() {
            let hname = rng.name(&tag);
            setup.push_str(&format!(
                "local function {hname}({params}) {inner} end;",
                hname = hname,
                params = params,
                inner = inner,
            ));
            h_entries[slot] = hname;
        } else {
            h_entries[slot] = format!("function({params}) {inner} end", params = params, inner = inner);
        }
    }
    setup.push_str(&format!("local {handlers_name}={{{entries}}};", handlers_name = handlers_name, entries = h_entries.join(",")));

    // Fallback in one of several equivalent shapes.
    setup.push_str(&match rng.range(3) {
        0 => format!("local {fallback}=function() return {pc},nil,nil,nil end;", fallback = fallback, pc = pc),
        1 => format!("local function {fallback}() do return {pc},nil,nil,nil end end;", fallback = fallback, pc = pc),
        _ => format!("local {fallback}=function() local {j}; return {pc},nil,nil,nil end;", fallback = fallback, pc = pc, j = rng.name(&tag)),
    });

    // ---- fronts: empty tables whose __index resolves from flat wire data -----
    // (schemes 4/11/14: metatable indirection, data-pool disguise, burn-after-use)
    let front_count = 1 + rng.range(2) as usize;
    let mut front_pairs: Vec<Vec<(u32, usize)>> = vec![Vec::new(); front_count];
    for (e_i, (opcode, _body)) in expanded_entries.iter().enumerate() {
        let slot = slot_of[handler_of[e_i]];
        let f = rng.range(front_count as u64) as usize;
        front_pairs[f].push((*opcode, slot));
    }
    // Keep fronts balanced-ish: move pairs out of the busiest front if one is empty.
    if front_count > 1 && front_pairs.iter().any(|p| p.is_empty()) {
        let (donor, _) = front_pairs.iter().enumerate().max_by_key(|(_, p)| p.len()).unwrap();
        for f in 0..front_count {
            if front_pairs[f].is_empty() {
                let moved = front_pairs[donor].pop().unwrap();
                front_pairs[f].push(moved);
            }
        }
    }
    let mut front_names: Vec<String> = Vec::new();
    for f in 0..front_count {
        let wname = rng.name(&tag);
        let wsname = rng.name(&tag);
        let fname = rng.name(&tag);
        let burn_fn = rng.name(&tag);
        let look_c = rng.name(&tag);
        let ck_f = 0x1000_0000 + (rng.range(0x6FFF_0000) as u32);
        let burn_at = 64 + rng.range(192);
        let mut pairs = front_pairs[f].clone();
        rng.shuffle(&mut pairs);
        let total = pairs.len();
        // Flat numeric wire blob: shuffled (opcode, masked slot) pairs plus
        // a few trailing garbage numbers so it reads like ordinary data.
        let mut nums: Vec<String> = Vec::with_capacity(total * 2 + 4);
        for (op, slot) in &pairs {
            nums.push(format!("0X{:X}", op));
            nums.push(format!("0X{:X}", (*slot as u32) + 1 + mask));
        }
        for _ in 0..rng.range(5) {
            nums.push(format!("0X{:X}", rng.next() as u32));
        }
        let scan_end = total * 2;
        // Resolver: scan wire pairs and cache slot indices on the prototype table `chunk`
        // (with burn-after-use wiping `w` and dropping the metatable), while the frame-local
        // front table caches the bound handler function directly for 1-hop hot-loop dispatch.
        setup.push_str(&format!(
            "local {ws}=chunk and chunk[0X{ck:X}];if not {ws} then local {w}={{{nums}}};local {lc}=0;local function {bf}(t) local j=1;while j<={end_i} do {rs}(t,{w}[j],{w}[j+1]-{mask});j=j+2 end;{w}=nil;{sm}(t,nil) end;{ws}={sm}({{}},{{__index=function(t,k) local i=1;while i<={end_i} do if {w}[i]==k then local s={w}[i+1]-{mask};{rs}(t,k,s);{lc}={lc}+1;if {lc}>={burn} then {bf}(t) end;return s end;i=i+2 end;{rs}(t,k,false);{lc}={lc}+1;if {lc}>={burn} then {bf}(t) end;return false end}});if chunk then chunk[0X{ck:X}]={ws} end end;local {f}={sm}({{}},{{__index=function(t,k) local s={ws}[k];local fn=s and {h}[s] or false;{rs}(t,k,fn);return fn end}});",
            ws = wsname,
            f = fname,
            ck = ck_f,
            w = wname,
            nums = nums.join(","),
            lc = look_c,
            bf = burn_fn,
            h = handlers_name,
            mask = format!("0X{:X}", mask),
            end_i = scan_end,
            burn = burn_at,
            sm = setmetatable,
            rs = rawset,
        ));
        front_names.push(fname);
    }
    // Dead-code decoys stay: plausible fake maps guarded by runtime handler-table invariants.
    setup.push_str(&decoy_block(&mut rng, &tag, &format!("{}_d", tag), &handlers_name, &fallback));

    // ---- dispatch expression (several equivalent templates) ------------------
    let mut order_f: Vec<usize> = (0..front_count).collect();
    rng.shuffle(&mut order_f);
    let ov = format!("{}-{}", route_op, bias);
    let f = rng.name(&tag);
    let g = rng.name(&tag);
    let np = rng.name(&tag);
    let (ra, rb, rc) = (rng.name(&tag), rng.name(&tag), rng.name(&tag));
    let chain = order_f
        .iter()
        .map(|i| format!("{}[{}]", front_names[*i], sub_op))
        .collect::<Vec<_>>()
        .join(" or ");
    let call = format!(
        "{sub}=nil;{np},{ra},{rb},{rc}={f}(op,inst_A,inst_B,inst_C);",
        sub = sub_op,
        np = np,
        ra = ra,
        rb = rb,
        rc = rc,
        f = f,
    );
    let tail = format!(
        "if {np}==true then {r1}=true;{sub}=nil else {pc}={np};if {ra}~=nil then {r1},{r2},{r3}={ra},{rb},{rc};if {ra}==true then {sub}=nil end end end;",
        np = np,
        pc = pc,
        r1 = r1,
        r2 = r2,
        r3 = r3,
        ra = ra,
        rb = rb,
        rc = rc,
        sub = sub_op,
    );
    let step_dispatch = match rng.range(3) {
        0 => format!("local {f}={chain} or {fallback};{call}{tail}", f = f, chain = chain, fallback = fallback, call = call, tail = tail),
        1 => format!(
            "local {f}={fallback};do local {g}={chain};if {g} then {f}={g} end end;{call}{tail}",
            f = f, fallback = fallback, g = g, chain = chain, call = call, tail = tail,
        ),
        _ => format!(
            "local {g}={chain};local {f}={g} or {fallback};{call}{tail}",
            g = g,
            chain = chain,
            f = f,
            fallback = fallback,
            call = call,
            tail = tail,
        ),
    };
    let dispatch = format!(
        "{sub}={ov};repeat {step_dispatch} until not {sub};",
        sub = sub_op,
        ov = ov,
        step_dispatch = step_dispatch,
    );

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
            format!("local {once}=op;while {once}==op do {once}=nil;{body} end;", once = once, body = body)
        }
        (3, false) => format!("repeat {} until op~=nil;", body),
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

/// Dead-code decoys: tables shaped like case/route maps, guarded by runtime table length / closure state.
fn decoy_block(rng: &mut TinyRng, tag: &str, dtag: &str, handlers_name: &str, fallback_name: &str) -> String {
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
        format!("if #{h}==0X0 or {fb}==nil then {inner} end;", h = handlers_name, fb = fallback_name, inner = inner)
    } else {
        format!("for {}=0X1,(#{h}>0X0 and 0X0 or 0X1) do {inner} end;", rng.name(tag), h = handlers_name, inner = inner)
    }
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

    // Eight distinct randomized state codes generated at runtime via metatable (__add/__sub/__mul).
    let mut offsets: Vec<u32> = (0..256).step_by(1).collect::<Vec<u32>>();
    rng.shuffle(&mut offsets);
    let state_nums: Vec<i64> = offsets[..8].iter().map(|o| (base + o * 0x100 + 0x11) as i64).collect();
    let mt_var = format!("{}_{}", route_name, rng.name("mt"));
    let mt_base = (((rng.next() as u32) & 0x00FF_FFFF) + 0x10_0000) as i64;
    let mut grng = crate::VM::VM_Backend::Generator_util::GenRng::new(flow_seed);
    let mt_decl = crate::VM::VM_Backend::Generator_util::emit_mt_state_decl(&mut grng, &mt_var, mt_base);
    let mt_decl = mt_decl.strip_prefix("local ").unwrap_or(&mt_decl).to_string();
    let s0 = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[0]);
    let s1 = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[1]);
    let s2 = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[2]);
    let s3 = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[3]);
    let s4 = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[4]);
    let s5 = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[5]);
    let s6 = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[6]);
    let s7 = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[7]);
    let s6_b = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[6]);
    let s7_b = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[7]);
    let s6_c = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[6]);
    let s7_c = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[7]);
    let s7_d = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[7]);
    let states: Vec<String> = (0..8)
        .map(|i| crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut grng, &mt_var, mt_base, state_nums[i]))
        .collect();

    // Keep setup in its original position; the nested step closure captures its locals.
    let loop_body = if !has_handlers {
        // Preserve the previous empty-tree behavior: enter once, break, and return no values.
        format!("while {step}~=nil do break end", step = step_name)
    } else {
        let (open, close) = match loop_form {
            LoopForm::While => (
                format!("while {step}~={core} do ", step = step_name, core = core_name),
                " end;".to_string(),
            ),
            LoopForm::Repeat => (
                "repeat ".to_string(),
                format!(" until {step}=={core};", step = step_name, core = core_name),
            ),
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
            "while {ra}~={rb} and {st}~={rb}[0X1] and {st}~={rb}[0X2] do {step} end;",
            ra = relay_a, rb = relay_b, st = state_name, step = route_step,
        ),
        LoopForm::Repeat => format!(
            "repeat {step} until {st}=={rb}[0X1] or {st}=={rb}[0X2];",
            step = route_step, st = state_name, rb = relay_b,
        ),
    };

    // Randomly shard the eight state handlers across the two relay tables.
    let state_bodies: Vec<String> = vec![
        format!("function({gate},...) if {gate} and {ra}~={rb} then return {ra}[0X3] end return {ra}[0X4] end", gate = gate_name, ra = relay_a, rb = relay_b),
        format!("function({gate},...) if not {gate} or {ra}=={rb} then return {s5} end return {s4} end", gate = gate_name, ra = relay_a, rb = relay_b, s5 = s5, s4 = s4),
        format!("function({gate},...) local {index}; repeat {index}={rb}[0X3] until {index}~=nil and {ra}~={rb}; return {index} end", gate = gate_name, index = index_name, ra = relay_a, rb = relay_b),
        format!("function(...) return {} end", s7_b),
        format!("function(...) return {} end", s6_c),
        format!(
            // 目标五：上界不再写死 `0X1,0X1`；由运行期 gate 决定 1~2 次，体是纯赋值可重复。
            "function({gate},...) local {index},{next_state}; for {index}=0X1,({gate} and 0X2 or 0X1) do if not {gate} or {ra}=={rb} then {next_state}={s7} end; if {gate} and {ra}~={rb} then {next_state}={s6} end end; return {next_state} or {s7_d} end",
            gate = gate_name, index = index_name, next_state = format!("{}_next", state_name), ra = relay_a, rb = relay_b, s7 = s7_c, s6 = s6, s7_d = s7_d,
        ),
        format!("function({gate},a,b,...) return a(...) end", gate = gate_name),
        format!("function({gate},a,b,...) return b(...) end", gate = gate_name),
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
    let ck1 = ((rng.next() as u32) & 0x3FFF_FFFF) | 0x1000_0000;
    let ck2 = ck1 ^ 0x05A5_A5A5;
    let ck3 = ck1 ^ 0x0A5A_5A5A;

    format!(
        r#"local function {core}(...) {core_body} end;
local function {exit_a}(...) return {core}(...) end;
local function {exit_b}(...) return {core}(...) end;
local {mt_var},{relay_a},{relay_b};
if {chunk} then {mt_var},{relay_a},{relay_b}={chunk}[0X{ck1:X}],{chunk}[0X{ck2:X}],{chunk}[0X{ck3:X}] end;
if not {mt_var} then {mt_decl}{relay_a},{relay_b}={{{s0},{s1},{s2},{s3}}},{{{s6},{s7},{s6_b}}};{relay_defs}if {chunk} then {chunk}[0X{ck1:X}],{chunk}[0X{ck2:X}],{chunk}[0X{ck3:X}]={mt_var},{relay_a},{relay_b} end end;
local function {route}(...)
  local {gate}=({chunk}~=nil and {ra}~={rb}) or {ra}=={rb};
  local {state}={start} and {ra}[0X1] or {ra}[0X2];
  {route_loop}
  return ({ra}[{state}] or {rb}[{state}])({gate},{exit_a},{exit_b},...)
end;
return {route}(...);"#,
        core = core_name,
        core_body = core_body,
        exit_a = exit_a,
        exit_b = exit_b,
        mt_var = mt_var,
        mt_decl = mt_decl,
        ck1 = ck1,
        ck2 = ck2,
        ck3 = ck3,
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
        s2 = s2,
        s3 = s3,
        s6 = s6,
        s7 = s7,
        s6_b = s6_b,
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
            (0x606, "{U0}=inst_A;{U1}=inst_B/*MICRO_SEP*/value={U0}+{U1};pc=pc+2;".to_string()),
            (0x707, "{U0}=inst_A;{U1}=inst_B/*MICRO_SEP*/value={U0}-{U1};pc=pc+2;".to_string()),
        ];
        for seed in [0x1234u64, 0xBEEF, 0x0F0F_0F0F, 0xDEAD_BEEF] {
            let dispatch = build_relay_dispatch(
                &entries, "pc", "top", "r1", "r2", "r3", "route_op", "bias", "relay_test", seed,
                "setmetatable", "rawset",
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
            for fold_lit in ["if false", "true or false", "false or false", "not true"] {
                assert!(!wrapped.contains(fold_lit), "constant-foldable boolean literal leaked: {fold_lit}");
            }
            assert!(wrapped.contains("setmetatable"), "front tables must hide behind __index");
            assert!(wrapped.contains("__index"), "resolver must live in the metatable");
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
                 local q,r,s,t,u,v=run(0x505,9,0,0);assert(q==11 and s==0 and t==true and u==0 and v==9); \
                 local ma,mb,mc=run(0x606,8,3,0);assert(ma==13 and mb==0 and mc==11); \
                 local md,me,mf=run(0x707,8,3,0);assert(md==13 and me==0 and mf==5);io.write('RELAY_OK')",
                wrapped = wrapped,
            );
            let compressed = Compressor::compress(&source).expect("compress relay code");
            assert_eq!(run_lua(&lua, &source, "relay_source.lua"), "RELAY_OK");
            assert_eq!(run_lua(&lua, &compressed, "relay_compressed.lua"), "RELAY_OK");
        }
    }
}
