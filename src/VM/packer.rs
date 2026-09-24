use std::time::SystemTime;
use rand::{rngs::StdRng, Rng, SeedableRng, random};

use crate::VM::Control_Flow::Control_flow::ControlFlowBuilder;
use crate::VM::VM_Backend::Generator::GenRng;
use crate::VM::VM_Backend::Sandbox::generate_sandbox;

struct SimpleRng {
    rng: StdRng,
}

impl SimpleRng {
    fn new(seed: u32) -> Self {
        let seed_val = if seed == 0 {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        } else {
            let t = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            t ^ (seed as u64)
        };
        
        Self {
            rng: StdRng::seed_from_u64(seed_val),
        }
    }

    fn next(&mut self) -> u32 {
        self.rng.random()
    }

    fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max { return min; }
        self.rng.random_range(min..max)
    }
}

#[derive(Clone, Copy)]
enum Step {
    Raw,
    Link { stride: u16, span: u16 },
}

pub struct Packer;

impl Packer {
    pub fn pack(input: &[u8], vm_rng: &mut GenRng) -> (String, String, String) {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0xDEADBEEF);
        let mut rng = SimpleRng::new(seed);
        let mut keys = Vec::new();
        for _ in 0..16 {
            keys.push((rng.next() & 0xFF) as u8);
        }
        let alpha_str = Self::generate_alphabet();

        let sandbox = generate_sandbox("kryvex");
        let compressed_sb = Self::encode_stream(sandbox.payload.as_bytes());
        let encrypted_sb = Self::xor_stream_with_keys(&compressed_sb, &keys);
        let b86_sb = Self::base86_encode_with_alpha(&encrypted_sb, &alpha_str);

        let compressed_main = Self::encode_stream(input);
        let encrypted_main = Self::xor_stream_with_keys(&compressed_main, &keys);
        let b86_main = Self::base86_encode_with_alpha(&encrypted_main, &alpha_str);

        let lua_payload = format!("{}~{}", b86_sb, b86_main);
        
        let (decoder_script, entry_func) = Self::build_decoder(&keys, &alpha_str, vm_rng);
        (lua_payload, decoder_script, entry_func)
    }

    fn encode_stream(input: &[u8]) -> Vec<u8> {
        let len = input.len();
        if len == 0 {
            return Vec::new();
        }

        let mut costs = vec![u32::MAX; len + 1];
        let mut links = vec![Step::Raw; len + 1];
        costs[0] = 0;

        for i in 0..len {
            if costs[i] == u32::MAX {
                continue;
            }

            let cost_raw = costs[i] + 9;
            if cost_raw < costs[i + 1] {
                costs[i + 1] = cost_raw;
                links[i + 1] = Step::Raw;
            }

            let max_search = if i > 65535 { i - 65535 } else { 0 };
            let max_span = std::cmp::min(258, len - i);

            let mut optimal_strides = vec![0u16; max_span + 1];
            let mut peak_span = 0;

            for start in max_search..i {
                if peak_span < max_span && input[start + peak_span] == input[i + peak_span] {
                    let mut current_span = 0;
                    while current_span < max_span && input[start + current_span] == input[i + current_span] {
                        current_span += 1;
                    }
                    if current_span > peak_span {
                        for l in (peak_span + 1)..=current_span {
                            optimal_strides[l] = (i - start) as u16;
                        }
                        peak_span = current_span;
                    }
                }
            }

            for span_l in 3..=peak_span {
                let cost_link = costs[i] + 25;
                let next_pos = i + span_l;
                if cost_link < costs[next_pos] {
                    costs[next_pos] = cost_link;
                    links[next_pos] = Step::Link {
                        stride: optimal_strides[span_l],
                        span: span_l as u16,
                    };
                }
            }
        }

        let mut route = Vec::new();
        let mut cursor = len;
        while cursor > 0 {
            match links[cursor] {
                Step::Raw => {
                    route.push(Step::Raw);
                    cursor -= 1;
                }
                Step::Link { stride, span } => {
                    route.push(Step::Link { stride, span });
                    cursor -= span as usize;
                }
            }
        }
        route.reverse();

        let mut output = Vec::new();
        let mut route_head = 0;
        let route_len = route.len();
        let mut read_head = 0;

        while route_head < route_len {
            let mut header = 0u8;
            let mut payload_part = Vec::new();

            for bit in 0..8 {
                if route_head >= route_len {
                    break;
                }

                match route[route_head] {
                    Step::Raw => {
                        header |= 1 << bit;
                        payload_part.push(input[read_head]);
                        read_head += 1;
                    }
                    Step::Link { stride, span } => {
                        let b1 = (stride >> 8) as u8;
                        let b2 = (stride & 0xFF) as u8;
                        let b3 = (span - 3) as u8;
                        payload_part.push(b1);
                        payload_part.push(b2);
                        payload_part.push(b3);
                        read_head += span as usize;
                    }
                }
                route_head += 1;
            }

            output.push(header);
            output.extend_from_slice(&payload_part);
        }

        output
    }

    fn xor_stream_with_keys(input: &[u8], keys: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        for (i, &b) in input.iter().enumerate() {
            output.push(b ^ keys[i % 16]);
        }
        output
    }

    fn generate_alphabet() -> String {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0x56781234);
        let mut rng = SimpleRng::new(seed);

        let mut base_chars: Vec<char> = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,./:;<=>?@|_\'\"\\".chars().collect();
        let n = base_chars.len();
        for i in (1..n).rev() {
            let j = rng.next_range(0, i + 1);
            base_chars.swap(i, j);
        }
        base_chars.insert(0, '-');
        base_chars.iter().collect()
    }

    fn base86_encode_with_alpha(input: &[u8], alphabet_str: &str) -> String {
        let base_chars: Vec<char> = alphabet_str.chars().collect();
        let mut encoded = String::new();
        let len = input.len();
        let chunks = len / 4;
        for i in 0..chunks {
            let val = ((input[i * 4] as usize) << 24)
                | ((input[i * 4 + 1] as usize) << 16)
                | ((input[i * 4 + 2] as usize) << 8)
                | (input[i * 4 + 3] as usize);
            let c1 = val / 54700816;
            let r1 = val % 54700816;
            let c2 = r1 / 636056;
            let r2 = r1 % 636056;
            let c3 = r2 / 7396;
            let r3 = r2 % 7396;
            let c4 = r3 / 86;
            let c5 = r3 % 86;
            encoded.push(base_chars[c1]);
            encoded.push(base_chars[c2]);
            encoded.push(base_chars[c3]);
            encoded.push(base_chars[c4]);
            encoded.push(base_chars[c5]);
        }
        let rem = len % 4;
        if rem == 3 {
            let val = ((input[len - 3] as usize) << 16)
                | ((input[len - 2] as usize) << 8)
                | (input[len - 1] as usize);
            let c1 = val / 636056;
            let r1 = val % 636056;
            let c2 = r1 / 7396;
            let r2 = r1 % 7396;
            let c3 = r2 / 86;
            let c4 = r2 % 86;
            encoded.push(base_chars[c1]);
            encoded.push(base_chars[c2]);
            encoded.push(base_chars[c3]);
            encoded.push(base_chars[c4]);
        } else if rem == 2 {
            let val = ((input[len - 2] as usize) << 8) | (input[len - 1] as usize);
            let c1 = val / 7396;
            let r1 = val % 7396;
            let c2 = r1 / 86;
            let c3 = r1 % 86;
            encoded.push(base_chars[c1]);
            encoded.push(base_chars[c2]);
            encoded.push(base_chars[c3]);
        } else if rem == 1 {
            let val = input[len - 1] as usize;
            let c1 = val / 86;
            let c2 = val % 86;
            encoded.push(base_chars[c1]);
            encoded.push(base_chars[c2]);
        }
        encoded
    }

    fn build_decoder(keys: &[u8], alphabet: &str, rng: &mut GenRng) -> (String, String) {
        let f_entry = rng.name();
        let v_data = rng.name();

        let m_bxor = rng.name();
        let m_next = rng.name();
        let m_init_map = rng.name();
        let m_init_insts = rng.name();
        let m_init_handlers = rng.name();
        let m_run = rng.name();
        let m_main = rng.name();

        let op_state0 = rng.range(100, 200);
        let op_state1 = rng.range(201, 300);
        let op_state2 = rng.range(301, 400);
        let op_state3 = rng.range(401, 500);
        let op_state4 = rng.range(501, 600);
        let op_state5 = rng.range(601, 700);
        let op_state6 = rng.range(701, 800);
        let op_state7 = rng.range(801, 900);
        let op_state8 = rng.range(901, 1000);
        let op_state9 = rng.range(1001, 1100);

        let mut pcs: Vec<usize> = (1..=10).collect();
        for i in (1..10).rev() {
            let j = rng.range(0, i + 1);
            pcs.swap(i, j);
        }
        let pc_state0 = pcs[0];
        let pc_state1 = pcs[1];
        let pc_state2 = pcs[2];
        let pc_state3 = pcs[3];
        let pc_state4 = pcs[4];
        let pc_state5 = pcs[5];
        let pc_state6 = pcs[6];
        let pc_state7 = pcs[7];
        let pc_state8 = pcs[8];
        let pc_state9 = pcs[9];

        let tamper_val = rng.range(10, 50);

        let mut insts_init = Vec::new();
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state0, op_state0));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state1, op_state1));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state2, op_state2));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state3, op_state3));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state4, op_state4));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state5, op_state5));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state6, op_state6));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state7, op_state7));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state8, op_state8));
        insts_init.push(format!("s.insts[{}]={{{}}};", pc_state9, op_state9));

        let n_insts = insts_init.len();
        let mut insts_states: Vec<usize> = (1..=n_insts+1).collect();
        for i in (1..insts_states.len()).rev() {
            let j = rng.range(0, i + 1);
            insts_states.swap(i, j);
        }
        
        let mut init_insts_loop = String::new();
        init_insts_loop.push_str(&format!("st={};while not(false or false) do ", insts_states[0]));
        for (i, inst) in insts_init.iter().enumerate() {
            let curr_st = insts_states[i];
            let next_st = insts_states[i+1];
            if i == 0 {
                init_insts_loop.push_str(&format!("if st=={} then {}st={};", curr_st, inst, next_st));
            } else {
                init_insts_loop.push_str(&format!("elseif st=={} then {}st={};", curr_st, inst, next_st));
            }
        }
        init_insts_loop.push_str("else break end end;");

        let mut handlers_init = Vec::new();
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) s.bc = 8; s.res = {{}}; s.pc = {}; end;", op_state0, tamper_val, pc_state1));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) if s.bc > 7 then s.pc = {} else s.pc = {} end end;", op_state1, tamper_val, pc_state2, pc_state3));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) s.f = q:{}(s); if not s.f then s.r_flg = true; s.r_vals = {{s.concat(s.res)}}; s.r_len = 1; return end; s.bc = 0; s.pc = {}; end;", op_state2, tamper_val, m_next, pc_state3));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) if (s.f % 2) == 1 then s.pc = {} else s.pc = {} end end;", op_state3, tamper_val, pc_state4, pc_state5));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) s.u = q:{}(s); if not s.u then s.r_flg = true; s.r_vals = {{s.concat(s.res)}}; s.r_len = 1; return end; s.res[#s.res+1] = s.char(s.u); s.pc = {}; end;", op_state4, tamper_val, m_next, pc_state9));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) s.p1 = q:{}(s); if not s.p1 then s.r_flg = true; s.r_vals = {{s.concat(s.res)}}; s.r_len = 1; return end; s.pc = {}; end;", op_state5, tamper_val, m_next, pc_state6));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) s.p2 = q:{}(s); if not s.p2 then s.r_flg = true; s.r_vals = {{s.concat(s.res)}}; s.r_len = 1; return end; s.pc = {}; end;", op_state6, tamper_val, m_next, pc_state7));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) s.w = q:{}(s); if not s.w then s.r_flg = true; s.r_vals = {{s.concat(s.res)}}; s.r_len = 1; return end; s.pc = {}; end;", op_state7, tamper_val, m_next, pc_state8));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst, iter) s.ptr = #s.res - (s.p1 * 256 + s.p2) + 1; iter = 0; while true do if iter >= s.w + 3 then break end; s.res[#s.res+1] = s.res[s.ptr + iter]; iter = iter + 1; end; s.pc = {}; end;", op_state8, tamper_val, pc_state9));
        handlers_init.push(format!("s.handlers[{}+{}] = function(inst) s.f = s.floor(s.f / 2); s.bc = s.bc + 1; s.pc = {}; end;", op_state9, tamper_val, pc_state1));

        let n_handlers = handlers_init.len();
        let mut handlers_states: Vec<usize> = (1..=n_handlers+1).collect();
        for i in (1..handlers_states.len()).rev() {
            let j = rng.range(0, i + 1);
            handlers_states.swap(i, j);
        }
        
        let mut init_handlers_loop = String::new();
        init_handlers_loop.push_str(&format!("st={};while true do ", handlers_states[0]));
        for (i, h) in handlers_init.iter().enumerate() {
            let curr_st = handlers_states[i];
            let next_st = handlers_states[i+1];
            if i == 0 {
                init_handlers_loop.push_str(&format!("if st=={} then {}st={};", curr_st, h, next_st));
            } else {
                init_handlers_loop.push_str(&format!("elseif st=={} then {}st={};", curr_st, h, next_st));
            }
        }
        init_handlers_loop.push_str("else break end end;");

        let router_code = ControlFlowBuilder::build_fast_router(
            "s.pc", "s.insts", "inst", "s.handlers", "s.r_flg", "s.r_vals", "s.r_len", "s.tamper", "s.tail_flg", rng
        );

        let num_key_parts = rng.range(3, 7);
        let mut key_boundaries = Vec::new();
        for _ in 0..num_key_parts.saturating_sub(1) {
            key_boundaries.push(rng.range(1, keys.len()));
        }
        key_boundaries.sort_unstable();
        key_boundaries.dedup();
        let mut kb = vec![0];
        kb.extend(key_boundaries);
        if *kb.last().unwrap() != keys.len() {
            kb.push(keys.len());
        }

        let mut key_parts_exprs = Vec::new();
        let num_actual_key_parts = kb.len() - 1;
        for i in 0..num_actual_key_parts {
            let start = kb[i];
            let end = kb[i + 1];
            let part_bytes = &keys[start..end];
            let method = rng.range(0, 2);
            let expr = match method {
                0 => {
                    let mut char_args = String::new();
                    for (idx, b) in part_bytes.iter().enumerate() {
                        if idx > 0 { char_args.push(','); }
                        char_args.push_str(&b.to_string());
                    }
                    format!("s.char({})", char_args)
                }
                _ => {
                    let mut escaped = String::new();
                    for b in part_bytes {
                        escaped.push_str(&format!("\\{:03}", b));
                    }
                    format!("\"{}\"", escaped)
                }
            };
            key_parts_exprs.push(expr);
        }
        let combined_key_expr = key_parts_exprs.join(",");

        let chars: Vec<char> = alphabet.chars().collect();
        let num_parts = rng.range(6, 12);
        let mut part_boundaries = Vec::new();
        for _ in 0..num_parts - 1 {
            part_boundaries.push(rng.range(1, chars.len()));
        }
        part_boundaries.sort_unstable();
        part_boundaries.dedup();
        let mut boundaries = vec![0];
        boundaries.extend(part_boundaries);
        if *boundaries.last().unwrap() != chars.len() {
            boundaries.push(chars.len());
        }

        let mut parts_exprs = Vec::new();
        let num_actual_parts = boundaries.len() - 1;

        for i in 0..num_actual_parts {
            let start = boundaries[i];
            let end = boundaries[i + 1];
            let part_chars = &chars[start..end];
            let method = rng.range(0, 3);
            let expr = match method {
                0 => {
                    let mut rev_chars = part_chars.to_vec();
                    rev_chars.reverse();
                    let mut safe_str = String::new();
                    for c in rev_chars {
                        match c {
                            '\\' => safe_str.push_str("\\\\"),
                            '"' => safe_str.push_str("\\\""),
                            '\'' => safe_str.push_str("\\'"),
                            '\n' => safe_str.push_str("\\n"),
                            '\r' => safe_str.push_str("\\r"),
                            _ => safe_str.push(c),
                        }
                    }
                    format!("s.reverse(\"{}\")", safe_str)
                }
                1 => {
                    let mut char_args = String::new();
                    for (idx, c) in part_chars.iter().enumerate() {
                        if idx > 0 { char_args.push(','); }
                        char_args.push_str(&(*c as u8).to_string());
                    }
                    format!("s.char({})", char_args)
                }
                _ => {
                    let mut escaped = String::new();
                    for c in part_chars {
                        escaped.push_str(&format!("\\{:03}", *c as u8));
                    }
                    format!("\"{}\"", escaped)
                }
            };
            parts_exprs.push(expr);
        }
        
        let combined_alpha_expr = parts_exprs.join(",");

        let script = format!("
local function {f_entry}({v_data})
    return ({{
        {m_bxor} = function(q, s, a, b, ra, rb, p, c, rra, rrb, k_bxor)
            k_bxor = a * 256 + b;
            local to=0 and true;
            if s.memo[k_bxor] then return s.memo[k_bxor] end;
            ra, rb, p, c = a, b, 1, 0;
            while to do
                if ra > 0 or rb > 0 then
                    rra, rrb = ra % 2, rb % 2;
                    if rra ~= rrb then c = c + p end;
                    ra, rb, p = s.floor((ra - rra) / 2), s.floor((rb - rrb) / 2), p * 2;
                else break end;
            end;
            s.memo[k_bxor] = c;
            local function hg(dr, ...) repeat return c or nil until dr end;local df=hg(true)
            return df;
        end,
        {m_next} = function(q, s, r, c, e, v, x, y, z, i, d, m, b, k, B, F)
    B, F = s.byte, s.floor;
    i, d, m, b, k = s.idx, s.data, s.map, s.buf, s.kidx;
    if #b > 0 then
        r = s.remove(b, 1);
        c = q:{m_bxor}(s, r, s.k[k + 1]);
        s.kidx = (k + 1) % 16;
        return c;
    end;
    if i > s.len then return nil end;
    e = s.len - i + 1;
    if e >= 5 then
        v = m[B(d, i)] * 54700816 + m[B(d, i+1)] * 636056 + m[B(d, i+2)] * 7396 + m[B(d, i+3)] * 86 + m[B(d, i+4)];
        z, y, x = v % 256, F(v / 256) % 256, F(v / 65536) % 256;
        v = F(v / 16777216);
        b[1], b[2], b[3], b[4] = v, x, y, z;
        i = i + 5;
    elseif e >= 4 then
        v = m[B(d, i)] * 636056 + m[B(d, i+1)] * 7396 + m[B(d, i+2)] * 86 + m[B(d, i+3)];
        y, x = v % 256, F(v / 256) % 256;
        v = F(v / 65536);
        b[1], b[2], b[3] = v, x, y;
        i = i + 4;
    elseif e >= 3 then
        v = m[B(d, i)] * 7396 + m[B(d, i+1)] * 86 + m[B(d, i+2)];
        x = v % 256;
        v = F(v / 256);
        b[1], b[2] = v, x;
        i = i + 3;
    elseif e >= 2 then
        v = m[B(d, i)] * 86 + m[B(d, i+1)];
        b[1] = v;
        i = i + 2;
    else
        i = i + 1;
    end;
    s.idx = i;
    return q:{m_next}(s);
end,
        {m_init_map} = function(q, s, parts, alpha, i, kparts, kstr)
            parts = {{{combined_alpha_expr}}};
            alpha = \"\";
            i = 1;
            while true do
                if i > {num_actual_parts} then break end;
                alpha = alpha .. parts[i];
                i = i + 1;
            end;
            i = 1;
            while true do
                if i > #alpha then break end;
                s.map[s.byte(alpha, i)] = i - 1;
                i = i + 1;
            end;
            kparts = {{{combined_key_expr}}};
            kstr = \"\";
            i = 1;
            while true do
                if i > {num_actual_key_parts} then break end;
                kstr = kstr .. kparts[i];
                i = i + 1;
            end;
            i = 1;
            while true do
                if i > #kstr then break end;
                s.k[i] = s.byte(kstr, i);
                i = i + 1;
            end;
        end,
        {m_init_insts} = function(q, s, st)
            {init_insts_loop}
        end,
        {m_init_handlers} = function(q, s, st)
            {init_handlers_loop}
        end,
        {m_run} = function(q, s)
            {router_code}
        end,
        {m_main} = function(q, data, unpack, char, byte, floor, insert, concat, remove, reverse, sub, load_func, gmatch)
            return (function(s)
                q:{m_init_map}(s);
                q:{m_init_insts}(s);
                q:{m_init_handlers}(s);
                
                local parts = {{}}
                for part in gmatch(s.data, \"[^~]+\") do
                    insert(parts, part)
                end
                
                s.data = parts[1];
                s.len = #s.data;
                local sb_expr = q:{m_run}(s);
                
                local get_sb_code = load_func(\"return \" .. sb_expr);
                local sb_code = get_sb_code and get_sb_code() or \"\";
                local env_maker_chunk = load_func(sb_code, \"kryvex\");
                
                local stage2 = function()
                    s.data = parts[2];
                    s.len = #s.data;
                    s.idx = 1; s.kidx = 0; s.buf = {{}}; s.res = {{}};
                    s.pc = {pc_state0}; s.bc = 0; s.f = 0; s.p1 = 0; s.p2 = 0; s.w = 0; s.u = 0; s.ptr = 0;
                    s.r_flg = false; s.r_vals = {{}}; s.r_len = 0; s.tail_flg = false;
                    return q:{m_run}(s);
                end
                
                local env_maker = env_maker_chunk and env_maker_chunk(stage2) or stage2;
                return env_maker();
            end)({{
                data = data, pc = {pc_state0}, insts = {{}}, tamper = {tamper_val}, handlers = {{}},
                r_flg = false, r_vals = {{}}, r_len = 0, tail_flg = false,
                map = {{}}, idx = 1, len = #data, k = {{}}, kidx = 0, buf = {{}}, memo = {{}},
                unpack = unpack, char = char, byte = byte, floor = floor, insert = insert, concat = concat, remove = remove, reverse = reverse,
                bc = 0, res = {{}}, f = 0, p1 = 0, p2 = 0, w = 0, u = 0, ptr = 0
            }});
        end
    }}):{m_main}({v_data}, unpack or table.unpack, string.char, string.byte, math.floor, table.insert, table.concat, table.remove, string.reverse, string.sub, loadstring or load, string.gmatch);
end
");
        (script, f_entry)
    }
}