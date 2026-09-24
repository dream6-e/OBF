//! Generator 的底层工具层：ChaCha8、数值/控制流混淆、随机名池、
//! 载荷读写与重写。从 Generator.rs 拆出（原文件 69 KB，超过可维护范围）。
use std::collections::HashSet;
use rand::{rng, Rng, SeedableRng};
use rand::rngs::StdRng;
use crate::compiler::instructions::{OpArgMask, OpCode, OpMode};

fn chacha_qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

fn chacha8_block(key: &[u32; 8], nonce: [u32; 3], counter: u32) -> [u8; 64] {
    let mut s: [u32; 16] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2],
    ];
    let orig = s;
    for _ in 0..4 {
        chacha_qr(&mut s, 0, 4, 8, 12);
        chacha_qr(&mut s, 1, 5, 9, 13);
        chacha_qr(&mut s, 2, 6, 10, 14);
        chacha_qr(&mut s, 3, 7, 11, 15);
        chacha_qr(&mut s, 0, 5, 10, 15);
        chacha_qr(&mut s, 1, 6, 11, 12);
        chacha_qr(&mut s, 2, 7, 8, 13);
        chacha_qr(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 { s[i] = s[i].wrapping_add(orig[i]); }
    let mut out = [0u8; 64];
    for i in 0..16 { out[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_le_bytes()); }
    out
}

fn chacha8_keystream(key: &[u32; 8], nonce: [u32; 3], n_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n_bytes + 64);
    let mut counter = 0u32;
    while out.len() < n_bytes {
        out.extend_from_slice(&chacha8_block(key, nonce, counter));
        counter = counter.wrapping_add(1);
    }
    out.truncate(n_bytes);
    out
}

pub(super) fn chacha8_xor(key: &[u32; 8], salt: u32, pool_idx: u32, kind: u32, data: &[u8]) -> Vec<u8> {
    let nonce = [salt, pool_idx, kind];
    let ks = chacha8_keystream(key, nonce, data.len());
    data.iter().zip(ks.iter()).map(|(b, k)| b ^ k).collect()
}

pub struct CipherKeys {
    pub grp1: u64,
    pub grp2: u64,
    pub key_bx: u64,
    pub key_ba: u64,
    pub key_add: u64,
    pub key_bs: u64,
    pub key_ba2: u64,
    pub key_bs2: u64,
    pub tbl_p: String,
}

pub struct ControlFlowBuilder;

impl ControlFlowBuilder {
    pub fn format_num(val: i64, rng: &mut GenRng) -> String {
        match rng.range(0, 2) {
            0 => {
                if val < 0 {
                    format!("-0x{:x}", val.unsigned_abs())
                } else {
                    format!("0x{:x}", val)
                }
            }
            _ => val.to_string(),
        }
    }

    pub fn obfuscate_num_depth(val: i64, depth: usize, keys: &CipherKeys, rng: &mut GenRng) -> String {
        if depth == 0 {
            return Self::format_num(val, rng);
        }

        let style = rng.range(0, 10);
        if style < 4 {
            let huge = rng.range(0x100, 0x2FFF) as i64;
            let offset = val.wrapping_add(huge);
            format!("({}-{})", 
                Self::obfuscate_num_depth(offset, depth - 1, keys, rng), 
                Self::obfuscate_num_depth(huge, depth - 1, keys, rng)
            )
        } else if style < 7 {
            let mask = rng.range(0x10, 0x2FFF) as i64;
            let xor_val = val ^ mask;
            format!("{}[{}][{}]({},{})", 
                keys.tbl_p,
                Self::format_num(keys.grp1 as i64, rng),
                Self::format_num(keys.key_bx as i64, rng),
                Self::obfuscate_num_depth(xor_val, depth - 1, keys, rng), 
                Self::obfuscate_num_depth(mask, depth - 1, keys, rng)
            )
        } else {
            let mask = rng.range(0x10, 0x2FFF) as i64;
            let add_val = val.wrapping_sub(mask);
            format!("{}[{}][{}]({},{})", 
                keys.tbl_p,
                Self::format_num(keys.grp1 as i64, rng),
                Self::format_num(keys.key_add as i64, rng),
                Self::obfuscate_num_depth(add_val, depth - 1, keys, rng), 
                Self::obfuscate_num_depth(mask, depth - 1, keys, rng)
            )
        }
    }

    pub fn generate_opaque_predicate(val: i64, var_name: &str, comp_op: &str, keys: &CipherKeys, rng: &mut GenRng) -> String {
        let key = rng.range(0x10, 0xFFF) as i64;
        let mutated_val = val.wrapping_add(key);
        format!("{}[{}][{}]({}<={} and {} or {},{}){}{}", 
            keys.tbl_p,
            Self::format_num(keys.grp1 as i64, rng),
            Self::format_num(keys.key_add as i64, rng),
            var_name, 
            var_name, 
            var_name, 
            Self::format_num(rng.range(0, 0xFFFF) as i64, rng), 
            Self::format_num(key, rng), 
            comp_op,
            Self::format_num(mutated_val, rng)
        )
    }

    pub fn build_fast_router(
        var_pc: &str,
        var_insts: &str,
        var_inst: &str,
        var_handlers: &str,
        var_r_flg: &str,
        var_r_vals: &str,
        var_r_len: &str,
        var_tamper: &str,
        var_tail_flg: &str,
        rng: &mut GenRng,
    ) -> String {
        // 8 个下标必须互不相同（撞车会让辅助表槽位互相覆盖），见 GenRng::distinct
        let idx = rng.distinct(8, 0x10, 0x7F);
        let keys = CipherKeys {
            grp1: idx[0],
            grp2: idx[1],
            key_bx: idx[2],
            key_ba: idx[3],
            key_add: idx[4],
            key_bs: idx[5],
            key_ba2: idx[6],
            key_bs2: idx[7],
            tbl_p: rng.name(),
        };

        let s_state = rng.name();
        let t_shadow = rng.name();
        let q_route = rng.name();
        let d_junk = rng.name();
        let f_tmp = rng.name();
        let var_t = rng.name();

        let fn_bx = "_BX";
        let fn_ba = "_BA";
        let fn_bs = "_BS";

        let num_routes = rng.range(16, 28) as i64;
        let mut junk_limit = rng.range(5, 12);

        let mut out = String::new();

        out.push_str(&format!("local {}={};", fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b)local r,p=0,1;while a>0 or b>0 do local ra,rb=a%2,b%2;if ra~=rb then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end"));
        out.push_str(&format!("local {}={};", fn_ba, "bit32 and bit32.band or bit and bit.band or function(a,b)local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end"));
        out.push_str(&format!("local {}={};", fn_bs, "bit32 and bit32.rshift or bit and bit.rshift or function(a,n)local d=2^n return (a-a%d)/d end"));
        
        let tbl_def = format!(
            "local {p}={{}};{p}[{g1}]={{}};{p}[{g1}][{bx}]={fbx};{p}[{g1}][{add}]=function(a,b)return a+b end;{p}[{g1}][{ba}]={fba};{p}[{g2}]={{}};{p}[{g2}][{ba2}]=function(a)return {fba}(a,{max_u32})end;{p}[{g2}][{bs2}]=function(a)return {fbs}(a,{one})end;",
            p = keys.tbl_p,
            g1 = Self::format_num(keys.grp1 as i64, rng),
            g2 = Self::format_num(keys.grp2 as i64, rng),
            bx = Self::format_num(keys.key_bx as i64, rng),
            add = Self::format_num(keys.key_add as i64, rng),
            ba = Self::format_num(keys.key_ba as i64, rng),
            ba2 = Self::format_num(keys.key_ba2 as i64, rng),
            bs2 = Self::format_num(keys.key_bs2 as i64, rng),
            fbx = fn_bx,
            fba = fn_ba,
            fbs = fn_bs,
            max_u32 = Self::format_num(4294967295i64, rng),
            one = Self::format_num(1i64, rng)
        );
        out.push_str(&tbl_def);

        out.push_str(&format!("local {},{},{},{},{},{};", s_state, t_shadow, d_junk, q_route, f_tmp, var_t));
        
        let fetch_state = rng.range(0x1000, 0x2FFF) as i64;
        let init_val1 = rng.range(10, 1000) as i64;
        let init_val2 = rng.range(1, 1000) as i64;
        
        out.push_str(&format!("{},{},{},{}={},{},{},{};", 
            s_state, t_shadow, d_junk, var_t, 
            Self::format_num(init_val1, rng), 
            Self::format_num(0, rng), 
            Self::format_num(init_val2, rng), 
            Self::obfuscate_num_depth(fetch_state, 1, &keys, rng)
        ));

        out.push_str("while true do ");
        
        out.push_str(&format!("if {}=={} then ", var_t, Self::obfuscate_num_depth(fetch_state, 1, &keys, rng)));
        out.push_str(&format!("if {}>#{} then return end;", var_pc, var_insts));
        out.push_str(&format!("{},{}={}[{}],{}+{};", var_inst, var_pc, var_insts, var_pc, var_pc, Self::obfuscate_num_depth(1, 1, &keys, rng)));
        
        let q_route_expr = format!("{}[{}][{}]({}[{}][{}]({}[{}],{}),{})", 
            keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_ba as i64, rng),
            keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_add as i64, rng),
            var_inst, Self::format_num(1, rng), s_state,
            Self::format_num(num_routes, rng)
        );
        out.push_str(&format!("{}={};", q_route, q_route_expr));
        
        let dispatch_state = rng.range(0x1000, 0x2FFF) as i64;
        out.push_str(&format!("{}={};", var_t, Self::obfuscate_num_depth(dispatch_state, 1, &keys, rng)));
        
        out.push_str("elseif ");
        out.push_str(&format!("{}=={} then ", var_t, Self::obfuscate_num_depth(dispatch_state, 1, &keys, rng)));
        out.push_str(&Self::generate_recursive_tree(
            0,
            num_routes as usize - 1,
            &q_route,
            var_inst,
            var_handlers,
            var_tamper,
            &s_state,
            &d_junk,
            &f_tmp,
            &var_t,
            fetch_state,
            &mut junk_limit,
            &keys,
            rng
        ));
        
        out.push_str("else ");
        out.push_str(&format!("if {} then if {} then {},{}=false,false;{}={};else return(unpack or table.unpack)({},{},{})end else {}={};end ", 
            var_r_flg, var_tail_flg, var_tail_flg, var_r_flg, var_t, Self::obfuscate_num_depth(fetch_state, 1, &keys, rng), var_r_vals, Self::format_num(1, rng), var_r_len, var_t, Self::obfuscate_num_depth(fetch_state, 1, &keys, rng)
        ));

        out.push_str("end end ");
        out
    }

    pub fn generate_leaf_node(
        var_inst: &str,
        var_handlers: &str,
        var_tamper: &str,
        s_state: &str,
        d_junk: &str,
        f_tmp: &str,
        var_t: &str,
        _fetch_state: i64,
        keys: &CipherKeys,
        rng: &mut GenRng,
    ) -> String {
        let next_s = rng.range(0, 512) as i64;
        let next_s_obf = Self::obfuscate_num_depth(next_s, 1, keys, rng);
        let else_state = 0i64;
        let state_transition = format!("{}={};", var_t, Self::obfuscate_num_depth(else_state, 1, keys, rng));
        let leaf_type = rng.range(0, 5);
        let mut node = String::new();
        let idx_1 = Self::format_num(1, rng);

        match leaf_type {
            0 => {
                node.push_str(&format!("{}={}+{};{}={}[{}[{}]+{}];{}({});{}={};{}", 
                    d_junk, d_junk, Self::format_num(1, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
            1 => {
                node.push_str(&format!("repeat {}={}[{}[{}]+{}];{}({});{}={};{}break until false;", 
                    f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
            2 => {
                node.push_str(&format!("for _={},{} do {}={}[{}[{}]+{}];{}({});end {}={};{}", 
                    Self::format_num(1, rng), Self::format_num(1, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
            3 => {
                node.push_str(&format!("if {}~={} then {}={}[{}[{}]+{}];{}({});{}={};{}end ", 
                    d_junk, Self::format_num(4294967295i64, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
            _ => {
                node.push_str(&format!("{}={}[{}[{}]+{}];{}({});{}={};{}", 
                    f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state, next_s_obf, state_transition));
            }
        }
        node
    }

    pub fn generate_recursive_tree(
        min: usize,
        max: usize,
        q_route: &str,
        var_inst: &str,
        var_handlers: &str,
        var_tamper: &str,
        s_state: &str,
        d_junk: &str,
        f_tmp: &str,
        var_t: &str,
        fetch_state: i64,
        junk_limit: &mut usize,
        keys: &CipherKeys,
        rng: &mut GenRng,
    ) -> String {
        if min == max {
            let real_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, keys, rng);
            if *junk_limit > 0 && rng.range(0, 5) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, keys, rng);
                let fake_cond = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                return format!("if {}=={} then {} else {} end ", d_junk, fake_cond, junk_leaf, real_leaf);
            }
            return real_leaf;
        }

        let mid = (min + max) / 2;
        let mut branch = String::new();
        let direction = rng.range(0, 2) == 0;

        let comp_expr = Self::generate_opaque_predicate(mid as i64, q_route, "<=", keys, rng);

        if direction {
            branch.push_str(&format!("if {} then ", comp_expr));
            branch.push_str(&Self::generate_recursive_tree(min, mid, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            
            if *junk_limit > 0 && rng.range(0, 4) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, keys, rng);
                let fake_cond = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                branch.push_str(&format!("elseif {}=={} then {} ", d_junk, fake_cond, junk_leaf));
            }

            branch.push_str("else ");
            branch.push_str(&Self::generate_recursive_tree(mid + 1, max, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            branch.push_str("end ");
        } else {
            let rev_comp = Self::generate_opaque_predicate(mid as i64, q_route, ">", keys, rng);

            branch.push_str(&format!("if {} then ", rev_comp));
            branch.push_str(&Self::generate_recursive_tree(mid + 1, max, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            
            if *junk_limit > 0 && rng.range(0, 4) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, keys, rng);
                let fake_cond = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                branch.push_str(&format!("elseif {}=={} then {} ", d_junk, fake_cond, junk_leaf));
            }

            branch.push_str("else ");
            branch.push_str(&Self::generate_recursive_tree(min, mid, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            branch.push_str("end ");
        }
        branch
    }
}

pub(super) struct PayloadReader<'a> { pub(super) data: &'a [u8], pub(super) pos: usize }

impl<'a> PayloadReader<'a> {
    pub(super) fn read_u8(&mut self) -> u8 { let b = self.data[self.pos]; self.pos += 1; b }
    pub(super) fn read_u32(&mut self) -> u32 { let b = &self.data[self.pos..self.pos+4]; self.pos += 4; u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
    pub(super) fn read_u64(&mut self) -> u64 { let b = &self.data[self.pos..self.pos+8]; self.pos += 8; u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) }
    pub(super) fn read_bytes(&mut self, len: usize) -> &'a [u8] { let b = &self.data[self.pos..self.pos+len]; self.pos += len; b }
    pub(super) fn read_string(&mut self) -> &'a [u8] { let len = self.read_u32(); self.read_bytes(len as usize) }
}

pub(super) fn write_string(w: &mut Vec<u8>, s: &[u8]) { w.extend_from_slice(&(s.len() as u32).to_le_bytes()); w.extend_from_slice(s); }

pub(super) fn scan_used_opcodes(r: &mut PayloadReader, used_ops: &mut HashSet<u8>) {
    let name_len = r.read_u32();
    r.read_bytes(name_len as usize);
    r.read_u32(); r.read_u32(); r.read_u8(); r.read_u8(); r.read_u8(); r.read_u8();
    let inst_count = r.read_u32();
    for _ in 0..inst_count {
        used_ops.insert(r.read_u8());
        r.read_u8(); r.read_u32(); r.read_u32();
    }
    let const_count = r.read_u32();
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => {}
            1 => { r.read_u8(); }
            2 => { r.read_u64(); }
            3 => { let s_len = r.read_u32(); r.read_bytes(s_len as usize); }
            _ => panic!(),
        }
    }
    let p_count = r.read_u32();
    for _ in 0..p_count { scan_used_opcodes(r, used_ops); }
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { let s_len = r.read_u32(); r.read_bytes(s_len as usize); r.read_u32(); r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { let s_len = r.read_u32(); r.read_bytes(s_len as usize); }
}

pub(super) fn scan_setglobal_targets(r: &mut PayloadReader, targets: &mut HashSet<Vec<u8>>, setglobal_op: u8) {
    r.read_string();
    r.read_u32(); r.read_u32();
    r.read_u8(); r.read_u8(); r.read_u8(); r.read_u8();
    let inst_count = r.read_u32();
    let mut raw_insts: Vec<(u8, u8, u32, u32)> = Vec::with_capacity(inst_count as usize);
    for _ in 0..inst_count {
        let op = r.read_u8(); let a = r.read_u8(); let b = r.read_u32(); let c = r.read_u32();
        raw_insts.push((op, a, b, c));
    }
    let const_count = r.read_u32();
    let mut local_consts: Vec<Option<Vec<u8>>> = Vec::with_capacity(const_count as usize);
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => local_consts.push(None),
            1 => { r.read_u8(); local_consts.push(None); }
            2 => { r.read_u64(); local_consts.push(None); }
            3 => { local_consts.push(Some(r.read_string().to_vec())); }
            _ => panic!(),
        }
    }
    for (op, _a, b, _c) in &raw_insts {
        if *op == setglobal_op {
            if let Some(Some(s)) = local_consts.get(*b as usize) {
                targets.insert(s.clone());
            }
        }
    }
    let p_count = r.read_u32();
    for _ in 0..p_count { scan_setglobal_targets(r, targets, setglobal_op); }
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { r.read_string(); r.read_u32(); r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { r.read_string(); }
}

pub(super) fn rewrite_chunk(r: &mut PayloadReader, w: &mut Vec<u8>, strings: &mut Vec<Vec<u8>>, numbers: &mut Vec<u64>, mapped_opcodes: &[Vec<u32>; 90], builtin_map: &[Vec<u32>], fused_map: &[Vec<u32>; crate::VM::Opcodes::builtins::FUSED_OP_COUNT], fused_used: &mut HashSet<usize>, setglobal_targets: &HashSet<Vec<u8>>, getglobal_op: u8, getglobalstr_op: u8, inverse_opcode_map: &[u8; 90], slot_perm: &[usize], rng: &mut StdRng) {
    write_string(w, r.read_string());
    w.extend_from_slice(&r.read_u32().to_le_bytes().to_vec()); w.extend_from_slice(&r.read_u32().to_le_bytes().to_vec());
    w.push(r.read_u8()); w.push(r.read_u8()); w.push(r.read_u8()); w.push(r.read_u8());
    let inst_count = r.read_u32();
    let mut raw_insts: Vec<(u8, u8, u32, u32)> = Vec::with_capacity(inst_count as usize);
    for _ in 0..inst_count {
        let op = r.read_u8(); let a = r.read_u8(); let b = r.read_u32(); let c = r.read_u32();
        raw_insts.push((op, a, b, c));
    }
    let const_count = r.read_u32();
    let mut local_consts: Vec<(u8, Vec<u8>)> = Vec::with_capacity(const_count as usize);
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => local_consts.push((0, Vec::new())),
            1 => { let b = r.read_u8(); local_consts.push((1, vec![b])); }
            2 => { let n = r.read_u64(); local_consts.push((2, n.to_le_bytes().to_vec())); }
            3 => { let s = r.read_string().to_vec(); local_consts.push((3, s)); }
            _ => panic!(),
        }
    }

    const BITRK: u32 = 128;
    let mut referenced_elsewhere: HashSet<usize> = HashSet::new();
    for (op, _a, b, c) in &raw_insts {
        if *op == getglobal_op || *op == getglobalstr_op { continue; }
        if let Some(real_op) = OpCode::from_u8(inverse_opcode_map[*op as usize]) {
            let is_bx = matches!(real_op.mode(), OpMode::IABx);
            if is_bx {
                if real_op.b_mode() == OpArgMask::K && (*b as usize) < local_consts.len() {
                    referenced_elsewhere.insert(*b as usize);
                }
            } else {
                if real_op.b_mode() == OpArgMask::K && *b >= BITRK {
                    referenced_elsewhere.insert((*b - BITRK) as usize);
                }
                if real_op.c_mode() == OpArgMask::K && *c >= BITRK {
                    referenced_elsewhere.insert((*c - BITRK) as usize);
                }
            }
        }
    }

    let mut builtin_rewrite: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut omit_const: HashSet<usize> = HashSet::new();
    for (idx, (ctype, bytes)) in local_consts.iter().enumerate() {
        if *ctype == 3 {
            if let Some(slot) = crate::VM::Opcodes::builtins::BUILTIN_NAMES.iter().position(|n| n.as_bytes() == bytes.as_slice()) {
                if !setglobal_targets.contains(bytes) {
                    builtin_rewrite.insert(idx, slot);
                    if !referenced_elsewhere.contains(&idx) {
                        omit_const.insert(idx);
                    }
                }
            }
        }
    }

    // ---- 融合前的准备：算出所有可能成为跳转目标的 pc ----
    //
    // 融合会把三条指令压成一条，handler 里 `pc += 2` 跳过两个死槽。死槽本身
    // 仍然占位（所以其余跳转偏移一个都不用改），但前提是**绝不能有控制流
    // 直接落进死槽**。两类来源都要排除：
    //   1. 相对跳转的目标：pc 在取指时已经自增过 1，所以目标是 (i + 1 + sBx)
    //   2. 条件跳下一条的指令（Eq/Lt/Le/Test/TestSet/TForLoop），目标是 i + 1
    const REL_JUMP_OPS: &[u8] = &[22, 31, 32, 48, 81, 82, 83, 84]; // Jmp ForLoop ForPrep TForPrep JmpIf JmpIfNot JmpEq JmpNe
    const SKIP_NEXT_OPS: &[u8] = &[23, 24, 25, 26, 27, 33];        // Eq Lt Le Test TestSet TForLoop
    const NO_FALLTHROUGH_OPS: &[u8] = &[29, 30, 85, 86, 87];       // TailCall Return Return0 Return1 Return2
    let mut jump_targets: HashSet<usize> = HashSet::new();
    for (i, (op, _a, b, _c)) in raw_insts.iter().enumerate() {
        let real = inverse_opcode_map[*op as usize];
        if REL_JUMP_OPS.contains(&real) {
            let t = i as i64 + 1 + *b as i32 as i64;
            if t >= 0 {
                jump_targets.insert(t as usize);
            }
        }
        if SKIP_NEXT_OPS.contains(&real) {
            jump_targets.insert(i + 1);
        }
    }

    w.extend_from_slice(&inst_count.to_le_bytes());
    let n_insts = raw_insts.len();
    let mut i = 0usize;
    let mut fused_count = 0usize;
    while i < n_insts {
        let (op, a, b, c) = raw_insts[i];

        // ---- SuperOperator: builtin-load + LoadK + Call(B=2, C=1) -> 1 条 ----
        if (op == getglobal_op || op == getglobalstr_op)
            && i + 2 < n_insts
            && !jump_targets.contains(&(i + 1))
            && !jump_targets.contains(&(i + 2))
        {
            // i == 0 是函数入口，没有前驱指令，控制流只能从这里开始，天然安全；
            // i > 0 则要求前一条指令一定会顺序落入本条（不会跳走、不会跳过本条）。
            let prev_falls_through = if i == 0 {
                true
            } else {
                let prev_real = inverse_opcode_map[raw_insts[i - 1].0 as usize];
                !SKIP_NEXT_OPS.contains(&prev_real)
                    && !REL_JUMP_OPS.contains(&prev_real)
                    && !NO_FALLTHROUGH_OPS.contains(&prev_real)
            };
            if prev_falls_through {
                if let Some(&slot) = builtin_rewrite.get(&(b as usize)) {
                    let (op1, a1, b1, _c1) = raw_insts[i + 1];
                    let (op2, a2, b2, c2) = raw_insts[i + 2];
                    let is_loadk = inverse_opcode_map[op1 as usize] == 1 && a1 as u32 == a as u32 + 1;
                    let is_call_1arg_0ret =
                        inverse_opcode_map[op2 as usize] == 28 && a2 == a && b2 == 2 && c2 == 1;
                    // 常量必须没被 omit_const 抹掉，否则 CONSTS[b1+1] 会取错
                    let const_alive = !omit_const.contains(&(b1 as usize));
                    if is_loadk && is_call_1arg_0ret && const_alive {
                        // 必须和 builtin-load 一样过 slot_perm：handler 是按
                        // fused_map[perm[名字下标]] 注册的，指令侧要用同一个下标。
                        let fused_vals = fused_map.get(slot_perm[slot]).map(|v| v.as_slice()).unwrap_or(&[]);
                        if !fused_vals.is_empty() {
                            let selected_op = fused_vals[rng.random_range(0..fused_vals.len())];
                            w.extend_from_slice(&selected_op.to_le_bytes());
                            w.push(a);
                            w.extend_from_slice(&0u32.to_le_bytes());
                            w.extend_from_slice(&b1.to_le_bytes()); // 常量下标搬进 C
                            fused_used.insert(slot_perm[slot]);
                            fused_count += 1;
                            i += 1; // i+1 / i+2 照常写出，成为永不执行的死槽
                            continue;
                        }
                    }
                }
            }
        }

        if op == getglobal_op || op == getglobalstr_op {
            if let Some(slot) = builtin_rewrite.get(&(b as usize)) {
                let op_index = crate::VM::Opcodes::builtins::BUILTIN_OP_BASE + slot_perm[*slot];
                let mapped_vals = builtin_map.get(op_index).map(|v| v.as_slice()).unwrap_or(&[]);
                let selected_op = if !mapped_vals.is_empty() { mapped_vals[rng.random_range(0..mapped_vals.len())] } else { op_index as u32 };
                w.extend_from_slice(&selected_op.to_le_bytes()); w.push(a); w.extend_from_slice(&0u32.to_le_bytes()); w.extend_from_slice(&0u32.to_le_bytes());
                i += 1;
                continue;
            }
        }
        let mapped_vals = mapped_opcodes.get(op as usize).map(|v| v.as_slice()).unwrap_or(&[]);
        let selected_op = if !mapped_vals.is_empty() { mapped_vals[rng.random_range(0..mapped_vals.len())] } else { op as u32 };
        w.extend_from_slice(&selected_op.to_le_bytes()); w.push(a); w.extend_from_slice(&b.to_le_bytes()); w.extend_from_slice(&c.to_le_bytes());
        i += 1;
    }

    w.extend_from_slice(&const_count.to_le_bytes());
    for (idx, (c_type, bytes)) in local_consts.iter().enumerate() {
        if omit_const.contains(&idx) {
            w.push(0);
            continue;
        }
        w.push(*c_type);
        match c_type {
            0 => {}
            1 => w.push(bytes[0]),
            2 => {
                let n = u64::from_le_bytes(bytes.as_slice().try_into().unwrap());
                let pos = numbers.iter().position(|&x| x == n).unwrap_or_else(|| { numbers.push(n); numbers.len() - 1 });
                w.extend_from_slice(&(pos as u32).to_le_bytes());
            }
            3 => {
                let pos = strings.iter().position(|x| x == bytes).unwrap_or_else(|| { strings.push(bytes.clone()); strings.len() - 1 });
                w.extend_from_slice(&(pos as u32).to_le_bytes());
            }
            _ => panic!(),
        }
    }

    let p_count = r.read_u32();
    w.extend_from_slice(&p_count.to_le_bytes());
    for _ in 0..p_count { rewrite_chunk(r, w, strings, numbers, mapped_opcodes, builtin_map, fused_map, fused_used, setglobal_targets, getglobal_op, getglobalstr_op, inverse_opcode_map, slot_perm, rng); }
    let l_count = r.read_u32();
    w.extend_from_slice(&l_count.to_le_bytes());
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    w.extend_from_slice(&loc_count.to_le_bytes());
    for _ in 0..loc_count { write_string(w, r.read_string()); w.extend_from_slice(&r.read_u32().to_le_bytes()); w.extend_from_slice(&r.read_u32().to_le_bytes()); }
    let upv_count = r.read_u32();
    w.extend_from_slice(&upv_count.to_le_bytes());
    for _ in 0..upv_count { write_string(w, r.read_string()); }
}

pub struct GenRng { used: HashSet<String>, slots: Vec<i64> }

impl GenRng {
    pub fn new(_seed: u64) -> Self { Self { used: HashSet::new(), slots: Vec::new() } }
    pub fn next(&mut self) -> u32 { rng().random::<u32>() }
    pub fn range(&mut self, min: usize, max: usize) -> usize { rng().random_range(min..max) }
    pub fn range64(&mut self, min: i64, max: i64) -> i64 { rng().random_range(min..max) }
    /// 取 n 个互不相同的随机数。
    ///
    /// CipherKeys 的下标必须走这里：辅助表是按
    /// `P[g1]={};P[g1][bx]=..;P[g1][add]=..;P[g1][ba]=..;P[g2]={};P[g2][ba2]=..;P[g2][bs2]=..`
    /// 建起来的，下标一旦撞车，后写的赋值就会覆盖前一个，甚至 `g1==g2` 时
    /// `P[g2]={}` 会把整个 `P[g1]` 清空 —— 于是运行时取到 nil，
    /// 报 `attempt to call field '?' (a nil value)`，产物直接坏掉。
    pub fn distinct(&mut self, n: usize, min: usize, max: usize) -> Vec<u64> {
        let mut out: Vec<u64> = Vec::with_capacity(n);
        while out.len() < n {
            let v = self.range(min, max) as u64;
            if !out.contains(&v) { out.push(v); }
        }
        out
    }
    pub fn name(&mut self) -> String {
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
        let keywords = ["and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"];
        loop {
            let len = self.range(7, 14);
            let s: String = (0..len).map(|_| chars[self.range(0, chars.len())]).collect();
            if !self.used.contains(&s) && !keywords.contains(&s.as_str()) { self.used.insert(s.clone()); return s; }
        }
    }
    /// 取一个互不重复的「槽位号」——数据流打乱用的随机大整数下标。
    /// 状态（pc/stk/top/常量表…）都住在 VM 对象的这些槽里，块的局部名字逐块随机。
    pub fn slot(&mut self) -> i64 {
        loop {
            let v = self.range64(0x0200_0000, 0x7FFF_FFFF);
            if !self.slots.contains(&v) { self.slots.push(v); return v; }
        }
    }

    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        let mut r = rng();
        for i in (1..slice.len()).rev() { slice.swap(i, r.random_range(0..=i)); }
    }
    pub fn format_num(&mut self, val: i64) -> String {
        match self.range(0, 2) { 0 => { if val < 0 { format!("-0x{:x}", val.unsigned_abs()) } else { format!("0x{:x}", val) } } _ => val.to_string() }
    }
    pub fn obfuscate_num(&mut self, val: i64, depth: usize, keys: &CipherKeys) -> String {
        if depth == 0 { return self.format_num(val); }
        let style = self.range(0, 10);
        if style < 4 {
            let huge = self.range64(0x10000000, 0x7FFFFFFF);
            format!("({}-{})", self.obfuscate_num(val.wrapping_add(huge), depth - 1, keys), self.obfuscate_num(huge, depth - 1, keys))
        } else if style < 7 {
            let mask = self.range64(0x10000000, 0x3FFFFFFF);
            format!("{}[{}][{}]({},{})", keys.tbl_p, self.format_num(keys.grp1 as i64), self.format_num(keys.key_bx as i64), self.obfuscate_num(val ^ mask, depth - 1, keys), self.obfuscate_num(mask, depth - 1, keys))
        } else {
            let mask = self.range64(0x10000000, 0x3FFFFFFF);
            format!("{}[{}][{}]({},{})", keys.tbl_p, self.format_num(keys.grp1 as i64), self.format_num(keys.key_add as i64), self.obfuscate_num(val.wrapping_sub(mask), depth - 1, keys), self.obfuscate_num(mask, depth - 1, keys))
        }
    }
}

pub(super) fn build_opcode_tree(handlers: &[(u32, String)], min_idx: usize, max_idx: usize, var_op: &str, keys: &CipherKeys, rng: &mut GenRng) -> String {
    if min_idx == max_idx { return handlers[min_idx].1.clone(); }
    let mid = (min_idx + max_idx) / 2;
    let left = build_opcode_tree(handlers, min_idx, mid, var_op, keys, rng);
    let right = build_opcode_tree(handlers, mid + 1, max_idx, var_op, keys, rng);
    let direction = rng.range(0, 2) == 0;
    if direction {
        let cond = ControlFlowBuilder::generate_opaque_predicate(handlers[mid].0 as i64, var_op, "<=", keys, rng);
        format!("if {} then {} else {} end ", cond, left, right)
    } else {
        let cond = ControlFlowBuilder::generate_opaque_predicate(handlers[mid].0 as i64, var_op, ">", keys, rng);
        format!("if {} then {} else {} end ", cond, right, left)
    }
}


/// 标识符字节判定（与 Lua 的 [A-Za-z0-9_] 一致）。
fn ident_byte(c: u8) -> bool { c.is_ascii_alphanumeric() || c == b'_' }

/// body 里是否出现了**独立**的标识符 name。
/// 必须按 token 判断：cfg 里的名字可能和模板里随机名的子串撞车，
/// 用 `contains` 会误判（漏取状态槽位就会取到 nil）。
pub(super) fn uses_ident(body: &str, name: &str) -> bool {
    if name.is_empty() { return false; }
    let b = body.as_bytes();
    let mut i = 0usize;
    while let Some(p) = body[i..].find(name) {
        let start = i + p;
        let end = start + name.len();
        let ok_l = start == 0 || !ident_byte(b[start - 1]);
        let ok_r = end >= b.len() || !ident_byte(b[end]);
        if ok_l && ok_r { return true; }
        i = end;
    }
    false
}

/// 把 body 里**独立的**标识符 from 整块换成 to（逐块换名字用）。
/// 只按 token 替换，不改字符串字面量内部（handler 模板里本来就没有字符串字面量）。
pub(super) fn rename_ident(body: &str, from: &str, to: &str) -> String {
    if from.is_empty() { return body.to_string(); }
    let b = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut i = 0usize;
    while i < b.len() {
        if ident_byte(b[i]) {
            let start = i;
            while i < b.len() && ident_byte(b[i]) { i += 1; }
            let tok = &body[start..i];
            out.push_str(if tok == from { to } else { tok });
        } else {
            let ch = body[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// 生成「只认原生 C 函数」的 loadstring 探测代码（防执行器/沙盒把 loadstring
/// 换成 Lua 钩子）。三个标识符由调用方从各自的命名池里取：
/// `nat` = isNative、`getf` = 取用函数、`pl` = 最终使用的 loadstring 变量。
///
/// 语义：按 `loadstring` → `getrenv()['loadstring']` → `getrenv()['load']` → `load`
/// 的顺序找**原生**的那一个；一个原生都没有时退回第一个可用的函数
/// （保证产物在完全没有原生候选的环境里还能跑；要改成「找不到就失败」，
/// 把最后那句 `return alt` 换成 `return nil` 即可）。
///
/// 线性逻辑/数据流同样打乱：定位到原生候选后用改下标的方式跳出循环
/// （而不是 return），末尾再用影子变量返回。
///
/// 注意一（改名器）：这段代码会进 VM 文本、过一遍压缩器的**成员改名器**，
/// 所以 `debug.getinfo` / `info.what` / `info.source` 一律写成**字符串键**，
/// 绝不能写成点访问 —— 改名器只改 `.名字`/`:名字`，字符串键不动；
/// 写点访问会被改成随机名，探测永远走兜底分支、形同虚设。
///
/// 注意二（明文）：字符串键留在产物里本身也是特征（`['getinfo']`、`'=[C]'`
/// 一眼就是「原生函数探测」），所以下面 9 个字符串**全部 XOR 加密**，
/// 以 `"\ddd\ddd…"` 十进制转义字面量出现，运行时用纯算术异或解回来
/// （不依赖 bit32 / bit，标准 Lua 5.1 与 Roblox 都能跑）。
/// 每个串一个独立随机密钥，密钥避开该串里出现过的字节，
/// 保证密文里不会写出 `\000`。只在启动时解 9 个短串，代价可忽略。
pub fn loadstring_probe_lua(nat: &str, getf: &str, pl: &str, rng: &mut GenRng) -> String {
    // ── 要隐藏的字符串：顺序与下面 format! 里的 k1…k9 一一对应 ──
    const PLAIN: [&str; 9] = [
        "getinfo",    // info 表的键
        "what",       // 判定是否为原生函数
        "C",          // what 的值
        "source",     // 源名
        "=[C]",       // 原生函数的 source 形状
        "getgenv",    // 执行器环境表键
        "getrenv",    // 执行器环境表键
        "loadstring", // 候选名
        "load",       // 候选名
    ];
    let mut names: Vec<String> = Vec::with_capacity(PLAIN.len());
    let mut lits: Vec<String> = Vec::with_capacity(PLAIN.len());
    let mut ks: Vec<u8> = Vec::with_capacity(PLAIN.len());
    for p in PLAIN.iter() {
        let k = xor_key(p, rng);
        names.push(rng.name());
        lits.push(xor_lit(p, k));
        ks.push(k);
    }

    // ── 解密器：纯算术 XOR，不用任何位库 ──
    let v_dx = rng.name();
    let (v_s, v_k) = (rng.name(), rng.name());
    let (v_o, v_i, v_n) = (rng.name(), rng.name(), rng.name());
    let (v_a, v_b, v_r, v_p, v_w) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
    let (v_xb, v_yb) = (rng.name(), rng.name());
    let dx_def = format!(
        "local function {dx}({s},{k}) local {o},{i}='',0; local {n}=#{s}; \
         while {i}<{n} do {i}={i}+1; local {a},{b}={k},string.byte({s},{i}); \
         local {r},{p}=0,1; for {w}=1,8 do local {xb},{yb}={a}%2,{b}%2; \
         if {xb}~={yb} then {r}={r}+{p} end; {a}=({a}-{xb})/2; {b}=({b}-{yb})/2; {p}={p}*2; end; \
         {o}={o}..string.char({r}); end; return {o}; end;",
        dx = v_dx, s = v_s, k = v_k, o = v_o, i = v_i, n = v_n,
        a = v_a, b = v_b, r = v_r, p = v_p, w = v_w, xb = v_xb, yb = v_yb
    );
    let mut keys_lua = String::new();
    for i in 0..PLAIN.len() {
        keys_lua.push_str(&format!("local {}={}({},0x{:02X});", names[i], v_dx, lits[i], ks[i]));
    }

    let v_d = rng.name();
    let v_gi = rng.name();
    let v_list = rng.name();
    let v_alt = rng.name();
    let v_i = rng.name();
    let v_n = rng.name();
    let v_f = rng.name();
    let v_t = rng.name();
    let v_g = rng.name();
    let v_ok = rng.name();
    let v_inf = rng.name();
    let v_gg = rng.name();
    let v_ge = rng.name();
    let v_env2 = rng.name();
    let body = format!(
        "local function {nat}({f}) \
            local {d} = debug; \
            if type({d}) ~= 'table' then return true end; \
            local {gi} = {d}[{k1}]; \
            if type({gi}) ~= 'function' then return true end; \
            local {ok}, {inf} = pcall({gi}, {f}, 'S'); \
            if not {ok} or type({inf}) ~= 'table' then return true end; \
            return {inf}[{k2}] == {k3} and {inf}[{k4}] == {k5}; \
        end; \
        local function {getf}() \
            local {g} = (getfenv and getfenv()) or _G; \
            local {gg} = {g}[{k6}]; \
            if type({gg}) == 'function' then {g} = {gg}() or {g}; end; \
            local {ge} = {g}[{k7}]; \
            local {env} = {g}; \
            if type({ge}) == 'function' then {env} = {ge}() or {g}; end; \
            local {list} = {{ loadstring, {env}[{k8}], {env}[{k9}], load }}; \
            local {alt}, {i} = nil, 0; \
            local {n} = #{list}; \
            while {i} < {n} do \
                {i} = {i} + 1; \
                local {f} = {list}[{i}]; \
                local {t} = type({f}); \
                if {t} == 'function' then \
                    if {nat}({f}) and {alt} == nil then {alt} = {f}; {i} = {n}; end; \
                    if {alt} == nil then {alt} = {f}; end; \
                end; \
            end; \
            return {alt}; \
        end; \
        local {pl} = {getf}();\n",
        nat = nat, getf = getf, pl = pl, d = v_d, gi = v_gi, list = v_list, alt = v_alt,
        i = v_i, n = v_n, f = v_f, t = v_t, g = v_g, ok = v_ok, inf = v_inf,
        gg = v_gg, ge = v_ge, env = v_env2,
        k1 = names[0], k2 = names[1], k3 = names[2], k4 = names[3], k5 = names[4],
        k6 = names[5], k7 = names[6], k8 = names[7], k9 = names[8]
    );
    format!("{dx_def}{keys_lua}{body}")
}

/// 把明文按密钥异或后写成 Lua 的 `\ddd` 十进制转义字符串字面量。
/// 全三位定宽，所以后面跟数字也不会被读成别的转义。
fn xor_lit(plain: &str, key: u8) -> String {
    let mut out = String::from("\"");
    for b in plain.bytes() {
        out.push_str(&format!("\\{:03}", b ^ key));
    }
    out.push('"');
    out
}

/// 取一个随机单字节密钥，且**不落在明文出现过的字节里** ——
/// 这样异或结果不会出现 `\000`（Lua 字符串能装 NUL，但没必要给
/// 压缩器的 lexer 找麻烦）。
fn xor_key(plain: &str, rng: &mut GenRng) -> u8 {
    let bytes: Vec<u8> = plain.bytes().collect();
    loop {
        let k = rng.range(1, 256) as u8;
        if !bytes.contains(&k) { return k; }
    }
}
