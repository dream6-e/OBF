use crate::VM::VM_Backend::Context::VmContext;
use crate::VM::VM_Backend::Lua_core;
use crate::VM::Opcodes::{self, OpcodeConfig};
use crate::VM::packer::Packer;
use crate::compiler::instructions::{OpCode, OpMode, OpArgMask};
use std::collections::HashSet;
use rand::{rng, Rng, SeedableRng};
use rand::rngs::StdRng;
use super::AntiTamper;

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

fn chacha8_xor(key: &[u32; 8], salt: u32, pool_idx: u32, kind: u32, data: &[u8]) -> Vec<u8> {
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
        let keys = CipherKeys {
            grp1: rng.range(0x10, 0x7F) as u64,
            grp2: rng.range(0x10, 0x7F) as u64,
            key_bx: rng.range(0x10, 0x7F) as u64,
            key_ba: rng.range(0x10, 0x7F) as u64,
            key_add: rng.range(0x10, 0x7F) as u64,
            key_bs: rng.range(0x10, 0x7F) as u64,
            key_ba2: rng.range(0x10, 0x7F) as u64,
            key_bs2: rng.range(0x10, 0x7F) as u64,
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

        out.push_str(&format!("local {}={};", fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b)local r,p=0,1;while a>0 or b>0 do local ra,rb=a%2,b%2;if ra~=rb then r=r+p end;a,b,p=math.floor(a/2),math.floor(b/2),p*2 end;return r end"));
        out.push_str(&format!("local {}={};", fn_ba, "bit32 and bit32.band or bit and bit.band or function(a,b)local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=math.floor(a/2),math.floor(b/2),p*2 end;return r end"));
        out.push_str(&format!("local {}={};", fn_bs, "bit32 and bit32.rshift or bit and bit.rshift or function(a,n)return math.floor(a/(2^n))end"));
        
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

struct PayloadReader<'a> { data: &'a [u8], pos: usize }

impl<'a> PayloadReader<'a> {
    fn read_u8(&mut self) -> u8 { let b = self.data[self.pos]; self.pos += 1; b }
    fn read_u32(&mut self) -> u32 { let b = &self.data[self.pos..self.pos+4]; self.pos += 4; u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
    fn read_u64(&mut self) -> u64 { let b = &self.data[self.pos..self.pos+8]; self.pos += 8; u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) }
    fn read_bytes(&mut self, len: usize) -> &'a [u8] { let b = &self.data[self.pos..self.pos+len]; self.pos += len; b }
    fn read_string(&mut self) -> &'a [u8] { let len = self.read_u32(); self.read_bytes(len as usize) }
}

fn write_string(w: &mut Vec<u8>, s: &[u8]) { w.extend_from_slice(&(s.len() as u32).to_le_bytes()); w.extend_from_slice(s); }

fn scan_used_opcodes(r: &mut PayloadReader, used_ops: &mut HashSet<u8>) {
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

fn scan_setglobal_targets(r: &mut PayloadReader, targets: &mut HashSet<Vec<u8>>, setglobal_op: u8) {
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

fn rewrite_chunk(r: &mut PayloadReader, w: &mut Vec<u8>, strings: &mut Vec<Vec<u8>>, numbers: &mut Vec<u64>, mapped_opcodes: &[Vec<u32>; 90], builtin_map: &[Vec<u32>], setglobal_targets: &HashSet<Vec<u8>>, getglobal_op: u8, getglobalstr_op: u8, inverse_opcode_map: &[u8; 90], slot_perm: &[usize], rng: &mut StdRng) {
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

    w.extend_from_slice(&inst_count.to_le_bytes());
    for (op, a, b, c) in &raw_insts {
        if *op == getglobal_op || *op == getglobalstr_op {
            if let Some(slot) = builtin_rewrite.get(&(*b as usize)) {
                let op_index = crate::VM::Opcodes::builtins::BUILTIN_OP_BASE + slot_perm[*slot];
                let mapped_vals = builtin_map.get(op_index).map(|v| v.as_slice()).unwrap_or(&[]);
                let selected_op = if !mapped_vals.is_empty() { mapped_vals[rng.random_range(0..mapped_vals.len())] } else { op_index as u32 };
                w.extend_from_slice(&selected_op.to_le_bytes()); w.push(*a); w.extend_from_slice(&0u32.to_le_bytes()); w.extend_from_slice(&0u32.to_le_bytes());
                continue;
            }
        }
        let mapped_vals = mapped_opcodes.get(*op as usize).map(|v| v.as_slice()).unwrap_or(&[]);
        let selected_op = if !mapped_vals.is_empty() { mapped_vals[rng.random_range(0..mapped_vals.len())] } else { *op as u32 };
        w.extend_from_slice(&selected_op.to_le_bytes()); w.push(*a); w.extend_from_slice(&b.to_le_bytes()); w.extend_from_slice(&c.to_le_bytes());
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
    for _ in 0..p_count { rewrite_chunk(r, w, strings, numbers, mapped_opcodes, builtin_map, setglobal_targets, getglobal_op, getglobalstr_op, inverse_opcode_map, slot_perm, rng); }
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

pub struct Generator { ctx: VmContext }

pub struct GenRng { used: HashSet<String> }

impl GenRng {
    pub fn new(_seed: u64) -> Self { Self { used: HashSet::new() } }
    pub fn next(&mut self) -> u32 { rng().random::<u32>() }
    pub fn range(&mut self, min: usize, max: usize) -> usize { rng().random_range(min..max) }
    pub fn range64(&mut self, min: i64, max: i64) -> i64 { rng().random_range(min..max) }
    pub fn name(&mut self) -> String {
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
        let keywords = ["and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"];
        loop {
            let len = self.range(7, 14);
            let s: String = (0..len).map(|_| chars[self.range(0, chars.len())]).collect();
            if !self.used.contains(&s) && !keywords.contains(&s.as_str()) { self.used.insert(s.clone()); return s; }
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

fn build_opcode_tree(handlers: &[(u32, String)], min_idx: usize, max_idx: usize, var_op: &str, keys: &CipherKeys, rng: &mut GenRng) -> String {
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

impl Generator {
    pub fn new(ctx: VmContext) -> Self { Self { ctx } }

    pub fn build(&self, payload: &[u8]) -> String {
        let mut rng = GenRng::new(self.ctx.seed);
        let var_l = rng.name();
        
        let key_seed_var = rng.name();
        let at = AntiTamper::generate_split(true, &key_seed_var);
        
        let mut used_ops = HashSet::new();
        { let mut scan_reader = PayloadReader { data: payload, pos: 0 }; scan_used_opcodes(&mut scan_reader, &mut used_ops); }

        let mut setglobal_targets: HashSet<Vec<u8>> = HashSet::new();
        let setglobal_op = self.ctx.opcode_map[7];
        let getglobal_op = self.ctx.opcode_map[5];
        let getglobalstr_op = self.ctx.opcode_map[56];
        let mut inverse_opcode_map = [0u8; 90];
        for i in 0..90 { inverse_opcode_map[self.ctx.opcode_map[i] as usize] = i as u8; }
        let builtin_slot_perm = Opcodes::builtins::slot_permutation(self.ctx.seed);
        { let mut sg_reader = PayloadReader { data: payload, pos: 0 }; scan_setglobal_targets(&mut sg_reader, &mut setglobal_targets, setglobal_op); }

        let mut mapped_opcodes: [Vec<u32>; Opcodes::builtins::TOTAL_OPCODES] = std::array::from_fn(|_| Vec::new());
        let mut transpile_map: [Vec<u32>; 90] = std::array::from_fn(|_| Vec::new());
        {
            let mut map_rng = StdRng::seed_from_u64(self.ctx.seed);
            let mut used = std::collections::HashSet::new();
            for i in 0..90 {
                let shuffled_val = self.ctx.opcode_map[i];
                let count = if used_ops.contains(&shuffled_val) { map_rng.random_range(3..=6) } else { 1 };
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); transpile_map[shuffled_val as usize].push(val); break; }
                    }
                }
            }
            for i in 90..Opcodes::builtins::TOTAL_OPCODES {
                let count = map_rng.random_range(3..=6);
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); break; }
                    }
                }
            }
        }

        let mut strings = Vec::new(); let mut numbers = Vec::new(); let mut rewritten_chunks = Vec::new();
        let mut reader = PayloadReader { data: payload, pos: 0 };
        let mut rewrite_rng = StdRng::seed_from_u64(self.ctx.seed + 1);
        rewrite_chunk(&mut reader, &mut rewritten_chunks, &mut strings, &mut numbers, &transpile_map, &mapped_opcodes, &setglobal_targets, getglobal_op, getglobalstr_op, &inverse_opcode_map, &builtin_slot_perm, &mut rewrite_rng);

        let mut builtin_pool_indices: Vec<usize> = Vec::with_capacity(Opcodes::builtins::BUILTIN_NAMES.len());
        for name in Opcodes::builtins::BUILTIN_NAMES.iter() {
            let nb = name.as_bytes().to_vec();
            let pos = strings.iter().position(|x| x == &nb).unwrap_or_else(|| { strings.push(nb); strings.len() - 1 });
            builtin_pool_indices.push(pos);
        }

        let chacha_key: [u32; 8] = std::array::from_fn(|_| rng.next());
        let chacha_salt: u32 = rng.next();

        let mut pool_bytes = Vec::new();
        pool_bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        for (idx, s) in strings.iter().enumerate() {
            let enc_s = chacha8_xor(&chacha_key, chacha_salt, idx as u32, 0, s);
            write_string(&mut pool_bytes, &enc_s);
        }
        pool_bytes.extend_from_slice(&(numbers.len() as u32).to_le_bytes());
        for (idx, n) in numbers.iter().enumerate() {
            let enc_n_bytes = chacha8_xor(&chacha_key, chacha_salt, idx as u32, 1, &n.to_le_bytes());
            pool_bytes.extend_from_slice(&enc_n_bytes);
        }
        
        let mut combined_payload = Vec::new();
        let (mut k1, mut k2, mut k3, mut k4) = ((rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8);
        combined_payload.push(k1); combined_payload.push(k2); combined_payload.push(k3); combined_payload.push(k4);
        
        for b in pool_bytes.iter_mut() {
            let orig = *b;
            *b = orig ^ k1; *b = b.wrapping_sub(k2); *b = b.rotate_left((k3 % 8) as u32); *b = *b ^ k4; *b = b.wrapping_add(0x42);
            k1 = k1.wrapping_add(orig).rotate_left(1).wrapping_add(0x1B);
            k2 = k2.wrapping_mul(3).wrapping_add(*b).rotate_right(2);
            k3 = k3 ^ k1.wrapping_sub(k4);
            k4 = k4.wrapping_add(k2).rotate_left(3);
        }
        combined_payload.extend(pool_bytes); combined_payload.extend(rewritten_chunks);
        
        let key_kryvex = String::from("x1"); let p_out: Vec<String> = (0..6).map(|_| rng.name()).collect();
        let var_s = rng.name(); let fn_N_ = rng.name(); let var_fU = rng.name(); let var_L = rng.name(); let var_get_count = rng.name();
        let hex_select_idx = format!("{:#x}", rng.range(10, 255));
        let var_state_flag = rng.name();
        let wai = rng.name();
        let mut header_block = String::new();
        header_block.push_str(&format!("return ({{ {} = function(agv,aggv,agv,agv,agv,aggv,agv,agv,aggv,aggv,aggv,agggv,agggv,agggv,agggv,aggv,{},{},{},{}, ...)\n", wai, p_out[0], p_out[1], p_out[2], p_out[3]));
        header_block.push_str(&format!("local {} = {{}}; local {} = false; ", var_s, var_state_flag));
        header_block.push_str(&format!("local {} = bit32 and bit32.rshift or bit and bit.rshift; ", var_fU));
        header_block.push_str(&format!("local {} = function(q, s, M, C) s[{}] = select; end; ", fn_N_, hex_select_idx));
        header_block.push_str(&format!("{}(nil, {}, nil, nil); ", fn_N_, var_s));
        
        let keys = CipherKeys { 
            grp1: rng.range(0x10, 0x7F) as u64, 
            grp2: rng.range(0x10, 0x7F) as u64, 
            key_bx: rng.range(0x10, 0x7F) as u64, 
            key_ba: rng.range(0x10, 0x7F) as u64, 
            key_add: rng.range(0x10, 0x7F) as u64, 
            key_bs: rng.range(0x10, 0x7F) as u64, 
            key_ba2: rng.range(0x10, 0x7F) as u64, 
            key_bs2: rng.range(0x10, 0x7F) as u64, 
            tbl_p: rng.name() 
        };

        let fn_bx = rng.name();
        let fn_ba = rng.name();
        let fn_bs = rng.name();
        let mut block_p_def = String::new();
        block_p_def.push_str(&format!("local {}={}; local {}={}; local {}={}; ", 
            fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b)local r,p=0,1;while a>0 or b>0 do local ra,rb=a%2,b%2;if ra~=rb then r=r+p end;a,b,p=math.floor(a/2),math.floor(b/2),p*2 end;return r end",
            fn_ba, "bit32 and bit32.band or bit and bit.band or function(a,b)local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=math.floor(a/2),math.floor(b/2),p*2 end;return r end",
            fn_bs, "bit32 and bit32.rshift or bit and bit.rshift or function(a,n)return math.floor(a/(2^n))end"
        ));
        let tbl_def = format!(
            "local {p}={{}};{p}[{g1}]={{}};{p}[{g1}][{bx}]={fbx};{p}[{g1}][{add}]=function(a,b)return a+b end;{p}[{g1}][{ba}]={fba};{p}[{g2}]={{}};{p}[{g2}][{ba2}]=function(a)return {fba}(a,{max_u32})end;{p}[{g2}][{bs2}]=function(a)return {fbs}(a,{one})end;",
            p = keys.tbl_p,
            g1 = rng.format_num(keys.grp1 as i64),
            g2 = rng.format_num(keys.grp2 as i64),
            bx = rng.format_num(keys.key_bx as i64),
            add = rng.format_num(keys.key_add as i64),
            ba = rng.format_num(keys.key_ba as i64),
            ba2 = rng.format_num(keys.key_ba2 as i64),
            bs2 = rng.format_num(keys.key_bs2 as i64),
            fbx = fn_bx,
            fba = fn_ba,
            fbs = fn_bs,
            max_u32 = rng.format_num(4294967295i64),
            one = rng.format_num(1i64)
        );
        block_p_def.push_str(&tbl_def);

        let block_vm_core = Lua_core::build_vm_core().replace("\n", " ");
        
        let (payload_str, decoder_script, entry_func) = Packer::pack(&combined_payload, &mut rng);
        let var_junk = rng.name(); let var_vc = rng.name(); let var_builtin_reg = rng.name();
        let block_packer_vars = format!("local {}, {}, {}; ", var_junk, var_vc, var_builtin_reg);

        let fn_execute = "execute";
        let var_pc = rng.name();
        let var_stk = rng.name();
        let var_top = rng.name();
        let var_inst = rng.name();
        let var_varargs = rng.name();
        let var_varargs_len = rng.name();
        let var_insts = rng.name();
        let var_opcodes = rng.name();
        let var_a_arr = rng.name();
        let var_b_arr = rng.name();
        let var_c_arr = rng.name();
        let mut block_execute_def = String::new();
        block_execute_def.push_str(&format!("local function {}(chunk, env, upvals, ...) ", fn_execute));
        block_execute_def.push_str(&format!("local {} = function(...) return {}[{}]('#', ...) end; ", var_get_count, var_s, hex_select_idx));
        block_execute_def.push_str(&format!("local {} = {}(...); ", var_L, var_get_count));
        block_execute_def.push_str(&format!("local unpack, zm = unpack or table and table.unpack or function() end, function(...) return {{n={}(...),...}} end; ", var_get_count));
        block_execute_def.push_str(&format!("local {}, {}, {}, {}, {}, {}, {} = chunk.opcodes, chunk.a_arr, chunk.b_arr, chunk.c_arr, 1, {{}}, 0; ", var_opcodes, var_a_arr, var_b_arr, var_c_arr, var_pc, var_stk, var_top));
        block_execute_def.push_str(&format!("for _=1,chunk.numparams do {}[_-1] = {}[{}](_,...) end; ", var_stk, var_s, hex_select_idx));
        block_execute_def.push_str(&format!("local {} = {} - chunk.numparams; local {} = {{{}[{}](chunk.numparams + 1, ...)}}; ", var_varargs_len, var_L, var_varargs, var_s, hex_select_idx));
        block_execute_def.push_str("while true do ");
        block_execute_def.push_str(&format!("{} = true; ", var_state_flag));
        block_execute_def.push_str(&format!("local op = {}[{}]; ", var_opcodes, var_pc));
        block_execute_def.push_str(&format!("local inst_A = {}[{}]; ", var_a_arr, var_pc));
        block_execute_def.push_str(&format!("local inst_B = {}[{}]; ", var_b_arr, var_pc));
        block_execute_def.push_str(&format!("local inst_C = {}[{}]; ", var_c_arr, var_pc));
        block_execute_def.push_str(&format!("{} = {} + 1; ", var_pc, var_pc));
        
        let cfg = OpcodeConfig { pc: var_pc.clone(), stk: var_stk.clone(), consts: "chunk.consts".to_string(), top: var_top.clone(), insts: var_insts.clone(), inst: var_inst.clone(), upvals: "upvals".to_string(), env: "env".to_string(), protos: "chunk.protos".to_string(), handlers: String::new(), varargs: var_varargs.clone(), varargs_len: var_varargs_len.clone(), virtual_closures: var_vc.clone(), builtin_reg: var_builtin_reg.clone() };
        let mut raw_handlers = Opcodes::generate_handlers(&mapped_opcodes, &cfg, self.ctx.seed).replace("execute(", &format!("{}(", fn_execute));
        
        raw_handlers = raw_handlers.replace(
            &format!("{}[{}][1]", var_insts, var_pc),
            &format!("{}[{}]", var_opcodes, var_pc)
        ).replace(
            &format!("{}[{}][2]", var_insts, var_pc),
            &format!("{}[{}]", var_a_arr, var_pc)
        ).replace(
            &format!("{}[{}][3]", var_insts, var_pc),
            &format!("{}[{}]", var_b_arr, var_pc)
        ).replace(
            &format!("{}[{}][4]", var_insts, var_pc),
            &format!("{}[{}]", var_c_arr, var_pc)
        ).replace(
            &format!("{}[{}]", var_insts, var_pc),
            &format!("({{ {}[{}], {}[{}], {}[{}], {}[{}] }})", var_opcodes, var_pc, var_a_arr, var_pc, var_b_arr, var_pc, var_c_arr, var_pc)
        ).replace(
            &format!("{}[1]", var_inst), "op"
        ).replace(
            &format!("{}[2]", var_inst), "inst_A"
        ).replace(
            &format!("{}[3]", var_inst), "inst_B"
        ).replace(
            &format!("{}[4]", var_inst), "inst_C"
        ).replace(
            &var_inst, "({op, inst_A, inst_B, inst_C})"
        );

        if raw_handlers.trim_start().starts_with("if op") { raw_handlers = raw_handlers.replacen("if op", "elseif op", 1); }

        let mut handlers_list: Vec<(u32, String)> = Vec::new();
        let mut remaining = raw_handlers.as_str();
        let mut current_ops: Vec<u32> = Vec::new(); let mut current_code = String::new();
        
        while let Some(idx) = remaining.find("elseif op") {
            let before = &remaining[..idx];
            if !current_ops.is_empty() {
                current_code.push_str(before); let code_str = current_code.trim().to_string();
                for &op in &current_ops { handlers_list.push((op, code_str.clone())); }
                current_code.clear();
            }
            remaining = &remaining[idx + 9..];
            if let Some(then_idx) = remaining.find("then") {
                let ops: Vec<u32> = remaining[..then_idx].split(|c: char| !c.is_numeric()).filter_map(|s| s.parse::<u32>().ok()).collect();
                if !ops.is_empty() { current_ops = ops; remaining = &remaining[then_idx + 4..]; } else { current_code.push_str("elseif op"); current_code.push_str(&remaining[..then_idx]); current_code.push_str("then"); remaining = &remaining[then_idx + 4..]; }
            }
        }
        if !current_ops.is_empty() {
            current_code.push_str(remaining); let code_str = current_code.trim().to_string();
            for &op in &current_ops { handlers_list.push((op, code_str.clone())); }
        }
        handlers_list.sort_by_key(|h| h.0);

        if !handlers_list.is_empty() { 
            block_execute_def.push_str(&build_opcode_tree(&handlers_list, 0, handlers_list.len() - 1, "op", &keys, &mut rng)); 
            block_execute_def.push_str(&format!(" end; {} = false; end; ", var_state_flag)); 
        } else { 
            let mut f = raw_handlers.replacen("elseif", "if", 1); 
            f.push_str(" end "); 
            block_execute_def.push_str(&f); 
            block_execute_def.push_str(&format!(" {} = false; end; ", var_state_flag)); 
        }

        let block_decoder_script = decoder_script.replace("\n", " ");
        
        let var_idx = rng.name(); let var_b = rng.name(); let var_tamper = rng.name(); let fn_s_byte = rng.name(); let fn_s_sub = rng.name(); let var_raw_p = rng.name(); let var_chk = rng.name(); let var_p = rng.name(); let var_a2 = rng.name(); let fn_a3 = rng.name(); let x = rng.name(); let var__a = rng.name(); let var__b = rng.name(); let fn_read_dec = rng.name(); let fn_bxor = rng.name(); let fn_b_rotr = rng.name(); let fn_a5 = rng.name(); let fn_read_string = rng.name(); let fn_a10 = rng.name(); let fn_dec_num = rng.name(); let fn_dec_str = rng.name(); let global_strings = rng.name(); let global_numbers = rng.name(); let fn_decode_chunk = rng.name(); let fn_u32_dec = rng.name(); let l = rng.name(); let s_t = rng.name(); let v = rng.name(); let v_sign = rng.name(); let v_exp = rng.name(); let v_mant = rng.name(); let t = rng.name(); let fn_c = rng.name();
        let var_boot_env = rng.name(); let var_bname = rng.name();

        let fn_qr = rng.name();
        let fn_xor32 = rng.name();
        let fn_rotl32 = rng.name();
        let fn_chacha_block = rng.name();
        let fn_chacha_stream = rng.name();
        let xor_tbl_var = rng.name();
        let chacha_key_var = rng.name();
        let chacha_salt_var = rng.name();
        let kind_str_obf = rng.obfuscate_num(0i64, 1, &keys);
        let kind_num_obf = rng.obfuscate_num(1i64, 1, &keys);
        let chacha_key_lua = (0..8).map(|i| rng.obfuscate_num(chacha_key[i] as i64, 1, &keys)).collect::<Vec<_>>().join(",");
        let chacha_salt_lua = rng.obfuscate_num(chacha_salt as i64, 1, &keys);

        let mut block_chacha_setup = String::new();
        block_chacha_setup.push_str(&format!(
            "local {xt}={{}}; for a=0,255 do local row={{}}; for b=0,255 do local x,y,r,p=a,b,0,1; while x>0 or y>0 do local rx,ry=x%2,y%2; if rx~=ry then r=r+p end; x,y,p=math_floor(x/2),math_floor(y/2),p*2 end; row[b]=r end; {xt}[a]=row end; ",
            xt = xor_tbl_var
        ));
        block_chacha_setup.push_str(&format!(
            "local function {xor32}(a,b) local a1,a2,a3,a4=a%256,math_floor(a/256)%256,math_floor(a/65536)%256,math_floor(a/16777216)%256; local b1,b2,b3,b4=b%256,math_floor(b/256)%256,math_floor(b/65536)%256,math_floor(b/16777216)%256; return {xt}[a1][b1]+{xt}[a2][b2]*256+{xt}[a3][b3]*65536+{xt}[a4][b4]*16777216 end; ",
            xor32 = fn_xor32, xt = xor_tbl_var
        ));
        block_chacha_setup.push_str(&format!(
            "local function {rotl32}(x,n) local m=2^n; return ((x*m)%4294967296)+math_floor(x/(4294967296/m)) end; ",
            rotl32 = fn_rotl32
        ));
        block_chacha_setup.push_str(&format!(
            "local function {qr}(s,a,b,c,d) s[a]=(s[a]+s[b])%4294967296; s[d]={xor32}(s[d],s[a]); s[d]={rotl32}(s[d],16); s[c]=(s[c]+s[d])%4294967296; s[b]={xor32}(s[b],s[c]); s[b]={rotl32}(s[b],12); s[a]=(s[a]+s[b])%4294967296; s[d]={xor32}(s[d],s[a]); s[d]={rotl32}(s[d],8); s[c]=(s[c]+s[d])%4294967296; s[b]={xor32}(s[b],s[c]); s[b]={rotl32}(s[b],7) end; ",
            qr = fn_qr, xor32 = fn_xor32, rotl32 = fn_rotl32
        ));
        block_chacha_setup.push_str(&format!(
            "local {ckey}={{{key_lua}}}; local {csalt}={salt_lua}; ",
            ckey = chacha_key_var, key_lua = chacha_key_lua, csalt = chacha_salt_var, salt_lua = chacha_salt_lua
        ));
        block_chacha_setup.push_str(&format!(
            "local function {cblock}(n1,n2,n3,ctr) local K={ckey}; local s={{0x61707865,0x3320646e,0x79622d32,0x6b206574,K[1],K[2],K[3],K[4],K[5],K[6],K[7],K[8],ctr,n1,n2,n3}}; local o={{}}; for i=1,16 do o[i]=s[i] end; for _=1,4 do {qr}(s,1,5,9,13); {qr}(s,2,6,10,14); {qr}(s,3,7,11,15); {qr}(s,4,8,12,16); {qr}(s,1,6,11,16); {qr}(s,2,7,12,13); {qr}(s,3,8,9,14); {qr}(s,4,5,10,15) end; local out={{}}; for i=1,16 do local w=(s[i]+o[i])%4294967296; out[(i-1)*4+1]=w%256; out[(i-1)*4+2]=math_floor(w/256)%256; out[(i-1)*4+3]=math_floor(w/65536)%256; out[(i-1)*4+4]=math_floor(w/16777216)%256 end; return out end; ",
            cblock = fn_chacha_block, ckey = chacha_key_var, qr = fn_qr
        ));
        block_chacha_setup.push_str(&format!(
            "local function {cstream}(pool_idx,kind,n) local out={{}}; local ctr=0; local pos=1; while pos<=n do local blk={cblock}({csalt},pool_idx,kind,ctr); for i=1,64 do if pos>n then break end; out[pos]=blk[i]; pos=pos+1 end; ctr=ctr+1 end; return out end; ",
            cstream = fn_chacha_stream, cblock = fn_chacha_block, csalt = chacha_salt_var
        ));
        
        let block_dec_header = format!("local {}, {} = {}, {}; local {} = ([=[KRYVEX{}]=]); local {}, {}, {} = {}, {}, {}; repeat local {}={}({},{}); {}={}+{}; {}={}+{}; {}={}+({}%{}); until {}>={}; {} = ({}-{}) + ({}-{}); {}={}+(type({})=='function' and 0 or {}); local mt_vc={{}}; mt_vc[\"__\"..\"mode\"]='k'; {} = setmetatable({{}}, mt_vc); local {}, {} = {}({}({},{}+{}*{})), {}; local function {}() local {}={}({},{},{}); {}={}+{}; return {} end; local k1,k2,k3,k4 = {}(),{}(),{}(),{}(); ", fn_s_byte, fn_s_sub, "string_byte", "string_sub", var_raw_p, payload_str, var_chk, var_idx, var_junk, rng.obfuscate_num(0i64, 1, &keys), rng.obfuscate_num(1i64, 1, &keys), rng.obfuscate_num(0i64, 1, &keys), var_b, fn_s_byte, var_raw_p, var_idx, var_chk, var_chk, var_b, var_idx, var_idx, rng.obfuscate_num(1i64, 1, &keys), var_junk, var_junk, var_b, rng.obfuscate_num(2i64, 1, &keys), var_idx, rng.obfuscate_num(7i64, 1, &keys), var_tamper, var_chk, var_chk, var_junk, var_junk, var_tamper, var_tamper, fn_s_byte, rng.obfuscate_num(73i64, 1, &keys), var_vc, var_p, var_a2, entry_func, fn_s_sub, var_raw_p, var_idx, var_tamper, rng.obfuscate_num(1337i64, 2, &keys), rng.obfuscate_num(1i64, 1, &keys), fn_a3, x, fn_s_byte, var_p, var_a2, var_a2, var_a2, var_a2, rng.obfuscate_num(1i64, 1, &keys), x, fn_a3, fn_a3, fn_a3, fn_a3);
        let block_dec_helpers = format!("local function {}(a, b) local r, p, c = 0, 1, 0; while a > 0 or b > 0 do local ra, rb = a % 2, b % 2; if ra ~= rb then c = c + p end; a, b, p = math_floor(a / 2), math_floor(b / 2), p * 2 end; return c end; local function {}(x, n) if n == 0 then return x end return ((x * (2^(8-n))) % 256) + math_floor(x / (2^n)) end; local function {}() local enc = {}(); local dec = (enc - 66 + 256) % 256; dec = {}(dec, k4); dec = {}(dec, k3 % 8); dec = (dec + k2) % 256; dec = {}(dec, k1); local orig = dec; k1 = (k1 + orig) % 256; k1 = ((k1 * 2) % 256) + math_floor(k1 / 128); k1 = (k1 + 27) % 256; k2 = (k2 * 3 + enc) % 256; k2 = ((k2 * 64) % 256) + math_floor(k2 / 4); k3 = {}(k3, (k1 - k4 + 256) % 256); k4 = (k4 + k2) % 256; k4 = ((k4 * 8) % 256) + math_floor(k4 / 32); return orig end; ", fn_bxor, fn_b_rotr, fn_read_dec, fn_a3, fn_bxor, fn_b_rotr, fn_bxor, fn_bxor);
        let block_dec_readers = format!("local function {}() local {}={{}}; for i=1,4 do {}[i]={}() end; return {}[1]+({}[2]*256)+({}[3]*65536)+({}[4]*16777216) end; local function {}() local {}={{}}; for i=1,4 do {}[i]={}() end; return {}[1]+({}[2]*{})+({}[3]*{})+({}[4]*{}) end; local function {}() local {}={}(); if {}=={} then return '' end; local {}={{}}; for _={},{} do {}[_]=string_char({}()) end; return table_concat({}) end; local function {}() local {}={}(); if {}>=2^31 then return {}-2^32 else return {} end end; ", fn_u32_dec, var__a, var__a, fn_read_dec, var__a, var__a, var__a, var__a, fn_a5, var__a, var__a, fn_a3, var__a, var__a, rng.obfuscate_num(256i64, 1, &keys), var__a, rng.obfuscate_num(65536i64, 1, &keys), var__a, rng.obfuscate_num(16777216i64, 1, &keys), fn_read_string, l, fn_a5, l, rng.obfuscate_num(0i64, 1, &keys), s_t, rng.obfuscate_num(1i64, 1, &keys), l, s_t, fn_a3, s_t, fn_a10, v, fn_a5, v, v, v);
        
        let mut f64_parts = vec![format!("({}[7]%16)*2^48", var__b), format!("({}[6]*2^40)", var__b), format!("({}[5]*2^32)", var__b), format!("({}[4]*2^24)", var__b), format!("({}[3]*2^16)", var__b), format!("({}[2]*2^8)", var__b), format!("{}[1]", var__b)];
        rng.shuffle(&mut f64_parts);

        let block_dec_numbers = format!(
            "local function {fn_dec_num}(v_enc, pool_idx) local ks={fn_chacha_stream}(pool_idx,{kind_num},8); local {vb}={{}}; for i=1,8 do {vb}[i]={xt}[v_enc[i]][ks[i]] end; local {v_sign} = {vb}[8]>=128 and -1 or 1; local {v_exp} = ({vb}[8]%128)*16+math_floor({vb}[7]/16); local {v_mant} = {f64parts}; if {v_exp}==0 then return {v_sign}*{v_mant}*(2^(-1074)) elseif {v_exp}==2047 then return {v_mant}==0 and {v_sign}*(1/0) or (0/0) else return {v_sign}*({v_mant}+2^52)*(2^({v_exp}-1075)) end end; ",
            fn_dec_num = fn_dec_num, fn_chacha_stream = fn_chacha_stream, kind_num = kind_num_obf, vb = var__b, xt = xor_tbl_var,
            v_sign = v_sign, v_exp = v_exp, v_mant = v_mant, f64parts = f64_parts.join("+"));

        let block_dec_strings = format!(
            "local function {fn_dec_str}(enc_s, pool_idx) local len=#enc_s; local ks={fn_chacha_stream}(pool_idx,{kind_str},len); local s={{}}; for j=1,len do s[j]=string_char({xt}[{fn_s_byte}(enc_s,j)][ks[j]]) end; return table_concat(s) end; ",
            fn_dec_str = fn_dec_str, fn_chacha_stream = fn_chacha_stream, kind_str = kind_str_obf, xt = xor_tbl_var, fn_s_byte = fn_s_byte);

        let block_pools_init_strings = format!("local {gs}={{}}; local str_count={u32d}(); for i=1,str_count do local len={u32d}(); local s={{}}; for j=1,len do s[j]=string_char({rd}()) end; {gs}[i]=table_concat(s); end; ",
            gs = global_strings, u32d = fn_u32_dec, rd = fn_read_dec);

        let block_pools_init_numbers = format!("local {gn}={{}}; local num_count={u32d}(); for i=1,num_count do local v={{}}; for j=1,8 do v[j]={rd}(); end; {gn}[i]=v; end; ",
            gn = global_numbers, u32d = fn_u32_dec, rd = fn_read_dec);

        let var_enc_c = rng.name();
        let var_tbl = rng.name();
        let var_idx_chunk = rng.name();
        let var_e = rng.name();
        let var_cache = rng.name();

        let var_state = rng.name();
        let s_init = rng.range(0x100, 0xFFF) as i64;
        let s_insts = rng.range(0x1000, 0x1FFF) as i64;
        let s_consts = rng.range(0x2000, 0x2FFF) as i64;
        let s_protos = rng.range(0x3000, 0x3FFF) as i64;
        let s_debug = rng.range(0x4000, 0x4FFF) as i64;
        let s_ret = rng.range(0x5000, 0x5FFF) as i64;

        let obf_s_init = rng.format_num(s_init);
        let obf_s_insts = rng.format_num(s_insts);
        let obf_s_consts = rng.format_num(s_consts);
        let obf_s_protos = rng.format_num(s_protos);
        let obf_s_debug = rng.format_num(s_debug);
        let obf_s_ret = rng.format_num(s_ret);
        
        let block_dec_chunk = format!(
            "local function {fn_dec_chunk}() \
                local {fn_c}, {t}, {var_state} = {{}}, nil, {obf_s_init}; \
                while true do \
                    if {var_state} == {obf_s_init} then \
                        {fn_c}.n={fn_read_string}(); \
                        {fn_c}.ld={fn_a5}(); \
                        {fn_c}.lld={fn_a5}(); \
                        {fn_c}.nups={fn_a3}(); \
                        {fn_c}.numparams={fn_a3}(); \
                        {fn_c}.is_vararg={fn_a3}(); \
                        {fn_c}.maxstack={fn_a3}(); \
                        {var_state} = {obf_s_insts}; \
                    elseif {var_state} == {obf_s_insts} then \
                        {fn_c}.opcodes={{}}; \
                        {fn_c}.a_arr={{}}; \
                        {fn_c}.b_arr={{}}; \
                        {fn_c}.c_arr={{}}; \
                        for _={one_obf},{fn_a5}() do \
                            {fn_c}.opcodes[_]={fn_a5}(); \
                            {fn_c}.a_arr[_]={fn_a3}(); \
                            {fn_c}.b_arr[_]={fn_a10}(); \
                            {fn_c}.c_arr[_]={fn_a10}(); \
                        end; \
                        {var_state} = {obf_s_consts}; \
                    elseif {var_state} == {obf_s_consts} then \
                        local {var_enc_c}={{}}; \
                        local {var_cache}={{}}; \
                        local mt_consts={{}}; \
                        mt_consts[\"__\"..\"index\"]=function({var_tbl},{var_idx_chunk}) \
                            if not {var_state_flag} then \
                                return \"KryvexObf_\"..{var_idx_chunk} \
                            end; \
                            local cached={var_cache}[{var_idx_chunk}]; \
                            if cached~=nil then \
                                return cached \
                            end; \
                            local {var_e}={var_enc_c}[{var_idx_chunk}]; \
                            if not {var_e} then \
                                return nil \
                            end; \
                            local val; \
                            if {var_e}[1]=={one_obf} then \
                                val={var_e}[2] \
                            elseif {var_e}[1]=={two_obf} then \
                                val={fn_dec_num}({var_e}[2],{var_e}[3]) \
                            elseif {var_e}[1]=={three_obf} then \
                                val={fn_dec_str}({var_e}[2],{var_e}[3]) \
                            end; \
                            {var_cache}[{var_idx_chunk}]=val; \
                            return val \
                        end; \
                        {fn_c}.consts=setmetatable({{}},mt_consts); \
                        for _={one_obf},{fn_a5}() do \
                            {t}={fn_a3}(); \
                            if {t}=={one_obf} then \
                                {var_enc_c}[_]={{1,{fn_a3}()~={zero_obf}}} \
                            elseif {t}=={two_obf} then \
                                local raw_idx={fn_a5}(); \
                                local idx=raw_idx+1; \
                                {var_enc_c}[_]={{2,{global_numbers}[idx],raw_idx}} \
                            elseif {t}=={three_obf} then \
                                local raw_idx={fn_a5}(); \
                                local idx=raw_idx+1; \
                                {var_enc_c}[_]={{3,{global_strings}[idx],raw_idx}} \
                            end \
                        end; \
                        {var_state} = {obf_s_protos}; \
                    elseif {var_state} == {obf_s_protos} then \
                        {fn_c}.protos={{}}; \
                        for _={one_obf},{fn_a5}() do \
                            {fn_c}.protos[_]={fn_dec_chunk}() \
                        end; \
                        {var_state} = {obf_s_debug}; \
                    elseif {var_state} == {obf_s_debug} then \
                        for _={one_obf},{fn_a5}() do \
                            {fn_a5}() \
                        end; \
                        for _={one_obf},{fn_a5}() do \
                            {fn_read_string}();{fn_a5}();{fn_a5}() \
                        end; \
                        for _={one_obf},{fn_a5}() do \
                            {fn_read_string}() \
                        end; \
                        {var_state} = {obf_s_ret}; \
                    elseif {var_state} == {obf_s_ret} then \
                        return {fn_c} \
                    end \
                end \
            end; ",
            fn_dec_chunk = fn_decode_chunk,
            fn_c = fn_c,
            t = t,
            var_state = var_state,
            obf_s_init = obf_s_init,
            obf_s_insts = obf_s_insts,
            obf_s_consts = obf_s_consts,
            obf_s_protos = obf_s_protos,
            obf_s_debug = obf_s_debug,
            obf_s_ret = obf_s_ret,
            fn_read_string = fn_read_string,
            fn_a5 = fn_a5,
            fn_a3 = fn_a3,
            one_obf = rng.obfuscate_num(1i64, 1, &keys),
            fn_a10 = fn_a10,
            var_enc_c = var_enc_c,
            var_cache = var_cache,
            var_tbl = var_tbl,
            var_idx_chunk = var_idx_chunk,
            var_state_flag = var_state_flag,
            var_e = var_e,
            fn_dec_num = fn_dec_num,
            fn_dec_str = fn_dec_str,
            zero_obf = rng.obfuscate_num(0i64, 1, &keys),
            two_obf = rng.obfuscate_num(2i64, 1, &keys),
            three_obf = rng.obfuscate_num(3i64, 1, &keys),
            global_numbers = global_numbers,
            global_strings = global_strings
        );

        let mut parts = vec![
            block_p_def,
            block_vm_core,
            block_packer_vars,
            block_execute_def,
            block_decoder_script,
            block_dec_header,
            block_dec_helpers,
            block_dec_readers,
            block_chacha_setup,
            block_dec_numbers,
            block_dec_strings,
            block_pools_init_strings,
            block_pools_init_numbers,
            block_dec_chunk,
        ];

        let mut shuffled_guards = at.guards.clone();
        rng.shuffle(&mut shuffled_guards);

        for guard in shuffled_guards {
            let gap_idx = rng.range(0, parts.len() + 1);
            parts.insert(gap_idx, guard);
        }

        let mut out = String::new();
        out.push_str(&format!("local {} = ...;\n", var_l));
        out.push_str(&header_block);
        out.push_str(&at.setup);
        out.push_str(&format!(" local {} = 0; ", key_seed_var));
        out.push_str(" ");
        out.push_str("local math_floor, string_char, string_sub, string_byte, table_concat = math.floor, string.char, string.sub, string.byte, table.concat; ");

        for part in parts {
            out.push_str(&part);
            out.push_str(" ");
        }

        out.push_str(&format!("local main_chunk={}(); ", fn_decode_chunk));
        out.push_str(&at.trigger);
        out.push_str(&format!(" {} = {{}}; local {} = (getfenv and getfenv() or _ENV or _G); local {}; ", var_builtin_reg, var_boot_env, var_bname));
        for (i, name) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
            let slot = builtin_slot_perm[i];
            let raw_idx = builtin_pool_indices[i];
            let lua_idx = raw_idx + 1;
            out.push_str(&format!(
                "{bname}={fn_dec_str}({gs}[{lidx}],{ridx}); {reg}[{slot}]={benv}[{bname}]; if {reg}[{slot}]==nil and getgenv then {reg}[{slot}]=getgenv()[{bname}] end; ",
                bname = var_bname, fn_dec_str = fn_dec_str, gs = global_strings,
                lidx = lua_idx, ridx = raw_idx, reg = var_builtin_reg, slot = slot + 1, benv = var_boot_env
            ));
            let _ = name;
        }
        let fu = rng.name();
        
        out.push_str(" ");
        out.push_str(&format!("return {}(main_chunk, {}, {{}}, {}) end,{}=function(x) x:{}() end", fn_execute, var_boot_env, var_l, fu, wai));
        out.push_str(&format!(" }}):{}()", fu));
        out
    }
}