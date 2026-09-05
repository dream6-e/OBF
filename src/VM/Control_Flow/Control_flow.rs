use crate::VM::VM_Backend::Generator::GenRng;

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
    fn format_num(val: i64, rng: &mut GenRng) -> String {
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

    fn generate_opaque_predicate(val: i64, var_name: &str, comp_op: &str, keys: &CipherKeys, rng: &mut GenRng) -> String {
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

        out.push_str("while not(nil and false) do ");
        
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

    fn generate_leaf_node(
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

    fn generate_recursive_tree(
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