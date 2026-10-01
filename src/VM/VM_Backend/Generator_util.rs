//! Generator 的底层工具层：数值/控制流混淆、随机名池、流表与游标机。
//! 载荷读写与字节码重写已拆至 Generator_rewrite.rs（守单文件 80 KB 上限）。
use std::collections::HashSet;
use rand::{rng, Rng, SeedableRng};
use rand::rngs::StdRng;

pub use super::Generator_rewrite::{loader_lookup, loadstring_probe_lua};
pub(super) use super::Generator_rewrite::*;

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
                    format!("-0X{:X}", val.unsigned_abs())
                } else {
                    format!("0X{:X}", val)
                }
            }
            _ => val.to_string(),
        }
    }

    pub fn obfuscate_num_depth(val: i64, depth: usize, keys: &CipherKeys, rng: &mut GenRng) -> String {
        if depth == 0 {
            return Self::format_num(val, rng);
        }

        // ㉚④：val==0 时禁走差式——`(x-x)` 是同字面量自抵消的暴露形态；
        // 零值改走运行时查表分支（真·不可静态折叠）。
        let style = rng.range(if val == 0 { 4 } else { 0 }, 10);
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
        // 改进项二：彻底消除「R<=R and R or J」单一正则锚点与固定 c[g1][add](X,K)<=M 模板。
        // 1) 变量恒等包装池（8 形态随机，R<=R 恒真式徹底退役）：
        //    0=裸变量  1=(R and R or J)  2=(K1~=K2 and R or J)  3=(K1==K2 and J or R)
        //    4=(R>=0X0 and R or J)  5=(R~=R and J or R)  6=(not(not R) and R or J)  7=(K1<K2 and R or J)
        let jn = Self::format_num(rng.range(0x10, 0xFFFF) as i64, rng);
        let ka = rng.range(0x10, 0x7FFF) as i64;
        let kb = ka + rng.range(0x1, 0x7FF) as i64;
        let ka_s = Self::format_num(ka, rng);
        let kb_s = Self::format_num(kb, rng);
        let x_expr = match rng.range(0, 8) {
            0 => var_name.to_string(),
            1 => format!("({v} and {v} or {j})", v = var_name, j = jn),
            2 => format!("({a}~={b} and {v} or {j})", a = ka_s, b = kb_s, v = var_name, j = jn),
            3 => format!("({a}=={b} and {j} or {v})", a = ka_s, b = kb_s, j = jn, v = var_name),
            4 => format!("({v}>=0X0 and {v} or {j})", v = var_name, j = jn),
            5 => format!("({v}~={v} and {j} or {v})", v = var_name, j = jn),
            6 => format!("(not(not {v}) and {v} or {j})", v = var_name, j = jn),
            _ => format!("({a}<{b} and {v} or {j})", a = ka_s, b = kb_s, v = var_name, j = jn),
        };

        // 2) 严格/非严格边界随机转换（整数域 X<=V ⇔ X<V+1；X>V ⇔ X>=V+1）
        let is_le = comp_op == "<=";
        let use_strict = rng.range(0, 2) == 0;
        let swap_sides = rng.range(0, 2) == 0;
        let t_val = if use_strict { val.wrapping_add(1) } else { val };

        let g1 = Self::format_num(keys.grp1 as i64, rng);
        let kadd = Self::format_num(keys.key_add as i64, rng);
        let add_call = format!("{}[{}][{}](", keys.tbl_p, g1, kadd);

        // 3) 六族异构代数变换（含正系数平移/双偏移/反号镜像/仿射缩放/阈值左折）：
        //    反号镜像族（K - X）使变量系数为负，不等号方向与阈值同步翻转，打破静态方向判定。
        let (lhs_x, rhs_t, eff_le, eff_strict) = match rng.range(0, 6) {
            0 => {
                let k = rng.range(0x10, 0xFFF) as i64;
                let ks = Self::format_num(k, rng);
                let lx = if rng.range(0, 2) == 0 {
                    format!("{add}{x},{k})", add = add_call, x = x_expr, k = ks)
                } else {
                    format!("{add}{k},{x})", add = add_call, x = x_expr, k = ks)
                };
                (lx, Self::format_num(t_val.wrapping_add(k), rng), is_le, use_strict)
            }
            1 => {
                let k1 = rng.range(0x20, 0xFFF) as i64;
                let k2 = rng.range(0x10, 0x7FF) as i64;
                let (k1s, k2s) = (Self::format_num(k1, rng), Self::format_num(k2, rng));
                let lx = if rng.range(0, 2) == 0 {
                    format!("({add}{x},{k1})-{k2})", add = add_call, x = x_expr, k1 = k1s, k2 = k2s)
                } else {
                    format!("(({x}-{k2})+{k1})", x = x_expr, k1 = k1s, k2 = k2s)
                };
                (lx, Self::format_num(t_val.wrapping_add(k1).wrapping_sub(k2), rng), is_le, use_strict)
            }
            2 => {
                let r = rng.range(0x100, 0xFFFF) as i64;
                let k = t_val.wrapping_add(r);
                let ks = Self::format_num(k, rng);
                let lx = if rng.range(0, 2) == 0 {
                    format!("({k}-{x})", k = ks, x = x_expr)
                } else {
                    format!("{add}{k},-{x})", add = add_call, k = ks, x = x_expr)
                };
                (lx, Self::format_num(r, rng), !is_le, !use_strict)
            }
            3 => {
                let s = [2i64, 3, 5, 7][rng.range(0, 4)];
                let k = rng.range(0x10, 0xFFF) as i64;
                let (ss, ks) = (Self::format_num(s, rng), Self::format_num(k, rng));
                let lx = if rng.range(0, 2) == 0 {
                    format!("{add}{x}*{s},{k})", add = add_call, x = x_expr, s = ss, k = ks)
                } else {
                    format!("({x}*{s}+{k})", x = x_expr, s = ss, k = ks)
                };
                (lx, Self::format_num(t_val.wrapping_mul(s).wrapping_add(k), rng), is_le, use_strict)
            }
            4 => {
                let k = rng.range(0x100, 0x7FFF) as i64;
                let ks = Self::format_num(k, rng);
                let lx = if t_val >= k {
                    let d = Self::format_num(t_val - k, rng);
                    format!("({x}-{d})", x = x_expr, d = d)
                } else {
                    let d = Self::format_num(k - t_val, rng);
                    format!("{add}{x},{d})", add = add_call, x = x_expr, d = d)
                };
                (lx, ks, is_le, use_strict)
            }
            _ => {
                let s = [2i64, 3, 4, 5][rng.range(0, 4)];
                let r = rng.range(0x100, 0xFFFF) as i64;
                let k = t_val.wrapping_mul(s).wrapping_add(r);
                let (ks, ss) = (Self::format_num(k, rng), Self::format_num(s, rng));
                let lx = format!("({k}-{x}*{s})", k = ks, x = x_expr, s = ss);
                (lx, Self::format_num(r, rng), !is_le, !use_strict)
            }
        };

        // 4) 左右操作数随机换位（LHS <op> RHS vs RHS <rev_op> LHS）
        if !swap_sides {
            let op_str = match (eff_le, eff_strict) {
                (true, false) => "<=",
                (true, true) => "<",
                (false, false) => ">",
                (false, true) => ">=",
            };
            format!("{}{}{}", lhs_x, op_str, rhs_t)
        } else {
            let op_str = match (eff_le, eff_strict) {
                (true, false) => ">=",
                (true, true) => ">",
                (false, false) => "<",
                (false, true) => "<=",
            };
            format!("{}{}{}", rhs_t, op_str, lhs_x)
        }
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

        out.push_str(&format!("local qT4b={{}};for i=0,15 do qT4b[i]={{}};for j=0,15 do local r,p=0,1;local x,y=i,j;for k=1,4 do local rx,ry=x%2,y%2;if rx~=ry then r=r+p end;x=(x-rx)/2;y=(y-ry)/2;p=p+p end;qT4b[i][j]=r end end;local qT8b={{}};for i=0,255 do qT8b[i]={{}};end;for i=0,255 do local qIb=qT8b[i];local qHb=(i-i%16)/16;for j=0,255 do qIb[j]=qT4b[i%16][j%16]+qT4b[qHb][(j-j%16)/16]*16 end end; local {}={};", fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b) local r,p=0,1;for k=1,4 do local x,y=a%256,b%256;r=r+qT8b[x][y]*p;a=(a-x)/256;b=(b-y)/256;p=p*256 end;return r end"));
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
    #[allow(dead_code)]
    pub fn slot(&mut self) -> i64 {
        loop {
            let v = self.range64(0x0200_0000, 0x7FFF_FFFF);
            if !self.slots.contains(&v) { self.slots.push(v); return v; }
        }
    }

    /// ④ 能动态生成的就动态生成：槽位号以前是逐个写死的十进制大整数，
    /// 同一个号在产物里出现几百次（`self[837110348]`），等于给逆向标好了路标；
    /// 而且「同一个大常量反复出现」本身就是可以搜索替换的特征。
    /// 现在改成**运行期**由一条线性同余序列推出来 —— 产物里不再有任何一个槽位号
    /// 字面量，每个号只在序列里出现一次，其余位置全是局部名字（还顺带变小）。
    /// 返回 (名字列表, 初始化语句)。序列取 `x = (x*乘数) % 模`，乘数 < 2^16、
    /// 模 < 2^31 ⇒ x*乘数 < 2^47，double 里仍是精确整数（Lua/Roblox 行为一致）。
    pub fn slot_key_block(&mut self, count: usize) -> (Vec<String>, String) {
        let m = self.range64(0x1000_0000, 0x7000_0000) as u64;
        let a = (self.range64(3, 0x1_0000) as u64) | 1;
        let seed = self.range64(1, m as i64 - 1) as u64;
        let floor = 0x0200_0000u64;
        let mut kept: Vec<(usize, u64)> = Vec::new();
        let mut v = seed;
        let mut idx = 0usize;
        while kept.len() < count && idx < 200_000 {
            idx += 1;
            v = (v.wrapping_mul(a)) % m;
            if v >= floor && !kept.iter().any(|&(_, x)| x == v) {
                kept.push((idx, v));
            }
        }
        let last = kept.last().map(|k| k.0).unwrap_or(1);
        // 兜底：极端情况下序列里凑不满 count 个合规值，就用直接随机的字面量补齐
        // （仍然保证互不相同），免得出现「名字比取值多」→ 取到 nil 键。
        let mut extra: Vec<u64> = Vec::new();
        while kept.len() + extra.len() < count {
            let v = self.range64(0x0200_0000, 0x7FFF_FFFF) as u64;
            if !kept.iter().any(|&(_, x)| x == v) && !extra.contains(&v) {
                extra.push(v);
            }
        }
        let (x_name, arr_name, _i_name) = (self.name(), self.name(), self.name());
        let names: Vec<String> = (0..count).map(|_| self.name()).collect();
        // ㉒① LCG 推导循环 → 数值游标机（原 for 的每一步都保留，只是改走
        // while true + if G==K 的扁平化游走；P 表此刻未建，常数用混合进制字面量）。
        let states = ((last + 7) / 8).min(8).max(2);
        let walk_off = self.range(0, 100);
        let walk = {
            let (xn, an) = (x_name.clone(), arr_name.clone());
            let (ah, mh) = (format!("0X{:X}", a), format!("0X{:X}", m));
            let unit = |iv: &str| format!("{x}=({x}*{a})%{m};{arr}[{iv}]={x};", x = xn, a = ah, m = mh, arr = an);
            cursor_walk_static(self, None, walk_off, 1, last as i64, states, None, &unit)
        };
        let setup = format!(
            "local {x}=0X{seed:X};local {arr}={{}};{walk}local {bindings}={picks}; ",
            x = x_name, arr = arr_name, walk = walk,
            seed = seed,
            bindings = names.join(","),
            picks = kept.iter().map(|(i, _)| format!("{}[{}]", arr_name, i))
                .chain(extra.iter().map(|v| format!("0X{:X}", v)))
                .collect::<Vec<_>>().join(",")
        );
        (names, setup)
    }

    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        let mut r = rng();
        for i in (1..slice.len()).rev() { slice.swap(i, r.random_range(0..=i)); }
    }
    pub fn format_num(&mut self, val: i64) -> String {
        match self.range(0, 2) { 0 => { if val < 0 { format!("-0X{:X}", val.unsigned_abs()) } else { format!("0X{:X}", val) } } _ => val.to_string() }
    }
    pub fn obfuscate_num(&mut self, val: i64, depth: usize, keys: &CipherKeys) -> String {
        if depth == 0 { return self.format_num(val); }
        // ㉚④：val==0 禁走差式——`(x-x)` 同字面量自抵消是暴露形态；零值走查表
        let style = self.range(if val == 0 { 4 } else { 0 }, 10);
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
    // 改进项二：1) 间隙随机枢轴（pivot 取自 [handlers[cut].0, handlers[cut+1].0 - 1] 开区间内部，
    // 节点比较常数不再等于任何真实 opcode 魔数）；2) 二叉/三叉混合 + 切分点随机抖动 + 三路顺序翻转。
    let pivot_at = |cut: usize, rng: &mut GenRng| -> i64 {
        let lo = handlers[cut].0 as i64;
        let hi = handlers[cut + 1].0 as i64;
        if hi > lo + 1 { lo + rng.range64(0, hi - lo) } else { lo }
    };
    let span = max_idx - min_idx + 1;
    if span >= 6 && rng.range(0, 3) == 0 {
        let third = span / 3;
        let cut1 = min_idx + third.saturating_sub(1) + rng.range(0, 2);
        let rem = max_idx - cut1;
        let cut2 = cut1 + (rem / 2).max(1);
        if cut1 >= min_idx && cut1 < cut2 && cut2 < max_idx {
            let p1 = pivot_at(cut1, rng);
            let p2 = pivot_at(cut2, rng);
            let left = build_opcode_tree(handlers, min_idx, cut1, var_op, keys, rng);
            let mid_b = build_opcode_tree(handlers, cut1 + 1, cut2, var_op, keys, rng);
            let right = build_opcode_tree(handlers, cut2 + 1, max_idx, var_op, keys, rng);
            return match rng.range(0, 3) {
                0 => {
                    let c1 = ControlFlowBuilder::generate_opaque_predicate(p1, var_op, "<=", keys, rng);
                    let c2 = ControlFlowBuilder::generate_opaque_predicate(p2, var_op, "<=", keys, rng);
                    format!("if {} then {} elseif {} then {} else {} end ", c1, left, c2, mid_b, right)
                }
                1 => {
                    let c1 = ControlFlowBuilder::generate_opaque_predicate(p2, var_op, ">", keys, rng);
                    let c2 = ControlFlowBuilder::generate_opaque_predicate(p1, var_op, ">", keys, rng);
                    format!("if {} then {} elseif {} then {} else {} end ", c1, right, c2, mid_b, left)
                }
                _ => {
                    let c1 = ControlFlowBuilder::generate_opaque_predicate(p1, var_op, "<=", keys, rng);
                    let c2 = ControlFlowBuilder::generate_opaque_predicate(p2, var_op, ">", keys, rng);
                    format!("if {} then {} elseif {} then {} else {} end ", c1, left, c2, right, mid_b)
                }
            };
        }
    }
    let mid = if span >= 4 && rng.range(0, 2) == 0 {
        let base = (min_idx + max_idx) / 2;
        let jitter = rng.range(0, 3) as isize - 1;
        ((base as isize + jitter).clamp(min_idx as isize, (max_idx - 1) as isize)) as usize
    } else {
        (min_idx + max_idx) / 2
    };
    let piv = pivot_at(mid, rng);
    let left = build_opcode_tree(handlers, min_idx, mid, var_op, keys, rng);
    let right = build_opcode_tree(handlers, mid + 1, max_idx, var_op, keys, rng);
    let direction = rng.range(0, 2) == 0;
    if direction {
        let cond = ControlFlowBuilder::generate_opaque_predicate(piv, var_op, "<=", keys, rng);
        format!("if {} then {} else {} end ", cond, left, right)
    } else {
        let cond = ControlFlowBuilder::generate_opaque_predicate(piv, var_op, ">", keys, rng);
        format!("if {} then {} else {} end ", cond, right, left)
    }
}

/// 改进项一：原生 Lua 闭包内联的指令惰性解码器（彻底废除 `loadstring`/`load` + `StreamTable` 源码级暴露）。
/// - 10 个核心常数（0x100/0x2/0x10001/0x45D9/2^32/2^31/0x3/0x101/0x1001/0x11）提升至外层 IIFE
///   并以 `deep10` 位异或链/KDF 派生+乱序声明，内层热闭包内零字面量魔数；
/// - 8 个绑定形参（Pa..Pk）按随机排列洗牌，调用点同步按同排列传参；
/// - 状态表 `dc_ds` 的 5 个字段名（原固定 `.n/.ch/.m1/.m2/.m3`）全量随机化；
/// - 内层填充闭包采用 3 态 + 1 诱饵态的平坦化 `while` 状态机分发（状态分支乱序）。
pub(super) fn build_inst_decoder_lua(
    rng: &mut GenRng,
    fn_bxor2: &str,
    chain_delta: u32,
    chain_m: u64,
    chain_k0: u64,
    var_opcodes: &str,
    var_a_arr: &str,
    var_b_arr: &str,
    var_c_arr: &str,
    dc_ds: &str,
    n_dc: &str,
    pf_lld: &str,
    n_kon: &str,
    n_mk1: &str,
    n_mk2: &str,
    n_mk3: &str,
    var_vm: &str,
    k_dc: &str,
    ds_fields: (&str, &str, &str, &str, &str),
) -> (String, String) {
    let (ds_n, ds_ch, ds_m1, ds_m2, ds_m3) = ds_fields;
    let dc_fn = rng.name();
    let dc_fill = rng.name();
    let dl_e = crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, chain_delta as i64);
    let chm_e = crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, chain_m as i64);
    let chk0_e = crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, chain_k0 as i64);
    let dc_family = rng.range(0, 4);

    // 外层 IIFE 常量局部名（全部经 deep10/kdf_pow2 一次求值，内层零字面量）
    let (c_100, c_2, c_10001, c_45d9, c_m32, c_m31, c_3, c_101, c_1001, c_11) = (
        rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
        rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
    );
    let mut const_decls = vec![
        format!("local {}={};", c_100, crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, 0x100)),
        format!("local {}={};", c_2, crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, 0x2)),
        format!("local {}={};", c_10001, crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, 0x10001)),
        format!("local {}={};", c_45d9, crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, 0x45D9)),
        format!("local {}={};", c_m32, crate::VM::VM_Backend::Generator_kdf::kdf_m32(rng)),
        format!("local {}={};", c_m31, crate::VM::VM_Backend::Generator_kdf::kdf_pow2(rng, 31)),
        format!("local {}={};", c_3, crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, 0x3)),
        format!("local {}={};", c_101, crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, 0x101)),
        format!("local {}={};", c_1001, crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, 0x1001)),
        format!("local {}={};", c_11, crate::VM::VM_Backend::Generator_flow::deep10(rng, fn_bxor2, 0x11)),
    ];
    rng.shuffle(&mut const_decls);

    // 8 个绑定形参名与调用实参同排列洗牌
    let (p_a, p_b, p_c, p_d, p_h, p_i, p_j, p_k) = (
        rng.name(), rng.name(), rng.name(), rng.name(),
        rng.name(), rng.name(), rng.name(), rng.name(),
    );
    let raw_params = [&p_a, &p_b, &p_c, &p_d, &p_h, &p_i, &p_j, &p_k];
    let raw_args = [
        var_opcodes.to_string(), var_a_arr.to_string(), var_b_arr.to_string(), var_c_arr.to_string(),
        dc_ds.to_string(), n_dc.to_string(), fn_bxor2.to_string(), dl_e,
    ];
    let mut perm: Vec<usize> = (0..8).collect();
    rng.shuffle(&mut perm);
    let params_str = perm.iter().map(|&i| raw_params[i].as_str()).collect::<Vec<_>>().join(",");
    let bind_args = perm.iter().map(|&i| raw_args[i].as_str()).collect::<Vec<_>>().join(",");

    // 内层闭包局部工作变量（在 while 外统一声明，跨状态共享）
    let (w_a, w_b, w_c, w_d, w_e, w_f, w_g, w_h, w_i, w_j, w_x) = (
        rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
        rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
    );

    // State 0: 推进游标 n + 读取 Wa + 计算 Wb/Wc/Wd/We
    let mut blk_eo = vec![
        format!("{wb}=({ph}.{ch}%{c100})*{c2};", wb = w_b, ph = p_h, ch = ds_ch, c100 = c_100, c2 = c_2),
        format!("{wc}=(({ph}.{ch}-({ph}.{ch}%{c100}))/{c100})%{c100};", wc = w_c, ph = p_h, ch = ds_ch, c100 = c_100),
    ];
    let blk_cc = vec![
        format!("{wd}=({ph}.{ch}*{c10001})%{cm32};", wd = w_d, ph = p_h, ch = ds_ch, c10001 = c_10001, cm32 = c_m32),
        format!("{we}=({wd}*{c45d9}+{ph}.{ch})%{cm32};", we = w_e, wd = w_d, ph = p_h, ch = ds_ch, c45d9 = c_45d9, cm32 = c_m32),
    ];
    rng.shuffle(&mut blk_eo);
    let mut blocks: Vec<Vec<String>> = if dc_family == 2 || dc_family == 3 {
        vec![blk_cc, blk_eo]
    } else {
        vec![blk_eo, blk_cc]
    };
    if rng.range(0, 2) == 0 { blocks.reverse(); }
    let mut st0_stmts = vec![
        format!("{ph}.{fn_}={ph}.{fn_}+0X1;", ph = p_h, fn_ = ds_n),
        format!("{wa}={pa}[{ph}.{fn_}];", wa = w_a, pa = p_a, ph = p_h, fn_ = ds_n),
    ];
    for blk in &blocks { st0_stmts.extend(blk.iter().cloned()); }

    // State 1: 四路字段解掩码 Wf/Wg/Wh/Wi（顺序洗牌）
    let mut st1_stmts: Vec<String> = vec![
        if dc_family == 3 {
            format!("{wf}=({wa}-({ph}.{ch}%{c100})*{c2})%{cm32};", wf = w_f, wa = w_a, ph = p_h, ch = ds_ch, c100 = c_100, c2 = c_2, cm32 = c_m32)
        } else {
            format!("{wf}=({wa}-{wb})%{cm32};", wf = w_f, wa = w_a, wb = w_b, cm32 = c_m32)
        },
        if dc_family == 3 {
            format!("{wg}=({pj}({pb}[{ph}.{fn_}],{ph}.{m1})-(({ph}.{ch}-({ph}.{ch}%{c100}))/{c100})%{c100})%{cm32};",
                wg = w_g, pj = p_j, pb = p_b, ph = p_h, fn_ = ds_n, m1 = ds_m1, ch = ds_ch, c100 = c_100, cm32 = c_m32)
        } else {
            format!("{wg}=({pj}({pb}[{ph}.{fn_}],{ph}.{m1})-{wc})%{cm32};",
                wg = w_g, pj = p_j, pb = p_b, ph = p_h, fn_ = ds_n, m1 = ds_m1, wc = w_c, cm32 = c_m32)
        },
        format!("{wh}={pj}({pj}({pc}[{ph}.{fn_}],{ph}.{m2})%{cm32},{wd}); if {wh}>={cm31} then {wh}={wh}-{cm32} end;",
            wh = w_h, pj = p_j, pc = p_c, ph = p_h, fn_ = ds_n, m2 = ds_m2, cm32 = c_m32, wd = w_d, cm31 = c_m31),
        format!("{wi}={pj}({pj}({pd}[{ph}.{fn_}],{ph}.{m3})%{cm32},{we}); if {wi}>={cm31} then {wi}={wi}-{cm32} end;",
            wi = w_i, pj = p_j, pd = p_d, ph = p_h, fn_ = ds_n, m3 = ds_m3, cm32 = c_m32, we = w_e, cm31 = c_m31),
    ];
    rng.shuffle(&mut st1_stmts);

    // State 2: 滚动链状态推进 + Wj + 奇偶交换 + rawset 写回
    let upd = if std::env::var("OBF_NOCHAIN").is_ok() {
        format!("{ph}.{ch}=0X0;", ph = p_h, ch = ds_ch)
    } else if dc_family == 1 {
        format!("{wx}=({ph}.{ch}*{c3}+({wf}-{pk})*{c101}+{wg}*{c1001})%{cm32}; {ph}.{ch}=({wx}+{wh}%{cm32}+({wi}%{cm32})*{c11})%{cm32};",
            wx = w_x, ph = p_h, ch = ds_ch, c3 = c_3, wf = w_f, pk = p_k, c101 = c_101, wg = w_g, c1001 = c_1001, cm32 = c_m32, wh = w_h, wi = w_i, c11 = c_11)
    } else {
        format!("{ph}.{ch}=({ph}.{ch}*{c3}+({wf}-{pk})*{c101}+{wg}*{c1001}+{wh}%{cm32}+({wi}%{cm32})*{c11})%{cm32};",
            ph = p_h, ch = ds_ch, c3 = c_3, wf = w_f, pk = p_k, c101 = c_101, wg = w_g, c1001 = c_1001, wh = w_h, cm32 = c_m32, wi = w_i, c11 = c_11)
    };
    let wj_stmt = format!("{wj}={wg}-({wf}-{pk});", wj = w_j, wg = w_g, wf = w_f, pk = p_k);
    let swap_stmt = format!("if {wf}%{c2}~=0X0 then {wh},{wi}={wi},{wh} end;", wf = w_f, c2 = c_2, wh = w_h, wi = w_i);
    let mut st2_stmts: Vec<String> = match rng.range(0, 3) {
        0 => vec![upd, wj_stmt, swap_stmt],
        1 => vec![upd, swap_stmt, wj_stmt],
        _ => vec![wj_stmt, upd, swap_stmt],
    };
    st2_stmts.push(format!("rawset({pi},{ph}.{fn_},{{{wf},{wj},{wh},{wi}}});",
        pi = p_i, ph = p_h, fn_ = ds_n, wf = w_f, wj = w_j, wh = w_h, wi = w_i));

    // 3 态 + 1 诱饵态的平坦化状态机
    let st_var = rng.name();
    let s_vals = rng.distinct(5, 0x100, 0x7FFF);
    let (s0, s1, s2, s_decoy, s_done) = (
        s_vals[0] as i64, s_vals[1] as i64, s_vals[2] as i64, s_vals[3] as i64, s_vals[4] as i64,
    );
    let oc = crate::VM::VM_Backend::Generator_kdf::obf_const;
    let b0 = format!("{} {}={};", st0_stmts.join(" "), st_var, oc(rng, s1 as u64));
    let b1 = format!("{} {}={};", st1_stmts.join(" "), st_var, oc(rng, s2 as u64));
    let b2 = format!("{} {}={};", st2_stmts.join(" "), st_var, oc(rng, s_done as u64));
    let b_dec = format!("{wx}={pj}({wa} or 0X0,{pk}); {st}={sd};",
        wx = w_x, pj = p_j, wa = w_a, pk = p_k, st = st_var, sd = oc(rng, s_done as u64));
    let mut branches = vec![(s0, b0), (s1, b1), (s2, b2), (s_decoy, b_dec)];
    rng.shuffle(&mut branches);

    let mut fsm = format!(
        "local {wa},{wb},{wc},{wd},{we},{wf},{wg},{wh},{wi},{wj},{wx}; local {st}={s0_init}; while {st}~={sd_chk} do ",
        wa = w_a, wb = w_b, wc = w_c, wd = w_d, we = w_e, wf = w_f, wg = w_g, wh = w_h, wi = w_i, wj = w_j, wx = w_x,
        st = st_var, s0_init = oc(rng, s0 as u64), sd_chk = oc(rng, s_done as u64),
    );
    for (idx, (sv, bbody)) in branches.iter().enumerate() {
        let kw = if idx == 0 { "if" } else { "elseif" };
        fsm.push_str(&format!("{} {}=={} then {} ", kw, st_var, oc(rng, *sv as u64), bbody));
    }
    fsm.push_str("end end");

    let factory_prefix = format!(
        "local {ff}=(function() {cdecls} return function({params}) return function() {fsm} end end end)(); ",
        ff = dc_fn, cdecls = const_decls.join(" "), params = params_str, fsm = fsm,
    );

    // 状态表字段初始化顺序同样洗牌
    let mut ds_inits = vec![
        format!("{fn_}={c}.{lld}", fn_ = ds_n, c = "chunk", lld = pf_lld),
        format!("{ch}=({bx}({kon},{c}.{lld})*{chm}+{chk0})%{dcm32}",
            ch = ds_ch, bx = fn_bxor2, kon = n_kon, c = "chunk", lld = pf_lld, chm = chm_e, chk0 = chk0_e,
            dcm32 = crate::VM::VM_Backend::Generator_kdf::kdf_m32(rng)),
        format!("{m1}={mk1}", m1 = ds_m1, mk1 = n_mk1),
        format!("{m2}={mk2}", m2 = ds_m2, mk2 = n_mk2),
        format!("{m3}={mk3}", m3 = ds_m3, mk3 = n_mk3),
    ];
    rng.shuffle(&mut ds_inits);

    let init_dc_stmt = format!(
        "local {ndc}={{}}; local {ds}={{{inits}}}; local {fill}={fn_}({bind}); \
         setmetatable({ndc},{{__index=function({tt},{kk}) while {ds}.{dsn}<{kk} do {fill}() end return rawget({tt},{kk}) end}}); {vm}[{kdc}]={ndc}; ",
        ndc = n_dc, ds = dc_ds, inits = ds_inits.join(","),
        fill = dc_fill, fn_ = dc_fn, bind = bind_args,
        tt = rng.name(), kk = rng.name(), dsn = ds_n, vm = var_vm, kdc = k_dc,
    );
    (factory_prefix, init_dc_stmt)
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

/// 把明文按密钥异或后写成 Lua 的 `\ddd` 十进制转义字符串字面量。
/// 全三位定宽，所以后面跟数字也不会被读成别的转义。
/// 字符串加密（探测串与守卫池共用同一套）：
/// ```text
/// c[i] = ((p[i] + k1) % 256) XOR ((k0 * i + k1) % 256)      i 从 1 开始计
/// ```
/// 解密反过来两步走：先按该位置的密钥异或，再减 k1。
/// 这里刻意不用 ChaCha 之类：只有两个字节的密钥，但密钥**随下标变化**，
/// 于是「密文 − 明文」不再是一个常量，拿两条调用比对也看不出规律。
pub fn mix_encrypt(plain: &[u8], k0: u32, k1: u32) -> Vec<u8> {
    plain
        .iter()
        .enumerate()
        .map(|(idx, &b)| {
            let i = (idx + 1) as u32;
            (((((b as u32) + k1) % 256) ^ ((k0 * i + k1) % 256)) & 0xFF) as u8
        })
        .collect()
}

/// 把加密结果写成 Lua 的定宽八进制转义字面量（`\ddd` 三位，解码端不用猜宽度）。
/// 形态⑫：字符串混合转义打碎——可打印安全字符随机原样/\\ddd 混拼，
/// 其余一律 \\ddd（恒 3 位定宽，后跟数字字符不粘连）。
pub fn lua_mixed(bytes: &[u8]) -> String {
    use rand::Rng;
    let mut r = rand::thread_rng();
    let mut out = String::new();
    for &c in bytes {
        let printable = (0x20..0x7F).contains(&c) && c != b'"' && c != b'\\';
        if printable && r.gen_range(0..2) == 0 {
            out.push(c as char);
        } else {
            out.push_str(&format!("\\{:03}", c));
        }
    }
    out
}

pub fn mix_lit(plain: &str, k0: u32, k1: u32) -> String {
    format!("\"{}\"", lua_mixed(&mix_encrypt(plain.as_bytes(), k0, k1)))
}

/// 取一组 16 位密钥（k0 恒非 0，否则退化成单字节密钥），
/// 并保证密文里不出现 `\000`：Lua 装得下 NUL，但没必要给词法器找麻烦。
pub fn mix_key(plain: &str, rng: &mut GenRng) -> (u32, u32) {
    loop {
        let k0 = rng.range(1, 256) as u32;
        let k1 = rng.range(1, 256) as u32;
        if mix_encrypt(plain.as_bytes(), k0, k1).iter().all(|&c| c != 0) {
            return (k0, k1);
        }
    }
}

/// ── 自定义流加密（独立于池）──
/// 用途：把产物里还剩的明文字符串（类型名、元方法名、模式串等）就地加密。
/// 与池的区别：不做「明文 → 哈希键」的查找（那是指纹）；这里是
/// **密文与密钥一起存进一张随机键表**，调用点只出现 `T[dk](T[a],T[b])` ——
/// 解码器本身匿名挂在表里（`[dk]=function(s,k)…end`），产物里没有解码器的名字。
/// 密码本体与探测块/池同一族（位置相关双字节混合，纯算术 XOR，不用位库）：
///   c[i] = ((p[i] + k1) % 256) XOR ((k0*i + k1) % 256)
/// 「没法一下算出来」靠的是密钥随下标走；也刻意保持简单，不堆轮数。
/// 解码器函数体（`function(s,k) … end`，不含 local 前缀——方便匿名挂进表）。
pub fn stream_dec_body() -> String {
    "function(s,k) local o,i='',0; local n=#s; local k1=k%256; local k0=(k-k1)/256; while i<n do i=i+1; local a=(k0*i+k1)%256; local b=string.byte(s,i); local r,p=0,1; for w=1,8 do local x,y=a%2,b%2; if x~=y then r=r+p end; a=(a-x)/2; b=(b-y)/2; p=p*2 end; o=o..string.char((r-k1)%256) end; return o end".to_string()
}

/// ── ⑤ 池键哈希的参数：逐产物随机 ──
/// 写死的 djb2（起手 5381、乘 33）是一眼可辨的已知算法指纹：产物里出现
/// `h=5381` 就等于告诉逆向方池子按 djb2 建键。换成同族的随机实例
/// `h = (h*乘数 + 字节 + 增量) mod 2^32`：乘数取奇数、`h*乘数 < 2^48`，
/// double 里是精确整数（Lua 5.1 / Luau / Roblox 行为一致）。
/// 参数经线程局部传递，免得测试并行跑多个产物时互相串味。
#[derive(Clone, Copy)]
pub struct HashParams {
    pub mult: u32,
    pub add: u32,
    pub seed: u32,
}

thread_local! {
    static HASH_PARAMS: std::cell::Cell<HashParams> =
        const { std::cell::Cell::new(HashParams { mult: 33, add: 0, seed: 5381 }) };
}

pub fn set_hash_params(p: HashParams) {
    HASH_PARAMS.with(|h| h.set(p));
}

pub fn hash_params() -> HashParams {
    HASH_PARAMS.with(|h| h.get())
}

/// 池键哈希。Rust 侧与 Lua 侧必须完全一致：Lua 里算的是
/// `h=(h*乘数+byte+增量)%4294967296`，参数见 [`HashParams`]（逐产物随机）。
pub fn poly_hash(s: &str) -> u32 {
    let p = hash_params();
    let mut h: u64 = p.seed as u64;
    for b in s.bytes() {
        h = (h * p.mult as u64 + b as u64 + p.add as u64) % 4294967296;
    }
    h as u32
}

/// 常量算术混淆：同一常量逐次换形态（原值 / (v-a)+a / (v+b)-b），
/// 让解码/扫描公式不以干净常量清单出现。值域 <2^33，double 精确，
/// 5.1 与 Luau 行为一致。

/// 随机取一对可用混合密钥（复用 mix_key：k0 非 0 且密文无 \000）。
pub fn stream_key(plain: &str, rng: &mut GenRng) -> (u32, u32) {
    mix_key(plain, rng)
}

/// 流加密键表：一个作用域一张。`call` 注册（密文条目 + 密钥条目）并返回
/// `T[dk](T[a],T[b])` 形态的调用表达式；`emit` 渲染整张表
/// （解码器匿名占一个随机键，条目顺序洗牌）。
pub struct StreamTable {
    pub name: String,
    entries: Vec<(u32, String)>,
    used: std::collections::HashSet<u32>,
    dec_key: u32,
}

impl StreamTable {
    pub fn new(name: String) -> Self {
        let mut used = std::collections::HashSet::new();
        let dec_key = Self::fresh_key(&mut used);
        StreamTable { name, entries: Vec::new(), used, dec_key }
    }

    fn fresh_key(used: &mut std::collections::HashSet<u32>) -> u32 {
        let mut r = rand::thread_rng();
        loop {
            let k = r.gen_range(0x1000_0000u64..0x7FFF_FFFF) as u32;
            if used.insert(k) {
                return k;
            }
        }
    }

    /// 注册一个调用点：密文与 16 位混合密钥各自占一个随机表键。
    /// 返回的调用表达式在三种等价拼写里轮换，避免同形连排。
    pub fn call(&mut self, plain: &str, k0: u32, k1: u32) -> String {
        let ck = Self::fresh_key(&mut self.used);
        let kk = Self::fresh_key(&mut self.used);
        self.entries.push((ck, mix_lit(plain, k0, k1)));
        self.entries.push((kk, format!("0X{:X}", k0 * 256 + k1)));
        let t = &self.name;
        let dk = self.dec_key;
        match self.entries.len() % 3 {
            0 => format!("{t}[{dk}]({t}[{ck}],{t}[{kk}])"),
            1 => format!("({t}[{dk}])({t}[{ck}],{t}[{kk}])"),
            _ => format!("{t}[{dk}]({t}[{ck}],({t}[{kk}]))"),
        }
    }

    /// 渲染整张表：`local T={[dk]=function(s,k)…end,[k]="…",[k]=0X…,…};`
    /// 条目顺序洗牌——构造器里密文/密钥/解码器混在一起，没有配对关系可看。
    pub fn emit(&self) -> String {
        let mut r = rand::thread_rng();
        let mut items: Vec<String> = Vec::new();
        items.push(format!("[{}]={}", self.dec_key, stream_dec_body()));
        for (k, v) in &self.entries {
            items.push(format!("[{}]={}", k, v));
        }
        for i in (1..items.len()).rev() {
            let j = r.gen_range(0..=i);
            items.swap(i, j);
        }
        format!("local {}={{{}}}; ", self.name, items.join(","))
    }
}

// ── ㉒ 控制流范畴消除：数值游标步行器 + 焊接缓存 ─────────────────────
//
// ① 数值游标+守卫的随机游走（打 CFG 重建）：把顺序批量工作改写为
//    `while true do if G==K then …` 的游走——每条出边 G=<混淆常量表达式>，
//    去平坦化退化成符号执行；全程游走 ≤10 次。不是循环，是扁平化游标机。
// ② 焊接构造（打人读）：一个 if 同时干「惰性缓存 + 大随机数当键 + 校验恒等式」
//    三件事——`if not X then X=f(…) end` 形态第二次执行在逻辑上无分支，
//    「这个分支会不会被走到」在文本上无法判定。长时状态只剩槽号，
//    新增局部名压到单字母并故意重复遮蔽（ShadowNames）。

/// 单字母名字池：故意循环复用同一小撮字母——兄弟作用域里反复出现同一个字母
/// （这里 E 是载荷槽、隔一段又变成寄存器），破坏「按作用域栈读代码」的习惯。
/// 同一作用域里允许重复声明遮蔽（Lua 允许 `local e; … local e;`）。
pub(super) struct ShadowNames { pool: Vec<char>, i: usize }
impl ShadowNames {
    pub fn new(off: usize) -> Self {
        let pool: Vec<char> = "emkqjwcgzh".chars().collect();
        Self { pool, i: off }
    }
    pub fn next(&mut self) -> String {
        let c = self.pool[self.i % self.pool.len()];
        self.i += 1;
        c.to_string()
    }
}

/// 静态分段游标步行器：原 `for i=lo,hi do <unit> end` → 游标机（≤states+1 次游走）。
/// `unit(idx)` 产出以 `idx` 为索引名的单次迭代体。keys=None（P 表尚不在作用域）
/// 时状态常数退化为混合进制字面量；否则走 obfuscate_num depth=1 常量表达式。
pub(super) fn cursor_walk_static(
    rng: &mut GenRng, keys: Option<&CipherKeys>, off: usize,
    lo: i64, hi: i64, states: usize,
    fix_iv: Option<&str>,
    unit: &dyn Fn(&str) -> String,
) -> String {
    let mut sn = ShadowNames::new(off);
    let g = sn.next();
    let mut ks: Vec<i64> = Vec::new();
    while ks.len() < states + 1 {
        let v = rng.range64(0x0200_0000, 0x7FFF_FFFF);
        if !ks.contains(&v) { ks.push(v); }
    }
    let n = (hi - lo + 1).max(1) as usize;
    let states = states.min(n).max(1);
    let per = (n + states - 1) / states;
    let mut out = format!("local {}={}; while true do ", g, match keys { Some(kk) => rng.obfuscate_num(ks[0], 1, kk), None => rng.format_num(ks[0]) });
    let mut done = 0usize; let mut sidx = 0usize; let mut cur = lo;
    while done < n {
        let take = per.min(n - done);
        let seg_hi = cur + take as i64 - 1;
        let iv = fix_iv.map(|f| f.to_string()).unwrap_or_else(|| sn.next());
        let batch = format!("local {}={}; while {}<={} do {} {}={}+1 end; ",
            iv, cur, iv, seg_hi, unit(&iv), iv, iv);
        let cond = match keys { Some(kk) => rng.obfuscate_num(ks[sidx], 1, kk), None => rng.format_num(ks[sidx]) };
        let nxt = match keys { Some(kk) => rng.obfuscate_num(ks[sidx + 1], 1, kk), None => rng.format_num(ks[sidx + 1]) };
        let body = if rng.range(0, 10) < 4 {
            format!("repeat {}{}={}; break until false; ", batch, g, nxt)
        } else {
            format!("{}{}={}; ", batch, g, nxt)
        };
        let kw = if sidx == 0 { "if" } else { "elseif" };
        out.push_str(&format!("{} {}=={} then {} ", kw, g, cond, body));
        done += take; cur = seg_hi + 1; sidx += 1;
    }
    out.push_str("else break end end; ");
    out
}

/// 动态分段游标步行器：上界是运行期表达式 `n_expr`（如 chunk 数、寄存器键数）。
/// 状态循环复用（K0→K1→…→K0），每轮推进 ≤batch 项，游标耗尽走出口态。
/// 总游走 ≈ ceil(n/batch)+1。
pub(super) fn cursor_walk_dyn(
    rng: &mut GenRng, keys: Option<&CipherKeys>, off: usize,
    n_expr: &str, batch: i64, states: usize,
    unit: &dyn Fn(&str) -> String,
) -> String {
    let mut sn = ShadowNames::new(off);
    let g = sn.next(); let idx = sn.next();
    let mut ks: Vec<i64> = Vec::new();
    while ks.len() < states + 1 {
        let v = rng.range64(0x0200_0000, 0x7FFF_FFFF);
        if !ks.contains(&v) { ks.push(v); }
    }
    let obf = |rr: &mut GenRng, v: i64| -> String {
        match keys { Some(kk) => rr.obfuscate_num(v, 1, kk), None => rr.format_num(v) }
    };
    let mut out = format!("local {}={}; local {}=1; while true do ", g, obf(rng, ks[0]), idx);
    for s in 0..states {
        let cond = obf(rng, ks[s]);
        let nxt = obf(rng, ks[(s + 1) % states]);
        let exit_k = obf(rng, ks[states]);
        let e = sn.next();
        let body = format!(
            "local {}={}; if {}+{}-1<{} then {}={}+{}-1 end; while {}<={} do {} {}={}+1 end; if {}>{} then {}={} else {}={} end; ",
            e, n_expr, idx, batch, n_expr, e, idx, batch,
            idx, e, unit(&idx), idx, idx,
            idx, n_expr, g, exit_k, g, nxt);
        let kw = if s == 0 { "if" } else { "elseif" };
        let body = if rng.range(0, 10) < 4 { format!("repeat {}break until false; ", body) } else { body };
        out.push_str(&format!("{} {}=={} then {} ", kw, g, cond, body));
    }
    out.push_str("else break end end; ");
    out
}

// ── ㉓ 统一流加密（UniStream）：4/5/6 三线并一流 ──────────────────────
// 一条逐产物随机的 LCG 密钥流扫过**全部**登记的明文：每个串占一段独立偏移，
// 密文 `c[g] = (p[g] + ks[g] + q0*g + q1) % 256`（g 为全流绝对位置，1 起计）——

// ㉓ UniStream 已拆至 Generator_unistream.rs（80 KB 规则）；再导出保路径不变。
pub use crate::VM::VM_Backend::Generator_unistream::UniStream;
