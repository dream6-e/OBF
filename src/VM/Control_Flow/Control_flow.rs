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
    // ㉔ 状态号等差数列（首项+公差）与四形态转移基建（状态表/惰性槽/委托）
    pub st_tbl: String, pub sl_tbl: String, pub dv_a: String, pub dv_b: String,
    pub st_first: i64, pub st_diff: i64,
}

pub struct ControlFlowBuilder;

impl ControlFlowBuilder {
    fn format_num(val: i64, rng: &mut GenRng) -> String {
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

    /// ㉔ 状态转移四形态：①常量算式 / ②状态表引用 / ③惰性槽 / ④委托调用返回值。
    /// 返回「把 var 写成 target」的完整语句（含尾分号）。
    fn transition_assign(var: &str, target: i64, keys: &CipherKeys, rng: &mut GenRng) -> String {
        let v = Self::obfuscate_num_depth(target, 1, keys, rng);
        match rng.range(0, 4) {
            0 => format!("{}={};", var, v),
            1 => {
                let k = Self::obfuscate_num_depth(rng.range(0x100, 0xFFFFF) as i64, 1, keys, rng);
                format!("{}[{}]={};{}={}[{}];", keys.st_tbl, k, v, var, keys.st_tbl, k)
            }
            2 => {
                let k = Self::obfuscate_num_depth(rng.range(0x100, 0xFFFFF) as i64, 1, keys, rng);
                format!("if not {}[{}] then {}[{}]={} end;{}={}[{}];",
                    keys.sl_tbl, k, keys.sl_tbl, k, v, var, keys.sl_tbl, k)
            }
            _ => {
                let j = Self::obfuscate_num_depth(rng.range(0x100, 0xFFFF) as i64, 1, keys, rng);
                let dv = if rng.range(0, 2) == 0 { &keys.dv_a } else { &keys.dv_b };
                format!("{}={}({},{});", var, dv, j, v)
            }
        }
    }

    /// ㉕ 无键数值混淆：把任意数值发成恒等算式（±差和/自抵消/倍差/乘除恒等），
    /// 产物里不再出现裸数字；供打包器解码脚本等没有 CipherKeys 的作用域使用。
    /// 数值域约束：所有中间量 <0xFFFFFE（压缩管线截断 >24bit 十六进制字面量）。
    pub fn obf_num(v: i64, rng: &mut GenRng) -> String {
        let hex = |x: i64, rng: &mut GenRng| -> String {
            if rng.range(0, 2) == 0 { format!("0X{:X}", x) } else { x.to_string() }
        };
        let cap = (0xF0000i64).min(0xFFFFFE - v.abs());
        let r = rng.range64(0x1000, cap.max(0x1002));
        let core = match rng.range(0, 4) {
            0 => format!("({}-{})", hex(v + r, rng), hex(r, rng)),
            1 => format!("(-{}+{})", hex(r, rng), hex(r + v, rng)),
            2 => format!("(({})-({}))+{}", hex(r, rng), hex(r, rng), hex(v, rng)),
            _ => {
                let q = rng.range64(3, 25);
                format!("(({})/({}))", hex(v * q, rng), hex(q, rng))
            }
        };
        if rng.range(0, 2) == 0 { core } else {
            let r2 = rng.range64(0x100, 0xF000);
            format!("({}+({}-{}))", core, hex(r2, rng), hex(r2, rng))
        }
    }

    /// ㉕ 运行时耦合的初始化状态机：把一串顺序执行的语句打散进 while-状态机，
    /// 但状态号在产物文本里零出现——等差数列（随机首项+随机奇数公差）只在运行时
    /// 由填充循环算进状态表；比较/转移/初值全部经状态表引用、惰性槽、恒等委托
    /// 三种间接形态流动。单步分析者必须先执行填充循环才能知道任何状态值。
    /// 返回 (局部声明+基建, 机器本体)；loop_kw 保留各调用点原有的循环头写法。
    pub fn build_router_machine(
        stmts: &[String], loop_kw: &str, st_var: &str, rng: &mut GenRng,
    ) -> (String, String) {
        let n = stmts.len();
        let (ct, sl, dv, ci, cc, dd) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let first = rng.range64(0x3000, 0x5FFF);
        let diff = rng.range64(7, 101) | 1;
        let val = |k: usize| first + k as i64 * diff;
        let mut perm: Vec<usize> = (0..=n).collect();
        for i in (1..perm.len()).rev() { let j = rng.range(0, i + 1); perm.swap(i, j); }
        let idx_of = |k: usize, rng: &mut GenRng| Self::obf_num((perm[k] + 1) as i64, rng);
        let cmp = |k: usize, rng: &mut GenRng| -> String {
            if rng.range(0, 3) == 0 { format!("{}({},{}[{}])", dv, Self::obf_num(rng.range64(0x100, 0xFFFF), rng), ct, idx_of(k, rng)) }
            else { format!("{}[{}]", ct, idx_of(k, rng)) }
        };
        let trans = |k: usize, rng: &mut GenRng| -> String {
            match rng.range(0, 3) {
                0 => format!("{}[{}]", ct, idx_of(k, rng)),
                1 => {
                    let sk = Self::obf_num(rng.range64(0x100, 0xFFFFF), rng);
                    format!("(function() if not {}[{}] then {}[{}]={}[{}] end return {}[{}] end)()",
                        sl, sk, sl, sk, ct, idx_of(k, rng), sl, sk)
                }
                _ => format!("{}({},{}[{}])", dv, Self::obf_num(rng.range64(0x100, 0xFFFF), rng), ct, idx_of(k, rng)),
            }
        };
        let mut decl = format!("local {}={{}};local {}={{}};local {}=function(w,u) local z=w%0X2 return u+(z-z) end;", ct, sl, dv);
        decl.push_str(&format!("local {}={};local {}={};for {}=1,{} do {}[{}]={};{}={}+{} end;",
            cc, Self::obf_num(first, rng), dd, Self::obf_num(diff, rng),
            ci, Self::obf_num((n + 1) as i64, rng), ct, ci, cc, cc, cc, dd));
        let mut body = format!("{}={};", st_var, trans(0, rng));
        body.push_str(loop_kw);
        for i in 0..n {
            let kw = if i == 0 { format!("if {}=={} then ", st_var, cmp(i, rng)) }
                     else { format!("elseif {}=={} then ", st_var, cmp(i, rng)) };
            body.push_str(&format!("{}{}{}={};", kw, stmts[i], st_var, trans(i + 1, rng)));
        }
        body.push_str("else break end end;");
        (decl, body)
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
        // ── 谓词池（多样化 ⑤）：四族不透明谓词，按节点随机抽取——
        // 全部恒等于「(var) <op> val」：
        //   A 加法式（原版）：(a<=a and a or j)+k <op> v+k
        //   B 双差式：a-(a and a or j)+k2 <op> v+k2（sel 恒真→减自身=0，平移抵消）
        //   C 按位族：BA(a,0XFFFF) 截低 16 位（路由值 0..27 恒等）
        //   D 交换式：(j>a and j or (a<=a and a)) 恒取 a
        let fam = rng.range(0, 4);
        let key = rng.range(0x10, 0xFFF) as i64;
        let mutated_val = val.wrapping_add(key);
        let jn = Self::format_num(rng.range(0, 0xFFFF) as i64, rng);
        let g1 = Self::format_num(keys.grp1 as i64, rng);
        let kadd = Self::format_num(keys.key_add as i64, rng);
        let kba = Self::format_num(keys.key_ba as i64, rng);
        let add_call = format!("{}[{}][{}](", keys.tbl_p, g1, kadd);
        match fam {
            0 => format!("{}[{}][{}]({}<={} and {} or {},{}){}{}",
                keys.tbl_p, g1, kadd,
                var_name, var_name, var_name, jn,
                Self::format_num(key, rng), comp_op, Self::format_num(mutated_val, rng)),
            1 => {
                let k2 = rng.range(0x10, 0xFFF) as i64;
                // 双差式：add(V,k2)-(k2 and k2 or 0) ≡ V（add 两参数齐全）
                format!("{}{},{})-({} and {} or {}){}{}",
                    add_call,
                    var_name, Self::format_num(k2, rng),
                    Self::format_num(k2, rng), Self::format_num(k2, rng), Self::format_num(0, rng),
                    comp_op, Self::format_num(val, rng))
            }
            2 => {
                // 按位族：band(V,低16位全1掩码)+key ≡ V+key（掩码随 build 随机化避免定值指纹）
                let ba_mask = 0xFFFF + (rng.range(0, 0x10) as i64) * 0x10000;
                format!("{}[{}][{}]({}[{}][{}]({}<={} and {} or {},{}),{}){}{}",
                    keys.tbl_p, g1, kadd,
                    keys.tbl_p, g1, kba,
                    var_name, var_name, var_name, jn,
                    Self::format_num(ba_mask, rng), Self::format_num(key, rng),
                    comp_op, Self::format_num(mutated_val, rng))
            }
            _ => format!("{}({}<{} and ({}+{}-{}) or ({}<={} and {} or {})),{}){}{}",
                add_call,
                jn, var_name,
                var_name, Self::format_num(key, rng), Self::format_num(key, rng),
                var_name, var_name, var_name, jn,
                Self::format_num(key, rng),
                comp_op, Self::format_num(mutated_val, rng))
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
        let mut keys = CipherKeys {
            grp1: idx[0],
            grp2: idx[1],
            key_bx: idx[2],
            key_ba: idx[3],
            key_add: idx[4],
            key_bs: idx[5],
            key_ba2: idx[6],
            key_bs2: idx[7],
            tbl_p: rng.name(),
            st_tbl: rng.name(), sl_tbl: rng.name(), dv_a: rng.name(), dv_b: rng.name(),
            st_first: 0, st_diff: 0,
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

        out.push_str(&format!("local qT4a={{}};for i=0,15 do qT4a[i]={{}};for j=0,15 do local r,p=0,1;local x,y=i,j;for k=1,4 do local rx,ry=x%2,y%2;if rx~=ry then r=r+p end;x=(x-rx)/2;y=(y-ry)/2;p=p+p end;qT4a[i][j]=r end end;local qT8a={{}};for i=0,255 do qT8a[i]={{}};end;for i=0,255 do local qIa=qT8a[i];local qHa=(i-i%16)/16;for j=0,255 do qIa[j]=qT4a[i%16][j%16]+qT4a[qHa][(j-j%16)/16]*16 end end; local {}={};", fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b) local r,p=0,1;for k=1,4 do local x,y=a%256,b%256;r=r+qT8a[x][y]*p;a=(a-x)/256;b=(b-y)/256;p=p*256 end;return r end"));
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
        // ㉔ 四形态转移基建：状态表（写读对）/惰性槽（首访填充）/委托（恒等扰动后返回）
        out.push_str(&format!("local {st},{sl}={{}},{{}}; local {da}=function({w},{u}) local {z}={w}%0X2 return {u}+({z}-{z}) end; local {db}=function({w},{u}) local {z}=({w}-{w})%0X3 return {u}*0X1+{z} end; ",
            st = keys.st_tbl, sl = keys.sl_tbl, da = keys.dv_a, db = keys.dv_b,
            w = rng.name(), u = rng.name(), z = rng.name()));
        
        // ㉔ 状态号 = 等差数列 + 随机首项：fetch/dispatch/中间态/叶子路由态全是
        // 数列成员（first + k*diff），静态提不出「随机小数状态」旧画像。
        let st_first = rng.range(0x1000, 0x2FFF) as i64;
        let st_diff = (rng.range(7, 101) as i64) | 1;
        keys.st_first = st_first; keys.st_diff = st_diff;
        let fetch_state = st_first + st_diff;
        let init_val1 = rng.range(10, 1000) as i64;
        let init_val2 = rng.range(1, 1000) as i64;
        
        out.push_str(&format!("{},{},{}={},{},{};", 
            s_state, t_shadow, d_junk, 
            Self::format_num(init_val1, rng), 
            Self::format_num(0, rng), 
            Self::format_num(init_val2, rng)
        ));
        out.push_str(&Self::transition_assign(&var_t, fetch_state, &keys, rng));

        // ── 骨架多样化 ①：恒真壳池（解析器无法用单一「while 恒真」指纹定位主循环）──
        // 三族壳运行语义相同（无限循环），形态不同：
        //   A while not(nil and false)（原版保留）；B repeat...until (nil and false)；
        //   C while {} do ... if (nil and false) then break end end（体首 break 哨兵）
        let loop_kind = rng.range(0, 3);
        match loop_kind {
            0 => { out.push_str("while not(nil and false) do "); }
            1 => { out.push_str("repeat "); }
            _ => { out.push_str("while {} do "); }
        }

        // ── 骨架多样化 ②：骨架 2~4 态（原版线性二态是其中一种）──
        // fetch(取指) → dispatch(派发) 是功能两态；中间插 0~2 个功能空转态：
        //   check 态（d_junk 一致性自检后落到 dispatch）/ shuffle 态（打乱后落 dispatch）。
        // 循环走「态图」：t=当前态 → 各态分支 → 无条件写下一态，解析器提不出线性两态模板。
        let extra_states = rng.range(0, 2); // 0..=2 个中间态
        let mut mid_states: Vec<i64> = Vec::new();
        let mut mid_kinds: Vec<u8> = Vec::new(); // 0=check 1=shuffle
        for mi_k in 0..extra_states {
            mid_states.push(st_first + (3 + mi_k as i64) * st_diff);
            mid_kinds.push(if rng.range(0, 2) == 0 { 0 } else { 1 });
        }
        // 随机中间态顺序（各自回到 dispatch）
        let mut mid_order: Vec<usize> = (0..extra_states).collect();
        rng.shuffle(&mut mid_order);

        let dispatch_entry: String;
        if extra_states == 0 {
            out.push_str(&format!("if {}=={} then ", var_t, Self::obfuscate_num_depth(fetch_state, 1, &keys, rng)));
            dispatch_entry = String::new();
        } else {
            // fetch 态取指后落入第一个中间态（而非直接 dispatch）
            out.push_str(&format!("if {}=={} then ", var_t, Self::obfuscate_num_depth(fetch_state, 1, &keys, rng)));
            dispatch_entry = String::new();
        }
        out.push_str(&format!("if {}>#{} then return end;", var_pc, var_insts));
        out.push_str(&format!("{},{}={}[{}],{}+{};", var_inst, var_pc, var_insts, var_pc, var_pc, Self::obfuscate_num_depth(1, 1, &keys, rng)));
        
        let q_route_expr = format!("{}[{}][{}]({}[{}][{}]({}[{}],{}),{})", 
            keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_ba as i64, rng),
            keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_add as i64, rng),
            var_inst, Self::format_num(1, rng), s_state,
            Self::format_num(num_routes, rng)
        );
        out.push_str(&format!("{}={};", q_route, q_route_expr));
        // ── 树形多样化 ③（放弃的方案留档）：route→handler 序号置换映射会改语义
        //（递归树的区间比较对「路由序」敏感，置换后 tree_entries 区间不再对应正确
        // handler——实测 compare two nil）。多样化由三叉+不等宽切分承担。
        let dispatch_state = st_first + 2 * st_diff;
        if extra_states == 0 {
            out.push_str(&Self::transition_assign(&var_t, dispatch_state, &keys, rng));
        } else {
            // 态图：fetch → 第一个中间态
            let first_mid = mid_states[mid_order[0] as usize];
            out.push_str(&Self::transition_assign(&var_t, first_mid, &keys, rng));
        }
        // 中间态分支（check/shuffle 空转后落 dispatch；功能零影响）
        for &mi in mid_order.iter() {
            let st_m = mid_states[mi as usize];
            out.push_str(&format!("elseif {}=={} then ", var_t, Self::obfuscate_num_depth(st_m, 1, &keys, rng)));
            match mid_kinds[mi as usize] {
                0 => {
                    // check 态：d_junk 一致性空转自检（与原版 junk 判定同族形态）
                    let fake_c = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                    out.push_str(&format!("if {}=={} then {}={}+{}; end ", d_junk, fake_c, d_junk, d_junk, Self::format_num(1, rng)));
                }
                _ => {
                    // shuffle 态：无副作用交换（对临时值双写同值）
                    let (sa, sb) = (Self::format_num(rng.range(0x10, 0xFF) as i64, rng), Self::format_num(rng.range(0x10, 0xFF) as i64, rng));
                    out.push_str(&format!("{}={};{}={}; ", f_tmp, sa, f_tmp, sb));
                }
            }
            out.push_str(&Self::transition_assign(&var_t, dispatch_state, &keys, rng));
        }
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
        let tf_a = Self::transition_assign(&var_t, fetch_state, &keys, rng);
        let tf_b = Self::transition_assign(&var_t, fetch_state, &keys, rng);
        out.push_str(&format!("if {} then if {} then {},{}=false,false;{}else return(unpack or table.unpack)({},{},{})end else {}end ", 
            var_r_flg, var_tail_flg, var_tail_flg, var_r_flg, tf_a, var_r_vals, Self::format_num(1, rng), var_r_len, tf_b
        ));

        out.push_str("end "); // 闭合骨架态图 if
        // 壳闭合（与开头三族壳一一对应；repeat 由 until 自闭，勿多发 end）
        match loop_kind {
            0 => { out.push_str("end "); } // while not(...) 壳
            1 => { out.push_str("until (nil and false) "); } // repeat 壳
            _ => { out.push_str("if (nil and false) then break end end "); } // 哨兵 if + while {} 壳
        }
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
        // ㉔ 路由态同为数列成员；两条转移按四形态随机
        let next_s = keys.st_first + rng.range(1, 48) as i64 * keys.st_diff;
        let s_state_trans = Self::transition_assign(s_state, next_s, keys, rng);
        let state_transition = Self::transition_assign(var_t, 0, keys, rng);
        let leaf_type = rng.range(0, 5);
        let mut node = String::new();
        let idx_1 = Self::format_num(1, rng);

        match leaf_type {
            0 => {
                node.push_str(&format!("{}={}+{};{}={}[{}[{}]+{}];{}({});{}{}", 
                    d_junk, d_junk, Self::format_num(1, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state_trans, state_transition));
            }
            1 => {
                node.push_str(&format!("repeat {}={}[{}[{}]+{}];{}({});{}{}break until false;", 
                    f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state_trans, state_transition));
            }
            2 => {
                node.push_str(&format!("for _={},{} do {}={}[{}[{}]+{}];{}({});end {}{}", 
                    Self::format_num(1, rng), Self::format_num(1, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state_trans, state_transition));
            }
            3 => {
                node.push_str(&format!("if {}~={} then {}={}[{}[{}]+{}];{}({});{}{}end ", 
                    d_junk, Self::format_num(4294967295i64, rng), f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state_trans, state_transition));
            }
            _ => {
                node.push_str(&format!("{}={}[{}[{}]+{}];{}({});{}{}", 
                    f_tmp, var_handlers, var_inst, idx_1, var_tamper, f_tmp, var_inst, s_state_trans, state_transition));
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

        let span = max - min + 1;
        // ── 树形多样化 ④：span≥6 时约 1/3 概率用三叉节点（两次比较走三路）；
        // 二叉时切分点随机偏移（不等宽），不再是恒等 mid
        if span >= 6 && rng.range(0, 3) == 0 {
            let cut1 = min + 1 + rng.range(0, (span - 2) / 2);
            let cut2 = cut1 + 1 + rng.range(0, max - cut1 - 1);
            let c1 = Self::generate_opaque_predicate(cut1 as i64, q_route, "<=", keys, rng);
            let c2 = Self::generate_opaque_predicate(cut2 as i64, q_route, "<=", keys, rng);
            let mut branch = format!("if {} then {} elseif {} then {} else {} end ",
                c1,
                Self::generate_recursive_tree(min, cut1, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng),
                c2,
                Self::generate_recursive_tree(cut1 + 1, cut2, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng),
                Self::generate_recursive_tree(cut2 + 1, max, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, fetch_state, junk_limit, keys, rng));
            return branch;
        }
        let mid = if span >= 4 && rng.range(0, 2) == 0 {
            // 不等宽切分：mid 在 [min+1, max-1] 内随机偏移
            min + 1 + rng.range(0, span - 2)
        } else {
            (min + max) / 2
        };
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