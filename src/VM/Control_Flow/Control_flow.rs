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
    // ㉖ 运行时状态值表：状态空间（首项/公差）由运行时读数推导后填进此表
    pub sv_tbl: String,
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
        Self::transition_assign_expr(var, &v, keys, rng)
    }

    /// ㉖ 运行时状态值表槽引用（25% 概率再包一层恒等委托）。
    /// 状态数值本身不落文本——分析者只能看到「表[混淆序号]」。
    fn sv_ref(keys: &CipherKeys, slot: usize, rng: &mut GenRng) -> String {
        let r = format!("{}[{}]", keys.sv_tbl, Self::obf_num(slot as i64, rng));
        if rng.range(0, 4) == 0 {
            let dv = if rng.range(0, 2) == 0 { &keys.dv_a } else { &keys.dv_b };
            format!("{}({}, {})", dv, Self::obf_num(rng.range64(0x100, 0xFFFF), rng), r)
        } else {
            r
        }
    }

    /// ㉖ 转移四形态的表达式目标版：target 可以是运行时状态表槽引用等任意表达式
    /// （状态值依赖运行时数据时使用；文本里不再出现该状态的数值）。
    fn transition_assign_expr(var: &str, target_expr: &str, keys: &CipherKeys, rng: &mut GenRng) -> String {
        match rng.range(0, 4) {
            0 => format!("{}={};", var, target_expr),
            1 => {
                let k = Self::obfuscate_num_depth(rng.range(0x100, 0xFFFFF) as i64, 1, keys, rng);
                format!("{}[{}]={};{}={}[{}];", keys.st_tbl, k, target_expr, var, keys.st_tbl, k)
            }
            2 => {
                let k = Self::obfuscate_num_depth(rng.range(0x100, 0xFFFFF) as i64, 1, keys, rng);
                format!("if not {}[{}] then {}[{}]={} end;{}={}[{}];",
                    keys.sl_tbl, k, keys.sl_tbl, k, target_expr, var, keys.sl_tbl, k)
            }
            _ => {
                let j = Self::obfuscate_num_depth(rng.range(0x100, 0xFFFF) as i64, 1, keys, rng);
                let dv = if rng.range(0, 2) == 0 { &keys.dv_a } else { &keys.dv_b };
                format!("{}={}({},{});", var, dv, j, target_expr)
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
            // ㉚④：v==0 时差式/和式都退化成同字面量自抵消——改 x%x 恒零
            0 if v == 0 => format!("({}%{})", hex(r, rng), hex(r, rng)),
            1 if v == 0 => format!("({}%{})", hex(r, rng), hex(r, rng)),
            0 => format!("({}-{})", hex(v + r, rng), hex(r, rng)),
            1 => format!("(-{}+{})", hex(r, rng), hex(r + v, rng)),
            // ㉚④：旧形 ((r)-(r))+v 让 v 裸现——改乘法折叠：
            // v = q*d + rem，rem 藏进 +(f)-((f)-rem) 拆分（v 可为负/零，
            // div/rem_euclid 保证 rem≥0；f>rem 恒立）
            2 => {
                // ㉚④：rem==0 时 (f)-(f-0) 仍露同值对——强制 rem≠0
                let d = rng.range64(3, 0x100);
                let mut d = if v.rem_euclid(d) == 0 { rng.range64(3, 0x100) } else { d };
                for _ in 0..8 { if v.rem_euclid(d) != 0 { break; } d = rng.range64(3, 0x100); }
                let q = v.div_euclid(d);
                let rem = v.rem_euclid(d);
                let f = rng.range64(0x100, 0x8000);
                format!("((({}*{})+{})-({}-{}))", hex(q, rng), hex(d, rng), hex(f, rng), hex(f, rng), hex(rem, rng))
            }
            _ => {
                let q = rng.range64(3, 25);
                format!("(({})/({}))", hex(v * q, rng), hex(q, rng))
            }
        };
        if rng.range(0, 2) == 0 { core } else {
            // ㉚④：外层零项不再用 (r2-r2) 同字面量自抵消——改 x%x 恒零
            let r2 = rng.range64(0x100, 0xF000);
            format!("({}+({}%{}))", core, hex(r2, rng), hex(r2, rng))
        }
    }

    /// ㉕ 运行时耦合的初始化状态机：把一串顺序执行的语句打散进 while-状态机，
    /// 但状态号在产物文本里零出现——㉖ 起首项/公差也依赖运行时：
    /// 首项 = (seed_src % 0X10000)*k0 + k1、公差 = ((seed_src) % dm)*2 + db（恒奇），
    /// seed_src 由调用点给（如「#载荷 + 密钥首字节」），只在运行时可求值——
    /// 常量集合 ≠ 可达状态集合。比较/转移/初值仍经状态表/惰性槽/委托间接流动。
    /// 返回 (局部声明+基建, 机器本体)；loop_kw 保留各调用点原有的循环头写法。
    pub fn build_router_machine(
        stmts: &[String], loop_kw: &str, st_var: &str, seed_src: &str, rng: &mut GenRng,
    ) -> (String, String) {
        let n = stmts.len();
        let (ct, sl, dv, ci, cc, dd, sd) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let k0 = rng.range(2, 9);
        let k1 = rng.range64(0x100, 0xFFF);
        let dm = rng.range(19, 47);
        let db = rng.range(3, 50) | 1;
        let mut perm: Vec<usize> = (0..=n).collect();
        for i in (1..perm.len()).rev() { let j = rng.range(0, i + 1); perm.swap(i, j); }
        let idx_of = |k: usize, rng: &mut GenRng| Self::obf_num((perm[k] + 1) as i64, rng);
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
        // ㉙① 去裸数字：公差除数 dm / 加数 db / 填表循环下界 1 全部混淆算式化
        decl.push_str(&format!("local {}=({});local {}=(({})%0X10000)*{}+{};local {}=((({}))%{})*2+{};for {}={},{} do {}[{}]={};{}={}+{} end;",
            sd, seed_src,
            cc, sd, Self::obf_num(k0 as i64, rng), Self::obf_num(k1, rng),
            dd, sd, Self::obf_num(dm as i64, rng), Self::obf_num(db as i64, rng),
            ci, Self::obf_num(1, rng), Self::obf_num((n + 1) as i64, rng), ct, ci, cc, cc, cc, dd));
        // ㉙① 条件表化：废除「状态变量==值」的可读 if/elseif 等式链——每步语句
        // 变成加载期闭包，装进派发表，键 = 运行时状态表槽值（ct[混淆下标] 表达式
        // 直接作键），闭包定义顺序洗牌；运行时按状态值一次查表取闭包执行。
        // 静态文本里没有状态比较序列，动态单步也只能看到「查表→调用」。
        let hb = rng.name();
        let mut hdefs: Vec<String> = Vec::new();
        for i in 0..n {
            hdefs.push(format!("{}[{}[{}]]=function() {}{}={};end;",
                hb, ct, idx_of(i, rng), stmts[i], st_var, trans(i + 1, rng)));
        }
        rng.shuffle(&mut hdefs);
        decl.push_str(&format!("local {}={{}};{}", hb, hdefs.join("")));
        let gj = rng.name();
        let mut body = format!("{}={};", st_var, trans(0, rng));
        body.push_str(loop_kw);
        body.push_str(&format!("local {}={}[{}];if {} then {}() else break end end;", gj, hb, st_var, gj, gj));
        (decl, body)
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
            // ㉚④：D 族原「var+key-key」零填充是同值自抵消暴露形态——
            // 改纯 select 链（两支都恒取 var，无算术痕迹）
            _ => format!("{}({}<{} and {} or ({}<={} and {} or {})),{}){}{}",
                add_call,
                jn, var_name, var_name,
                var_name, var_name, var_name, jn,
                Self::format_num(key, rng),
                comp_op, Self::format_num(mutated_val, rng))
        }
    }

    /// ㉙① 状态比较间接化（热路径四形态）：①直等（少数保留）②双侧恒等委托
    /// ③双侧平移（+K 后比）④双侧低位掩码（band，值域 <2^20 时恒等）。
    /// 条件文本不再是裸的「t==表[槽]」单形态。
    fn state_cmp(var_t: &str, slot_ref: &str, keys: &CipherKeys, rng: &mut GenRng) -> String {
        match rng.range(0, 4) {
            0 => format!("{}=={}", var_t, slot_ref),
            1 => {
                let dv1 = if rng.range(0, 2) == 0 { &keys.dv_a } else { &keys.dv_b };
                let dv2 = if rng.range(0, 2) == 0 { &keys.dv_a } else { &keys.dv_b };
                format!("{}({}, {})=={}({}, {})",
                    dv1, Self::obfuscate_num_depth(rng.range(0x100, 0xFFFF) as i64, 1, keys, rng), var_t,
                    dv2, Self::obfuscate_num_depth(rng.range(0x100, 0xFFFF) as i64, 1, keys, rng), slot_ref)
            }
            2 => {
                let k = Self::obfuscate_num_depth(rng.range(0x100, 0xFFFF) as i64, 1, keys, rng);
                format!("{}[{}][{}]({},{})=={}[{}][{}]({},{})",
                    keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_add as i64, rng), var_t, k,
                    keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_add as i64, rng), slot_ref, k)
            }
            _ => {
                let mask = Self::format_num((1i64 << rng.range(20, 24)) - 1, rng);
                format!("{}[{}][{}]({},{})=={}[{}][{}]({},{})",
                    keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_ba as i64, rng), var_t, mask,
                    keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_ba as i64, rng), slot_ref, mask)
            }
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
        var_seed: &str,
        h_base: &str,
        h_stride: &str,
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
            sv_tbl: String::new(),
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
        // ㉗ 出口码序号：叶子逐个领取唯一出口槽（≤ 路由数28 + 垃圾叶11，带域 64..112 足够）
        let mut exit_seq: usize = 0;

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
        
        // ㉖ 状态空间运行时依赖：首项/公差由运行时读数当场推导——
        //   svMix = (#insts + #handlers + <载荷种子表达式>) % 0X100
        //   svTrm = tamper % 0X40
        //   首项 = svMix*k0 + svTrm*k1 + k2；公差 = ((svMix+svTrm) % dm)*2 + db（恒奇）
        // 状态值运行时填进状态值表；文本只剩混合常量与槽序号——常量集合 ≠
        // 可达状态集合，静态区间/差分分析失去锚点。
        // 槽位：1=fetch 2=dispatch 3..5=中间态 6..53=叶子路由态 64..=出口码带（㉗ 每叶唯一）。
        let (sv_t, sv_m, sv_n, sv_f, sv_d, sv_i) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        keys.sv_tbl = sv_t.clone();
        let k0 = rng.range(3, 31);
        let k1 = rng.range(2, 17);
        let k2 = rng.range64(0x100, 0xFFF);
        let dm = rng.range(19, 47);
        let db = rng.range(3, 50) | 1;
        let init_val1 = rng.range(10, 1000) as i64;
        let init_val2 = rng.range(1, 1000) as i64;

        // ㉙① 去裸数字：公差除数/加数（dm/db）与填表循环下界 1 全部混淆算式化
        out.push_str(&format!(
            "local {}={{}};local {}=((#{}+#{}+({}))%0X100);local {}=(({})%0X40);local {}=({})*{}+({})*{}+{};local {}=((({}+({}))%{})*2+{});for {}={},{} do {}[{}]={};{}={}+{} end;",
            sv_t,
            sv_m, var_insts, var_handlers, var_seed,
            sv_n, var_tamper,
            sv_f, sv_m, Self::obf_num(k0 as i64, rng), sv_n, Self::obf_num(k1 as i64, rng), Self::obf_num(k2, rng),
            sv_d, sv_m, sv_n, Self::obf_num(dm as i64, rng), Self::obf_num(db as i64, rng),
            sv_i, Self::obf_num(1, rng), Self::obf_num(112, rng), sv_t, sv_i, sv_f, sv_f, sv_f, sv_d));

        // ㉙① 状态机三个辅助状态初值改混淆算式（原先 50% 概率裸十进制）
        out.push_str(&format!("{},{},{}={},{},{};",
            s_state, t_shadow, d_junk,
            Self::obfuscate_num_depth(init_val1, 1, &keys, rng),
            Self::obfuscate_num_depth(0, 1, &keys, rng),
            Self::obfuscate_num_depth(init_val2, 1, &keys, rng)
        ));
        out.push_str(&Self::transition_assign_expr(&var_t, &Self::sv_ref(&keys, 1, rng), &keys, rng));

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
        let mut mid_states: Vec<usize> = Vec::new();
        let mut mid_kinds: Vec<u8> = Vec::new(); // 0=check 1=shuffle
        for mi_k in 0..extra_states {
            mid_states.push(3 + mi_k);
            mid_kinds.push(if rng.range(0, 2) == 0 { 0 } else { 1 });
        }
        // 随机中间态顺序（各自回到 dispatch）
        let mut mid_order: Vec<usize> = (0..extra_states).collect();
        rng.shuffle(&mut mid_order);

        // ㉙① 骨架键控分支（fetch/中间态/派发）互斥——先各自建成再洗牌发射；
        // 条件走 state_cmp 四形态；else 尾支（返回语义）保持语法末位。
        let mut branches: Vec<(String, String)> = Vec::new();

        // fetch 支：越界哨兵 + 取指 + 路由推导 + 转移（1/路由数均混淆算式）
        let mut fetch_body = String::new();
        fetch_body.push_str(&format!("if {}>#{} then return end;", var_pc, var_insts));
        fetch_body.push_str(&format!("{},{}={}[{}],{}+{};", var_inst, var_pc, var_insts, var_pc, var_pc, Self::obfuscate_num_depth(1, 1, &keys, rng)));
        let q_route_expr = format!("{}[{}][{}]({}[{}][{}]({}[{}],{}),{})",
            keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_ba as i64, rng),
            keys.tbl_p, Self::format_num(keys.grp1 as i64, rng), Self::format_num(keys.key_add as i64, rng),
            var_inst, Self::obfuscate_num_depth(1, 1, &keys, rng), s_state,
            Self::obfuscate_num_depth(num_routes, 1, &keys, rng)
        );
        fetch_body.push_str(&format!("{}={};", q_route, q_route_expr));
        // ── 树形多样化 ③（放弃的方案留档）：route→handler 序号置换映射会改语义
        //（递归树的区间比较对「路由序」敏感，置换后 tree_entries 区间不再对应正确
        // handler——实测 compare two nil）。多样化由三叉+不等宽切分承担。
        if extra_states == 0 {
            fetch_body.push_str(&Self::transition_assign_expr(&var_t, &Self::sv_ref(&keys, 2, rng), &keys, rng));
        } else {
            // 态图：fetch → 第一个中间态
            let first_mid = mid_states[mid_order[0] as usize];
            fetch_body.push_str(&Self::transition_assign_expr(&var_t, &Self::sv_ref(&keys, first_mid, rng), &keys, rng));
        }
        let sr_fetch = Self::sv_ref(&keys, 1, rng);
        branches.push((Self::state_cmp(&var_t, &sr_fetch, &keys, rng), fetch_body));

        // 中间态分支（check/shuffle 空转后落 dispatch；功能零影响；+1 亦混淆）
        for &mi in mid_order.iter() {
            let st_m = mid_states[mi as usize];
            let mut mid_body = String::new();
            match mid_kinds[mi as usize] {
                0 => {
                    // check 态：d_junk 一致性空转自检（与原版 junk 判定同族形态）
                    let fake_c = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                    mid_body.push_str(&format!("if {}=={} then {}={}+{}; end ", d_junk, fake_c, d_junk, d_junk, Self::obfuscate_num_depth(1, 1, &keys, rng)));
                }
                _ => {
                    // shuffle 态：无副作用交换（对临时值双写同值）
                    let (sa, sb) = (Self::format_num(rng.range(0x10, 0xFF) as i64, rng), Self::format_num(rng.range(0x10, 0xFF) as i64, rng));
                    mid_body.push_str(&format!("{}={};{}={}; ", f_tmp, sa, f_tmp, sb));
                }
            }
            mid_body.push_str(&Self::transition_assign_expr(&var_t, &Self::sv_ref(&keys, 2, rng), &keys, rng));
            let sr_mid = Self::sv_ref(&keys, st_m, rng);
            branches.push((Self::state_cmp(&var_t, &sr_mid, &keys, rng), mid_body));
        }

        // dispatch 支：递归树（句柄索引走运行时键基/步长）
        let sr_disp = Self::sv_ref(&keys, 2, rng);
        branches.push((
            Self::state_cmp(&var_t, &sr_disp, &keys, rng),
            Self::generate_recursive_tree(
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
                &mut exit_seq,
                &mut junk_limit,
                h_base,
                h_stride,
                &keys,
                rng
            )
        ));

        rng.shuffle(&mut branches);
        for (bi, (cond, body)) in branches.iter().enumerate() {
            if bi == 0 { out.push_str(&format!("if {} then ", cond)); }
            else { out.push_str(&format!("elseif {} then ", cond)); }
            out.push_str(body);
        }

        out.push_str("else ");
        let tf_a = Self::transition_assign_expr(&var_t, &Self::sv_ref(&keys, 1, rng), &keys, rng);
        let tf_b = Self::transition_assign_expr(&var_t, &Self::sv_ref(&keys, 1, rng), &keys, rng);
        out.push_str(&format!("if {} then if {} then {},{}=false,false;{}else return(unpack or table.unpack)({},{},{})end else {}end ", 
            var_r_flg, var_tail_flg, var_tail_flg, var_r_flg, tf_a, var_r_vals, Self::obfuscate_num_depth(1, 1, &keys, rng), var_r_len, tf_b
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
        exit_seq: &mut usize,
        h_base: &str,
        h_stride: &str,
        keys: &CipherKeys,
        rng: &mut GenRng,
    ) -> String {
        // ㉖ 路由态 = 运行时状态值表槽 6..53（值含运行时种子，文本零状态常量）
        let next_slot = 6 + rng.range(0, 48);
        let s_state_trans = Self::transition_assign_expr(s_state, &Self::sv_ref(keys, next_slot, rng), keys, rng);
        // ㉗ 出口码不复用：每叶从出口槽带 64+ 顺序取唯一槽（值经运行时状态值表），
        // 不再共享哨兵 0——文本里没有「所有叶子写同一值」的结构指纹，
        // 动态出口枚举必须逐路径解析。
        let exit_slot = 64 + *exit_seq;
        *exit_seq += 1;
        let state_transition = Self::transition_assign_expr(var_t, &Self::sv_ref(keys, exit_slot, rng), keys, rng);
        let leaf_type = rng.range(0, 5);
        let mut node = String::new();
        let idx_1 = Self::obfuscate_num_depth(1, 1, keys, rng);
        // ㉙② 句柄索引运行时化：handlers[键基+(指令码+篡改)*步长]——键基/步长
        // 均为运行时推导值（见 packer m_main），静态求值注册表达式拿不到键集合
        let hidx = format!("{}[{}+({}[{}]+{})*{}]", var_handlers, h_base, var_inst, idx_1, var_tamper, h_stride);

        match leaf_type {
            0 => {
                node.push_str(&format!("{}={}+{};{}={};{}({});{}{}",
                    d_junk, d_junk, Self::obfuscate_num_depth(1, 1, keys, rng), f_tmp, hidx, f_tmp, var_inst, s_state_trans, state_transition));
            }
            1 => {
                node.push_str(&format!("repeat {}={};{}({});{}{}break until false;",
                    f_tmp, hidx, f_tmp, var_inst, s_state_trans, state_transition));
            }
            2 => {
                node.push_str(&format!("for _={},{} do {}={};{}({});end {}{}",
                    Self::obfuscate_num_depth(1, 1, keys, rng), Self::obfuscate_num_depth(1, 1, keys, rng), f_tmp, hidx, f_tmp, var_inst, s_state_trans, state_transition));
            }
            3 => {
                node.push_str(&format!("if {}~={} then {}={};{}({});{}{}end ",
                    d_junk, Self::obfuscate_num_depth(4294967295i64, 1, keys, rng), f_tmp, hidx, f_tmp, var_inst, s_state_trans, state_transition));
            }
            _ => {
                node.push_str(&format!("{}={};{}({});{}{}",
                    f_tmp, hidx, f_tmp, var_inst, s_state_trans, state_transition));
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
        exit_seq: &mut usize,
        junk_limit: &mut usize,
        h_base: &str,
        h_stride: &str,
        keys: &CipherKeys,
        rng: &mut GenRng,
    ) -> String {
        if min == max {
            let real_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, h_base, h_stride, keys, rng);
            if *junk_limit > 0 && rng.range(0, 5) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, h_base, h_stride, keys, rng);
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
                Self::generate_recursive_tree(min, cut1, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, junk_limit, h_base, h_stride, keys, rng),
                c2,
                Self::generate_recursive_tree(cut1 + 1, cut2, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, junk_limit, h_base, h_stride, keys, rng),
                Self::generate_recursive_tree(cut2 + 1, max, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, junk_limit, h_base, h_stride, keys, rng));
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
            branch.push_str(&Self::generate_recursive_tree(min, mid, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, junk_limit, h_base, h_stride, keys, rng));
            
            if *junk_limit > 0 && rng.range(0, 4) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, h_base, h_stride, keys, rng);
                let fake_cond = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                branch.push_str(&format!("elseif {}=={} then {} ", d_junk, fake_cond, junk_leaf));
            }

            branch.push_str("else ");
            branch.push_str(&Self::generate_recursive_tree(mid + 1, max, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, junk_limit, h_base, h_stride, keys, rng));
            branch.push_str("end ");
        } else {
            let rev_comp = Self::generate_opaque_predicate(mid as i64, q_route, ">", keys, rng);

            branch.push_str(&format!("if {} then ", rev_comp));
            branch.push_str(&Self::generate_recursive_tree(mid + 1, max, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, junk_limit, h_base, h_stride, keys, rng));
            
            if *junk_limit > 0 && rng.range(0, 4) == 0 {
                *junk_limit -= 1;
                let junk_leaf = Self::generate_leaf_node(var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, h_base, h_stride, keys, rng);
                let fake_cond = Self::format_num(rng.range(0x1000, 0x2FFF) as i64, rng);
                branch.push_str(&format!("elseif {}=={} then {} ", d_junk, fake_cond, junk_leaf));
            }

            branch.push_str("else ");
            branch.push_str(&Self::generate_recursive_tree(min, mid, q_route, var_inst, var_handlers, var_tamper, s_state, d_junk, f_tmp, var_t, exit_seq, junk_limit, h_base, h_stride, keys, rng));
            branch.push_str("end ");
        }
        branch
    }
}