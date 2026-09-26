//! 控制流形态共享件（自 Generator.rs 拆出）：
//! K 表运行期派生 / 读取族状态梯子 / HH 常量池返回码协议 / 滚动读取器打散
use crate::VM::VM_Backend::Generator_util::{CipherKeys, GenRng};

/// 形态②的派生值集合：kspell=K 表字面量拼写；e_*=梯子态/注册键；eh_*=HH 返回码
pub struct KConsts {
    pub kspell: [String; 9],
    pub e_a: String, pub e_b: String, pub e_c: String, pub e_d: String,
    pub e_ka: String, pub e_kb: String, pub e_kc: String,
    pub eh_ret: String, pub eh_nil: String, pub eh_next: String,
    pub eh_val: String, pub eh_fail: String,
}

/// 形态⑩：常数=自写位运算闭包派生链——bx(bx(a,b),c) = a^b^c = val，深括号两层
pub fn deep10(rng: &mut GenRng, bx: &str, val: i64) -> String {
    let a = rng.range64(0x1000, 0xFFFFF);
    let b = rng.range64(0x1000, 0xFFFFF);
    let c = val ^ a ^ b;
    format!("{bx}({bx}({a},{b}),{c})")
}

fn kval(kv: &[i64; 9], i: usize, j: usize, add: bool) -> i64 {
    if add { kv[i] + kv[j] } else if kv[i] >= kv[j] { kv[i] - kv[j] } else { kv[j] - kv[i] }
}

fn kexpr(kt: &str, kv: &[i64; 9], i: usize, j: usize, add: bool, rng: &mut GenRng) -> String {
    // ⑬ 括号包裹索引逐出现随机：(K[(1)]) 与 K[1] 混拼
    let mut w = |x: usize| if rng.range(0, 2) == 0 { format!("[({})]", x) } else { format!("[{}]", x) };
    let (a, b) = (w(i + 1), w(j + 1));
    if add { format!("{0}{1}+{0}{2}", kt, a, b) }
    else if kv[i] >= kv[j] { format!("{0}{1}-{0}{2}", kt, a, b) }
    else { format!("{0}{2}-{0}{1}", kt, a, b) }
}

/// K 表 9 魔数（互异重摇 12 派生值）+ 全部派生拼写
pub fn build_k(rng: &mut GenRng, kt_name: &str) -> KConsts {
        let kv: [i64; 9] = loop {
            let mut kv = [0i64; 9];
            for i in 0..9 { kv[i] = rng.range(1 << 20, (1 << 24) - 1) as i64; }
            let g = |i: usize, j: usize, add: bool| -> i64 {
                if add { kv[i] + kv[j] } else if kv[i] >= kv[j] { kv[i] - kv[j] } else { kv[j] - kv[i] }
            };
            let mut vs = vec![
                g(0, 1, false), g(2, 3, true), g(4, 5, false), g(6, 7, true),
                g(8, 2, true), g(7, 4, false), g(5, 3, true),
                g(2, 5, true), g(3, 6, true), g(1, 5, true), g(0, 6, true), g(7, 2, true),
            ];
            vs.sort(); vs.dedup();
            if vs.len() == 12 { break kv; }
        };
        let kspell: Vec<String> = (0..9)
            .map(|i| if rng.range(0, 2) == 0 { format!("0X{:X}", kv[i]) } else { format!("{}", kv[i]) })
            .collect();
        fn kval(kv: &[i64; 9], i: usize, j: usize, add: bool) -> i64 {
            if add { kv[i] + kv[j] } else if kv[i] >= kv[j] { kv[i] - kv[j] } else { kv[j] - kv[i] }
        }
        fn kexpr(kt: &str, kv: &[i64; 9], i: usize, j: usize, add: bool, rng: &mut GenRng) -> String {
            // ⑬ 括号包裹索引逐出现随机：(K[(1)]) 与 K[1] 混拼
            let mut w = |x: usize| if rng.range(0, 2) == 0 { format!("[({})]", x) } else { format!("[{}]", x) };
            let (a, b) = (w(i + 1), w(j + 1));
            if add { format!("{0}{1}+{0}{2}", kt, a, b) }
            else if kv[i] >= kv[j] { format!("{0}{1}-{0}{2}", kt, a, b) }
            else { format!("{0}{2}-{0}{1}", kt, a, b) }
        }
        let (m_a, e_a) = (kval(&kv, 0, 1, false), kexpr(&kt_name, &kv, 0, 1, false, rng));
        let (m_b, e_b) = (kval(&kv, 2, 3, true), kexpr(&kt_name, &kv, 2, 3, true, rng));
        let (m_c, e_c) = (kval(&kv, 4, 5, false), kexpr(&kt_name, &kv, 4, 5, false, rng));
        let (m_d, e_d) = (kval(&kv, 6, 7, true), kexpr(&kt_name, &kv, 6, 7, true, rng));
        let (h_ka, e_ka) = (kval(&kv, 8, 2, true), kexpr(&kt_name, &kv, 8, 2, true, rng));
        let (h_kb, e_kb) = (kval(&kv, 7, 4, false), kexpr(&kt_name, &kv, 7, 4, false, rng));
        let (h_kc, e_kc) = (kval(&kv, 5, 3, true), kexpr(&kt_name, &kv, 5, 3, true, rng));
        // HH 码同走 K 派生
        let (hh_ret, eh_ret) = (kval(&kv, 2, 5, true), kexpr(&kt_name, &kv, 2, 5, true, rng));
        let (hh_nil, eh_nil) = (kval(&kv, 3, 6, true), kexpr(&kt_name, &kv, 3, 6, true, rng));
        let (hh_next, eh_next) = (kval(&kv, 1, 5, true), kexpr(&kt_name, &kv, 1, 5, true, rng));
        let (hh_val, eh_val) = (kval(&kv, 0, 6, true), kexpr(&kt_name, &kv, 0, 6, true, rng));
        let (hh_fail, eh_fail) = (kval(&kv, 7, 2, true), kexpr(&kt_name, &kv, 7, 2, true, rng));
    KConsts {
        kspell: kspell.try_into().unwrap(),
        e_a: e_a, e_b: e_b, e_c: e_c, e_d: e_d,
        e_ka: e_ka, e_kb: e_kb, e_kc: e_kc,
        eh_ret: eh_ret, eh_nil: eh_nil, eh_next: eh_next,
        eh_val: eh_val, eh_fail: eh_fail,
    }
}

/// 滚动读取器打散：逆运算四步+状态更新三组拆随机键调度表（形态⑥循环壳）
pub fn build_scatter(
    rng: &mut GenRng, fn_bxor: &str, fn_b_rotr: &str, fn_read_dec: &str, fn_a3: &str,
    v_bx_a: &str, v_bx_b: &str, v_bx_r: &str, v_bx_w: &str, v_bx_g: &str, v_bx_s: &str,
    v_rt_x: &str, v_rt_n: &str, v_rt_d: &str, v_rt_g: &str, v_rt_t: &str,
    v_rd_o: &str, v_rd_g: &str, v_rd_e: &str, v_rd_c1: &str, v_rd_c2: &str,
    v_rd_c3: &str, v_rd_c4: &str, v_rd_c5: &str,
    sc_add: u8, sc_rot_in: u32, sc_add_k1: u8, sc_mul_k2: u8, sc_rot_k2: u32, sc_rot_k4: u32,
) -> String {                // ──⑥ 滚动读取器打散
                // 真实顺序只在键名/调度表
                // 循环壳与假出口逐产物随机 —— 静态读产物看不出解密链
                // 铁律：k1 吃解后字节、k2 吃原始字节、k34 最后跑。
                // 键用随机整数（不引入新名字——未声明的标识符在 Lua 里是全局 nil
                // aE[名字]=… 直接 table index is nil）
                let mut ikeys: Vec<u32> = Vec::new();
                while ikeys.len() < 7 {
                    let k = rng.range(1, 100) as u32;
                    if !ikeys.contains(&k) { ikeys.push(k); }
                }
                let (d1, d2, d3, d4) = (ikeys[0], ikeys[1], ikeys[2], ikeys[3]);
                let (u1, u2, u34) = (ikeys[4], ikeys[5], ikeys[6]);
                let inv_add_v = 256 - sc_add as i32;
                let mut defs = vec![
                    format!("{}[{}]=function(e) return (e+{})%256 end; ", v_rd_c4, d1, inv_add_v),
                    format!("{}[{}]=function(e) return {}(e,k4) end; ", v_rd_c4, d2, fn_bxor),
                    format!("{}[{}]=function(e) return {}(e,k3%8) end; ", v_rd_c4, d3, fn_b_rotr),
                    format!("{}[{}]=function(e) return {}((e+k2)%256,k1) end; ", v_rd_c4, d4, fn_bxor),
                    format!("{}[{}]=function(e) k1=(k1+e)%256; k1=((k1*{})%256)+((k1-(k1%{}))/{}); k1=(k1+{})%256 end; ",
                        v_rd_c4, u1, 1u32 << sc_rot_in, 1u32 << (8 - sc_rot_in), 1u32 << (8 - sc_rot_in), sc_add_k1),
                    format!("{}[{}]=function(e) k2=(k2*{}+e)%256; k2=((k2*{})%256)+((k2-(k2%{}))/{}); end; ",
                        v_rd_c4, u2, sc_mul_k2, 1u32 << (8 - sc_rot_k2), 1u32 << sc_rot_k2, 1u32 << sc_rot_k2),
                    format!("{}[{}]=function() k3={}(k3,(k1-k4+256)%256); k4=(k4+k2)%256; k4=((k4*{})%256)+((k4-(k4%{}))/{}); end; ",
                        v_rd_c4, u34, fn_bxor, 1u32 << sc_rot_k4, 1u32 << (8 - sc_rot_k4), 1u32 << (8 - sc_rot_k4)),
                ];
                rng.shuffle(&mut defs);
                let (fupd, farg, supd, sarg) = if rng.range(0, 2) == 0 {
                    (u1.clone(), v_rd_c1.clone(), u2.clone(), v_rd_e.clone())
                } else {
                    (u2.clone(), v_rd_e.clone(), u1.clone(), v_rd_c1.clone())
                };
                let (s0, sl) = [(0i32, 1i32), (5, 6), (17, 18), (-3, -2)][rng.range(0, 4)];
                let big = rng.range(9, 99);
                let mut lua = format!("local {}={{}}", v_rd_c4);
                for d in &defs { lua.push_str(d); }
                // 调度表：键序即执行序 —— 键是随机名，静态看不出对应哪步
                lua.push_str(&format!("local {}={{{},{},{},{}}}; ", v_rd_c5, d1, d2, d3, d4));
                // 形态⑥：for 序列跳转——怪异 start/step 随机路径，区间二分派发 4 步
                let chain = if rng.range(0, 3) == 0 {
                    format!(
                        "local {e}={raw} local {j}=1 while {j}<=4 do {e}={st}[{seq}[{j}]]({e}) {j}={j}+1 end {o}={e} ",
                        e = v_rd_c1, raw = v_rd_e, j = v_rd_c2, st = v_rd_c4, seq = v_rd_c5, o = v_rd_o
                    )
                } else {
                    let s6 = rng.range(0x50, 0xFFFF0) as i64;
                    let p6 = (rng.range(1, 0xFFFF) as i64) * 2 + 1;
                    let (q1, q2, q3, qe) = (s6 + p6, s6 + 2 * p6, s6 + 3 * p6, s6 + 3 * p6);
                    format!(
                        "local {e}={raw} for {j}=0X{SS:X},0X{QE:X},0X{PP:X} do if {j}<0X{Q2:X} then if {j}<0X{Q1:X} then {e}={st}[({seq}[(0X1)])]({e}) else {e}={st}[({seq}[(0X2)])]({e}) end else if {j}<0X{Q3:X} then {e}={st}[({seq}[(0X3)])]({e}) else {e}={st}[({seq}[(0X4)])]({e}) end end end {o}={e} ",
                        e = v_rd_c1, raw = v_rd_e, j = v_rd_c2, st = v_rd_c4, seq = v_rd_c5, o = v_rd_o,
                        SS = s6, QE = qe, PP = p6, Q1 = q1, Q2 = q2, Q3 = q3
                    )
                };
                let upds = format!(
                    "{st}[{fu}]({fa}) {st}[{su}]({sa}) {st}[{u34}]() ",
                    st = v_rd_c4, fu = fupd, fa = farg, su = supd, sa = sarg, u34 = u34
                );
                let (open, close, inc) = match rng.range(0, 3) {
                    0 => (
                        format!("local {g}={s0} while {g}<{sl} do ", g = v_rd_c3, s0 = s0, sl = sl),
                        "end; ".to_string(),
                        format!("{g}={g}+1; ", g = v_rd_c3),
                    ),
                    1 => (
                        format!("local {g}={s0} repeat ", g = v_rd_c3, s0 = s0),
                        format!("until {g}>={sl} ", g = v_rd_c3, sl = sl),
                        format!("{g}={g}+1; ", g = v_rd_c3),
                    ),
                    _ => (
                        format!("for {g}={s0},{s1} do ", g = v_rd_c3, s0 = s0, s1 = s0),
                        "end; ".to_string(),
                        String::new(),
                    ),
                };
                let fake = if inc.is_empty() { String::new() } else {
                    format!("if {g}>{big} then {g}={sl} end; ", g = v_rd_c3, big = big, sl = sl)
                };
                lua.push_str(&format!(
                    "local function {rd}() local {o}=0; {open}local {raw}={a3}() {chain}{upds}{fake}{inc}{close}return {o} end; ",
                    rd = fn_read_dec, o = v_rd_o, open = open, raw = v_rd_e, a3 = fn_a3,
                    chain = chain, upds = upds, fake = fake, inc = inc, close = close
                ));
                lua
}

/// 读取族（u32/a5/rS/a10）状态梯子：形态③④⑤ + ⑥ for 区间跳转 + ⑬ 包裹索引
#[allow(clippy::too_many_arguments)]
pub fn build_readers(
    mut rng: &mut GenRng, keys: &CipherKeys, k: &KConsts, kt_name: &str, pj_name: &str, fn_bxor: &str,
    fn_u32_dec: &str, fn_a5: &str, fn_read_string: &str, fn_read_dec: &str, fn_a10: &str,
    v_u32_t: &str, v_u32_n: &str, v_u32_i: &str, v_u32_v: &str,
    v_rs_l: &str, v_a10_v: &str, v_a10_h: &str,
) -> String {
    let (e_a, e_b, e_c, e_d) = (k.e_a.as_str(), k.e_b.as_str(), k.e_c.as_str(), k.e_d.as_str());
    let kspell = &k.kspell;                // u32 读取族打散；铁律
    // ⑩ 派生值提升为加载期 local（热路径零开销）
    let numA = { let v = rng.range(100000, 9999999) as i64; deep10(rng, fn_bxor, v) };
    let wk1 = { let v = rng.range(0x51, 0xFFFFF) as i64; deep10(rng, fn_bxor, v) };
    let nAv = rng.name();
    let w1v = rng.name();
                fn combine_u32(b: [&str; 4], rng: &mut GenRng) -> String {
                    match rng.range(0, 3) {
                        0 => {
                            // 霍纳（高字节在前进）：(((b4*W+b3)*W+b2)*W+b1)
                            let w = if rng.range(0, 2) == 0 { "256" } else { "2^8" };
                            format!("((({x}*{w}+{y})*{w}+{z})*{w}+{r})", x = b[3], y = b[2], z = b[1], r = b[0], w = w)
                        }
                        1 => {
                            // 双 u16 段拼：lo=b1+b2*W、hi=b3+b4*W，段权 W16
                            let w1 = if rng.range(0, 2) == 0 { "256" } else { "2^8" };
                            let w2 = if rng.range(0, 2) == 0 { "65536" } else { "2^16" };
                            let lo = format!("({}+{}*{})", b[0], b[1], w1);
                            let hi = format!("({}+{}*{})", b[2], b[3], w1);
                            if rng.range(0, 2) == 0 { format!("{}+{}*{}", lo, hi, w2) } else { format!("{}*{}+{}", hi, w2, lo) }
                        }
                        _ => {
                            // 乱序加权和：权重拼写独立、项序洗牌、累加起点换随机零种子
                            let w8 = if rng.range(0, 2) == 0 { "256" } else { "2^8" };
                            let w16 = if rng.range(0, 2) == 0 { "65536" } else { "2^16" };
                            let w24 = ["16777216", "2^24", "2^16*256"][rng.range(0, 3)];
                            let mut terms = vec![
                                b[0].to_string(),
                                format!("{}*{}", b[1], w8),
                                format!("{}*{}", b[2], w16),
                                format!("{}*{}", b[3], w24),
                            ];
                            rng.shuffle(&mut terms);
                            let seed = match rng.range(0, 3) {
                                0 => "0".to_string(),
                                1 => format!("({}-{})", b[1], b[1]),
                                _ => format!("({}*0)", b[3]),
                            };
                            if rng.range(0, 2) == 0 { format!("{}+({})", seed, terms.join("+")) }
                            else { format!("({})+{}", terms.join("+"), seed) }
                        }
                    }
                }
                let mut family = String::new();
                // ⑩ 派生值提升为加载期 local（真实发射点；此前误注入被遮蔽的外层变量）
                family.push_str(&format!("local {nA_}={nA0}; local {w1_}={w10}; ",
                    nA_ = nAv, nA0 = numA, w1_ = w1v, w10 = wk1));
                // K/PJ 表先行（形态②⑤的派生源/探针源，读取族与常量池共用）
                family.push_str(&format!(
                    "local {kt}={{{k0},{k1},{k2},{k3},{k4},{k5},{k6},{k7},{k8}}}; local {pj}={{}}; ",
                    kt = kt_name, pj = pj_name,
                    k0 = kspell[0], k1 = kspell[1], k2 = kspell[2], k3 = kspell[3], k4 = kspell[4],
                    k5 = kspell[5], k6 = kspell[6], k7 = kspell[7], k8 = kspell[8]));
                for (fname, is_u32) in [(fn_u32_dec, true), (fn_a5, false)] {
                    let comb_bytes: [String; 4];
                    let reversed: bool = rng.range(0, 2) == 1;
                    let head: String;      // 声明段（不含 function 头）
                    let collect: String;   // 收集段（空 = B 变体，读取在声明里完成）
                    match rng.range(0, 4) {
                        3 => {
                            // 收集 D：⑥ for 区间跳转（(i-S)/P 恒整、计数器兼任下标）
                            let (t, i) = (rng.name(), rng.name());
                            let s6 = rng.range(0x03, 0xFFFF0) as i64;
                            let p6 = (rng.range(1, 0xFFFF) as i64) * 2 + 1;
                            head = format!("local {t}={{}} ", t = t);
                            collect = format!(
                                "for {i}=0X{SS:X},0X{QE:X},0X{PP:X} do {t}[({i}-0X{SS:X})/0X{PP:X}+0X1]={rd}() end; ",
                                t = t, i = i, SS = s6, QE = s6 + 3 * p6, PP = p6, rd = fn_read_dec);
                            comb_bytes = [
                                format!("{}[1]", t), format!("{}[2]", t),
                                format!("{}[3]", t), format!("{}[4]", t),
                            ];
                        }
                        0 => {
                            // 收集 A：表 + while 正向
                            head = format!("local {t},{n},{i}={{}},4,0; ",
                                t = v_u32_t, n = v_u32_n, i = v_u32_i);
                            collect = format!("while {i}<{n} do {i}={i}+1; {t}[{i}]={rd}() end; ",
                                t = v_u32_t, n = v_u32_n, i = v_u32_i, rd = fn_read_dec);
                            comb_bytes = [
                                format!("{}[1]", v_u32_t), format!("{}[2]", v_u32_t),
                                format!("{}[3]", v_u32_t), format!("{}[4]", v_u32_t),
                            ];
                        }
                        1 => {
                            // 收集B：逐局部；方向随机（反向时倒写、逗号不少）
                            let q: Vec<String> = (0..4).map(|_| rng.name()).collect();
                            if !reversed {
                                head = format!(
                                    "local {a}={rd}() local {b}={rd}() local {c}={rd}() local {d}={rd}() ",
                                    a = q[0], b = q[1], c = q[2], d = q[3], rd = fn_read_dec
                                );
                            } else {
                                head = format!(
                                    "local {d},{c},{b},{a}={rd}(),{rd}(),{rd}(),{rd}() ",
                                    a = q[0], b = q[1], c = q[2], d = q[3], rd = fn_read_dec
                                );
                            }
                            // 多赋值左名字收右值：反向声明时字节归属跟着镜像
                            if !reversed {
                                comb_bytes = [q[0].clone(), q[1].clone(), q[2].clone(), q[3].clone()];
                            } else {
                                comb_bytes = [q[3].clone(), q[2].clone(), q[1].clone(), q[0].clone()];
                            }
                            collect = String::new();
                        }
                        _ => {
                            // 收集 C：表 + repeat until（换壳）
                            let (t, i) = (rng.name(), rng.name());
                            head = format!("local {t}={{}} local {i}=0 ", t = t, i = i);
                            collect = format!("repeat {i}={i}+1 {t}[{i}]={rd}() until {i}>=4 ",
                                t = t, i = i, rd = fn_read_dec);
                            comb_bytes = [
                                format!("{}[1]", t), format!("{}[2]", t),
                                format!("{}[3]", t), format!("{}[4]", t),
                            ];
                        }
                    }
                    let comb = combine_u32(
                        [&comb_bytes[0], &comb_bytes[1], &comb_bytes[2], &comb_bytes[3]], &mut rng
                    );
                    // 形态③⑤：状态梯子（elseif+嵌套 else if 混用），双否定探针臂=诱饵
                    let sv = rng.name();
                    let (lit_a, lit_b, lit_c) = (e_a, e_b, e_c);
                    let pk1 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    let pkA = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    if collect.is_empty() {
                        // B 变体：收集在声明段完成，第一态直接拼装返回
                        family.push_str(&format!(
                            "local function {f}() {head}local {sv}={e_a}; while true do \
                             if {sv}=={lit_a} then if {pj}[({pkA})]=={numA} then else return {comb} end; \
                             elseif not(not {pj}[({pk1})]) then {sv}={e_c}; \
                             else if {sv}=={lit_b} then return ({b0}-{b0}) end; {sv}={e_d}; end; end end; ",
                            f = fname, head = head, sv = sv, e_a = e_a, lit_a = lit_a, comb = comb,
                            pj = pj_name, pk1 = pk1, pkA = pkA, numA = numA, e_c = e_c, lit_b = lit_b, b0 = comb_bytes[0],
                            e_d = e_d));
                    } else {
                        // A/C 变体：收集、拼装拆成两个真实状态
                        family.push_str(&format!(
                            "local function {f}() {head}local {sv}={e_a}; while true do \
                             if {sv}=={lit_a} then {collect}{sv}={e_b}; \
                             elseif not(not {pj}[({pk1})]) then {sv}={e_c}; \
                             else if {sv}=={lit_b} then if {pj}[({pkA})]=={numA} then else return {comb} end end; {sv}={e_d}; end; end end; ",
                            f = fname, head = head, sv = sv, e_a = e_a, lit_a = lit_a,
                            collect = collect, e_b = e_b, pj = pj_name, pk1 = pk1, pkA = pkA, numA = numA,
                            e_c = e_c, lit_b = lit_b, comb = comb, e_d = e_d));
                    }
                }
                // read_string 四态梯子
                {
                    let (t, i, j) = (rng.name(), rng.name(), rng.name());
                    let shell = if rng.range(0, 2) == 0 {
                        format!("local {i}=0; while {i}<{l} do {i}={i}+1; {t}[({i})]=string_char({rd}()) end", i = i, l = v_rs_l, t = t, rd = fn_read_dec)
                    } else {
                        format!("for {j}=0X1,{l} do {t}[({j})]=string_char({rd}()) end", j = j, l = v_rs_l, t = t, rd = fn_read_dec)
                    };
                    let sv = rng.name();
                    let (lit_a, lit_b, lit_c) = (e_a, e_b, e_c);
                    let pk2 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    let pk3 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    family.push_str(&format!(
                        "local function {rs}() local {l},{tb}=0,{{}}; local {sv}={e_a}; while true do \
                         if {sv}=={lit_a} then {l}={a5}(); {sv}={e_b}; \
                         elseif {sv}=={lit_b} then if {l}~={zero} then else return '' end; {sv}={e_c}; \
                         elseif not(not {pj}[({pk2})]) then {sv}={e_d}; {pj}[({pk3})]={l}; \
                         else if {sv}=={lit_c} then {shell}; while {w1v} do return table_concat({tb}) end end; {sv}={e_a}; end; end end; ",
                        rs = fn_read_string, l = v_rs_l, tb = t, sv = sv, e_a = e_a,
                        lit_a = lit_a, a5 = fn_a5, e_b = e_b, lit_b = lit_b,
                        zero = rng.obfuscate_num(0i64, 1, &keys), e_c = e_c,
                        pj = pj_name, pk2 = pk2, e_d = e_d, pk3 = pk3,
                        lit_c = lit_c, shell = shell, w1v = w1v));
                }
                // a10（i32 符号还原）
                {
                    let hexp = ["2^31", "2^30*2", "2147483648", "2^16*2^15"][rng.range(0, 4)];
                    let cond = match rng.range(0, 3) {
                        0 => format!("{v}>=2*{h}-{h}", v = v_u32_v, h = v_a10_h),
                        1 => format!("not({v}<{h})", v = v_u32_v, h = v_a10_h),
                        _ => format!("{v}-{h}>=0", v = v_u32_v, h = v_a10_h),
                    };
                    let ret = match rng.range(0, 3) {
                        0 => format!("{v}-{h}-{h}", v = v_u32_v, h = v_a10_h),
                        1 => format!("{v}-({h}+{h})", v = v_u32_v, h = v_a10_h),
                        _ => format!("{v}-2*{h}", v = v_u32_v, h = v_a10_h),
                    };
                    let sv = rng.name();
                    let (lit_c, lit_d) = (e_c, e_d);
                    let pk4 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    family.push_str(&format!(
                        "local function {a10}() local {v},{h}=0,0; local {sv}={e_c}; while true do \
                         if {sv}=={lit_c} then {v}={a5}(); if not(not {pj}[({pk4})]) then {h}=0X0; else {h}={hexp}; end; {sv}={e_d}; \
                         elseif {sv}=={lit_d} then if not {pj}[({pk4})] then if {cond} then return {ret} end end; return {v}; \
                         else {sv}={e_c}; end; end end; ",
                        a10 = fn_a10, v = v_u32_v, h = v_a10_h, sv = sv, e_c = e_c,
                        lit_c = lit_c, a5 = fn_a5, hexp = hexp, e_d = e_d,
                        lit_d = lit_d, pj = pj_name, pk4 = pk4, cond = cond, ret = ret
                    ));
                }
                family
}

/// 常量池查表协议：HH 三 handler 返回码状态机（形态①②）+ ④⑤ 探针反转臂
#[allow(clippy::too_many_arguments)]
pub fn build_consts(
    rng: &mut GenRng, keys: &CipherKeys, k: &KConsts, pj_name: &str, fn_bxor: &str,
    sc_index2: &str, sc_kobf: &str, var_state_flag: &str, var_idx_chunk: &str,
    var_tbl: &str, var_e: &str, ds: &[String; 4], dn: &[String; 4], fn_read_string: &str,
    fn_a5: &str, fn_read_dec: &str, var_enc_c: &str, var_cache: &str,
    fn_c: &str, pf_consts: &str,
    v_ch_i: &str, v_ch_n: &str, t: &str,
    salt_lits: &[String; 4], tag_lits: &[String; 4],
    pf_opc: &str, pf_aa: &str, pf_bb: &str, pf_cc: &str,
) -> String {
    let (e_ka, e_kb, e_kc) = (k.e_ka.as_str(), k.e_kb.as_str(), k.e_kc.as_str());
    let (eh_ret, eh_nil, eh_next, eh_val, eh_fail) =
        (k.eh_ret.as_str(), k.eh_nil.as_str(), k.eh_next.as_str(), k.eh_val.as_str(), k.eh_fail.as_str());                // ── ⑥ 常量池查表打散
                // 读入侧/访问侧各一张调度表，键 = 混淆数字展开式（运行期才是 1/2/3）
                // 注册洗牌；挂永不命中诱饵键
                // 缓存检查拆成独立前哨闭包。缓存值只可能是 string/number/false
                // 用 ~=nil 判命中无歧义。
                let mt_name = rng.name();
                let dsp_name = rng.name();
                // 形态①②：__index 三handler+驱动换相
                let hh_name = rng.name();
                let (hh_cur, hh_c, hh_a2, hh_aux) = (rng.name(), rng.name(), rng.name(), rng.name());
                let hh_codes: Vec<i64> = {
                    let mut cs = Vec::new();
                    while cs.len() < 5 {
                        let m = rng.range(1 << 20, (1 << 24) - 1) as i64;
                        if !cs.contains(&m) { cs.push(m); }
                    }
                    cs
                };
                let (hh_ret, hh_nil, hh_next, hh_val, hh_fail) =
                    (hh_codes[0], hh_codes[1], hh_codes[2], hh_codes[3], hh_codes[4]);
                let (x_ret1, x_nil1, x_next1, x_val1, x_fail1) =
                    (eh_ret, eh_nil, eh_next, eh_val, eh_fail);
                let x_ka = e_ka;
                let pk6 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                let pkB = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                let numB = { let v = rng.range(100000, 9999999) as i64; deep10(rng, fn_bxor, v) };
                let pkC = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                let numC = { let v = rng.range(100000, 9999999) as i64; deep10(rng, fn_bxor, v) };
                let wk2 = { let v = rng.range(0x51, 0xFFFFF) as i64; deep10(rng, fn_bxor, v) };
                let wk3 = { let v = rng.range(0x51, 0xFFFFF) as i64; deep10(rng, fn_bxor, v) };
                let wk4 = { let v = rng.range(0x51, 0xFFFFF) as i64; deep10(rng, fn_bxor, v) };
                let ld_name = rng.name();
                let memo_name = rng.name();
                let h_name = rng.name();
                let _got_name = rng.name();
                let val_name = rng.name();
                let ddm = rng.name(); let ddd = rng.name(); let ddl = rng.name();
                let rvv = rng.name();
                // ㉓ tag 键=逐 build 随机字母表（值表达式包括号保优先级）
                let t1v = format!("({})", tag_lits[1]);
                let t2v = format!("({})", tag_lits[2]);
                let t3v = format!("({})", tag_lits[3]);
                let zero = rng.obfuscate_num(0i64, 1, &keys);
                let decoy_ld = rng.range(60, 250);
                let decoy_dsp = rng.range(60, 250);
                // 访问侧：tag → 解码闭包（定义顺序洗牌）
                // ⑰ 组→解码器绑定：先读组字节（载荷节首），从四个散置簇闭包中
                // 直连本组的 dec_str/dec_num——无统一路由入口
                let gname = rng.name();
                let fds = rng.name();
                let fdn = rng.name();
                let sel_s = format!("({g}==0 and {a} or {g}==1 and {b} or {g}==2 and {c} or {d4})",
                    g = gname, a = ds[0], b = ds[1], c = ds[2], d4 = ds[3]);
                let sel_n = format!("({g}==0 and {a} or {g}==1 and {b} or {g}==2 and {c} or {d4})",
                    g = gname, a = dn[0], b = dn[1], c = dn[2], d4 = dn[3]);
                let mut dsp_defs = vec![
                    format!("{d}[{t3}]=function({ddd},ev) return {fds}(ev[(0X2)],ev[(0X3)],{rv}) end; ",
                        d = dsp_name, t3 = t3v, fds = fds, ddd = ddd, rv = rvv),
                    format!("{d}[{t2}]=function({ddd},ev) return {fdn}(ev[(0X2)],ev[(0X3)],{rv}) end; ",
                        d = dsp_name, t2 = t2v, fdn = fdn, ddd = ddd, rv = rvv),
                    format!("{d}[{t1}]=function({ddd},ev) return ev[(0X2)] end; ", d = dsp_name, t1 = t1v, ddd = ddd),
                    format!("{d}[{dd}]=function(ev) return nil end; ", d = dsp_name, dd = decoy_dsp),
                ];
                rng.shuffle(&mut dsp_defs);
                // 读入侧：tag → 装载闭包（定义顺序洗牌）
                let bn = rng.name();
                let bj = rng.name();
                let mut ld_defs = vec![
                    format!("{l}[{t3}]=function({ddl},pos) local bl={rs}() {ec}[(pos)]={{{t3v},bl,pos-1}} end; ",
                        l = ld_name, t3 = t3v, t3v = t3v, rs = fn_read_string, ec = var_enc_c, ddl = ddl),
                    format!("{l}[{t2}]=function({ddl},pos) local {bn}={{}} for {bj}=1,8 do {bn}[{bj}]={rd}() end {ec}[(pos)]={{{t2v},{bn},pos-1}} end; ",
                        l = ld_name, t2 = t2v, t2v = t2v, bn = bn, bj = bj, rd = fn_read_dec, ec = var_enc_c, ddl = ddl),
                    format!("{l}[{t1}]=function({ddl},pos) {ec}[(pos)]={{{t1v},{rd}()~={zero}}} end; ",
                        l = ld_name, t1 = t1v, t1v = t1v, ec = var_enc_c, rd = fn_read_dec, zero = zero, ddl = ddl),
                    format!("{l}[{dd}]=function() end; ", l = ld_name, dd = decoy_ld),
                ];
                rng.shuffle(&mut ld_defs);
                let (nBv, nCv, w2v, w3v, w4v) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
                let mut lua = format!(
                    // ⑱ 密文/明文缓存两表 proxy 化（打折版）：newproxy(true) 返回 userdata，
                    // pairs 遍历直接报错；后备退化为普通表（fail-open）
                    "local {ecb},{cab}={{}},{{}}; local {ec}=newproxy and newproxy(true) or {ecb}; local {ca}=newproxy and newproxy(true) or {cab}; \
                     do local {m1}=getmetatable({ec}) if {m1} then {m1}.__index={ecb} {m1}.__newindex={ecb} end; local {m2}=getmetatable({ca}) if {m2} then {m2}.__index={cab} {m2}.__newindex={cab} end end; \
                     local {dsp},{ld}={{}},{{}}; local {nB_}={nB0}; local {nC_}={nC0}; local {w2_}={w20}; local {w3_}={w30}; local {w4_}={w40}; ",
                    ec = var_enc_c, ecb = rng.name(), ca = var_cache, cab = rng.name(),
                    m1 = rng.name(), m2 = rng.name(),
                    dsp = dsp_name, ld = ld_name,
                    nB_ = nBv, nB0 = numB, nC_ = nCv, nC0 = numC,
                    w2_ = w2v, w20 = wk2, w3_ = w3v, w30 = wk3, w4_ = w4v, w40 = wk4);
                lua.push_str(&format!(
                    "local {g}={rd}(); local {fds},{fdn}={ss},{sn}; ",
                    g = gname, rd = fn_read_dec, fds = fds, fdn = fdn, ss = sel_s, sn = sel_n));
                // ㉓ R=指令流滚动值（与 rewrite_chunk 同式；rotl7 余数式）。常量密钥派生自
                // 全部指令魔数/字段——不解指令流解不出任何字符串（解密依赖解释）
                lua.push_str(&format!(
                    "do local {sarr}={{{m0},{m1},{m2},{m3}}}; local {rvv}={bx}(0X2545F491,{sarr}[{g}+1]); \
                     local {T},{ta},{tbb},{tc}={c}.{po},{c}.{pa},{c}.{pb},{c}.{pc}; \
                     for {j}=1,#{T} do local {av}={ta}[{j}] if {av}<0 then {av}={av}+4294967296 end \
                     local {bv}={tbb}[{j}] if {bv}<0 then {bv}={bv}+4294967296 end \
                     local {cv}={tc}[{j}] if {cv}<0 then {cv}={cv}+4294967296 end \
                     local {r7}=({rvv}*128)%4294967296+({rvv}-{rvv}%33554432)/33554432 \
                     {rvv}=({bx}({r7},{T}[{j}])+{av}+{bx}({bv},{cv}))%4294967296 end end; ",
                    sarr = rng.name(), m0 = salt_lits[0], m1 = salt_lits[1], m2 = salt_lits[2], m3 = salt_lits[3],
                    rvv = rvv, bx = fn_bxor, g = gname,
                    T = rng.name(), ta = rng.name(), tbb = rng.name(), tc = rng.name(),
                    c = fn_c, po = pf_opc, pa = pf_aa, pb = pf_bb, pc = pf_cc,
                    j = rng.name(), av = rng.name(), bv = rng.name(), cv = rng.name(), r7 = rng.name()));
                for x in &dsp_defs { lua.push_str(x); }
                // 缓存前哨：命中（值非 nil）直接短路
                lua.push_str(&format!(
                    "local {memo}=function({ddm},{ix}) local cd={ca}[({ix})] if cd~=nil then return cd end end; ",
                    memo = memo_name, ix = var_idx_chunk, ca = var_cache, ddm = ddm));
                lua.push_str(&format!("local {mt}={{}}; ", mt = mt_name));
                lua.push_str(&format!(
                    "local {hh}={{}}; \
                     {hh}[{e_ka}]=function({ix},{ix}) if {flg} then else return {x_fail1},({kobf}..{ix}) end; \
                       local g={memo}(0X1,{ix}) if g~=nil then if {pj}[{pkB}]=={nBv} then else return {x_ret1},g end end while {w2v} do return {x_next1} end end; \
                     {hh}[{e_kb}]=function({ix},{ix}) local {ev}={ec}[({ix})] if type({ev})~='table' then return {x_nil1} end \
                       local {h}={dsp}[({ev}[(0X1)])] if not {h} then {ec}[({ix})]=nil return {x_nil1} end local {vv}={h}(0X1,{ev}) {ec}[({ix})]=nil return {x_val1},{vv} end; \
                     {hh}[{e_kc}]=function({ix},{aux}) {ca}[({ix})]={aux} while {w3v} do return {x_ret1},{aux} end end; ",
                    hh = hh_name, e_ka = e_ka, e_kb = e_kb, e_kc = e_kc,
                    vv = rng.name(),
                    ix = var_idx_chunk, aux = hh_aux, flg = var_state_flag,
                    x_fail1 = x_fail1, kobf = sc_kobf, memo = memo_name,
                    x_ret1 = x_ret1, x_next1 = x_next1, ec = var_enc_c,
                    ev = var_e, h = h_name, dsp = dsp_name, x_nil1 = x_nil1,
                    x_val1 = x_val1, ca = var_cache, pj = pj_name, pkB = pkB, nBv = nBv, w2v = w2v, w3v = w3v));
                lua.push_str(&format!(
                    "{mt}[{idx}]=function({tb},{ix}) local {cur}={x_ka}; local {aux}; \
                     while true do local {a2x}; if {cur}=={e_kc} then {a2x}={aux} else {a2x}={ix} end; local {c},{a2}={hh}[{cur}]({ix},{a2x}); \
                       if {c}=={x_ret1} then return {a2} end; \
                       if {c}=={x_fail1} then return {a2} end; \
                       if {c}=={x_nil1} then while {w4v} do return nil end end; \
                       if {c}=={x_next1} then {cur}={e_kb}; else {cur}={e_kc}; {aux}={a2} end; \
                     end end; ",
                    mt = mt_name, idx = sc_index2, tb = var_tbl, ix = var_idx_chunk,
                    cur = hh_cur, x_ka = x_ka, aux = hh_aux, c = hh_c, a2 = hh_a2,
                    hh = hh_name, x_fail1 = x_fail1, e_kb = e_kb, e_kc = e_kc, w4v = w4v, a2x = rng.name()));
                lua.push_str(&format!(
                    "{c}.{pf}=setmetatable({{}},{mt}); {mt}=({{}})[{mtn}]; ",
                    c = fn_c, pf = pf_consts, mt = mt_name, mtn = format!("0X{:X}", rng.range(0x1000, 0xFFFFF))));
                for x in &ld_defs { lua.push_str(x); }
                lua.push_str(&format!(
                    "local {i}=0; local {n}={a5}(); if not(not {pj}[({pk6})]) then {i}={n}; else \
                     while {i}<{n} do {i}={i}+1; local {t}={rd}(); \
                     local {h}={ld}[({t})]; if {h} then if {pj}[({pkC})]=={numC} then else {h}(0X0,{i}) end end end end; ",
                    i = v_ch_i, n = v_ch_n, a5 = fn_a5, pj = pj_name, pk6 = pk6,
                    t = t, rd = fn_read_dec, h = h_name, ld = ld_name, pkC = pkC, numC = numC));
                lua
}

/// 解头（防篡改探针+入口解密装配）—— 自 Generator.rs 拆出
#[allow(clippy::too_many_arguments)]
pub fn build_header(
    rng: &mut GenRng, keys: &CipherKeys, fn_s_byte: &str, fn_s_sub: &str, var_raw_p: &str,
    payload_str: &str, var_chk: &str, var_idx: &str, var_junk: &str, var_b: &str, var_tamper: &str,
    var_vc: &str, var_p: &str, var_a2: &str, entry_func: &str, fn_a3: &str, x: &str,
    fn_lit: &str, mode_lit: &str, k_lit: &str,
) -> String {
    // ㉓ 去 KRYVEX 明文标记：载荷前缀改逐 build 随机 6 字母（同长不破坏校验和游走）
    let kmark: String = (0..6).map(|_| (b'a' + rng.range(0, 26) as u8) as char).collect();
    format!("local {}, {} = {}, {}; local {} = ([=[{km}{}]=]); local {}, {}, {} = {}, {}, {}; repeat local {}={}({},{}); {}={}+{}; {}={}+{}; {}={}+({}%{}); until {}>={}; {} = ({}-{}) + ({}-{}); {}={}+(type({})=={fn_lit} and 0 or {}); local mt_vc={{}}; mt_vc[{mode_lit}]={k_lit}; {} = setmetatable({{}}, mt_vc); local {}, {} = {}({}({},{}+{}*{})), {}; local function {}() local {}={}({},{},{}); {}={}+{}; return {} end; local k1,k2,k3,k4 = {}(),{}(),{}(),{}(); ", fn_s_byte, fn_s_sub, "string_byte", "string_sub", var_raw_p, payload_str, var_chk, var_idx, var_junk, rng.obfuscate_num(0i64, 1, &keys), rng.obfuscate_num(1i64, 1, &keys), rng.obfuscate_num(0i64, 1, &keys), var_b, fn_s_byte, var_raw_p, var_idx, var_chk, var_chk, var_b, var_idx, var_idx, rng.obfuscate_num(1i64, 1, &keys), var_junk, var_junk, var_b, rng.obfuscate_num(2i64, 1, &keys), var_idx, rng.obfuscate_num(7i64, 1, &keys), var_tamper, var_chk, var_chk, var_junk, var_junk, var_tamper, var_tamper, fn_s_byte, rng.obfuscate_num(73i64, 1, &keys), var_vc, var_p, var_a2, entry_func, fn_s_sub, var_raw_p, var_idx, var_tamper, rng.obfuscate_num(1337i64, 2, &keys), rng.obfuscate_num(1i64, 1, &keys), fn_a3, x, fn_s_byte, var_p, var_a2, var_a2, var_a2, var_a2, rng.obfuscate_num(1i64, 1, &keys), x, fn_a3, fn_a3, fn_a3, fn_a3, km = kmark)
}

/// 数字解码器（IEEE754 重组）—— 拆出；2^(-1074)/2^(exp-1075) 浮点语义勿动
#[allow(clippy::too_many_arguments)]
pub fn build_decnum(
    fn_dec_num: &str, fn_chacha_stream: &str, kind_num: &str, vb: &str, xt: &str,
    v_sign: &str, v_exp: &str, v_mant: &str, f64parts: String,
    v_num_ks: &str, v_num_i: &str, v_num_g: &str, _fn_bxor: &str,
) -> String {
    format!(
            "local function {fn_dec_num}(v_enc, pool_idx, rv) local {ks}={fn_chacha_stream}(rv,pool_idx,{kind_num},8); \
             local {vb}, {i}, {g} = {{}}, 0, 0; \
             while {i} < 8 do {i} = {i} + 1; {vb}[{i}] = {xt}[v_enc[{i}]][{ks}[{i}]] end; \
             local {v_sign} = 1 - 2 * (({vb}[8] - ({vb}[8] % 128)) / 128); \
             local {v_exp} = ({vb}[8] % 128) * 8 * 2 + (({vb}[7] - ({vb}[7] % 16)) / 16); \
             local {v_mant} = {f64parts}; \
             if {v_exp} == 2047 then return {v_mant} == 0 and {v_sign} * (1/0) or (0/0) \
             elseif {v_exp} == 0 then return {v_sign} * {v_mant} * (2^(-1074)) \
             else return {v_sign} * ({v_mant} + 2^52) * (2^({v_exp} - 1075)) end end; ",
            i = v_num_i, g = v_num_g, ks = v_num_ks
        )
}

/// 字符串解码器（ChaCha 流异或逐字节）—— 拆出
#[allow(clippy::too_many_arguments)]
pub fn build_decstr(
    rng: &mut GenRng, fn_dec_str: &str, fn_chacha_stream: &str, kind_str: &str, xt: &str,
    fn_s_byte: &str, v_str_ks: &str, v_str_s: &str, v_str_i: &str, v_str_g: &str,
    _fn_bxor: &str, rvp: &str, rvx: &str,
) -> String {
    format!(
            "local function {fn_dec_str}({e},{p}{rvp}) local {n}=#{e}; local {ks}={fn_chacha_stream}({rvx}{p},{kind_str},{n}); \
             local {s}, {i}, {g} = {{}}, 0, 0; \
             while {i} < {n} do {i} = {i} + 1; {s}[{i}] = string_char({xt}[{fn_s_byte}({e},{i})][{ks}[{i}]]) end; \
             return table_concat({s}) end; ",
            e = rng.name(), p = rng.name(), n = rng.name(), rvp = rvp, rvx = rvx,
            ks = v_str_ks, s = v_str_s, i = v_str_i, g = v_str_g
        )
}
