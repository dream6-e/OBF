use rand::{thread_rng, Rng};

use super::Generator_util::{
    hash_params, mix_encrypt, poly_hash, set_hash_params, HashParams, StreamTable,
};

pub struct AntiTamperResult {
    pub setup: String,
    pub guards: Vec<String>,
    pub trigger: String,
    pub expected_final: i64,
    /// 流加密键表（解码器匿名挂在表里）。Generator 的解头/方法原型/body_consts
    /// 与守卫同作用域，复用同一张表；探测块的调用点也在收表前注册完毕。
    pub st: StreamTable,
}

impl AntiTamperResult {
    /// 全部调用点注册完后调用：把键表渲染进 setup 尾部。
    pub fn finish_setup(&mut self) {
        self.setup.push_str(&self.st.emit());
    }
}

/// 把常量写成「运行期算出来」的形态（③ 守卫键/状态常量的派生算式）：
/// `(0X<A>-0X<B>)` / `(0X<A>+0X<B>)` / `(0X<A>*0X2+0X<C>)`，
/// 三种写法求值都恰好等于 val，但产物里再也看不到 val 本身，
/// 同一个常量在不同位置也会被写成不同片段（无法搜索替换）。
fn derived_num(val: u64, rng: &mut impl Rng) -> String {
    match rng.gen_range(0..3) {
        0 => {
            let b = rng.gen_range(0x1000u64..0xFF_FFFF);
            format!("(0X{:X}-0X{:X})", val + b, b)
        }
        1 => {
            let b = rng.gen_range(1u64..0x8000);
            if val > b {
                format!("(0X{:X}+0X{:X})", val - b, b)
            } else {
                let c = rng.gen_range(0x1000u64..0xFF_FFFF);
                format!("(0X{:X}-0X{:X})", val + c, c)
            }
        }
        _ => format!("(0X{:X}*0X2+0X{:X})", val / 2, val % 2),
    }
}

/// ㉒族恒等转移式（三款，目标值恒等）：-r+(r+t) / (r-r)+t / (2r-(r+r))+t
fn opq_ident<T: Rng>(rng: &mut T, target: u32) -> String {
    let bound = (0xFFFFFu32).min(0xFFFFFEu32.saturating_sub(target)).max(0x1000);
    let r: u32 = rng.gen_range(0x1000..bound);
    match rng.gen_range(0..3) {
        0 => format!("-0X{:X}+0X{:X}", r, r + target),
        1 => format!("(0X{:X}-0X{:X})+0X{:X}", r, r, target),
        _ => format!("((2*0X{:X})-(0X{:X}+0X{:X}))+0X{:X}", r, r, r, target),
    }
}
/// 常量伪装：值恒等的随机算式（内层异或循环的 8/2 等）
fn opq_const<T: Rng>(rng: &mut T, v: u32) -> String {
    match rng.gen_range(0..3) {
        0 => { let a: u32 = rng.gen_range(0..v.max(1)); format!("(0X{:X}+0X{:X})", a, v - a) }
        1 => { let k: u32 = rng.gen_range(v + 1..v + 0x1000); format!("(0X{:X}-0X{:X})", k, k - v) }
        _ => format!("0X{:X}", v),
    }
}
fn rand_state<T: Rng>(rng: &mut T, used: &mut Vec<u32>) -> u32 {
    loop {
        let v: u32 = 0x10000 + rng.gen_range(0..0xEFF000);
        if !used.contains(&v) { used.push(v); return v; }
    }
}

fn rand_var() -> String {
    let mut rng = thread_rng();
    let len = rng.gen_range(7..=12);
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    (0..len).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

fn random_string() -> String {
    let mut rng = thread_rng();
    let len = rng.gen_range(8..=16);
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    (0..len).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}

/// 流加密密钥对（thread_rng 版，逻辑与 Generator_util::mix_key 一致）：
/// k0 恒非 0，且保证密文里不出现 \000。
fn sc_key(plain: &str) -> (u32, u32) {
    let mut r = thread_rng();
    loop {
        let k0 = r.gen_range(1..256u32);
        let k1 = r.gen_range(1..256u32);
        if mix_encrypt(plain.as_bytes(), k0, k1).iter().all(|&c| c != 0) {
            return (k0, k1);
        }
    }
}

fn shuffle_vec(vec: &mut Vec<usize>) {
    let mut rng = thread_rng();
    for i in (1..vec.len()).rev() {
        let j = rng.gen_range(0..=i);
        vec.swap(i, j);
    }
}

pub fn generate_split(use_debug: bool, key_var: &str) -> AntiTamperResult {
    let mut rng = thread_rng();
    
    let v_env = rand_var();
    let v_net = rand_var();
    let v_crash = rand_var();
    let v_dec = rand_var();
    let v_res = rand_var();
    let v_pool = rand_var();

    // 将所有敏感 API 存入基于哈希的加密池
    // （池里除全局 API 名，还有行号守卫要用的字段名与模式串 —— 见下面的 pool_strings）
    let strings: Vec<String> = vec![
        "debug".into(), "pcall".into(), "sethook".into(), "gethook".into(), "getinfo".into(),
        "C".into(), "string".into(), "dump".into(), "error".into(), "info".into(), "math".into(),
        "type".into(), "tonumber".into(), "table".into(), "number".into(), "function".into(),
        // 行号守卫（反美化）用到的字符串，一个都不留在明文里
        "S".into(), "l".into(), "linedefined".into(), "currentline".into(),
        ":(%d+)[:\r\n ]".into(),
        // ③ 陷阱门用：setmetatable(__index 元表陷阱)。凡 poly_hash 查池的串必须在此
        // 登记过，否则查表得 nil → 构造器 [nil]=… 直接「table index is nil」。
        "setmetatable".into(), "__index".into(),
    ];
    // 池级密钥（16 位）逐产物随机；所有条目共用一组，解码器只需要带一个常量。
    // 与探测串同一套混合：密文按位置相关密钥生成，不是单字节 XOR，肉眼算不出来。
    let (pk0, pk1) = loop {
        let (a, b) = (rng.gen_range(1..256) as u32, rng.gen_range(1..256) as u32);
        let clean = strings
            .iter()
            .all(|t| mix_encrypt(t.as_bytes(), a, b).iter().all(|&c| c != 0));
        if clean {
            break (a, b);
        }
    };
    let pool_key = pk0 * 256 + pk1;
    // ⑤ 池键哈希参数逐产物随机（抹掉 djb2 的 5381/33 指纹）：
    //    多重抽几次参数，直到所有池条目的键互不相同（撞键会让池条目互相覆盖）。
    let _hp: HashParams = loop {
        let p = HashParams {
            mult: rng.gen_range(3..0x1_0000u32) | 1,
            add: rng.gen_range(0..0x1_0000u32),
            seed: rng.gen_range(0x1000..0x100000u32),
        };
        set_hash_params(p);
        let mut hs: Vec<u32> = strings.iter().map(|t| poly_hash(t)).collect();
        hs.sort_unstable();
        hs.dedup();
        if hs.len() == strings.len() {
            break p;
        }
    };
    let mut pool_entries = Vec::new();
    for s in &strings {
        let hash = poly_hash(s);
        let enc: Vec<String> = mix_encrypt(s.as_bytes(), pk0, pk1).iter().map(|c| c.to_string()).collect();
        pool_entries.push(format!("[{}]={{{}}}", hash, enc.join(",")));
    }

    // 生成一个随机变量名用于毒药表（Poison Pill）注入；哈希与池条目撞键就重抽
    let (rand_str, rand_hash) = loop {
        let rs = random_string();
        let h = poly_hash(&rs);
        if !strings.iter().any(|t| poly_hash(t) == h) {
            break (rs, h);
        }
    };
    let enc: Vec<String> = mix_encrypt(rand_str.as_bytes(), pk0, pk1).iter().map(|c| c.to_string()).collect();
    pool_entries.push(format!("[{}]={{{}}}", rand_hash, enc.join(",")));
    
    let pool_data = pool_entries.join(",");

    let mut setup = String::new();
    // 使用 getgenv() 完美适配 Roblox 执行器全局环境
    setup.push_str(&format!("local {} = getgenv and getgenv() or getfenv and getfenv() or _ENV or _G or {{}};\n", v_env));

    // 自定义流加密键表（独立于池）：解码器匿名挂在表里（finish_setup 时渲染）。
    // 守卫体与 Generator 的解头/方法原型/body_consts 复用同一张表。
    let mut st = StreamTable::new(rand_var());

    // 递归爆栈用的两个隐藏名：函数名 + 参数名，逐产物随机
    let fn_crash_rec = rand_var();
    let v_crash_arg = rand_var();
    // 纯物理爆栈导致卡死，无视 Roblox 的 string.rep / 内存上限等沙盒过滤。
    // 递归写成「把要递归的函数当参数传进去」的形式（`f(o) o(f,o)`），
    // 产物里看不到 `pcall(f)` 这种一眼可辨的图案。
    setup.push_str(&format!(
    "local function {}() \
        local j,s,k,v=_ENV,false;local t={{}};local p=type;if not k then v=s end;if p(t)~={crash_tab} then p=j end;repeat p={{}} until v; \
         local function {}({}) {}({},{}); {}({},{}) end \
         {}(pcall); \
     local function we(x) return not x end;local gd if we(gd) then while we(s) do end;end \
     end;\n",
    v_crash, fn_crash_rec, v_crash_arg, v_crash_arg, fn_crash_rec, v_crash_arg, v_crash_arg, fn_crash_rec, v_crash_arg, fn_crash_rec,
    crash_tab = {
        let (a, b) = sc_key("table");
        st.call("table", a, b)
    }
));
    setup.push_str(&format!("local {} = {{{}}};\n", v_pool, pool_data));
    // 池解码器的「打乱线性逻辑 / 数据流」版本：
    //   ① 循环写成 while + 自增下标（数字 for 太规整）；下标先取出来再自己加；
    //   ② 解密算式写成 `(b - key + j - j) % 256`：j 是影子计数，前后抵消，
    //      但读起来像在参与运算；常量 key 与 256 也被埋进这条链里；
    //   ③ 拼接外面套一个恒真的判断（`(j+j)-j > 0` 即 j>0），打断线性阅读；
    //   ④ 全部局部变量逐产物随机名。纯冷路径（只在守卫/池查表时走），不吃性能。
    // 池解码器 v2「拆散打乱线性逻辑 / 数据流」：
    //   ① 循环体拆成五态数值状态机（查长/自增/键流取数/谓词+异或拼装），转移走
    //      三款恒等式，状态值逐产物随机；线性 while 阅读被彻底打散；
    //   ② 循环携带数据（下标/累计串/长度/键流系数）全部经暂存表槽流动，
    //      跨态共享的 a/b/r/p 提升到机器前声明（跨 elseif 块作用域）；
    //   ③ 键流算式拆分 ((k0*i)%256 与 +k1 两步)、K 的拆解嵌差值恒等式、
    //      判空改 return 原值（nil）；
    //   ④ 内层异或 for 的常量（8/2）逐处独立伪装、谓词从恒真族随机取。
    // 纯冷路径（守卫/池查表时走），不吃性能。
    let v_dec = rand_var();
    let d_t = rand_var();
    let d_e = rand_var();
    let d_k1 = rand_var();
    let d_j = rand_var();
    let d_a = rand_var();
    let d_b = rand_var();
    let d_r = rand_var();
    let d_p = rand_var();
    let d_w = rand_var();
    let d_xb = rand_var();
    let d_yb = rand_var();
    let d_st = rand_var();
    let d_dl = rand_var();
    let d_c = rand_var();
    let mut used_states: Vec<u32> = Vec::new();
    let s1 = rand_state(&mut rng, &mut used_states);
    let s2 = rand_state(&mut rng, &mut used_states);
    let s3 = rand_state(&mut rng, &mut used_states);
    let s4 = rand_state(&mut rng, &mut used_states);
    let tr12 = opq_ident(&mut rng, s2);
    let tr23 = opq_ident(&mut rng, s3);
    let tr34 = opq_ident(&mut rng, s4);
    let tr41 = opq_ident(&mut rng, s1);
    let s_done = rand_state(&mut rng, &mut used_states);
    let st_init = opq_ident(&mut rng, s1);
    let e8 = opq_const(&mut rng, 8);
    let e2a = opq_const(&mut rng, 2);
    let e2b = opq_const(&mut rng, 2);
    let e2c = opq_const(&mut rng, 2);
    let e2d = opq_const(&mut rng, 2);
    let e2e = opq_const(&mut rng, 2);
    let opq = match rng.gen_range(0..3) {
        0 => format!("({j}+{j})-{j}>0", j = d_j),
        1 => format!("({j}-{j})+{j}>0", j = d_j),
        _ => format!("{j}*{j}>={j}", j = d_j),
    };
    setup.push_str(&format!(
        "local function {dec}(h) \
            local {t}={{i=0X0000,o=''}};local {e}={pool}[h]; \
            if not {e} then return {e} end; \
            {t}.n=#{e};local {dl}=0X{dlx:X}; \
            local {k1}=({K}+{dl}-{dl})%256;{t}.k=({K}-{k1})/256; \
            local {c}=string.char;local {a},{b},{r},{p},{j}=0X0,0X0,0X0,0X1,{j0}; \
            local {st}={init}; \
            while true do \
                if {st}=={S1} then if {t}.i<{t}.n then {st}={tr12} else {st}={tdone} end \
                elseif {st}=={S2} then {t}.i={t}.i+0X1;{st}={tr23} \
                elseif {st}=={S3} then local {t2}=({t}.k*{t}.i)%256;{a}=({t2}+{k1})%256;{b}={e}[{t}.i];{st}={tr34} \
                elseif {st}=={S4} then {j}={j}+0X1; \
                    if {opq} then {r}=0X0;{p}=0X1; \
                        for {w}=1,{E8} do local {xb},{yb}={a}%{E2a},{b}%{E2b}; \
                            if {xb}~={yb} then {r}={r}+{p} end; \
                            {a}=({a}-{xb})/{E2c};{b}=({b}-{yb})/{E2d};{p}={p}*{E2e}; \
                        end; \
                        {t}.o={t}.o..{c}(({r}-{k1}+0X100)%0X100) \
                    end; \
                    {st}={tr41b} \
                else break end \
            end; \
            return {t}.o; \
        end;\n",
        dec = v_dec, t = d_t, t2 = rand_var(), pool = v_pool, e = d_e, k1 = d_k1,
        j = d_j, j0 = rng.gen_range(1..64), c = d_c, a = d_a, b = d_b, r = d_r,
        p = d_p, w = d_w, xb = d_xb, yb = d_yb, st = d_st, dl = d_dl,
        dlx = rng.gen_range(0x1000..0xFFFFFu32),
        init = st_init, S1 = s1, S2 = s2, S3 = s3, S4 = s4,
        tr12 = tr12, tr23 = tr23, tr34 = tr34, tr41b = tr41, tdone = s_done,
        opq = opq, E8 = e8, E2a = e2a, E2b = e2b, E2c = e2c, E2d = e2d, E2e = e2e,
        K = format!("0X{:04X}", pool_key)
    ));
    setup.push_str(&format!(
        "local function {}(h) \
            local xc,yu=true;local s = {}(h); if not s then return yu end; \
             return xc and {}[s]; \
         end;\n",
         v_res, v_dec, v_env
    ));
    setup.push_str(&format!(
    "local rt=function(z,x,c,g,nt) local v,b,n,y,op=\"\\116\\97\\98\\108\\101\",\"\\49\\37\\64\",0X0,\"\\76\\117\\97\\117\";if n<=0.0 then op=z else op=x end;local te;local ui=nt;while ui==y do if not te then te=x else te=g end;if te~=nil then if z(te)~=v then c(b,n) else g(1) end end;break;end;end;rt(typeof,raknet,error,print,_VERSION);\n"
));
    setup.push_str(&format!("local {}={{}};\n", v_net));
    // 网表的陷阱门：任何取不到的键（有人删掉/改掉某块的键，或自己构造下标试探）
    // 都返回爆栈函数 —— 直接卡死，而不是抛一句读得懂的 nil 调用错误暴露结构。
    setup.push_str(&format!(
        "{}({},{{[{}]=function() return {} end}});\n",
        format!("{}({})", v_res, poly_hash("setmetatable")),
        v_net, format!("{}({})", v_dec, poly_hash("__index")), v_crash
    ));

    let mut current_expected: i64 = rng.gen_range(1000..9999);
    let initial_token = current_expected;
    
    let mut guards_indices = vec![0, 1, 2, 3, 4, 5, 7, 8];
    shuffle_vec(&mut guards_indices);
    guards_indices.push(6);
    shuffle_vec(&mut guards_indices);

    // ── ③ 代码块互锁（紧密耦合 / 互相嵌合） ──
    // 三件事让「逐段破解」失效：
    //   ① 网表不再用 0/1/2… 顺序下标：每个守卫挂在一个随机 u32 键上，「下一块」
    //      也要靠链上的键去找 —— 光看代码看不出执行顺序；定义/调用/触发各写同一个
    //      值的不同派生算式，文本搜索对不上号；
    //   ② 全链共享一个运行期状态量：每块入口按自己的 (乘数, 加数) 推进它，并把
    //      「自己算出来的状态 − 这一步应有的状态」混进传给下一块的令牌里。
    //      链路完整时这一项恒为 0（令牌与以前一模一样）；少跑/改跑/换序任何一块，
    //      状态就对不上，令牌被污染 → 链尾自检失败 → 卡死。
    //      校正项是「自然抵消」而不是一句 if，产物里没有「检查状态」的痕迹；
    //   ③ 网表挂 __index → 爆栈 的陷阱门 + 两条形状一致的诱饵（见循环后）。
    let n_guards = guards_indices.len();
    let mut keys: Vec<u64> = Vec::new();
    while keys.len() < n_guards + 2 {
        let k = rng.gen_range(0x1000_0000u64..0x7FFF_FFFF);
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    let v_state = rand_var();
    let mut step_a: Vec<u64> = Vec::new();
    let mut step_b: Vec<u64> = Vec::new();
    let mut state_at: Vec<u64> = vec![(rng.gen_range(1..0xFFFFu64) << 16) | rng.gen_range(1..0xFFFFu64)];
    for _ in 0..n_guards {
        // 乘数取小（< 1000）保证 x*A+B < 2^42，double 里是精确整数
        let a = rng.gen_range(3..997u64) | 1;
        let b = rng.gen_range(1..0xFFFF_FFFFu64);
        step_a.push(a);
        step_b.push(b);
        let prev = *state_at.last().unwrap();
        state_at.push((prev.wrapping_mul(a).wrapping_add(b)) % 0x1_0000_0000);
    }
    setup.push_str(&format!("local {}={};\n", v_state, derived_num(state_at[0], &mut rng)));

    let mut guards_code = Vec::new();

    for i in 0..guards_indices.len() {
        let delta = rng.gen_range(10..99);
        let guard_type = guards_indices[i];

        // 每块入口先推进共享状态，并把「实算状态 − 本步应有状态」混进令牌：
        let state_step = format!(
            "{}=({}*{}+{})%0X100000000;",
            v_state, v_state, derived_num(step_a[i], &mut rng), derived_num(step_b[i], &mut rng)
        );
        let corr = format!("+({}-0X{:X})", v_state, state_at[i + 1]);
        let next_key = derived_num(keys[i + 1], &mut rng);
        let next_good = if i == n_guards - 1 {
            format!("return k+{}{}", delta, corr)
        } else {
            format!("return {}[{}](k+{}{})", v_net, next_key, delta, corr)
        };
        
        let next_bad = if i == n_guards - 1 {
            format!("return k-{}{}", rng.gen_range(100..999), corr)
        } else {
            format!("return {}[{}](k-{}{})", v_net, next_key, rng.gen_range(100..999), corr)
        };
        
        let mut check_code = String::new();
        match guard_type {
            0 => {
                let fnv_pcall = poly_hash("pcall");
                let fnv_string = poly_hash("string");
                let fnv_math = poly_hash("math");
                let (k0n, k1n) = sc_key("nil");
                let sc_nil = st.call("nil", k0n, k1n);
                // 用哈希组精确取值校验，避免受 pairs 迭代 __index 失效的影响
                check_code = format!(
                    "local sc_val = 0; \
                     local chk = {{{}, {}, {}}}; \
                     for idx = 1, 3 do \
                         if type({}(chk[idx])) ~= {nil_lit} then sc_val = sc_val + 1 end \
                     end; \
                     if sc_val ~= 3 then {} else {} end\n",
                    fnv_pcall, fnv_string, fnv_math, v_res, next_bad, next_good, nil_lit = sc_nil
                );
            }
            1 => {
                let hash_pcall = poly_hash("pcall");
                // 元方法名整串加密（连 __ 前缀一起），键表挂的就是运行期解出来的名字。
                let mut mm_calls: Vec<String> = Vec::new();
                for mm in ["__add", "__sub", "__mul", "__call"] {
                    let (a, b) = sc_key(mm);
                    mm_calls.push(st.call(mm, a, b));
                }
                check_code = format!(
                    "local z = setmetatable({{}}, {{ \
                        [{m0}]=function(a)return a end, \
                        [{m1}]=function(a)return a end, \
                        [{m2}]=function(a)return a end, \
                        [{m3}]=function(...)return ... end \
                     }}); \
                     local p={}({}); if not p then {} else \
                     local st,r=p(function() local x=z+z-z*z; local y=z(z); return x==z and y==z end); \
                     if not st or not r then {} else {} end end\n",
                    v_res, hash_pcall, next_bad, next_bad, next_good,
                    m0 = mm_calls[0], m1 = mm_calls[1], m2 = mm_calls[2], m3 = mm_calls[3]
                );
            }
            2 => {
                if use_debug {
                    let hash_debug = poly_hash("debug");
                    let hash_pcall = poly_hash("pcall");
                    let hash_sethook = poly_hash("sethook");
                    let hash_gethook = poly_hash("gethook");
                    let hash_info = poly_hash("info");
                    // Luau Roblox 自适应：如果没有 sethook，探测 info（Luau特征），符合则放行
                    check_code = format!(
                        "local d={}({}); local p={}({}); \
                         if not (d and p) then {} else \
                         local sh = d[{}({})]; local gh = d[{}({})]; \
                         if not (sh and gh) then \
                             if d[{}({})] then {} else {} end \
                         else \
                             local ok, h = p(gh); \
                             if not ok then {} else \
                             local c = 0; local ok2 = p(sh, function() c=c+1 end, string.char(99)); \
                             if not ok2 then {} else \
                             local function tmp() end; tmp(); p(sh); \
                             if c < 1 then {} else {} end end end end end\n",
                        v_res, hash_debug, v_res, hash_pcall,
                        next_bad,
                        v_dec, hash_sethook, v_dec, hash_gethook,
                        v_dec, hash_info, next_good, next_bad,
                        next_bad,
                        next_bad,
                        next_bad, next_good
                    );
                } else {
                    check_code = format!("{}\n", next_good);
                }
            }
            3 => {
                if use_debug {
                    let hash_debug = poly_hash("debug");
                    let hash_pcall = poly_hash("pcall");
                    let hash_getinfo = poly_hash("getinfo");
                    let hash_info = poly_hash("info");
                    let hash_C = poly_hash("C");
                    let (t0, t1) = sc_key("table");
                    let sc_tab = st.call("table", t0, t1);
                    check_code = format!(
                        "local d={}({}); local p={}({}); \
                         if not (d and p) then {} else \
                         local gi = d[{}({})]; \
                         if not gi then \
                             if d[{}({})] then {} else {} end \
                         else \
                             local ok, inf = p(gi, p); \
                             if not ok or type(inf)~={tab_lit} then {} else \
                             local w=inf.what; local h={hp_seed}; \
                             for idx=1,#w do h=(h*{hp_mult}+string.byte(w,idx)+{hp_add})%4294967296 end; \
                             if h~={} then {} else {} end end end end\n",
                        v_res, hash_debug, v_res, hash_pcall,
                        next_bad,
                        v_dec, hash_getinfo,
                        v_dec, hash_info, next_good, next_bad,
                        next_bad,
                        hash_C, next_bad, next_good,
                        tab_lit = sc_tab,
                        hp_seed = format!("0X{:X}", hash_params().seed),
                        hp_mult = format!("0X{:X}", hash_params().mult),
                        hp_add = format!("0X{:X}", hash_params().add)
                    );
                } else {
                    check_code = format!("{}\n", next_good);
                }
            }
            4 => {
                let hash_pcall = poly_hash("pcall");
                let hash_error = poly_hash("error");
                check_code = format!(
                    "local p={}({}); local e={}({}); \
                     if not p or not e then {} else \
                     local st, r = p(function() e(1) end); \
                     if st then {} else {} end end\n",
                    v_res, hash_pcall, v_res, hash_error,
                    next_bad, next_bad, next_good
                );
            }
            5 => {
                let hash_string = poly_hash("string");
                let hash_pcall = poly_hash("pcall");
                let hash_dump = poly_hash("dump");
                let hash_debug = poly_hash("debug");
                let hash_info = poly_hash("info");
                check_code = format!(
                    "local s={}({}); local p={}({}); local d={}({}); \
                     if not (s and p) then {} else \
                     local du=s[{}({})]; \
                     if not du then \
                         if d and d[{}({})] then {} else {} end \
                     else \
                         local st = p(du, function() end); \
                         if not st then \
                             if d and d[{}({})] then {} else {} end \
                         else \
                             {} \
                         end \
                     end end\n",
                     v_res, hash_string, v_res, hash_pcall, v_res, hash_debug,
                     next_bad,
                     v_dec, hash_dump,
                     v_dec, hash_info, next_good, next_bad,
                     v_dec, hash_info, next_good, next_bad,
                     next_good
                );
            }
            6 => {
                check_code = format!(
                    "local t=false; local v1=1; local o={}; \
                     t = o and o==v1; \
                     if t then {} else {} end\n",
                    rng.gen_range(100..999), next_bad, next_good
                );
            }
            7 => {
                // 守卫的原形（用户点名要打乱的那段）：
                //   local eK = Vm
                //   if type(eK) ~= 'table' then return ep - 254
                //   else local gF = setmetatable({}, {__tostring=Qt, __index=Qt, __newindex=Qt, __call=Qt})
                //        pcall(function() eK[x(2890034435)] = gF end)
                //        return ep + 45 end
                // 现在：线性逻辑与数据流都打乱 ——
                //   ① 类型判定拆成 影子变量 + 一个恒真的复合条件，不再是一句 if type(...)；
                //   ② 元方法按随机顺序逐条挂，中间还插一条永远不会触发的诱饵（__eq / __concat）；
                //   ③ 用一个影子计数器 j 把「写毒表」前后串起来，末尾拿 j 与 pcall 的结果
                //      做一个恒假判断收尾（读起来像在判错，实际永远走 next_good）；
                //   ④ 表名、键名、标志位全部逐产物随机名。
                let g_e = rand_var();
                let g_t = rand_var();
                let g_flag = rand_var();
                let g_mt = rand_var();
                let (t70, t71) = sc_key("table");
                let sc_tab = st.call("table", t70, t71);
                let g_pk = rand_var();
                let g_j = rand_var();
                let g_ok = rand_var();
                let mut meta_lines: Vec<String> = Vec::new();
                let mut mms: Vec<&str> = vec!["tostring", "index", "newindex", "call"];
                for i in (1..mms.len()).rev() {
                    let j = rng.gen_range(0..=i);
                    mms.swap(i, j);
                }
                let decoy = if rng.gen_bool(0.5) { "eq" } else { "concat" };
                // 元方法名整串（含 __ 前缀）流加密；诱饵条目同样处理。
                let mm_call = |mm: &str, st: &mut StreamTable| -> String {
                    let (a, b) = sc_key(mm);
                    st.call(mm, a, b)
                };
                for (idx, mm) in mms.iter().enumerate() {
                    if idx == 2 {
                        meta_lines.push(format!("{}[{}]={};", g_mt, mm_call(decoy, &mut st), v_crash));
                    }
                    meta_lines.push(format!("{}[{}]={};", g_mt, mm_call(mm, &mut st), v_crash));
                }
                check_code = format!(
                    "local {e} = {env}; \
                     local {t} = type({e}); \
                     local {flag} = ({t} == {tab_lit}); \
                     local {mt} = {{}}; \
                     {meta} \
                     local {pk} = setmetatable({{}}, {mt}); \
                     local {j} = 0; \
                     if not {flag} and {t} ~= {tab_lit} then {bad} else \
                     {j} = {j} + 1; \
                     local {ok} = pcall(function() {e}[{dec}({h})] = {pk} end); \
                     {j} = {j} - 1; \
                     if {j} ~= 0 or {ok} == {j} then {bad} else {good} end \
                     end\n",
                    e = g_e, env = v_env, t = g_t, flag = g_flag, mt = g_mt,
                    meta = meta_lines.join(" "), pk = g_pk, j = g_j, ok = g_ok,
                    bad = next_bad, good = next_good, dec = v_dec, h = rand_hash,
                    tab_lit = sc_tab
                );
            }
            8 => {
                // ── 反美化守卫（anti-beautify）：三段管线版 ──
                // 判定分支与判定顺序跟旧的单段 if/elseif 链**逐条相同**：
                //   u/v 双路读数不一致 → bad；(l1-l1)+l1~=l2（f2/f3 的 linedefined）→ bad；
                //   报错行 tonumber 后 ~= 当前行 → bad；任何一步信息取不到 → good（fail-open）。
                // 改变的只是形态：「能力采样 → 测量 → 判定」拆成三个闭包，键乱序注册、
                // 逻辑序由顺序表驱动，数据全走闭包 upvalue —— 读起来不再是行号校验梯子。
                // 字符串照旧全走池（同一个池、同一批哈希），明文零新增。
                let (g_f1, g_f2, g_f3, g_q) = (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_d, g_gi, g_tn) = (rand_var(), rand_var(), rand_var());
                let (g_i1, g_i2, g_l1, g_l2) = (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_ok, g_msg, g_sp, g_ep, g_num) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                let (g_u, g_v, g_cur, g_clv) = (rand_var(), rand_var(), rand_var(), rand_var());
                // string 的成员在这个作用域里用到 4 次 => 先 local 出来再用。
                let (g_sb, g_sc, g_sf, g_ss) = (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_tp, g_pc, g_st) = (rand_var(), rand_var(), rand_var());
                let (g_ts_tab, g_ts_num, g_ts_fun, g_ts_str) =
                    (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_pt, g_po, g_pj, g_pr) = (rand_var(), rand_var(), rand_var(), rand_var());
                // 管线键（互异）+ 逻辑序表；注册时键与体配对洗牌，执行按 {po} 的逻辑序走。
                let (mut k_a, mut k_b, mut k_c) = (
                    rng.gen_range(0x1000..0xFFFF),
                    rng.gen_range(0x1000..0xFFFF),
                    rng.gen_range(0x1000..0xFFFF),
                );
                while k_b == k_a { k_b = rng.gen_range(0x1000..0xFFFF); }
                while k_c == k_a || k_c == k_b { k_c = rng.gen_range(0x1000..0xFFFF); }
                let (ka, kb, kc) = (
                    format!("0X{:X}", k_a),
                    format!("0X{:X}", k_b),
                    format!("0X{:X}", k_c),
                );
                let h_type = poly_hash("type");
                let h_debug = poly_hash("debug");
                let h_getinfo = poly_hash("getinfo");
                let h_tonumber = poly_hash("tonumber");
                let h_string = poly_hash("string");
                let h_table = poly_hash("table");
                let h_number = poly_hash("number");
                let h_function = poly_hash("function");
                let h_pcall = poly_hash("pcall");
                let h_S = poly_hash("S");
                let h_l = poly_hash("l");
                let h_ld = poly_hash("linedefined");
                let h_cur = poly_hash("currentline");
                let h_pat = poly_hash(":(%d+)[:\r\n ]");
                // ① 能力采样：解出 string/type/debug/pcall/tonumber 与类型名；逐项 fail-open。
                let phase_a = format!(
                    "{st}={res}({h_st}); {pc}={res}({h_pc}); {sb},{sc},{sf},{ss}={st}.byte,{st}.char,{st}.find,{st}.sub; {tp}={res}({h_tp}); {d}={res}({h_dbg}); {tb},{nm},{fn},{sg}={dec}({h_tb}),{dec}({h_nm}),{dec}({h_fn}),{dec}({h_sg}); if {tp}({d})~={tb} then {good} end; {gi}={d}[{dec}({h_gi})]; if {tp}({gi})~={fn} then {good} end; {tn}={res}({h_tn}); if {tp}({tn})~={fn} then {good} end; ",
                    st = g_st, res = v_res, h_st = h_string, pc = g_pc, h_pc = h_pcall,
                    sb = g_sb, sc = g_sc, sf = g_sf, ss = g_ss, tp = g_tp, h_tp = h_type,
                    d = g_d, h_dbg = h_debug, dec = v_dec,
                    tb = g_ts_tab, nm = g_ts_num, fn = g_ts_fun, sg = g_ts_str,
                    h_tb = h_table, h_nm = h_number, h_fn = h_function, h_sg = h_string,
                    good = next_good, gi = g_gi, h_gi = h_getinfo, tn = g_tn, h_tn = h_tonumber
                );
                // ② 测量：f2/f3 的 linedefined、f1 的报错行号（两种读法）、当前执行行。
                let phase_b = format!(
                    "{i1},{i2}={gi}({f2},{dec}({h_s})),{gi}({f3},{dec}({h_s})); if {tp}({i1})~={tb} or {tp}({i2})~={tb} then {good} end; {l1},{l2}={i1}[{dec}({h_ld})],{i2}[{dec}({h_ld})]; if {tp}({l1})~={nm} or {tp}({l2})~={nm} then {good} end; local {ok},{msg}={pc}({f1}); if {tp}({msg})~={sg} then {msg}=''  end; {sp},{ep},{num}={sf}({msg},{dec}({h_pat})); if not {sp} or not {ep} then {good} end; {u}={ss}({msg},{sp}+1,{ep}-1); {v}={sc}({sb}({msg},{sp}+1,{ep}-1)); local {cur}={gi}(1,{dec}({h_l})); {clv}={cur} and {cur}[{dec}({h_cl})]; ",
                    i1 = g_i1, i2 = g_i2, gi = g_gi, f2 = g_f2, f3 = g_f3, dec = v_dec,
                    h_s = h_S, tp = g_tp, tb = g_ts_tab, good = next_good,
                    l1 = g_l1, l2 = g_l2, h_ld = h_ld, nm = g_ts_num,
                    ok = g_ok, msg = g_msg, pc = g_pc, f1 = g_f1, sg = g_ts_str,
                    sp = g_sp, ep = g_ep, num = g_num, sf = g_sf, h_pat = h_pat,
                    u = g_u, ss = g_ss, v = g_v, sc = g_sc, sb = g_sb,
                    cur = g_cur, h_l = h_l, clv = g_clv, h_cl = h_cur
                );
                // ③ 判定：与旧链相同的四个分支，最后一个 {good} 收口（链继续/终止）。
                let phase_c = format!(
                    "if not {u} or not {v} then {good} end; if {u}~={v} then {bad} end; if ({l1}-{l1})+{l1}~={l2} then {bad} end; if {clv}~=nil and {tn}({num})~=nil and {tn}({num})~={clv} then {bad} end; {good}",
                    u = g_u, v = g_v, good = next_good, bad = next_bad,
                    l1 = g_l1, l2 = g_l2, clv = g_clv, tn = g_tn, num = g_num
                );
                // 注册乱序：键与体配对后洗牌；执行顺序由 {po}（逻辑序）决定。
                let mut reg: Vec<(String, String)> = vec![
                    (ka.clone(), phase_a),
                    (kb.clone(), phase_b),
                    (kc.clone(), phase_c),
                ];
                for iri in (1..reg.len()).rev() {
                    let jri = rng.gen_range(0..=iri);
                    reg.swap(iri, jri);
                }
                let reg_s = reg
                    .iter()
                    .map(|(kk, bb)| format!("[{}]=function() {} end", kk, bb))
                    .collect::<Vec<_>>()
                    .join(",");
                check_code = format!(
                    "local {sb},{sc},{sf},{ss},{tp},{d},{tb},{nm},{fn},{sg},{gi},{tn},{i1},{i2},{l1},{l2},{sp},{ep},{num},{u},{v},{clv}; local {f1}=function() local {q}=nil; return {q}[1] end; local {f2}=function() return 1 end; local {f3}=function() return 2 end; local {pt}={{{reg_s}}}; local {po}={{{ka},{kb},{kc}}}; for {pj}=1,0X3 do local {pr}={pt}[{po}[{pj}]](); if {pr}~=nil then return {pr} end end; {good}\n",
                    sb = g_sb, sc = g_sc, sf = g_sf, ss = g_ss, tp = g_tp, d = g_d,
                    tb = g_ts_tab, nm = g_ts_num, fn = g_ts_fun, sg = g_ts_str,
                    gi = g_gi, tn = g_tn, i1 = g_i1, i2 = g_i2, l1 = g_l1, l2 = g_l2,
                    sp = g_sp, ep = g_ep, num = g_num, u = g_u, v = g_v, clv = g_clv,
                    f1 = g_f1, q = g_q, f2 = g_f2, f3 = g_f3,
                    pt = g_pt, reg_s = reg_s, po = g_po, ka = ka, kb = kb, kc = kc,
                    pj = g_pj, pr = g_pr, good = next_good
                );
            }
            _ => {
                check_code = format!("{}\n", next_good);
            }
        }
        
        current_expected += delta;
        // 定义处也写派生形态：同一个键在定义点/调用点各是一个不同算式；
        // 状态推进语句块在最前（管线/链式两种形态都兼容）。
        let single_guard_raw = format!(
            "{}[{}]=function(k)\n{}{}end;\n",
            v_net, derived_num(keys[i], &mut rng), state_step, check_code
        );
        let minified_guard = minify_lua(&single_guard_raw);
        guards_code.push(minified_guard);
    }
    
    // 诱饵条目：形状与守卫一致（照样从池里取值、照样动状态），但不参与链条。
    for d in 0..2 {
        let kx = keys[n_guards + d];
        let probe = if d == 0 { "table" } else { "number" };
        guards_code.push(format!(
            "{}[{}]=function(k) local y={}({});{}={}*0X3+0X5;if y then return k end return k end;",
            v_net, derived_num(kx, &mut rng), v_res, poly_hash(probe), v_state, v_state
        ));
    }

    let v_jump = rand_var();
    let mut trigger = String::new();
    trigger.push_str(&format!(
        "{}={}[{}]({});\n",
        key_var, v_net, derived_num(keys[0], &mut rng), initial_token
    ));
    trigger.push_str(&format!(
        "local {} = setmetatable({{}}, {{ [{}] = function() return {} end }});\n",
        v_jump,
        {
            let (a, b) = sc_key("__index");
            st.call("__index", a, b)
        },
        v_crash
    ));
    trigger.push_str(&format!("{}[{}] = function() end;\n", v_jump, current_expected));
    trigger.push_str(&format!("{}[{}]();\n", v_jump, key_var));
    
    AntiTamperResult {
        setup: minify_lua(&setup),
        guards: guards_code,
        trigger: minify_lua(&trigger),
        expected_final: current_expected,
        st,
    }
}

fn minify_lua(code: &str) -> String {
    code.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>()
        .join(" ")
        .replace("= ", "=")
        .replace(" =", "=")
        .replace(" + ", "+")
        .replace(" - ", "-")
        .replace(" == ", "==")
        .replace(" ~= ", "~=")
}