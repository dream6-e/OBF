use rand::{thread_rng, Rng};

use super::Generator_util::{hash_params, mix_encrypt, mix_key, poly_hash, set_hash_params, HashParams};

pub struct AntiTamperResult {
    pub setup: String,
    pub guards: Vec<String>,
    pub trigger: String,
    pub expected_final: i64,
    /// 池解码器 / 池取全局 的函数名。同一份 chunk 里其它模块（如 packer 的探测代码）
    /// 要隐藏字符串时，直接引用这两个名字即可，不必自己再带一份表。
    pub dec_fn: String,
    pub res_fn: String,
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

fn shuffle_vec(vec: &mut Vec<usize>) {
    let mut rng = thread_rng();
    for i in (1..vec.len()).rev() {
        let j = rng.gen_range(0..=i);
        vec.swap(i, j);
    }
}

/// 把常量写成「运行期算出来」的形态（④ 能动态生成的就动态生成）：
/// `(0X<A>-0X<B>)` / `(0X<A>+0X<B>)` / `(0X<A>*0X2+0X<C>)`，
/// 三种写法求值都恰好等于 `val`，但产物里再也看不到 `val` 本身，
/// 同一个常量在不同位置也会被写成不同片段（无法搜索替换）。
/// 只用于守卫键 / 状态种子 / 增量这一类「必须存在但不必以字面量存在」的数字。
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
        // 全局 API 名
        "debug".into(), "pcall".into(), "sethook".into(), "gethook".into(), "getinfo".into(),
        "C".into(), "string".into(), "dump".into(), "error".into(), "info".into(), "math".into(),
        "type".into(), "setmetatable".into(), "getfenv".into(), "_G".into(), "byte".into(),
        // type() 的返回值：产物里不再出现 'table' / 'function' / 'number' / 'nil'
        "table".into(), "number".into(), "function".into(), "nil".into(),
        // 行号守卫（反美化）用到的选项与字段
        "S".into(), "l".into(), "linedefined".into(), "currentline".into(),
        // 成员键（`.what` 之类的点访问会被成员改名器盯上，统一走池 + 字符串键）
        "what".into(),
        // 元方法名（原来以 "__".."xxx" 拼接，一眼就是元表陷阱）
        "__index".into(), "__newindex".into(), "__tostring".into(), "__call".into(),
        "__add".into(), "__sub".into(), "__mul".into(), "__mode".into(),
        "__eq".into(), "__concat".into(), "k".into(),
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
    // ⑤ 池键哈希参数逐产物随机（把 djb2 的 5381/33 指纹抹掉）：
    //    多重抽几次参数，直到所有池条目的键互不相同（撞键会让池条目互相覆盖）。
    let _hp: HashParams = loop {
        let p = HashParams {
            mult: rng.gen_range(3..0x1_0000u32) | 1,
            add: rng.gen_range(0..0x1_0000u32),
            seed: rng.gen_range(0x1000..0x100000u32),
        };
        set_hash_params(p);
        let mut hs: Vec<u32> = strings.iter().map(|s| poly_hash(s)).collect();
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

    // 生成一个随机变量名用于毒药表（Poison Pill）注入
    let rand_hash = loop {
        let rs = random_string();
        let h = poly_hash(&rs);
        if !strings.iter().any(|s| poly_hash(s) == h) {
            break (rs, h);
        }
    };
    let rand_str = rand_hash.0;
    let rand_hash = rand_hash.1;
    let enc: Vec<String> = mix_encrypt(rand_str.as_bytes(), pk0, pk1).iter().map(|c| c.to_string()).collect();
    pool_entries.push(format!("[{}]={{{}}}", rand_hash, enc.join(",")));
    
    let pool_data = pool_entries.join(",");

    let mut setup = String::new();
    // 使用 getgenv() 完美适配 Roblox 执行器全局环境
    setup.push_str(&format!("local {} = getgenv and getgenv() or getfenv and getfenv() or _ENV or _G or {{}};\n", v_env));
    
    setup.push_str(&format!("local {} = {{{}}};\n", v_pool, pool_data));
    // 池解码器的「打乱线性逻辑 / 数据流」版本：
    //   ① 循环写成 while + 自增下标（数字 for 太规整）；下标先取出来再自己加；
    //   ② 解密算式写成 `(b - key + j - j) % 256`：j 是影子计数，前后抵消，
    //      但读起来像在参与运算；常量 key 与 256 也被埋进这条链里；
    //   ③ 拼接外面套一个恒真的判断（`(j+j)-j > 0` 即 j>0），打断线性阅读；
    //   ④ 全部局部变量逐产物随机名。纯冷路径（只在守卫/池查表时走），不吃性能。
    let d_e = rand_var();
    let d_i = rand_var();
    let d_n = rand_var();
    let d_out = rand_var();
    let d_chr = rand_var();
    let d_b = rand_var();
    let d_j = rand_var();
    let d_k1 = rand_var();
    let d_k0 = rand_var();
    let d_a = rand_var();
    let d_r = rand_var();
    let d_p = rand_var();
    let d_w = rand_var();
    let d_xb = rand_var();
    let d_yb = rand_var();
    setup.push_str(&format!(
        "local function {dec}(h) \
            local {e} = {pool}[h]; \
            if {e} == nil then return nil end; \
            local {k1} = {K} % 256; local {k0} = ({K} - {k1}) / 256; \
            local {i}, {n} = 0, #{e}; \
            local {chr}, {out} = string.char, ''; \
            local {j} = {j0}; \
            while {i} < {n} do \
                {i} = {i} + 1; \
                local {a} = ({k0} * {i} + {k1}) % 256; \
                local {b} = {e}[{i}]; \
                {j} = {j} + 1; \
                if ({j} + {j}) - {j} > 0 then \
                    local {r}, {p} = 0, 1; \
                    for {w} = 1, 8 do local {xb}, {yb} = {a} % 2, {b} % 2; \
                        if {xb} ~= {yb} then {r} = {r} + {p} end; \
                        {a} = ({a} - {xb}) / 2; {b} = ({b} - {yb}) / 2; {p} = {p} * 2; \
                    end; \
                    {out} = {out} .. {chr}(({r} - {k1}) % 256); \
                end; \
            end; \
            return {out}; \
        end;\n",
        dec = v_dec, e = d_e, pool = v_pool, i = d_i, n = d_n, chr = d_chr, out = d_out,
        j = d_j, j0 = rng.gen_range(1..64), b = d_b, k1 = d_k1, k0 = d_k0,
        a = d_a, r = d_r, p = d_p, w = d_w, xb = d_xb, yb = d_yb,
        K = format!("0X{:04X}", pool_key)
    ));
    setup.push_str(&format!(
        "local function {}(h) \
            local xc,yu=true;local s = {}(h); if not s then return yu end; \
             return xc and {}[s]; \
         end;\n",
         v_res, v_dec, v_env
    ));
    // 递归爆栈用的两个隐藏名：函数名 + 参数名，逐产物随机
    let fn_crash_rec = rand_var();
    let v_crash_arg = rand_var();
    // 纯物理爆栈导致卡死，无视 Roblox 的 string.rep / 内存上限等沙盒过滤。
    // 递归写成「把要递归的函数当参数传进去」的形式（`f(o) o(f,o)`），
    // 产物里看不到 `pcall(f)` 这种一眼可辨的图案。
    setup.push_str(&format!(
    "local function {}() \
        local j,s,k,v=_ENV,false;local t={{}};local p=type;if not k then v=s end;if p(t)~={dec}({h_tb}) then p=j end;repeat p={{}} until v; \
         local function {}({}) {}({},{}); {}({},{}) end \
         {}(pcall); \
     local function we(x) return not x end;local gd if we(gd) then while we(s) do end;end \
     end;\n",
    v_crash, fn_crash_rec, v_crash_arg, v_crash_arg, fn_crash_rec, v_crash_arg, v_crash_arg, fn_crash_rec, v_crash_arg, fn_crash_rec,
        dec = v_dec, h_tb = poly_hash("table")
));
    setup.push_str(&format!(
    "local rt=function(z,x,c,g,nt) local v,b,n,y,op=\"\\116\\97\\98\\108\\101\",\"\\49\\37\\64\",0X0,\"\\76\\117\\97\\117\";if n<=0.0 then op=z else op=x end;local te;local ui=nt;while ui==y do if not te then te=x else te=g end;if z(te)~=v then c(b,n) else g(1) end;break;end;end;rt(typeof,raknet,error,print,_VERSION);\n"
));
    // 网表的陷阱门：任何取不到的键（例如有人删掉/改掉了某一块的键，或自己构造下标来
    // 试探）都会返回爆栈函数 —— 表现为直接卡死，而不是抛一句读得懂的
    // 「attempt to call a nil value」暴露出结构。
    setup.push_str(&format!("local {}={{}};\n", v_net));
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
    //   ① 网表不再用 0/1/2… 这种顺序下标：每个守卫挂在一个随机 u32 键上，
    //      「下一块」也要靠链上的键去找 —— 光看代码看不出执行顺序；
    //   ② 全链共享一个运行期状态量 {state}：每块入口按自己的 (乘数, 加数) 推进它，
    //      并把「自己算出来的状态 − 这一步应有的状态」混进传给下一块的令牌里。
    //      链路完整时这一项恒为 0（令牌与以前一模一样）；少跑/改跑/换序任何一块，
    //      状态就对不上，令牌被污染 → 链尾自检失败 → 卡死。
    //      因为校正项是「自然抵消」而不是一句 if，产物里没有「检查状态」的痕迹；
    //   ③ 再挂两个不参与链的诱饵条目（同样带池取值、同样动状态），增加误导。
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

        // ③ 每块入口先推进共享状态，并把「实算状态 − 本步应有状态」混进传下去的令牌：
        //    链路完整 ⇒ 这一项恒为 0（令牌与不加它时逐位相同）；否则令牌被污染，
        //    一路带到链尾自检 → 不匹配 → 卡死。全程不出现「比较状态」的语句。
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

        // 异常增量先抽出来：守卫 8 要用它算「异常档」的取值，不再只看拼好的语句。
        // 抽取顺序与以前一致（每轮正好一次），不影响其它随机量。
        let delta_bad = rng.gen_range(100..999);
        let next_bad = if i == n_guards - 1 {
            format!("return k-{}{}", delta_bad, corr)
        } else {
            format!("return {}[{}](k-{}{})", v_net, next_key, delta_bad, corr)
        };
        
        let mut check_code = String::new();
        match guard_type {
            0 => {
                let fnv_pcall = poly_hash("pcall");
                let fnv_string = poly_hash("string");
                let fnv_math = poly_hash("math");
                // 用哈希组精确取值校验，避免受 pairs 迭代 __index 失效的影响
                // type 与 'nil' 都从池里取：产物里不再出现这两个字面量。
                check_code = format!(
                    "local {tp}={res}({h_tp}); local sc_val = 0; \
                     local chk = {{{}, {}, {}}}; \
                     for idx = 1, 3 do \
                         if {tp}({res}(chk[idx])) ~= {nil_} then sc_val = sc_val + 1 end \
                     end; \
                     if sc_val ~= 3 then {bad} else {good} end\n",
                    fnv_pcall, fnv_string, fnv_math,
                    tp = rand_var(), res = v_res, h_tp = poly_hash("type"),
                    nil_ = format!("{}({})", v_dec, poly_hash("nil")),
                    bad = next_bad, good = next_good
                );
            }
            1 => {
                let hash_pcall = poly_hash("pcall");
                let hash_sm = poly_hash("setmetatable");
                // 四个元方法名不再以 "__".."xxx" 拼接（那是一眼可见的元表陷阱），改从池里取。
                let (h_add, h_sub, h_mul, h_call) = (
                    poly_hash("__add"), poly_hash("__sub"), poly_hash("__mul"), poly_hash("__call"),
                );
                check_code = format!(
                    "local {sm}={res}({h_sm}); local p={res}({h_pc}); if not (p and {sm}) then {bad} else \
                     local z = {sm}({{}}, {{ \
                        [{dec}({h_add})]=function(q)return q end, \
                        [{dec}({h_sub})]=function(q)return q end, \
                        [{dec}({h_mul})]=function(q)return q end, \
                        [{dec}({h_call})]=function(...)return ... end \
                     }}); \
                     local st,r=p(function() local x=z+z-z*z; local y=z(z); return x==z and y==z end); \
                     if not st or not r then {bad} else {good} end end\n",
                    sm = rand_var(), h_sm = hash_sm, res = v_res, h_pc = hash_pcall,
                    dec = v_dec, h_add = h_add, h_sub = h_sub, h_mul = h_mul, h_call = h_call,
                    bad = next_bad, good = next_good
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
                    check_code = format!(
                        "local d={res}({h_dbg}); local p={res}({h_pc}); local {tp}={res}({h_tp}); \
                         if not (d and p) then {bad} else \
                         local gi = d[{dec}({h_gi})]; \
                         if not gi then \
                             if d[{dec}({h_info})] then {good} else {bad} end \
                         else \
                             local {ok},{inf} = p(gi, p); \
                             if not {ok} or {tp}({inf})~={tb} then {bad} else \
                             local w={inf}[{dec}({h_what})]; local h={hp_seed}; \
                             for idx=1,#w do h=(h*{hp_mult}+string.byte(w,idx)+{hp_add})%4294967296 end; \
                             if h~={hc} then {bad} else {good} end end end end\n",
                        res = v_res, h_dbg = hash_debug, h_pc = hash_pcall,
                        h_tp = poly_hash("type"), bad = next_bad, ok = rand_var(),
                        dec = v_dec, h_gi = hash_getinfo,
                        h_info = hash_info, good = next_good,
                        tp = rand_var(), inf = rand_var(), tb = format!("{}({})", v_dec, poly_hash("table")),
                        h_what = poly_hash("what"), hc = hash_C,
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
                let g_pk = rand_var();
                let g_j = rand_var();
                let g_ok = rand_var();
                let mut meta_lines: Vec<String> = Vec::new();
                let mut mms: Vec<String> = vec![
                    "__tostring".to_string(),
                    "__index".to_string(),
                    "__newindex".to_string(),
                    "__call".to_string(),
                ];
                for i in (1..mms.len()).rev() {
                    let j = rng.gen_range(0..=i);
                    mms.swap(i, j);
                }
                // 诱饵：一个永远不会触发的元方法（从池里取，同样是密文）
                let decoy = if rng.gen_bool(0.5) { "__eq" } else { "__concat" };
                for (idx, mm) in mms.iter().enumerate() {
                    if idx == 2 {
                        meta_lines.push(format!(
                            "{}[{}({})]={};",
                            g_mt, v_dec, poly_hash(decoy), v_crash
                        ));
                    }
                    meta_lines.push(format!("{}[{}({})]={};", g_mt, v_dec, poly_hash(mm), v_crash));
                }
                check_code = format!(
                    "local {e} = {env}; \
                     local {tp} = {res}({h_tp}); local {sm} = {res}({h_sm}); local {pc} = {res}({h_pc}); \
                     local {t} = {tp}({e}); \
                     local {flag} = ({t} == {tb}); \
                     local {mt} = {{}}; \
                     {meta} \
                     local {pk} = {sm}({{}}, {mt}); \
                     local {j} = 0; \
                     if not {flag} and {t} ~= {tb} then {bad} else \
                     {j} = {j} + 1; \
                     local {ok} = {pc}(function() {e}[{dec}({h})] = {pk} end); \
                     {j} = {j} - 1; \
                     if {j} ~= 0 or {ok} == {j} then {bad} else {good} end \
                     end\n",
                    e = g_e, env = v_env, t = g_t, flag = g_flag, mt = g_mt,
                    meta = meta_lines.join(" "), pk = g_pk, j = g_j, ok = g_ok,
                    res = v_res, h_tp = poly_hash("type"), h_sm = poly_hash("setmetatable"),
                    h_pc = poly_hash("pcall"), tp = rand_var(),
                    sm = rand_var(), pc = rand_var(), tb = format!("{}({})", v_dec, poly_hash("table")),
                    bad = next_bad, good = next_good, dec = v_dec, h = rand_hash
                );
            }
            8 => {
                // ── 隐式行号校验（反美化） ──
                // 判据还是「产物整体落在极少的物理行里」这件事，但表层写法刻意不留检查的痕迹：
                //   * 不用模式串、不用 string.find：自己按字节刮数字，且要求数字**紧跟冒号**
                //     （否则 /tmp/xxx2.lua 这类路径里的数字会被误当成行号）；字符串与全局名全从池里取；
                //   * 两路线号（错误消息里的行号、当前执行行）以及同一行上定义的 f2/f3 的
                //     linedefined，都被折进一个**残差** r：对得上 → r 恰为 0；
                //     对不上（被拆行）→ r 非 0；任何一步信息取不到（Roblox 之类环境）权重为 0、
                //     残差仍是 0 —— 天然放行，不需要任何 if 去写「取不到就放过」；
                //   * 全程没有一句「判断对错」：把 r*r 当表键，在「正常增量」与「异常增量」
                //     之间取值（r=0 时两个键重合，后写的那条生效），最后只看到一句
                //     `return 网表[i](k + 那个值)`。
                let (g_st, g_dbg, g_gi, g_pc, g_tp) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                let (g_nm, g_tb, g_fn, g_sg) = (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_ld, g_cl, g_so, g_lo) = (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_sb, g_f1, g_f2, g_f3, g_q) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                let (g_ok, g_msg, g_num, g_sn) = (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_i, g_n, g_pv, g_b, g_hit) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                let (g_p1, g_p2, g_p3, g_a1, g_a2, g_cv) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                let (g_w1, g_w2, g_w3, g_dx, g_dy) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                let (g_z, g_t, g_r, g_m) = (rand_var(), rand_var(), rand_var(), rand_var());
                let k_resid_a = rng.gen_range(3..=97);
                let k_resid_b = rng.gen_range(3..=97);
                let decoy_rounds = rng.gen_range(2..=6);
                let tail = if i == n_guards - 1 {
                    format!("return k+{m}[{r}*{r}]{corr}", m = g_m, r = g_r, corr = corr)
                } else {
                    format!(
                        "return {net}[{idx}](k+{m}[{r}*{r}]{corr})",
                        net = v_net, idx = next_key, m = g_m, r = g_r, corr = corr
                    )
                };
                check_code = format!(
                    "local {st}={res}({h_st}); \
                     local {dbg}={res}({h_dbg}); \
                     local {gi}={dbg} and {dbg}[{dec}({h_gi})]; \
                     local {pc}={res}({h_pc}); \
                     local {tp}={res}({h_tp}); \
                     local {nm},{tb},{fn},{sg}={dec}({h_nm}),{dec}({h_tb}),{dec}({h_fn}),{dec}({h_sg}); \
                     local {ld},{cl}={dec}({h_ld}),{dec}({h_cl}); \
                     local {so},{lo}={dec}({h_S}),{dec}({h_l}); \
                     local {sb}=({st} and {st}[{dec}({h_bt})]) or function() return 0 end; \
                     local {f1}=function() local {q}=nil; return {q}[1] end; \
                     local {f2}=function() return 1 end; \
                     local {f3}=function() return 2 end; \
                     local {ok},{msg}=false,''; \
                     if {pc} then {ok},{msg}={pc}({f1}); end; \
                     if {tp} and {tp}({msg})~={sg} then {msg}='' end; \
                     local {num},{sn},{i},{n},{pv}=0,0,0,#{msg},0; \
                     while {i}<{n} do \
                         {i}={i}+1; \
                         local {b}={sb}({msg},{i}); \
                         local {hit}=0; \
                         if {b}>47 and {b}<58 then {hit}=1 end; \
                         if {sn}==0 then \
                             if {hit}==1 and {pv}==58 then {sn}=1; {num}={b}-48 else {pv}={b} end \
                         elseif {sn}==1 then \
                             if {hit}==1 then {num}={num}*10+({b}-48) else {sn}=2 end \
                         end; \
                         if {sn}==2 then {i}={n} end; \
                     end; \
                     local {p1}={gi} and {gi}({f2},{so}) or nil; \
                     local {p2}={gi} and {gi}({f3},{so}) or nil; \
                     local {p3}={gi} and {gi}(1,{lo}) or nil; \
                     local {a1},{a2}={p1} and {p1}[{ld}],{p2} and {p2}[{ld}]; \
                     local {cv}={p3} and {p3}[{cl}]; \
                     local {w1}=({tp} and {tp}({a1})=={nm} and {tp}({a2})=={nm}) and 1 or 0; \
                     local {w2}=({tp} and {tp}({cv})=={nm}) and 1 or 0; \
                     local {w3}=({sn}>0) and 1 or 0; \
                     local {dx}=({a1} or 0)-({a2} or 0); \
                     local {dy}={num}-({cv} or 0); \
                     local {z}=0; \
                     for {t}=1,{rounds} do {z}={z}+({t}%1) end; \
                     local {r}={w1}*{dx}*{dx}*{ka}+{w2}*{w3}*{dy}*{dy}*{kb}+{z}+(k-k); \
                     local {m}={{[{r}*{r}]={badv},[0]={goodv}}}; \
                     {tail}\n",
                    st = g_st, res = v_res, h_st = poly_hash("string"),
                    dbg = g_dbg, h_dbg = poly_hash("debug"),
                    gi = g_gi, dec = v_dec, h_gi = poly_hash("getinfo"),
                    pc = g_pc, h_pc = poly_hash("pcall"),
                    tp = g_tp, h_tp = poly_hash("type"),
                    nm = g_nm, tb = g_tb, fn = g_fn, sg = g_sg,
                    h_nm = poly_hash("number"), h_tb = poly_hash("table"),
                    h_fn = poly_hash("function"), h_sg = poly_hash("string"),
                    ld = g_ld, cl = g_cl, h_ld = poly_hash("linedefined"), h_cl = poly_hash("currentline"),
                    so = g_so, lo = g_lo, h_S = poly_hash("S"), h_l = poly_hash("l"),
                    sb = g_sb, h_bt = poly_hash("byte"),
                    f1 = g_f1, q = g_q, f2 = g_f2, f3 = g_f3,
                    ok = g_ok, msg = g_msg, num = g_num, sn = g_sn,
                    i = g_i, n = g_n, pv = g_pv, b = g_b, hit = g_hit,
                    p1 = g_p1, p2 = g_p2, p3 = g_p3, a1 = g_a1, a2 = g_a2, cv = g_cv,
                    w1 = g_w1, w2 = g_w2, w3 = g_w3, dx = g_dx, dy = g_dy,
                    z = g_z, t = g_t, r = g_r, m = g_m,
                    rounds = decoy_rounds,
                    ka = format!("0X{:04X}", k_resid_a), kb = format!("0X{:04X}", k_resid_b),
                    goodv = delta, badv = format!("-{}", delta_bad),
                    tail = tail
                );
            }
            _ => {
                check_code = format!("{}\n", next_good);
            }
        }
        
        current_expected += delta;
        // 定义处也写派生形态：同一个键在定义点/调用点各是一个不同的算式，
        // 文本搜索对不上号；键值本身在产物里从头到尾没有字面量。
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
        "local {} = setmetatable({{}}, {{ [{}({})] = function() return {} end }});\n",
        v_jump, v_dec, poly_hash("__index"), v_crash
    ));
    trigger.push_str(&format!("{}[{}] = function() end;\n", v_jump, current_expected));
    trigger.push_str(&format!("{}[{}]();\n", v_jump, key_var));
    
    AntiTamperResult {
        setup: minify_lua(&setup),
        guards: guards_code,
        trigger: minify_lua(&trigger),
        expected_final: current_expected,
        dec_fn: v_dec,
        res_fn: v_res,
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