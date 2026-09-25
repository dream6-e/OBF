use rand::{thread_rng, Rng};

use super::Generator_util::{mix_encrypt, mix_key, stream_call, stream_dec_lua};

pub struct AntiTamperResult {
    pub setup: String,
    pub guards: Vec<String>,
    pub trigger: String,
    pub expected_final: i64,
    /// 流加密解码器的函数名（在 setup 里定义、chunk 顶层作用域）。
    /// Generator 的解头/方法原型/body_consts 与守卫同作用域，直接复用这一只。
    pub sc_fn: String,
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

fn poly_hash(s: &str) -> u32 {
    let mut h: u64 = 5381;
    for b in s.bytes() {
        h = (h * 33 + b as u64) % 4294967296;
    }
    h as u32
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
    let mut pool_entries = Vec::new();
    for s in &strings {
        let hash = poly_hash(s);
        let enc: Vec<String> = mix_encrypt(s.as_bytes(), pk0, pk1).iter().map(|c| c.to_string()).collect();
        pool_entries.push(format!("[{}]={{{}}}", hash, enc.join(",")));
    }

    // 生成一个随机变量名用于毒药表（Poison Pill）注入
    let rand_str = random_string();
    let rand_hash = poly_hash(&rand_str);
    let enc: Vec<String> = mix_encrypt(rand_str.as_bytes(), pk0, pk1).iter().map(|c| c.to_string()).collect();
    pool_entries.push(format!("[{}]={{{}}}", rand_hash, enc.join(",")));
    
    let pool_data = pool_entries.join(",");

    let mut setup = String::new();
    // 使用 getgenv() 完美适配 Roblox 执行器全局环境
    setup.push_str(&format!("local {} = getgenv and getgenv() or getfenv and getfenv() or _ENV or _G or {{}};\n", v_env));

    // 自定义流加密解码器（独立于池）：守卫体与 Generator 的解头/方法原型共用这一只。
    // 定义放 setup 最前（chunk 顶层作用域），后面所有部件都能看到。
    let sc_fn = rand_var();
    setup.push_str(&stream_dec_lua(&sc_fn));

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
        stream_call(&sc_fn, "table", a, b)
    }
));
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
    setup.push_str(&format!(
    "local rt=function(z,x,c,g,nt) local v,b,n,y,op=\"\\116\\97\\98\\108\\101\",\"\\49\\37\\64\",0X0,\"\\76\\117\\97\\117\";if n<=0.0 then op=z else op=x end;local te;local ui=nt;while ui==y do if not te then te=x else te=g end;if z(te)~=v then c(b,n) else g(1) end;break;end;end;rt(typeof,raknet,error,print,_VERSION);\n"
));
    setup.push_str(&format!("local {}={{}};\n", v_net));

    let mut current_expected: i64 = rng.gen_range(1000..9999);
    let initial_token = current_expected;
    
    let mut guards_indices = vec![0, 1, 2, 3, 4, 5, 7, 8];
    shuffle_vec(&mut guards_indices);
    guards_indices.push(6);
    shuffle_vec(&mut guards_indices);
    
    let mut guards_code = Vec::new();
    
    for i in 0..guards_indices.len() {
        let delta = rng.gen_range(10..99);
        let guard_type = guards_indices[i];
        
        let next_good = if i == guards_indices.len() - 1 {
            format!("return k+{}", delta)
        } else {
            format!("return {}[{}](k+{})", v_net, i + 1, delta)
        };
        
        let next_bad = if i == guards_indices.len() - 1 {
            format!("return k-{}", rng.gen_range(100..999))
        } else {
            format!("return {}[{}](k-{})", v_net, i + 1, rng.gen_range(100..999))
        };
        
        let mut check_code = String::new();
        match guard_type {
            0 => {
                let fnv_pcall = poly_hash("pcall");
                let fnv_string = poly_hash("string");
                let fnv_math = poly_hash("math");
                let (k0n, k1n) = sc_key("nil");
                let sc_nil = stream_call(&sc_fn, "nil", k0n, k1n);
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
                    mm_calls.push(stream_call(&sc_fn, mm, a, b));
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
                    let sc_tab = stream_call(&sc_fn, "table", t0, t1);
                    check_code = format!(
                        "local d={}({}); local p={}({}); \
                         if not (d and p) then {} else \
                         local gi = d[{}({})]; \
                         if not gi then \
                             if d[{}({})] then {} else {} end \
                         else \
                             local ok, inf = p(gi, p); \
                             if not ok or type(inf)~={tab_lit} then {} else \
                             local w=inf.what; local h=5381; \
                             for idx=1,#w do h=(h*33+string.byte(w,idx))%4294967296 end; \
                             if h~={} then {} else {} end end end end\n",
                        v_res, hash_debug, v_res, hash_pcall,
                        next_bad,
                        v_dec, hash_getinfo,
                        v_dec, hash_info, next_good, next_bad,
                        next_bad,
                        hash_C, next_bad, next_good,
                        tab_lit = sc_tab
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
                let sc_tab = stream_call(&sc_fn, "table", t70, t71);
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
                let mm_call = |mm: &str| -> String {
                    let (a, b) = sc_key(mm);
                    stream_call(&sc_fn, mm, a, b)
                };
                for (idx, mm) in mms.iter().enumerate() {
                    if idx == 2 {
                        meta_lines.push(format!("{}[{}]={};", g_mt, mm_call(decoy), v_crash));
                    }
                    meta_lines.push(format!("{}[{}]={};", g_mt, mm_call(mm), v_crash));
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
        let single_guard_raw = format!("{}[{}]=function(k)\n{}end;\n", v_net, i, check_code);
        let minified_guard = minify_lua(&single_guard_raw);
        guards_code.push(minified_guard);
    }
    
    let v_jump = rand_var();
    let mut trigger = String::new();
    trigger.push_str(&format!("{}={}[0]({});\n", key_var, v_net, initial_token));
    trigger.push_str(&format!(
        "local {} = setmetatable({{}}, {{ [{}] = function() return {} end }});\n",
        v_jump,
        {
            let (a, b) = sc_key("__index");
            stream_call(&sc_fn, "__index", a, b)
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
        sc_fn,
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