use rand::{thread_rng, Rng};

use super::Generator_util::{mix_encrypt, mix_key, poly_hash};

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
        // 行号守卫用到的全局与模式串（守卫 8 保留 V2 的显式结构，只借池去明文）
        "tonumber".into(),
        ":(%d+)[:\r\n ]".into(),
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
        
        // 异常增量先抽出来：守卫 8 要用它算「异常档」的取值，不再只看拼好的语句。
        // 抽取顺序与以前一致（每轮正好一次），不影响其它随机量。
        let delta_bad = rng.gen_range(100..999);
        let next_bad = if i == guards_indices.len() - 1 {
            format!("return k-{}", delta_bad)
        } else {
            format!("return {}[{}](k-{})", v_net, i + 1, delta_bad)
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
                             local w={inf}[{dec}({h_what})]; local h=5381; \
                             for idx=1,#w do h=(h*33+string.byte(w,idx))%4294967296 end; \
                             if h~={hc} then {bad} else {good} end end end end\n",
                        res = v_res, h_dbg = hash_debug, h_pc = hash_pcall,
                        h_tp = poly_hash("type"), bad = next_bad, ok = rand_var(),
                        dec = v_dec, h_gi = hash_getinfo,
                        h_info = hash_info, good = next_good,
                        tp = rand_var(), inf = rand_var(), tb = format!("{}({})", v_dec, poly_hash("table")),
                        h_what = poly_hash("what"), hc = hash_C
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
                // ── 反美化守卫（anti-beautify）──
                // 产物整体写在极少的物理行里，所以「同一行上定义的函数」的 linedefined 必然相等，
                // pcall 捕获的错误消息里的行号、以及当前执行行也必须落在同一行。
                // 一旦被 beautifier / 格式化工具重排（每个语句一行），这些等式立刻不成立 → next_bad。
                // 取行号用的是用户给的写法：先 string.find 抓数字，再分别用 sub 与 char+byte 往返两次取值，
                // 两次不一致就说明行号被动过手脚。
                // 判据刻意不比较「错误行号 vs linedefined」——两者来源不同（错误消息 vs debug），
                // 在 Roblox 一类环境里格式可能有差异会误杀；改成比较同源的
                // 「错误行号 vs 当前执行行 currentline」，两边都在同一 chunk 里，行号口径一致。
                // 成员一律字符串键（压缩器的成员改名器会改点访问，见 §5.11）；
                // 任何一步取不到信息都直接放行，绝不误杀（没有 debug 库的环境也能跑）。
                let (g_f1, g_f2, g_f3, g_q) = (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_d, g_gi, g_i1, g_i2, g_l1, g_l2) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                let (g_ok, g_msg, g_sp, g_ep, g_num) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                let (g_u, g_v, g_tn, g_cur, g_cl) = (rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
                // string 的成员在这个作用域里用到 4 次 => 先 local 出来再用：既省体积
                // （`{st}.byte` 写四遍比四个短名长），也少四次表索引。
                let (g_sb, g_sc, g_sf, g_ss) = (rand_var(), rand_var(), rand_var(), rand_var());
                let (g_tp, g_pc, g_st) = (rand_var(), rand_var(), rand_var());
                // 类型名（table/number/function/string）也从池里解出来，同样不留明文。
                let (g_ts_tab, g_ts_num, g_ts_fun, g_ts_str) =
                    (rand_var(), rand_var(), rand_var(), rand_var());
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
                check_code = format!(
                    "local {st}={res}({h_st}); \
                     local {pc}={res}({h_pc}); \
                     local {sb},{sc},{sf},{ss}={st}.byte,{st}.char,{st}.find,{st}.sub; \
                     local {tp}={res}({h_tp}); \
                     local {d}={res}({h_dbg}); \
                     local {tb},{nm},{fn},{sg}={dec}({h_tb}),{dec}({h_nm}),{dec}({h_fn}),{dec}({h_sg}); \
                     local {f1}=function() local {q}=nil; return {q}[1] end; \
                     local {f2}=function() return 1 end; \
                     local {f3}=function() return 2 end; \
                     if {tp}({d})~={tb} then {good} else \
                     local {gi}={d}[{dec}({h_gi})]; \
                     if {tp}({gi})~={fn} then {good} else \
                     local {tn}={res}({h_tn}); \
                     if {tp}({tn})~={fn} then {good} else \
                     local {i1},{i2}={gi}({f2},{dec}({h_s})),{gi}({f3},{dec}({h_s})); \
                     if {tp}({i1})~={tb} or {tp}({i2})~={tb} then {good} else \
                     local {l1},{l2}={i1}[{dec}({h_ld})],{i2}[{dec}({h_ld})]; \
                     if {tp}({l1})~={nm} or {tp}({l2})~={nm} then {good} else \
                     local {ok},{msg}={pc}({f1}); \
                     if {tp}({msg})~={sg} then {msg}='' end; \
                     local {sp},{ep},{num}={sf}({msg},{dec}({h_pat})); \
                     if not {sp} or not {ep} then {good} else \
                     local {u}={ss}({msg},{sp}+1,{ep}-1); \
                     local {v}={sc}({sb}({msg},{sp}+1,{ep}-1)); \
                     local {cur}={gi}(1,{dec}({h_l})); \
                     local {clv}={cur} and {cur}[{dec}({h_cl})]; \
                     if not {u} or not {v} then {good} \
                     elseif {u}~={v} then {bad} \
                     elseif ({l1}-{l1})+{l1}~={l2} then {bad} \
                     elseif {clv}~=nil and {tn}({num})~=nil and {tn}({num})~={clv} then {bad} \
                     else {good} end end end end end end end\n",
                    sb = g_sb, sc = g_sc, sf = g_sf, ss = g_ss, st = g_st, h_st = h_string,
                    tp = g_tp, res = v_res, h_tp = h_type,
                    d = g_d, h_dbg = h_debug,
                    tb = g_ts_tab, nm = g_ts_num, fn = g_ts_fun, sg = g_ts_str,
                    h_tb = h_table, h_nm = h_number, h_fn = h_function, h_sg = h_string,
                    dec = v_dec, f1 = g_f1, q = g_q, f2 = g_f2, f3 = g_f3,
                    good = next_good, bad = next_bad, gi = g_gi, h_gi = h_getinfo,
                    tn = g_tn, h_tn = h_tonumber, i1 = g_i1, i2 = g_i2, h_s = h_S,
                    l1 = g_l1, l2 = g_l2, h_ld = h_ld, ok = g_ok, msg = g_msg, pc = g_pc,
                    h_pc = h_pcall, sp = g_sp, ep = g_ep, num = g_num, h_pat = h_pat,
                    u = g_u, v = g_v, cur = g_cur, h_l = h_l, clv = g_cl, h_cl = h_cur
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