use rand::{thread_rng, Rng};

pub struct AntiTamperResult {
    pub setup: String,
    pub guards: Vec<String>,
    pub trigger: String,
    pub expected_final: i64,
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

    let key: u8 = rng.gen_range(10..240);

    // 将所有敏感 API 存入基于哈希的加密池
    let strings = vec![
        "debug", "pcall", "sethook", "gethook", "getinfo", "C", "string", "dump", "error", "info", "math"
    ];
    let mut pool_entries = Vec::new();
    for s in &strings {
        let hash = poly_hash(s);
        let enc: Vec<String> = s.bytes().map(|b| ((b as u16 + key as u16) % 256).to_string()).collect();
        pool_entries.push(format!("[{}]={{{}}}", hash, enc.join(",")));
    }
    
    // 生成一个随机变量名用于毒药表（Poison Pill）注入
    let rand_str = random_string();
    let rand_hash = poly_hash(&rand_str);
    let enc: Vec<String> = rand_str.bytes().map(|b| ((b as u16 + key as u16) % 256).to_string()).collect();
    pool_entries.push(format!("[{}]={{{}}}", rand_hash, enc.join(",")));
    
    let pool_data = pool_entries.join(",");

    let mut setup = String::new();
    // 使用 getgenv() 完美适配 Roblox 执行器全局环境
    setup.push_str(&format!("local {} = getgenv and getgenv() or getfenv and getfenv() or _ENV or _G or {{}};\n", v_env));
    
    // 递归爆栈用的两个隐藏名：函数名 + 参数名，逐产物随机
    let fn_crash_rec = rand_var();
    let v_crash_arg = rand_var();
    // 纯物理爆栈导致卡死，无视 Roblox 的 string.rep / 内存上限等沙盒过滤。
    // 递归写成「把要递归的函数当参数传进去」的形式（`f(o) o(f,o)`），
    // 产物里看不到 `pcall(f)` 这种一眼可辨的图案。
    setup.push_str(&format!(
    "local function {}() \
        local j,s,k,v=_ENV,false;local t={{}};local p=type;if not k then v=s end;if p(t)~=\"table\" then p=j end;repeat p={{}} until v; \
         local function {}({}) {}({},{}); {}({},{}) end \
         {}(pcall); \
     local function we(x) return not x end;local gd if we(gd) then while we(s) do end;end \
     end;\n",
    v_crash, fn_crash_rec, v_crash_arg, v_crash_arg, fn_crash_rec, v_crash_arg, v_crash_arg, fn_crash_rec, v_crash_arg, fn_crash_rec
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
    setup.push_str(&format!(
        "local function {dec}(h) \
            local {e} = {pool}[h]; \
            if {e} == nil then return nil end; \
            local {i}, {n} = 0, #{e}; \
            local {chr}, {out} = string.char, ''; \
            local {j} = {j0}; \
            while {i} < {n} do \
                {i} = {i} + 1; \
                local {b} = {e}[{i}]; \
                {j} = {j} + 1; \
                if ({j} + {j}) - {j} > 0 then \
                    {out} = {out} .. {chr}(({b} - {k} + {j} - {j}) % 256); \
                end; \
            end; \
            return {out}; \
        end;\n",
        dec = v_dec, e = d_e, pool = v_pool, i = d_i, n = d_n, chr = d_chr, out = d_out,
        j = d_j, j0 = rng.gen_range(1..64), b = d_b, k = key as i64
    ));
    setup.push_str(&format!(
        "local function {}(h) \
            local xc,yu=true;local s = {}(h); if not s then return yu end; \
             return xc and {}[s]; \
         end;\n",
         v_res, v_dec, v_env
    ));
    setup.push_str(&format!(
    "local rt=function(z,x,c,g,nt) local v,b,n,y,op=\"\\116\\97\\98\\108\\101\",\"\\49\\37\\64\",0x0,\"\\76\\117\\97\\117\";if n<=0.0 then op=z else op=x end;local te;local ui=nt;while ui==y do if not te then te=x else te=g end;if z(te)~=v then c(b,n) else g(1) end;break;end;end;rt(typeof,raknet,error,print,_VERSION);\n"
));
    setup.push_str(&format!("local {}={{}};\n", v_net));

    let mut current_expected: i64 = rng.gen_range(1000..9999);
    let initial_token = current_expected;
    
    let mut guards_indices = vec![0, 1, 2, 3, 4, 5, 7];
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
                // 用哈希组精确取值校验，避免受 pairs 迭代 __index 失效的影响
                check_code = format!(
                    "local sc_val = 0; \
                     local chk = {{{}, {}, {}}}; \
                     for idx = 1, 3 do \
                         if type({}(chk[idx])) ~= 'nil' then sc_val = sc_val + 1 end \
                     end; \
                     if sc_val ~= 3 then {} else {} end\n",
                    fnv_pcall, fnv_string, fnv_math, v_res, next_bad, next_good
                );
            }
            1 => {
                let hash_pcall = poly_hash("pcall");
                check_code = format!(
                    "local z = setmetatable({{}}, {{ \
                        [\"__\"..\"add\"]=function(a)return a end, \
                        [\"__\"..\"sub\"]=function(a)return a end, \
                        [\"__\"..\"mul\"]=function(a)return a end, \
                        [\"__\"..\"call\"]=function(...)return ... end \
                     }}); \
                     local p={}({}); if not p then {} else \
                     local st,r=p(function() local x=z+z-z*z; local y=z(z); return x==z and y==z end); \
                     if not st or not r then {} else {} end end\n",
                    v_res, hash_pcall, next_bad, next_bad, next_good
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
                        "local d={}({}); local p={}({}); \
                         if not (d and p) then {} else \
                         local gi = d[{}({})]; \
                         if not gi then \
                             if d[{}({})] then {} else {} end \
                         else \
                             local ok, inf = p(gi, p); \
                             if not ok or type(inf)~='table' then {} else \
                             local w=inf.what; local h=5381; \
                             for idx=1,#w do h=(h*33+string.byte(w,idx))%4294967296 end; \
                             if h~={} then {} else {} end end end end\n",
                        v_res, hash_debug, v_res, hash_pcall,
                        next_bad,
                        v_dec, hash_getinfo,
                        v_dec, hash_info, next_good, next_bad,
                        next_bad,
                        hash_C, next_bad, next_good
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
                let mut mms: Vec<&str> = vec!["tostring", "index", "newindex", "call"];
                for i in (1..mms.len()).rev() {
                    let j = rng.gen_range(0..=i);
                    mms.swap(i, j);
                }
                let decoy = if rng.gen_bool(0.5) { "eq" } else { "concat" };
                for (idx, mm) in mms.iter().enumerate() {
                    if idx == 2 {
                        meta_lines.push(format!("{}[\"__\"..\"{}\"]={};", g_mt, decoy, v_crash));
                    }
                    meta_lines.push(format!("{}[\"__\"..\"{}\"]={};", g_mt, mm, v_crash));
                }
                check_code = format!(
                    "local {e} = {env}; \
                     local {t} = type({e}); \
                     local {flag} = ({t} == 'table'); \
                     local {mt} = {{}}; \
                     {meta} \
                     local {pk} = setmetatable({{}}, {mt}); \
                     local {j} = 0; \
                     if not {flag} and {t} ~= 'table' then {bad} else \
                     {j} = {j} + 1; \
                     local {ok} = pcall(function() {e}[{dec}({h})] = {pk} end); \
                     {j} = {j} - 1; \
                     if {j} ~= 0 or {ok} == {j} then {bad} else {good} end \
                     end\n",
                    e = g_e, env = v_env, t = g_t, flag = g_flag, mt = g_mt,
                    meta = meta_lines.join(" "), pk = g_pk, j = g_j, ok = g_ok,
                    bad = next_bad, good = next_good, dec = v_dec, h = rand_hash
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
        "local {} = setmetatable({{}}, {{ [\"__\"..\"index\"] = function() return {} end }});\n",
        v_jump, v_crash
    ));
    trigger.push_str(&format!("{}[{}] = function() end;\n", v_jump, current_expected));
    trigger.push_str(&format!("{}[{}]();\n", v_jump, key_var));
    
    AntiTamperResult {
        setup: minify_lua(&setup),
        guards: guards_code,
        trigger: minify_lua(&trigger),
        expected_final: current_expected,
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