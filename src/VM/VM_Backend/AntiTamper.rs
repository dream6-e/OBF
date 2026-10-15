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
    /// 供外层 `return({...})` 壳兄弟方法导出给 `wai` 守卫闭包捕获的 6 个局部名：
    /// `[v_env, v_dec, v_res, v_net, v_state, st.name]`。
    pub exports: [String; 6],
    /// 绑定的毒化旗变量名（供外层兄弟方法替换为回调闭包）。
    pub poison_var: String,
}

impl AntiTamperResult {
    /// 全部调用点注册完后调用：把键表渲染进 setup 状态机分支内。
    pub fn finish_setup(&mut self) {
        let st_assign = minify_lua(&self.st.emit_assign());
        self.setup = self.setup.replace("@ST_ASSIGN@", &st_assign);
    }
}

/// 守卫键/状态常量直接以十进制字面量发射，不再包装成可静态折叠的算式。
fn derived_num(val: u64, _rng: &mut impl Rng) -> String {
    val.to_string()
}

/// 状态迁移目标直接以字面量发射，不再拆成可静态折叠的乘加式。
fn opq_ident<T: Rng>(_rng: &mut T, target: u32) -> String {
    target.to_string()
}

/// 小型守卫常量直接发射。
fn opq_const<T: Rng>(_rng: &mut T, v: u32) -> String {
    v.to_string()
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

/// 四字节字符串流密钥；避免字符串字面量中的 NUL 密文转义。
fn sc_key(plain: &str) -> u32 {
    let mut r = thread_rng();
    loop {
        let q0 = r.gen_range(1..256u32);
        let q1 = r.gen_range(1..256u32);
        let q2 = r.gen_range(1..256u32);
        let q3 = r.gen_range(1..256u32);
        let key = (q0 << 24) | (q1 << 16) | (q2 << 8) | q3;
        if mix_encrypt(plain.as_bytes(), key).iter().all(|&c| c != 0) {
            return key;
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

pub fn generate_split(use_debug: bool, key_var: &str, poison_var: &str, vault: &mut crate::VM::VM_Backend::Generator_names::NameVault) -> AntiTamperResult {
    let mut rng = thread_rng();
    // ㉜ 明文 API 名全部改走 NB 槽（守卫/setup/trigger 都在 NB 建表之后运行）
    let v_getgenv = vault.global("getgenv");
    let v_root = vault.root();
    let v_type = vault.global("type");
    let v_pcall = vault.global("pcall");
    let v_tostring = vault.global("tostring");
    let v_setmeta = vault.global("setmetatable");
    let v_sbyte = vault.member("string", "byte");
    let v_schar = vault.member("string", "char");
    let v_sfind = vault.member("string", "find");
    let v_ssub = vault.member("string", "sub");
    let v_mfloor = vault.member("math", "floor");
    let v_typeof = vault.global("typeof");
    let v_raknet = vault.global("raknet");
    let v_error = vault.global("error");
    let v_print = vault.global("print");
    
    let v_env = rand_var();
    let v_net = rand_var();
    let v_tripwire = rand_var();
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
        // sethook 的调用掩码：原先以 string.char(99) 字面量出现，改走池取用
        "c".into(),
        ":(%d+)[:\r\n ]".into(),
        // ③ 陷阱门用：setmetatable(__index 元表陷阱)。凡 poly_hash 查池的串必须在此
        // 登记过，否则查表得 nil → 构造器 [nil]=… 直接「table index is nil」。
        "setmetatable".into(), "__index".into(),
    ];
    // 池级四字节密钥逐产物随机；所有条目共用一组，解码器只需要带一个常量。
    let pool_key = loop {
        let q0 = rng.gen_range(1..256u32);
        let q1 = rng.gen_range(1..256u32);
        let q2 = rng.gen_range(1..256u32);
        let q3 = rng.gen_range(1..256u32);
        let key = (q0 << 24) | (q1 << 16) | (q2 << 8) | q3;
        if strings.iter().all(|t| mix_encrypt(t.as_bytes(), key).iter().all(|&c| c != 0)) {
            break key;
        }
    };
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
        let enc: Vec<String> = mix_encrypt(s.as_bytes(), pool_key).iter().map(|c| c.to_string()).collect();
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
    let enc: Vec<String> = mix_encrypt(rand_str.as_bytes(), pool_key).iter().map(|c| c.to_string()).collect();
    pool_entries.push(format!("[{}]={{{}}}", rand_hash, enc.join(",")));
    
    let pool_data = pool_entries.join(",");

    // 自定义流加密键表（独立于池）：解码器匿名挂在表里（finish_setup 时渲染）。
    // 守卫体与 Generator 的解头/方法原型/body_consts 复用同一张表。
    let mut st = StreamTable::new(rand_var());
    st.set_decoder(crate::VM::VM_Backend::Generator_util::stream_dec_body_with(&v_mfloor, &v_sbyte, &v_schar));

    let v_dec = rand_var();
    let dec_fn = crate::VM::VM_Backend::Generator_util::emit_scrambled_mix_dec(
        Some((&v_pool, pool_key)),
        &v_sbyte,
        &v_schar,
    );

    let mut current_expected: i64 = rng.gen_range(1000..9999);
    let initial_token = current_expected;
    
    let mut guards_indices = vec![0, 1, 2, 3, 4, 5, 7, 8];
    shuffle_vec(&mut guards_indices);
    guards_indices.push(6);
    shuffle_vec(&mut guards_indices);

    // ── ③ 代码块互锁（紧密耦合 / 互相嵌合） ──
    // 随机子集探测只改变不透明令牌；最终失配置共享 poison，不给固定早退/报错点。
    // 缺失网表键由 __index 返回恒等闭包并置 poison；正常链路的令牌计算保持原样。
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

    // 顶层 setup 同样采用乱序跳表 + 二分判定树状态机，消除 m_at 首部线性序列
    let mut used_top_states: Vec<u32> = Vec::new();
    let mut top_ids: Vec<u32> = Vec::with_capacity(7);
    for _ in 0..7 {
        top_ids.push(rand_state(&mut rng, &mut used_top_states));
    }
    let mut top_phys: Vec<usize> = (1..=7).collect();
    shuffle_vec(&mut top_phys);
    let mut top_tbl_elems = vec![0u32; 7];
    for (logic_i, &p_slot) in top_phys.iter().enumerate() {
        top_tbl_elems[p_slot - 1] = top_ids[logic_i];
    }
    let top_tbl_var = rand_var();
    let top_st_var = rand_var();
    let trap_arg = rand_var();
    let rt_var = rand_var();

    let mut decl_names = vec![
        v_env.clone(),
        v_tripwire.clone(),
        v_pool.clone(),
        v_dec.clone(),
        v_res.clone(),
        v_net.clone(),
        v_state.clone(),
        st.name.clone(),
    ];
    for i in (1..decl_names.len()).rev() {
        let j = rng.gen_range(0..=i);
        decl_names.swap(i, j);
    }

    let tb0 = format!(
        "{env}=({gg} and {gg}()) or {rt} or {{}};{tw}=function(...) {psn}=true end;{st}={tbl}[{nx1}];",
        env = v_env, gg = v_getgenv, rt = v_root, tw = v_tripwire, psn = poison_var,
        st = top_st_var, tbl = top_tbl_var, nx1 = top_phys[1]
    );
    let tb1 = format!(
        "{pool}={{{pdata}}};@ST_ASSIGN@{st}={tbl}[{nx2}];",
        pool = v_pool, pdata = pool_data, st = top_st_var, tbl = top_tbl_var, nx2 = top_phys[2]
    );
    let tb2 = format!(
        "{dec}={dec_fn};{res}=function(h) local xc,yu=true;local s={dec}(h);if not s then return yu end;return xc and {env}[s] end;{st}={tbl}[{nx3}];",
        dec = v_dec, dec_fn = dec_fn, res = v_res, env = v_env,
        st = top_st_var, tbl = top_tbl_var, nx3 = top_phys[3]
    );
    let lit_rt_tab = vault.lit("table");
    let lit_rt_err = vault.lit("1%@");
    let lit_rt_luau = vault.lit("Luau");
    let tb3 = format!(
        "local {rt}=function(z,x,c,g,nt) local v,b,n,y,op={ltab},{lerr},0X0,{lluau};if n<=0.0 then op=z else op=x end;local te;local ui=nt;while ui==y do if not te then te=x else te=g end;if te~=nil then if z(te)~=v then c(b,n) else g(1) end end;break;end;end;{rt}({tof},{rk},{er},{pr},_VERSION);{vst}={s0};{st}={tbl}[{nx4}];",
        rt = rt_var, ltab = lit_rt_tab, lerr = lit_rt_err, lluau = lit_rt_luau,
        tof = v_typeof, rk = v_raknet, er = v_error, pr = v_print,
        vst = v_state, s0 = derived_num(state_at[0], &mut rng),
        st = top_st_var, tbl = top_tbl_var, nx4 = top_phys[4]
    );
    let tb4 = format!(
        "{net}={{}};{res}({h_sm})({net},{{[{dec}({h_ix})]=function(...) {psn}=true;return function({ta}) return {ta} end end}});{st}={tbl}[{nxe}];",
        net = v_net, res = v_res, h_sm = poly_hash("setmetatable"),
        dec = v_dec, h_ix = poly_hash("__index"), psn = poison_var, ta = trap_arg,
        st = top_st_var, tbl = top_tbl_var, nxe = top_phys[6]
    );
    let tb5 = format!(
        "{vst}=(({vst} or 0X0)*0X13+0X7)%4294967296;{st}={tbl}[{nx2}];",
        vst = v_state, st = top_st_var, tbl = top_tbl_var, nx2 = top_phys[2]
    );

    let mut top_branches: Vec<(u32, String)> = vec![
        (top_ids[0], tb0),
        (top_ids[1], tb1),
        (top_ids[2], tb2),
        (top_ids[3], tb3),
        (top_ids[4], tb4),
        (top_ids[5], tb5),
    ];
    top_branches.sort_by_key(|&(k, _)| k);
    let top_tree = crate::VM::VM_Backend::Generator_util::build_bst_dispatch(&top_branches, &top_st_var);
    let top_tbl_str = top_tbl_elems
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let setup = format!(
        "local {decls};local {tbl}={{{tbl_str}}};local {st}={tbl}[{nx0}];while {st}~={tbl}[{nxe}] do {tree} end;",
        decls = decl_names.join(","),
        tbl = top_tbl_var,
        tbl_str = top_tbl_str,
        st = top_st_var,
        nx0 = top_phys[0],
        nxe = top_phys[6],
        tree = top_tree
    );

    let mut guards_code = Vec::new();

    for i in 0..guards_indices.len() {
        let delta = rng.gen_range(10..99);
        let guard_type = guards_indices[i];

        // 每块入口先推进共享状态，并把「实算状态 − 本步应有状态」混进令牌：
        let st_m32 = "4294967296";
        let state_step = format!(
            "{}=({}*{}+{})%{};",
            v_state, v_state, derived_num(step_a[i], &mut rng), derived_num(step_b[i], &mut rng), st_m32
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
                let k_nil = sc_key("nil");
                let sc_nil = st.call("nil", k_nil);
                // 用哈希组精确取值校验，避免受 pairs 迭代 __index 失效的影响
                check_code = format!(
                    "local sc_val = 0; \
                     local chk = {{{}, {}, {}}}; \
                     for idx = 1, 3 do \
                         if {ty}({}(chk[idx])) ~= {nil_lit} then sc_val = sc_val + 1 end \
                     end; \
                     if sc_val ~= 3 then {} else {} end\n",
                    fnv_pcall, fnv_string, fnv_math, v_res, next_bad, next_good, nil_lit = sc_nil, ty = v_type
                );
            }
            1 => {
                let hash_pcall = poly_hash("pcall");
                // 元方法名整串加密（连 __ 前缀一起），键表挂的就是运行期解出来的名字。
                let mut mm_calls: Vec<String> = Vec::new();
                for mm in ["__add", "__sub", "__mul", "__call"] {
                    let key = sc_key(mm);
                    mm_calls.push(st.call(mm, key));
                }
                check_code = format!(
                    "local z = {sm}({{}}, {{ \
                        [{m0}]=function(a)return a end, \
                        [{m1}]=function(a)return a end, \
                        [{m2}]=function(a)return a end, \
                        [{m3}]=function(...)return ... end \
                     }}); \
                     local p={}({}); if not p then {} else \
                     local st,r=p(function() local x=z+z-z*z; local y=z(z); return x==z and y==z end); \
                     if not st or not r then {} else {} end end\n",
                    v_res, hash_pcall, next_bad, next_bad, next_good,
                    sm = v_setmeta,
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
                    let hash_c_mask = poly_hash("c");
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
                             local c = 0; local ok2 = p(sh, function() c=c+1 end, {}({})); \
                             if not ok2 then {} else \
                             local function tmp() end; tmp(); p(sh); \
                             if c < 1 then {} else {} end end end end end\n",
                        v_res, hash_debug, v_res, hash_pcall,
                        next_bad,
                        v_dec, hash_sethook, v_dec, hash_gethook,
                        v_dec, hash_info, next_good, next_bad,
                        next_bad,
                        v_dec, hash_c_mask,
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
                    let key = sc_key("table");
                    let sc_tab = st.call("table", key);
                    let sc_what = vault.lit("what");
                    check_code = format!(
                        "local d={}({}); local p={}({}); \
                         if not (d and p) then {} else \
                         local gi = d[{}({})]; \
                         if not gi then \
                             if d[{}({})] then {} else {} end \
                         else \
                             local ok, inf = p(gi, p); \
                             if not ok or {ty}(inf)~={tab_lit} then {} else \
                             local w=inf[{what_lit}]; local h={hp_seed}; \
                             for idx=1,#w do h=(h*{hp_mult}+{sb}(w,idx)+{hp_add})%{hm32} end; \
                             if h~={} then {} else {} end end end end\n",
                        v_res, hash_debug, v_res, hash_pcall,
                        next_bad,
                        v_dec, hash_getinfo,
                        v_dec, hash_info, next_good, next_bad,
                        next_bad,
                        hash_C, next_bad, next_good,
                        ty = v_type, sb = v_sbyte,
                        tab_lit = sc_tab, what_lit = sc_what,
                        hm32 = "4294967296",
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
                let key = sc_key("table");
                let sc_tab = st.call("table", key);
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
                    let key = sc_key(mm);
                    st.call(mm, key)
                };
                for (idx, mm) in mms.iter().enumerate() {
                    if idx == 2 {
                        meta_lines.push(format!("{}[{}]={};", g_mt, mm_call(decoy, &mut st), v_tripwire));
                    }
                    meta_lines.push(format!("{}[{}]={};", g_mt, mm_call(mm, &mut st), v_tripwire));
                }
                check_code = format!(
                    "local {e} = {env}; \
                     local {t} = {ty}({e}); \
                     local {flag} = ({t} == {tab_lit}); \
                     local {mt} = {{}}; \
                     {meta} \
                     local {pk} = {sm}({{}}, {mt}); \
                     local {j} = 0; \
                     if not {flag} and {t} ~= {tab_lit} then {bad} else \
                     {j} = {j} + 1; \
                     local {ok} = {pc}(function() {e}[{dec}({h})] = {pk} end); \
                     {j} = {j} - 1; \
                     if {j} ~= 0 or {ok} == {j} then {bad} else {good} end \
                     end\n",
                    e = g_e, env = v_env, t = g_t, flag = g_flag, mt = g_mt,
                    meta = meta_lines.join(" "), pk = g_pk, j = g_j, ok = g_ok,
                    bad = next_bad, good = next_good, dec = v_dec, h = rand_hash,
                    ty = v_type, sm = v_setmeta, pc = v_pcall,
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
                    "{st}={res}({h_st}); {pc}={res}({h_pc}); {members}; {tp}={res}({h_tp}); {d}={res}({h_dbg}); {tb},{nm},{fn},{sg}={dec}({h_tb}),{dec}({h_nm}),{dec}({h_fn}),{dec}({h_sg}); if {tp}({d})~={tb} then {good} end; {gi}={d}[{dec}({h_gi})]; if {tp}({gi})~={fn} then {good} end; {tn}={res}({h_tn}); if {tp}({tn})~={fn} then {good} end; ",
                    st = g_st, res = v_res, h_st = h_string, pc = g_pc, h_pc = h_pcall,
                    tp = g_tp, h_tp = h_type,
                    d = g_d, h_dbg = h_debug, dec = v_dec,
                    tb = g_ts_tab, nm = g_ts_num, fn = g_ts_fun, sg = g_ts_str,
                    h_tb = h_table, h_nm = h_number, h_fn = h_function, h_sg = h_string,
                    good = next_good, gi = g_gi, h_gi = h_getinfo, tn = g_tn, h_tn = h_tonumber,
                    members = format!("{sb},{sc},{sf},{ss}={vb},{vc},{vf},{vs}",
                        sb = g_sb, sc = g_sc, sf = g_sf, ss = g_ss,
                        vb = v_sbyte, vc = v_schar, vf = v_sfind, vs = v_ssub)
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
        
        // 抽样位由两个同时存活的局部对象地址哈希派生；不触碰用户 math.random 状态。
        let (gate_ok, gate_bit, gate_a, gate_b, gate_s, gate_h, gate_i) =
            (rand_var(), rand_var(), rand_var(), rand_var(), rand_var(), rand_var(), rand_var());
        let gate_seed = rng.gen_range(0x1000u64..0x7FFF_FF00u64);
        let sampled_check = format!(
            "local {ok},{bit}={pc}(function() local {a},{b}={{}},{{}};local {s}={ts}({a})..{ts}({b});local {h}=0X{seed:X};for {i}=1,#{s} do {h}=({h}*0X21+{sb}({s},{i}))%0X7FFFFF01 end;return {h}%0X2 end);if {ok} and {bit}==0X0 then {check} else {good} end;",
            ok = gate_ok, bit = gate_bit, a = gate_a, b = gate_b, s = gate_s, h = gate_h, i = gate_i,
            seed = gate_seed, check = check_code, good = next_good,
            pc = v_pcall, ts = v_tostring, sb = v_sbyte
        );
        current_expected += delta;
        // 状态推进始终执行；只有探测体随机选中时才检查环境，并将坏令牌继续沿链传播。
        let single_guard_raw = format!(
            "{}[{}]=function(k)\n{}{}end;\n",
            v_net, derived_num(keys[i], &mut rng), state_step, sampled_check
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
        "local {} = {}({{}}, {{ [{}] = function(...) {}=true; return function() end end }});\n",
        v_jump,
        v_setmeta,
        {
            let key = sc_key("__index");
            st.call("__index", key)
        },
        poison_var
    ));
    trigger.push_str(&format!("{}[{}] = function() end;\n", v_jump, current_expected));
    trigger.push_str(&format!("{}[{}]();\n", v_jump, key_var));
    
    let st_name = st.name.clone();
    AntiTamperResult {
        setup: minify_lua(&setup),
        guards: guards_code,
        trigger: minify_lua(&trigger),
        expected_final: current_expected,
        st,
        exports: [v_env, v_dec, v_res, v_net, v_state, st_name],
        poison_var: poison_var.to_string(),
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