//! Generator_chain 的后半段：原型解码状态机（body_init/insts/consts/protos/debug/ret）、
//! 行完整性守卫、Part 洗牌拼接与最外层启动壳。
//! 从 Generator_chain.rs 拆出（守单文件 80 KB 上限，保持两文件各约 42 KB）。

use super::Generator_util::{ControlFlowBuilder, GenRng};
use super::Generator_chain::{ChainIn, ChainMid};

#[allow(unused_variables, unused_mut)]
pub(super) fn build_chain_tail(mid: ChainMid) -> String {
    let ChainMid {
        x,
        h_var,
        block_chacha_setup,
        ds_names,
        dn_names,
        salt_names,
        root_fetch,
        kdf_name,
        cluster_parts,
        kc,
        kt_name,
        pj_name,
        block_dec_header,
        block_dec_helpers,
        block_dec_readers,
    } = mid;
    let ChainIn {
        rng: mut rng, at: mut at, keys, enc,
        sigma,
        fn_a3,
        fn_bxor,
        fn_c,
        fn_decode_chunk,
        fn_s_byte,
        fn_s_sub,
        pf_a_arr,
        pf_b_arr,
        pf_c_arr,
        pf_is_vararg,
        pf_ld,
        pf_lld,
        pf_maxstack,
        pf_n,
        pf_numparams,
        pf_nups,
        pf_opcodes,
        pf_protos,
        psn_n,
        poison_delay_key,
        var_a2,
        var_whiten,
        var_whiten_pos,
        whiten_mul,
        whiten_add,
        var_builtin_reg,
        np21,
        md21,
        th21,
        tw21,
        rk21,
        kreg_n,
        fn_execute,
        bc_kb,
        bc_kc,
        bc_ki1,
        bc_ki2,
        chain_delta,
        chain_m,
        chain_k0,
        pm_r0,
        pm_r1,
        pm_r2,
        pm_r3,
        sc_add,
        sc_add_k1,
        sc_mul_k2,
        sc_rot_in,
        sc_rot_k2,
        sc_rot_k4,
        pm_s,
        tag_map18,
        fc18,
        block_decoder_script,
        block_execute_def,
        block_methods,
        block_p_def,
        block_packer_vars,
        block_vm_core,
        entry_func,
        fn_a10,
        fn_a5,
        fn_b_rotr,
        fn_qr,
        fn_read_dec,
        fn_read_string,
        fn_rotl32,
        fn_u32_dec,
        fn_xor32,
        header_block,
        key_seed_var,
        payload_str,
        pf_cnt18,
        pf_consts,
        sk_setup,
        t,
        x,
        const_path_key,
        var_boot_env,
        var_l,
        var_state_flag,
        wai,
        xor_tbl_var,
        weld: mut weld,
        uni: mut uni,
        ..
    } = x;
    let poison_delay_expr = format!("{}[0X{:X}]", kreg_n, poison_delay_key);
    let poison_ks = |rng: &mut GenRng, ks: &str| -> String {
        let k1 = rng.range(0x100, 0xFFFF) as u32;
        let k2 = rng.range(0x100, 0xFFFF) as u32;
        match rng.range(0, 4) {
            0 => format!("if {psn} and {delay}<=0 then {ks}[0X1]=(0X{k:X}-{ks}[0X1])%0X100 end; ", psn = psn_n, delay = poison_delay_expr, ks = ks, k = k1),
            1 => format!("if {psn} and {delay}<=0 then local {z}=#{ks} while {z}>0X0 do {ks}[{z}]=(0X{k:X}-{ks}[{z}])%0X100; {z}={z}-0X1 end end; ", psn = psn_n, delay = poison_delay_expr, ks = ks, k = k1, z = rng.name()),
            2 => format!("if {psn} and {delay}<=0 then {ks}[0X1]=({ks}[0X1]+0X{k:X})%0X100; {ks}[#{ks}]=(0X{k2:X})%0X100 end; ", psn = psn_n, delay = poison_delay_expr, ks = ks, k = k1, k2 = k2),
            _ => format!("if {psn} and {delay}<=0 then for {z}=0X1,#{ks} do {ks}[{z}]=({ks}[{z}]*0X{k:X}+0X{k2:X})%0X100 end end; ", psn = psn_n, delay = poison_delay_expr, ks = ks, k = k1, k2 = k2, z = rng.name()),
        }
    };
    let bind2 = |rng: &mut GenRng, dst: &str, n0: &str, n1: &str| -> String {
        let (a, b) = if rng.range(0, 2) == 0 { (n0, n1) } else { (n1, n0) };
        match rng.range(0, 3) {
            0 => format!("{d}={b}; if ({h}%0X2)==0X0 then {d}={a} end; ", d = dst, a = a, b = b, h = h_var),
            1 => format!("if ({h}%0X2)==0X0 then {d}={a} else {d}={b} end; ", d = dst, a = a, b = b, h = h_var),
            _ => format!("local {t}={{{a},{b}}}; {d}={t}[({h}%0X2)+0X1]; ", d = dst, a = a, b = b, h = h_var, t = rng.name()),
        }
    };
    let mk_m = |_rng: &mut GenRng| -> String { "4294967296".to_string() };
    let mk_rounds = |rng: &mut GenRng, qrn: &str, ly: &crate::VM::VM_Backend::Generator_chacha::ChaChaLayout| -> String {
        let mut cols: Vec<(u32, u32, u32, u32)> = vec![(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15)];
        let mut dias: Vec<(u32, u32, u32, u32)> = vec![(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)];
        rng.shuffle(&mut cols); rng.shuffle(&mut dias);
        let mut ents: Vec<String> = Vec::new();
        for &(a, b, c, d) in cols.iter().chain(dias.iter()) {
            let m = |v: u32| (ly.rho[v as usize] + 1) as u32;
            let f = |rng: &mut GenRng, v: u32| -> String { rng.format_num(v as i64) };
            ents.push(format!("{{{},{},{},{}}}", f(rng, m(a)), f(rng, m(b)), f(rng, m(c)), f(rng, m(d))));
        }
        let (tv, iv, ev) = (rng.name(), rng.name(), rng.name());
        let rounds = (ly.rounds / 2) as u32;
        format!(
            "local {tv}={{{ents}}}; for _=1,{rounds} do for {iv}=1,#{tv} do local {ev}={tv}[{iv}]; {qrn}({sv},{ev}[1],{ev}[2],{ev}[3],{ev}[4]) end end; ",
            tv = tv, iv = iv, ev = ev, ents = ents.join(","), qrn = qrn, sv = "s", rounds = rounds)
    };
// ⑰ 中央字符串/数值池初始化块废除（池不存在了）。⑦ 的 while/repeat
        // 抽签壳保留在 body_ret/body_debug；池壳随池一起退役。
        let var_enc_c = rng.name();
        let var_tbl = rng.name();
        let var_idx_chunk = rng.name();
        let var_e = rng.name();
        let var_cache = rng.name();

        let var_state = rng.name();
        let s_init = rng.range(0x100, 0xFFF) as i64;
        let s_insts = rng.range(0x1000, 0x1FFF) as i64;
        let s_consts = rng.range(0x2000, 0x2FFF) as i64;
        let s_protos = rng.range(0x3000, 0x3FFF) as i64;
        let s_debug = rng.range(0x4000, 0x4FFF) as i64;
        let s_ret = rng.range(0x5000, 0x5FFF) as i64;

        let obf_s_init = rng.format_num(s_init);
        let obf_s_insts = rng.format_num(s_insts);
        let obf_s_consts = rng.format_num(s_consts);
        let obf_s_protos = rng.format_num(s_protos);
        let obf_s_debug = rng.format_num(s_debug);
        let obf_s_ret = rng.format_num(s_ret);
        
        // ── 状态机（第 6 项：解密逻辑打乱）──
        // 原形态：if state==A then <体>
        // 状态推进总在体尾，一眼就是「顺序状态机」。现在：
        //   ① 六个状态体各自构造后 **shuffle**（分支条件互相排斥，顺序无关）
        //   ② 状态推进提到体首（体内不读 state，等价）；
        //   ③ 所有 for 循环换成 while + 显式自增下标 + 独立局部下标；
        //   ④ 结尾统一 return（不再是分支内 return），并带一个恒假谓词与影子守卫
        // 注意：体内的**读流顺序**一个字都不能动 —— 那些字节是按顺序读进来的
        let (v_ch_g, v_ch_out, v_ch_i, v_ch_n) = (rng.name(), rng.name(), rng.name(), rng.name());

        // ⑧ 常数提供者：连常数 1 都要过一次形参重名函数
        let cpp = rng.name();
        let cpq = rng.name();
        let body_init = format!(
            "local function {cpp}({cpq},{cpq}) {cpq}=0X1; return {cpq} end; {st}={nxt}; {c}.{pf_n}={rs}(); {c}.{pf_ld}={a5}(); {c}.{pf_lld}={a5}(); {c}.{pf_nups}={rd}(); \
             {c}.{pf_numparams}={rd}(); {c}.{pf_is_vararg}={rd}(); {c}.{pf_maxstack}={rd}(); if {i} > {cpp}({cpq},{cpq}) then {i} = {i} - {cpp}({cpq},{cpq}) end; ",
            st = var_state, nxt = obf_s_insts, c = fn_c, rs = fn_read_string, a5 = fn_a5, rd = fn_read_dec,
            pf_n = pf_n, pf_ld = pf_ld, pf_lld = pf_lld, pf_nups = pf_nups,
            pf_numparams = pf_numparams, pf_is_vararg = pf_is_vararg, pf_maxstack = pf_maxstack, i = v_ch_i,
            cpp = cpp, cpq = cpq
        );
        // ⑨ 区间二分树诱饵：not(x<=k) 双重否定嵌套（恒空转，美化后深度剧增）
        let it9 = |rng: &mut GenRng, st: &str| format!(
            "if not({st}<=0X{:X}) then if not({st}<=0X{:X}) then else end else end; ",
            rng.range(0x1000, 0xFFFF), rng.range(0x10000, 0xFFFFF));
        // ① B/C 解掩码：线上=值^(mag^ki)^k（k/ki 逐产物、mag 逐条别名魔数）。
        // a10 返回带符号值：先回 2^32 域异或，再按 2^31 还原符号——与旧 a10 语义逐位一致
        let (kb_x, kc_x, ki1_x, ki2_x) = (
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_kb as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_kc as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_ki1 as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_ki2 as i64),
        );
        // 目标二③（第二部分，共享指令空间）：所有原型共用同一批指令数组——它们是
        // 解码器的持久 upvalue（跨 thunk 调用存活），每个原型只占其中一段互不重叠的
        // 下标区间（基址 = payload 头 pf_lld，先序分配、段间随机死槽）。静态读者再也
        // 不能靠「一个数组 = 一个函数」划边界；运行期入口把 pc 切到本原型基址，
        // 相对跳转与记录条数语义不变。
        // 注册表挂在既有的弱键长存表上（数字键，**零新增局部**——payload 顶层局部数
        // 已接近 Lua 的 200 上限，多一枚都可能让整份产物编译失败）：首次取用时惰性
        // 建 4 张表，此后所有原型共用同一批数组。
        let sh_key_v = rng.range(0x10000, 0xFFFFFFF) as i64;
        let sh_key = rng.obfuscate_num(sh_key_v, 1, &keys);
        let mut sh_idx: Vec<usize> = (1..=4).collect();
        rng.shuffle(&mut sh_idx);
        let sh_get = format!(
            "{kr}[{k}]={kr}[{k}] or {{{{}},{{}},{{}},{{}}}}; ",
            kr = kreg_n, k = sh_key);
        let sh_arrs: Vec<&String> = vec![&pf_opcodes, &pf_a_arr, &pf_b_arr, &pf_c_arr];
        let sh_assign: String = sh_arrs.iter().zip(sh_idx.iter())
            .map(|(f, i)| format!("{c}.{f}={kr}[{k}][{i}]; ", c = fn_c, f = f, kr = kreg_n, k = sh_key, i = i))
            .collect();
        let body_insts = format!(
            "{st}={nxt}; {tree9} {sh_get}{sh_assign} \
             local function {dcb}({w},{m},{k},{q}) if {w}<0X0 then {w}={w}+{m32v} end {w}={bx}({bx}({w},{k}),{bx}({m},{q})) if {w}>={m31v} then {w}={w}-{m32v} end return {w} end; \
             local {i}=0; local {n}={a5}(); {c}.{cnt18}={n}; local {kp}={c}.{pf_ld}; local {pb}={c}.{pf_lld}; local {ka}={bx}({kp},{pb}); local {kb18}={bx}({kp},{ka}); local {kc18}={bx}({pb},{ka}) \
             while {i} < {n} do {i} = {i} + 1; \
             local {mv}={a5}() if {mv}<0 then {mv}={mv}+{m32v} end local {g18}={bx}({mv},{kp}) {c}.{pf_opcodes}[{i}+{pb}]={g18} {c}.{pf_a_arr}[{i}+{pb}]={bx}({a10}()%{m32v},{ka}) {c}.{pf_b_arr}[{i}+{pb}]={bx}({dcb}({a10}(),{g18},{kbx},{k1x})%{m32v},{kb18}) {c}.{pf_c_arr}[{i}+{pb}]={bx}({dcb}({a10}(),{g18},{kcx},{k2x})%{m32v},{kc18}) local {jv}=(({mv}-({mv}%0X20000000))/0X20000000)%4; for _=1,{jv} do {rd}() end end; ",
            tree9 = it9(&mut rng, var_state.as_str()),
            m32v = crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 32),
            m31v = crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 31),
            st = var_state, nxt = obf_s_consts, c = fn_c, a5 = fn_a5, a10 = fn_a10,
            pf_opcodes = pf_opcodes, pf_a_arr = pf_a_arr, pf_b_arr = pf_b_arr, pf_c_arr = pf_c_arr,
            sh_assign = sh_assign, sh_get = sh_get,
            i = v_ch_i, n = v_ch_n, cnt18 = pf_cnt18, kp = rng.name(), g18 = rng.name(),
            pb = rng.name(), ka = rng.name(), kb18 = rng.name(), kc18 = rng.name(),
            pf_ld = pf_ld, pf_lld = pf_lld,
            dcb = rng.name(), w = rng.name(), m = rng.name(), k = rng.name(), q = rng.name(),
            bx = fn_bxor.as_str(), mv = rng.name(), kbx = kb_x, kcx = kc_x, k1x = ki1_x, k2x = ki2_x,
            jv = rng.name(), rd = fn_read_dec.as_str()
        );
        // ㉓ 统一流守卫："__index"/"KryvexObf_" 不留明文（惰性解密）
        let cid_index = uni.register("__index");
        let cid_gk = uni.register("KryvexObf_");
        let (ci_stmt, sc_index2) = uni.fetch(&mut rng, cid_index);
        let (gk_stmt, sc_kobf) = uni.fetch(&mut rng, cid_gk);
        let (bc_scatter, agg_field) = crate::VM::VM_Backend::Generator_flow::build_consts(
                &mut rng, &keys, &kc, pj_name.as_str(), fn_bxor.as_str(),
                sc_index2.as_str(), sc_kobf.as_str(), var_state_flag.as_str(), var_idx_chunk.as_str(),
                var_tbl.as_str(), var_e.as_str(), &ds_names, &dn_names, fn_read_string.as_str(), fn_s_byte.as_str(),
                fn_a5.as_str(), fn_read_dec.as_str(), var_enc_c.as_str(), var_cache.as_str(),
                fn_c.as_str(), pf_consts.as_str(), const_path_key.as_str(),
                &v_ch_i, &v_ch_n, &t,
                pf_opcodes.as_str(), pf_a_arr.as_str(), pf_b_arr.as_str(), pf_c_arr.as_str(), fn_rotl32.as_str(), &fc18,
                &tag_map18, &salt_names, pf_ld.as_str(), pf_lld.as_str(), pf_cnt18.as_str(),
                chain_delta, chain_m, chain_k0, psn_n.as_str(),
                poison_delay_expr.as_str());
        let body_consts = format!("{st}={nxt}; {ci_stmt}{gk_stmt} {bc_scatter} ",
            st = var_state, nxt = obf_s_protos);
        let pkx1 = { let v = rng.range(0x10000, 0xFFFFF) as i64; crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), v) };
        // ⑱ 惰性原型：读取游标是 var_a2（fn_a3 读载荷子串 P[A2]），read_dec 是
        // 滚动密钥流（k1..k4 随消费演化）——跳读须逐字节喂 rd() 推进外层密钥；
        // 快照取在 len 之后（=子块首字节前的 A2 与滚动密钥），thunk 换入快照解码、
        // 换出恢复；防篡改旗彼时为 false，同样保存/置位/恢复
        let (ln18, p18, s1a, b1a, sv18, svf18, rr18) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        // ⑱.2 读侧掩码还原：ln=u32d() 后与 f(u32d 前快照的 k1..k4, 层内序号) 异或。
        // 公式与写侧 pm_g/pm_sb 同源：mask 字节=(rotl8(ka^kb)+盐)%256，
        // rotl8(r)=fn_b_rotr 的 rotr8(8-r)，旋转位数在生成阶段预先计算并直接输出；
        // 盐=(i*A+B)%256，A/B 逐产物随机（pm_s）。
        let (qa18, qb18, qc18, qd18) = (rng.name(), rng.name(), rng.name(), rng.name());
        let pm_lua = |x: &str, y: &str, r: u32, j: usize| -> String {
            let rotation = 8 - r;
            format!("({rt}({bx}({x},{y}),0X{rotation:X})+({i}*0X{a:X}+0X{b:X})%256)%256",
                rt = fn_b_rotr, bx = fn_bxor, i = v_ch_i,
                a = pm_s[j * 2], b = pm_s[j * 2 + 1], rotation = rotation)
        };
        let m18_0 = pm_lua(&qa18, &qd18, pm_r0, 0);
        let m18_1 = pm_lua(&qb18, &qa18, pm_r1, 1);
        let m18_2 = pm_lua(&qc18, &qb18, pm_r2, 2);
        let m18_3 = pm_lua(&qd18, &qc18, pm_r3, 3);
        let body_protos = format!(
            "{st}={nxt}; {tree9} {c}.{pf_protos}={{}}; local {i}=0; local {n}={a5}(); {md18}={c}.{pf_protos}; {np18}={n}; \
             if not {pj}[({pkx1})] then while {i} < {n} do {i} = {i} + 1; local {qa},{qb},{qc},{qd}=k1,k2,k3,k4; local {ln}={bx}({u32d}(),{m0}+{m1}*256+{m2}*65536+{m3}*16777216); \
               local {p0}={a2}; local {s1},k2s,k3s,k4s=k1,k2,k3,k4; for _=0X1,{ln} do {rd}() end; \
               {c}.{pf_protos}[{i}]=function() local {sv}={a2}; local {svf}={flg}; local {b1},k2b,k3b,k4b=k1,k2,k3,k4; \
                 {a2}={p0}; k1,k2,k3,k4={s1},k2s,k3s,k4s; {flg}=true; local {rr}={dc}(); \
                 {a2}={sv}; k1,k2,k3,k4={b1},k2b,k3b,k4b; {flg}={svf}; return {rr} end end else {i}={n}; {n}=0X0; end; ",
            st = var_state, nxt = obf_s_debug, c = fn_c, pf_protos = pf_protos, a5 = fn_a5,
            dc = fn_decode_chunk, i = v_ch_i, n = v_ch_n, pj = pj_name, pkx1 = pkx1,
            u32d = fn_u32_dec, md18 = md21, np18 = np21,
            a2 = var_a2, flg = var_state_flag, rd = fn_read_dec,
            bx = fn_bxor, qa = qa18, qb = qb18, qc = qc18, qd = qd18,
            m0 = m18_0, m1 = m18_1, m2 = m18_2, m3 = m18_3,
            ln = ln18, p0 = p18, s1 = s1a, b1 = b1a, sv = sv18, svf = svf18, rr = rr18,
            tree9 = it9(&mut rng, var_state.as_str())
        );
        // ⑭ 九元联合 nil 声明 + ⑦ repeat…until false 换皮 + ⑨ 区间树
        let d14: Vec<String> = (0..9).map(|_| rng.name()).collect();
        // ③ 汇总校验：随机选中的采样点发现不符时只置共享投毒旗，不调用失败闭包。
        // 采样位来自局部对象地址哈希，不消耗用户 math.random 的状态。
        let m32d = crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 32);
        let (go, gb, ga, gx, gs, gh, gi) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let gate_seed = rng.range(0x1000, 0x7FFF_FF00);
        let verify_agg = format!(
            "local {go},{gb}=pcall(function() local {ga},{gx}={{}},{{}};local {gs}=tostring({ga})..tostring({gx});local {gh}=0X{seed:X};for {gi}=1,#{gs} do {gh}=({gh}*0X21+string.byte({gs},{gi}))%0X7FFFFF01 end;return {gh}%0X2 end);if {go} and {gb}==0X0 then local {co},{cm}=pcall(function() return type({d0})~='number' or {d0}%{mod}~={c}.{aggf} end);{psn}={psn} or (not {co} or {cm}) end;",
            go = go, gb = gb, ga = ga, gx = gx, gs = gs, gh = gh, gi = gi, seed = gate_seed,
            d0 = d14[0], mod = m32d, c = fn_c, aggf = agg_field, psn = psn_n, co = rng.name(), cm = rng.name()
        );
        let body_debug = format!(
            "{st}={nxt}; {tree9} repeat \
             local {d0},{d1},{d2},{d3},{d4},{d5},{d6},{d7},{d8}; \
             local {i}=0; local {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {d0}={a5}(); {verify} end; \
             {i}=0; {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {rs}(); {a5}(); {a5}() end; \
             {i}=0; {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {rs}() end; break; until false; ",
            st = var_state, nxt = obf_s_ret, a5 = fn_a5, rs = fn_read_string, i = v_ch_i, n = v_ch_n,
            d0 = d14[0], d1 = d14[1], d2 = d14[2], d3 = d14[3], d4 = d14[4],
            d5 = d14[5], d6 = d14[6], d7 = d14[7], d8 = d14[8], verify = verify_agg,
            tree9 = it9(&mut rng, var_state.as_str())
        );
        // ⑦ while true 壳 + ⑭ return nil 兜底（ret 态跑完显式出）
        // ⑦ while true 壳 + ⑭ return nil 兜底（藏在恒假守卫内，真死代码）
        let r14 = rng.name();
        let body_ret = format!("while true do if not(not {pj}[({pkx1})]) then {g}={g}+1; else {out}={c}; {g}={g}+1; end; local {r14}=nil; if {r14} then return nil end; break; end; ",
            out = v_ch_out, c = fn_c, g = v_ch_g, pj = pj_name, pkx1 = pkx1, r14 = r14);

        // ⑳ 行完整性守卫：运行期抽样探测行位置；失配只置共享投毒旗并继续。
        // 每个采样点以对象地址哈希选取，不调用 math.random，也不改变脚本的随机序列。
        // 定义式/内联两形态仍保留随机化探针与错误消息针式，但不再制造固定报错。
        // ㉓ inline=true 的 fu 与 wai 是兄弟闭包；共享 poison 已移到二者共同的外围作用域。
        let line_guard = |rng: &mut GenRng, uni: &mut crate::VM::VM_Backend::Generator_util::UniStream, inline: bool| -> String {
            let tbl = rng.name();
            let probe_body = |rng: &mut GenRng| -> String {
                let v = rng.name();
                match rng.range(0, 4) {
                    0 => format!("local {v};return {v}.{f}", v = v, f = rng.name()),
                    1 => format!("local {v};return {v}()", v = v),
                    2 => format!("local {v};return {v}+0X1", v = v),
                    _ => format!("local {v};return {v}..\"\"", v = v),
                }
            };
            let trig_stmt = |rng: &mut GenRng, u: &str| -> (String, String) {
                match rng.range(0, 3) {
                    0 => (format!("{u}.{f}=0X1", u = u, f = rng.name()), "{}".to_string()),
                    1 => (format!("{u}()", u = u), "function()end".to_string()),
                    _ => (format!("{u}={u}..\"\"", u = u), "\"\"".to_string()),
                }
            };
            let (m_drv, m_pcall, m_probe, m_chk, m_hit) =
                (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            let (p_err, p_hit, p_u, p_self) = (rng.name(), rng.name(), rng.name(), rng.name());
            // ⑧ 针式去冒号字面量：":"..N..":" 是错误消息行号嗅探指纹.
            // 冒号与字符 2 使用直接数字字面量，由 string.char/连接在运行期构造目标串。
            let sc = rng.name();
            let c58 = "0X3A";
            let needle = format!("{s}({c})..(0X2)..{s}({c})", s = sc, c = c58);
            let pb = probe_body(rng);
            let (ts, tolerant) = trig_stmt(rng, &p_u);
            // 失败时只置共享 poison；填充语句及探针仍按产物随机化，且脚本继续运行。
            let (f1, f2) = (rng.name(), rng.name());
            let mut ht_body = format!("local {u}={h} and {tol} or nil; local {f1}=type({u}); ",
                u = p_u, h = p_hit, tol = tolerant, f1 = f1);
            // ㉓ 填充语型别串：壳内守卫走统一流惰性解密；fu 内守卫（inline）
            // 用 string.char 数字拼装自足表达，二者都零字面量。
            let (jf_stmt, jf_expr) = if inline {
                // ㉓.4 fu 守卫型别串：字节先与随机掩码异或落为密文数字，运行期用
                // 自带算术 XOR（不依赖 bit32/bit，Lua 5.1 与 Luau 通吃）还原——
                // ASCII 明文数字消失，string.char 只做字节→字符拼装。
                let mask = rng.range(1, 256) as u8;
                let plain: [u8; 8] = [102, 117, 110, 99, 116, 105, 111, 110]; // "function"
                let (xh, mv) = (rng.name(), rng.name());
                let (pa, pb, pr, pw, pv, pda, pdb) = (rng.name(), rng.name(), rng.name(),
                    rng.name(), rng.name(), rng.name(), rng.name());
                let nlit = |rng: &mut GenRng, v: u8| -> String {
                    if rng.range(0, 2) == 0 { format!("{}", v) } else { format!("0X{:X}", v) }
                };
                let stmt = format!(
                    "local {xh}=function({a},{b}) local {r},{w}=0X0,0X1 for {v}=0X1,0X8 do local {da},{db}={a}%0X2,{b}%0X2 if {da}~={db} then {r}={r}+{w} end; {a}=({a}-{da})/0X2 {b}=({b}-{db})/0X2 {w}={w}+{w} end; return {r} end; local {mv}={mk}; ",
                    xh = xh, a = pa, b = pb, r = pr, w = pw, v = pv, da = pda, db = pdb,
                    mv = mv, mk = nlit(&mut *rng, mask));
                let args = plain.iter()
                    .map(|b| format!("{xh}({c},{m})", xh = xh, c = nlit(&mut *rng, b ^ mask), m = mv))
                    .collect::<Vec<_>>()
                    .join(",");
                (stmt, format!("string.char({})", args))
            } else {
                let jf_id = uni.register("function");
                uni.fetch(&mut *rng, jf_id)
            };
            let mut hopts = vec![
                format!("if {u}~={u} then {u}={u} end; ", u = p_u),
                format!("{jf_stmt}if {f1}=={jf_expr}then {u}={u} end; ", jf_stmt = jf_stmt, f1 = f1, jf_expr = jf_expr, u = p_u),
                format!("if {f1}==\"string\"and #{u}>0X0 then {u}={u} end; ", f1 = f1, u = p_u),
                format!("for {f2}=0X1,0X{} do if {u} then break end end; ", rng.range(2, 6), f2 = f2, u = p_u),
                format!("local {f2}=({u})and 0X1 or 0X0; ", f2 = f2, u = p_u),
            ];
            rng.shuffle(&mut hopts);
            let hn = 1 + rng.range(0, 2);
            for i in 0..hn { ht_body.push_str(&hopts[i]); }
            if rng.range(0, 2) == 0 {
                ht_body.push_str(&format!("if not {u} then {psn}={psn} or not {u} else {ts} end; ", u = p_u, psn = psn_n, ts = ts));
            } else {
                ht_body.push_str(&format!("if not {u} then {psn}={psn} or not {u} end; if {u} then {ts} end; ", u = p_u, psn = psn_n, ts = ts));
            }
            let mut ms = vec![
                format!("{t}.{drv}=function({s})local {o},{e}={s}:{pc}() {s}:{ht}({s}:{ck}({e}))end; ",
                    t = tbl, drv = m_drv, s = p_self, o = rng.name(), e = p_err,
                    pc = m_pcall, ht = m_hit, ck = m_chk),
                format!("{t}.{pc}=function({s})return pcall({s}.{pb},{s})end; ",
                    t = tbl, pc = m_pcall, s = p_self, pb = m_probe),
                format!("{t}.{pb}=function({s}){body} end; ",
                    t = tbl, pb = m_probe, s = p_self, body = pb),
                format!("{t}.{ck}=function({s},{e})local {sc}=string.char;return type({e})==\"string\"and {e}:find({ndl})end; ",
                    t = tbl, ck = m_chk, s = p_self, e = p_err, sc = sc, ndl = needle),
                format!("{t}.{ht}=function({s},{h}){hb} end; ",
                    t = tbl, ht = m_hit, s = p_self, h = p_hit, hb = ht_body),
                format!("{t}.{d1}=function({s},{q})return {q} end; ",
                    t = tbl, d1 = rng.name(), s = p_self, q = rng.name()),
            ];
            if rng.range(0, 2) == 1 {
                ms.push(format!("{t}.{d2}=function({s},{q})return {q} end; ",
                    t = tbl, d2 = rng.name(), s = p_self, q = rng.name()));
            }
            rng.shuffle(&mut ms);
            let body = format!("local {t}={{}} {ms} {t}:{drv}() ",
                t = tbl, ms = ms.concat(), drv = m_drv);
            let (go, gb, ga, gx, gs, gh, gi) =
                (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            let gate_seed = rng.range(0x1000, 0x7FFF_FF00);
            format!(
                "local {go},{gb}=pcall(function() local {ga},{gx}={{}},{{}};local {gs}=tostring({ga})..tostring({gx});local {gh}=0X{seed:X};for {gi}=1,#{gs} do {gh}=({gh}*0X21+string.byte({gs},{gi}))%0X7FFFFF01 end;return {gh}%0X2 end);if {go} and {gb}==0X0 then {body} end;",
                go = go, gb = gb, ga = ga, gx = gx, gs = gs, gh = gh, gi = gi,
                seed = gate_seed, body = body
            )
        };
        let mut ch_pairs: Vec<(String, String)> = vec![
            (obf_s_init.clone(), body_init),
            (obf_s_insts.clone(), body_insts),
            (obf_s_consts.clone(), body_consts),
            (obf_s_protos.clone(), body_protos),
            (obf_s_debug.clone(), body_debug),
            (obf_s_ret.clone(), body_ret),
        ];
        rng.shuffle(&mut ch_pairs);
        let mut chain = String::new();
        for (idx, (val, body)) in ch_pairs.iter().enumerate() {
            let kw = if idx == 0 { "if" } else { "elseif" };
            chain.push_str(&format!("{} {} == {} then {} ", kw, var_state, val, body));
        }
        chain.push_str(&format!("else {} = {} + 1; end; ", v_ch_g, v_ch_g));

        let block_dec_chunk = format!(
            "local function {fn_dec_chunk}() local {fn_c}, {t}, {var_state} = {{}}, nil, {obf_s_init}; \
             local {g}, {out}, {i}, {n} = 0, nil, 0, 0; \
             while {g} < 1 do {chain} end; \
             return {out} end; ",
            fn_dec_chunk = fn_decode_chunk, fn_c = fn_c, t = t, var_state = var_state,
            obf_s_init = obf_s_init, g = v_ch_g, out = v_ch_out, i = v_ch_i, n = v_ch_n,
            chain = chain
        );

        let mut parts = vec![
            block_p_def,
            block_methods,
            block_vm_core,
            block_packer_vars,
            block_execute_def,
            block_decoder_script,
            block_dec_header,
            block_dec_helpers,
            block_dec_readers,
            block_chacha_setup,
            cluster_parts[0].clone(),
            cluster_parts[1].clone(),
            cluster_parts[2].clone(),
            block_dec_chunk,
        ];

        {
            let lg20 = line_guard(&mut rng, &mut uni, false);
            let gap20 = rng.range(0, parts.len() + 1);
            parts.insert(gap20, lg20);
        }

        let mut shuffled_guards = at.guards.clone();
        rng.shuffle(&mut shuffled_guards);

        for guard in shuffled_guards {
            let gap_idx = rng.range(0, parts.len() + 1);
            parts.insert(gap_idx, guard);
        }

        let mut out = String::new();
        out.push_str(&format!("local {} = ...;\n", var_l));
        // fu 与 wai 是兄弟闭包；共享投毒旗必须位于二者共同可见的词法作用域。
        // 保持与 return 壳同一物理行，不影响行完整性探针的目标行号。
        out.push_str(&format!("local {}=false; ", psn_n));
        out.push_str(&header_block);
        // ㉓ 统一流前导（表+惰性解码器）：直接落在主 return({}) 壳内——header_block
        // 打开的 wai 函数体开头（用户指示，不另起壳）；壳内所有取用点（守卫/散点/
        // 打乱 parts/解码脚本）都在其后，解码脚本以 upvalue 捕获。fu 是兄弟字段且在
        // wai 之前执行，其守卫的型别填充改用自足 string.char 数字拼装（见 line_guard）。
        out.push_str(&uni.emit_prelude(&mut rng));
        // ㉑ 保守版明文窗口：NP(原型数)/MD(=C.pr 别名)/TH(thunk 快照)/tw(回收水位)
        // 必须在 execute 定义（parts）之前声明，execute 内才能捕获为 upvalue
        // ㉘D1 六件套声明形式打乱：名字-初值配对后洗牌发射；共享 poison 在外围先声明。
        {
            // 注意：此处早于 block_p_def（键表），不能用 obfuscate_num 的键表形态，
            // 只用纯算式零（大写十六进制）。㉚④：零用 x%x 恒零——不再用
            // (x-x) 同字面量自抵消形态
            let zk = rng.range(0x100, 0xFFFFF);
            let z_rk = format!("(0X{:X}%0X{:X})", zk, zk);
            let mut decls: Vec<(String, String)> = vec![
                (np21.clone(), "0".to_string()),
                (md21.clone(), "{}".to_string()),
                (th21.clone(), "{}".to_string()),
                (tw21.clone(), "0X0".to_string()),
                (rk21.clone(), z_rk),
                (kreg_n.clone(), "setmetatable({},{__mode='k'})".to_string()),
            ];
            rng.shuffle(&mut decls);
            let names: Vec<String> = decls.iter().map(|(n, _)| n.clone()).collect();
            let vals: Vec<String> = decls.iter().map(|(_, v)| v.clone()).collect();
            out.push_str(&format!("local {}={}; ", names.join(","), vals.join(",")));
            // 复用 kreg 的私有槽，避免新增 Lua upvalue；地址哈希提供每次启动的小幅抖动，
            // 不读取或消费 math.random。失败后先让 VM 继续一段随机指令数，再启用扰动。
            let poison_delay_seed = rng.range(32, 80);
            out.push_str(&format!(
                "{tab}[0X{key:X}]={seed}+(function()local s=tostring({tab});local h=0;for i=1,#s do h=(h*33+string.byte(s,i))%17 end;return h end)(); ",
                tab = kreg_n, key = poison_delay_key, seed = poison_delay_seed
            ));
        }
        // ㉒② 焊接缓存表声明：长时状态只剩槽号；此后各站点以「一个 if 三件事」
        // 形态（惰性缓存+随机大数键）发射焊接构造。
        out.push_str(&weld.declare());
        // ⑳.4 守卫必须在 return 壳内（用户指示）：三处采样全部作为壳方法体的
        // 开头/缝隙语句，行 2 头部只留 local L=... 和 return({——壳外零检测代码
        out.push_str(&line_guard(&mut rng, &mut uni, false));
        // ④ 槽位键的运行期推导块必须在所有用键代码之前；
        // finish_setup 把状态链种子/陷阱门等收尾语句并进 setup（在全部注册后调用）
        out.push_str(&sk_setup);
        at.finish_setup();
        out.push_str(&at.setup);
        // ㉘D1 key_seed 初值零改算式形态（此处早于键表；㉚④：x%x 恒零，
        // 不再用同字面量自抵消）
        {
            let zk2 = rng.range(0x100, 0xFFFFF);
            out.push_str(&format!(" local {} = (0X{:X}%0X{:X}); ", key_seed_var, zk2, zk2));
        }
        out.push_str(" ");
        // A 解码器前奏打散：五件套不再「库-函数」对齐并列（math.floor,string.char,... 教科书
        // 解码器开场）。先落随机键库表，五个 local 按洗牌序逐个经表取用，.m/["m"] 访问混用；
        // 后续模板仍引用同名局部（math_floor/string_char/...），语义不变
        {
            let pt = rng.name();
            let kf = |v: usize| -> String { format!("0X{:X}", v) };
            let (km, ks, kt) = (rng.range(0x1000, 0xFFFFF), rng.range(0x1000, 0xFFFFF), rng.range(0x1000, 0xFFFFF));
            let mut members = vec![
                (km, "math_floor", "floor"),
                (ks, "string_char", "char"),
                (ks, "string_sub", "sub"),
                (ks, "string_byte", "byte"),
                (kt, "table_concat", "concat"),
            ];
            rng.shuffle(&mut members);
            let mut frag = format!("local {}={{[{}]=math,[{}]=string,[{}]=table}}; ", pt, kf(km), kf(ks), kf(kt));
            for (k, loc, m) in &members {
                let acc = if rng.range(0, 2) == 0 { format!(".{}", m) } else { format!("[\"{}\"]", m) };
                frag.push_str(&format!("local {}={}[{}]{}; ", loc, pt, kf(*k), acc));
            }
            out.push_str(&frag);
        }

        for part in parts {
            out.push_str(&part);
            out.push_str(" ");
        }

        out.push_str(&line_guard(&mut rng, &mut uni, false));
        // ㉘D7 尾部形式改写：空的兼容 registry 与当前环境捕获前移到解码之前；
        // 解码调用包一层函数边界，打破「解码→触发→取环境」的平铺调用链形态。全局名已走普通常量。
        out.push_str(&format!("{}={{}}; local {}=(getfenv and getfenv() or _ENV or _G); ", var_builtin_reg, var_boot_env));
        out.push_str(&format!("local main_chunk=(function() return {}() end)(); ", fn_decode_chunk));
        out.push_str(&at.trigger);
        // ㉑ thunk 快照：密文 thunk 常驻，明文可随时写回回收
        // ㉒① thunk 快照环 → 动态分段游标机（上界=运行期原型数，P 表在作用域）。
        let thunk_walk = {
            let (th2, md2) = (th21.clone(), md21.clone());
            let off = rng.range(0, 100);
            let unit = |iv: &str| format!("{th}[{iv}]={md}[{iv}]; ", th = th2, md = md2, iv = iv);
            crate::VM::VM_Backend::Generator_util::cursor_walk_dyn(&mut rng, Some(&keys), off, &np21, 2, 3, &unit)
        };
        out.push_str(&thunk_walk);
        let fu = rng.name();
        
        // ⑳.5 尾部探针：此前最后一个采样点在 parts 之后——main_chunk 解码/
        // thunk 快照/return 壳整段是"探针之下"的插入盲区（用户实测 print 插行未检出）。
        // 紧贴 return 再布一枚，把盲区压缩到 return 语句本身；⑤ fu 壳内最后一针
        // 封住 return 壳表达式内的语句缝隙。二者均在行 2 内，针式 :2: 一致。
        out.push_str(&line_guard(&mut rng, &mut uni, false));
        out.push_str(&line_guard(&mut rng, &mut uni, false));
        out.push_str(" ");
        out.push_str(&format!("return {}(main_chunk, {}, {{}}, {}) end,{}=function(x) {} x:{}() end", fn_execute, var_boot_env, var_l, fu, line_guard(&mut rng, &mut uni, true), wai));
        out.push_str(&format!(" }}):{}()", fu));
        out
}
