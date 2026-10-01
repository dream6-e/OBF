//! Generator_chain 的后半段：原型解码状态机（body_init/insts/consts/protos/debug/ret）、
//! 行完整性守卫、Part 洗牌拼接、Boot 内建名解密簇与最外层启动壳。
//! 从 Generator_chain.rs 拆出（守单文件 80 KB 上限，保持两文件各约 42 KB）。

use crate::VM::Opcodes;
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
        builtin_slot_perm, sigma,
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
        var_a2,
        var_b,
        var_builtin_reg,
        var_chk,
        var_idx,
        var_junk,
        var_p,
        var_raw_p,
        var_tamper,
        var_vc,
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
        var_bname,
        var_boot_env,
        var_l,
        var_state_flag,
        wai,
        xor_tbl_var,
        weld: mut weld,
        uni: mut uni,
    } = x;
    const CG: usize = super::Generator_chain::CG_GROUPS;
    let poison_ks = |rng: &mut GenRng, ks: &str| -> String {
        let k1 = rng.range(0x100, 0xFFFF) as u32;
        let k2 = rng.range(0x100, 0xFFFF) as u32;
        match rng.range(0, 4) {
            0 => format!("if {psn} then {ks}[0X1]=(0X{k:X}-{ks}[0X1])%0X100 end; ", psn = psn_n, ks = ks, k = k1),
            1 => format!("if {psn} then local {z}=#{ks} while {z}>0X0 do {ks}[{z}]=(0X{k:X}-{ks}[{z}])%0X100; {z}={z}-0X1 end end; ", psn = psn_n, ks = ks, k = k1, z = rng.name()),
            2 => format!("if {psn} then {ks}[0X1]=({ks}[0X1]+0X{k:X})%0X100; {ks}[#{ks}]=(0X{k2:X})%0X100 end; ", psn = psn_n, ks = ks, k = k1, k2 = k2),
            _ => format!("if {psn} then for {z}=0X1,#{ks} do {ks}[{z}]=({ks}[{z}]*0X{k:X}+0X{k2:X})%0X100 end end; ", psn = psn_n, ks = ks, k = k1, k2 = k2, z = rng.name()),
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
    let mk_m = |rng: &mut GenRng| -> String {
        let k = rng.range(0x1000, 0xFFFFFF) as u64;
        format!("(0X{:X}-0X{:X})", 4294967296u64 + k, k)
    };
    let mk_rounds = |rng: &mut GenRng, qrn: &str, ly: &crate::VM::VM_Backend::Generator_chacha::ChaChaLayout| -> String {
        let mut cols: Vec<(u32, u32, u32, u32)> = vec![(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15)];
        let mut dias: Vec<(u32, u32, u32, u32)> = vec![(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)];
        rng.shuffle(&mut cols); rng.shuffle(&mut dias);
        let mut ents: Vec<String> = Vec::new();
        for &(a, b, c, d) in cols.iter().chain(dias.iter()) {
            let m = |v: u32| (ly.rho[v as usize] + 1) as u32;
            let f = |rng: &mut GenRng, v: u32| -> String {
                if rng.range(0, 2) == 0 { v.to_string() }
                else { let k = rng.range(0x10, 0xFFFF) as u32; format!("(0X{:X}-0X{:X})", v + k, k) }
            };
            ents.push(format!("{{{},{},{},{}}}", f(rng, m(a)), f(rng, m(b)), f(rng, m(c)), f(rng, m(d))));
        }
        let (tv, iv, ev) = (rng.name(), rng.name(), rng.name());
        let kf = rng.range(0x10, 0xFFFF) as u32;
        let rounds = (ly.rounds / 2) as u32;
        format!(
            "local {tv}={{{ents}}}; for _=1,(0X{:X}-0X{:X}) do for {iv}=1,#{tv} do local {ev}={tv}[{iv}]; {qrn}({sv},{ev}[1],{ev}[2],{ev}[3],{ev}[4]) end end; ",
            kf + rounds, kf, tv = tv, iv = iv, ev = ev, ents = ents.join(","), qrn = qrn, sv = "s")
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
        let body_insts = format!(
            "{st}={nxt}; {tree9} {c}.{pf_opcodes}={{}}; {c}.{pf_a_arr}={{}}; {c}.{pf_b_arr}={{}}; {c}.{pf_c_arr}={{}}; \
             local function {dcb}({w},{m},{k},{q}) if {w}<0X0 then {w}={w}+{m32v} end {w}={bx}({bx}({w},{k}),{bx}({m},{q})) if {w}>={m31v} then {w}={w}-{m32v} end return {w} end; \
             local {i}=0; local {n}={a5}(); {c}.{cnt18}={n}; local {kp}={c}.{pf_ld}; local {pb}={c}.{pf_lld}; local {ka}={bx}({kp},{pb}); local {kb18}={bx}({kp},{ka}); local {kc18}={bx}({pb},{ka}) \
             while {i} < {n} do {i} = {i} + 1; \
             local {mv}={a5}() if {mv}<0 then {mv}={mv}+{m32v} end local {g18}={bx}({mv},{kp}) {c}.{pf_opcodes}[{i}+{pb}]={g18} {c}.{pf_a_arr}[{i}+{pb}]={bx}({a10}()%{m32v},{ka}) {c}.{pf_b_arr}[{i}+{pb}]={bx}({dcb}({a10}(),{g18},{kbx},{k1x})%{m32v},{kb18}) {c}.{pf_c_arr}[{i}+{pb}]={bx}({dcb}({a10}(),{g18},{kcx},{k2x})%{m32v},{kc18}) local {jv}=(({mv}-({mv}%0X20000000))/0X20000000)%4; for _=1,{jv} do {rd}() end end; ",
            tree9 = it9(&mut rng, var_state.as_str()),
            m32v = crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 32),
            m31v = crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 31),
            st = var_state, nxt = obf_s_consts, c = fn_c, a5 = fn_a5, a10 = fn_a10,
            pf_opcodes = pf_opcodes, pf_a_arr = pf_a_arr, pf_b_arr = pf_b_arr, pf_c_arr = pf_c_arr,
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
        let body_consts = format!(
            "{st}={nxt}; {bc_scatter} ",
            st = var_state, nxt = obf_s_protos,
bc_scatter = crate::VM::VM_Backend::Generator_flow::build_consts(
                &mut rng, &keys, &kc, pj_name.as_str(), fn_bxor.as_str(),
                sc_index2.as_str(), sc_kobf.as_str(), var_state_flag.as_str(), var_idx_chunk.as_str(),
                var_tbl.as_str(), var_e.as_str(), &ds_names, &dn_names, fn_read_string.as_str(), fn_s_byte.as_str(),
                fn_a5.as_str(), fn_read_dec.as_str(), var_enc_c.as_str(), var_cache.as_str(),
                fn_c.as_str(), pf_consts.as_str(),
                &v_ch_i, &v_ch_n, &t,
                pf_opcodes.as_str(), pf_a_arr.as_str(), pf_b_arr.as_str(), pf_c_arr.as_str(), fn_rotl32.as_str(), &fc18,
                &tag_map18, &salt_names, pf_ld.as_str(), pf_lld.as_str(), pf_cnt18.as_str(),
                chain_delta, chain_m, chain_k0, psn_n.as_str())
        );
        let body_consts = format!("{ci_stmt}{gk_stmt}") + &body_consts;
        let pkx1 = { let v = rng.range(0x10000, 0xFFFFF) as i64; crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), v) };
        // ⑱ 惰性原型：读取游标是 var_a2（fn_a3 读载荷子串 P[A2]），read_dec 是
        // 滚动密钥流（k1..k4 随消费演化）——跳读须逐字节喂 rd() 推进外层密钥；
        // 快照取在 len 之后（=子块首字节前的 A2 与滚动密钥），thunk 换入快照解码、
        // 换出恢复；防篡改旗彼时为 false，同样保存/置位/恢复
        let (ln18, p18, s1a, b1a, sv18, svf18, rr18) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        // ⑱.2 读侧掩码还原：ln=u32d() 后与 f(u32d 前快照的 k1..k4, 层内序号) 异或。
        // 公式与写侧 pm_g/pm_sb 同源：mask 字节=(rotl8(ka^kb)+盐)%256，
        // rotl8(r)=fn_b_rotr 的 rotr8(8-r)；盐=(i*A+B)%256，A/B 逐产物随机（pm_s）。
        let (qa18, qb18, qc18, qd18) = (rng.name(), rng.name(), rng.name(), rng.name());
        let pm_lua = |x: &str, y: &str, r: u32, j: usize| -> String {
            format!("({rt}({bx}({x},{y}),8-0X{r:X})+({i}*0X{a:X}+0X{b:X})%256)%256",
                rt = fn_b_rotr, bx = fn_bxor, i = v_ch_i,
                a = pm_s[j * 2], b = pm_s[j * 2 + 1], r = r)
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
        let body_debug = format!(
            "{st}={nxt}; {tree9} repeat \
             local {d0},{d1},{d2},{d3},{d4},{d5},{d6},{d7},{d8}; \
             local {i}=0; local {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {a5}() end; \
             {i}=0; {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {rs}(); {a5}(); {a5}() end; \
             {i}=0; {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {rs}() end; break; until false; ",
            st = var_state, nxt = obf_s_ret, a5 = fn_a5, rs = fn_read_string, i = v_ch_i, n = v_ch_n,
            d0 = d14[0], d1 = d14[1], d2 = d14[2], d3 = d14[3], d4 = d14[4],
            d5 = d14[5], d6 = d14[6], d7 = d14[7], d8 = d14[8],
            tree9 = it9(&mut rng, var_state.as_str())
        );
        // ⑦ while true 壳 + ⑭ return nil 兜底（ret 态跑完显式出）
        // ⑦ while true 壳 + ⑭ return nil 兜底（藏在恒假守卫内，真死代码）
        let r14 = rng.name();
        let body_ret = format!("while true do if not(not {pj}[({pkx1})]) then {g}={g}+1; else {out}={c}; {g}={g}+1; end; local {r14}=nil; if {r14} then return nil end; break; end; ",
            out = v_ch_out, c = fn_c, g = v_ch_g, pj = pj_name, pkx1 = pkx1, r14 = r14);

        // ⑳ 行完整性守卫（用户 2026-09-25 指示，推翻早前"放弃行数守卫/反美化 fail-open"）：
        // 产物只许 1 行注释 + 1 行整体逻辑；采样点用 pcall 触发真实索引错误，
        // 从解释器位置前缀取行号（gmatch 取最后一个 :N:，防 chunkname 内含 :N: 干扰），
        // 行号≠期望值时触发同型索引错误自然崩溃——文案为解释器原生，无 error()、无自造报错。
        // 已知边界：最后一个采样点之后的拆行不在守卫范围内。
        // ⑳.2 守卫伪装化：不再提取行号（gmatch/tonumber/行号变量全删）——
        // 形态是「自检函数 + pcall 验证 + 错误消息内容断言」：探针每构建从
        // 索引/调用/算术/连接四族随机取型；期望行以 ":"..(r1-r2)..":" 针式内嵌
        // 于 find（消息里找不到该前缀才触发同型自然错误）；定义式/内联两形态随机
        // ⑳.3 守卫去线性化：逻辑拆进挂表的多个 function、全部以 : 方法调用
        // 驱动，数据流折进参数树（t:dz(t:cx(e))），定义顺序洗牌+诱饵方法埋伏；
        // 链路：驱动→m1(pcall 自派发)→m2(探针错误族随机)→m3(find 针式)→
        // m4(触发族随机：h and 容纳值 or nil 折叠，nil 时自然崩溃)
        // ㉓ inline=true：守卫落在 fu（兄弟字段，先于 wai 执行、够不到前导局部），
        // 型别填充不走统一流，用自足 string.char(数字) 拼装——同样零字面量。
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
            let d = rng.range(0x1000, 0xFFFF);
            // ⑧ 针式去冒号字面量：":"..N..":" 是错误消息行号嗅探指纹——
            // 冒号改 string.char(0X3A)（或差式）运行期构造，数值本身不变
            let sc = rng.name();
            let c58 = if rng.range(0, 2) == 0 { "0X3A".to_string() } else { format!("0X{:X}-0X{:X}", 0x1000 + 58, 0x1000) };
            let needle = format!("{s}({c})..(0X{:X}-0X{:X})..{s}({c})", d + 2, d, s = sc, c = c58);
            let pb = probe_body(rng);
            let (ts, tolerant) = trig_stmt(rng, &p_u);
            // ⑦ m_hit 去空壳：原来 local u=h and tol or nil; ts 一眼即知是桩。
            // 先捕获 type(u)，再洗牌插 1~2 句对 ""/function/nil 全安全的填充语，
            // 触发语句按随机形态收尾（直尾 / if not u 尾）——触发语义不变：
            // u=nil 时 ts 仍抛同型自然错误
            let (f1, f2) = (rng.name(), rng.name());
            // 投毒赋值去 "=true" 指纹：差式恒真谓词（0XA-0XB==0XC，逐守卫实例随机，
            // 与库内既有差式数字形态一致）；psn=psn or (…) 幂等
            let (ga, gb) = (rng.range(0x1_0000, 0xFFFF_FFFF) as i64, rng.range(0x1_0000, 0xFFFF_FFFF) as i64);
            let taut = format!("(0X{:X}-0X{:X}==0X{:X})", ga, gb, ga - gb);
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
            // 诱饵化：命中失败不再抛同型错误（用户指示：运行不报错）——
            // 改置投毒旗（后续常量解码全乱码、程序走进错误分支），形态保持 if not u 触发族
            if rng.range(0, 2) == 0 {
                ht_body.push_str(&format!("if not {u} then {psn}={psn} or {taut} else {ts} end; ", u = p_u, psn = psn_n, taut = taut, ts = ts));
            } else {
                ht_body.push_str(&format!("if not {u} then {psn}={psn} or {taut} end; if {u} then {ts} end; ", u = p_u, psn = psn_n, taut = taut, ts = ts));
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
            format!("local {t}={{}} {ms} {t}:{drv}() ",
                t = tbl, ms = ms.concat(), drv = m_drv)
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
        out.push_str(&header_block);
        // ㉓ 统一流前导（表+惰性解码器）：直接落在主 return({}) 壳内——header_block
        // 打开的 wai 函数体开头（用户指示，不另起壳）；壳内所有取用点（守卫/散点/
        // 打乱 parts/解码脚本）都在其后，解码脚本以 upvalue 捕获。fu 是兄弟字段且在
        // wai 之前执行，其守卫的型别填充改用自足 string.char 数字拼装（见 line_guard）。
        out.push_str(&uni.emit_prelude(&mut rng));
        // ㉑ 保守版明文窗口：NP(原型数)/MD(=C.pr 别名)/TH(thunk 快照)/tw(回收水位)
        // 必须在 execute 定义（parts）之前声明，execute 内才能捕获为 upvalue
        // ㉘D1 七件套声明形式打乱：名字-初值配对后洗牌发射——固定的
        // 「np,md,th,tw,rk,kreg,psn」字面顺序消失；后续按名引用，顺序无语义
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
                (psn_n.clone(), "false".to_string()),
            ];
            rng.shuffle(&mut decls);
            let names: Vec<String> = decls.iter().map(|(n, _)| n.clone()).collect();
            let vals: Vec<String> = decls.iter().map(|(_, v)| v.clone()).collect();
            out.push_str(&format!("local {}={}; ", names.join(","), vals.join(",")));
        }
        // ㉒② 焊接缓存表声明：长时状态只剩槽号；此后各站点以「一个 if 三件事」
        // 形态（惰性缓存+大随机数当键+校验恒等式）发射焊接构造。
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
            let kf = |v: usize| -> String {
                if v % 2 == 0 { format!("0X{:X}", v) } else { format!("(0X{:X}-7)", v + 7) }
            };
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
        // ㉘D7 尾部形式改写：reg/env/名暂存三声明与解码调用互不依赖，前移到解码
        // 之前；解码调用包一层函数边界，打破「解码→触发→取环境」的平铺调用链形态
        out.push_str(&format!(" {} = {{}}; local {} = (getfenv and getfenv() or _ENV or _G); local {}; ", var_builtin_reg, var_boot_env, var_bname));
        out.push_str(&format!("local main_chunk=(function() return {}() end)(); ", fn_decode_chunk));
        out.push_str(&at.trigger);
        // ⑰ 内建名专用簇：独立 key/salt/kind，密文以混合转义字面量内嵌，
        // 与四组常量簇完全分离——导出任何常量簇参数都拿不到内建名
        {
            // 第 3 项 D：boot 簇也走单根派生——组号 = CG，密钥/盐/kind 全由 K0 现算
            let dgb = crate::VM::VM_Backend::Generator_kdf::derive_group(&mut rng, &keys, kdf_name.as_str(), &root_fetch, CG);
            let bges = crate::VM::VM_Backend::Generator_chacha::group_keys(&enc.root, CG as u32);
            let bkey: [u32; 8] = bges.key;
            let bsalt: u32 = bges.salt;
            let bkind: u32 = bges.knum;
            // 第 2 项：内建名簇同样带自己的状态布局（ρ / 轮数 / counter 步进）
            let blay = crate::VM::VM_Backend::Generator_chacha::ChaChaLayout::new(&mut rng);
            let binv = blay.inv();
            let mut boot_lits: Vec<String> = Vec::with_capacity(Opcodes::builtins::BUILTIN_NAMES.len());
            for (i, name) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
                let blob = crate::VM::VM_Backend::Generator_chacha::stream_xor(&bkey, [bsalt, i as u32, bkind], name.as_bytes(), &blay);
                boot_lits.push(format!("\"{}\"", crate::VM::VM_Backend::Generator_util::lua_mixed(&blob)));
            }
            let (bk, bs, bcb, bsm, bdec, bpt) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            // 第 3 项 D：盐同样由根现算（KDF 值直接落名，无 X/掩码表）
            let salt_decl_b = format!("local {bs}={s}; ", bs = bs, s = dgb.salt);
            // ① sigma 还原与密钥解耦（只由本簇独立随机数还原，无密钥锚点）
            let sm32b = rng.name();
            let sm32bv = crate::VM::VM_Backend::Generator_kdf::kdf_m32(&mut rng);
            let sigma_items_b: Vec<String> = (0..4)
                .map(|i| {
                    let r = rng.next();
                    let d = sigma[i].wrapping_sub(r);
                    format!("(({}+{})%{m32})", rng.obfuscate_num(d as i64, 1, &keys), rng.obfuscate_num(r as i64, 1, &keys), m32 = sm32b)
                })
                .collect();
            let sigma_lua = sigma_items_b.join(",");
            let bkey_fetch = dgb.fetch.join(",");
            let btm = rng.name();
            // 逻辑序 16 字 → 物理位置序（boot 簇同款）
            let mut blogical: [String; 16] = std::array::from_fn(|_| String::new());
            for i in 0..4 { blogical[i] = sigma_items_b[i].clone(); }
            for j in 0..8 { blogical[4 + j] = dgb.fetch[j].clone(); }
            for i in 12..16 { blogical[i] = "0X0".to_string(); }
            // ㉘D7 簇头声明互无依赖者洗牌发射（密钥 token 声明与盐有先后依赖，合并为一条）
            let mut cluster_decls: Vec<String> = vec![
                format!("local {m32}={m32v}; ", m32 = sm32b, m32v = sm32bv),
                format!("local {bp}={{{lits}}}; ", bp = bpt, lits = boot_lits.join(",")),
                dgb.decl.clone(),
                salt_decl_b,
            ];
            let (kd_a, kd_b) = (cluster_decls[2].clone(), cluster_decls[3].clone());
            cluster_decls.truncate(2);
            rng.shuffle(&mut cluster_decls);
            cluster_decls.push(kd_a);
            cluster_decls.push(kd_b);
            for d in &cluster_decls { out.push_str(d); }
            // 状态模板（指纹选路第二支整表拷贝）——必须在 sm32/密钥 token 声明之后
            out.push_str(&format!("local {tm}={}; ",
                crate::VM::VM_Backend::Generator_chacha::state_literal(&blay, &blogical), tm = btm));
            let mut bdirect = blogical.clone();
            bdirect[12] = "ctr".to_string();
            bdirect[13] = "n1".to_string();
            bdirect[14] = "n2".to_string();
            bdirect[15] = "n3".to_string();
            let bs_lit = crate::VM::VM_Backend::Generator_chacha::state_literal(&blay, &bdirect);
            let bov = |rng: &mut GenRng, i: usize| -> String {
                rng.obfuscate_num((blay.rho[i] + 1) as i64, 1, &keys)
            };
            let (bo12, bo13, bo14, bo15) = (bov(&mut rng, 12), bov(&mut rng, 13), bov(&mut rng, 14), bov(&mut rng, 15));
            // ㉒② 焊接混合模数（cb 每 64 字节块重入——第二次起逻辑无分支）；
            // ㉒① 两条 16 环 → 4 态游标机（块内局部名 wq 双字母避开遮蔽池）。
            let mix_m_v = mk_m(&mut rng);
            let mix_e = weld.dst();
            let mix_weld = format!("local {};", mix_e) + &weld.weld(&mut rng, &mix_e, &format!("({})", mix_m_v));
            let s1_walk = {
                let off = rng.range(0, 100);
                let unit = |iv: &str| format!("o[{iv}]=s[{iv}]; ", iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 16, 4, None, &unit)
            };
            // ⑤ u32 拆分字节权逐构建派生
            let (bp2, bp3) = (rng.name(), rng.name());
            let (bp2v, bp3v) = (crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 16), crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 24));
            let bmap = rng.name();
            let bbase: Vec<String> = (0..16).map(|p| {
                let k = rng.range(0x40, 0xFFFF) as u32;
                format!("(0X{:X}-0X{:X})", (binv[p] * 4 + 1) as u32 + k, k)
            }).collect();
            out.push_str(&format!("local {bmap}={{{lits}}}; ", bmap = bmap, lits = bbase.join(",")));
            let bi_nb = rng.name();
            let s2_walk = {
                let off = rng.range(0, 100);
                let me = mix_e.clone();
                let bm = bmap.clone();
                let bn = bi_nb.clone();
                let unit = |iv: &str| format!("local {bi}={bm}[{iv}]; local wq=(s[{iv}]+o[{iv}])%{me}; out[{bi}]=wq%256; out[{bi}+0X1]=math_floor(wq/256)%256; out[{bi}+0X2]=math_floor(wq/{p2})%256; out[{bi}+0X3]=math_floor(wq/{p3})%256; ", me = me, iv = iv, bi = bn, bm = bm, p2 = bp2, p3 = bp3);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 16, 4, None, &unit)
            };
            out.push_str(&format!(
                "local function {cb}(n1,n2,n3,ctr) {mixw} local s; if ({h}%0X3)==0X0 then s={lit} else s={{}}; for {ti}=0X1,0X10 do s[{ti}]={tm}[{ti}] end; s[{o12}]=ctr; s[{o13}]=n1; s[{o14}]=n2; s[{o15}]=n3 end; local o={{}}; local {p2}={p2v}; local {p3}={p3v}; {w1} {rounds} local out={{}}; {w2} return out end; ",
                cb = bcb, h = h_var, lit = bs_lit, tm = btm, ti = rng.name(), mixw = mix_weld, w1 = s1_walk, w2 = s2_walk,
                o12 = bo12, o13 = bo13, o14 = bo14, o15 = bo15,
                p2 = bp2, p3 = bp3, p2v = bp2v, p3v = bp3v,
                rounds = mk_rounds(&mut rng, fn_qr.as_str(), &blay)));
            // 第 2 项：boot 簇 counter 同样走奇步长线性表；第 3 项 C：块链式解密
            // （与四个载荷簇同一套「上一块明文喂下一块 counter」规则）
            let bctr0e = rng.obfuscate_num(blay.ctr0 as i64, 1, &keys);
            let bstepe = rng.obfuscate_num(blay.step as i64, 1, &keys);
            let pz_b = poison_ks(&mut rng, "blk");
            {
                let (bn, bpos, bctr, bq, bfw, bww, blim) =
                    (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
                out.push_str(&format!(
                    "local function {sm}(e,pool_idx,kind) local {n}=#e; local out={{}}; local {pos}=0X1; local {ctr}={c0};                      while {pos}<={n} do local blk={cb}({sl},pool_idx,kind,{ctr}); {pz} local {lim}={pos}+0X3F; if {lim}>{n} then {lim}={n} end                        local {q}=0X0; local {fw}=0X0; local {ww}=0X1;                        while {pos}<={lim} do {q}={q}+0X1; local p={xt}[{sb}(e,{pos})][blk[{q}]]; out[{pos}]=p; if {q}<=0X8 then {fw}=({fw}+p*{ww})%{m32} {ww}=({ww}*0X100)%{m32} end {pos}={pos}+0X1 end                        {ctr}=({ctr}+{st}+{fw})%{m32} end; return out end; ",
                    sm = bsm, cb = bcb, sl = bs, c0 = bctr0e, pz = pz_b, m32 = sm32b, st = bstepe,
                    xt = xor_tbl_var, sb = fn_s_byte,
                    n = bn, pos = bpos, ctr = bctr, q = bq, fw = bfw, ww = bww, lim = blim));
            }
            let (v_str_i, v_str_g, v_str_s) = (rng.name(), rng.name(), rng.name());
            let fd18b = rng.name(); // 哑形参：boot 域 bsm 是 3 参，fold/rl 实参多余即弃
            let rl18b = rng.name();
            // kind 取 dgb.knum：与写侧 `stream_xor(&bkey,[bsalt,i,bkind],…)` 的
            // bkind（= bges.knum）必须同值；kstr 是载荷簇字符串解码器用的那个。
            let (bkind_decl, bkind_lit) = (String::new(), dgb.knum.clone());
            let _ = bkind;
            out.push_str(&bkind_decl);
            // 第 2 项：boot 簇 dec_str 同样两型发射 + 运行期按指纹选路
            let (bd_f0, bd_f1) = {
                let a = rng.range(0, 4);
                let mut b = rng.range(0, 3);
                if b >= a { b += 1; }
                (a, b)
            };
            let bd_a = rng.name();
            let bd_b = rng.name();
            for (f, nm) in [(bd_f0, bd_a.clone()), (bd_f1, bd_b.clone())] {
                out.push_str(&crate::VM::VM_Backend::Generator_flow::build_decstr(
                    &mut rng, f, nm.as_str(), bsm.as_str(), bkind_lit.as_str(),
                    v_str_s.as_str(), v_str_i.as_str(), v_str_g.as_str(), fd18b.as_str(), rl18b.as_str()));
            }
            out.push_str(&format!("local {b}=nil; ", b = bdec));
            out.push_str(&bind2(&mut rng, bdec.as_str(), bd_a.as_str(), bd_b.as_str()));
            // ㉒② 每个内建槽号过一次焊接构造：惰性缓存+大随机键+校验恒等式。
            // 全块只声明一个单字母局部（do 域内复用——E 先是载荷槽、下一个内建又变
            // 寄存器位），局部数不膨胀，命名维度消失。
            let bi_e = weld.dst();
            out.push_str(&format!("do local {};", bi_e));
            // ㉘D6 内建名各次迭代互不依赖（各自写不同槽位、bname 仅暂存、焊接
            // 构造按调用独立缓存）——迭代整体洗牌，消除 BUILTIN_NAMES 的固定枚举序
            let mut builtin_stmts: Vec<String> = Vec::new();
            for (i, _) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
                let slot = builtin_slot_perm[i];
                let wslot_stmt = weld.weld(&mut rng, &bi_e, &(slot + 1).to_string());
                builtin_stmts.push(format!(
                    "{bname}={bdec}({bp}[{lidx}],{ridx}); {ws} {reg}[{we}]={benv}[{bname}]; if {reg}[{we}]==nil and getgenv then {reg}[{we}]=getgenv()[{bname}] end; ",
                    bname = var_bname, bdec = bdec, bp = bpt, lidx = i + 1, ridx = i,
                    ws = wslot_stmt, we = bi_e,
                    reg = var_builtin_reg, benv = var_boot_env
                ));
            }
            rng.shuffle(&mut builtin_stmts);
            for stmt in &builtin_stmts { out.push_str(stmt); }
            out.push_str(" end; ");
            // ⑱ 用毕销毁（⑳.1 伪装化）：连续 X=nil 运行是指纹——每个变量换一种
            // "取值赋值" 形态消化，nil 全部来自合法表达式的自然缺失：
            // 槽位表取未用键 / 未命中补取(恒执行) / 空表取键 / or 链 /
            // 条件式恒 nil / 间接索引，混入常见池取图案，无 =nil 字面赋值
            let (g1, g2, g3) = (rng.name(), rng.name(), rng.name());
            let h1 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h2 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h3 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h4 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h5 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            let h6 = format!("0X{:X}", rng.range(0x1000, 0xFFFFF));
            out.push_str(&format!(
                "local {g1}={reg}[{h1}]; {bk}={g1}; if not {g1} then {bs}={reg}[{h2}] end; \
                 local {g2}=({{}})[{h3}]; {bcb}={g2}; {bsm}={reg}[{h4}] or ({{}})[{h5}]; \
                 {bdec}={bdec} and nil or {bdec}; local {g3}={reg}; {bpt}={g3}[({{}})[{h6}]]; ",
                reg = var_builtin_reg, g1 = g1, g2 = g2, g3 = g3,
                bk = bk, bs = bs, bcb = bcb, bsm = bsm, bdec = bdec, bpt = bpt,
                h1 = h1, h2 = h2, h3 = h3, h4 = h4, h5 = h5, h6 = h6));
            // ② 内建名簇的 token 辅料（X/掩码/槽位表/异或实现/状态模板/kind）同样用毕销毁
            let mut boot_aux = vec![btm.clone()];
            boot_aux.push(bkind_lit.clone());
            out.push_str(&crate::VM::VM_Backend::Generator_kdf::dispose_stmt(&mut rng, &boot_aux));
        }
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
        
        // ⑳.5 尾部探针：此前最后一个采样点在 parts 之后——main_chunk 解码/内建簇/
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
