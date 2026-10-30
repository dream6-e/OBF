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
        fix_var,
        root_kw,
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
        shell: mut shell,
    } = mid;
    let ChainIn {
        rng: mut rng, global_names, gn_key, at: mut at, keys, enc,
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
        psn_pool,
        poison_delay_key,
        var_a2,
        var_whiten,
        var_whiten_pos,
        whiten_mul,
        whiten_add,
        var_builtin_reg,
        native_type,
        native_pairs,
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
        sc_add,
        sc_add_k1,
        sc_mul_k2,
        sc_rot_in,
        sc_rot_k2,
        sc_rot_k4,
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
        vault: mut vault,
        header_captures,
        ros_params,
        ..
    } = x;
    let poison_delay_expr = format!("{}[0X{:X}]", kreg_n, poison_delay_key);
        let var_enc_c = rng.name();
        let var_tbl = rng.name();
        let var_idx_chunk = rng.name();
        let var_e = rng.name();
        let var_cache = rng.name();

        let var_state = rng.name();
        let var_scan_only = rng.name();
        let var_uctx = rng.name();
        let wg_u = rng.obfuscate_num(crate::VM::VM_Backend::Generator::WHITEN_GROUP as i64, 1, &keys);
        let ww_u = rng.obfuscate_num((crate::VM::VM_Backend::Generator::WHITEN_WORD + 5) as i64, 1, &keys);
        let u_ctx_init = format!("{kdf}({root},{g},{w})", kdf = kdf_name, root = root_fetch[6], g = wg_u, w = ww_u);
        let s_init = rng.range(0x100, 0xFFF) as i64;
        let s_insts = rng.range(0x1000, 0x1FFF) as i64;
        let s_consts = rng.range(0x2000, 0x2FFF) as i64;
        let s_protos = rng.range(0x3000, 0x3FFF) as i64;
        let s_debug = rng.range(0x4000, 0x4FFF) as i64;
        let s_ret = rng.range(0x5000, 0x5FFF) as i64;

        let mt_dc = rng.name();
        let mt_dc_base = rng.range64(0x10_0000, 0x01FF_FFFF);
        let mt_dc_decl = crate::VM::VM_Backend::Generator_util::emit_mt_state_decl(&mut rng, &mt_dc, mt_dc_base);
        let obf_s_init = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_init);
        let obf_s_insts = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_insts);
        let obf_s_consts = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_consts);
        let obf_s_protos = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_protos);
        let obf_s_debug = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_debug);
        let obf_s_ret = crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_ret);
        let (v_ch_g, v_ch_out, v_ch_i, v_ch_n) = (rng.name(), rng.name(), rng.name(), rng.name());

        let cpp = rng.name();
        let cpq = rng.name();
        let body_init = format!(
            "local function {cpp}({cpq},{cpq}) {cpq}=0X1; return {cpq} end; {st}={nxt}; {c}.{pf_n}={bx}({a5}(),{uctx}); {c}.{pf_ld}={bx}({a5}(),{bx}({rot}({c}.{pf_n},0X5),{rot}({uctx},0XB))); {c}.{pf_lld}={bx}({a5}(),{bx}({rot}({c}.{pf_n},0XD),{rot}({uctx},0X13))); {c}.{pf_nups}={rd}(); \
             {c}.{pf_numparams}={rd}(); {c}.{pf_is_vararg}={rd}(); {c}.{pf_maxstack}={rd}(); if {i} > {cpp}({cpq},{cpq}) then {i} = {i} - {cpp}({cpq},{cpq}) end; ",
            st = var_state, nxt = obf_s_insts, c = fn_c, a5 = fn_a5, rd = fn_read_dec,
            bx = fn_bxor, rot = fn_rotl32, uctx = var_uctx,
            pf_n = pf_n, pf_ld = pf_ld, pf_lld = pf_lld, pf_nups = pf_nups,
            pf_numparams = pf_numparams, pf_is_vararg = pf_is_vararg, pf_maxstack = pf_maxstack, i = v_ch_i,
            cpp = cpp, cpq = cpq
        );
        // ⑨ 真分支状态扰动：按运行期 (st+i)%2 走两条不同算术更新支（取代原先空 then/else）
        let it9 = |_rng: &mut GenRng, st: &str| format!(
            "if (({st}+{i})%0X2)==0X0 then {g}=({g}*0X3)%0X7F else {g}=({g}*0X5)%0X7F end; ",
            st = st, i = v_ch_i, g = v_ch_g);
        let (kb_x, kc_x, ki1_x, ki2_x) = (
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_kb as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_kc as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_ki1 as i64),
            crate::VM::VM_Backend::Generator_flow::deep10(&mut rng, fn_bxor.as_str(), bc_ki2 as i64),
        );
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
        let arr_init = format!(
            "if {scan_only} then {c}.{op}={{}}; {c}.{a}={{}}; {c}.{b}={{}}; {c}.{cc}={{}}; else {sh_get}{sh_assign} end; ",
            scan_only = var_scan_only, c = fn_c, op = pf_opcodes, a = pf_a_arr,
            b = pf_b_arr, cc = pf_c_arr, sh_get = sh_get, sh_assign = sh_assign
        );
        let insts_params: [&str; 10] = [
            &fn_c, &var_scan_only, &kreg_n, &keys.tbl_p, &fn_bxor, &fn_rotl32, &fn_a5, &fn_a10, &fn_read_dec, &var_uctx,
        ];
        let m32_ins = rng.name();
        let insts_body = format!(
            "{arr_init} local {m32}={m32v}; \
             local function {dcb}({w},{m},{k},{q}) if {w}<0X0 then {w}={w}+{m32} end {w}={bx}({bx}({w},{k}),{bx}({m},{q})) if {w}>={m31v} then {w}={w}-{m32} end return {w} end; \
             local {i}=0; local {n}={bx}({a5}(),{bx}({rot}({c}.{pf_n},0XB),{rot}({uctx},0X7))); {c}.{cnt18}={n}; local {kp}={c}.{pf_ld}; local {pb}={c}.{pf_lld}; local {ka}={bx}({kp},{pb}); local {kb18}={bx}({kp},({pb}*0X13+0X5A3C9)%{m32}); local {kc18}={bx}({pb},({kp}*0X0B+0X3579B)%{m32}); \
             local {kbp}={bx}({kbx},{bx}({rot}({c}.{pf_n},0X3),{rot}({uctx},0X7))); local {kcp}={bx}({kcx},{bx}({rot}({kp},0X9),{rot}({uctx},0XD))); \
             local {k1p}={bx}({k1x},{bx}({rot}({pb},0XF),{rot}({c}.{pf_n},0X15))); local {k2p}={bx}({k2x},{bx}({rot}({uctx},0X11),{rot}({kp},0X19))); \
             {kr}[0X{jtk:X}]={kr}[0X{jtk:X}] or {{}}; {kr}[0X{jtk:X}][{pb}]={bx}({kbp},{k1p})%0X100000; \
             local {wr}={bx}({bx}({c}.{pf_n},{rot}({kp},0X7)),{bx}({rot}({pb},0XD),{rot}({uctx},0X13))); \
             while {i} < {n} do {i} = {i} + 1; \
             local {mv}={a5}() if {mv}<0 then {mv}={mv}+{m32} end local {g18}={bx}({mv},{bx}({kp},{wr}%0X10000000)) {c}.{pf_opcodes}[{i}+{pb}]={g18} \
             local {ad}={bx}({a10}()%{m32},{bx}({rot}({wr},0X5),{c}.{pf_n})) {c}.{pf_a_arr}[{i}+{pb}]={bx}({ad},{ka}) \
             local {kbi}={bx}({kbp},{rot}({wr},0XB)) local {kci}={bx}({kcp},{rot}({wr},0X11)) \
             {c}.{pf_b_arr}[{i}+{pb}]={bx}({dcb}({a10}(),{g18},{kbi},{k1p})%{m32},{kb18}) {c}.{pf_c_arr}[{i}+{pb}]={bx}({dcb}({a10}(),{g18},{kci},{k2p})%{m32},{kc18}) \
             {wr}={bx}(({rot}({wr},0X7)+{g18})%{m32},{ad}) \
             local {jv}=(({mv}-({mv}%0X20000000))/0X20000000)%4; for _=1,{jv} do {wr}=({rot}({wr},0X3)+{rd}()+0X3D)%{m32} end end; \
             return {bx}({uctx},{rot}({wr},0X9))",
            m32 = m32_ins,
            m32v = crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 32),
            m31v = crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 31),
            c = fn_c, a5 = fn_a5, a10 = fn_a10,
            pf_opcodes = pf_opcodes, pf_a_arr = pf_a_arr, pf_b_arr = pf_b_arr, pf_c_arr = pf_c_arr,
            arr_init = arr_init,
            i = rng.name(), n = rng.name(), cnt18 = pf_cnt18, kp = rng.name(), g18 = rng.name(),
            pb = rng.name(), ka = rng.name(), kb18 = rng.name(), kc18 = rng.name(),
            kbp = rng.name(), kcp = rng.name(), k1p = rng.name(), k2p = rng.name(),
            wr = rng.name(), ad = rng.name(), kbi = rng.name(), kci = rng.name(),
            pf_n = pf_n, pf_ld = pf_ld, pf_lld = pf_lld,
            dcb = rng.name(), w = rng.name(), m = rng.name(), k = rng.name(), q = rng.name(),
            bx = fn_bxor.as_str(), rot = fn_rotl32.as_str(), uctx = var_uctx.as_str(),
            mv = rng.name(), kbx = kb_x, kcx = kc_x, k1x = ki1_x, k2x = ki2_x,
            jv = rng.name(), rd = fn_read_dec.as_str(), kr = kreg_n, jtk = fc18.jtbl_key
        );
        let m_insts = shell.add(&mut rng, &insts_params, insts_body);
        let body_insts = format!(
            "{st}={nxt}; {tree9} {uctx}={call}; ",
            st = var_state, nxt = obf_s_consts, uctx = var_uctx,
            tree9 = it9(&mut rng, var_state.as_str()),
            call = shell.call(&m_insts, &insts_params)
        );
        let cid_index = uni.register("__index");
        let cid_gk = uni.register("KryvexObf_");
        let (ci_stmt, sc_index2) = uni.fetch(&mut rng, cid_index);
        let (gk_stmt, sc_kobf) = uni.fetch(&mut rng, cid_gk);
        let (v_sc_idx, v_sc_kobf) = (rng.name(), rng.name());
        let psn_pick = psn_pool[rng.range(0, psn_pool.len())].as_str().to_string();
        let psn_pick = psn_pick.as_str();
        let rkb_expr = format!(
            "{kdf}({root},0X{gr:X},0X{rw:X})",
            kdf = kdf_name,
            root = root_fetch[ros_params.r_rk],
            gr = ros_params.r_gr,
            rw = ros_params.r_w
        );
        let bc_scatter = crate::VM::VM_Backend::Generator_flow::build_consts(
                &mut shell, kreg_n.as_str(),
                &mut vault, &mut rng, &keys, &kc, pj_name.as_str(), fn_bxor.as_str(),
                v_sc_idx.as_str(), v_sc_kobf.as_str(), var_state_flag.as_str(), var_idx_chunk.as_str(),
                var_tbl.as_str(), var_e.as_str(), &ds_names, &dn_names, fn_read_string.as_str(), fn_s_byte.as_str(),
                fn_a5.as_str(), fn_read_dec.as_str(), native_type.as_str(), native_pairs.as_str(),
                var_enc_c.as_str(), var_cache.as_str(),
                fn_c.as_str(), pf_consts.as_str(), const_path_key.as_str(),
                &v_ch_i, &v_ch_n, &t,
                pf_opcodes.as_str(), pf_a_arr.as_str(), pf_b_arr.as_str(), pf_c_arr.as_str(), fn_rotl32.as_str(), &fc18,
                &tag_map18, &salt_names, pf_n.as_str(), pf_ld.as_str(), pf_lld.as_str(), pf_cnt18.as_str(),
                chain_delta, chain_m, chain_k0, {psn_pick},
                poison_delay_expr.as_str(), var_uctx.as_str(),
                &ros_params, rkb_expr.as_str());
        let body_consts = format!(
            "{st}={nxt}; {ci_stmt}{gk_stmt} local {vi},{vk}={sci},{sck}; {bc_scatter} ",
            st = var_state, nxt = obf_s_protos,
            ci_stmt = ci_stmt, gk_stmt = gk_stmt,
            vi = v_sc_idx, vk = v_sc_kobf, sci = sc_index2, sck = sc_kobf,
            bc_scatter = bc_scatter
        );
        let (p18, u0_18, ub_18, s1a, b1a, sv18, svf18, rr18, scan18, scan_flag18, scan_mode_snapshot, thk18) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let body_protos = format!(
            "{st}={nxt}; {tree9} {c}.{pf_protos}={{}}; local {i}=0; local {n}={bx}({a5}(),{bx}({rot}({c}.{pf_n},0XF),{rot}({uctx},0X5))); {md18}={c}.{pf_protos}; {np18}={n}; \
             while {i} < {n} do {i} = {i} + 1; \
               local {p0},{u0}={a2},{uctx}; local {s1},k2s,k3s,k4s=k1,k2,k3,k4; local {scan_flag}={flg}; {flg}=true; local {scan_mode_snapshot}={scan_mode}; {scan_mode}={scan_mode_snapshot}; local {scan}={dc}(); {scan_mode}={scan_mode_snapshot}; {flg}={scan_flag}; \
               local {thk}=function() if {scan} then local {rr}={scan}; {scan}=nil; return {rr} end; local {sv},{ub}={a2},{uctx}; local {svf}={flg}; local {b1},k2b,k3b,k4b=k1,k2,k3,k4; \
                 {a2}={p0}; {uctx}={u0}; k1,k2,k3,k4={s1},k2s,k3s,k4s; {flg}=true; local {rr}={dc}(); \
                 {a2}={sv}; {uctx}={ub}; k1,k2,k3,k4={b1},k2b,k3b,k4b; {flg}={svf}; return {rr} end; \
               if ({i}%0X2)==0X0 then {c}.{pf_protos}[{i}+({i}%0X2)]={thk} else {c}.{pf_protos}[{i}+(({i}%0X2)-0X1)]={thk} end; \
               {md18}={c}.{pf_protos}; {np18}={n}; \
             end; ",
            st = var_state, nxt = obf_s_debug, c = fn_c, pf_protos = pf_protos, pf_n = pf_n, a5 = fn_a5,
            bx = fn_bxor, rot = fn_rotl32, uctx = var_uctx,
            dc = fn_decode_chunk, i = v_ch_i, n = v_ch_n, thk = thk18,
            md18 = md21, np18 = np21, a2 = var_a2, flg = var_state_flag,
            scan_mode = var_scan_only, scan_mode_snapshot = scan_mode_snapshot,
            p0 = p18, u0 = u0_18, ub = ub_18, s1 = s1a, b1 = b1a, sv = sv18, svf = svf18,
            rr = rr18, scan = scan18, scan_flag = scan_flag18,
            tree9 = it9(&mut rng, var_state.as_str())
        );
        let (go, gb, ga, gx, gs, gh, gi, co, cm) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
             rng.name(), rng.name());
        let gate_seed = rng.range(0x1000, 0x7FFF_FF00);
        let wipe_k = rng.range(0x1000, 0xFFFFF);
        let (v_va_pc, v_va_ts, v_va_sb, v_va_tnum) = (
            vault.global("pcall"), vault.global("tostring"),
            vault.member("string", "byte"), vault.lit("number"));
        let dbg_params: [&str; 3] = [&fn_c, &kreg_n, &native_type];
        let dbg_body = format!(
            "{c}.{pn}=({{}})[0X{wk:X}];local {go},{gb}={pc}(function() local {ga},{gx}={{}},{{}};local {gs}={ts}({ga})..{ts}({gx});local {gh}=0X{seed:X};for {gi}=1,#{gs} do {gh}=({gh}*0X21+{sby}({gs},{gi}))%0X7FFFFF01 end;return {gh}%0X2 end);if {go} and {gb}==0X0 then local {co},{cm}={pc}(function() local {ga},{gx}={{}},{{}};return {ts}({ga})=={ts}({gx}) or {nt}(#{ts}({ga}))~={tnum} end);return (not {co} or {cm}) end;return false",
            c = fn_c, pn = pf_n, wk = wipe_k,
            go = go, gb = gb, ga = ga, gx = gx, gs = gs, gh = gh, gi = gi, seed = gate_seed,
            co = co, cm = cm, nt = native_type,
            pc = v_va_pc, ts = v_va_ts, sby = v_va_sb, tnum = v_va_tnum
        );
        let m_dbg = shell.add(&mut rng, &dbg_params, dbg_body);
        let dbg_psn = psn_pool[rng.range(0, psn_pool.len())].clone();
        let body_debug = format!(
            "{st}={nxt}; {tree9} if {call} then {psn}=true end; ",
            st = var_state, nxt = obf_s_ret,
            call = shell.call(&m_dbg, &dbg_params),
            psn = dbg_psn,
            tree9 = it9(&mut rng, var_state.as_str())
        );
        let body_ret = format!(
            "if ({c}.{plld}%0X2)==0X0 then {out}={c}; {g}={g}+0X1+({c}.{plld}%0X2) else {out}={c}; {g}={g}+({c}.{plld}%0X2) end; ",
            out = v_ch_out, c = fn_c, plld = pf_lld, g = v_ch_g
        );

        // ⑳ 行信息探针仅作兼容性检查：宿主错误栈格式/行号不同或不可用时必须 fail-open，
        // 不得把正常 Lua 运行环境判成篡改。采样位来自对象地址，不消费 math.random。
        // 定义式/内联两形态仍保留随机化探针与错误消息针式，但不制造固定报错。
        let (v_lg_pc, v_lg_ts, v_lg_sb, v_lg_sc, v_lg_sf, v_lg_sfun, v_lg_sstr) = (
            vault.global("pcall"), vault.global("tostring"),
            vault.member("string", "byte"), vault.member("string", "char"),
            vault.member("string", "find"),
            vault.lit("function"), vault.lit("string"));
        let line_guard = |rng: &mut GenRng, _uni: &mut crate::VM::VM_Backend::Generator_util::UniStream, inline: bool| -> String {
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
            let (f1, f2, f3) = (rng.name(), rng.name(), rng.name());
            let mut ht_body = format!("local {u}={h} and {tol} or nil; local {f1}={nt}({u}); local {f3}=0X1; ",
                u = p_u, h = p_hit, tol = tolerant, f1 = f1, nt = native_type, f3 = f3);
            let (xh_pre, jf_expr, js_expr, sf_expr) = if inline {
                let mask = rng.range(1, 256) as u8;
                let (xh, mv) = (rng.name(), rng.name());
                let (pa, pb, pr, pw, pv, pda, pdb) = (rng.name(), rng.name(), rng.name(),
                    rng.name(), rng.name(), rng.name(), rng.name());
                let nlit = |rng: &mut GenRng, v: u8| -> String {
                    if rng.range(0, 2) == 0 { format!("{}", v) } else { format!("0X{:X}", v) }
                };
                let pre = format!(
                    "local {xh}=function({a},{b}) local {r},{w}=0X0,0X1 for {v}=0X1,0X8 do local {da},{db}={a}%0X2,{b}%0X2 if {da}~={db} then {r}={r}+{w} end; {a}=({a}-{da})/0X2 {b}=({b}-{db})/0X2 {w}={w}+{w} end; return {r} end; local {mv}={mk}; ",
                    xh = xh, a = pa, b = pb, r = pr, w = pw, v = pv, da = pda, db = pdb,
                    mv = mv, mk = nlit(&mut *rng, mask));
                let mut xstr = |plain: &[u8]| -> String {
                    let args = plain.iter()
                        .map(|b| format!("{xh}({c},{m})", xh = xh, c = nlit(&mut *rng, b ^ mask), m = mv))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("string.char({})", args)
                };
                let jf = xstr(&[102, 117, 110, 99, 116, 105, 111, 110]);
                let js = xstr(&[115, 116, 114, 105, 110, 103]);
                let sfind = format!("string[{}]", xstr(&[102, 105, 110, 100]));
                (pre, jf, js, sfind)
            } else {
                (String::new(), v_lg_sfun.clone(), v_lg_sstr.clone(), v_lg_sf.clone())
            };
            let mut hopts = vec![
                format!("if {f1}=={jf_expr} then {f3}=({f3}*0X3+0X1)%0X7F else {f3}=({f3}*0X5+0X3)%0X7F end; ", f1 = f1, jf_expr = jf_expr, f3 = f3),
                format!("if {f1}=={js_expr} and #{u}>0X0 then {f3}=({f3}+#{u})%0X7F else {f3}=({f3}*0X7+0X2)%0X7F end; ", f1 = f1, js_expr = js_expr, u = p_u, f3 = f3),
                format!("for {f2}=0X1,0X{} do if {u} then {f3}=({f3}+{f2})%0X7F break else {f3}=({f3}*0X2+0X1)%0X7F end end; ", rng.range(2, 6), f2 = f2, u = p_u, f3 = f3),
                format!("local {f2}=({u})and ({f3}+0X1) or ({f3}+0X2); {f3}={f2}%0X7F; ", f2 = f2, u = p_u, f3 = f3),
            ];
            rng.shuffle(&mut hopts);
            let hn = 1 + rng.range(0, 2);
            for i in 0..hn { ht_body.push_str(&hopts[i]); }
            if rng.range(0, 2) == 0 {
                ht_body.push_str(&format!("if not {u} then {f3}=({f3}*0X3+0X5)%0X7F else {ts} end; ", u = p_u, f3 = f3, ts = ts));
            } else {
                ht_body.push_str(&format!("if {u} then {ts} else {f3}=({f3}*0X5+0X7)%0X7F end; ", u = p_u, f3 = f3, ts = ts));
            }
            let mut ms = vec![
                format!("{t}.{drv}=function({s})local {o},{e}={s}:{pc}() {s}:{ht}({s}:{ck}({e}))end; ",
                    t = tbl, drv = m_drv, s = p_self, o = rng.name(), e = p_err,
                    pc = m_pcall, ht = m_hit, ck = m_chk),
                format!("{t}.{pc}=function({s})return {pcf}({s}.{pb},{s})end; ",
                    t = tbl, pc = m_pcall, s = p_self, pb = m_probe,
                    pcf = if inline { "pcall" } else { v_lg_pc.as_str() }),
                format!("{t}.{pb}=function({s}){body} end; ",
                    t = tbl, pb = m_probe, s = p_self, body = pb),
                format!("{t}.{ck}=function({s},{e})local {sc}={scf};return {nt}({e})=={js} and {sf}({e},{ndl})end; ",
                    t = tbl, ck = m_chk, s = p_self, e = p_err, sc = sc, ndl = needle, nt = native_type,
                    js = js_expr, sf = sf_expr,
                    scf = if inline { "string.char" } else { v_lg_sc.as_str() }),
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
            let body = format!("{xh_pre}local {t}={{}} {ms} {t}:{drv}() ",
                xh_pre = xh_pre, t = tbl, ms = ms.concat(), drv = m_drv);
            let (go, gb, ga, gx, gs, gh, gi) =
                (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            let gate_seed = rng.range(0x1000, 0x7FFF_FF00);
            if inline {
                format!("do {} end;", body)
            } else {
                format!(
                    "local {go},{gb}={pc}(function() local {ga},{gx}={{}},{{}};local {gs}={ts}({ga})..{ts}({gx});local {gh}=0X{seed:X};for {gi}=1,#{gs} do {gh}=({gh}*0X21+{sb}({gs},{gi}))%0X7FFFFF01 end;return {gh}%0X2 end);if {go} and {gb}==0X0 then {body} end",
                    go = go, gb = gb, ga = ga, gx = gx, gs = gs, gh = gh, gi = gi,
                    pc = v_lg_pc, ts = v_lg_ts, sb = v_lg_sb,
                    seed = gate_seed, body = body
                )
            }
        };
        let lg_params: [&str; 2] = [&kreg_n, &native_type];
        let lg_b0 = line_guard(&mut rng, &mut uni, false);
        let lg_b1 = line_guard(&mut rng, &mut uni, false);
        let m_lg0 = shell.add(&mut rng, &lg_params, lg_b0);
        let m_lg1 = shell.add(&mut rng, &lg_params, lg_b1);
        let lg_call0 = format!("{}; ", shell.call(&m_lg0, &lg_params));
        let lg_call1 = format!("{}; ", shell.call(&m_lg1, &lg_params));
        let mut ch_pairs: Vec<(String, String)> = vec![
            (crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_init), body_init),
            (crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_insts), body_insts),
            (crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_consts), body_consts),
            (crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_protos), body_protos),
            (crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_debug), body_debug),
            (crate::VM::VM_Backend::Generator_util::emit_mt_state_expr(&mut rng, &mt_dc, mt_dc_base, s_ret), body_ret),
        ];
        rng.shuffle(&mut ch_pairs);
        let mut chain = String::new();
        for (idx, (val, body)) in ch_pairs.iter().enumerate() {
            let kw = if idx == 0 { "if" } else { "elseif" };
            chain.push_str(&format!("{} {} == {} then {} ", kw, var_state, val, body));
        }
        chain.push_str(&format!("else {} = {} + 1; end; ", v_ch_g, v_ch_g));

    let block_dec_chunk = format!(
        "local {scan_mode}=false; local {uctx}={uinit}; {mt_dc_decl} local function {fn_dec_chunk}() local {fn_c}, {t}, {var_state} = {{}}, nil, {obf_s_init}; \
         local {g}, {out}, {i}, {n} = 0, nil, 0, 0; \
         while {g} < 1 do {chain} end; \
         return {out} end; ",
        fn_dec_chunk = fn_decode_chunk, fn_c = fn_c, t = t, var_state = var_state,
        scan_mode = var_scan_only, uctx = var_uctx, uinit = u_ctx_init,
        mt_dc_decl = mt_dc_decl, obf_s_init = obf_s_init,
        g = v_ch_g, out = v_ch_out, i = v_ch_i, n = v_ch_n,
        chain = chain
    );

        let (pdef_body, pdef_exports) = block_p_def
            .split_once(" @PDEF@")
            .expect("block_p_def must contain @PDEF@");
        let pdef_exports = pdef_exports.trim().to_string();
        let fn_bxor2 = pdef_exports
            .split(',')
            .nth(1)
            .expect("pdef_exports has fn_bxor2")
            .trim()
            .to_string();
        let m_pdef = shell.add(
            &mut rng,
            &[&kreg_n],
            format!("{} return {}", pdef_body, pdef_exports),
        );
        let block_p_def = format!(
            "local {}={}; ",
            pdef_exports,
            shell.call(&m_pdef, &[&kreg_n])
        );

        let m_vmcore = shell.add(&mut rng, &[&kreg_n], block_vm_core);
        let block_vm_core = format!("{}; ", shell.call(&m_vmcore, &[&kreg_n]));

        let v_mm_idx = vault.lit("__index");
        let block_execute_def = block_execute_def.replace("{__index=", &format!("{{[{}]=", v_mm_idx));
        let (rkey_stmt, block_execute_def) = if let Some((hdr_and_body, rest)) = block_execute_def.split_once("@RKEY@") {
            let (body, after_rkey) = rest.split_once("@RKEY@").expect("second @RKEY@");
            let hdr_items: Vec<&str> = hdr_and_body.split(',').map(|s| s.trim()).collect();
            let fn_rkey_name = hdr_items[0];
            let rkey_params: Vec<&str> = hdr_items[1..].to_vec();
            let rk_var = rkey_params[1];
            let kr_var = rkey_params[2];
            let call_params: Vec<&str> = rkey_params[13..].to_vec();
            let m_rkey = shell.add(&mut rng, &rkey_params, body.to_string());
            let (rn1, rn2, rn3) = (rng.name(), rng.name(), rng.name());
            let stmt = format!(
                "local {fn_rkey}=function({cargs}) local {rn1},{rn2},{rn3}; {rk},{kr},{rn1},{rn2},{rn3}={call}; return {rn1},{rn2},{rn3} end; ",
                fn_rkey = fn_rkey_name,
                cargs = call_params.join(","),
                rn1 = rn1, rn2 = rn2, rn3 = rn3,
                rk = rk_var, kr = kr_var,
                call = shell.call(&m_rkey, &rkey_params),
            );
            (stmt, after_rkey.to_string())
        } else {
            (String::new(), block_execute_def)
        };
        let exec_marker = format!("{} = function(", fn_execute);
        let block_execute_def = if let Some(pos) = block_execute_def.find(&exec_marker) {
            let prefix = &block_execute_def[..pos];
            let rest = &block_execute_def[pos..];
            let dc_var = prefix
                .trim_start()
                .strip_prefix("local ")
                .and_then(|s| s.split('=').next())
                .unwrap()
                .trim()
                .to_string();
            let m_dc = shell.add(
                &mut rng,
                &[&fn_bxor2, &kreg_n],
                format!("{} return {}", prefix, dc_var),
            );
            format!(
                "{}local {}={}; {}",
                rkey_stmt,
                dc_var,
                shell.call(&m_dc, &[&fn_bxor2, &kreg_n]),
                rest
            )
        } else {
            format!("{}{}", rkey_stmt, block_execute_def)
        };

        let mut parts = vec![
            block_p_def,
            block_methods,
            block_vm_core,
            block_packer_vars,
            block_execute_def,
            block_dec_header,
            block_dec_helpers,
            block_dec_readers,
            block_chacha_setup.clone(),
            cluster_parts[0].clone(),
            cluster_parts[1].clone(),
            cluster_parts[2].clone(),
            block_dec_chunk,
        ];

        // 外部 API 名 handle 映射（GlobalHandles pass 的产物侧）：拆入外层兄弟方法 m_gn。
        if !global_names.is_empty() {
            let gr_gn = rng.range(0x0300, 0xFFFF) as u32;
            let rk = rng.range(0, 8);
            let w0 = rng.range(0x40, 0x100) as u32;
            let mut idx_map: Vec<String> = Vec::new();
            let mut ents: Vec<String> = Vec::new();
            for (idx, (h, name)) in global_names.iter().enumerate() {
                let i = (idx + 1) as u32;
                idx_map.push(format!("[0X{:X}]=0X{:X}", h, i));
                let mut bs: Vec<String> = Vec::new();
                for (j, byte) in name.iter().enumerate() {
                    let w = w0 + i * 0x100 + j as u32 + 1;
                    let kw = crate::VM::VM_Backend::Generator_chacha::derive_word(enc.root[rk], gr_gn, w);
                    bs.push(format!("0X{:X}", (*byte as u32) ^ (kw & 0xFF)));
                }
                ents.push(format!("{{{}}}", bs.join(",")));
            }
            let (v_i, v_e, v_h, v_o, v_j, v_ii, v_ee) =
                (rng.name(), rng.name(), rng.name(),
                 rng.name(), rng.name(), rng.name(), rng.name());
            let gn_part = format!(
                "{kreg}[0X{key:X}]=(function() local {vi}={{{im}}}; local {ve}={{{en}}}; \
                 return function({h}) \
                 local {ii}={vi}[{h}]; local {ee}={ve}[{ii}]; local {o}={{}}; \
                 for {j}=0X1,#{ee} do {o}[{j}]=string_char({bx}({ee}[{j}],{kdf}({root},0X{g:X},0X{w0:X}+{ii}*0X100+{j})%0X100)) end; \
                 return table_concat({o}) end end)(); ",
                vi = v_i, im = idx_map.join(","), ve = v_e, en = ents.join(","),
                h = v_h, ii = v_ii, ee = v_ee, o = v_o, j = v_j,
                bx = fn_bxor, kdf = kdf_name, root = root_fetch[rk], g = gr_gn, w0 = w0,
                kreg = kreg_n, key = gn_key
            );
            let m_gn = shell.add(
                &mut rng,
                &[&kreg_n, &keys.tbl_p, &fn_bxor, &kdf_name, &root_kw, &fix_var, &fn_xor32, "string_char", "table_concat"],
                gn_part,
            );
            let gn_call = format!(
                "{}; ",
                shell.call(
                    &m_gn,
                    &[&kreg_n, &keys.tbl_p, &fn_bxor, &kdf_name, &root_kw, &fix_var, &fn_xor32, "string_char", "table_concat"],
                )
            );
            // block_chacha_setup 在 vec 里按内容定位（其声明带 xor32/kdf/根 token）
            let chacha_pos = parts.iter().position(|p| *p == block_chacha_setup);
            parts.insert(chacha_pos.map(|p| p + 1).unwrap_or(parts.len()), gn_call);
        }

        {
            let gap20 = rng.range(0, parts.len() + 1);
            parts.insert(gap20, lg_call0.clone());
        }

        let mut shuffled_guards = at.guards.clone();
        rng.shuffle(&mut shuffled_guards);
        let [at_env, at_dec, at_res, at_net, at_state, at_st, at_tw] = at.exports.clone();
        {
            let atg_params: [&str; 8] = [&kreg_n, &at_env, &at_dec, &at_res, &at_net, &at_state, &at_st, &at_tw];
            let m_atg = shell.add(&mut rng, &atg_params, shuffled_guards.join(" "));
            let gap_idx = rng.range(0, parts.len() + 1);
            parts.insert(gap_idx, format!("{}; ", shell.call(&m_atg, &atg_params)));
        }

        let mut wai_body = String::new();
        let (hdr_pre, digest_body) = header_block
            .split_once("@DIGEST@")
            .expect("header_block must contain @DIGEST@");
        let var_s_name = hdr_pre
            .trim_start()
            .strip_prefix("local ")
            .and_then(|s| s.split('=').next())
            .unwrap()
            .trim()
            .to_string();
        let fn_digest_name = digest_body
            .rsplit_once("return ")
            .map(|(_, n)| n.trim().to_string())
            .unwrap();
        let m_digest = shell.add(&mut rng, &[], digest_body.to_string());
        wai_body.push_str(&format!(
            "{}{}={}; ",
            hdr_pre,
            fn_digest_name,
            shell.call(&m_digest, &[])
        ));
        for pf_ in &psn_pool { wai_body.push_str(&format!("local {}=false; ", pf_)); }
        // ㉓ 统一流前导拆入外层兄弟方法 m_uni，同时补上 uni.tbl 的 local 声明。
        let (u_tbl, u_dec, u_kb) = (uni.tbl.clone(), uni.dec.clone(), uni.k_b.clone());
        let uni_pre = uni.emit_prelude(&mut rng);
        let m_uni = shell.add(
            &mut rng,
            &[],
            format!("local {}; {} return {},{},{}", u_tbl, uni_pre, u_tbl, u_dec, u_kb),
        );
        wai_body.push_str(&format!(
            "local {},{},{}={}; ",
            u_tbl, u_dec, u_kb, shell.call(&m_uni, &[])
        ));
        // ㉑ 保守版明文窗口：NP(原型数)/MD(=C.pr 别名)/TH(thunk 快照)/tw(回收水位)
        // 必须在 execute 定义（parts）之前声明，execute 内才能捕获为 upvalue
        {
            let zk = rng.range(0x100, 0xFFFFF);
            let z_rk = format!("(0X{:X}%0X{:X})", zk, zk);
            let mut decls: Vec<(String, String)> = vec![
                (np21.clone(), "0".to_string()),
                (md21.clone(), "{}".to_string()),
                (th21.clone(), "{}".to_string()),
                (tw21.clone(), "0X0".to_string()),
                (rk21.clone(), z_rk),
                (kreg_n.clone(), "{}".to_string()),
            ];
            rng.shuffle(&mut decls);
            let names: Vec<String> = decls.iter().map(|(n, _)| n.clone()).collect();
            let vals: Vec<String> = decls.iter().map(|(_, v)| v.clone()).collect();
            wai_body.push_str(&format!("local {}={}; ", names.join(","), vals.join(",")));
        }
        // ㉜ chain_tail 所需 NB 槽表达式必须**先于 build 登记**。
        let v_type = vault.global("type");
        let v_pairs = vault.global("pairs");
        let v_tostring = vault.global("tostring");
        let v_sbyte = vault.member("string", "byte");
        let v_boot_gf = vault.global("getfenv");
        let v_mfloor = vault.member("math", "floor");
        let v_schar = vault.member("string", "char");
        let v_ssub = vault.member("string", "sub");
        let v_tconcat = vault.member("table", "concat");
        let v_smetas: [String; 4] = std::array::from_fn(|t| vault.global_fresh(t, "setmetatable"));
        let v_mm_adds: [String; 4] = std::array::from_fn(|t| vault.lit_fresh(t, "__add"));
        let v_mm_subs: [String; 4] = std::array::from_fn(|t| vault.lit_fresh(t, "__sub"));
        let v_mm_muls: [String; 4] = std::array::from_fn(|t| vault.lit_fresh(t, "__mul"));
        {
            // ㉜ NB 建表 + header_captures + 毒化延迟写拆入外层兄弟方法 m_vault。
            let nb_build = vault.build(&mut rng, &mut uni, Some(&kreg_n));
            let poison_delay_seed = rng.range(32, 80);
            let delay_init = format!(
                "{tab}[0X{key:X}]={seed}+(function()local s={ts}({tab});local h=0;for i=1,#s do h=(h*33+{sb}(s,i))%17 end;return h end)(); ",
                tab = kreg_n, key = poison_delay_key, seed = poison_delay_seed,
                ts = v_tostring, sb = v_sbyte
            );
            let m_vault = shell.add(
                &mut rng,
                &[&kreg_n, &u_tbl, &u_dec, &u_kb, &var_s_name],
                format!("{}{}{}return {},{}", nb_build, header_captures, delay_init, v_type, v_pairs),
            );
            wai_body.push_str(&format!(
                "local {},{}={}; ",
                native_type,
                native_pairs,
                shell.call(&m_vault, &[&kreg_n, &u_tbl, &u_dec, &u_kb, &var_s_name])
            ));
        }
        wai_body.push_str(&weld.declare());
        wai_body.push_str(&lg_call1);
        // ④ 槽位键的运行期推导游标机拆入外层兄弟方法 m_sk，wai 内用 do...end 解包 28 个键。
        {
            let (sk_walk_part, sk_bind_part) = sk_setup
                .rsplit_once("local ")
                .expect("sk_setup has local bindings");
            let sk_arr_name = sk_walk_part
                .split(";local ")
                .nth(1)
                .and_then(|s| s.split('=').next())
                .unwrap()
                .trim()
                .to_string();
            let (sk_names_str, sk_picks_str) = sk_bind_part
                .trim()
                .trim_end_matches(';')
                .split_once('=')
                .unwrap();
            let m_sk = shell.add(
                &mut rng,
                &[&kreg_n],
                format!("{} return {}", sk_walk_part, sk_arr_name),
            );
            wai_body.push_str(&format!(
                "local {}; do local {}={}; {}={} end; ",
                sk_names_str,
                sk_arr_name,
                shell.call(&m_sk, &[&kreg_n]),
                sk_names_str,
                sk_picks_str
            ));
        }
        // AntiTamper 初始化拆入外层兄弟方法 m_at。
        at.finish_setup();
        {
            let at_psn_fn = rng.name();
            let at_setup_body = at.setup.replace(
                &format!("{}=true", at.poison_var),
                &format!("{}()", at_psn_fn),
            );
            let m_at = shell.add(
                &mut rng,
                &[&kreg_n, &at_psn_fn],
                format!(
                    "{} return {},{},{},{},{},{},{}",
                    at_setup_body, at_env, at_dec, at_res, at_net, at_state, at_st, at_tw
                ),
            );
            wai_body.push_str(&format!(
                "local {},{},{},{},{},{},{}={}:{}({},function() {}=true end); ",
                at_env, at_dec, at_res, at_net, at_state, at_st, at_tw,
                shell.self_var, m_at, kreg_n, at.poison_var
            ));
        }
        // A 解码器前奏打散：五件套改从 NB 槽直取（㉜）
        {
            let mut members = vec![
                ("math_floor".to_string(), v_mfloor.clone()),
                ("string_char".to_string(), v_schar.clone()),
                ("string_sub".to_string(), v_ssub.clone()),
                ("string_byte".to_string(), v_sbyte.clone()),
                ("table_concat".to_string(), v_tconcat.clone()),
            ];
            rng.shuffle(&mut members);
            let mnames: Vec<&str> = members.iter().map(|(n, _)| n.as_str()).collect();
            let mexprs: Vec<String> = members.iter().map(|(_, e)| e.clone()).collect();
            wai_body.push_str(&format!("local {}={}; ", mnames.join(","), mexprs.join(",")));
        }

        for part in parts {
            wai_body.push_str(&part);
            wai_body.push_str(" ");
        }

        wai_body.push_str(&lg_call0);
        wai_body.push_str(&format!(
            "{}={{}}; local main_chunk=(function() return {}() end)(); ",
            var_builtin_reg, fn_decode_chunk
        ));
        // 尾部 at.trigger + thunk_walk + boot_env 求值拆入外层兄弟方法 m_tail。
        let thunk_walk = {
            let (th2, md2) = (th21.clone(), md21.clone());
            let off = rng.range(0, 100);
            let unit = |iv: &str| format!("{th}[{iv}]={md}[{iv}]; ", th = th2, md = md2, iv = iv);
            crate::VM::VM_Backend::Generator_util::cursor_walk_dyn(&mut rng, Some(&keys), off, &np21, 2, 3, &unit)
        };
        {
            let tail_psn_fn = rng.name();
            let zk2 = rng.range(0x100, 0xFFFFF);
            let at_trig_body = at.trigger.replace(
                &format!("{}=true", at.poison_var),
                &format!("{}()", tail_psn_fn),
            );
            let var_boot_gf = rng.name();
            let tail_body = format!(
                "local {}=(0X{:X}%0X{:X}); {} {} local {}={}; return ({} and {}()) or _ENV or _G",
                key_seed_var, zk2, zk2, at_trig_body, thunk_walk,
                var_boot_gf, v_boot_gf, var_boot_gf, var_boot_gf
            );
            let m_tail = shell.add(
                &mut rng,
                &[&at_net, &at_st, &kreg_n, &th21, &md21, &np21, &keys.tbl_p, &tail_psn_fn],
                tail_body,
            );
            wai_body.push_str(&format!(
                "local {}={}:{}({},{},{},{},{},{},{},function() {}=true end); ",
                var_boot_env, shell.self_var, m_tail,
                at_net, at_st, kreg_n, th21, md21, np21, keys.tbl_p, at.poison_var
            ));
        }
        let fu = rng.name();
        wai_body.push_str(&lg_call1);
        wai_body.push_str(&lg_call0);
        // 【vararg 完全透明】壳方法自己就是 vararg 函数，这里把收到的 `...` 原样交给
        // execute；payload 的 `select('#', ...)` 与 `{...}` 因此看到的是**宿主真实
        // 传进来的全部实参**（旧形态只取第一个：`local L = ...` 后传 L）。
        wai_body.push_str(&format!(
            "return {}(main_chunk, {}, {{}}, nil, nil, ...)",
            fn_execute, var_boot_env
        ));
        let _ = &var_l; // 旧形态的 vararg 载体，现在由 `...` 直接透传，不再需要

        let mut mt_ctr = 0usize;
        let mut rewrite_mt = |mut s: String| -> String {
            for (pat, slots, is_call) in [
                ("setmetatable(", &v_smetas, true),
                ("__add=", &v_mm_adds, false),
                ("__sub=", &v_mm_subs, false),
                ("__mul=", &v_mm_muls, false),
            ] {
                while let Some(pos) = s.find(pat) {
                    let slot = &slots[mt_ctr % slots.len()];
                    mt_ctr = mt_ctr.wrapping_add(1);
                    let rep = if is_call {
                        format!("{}(", slot)
                    } else {
                        format!("[{}]=", slot)
                    };
                    s.replace_range(pos..pos + pat.len(), &rep);
                }
            }
            s
        };
        shell.map_bodies(&mut rewrite_mt);
        let mut wai_body = rewrite_mt(wai_body);

        // 【外形对齐 luraph14.9】整份产物 = 一个表达式，形如：
        //     return({ 字段表 }):入口()(...)
        // 与旧形态（`local X = ...;` 前缀 + `return ({ 表 }):入口()`）的区别：
        //   ① 没有块级 `local … = ...` 前缀 —— 入口方法自己带 `...`，脚本的 vararg
        //      由入口收下（旧形态也是只取第一个 vararg，语义一致）；
        //   ② 入口是表里的一个字段，只有到文件最末尾才出现 `:入口(`；
        //   ③ 入口被调用后返回一个闭包，再由 `(...)` 用宿主 vararg 调一次，
        //      因此这个包裹对 `...` 是透明的（luraph 的 `):T()(...)`）；
        //   ④ 字段之间不留空格/换行，整份产物只有一行。
        // 注意：这里只改外壳形态，入口/解码/装载流程一步未动。
        let fu_self = rng.name();
        let fu_field = format!(
            "{}=function({},...) local {}=type; {} return function(...) return {}:{}(...) end end",
            fu, fu_self, native_type, line_guard(&mut rng, &mut uni, true),
            fu_self, wai
        );
        // 递归检查已有闭包的词法引用；可证明不依赖外层 upvalue 的安全块，
        // 直接提升为外层兄弟方法，而不是继续把 helper 留在原大字段里。
        let _nested_lifts = shell.fragment_nested_body(&mut wai_body, &mut rng, 4);
        // 结构对齐 luraph14.9 §3.3/§3.5：把巨型方法体切成碎函数 + 单次调用树
        // （每片在外层表里各占一个字段，只被调用一次；原位置换成微状态机）。
        let _frag = shell.fragment_all(&mut rng);
        let (mut f_wai, mut m_wai) = (0usize, 0usize);
        for _ in 0..6 {
            let (f, m) = shell.fragment_body(&mut wai_body, &mut rng);
            if m == 0 {
                break;
            }
            f_wai += f;
            m_wai += m;
        }
        let _ = (f_wai, m_wai);
        // `fragment_body` 会把部分 wai 语句搬进兄弟字段；必须在改写后再快照入口体，
        // 否则旧 wai_field 保留完整原体，同时新碎片字段又含搬出的代码（加密 payload 会双份）。
        let wai_field = format!(
            "{}=function({},...) {} end",
            wai, shell.self_var, wai_body
        );
        let shell_fields = shell.into_balanced_fields(&mut rng, wai_field, fu_field);

        let mut out = String::new();
        out.push_str(&format!(
            "return({{{}}}):{}()(...)",
            shell_fields.join(","),
            fu
        ));
        out
}
