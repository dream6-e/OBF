//! Generator 第二阶段：ChaCha 簇搭建 + 解码链 + 最终装配。
//!
//! 按 README 单文件 ≤ 80 KB 规则，自 Generator.rs 原样搬出的 `build()` 后半段
//! （原 L853-1507）。代码本身零改写，仅通过 [`ChainIn`] 传入第一阶段已生成的
//! 全部名字/块/密钥，返回装配完成的目标源码。随机流（`rng`）按值传入，
//! 消耗顺序与拆分前完全一致。

use super::AntiTamper::AntiTamperResult;
use super::Generator_util::{CipherKeys, EncCtx, GenRng, StreamTable};
use crate::VM::VM_Backend::Generator_util::{chacha8_xor, build_opcode_tree, uses_ident};
use crate::VM::Opcodes::{self, OpcodeConfig};
use crate::VM::packer::Packer;
use crate::compiler::instructions::{OpCode, OpMode, OpArgMask};
use std::collections::HashSet;
use rand::{rng as rand_rng, Rng, SeedableRng};
use rand::rngs::StdRng;

/// 第一阶段（Generator::build 前半）交给第二阶段的全部状态。
pub(super) struct ChainIn {
    pub rng: GenRng,
    pub at: AntiTamperResult,
    pub keys: CipherKeys,
    pub enc: EncCtx,
    pub builtin_slot_perm: Vec<usize>,
    pub sigma: [u32; 4],
    pub fn_a3: String,
    pub fn_bxor: String,
    pub fn_c: String,
    pub fn_decode_chunk: String,
    pub fn_s_byte: String,
    pub fn_s_sub: String,
    pub pf_a_arr: String,
    pub pf_b_arr: String,
    pub pf_c_arr: String,
    pub pf_is_vararg: String,
    pub pf_ld: String,
    pub pf_lld: String,
    pub pf_maxstack: String,
    pub pf_n: String,
    pub pf_numparams: String,
    pub pf_nups: String,
    pub pf_opcodes: String,
    pub pf_protos: String,
    pub psn_n: String,
    pub var_a2: String,
    pub var_b: String,
    pub var_builtin_reg: String,
    pub var_chk: String,
    pub var_idx: String,
    pub var_junk: String,
    pub var_p: String,
    pub var_raw_p: String,
    pub var_tamper: String,
    pub var_vc: String,
    pub np21: String,
    pub md21: String,
    pub th21: String,
    pub tw21: String,
    pub rk21: String,
    pub kreg_n: String,
    pub block_decoder_script: String,
    pub block_execute_def: String,
    pub block_methods: String,
    pub block_p_def: String,
    pub block_packer_vars: String,
    pub block_vm_core: String,
    pub entry_func: String,
    pub fn_a10: String,
    pub fn_a5: String,
    pub fn_b_rotr: String,
    pub fn_qr: String,
    pub fn_read_dec: String,
    pub fn_read_string: String,
    pub fn_rotl32: String,
    pub fn_u32_dec: String,
    pub fn_xor32: String,
    pub header_block: String,
    pub key_seed_var: String,
    pub payload_str: String,
    pub pf_cnt18: String,
    pub pf_consts: String,
    pub sk_setup: String,
    pub t: String,
    pub x: String,
    pub var_bname: String,
    pub var_boot_env: String,
    pub var_l: String,
    pub var_state_flag: String,
    pub wai: String,
    pub xor_tbl_var: String,
    pub fn_execute: &'static str,
    pub bc_kb: u32,
    pub bc_kc: u32,
    pub bc_ki1: u32,
    pub bc_ki2: u32,
    pub pm_r0: u32,
    pub pm_r1: u32,
    pub pm_r2: u32,
    pub pm_r3: u32,
    pub sc_add: u8,
    pub sc_add_k1: u8,
    pub sc_mul_k2: u8,
    pub sc_rot_in: u32,
    pub sc_rot_k2: u32,
    pub sc_rot_k4: u32,
    pub pm_s: [u64; 8],
    pub tag_map18: [u8; 4],
    pub fc18: crate::VM::VM_Backend::Generator_util::FoldCtx,
    pub weld: crate::VM::VM_Backend::Generator_util::WeldCache,
}

/// 第二阶段：chacha 簇 + 解码链 + 装配，返回最终目标源码。
pub(super) fn build_chain(x: ChainIn) -> String {
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
    } = x;
    // CG 原为第一阶段块内 const，随代码原样搬迁重声明（同值同路径）。
    #[allow(dead_code)]
    const CG: usize = crate::VM::VM_Backend::Generator_util::CONST_GROUPS;
        let mut block_chacha_setup = String::new();
        // ㉒① XOR 表构建（256×256）→ 双层数值游标机：外层扫行（8 态×32 行），
        // 内层扫列（8 态×32 列）。经典双重 for 消失，只剩 while true + if G==K
        // 的扁平化游走（行游标名固定 av，供内层文本引用；列表格名 rw 双字母
        // 避开单字母遮蔽池）。每格里的位运算 while 是数据驱动的游标守卫，保留。
        let xor_walk = {
            use crate::VM::VM_Backend::Generator_util::{cursor_walk_static};
            let xt2 = xor_tbl_var.clone();
            let in_off = rng.range(0, 100);
            let inner = {
                let unit = |jv: &str| format!(
                    "local x,y,r,p=av,{jv},0,1; while x>0 or y>0 do local rx,ry=x%2,y%2; if rx~=ry then r=r+p end; x,y,p=math_floor(x/2),math_floor(y/2),p*2 end; rw[{jv}]=r; ",
                    jv = jv);
                cursor_walk_static(&mut rng, None, in_off, 0, 255, 8, Some("cv"), &unit)
            };
            let out_off = rng.range(0, 100);
            let outer_unit = |av: &str| format!(
                "local rw={{}}; {inner} {xt}[{av}]=rw; ",
                inner = inner, xt = xt2, av = av);
            cursor_walk_static(&mut rng, None, out_off, 0, 255, 8, Some("av"), &outer_unit)
        };
        block_chacha_setup.push_str(&format!(
            "local {xt}={{}}; {walk} ",
            xt = xor_tbl_var, walk = xor_walk
        ));
        block_chacha_setup.push_str(&format!(
            "local function {xor32}(a,b) local a1,a2,a3,a4=a%256,math_floor(a/256)%256,math_floor(a/65536)%256,math_floor(a/16777216)%256; local b1,b2,b3,b4=b%256,math_floor(b/256)%256,math_floor(b/65536)%256,math_floor(b/16777216)%256; return {xt}[a1][b1]+{xt}[a2][b2]*256+{xt}[a3][b3]*65536+{xt}[a4][b4]*16777216 end; ",
            xor32 = fn_xor32, xt = xor_tbl_var
        ));
        // ㉔ 2^32 逐实例算式化（k-差式=k 恒等 2^32；各站点独立推导不同形）
        let mk_m = |rng: &mut GenRng| -> String {
            let k = rng.range(0x1000, 0xFFFFFF) as u64;
            format!("(0X{:X}-0X{:X})", 4294967296u64 + k, k)
        };
        let (m_rot1, m_rot2) = (mk_m(&mut rng), mk_m(&mut rng));
        block_chacha_setup.push_str(&format!(
            "local function {rotl32}(x,n) local m=2^n; return ((x*m)%{m1})+math_floor(x/({m2}/m)) end; ",
            rotl32 = fn_rotl32, m1 = m_rot1, m2 = m_rot2
        ));
        // ㉔ quarter-round 去指纹：正文四臂结构池（0=教科书原版保留）+ 旋转常数
        // 16/12/8/7 逐实例算式化 + 形参随机化（单字母 s,a,b,c,d 即参考实现指纹）。
        // 各臂输出与标准 QR 恒等（A+=B;D^=A;D=rot(D,16);C+=D;B^=C;B=rot(B,12);×2 变体）。
        let r_lit = |rng: &mut GenRng, v: u32| -> String {
            let k = rng.range(0x10, 0xFFFF) as u32;
            format!("(0X{:X}-0X{:X})", v + k, k)
        };
        let (qS, qA, qB, qC, qD) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (r1e, r2e, r3e, r4e) = (r_lit(&mut rng, 16), r_lit(&mut rng, 12), r_lit(&mut rng, 8), r_lit(&mut rng, 7));
        let m_qr1 = mk_m(&mut rng); let m_qr2 = mk_m(&mut rng);
        let x32 = fn_xor32.as_str(); let rt = fn_rotl32.as_str();
        let qr_def = match rng.range(0, 4) {
            0 => {
                // ㉒② 焊接模数：QR 每块 20 轮重入，第二次起该 if 逻辑上无分支。
                let qe = weld.dst();
                let qw = format!("local {};", qe) + &weld.weld(&mut rng, &qe, &m_qr1);
                format!(
                "local function {qr}({S},{A},{B},{C},{D}) {w} {S}[{A}]=({S}[{A}]+{S}[{B}])%{m1}; {S}[{D}]={x}({S}[{D}],{S}[{A}]); {S}[{D}]={r}({S}[{D}],{c1}); {S}[{C}]=({S}[{C}]+{S}[{D}])%{m1}; {S}[{B}]={x}({S}[{B}],{S}[{C}]); {S}[{B}]={r}({S}[{B}],{c2}); {S}[{A}]=({S}[{A}]+{S}[{B}])%{m1}; {S}[{D}]={x}({S}[{D}],{S}[{A}]); {S}[{D}]={r}({S}[{D}],{c3}); {S}[{C}]=({S}[{C}]+{S}[{D}])%{m1}; {S}[{B}]={x}({S}[{B}],{S}[{C}]); {S}[{B}]={r}({S}[{B}],{c4}) end; ",
                qr = fn_qr, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw,
                m1 = qe, x = x32, r = rt, c1 = r1e, c2 = r2e, c3 = r3e, c4 = r4e)
            },
            1 => {
                // 半轮助手四连调用：视觉上不再是「加/异或/移位」三连奏
                let hname = rng.name(); let m_h = mk_m(&mut rng);
                let he = weld.dst();
                let hw = format!("local {};", he) + &weld.weld(&mut rng, &he, &m_h);
                format!(
                    "local function {h}({S},{U},{V},{W},{Rr}) {w} {S}[{U}]=({S}[{U}]+{S}[{V}])%{m}; {S}[{W}]={x}({S}[{W}],{S}[{U}]); {S}[{W}]={r}({S}[{W}],{Rr}) end; local function {qr}({S},{A},{B},{C},{D}) {h}({S},{A},{B},{D},{c1}); {h}({S},{C},{D},{B},{c2}); {h}({S},{A},{B},{D},{c3}); {h}({S},{C},{D},{B},{c4}) end; ",
                    h = hname, qr = fn_qr, S = qS, U = rng.name(), V = rng.name(), W = rng.name(), Rr = rng.name(), w = hw,
                    A = qA, B = qB, C = qC, D = qD, m = he, x = x32, r = rt,
                    c1 = r1e, c2 = r2e, c3 = r3e, c4 = r4e)
            }
            2 => {
                // 局部化平展：热路径零表索引，收尾一次写回
                {
                    let qe2 = weld.dst();
                    let qw2 = format!("local {};", qe2) + &weld.weld(&mut rng, &qe2, &m_qr1);
                    format!(
                    "local function {qr}({S},{A},{B},{C},{D}) local {a},{b},{c},{d}={S}[{A}],{S}[{B}],{S}[{C}],{S}[{D}]; {w} {a}=({a}+{b})%{m1}; {d}={x}({d},{a}); {d}={r}({d},{c1}); {c}=({c}+{d})%{m1}; {b}={x}({b},{c}); {b}={r}({b},{c2}); {a}=({a}+{b})%{m1}; {d}={x}({d},{a}); {d}={r}({d},{c3}); {c}=({c}+{d})%{m1}; {b}={x}({b},{c}); {b}={r}({b},{c4}); {S}[{A}],{S}[{B}],{S}[{C}],{S}[{D}]={a},{b},{c},{d} end; ",
                    qr = fn_qr, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw2,
                    a = rng.name(), b = rng.name(), c = rng.name(), d = rng.name(),
                    m1 = qe2, x = x32, r = rt, c1 = r1e, c2 = r2e, c3 = r3e, c4 = r4e)
                }
            }
            _ => {
                // 步骤闭包表+驱动：与 QR 形态最远（12 个无序可读的单操作闭包）
                let st = rng.name(); let m_s = mk_m(&mut rng);
                // ㉒② 模数焊接（闭包捕获焊接值）；㉒① 12 闭包驱动环 → 3 态游标机。
                let qe3 = weld.dst();
                let qw3 = format!("local {};", qe3) + &weld.weld(&mut rng, &qe3, &m_s);
                let qw_off = rng.range(0, 100);
                let st2 = st.clone();
                let qwalk = {
                    let unit = |iv: &str| format!("{}[{}](); ", st2, iv);
                    crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, qw_off, 1, 12, 3, None, &unit)
                };
                format!(
                    "local function {qr}({S},{A},{B},{C},{D}) {w} local {st}={{function() {S}[{A}]=({S}[{A}]+{S}[{B}])%{m} end,function() {S}[{D}]={x}({S}[{D}],{S}[{A}]) end,function() {S}[{D}]={r}({S}[{D}],{c1}) end,function() {S}[{C}]=({S}[{C}]+{S}[{D}])%{m} end,function() {S}[{B}]={x}({S}[{B}],{S}[{C}]) end,function() {S}[{B}]={r}({S}[{B}],{c2}) end,function() {S}[{A}]=({S}[{A}]+{S}[{B}])%{m} end,function() {S}[{D}]={x}({S}[{D}],{S}[{A}]) end,function() {S}[{D}]={r}({S}[{D}],{c3}) end,function() {S}[{C}]=({S}[{C}]+{S}[{D}])%{m} end,function() {S}[{B}]={x}({S}[{B}],{S}[{C}]) end,function() {S}[{B}]={r}({S}[{B}],{c4}) end}}; {walk} end; ",
                    qr = fn_qr, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw3, walk = qwalk,
                    st = st, m = qe3, x = x32, r = rt,
                    c1 = r1e, c2 = r2e, c3 = r3e, c4 = r4e)
            }
        };
        block_chacha_setup.push_str(&qr_def);
        // ㉔ 调用矩阵去指纹：列组/对角组内洗牌（4 列互不相交、4 对角互不相交，
        // 组内换序恒等；组间顺序固定保 ChaCha 语义），8 元组改数据表驱动，
        // 元组数字部分裸写部分算式化；循环次数 4 同步算式化。
        let mk_rounds = |rng: &mut GenRng, qrn: &str| -> String {
            let mut cols: Vec<(u32, u32, u32, u32)> = vec![(1,5,9,13),(2,6,10,14),(3,7,11,15),(4,8,12,16)];
            let mut dias: Vec<(u32, u32, u32, u32)> = vec![(1,6,11,16),(2,7,12,13),(3,8,9,14),(4,5,10,15)];
            rng.shuffle(&mut cols); rng.shuffle(&mut dias);
            let mut ents: Vec<String> = Vec::new();
            for &(a, b, c, d) in cols.iter().chain(dias.iter()) {
                let f = |rng: &mut GenRng, v: u32| -> String {
                    if rng.range(0, 2) == 0 { v.to_string() }
                    else { let k = rng.range(0x10, 0xFFFF) as u32; format!("(0X{:X}-0X{:X})", v + k, k) }
                };
                ents.push(format!("{{{},{},{},{}}}", f(rng, a), f(rng, b), f(rng, c), f(rng, d)));
            }
            let (tv, iv, ev) = (rng.name(), rng.name(), rng.name());
            let kf = rng.range(0x10, 0xFFFF) as u32;
            format!(
                "local {tv}={{{ents}}}; for _=1,(0X{:X}-0X{:X}) do for {iv}=1,#{tv} do local {ev}={tv}[{iv}]; {qrn}({sv},{ev}[1],{ev}[2],{ev}[3],{ev}[4]) end end; ",
                kf + 4, kf, tv = tv, iv = iv, ev = ev, ents = ents.join(","), qrn = qrn, sv = "s")
        };
        // ⑰ 每组一个自包含簇：K/salt/sigma 排列/cblock/cstream + 专属 dec_str/dec_num
        // （无统一路由入口——四个簇打散插到产物不同位置，各原型按组直连本簇解码器）
        let mut clusters: Vec<String> = Vec::with_capacity(CG);
        let mut ds_names: [String; CG] = std::array::from_fn(|_| String::new());
        let mut dn_names: [String; CG] = std::array::from_fn(|_| String::new());
        let mut salt_names: [String; CG] = std::array::from_fn(|_| String::new());
        for g in 0..CG {
            let mut cl = String::new();
            let kname = rng.name();
            let slname = rng.name();
            let sname = rng.name();
            let cbname = rng.name();
            let key_lua = (0..8).map(|i| rng.obfuscate_num(enc.keys[g][i] as i64, 1, &keys)).collect::<Vec<_>>().join(",");
            let salt_lua = rng.obfuscate_num(enc.salts[g] as i64, 1, &keys);
            let mut idxs: Vec<usize> = vec![1, 2, 3, 4, 5, 6, 7, 8];
            for j in (1..idxs.len()).rev() { let k = rng.range(0, j + 1); idxs.swap(j, k); }
            let sig_idx = [idxs[0], idxs[1], idxs[2], idxs[3]];
            let sigma_lua = (0..4)
                .map(|i| {
                    let d = sigma[i].wrapping_sub(enc.keys[g][sig_idx[i] - 1]);
                    format!("(({}+K[{}])%4294967296)", rng.obfuscate_num(d as i64, 1, &keys), sig_idx[i])
                })
                .collect::<Vec<_>>()
                .join(",");
            cl.push_str(&format!(
                "local {kn}={{{key_lua}}}; local {sl}={salt_lua}; ",
                kn = kname, key_lua = key_lua, sl = slname, salt_lua = salt_lua));
            // ㉒ 簇内 cb 同 boot 域处理：焊接混合模数 + 两条 16 环游标化。
            let gmix_v = mk_m(&mut rng);
            let gmix_e = weld.dst();
            let gmix_weld = format!("local {};", gmix_e) + &weld.weld(&mut rng, &gmix_e, &format!("({})", gmix_v));
            let gs1_walk = {
                let off = rng.range(0, 100);
                let unit = |iv: &str| format!("o[{iv}]=s[{iv}]; ", iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 16, 4, None, &unit)
            };
            let gs2_walk = {
                let off = rng.range(0, 100);
                let me = gmix_e.clone();
                let unit = |iv: &str| format!("local wq=(s[{iv}]+o[{iv}])%{me}; out[({iv}-1)*4+1]=wq%256; out[({iv}-1)*4+2]=math_floor(wq/256)%256; out[({iv}-1)*4+3]=math_floor(wq/65536)%256; out[({iv}-1)*4+4]=math_floor(wq/16777216)%256; ", me = me, iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 16, 4, None, &unit)
            };
            cl.push_str(&format!(
                "local function {cb}(n1,n2,n3,ctr) local K={kn}; {mixw} local s={{{sig},K[1],K[2],K[3],K[4],K[5],K[6],K[7],K[8],ctr,n1,n2,n3}}; local o={{}}; {w1} {rounds} local out={{}}; {w2} return out end; ",
                cb = cbname, kn = kname, sig = sigma_lua, mixw = gmix_weld, w1 = gs1_walk, w2 = gs2_walk,
                rounds = mk_rounds(&mut rng, fn_qr.as_str())));
            // ㉓-A sm 换公式：nonce=[盐^roll^fold, r7^(槽*6+kind), 盐^rotl7(r7)]——
            // layouts 直传退役；roll/fold 由 body_consts 扫描重算后经 dsp 透传
            let salt_v18 = slname.as_str();
            let gsm_walk = {
                let off = rng.range(0, 100);
                let unit = |iv: &str| format!("if pos>n then break end; out[pos]=blk[{iv}]; pos=pos+1; ", iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 64, 4, None, &unit)
            };
            cl.push_str(&format!(
                "local function {sm}(pool_idx,kind,n,fold,rl) local out={{}}; local ctr=0; local pos=1; local {r7v}={rot}(rl or 0X0,0X7); while pos<=n do local blk={cb}({bx}({bx}({sl},rl or 0X0),fold or 0X0), {bx}({r7v},pool_idx*0X6+kind), {bx}({sl},{rot}({r7v},0X7)), ctr); {w64} ctr=ctr+1 end; return out end; ",
                sm = sname, cb = cbname, sl = salt_v18, bx = fn_bxor.as_str(), rot = fn_rotl32.as_str(), r7v = rng.name(), w64 = gsm_walk));
            // 组专属解码器：kind 常量内嵌（每组不同随机值），下标参数=节内槽位号
            let (vb, vs, ve, vm) = (rng.name(), rng.name(), rng.name(), rng.name());
            let mut f64_parts = vec![format!("({vb}[7]%16)*2^48", vb = vb), format!("({vb}[6]*2^40)", vb = vb), format!("({vb}[5]*2^32)", vb = vb), format!("({vb}[4]*2^24)", vb = vb), format!("({vb}[3]*2^16)", vb = vb), format!("({vb}[2]*2^8)", vb = vb), format!("{vb}[1]", vb = vb)];
            rng.shuffle(&mut f64_parts);
            let (v_num_i, v_num_g, v_num_ks) = (rng.name(), rng.name(), rng.name());
            let dname = rng.name();
            let fd18n = rng.name();
            let rl18n = rng.name();
            cl.push_str(&crate::VM::VM_Backend::Generator_flow::build_decnum(
                dname.as_str(), sname.as_str(), rng.obfuscate_num(enc.knum[g] as i64, 1, &keys).as_str(), vb.as_str(),
                xor_tbl_var.as_str(), vs.as_str(), ve.as_str(), vm.as_str(), f64_parts.join("+"),
                v_num_ks.as_str(), v_num_i.as_str(), v_num_g.as_str(), fd18n.as_str(), rl18n.as_str()));
            salt_names[g] = slname.clone();
            dn_names[g] = dname;
            let (v_str_i, v_str_g, v_str_ks, v_str_s) = (rng.name(), rng.name(), rng.name(), rng.name());
            let sname_d = rng.name();
            let fd18s = rng.name();
            let rl18s = rng.name();
            let kstr_lit = rng.obfuscate_num(enc.kstr[g] as i64, 1, &keys);
            cl.push_str(&crate::VM::VM_Backend::Generator_flow::build_decstr(
                &mut rng, sname_d.as_str(), sname.as_str(), kstr_lit.as_str(),
                xor_tbl_var.as_str(), fn_s_byte.as_str(), v_str_ks.as_str(), v_str_s.as_str(),
                v_str_i.as_str(), v_str_g.as_str(), fd18s.as_str(), rl18s.as_str()));
            ds_names[g] = sname_d;
            clusters.push(cl);
        }
        // 簇落位洗牌：1 个进 chacha_setup 尾部，其余 3 个作为独立 parts 插在
        // chacha_setup 之后、decode_chunk 之前（词法作用域先行，落位随机）
        let mut cluster_order: Vec<usize> = (0..CG).collect();
        rng.shuffle(&mut cluster_order);
        block_chacha_setup.push_str(&clusters[cluster_order[0]]);
        let cluster_parts: Vec<String> = vec![
            clusters[cluster_order[1]].clone(),
            clusters[cluster_order[2]].clone(),
            clusters[cluster_order[3]].clone(),
        ];
        
        let (fh0, fh1) = crate::VM::VM_Backend::Generator_util::stream_key("function", &mut rng);
        let sc_fn_hdr = at.st.call("function", fh0, fh1);
        let (md0, md1) = crate::VM::VM_Backend::Generator_util::stream_key("__mode", &mut rng);
        let sc_mode = at.st.call("__mode", md0, md1);
        let (mk0, mk1) = crate::VM::VM_Backend::Generator_util::stream_key("k", &mut rng);
        let sc_k = at.st.call("k", mk0, mk1);
        let block_dec_header = crate::VM::VM_Backend::Generator_flow::build_header(
            &mut rng, &keys, fn_s_byte.as_str(), fn_s_sub.as_str(), var_raw_p.as_str(), payload_str.as_str(),
            var_chk.as_str(), var_idx.as_str(), var_junk.as_str(), var_b.as_str(), var_tamper.as_str(),
            var_vc.as_str(), var_p.as_str(), var_a2.as_str(), entry_func.as_str(), fn_a3.as_str(), x.as_str(),
            sc_fn_hdr.as_str(), sc_mode.as_str(), sc_k.as_str());
        // ── 解码链（第 6 项：解密逻辑打乱）──
        // 冷路径一次性函数，放心打乱形态。
        let (v_bx_a, v_bx_b, v_bx_r, v_bx_w, v_bx_g, v_bx_s) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (v_rt_x, v_rt_n, v_rt_d, v_rt_g, v_rt_t) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (v_rd_o, v_rd_g, v_rd_e) = (rng.name(), rng.name(), rng.name());
        let (v_rd_c1, v_rd_c2, v_rd_c3, v_rd_c4, v_rd_c5) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());

        // 注意：产物里的 k1..k4 是固定局部名，模板里只能写裸标识符 k1 —— 写成 {k1}
        // 会被 format! 隐式捕获抓走同名生成器变量（产物语法错）；
        // 同理 Lua 的空表要写 {{}}，裸 {} 是位置参数占位符。
        // 原形态：逐位比较累权重、n==0早返回右移、滚动密钥顺序赋值
        // 现在：位异或写成 (xa+xb)%2 乘权重、右移用 256/2^n 代 2^(8-n) 去早返回
        // 解密链拆 5 个中间变量、密钥演化换等价变形（-229 代 +27、
        // (v-v%d)/d 代 floor、k2*2+k2 代 k2*3，包单次循环+影子计数器。
        let block_dec_helpers = format!(
            "local function {bx}({a},{b}) local {r},{w},{g},{s}=0,1,0,0; \
             while {g}<({r}-{r})+1 do \
             if {a}<=0 and {b}<=0 then {g}={g}+1 else \
             {s}=(({a}%2)+({b}%2))%2; {r}={r}+{s}*{w}; \
             {a}=({a}-({a}%2))/2; {b}=({b}-({b}%2))/2; {w}={w}+{w}; end end; \
             return {r} end; \
             local function {rt}({x},{n}) local {d},{g},{t}=2^{n},0,0; \
             while {g}<({t}-{t})+1 do \
             {t}=(({x}*(256/{d}))%256)+(({x}-({x}%{d}))/{d}); {g}={g}+1; end; \
             return {t} end; \
             {rd_scatter} ",
            bx = fn_bxor, a = v_bx_a, b = v_bx_b, r = v_bx_r, w = v_bx_w, g = v_bx_g, s = v_bx_s,
            rt = fn_b_rotr, x = v_rt_x, n = v_rt_n, d = v_rt_d, t = v_rt_t,
rd_scatter = crate::VM::VM_Backend::Generator_flow::build_scatter(
                &mut rng, fn_bxor.as_str(), fn_b_rotr.as_str(), fn_read_dec.as_str(), fn_a3.as_str(),
                &v_bx_a, &v_bx_b, &v_bx_r, &v_bx_w, &v_bx_g, &v_bx_s,
                &v_rt_x, &v_rt_n, &v_rt_d, &v_rt_g, &v_rt_t,
                &v_rd_o, &v_rd_g, &v_rd_e, &v_rd_c1, &v_rd_c2, &v_rd_c3, &v_rd_c4, &v_rd_c5,
                sc_add, sc_rot_in, sc_add_k1, sc_mul_k2, sc_rot_k2, sc_rot_k4)
        );
        let (kt_name, pj_name) = (rng.name(), rng.name());
        let kc = crate::VM::VM_Backend::Generator_flow::build_k(&mut rng, kt_name.as_str());
        let (v_u32_t, v_u32_n, v_u32_i, v_u32_v) = (rng.name(), rng.name(), rng.name(), rng.name());
        let (v_a5_t, v_a5_n, v_a5_i) = (rng.name(), rng.name(), rng.name());
        let (v_rs_l, v_rs_t, v_rs_i) = (rng.name(), rng.name(), rng.name());
        let (v_a10_v, v_a10_h) = (rng.name(), rng.name());

        // 原形态：for 循环按 1..4 读、再按固定顺序累加、权重全是十进制常量
        // 现在：while + 显式自增下标、累加项顺序打乱（整数加法精确，顺序无影响）
        // 权重换 2^8/2^16/2^24 与自减零初值、零长度短路、有符号转换改形
        let block_dec_readers = format!(
            "{u32_family} ",
u32_family = crate::VM::VM_Backend::Generator_flow::build_readers(
                &mut rng, &keys, &kc, kt_name.as_str(), pj_name.as_str(), fn_bxor.as_str(),
                fn_u32_dec.as_str(), fn_a5.as_str(), fn_read_string.as_str(), fn_read_dec.as_str(), fn_a10.as_str(),
                &v_u32_t, &v_u32_n, &v_u32_i, &v_u32_v, &v_rs_l, &v_a10_v, &v_a10_h)
        );
        
        // ⑰ 旧统一 dec_num/dec_str 已由四组簇内专属解码器取代。

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
             local function {dcb}({w},{m},{k},{q}) if {w}<0X0 then {w}={w}+0X100000000 end {w}={bx}({bx}({w},{k}),{bx}({m},{q})) if {w}>=0X80000000 then {w}={w}-0X100000000 end return {w} end; \
             local {i}=0; local {n}={a5}(); {c}.{cnt18}={n}; local {kp}={c}.{pf_ld}; local {pb}={c}.{pf_lld}; local {ka}={bx}({kp},{pb}); local {kb18}={bx}({kp},{ka}); local {kc18}={bx}({pb},{ka}) \
             while {i} < {n} do {i} = {i} + 1; \
             local {mv}={a5}() local {g18}={bx}({mv},{kp}) {c}.{pf_opcodes}[{i}+{pb}]={g18} {c}.{pf_a_arr}[{i}+{pb}]={bx}({a10}()%4294967296,{ka}) {c}.{pf_b_arr}[{i}+{pb}]={bx}({dcb}({a10}(),{g18},{kbx},{k1x})%4294967296,{kb18}) {c}.{pf_c_arr}[{i}+{pb}]={bx}({dcb}({a10}(),{g18},{kcx},{k2x})%4294967296,{kc18}) local {jv}=(({mv}-({mv}%0X20000000))/0X20000000)%4; for _=1,{jv} do {rd}() end end; ",
            tree9 = it9(&mut rng, var_state.as_str()),
            st = var_state, nxt = obf_s_consts, c = fn_c, a5 = fn_a5, a10 = fn_a10,
            pf_opcodes = pf_opcodes, pf_a_arr = pf_a_arr, pf_b_arr = pf_b_arr, pf_c_arr = pf_c_arr,
            i = v_ch_i, n = v_ch_n, cnt18 = pf_cnt18, kp = rng.name(), g18 = rng.name(),
            pb = rng.name(), ka = rng.name(), kb18 = rng.name(), kc18 = rng.name(),
            pf_ld = pf_ld, pf_lld = pf_lld,
            dcb = rng.name(), w = rng.name(), m = rng.name(), k = rng.name(), q = rng.name(),
            bx = fn_bxor.as_str(), mv = rng.name(), kbx = kb_x, kcx = kc_x, k1x = ki1_x, k2x = ki2_x,
            jv = rng.name(), rd = fn_read_dec.as_str()
        );
        let (bi0, bi1) = crate::VM::VM_Backend::Generator_util::stream_key("__index", &mut rng);
        let sc_index2 = at.st.call("__index", bi0, bi1);
        let (ko0, ko1) = crate::VM::VM_Backend::Generator_util::stream_key("KryvexObf_", &mut rng);
        let sc_kobf = at.st.call("KryvexObf_", ko0, ko1);
        let body_consts = format!(
            "{st}={nxt}; {bc_scatter} ",
            st = var_state, nxt = obf_s_protos,
bc_scatter = crate::VM::VM_Backend::Generator_flow::build_consts(
                &mut rng, &keys, &kc, pj_name.as_str(), fn_bxor.as_str(),
                sc_index2.as_str(), sc_kobf.as_str(), var_state_flag.as_str(), var_idx_chunk.as_str(),
                var_tbl.as_str(), var_e.as_str(), &ds_names, &dn_names, fn_read_string.as_str(),
                fn_a5.as_str(), fn_read_dec.as_str(), var_enc_c.as_str(), var_cache.as_str(),
                fn_c.as_str(), pf_consts.as_str(),
                &v_ch_i, &v_ch_n, &t,
                pf_opcodes.as_str(), pf_a_arr.as_str(), pf_b_arr.as_str(), pf_c_arr.as_str(), fn_rotl32.as_str(), &fc18,
                &tag_map18, &salt_names, pf_ld.as_str(), pf_lld.as_str(), pf_cnt18.as_str(), psn_n.as_str())
        );
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
        let line_guard = |rng: &mut GenRng| -> String {
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
            let mut hopts = vec![
                format!("if {u}~={u} then {u}={u} end; ", u = p_u),
                format!("if {f1}==\"function\"then {u}={u} end; ", f1 = f1, u = p_u),
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
            let lg20 = line_guard(&mut rng);
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
        // ㉑ 保守版明文窗口：NP(原型数)/MD(=C.pr 别名)/TH(thunk 快照)/tw(回收水位)
        // 必须在 execute 定义（parts）之前声明，execute 内才能捕获为 upvalue
        out.push_str(&format!("local {np},{md},{th},{tw},{rk},{kreg},{psn}=0,{{}},{{}},0X0,0X0,setmetatable({{}},{{__mode='k'}}),false; ", np = np21, md = md21, th = th21, tw = tw21, rk = rk21, kreg = kreg_n, psn = psn_n));
        // ㉒② 焊接缓存表声明：长时状态只剩槽号；此后各站点以「一个 if 三件事」
        // 形态（惰性缓存+大随机数当键+校验恒等式）发射焊接构造。
        out.push_str(&weld.declare());
        // ⑳.4 守卫必须在 return 壳内（用户指示）：三处采样全部作为壳方法体的
        // 开头/缝隙语句，行 2 头部只留 local L=... 和 return({——壳外零检测代码
        out.push_str(&line_guard(&mut rng));
        // ④ 槽位键的运行期推导块必须在所有用键代码之前；
        // finish_setup 把状态链种子/陷阱门等收尾语句并进 setup（在全部注册后调用）
        out.push_str(&sk_setup);
        at.finish_setup();
        out.push_str(&at.setup);
        out.push_str(&format!(" local {} = 0; ", key_seed_var));
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

        out.push_str(&line_guard(&mut rng));
        out.push_str(&format!("local main_chunk={}(); ", fn_decode_chunk));
        out.push_str(&at.trigger);
        out.push_str(&format!(" {} = {{}}; local {} = (getfenv and getfenv() or _ENV or _G); local {}; ", var_builtin_reg, var_boot_env, var_bname));
        // ⑰ 内建名专用簇：独立 key/salt/kind，密文以混合转义字面量内嵌，
        // 与四组常量簇完全分离——导出任何常量簇参数都拿不到内建名
        {
            let bkey: [u32; 8] = std::array::from_fn(|_| rng.next());
            let bsalt: u32 = rng.next();
            let bkind: u32 = rng.next();
            let mut boot_lits: Vec<String> = Vec::with_capacity(Opcodes::builtins::BUILTIN_NAMES.len());
            for (i, name) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
                let blob = crate::VM::VM_Backend::Generator_util::chacha8_xor(&bkey, [bsalt, i as u32, bkind], name.as_bytes());
                boot_lits.push(format!("\"{}\"", crate::VM::VM_Backend::Generator_util::lua_mixed(&blob)));
            }
            let (bk, bs, bcb, bsm, bdec, bpt) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
            let key_lua = (0..8).map(|i| rng.obfuscate_num(bkey[i] as i64, 1, &keys)).collect::<Vec<_>>().join(",");
            let salt_lua = rng.obfuscate_num(bsalt as i64, 1, &keys);
            let mut idxs: Vec<usize> = vec![1, 2, 3, 4, 5, 6, 7, 8];
            for j in (1..idxs.len()).rev() { let k = rng.range(0, j + 1); idxs.swap(j, k); }
            let sig_idx = [idxs[0], idxs[1], idxs[2], idxs[3]];
            let sigma_lua = (0..4)
                .map(|i| {
                    let d = sigma[i].wrapping_sub(bkey[sig_idx[i] - 1]);
                    format!("(({}+K[{}])%4294967296)", rng.obfuscate_num(d as i64, 1, &keys), sig_idx[i])
                })
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!(
                "local {bp}={{{lits}}}; local {kn}={{{key_lua}}}; local {sl}={salt_lua}; ",
                bp = bpt, lits = boot_lits.join(","), kn = bk, key_lua = key_lua, sl = bs, salt_lua = salt_lua));
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
            let s2_walk = {
                let off = rng.range(0, 100);
                let me = mix_e.clone();
                let unit = |iv: &str| format!("local wq=(s[{iv}]+o[{iv}])%{me}; out[({iv}-1)*4+1]=wq%256; out[({iv}-1)*4+2]=math_floor(wq/256)%256; out[({iv}-1)*4+3]=math_floor(wq/65536)%256; out[({iv}-1)*4+4]=math_floor(wq/16777216)%256; ", me = me, iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 16, 4, None, &unit)
            };
            out.push_str(&format!(
                "local function {cb}(n1,n2,n3,ctr) local K={kn}; {mixw} local s={{{sig},K[1],K[2],K[3],K[4],K[5],K[6],K[7],K[8],ctr,n1,n2,n3}}; local o={{}}; {w1} {rounds} local out={{}}; {w2} return out end; ",
                cb = bcb, kn = bk, sig = sigma_lua, mixw = mix_weld, w1 = s1_walk, w2 = s2_walk,
                rounds = mk_rounds(&mut rng, fn_qr.as_str())));
            // ㉒① 64 字节分发环 → 4 态游标机（pos>n 提前出口保留为批内 break）。
            let sm_walk = {
                let off = rng.range(0, 100);
                let unit = |iv: &str| format!("if pos>n then break end; out[pos]=blk[{iv}]; pos=pos+1; ", iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 64, 4, None, &unit)
            };
            out.push_str(&format!(
                "local function {sm}(pool_idx,kind,n) local out={{}}; local ctr=0; local pos=1; while pos<=n do local blk={cb}({sl},pool_idx,kind,ctr); {w64} ctr=ctr+1 end; return out end; ",
                sm = bsm, cb = bcb, sl = bs, w64 = sm_walk));
            let (v_str_i, v_str_g, v_str_ks, v_str_s) = (rng.name(), rng.name(), rng.name(), rng.name());
            let fd18b = rng.name(); // 哑形参：boot 域 bsm 是 3 参，fold/rl 实参多余即弃
            let rl18b = rng.name();
            let bkind_lit = rng.obfuscate_num(bkind as i64, 1, &keys);
            out.push_str(&crate::VM::VM_Backend::Generator_flow::build_decstr(
                &mut rng, bdec.as_str(), bsm.as_str(), bkind_lit.as_str(),
                xor_tbl_var.as_str(), fn_s_byte.as_str(), v_str_ks.as_str(), v_str_s.as_str(),
                v_str_i.as_str(), v_str_g.as_str(), fd18b.as_str(), rl18b.as_str()));
            // ㉒② 每个内建槽号过一次焊接构造：惰性缓存+大随机键+校验恒等式。
            // 全块只声明一个单字母局部（do 域内复用——E 先是载荷槽、下一个内建又变
            // 寄存器位），局部数不膨胀，命名维度消失。
            let bi_e = weld.dst();
            out.push_str(&format!("do local {};", bi_e));
            for (i, _) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
                let slot = builtin_slot_perm[i];
                let wslot_stmt = weld.weld(&mut rng, &bi_e, &(slot + 1).to_string());
                out.push_str(&format!(
                    "{bname}={bdec}({bp}[{lidx}],{ridx}); {ws} {reg}[{we}]={benv}[{bname}]; if {reg}[{we}]==nil and getgenv then {reg}[{we}]=getgenv()[{bname}] end; ",
                    bname = var_bname, bdec = bdec, bp = bpt, lidx = i + 1, ridx = i,
                    ws = wslot_stmt, we = bi_e,
                    reg = var_builtin_reg, benv = var_boot_env
                ));
            }
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
        out.push_str(&line_guard(&mut rng));
        out.push_str(&line_guard(&mut rng));
        out.push_str(" ");
        out.push_str(&format!("return {}(main_chunk, {}, {{}}, {}) end,{}=function(x) {} x:{}() end", fn_execute, var_boot_env, var_l, fu, line_guard(&mut rng), wai));
        out.push_str(&format!(" }}):{}()", fu));
        out
}
