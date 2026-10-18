//! Generator 第二阶段：ChaCha 簇搭建 + 解码链 + 最终装配。
//!
//! 按 README 单文件 ≤ 80 KB 规则，自 Generator.rs 原样搬出的 `build()` 后半段
//! （原 L853-1507）。代码本身零改写，仅通过 [`ChainIn`] 传入第一阶段已生成的
//! 全部名字/块/密钥，返回装配完成的目标源码。随机流（`rng`）按值传入，
//! 消耗顺序与拆分前完全一致。

use super::AntiTamper::AntiTamperResult;
use super::Generator_util::{CipherKeys, EncCtx, GenRng, StreamTable};
use crate::VM::VM_Backend::Generator_util::{build_opcode_tree, uses_ident};
use crate::VM::Opcodes::{self, OpcodeConfig};
use crate::VM::packer::Packer;
use crate::compiler::instructions::{OpCode, OpMode, OpArgMask};
use std::collections::HashSet;
use rand::{rng as rand_rng, Rng, SeedableRng};
use rand::rngs::StdRng;

/// 第一阶段（Generator::build 前半）交给第二阶段的全部状态。
pub(super) struct ChainIn {
    pub rng: GenRng,
    /// 外部 API 名 handle 注册表 (handle, 名字)；chain_tail 发射保险库+解码器。
    pub global_names: Vec<(u32, Vec<u8>)>,
    /// 解码器在 kreg 注册表里的槽键（与 OpcodeConfig.gn 的取用表达式同源）。
    pub gn_key: u32,
    pub at: AntiTamperResult,
    pub keys: CipherKeys,
    pub enc: EncCtx,
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
    pub psn_pool: Vec<String>,
    pub poison_delay_key: u32,
    pub var_a2: String,
    pub var_whiten: String,
    pub var_whiten_pos: String,
    pub whiten_mul: u64,
    pub whiten_add: u64,
    pub var_builtin_reg: String,
    pub var_p: String,
    pub var_raw_p: String,
    pub var_vc: String,
    pub native_type: String,
    pub native_pairs: String,
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
    pub const_path_key: String,
    pub sk_setup: String,
    pub t: String,
    pub x: String,
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
    pub chain_delta: u32,
    pub chain_m: u64,
    pub chain_k0: u64,
    pub sc_add: u8,
    pub sc_add_k1: u8,
    pub sc_mul_k2: u8,
    pub sc_rot_in: u32,
    pub sc_rot_k2: u32,
    pub sc_rot_k4: u32,

    pub tag_map18: [u8; 4],
    pub fc18: crate::VM::VM_Backend::Generator_util::FoldCtx,
    pub weld: crate::VM::VM_Backend::Generator_kdf::WeldCache,
    pub uni: crate::VM::VM_Backend::Generator_util::UniStream,
    /// ㉜ API 名保险库：发射点登记 NB 槽，chain_tail 建表 IIFE 一次发射。
    pub vault: crate::VM::VM_Backend::Generator_names::NameVault,
    /// 头部 select 捕获（推迟到 NB 建表之后发射）。
    pub header_captures: String,
    pub ros_params: crate::VM::VM_Backend::Rosetta::RosettaParams,
}

pub(super) const CG_GROUPS: usize = crate::VM::VM_Backend::Generator_util::CONST_GROUPS;

pub(super) struct ChainMid {
    pub x: ChainIn,
    pub h_var: String,
    pub fix_var: String,
    pub root_kw: String,
    pub block_chacha_setup: String,
    pub ds_names: [String; CG_GROUPS],
    pub dn_names: [String; CG_GROUPS],
    pub salt_names: [String; CG_GROUPS],
    pub root_fetch: Vec<String>,
    pub kdf_name: String,
    pub cluster_parts: Vec<String>,
    pub kc: crate::VM::VM_Backend::Generator_flow::KConsts,
    pub kt_name: String,
    pub pj_name: String,
    pub block_dec_header: String,
    pub block_dec_helpers: String,
    pub block_dec_readers: String,
    pub shell: crate::VM::VM_Backend::Generator_names::ShellMethods,
}

/// 第二阶段：chacha 簇 + 解码链 + 装配，返回最终目标源码。
pub(super) fn build_chain(x: ChainIn) -> String {
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
        var_p,
        var_raw_p,
        var_vc,
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
    } = x;
    let mut shell = crate::VM::VM_Backend::Generator_names::ShellMethods::new(&mut rng);
    let poison_delay_expr = format!("{}[0X{:X}]", kreg_n, poison_delay_key);
    // CG 原为第一阶段块内 const，随代码原样搬迁重声明（同值同路径）。
    #[allow(dead_code)]
    const CG: usize = crate::VM::VM_Backend::Generator_util::CONST_GROUPS;
        let mut block_chacha_setup = String::new();
        // ② 运行期指纹两股：动态指纹（地址/GC，非确定）只做等价形态选路；
        // 确定性指纹 hfix（改进 2）的值被折进根 K0 token 扭曲量——跳过指纹层
        // 即失去全部密钥材料，层不再可整层略过。拆入外层兄弟方法 m_fp。
        let (fp_src, h_var) = crate::VM::VM_Backend::Generator_native::emit_fingerprint(&mut rng, Some(&mut vault));
        let (fix_src, fix_var, fix_val) = crate::VM::VM_Backend::Generator_kdf::emit_fix_fingerprint(&mut rng, Some(&mut vault));
        let m_fp = shell.add(
            &mut rng,
            &[&kreg_n],
            format!("{}{} return {},{}", fp_src, fix_src, h_var, fix_var),
        );
        block_chacha_setup.push_str(&format!(
            "local {},{}={}; ",
            h_var, fix_var, shell.call(&m_fp, &[&kreg_n])
        ));
        // 第 2 项：形态选路的**运行期绑定**——同一逻辑功能发射两型逐位等价的实现，
        // 由宿主指纹 h 在运行期择一（三种择一写法随机轮抽，产物里看不到固定
        // if/表形态；静态读者也必须先仿真宿主语义才知道走哪支）。
        // 第 2 项：**延迟静默投毒**——守卫失败只立共享旗 psn；随机指令窗口结束后，
        // 再渐进污染密钥/常量与路由。探针不早退、不抛专属错误；后续只呈现自然劣化。
        // 四种 Keystream 扰动均为模 256 运算，并按短命对象地址作运行期抽样；不消耗全局随机数。
        // 改进 3：毒化读取不再盯单旗——三旗乱序析取（两种包裹形态），钉一旗不哑火
        let psn_read = |rng: &mut GenRng| -> String {
            let mut idx: Vec<usize> = (0..psn_pool.len()).collect();
            rng.shuffle(&mut idx);
            let names: Vec<&str> = idx.iter().map(|&i| psn_pool[i].as_str()).collect();
            match rng.range(0, 2) {
                0 => format!("({})", names.join(" or ")),
                _ => format!("(({}))", names.iter().map(|n| format!("({})", n)).collect::<Vec<_>>().join(" or ")),
            }
        };
        let v_pks_ts = vault.global("tostring");
        let v_pks_sb = vault.member("string", "byte");
        let poison_ks = |rng: &mut GenRng, ks: &str| -> String {
            let pe = psn_read(rng);
            let k1 = rng.range(0x100, 0xFFFF) as u32;
            let k2 = rng.range(0x100, 0xFFFF) as u32;
            let (sample_s, sample_h, sample_i) = (rng.name(), rng.name(), rng.name());
            let poison_sample = format!(
                "(function()local {s}={ts}({{}});local {h}=0;for {i}=1,#{s} do {h}=({h}*0X21+{sb}({s},{i}))%0X7FFFFF01 end;return {h}%0X80==0X0 end)()",
                s = sample_s, h = sample_h, i = sample_i, ts = v_pks_ts, sb = v_pks_sb
            );
            match rng.range(0, 4) {
                0 => format!("if {psn} and {delay}<=0 and {sample} then {ks}[0X1]=(0X{k:X}-{ks}[0X1])%0X100 end; ", psn = pe, delay = poison_delay_expr, sample = poison_sample, ks = ks, k = k1),
                1 => format!("if {psn} and {delay}<=0 and {sample} then local {z}=#{ks} while {z}>0X0 do {ks}[{z}]=(0X{k:X}-{ks}[{z}])%0X100; {z}={z}-0X1 end end; ", psn = pe, delay = poison_delay_expr, sample = poison_sample, ks = ks, k = k1, z = rng.name()),
                2 => format!("if {psn} and {delay}<=0 and {sample} then {ks}[0X1]=({ks}[0X1]+0X{k:X})%0X100; {ks}[#{ks}]=(0X{k2:X})%0X100 end; ", psn = pe, delay = poison_delay_expr, sample = poison_sample, ks = ks, k = k1, k2 = k2),
                _ => format!("if {psn} and {delay}<=0 and {sample} then for {z}=0X1,#{ks} do {ks}[{z}]=({ks}[{z}]*0X{k:X}+0X{k2:X})%0X100 end end; ", psn = pe, delay = poison_delay_expr, sample = poison_sample, ks = ks, k = k1, k2 = k2, z = rng.name()),
            }
        };
        let bind2 = |rng: &mut GenRng, dst: &str, n_even: &str, n_odd: &str| -> String {
            let (p1, p2, p3, p4, p5, p6) = (
                rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
            );
            match rng.range(0, 2) {
                0 => format!(
                    "local {d}=function({p1},{p2},{p3},{p4},{p5},{p6}) if (({p2} or 0X0)%0X2)==0X0 then return {ne}({p1},{p2},{p3},{p4},{p5},{p6}) else return {no}({p1},{p2},{p3},{p4},{p5},{p6}) end end; ",
                    d = dst, p1 = p1, p2 = p2, p3 = p3, p4 = p4, p5 = p5, p6 = p6, ne = n_even, no = n_odd
                ),
                _ => format!(
                    "local {d}=function({p1},{p2},{p3},{p4},{p5},{p6}) if (({p2} or 0X0)%0X2)~=0X0 then return {no}({p1},{p2},{p3},{p4},{p5},{p6}) else return {ne}({p1},{p2},{p3},{p4},{p5},{p6}) end end; ",
                    d = dst, p1 = p1, p2 = p2, p3 = p3, p4 = p4, p5 = p5, p6 = p6, ne = n_even, no = n_odd
                ),
            }
        };
        // ㉒① XOR 表构建（256×256）+ xor32 + rotl32 拆入外层兄弟方法 m_xt。
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
        let (x16, x24) = (rng.name(), rng.name());
        let (x16v, x24v) = (crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 16), crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 24));
        let mk_m = |_rng: &mut GenRng| -> String { "4294967296".to_string() };
        let (m_rot1, m_rot2) = (mk_m(&mut rng), mk_m(&mut rng));
        let slot_bxor = vault.bitop("bxor");
        let xt_body = format!(
            "local {xt}={{}}; local {xor32}={slot_bxor}; if not {xor32} then {walk} \
             {xor32}=function(a,b) local {p2}={p2v}; local {p3}={p3v}; local a1,a2,a3,a4=a%256,math_floor(a/256)%256,math_floor(a/{p2})%256,math_floor(a/{p3})%256; local b1,b2,b3,b4=b%256,math_floor(b/256)%256,math_floor(b/{p2})%256,math_floor(b/{p3})%256; return {xt}[a1][b1]+{xt}[a2][b2]*256+{xt}[a3][b3]*{p2}+{xt}[a4][b4]*{p3} end end; \
             local function {rotl32}(x,n) local m=2^n; return ((x*m)%{m1})+math_floor(x/({m2}/m)) end; \
             return {xt},{xor32},{rotl32}",
            xt = xor_tbl_var, walk = xor_walk, slot_bxor = slot_bxor,
            xor32 = fn_xor32, p2 = x16, p3 = x24, p2v = x16v, p3v = x24v,
            rotl32 = fn_rotl32, m1 = m_rot1, m2 = m_rot2
        );
        let m_xt = shell.add(&mut rng, &["math_floor", &kreg_n], xt_body);
        block_chacha_setup.push_str(&format!(
            "local {},{},{}={}; ",
            xor_tbl_var, fn_xor32, fn_rotl32, shell.call(&m_xt, &["math_floor", &kreg_n])
        ));
        let r_lit = |rng: &mut GenRng, v: u32| -> String { rng.format_num(v as i64) };
        let (qS, qA, qB, qC, qD) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (r1e, r2e, r3e, r4e) = (r_lit(&mut rng, 16), r_lit(&mut rng, 12), r_lit(&mut rng, 8), r_lit(&mut rng, 7));
        // 第 3 项 D：单根 K0 + KDF + 白化种子派生拆入外层兄弟方法 m_kdf。
        let (root_tok, root_fetch) = {
            let rt = crate::VM::VM_Backend::Generator_kdf::root_tokens(&mut rng, &keys, &enc.root, &h_var,
                &fix_var, fix_val, fn_xor32.as_str());
            let f: Vec<String> = (0..8).map(|i| rt.fetch[i].clone()).collect();
            (rt, f)
        };
        let root_kw = root_tok.kw.clone();
        let dispose_s = crate::VM::VM_Backend::Generator_kdf::dispose_stmt(&mut rng, &root_tok.aux);
        let kdf_name = rng.name();
        let kdf_m32v = crate::VM::VM_Backend::Generator_kdf::kdf_m32(&mut rng);
        let kdf_decl = crate::VM::VM_Backend::Generator_kdf::kdf_fn_decl(
            &mut rng, &keys, kdf_name.as_str(), fn_xor32.as_str(), fn_rotl32.as_str(), kdf_m32v.as_str());
        let w_seed_stmt = {
            let wg = rng.obfuscate_num(crate::VM::VM_Backend::Generator::WHITEN_GROUP as i64, 1, &keys);
            let ww = rng.obfuscate_num(crate::VM::VM_Backend::Generator::WHITEN_WORD as i64, 1, &keys);
            let ww2 = rng.obfuscate_num((crate::VM::VM_Backend::Generator::WHITEN_WORD + 2) as i64, 1, &keys);
            let wmod = rng.obfuscate_num(2147483646i64, 1, &keys);
            let mw_var = rng.name();
            let seed = format!("{kdf}({root},{g},{w})", kdf = kdf_name, root = root_fetch[3], g = wg, w = ww);
            let mseed = format!("{kdf}({root},{g},{w2})", kdf = kdf_name, root = root_fetch[5], g = wg, w2 = ww2);
            format!(
                "local {mw}={mseed}; \
                 k1={x32}(k1,{mw}%0X100); \
                 k2={x32}(k2,math_floor({mw}/0X100)%0X100); \
                 k3={x32}(k3,math_floor({mw}/0X10000)%0X100); \
                 k4={x32}(k4,math_floor({mw}/0X1000000)%0X100); \
                 local {wk}=(({seed}+k1*0X10001+k2*0X101+k3*0X11+k4)%{m})+0X1; ",
                mw = mw_var, mseed = mseed, x32 = fn_xor32,
                wk = var_whiten, seed = seed, m = wmod
            )
        };
        let m_kdf = shell.add(
            &mut rng,
            &[&keys.tbl_p, &h_var, &fix_var, &fn_xor32, &fn_rotl32, "math_floor", "k1", "k2", "k3", "k4"],
            format!(
                "{}{}{}{}return {},{},{},k1,k2,k3,k4",
                root_tok.decl, dispose_s, kdf_decl, w_seed_stmt, root_kw, kdf_name, var_whiten
            ),
        );
        block_chacha_setup.push_str(&format!(
            "local {},{}; {},{},{},k1,k2,k3,k4={}; ",
            root_kw, kdf_name, root_kw, kdf_name, var_whiten,
            shell.call(&m_kdf, &[&keys.tbl_p, &h_var, &fix_var, &fn_xor32, &fn_rotl32, "math_floor", "k1", "k2", "k3", "k4"])
        ));
        let m_qr1 = mk_m(&mut rng); let m_qr2 = mk_m(&mut rng);
        let qbias = (rng.range(0x101, 0x3FFF_FFFF) as u32) | 1;
        let qbias_comp = 0x1_0000_0000u64 - (qbias as u64);
        let x32 = fn_xor32.as_str(); let rt = fn_rotl32.as_str();
        let mk_qr = |rng: &mut GenRng,
                     wc: &mut crate::VM::VM_Backend::Generator_kdf::WeldCache,
                     kind: usize,
                     is_second: bool,
                     name: &str|
         -> String {
            let m1 = m_qr1.as_str();
            let (ca, cb_rot) = if !is_second { (r1e.as_str(), r2e.as_str()) } else { (r3e.as_str(), r4e.as_str()) };
            match kind {
                0 => {
                    let qe = wc.dst();
                    let qw = format!("local {};", qe) + &wc.weld(rng, &qe, m1);
                    if !is_second {
                        format!(
                            "local function {qr}({S},{A},{B},{C},{D}) {w} {S}[{A}]=({S}[{A}]+{S}[{B}])%{m1}; {S}[{D}]={x}({S}[{D}],{S}[{A}]); {S}[{D}]={r}({S}[{D}],{c1}); {S}[{C}]=({S}[{C}]+{S}[{D}])%{m1}; {S}[{B}]={x}({S}[{B}],{S}[{C}]); {S}[{B}]={r}({S}[{B}],{c2}); {S}[{A}]=({S}[{A}]+0X{qb:X})%{m1} end; ",
                            qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw,
                            m1 = qe, x = x32, r = rt, c1 = ca, c2 = cb_rot, qb = qbias)
                    } else {
                        format!(
                            "local function {qr}({S},{A},{B},{C},{D}) {w} {S}[{A}]=({S}[{A}]+0X{qc:X})%{m1}; {S}[{A}]=({S}[{A}]+{S}[{B}])%{m1}; {S}[{D}]={x}({S}[{D}],{S}[{A}]); {S}[{D}]={r}({S}[{D}],{c1}); {S}[{C}]=({S}[{C}]+{S}[{D}])%{m1}; {S}[{B}]={x}({S}[{B}],{S}[{C}]); {S}[{B}]={r}({S}[{B}],{c2}) end; ",
                            qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw,
                            m1 = qe, x = x32, r = rt, c1 = ca, c2 = cb_rot, qc = qbias_comp)
                    }
                }
                1 => {
                    let hname = rng.name(); let m_h = mk_m(rng);
                    let he = wc.dst();
                    let hw = format!("local {};", he) + &wc.weld(rng, &he, &m_h);
                    if !is_second {
                        format!(
                            "local function {h}({S},{U},{V},{W},{Rr}) {w} {S}[{U}]=({S}[{U}]+{S}[{V}])%{m}; {S}[{W}]={x}({S}[{W}],{S}[{U}]); {S}[{W}]={r}({S}[{W}],{Rr}) end; local function {qr}({S},{A},{B},{C},{D}) {w} {h}({S},{A},{B},{D},{c1}); {h}({S},{C},{D},{B},{c2}); {S}[{A}]=({S}[{A}]+0X{qb:X})%{m} end; ",
                            h = hname, qr = name, S = qS, U = rng.name(), V = rng.name(), W = rng.name(), Rr = rng.name(), w = hw,
                            A = qA, B = qB, C = qC, D = qD, m = he, x = x32, r = rt,
                            c1 = ca, c2 = cb_rot, qb = qbias)
                    } else {
                        format!(
                            "local function {h}({S},{U},{V},{W},{Rr}) {w} {S}[{U}]=({S}[{U}]+{S}[{V}])%{m}; {S}[{W}]={x}({S}[{W}],{S}[{U}]); {S}[{W}]={r}({S}[{W}],{Rr}) end; local function {qr}({S},{A},{B},{C},{D}) {w} {S}[{A}]=({S}[{A}]+0X{qc:X})%{m}; {h}({S},{A},{B},{D},{c1}); {h}({S},{C},{D},{B},{c2}) end; ",
                            h = hname, qr = name, S = qS, U = rng.name(), V = rng.name(), W = rng.name(), Rr = rng.name(), w = hw,
                            A = qA, B = qB, C = qC, D = qD, m = he, x = x32, r = rt,
                            c1 = ca, c2 = cb_rot, qc = qbias_comp)
                    }
                }
                2 => {
                    let qe2 = wc.dst();
                    let qw2 = format!("local {};", qe2) + &wc.weld(rng, &qe2, m1);
                    if !is_second {
                        format!(
                            "local function {qr}({S},{A},{B},{C},{D}) local {a},{b},{c},{d}={S}[{A}],{S}[{B}],{S}[{C}],{S}[{D}]; {w} {a}=({a}+{b})%{m1}; {d}={x}({d},{a}); {d}={r}({d},{c1}); {c}=({c}+{d})%{m1}; {b}={x}({b},{c}); {b}={r}({b},{c2}); {a}=({a}+0X{qb:X})%{m1}; {S}[{A}],{S}[{B}],{S}[{C}],{S}[{D}]={a},{b},{c},{d} end; ",
                            qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw2,
                            a = rng.name(), b = rng.name(), c = rng.name(), d = rng.name(),
                            m1 = qe2, x = x32, r = rt, c1 = ca, c2 = cb_rot, qb = qbias)
                    } else {
                        format!(
                            "local function {qr}({S},{A},{B},{C},{D}) local {a},{b},{c},{d}={S}[{A}],{S}[{B}],{S}[{C}],{S}[{D}]; {w} {a}=({a}+0X{qc:X})%{m1}; {a}=({a}+{b})%{m1}; {d}={x}({d},{a}); {d}={r}({d},{c1}); {c}=({c}+{d})%{m1}; {b}={x}({b},{c}); {b}={r}({b},{c2}); {S}[{A}],{S}[{B}],{S}[{C}],{S}[{D}]={a},{b},{c},{d} end; ",
                            qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw2,
                            a = rng.name(), b = rng.name(), c = rng.name(), d = rng.name(),
                            m1 = qe2, x = x32, r = rt, c1 = ca, c2 = cb_rot, qc = qbias_comp)
                    }
                }
                _ => {
                    let st = rng.name(); let m_s = mk_m(rng);
                    let qe3 = wc.dst();
                    let qw3 = format!("local {};", qe3) + &wc.weld(rng, &qe3, &m_s);
                    let qw_off = rng.range(0, 100);
                    let st2 = st.clone();
                    let qwalk = {
                        let unit = |iv: &str| format!("{}[{}](); ", st2, iv);
                        crate::VM::VM_Backend::Generator_util::cursor_walk_static(rng, None, qw_off, 1, 7, 3, None, &unit)
                    };
                    if !is_second {
                        format!(
                            "local function {qr}({S},{A},{B},{C},{D}) {w} local {st}={{function() {S}[{A}]=({S}[{A}]+{S}[{B}])%{m} end,function() {S}[{D}]={x}({S}[{D}],{S}[{A}]) end,function() {S}[{D}]={r}({S}[{D}],{c1}) end,function() {S}[{C}]=({S}[{C}]+{S}[{D}])%{m} end,function() {S}[{B}]={x}({S}[{B}],{S}[{C}]) end,function() {S}[{B}]={r}({S}[{B}],{c2}) end,function() {S}[{A}]=({S}[{A}]+0X{qb:X})%{m} end}}; {walk} end; ",
                            qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw3, walk = qwalk,
                            st = st, m = qe3, x = x32, r = rt, c1 = ca, c2 = cb_rot, qb = qbias)
                    } else {
                        format!(
                            "local function {qr}({S},{A},{B},{C},{D}) {w} local {st}={{function() {S}[{A}]=({S}[{A}]+0X{qc:X})%{m} end,function() {S}[{A}]=({S}[{A}]+{S}[{B}])%{m} end,function() {S}[{D}]={x}({S}[{D}],{S}[{A}]) end,function() {S}[{D}]={r}({S}[{D}],{c1}) end,function() {S}[{C}]=({S}[{C}]+{S}[{D}])%{m} end,function() {S}[{B}]={x}({S}[{B}],{S}[{C}]) end,function() {S}[{B}]={r}({S}[{B}],{c2}) end}}; {walk} end; ",
                            qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw3, walk = qwalk,
                            st = st, m = qe3, x = x32, r = rt, c1 = ca, c2 = cb_rot, qc = qbias_comp)
                    }
                }
            }
        };
        // 将 QR 拆为非等价且由奇偏置 qbias 耦合的前半轮 qn0 与后半轮 qn1，
        // 在运行期按状态奇偶分派：每次 QR 调用必经双臂，删改任一臂均破坏状态偏置抵消。
        let (qk0, qk1) = {
            let a = rng.range(0, 4);
            let mut b = rng.range(0, 3);
            if b >= a { b += 1; }
            (a, b)
        };
        let qn0 = rng.name();
        let qn1 = rng.name();
        let qd0 = mk_qr(&mut rng, &mut weld, qk0, false, &qn0);
        let qd1 = mk_qr(&mut rng, &mut weld, qk1, true, &qn1);
        let (q_st, q_kv) = (rng.name(), rng.name());
        let qsel = format!(
            "local function {qr}({S},{A},{B},{C},{D}) local {st}=(({S}[{A}]+{h})%0X2); for {kv}=0X1,0X2 do if (({st}+{kv})%0X2)~={st} then {n0}({S},{A},{B},{C},{D}) else {n1}({S},{A},{B},{C},{D}) end end end; ",
            qr = fn_qr, S = qS, A = qA, B = qB, C = qC, D = qD, st = q_st, kv = q_kv, h = h_var, n0 = qn0, n1 = qn1
        );
        let (w_t0, w_t1, w_t2) = (
            weld.tables[0].clone(),
            weld.tables[1].clone(),
            weld.tables[2].clone(),
        );
        let m_qr = shell.add(
            &mut rng,
            &[&h_var, &fn_xor32, &fn_rotl32, &w_t0, &w_t1, &w_t2, &kreg_n],
            format!("{}{}{} return {}", qd0, qd1, qsel, fn_qr),
        );
        block_chacha_setup.push_str(&format!(
            "local {}={}; ",
            fn_qr,
            shell.call(&m_qr, &[&h_var, &fn_xor32, &fn_rotl32, &w_t0, &w_t1, &w_t2, &kreg_n])
        ));
        // ㉔ 调用矩阵去指纹：列组/对角组内洗牌（4 列互不相交、4 对角互不相交，
        // 组内换序恒等；组间顺序固定保 ChaCha 语义），8 元组改数据表驱动，
        // 元组成员与循环次数均直接写成数值字面量。
        let mk_rounds = |rng: &mut GenRng, qrn: &str, ly: &crate::VM::VM_Backend::Generator_chacha::ChaChaLayout| -> String {
            let mut cols: Vec<(u32, u32, u32, u32)> = vec![(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15)];
            let mut dias: Vec<(u32, u32, u32, u32)> = vec![(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)];
            rng.shuffle(&mut cols); rng.shuffle(&mut dias);
            let mut ents: Vec<String> = Vec::new();
            for &(a, b, c, d) in cols.iter().chain(dias.iter()) {
                // 第 2 项：元组走全状态置换 ρ——列/对角组内换序恒等（组内四元组
                // 互不相交），映射后即物理位置；标准 ChaCha 的 {1,6,11,16} 形态消失
                let m = |v: u32| (ly.rho[v as usize] + 1) as u32;
                let f = |rng: &mut GenRng, v: u32| -> String { rng.format_num(v as i64) };
                ents.push(format!("{{{},{},{},{}}}", f(rng, m(a)), f(rng, m(b)), f(rng, m(c)), f(rng, m(d))));
            }
            let (tv, iv, ev) = (rng.name(), rng.name(), rng.name());
            // 轮数逐簇（8/10/12 的半数 = 每个 QR 轮的 4 列 + 4 对角），直接输出字面量。
            let rounds = (ly.rounds / 2) as u32;
            format!(
                "local {tv}={{{ents}}}; for _=1,{rounds} do for {iv}=1,#{tv} do local {ev}={tv}[{iv}]; {qrn}({sv},{ev}[1],{ev}[2],{ev}[3],{ev}[4]) end end; ",
                tv = tv, iv = iv, ev = ev, ents = ents.join(","), qrn = qrn, sv = "s", rounds = rounds)
        };
        let (p_psn0, p_psn1, p_psn2) = (
            psn_pool[0].clone(),
            psn_pool[1].clone(),
            psn_pool[2].clone(),
        );
        let cg_params: [&str; 21] = [
            &keys.tbl_p,
            &kreg_n,
            &kdf_name,
            &root_kw,
            &fix_var,
            &fn_xor32,
            &fn_rotl32,
            &fn_bxor,
            &xor_tbl_var,
            &fn_qr,
            &h_var,
            &fn_s_byte,
            "math_floor",
            "string_char",
            "table_concat",
            &w_t0,
            &w_t1,
            &w_t2,
            &p_psn0,
            &p_psn1,
            &p_psn2,
        ];
        // ⑰ 每组一个自包含簇：拆入外层 return({...}) 兄弟方法 m_cg0..m_cg3 承载，
        // 避免 4 个 ChaCha 簇内联在 wai 造成局部槽位与常量表压力。
        let mut clusters: Vec<String> = Vec::with_capacity(CG);
        let mut ds_names: [String; CG] = std::array::from_fn(|_| String::new());
        let mut dn_names: [String; CG] = std::array::from_fn(|_| String::new());
        let mut salt_names: [String; CG] = std::array::from_fn(|_| String::new());
        for g in 0..CG {
            let dg = crate::VM::VM_Backend::Generator_kdf::derive_group(&mut rng, &keys, kdf_name.as_str(), &root_fetch, g);
            let slname = dg.salt.clone();
            let knum_var = dg.knum.clone();
            let kstr_var = dg.kstr.clone();
            let cbname = rng.name();
            let out_ds = rng.name();
            let out_dn = rng.name();
            let out_sl = rng.name();
            let mut cl = String::new();
            let sm32 = rng.name();
            let sm32v = crate::VM::VM_Backend::Generator_kdf::kdf_m32(&mut rng);
            let sigma_items: Vec<String> = (0..4)
                .map(|i| {
                    let r = rng.next();
                    let d = sigma[i].wrapping_sub(r);
                    format!("(({}+{})%{m32})", rng.obfuscate_num(d as i64, 1, &keys), rng.obfuscate_num(r as i64, 1, &keys), m32 = sm32)
                })
                .collect();
            cl.push_str(&format!("local {sm32}={sm32v}; ", sm32 = sm32, sm32v = sm32v));
            cl.push_str(&dg.decl);
            let ly = enc.layout[g];
            let inv = ly.inv();
            let mut logical: [String; 16] = std::array::from_fn(|_| String::new());
            for i in 0..4 { logical[i] = sigma_items[i].clone(); }
            for j in 0..8 { logical[4 + j] = dg.fetch[j].clone(); }
            for i in 12..16 { logical[i] = "0X0".to_string(); }
            // 状态模板带每簇随机偏置 cb_bias：运行期按 (ctr+n2+h)%2 动态走双支，
            // 第二支必须以补数 cb_comp 去偏置后装载，两支均为非等价真分支。
            let cb_bias = (rng.range(0x1001, 0x3FFF_FFFF) as u32) | 1;
            let cb_comp = 0x1_0000_0000u64 - (cb_bias as u64);
            let biased_logical: [String; 16] = std::array::from_fn(|i| {
                format!("(({}+0X{:X})%{})", logical[i], cb_bias, sm32)
            });
            let tm = rng.name();
            cl.push_str(&format!("local {tm}={}; ",
                crate::VM::VM_Backend::Generator_chacha::state_literal(&ly, &biased_logical), tm = tm));
            let mut direct = logical.clone();
            direct[12] = "ctr".to_string();
            direct[13] = "n1".to_string();
            direct[14] = "n2".to_string();
            direct[15] = "n3".to_string();
            let s_lit = crate::VM::VM_Backend::Generator_chacha::state_literal(&ly, &direct);
            let ov = |rng: &mut GenRng, i: usize| -> String {
                rng.obfuscate_num((ly.rho[i] + 1) as i64, 1, &keys)
            };
            let (o12, o13, o14, o15) = (ov(&mut rng, 12), ov(&mut rng, 13), ov(&mut rng, 14), ov(&mut rng, 15));
            let gmix_v = mk_m(&mut rng);
            let gmix_e = weld.dst();
            let gmix_weld = format!("local {};", gmix_e) + &weld.weld(&mut rng, &gmix_e, &format!("({})", gmix_v));
            let gs1_walk = {
                let off = rng.range(0, 100);
                let unit = |iv: &str| format!("o[{iv}]=s[{iv}]; ", iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 16, 4, None, &unit)
            };
            let (gp2, gp3) = (rng.name(), rng.name());
            let (gp2v, gp3v) = (crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 16), crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 24));
            let gmap = rng.name();
            let gbmap: Vec<String> = (0..16)
                .map(|p| rng.format_num((inv[p] * 4 + 1) as i64))
                .collect();
            cl.push_str(&format!("local {bmap}={{{lits}}}; ", bmap = gmap, lits = gbmap.join(",")));
            let bi_n = rng.name();
            let gs2_walk = {
                let off = rng.range(0, 100);
                let me = gmix_e.clone();
                let bm = gmap.clone();
                let bn = bi_n.clone();
                let unit = |iv: &str| format!("local {bi}={bm}[{iv}]; local wq=(s[{iv}]+o[{iv}])%{me}; out[{bi}]=wq%256; out[{bi}+0X1]=math_floor(wq/256)%256; out[{bi}+0X2]=math_floor(wq/{p2})%256; out[{bi}+0X3]=math_floor(wq/{p3})%256; ", me = me, iv = iv, bi = bn, bm = bm, p2 = gp2, p3 = gp3);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 16, 4, None, &unit)
            };
            cl.push_str(&format!(
                "local function {cb}(n1,n2,n3,ctr) {mixw} local s; if ((ctr+n2+{h})%0X2)==0X0 then s={lit} else s={{}}; for {ti}=0X1,0X10 do s[{ti}]=({tm}[{ti}]+0X{cbc:X})%{m32} end; s[{o12}]=ctr; s[{o13}]=n1; s[{o14}]=n2; s[{o15}]=n3 end; local o={{}}; local {p2}={p2v}; local {p3}={p3v}; {w1} {rounds} local out={{}}; {w2} return out end; ",
                cb = cbname, mixw = gmix_weld, h = h_var, lit = s_lit, tm = tm, ti = rng.name(),
                cbc = cb_comp, m32 = sm32,
                o12 = o12, o13 = o13, o14 = o14, o15 = o15,
                w1 = gs1_walk, w2 = gs2_walk, p2 = gp2, p3 = gp3, p2v = gp2v, p3v = gp3v,
                rounds = mk_rounds(&mut rng, fn_qr.as_str(), &ly)));
            let salt_v18 = slname.clone();
            let ctr0e = rng.obfuscate_num(ly.ctr0 as i64, 1, &keys);
            let stepe = rng.obfuscate_num(ly.step as i64, 1, &keys);
            let (sm_p, sm_s) = (rng.name(), rng.name());
            let pz_p = poison_ks(&mut rng, "blk");
            let pz_s = poison_ks(&mut rng, "blk");
            let mk_nonce = |rng: &mut GenRng, sl: &str, bx: &str, rot: &str, m32: &str| -> (String, String, String, String) {
                let (e1, r7v, e2, e3) = (rng.name(), rng.name(), rng.name(), rng.name());
                let t = format!(
                    "local {e1}={bx}({bx}({sl},rl or 0X0),fold or 0X0); local {r7v}={rot}(rl or 0X0,0X7); local {e2}={bx}({bx}({r7v},(pool_idx*0X6+kind)%{m32}),{rot}(fold or 0X0,0XD)); local {e3}={bx}({bx}({sl},{rot}({r7v},0X7)),{rot}(fold or 0X0,0X5)); ",
                    e1 = e1, r7v = r7v, e2 = e2, e3 = e3, sl = sl, bx = bx, rot = rot, m32 = m32);
                (t, e1, e2, e3)
            };
            {
                let (nd, e1, e2, e3) = mk_nonce(&mut rng, salt_v18.as_str(), fn_bxor.as_str(), fn_rotl32.as_str(), sm32.as_str());
                let i = rng.name();
                cl.push_str(&format!(
                    "local function {smp}(v,pool_idx,kind,fold,rl) {nd}local blk={cb}({e1},{e2},{e3},{c0}); {pz} local out={{}}; for {i}=0X1,0X8 do out[{i}]={x32}(v[{i}],blk[{i}]) end; return out end; ",
                    smp = sm_p, nd = nd, e1 = e1, e2 = e2, e3 = e3, cb = cbname, c0 = ctr0e,
                    pz = pz_p, i = i, x32 = fn_xor32));
            }
            {
                let (nd, e1, e2, e3) = mk_nonce(&mut rng, salt_v18.as_str(), fn_bxor.as_str(), fn_rotl32.as_str(), sm32.as_str());
                let (n, pos, ctr, q, fw, ww, lim) =
                    (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
                let core = match rng.range(0, 2) {
                    0 => format!(
                        "local {n}=#e; local out={{}}; local {pos}=0X1; local {ctr}={c0}; \
                         while {pos}<={n} do local blk={cb}({e1},{e2},{e3},{ctr}); {pz} local {lim}={pos}+0X3F; if {lim}>{n} then {lim}={n} end \
                           local {q}=0X0; local {fw}=0X0; local {ww}=0X1; \
                           while {pos}<={lim} do {q}={q}+0X1; local p={x32}({sb}(e,{pos}),blk[{q}]); out[{pos}]=p; if {q}<=0X8 then {fw}=({fw}+p*{ww})%{m32} {ww}=({ww}*0X100)%{m32} end {pos}={pos}+0X1 end \
                           {ctr}=({ctr}+{st}+{fw})%{m32} end; return out end; ",
                        n = n, pos = pos, ctr = ctr, q = q, fw = fw, ww = ww, lim = lim,
                        cb = cbname, e1 = e1, e2 = e2, e3 = e3, c0 = ctr0e, pz = pz_s,
                        x32 = fn_xor32, sb = fn_s_byte, m32 = sm32, st = stepe),
                    _ => format!(
                        "local {n}=#e; local out={{}}; local {pos}=0X1; local {ctr}={c0}; \
                         repeat local blk={cb}({e1},{e2},{e3},{ctr}); {pz} local {q}=0X0; local {fw}=0X0; local {ww}=0X1; local {lim}={pos}+0X3F; if {lim}>{n} then {lim}={n} end \
                           if {pos}<={lim} then repeat {q}={q}+0X1; local p={x32}({sb}(e,{pos}),blk[{q}]); out[{pos}]=p; if {q}<=0X8 then {fw}=({fw}+p*{ww})%{m32} {ww}=({ww}*0X100)%{m32} end {pos}={pos}+0X1 \
                           until {pos}>{lim} or {q}>=0X40 end; {ctr}=({ctr}+{st}+{fw})%{m32} until {pos}>{n}; return out end; ",
                        n = n, pos = pos, ctr = ctr, q = q, fw = fw, ww = ww, lim = lim,
                        cb = cbname, e1 = e1, e2 = e2, e3 = e3, c0 = ctr0e, pz = pz_s,
                        x32 = fn_xor32, sb = fn_s_byte, m32 = sm32, st = stepe),
                };
                cl.push_str(&format!("local function {sms}(e,pool_idx,kind,fold,rl) {nd}{core}", sms = sm_s, nd = nd, core = core));
            }
            let (sbt, nbm, c1v, c2v, c3v, xv, u1v, u2v, u3v, u4v) = (
                rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
                rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
            );
            let [sa1, sa2, sa3] = enc.sbox_a[g];
            let nbm_lits: Vec<String> = (0..8)
                .map(|j| format!("0X{:X}", enc.num_bperm[g][j] + 1))
                .collect();
            let (kna_var, knb_var, ksa_var, ksb_var) = (rng.name(), rng.name(), rng.name(), rng.name());
            cl.push_str(&format!(
                "local {sbt}={{}}; local {nbm}={{{nbm_lits}}}; do local {c1},{c2},{c3}={sl}%0X100,{ks}%0X100,{kn}%0X100; for {xv}=0X0,0XFF do local {u1}=({xv}*0X{a1:X}+{c1})%0X100; local {u2}={x32}({u1},({u1}-{u1}%0X10)/0X10); local {u3}=({u2}*0X{a2:X}+{c2})%0X100; local {u4}={x32}({u3},({u3}-{u3}%0X10)/0X10); {sbt}[{xv}]=({u4}*0X{a3:X}+{c3})%0X100 end end; \
                 local {kna}=({kn}+({sl}%0X10000)*0X7+0X37)%{m32}; local {knb}=({kn}+({sl}%0X10000)*0XB+0X4D)%{m32}; \
                 local {ksa}=({ks}+({sl}%0X10000)*0X3+0X11)%{m32}; local {ksb}=({ks}+({sl}%0X10000)*0X5+0X23)%{m32}; ",
                sbt = sbt, nbm = nbm, nbm_lits = nbm_lits.join(","),
                c1 = c1v, c2 = c2v, c3 = c3v, sl = slname, ks = kstr_var, kn = knum_var,
                xv = xv, u1 = u1v, u2 = u2v, u3 = u3v, u4 = u4v,
                a1 = sa1, a2 = sa2, a3 = sa3, x32 = fn_xor32,
                kna = kna_var, knb = knb_var, ksa = ksa_var, ksb = ksb_var, m32 = sm32
            ));
            let sbox_params = (
                enc.sbox_smul[g],
                enc.sbox_pmul[g],
                enc.sbox_cmul[g],
                enc.sbox_cadd[g],
                enc.num_bbstep[g],
            );
            let (vb, vs, ve, vm) = (rng.name(), rng.name(), rng.name(), rng.name());
            let mut f64_parts = vec![
                format!("({vb}[7]%16)*2^48", vb = vb), format!("({vb}[6]*2^40)", vb = vb),
                format!("({vb}[5]*2^32)", vb = vb), format!("({vb}[4]*2^24)", vb = vb),
                format!("({vb}[3]*2^16)", vb = vb), format!("({vb}[2]*2^8)", vb = vb),
                format!("{vb}[1]", vb = vb),
            ];
            rng.shuffle(&mut f64_parts);
            let (v_num_i, v_num_g) = (rng.name(), rng.name());
            let fd18n = rng.name();
            let rl18n = rng.name();
            let (num_path_arg, num_count_arg) = (rng.name(), rng.name());
            // 奇偶槽双键真分支：dn_a 绑偶槽密钥 kna，dn_b 绑奇槽密钥 knb，两支不等价且运行期皆命中
            let (dn_f0, dn_f1) = {
                let a = rng.range(0, 4);
                let mut b = rng.range(0, 3);
                if b >= a { b += 1; }
                (a, b)
            };
            let dn_a = rng.name();
            let dn_b = rng.name();
            for (f, nm, kn_pick) in [(dn_f0, dn_a.clone(), kna_var.as_str()), (dn_f1, dn_b.clone(), knb_var.as_str())] {
                cl.push_str(&crate::VM::VM_Backend::Generator_flow::build_decnum(
                    &mut rng, f, nm.as_str(), sm_p.as_str(), kn_pick, vb.as_str(),
                    vs.as_str(), ve.as_str(), vm.as_str(), f64_parts.join("+"),
                    v_num_i.as_str(), v_num_g.as_str(), fd18n.as_str(), rl18n.as_str(),
                    num_path_arg.as_str(), num_count_arg.as_str(), fn_bxor.as_str(),
                    sbt.as_str(), nbm.as_str(), slname.as_str(), sbox_params));
            }
            cl.push_str(&bind2(&mut rng, out_dn.as_str(), dn_a.as_str(), dn_b.as_str()));
            let (v_str_i, v_str_g, v_str_s) = (rng.name(), rng.name(), rng.name());
            let fd18s = rng.name();
            let rl18s = rng.name();
            let (str_path_arg, str_count_arg) = (rng.name(), rng.name());
            let (ds_f0, ds_f1) = {
                let a = rng.range(0, 4);
                let mut b = rng.range(0, 3);
                if b >= a { b += 1; }
                (a, b)
            };
            let ds_a = rng.name();
            let ds_b = rng.name();
            for (f, nm, ks_pick) in [(ds_f0, ds_a.clone(), ksa_var.as_str()), (ds_f1, ds_b.clone(), ksb_var.as_str())] {
                cl.push_str(&crate::VM::VM_Backend::Generator_flow::build_decstr(
                    &mut rng, f, nm.as_str(), sm_s.as_str(), ks_pick,
                    v_str_s.as_str(), v_str_i.as_str(), v_str_g.as_str(), fd18s.as_str(), rl18s.as_str(),
                    str_path_arg.as_str(), str_count_arg.as_str(), fn_bxor.as_str(), fn_s_byte.as_str(),
                    sbt.as_str(), sbox_params));
            }
            let (k_dn, k_ds, k_sl) = (
                rng.range(0x10_0000, 0x7FFF_FFFF) as u32,
                rng.range(0x10_0000, 0x7FFF_FFFF) as u32,
                rng.range(0x10_0000, 0x7FFF_FFFF) as u32,
            );
            cl.push_str(&bind2(&mut rng, out_ds.as_str(), ds_a.as_str(), ds_b.as_str()));
            cl.push_str(&format!(
                "{kr}[0X{kdn:X}],{kr}[0X{kds:X}],{kr}[0X{ksl:X}]={dn},{ds},{sl}",
                kr = kreg_n, kdn = k_dn, kds = k_ds, ksl = k_sl,
                dn = out_dn, ds = out_ds, sl = slname
            ));
            let m_cg = shell.add(&mut rng, &cg_params, cl);
            clusters.push(format!("{}; ", shell.call(&m_cg, &cg_params)));
            salt_names[g] = format!("{}[0X{:X}]", kreg_n, k_sl);
            dn_names[g] = format!("{}[0X{:X}]", kreg_n, k_dn);
            ds_names[g] = format!("{}[0X{:X}]", kreg_n, k_ds);
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
        
        // ㉓ 统一流守卫："function"/"__mode"/"k" 不留明文（惰性解密+纯数字密文）
        let hid_fun = uni.register("function");
        let hid_mode = uni.register("__mode");
        let hid_k = uni.register("k");
        let (fun_stmt, sc_fn_hdr) = uni.fetch(&mut rng, hid_fun);
        let (mode_stmt, sc_mode) = uni.fetch(&mut rng, hid_mode);
        let (k_stmt, sc_k) = uni.fetch(&mut rng, hid_k);
        let psn_pick = psn_pool[rng.range(0, psn_pool.len())].clone();
        let (hdr_m_body, hdr_wai_body) = crate::VM::VM_Backend::Generator_flow::build_header(
            &mut vault, &mut rng, &keys, fn_s_byte.as_str(), fn_s_sub.as_str(), var_raw_p.as_str(), payload_str.as_str(),
            var_vc.as_str(), var_p.as_str(), var_a2.as_str(), entry_func.as_str(), fn_a3.as_str(), x.as_str(),
            sc_fn_hdr.as_str(), sc_mode.as_str(), sc_k.as_str(), var_whiten.as_str(), var_whiten_pos.as_str(),
            native_type.as_str(), psn_pick.as_str());
        let (u_tbl, u_dec, u_kb) = (uni.tbl.clone(), uni.dec.clone(), uni.k_b.clone());
        let v_pack_arg = rng.name();
        let m_pack = shell.add(
            &mut rng,
            &[&v_pack_arg, &kreg_n, &u_tbl, &u_dec, &u_kb],
            format!("{} return {}({})", block_decoder_script, entry_func, v_pack_arg),
        );
        let s_hdr = rng.name();
        let d_hdr = rng.name();
        let m_hdr = shell.add_self(
            &mut rng,
            &s_hdr,
            &[&var_raw_p, &kreg_n, &u_tbl, &u_dec, &u_kb, &native_type, &keys.tbl_p, &fn_s_byte, &fn_s_sub],
            format!(
                "local function {}({}) return {}:{}({},{},{},{},{}) end; {}{}{}{}",
                entry_func, d_hdr, s_hdr, m_pack, d_hdr, kreg_n, u_tbl, u_dec, u_kb,
                fun_stmt, mode_stmt, k_stmt, hdr_m_body
            ),
        );
        let hdr_call_expr = shell.call(
            &m_hdr,
            &[&var_raw_p, &kreg_n, &u_tbl, &u_dec, &u_kb, &native_type, &keys.tbl_p, &fn_s_byte, &fn_s_sub],
        );
        let block_dec_header = hdr_wai_body.replace("@HDR_CALL@", &hdr_call_expr);
        // ㉛ 白化参数（逐构建随机）的产物侧拼写——read_dec 内每字节现算掩码用
        let rng_whiten_mul_s = rng.obfuscate_num(whiten_mul as i64, 1, &keys);
        let rng_whiten_add_s = rng.obfuscate_num(whiten_add as i64, 1, &keys);
        // ── 解码链（第 6 项：解密逻辑打乱）──
        // 冷路径一次性函数，放心打乱形态。
        let (v_bx_a, v_bx_b, v_bx_r, v_bx_w, v_bx_g, v_bx_s) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (v_rt_x, v_rt_n, v_rt_d, v_rt_g, v_rt_t) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (v_rd_o, v_rd_g, v_rd_e) = (rng.name(), rng.name(), rng.name());
        let (v_rd_c1, v_rd_c2, v_rd_c3, v_rd_c4, v_rd_c5) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());

        let dh_body = format!(
            "local {bx}={slot_bxor} or function({a},{b}) local {r},{w},{g},{s}=0,1,0,0; \
             while {g}<({r}*0X2-{r})-({r}-0X1) do \
             if {a}<=0 and {b}<=0 then {g}={g}+1 else \
             {s}=(({a}%2)+({b}%2))%2; {r}={r}+{s}*{w}; \
             {a}=({a}-({a}%2))/2; {b}=({b}-({b}%2))/2; {w}={w}+{w}; end end; \
             return {r} end; \
             local function {rt}({x},{n}) local {d},{g},{t}=2^{n},0,0; \
             while {g}<({t}*0X2-{t})-({t}-0X1) do \
             {t}=(({x}*(256/{d}))%256)+(({x}-({x}%{d}))/{d}); {g}={g}+1; end; \
             return {t} end; \
             return {bx},{rt}",
            bx = fn_bxor, slot_bxor = slot_bxor,
            a = v_bx_a, b = v_bx_b, r = v_bx_r, w = v_bx_w, g = v_bx_g, s = v_bx_s,
            rt = fn_b_rotr, x = v_rt_x, n = v_rt_n, d = v_rt_d, t = v_rt_t
        );
        let m_dh = shell.add(&mut rng, &[&kreg_n], dh_body);
        let rd_scatter = crate::VM::VM_Backend::Generator_flow::build_scatter(
            &mut rng, fn_bxor.as_str(), fn_b_rotr.as_str(), fn_read_dec.as_str(), fn_a3.as_str(),
            &v_bx_a, &v_bx_b, &v_bx_r, &v_bx_w, &v_bx_g, &v_bx_s,
            &v_rt_x, &v_rt_n, &v_rt_d, &v_rt_g, &v_rt_t,
            &v_rd_o, &v_rd_g, &v_rd_e, &v_rd_c1, &v_rd_c2, &v_rd_c3, &v_rd_c4, &v_rd_c5,
            sc_add, sc_rot_in, sc_add_k1, sc_mul_k2, sc_rot_k2, sc_rot_k4, var_whiten.as_str(),
            &rng_whiten_mul_s, &rng_whiten_add_s, &var_whiten_pos, var_a2.as_str());
        let block_dec_helpers = format!(
            "local {bx}; local {rd}; do local {rt}; {bx},{rt}={call}; {scatter} ",
            bx = fn_bxor,
            rd = fn_read_dec,
            rt = fn_b_rotr,
            call = shell.call(&m_dh, &[&kreg_n]),
            scatter = rd_scatter
                .strip_prefix(&format!("local {}; do ", fn_read_dec))
                .unwrap_or(&rd_scatter)
        );
        let (kt_name, pj_name) = (rng.name(), rng.name());
        let kc = crate::VM::VM_Backend::Generator_flow::build_k(&mut rng, kt_name.as_str());
        let (v_u32_t, v_u32_n, v_u32_i, v_u32_v) = (rng.name(), rng.name(), rng.name(), rng.name());
        let (v_a5_t, v_a5_n, v_a5_i) = (rng.name(), rng.name(), rng.name());
        let (v_rs_l, v_rs_t, v_rs_i) = (rng.name(), rng.name(), rng.name());
        let (v_a10_v, v_a10_h) = (rng.name(), rng.name());

        let u32_family = crate::VM::VM_Backend::Generator_flow::build_readers(
            &mut rng, &keys, &kc, kt_name.as_str(), pj_name.as_str(), fn_bxor.as_str(),
            fn_u32_dec.as_str(), fn_a5.as_str(), fn_read_string.as_str(), fn_read_dec.as_str(), fn_a10.as_str(),
            &v_u32_t, &v_u32_n, &v_u32_i, &v_u32_v, &v_rs_l, &v_a10_v, &v_a10_h);
        let m_dr = shell.add(
            &mut rng,
            &[&keys.tbl_p, &fn_bxor, &fn_read_dec, "string_char", "table_concat"],
            format!(
                "{} return {},{},{},{},{}",
                u32_family, fn_u32_dec, fn_a5, fn_read_string, fn_a10, kt_name
            ),
        );
        let block_dec_readers = format!(
            "local {},{},{},{},{}={}; ",
            fn_u32_dec, fn_a5, fn_read_string, fn_a10, kt_name,
            shell.call(&m_dr, &[&keys.tbl_p, &fn_bxor, &fn_read_dec, "string_char", "table_concat"])
        );
        
        // ⑰ 旧统一 dec_num/dec_str 已由四组簇内专属解码器取代。


        let x_repacked = ChainIn {
            rng,
            global_names,
            gn_key,
            at,
            keys,
            enc,
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
            psn_pool: psn_pool.clone(),
            poison_delay_key,
            var_a2,
            var_whiten,
            var_whiten_pos,
            whiten_mul,
            whiten_add,
            var_builtin_reg,
            var_p,
            var_raw_p,
            var_vc,
            native_type,
            native_pairs,
            np21,
            md21,
            th21,
            tw21,
            rk21,
            kreg_n,
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
            weld,
            uni,
            vault,
            header_captures,
            ros_params,
        };
        let mid = ChainMid {
            x: x_repacked,
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
            shell,
        };
        super::Generator_chain_tail::build_chain_tail(mid)
}
