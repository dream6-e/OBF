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
}

pub(super) const CG_GROUPS: usize = crate::VM::VM_Backend::Generator_util::CONST_GROUPS;

pub(super) struct ChainMid {
    pub x: ChainIn,
    pub h_var: String,
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
}

/// 第二阶段：chacha 簇 + 解码链 + 装配，返回最终目标源码。
pub(super) fn build_chain(x: ChainIn) -> String {
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
    } = x;
    let poison_delay_expr = format!("{}[0X{:X}]", kreg_n, poison_delay_key);
    // CG 原为第一阶段块内 const，随代码原样搬迁重声明（同值同路径）。
    #[allow(dead_code)]
    const CG: usize = crate::VM::VM_Backend::Generator_util::CONST_GROUPS;
        let mut block_chacha_setup = String::new();
        // ② 运行期指纹两股：动态指纹（地址/GC，非确定）只做等价形态选路；
        // 确定性指纹 hfix（改进 2）的值被折进根 K0 token 扭曲量——跳过指纹层
        // 即失去全部密钥材料，层不再可整层略过。静态读者要读装配细节，仍须
        // 先仿真宿主语义。
        let (fp_src, h_var) = crate::VM::VM_Backend::Generator_native::emit_fingerprint(&mut rng);
        block_chacha_setup.push_str(&fp_src);
        let (fix_src, fix_var, fix_val) = crate::VM::VM_Backend::Generator_kdf::emit_fix_fingerprint(&mut rng);
        block_chacha_setup.push_str(&fix_src);
        // 第 2 项：形态选路的**运行期绑定**——同一逻辑功能发射两型逐位等价的实现，
        // 由宿主指纹 h 在运行期择一（三种择一写法随机轮抽，产物里看不到固定
        // if/表形态；静态读者也必须先仿真宿主语义才知道走哪支）。
        // 第 2 项：**延迟静默投毒**——守卫失败只立共享旗 psn；随机指令窗口结束后，
        // 再渐进污染密钥/常量与路由。探针不早退、不抛专属错误；后续只呈现自然劣化。
        // 四种 Keystream 扰动均为模 256 运算，并按短命对象地址作运行期抽样；不消耗全局随机数。
        let poison_ks = |rng: &mut GenRng, ks: &str| -> String {
            let k1 = rng.range(0x100, 0xFFFF) as u32;
            let k2 = rng.range(0x100, 0xFFFF) as u32;
            let (sample_s, sample_h, sample_i) = (rng.name(), rng.name(), rng.name());
            let poison_sample = format!(
                "(function()local {s}=tostring({{}});local {h}=0;for {i}=1,#{s} do {h}=({h}*0X21+string.byte({s},{i}))%0X7FFFFF01 end;return {h}%0X80==0X0 end)()",
                s = sample_s, h = sample_h, i = sample_i
            );
            match rng.range(0, 4) {
                0 => format!("if {psn} and {delay}<=0 and {sample} then {ks}[0X1]=(0X{k:X}-{ks}[0X1])%0X100 end; ", psn = psn_n, delay = poison_delay_expr, sample = poison_sample, ks = ks, k = k1),
                1 => format!("if {psn} and {delay}<=0 and {sample} then local {z}=#{ks} while {z}>0X0 do {ks}[{z}]=(0X{k:X}-{ks}[{z}])%0X100; {z}={z}-0X1 end end; ", psn = psn_n, delay = poison_delay_expr, sample = poison_sample, ks = ks, k = k1, z = rng.name()),
                2 => format!("if {psn} and {delay}<=0 and {sample} then {ks}[0X1]=({ks}[0X1]+0X{k:X})%0X100; {ks}[#{ks}]=(0X{k2:X})%0X100 end; ", psn = psn_n, delay = poison_delay_expr, sample = poison_sample, ks = ks, k = k1, k2 = k2),
                _ => format!("if {psn} and {delay}<=0 and {sample} then for {z}=0X1,#{ks} do {ks}[{z}]=({ks}[{z}]*0X{k:X}+0X{k2:X})%0X100 end end; ", psn = psn_n, delay = poison_delay_expr, sample = poison_sample, ks = ks, k = k1, k2 = k2, z = rng.name()),
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
        // ⑤ 字节权 2^16/2^24 直接以数值字面量发射（xor32 内局部）。
        let (x16, x24) = (rng.name(), rng.name());
        let (x16v, x24v) = (crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 16), crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 24));
        block_chacha_setup.push_str(&format!(
            "local function {xor32}(a,b) local {p2}={p2v}; local {p3}={p3v}; local a1,a2,a3,a4=a%256,math_floor(a/256)%256,math_floor(a/{p2})%256,math_floor(a/{p3})%256; local b1,b2,b3,b4=b%256,math_floor(b/256)%256,math_floor(b/{p2})%256,math_floor(b/{p3})%256; return {xt}[a1][b1]+{xt}[a2][b2]*256+{xt}[a3][b3]*{p2}+{xt}[a4][b4]*{p3} end; ",
            xor32 = fn_xor32, xt = xor_tbl_var,
            p2 = x16, p3 = x24, p2v = x16v, p3v = x24v
        ));
        // ㉔ 2^32 模数直接发射数值字面量，不再生成可折叠差式。
        let mk_m = |_rng: &mut GenRng| -> String { "4294967296".to_string() };
        let (m_rot1, m_rot2) = (mk_m(&mut rng), mk_m(&mut rng));
        block_chacha_setup.push_str(&format!(
            "local function {rotl32}(x,n) local m=2^n; return ((x*m)%{m1})+math_floor(x/({m2}/m)) end; ",
            rotl32 = fn_rotl32, m1 = m_rot1, m2 = m_rot2
        ));
        // ㉔ quarter-round 形态池（0=教科书原版保留）+ 旋转常量直接输出数值字面量，
        // 并随机化形参（单字母 s,a,b,c,d 即参考实现指纹）。
        // 各臂输出与标准 QR 恒等（A+=B;D^=A;D=rot(D,16);C+=D;B^=C;B=rot(B,12);×2 变体）。
        let r_lit = |rng: &mut GenRng, v: u32| -> String { rng.format_num(v as i64) };
        let (qS, qA, qB, qC, qD) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (r1e, r2e, r3e, r4e) = (r_lit(&mut rng, 16), r_lit(&mut rng, 12), r_lit(&mut rng, 8), r_lit(&mut rng, 7));
        // 第 3 项 D：单根 K0 与 KDF 函数——四组的全部密钥材料都从这一份
        // 根现算。根以 token 掩码形态落盘（X/掩码分表、槽位洗牌、运行期异或还原）；
        // KDF 是纯算术（32 位异或实现 + 算术旋转 + 16 位拆乘），与 Rust 侧逐位同式。
        // 位置：在 xor32/rotl32 定义之后（KDF 体引用这两个局部），且在各簇之前。
        let (root_tok, root_fetch) = {
            let rt = crate::VM::VM_Backend::Generator_kdf::root_tokens(&mut rng, &keys, &enc.root, &h_var,
                &fix_var, fix_val, fn_xor32.as_str());
            block_chacha_setup.push_str(&rt.decl);
            let f: Vec<String> = (0..8).map(|i| rt.fetch[i].clone()).collect();
            (rt, f)
        };
        // 根装配辅料（X/掩码/槽位表 + 异或实现）只在装配期用：装完即销毁；
        // 值表本身必须常驻（各常量解码簇的流闭包以 upvalue 捕获它）
        block_chacha_setup.push_str(&crate::VM::VM_Backend::Generator_kdf::dispose_stmt(&mut rng, &root_tok.aux));
        let kdf_name = rng.name();
        let kdf_m32v = crate::VM::VM_Backend::Generator_kdf::kdf_m32(&mut rng);
        block_chacha_setup.push_str(&crate::VM::VM_Backend::Generator_kdf::kdf_fn_decl(
            &mut rng, &keys, kdf_name.as_str(), fn_xor32.as_str(), fn_rotl32.as_str(), kdf_m32v.as_str()));
        // ㉛ 载荷白化种子：kdf(根字, 专用组号, 字序号) —— 与 Rust 侧
        // `Generator::whiten_byte` 的 seed 同式同值。读者侧 read_dec 以
        // (seed, 位置) 现算掩码字节，故产物里落不下任何白化参数：
        // 要还原载荷结构，必须先装出根 K0（另一层）再复刻 KDF。
        {
            let wg = rng.obfuscate_num(crate::VM::VM_Backend::Generator::WHITEN_GROUP as i64, 1, &keys);
            let ww = rng.obfuscate_num(crate::VM::VM_Backend::Generator::WHITEN_WORD as i64, 1, &keys);
            // 与 Rust 侧 `w % 2147483646 + 1` 同式：模 2^31-2 后 +1（避开 0 不动点）
            let wmod = rng.obfuscate_num(2147483646i64, 1, &keys);
            let seed = format!("{kdf}({root},{g},{w})", kdf = kdf_name, root = root_fetch[3], g = wg, w = ww);
            block_chacha_setup.push_str(&format!("{wk}=({seed}%{m})+0X1; ", wk = var_whiten, seed = seed, m = wmod));
        }
        let m_qr1 = mk_m(&mut rng); let m_qr2 = mk_m(&mut rng);
        let x32 = fn_xor32.as_str(); let rt = fn_rotl32.as_str();
        let mk_qr = |rng: &mut GenRng,
                     wc: &mut crate::VM::VM_Backend::Generator_kdf::WeldCache,
                     kind: usize,
                     name: &str|
         -> String {
            let (m1, m2) = (m_qr1.as_str(), m_qr2.as_str());
            match kind {
                0 => {
                    // ㉒② 焊接模数：QR 每块 20 轮重入，第二次起该 if 逻辑上无分支。
                    let qe = wc.dst();
                    let qw = format!("local {};", qe) + &wc.weld(rng, &qe, m1);
                    format!(
                    "local function {qr}({S},{A},{B},{C},{D}) {w} {S}[{A}]=({S}[{A}]+{S}[{B}])%{m1}; {S}[{D}]={x}({S}[{D}],{S}[{A}]); {S}[{D}]={r}({S}[{D}],{c1}); {S}[{C}]=({S}[{C}]+{S}[{D}])%{m1}; {S}[{B}]={x}({S}[{B}],{S}[{C}]); {S}[{B}]={r}({S}[{B}],{c2}); {S}[{A}]=({S}[{A}]+{S}[{B}])%{m1}; {S}[{D}]={x}({S}[{D}],{S}[{A}]); {S}[{D}]={r}({S}[{D}],{c3}); {S}[{C}]=({S}[{C}]+{S}[{D}])%{m1}; {S}[{B}]={x}({S}[{B}],{S}[{C}]); {S}[{B}]={r}({S}[{B}],{c4}) end; ",
                    qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw,
                    m1 = qe, x = x32, r = rt, c1 = r1e, c2 = r2e, c3 = r3e, c4 = r4e)
                }
                1 => {
                    // 半轮助手四连调用：视觉上不再是「加/异或/移位」三连奏
                    let hname = rng.name(); let m_h = mk_m(rng);
                    let he = wc.dst();
                    let hw = format!("local {};", he) + &wc.weld(rng, &he, &m_h);
                    format!(
                        "local function {h}({S},{U},{V},{W},{Rr}) {w} {S}[{U}]=({S}[{U}]+{S}[{V}])%{m}; {S}[{W}]={x}({S}[{W}],{S}[{U}]); {S}[{W}]={r}({S}[{W}],{Rr}) end; local function {qr}({S},{A},{B},{C},{D}) {h}({S},{A},{B},{D},{c1}); {h}({S},{C},{D},{B},{c2}); {h}({S},{A},{B},{D},{c3}); {h}({S},{C},{D},{B},{c4}) end; ",
                        h = hname, qr = name, S = qS, U = rng.name(), V = rng.name(), W = rng.name(), Rr = rng.name(), w = hw,
                        A = qA, B = qB, C = qC, D = qD, m = he, x = x32, r = rt,
                        c1 = r1e, c2 = r2e, c3 = r3e, c4 = r4e)
                }
                2 => {
                    // 局部化平展：热路径零表索引，收尾一次写回
                    let qe2 = wc.dst();
                    let qw2 = format!("local {};", qe2) + &wc.weld(rng, &qe2, m1);
                    format!(
                    "local function {qr}({S},{A},{B},{C},{D}) local {a},{b},{c},{d}={S}[{A}],{S}[{B}],{S}[{C}],{S}[{D}]; {w} {a}=({a}+{b})%{m1}; {d}={x}({d},{a}); {d}={r}({d},{c1}); {c}=({c}+{d})%{m1}; {b}={x}({b},{c}); {b}={r}({b},{c2}); {a}=({a}+{b})%{m1}; {d}={x}({d},{a}); {d}={r}({d},{c3}); {c}=({c}+{d})%{m1}; {b}={x}({b},{c}); {b}={r}({b},{c4}); {S}[{A}],{S}[{B}],{S}[{C}],{S}[{D}]={a},{b},{c},{d} end; ",
                    qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw2,
                    a = rng.name(), b = rng.name(), c = rng.name(), d = rng.name(),
                    m1 = qe2, x = x32, r = rt, c1 = r1e, c2 = r2e, c3 = r3e, c4 = r4e)
                }
                _ => {
                    // 步骤闭包表+驱动：与 QR 形态最远（12 个无序可读的单操作闭包）
                    let st = rng.name(); let m_s = mk_m(rng);
                    // ㉒② 模数焊接（闭包捕获焊接值）；㉒① 12 闭包驱动环 → 3 态游标机。
                    let qe3 = wc.dst();
                    let qw3 = format!("local {};", qe3) + &wc.weld(rng, &qe3, &m_s);
                    let qw_off = rng.range(0, 100);
                    let st2 = st.clone();
                    let qwalk = {
                        let unit = |iv: &str| format!("{}[{}](); ", st2, iv);
                        crate::VM::VM_Backend::Generator_util::cursor_walk_static(rng, None, qw_off, 1, 12, 3, None, &unit)
                    };
                    format!(
                        "local function {qr}({S},{A},{B},{C},{D}) {w} local {st}={{function() {S}[{A}]=({S}[{A}]+{S}[{B}])%{m} end,function() {S}[{D}]={x}({S}[{D}],{S}[{A}]) end,function() {S}[{D}]={r}({S}[{D}],{c1}) end,function() {S}[{C}]=({S}[{C}]+{S}[{D}])%{m} end,function() {S}[{B}]={x}({S}[{B}],{S}[{C}]) end,function() {S}[{B}]={r}({S}[{B}],{c2}) end,function() {S}[{A}]=({S}[{A}]+{S}[{B}])%{m} end,function() {S}[{D}]={x}({S}[{D}],{S}[{A}]) end,function() {S}[{D}]={r}({S}[{D}],{c3}) end,function() {S}[{C}]=({S}[{C}]+{S}[{D}])%{m} end,function() {S}[{B}]={x}({S}[{B}],{S}[{C}]) end,function() {S}[{B}]={r}({S}[{B}],{c4}) end}}; {walk} end; ",
                        qr = name, S = qS, A = qA, B = qB, C = qC, D = qD, w = qw3, walk = qwalk,
                        st = st, m = qe3, x = x32, r = rt,
                        c1 = r1e, c2 = r2e, c3 = r3e, c4 = r4e)
                }
            }
        };
        // 第 2 项：QR 形态池四型，逐构建抽**两型**同时发射，运行期按宿主指纹 h 选路——
        // 两型逐位等价（同加/异或/旋转语义，只是写法与数据通路不同），静态读者既读
        // 不出走哪支，也无法只按一种教科书写法对上号；产物里也不再有单一 QR 体。
        let (qk0, qk1) = {
            let a = rng.range(0, 4);
            let mut b = rng.range(0, 3);
            if b >= a { b += 1; }
            (a, b)
        };
        let qn0 = rng.name();
        let qn1 = rng.name();
        let qd0 = mk_qr(&mut rng, &mut weld, qk0, &qn0);
        let qd1 = mk_qr(&mut rng, &mut weld, qk1, &qn1);
        let qsel = match rng.range(0, 3) {
            0 => format!("local {qr}={n1}; if ({h}%0X2)==0X0 then {qr}={n0} end; ",
                    qr = fn_qr, n0 = qn0, n1 = qn1, h = h_var),
            1 => format!("local {qr}; if ({h}%0X2)==0X0 then {qr}={n0} else {qr}={n1} end; ",
                    qr = fn_qr, n0 = qn0, n1 = qn1, h = h_var),
            _ => format!("local {tv}={{[0X1]={n0},[0X2]={n1}}}; local {qr}={tv}[({h}%0X2)+0X1]; ",
                    qr = fn_qr, n0 = qn0, n1 = qn1, h = h_var, tv = rng.name()),
        };
        block_chacha_setup.push_str(&format!("{}{}{}", qd0, qd1, qsel));
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
        // ⑰ 每组一个自包含簇：K/salt/sigma 排列/cblock/cstream + 专属 dec_str/dec_num
        // （无统一路由入口——四个簇打散插到产物不同位置，各原型按组直连本簇解码器）
        let mut clusters: Vec<String> = Vec::with_capacity(CG);
        let mut ds_names: [String; CG] = std::array::from_fn(|_| String::new());
        let mut dn_names: [String; CG] = std::array::from_fn(|_| String::new());
        let mut salt_names: [String; CG] = std::array::from_fn(|_| String::new());
        for g in 0..CG {
            // 第 3 项 D：**单根派生**——本簇不再带自己的密钥材料，8 个密钥字与
            // 盐/kind 全部由根 K0 在运行期经 KDF 现算（K0 自身也只是 token 掩码，
            // 且来自原生流）。产物里既没有「一组 8 个密钥字」，也没有「每组一套
            // 材料」可循；静态读者要先复刻异或表/算术旋转才能重现派生。
            let dg = crate::VM::VM_Backend::Generator_kdf::derive_group(&mut rng, &keys, kdf_name.as_str(), &root_fetch, g);
            let slname = dg.salt.clone();
            let knum_var = dg.knum.clone();
            let kstr_var = dg.kstr.clone();
            let sname = rng.name();
            let cbname = rng.name();
            // 簇外可见的三个出口（簇体落在 do…end 里，壳函数活动局部数不膨胀）
            let out_ds = rng.name();
            let out_dn = rng.name();
            let out_sl = rng.name();
            let mut cl = String::new();
            // ⑤ sigma 还原模数直接发射数值字面量。
            let sm32 = rng.name();
            let sm32v = crate::VM::VM_Backend::Generator_kdf::kdf_m32(&mut rng);
            let sigma_items: Vec<String> = (0..4)
                .map(|i| {
                    let r = rng.next();
                    let d = sigma[i].wrapping_sub(r);
                    format!("(({}+{})%{m32})", rng.obfuscate_num(d as i64, 1, &keys), rng.obfuscate_num(r as i64, 1, &keys), m32 = sm32)
                })
                .collect();
            let sigma_lua = sigma_items.join(",");
            cl.push_str(&format!("local {sm32}={sm32v}; ", sm32 = sm32, sm32v = sm32v));
            cl.push_str(&dg.decl);
            // 第 2 项：本簇的 ChaCha 状态布局（全状态置换 ρ / 轮数 / counter 步进），
            // 读写两侧同参——产物里的「4 sigma + 8 密钥 + counter + 3 nonce」排列消失
            let ly = enc.layout[g];
            let inv = ly.inv();
            // 逻辑序 16 字 → 物理位置序字面量
            let mut logical: [String; 16] = std::array::from_fn(|_| String::new());
            for i in 0..4 { logical[i] = sigma_items[i].clone(); }
            for j in 0..8 { logical[4 + j] = dg.fetch[j].clone(); }
            for i in 12..16 { logical[i] = "0X0".to_string(); }
            // 状态模板：指纹选路的第二支用它整表拷贝（省 8 次算式求值），两支同结果
            let tm = rng.name();
            cl.push_str(&format!("local {tm}={}; ",
                crate::VM::VM_Backend::Generator_chacha::state_literal(&ly, &logical), tm = tm));
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
            // ㉒ 簇内 cb 与通用解码路径一致：焊接混合模数 + 两条 16 环游标化。
            let gmix_v = mk_m(&mut rng);
            let gmix_e = weld.dst();
            let gmix_weld = format!("local {};", gmix_e) + &weld.weld(&mut rng, &gmix_e, &format!("({})", gmix_v));
            let gs1_walk = {
                let off = rng.range(0, 100);
                let unit = |iv: &str| format!("o[{iv}]=s[{iv}]; ", iv = iv);
                crate::VM::VM_Backend::Generator_util::cursor_walk_static(&mut rng, None, off, 1, 16, 4, None, &unit)
            };
            // ⑤ u32 拆分字节权逐构建派生
            let (gp2, gp3) = (rng.name(), rng.name());
            let (gp2v, gp3v) = (crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 16), crate::VM::VM_Backend::Generator_kdf::kdf_pow2(&mut rng, 24));
            // 第 2 项：输出字按 ρ⁻¹ 写回各自的输出字节位（物理槽 ≠ 逻辑字）。
            // 物理槽 → 输出首字节下标 的映射落成一张直接数值表。
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
                "local function {cb}(n1,n2,n3,ctr) {mixw} local s; if ({h}%0X3)==0X0 then s={lit} else s={{}}; for {ti}=0X1,0X10 do s[{ti}]={tm}[{ti}] end; s[{o12}]=ctr; s[{o13}]=n1; s[{o14}]=n2; s[{o15}]=n3 end; local o={{}}; local {p2}={p2v}; local {p3}={p3v}; {w1} {rounds} local out={{}}; {w2} return out end; ",
                cb = cbname, mixw = gmix_weld, h = h_var, lit = s_lit, tm = tm, ti = rng.name(),
                o12 = o12, o13 = o13, o14 = o14, o15 = o15,
                w1 = gs1_walk, w2 = gs2_walk, p2 = gp2, p3 = gp3, p2v = gp2v, p3v = gp3v,
                rounds = mk_rounds(&mut rng, fn_qr.as_str(), &ly)));
            // ㉓-A 换公式：nonce=[盐^roll^fold, r7^(槽*6+kind), 盐^rotl7(r7)]——
            // layouts 直传退役；roll/fold 由 body_consts 扫描重算后经 dsp 透传
            let salt_v18 = slname.clone();
            // 第 2 项：counter 走奇步长线性表；第 3 项 C 起 counter 还叠一块反馈。
            let ctr0e = rng.obfuscate_num(ly.ctr0 as i64, 1, &keys);
            let stepe = rng.obfuscate_num(ly.step as i64, 1, &keys);
            // 第 3 项 C：**链式解密**——解密器不再吐 Keystream 让调用者自己异或，
            // 而是按 64 字节块就地解密：第 j+1 块 counter = 第 j 块 counter +
            // step + fold(第 j 块**已解明文**前 8 字节)。要拿下一块流，必须先把
            // 上一块明文解出来——静态复现者绕不过这一步（第 1 块除外）。
            let (sm_p, sm_s) = (rng.name(), rng.name());
            let pz_p = poison_ks(&mut rng, "blk");
            let pz_s = poison_ks(&mut rng, "blk");
            let mk_nonce = |rng: &mut GenRng, sl: &str, bx: &str, rot: &str| -> (String, String, String, String) {
                let (e1, r7v, e2, e3) = (rng.name(), rng.name(), rng.name(), rng.name());
                let t = format!(
                    "local {e1}={bx}({bx}({sl},rl or 0X0),fold or 0X0); local {r7v}={rot}(rl or 0X0,0X7); local {e2}={bx}({r7v},pool_idx*0X6+kind); local {e3}={bx}({sl},{rot}({r7v},0X7)); ",
                    e1 = e1, r7v = r7v, e2 = e2, e3 = e3, sl = sl, bx = bx, rot = rot);
                (t, e1, e2, e3)
            };
            // 数字解密器：8 字节正好一块，无后续块故无链；仍走同一解密/投毒通路
            {
                let (nd, e1, e2, e3) = mk_nonce(&mut rng, salt_v18.as_str(), fn_bxor.as_str(), fn_rotl32.as_str());
                let i = rng.name();
                cl.push_str(&format!(
                    "local function {smp}(v,pool_idx,kind,fold,rl) {nd}local blk={cb}({e1},{e2},{e3},{c0}); {pz} local out={{}}; for {i}=0X1,0X8 do out[{i}]={xt}[v[{i}]][blk[{i}]] end; return out end; ",
                    smp = sm_p, nd = nd, e1 = e1, e2 = e2, e3 = e3, cb = cbname, c0 = ctr0e,
                    pz = pz_p, i = i, xt = xor_tbl_var));
            }
            // 字符串解密器：块链式（内层游标形态两抽：while / repeat）
            {
                let (nd, e1, e2, e3) = mk_nonce(&mut rng, salt_v18.as_str(), fn_bxor.as_str(), fn_rotl32.as_str());
                let (n, pos, ctr, q, fw, ww, lim) =
                    (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
                let core = match rng.range(0, 2) {
                    0 => format!(
                        "local {n}=#e; local out={{}}; local {pos}=0X1; local {ctr}={c0}; \
                         while {pos}<={n} do local blk={cb}({e1},{e2},{e3},{ctr}); {pz} local {lim}={pos}+0X3F; if {lim}>{n} then {lim}={n} end \
                           local {q}=0X0; local {fw}=0X0; local {ww}=0X1; \
                           while {pos}<={lim} do {q}={q}+0X1; local p={xt}[{sb}(e,{pos})][blk[{q}]]; out[{pos}]=p; if {q}<=0X8 then {fw}=({fw}+p*{ww})%{m32} {ww}=({ww}*0X100)%{m32} end {pos}={pos}+0X1 end \
                           {ctr}=({ctr}+{st}+{fw})%{m32} end; return out end; ",
                        n = n, pos = pos, ctr = ctr, q = q, fw = fw, ww = ww, lim = lim,
                        cb = cbname, e1 = e1, e2 = e2, e3 = e3, c0 = ctr0e, pz = pz_s,
                        xt = xor_tbl_var, sb = fn_s_byte, m32 = sm32, st = stepe),
                    _ => format!(
                        "local {n}=#e; local out={{}}; local {pos}=0X1; local {ctr}={c0}; \
                         repeat local blk={cb}({e1},{e2},{e3},{ctr}); {pz} local {q}=0X0; local {fw}=0X0; local {ww}=0X1; local {lim}={pos}+0X3F; if {lim}>{n} then {lim}={n} end \
                           if {pos}<={lim} then repeat {q}={q}+0X1; local p={xt}[{sb}(e,{pos})][blk[{q}]]; out[{pos}]=p; if {q}<=0X8 then {fw}=({fw}+p*{ww})%{m32} {ww}=({ww}*0X100)%{m32} end {pos}={pos}+0X1 \
                           until {pos}>{lim} or {q}>=0X40 end; {ctr}=({ctr}+{st}+{fw})%{m32} until {pos}>{n}; return out end; ",
                        n = n, pos = pos, ctr = ctr, q = q, fw = fw, ww = ww, lim = lim,
                        cb = cbname, e1 = e1, e2 = e2, e3 = e3, c0 = ctr0e, pz = pz_s,
                        xt = xor_tbl_var, sb = fn_s_byte, m32 = sm32, st = stepe),
                };
                cl.push_str(&format!("local function {sms}(e,pool_idx,kind,fold,rl) {nd}{core}", sms = sm_s, nd = nd, core = core));
            }
            // 组专属解码器：kind 常量内嵌（每组不同随机值，同样是运行期现算的 token）
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
            // 第 2 项：dec_num 形态池四型 → 本簇抽两型同时发射 + 运行期 h 选路
            let (dn_f0, dn_f1) = {
                let a = rng.range(0, 4);
                let mut b = rng.range(0, 3);
                if b >= a { b += 1; }
                (a, b)
            };
            let dn_a = rng.name();
            let dn_b = rng.name();
            for (f, nm) in [(dn_f0, dn_a.clone()), (dn_f1, dn_b.clone())] {
                cl.push_str(&crate::VM::VM_Backend::Generator_flow::build_decnum(
                    &mut rng, f, nm.as_str(), sm_p.as_str(), knum_var.as_str(), vb.as_str(),
                    vs.as_str(), ve.as_str(), vm.as_str(), f64_parts.join("+"),
                    v_num_i.as_str(), v_num_g.as_str(), fd18n.as_str(), rl18n.as_str(),
                    num_path_arg.as_str(), num_count_arg.as_str(), fn_bxor.as_str()));
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
            for (f, nm) in [(ds_f0, ds_a.clone()), (ds_f1, ds_b.clone())] {
                cl.push_str(&crate::VM::VM_Backend::Generator_flow::build_decstr(
                    &mut rng, f, nm.as_str(), sm_s.as_str(), kstr_var.as_str(),
                    v_str_s.as_str(), v_str_i.as_str(), v_str_g.as_str(), fd18s.as_str(), rl18s.as_str(),
                    str_path_arg.as_str(), str_count_arg.as_str(), fn_bxor.as_str(), fn_s_byte.as_str()));
            }
            cl.push_str(&bind2(&mut rng, out_ds.as_str(), ds_a.as_str(), ds_b.as_str()));
            // 出口赋给簇外可见名。注意：派生表（密钥字表）**不能**在这里销毁——
            // 簇内流闭包以 upvalue 捕获它（旧式销毁的是 X/掩码/槽位表与异或实现，
            // 那些现在只存在于根装配处，已随根装配一并销毁）。
            cl.push_str(&format!("{o3}={sl2}; ", o3 = out_sl, sl2 = slname));
            // 整簇落在 do…end：簇内的表/闭包/临时名随块结束释放（lua5.1 单函数
            // 200 局部上限），簇外的解码器与盐以 upvalue 捕获
            clusters.push(crate::VM::VM_Backend::Generator_kdf::cluster_scope(
                &[out_dn.clone(), out_ds.clone(), out_sl.clone()], &cl));
            salt_names[g] = out_sl;
            dn_names[g] = out_dn;
            ds_names[g] = out_ds;
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
        let block_dec_header = crate::VM::VM_Backend::Generator_flow::build_header(
            &mut rng, &keys, fn_s_byte.as_str(), fn_s_sub.as_str(), var_raw_p.as_str(), payload_str.as_str(),
            var_vc.as_str(), var_p.as_str(), var_a2.as_str(), entry_func.as_str(), fn_a3.as_str(), x.as_str(),
            sc_fn_hdr.as_str(), sc_mode.as_str(), sc_k.as_str(), var_whiten.as_str(), var_whiten_pos.as_str(),
            native_type.as_str(), psn_n.as_str());
        let block_dec_header = format!("{fun_stmt}{mode_stmt}{k_stmt}") + &block_dec_header;
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

        // 注意：产物里的 k1..k4 是固定局部名，模板里只能写裸标识符 k1 —— 写成 {k1}
        // 会被 format! 隐式捕获抓走同名生成器变量（产物语法错）；
        // 同理 Lua 的空表要写 {{}}，裸 {} 是位置参数占位符。
        // 原形态：逐位比较累权重、n==0早返回右移、滚动密钥顺序赋值
        // 现在：位异或写成 (xa+xb)%2 乘权重、右移用 256/2^n 代 2^(8-n) 去早返回
        // 解密链拆 5 个中间变量、密钥演化换等价变形（-229 代 +27、
        // (v-v%d)/d 代 floor、k2*2+k2 代 k2*3，包单次循环+影子计数器。
        let block_dec_helpers = format!(
            "local function {bx}({a},{b}) local {r},{w},{g},{s}=0,1,0,0; \
             while {g}<({r}*0X2-{r})-({r}-0X1) do \
             if {a}<=0 and {b}<=0 then {g}={g}+1 else \
             {s}=(({a}%2)+({b}%2))%2; {r}={r}+{s}*{w}; \
             {a}=({a}-({a}%2))/2; {b}=({b}-({b}%2))/2; {w}={w}+{w}; end end; \
             return {r} end; \
             local function {rt}({x},{n}) local {d},{g},{t}=2^{n},0,0; \
             while {g}<({t}*0X2-{t})-({t}-0X1) do \
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
                sc_add, sc_rot_in, sc_add_k1, sc_mul_k2, sc_rot_k2, sc_rot_k4, var_whiten.as_str(),
                &rng_whiten_mul_s, &rng_whiten_add_s, &var_whiten_pos, var_a2.as_str())
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


        let x_repacked = ChainIn {
            rng,
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
        };
        let mid = ChainMid {
            x: x_repacked,
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
        };
        super::Generator_chain_tail::build_chain_tail(mid)
}
