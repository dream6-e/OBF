//! Generator 的载荷读写、字节码重写与加载器探测工具层。
//! 从 Generator_util.rs 拆出（守单文件 80 KB 上限，保持两文件各约 40 KB）。
use std::collections::HashSet;
use rand::{Rng, rngs::StdRng};
use crate::compiler::instructions::{OpArgMask, OpCode, OpMode};
use super::CustomIsa::{VM_OPCODE_COUNT, VmOp};
use super::Generator_chacha::{ChaChaLayout, SIGMA as CHACHA_SIGMA, stream_xor as chacha_xor_layout};
use super::Generator_util::{GenRng, UniStream};

/// #3 常量密钥混入引用折叠：逐产物随机参数（谓词/f 函数常数），
/// Rust 写侧与 Lua body_consts 扫描同式重算 F_li=Σf(pc)
pub(super) struct FoldCtx {
    pub r6b: u32, pub p1b: u32, pub p3b: u32,   // B 位引用谓词 pv_b(v)=(rotl32(v,r6b)^p1b)%100<p3b
    pub r6c: u32, pub p1c: u32, pub p3c: u32,   // C 位引用谓词
    pub f1: u32, pub f2: u32,                   // f(pc)=(pc*f1)^f2
    // ③-3 每常量 MAC 参数（逐 build 随机；读写两侧同式）：
    // s=m1^(slot*m2)^fold^rotl(roll,m3)；逐字节 s=(s+b*m4)%2^32, s^=rotl(s,m5)
    pub m1: u32, pub m2: u32, pub m3: u32, pub m4: u32, pub m5: u32,
    pub rs18: u32, // ⑤ R 链滚动初值种子（逐构建随机，替代固定 0x2545F491）
    pub fk1: u32,  // 引用扫描动态左旋乘数（奇数 3..=31）
    pub fk2: u32,  // Ftbl[slot] 逐槽异构左旋乘数（奇数 3..=31）
    pub fk3: u32,  // Rtbl[slot] 逐槽异构左旋乘数（奇数 3..=31）
    pub emul: u32,
    pub eadd: u32,
    pub jmul: u32,
    pub jtbl_key: u32,
    pub bmul: u32,
    pub binv: u32,
    pub badd: u32,
    pub bsub: u32,
    pub bxor_c: u32,
}

fn fold_step(
    fold_map: &mut std::collections::HashMap<u32, u32>,
    roll_map: &mut std::collections::HashMap<u32, u32>,
    sk: u32,
    pc18: u32,
    fp: u32,
    roll18: u32,
    fk1: u32,
) {
    let k_step = ((sk.wrapping_mul(fk1).wrapping_add(pc18)) % 15) + 1;
    let e = fold_map.entry(sk).or_insert(0u32);
    *e = e.rotate_left(k_step).wrapping_add(fp);
    roll_map.insert(sk, roll18);
}

/// ③-3 每常量 MAC：对 (密文块, 槽号, 折叠值, R链值) 的滚动校验和——
/// 只用加/异或/旋转（Lua double 下全精确：b*m4 ≤ 255*(2^32-1) < 2^40）。
/// 篡改密文/槽位/指令流（fold、roll 变）任一处都会使校验失败。
pub(super) fn const_mac18(blob: &[u8], slot: u32, fold: u32, roll: u32, fc: &FoldCtx) -> u32 {
    let mut s = fc.m1 ^ slot.wrapping_mul(fc.m2) ^ fold ^ roll.rotate_left(fc.m3);
    for &b in blob {
        s = s.wrapping_add((b as u32).wrapping_mul(fc.m4));
        s ^= s.rotate_left(fc.m5);
    }
    s
}

/// ⑰ 常量按原型分组内联加密：每组独立 key/salt/nonce 布局/kind。
/// 密文块直接写进各原型的常量节——产物里不再存在整张中央密文表，
/// 恢复一组参数也只能解「用了这一组的那些原型」的常量。
pub(super) const CONST_GROUPS: usize = 4;

pub(super) struct EncCtx {
    pub keys: Vec<[u32; 8]>,
    pub salts: Vec<u32>,
    pub layouts: Vec<[usize; 3]>,
    pub kstr: Vec<u32>,
    pub knum: Vec<u32>,
    /// 第 2 项：每簇的 ChaCha 状态布局（全状态置换 ρ / 轮数 / counter 步进）——
    /// 读写两侧同参；产物侧的摆位与元组由 Generator_chain 按此发射
    pub layout: Vec<ChaChaLayout>,
    /// 第 3 项 D：单根 K0（8 字）——四组密钥/盐/kind 全部由它 KDF 现算；
    /// 它本身取自原生流（Native Stream），产物里以 token 掩码形态落一份
    pub root: [u32; 8],
    /// 消灭可打印性锚点：每簇 KDF 驱动的 256 项双射 S-Box 参数与正逆表
    pub sbox_a: Vec<[u8; 3]>,
    pub sbox: Vec<[u8; 256]>,
    pub inv_sbox: Vec<[u8; 256]>,
    pub sbox_smul: Vec<u32>,
    pub sbox_pmul: Vec<u32>,
    pub sbox_cmul: Vec<u32>,
    pub sbox_cadd: Vec<u32>,
    /// 消除 double 全零尾数特征：每簇 8 字节下标置换与逐字节模偏移步长
    pub num_bperm: Vec<[usize; 8]>,
    pub num_bbstep: Vec<u32>,
}

impl EncCtx {
    pub(super) fn new(rng: &mut GenRng, k0: [u32; 8]) -> Self {
        let mut keys = Vec::with_capacity(CONST_GROUPS);
        let mut salts = Vec::with_capacity(CONST_GROUPS);
        let mut kstr = Vec::with_capacity(CONST_GROUPS);
        let mut knum = Vec::with_capacity(CONST_GROUPS);
        for g in 0..CONST_GROUPS as u32 {
            let gk = super::Generator_chacha::group_keys(&k0, g);
            keys.push(gk.key);
            salts.push(gk.salt);
            kstr.push(gk.kstr);
            knum.push(gk.knum);
        }
        let mut layouts = Vec::with_capacity(CONST_GROUPS);
        for _ in 0..CONST_GROUPS {
            let mut ly = [0usize, 1, 2];
            for j in (1..3).rev() {
                let k = rng.range(0, j + 1);
                ly.swap(j, k);
            }
            layouts.push(ly);
        }
        let layout: Vec<ChaChaLayout> =
            (0..CONST_GROUPS).map(|_| ChaChaLayout::new(rng)).collect();
        let mut sbox_a = Vec::with_capacity(CONST_GROUPS);
        let mut sbox = Vec::with_capacity(CONST_GROUPS);
        let mut inv_sbox = Vec::with_capacity(CONST_GROUPS);
        let mut sbox_smul = Vec::with_capacity(CONST_GROUPS);
        let mut sbox_pmul = Vec::with_capacity(CONST_GROUPS);
        let mut sbox_cmul = Vec::with_capacity(CONST_GROUPS);
        let mut sbox_cadd = Vec::with_capacity(CONST_GROUPS);
        let mut num_bperm = Vec::with_capacity(CONST_GROUPS);
        let mut num_bbstep = Vec::with_capacity(CONST_GROUPS);
        for g in 0..CONST_GROUPS {
            let a1 = (rng.range(1, 128) as u8) * 2 + 1;
            let a2 = (rng.range(1, 128) as u8) * 2 + 1;
            let a3 = (rng.range(1, 128) as u8) * 2 + 1;
            let c1 = salts[g] & 0xFF;
            let c2 = kstr[g] & 0xFF;
            let c3 = knum[g] & 0xFF;
            let mut sb = [0u8; 256];
            let mut isb = [0u8; 256];
            for x in 0..256u32 {
                let u1 = (x * (a1 as u32) + c1) & 0xFF;
                let u2 = u1 ^ (u1 >> 4);
                let u3 = (u2 * (a2 as u32) + c2) & 0xFF;
                let u4 = u3 ^ (u3 >> 4);
                let y = ((u4 * (a3 as u32) + c3) & 0xFF) as u8;
                sb[x as usize] = y;
                isb[y as usize] = x as u8;
            }
            sbox_a.push([a1, a2, a3]);
            sbox.push(sb);
            inv_sbox.push(isb);
            sbox_smul.push((rng.range(1, 128) as u32) * 2 + 1);
            sbox_pmul.push((rng.range(1, 128) as u32) * 2 + 1);
            sbox_cmul.push((rng.range(1, 64) as u32) * 4 + 2);
            sbox_cadd.push((rng.range(1, 256) as u32) | 1);
            let mut bp = [0usize, 1, 2, 3, 4, 5, 6, 7];
            for j in (1..8).rev() {
                let k = rng.range(0, j + 1);
                bp.swap(j, k);
            }
            num_bperm.push(bp);
            num_bbstep.push((rng.range(1, 128) as u32) * 2 + 1);
        }
        Self {
            keys, salts, layouts, kstr, knum, layout, root: k0,
            sbox_a, sbox, inv_sbox, sbox_smul, sbox_pmul, sbox_cmul, sbox_cadd,
            num_bperm, num_bbstep,
        }
    }
}

#[derive(Clone, Copy)]
enum ConstantSlot {
    Source(usize),
    Decoy(usize),
}

pub(super) struct PayloadReader<'a> { pub(super) data: &'a [u8], pub(super) pos: usize }

impl<'a> PayloadReader<'a> {
    pub(super) fn read_u8(&mut self) -> u8 { let b = self.data[self.pos]; self.pos += 1; b }
    pub(super) fn read_u32(&mut self) -> u32 { let b = &self.data[self.pos..self.pos+4]; self.pos += 4; u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
    pub(super) fn read_u64(&mut self) -> u64 { let b = &self.data[self.pos..self.pos+8]; self.pos += 8; u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) }
    pub(super) fn read_bytes(&mut self, len: usize) -> &'a [u8] { let b = &self.data[self.pos..self.pos+len]; self.pos += len; b }
    pub(super) fn read_string(&mut self) -> &'a [u8] { let len = self.read_u32(); self.read_bytes(len as usize) }
}

pub(super) fn write_string(w: &mut Vec<u8>, s: &[u8]) { w.extend_from_slice(&(s.len() as u32).to_le_bytes()); w.extend_from_slice(s); }

pub(super) fn scan_used_opcodes(r: &mut PayloadReader, used_ops: &mut HashSet<u8>) {
    let name_len = r.read_u32();
    r.read_bytes(name_len as usize);
    r.read_u32(); r.read_u32(); r.read_u8(); r.read_u8(); r.read_u8(); r.read_u8();
    let inst_count = r.read_u32();
    for _ in 0..inst_count {
        used_ops.insert(r.read_u8());
        r.read_u8(); r.read_u32(); r.read_u32();
    }
    let const_count = r.read_u32();
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => {}
            1 => { r.read_u8(); }
            2 => { r.read_u64(); }
            3 => { let s_len = r.read_u32(); r.read_bytes(s_len as usize); }
            _ => panic!(),
        }
    }
    let p_count = r.read_u32();
    for _ in 0..p_count { scan_used_opcodes(r, used_ops); }
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { let s_len = r.read_u32(); r.read_bytes(s_len as usize); r.read_u32(); r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { let s_len = r.read_u32(); r.read_bytes(s_len as usize); }
}

/// 扫描所有原型的最大 max_stack（判据③修复用：全局寄存器平移量 G 的上限
/// 由它决定——平移后寄存器必须仍在 <128 的 RK 边界内）。
pub(super) fn scan_max_stack(r: &mut PayloadReader, out: &mut u8) {
    let name_len = r.read_u32();
    r.read_bytes(name_len as usize);
    r.read_u32(); r.read_u32(); r.read_u8(); r.read_u8(); r.read_u8();
    let ms = r.read_u8();
    if ms > *out { *out = ms; }
    let inst_count = r.read_u32();
    for _ in 0..inst_count {
        r.read_u8(); r.read_u8(); r.read_u32(); r.read_u32();
    }
    let const_count = r.read_u32();
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => {}
            1 => { r.read_u8(); }
            2 => { r.read_u64(); }
            3 => { let s_len = r.read_u32(); r.read_bytes(s_len as usize); }
            _ => panic!(),
        }
    }
    let p_count = r.read_u32();
    for _ in 0..p_count { scan_max_stack(r, out); }
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { let s_len = r.read_u32(); r.read_bytes(s_len as usize); r.read_u32(); r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { let s_len = r.read_u32(); r.read_bytes(s_len as usize); }
}

// 反混淆判据②修复 + 跨单元指令流滚钥加密：
// 每条线上指令的 4 个字段 (mag_file, a_wire, fb, fc) 均受本单元派生的 (kb_p, kc_p, ki1_p, ki2_p)
// 与逐指令滚动的 w_roll 掩码保护；尾部 0..3 个随机字节不再是被丢弃的填充，而是直接混入 w_roll 推进后续指令密钥。
#[allow(clippy::too_many_arguments)]
fn emit_inst_wire(
    w: &mut Vec<u8>,
    w_roll: &mut u32,
    rng: &mut StdRng,
    g18: u32,
    a_dec: u32,
    fb0: u32,
    cb18: u32,
    fc0: u32,
    cc18: u32,
    hn18: u32,
    kp18: u32,
    kb_p: u32,
    kc_p: u32,
    ki1_p: u32,
    ki2_p: u32,
) {
    let wr = *w_roll;
    let km_i = kp18 ^ (wr & 0x0FFF_FFFF);
    let ka_i = wr.rotate_left(5) ^ hn18;
    let kb_i = kb_p ^ wr.rotate_left(11);
    let kc_i = kc_p ^ wr.rotate_left(17);
    let mag_file = g18 ^ km_i;
    let a_wire = a_dec ^ ka_i;
    let fb = (fb0 ^ cb18) ^ (g18 ^ ki1_p) ^ kb_i;
    let fc = (fc0 ^ cc18) ^ (g18 ^ ki2_p) ^ kc_i;
    w.extend_from_slice(&mag_file.to_le_bytes());
    w.extend_from_slice(&a_wire.to_le_bytes());
    w.extend_from_slice(&fb.to_le_bytes());
    w.extend_from_slice(&fc.to_le_bytes());
    let mut wr_next = wr.rotate_left(7).wrapping_add(g18) ^ a_dec;
    let jn = (mag_file >> 29) & 3;
    for _ in 0..jn {
        let jb = rng.random_range(0..256u32) as u8;
        w.push(jb);
        wr_next = wr_next.rotate_left(3).wrapping_add(jb as u32).wrapping_add(0x3D);
    }
    *w_roll = wr_next;
}

pub(super) fn rewrite_chunk(r: &mut PayloadReader, w: &mut Vec<u8>, mapped_opcodes: &[Vec<u32>; VM_OPCODE_COUNT], fused_map: &[Vec<u32>; crate::VM::Opcodes::builtins::FUSED_OP_COUNT], fused_used: &mut HashSet<usize>, inverse_opcode_map: &[u8; VM_OPCODE_COUNT], op_magic: &std::collections::HashMap<u32, u32>, enc: &EncCtx, group: usize, rng: &mut StdRng, kb: u32, kc: u32, ki1: u32, ki2: u32, fc18: &FoldCtx, tag_map: &[u8; 4], delta: u32, ch_m: u64, ch_k0: u64, alloc18: &mut u32, u_ctx: &mut u32, rosetta: &crate::VM::VM_Backend::Rosetta::RosettaPlan, proto_cursor: &mut usize) {
    let p_idx = *proto_cursor;
    *proto_cursor += 1;
    let p_plan = &rosetta.protos[p_idx];
    let u_in: u32 = *u_ctx;
    let kp18: u32 = rng.random_range(1..0x2000000u32) | 0x0100_0000;
    let pb18: u32 = *alloc18;
    // ㉚ 链式编码状态：种子=(kp18^pb18)*ch_m+(ch_k0^pb18)（与 Lua 扫描/解码器同式）；
    // 每条指令发射前取 (EO,CA,CB,CC)，发射后用本条逻辑值推进——单条公式全解作废
    let nochain18 = std::env::var("OBF_NOCHAIN").is_ok();
    let ch_k0_p: u64 = if nochain18 { 0 } else { ch_k0 ^ (pb18 as u64) };
    let mut chain18: u64 = (((kp18 ^ pb18) as u64).wrapping_mul(ch_m).wrapping_add(ch_k0_p)) % 0x1_0000_0000;
    #[allow(clippy::type_complexity)]
    let ch_split = |ch: u64| -> (u32, u32, u32, u32) {
        if std::env::var("OBF_NOCHAIN").is_ok() { return (0, 0, 0, 0); }
        let eo = ((ch % 0x100) * 2) as u32;
        let ca = ((ch / 0x100) % 0x100) as u32;
        let cb = ((ch.wrapping_mul(0x1_0001)) % 0x1_0000_0000) as u32;
        let cc = (((cb as u64).wrapping_mul(0x45D9) + ch) % 0x1_0000_0000) as u32;
        (eo, ca, cb, cc)
    };
    // 注：推进项用逻辑魔数（不含 Δ——扫描读侧撤销 EO 后手里只有 mag）
    let ch_step = |ch: u64, mag: u32, a: u32, fb0: u32, fc0: u32| -> u64 {
        if std::env::var("OBF_NOCHAIN").is_ok() { return 0; }
        (ch * 3 + (mag as u64) * 0x101 + (a as u64) * 0x1001
            + fb0 as u64 + (fc0 as u64) * 0x11) % 0x1_0000_0000
    };
    let _ = nochain18;
    // 跨单元头部耦合：hn18/kp18/pb18 均由前序单元终态 u_in 加密落盘，
    // 未完整解码父单元/前序兄弟单元的指令流与常量明文链则无法解出当前单元头部。
    let _ = r.read_string();
    let hn18: u32 = rng.random_range(0x0101_0101u32..=0xFFFF_FFFEu32);
    let hn_wire: u32 = hn18 ^ u_in;
    let kp_wire: u32 = kp18 ^ hn18.rotate_left(5) ^ u_in.rotate_left(11);
    let pb_wire: u32 = pb18 ^ hn18.rotate_left(13) ^ u_in.rotate_left(19);
    w.extend_from_slice(&hn_wire.to_le_bytes());
    let _ = r.read_u32(); let _ = r.read_u32();
    w.extend_from_slice(&kp_wire.to_le_bytes()); w.extend_from_slice(&pb_wire.to_le_bytes());
    w.push(r.read_u8()); w.push(r.read_u8()); w.push(r.read_u8());
    let max_stack = r.read_u8();
    // Per-Proto 偏移受 max_stack 约束，确保寄存器仍落在 RK 的 7-bit 域。
    let gshift_p: u8 = if max_stack < 127 {
        let cap = (127u8 - max_stack).min(48);
        rng.random_range(1u8..=cap.max(1))
    } else { 0 };
    // 该字段运行期不用于分配，复用作偏移元数据；字段名由生成器随机化。
    w.push(gshift_p);
    let raw_inst_cnt = r.read_u32();
    for _ in 0..raw_inst_cnt { r.read_u8(); r.read_u8(); r.read_u32(); r.read_u32(); }
    let raw_const_cnt = r.read_u32();
    for _ in 0..raw_const_cnt {
        match r.read_u8() {
            0 => {}
            1 => { r.read_u8(); }
            2 => { r.read_u64(); }
            3 => { let _ = r.read_string(); }
            _ => panic!(),
        }
    }
    let mut raw_insts = p_plan.raw_insts.clone();
    let inst_count = raw_insts.len() as u32;
    let const_count = p_plan.cperm.len() as u32;
    let decoy_count18 = p_plan.decoy_slots.len();
    let cperm = &p_plan.cperm;
    let decoy_slots = &p_plan.decoy_slots;
    let all_gslots = &p_plan.all_proto_gslots;

    const BITRK: u32 = 128;
    // Per-Proto 独立平移。这里按自定义 ISA 的字段定义移动寄存器，绝不借用
    // Lua 5.1 的 OpMode/B/C 操作数掩码。
    if gshift_p != 0 {
        for (op, a, b, c) in raw_insts.iter_mut() {
            let canonical = inverse_opcode_map[*op as usize];
            let vop = VmOp::from_global(canonical)
                .unwrap_or_else(|| panic!("非自定义 opcode 落入 VM 载荷：{canonical}"));
            if vop.has_register_a() {
                *a = (*a as u32 + gshift_p as u32) as u8;
            }
            if vop.has_register_b() {
                *b += gshift_p as u32;
            } else if vop.has_rk_b() && *b < BITRK {
                *b += gshift_p as u32;
            }
            if vop.has_register_c() {
                *c += gshift_p as u32;
            }
        }
    }
    let remap_rk = |v: u32| -> u32 {
        if v >= BITRK && (v - BITRK) < const_count { BITRK + cperm[(v - BITRK) as usize] } else { v }
    };
    let remap_bx = |v: u32| -> u32 { if v < const_count { BITRK + cperm[v as usize] } else { v } };

    // ---- 融合前的准备：算出所有可能成为跳转目标的 pc ----
    //
    // 融合会把三条指令压成一条，handler 里 `pc += 2` 跳过两个死槽。死槽本身
    // 仍然占位（所以其余跳转偏移一个都不用改），但前提是**绝不能有控制流
    // 直接落进死槽**。两类来源都要排除：
    //   1. 相对跳转的目标：pc 在取指时已经自增过 1，所以目标是 (i + 1 + sBx)
    //   2. 条件跳下一条的指令（Eq/Lt/Le/Test/TestSet/TForLoop），目标是 i + 1
    const REL_JUMP_OPS: &[u8] = &[22, 31, 32, 48, 81, 82, 83, 84]; // Jmp ForLoop ForPrep TForPrep JmpIf JmpIfNot JmpEq JmpNe
    const SKIP_NEXT_OPS: &[u8] = &[23, 24, 25, 26, 27, 33];        // Eq Lt Le Test TestSet TForLoop
    const NO_FALLTHROUGH_OPS: &[u8] = &[29, 30, 85, 86, 87];       // TailCall Return Return0 Return1 Return2
    let mut jump_targets: HashSet<usize> = HashSet::new();
    for (i, (op, _a, b, c)) in raw_insts.iter().enumerate() {
        let real = inverse_opcode_map[*op as usize];
        if REL_JUMP_OPS.contains(&real) {
            let t = i as i64 + 1 + *b as i32 as i64;
            if t >= 0 {
                jump_targets.insert(t as usize);
            }
        }
        if SKIP_NEXT_OPS.contains(&real) {
            jump_targets.insert(i + 1);
        }
        if let Some(vop) = VmOp::from_global(real) {
            if let Some(offset) = vop.branch_offset(*b, *c) {
                let target = i as i64 + 1 + offset as i64;
                if target >= 0 {
                    jump_targets.insert(target as usize);
                }
            }
        }
    }

    // 反混淆判据③续（死指令）：真实指令流末尾（最后一条 RETURN 之后，永不执行）
    // 追加少量死指令，A 域取高于活跃寄存器区的随机值——解码后的 A 集合不再是
    // 「恰好铺满 0..maxstack」的干净区间。dead_count 先于循环抽签（inst_count 写头要用）。
    let dead_min = (decoy_count18 * 2).max(2); // 每个常量诱饵由 PushRk/Drop 两条自定义指令引用并回收栈项
    let dead_max = std::cmp::min(48, 4 + raw_insts.len() / 18).max(dead_min);
    let dead_count: usize = rng.random_range(dead_min..=dead_max);
    // 目标二③（第二部分）：本原型的记录段是 [pb18+1, pb18+inst_count+dead_count]，
    // 游标推到段尾再留一段随机死槽——下一个原型（先序遍历）的基址必落在其后，
    // 所有原型的段在共用空间里互不重叠。
    *alloc18 = pb18
        .wrapping_add(inst_count)
        .wrapping_add(dead_count as u32)
        .wrapping_add(rng.random_range(1..=64u32));
    let inst_total = inst_count + dead_count as u32;
    let inst_cnt_wire = inst_total ^ hn18.rotate_left(11) ^ u_in.rotate_left(7);
    w.extend_from_slice(&inst_cnt_wire.to_le_bytes());
    let kb_p: u32 = kb ^ hn18.rotate_left(3) ^ u_in.rotate_left(7);
    let kc_p: u32 = kc ^ kp18.rotate_left(9) ^ u_in.rotate_left(13);
    let ki1_p: u32 = ki1 ^ pb18.rotate_left(15) ^ hn18.rotate_left(21);
    let ki2_p: u32 = ki2 ^ u_in.rotate_left(17) ^ kp18.rotate_left(25);
    let mut w_roll: u32 = hn18 ^ kp18.rotate_left(7) ^ pb18.rotate_left(13) ^ u_in.rotate_left(19);
    let n_insts = raw_insts.len();
    let mut i = 0usize;
    let mut fused_count = 0usize;
    // 族五专用：冻结窗口内不做族一~族四融合。handler 按「本记录 → 比较记录」的
    // **记录条数**跳转，只有该区间内一条不折叠，写侧算出的 gap 才与运行期一致。
    let mut freeze_until: usize = 0;
    // 已被前面融合吞成死槽的记录：族二的第二个槽是 GETTABLE，族五必须跳过它
    // （否则会把「内建取字段」当成表的取字段再取一遍，写坏目标寄存器）。
    let mut fused_dead: HashSet<usize> = HashSet::new();
    // #3 折叠扫描状态：pc18=已写出指令数（1-based，与 Lua 数组下标一致）；
    // fold_map[li] = Σ f(pc)（对判定为引用本常量槽的指令求和）
    // 按单元（proto）派生独立的常量折叠参数，打破全文件共享同一套 fc18 的杠杆。
    let mut fold_map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut pc18: u32 = 0;
    let f1_p: u32 = fc18.f1 ^ (((hn18 & 0xFFFF) * 2) + 1);
    let f2_p: u32 = fc18.f2 ^ kp18 ^ pb18.rotate_left(9);
    let p1b_p: u32 = fc18.p1b ^ hn18.rotate_left(3);
    let p1c_p: u32 = fc18.p1c ^ kp18.rotate_left(5);
    let fk1_p: u32 = ((fc18.fk1 + (hn18 % 15) * 2) % 30) + 1;
    let fc_f = |pc: u32| -> u32 { pc.wrapping_mul(f1_p) ^ f2_p };
    // 谓词用 xor（32 位域同构，避免 Rust wrapping mod 2^32 与 Lua 直接 %100 不同余）
    let fc_pb = |v: u32| -> bool { (v.rotate_left(fc18.r6b) ^ p1b_p) % 100 < fc18.p3b };
    let fc_pc = |v: u32| -> bool { (v.rotate_left(fc18.r6c) ^ p1c_p) % 100 < fc18.p3c };
    let fold_slot_key = |v: u32| -> u32 { if v > 127 { v - 128 } else { v } };
    // ㉓-A R 链（指令流滚动状态）：roll 初值=0x2545F491^盐；逐记录
    // r7=rotl7(roll)、roll=(r7^文件魔数)+文件A+(预掩码预交换 b/c 异或和) (mod 2^32)。
    // 读侧 body_consts 扫描同式重算（数组 b/c 经 dcb 已是明文=fb0/fc0，含死槽/builtin）。
    // 第 li 槽密钥用「最后一条引用它的指令之后」的 roll（未引用槽用链末值）。
    // ⑤ roll 初值逐构建随机并混入本原型头部盐 hn18
    let mut roll18: u32 = fc18.rs18 ^ enc.salts[group] ^ hn18;
    let mut roll_map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    while i < n_insts {
        let (op, a, b, c) = raw_insts[i];

        // ---- 性能型 SuperOperator：custom ISA 的栈式四指令序列 → 单条寄存器快路径 ----
        // 固定记录数不变：融合 handler 前移 PC 3 格，其余三条仍写成不可达死槽；
        // 因而已有分支位移、共享指令空间与滚动编码链都保持原样。
        if i >= freeze_until
            && i + 3 < n_insts
            && !fused_dead.contains(&i)
            && (i + 1..=i + 3).all(|target| !jump_targets.contains(&target))
        {
            let opcode_at = |offset: usize| {
                let (candidate, _, _, _) = raw_insts[i + offset];
                VmOp::from_global(inverse_opcode_map[candidate as usize])
            };
            let candidate = match opcode_at(0) {
                Some(VmOp::PushRk) => {
                    let (_, first_a, first_b, first_c) = raw_insts[i];
                    let (_, second_a, second_b, second_c) = raw_insts[i + 1];
                    let (_, op_a, op_b, op_c) = raw_insts[i + 2];
                    let (_, dest, pop_b, pop_c) = raw_insts[i + 3];
                    let offset = match opcode_at(2) {
                        Some(VmOp::Add) => Some(0),
                        Some(VmOp::Sub) => Some(1),
                        Some(VmOp::Mul) => Some(2),
                        Some(VmOp::Div) => Some(3),
                        Some(VmOp::Mod) => Some(4),
                        Some(VmOp::Pow) => Some(5),
                        _ => None,
                    };
                    if first_a == 0
                        && first_c == 0
                        && opcode_at(1) == Some(VmOp::PushRk)
                        && second_a == 0
                        && second_c == 0
                        && offset.is_some()
                        && op_a == 0
                        && op_b == 0
                        && op_c == 0
                        && opcode_at(3) == Some(VmOp::PopReg)
                        && pop_b == 0
                        && pop_c == 0
                    {
                        offset.map(|n| (
                            crate::VM::Opcodes::builtins::FUSED_ARITH_BASE + n,
                            dest as u32,
                            remap_rk(first_b),
                            remap_rk(second_b),
                        ))
                    } else {
                        None
                    }
                }
                Some(VmOp::PushReg) => {
                    let (_, table_reg, table_b, table_c) = raw_insts[i];
                    let (_, first_a, first_value, first_rk_c) = raw_insts[i + 1];
                    let (_, second_a, second_b, second_c) = raw_insts[i + 2];
                    let (_, dest, last_b, last_c) = raw_insts[i + 3];
                    if table_b == 0 && table_c == 0
                        && opcode_at(1) == Some(VmOp::PushRk)
                        && first_a == 0 && first_rk_c == 0
                        && opcode_at(2) == Some(VmOp::GetIndex)
                        && second_a == 0 && second_b == 0 && second_c == 0
                        && opcode_at(3) == Some(VmOp::PopReg)
                        && last_b == 0 && last_c == 0
                    {
                        Some((
                            crate::VM::Opcodes::builtins::FUSED_TABLE_GET,
                            dest as u32,
                            table_reg as u32,
                            remap_rk(first_value),
                        ))
                    } else if table_b == 0 && table_c == 0
                        && opcode_at(1) == Some(VmOp::PushRk)
                        && first_a == 0 && first_rk_c == 0
                        && opcode_at(2) == Some(VmOp::PushRk)
                        && second_a == 0 && second_c == 0
                        && opcode_at(3) == Some(VmOp::SetIndex)
                        && dest == 0 && last_b == 0 && last_c == 0
                    {
                        Some((
                            crate::VM::Opcodes::builtins::FUSED_TABLE_SET,
                            table_reg as u32,
                            remap_rk(first_value),
                            remap_rk(second_b),
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some((family, fused_a, fused_b, fused_c)) = candidate {
                if let Some(fused_vals) = fused_map.get(family) {
                    if !fused_vals.is_empty() {
                        let selected_op = fused_vals[rng.random_range(0..fused_vals.len())];
                        let mag = op_magic.get(&selected_op).copied().unwrap_or(selected_op);
                        let a_enc = fused_a.wrapping_add(mag);
                        let (fb0, fc0) = if mag % 2 == 1 {
                            (fused_c, fused_b)
                        } else {
                            (fused_b, fused_c)
                        };
                        let (eo18, ca18, cb18, cc18) = ch_split(chain18);
                        let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
                        emit_inst_wire(
                            w, &mut w_roll, rng, g18, a_enc.wrapping_add(ca18),
                            fb0, cb18, fc0, cc18, hn18, kp18, kb_p, kc_p, ki1_p, ki2_p,
                        );
                        fused_used.insert(family);
                        fused_count += 1;
                        pc18 += 1;
                        let r718 = roll18.rotate_left(7);
                        roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                        chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                        if fc_pb(mag) {
                            fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fb0), pc18, fc_f(pc18), roll18, fk1_p);
                        }
                        if fc_pc(mag) {
                            fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fc0), pc18, fc_f(pc18), roll18, fk1_p);
                        }
                        fused_dead.extend(i + 1..=i + 3);
                        i += 1;
                        continue;
                    }
                }
            }
        }

        // ---- SuperOperator 族三/四：取字段 + 调用（目标二第 2 条）----
        // 族三：SELF(A,B,C) + CALL(A,2,1) —— 零参方法调用（`o:m()` 形态）
        // 族四：GETTABLE(A,B,C) + CALL(A,1,1) —— 零参点调用（`t.f()` 形态）
        // 两者的逻辑布局都一样（B=表、C=键），线上按魔数奇偶预交换（DC 惰性解码器
        // 按同式换回）；与族一/族二共用同一条 CALL 收尾约定（1 返回值、丢弃结果）。
        {
            let real_prev = inverse_opcode_map[op as usize];
            let fam: Option<usize> = if i < freeze_until { None } else if real_prev == 11 && i + 1 < n_insts {
                let (op2, a2, b2, c2) = raw_insts[i + 1];
                if inverse_opcode_map[op2 as usize] == 28 && a2 == a && b2 == 2 && c2 == 1 {
                    Some(crate::VM::Opcodes::builtins::BUILTIN_NAMES.len() * 2)
                } else { None }
            } else if real_prev == 6 && i + 1 < n_insts {
                let (op2, a2, b2, c2) = raw_insts[i + 1];
                if inverse_opcode_map[op2 as usize] == 28 && a2 == a && b2 == 1 && c2 == 1 {
                    Some(crate::VM::Opcodes::builtins::BUILTIN_NAMES.len() * 2 + 1)
                } else { None }
            } else { None };
            let skip_here = if i + 1 >= n_insts { true } else { jump_targets.contains(&(i + 1)) };
            let prev_falls_through = if i == 0 {
                true
            } else {
                let prev_real = inverse_opcode_map[raw_insts[i - 1].0 as usize];
                !SKIP_NEXT_OPS.contains(&prev_real)
                    && !REL_JUMP_OPS.contains(&prev_real)
                    && !NO_FALLTHROUGH_OPS.contains(&prev_real)
            };
            if let Some(fidx) = fam {
                if !skip_here && prev_falls_through {
                    let fused_vals = fused_map.get(fidx).map(|v| v.as_slice()).unwrap_or(&[]);
                    if !fused_vals.is_empty() {
                        let selected_op = fused_vals[rng.random_range(0..fused_vals.len())];
                        let mag = op_magic.get(&selected_op).copied().unwrap_or(selected_op);
                        let a_enc = (a as u32).wrapping_add(mag);
                        let real_op18 = OpCode::from_u8(inverse_opcode_map[op as usize]);
                        let (be18, ce18) = match real_op18 {
                            Some(ro) if ro.mode() == OpMode::IABC => (
                                if ro.b_mode() == OpArgMask::K { remap_rk(b) } else { b },
                                if ro.c_mode() == OpArgMask::K { remap_rk(c) } else { c }),
                            _ => (b, c),
                        };
                        let (fb0, fc0) = if mag % 2 == 1 { (ce18, be18) } else { (be18, ce18) };
                        let (eo18, ca18, cb18, cc18) = ch_split(chain18);
                        let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
                        emit_inst_wire(
                            w, &mut w_roll, rng, g18, a_enc.wrapping_add(ca18),
                            fb0, cb18, fc0, cc18, hn18, kp18, kb_p, kc_p, ki1_p, ki2_p,
                        );
                        fused_used.insert(fidx);
                        fused_count += 1;
                        pc18 += 1;
                        let r718 = roll18.rotate_left(7);
                        roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                        chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                        if fc_pb(mag) { fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fb0), pc18, fc_f(pc18), roll18, fk1_p); }
                        if fc_pc(mag) { fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fc0), pc18, fc_f(pc18), roll18, fk1_p); }
                        fused_dead.insert(i + 1);
                        i += 1; // 被融合的那条 CALL 照常写出，成为永不执行的死槽
                        continue;
                    }
                }
            }
        }
        // ---- SuperOperator 族五：取字段 + 比较（目标二第 2 条）----
        // 形状：GETTABLE(A,B,C) 紧跟 EQ(cond, A, RK_other)，再跟 JMP。序列化器会把基本块
        // 打乱：两者可能紧邻，也可能被别的块隔开、由重排器插入的桥接 JMP 直指比较块。
        // 两种形态都融合，用 gap 记住「比较记录相对本记录的条数」（族五冻结窗口保证该
        // 区间内不再发生别的折叠，条数在写侧与运行期严格一致）。
        // 融合后：A = 打包(dest | RK_other<<8 | cond<<17 | gap<<18)，B = 表寄存器，
        // C = 键 RK；EQ 与其后的 JMP 照旧留在流里——handler 算出 (v==other)~=(cond~=0)，
        // 为真则越过那条 JMP，否则落在它上面照常执行，等价于原来两条指令。
        {
            let real5 = inverse_opcode_map[op as usize];
            if real5 == 6 && i >= freeze_until && !fused_dead.contains(&i) && i + 1 < n_insts {
                // 比较记录位置 j：紧邻（gap=1），或桥接 JMP 直指（gap=j-i）
                let mut cand: Option<(usize, u32)> = None;
                let (op1, _a1, b1, _c1) = raw_insts[i + 1];
                if inverse_opcode_map[op1 as usize] == 23 && !jump_targets.contains(&(i + 1)) && i + 2 < n_insts {
                    cand = Some((i + 1, 1));
                } else if inverse_opcode_map[op1 as usize] == 22 {
                    let t = (i + 2) as i64 + b1 as i32 as i64;
                    if t >= (i + 2) as i64 && t - i as i64 <= 255 && (t as usize) + 1 < n_insts {
                        if inverse_opcode_map[raw_insts[t as usize].0 as usize] == 23 {
                            cand = Some((t as usize, (t - i as i64) as u32));
                        }
                    }
                }
                if let Some((j, gap)) = cand {
                    let (_eq_op, eq_a, eq_b, eq_c) = raw_insts[j];
                    let is_jmp_after = inverse_opcode_map[raw_insts[j + 1].0 as usize] == 22;
                    // EQ 的某一侧必须是本条的 A（否则比较的不是刚取的字段，不能融合）
                    let other_raw = if eq_b == a as u32 { Some(eq_c) } else if eq_c == a as u32 { Some(eq_b) } else { None };
                    let cond = eq_a.min(1) as u32;
                    if is_jmp_after {
                        if let Some(oth_raw) = other_raw {
                            // B 是寄存器域（GETTABLE.b_mode=REG）、C 是 RK：常量域照旧洗牌映射
                            let oth = if oth_raw >= BITRK { remap_rk(oth_raw) } else { oth_raw };
                            let fused_vals = fused_map.get(crate::VM::Opcodes::builtins::BUILTIN_NAMES.len() * 2 + 2)
                                .map(|v| v.as_slice()).unwrap_or(&[]);
                            if !fused_vals.is_empty() {
                                if !fused_vals.is_empty() {
                                    let packed: u32 = (a as u32) | ((oth & 0x1FF) << 8)
                                        | ((cond & 1) << 17) | ((gap & 0xFF) << 18);
                                    let selected_op = fused_vals[rng.random_range(0..fused_vals.len())];
                                    let mag = op_magic.get(&selected_op).copied().unwrap_or(selected_op);
                                    let a_enc = packed.wrapping_add(mag);
                                    let ce18 = remap_rk(c);
                                    let (fb0, fc0) = if mag % 2 == 1 { (ce18, b) } else { (b, ce18) };
                                    let (eo18, ca18, cb18, cc18) = ch_split(chain18);
                                    let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
                                    emit_inst_wire(
                                        w, &mut w_roll, rng, g18, a_enc.wrapping_add(ca18),
                                        fb0, cb18, fc0, cc18, hn18, kp18, kb_p, kc_p, ki1_p, ki2_p,
                                    );
                                    fused_used.insert(crate::VM::Opcodes::builtins::BUILTIN_NAMES.len() * 2 + 2);
                                    fused_count += 1;
                                    pc18 += 1;
                                    let r718 = roll18.rotate_left(7);
                                    roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                                    chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                                    if fc_pb(mag) { fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fb0), pc18, fc_f(pc18), roll18, fk1_p); }
                                    if fc_pc(mag) { fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fc0), pc18, fc_f(pc18), roll18, fk1_p); }
                                    // 冻结到比较 JMP 之后；比较记录本体作为死槽照常写出
                                    freeze_until = (j + 2).max(freeze_until);
                                    fused_dead.insert(j);
                                    i += 1;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }
        // ③ 自定义 ISA 的常量槽重排：只有 PushConst/GetGlobal/SetGlobal 的 B
        // 域是普通常量索引，PushRk 的 B 域是 RK；其他字段属于寄存器、偏移或立即数。
        let canonical = inverse_opcode_map[op as usize];
        let real_op18 = VmOp::from_global(canonical)
            .unwrap_or_else(|| panic!("非自定义 opcode 落入 VM 载荷：{canonical}"));
        let (mut be18, mut ce18) = if real_op18.has_constant_b() {
            (remap_bx(b), c)
        } else if real_op18.has_rk_b() {
            (remap_rk(b), c)
        } else {
            (b, c)
        };
        // ---- 混淆改进方案第 2 项：全四类跳转目标掺入运行时状态量 ----
        // 运行时种子 jseed_p = (kb_p ^ ki1_p) % 0X100000 在 m_insts 解码期间（c.pf_n 抹除前）
        // 写入 kreg[jtbl_key][pb18]；execute 派发环每步按上一条指令实际 PC 转移量
        // (pc - prev_pc) * jmul 推进运行时累加器 jstate。
        let jseed_p: u32 = (kb_p ^ ki1_p) & 0x000F_FFFF;
        let prev_pc: u32 = pb18.wrapping_add(pc18 as u32).wrapping_add(1);
        let jst: u32 = jseed_p.wrapping_add(prev_pc.wrapping_mul(fc18.jmul)) & 0x000F_FFFF;
        let jkey: u32 = jst ^ kp18;

        let mut a_log: u32 = a as u32;
        let mut cj_sel: Option<u32> = None;
        if real_op18 == VmOp::Jump && dead_count > 0 && rng.random_range(0..10) < 7 {
            let fam6 = crate::VM::Opcodes::builtins::BUILTIN_NAMES.len() * 2 + 3;
            let fv = fused_map.get(fam6).map(|v| v.as_slice()).unwrap_or(&[]);
            // 目标记录下标 = 本记录下标(pb18+pc18+1) + 1 + sBx（Jmp 取指后 pc 已自增）
            let t1 = pb18 as i64 + pc18 as i64 + 2 + (b as i32 as i64);
            if !fv.is_empty() && t1 >= pb18 as i64 + 1 && t1 <= pb18 as i64 + inst_count as i64 {
                let t2 = pb18 as i64 + inst_count as i64 + 1 + rng.random_range(0..dead_count) as i64;
                let branch_swap = rng.random_range(0..2u32);
                let salt_raw = rng.random_range(0x1000..0x0F_FFFFu32);
                let salt = (salt_raw & !1u32) | ((jst & 1) ^ branch_swap);
                let k1 = jkey ^ salt;
                let (plain_a, plain_b) = if branch_swap == 0 {
                    (t1 as u32, t2 as u32)
                } else {
                    (t2 as u32, t1 as u32)
                };
                a_log = plain_a ^ k1;
                be18 = plain_b ^ k1;
                ce18 = salt;
                cj_sel = Some(fv[rng.random_range(0..fv.len())]);
                fused_used.insert(fam6);
            }
        }
        if cj_sel.is_none() {
            match real_op18 {
                VmOp::Jump | VmOp::Branch | VmOp::ForInit | VmOp::ForNext => {
                    let t_abs = (pb18 as i64 + pc18 as i64 + 2 + (b as i32 as i64)) as u32;
                    be18 = t_abs ^ jkey;
                }
                VmOp::BranchSetTrue | VmOp::BranchSetFalse | VmOp::IteratorNext => {
                    let t_abs = (pb18 as i64 + pc18 as i64 + 2 + (c as i32 as i64)) as u32;
                    ce18 = t_abs ^ jkey;
                }
                _ => {}
            }
            // 消除未使用操作数恒为 0 的已知明文锚点（如 ReturnNone/Add/Sub/Drop/PopReg 的 0 字段）：
            // 对当前 VmOp 不读取的 (A, B, C) 字段填入伪装寄存器号或常量/RK 槽位，
            // 使其同时混入指令滚动链、w_roll 及 Ftbl/Rtbl 常量引用折叠。
            if !real_op18.uses_field_a() {
                a_log = rng.random_range(1..=126u32);
            }
            if !real_op18.uses_field_b() {
                be18 = if !all_gslots.is_empty() && rng.random_range(0..2u32) == 0 {
                    BITRK + all_gslots[rng.random_range(0..all_gslots.len())]
                } else {
                    rng.random_range(1..=127u32)
                };
            }
            if !real_op18.uses_field_c() {
                ce18 = if !all_gslots.is_empty() && rng.random_range(0..2u32) == 0 {
                    BITRK + all_gslots[rng.random_range(0..all_gslots.len())]
                } else {
                    rng.random_range(1..=127u32)
                };
            }
        }
        let mapped_vals = mapped_opcodes.get(op as usize).map(|v| v.as_slice()).unwrap_or(&[]);
        let selected_op = match cj_sel {
            Some(v) => v,
            None => {
                assert!(!mapped_vals.is_empty(), "自定义 opcode 缺少线上别名");
                mapped_vals[rng.random_range(0..mapped_vals.len())]
            }
        };
        let mag = op_magic.get(&selected_op).copied().unwrap_or(selected_op);
        let a_enc = a_log.wrapping_add(mag);
        let (fb0, fc0) = if mag % 2 == 1 { (ce18, be18) } else { (be18, ce18) };
        let (eo18, ca18, cb18, cc18) = ch_split(chain18);
        let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
        emit_inst_wire(
            w, &mut w_roll, rng, g18, a_enc.wrapping_add(ca18),
            fb0, cb18, fc0, cc18, hn18, kp18, kb_p, kc_p, ki1_p, ki2_p,
        );
        pc18 += 1;
        let r718 = roll18.rotate_left(7);
        roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
        chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
        if fc_pb(mag) { fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fb0), pc18, fc_f(pc18), roll18, fk1_p); }
        if fc_pc(mag) { fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fc0), pc18, fc_f(pc18), roll18, fk1_p); }
        i += 1;
    }

    // 死指令写在真实指令尾部；前 dead_count 条 ADD 的 C 域分别指向混排数字诱饵。
    // 尾段没有任何控制流入边，但写侧/读侧都完整推进指令链、引用折叠与常量 MAC。
    {
        let mut alias_mags: Vec<u32> = Vec::new();
        for lst in mapped_opcodes.iter() {
            if let Some(&v0) = lst.first() {
                alias_mags.push(op_magic.get(&v0).copied().unwrap_or(v0));
            }
        }
        if alias_mags.is_empty() { alias_mags.push(0x0123_4567); }
        let push_rk_wire = inverse_opcode_map
            .iter()
            .position(|&canonical| canonical as usize == VmOp::PushRk.global_id())
            .expect("PushRk 缺少 opcode 映射");
        let drop_wire = inverse_opcode_map
            .iter()
            .position(|&canonical| canonical as usize == VmOp::Drop.global_id())
            .expect("Drop 缺少 opcode 映射");
        let push_rk_alias = mapped_opcodes[push_rk_wire][0];
        let drop_alias = mapped_opcodes[drop_wire][0];
        let lo = (max_stack as u32 + gshift_p as u32 + 1).min(120);
        for dead_idx in 0..dead_count {
            let a_dead = rng.random_range(lo..128u32);
            let (alias, b_dead, c_dead) = if dead_idx < decoy_count18 * 2 {
                if dead_idx % 2 == 0 {
                    // PushRk 的常量直接指向混排后的诱饵槽；下一条 Drop 配对回收。
                    (push_rk_alias, BITRK + decoy_slots[dead_idx / 2], 0)
                } else {
                    (drop_alias, rng.random_range(0..128u32), 0)
                }
            } else {
                (alias_mags[rng.random_range(0..alias_mags.len())],
                 rng.random_range(0..128u32), rng.random_range(0..128u32))
            };
            let mag = op_magic.get(&alias).copied().unwrap_or(alias);
            let a_enc = a_dead.wrapping_add(mag);
            let (fb0, fc0) = if mag % 2 == 1 { (c_dead, b_dead) } else { (b_dead, c_dead) };
            let (eo18, ca18, cb18, cc18) = ch_split(chain18);
            let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
            emit_inst_wire(
                w, &mut w_roll, rng, g18, a_enc.wrapping_add(ca18),
                fb0, cb18, fc0, cc18, hn18, kp18, kb_p, kc_p, ki1_p, ki2_p,
            );
            pc18 += 1;
            let r718 = roll18.rotate_left(7);
            roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
            chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
            if fc_pb(mag) {
                fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fb0), pc18, fc_f(pc18), roll18, fk1_p);
            }
            if fc_pc(mag) {
                fold_step(&mut fold_map, &mut roll_map, fold_slot_key(fc0), pc18, fc_f(pc18), roll18, fk1_p);
            }
        }
    }
    // ⑰ 组字节先行（组=本原型的参数组下标），然后逐条内联密文：
    // 字符串=tag+加密槽号+长度前缀密文；数字=tag+加密槽号+8B 密文。
    // 物理排放顺序 emit_order 与全局槽位 slot 经跨函数混合批次与 Fisher-Yates 独立置换解耦。
    let u_after_insts: u32 = u_in ^ w_roll.rotate_left(9);
    w.push(group as u8);
    let emit_batch = &p_plan.emit_batch;
    let total_const_count = emit_batch.len() as u32;
    let const_cnt_wire: u32 = total_const_count ^ hn18.rotate_left(9) ^ u_after_insts.rotate_left(15);
    w.extend_from_slice(&const_cnt_wire.to_le_bytes());
    let mut emit_order: Vec<usize> = (0..emit_batch.len()).collect();
    for idx in (1..emit_order.len()).rev() {
        let j = rng.random_range(0..=idx);
        emit_order.swap(idx, j);
    }
    // ③ 常量真链式 + 跨单元指令流终态耦合：
    // p_ckey 与 agg18 同时混入本单元指令线上滚动终态 u_after_insts 与指令逻辑终态 roll18，
    // 未完整解码前序单元及本单元全部指令（含每条指令尾部 0..3 个随机滚钥字节）则无法启动常量链。
    let p_ckey: u32 = hn18 ^ kp18.rotate_left(11) ^ pb18.rotate_left(19) ^ roll18.rotate_left(5) ^ u_after_insts.rotate_left(23);
    let mut agg18: u32 = hn18 ^ kp18 ^ pb18.rotate_left(7) ^ roll18.rotate_left(13) ^ u_after_insts.rotate_left(17);
    for (phys_idx, &batch_idx) in emit_order.iter().enumerate() {
        let pos18 = (phys_idx as u32) + 1;
        let entry = &emit_batch[batch_idx];
        let slot = entry.slot;
        let c_type = entry.c_type;
        let bytes = entry.bytes.as_slice();
        let slot_mask = agg18
            ^ kp18.rotate_left((pos18 % 13) + 1)
            ^ pos18.wrapping_mul(fc18.emul);
        let enc_slot = slot ^ slot_mask;
        match c_type {
            0 => {
                w.push(tag_map[0]);
                w.extend_from_slice(&enc_slot.to_le_bytes());
                agg18 = agg18
                    .wrapping_mul(31)
                    .wrapping_add(slot.wrapping_mul(fc18.emul))
                    .wrapping_add(7);
            }
            // bool 也走 8 字节 double 密文管线，线上 tag 与数字结构一致。
            1 | 2 | 3 => {
                let raw_fold = fold_map.get(&slot).copied().unwrap_or(0u32);
                let kf = ((slot.wrapping_mul(fc18.fk2).wrapping_add(hn18 % 29)) % 29) + 1;
                let fold0 = raw_fold.rotate_left(kf);
                let raw_roll = roll_map.get(&slot).copied().unwrap_or(roll18);
                let kr = ((slot.wrapping_mul(fc18.fk3).wrapping_add(kp18 % 29)) % 29) + 1;
                let rl0 = raw_roll.rotate_left(kr);
                let fold = fold0 ^ agg18 ^ p_ckey.rotate_left((slot % 17) + 1);
                let rl18 = rl0 ^ agg18.rotate_left(11) ^ p_ckey.rotate_left((slot % 19) + 1);
                let r7l18 = rl18.rotate_left(7);
                let sl_low = enc.salts[group] & 0xFFFF;
                let kind = if c_type == 3 {
                    if slot % 2 == 0 {
                        enc.kstr[group].wrapping_add(sl_low * 3 + 0x11)
                    } else {
                        enc.kstr[group].wrapping_add(sl_low * 5 + 0x23)
                    }
                } else if slot % 2 == 0 {
                    enc.knum[group].wrapping_add(sl_low * 7 + 0x37)
                } else {
                    enc.knum[group].wrapping_add(sl_low * 11 + 0x4D)
                };
                let s118 = enc.salts[group] ^ rl18 ^ fold;
                let s218 = r7l18 ^ slot.wrapping_mul(6).wrapping_add(kind) ^ fold.rotate_left(13);
                let s318 = enc.salts[group] ^ r7l18.rotate_left(7) ^ fold.rotate_left(5);
                let (plain_for_mac, raw_plain): (Vec<u8>, Vec<u8>) = if c_type == 3 {
                    let v = bytes.to_vec();
                    (v.clone(), v)
                } else {
                    let f64_bytes: [u8; 8] = if c_type == 1 {
                        // 消除 1.0/0.0 全零尾数特征：按正负号编码 true/false，8 字节全部非零
                        let sign: u64 = if bytes[0] != 0 { 0 } else { 1 };
                        let exp: u64 = rng.random_range(0x3FAu64..=0x40Au64);
                        let mut mant: u64 = 0;
                        for sh in (0..48).step_by(8) {
                            mant |= rng.random_range(1u64..=255u64) << sh;
                        }
                        mant |= rng.random_range(1u64..=15u64) << 48;
                        ((sign << 63) | (exp << 52) | mant).to_le_bytes()
                    } else {
                        bytes[0..8].try_into().unwrap()
                    };
                    let bboff = (enc.salts[group] ^ slot ^ fold ^ rl18) & 0xFF;
                    let rp: Vec<u8> = (0..8)
                        .map(|j| {
                            let b0 = f64_bytes[enc.num_bperm[group][j]] as u32;
                            let i = (j as u32) + 1;
                            ((b0 + bboff + i * enc.num_bbstep[group]) & 0xFF) as u8
                        })
                        .collect();
                    (f64_bytes.to_vec(), rp)
                };
                // 消灭可打印性锚点：进入 ChaCha 之前先过每簇 KDF 驱动的逆 S-Box 与级联反馈白化，
                // 使 ChaCha 密文对应的中间字节流均匀分布在 0..255 全域，无 ASCII/UTF-8 可打印偏置。
                let mut acc18: u32 = ((kind & 0xFF)
                    .wrapping_add(slot.wrapping_mul(enc.sbox_smul[group]))
                    .wrapping_add(fold & 0xFF)
                    .wrapping_add(rl18 & 0xFF))
                    & 0xFF;
                let payload18: Vec<u8> = raw_plain
                    .iter()
                    .enumerate()
                    .map(|(j, &plain_b)| {
                        let i = (j as u32) + 1;
                        let raw = ((enc.inv_sbox[group][plain_b as usize] as u32)
                            .wrapping_sub(acc18)
                            .wrapping_sub(i.wrapping_mul(enc.sbox_pmul[group]))
                            & 0xFF) as u8;
                        acc18 = (acc18
                            .wrapping_mul(enc.sbox_cmul[group])
                            .wrapping_add(raw as u32)
                            .wrapping_add(enc.sbox_cadd[group]))
                            & 0xFF;
                        raw
                    })
                    .collect();
                let blob = chacha_xor_layout(&enc.keys[group], [s118, s218, s318], &payload18, &enc.layout[group]);
                w.push(tag_map[c_type as usize]);
                w.extend_from_slice(&enc_slot.to_le_bytes());
                if c_type == 3 { write_string(w, &blob); } else { w.extend_from_slice(&blob); }
                let mac_in = if c_type == 3 { blob.as_slice() } else { plain_for_mac.as_slice() };
                let mac18 = const_mac18(mac_in, slot, fold, rl18, fc18);
                agg18 = agg18.wrapping_mul(31).wrapping_add(mac18).wrapping_add(1);
            }
            _ => panic!(),
        }
    }

    // 跨单元状态推进：当前单元的指令流终态 (u_after_insts, roll18) 与常量明文链终态 agg18
    // 共同折叠更新 u_ctx，直接加密子单元数量 p_count 及后续子单元/兄弟单元的全部头部、指令与常量。
    *u_ctx = u_after_insts.rotate_left(7) ^ roll18.rotate_left(13) ^ agg18 ^ hn18;
    let p_count = r.read_u32();
    let p_cnt_wire: u32 = p_count ^ hn18.rotate_left(15) ^ (*u_ctx).rotate_left(5);
    w.extend_from_slice(&p_cnt_wire.to_le_bytes());
    // 子 proto 直接按序递归写入：线上不带长度、边界标记或可跳过填充。
    // 读侧必须完整解析当前 proto（含其子树）才能抵达下一个兄弟 proto。
    for _ in 0..p_count {
        let g2 = rng.random_range(0..CONST_GROUPS);
        rewrite_chunk(r, w, mapped_opcodes, fused_map, fused_used, inverse_opcode_map, op_magic, enc, g2, rng, kb, kc, ki1, ki2, fc18, tag_map, delta, ch_m, ch_k0, alloc18, u_ctx, rosetta, proto_cursor);
    }

    // 目标五②：末尾行号、局部变量及 upvalue 调试区全部消费后丢弃。
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { let _ = r.read_string(); let _ = r.read_u32(); let _ = r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { let _ = r.read_string(); }
}

/// ④E：**加载器取用不再有标识符**——产物里不出现 `loadstring` / `load` 这两个词，
/// 也不出现 `X or Y` 这种「一眼就是取加载器」的算子对。
///
/// 做法：两个名字（"loadstring"、"load"）登记进统一流，以**数字密文**落盘，
/// 运行期才解回字符串；再从环境表按名字取用。环境表沿用产物他处的同一式
/// `(getfenv and getfenv() or _ENV or _G)`（lua5.1 / luau / Roblox 执行器都适用）。
///
/// 返回 `(前置语句, 变量名)`：语句里落下取自环境表的加载器（取不到就是 nil，
/// 调用点自然失败，与旧式 `loadstring or load` 同为 nil 的行为一致）。
/// `pre` 给定时优先使用该表达式（例如探测结果 `v_pload`），取不到才回落到环境表。
pub fn loader_lookup(
    uni: &mut UniStream, rng: &mut GenRng, pre: Option<&str>, decls: bool,
) -> (String, String) {
    let id_ls = uni.register("loadstring");
    let id_ld = uni.register("load");
    let (st_ls, ex_ls) = uni.fetch(rng, id_ls);
    let (st_ld, ex_ld) = uni.fetch(rng, id_ld);
    // decls=false：变量由调用方在更外层声明（值在运行期才赋）——用于必须保持
    // 「先声明、后定义」顺序的场景（如壳内 f_load 前的 env 变量）
    let (v_ls, v_ld, v_env, v_ldr) = (rng.name(), rng.name(), rng.name(), rng.name());
    let head = if decls {
        format!("local {ls},{ld}; ", ls = v_ls, ld = v_ld)
    } else {
        String::new()
    };
    let pick = match pre {
        Some(p) => format!("{p} or {env}[{ls}] or {env}[{ld}]", p = p, env = v_env, ls = v_ls, ld = v_ld),
        None => format!("{env}[{ls}] or {env}[{ld}]", env = v_env, ls = v_ls, ld = v_ld),
    };
    let stmts = format!(
        "{head}local {env}=(getfenv and getfenv() or _ENV or _G); {s1}{s2}{ls}={e1}; {ld}={e2}; local {ldr}={pick}; ",
        head = head, env = v_env, s1 = st_ls, s2 = st_ld,
        ls = v_ls, ld = v_ld, e1 = ex_ls, e2 = ex_ld, ldr = v_ldr, pick = pick);
    (stmts, v_ldr)
}

/// 生成「只认原生 C 函数」的 loadstring 探测代码（防执行器/沙盒把 loadstring
/// 换成 Lua 钩子）。三个标识符由调用方从各自的命名池里取：
/// `nat` = isNative、`getf` = 取用函数、`pl` = 最终使用的 loadstring 变量。
///
/// 语义：按「当前环境 `loadstring`」→ `getrenv()['loadstring']` → `getrenv()['load']`
/// →「当前环境 `load`」的顺序找**原生**的那一个；一个原生都没有时退回第一个可用的函数。
/// 四个候选全部按**运行期还原的名字**从环境表取用（`loadstring`/`load` 两个标识符
/// 不在产物里出现，名字经统一流以数字密文落盘、运行期才解出）
/// （保证产物在完全没有原生候选的环境里还能跑；要改成「找不到就失败」，
/// 把最后那句 `return alt` 换成 `return nil` 即可）。
///
/// 线性逻辑/数据流同样打乱：定位到原生候选后用改下标的方式跳出循环
/// （而不是 return），末尾再用影子变量返回。
///
/// 注意一（改名器）：这段代码会进 VM 文本、过一遍压缩器的**成员改名器**，
/// 所以 `debug.getinfo` / `info.what` / `info.source` 一律写成**字符串键**，
/// 绝不能写成点访问 —— 改名器只改 `.名字`/`:名字`，字符串键不动；
/// 写点访问会被改成随机名，探测永远走兜底分支、形同虚设。
///
/// 注意二（明文）：字符串键留在产物里本身也是特征（`['getinfo']`、`'=[C]'`
/// 一眼就是「原生函数探测」），所以下面 9 个字符串**全部 XOR 加密**，
/// 以 `"\ddd\ddd…"` 十进制转义字面量出现，运行时用纯算术异或解回来
/// （不依赖 bit32 / bit，标准 Lua 5.1 与 Roblox 都能跑）。
/// 每个串一个独立随机密钥，密钥避开该串里出现过的字节，
/// 保证密文里不会写出 `\000`。只在启动时解 9 个短串，代价可忽略。
pub fn loadstring_probe_lua(
    nat: &str, getf: &str, pl: &str, uni: &mut UniStream, rng: &mut GenRng,
    vault: Option<&mut crate::VM::VM_Backend::Generator_names::NameVault>,
) -> String {
    // ── 要隐藏的字符串（九件套 + 三个类型名）全并入统一流（㉓）──
    const PLAIN: [&str; 9] = [
        "getinfo",    // info 表的键
        "what",       // 判定是否为原生函数
        "C",          // what 的值
        "source",     // 源名
        "=[C]",       // 原生函数的 source 形状
        "getgenv",    // 执行器环境表键
        "getrenv",    // 执行器环境表键
        "loadstring", // 候选名
        "load",       // 候选名
    ];
    // 逐串登记进统一流；取用在各函数体内**惰性**发生：第一次走进才解密，
    // 其后命中缓存直通（共享串第二次解码逻辑上无分支）。密文纯数字，零字面量。
    let mut ids: Vec<usize> = Vec::with_capacity(PLAIN.len() + 3);
    for ptxt in PLAIN.iter() { ids.push(uni.register(ptxt)); }
    let id_s = uni.register("S");
    let id_table = uni.register("table");
    let id_function = uni.register("function");
    let mut exprs: Vec<String> = Vec::new();
    let mut stmts: Vec<String> = Vec::new();
    for &id in ids.iter() {
        let (st, ex) = uni.fetch(rng, id);
        stmts.push(st); exprs.push(ex);
    }
    let (st_s, ex_s) = uni.fetch(rng, id_s);
    let (st_table, ex_table) = uni.fetch(rng, id_table);
    let (st_fn, ex_fn) = uni.fetch(rng, id_function);

    // ㉜ vault 给定时 debug/type/pcall/环境根全部走 NB 槽（None 给 stub_generator）
    let (r_dbg, r_ty, r_pc, r_root) = match vault {
        Some(v) => (
            v.global("debug"),
            v.global("type"),
            v.global("pcall"),
            v.root(),
        ),
        None => (
            "debug".to_string(),
            "type".to_string(),
            "pcall".to_string(),
            "((getfenv and getfenv()) or _G)".to_string(),
        ),
    };
    let v_d = rng.name(); let v_gi = rng.name();
    let v_ok = rng.name(); let v_inf = rng.name();
    // nat：用到 getinfo/what/C/source/=[C]/S/table/function
    let nat_stmts = format!("{}{}{}{}{}{}{}{}",
        stmts[0], stmts[1], stmts[2], stmts[3], stmts[4], st_s, st_table, st_fn);
    let nat_body = format!(
        "local function {nat}({f}) \
            local {d} = {dbg}; {stms} \
            if {ty}({d}) ~= {sc_t} then return true end; \
            local {gi} = {d}[{k1}]; \
            if {ty}({gi}) ~= {sc_f} then return true end; \
            local {ok}, {inf} = {pc}({gi}, {f}, {sc_s}); \
            if not {ok} or {ty}({inf}) ~= {sc_t} then return true end; \
            return {inf}[{k2}] == {k3} and {inf}[{k4}] == {k5}; \
        end; ",
        nat = nat, f = rng.name(), d = v_d, stms = nat_stmts,
        dbg = r_dbg, ty = r_ty, pc = r_pc,
        sc_t = ex_table, sc_f = ex_fn, sc_s = ex_s,
        gi = v_gi, k1 = exprs[0], ok = v_ok, inf = v_inf,
        k2 = exprs[1], k3 = exprs[2], k4 = exprs[3], k5 = exprs[4]);

    // getf：用到 getgenv/getrenv/loadstring/load/function（table/function 命中缓存）
    let (v_g, v_gg, v_ge, v_env2) = (rng.name(), rng.name(), rng.name(), rng.name());
    let (v_list, v_alt, v_i2, v_n2, v_f2, v_t2) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
    let getf_stmts = format!("{}{}{}{}{}{}{}",
        stmts[5], stmts[6], stmts[7], stmts[8], st_fn, st_table, st_s);
    let getf_body = format!(
        "local function {getf}() \
            local {g} = {rt}; {stms} \
            local {gg} = {g}[{k6}]; \
            if {ty}({gg}) == {sc_f} then {g} = {gg}() or {g}; end; \
            local {ge} = {g}[{k7}]; \
            local {env} = {g}; \
            if {ty}({ge}) == {sc_f} then {env} = {ge}() or {g}; end; \
            local {list} = {{ {g}[{k8}], {env}[{k8}], {env}[{k9}], {g}[{k9}] }}; \
            local {alt}, {i} = nil, 0; \
            local {n} = #{list}; \
            while {i} < {n} do \
                {i} = {i} + 1; \
                local {f} = {list}[{i}]; \
                local {t} = {ty}({f}); \
                if {t} == {sc_f} then \
                    if {nat}({f}) and {alt} == nil then {alt} = {f}; {i} = {n}; end; \
                    if {alt} == nil then {alt} = {f}; end; \
                end; \
            end; \
            return {alt}; \
        end; \
        local {pl} = {getf}();\n",
        getf = getf, g = v_g, rt = r_root, ty = r_ty, stms = getf_stmts,
        gg = v_gg, k6 = exprs[5], sc_f = ex_fn, ge = v_ge, k7 = exprs[6],
        env = v_env2, list = v_list, k8 = exprs[7], k9 = exprs[8],
        alt = v_alt, i = v_i2, n = v_n2, f = v_f2, t = v_t2,
        nat = nat, pl = pl);
    format!("{}{}", nat_body, getf_body)
}

#[cfg(test)]
mod sbox_anchor_tests {
    use super::*;

    #[test]
    fn enc_ctx_sbox_is_bijective_and_eliminates_ascii_and_zero_mantissa_anchors() {
        let mut rng = GenRng::new(0x1357_9BDF_2468_ACE0);
        let k0 = [
            0x1234_5678, 0x9ABC_DEF0, 0x1357_2468, 0xCAFE_BABE,
            0xDEAD_BEEF, 0x0F1E_2D3C, 0x4B5A_6978, 0x8796_A5B4,
        ];
        let enc = EncCtx::new(&mut rng, k0);
        for g in 0..CONST_GROUPS {
            let mut seen = [false; 256];
            for x in 0..256 {
                let y = enc.sbox[g][x] as usize;
                seen[y] = true;
                assert_eq!(enc.inv_sbox[g][y] as usize, x);
            }
            assert!(seen.iter().all(|&b| b), "S-Box 必须是 0..255 上的严格双射");

            // 验证可打印字符串 "aaaaaaaaaa" 经逆 S-Box + CFB 级联后全异且含非 ASCII 字节
            let msg = b"aaaaaaaaaa";
            let mut acc = ((enc.kstr[g] & 0xFF) + 3 * enc.sbox_smul[g]) & 0xFF;
            let mut encoded = Vec::with_capacity(msg.len());
            for (j, &plain_b) in msg.iter().enumerate() {
                let i = (j as u32) + 1;
                let raw = ((enc.inv_sbox[g][plain_b as usize] as u32)
                    .wrapping_sub(acc)
                    .wrapping_sub(i.wrapping_mul(enc.sbox_pmul[g]))
                    & 0xFF) as u8;
                acc = (acc
                    .wrapping_mul(enc.sbox_cmul[g])
                    .wrapping_add(raw as u32)
                    .wrapping_add(enc.sbox_cadd[g]))
                    & 0xFF;
                encoded.push(raw);
            }
            let unique_cnt = encoded.iter().copied().collect::<HashSet<u8>>().len();
            assert!(unique_cnt >= 6, "重复可打印字符经 CFB 级联后不得残留重复模式");

            // 验证 0.0 与 1.0 经 8 字节置换与模偏移后不再含连续零字节
            for &val in &[0.0f64, 1.0f64] {
                let f64_bytes = val.to_le_bytes();
                let bboff = (enc.salts[g] ^ 5) & 0xFF;
                let biased: Vec<u8> = (0..8)
                    .map(|j| {
                        let b0 = f64_bytes[enc.num_bperm[g][j]] as u32;
                        let i = (j as u32) + 1;
                        ((b0 + bboff + i * enc.num_bbstep[group_idx_or(g)]) & 0xFF) as u8
                    })
                    .collect();
                let zero_cnt = biased.iter().filter(|&&b| b == 0).count();
                assert!(zero_cnt <= 1, "{val} 的 8 字节偏置表示不得残留全零尾数特征");
            }
        }
    }

    fn group_idx_or(g: usize) -> usize { g }

    #[test]
    fn const_index_decoupling_and_heterogeneous_rotation_roundtrips() {
        let fc = FoldCtx {
            r6b: 5, p1b: 0x1234_5678, p3b: 50,
            r6c: 7, p1c: 0x9ABC_DEF0, p3c: 50,
            f1: 0x1357_9BDF, f2: 0x2468_ACE0,
            m1: 0xCAFE_BABE, m2: 0xDEAD_BEEF, m3: 11, m4: 0x0101_0103, m5: 7,
            rs18: 0x8765_4321,
            fk1: 13, fk2: 19, fk3: 23,
            emul: 0x6B43, eadd: 0x3141_5926,
            jmul: 0x3579, jtbl_key: 0x123456,
            bmul: 5, binv: 13, badd: 19, bsub: ((64 - 19) * 13) % 64, bxor_c: 0x2B,
        };
        let hn18: u32 = 0x5A3C_96E1;
        let kp18: u32 = 0xC3A5_1E69;
        let pb18: u32 = 17;

        // 1. 验证散列键 tk(slot) 在 0..4096 上双射无碰撞，且不等于线性 slot / slot+1
        let mut tk_seen = HashSet::new();
        for slot in 0..4096u32 {
            let tk = slot
                .wrapping_mul(fc.emul)
                .wrapping_add(fc.eadd)
                .wrapping_add(kp18);
            assert!(tk_seen.insert(tk), "散列键 tk(slot) 必须无碰撞");
            assert_ne!(tk, slot);
            assert_ne!(tk, slot + 1);
        }

        // 2. 验证引用折叠 fold_step 与逐槽异构左旋 kf/kr 对相同引用历史的不同槽产生不同 fold0
        let mut fold_map = std::collections::HashMap::new();
        let mut roll_map = std::collections::HashMap::new();
        fold_step(&mut fold_map, &mut roll_map, 2, 10, 0x1111_2222, 0xAAAA_BBBB, fc.fk1);
        fold_step(&mut fold_map, &mut roll_map, 2, 25, 0x3333_4444, 0xCCCC_DDDD, fc.fk1);
        let raw_f = fold_map[&2];
        let kf_slot2 = ((2u32.wrapping_mul(fc.fk2).wrapping_add(hn18 % 29)) % 29) + 1;
        let kf_slot3 = ((3u32.wrapping_mul(fc.fk2).wrapping_add(hn18 % 29)) % 29) + 1;
        assert_ne!(kf_slot2, kf_slot3);
        assert_ne!(raw_f.rotate_left(kf_slot2), raw_f.rotate_left(kf_slot3));

        // 3. 验证乱序物理排放下 enc_slot 链式加解密（含 nil 槽推进 agg18）严格对齐
        let emit_order: Vec<u32> = vec![5, 0, 7, 2, 1, 6, 3, 4];
        let is_nil = [false, true, false, false, true, false, false, false];
        let mut agg_w: u32 = hn18 ^ kp18 ^ pb18.rotate_left(7);
        let mut wire_enc_slots = Vec::new();
        for (phys_idx, &slot) in emit_order.iter().enumerate() {
            let pos18 = (phys_idx as u32) + 1;
            let mask = agg_w ^ kp18.rotate_left((pos18 % 13) + 1) ^ pos18.wrapping_mul(fc.emul);
            wire_enc_slots.push(slot ^ mask);
            if is_nil[slot as usize] {
                agg_w = agg_w.wrapping_mul(31).wrapping_add(slot.wrapping_mul(fc.emul)).wrapping_add(7);
            } else {
                let mac = const_mac18(&[slot as u8; 8], slot, slot.rotate_left(3), 0x1234_5678, &fc);
                agg_w = agg_w.wrapping_mul(31).wrapping_add(mac).wrapping_add(1);
            }
        }
        let mut agg_r: u32 = hn18 ^ kp18 ^ pb18.rotate_left(7);
        let mut decoded_slots = Vec::new();
        for (phys_idx, &enc_s) in wire_enc_slots.iter().enumerate() {
            let i = (phys_idx as u32) + 1;
            let mask = agg_r ^ kp18.rotate_left((i % 13) + 1) ^ i.wrapping_mul(fc.emul);
            let slot = enc_s ^ mask;
            decoded_slots.push(slot);
            if is_nil[slot as usize] {
                agg_r = agg_r.wrapping_mul(31).wrapping_add(slot.wrapping_mul(fc.emul)).wrapping_add(7);
            } else {
                let mac = const_mac18(&[slot as u8; 8], slot, slot.rotate_left(3), 0x1234_5678, &fc);
                agg_r = agg_r.wrapping_mul(31).wrapping_add(mac).wrapping_add(1);
            }
        }
        assert_eq!(decoded_slots, emit_order);
        assert_eq!(agg_r, agg_w);

        // 4. 验证明文反馈入链与按单元 (proto) 独立参数派生：
        // 改动前序常量 1 bit 明文即导致后续所有常量的 enc_slot、fd、rl 及 ChaCha nonce 全盘雪崩；
        // 不同原型的 (hn18, kp18, pb18, roll_final) 派生出完全不同的折叠参数与 p_ckey。
        let rf_a: u32 = 0x7F3A_91C5;
        let rf_b: u32 = 0x4E2B_80D3;
        let pck_a = hn18 ^ kp18.rotate_left(11) ^ pb18.rotate_left(19) ^ rf_a.rotate_left(5);
        let pck_b = (hn18 ^ 0x101) ^ kp18.rotate_left(11) ^ pb18.rotate_left(19) ^ rf_b.rotate_left(5);
        assert_ne!(pck_a, pck_b);

        let f1_pa = fc.f1 ^ (((hn18 & 0xFFFF) * 2) + 1);
        let f1_pb = fc.f1 ^ ((((hn18 ^ 0x100) & 0xFFFF) * 2) + 1);
        assert_ne!(f1_pa, f1_pb);

        let mut agg1 = hn18 ^ kp18 ^ pb18.rotate_left(7) ^ rf_a.rotate_left(13);
        let mut agg2 = agg1;
        let fd_0 = 0x1357_2468 ^ agg1 ^ pck_a.rotate_left((5 % 17) + 1);
        let rl_0 = 0x2468_1357 ^ agg1.rotate_left(11) ^ pck_a.rotate_left((5 % 19) + 1);
        let mac_ok = const_mac18(b"hello_world", 5, fd_0, rl_0, &fc);
        let mac_flip = const_mac18(b"hello_worle", 5, fd_0, rl_0, &fc);
        agg1 = agg1.wrapping_mul(31).wrapping_add(mac_ok).wrapping_add(1);
        agg2 = agg2.wrapping_mul(31).wrapping_add(mac_flip).wrapping_add(1);
        assert_ne!(agg1, agg2, "前序常量 1 bit 明文差异必须使 agg18 雪崩");
        let next_fd1 = 0xAAAA_5555 ^ agg1 ^ pck_a.rotate_left((2 % 17) + 1);
        let next_fd2 = 0xAAAA_5555 ^ agg2 ^ pck_a.rotate_left((2 % 17) + 1);
        let next_rl1 = 0x5555_AAAA ^ agg1.rotate_left(11) ^ pck_a.rotate_left((2 % 19) + 1);
        let next_rl2 = 0x5555_AAAA ^ agg2.rotate_left(11) ^ pck_a.rotate_left((2 % 19) + 1);
        assert_ne!(next_fd1, next_fd2);
        assert_ne!(next_rl1, next_rl2);
    }

    #[test]
    fn cross_unit_coupling_and_rolling_wire_inst_encryption() {
        use rand::SeedableRng;
        let mut rng1 = StdRng::seed_from_u64(0xC0FFEE_1234);
        let mut rng2 = StdRng::seed_from_u64(0xC0FFEE_1234);
        let hn18: u32 = 0x5A3C_96E1;
        let kp18: u32 = 0x01A5_1E69;
        let pb18: u32 = 24;
        let (kb, kc, ki1, ki2) = (0x1122_3344u32, 0x5566_7788u32, 0x99AA_BBCCu32, 0xDDEE_FF00u32);

        // 1. 不同前序单元终态 u_in 派生出完全不同的本单元指令键 (kb_p, kc_p, ki1_p, ki2_p) 与 w_roll，
        // 且同一单元内连续两条相同逻辑指令的线上 4 字 (mag_file, a_wire, fb, fc) 全部不同。
        let u_in_a: u32 = 0x7391_B2C4;
        let u_in_b: u32 = u_in_a ^ 1; // 仅差 1 bit
        let kb_pa = kb ^ hn18.rotate_left(3) ^ u_in_a.rotate_left(7);
        let kb_pb = kb ^ hn18.rotate_left(3) ^ u_in_b.rotate_left(7);
        let kc_pa = kc ^ kp18.rotate_left(9) ^ u_in_a.rotate_left(13);
        let ki1_pa = ki1 ^ pb18.rotate_left(15) ^ hn18.rotate_left(21);
        let ki2_pa = ki2 ^ u_in_a.rotate_left(17) ^ kp18.rotate_left(25);
        assert_ne!(kb_pa, kb_pb);

        let mut wr_a: u32 = hn18 ^ kp18.rotate_left(7) ^ pb18.rotate_left(13) ^ u_in_a.rotate_left(19);
        let wr_init = wr_a;
        let mut w1 = Vec::new();
        let g18: u32 = 0x4567_89AB;
        let a_dec: u32 = 0x0000_0012;
        emit_inst_wire(
            &mut w1, &mut wr_a, &mut rng1, g18, a_dec, 3, 0x1111, 4, 0x2222,
            hn18, kp18, kb_pa, kc_pa, ki1_pa, ki2_pa,
        );
        let len1 = w1.len();
        assert!((16..=19).contains(&len1));
        assert_ne!(wr_a, wr_init, "单条指令发射后 w_roll 必须滚动推进");
        // 高 3 位垃圾字节计数必须与 (g18 ^ kp18) >> 29 一致
        let mag_file_1 = u32::from_le_bytes(w1[0..4].try_into().unwrap());
        assert_eq!((mag_file_1 >> 29) & 3, ((g18 ^ kp18) >> 29) & 3);

        // 紧接着发射完全相同的第二条指令，线上密文四字必须与第一条全部不同（打破 2000:1 同式杠杆）
        emit_inst_wire(
            &mut w1, &mut wr_a, &mut rng1, g18, a_dec, 3, 0x1111, 4, 0x2222,
            hn18, kp18, kb_pa, kc_pa, ki1_pa, ki2_pa,
        );
        assert_ne!(&w1[0..4], &w1[len1..len1 + 4]);
        assert_ne!(&w1[4..8], &w1[len1 + 4..len1 + 8]);
        assert_ne!(&w1[8..12], &w1[len1 + 8..len1 + 12]);
        assert_ne!(&w1[12..16], &w1[len1 + 12..len1 + 16]);

        // 2. 验证父单元 1 bit 差异经 u_after_insts -> agg18 -> u_ctx 传导后，
        // 子单元的头部 (hn_wire, kp_wire, pb_wire) 若用错误父态解掩码则全部失真。
        let mut wr_b: u32 = hn18 ^ kp18.rotate_left(7) ^ pb18.rotate_left(13) ^ u_in_b.rotate_left(19);
        let mut w2 = Vec::new();
        emit_inst_wire(
            &mut w2, &mut wr_b, &mut rng2, g18, a_dec, 3, 0x1111, 4, 0x2222,
            hn18, kp18, kb_pb, kc_pa ^ 8, ki1_pa, ki2_pa ^ 16,
        );
        let u_after_a = u_in_a ^ wr_a.rotate_left(9);
        let u_after_b = u_in_b ^ wr_b.rotate_left(9);
        assert_ne!(u_after_a, u_after_b);

        let roll_fin: u32 = 0x89AB_CDEF;
        let agg_a: u32 = hn18 ^ kp18 ^ pb18.rotate_left(7) ^ roll_fin.rotate_left(13) ^ u_after_a.rotate_left(17);
        let agg_b: u32 = hn18 ^ kp18 ^ pb18.rotate_left(7) ^ roll_fin.rotate_left(13) ^ u_after_b.rotate_left(17);
        let u_out_a = u_after_a.rotate_left(7) ^ roll_fin.rotate_left(13) ^ agg_a ^ hn18;
        let u_out_b = u_after_b.rotate_left(7) ^ roll_fin.rotate_left(13) ^ agg_b ^ hn18;
        assert_ne!(u_out_a, u_out_b);

        // 子单元真实头部
        let (child_hn, child_kp, child_pb) = (0x3141_5926u32, 0x0171_8281u32, 128u32);
        let hn_wire = child_hn ^ u_out_a;
        let kp_wire = child_kp ^ child_hn.rotate_left(5) ^ u_out_a.rotate_left(11);
        let pb_wire = child_pb ^ child_hn.rotate_left(13) ^ u_out_a.rotate_left(19);
        // 正确父态还原
        let dec_hn = hn_wire ^ u_out_a;
        let dec_kp = kp_wire ^ dec_hn.rotate_left(5) ^ u_out_a.rotate_left(11);
        let dec_pb = pb_wire ^ dec_hn.rotate_left(13) ^ u_out_a.rotate_left(19);
        assert_eq!((dec_hn, dec_kp, dec_pb), (child_hn, child_kp, child_pb));
        // 错误父态还原全部失真
        let bad_hn = hn_wire ^ u_out_b;
        let bad_kp = kp_wire ^ bad_hn.rotate_left(5) ^ u_out_b.rotate_left(11);
        let bad_pb = pb_wire ^ bad_hn.rotate_left(13) ^ u_out_b.rotate_left(19);
        assert_ne!(bad_hn, child_hn);
        assert_ne!(bad_kp, child_kp);
        assert_ne!(bad_pb, child_pb);
    }

    #[test]
    fn runtime_jump_state_breaks_static_cfg_on_all_four_jump_categories() {
        let jmul: u32 = 0x3579;
        let kp18: u32 = 0x01C3_A569; // in [0x0100_0000, 0x0300_0000)
        let pb18: u32 = 40;
        let jseed_a: u32 = 0x0A53C;
        let jseed_b: u32 = 0x0A53D; // 1-bit difference in u_in / hn18 changes jseed_p

        // 模拟正向跳转 + 负向回跳汇合到同一 PC (pc = 58)
        let entry_pc: i64 = pb18 as i64 + 1;
        let mut jstate_lua: i64 = (jseed_a as i64 + entry_pc * jmul as i64).rem_euclid(0x100000);
        // 路径 1：41 -> 65 -> 58（含负向回跳 delta = -7）
        for &(from, to) in &[(41i64, 65i64), (65, 58)] {
            jstate_lua = (jstate_lua + (to - from) * jmul as i64).rem_euclid(0x100000);
        }
        let jst_rust: u32 = jseed_a.wrapping_add((58u32).wrapping_mul(jmul)) & 0x000F_FFFF;
        assert_eq!(jstate_lua as u32, jst_rust);

        let jkey_a = jst_rust ^ kp18;
        let jkey_b = (jseed_b.wrapping_add((58u32).wrapping_mul(jmul)) & 0x000F_FFFF) ^ kp18;
        assert_ne!(jkey_a, jkey_b);

        // 验证加密后跳转目标落在 [0x0100_0000, 0x03FF_FFFF]（不触发符号扩展且不碰撞常量槽）
        for &t_abs in &[42u32, 77u32, 105u32] {
            let enc = t_abs ^ jkey_a;
            assert!((0x0100_0000..=0x03FF_FFFF).contains(&enc));
            assert_eq!(enc ^ jkey_a, t_abs);
            assert_ne!(enc ^ jkey_b, t_abs);
        }

        // 验证第 3 项：内置表 bv 写侧逆仿射(binv,bsub) + kreg 种子 与 读侧运行期计数器 + 正仿射(bmul,badd) 非对称往返
        let (bmul, binv, badd, bxor_c) = (5u32, 13u32, 19u32, 0x2Bu32);
        let bsub = ((64 - badd) * binv) % 64;
        let w_mask = (jseed_a % 64) ^ bxor_c;
        let mut bv = [0u32; 64];
        for p in 0..64u32 {
            let src_idx = (((p * binv + bsub) % 64) ^ w_mask) as usize;
            bv[p as usize] = 1000 + src_idx as u32;
        }
        let kstep = (64 - (jmul % 64)) % 64;
        let rt_bmask = ((jst_rust + kstep * 58) % 64) ^ bxor_c;
        assert_eq!(rt_bmask, w_mask);
        for op_b in 0..64u32 {
            let read_idx = (((op_b ^ rt_bmask) * bmul + badd) % 64) as usize;
            assert_eq!(bv[read_idx], 1000 + op_b);
        }
    }
}



