//! Generator 的载荷读写、字节码重写与加载器探测工具层。
//! 从 Generator_util.rs 拆出（守单文件 80 KB 上限，保持两文件各约 40 KB）。
use std::collections::HashSet;
use rand::{Rng, rngs::StdRng};
use crate::compiler::instructions::{OpArgMask, OpCode, OpMode};
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
    /// 第 3 项 D：单根 K0（8 字）——四组与 boot 的密钥/盐/kind 全部由它 KDF 现算；
    /// 它本身取自原生流（Native Stream），产物里以 token 掩码形态落一份
    pub root: [u32; 8],
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

pub(super) fn scan_setglobal_targets(r: &mut PayloadReader, targets: &mut HashSet<Vec<u8>>, setglobal_op: u8) {
    r.read_string();
    r.read_u32(); r.read_u32();
    r.read_u8(); r.read_u8(); r.read_u8(); r.read_u8();
    let inst_count = r.read_u32();
    let mut raw_insts: Vec<(u8, u8, u32, u32)> = Vec::with_capacity(inst_count as usize);
    for _ in 0..inst_count {
        let op = r.read_u8(); let a = r.read_u8(); let b = r.read_u32(); let c = r.read_u32();
        raw_insts.push((op, a, b, c));
    }
    let const_count = r.read_u32();
    let mut local_consts: Vec<Option<Vec<u8>>> = Vec::with_capacity(const_count as usize);
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => local_consts.push(None),
            1 => { r.read_u8(); local_consts.push(None); }
            2 => { r.read_u64(); local_consts.push(None); }
            3 => { local_consts.push(Some(r.read_string().to_vec())); }
            _ => panic!(),
        }
    }
    for (op, _a, b, _c) in &raw_insts {
        if *op == setglobal_op {
            if let Some(Some(s)) = local_consts.get(*b as usize) {
                targets.insert(s.clone());
            }
        }
    }
    let p_count = r.read_u32();
    for _ in 0..p_count { scan_setglobal_targets(r, targets, setglobal_op); }
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { r.read_string(); r.read_u32(); r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { r.read_string(); }
}

// 反混淆判据②修复：每条线上指令尾部挂 0..3 个随机垃圾字节，数量编码在线上魔数
// 高 2 位（mag 取值 0x0100_0000..0x7FFF_0000，kp18 ≤ 0x02FF_FFFF 不碰高位，
// 所以 (mag^kp18)>>29 与 mag>>29 一致，读写两侧同式）。「每条恰好 16B、
// N 条 ×16 精确对齐」的游标特征消失；垃圾字节随滚动密钥流一起加密。
fn inst_junk(w: &mut Vec<u8>, mag_file: u32, rng: &mut StdRng) {
    let jn = (mag_file >> 29) & 3;
    for _ in 0..jn { w.push(rng.random_range(0..256u32) as u8); }
}

pub(super) fn rewrite_chunk(r: &mut PayloadReader, w: &mut Vec<u8>, mapped_opcodes: &[Vec<u32>; 90], builtin_map: &[Vec<u32>], fused_map: &[Vec<u32>; crate::VM::Opcodes::builtins::FUSED_OP_COUNT], fused_used: &mut HashSet<usize>, setglobal_targets: &HashSet<Vec<u8>>, getglobal_op: u8, getglobalstr_op: u8, inverse_opcode_map: &[u8; 90], slot_perm: &[usize], op_magic: &std::collections::HashMap<u32, u32>, enc: &EncCtx, group: usize, rng: &mut StdRng, kb: u32, kc: u32, ki1: u32, ki2: u32, fc18: &FoldCtx, tag_map: &[u8; 4], delta: u32, ch_m: u64, ch_k0: u64) -> Vec<(usize, u32)> {
    // ② 元数据剥离：chunk 名/lines/locals/upvalue 名在 VM 端零消费者
    // （错误消息=宿主真 Lua 原生报错，行守卫针式=恒 :2: 物理行）——读流保同步、
    // 落盘写空/零：反编译器失去变量命名、行号映射与源文件路径
    // ⑱.3 每原型随机参数：kp18=本原型线上 op 异或键（二级重映射，跨原型同全局码
    // 线上值不同）、pb18=pc↔槽仿射偏移（槽=pc+pb，随机死槽；所有 pc 运算皆相对=零模板改动）。
    // 两值写入 ② 剥离后的 linedefined/numparams 两空槽（随机数，无源信息）。
    let kp18: u32 = rng.random_range(1..0x2000000u32) | 0x0100_0000;
    let pb18: u32 = rng.random_range(4..=64u32);
    // ㉚ 链式编码状态：种子=(kp18^pb18)*ch_m+ch_k0（与 Lua 扫描/解码器同式）；
    // 每条指令发射前取 (EO,CA,CB,CC)，发射后用本条逻辑值推进——单条公式全解作废
    let nochain18 = std::env::var("OBF_NOCHAIN").is_ok();
    let mut chain18: u64 = (((kp18 ^ pb18) as u64).wrapping_mul(ch_m).wrapping_add(ch_k0)) % 0x1_0000_0000;
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
    let _ = r.read_string(); write_string(w, b"");
    let _ = r.read_u32(); let _ = r.read_u32();
    w.extend_from_slice(&kp18.to_le_bytes()); w.extend_from_slice(&pb18.to_le_bytes());
    w.push(r.read_u8()); w.push(r.read_u8()); w.push(r.read_u8());
    let max_stack = r.read_u8();
    // Per-Proto 偏移受 max_stack 约束，确保寄存器仍落在 RK 的 7-bit 域。
    let gshift_p: u8 = if max_stack < 127 {
        let cap = (127u8 - max_stack).min(48);
        rng.random_range(1u8..=cap.max(1))
    } else { 0 };
    // 该字段运行期不用于分配，复用作偏移元数据；字段名由生成器随机化。
    w.push(gshift_p);
    let inst_count = r.read_u32();
    let mut raw_insts: Vec<(u8, u8, u32, u32)> = Vec::with_capacity(inst_count as usize);
    for _ in 0..inst_count {
        let op = r.read_u8(); let a = r.read_u8(); let b = r.read_u32(); let c = r.read_u32();
        raw_insts.push((op, a, b, c));
    }
    let const_count = r.read_u32();
    let mut local_consts: Vec<(u8, Vec<u8>)> = Vec::with_capacity(const_count as usize);
    for _ in 0..const_count {
        let c_type = r.read_u8();
        match c_type {
            0 => local_consts.push((0, Vec::new())),
            1 => { let b = r.read_u8(); local_consts.push((1, vec![b])); }
            2 => { let n = r.read_u64(); local_consts.push((2, n.to_le_bytes().to_vec())); }
            3 => { let s = r.read_string().to_vec(); local_consts.push((3, s)); }
            _ => panic!(),
        }
    }

    const BITRK: u32 = 128;
    // Per-Proto 独立平移。A 恒为寄存器；IABC 的 B/C 按操作码模式表平移。
    if gshift_p != 0 {
        for (op, a, b, c) in raw_insts.iter_mut() {
            let real_op = OpCode::from_u8(inverse_opcode_map[*op as usize]);
            // Eq/Lt/Le 的 A 域是「期望比较结果」旗标（0/1），不是寄存器——不平移
            // （模板：if (rk_b == rk_c) ~= (inst_A ~= 0) then pc+=1）
            let a_is_flag = matches!(real_op, Some(OpCode::Eq) | Some(OpCode::Lt) | Some(OpCode::Le));
            if !a_is_flag {
                *a = (*a as u32 + gshift_p as u32) as u8;
            }
            if let Some(real_op) = real_op {
                if real_op.mode() == OpMode::IABC {
                    match real_op.b_mode() {
                        OpArgMask::R => *b += gshift_p as u32,
                        OpArgMask::K => if *b < BITRK { *b += gshift_p as u32; },
                        _ => {}
                    }
                    match real_op.c_mode() {
                        OpArgMask::R => *c += gshift_p as u32,
                        OpArgMask::K => if *c < BITRK { *c += gshift_p as u32; },
                        _ => {}
                    }
                }
            }
        }
    }
    let mut referenced_elsewhere: HashSet<usize> = HashSet::new();
    for (op, _a, b, c) in &raw_insts {
        if *op == getglobal_op || *op == getglobalstr_op { continue; }
        if let Some(real_op) = OpCode::from_u8(inverse_opcode_map[*op as usize]) {
            let is_bx = matches!(real_op.mode(), OpMode::IABx);
            if is_bx {
                if real_op.b_mode() == OpArgMask::K && (*b as usize) < local_consts.len() {
                    referenced_elsewhere.insert(*b as usize);
                }
            } else {
                if real_op.b_mode() == OpArgMask::K && *b >= BITRK {
                    referenced_elsewhere.insert((*b - BITRK) as usize);
                }
                if real_op.c_mode() == OpArgMask::K && *c >= BITRK {
                    referenced_elsewhere.insert((*c - BITRK) as usize);
                }
            }
        }
    }

    let mut builtin_rewrite: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut omit_const: HashSet<usize> = HashSet::new();
    for (idx, (ctype, bytes)) in local_consts.iter().enumerate() {
        if *ctype == 3 {
            if let Some(slot) = crate::VM::Opcodes::builtins::BUILTIN_NAMES.iter().position(|n| n.as_bytes() == bytes.as_slice()) {
                if !setglobal_targets.contains(bytes) {
                    builtin_rewrite.insert(idx, slot);
                    if !referenced_elsewhere.contains(&idx) {
                        omit_const.insert(idx);
                    }
                }
            }
        }
    }

    // ③ 槽位 PRP 洗牌：常量的落盘槽位过一遍随机置换——落盘常量表第 s 槽
    // 放原常量 inv[s]，指令侧 RK/IABx-K 引用同步重映射为 perm[idx]。读侧
    // 一切（折叠扫描、R 链、解密 nonce、建表）都以「线上操作数值/落盘槽号」
    // 为准逐式重放，与写侧对同一置换对称——读侧零改动。
    let mut cperm: Vec<u32> = (0..const_count).collect();
    for pi in (1..cperm.len()).rev() {
        let pj = rng.random_range(0..=pi);
        cperm.swap(pi, pj);
    }
    let remap_rk = |v: u32| -> u32 {
        if v >= BITRK && (v - BITRK) < const_count { BITRK + cperm[(v - BITRK) as usize] } else { v }
    };
    let remap_bx = |v: u32| -> u32 { if v < const_count { cperm[v as usize] } else { v } };

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
    for (i, (op, _a, b, _c)) in raw_insts.iter().enumerate() {
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
    }

    // 反混淆判据③续（死指令）：真实指令流末尾（最后一条 RETURN 之后，永不执行）
    // 追加少量死指令，A 域取高于活跃寄存器区的随机值——解码后的 A 集合不再是
    // 「恰好铺满 0..maxstack」的干净区间。dead_count 先于循环抽签（inst_count 写头要用）。
    let dead_count: usize = rng.random_range(2..=std::cmp::min(24, 4 + raw_insts.len() / 18).max(4));
    w.extend_from_slice(&(inst_count + dead_count as u32).to_le_bytes());
    let n_insts = raw_insts.len();
    let mut i = 0usize;
    let mut fused_count = 0usize;
    // #3 折叠扫描状态：pc18=已写出指令数（1-based，与 Lua 数组下标一致）；
    // fold_map[li] = Σ f(pc)（对判定为引用本常量槽的指令求和）
    let mut fold_map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut pc18: u32 = 0;
    let fc_f = |pc: u32| -> u32 { pc.wrapping_mul(fc18.f1) ^ fc18.f2 };
    // 谓词用 xor（32 位域同构，避免 Rust wrapping mod 2^32 与 Lua 直接 %100 不同余）
    let fc_pb = |v: u32| -> bool { (v.rotate_left(fc18.r6b) ^ fc18.p1b) % 100 < fc18.p3b };
    let fc_pc = |v: u32| -> bool { (v.rotate_left(fc18.r6c) ^ fc18.p1c) % 100 < fc18.p3c };
    // ㉓-A R 链（指令流滚动状态）：roll 初值=0x2545F491^盐；逐记录
    // r7=rotl7(roll)、roll=(r7^文件魔数)+文件A+(预掩码预交换 b/c 异或和) (mod 2^32)。
    // 读侧 body_consts 扫描同式重算（数组 b/c 经 dcb 已是明文=fb0/fc0，含死槽/builtin）。
    // 第 li 槽密钥用「最后一条引用它的指令之后」的 roll（未引用槽用链末值）。
    // ⑤ roll 初值逐构建随机（原 0x2545F491 是可识别算法指纹常量）
    let mut roll18: u32 = fc18.rs18 ^ enc.salts[group];
    let mut roll_map: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    while i < n_insts {
        let (op, a, b, c) = raw_insts[i];

        // ---- SuperOperator: builtin-load + LoadK + Call(B=2, C=1) -> 1 条 ----
        if (op == getglobal_op || op == getglobalstr_op)
            && i + 1 < n_insts
            && !jump_targets.contains(&(i + 1))
        {
            // i == 0 是函数入口，没有前驱指令，控制流只能从这里开始，天然安全；
            // i > 0 则要求前一条指令一定会顺序落入本条（不会跳走、不会跳过本条）。
            let prev_falls_through = if i == 0 {
                true
            } else {
                let prev_real = inverse_opcode_map[raw_insts[i - 1].0 as usize];
                !SKIP_NEXT_OPS.contains(&prev_real)
                    && !REL_JUMP_OPS.contains(&prev_real)
                    && !NO_FALLTHROUGH_OPS.contains(&prev_real)
            };
            if prev_falls_through {
                if let Some(&slot) = builtin_rewrite.get(&(b as usize)) {
                    // 族二：builtin-load + GETTABLE(A_dst, B=builtin寄存器, C=RK)。
                    let (op2, a2, b2, c2) = raw_insts[i + 1];
                    let fslot2 = crate::VM::Opcodes::builtins::BUILTIN_NAMES.len() + slot_perm[slot];
                    if inverse_opcode_map[op2 as usize] == 6 && b2 == a as u32 {
                        let key_alive = c2 < BITRK || !omit_const.contains(&((c2 - BITRK) as usize));
                        let fused_vals = fused_map.get(fslot2).map(|v| v.as_slice()).unwrap_or(&[]);
                        if key_alive && !fused_vals.is_empty() {
                            let selected_op = fused_vals[rng.random_range(0..fused_vals.len())];
                            let mag = op_magic.get(&selected_op).copied().unwrap_or(selected_op);
                            let a_enc = (a2 as u32).wrapping_add(mag);
                            let key = remap_rk(c2);
                            let slot_value = slot_perm[slot] as u32;
                            // Handler 的逻辑 B=槽号、逻辑 C=表键；奇数魔数在写侧预交换。
                            let (fb0, fc0) = if mag % 2 == 1 { (key, slot_value) } else { (slot_value, key) };
                            let (eo18, ca18, cb18, cc18) = ch_split(chain18);
                            let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
                            let (fb, fc) = ((fb0 ^ cb18) ^ (g18 ^ ki1) ^ kb, (fc0 ^ cc18) ^ (g18 ^ ki2) ^ kc);
                            let mag_file = g18 ^ kp18;
                            w.extend_from_slice(&mag_file.to_le_bytes());
                            w.extend_from_slice(&a_enc.wrapping_add(ca18).to_le_bytes());
                            w.extend_from_slice(&fb.to_le_bytes());
                            w.extend_from_slice(&fc.to_le_bytes());
                            inst_junk(w, mag_file, rng);
                            fused_used.insert(fslot2);
                            fused_count += 1;
                            pc18 += 1;
                            let r718 = roll18.rotate_left(7);
                            roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                            chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                            if fb0 > 127 && fc_pb(mag) { let e = fold_map.entry(fb0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fb0 - 128).or_insert(0u32); *e2 = roll18; }
                            if fc0 > 127 && fc_pc(mag) { let e = fold_map.entry(fc0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fc0 - 128).or_insert(0u32); *e2 = roll18; }
                            i += 1;
                            continue;
                        }
                    }
                    if i + 2 < n_insts && !jump_targets.contains(&(i + 2)) {
                    let (op1, a1, b1, _c1) = raw_insts[i + 1];
                    let (op2, a2, b2, c2) = raw_insts[i + 2];
                    let is_loadk = inverse_opcode_map[op1 as usize] == 1 && a1 as u32 == a as u32 + 1;
                    let is_call_1arg_0ret =
                        inverse_opcode_map[op2 as usize] == 28 && a2 == a && b2 == 2 && c2 == 1;
                    // 常量必须没被 omit_const 抹掉，否则 CONSTS[b1+1] 会取错
                    let const_alive = !omit_const.contains(&(b1 as usize));
                    if is_loadk && is_call_1arg_0ret && const_alive {
                        // 必须和 builtin-load 一样过 slot_perm：handler 是按
                        // fused_map[perm[名字下标]] 注册的，指令侧要用同一个下标。
                        let fused_vals = fused_map.get(slot_perm[slot]).map(|v| v.as_slice()).unwrap_or(&[]);
                        if !fused_vals.is_empty() {
                            let selected_op = fused_vals[rng.random_range(0..fused_vals.len())];
                            // ⑮ 线格式：op=魔数、A=(a+魔数) u32、(B,C) 按魔数奇偶预交换
                            let mag = op_magic.get(&selected_op).copied().unwrap_or(selected_op);
                            let a_enc = (a as u32).wrapping_add(mag);
                            let b1e = remap_bx(b1); // ③ 槽位洗牌：常量下标同步置换
                            let slot_value = slot_perm[slot] as u32;
                            // Handler 的逻辑 B=槽号、逻辑 C=常量索引；奇数魔数在写侧预交换。
                            let (fb0, fc0) = if mag % 2 == 1 { (b1e, slot_value) } else { (slot_value, b1e) };
                            let (eo18, ca18, cb18, cc18) = ch_split(chain18);
                            let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
                            let (fb, fc) = ((fb0 ^ cb18) ^ (g18 ^ ki1) ^ kb, (fc0 ^ cc18) ^ (g18 ^ ki2) ^ kc);
                            let mag_file = g18 ^ kp18;
                            w.extend_from_slice(&mag_file.to_le_bytes());
                            w.extend_from_slice(&a_enc.wrapping_add(ca18).to_le_bytes());
                            w.extend_from_slice(&fb.to_le_bytes());
                            w.extend_from_slice(&fc.to_le_bytes()); // 常量下标搬进 C
                            inst_junk(w, mag_file, rng);
                            fused_used.insert(slot_perm[slot]);
                            fused_count += 1;
                            pc18 += 1;
                            let r718 = roll18.rotate_left(7);
                            roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                            chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                            if fb0 > 127 && fc_pb(mag) { let e = fold_map.entry(fb0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fb0 - 128).or_insert(0u32); *e2 = roll18; }
                            if fc0 > 127 && fc_pc(mag) { let e = fold_map.entry(fc0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fc0 - 128).or_insert(0u32); *e2 = roll18; }
                            i += 1; // i+1 / i+2 照常写出，成为永不执行的死槽
                            continue;
                        }
                    }
                    }
                }
            }
        }

        if op == getglobal_op || op == getglobalstr_op {
            if let Some(slot) = builtin_rewrite.get(&(b as usize)) {
                let op_index = crate::VM::Opcodes::builtins::BUILTIN_OP_BASE + slot_perm[*slot];
                let mapped_vals = builtin_map.get(op_index).map(|v| v.as_slice()).unwrap_or(&[]);
                let selected_op = if !mapped_vals.is_empty() { mapped_vals[rng.random_range(0..mapped_vals.len())] } else { op_index as u32 };
                let mag = op_magic.get(&selected_op).copied().unwrap_or(selected_op);
                let a_enc = (a as u32).wrapping_add(mag);
                let (eo18, ca18, cb18, cc18) = ch_split(chain18);
                let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
                let mag_file = g18 ^ kp18;
                w.extend_from_slice(&mag_file.to_le_bytes()); w.extend_from_slice(&a_enc.wrapping_add(ca18).to_le_bytes());
                let slot_value = slot_perm[*slot] as u32;
                let (fb0, fc0) = if mag % 2 == 1 { (0u32, slot_value) } else { (slot_value, 0u32) };
                w.extend_from_slice(&(((fb0 ^ cb18) ^ (g18 ^ ki1)) ^ kb).to_le_bytes()); w.extend_from_slice(&(((fc0 ^ cc18) ^ (g18 ^ ki2)) ^ kc).to_le_bytes());
                inst_junk(w, mag_file, rng);
                pc18 += 1; // 槽号 <128，不会被常量折叠扫描识别
                let r718 = roll18.rotate_left(7);
                roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                i += 1;
                continue;
            }
        }
        let mapped_vals = mapped_opcodes.get(op as usize).map(|v| v.as_slice()).unwrap_or(&[]);
        let selected_op = if !mapped_vals.is_empty() { mapped_vals[rng.random_range(0..mapped_vals.len())] } else { op as u32 };
        let mag = op_magic.get(&selected_op).copied().unwrap_or(selected_op);
        let a_enc = (a as u32).wrapping_add(mag);
        // ③ 槽位洗牌：K 域操作数按模式重映射（RK→perm，IABx-K→perm）；
        // 寄存器/跳转域不动
        let real_op18 = OpCode::from_u8(inverse_opcode_map[op as usize]);
        let (be18, ce18) = match real_op18 {
            Some(ro) if ro.mode() == OpMode::IABC => (
                if ro.b_mode() == OpArgMask::K { remap_rk(b) } else { b },
                if ro.c_mode() == OpArgMask::K { remap_rk(c) } else { c }),
            Some(ro) if ro.mode() == OpMode::IABx && ro.b_mode() == OpArgMask::K => (remap_bx(b), c),
            _ => (b, c),
        };
        let (fb0, fc0) = if mag % 2 == 1 { (ce18, be18) } else { (be18, ce18) };
        let (eo18, ca18, cb18, cc18) = ch_split(chain18);
        let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
        let (fb, fc) = ((fb0 ^ cb18) ^ (g18 ^ ki1) ^ kb, (fc0 ^ cc18) ^ (g18 ^ ki2) ^ kc);
        let mag_file = g18 ^ kp18;
        w.extend_from_slice(&mag_file.to_le_bytes()); w.extend_from_slice(&a_enc.wrapping_add(ca18).to_le_bytes()); w.extend_from_slice(&fb.to_le_bytes()); w.extend_from_slice(&fc.to_le_bytes());
        inst_junk(w, mag_file, rng);
        pc18 += 1;
        let r718 = roll18.rotate_left(7);
        roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
        chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
        if fb0 > 127 && fc_pb(mag) { let e = fold_map.entry(fb0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fb0 - 128).or_insert(0u32); *e2 = roll18; }
        if fc0 > 127 && fc_pc(mag) { let e = fold_map.entry(fc0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fc0 - 128).or_insert(0u32); *e2 = roll18; }
        i += 1;
    }

    // 反混淆判据③续：死指令本体。排在真实指令流之后（最后一条 RETURN 之后，
    // 任何跳转目标都 ≤ 原指令数，控制流不可能进入）；魔数取自本表真实别名，
    // A 域取高于活跃寄存器区的随机值（<128，不碰 RK 常量域），B/C 取 <128 的
    // 寄存器态值（解码后 <128 ⇒ 永不被折叠扫描当成常量引用）。R 链照常推进
    // （读侧 body_consts 扫描会重放全部数组项，含死指令），折叠表不受污染。
    {
        let mut alias_mags: Vec<u32> = Vec::new();
        for lst in mapped_opcodes.iter() {
            if let Some(&v0) = lst.first() {
                alias_mags.push(op_magic.get(&v0).copied().unwrap_or(v0));
            }
        }
        if alias_mags.is_empty() { alias_mags.push(0x0123_4567); }
        let lo = (max_stack as u32 + gshift_p as u32 + 1).min(120);
        for _ in 0..dead_count {
            let mag = alias_mags[rng.random_range(0..alias_mags.len())];
            let a_dead = rng.random_range(lo..128u32);
            let b_dead = rng.random_range(0..128u32);
            let c_dead = rng.random_range(0..128u32);
            let a_enc = a_dead.wrapping_add(mag);
            let (fb0, fc0) = if mag % 2 == 1 { (c_dead, b_dead) } else { (b_dead, c_dead) };
            let (eo18, ca18, cb18, cc18) = ch_split(chain18);
            let g18 = mag.wrapping_add(eo18).wrapping_add(delta);
            let (fb, fc) = ((fb0 ^ cb18) ^ (g18 ^ ki1) ^ kb, (fc0 ^ cc18) ^ (g18 ^ ki2) ^ kc);
            let mag_file = g18 ^ kp18;
            w.extend_from_slice(&mag_file.to_le_bytes());
            w.extend_from_slice(&a_enc.wrapping_add(ca18).to_le_bytes());
            w.extend_from_slice(&fb.to_le_bytes());
            w.extend_from_slice(&fc.to_le_bytes());
            inst_junk(w, mag_file, rng);
            pc18 += 1;
            let r718 = roll18.rotate_left(7);
            roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
            chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
        }
    }
    // ⑰ 组字节先行（组=本原型的参数组下标），然后逐条内联密文：
    // 字符串=tag+长度前缀密文；数字=tag+8B 密文。nonce 的池下标改用
    // **节内槽位号**（与 Lua 侧 pos-1 一致）；同值复用同一 (blob,li)。
    w.push(group as u8);
    // ㉓-C 死常量：每原型追加随机个诱饵槽（nil/bool/num 混排，blob=随机字节——
    // 惰性解码下诱饵永不被访问即永不解密），常量槽数量/节尺寸不再对应真实使用。
    // 诱饵槽排在真实槽之后，指令的 RK 引用不可能到达（li<真实数），无副作用。
    let d_count18: u32 = rng.random_range(0..=1 + (const_count as usize).min(24) as u32);
    w.extend_from_slice(&((const_count + d_count18).to_le_bytes()));
    // ③ 槽位洗牌落盘：第 slot 槽写原常量 inv_perm[slot]；nonce/折叠键仍用
    // 槽位号（=指令侧重映射后的操作数值，读写两侧同式）
    let mut inv_perm: Vec<usize> = vec![0; const_count as usize];
    for (oi, &ppos) in cperm.iter().enumerate() { inv_perm[ppos as usize] = oi; }
    let mut slot: u32 = 0;
    let mut seen: std::collections::HashMap<(Vec<u8>, u32, u32), (u8, Vec<u8>, u32)> = std::collections::HashMap::new();
    for pos in 0..const_count as usize {
        let idx = inv_perm[pos];
        let (c_type, bytes) = &local_consts[idx];
        if omit_const.contains(&idx) {
            w.push(tag_map[0]); // ㉓-B 省略槽 tag 逐 build 随机
            slot += 1;
            continue;
        }
        match c_type {
            0 => { w.push(tag_map[0]); }
            // ③-2 统一加密：bool 不再裸字节——按 0.0/1.0 双精度走 knum 加密
            // 管线（8B 密文），线上形态与数字槽完全一致
            1 | 2 | 3 => {
                // #3 折叠 + ㉓-A R 链混入：nonce=[盐^roll^F, r7^(槽*6+kind), 盐^rotl7(r7)]
                // roll=最后引用本槽指令之后的 R 状态（未引用槽=链末值）——常量解密
                // 依赖解释（指令流文件值），不依赖槽位号直传
                let fold = fold_map.get(&slot).copied().unwrap_or(0u32);
                let rl18 = roll_map.get(&slot).copied().unwrap_or(roll18);
                let r7l18 = rl18.rotate_left(7);
                let kind = if *c_type == 3 { enc.kstr[group] } else { enc.knum[group] };
                let s118 = enc.salts[group] ^ rl18 ^ fold;
                let s218 = r7l18 ^ slot.wrapping_mul(6).wrapping_add(kind);
                let s318 = enc.salts[group] ^ r7l18.rotate_left(7);
                let entry = match seen.get(&(bytes.clone(), fold, rl18)) {
                    Some(e) => e.clone(),
                    None => {
                        let li = slot;
                        let payload18: Vec<u8> = if *c_type == 1 {
                            let dv: f64 = if bytes[0] != 0 { 1.0 } else { 0.0 };
                            dv.to_le_bytes().to_vec()
                        } else { bytes.clone() };
                        let blob = chacha_xor_layout(&enc.keys[group], [s118, s218, s318], &payload18, &enc.layout[group]);
                        seen.insert((bytes.clone(), fold, rl18), (*c_type, blob.clone(), li));
                        (*c_type, blob, li)
                    }
                };
                w.push(tag_map[*c_type as usize]);
                if *c_type == 3 { write_string(w, &entry.1); } else { w.extend_from_slice(&entry.1); }
                // ③-3 每常量 MAC：密文块后 4B 校验和（密文+槽号+折叠+R链），
                // 读侧分派闭包先验后解
                w.extend_from_slice(&const_mac18(&entry.1, slot, fold, rl18, fc18).to_le_bytes());
            }
            _ => panic!(),
        }
        slot += 1;
    }

    // ㉓-C 诱饵槽发射（排在真实槽后；blob 随机字节即可——永不解密）
    for _ in 0..d_count18 {
        match rng.random_range(0..5) {
            0 => { w.push(tag_map[0]); } // nil：仅占一个槽号
            1 => { w.push(tag_map[1]); for _ in 0..12 { w.push(rng.random_range(0..=255u8)); } } // bool：8B+4B MAC 同线长
            _ => { w.push(tag_map[2]); for _ in 0..12 { w.push(rng.random_range(0..=255u8)); } } // num：8B+4B MAC
        }
    }

    let p_count = r.read_u32();
    w.extend_from_slice(&p_count.to_le_bytes());
    // ⑱.2 尺寸前缀掩码：ln 站点收集（本层 w 内绝对偏移, 层内 1-based 序号），
    // 子层站点偏移经 child_base 换算合并——根调用者拿到全量先序站点表
    let mut proto_sites: Vec<(usize, u32)> = Vec::new();
    let mut pidx18: u32 = 0;
    for _ in 0..p_count {
        // ⑱ 惰性原型：每个子块加 u32 长度前缀，Lua 侧 body_protos 按长跳过、
        // CLOSURE 首调才递归解码——整棵原型树不再一次性展开成明文
        pidx18 += 1;
        let mut child: Vec<u8> = Vec::new();
        let g2 = rng.random_range(0..CONST_GROUPS);
        let sub_sites = rewrite_chunk(r, &mut child, mapped_opcodes, builtin_map, fused_map, fused_used, setglobal_targets, getglobal_op, getglobalstr_op, inverse_opcode_map, slot_perm, op_magic, enc, g2, rng, kb, kc, ki1, ki2, fc18, tag_map, delta, ch_m, ch_k0);
        let ln_off = w.len();
        w.extend_from_slice(&(child.len() as u32).to_le_bytes());
        let child_base = w.len();
        w.extend_from_slice(&child);
        proto_sites.push((ln_off, pidx18));
        for (so, si) in sub_sites { proto_sites.push((so + child_base, si)); }
    }
    // ② 元数据剥离（续）：lines/locals/upvalue 名只消费不落盘
    let l_count = r.read_u32();
    w.extend_from_slice(&0u32.to_le_bytes());
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    w.extend_from_slice(&0u32.to_le_bytes());
    for _ in 0..loc_count { let _ = r.read_string(); let _ = r.read_u32(); let _ = r.read_u32(); }
    let upv_count = r.read_u32();
    w.extend_from_slice(&0u32.to_le_bytes());
    for _ in 0..upv_count { let _ = r.read_string(); }
    proto_sites
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
pub fn loadstring_probe_lua(nat: &str, getf: &str, pl: &str, uni: &mut UniStream, rng: &mut GenRng) -> String {
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

    let v_d = rng.name(); let v_gi = rng.name();
    let v_ok = rng.name(); let v_inf = rng.name();
    // nat：用到 getinfo/what/C/source/=[C]/S/table/function
    let nat_stmts = format!("{}{}{}{}{}{}{}{}",
        stmts[0], stmts[1], stmts[2], stmts[3], stmts[4], st_s, st_table, st_fn);
    let nat_body = format!(
        "local function {nat}({f}) \
            local {d} = debug; {stms} \
            if type({d}) ~= {sc_t} then return true end; \
            local {gi} = {d}[{k1}]; \
            if type({gi}) ~= {sc_f} then return true end; \
            local {ok}, {inf} = pcall({gi}, {f}, {sc_s}); \
            if not {ok} or type({inf}) ~= {sc_t} then return true end; \
            return {inf}[{k2}] == {k3} and {inf}[{k4}] == {k5}; \
        end; ",
        nat = nat, f = rng.name(), d = v_d, stms = nat_stmts,
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
            local {g} = (getfenv and getfenv()) or _G; {stms} \
            local {gg} = {g}[{k6}]; \
            if type({gg}) == {sc_f} then {g} = {gg}() or {g}; end; \
            local {ge} = {g}[{k7}]; \
            local {env} = {g}; \
            if type({ge}) == {sc_f} then {env} = {ge}() or {g}; end; \
            local {list} = {{ {g}[{k8}], {env}[{k8}], {env}[{k9}], {g}[{k9}] }}; \
            local {alt}, {i} = nil, 0; \
            local {n} = #{list}; \
            while {i} < {n} do \
                {i} = {i} + 1; \
                local {f} = {list}[{i}]; \
                local {t} = type({f}); \
                if {t} == {sc_f} then \
                    if {nat}({f}) and {alt} == nil then {alt} = {f}; {i} = {n}; end; \
                    if {alt} == nil then {alt} = {f}; end; \
                end; \
            end; \
            return {alt}; \
        end; \
        local {pl} = {getf}();\n",
        getf = getf, g = v_g, stms = getf_stmts,
        gg = v_gg, k6 = exprs[5], sc_f = ex_fn, ge = v_ge, k7 = exprs[6],
        env = v_env2, list = v_list, k8 = exprs[7], k9 = exprs[8],
        alt = v_alt, i = v_i2, n = v_n2, f = v_f2, t = v_t2,
        nat = nat, pl = pl);
    format!("{}{}", nat_body, getf_body)
}

