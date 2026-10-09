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

// 反混淆判据②修复：每条线上指令尾部挂 0..3 个随机垃圾字节，数量编码在线上魔数
// 高 2 位（mag 取值 0x0100_0000..0x7FFF_0000，kp18 ≤ 0x02FF_FFFF 不碰高位，
// 所以 (mag^kp18)>>29 与 mag>>29 一致，读写两侧同式）。「每条恰好 16B、
// N 条 ×16 精确对齐」的游标特征消失；垃圾字节随滚动密钥流一起加密。
fn inst_junk(w: &mut Vec<u8>, mag_file: u32, rng: &mut StdRng) {
    let jn = (mag_file >> 29) & 3;
    for _ in 0..jn { w.push(rng.random_range(0..256u32) as u8); }
}

pub(super) fn rewrite_chunk(r: &mut PayloadReader, w: &mut Vec<u8>, mapped_opcodes: &[Vec<u32>; VM_OPCODE_COUNT], fused_map: &[Vec<u32>; crate::VM::Opcodes::builtins::FUSED_OP_COUNT], fused_used: &mut HashSet<usize>, inverse_opcode_map: &[u8; VM_OPCODE_COUNT], op_magic: &std::collections::HashMap<u32, u32>, enc: &EncCtx, group: usize, rng: &mut StdRng, kb: u32, kc: u32, ki1: u32, ki2: u32, fc18: &FoldCtx, tag_map: &[u8; 4], delta: u32, ch_m: u64, ch_k0: u64, alloc18: &mut u32) {
    // ② 元数据剥离：chunk 名/lines/locals/upvalue 名在 VM 端零消费者
    // （错误消息=宿主真 Lua 原生报错，行守卫针式=恒 :2: 物理行）——读流保同步；
    // name 槽改承载 4B 原型汇总校验，行号/局部名/upvalue 名不写入载荷。
    // ⑱.3 每原型随机参数：kp18=本原型线上 op 异或键（二级重映射，跨原型同全局码
    // 线上值不同）、pb18=pc↔槽仿射偏移（槽=pc+pb，随机死槽；所有 pc 运算皆相对=零模板改动）。
    // 目标二③（第二部分，共享指令空间）：pb18 不再是本原型自取的小偏移，而是调用方
    // 游标分配的**全文件共用指令空间基址**——整棵原型树的记录落在同一段下标区间里、
    // 段间留随机死槽，读侧所有原型共用同一批数组、入口只切换 pc 基址（跳转全相对）。
    // 两值写入 ② 剥离后的 linedefined/numparams 两空槽（随机数，无源信息）。
    let kp18: u32 = rng.random_range(1..0x2000000u32) | 0x0100_0000;
    let pb18: u32 = *alloc18;
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
    // 源 chunk 名是调试元数据，不落入最终载荷。复用原 name 字段保存 4B
    // 原型常量汇总校验值；body_debug 从该字段校验，末尾不再保留可跳过的调试区。
    let _ = r.read_string();
    w.extend_from_slice(&4u32.to_le_bytes());
    let checksum_offset = w.len();
    w.extend_from_slice(&[0u8; 4]);
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
    // 每原型始终加入少量有效数字诱饵。它们稍后会被随机插入真实槽之间，
    // 并由尾部不可达 ADD 指令引用；密文、槽位与聚合 MAC 都走正式管线。
    let decoy_count18 = rng.random_range(1..=(const_count as usize + 1).min(8).max(1));
    let decoy_consts: Vec<Vec<u8>> = (0..decoy_count18).map(|_| {
        let whole = rng.random_range(10_000u64..=9_999_999u64) as f64;
        let frac = rng.random_range(0u64..=99_999u64) as f64 / 100_000.0;
        (whole + frac).to_le_bytes().to_vec()
    }).collect();

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
    // 全局名（包括内建名）保留为普通字符串常量，统一由常量解码器和环境表处理。

    // 真实常量与有效诱饵共用一次槽位置换。cperm 只映射真实源槽；decoy_slots
    // 专供不可达尾部指令使用，确保活跃指令永远不会引用诱饵。
    let total_const_count = const_count + decoy_count18 as u32;
    let mut const_layout: Vec<ConstantSlot> = (0..const_count as usize)
        .map(ConstantSlot::Source)
        .chain((0..decoy_count18).map(ConstantSlot::Decoy))
        .collect();
    for i in (1..const_layout.len()).rev() {
        let j = rng.random_range(0..=i);
        const_layout.swap(i, j);
    }
    let mut cperm = vec![0u32; const_count as usize];
    let mut decoy_slots = vec![0u32; decoy_count18];
    for (slot, entry) in const_layout.iter().enumerate() {
        match *entry {
            ConstantSlot::Source(idx) => cperm[idx] = slot as u32,
            ConstantSlot::Decoy(idx) => decoy_slots[idx] = slot as u32,
        }
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
    w.extend_from_slice(&(inst_count + dead_count as u32).to_le_bytes());
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
                        let (fb, fc) = (
                            (fb0 ^ cb18) ^ (g18 ^ ki1) ^ kb,
                            (fc0 ^ cc18) ^ (g18 ^ ki2) ^ kc,
                        );
                        let mag_file = g18 ^ kp18;
                        w.extend_from_slice(&mag_file.to_le_bytes());
                        w.extend_from_slice(&a_enc.wrapping_add(ca18).to_le_bytes());
                        w.extend_from_slice(&fb.to_le_bytes());
                        w.extend_from_slice(&fc.to_le_bytes());
                        inst_junk(w, mag_file, rng);
                        fused_used.insert(family);
                        fused_count += 1;
                        pc18 += 1;
                        let r718 = roll18.rotate_left(7);
                        roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                        chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                        if fb0 > 127 && fc_pb(mag) {
                            let slot = fb0 - 128;
                            let e = fold_map.entry(slot).or_insert(0u32);
                            *e = e.wrapping_add(fc_f(pc18));
                            roll_map.insert(slot, roll18);
                        }
                        if fc0 > 127 && fc_pc(mag) {
                            let slot = fc0 - 128;
                            let e = fold_map.entry(slot).or_insert(0u32);
                            *e = e.wrapping_add(fc_f(pc18));
                            roll_map.insert(slot, roll18);
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
                        let (fb, fc) = ((fb0 ^ cb18) ^ (g18 ^ ki1) ^ kb, (fc0 ^ cc18) ^ (g18 ^ ki2) ^ kc);
                        let mag_file = g18 ^ kp18;
                        w.extend_from_slice(&mag_file.to_le_bytes());
                        w.extend_from_slice(&a_enc.wrapping_add(ca18).to_le_bytes());
                        w.extend_from_slice(&fb.to_le_bytes());
                        w.extend_from_slice(&fc.to_le_bytes());
                        inst_junk(w, mag_file, rng);
                        fused_used.insert(fidx);
                        fused_count += 1;
                        pc18 += 1;
                        let r718 = roll18.rotate_left(7);
                        roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                        chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                        if fb0 > 127 && fc_pb(mag) { let e = fold_map.entry(fb0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fb0 - 128).or_insert(0u32); *e2 = roll18; }
                        if fc0 > 127 && fc_pc(mag) { let e = fold_map.entry(fc0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fc0 - 128).or_insert(0u32); *e2 = roll18; }
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
                                    let (fb, fc) = ((fb0 ^ cb18) ^ (g18 ^ ki1) ^ kb, (fc0 ^ cc18) ^ (g18 ^ ki2) ^ kc);
                                    let mag_file = g18 ^ kp18;
                                    w.extend_from_slice(&mag_file.to_le_bytes());
                                    w.extend_from_slice(&a_enc.wrapping_add(ca18).to_le_bytes());
                                    w.extend_from_slice(&fb.to_le_bytes());
                                    w.extend_from_slice(&fc.to_le_bytes());
                                    inst_junk(w, mag_file, rng);
                                    fused_used.insert(crate::VM::Opcodes::builtins::BUILTIN_NAMES.len() * 2 + 2);
                                    fused_count += 1;
                                    pc18 += 1;
                                    let r718 = roll18.rotate_left(7);
                                    roll18 = (r718 ^ mag).wrapping_add(a_enc).wrapping_add(fb0 ^ fc0);
                                    chain18 = ch_step(chain18, mag, a_enc, fb0, fc0);
                                    if fb0 > 127 && fc_pb(mag) { let e = fold_map.entry(fb0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fb0 - 128).or_insert(0u32); *e2 = roll18; }
                                    if fc0 > 127 && fc_pc(mag) { let e = fold_map.entry(fc0 - 128).or_insert(0u32); *e = e.wrapping_add(fc_f(pc18)); let e2 = roll_map.entry(fc0 - 128).or_insert(0u32); *e2 = roll18; }
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
        // ---- 目标三②③：普通 JMP → 族六「计算式跳转」----
        // 随机挑一部分 JMP 改成：真实后继与诱饵后继都以密文落盘（密钥 = 运行期
        // PC 与本原型 pf_ld 现算），静态读不出下一条是谁；诱饵后继指向本原型尾部
        // 的死指令段——那段垃圾因此在静态 CFG 上多出一条「只有运行期才知道真假」
        // 的入边（实际永不执行）。
        let mut a_log: u32 = a as u32;
        let mut cj_sel: Option<u32> = None;
        if real_op18 == VmOp::Jump && dead_count > 0 && rng.random_range(0..10) < 7 {
            let fam6 = crate::VM::Opcodes::builtins::BUILTIN_NAMES.len() * 2 + 3;
            let fv = fused_map.get(fam6).map(|v| v.as_slice()).unwrap_or(&[]);
            // 目标记录下标 = 本记录下标(pb18+pc18+1) + 1 + sBx（Jmp 取指后 pc 已自增）
            let t1 = pb18 as i64 + pc18 as i64 + 2 + (b as i32 as i64);
            if !fv.is_empty() && t1 >= pb18 as i64 + 1 && t1 <= pb18 as i64 + inst_count as i64 {
                let t2 = pb18 as i64 + inst_count as i64 + 1 + rng.random_range(0..dead_count) as i64;
                let salt = rng.random_range(0x1000..0xFF_FFFFu32);
                // 密钥与 handler 同式：k=( (PC ^ ld) ^ salt )——纯异或（不取模）。
                // 注意 handler 看到的 PC 是「取指后已自增」的值 = 记录下标 + 1。
                let pcr = pb18.wrapping_add(pc18 as u32).wrapping_add(2);
                let k1 = (pcr ^ kp18) ^ salt;
                a_log = (t1 as u32) ^ k1;
                be18 = (t2 as u32) ^ k1;
                ce18 = salt;
                cj_sel = Some(fv[rng.random_range(0..fv.len())]);
                fused_used.insert(fam6);
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
            if fb0 > 127 && fc_pb(mag) {
                let fold_slot = fb0 - 128;
                let e = fold_map.entry(fold_slot).or_insert(0u32);
                *e = e.wrapping_add(fc_f(pc18));
                roll_map.insert(fold_slot, roll18);
            }
            if fc0 > 127 && fc_pc(mag) {
                let fold_slot = fc0 - 128;
                let e = fold_map.entry(fold_slot).or_insert(0u32);
                *e = e.wrapping_add(fc_f(pc18));
                roll_map.insert(fold_slot, roll18);
            }
        }
    }
    // ⑰ 组字节先行（组=本原型的参数组下标），然后逐条内联密文：
    // 字符串=tag+长度前缀密文；数字=tag+8B 密文。每槽按自己的槽号派生 nonce，
    // 不复用其他槽的密文，以保证洗牌后的折叠键与运行期解密键严格一致。
    w.push(group as u8);
    // 常量记录按同一混排布局发射。诱饵使用有效 f64 明文，并与真实数值常量
    // 共用 fold/R 派生、ChaCha 加密和聚合 MAC；其引用仅位于不可达尾部。
    w.extend_from_slice(&total_const_count.to_le_bytes());
    let mut slot: u32 = 0;
    // ③ 汇总校验器：每个非 nil 记录（含诱饵）都按落盘顺序累计；读侧使用同式。
    let mut agg18: u32 = 0;
    for layout_entry in &const_layout {
        let (c_type, bytes) = match *layout_entry {
            ConstantSlot::Source(idx) => (local_consts[idx].0, local_consts[idx].1.as_slice()),
            ConstantSlot::Decoy(idx) => (2, decoy_consts[idx].as_slice()),
        };
        match c_type {
            0 => { w.push(tag_map[0]); }
            // bool 也走 8 字节 double 密文管线，线上 tag 与数字结构一致。
            1 | 2 | 3 => {
                let fold = fold_map.get(&slot).copied().unwrap_or(0u32);
                let rl18 = roll_map.get(&slot).copied().unwrap_or(roll18);
                let r7l18 = rl18.rotate_left(7);
                let kind = if c_type == 3 { enc.kstr[group] } else { enc.knum[group] };
                let s118 = enc.salts[group] ^ rl18 ^ fold;
                let s218 = r7l18 ^ slot.wrapping_mul(6).wrapping_add(kind);
                let s318 = enc.salts[group] ^ r7l18.rotate_left(7);
                let payload18: Vec<u8> = if c_type == 1 {
                    let dv: f64 = if bytes[0] != 0 { 1.0 } else { 0.0 };
                    dv.to_le_bytes().to_vec()
                } else { bytes.to_vec() };
                let blob = chacha_xor_layout(&enc.keys[group], [s118, s218, s318], &payload18, &enc.layout[group]);
                w.push(tag_map[c_type as usize]);
                if c_type == 3 { write_string(w, &blob); } else { w.extend_from_slice(&blob); }
                let mac18 = const_mac18(&blob, slot, fold, rl18, fc18);
                agg18 = agg18.wrapping_mul(31).wrapping_add(mac18).wrapping_add(1);
            }
            _ => panic!(),
        }
        slot += 1;
    }

    let p_count = r.read_u32();
    w.extend_from_slice(&p_count.to_le_bytes());
    // 子 proto 直接按序递归写入：线上不带长度、边界标记或可跳过填充。
    // 读侧必须完整解析当前 proto（含其子树）才能抵达下一个兄弟 proto。
    for _ in 0..p_count {
        let g2 = rng.random_range(0..CONST_GROUPS);
        rewrite_chunk(r, w, mapped_opcodes, fused_map, fused_used, inverse_opcode_map, op_magic, enc, g2, rng, kb, kc, ki1, ki2, fc18, tag_map, delta, ch_m, ch_k0, alloc18);
    }

    // 目标五②：末尾行号、局部变量及 upvalue 调试区全部消费后丢弃。
    // 汇总校验值已回填到 name 字段，不再依赖可识别的三段尾部结构。
    let l_count = r.read_u32();
    r.read_bytes((l_count * 4) as usize);
    let loc_count = r.read_u32();
    for _ in 0..loc_count { let _ = r.read_string(); let _ = r.read_u32(); let _ = r.read_u32(); }
    let upv_count = r.read_u32();
    for _ in 0..upv_count { let _ = r.read_string(); }

    // 校验值与运行时 aggf 同式：整原型常量 MAC 混合 kp/pb，作为有意义的
    // 4 字节 name-field 负载；源文件名和调试信息本身不会进入成品。
    let mix18: u32 = kp18 ^ pb18.rotate_left(7);
    let checksum = agg18 ^ mix18;
    w[checksum_offset..checksum_offset + 4].copy_from_slice(&checksum.to_le_bytes());
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

