use crate::BytecodeCompiler::ir::chunk::{Chunk, Constant};
use crate::BytecodeCompiler::ir::instruction::Instruction;
use crate::BytecodeCompiler::ir::opcode::Opcode;
use crate::VM::VM_Backend::Context::VmContext;
use crate::VM::VM_Backend::CustomIsa::{CustomInstruction, VmOp, lower_to_custom_with_splits};
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::collections::{HashMap, HashSet};

pub struct Serializer;

#[derive(Clone, Copy)]
struct Unit {
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct BasicBlock {
    first_unit: usize,
    last_unit: usize,
    start: usize,
    end: usize,
    fallthrough: Option<usize>,
}

struct ReorderedCode {
    instructions: Vec<Instruction>,
    source_pc: Vec<usize>,
}

impl Serializer {
    pub fn serialize(chunk: &Chunk, ctx: &VmContext) -> Vec<u8> {
        Self::serialize_proto(chunk, ctx, ctx.seed)
    }

    fn serialize_proto(chunk: &Chunk, ctx: &VmContext, seed: u64) -> Vec<u8> {
        let reordered = reorder_basic_blocks(&chunk.instructions, &chunk.protos, chunk.max_stack, seed);
        let instructions = reordered
            .as_ref()
            .map(|code| code.instructions.as_slice())
            .unwrap_or(&chunk.instructions);
        let source_lines: Vec<i32> = if let Some(code) = &reordered {
            if chunk.lines.len() == chunk.instructions.len() {
                code.source_pc.iter().map(|&pc| chunk.lines[pc]).collect()
            } else {
                code.instructions.iter().map(|inst| inst.line).collect()
            }
        } else if chunk.lines.len() == chunk.instructions.len() {
            chunk.lines.clone()
        } else {
            chunk.instructions.iter().map(|inst| inst.line).collect()
        };
        // 自证常量拆解：仅由 LoadK/LoadKx 引用的 +0.0 与 1.0 槽在降级期拆为
        // [PushConst(k), PushConst(k), Sub/Div, PopReg(a)]（r - r = 0.0、r / r = 1.0），
        // 并将常量槽本身替换为 8 字节全非零的随机有限浮点数 r，使其不进常量池。
        let mut rk_used: HashSet<i32> = HashSet::new();
        let mut loadk_used: HashSet<i32> = HashSet::new();
        let mut pc_scan = 0usize;
        while pc_scan < instructions.len() {
            let inst = &instructions[pc_scan];
            match inst.opcode {
                Opcode::LoadK => { loadk_used.insert(inst.b); }
                Opcode::LoadKx => {
                    if pc_scan + 1 < instructions.len() {
                        loadk_used.insert(instructions[pc_scan + 1].b);
                    }
                }
                Opcode::GetGlobal | Opcode::SetGlobal => { rk_used.insert(inst.b); }
                Opcode::GetTable | Opcode::SelfOp => {
                    if inst.c >= 128 { rk_used.insert(inst.c - 128); }
                }
                Opcode::SetTable
                | Opcode::Add | Opcode::Sub | Opcode::Mul | Opcode::Div | Opcode::Mod | Opcode::Pow
                | Opcode::Eq | Opcode::Lt | Opcode::Le => {
                    if inst.b >= 128 { rk_used.insert(inst.b - 128); }
                    if inst.c >= 128 { rk_used.insert(inst.c - 128); }
                }
                _ => {}
            }
            pc_scan += 1;
        }
        let mut split_rng = StdRng::seed_from_u64(seed ^ 0x6A09_E667_F3BC_C908);
        let mut zero_one_splits: HashMap<i32, VmOp> = HashMap::new();
        let mut split_replacements: HashMap<usize, u64> = HashMap::new();
        for (k_idx, constant) in chunk.constants.iter().enumerate() {
            let k_i32 = k_idx as i32;
            if loadk_used.contains(&k_i32) && !rk_used.contains(&k_i32) {
                if let Constant::Number(n) = constant {
                    let bits = n.to_bits();
                    let split_op = if bits == 0 {
                        Some(VmOp::Sub)
                    } else if bits == 1.0f64.to_bits() {
                        Some(VmOp::Div)
                    } else {
                        None
                    };
                    if let Some(op) = split_op {
                        let sign: u64 = split_rng.random_range(0u64..=1u64);
                        let exp: u64 = split_rng.random_range(0x3FAu64..=0x40Au64);
                        let mut mant: u64 = 0;
                        for sh in (0..48).step_by(8) {
                            mant |= split_rng.random_range(1u64..=255u64) << sh;
                        }
                        mant |= split_rng.random_range(1u64..=15u64) << 48;
                        zero_one_splits.insert(k_i32, op);
                        split_replacements.insert(k_idx, (sign << 63) | (exp << 52) | mant);
                    }
                }
            }
        }
        let lowered = lower_to_custom_with_splits(instructions, &chunk.protos, &zero_one_splits)
            .unwrap_or_else(|err| panic!("{err}"));
        let mut extra_consts: Vec<u64> = Vec::new();
        let lowered = if lowered.len() < 24 {
            inflate_small_custom_proto(
                lowered,
                chunk.constants.len(),
                &mut extra_consts,
                seed ^ 0x9E37_79B9_7F4A_7C15,
            )
        } else if reordered.is_some() && chunk.instructions.len() >= 18 {
            weave_custom_cfg_hubs(
                lowered,
                &chunk.instructions,
                reordered.as_ref().map(|r| r.source_pc.as_slice()),
                chunk.constants.len(),
                &mut extra_consts,
                seed ^ 0x9E37_79B9_7F4A_7C15,
            )
        } else {
            lowered
        };
        let mut bytes = Vec::new();

        Self::write_string(&mut bytes, chunk.name.as_bytes());

        bytes.extend_from_slice(&chunk.line_defined.to_le_bytes());
        bytes.extend_from_slice(&chunk.last_line_defined.to_le_bytes());

        bytes.push(chunk.upvalue_count);
        bytes.push(chunk.param_count);
        bytes.push(chunk.is_vararg);
        bytes.push(chunk.max_stack);

        let inst_count = lowered.len() as u32;
        bytes.extend_from_slice(&inst_count.to_le_bytes());

        for inst in &lowered {
            let mapped_op = ctx.opcode_map[inst.op.global_id()];
            bytes.push(mapped_op);
            bytes.push(inst.a);
            bytes.extend_from_slice(&inst.b.to_le_bytes());
            bytes.extend_from_slice(&inst.c.to_le_bytes());
        }

        let const_count = (chunk.constants.len() + extra_consts.len()) as u32;
        bytes.extend_from_slice(&const_count.to_le_bytes());

        for (k_idx, constant) in chunk.constants.iter().enumerate() {
            match constant {
                Constant::Nil => bytes.push(0),
                Constant::Boolean(b) => {
                    bytes.push(1);
                    bytes.push(if *b { 1 } else { 0 });
                }
                Constant::Number(n) => {
                    bytes.push(2);
                    let bits = split_replacements.get(&k_idx).copied().unwrap_or_else(|| n.to_bits());
                    bytes.extend_from_slice(&bits.to_le_bytes());
                }
                Constant::String(s) => {
                    bytes.push(3);
                    Self::write_string(&mut bytes, s);
                }
            }
        }
        for &bits in &extra_consts {
            bytes.push(2);
            bytes.extend_from_slice(&bits.to_le_bytes());
        }

        let p_count = chunk.protos.len() as u32;
        bytes.extend_from_slice(&p_count.to_le_bytes());
        for (index, proto) in chunk.protos.iter().enumerate() {
            let child_seed = seed
                .wrapping_add((index as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15))
                .rotate_left(17);
            bytes.extend(Self::serialize_proto(proto, ctx, child_seed));
        }

        let lines: Vec<i32> = lowered
            .iter()
            .map(|inst| source_lines.get(inst.source_pc).copied().unwrap_or(0))
            .collect();
        bytes.extend_from_slice(&(lines.len() as u32).to_le_bytes());
        for line in lines {
            bytes.extend_from_slice(&line.to_le_bytes());
        }

        let loc_count = chunk.locals.len() as u32;
        bytes.extend_from_slice(&loc_count.to_le_bytes());
        for loc in &chunk.locals {
            Self::write_string(&mut bytes, loc.name.as_bytes());
            bytes.extend_from_slice(&loc.start_pc.to_le_bytes());
            bytes.extend_from_slice(&loc.end_pc.to_le_bytes());
        }

        let upv_count = chunk.upvalues.len() as u32;
        bytes.extend_from_slice(&upv_count.to_le_bytes());
        for upv in &chunk.upvalues {
            Self::write_string(&mut bytes, upv.as_bytes());
        }

        bytes
    }

    fn write_string(bytes: &mut Vec<u8>, s_bytes: &[u8]) {
        let len = s_bytes.len() as u32;
        bytes.extend_from_slice(&len.to_le_bytes());
        if len > 0 {
            bytes.extend_from_slice(s_bytes);
        }
    }
}

fn is_test_opcode(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Eq
            | Opcode::Lt
            | Opcode::Le
            | Opcode::Test
            | Opcode::TestSet
            | Opcode::EqInt
            | Opcode::LtInt
            | Opcode::LeInt
            | Opcode::EqStr
            | Opcode::LtStr
            | Opcode::LeStr
            | Opcode::TestInt
            | Opcode::TestStr
    )
}

fn is_relative_jump(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Jmp
            | Opcode::ForLoop
            | Opcode::ForPrep
            | Opcode::TForPrep
            | Opcode::JmpIf
            | Opcode::JmpIfNot
            | Opcode::JmpEq
            | Opcode::JmpNe
    )
}

fn is_conditional_jump(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::ForLoop
            | Opcode::TForPrep
            | Opcode::JmpIf
            | Opcode::JmpIfNot
            | Opcode::JmpEq
            | Opcode::JmpNe
    )
}

fn is_return(op: Opcode) -> bool {
    matches!(op, Opcode::Return | Opcode::Return0 | Opcode::Return1 | Opcode::Return2 | Opcode::TailCall)
}

fn relative_target(pc: usize, inst: &Instruction, len: usize) -> Option<usize> {
    let target = pc as i64 + 1 + inst.b as i64;
    (target >= 0 && target <= len as i64).then_some(target as usize)
}

fn make_instruction(opcode: Opcode, a: u8, b: i32, c: i32, line: i32) -> Instruction {
    Instruction {
        data: 0,
        opcode,
        a,
        b,
        c,
        line,
        v_opcode: None,
        is_junk: false,
    }
}

fn full_entropy_f64_bits(rng: &mut StdRng, exp: u64) -> u64 {
    let mut mant: u64 = 0;
    for sh in (0..48).step_by(8) {
        mant |= rng.random_range(1u64..=254u64) << sh;
    }
    mant |= rng.random_range(1u64..=15u64) << 48;
    (exp << 52) | mant
}

fn ci(op: VmOp, a: u8, b: i32, c: i32) -> CustomInstruction {
    CustomInstruction { op, a, b, c, source_pc: 0 }
}

/// 消灭最小闭包已知结构探针（Crib）：
/// 对短小原型（`lowered.len() < 24`，如空闭包 `function() end`、单常量返回闭包及短回调）
/// 注入 3 个全非零尾数有限浮点常量，并将真实指令切分/包裹进乱序的 4~5 基本块控制流图中：
/// 1. 真实 `ReturnNone`/`ReturnOne`/`ReturnRange` 被置于函数体中部（不再位于末尾）；
/// 2. 入口块与中继块通过运行期解密常量池中的 `k0, k1, k2` 执行算术与比较分支（前向 + 后向跳转）；
/// 3. 所有注入计算仅在 `vstack` 上平衡压弹，零触碰 `stk` 局部寄存器或 `top`/`upvals`。
fn inflate_small_custom_proto(
    lowered: Vec<CustomInstruction>,
    base_const_count: usize,
    extra_consts: &mut Vec<u64>,
    seed: u64,
) -> Vec<CustomInstruction> {
    if lowered.is_empty() || lowered.len() >= 24 {
        return lowered;
    }
    let mut rng = StdRng::seed_from_u64(seed);
    let e0 = rng.random_range(0x400u64..=0x402u64);
    let e1 = rng.random_range(0x404u64..=0x405u64);
    let e2 = rng.random_range(0x408u64..=0x40Au64);
    let b0 = full_entropy_f64_bits(&mut rng, e0); // [2.0, 32.0)
    let b1 = full_entropy_f64_bits(&mut rng, e1); // [32.0, 128.0)
    let b2 = full_entropy_f64_bits(&mut rng, e2); // [512.0, 4096.0)
    let mut c_perm = [0usize, 1, 2];
    c_perm.shuffle(&mut rng);
    let raw_vals = [b0, b1, b2];
    let mut k_slots = [0i32; 3];
    for (slot_offset, &logical_idx) in c_perm.iter().enumerate() {
        extra_consts.push(raw_vals[logical_idx]);
        k_slots[logical_idx] = (base_const_count + slot_offset) as i32;
    }
    let (k0, k1, k2) = (k_slots[0], k_slots[1], k_slots[2]);

    let has_branches = lowered
        .iter()
        .any(|inst| inst.op.branch_offset(inst.b as u32, inst.c as u32).is_some());

    // 按不可拆分的原子单元切分（MakeClosure 及其紧随的 c 条捕获描述符保持同单元）
    let mut units: Vec<Vec<CustomInstruction>> = Vec::new();
    let mut idx = 0usize;
    while idx < lowered.len() {
        let inst = lowered[idx];
        let extra = if inst.op == VmOp::MakeClosure && inst.c > 0 {
            (inst.c as usize).min(lowered.len() - 1 - idx)
        } else {
            0
        };
        units.push(lowered[idx..=idx + extra].to_vec());
        idx += 1 + extra;
    }

    let single_terminal_at_end = !has_branches
        && !units.is_empty()
        && units.last().unwrap().last().unwrap().op.is_terminator()
        && units[..units.len() - 1]
            .iter()
            .all(|u| !u.iter().any(|i| i.op.is_terminator()));

    if single_terminal_at_end {
        let prefix = &units[..units.len() - 1];
        let mid = prefix.len() / 2;
        let part1: Vec<CustomInstruction> = prefix[..mid].iter().flatten().copied().collect();
        let part2: Vec<CustomInstruction> = prefix[mid..].iter().flatten().copied().collect();
        let term: Vec<CustomInstruction> = units.last().unwrap().clone();

        // Block 0: Entry (always at index 0) -> branches to Block 1 (truthy: Noop(v0) < v2)
        let blk0 = vec![
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Noop, 0, 0, 0),
            ci(VmOp::PushConst, 0, k2, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 1, 0, 0),
        ];
        // Block 1: Part 1 + stack op -> jumps to Block 2
        let mut blk1 = part1;
        blk1.extend([
            ci(VmOp::PushConst, 0, k2, 0),
            ci(VmOp::PushConst, 0, k1, 0),
            ci(VmOp::Sub, 0, 0, 0),
            ci(VmOp::Drop, 0, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ]);
        // Block 2: Part 2 + second runtime state-modulated branch -> branches to Block 4 (falsy: Noop(v2) < v0)
        let mut blk2 = part2;
        blk2.extend([
            ci(VmOp::PushConst, 0, k2, 0),
            ci(VmOp::Noop, 0, 0, 0),
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 0, 0, 0),
        ]);
        // Block 3: Decoy alternate block -> jumps to Block 1
        let blk3 = vec![
            ci(VmOp::PushConst, 0, k1, 0),
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Mul, 0, 0, 0),
            ci(VmOp::Drop, 0, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ];
        // Block 4: Real Terminator block (placed in the middle of the function, never at the end)
        let mut blk4 = vec![
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Neg, 0, 0, 0),
            ci(VmOp::Drop, 0, 0, 0),
        ];
        blk4.extend(term);

        let all_blocks = [blk0, blk1, blk2, blk3, blk4];
        const ORDERS: [[usize; 5]; 4] = [
            [0, 3, 4, 1, 2],
            [0, 1, 4, 3, 2],
            [0, 2, 4, 3, 1],
            [0, 4, 3, 1, 2],
        ];
        let order = ORDERS[rng.random_range(0..ORDERS.len())];
        let mut out = Vec::new();
        let mut starts = [0usize; 5];
        let mut ends = [0usize; 5];
        for &b_id in &order {
            starts[b_id] = out.len();
            out.extend_from_slice(&all_blocks[b_id]);
            ends[b_id] = out.len() - 1;
        }
        let rel = |from: usize, to: usize| -> i32 { (to as i64 - (from as i64 + 1)) as i32 };
        out[ends[0]].b = rel(ends[0], starts[1]);
        out[ends[1]].b = rel(ends[1], starts[2]);
        out[ends[2]].b = rel(ends[2], starts[4]);
        out[ends[3]].b = rel(ends[3], starts[1]);
        out
    } else {
        // 含内部跳转的短小闭包：将原指令流整体置于中部（内部相对偏移天然保持不变），
        // 入口块前向跳至尾部块，尾部块再后向跳回中部核心块。
        let blk_entry = vec![
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Noop, 0, 0, 0),
            ci(VmOp::PushConst, 0, k2, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 1, 0, 0),
        ];
        let blk_decoy = vec![
            ci(VmOp::PushConst, 0, k1, 0),
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Mul, 0, 0, 0),
            ci(VmOp::Drop, 0, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ];
        let blk_tail = vec![
            ci(VmOp::PushConst, 0, k2, 0),
            ci(VmOp::PushConst, 0, k1, 0),
            ci(VmOp::Sub, 0, 0, 0),
            ci(VmOp::Drop, 0, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ];
        let mut out = Vec::with_capacity(blk_entry.len() + blk_decoy.len() + lowered.len() + blk_tail.len());
        out.extend_from_slice(&blk_entry);
        let end_entry = out.len() - 1;
        out.extend_from_slice(&blk_decoy);
        let end_decoy = out.len() - 1;
        let start_core = out.len();
        out.extend_from_slice(&lowered);
        let start_tail = out.len();
        out.extend_from_slice(&blk_tail);
        let end_tail = out.len() - 1;
        let rel = |from: usize, to: usize| -> i32 { (to as i64 - (from as i64 + 1)) as i32 };
        out[end_entry].b = rel(end_entry, start_tail);
        out[end_decoy].b = rel(end_decoy, start_core);
        out[end_tail].b = rel(end_tail, start_core);
        out
    }
}

/// 字节码级控制流平坦化与多路分发枢纽交织（针对 `lowered.len() >= 24` 的中大型函数，如 `u10`）：
/// 1. 向常量池注入 4 个严格递增的全非零尾数有限浮点状态常量 `v0 < v1 < v2 < v3`（满足 `v0 + v1 < v2`）；
/// 2. 通过 BFS 识别可达指令流中的非热环 `VmOp::Jump`（含基本块裂解产生的桥接跳转与分支合流跳转）；
/// 3. 将多达 16 条块间跳转分组接入 **4 路 `vstack` 二叉状态分发枢纽（Dispatcher Hub）**：
///    跳板 `Pad_m` 在 `vstack` 压入双份状态常量 `k_m` 后统一跳入 `Hub_Root`，由 `Hub_Root -> Hub_Left / Hub_Right`
///    经两次运行期常量比较分派至真实目标块 `T_0..T_3` 或静态可达的诱饵块 `Decoy`（全程 `vstack` 严格平衡、零触碰 `stk` 寄存器）；
/// 4. 其余多达 8 条块间跳转改写为运行期常量条件门（`Gate`），并将所有 `Pad / Hub / Decoy / Gate` 块随机洗牌后
///    分置在原指令流前后的 Prefix/Suffix Arena 中（原指令流作为连续核心切片置于中部，内部相对分支偏移天然保持不变）。
fn weave_custom_cfg_hubs(
    lowered: Vec<CustomInstruction>,
    orig_instructions: &[Instruction],
    reordered_source_pc: Option<&[usize]>,
    base_const_count: usize,
    extra_consts: &mut Vec<u64>,
    seed: u64,
) -> Vec<CustomInstruction> {
    if lowered.len() < 24 {
        return lowered;
    }
    let mut rng = StdRng::seed_from_u64(seed ^ 0xD1B5_4A32_D192_ED03);
    let e0 = rng.random_range(0x400u64..=0x401u64); // [2.0, 8.0)
    let e1 = rng.random_range(0x403u64..=0x404u64); // [16.0, 64.0)
    let e2 = rng.random_range(0x406u64..=0x407u64); // [128.0, 512.0)
    let e3 = rng.random_range(0x409u64..=0x40Au64); // [1024.0, 4096.0)
    let raw_vals = [
        full_entropy_f64_bits(&mut rng, e0),
        full_entropy_f64_bits(&mut rng, e1),
        full_entropy_f64_bits(&mut rng, e2),
        full_entropy_f64_bits(&mut rng, e3),
    ];
    let mut c_perm = [0usize, 1, 2, 3];
    c_perm.shuffle(&mut rng);
    let mut k_slots = [0i32; 4];
    for (slot_offset, &logical_idx) in c_perm.iter().enumerate() {
        extra_consts.push(raw_vals[logical_idx]);
        k_slots[logical_idx] = (base_const_count + slot_offset) as i32;
    }
    let (k0, k1, k2, k3) = (k_slots[0], k_slots[1], k_slots[2], k_slots[3]);

    // 识别原始未重排指令中的循环区间（后向跳转覆盖区间），避免对紧密内层循环注入分发跳板
    let orig_len = orig_instructions.len();
    let mut orig_in_loop = vec![false; orig_len];
    for (pc, inst) in orig_instructions.iter().enumerate() {
        if is_relative_jump(inst.opcode) {
            if let Some(target) = relative_target(pc, inst, orig_len) {
                if target <= pc {
                    for slot in orig_in_loop.iter_mut().take(pc + 1).skip(target) {
                        *slot = true;
                    }
                }
            }
        }
    }

    // BFS 找出 lowered 中从入口 0 可达的指令（排除 reorder_basic_blocks 末尾追加的不可达自环死块）
    let n_low = lowered.len();
    let mut reachable = vec![false; n_low];
    let mut queue = std::collections::VecDeque::new();
    reachable[0] = true;
    queue.push_back(0usize);
    while let Some(pc) = queue.pop_front() {
        let inst = lowered[pc];
        if let Some(off) = inst.op.branch_offset(inst.b as u32, inst.c as u32) {
            let target = pc as i64 + 1 + off as i64;
            if target >= 0 && (target as usize) < n_low && !reachable[target as usize] {
                reachable[target as usize] = true;
                queue.push_back(target as usize);
            }
        }
        if !inst.op.is_terminator() && inst.op != VmOp::Jump {
            let step = if inst.op == VmOp::MakeClosure && inst.c > 0 {
                1 + inst.c as usize
            } else {
                1
            };
            if pc + step < n_low && !reachable[pc + step] {
                reachable[pc + step] = true;
                queue.push_back(pc + step);
            }
        }
    }

    let mut non_loop_jumps: Vec<(usize, usize)> = Vec::new();
    let mut loop_fwd_jumps: Vec<(usize, usize)> = Vec::new();
    for (pc, inst) in lowered.iter().enumerate() {
        if !reachable[pc] || inst.op != VmOp::Jump {
            continue;
        }
        let target = pc as i64 + 1 + inst.b as i64;
        if target < 0 || (target as usize) >= n_low {
            continue;
        }
        let orig_pc = reordered_source_pc
            .and_then(|map| map.get(inst.source_pc).copied())
            .unwrap_or(inst.source_pc);
        let is_loop = orig_in_loop.get(orig_pc).copied().unwrap_or(false);
        if !is_loop {
            non_loop_jumps.push((pc, target as usize));
        } else if inst.b > 0 {
            loop_fwd_jumps.push((pc, target as usize));
        }
    }
    non_loop_jumps.shuffle(&mut rng);
    loop_fwd_jumps.shuffle(&mut rng);
    let mut candidates = non_loop_jumps;
    if candidates.len() < 4 {
        for item in loop_fwd_jumps {
            if candidates.len() >= 4 {
                break;
            }
            candidates.push(item);
        }
    }

    // 构造 Arena 基本块池
    let mut arena_blocks: Vec<Vec<CustomInstruction>> = Vec::new();
    let mut add_block = |ins: Vec<CustomInstruction>| -> usize {
        let id = arena_blocks.len();
        arena_blocks.push(ins);
        id
    };

    struct HubPatch {
        pads: [usize; 4],
        root: usize,
        left: usize,
        right: usize,
        decoy: usize,
        targets_in_low: [usize; 4],
    }
    struct GatePatch {
        gate: usize,
        target_in_low: usize,
        decoy_block: usize,
    }

    let mut hub_patches: Vec<HubPatch> = Vec::new();
    let mut gate_patches: Vec<GatePatch> = Vec::new();
    let mut jump_redirs: Vec<(usize, usize)> = Vec::new(); // (low_pc, target_arena_block_id)

    let num_full_hubs = (candidates.len() / 4).min(4);
    let mut cursor = 0usize;
    let hub_count = if num_full_hubs > 0 {
        num_full_hubs
    } else if !candidates.is_empty() {
        1
    } else {
        0
    };

    for _ in 0..hub_count {
        let mut group = [(0usize, 0usize); 4];
        for g_idx in 0..4 {
            if cursor < candidates.len() {
                group[g_idx] = candidates[cursor];
                cursor += 1;
            } else {
                group[g_idx] = group[0];
            }
        }
        let k_arr = [k0, k1, k2, k3];
        let mut pads = [0usize; 4];
        for m in 0..4 {
            pads[m] = add_block(vec![
                ci(VmOp::PushConst, 0, k_arr[m], 0),
                ci(VmOp::PushConst, 0, k_arr[m], 0),
                ci(VmOp::Noop, 0, 0, 0),
                ci(VmOp::Jump, 0, 0, 0),
            ]);
        }
        let root = add_block(vec![
            ci(VmOp::PushConst, 0, k2, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 1, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ]);
        let left = add_block(vec![
            ci(VmOp::PushConst, 0, k1, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 1, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ]);
        let right = add_block(vec![
            ci(VmOp::PushConst, 0, k3, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 1, 0, 0),
            ci(VmOp::PushConst, 0, k3, 0),
            ci(VmOp::Noop, 0, 0, 0),
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 0, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ]);
        let decoy = add_block(vec![
            ci(VmOp::PushConst, 0, k2, 0),
            ci(VmOp::Noop, 0, 0, 0),
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 1, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ]);
        for m in 0..4 {
            let (low_pc, _) = group[m];
            if !jump_redirs.iter().any(|&(p, _)| p == low_pc) {
                jump_redirs.push((low_pc, pads[m]));
            }
        }
        hub_patches.push(HubPatch {
            pads,
            root,
            left,
            right,
            decoy,
            targets_in_low: [group[0].1, group[1].1, group[2].1, group[3].1],
        });
    }

    // 兜底诱饵块（当无可用 Jump 时仍构造静态可达的前后缀混淆块）
    let fallback_decoy = if let Some(hp) = hub_patches.first() {
        hp.decoy
    } else {
        let d_id = add_block(vec![
            ci(VmOp::PushConst, 0, k2, 0),
            ci(VmOp::PushConst, 0, k1, 0),
            ci(VmOp::Sub, 0, 0, 0),
            ci(VmOp::Drop, 0, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ]);
        let t_id = add_block(vec![
            ci(VmOp::PushConst, 0, k3, 0),
            ci(VmOp::PushConst, 0, k0, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, 0, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ]);
        gate_patches.push(GatePatch {
            gate: t_id,
            target_in_low: 0,
            decoy_block: d_id,
        });
        d_id
    };

    // 剩余候选 Jump（至多 8 条）改写为条件常量门 Gate
    let max_gates = 8usize;
    let mut gates_added = 0usize;
    while cursor < candidates.len() && gates_added < max_gates {
        let (low_pc, target_in_low) = candidates[cursor];
        cursor += 1;
        let truthy = rng.random_range(0..2u8) == 1;
        let (ka, kb, pol) = if truthy { (k0, k2, 1u8) } else { (k3, k1, 0u8) };
        let gate = add_block(vec![
            ci(VmOp::PushConst, 0, ka, 0),
            ci(VmOp::PushConst, 0, kb, 0),
            ci(VmOp::Less, 0, 0, 0),
            ci(VmOp::Branch, pol, 0, 0),
            ci(VmOp::Jump, 0, 0, 0),
        ]);
        let decoy_block = if !hub_patches.is_empty() {
            hub_patches[gates_added % hub_patches.len()].decoy
        } else {
            fallback_decoy
        };
        jump_redirs.push((low_pc, gate));
        gate_patches.push(GatePatch {
            gate,
            target_in_low,
            decoy_block,
        });
        gates_added += 1;
    }

    // 洗牌全部 Arena 块并平分到 lowered 前（Prefix Arena）与后（Suffix Arena）
    let mut arena_order: Vec<usize> = (0..arena_blocks.len()).collect();
    arena_order.shuffle(&mut rng);
    let split_half = arena_order.len() / 2;
    let prefix_ids = &arena_order[..split_half];
    let suffix_ids = &arena_order[split_half..];

    let blk_entry = vec![
        ci(VmOp::PushConst, 0, k0, 0),
        ci(VmOp::Noop, 0, 0, 0),
        ci(VmOp::PushConst, 0, k2, 0),
        ci(VmOp::Less, 0, 0, 0),
        ci(VmOp::Branch, 1, 0, 0),
    ];

    let mut out = Vec::with_capacity(blk_entry.len() + lowered.len() + arena_blocks.len() * 6);
    out.extend_from_slice(&blk_entry);
    let end_entry = out.len() - 1;

    let mut arena_starts = vec![0usize; arena_blocks.len()];
    let mut arena_ends = vec![0usize; arena_blocks.len()];
    for &b_id in prefix_ids {
        arena_starts[b_id] = out.len();
        out.extend_from_slice(&arena_blocks[b_id]);
        arena_ends[b_id] = out.len() - 1;
    }

    let start_core = out.len();
    out.extend_from_slice(&lowered);

    for &b_id in suffix_ids {
        arena_starts[b_id] = out.len();
        out.extend_from_slice(&arena_blocks[b_id]);
        arena_ends[b_id] = out.len() - 1;
    }

    let rel = |from: usize, to: usize| -> i32 { (to as i64 - (from as i64 + 1)) as i32 };

    // 入口块跳至核心块起点（若无后继 Prefix 块则跳至首个 Suffix 块再跳回 start_core）
    out[end_entry].b = rel(end_entry, start_core);

    // 修补全部 4 路 Dispatcher Hub 偏移
    for hp in &hub_patches {
        let root_start = arena_starts[hp.root];
        let left_start = arena_starts[hp.left];
        let right_start = arena_starts[hp.right];
        let decoy_start = arena_starts[hp.decoy];
        for &pad_id in &hp.pads {
            let pad_end = arena_ends[pad_id];
            out[pad_end].b = rel(pad_end, root_start);
        }
        out[root_start + 2].b = rel(root_start + 2, left_start);
        out[root_start + 3].b = rel(root_start + 3, right_start);

        let t0 = start_core + hp.targets_in_low[0];
        let t1 = start_core + hp.targets_in_low[1];
        let t2 = start_core + hp.targets_in_low[2];
        let t3 = start_core + hp.targets_in_low[3];

        out[left_start + 2].b = rel(left_start + 2, t0);
        out[left_start + 3].b = rel(left_start + 3, t1);

        out[right_start + 2].b = rel(right_start + 2, t2);
        out[right_start + 7].b = rel(right_start + 7, t3);
        out[right_start + 8].b = rel(right_start + 8, decoy_start);

        out[decoy_start + 4].b = rel(decoy_start + 4, t0);
        out[decoy_start + 5].b = rel(decoy_start + 5, t2);
    }

    if hub_patches.is_empty() {
        let d_end = arena_ends[fallback_decoy];
        out[d_end].b = rel(d_end, start_core);
    }

    // 修补全部条件常量门 Gate 偏移
    for gp in &gate_patches {
        let g_start = arena_starts[gp.gate];
        let t_pc = start_core + gp.target_in_low;
        let d_pc = arena_starts[gp.decoy_block];
        out[g_start + 3].b = rel(g_start + 3, t_pc);
        out[g_start + 4].b = rel(g_start + 4, d_pc);
    }

    // 重定向核心块内被选中的 VmOp::Jump 至对应 Pad / Gate
    for &(low_pc, target_arena_id) in &jump_redirs {
        let from_pc = start_core + low_pc;
        let to_pc = arena_starts[target_arena_id];
        out[from_pc].b = rel(from_pc, to_pc);
    }

    out
}

/// 重排仅在完整识别控制流和指令附属区后启用；遇到不完整/非规范配对则保留原型布局。
fn reorder_basic_blocks(
    instructions: &[Instruction],
    protos: &[Chunk],
    max_stack: u8,
    seed: u64,
) -> Option<ReorderedCode> {
    let len = instructions.len();
    if len < 4 {
        return None;
    }

    // 建立不可拆开的指令单元：闭包捕获描述、测试+JMP、TFORLOOP+JMP、
    // LOADBOOL 跳过区以及消费后继字的 LOADKX/SETLIST 都必须保持相邻。
    let mut units = Vec::new();
    let mut unit_of_pc = vec![usize::MAX; len];
    let mut pc = 0usize;
    while pc < len {
        let inst = &instructions[pc];
        let end = match inst.opcode {
            Opcode::Closure => {
                let child = protos.get(usize::try_from(inst.b).ok()?)?;
                let captures = child.upvalue_count as usize;
                let end = pc.checked_add(captures)?;
                if end >= len
                    || instructions[pc + 1..=end]
                        .iter()
                        .any(|capture| !matches!(capture.opcode, Opcode::Move | Opcode::GetUpval))
                {
                    return None;
                }
                end
            }
            Opcode::LoadKx => {
                if pc + 1 >= len || instructions[pc + 1].opcode != Opcode::ExtraArg {
                    return None;
                }
                pc + 1
            }
            Opcode::SetList if inst.c == 0 => {
                if pc + 1 >= len {
                    return None;
                }
                pc + 1
            }
            Opcode::TForLoop => {
                if pc + 1 >= len || instructions[pc + 1].opcode != Opcode::Jmp {
                    return None;
                }
                pc + 1
            }
            op if is_test_opcode(op) => {
                if pc + 1 >= len || instructions[pc + 1].opcode != Opcode::Jmp {
                    return None;
                }
                pc + 1
            }
            Opcode::LoadBool if inst.c > 0 => {
                let target = pc.checked_add(1 + inst.c as usize)?;
                if target > len {
                    return None;
                }
                if target == pc + 1 { pc } else { target - 1 }
            }
            _ => pc,
        };
        if end >= len {
            return None;
        }
        let unit_index = units.len();
        for owner in unit_of_pc.iter_mut().take(end + 1).skip(pc) {
            if *owner != usize::MAX {
                return None;
            }
            *owner = unit_index;
        }
        units.push(Unit { start: pc, end });
        pc = end + 1;
    }

    // 所有可达边目标和控制转移后的线性后继都是基本块入口。
    let mut leaders = vec![false; len];
    leaders[0] = true;
    for (pc, inst) in instructions.iter().enumerate() {
        if is_relative_jump(inst.opcode) {
            let target = relative_target(pc, inst, len)?;
            if target < len { leaders[target] = true; }
            if pc + 1 < len { leaders[pc + 1] = true; }
        }
        if is_test_opcode(inst.opcode) || inst.opcode == Opcode::TForLoop {
            leaders[pc] = true;
            let after_pair = pc + 2;
            if after_pair < len { leaders[after_pair] = true; }
        }
        if is_return(inst.opcode) && pc + 1 < len {
            leaders[pc + 1] = true;
        }
        if inst.opcode == Opcode::LoadBool && inst.c > 0 {
            let target = pc.checked_add(1 + inst.c as usize)?;
            if target < len { leaders[target] = true; }
        }
    }

    let mut block_starts = Vec::new();
    for (leader_pc, &is_leader) in leaders.iter().enumerate() {
        if !is_leader { continue; }
        let unit_index = *unit_of_pc.get(leader_pc)?;
        if unit_index == usize::MAX {
            return None;
        }
        let unit = units[unit_index];
        if unit.start != leader_pc {
            // A jump may legally enter the instruction skipped by LOADBOOL. Keep the
            // pair adjacent as one unit; an inner LOADBOOL C=0 has the same fallthrough
            // as the pair, so the edge can target its mapped instruction directly.
            let safe_loadbool_entry = instructions[unit.start].opcode == Opcode::LoadBool
                && instructions[unit.start].c == 1
                && unit.end == leader_pc
                && leader_pc == unit.start + 1
                && instructions[leader_pc].opcode == Opcode::LoadBool
                && instructions[leader_pc].c == 0;
            if safe_loadbool_entry {
                continue;
            }
            return None;
        }
        block_starts.push(unit_index);
    }
    block_starts.sort_unstable();
    block_starts.dedup();
    if block_starts.len() < 3 {
        return None;
    }
    // 基本块裂解（Block Fission，方案 4）：对已具备 >= 3 个原始基本块的函数，将含 >= 4 个原子 Unit 的
    // 非热环基本块按 3..=5 Unit 粒度切分为子基本块（单函数上限 36 块），既打碎原始基本块边界，
    // 又保留块内算术/表操作 4 指令融合快路径与运行速度。
    let mut in_loop = vec![false; len];
    for (pc, inst) in instructions.iter().enumerate() {
        if is_relative_jump(inst.opcode) {
            if let Some(target) = relative_target(pc, inst, len) {
                if target <= pc {
                    for slot in in_loop.iter_mut().take(pc + 1).skip(target) {
                        *slot = true;
                    }
                }
            }
        }
    }
    let mut fission_rng = StdRng::seed_from_u64(seed ^ 0x517C_C1B7_2722_0A95);
    let mut fissioned_starts = Vec::with_capacity(block_starts.len() * 2);
    for (index, &first_unit) in block_starts.iter().enumerate() {
        let last_unit = block_starts.get(index + 1).copied().unwrap_or(units.len()) - 1;
        fissioned_starts.push(first_unit);
        let unit_span = last_unit.saturating_sub(first_unit) + 1;
        let blk_in_loop = in_loop[units[first_unit].start];
        if unit_span >= 4 && !blk_in_loop && fissioned_starts.len() < 36 {
            let mut cur = first_unit;
            while cur < last_unit && fissioned_starts.len() < 36 {
                let step = fission_rng.random_range(3..=5);
                if cur + step <= last_unit {
                    cur += step;
                    fissioned_starts.push(cur);
                } else {
                    break;
                }
            }
        }
    }
    fissioned_starts.sort_unstable();
    fissioned_starts.dedup();
    let block_starts = fissioned_starts;

    let mut blocks = Vec::with_capacity(block_starts.len());
    for (index, &first_unit) in block_starts.iter().enumerate() {
        let last_unit = block_starts.get(index + 1).copied().unwrap_or(units.len()) - 1;
        let start = units[first_unit].start;
        let end = units[last_unit].end;
        let first_op = instructions[start].opcode;
        let last_inst = &instructions[end];
        let paired_branch = (is_test_opcode(first_op) || first_op == Opcode::TForLoop)
            && last_inst.opcode == Opcode::Jmp;
        let fallthrough = if paired_branch {
            Some(end + 1)
        } else if matches!(last_inst.opcode, Opcode::Jmp | Opcode::ForPrep) || is_return(last_inst.opcode) {
            None
        } else {
            Some(end + 1)
        };
        blocks.push(BasicBlock { first_unit, last_unit, start, end, fallthrough });
    }

    let mut order: Vec<usize> = (0..blocks.len()).collect();
    let mut rng = StdRng::seed_from_u64(seed ^ 0xA076_1D64_78BD_642F);
    order[1..].shuffle(&mut rng);
    if order.iter().copied().eq(0..order.len()) {
        order.swap(1, 2);
    }

    let mut output = Vec::with_capacity(len + blocks.len() + 24);
    let mut source_pc = Vec::with_capacity(output.capacity());
    let mut old_to_new = vec![usize::MAX; len];
    let mut bridge_jumps = Vec::new();

    for (position, &block_index) in order.iter().enumerate() {
        let block = blocks[block_index];
        for unit_index in block.first_unit..=block.last_unit {
            let unit = units[unit_index];
            for old_pc in unit.start..=unit.end {
                old_to_new[old_pc] = output.len();
                output.push(instructions[old_pc].clone());
                source_pc.push(old_pc);
            }
        }
        if let Some(target_old) = block.fallthrough {
            let next_is_fallthrough = order
                .get(position + 1)
                .is_some_and(|&next| blocks[next].start == target_old);
            if !next_is_fallthrough {
                let bridge_pc = output.len();
                output.push(make_instruction(Opcode::Jmp, 0, 0, -1, instructions[block.end].line));
                source_pc.push(block.end);
                bridge_jumps.push((bridge_pc, target_old));
            }
        }
    }

    // 方案 2：消除不可达旧死块与 weave_custom_cfg_hubs 静态可达 Decoy 诱饵块的双重叠加：
    // 对 >= 18 条指令（由 weave_custom_cfg_hubs 织入可达 Decoy 块）的函数不再重复追加不可达死块；
    // 对 < 18 条指令的函数仅保留 1 个精简不可达自环尾块。
    let mut fake_jumps = Vec::new();
    if len < 18 {
        let reg_limit = usize::from(max_stack).max(1);
        let reg = rng.random_range(0..reg_limit) as u8;
        let path1 = output.len();
        output.push(make_instruction(Opcode::Move, reg, i32::from(reg), 0, 0));
        source_pc.push(0);
        let loop1 = output.len();
        output.push(make_instruction(Opcode::Jmp, 0, 0, -1, 0));
        source_pc.push(0);
        fake_jumps.push((loop1, path1));
    }

    let exit_pc = output.len();
    for (new_pc, target_old) in bridge_jumps {
        let target_new = if target_old == len { exit_pc } else { *old_to_new.get(target_old)? };
        output[new_pc].b = i32::try_from(target_new as i64 - new_pc as i64 - 1).ok()?;
    }
    for (old_pc, &new_pc) in old_to_new.iter().enumerate() {
        let inst = &mut output[new_pc];
        if is_relative_jump(inst.opcode) {
            let target_old = relative_target(old_pc, &instructions[old_pc], len)?;
            let target_new = if target_old == len { exit_pc } else { *old_to_new.get(target_old)? };
            inst.b = i32::try_from(target_new as i64 - new_pc as i64 - 1).ok()?;
        }
    }
    for (new_pc, target_new) in fake_jumps {
        output[new_pc].b = i32::try_from(target_new as i64 - new_pc as i64 - 1).ok()?;
    }
    Some(ReorderedCode { instructions: output, source_pc })
}

#[cfg(test)]
mod cfg_tests {
    use super::*;

    fn inst(opcode: Opcode, b: i32, c: i32) -> Instruction {
        make_instruction(opcode, 0, b, c, 1)
    }

    #[test]
    fn jump_can_enter_loadbool_skipped_loadbool_without_splitting_pair() {
        let instructions = vec![
            inst(Opcode::LoadBool, 0, 1),
            inst(Opcode::LoadBool, 0, 0),
            inst(Opcode::Jmp, -2, -1),
            inst(Opcode::LoadK, 0, 0),
            inst(Opcode::Jmp, 0, -1),
            inst(Opcode::Return0, 0, 0),
        ];
        let code = reorder_basic_blocks(&instructions, &[], 4, 0x51A9_EB00)
            .expect("safe entry into the skipped LoadBool should remain reorderable");
        let new_pc = |old_pc| code.source_pc.iter().position(|&source| source == old_pc).unwrap();
        let loadbool = new_pc(0);
        let alternate_entry = new_pc(1);
        assert_eq!(alternate_entry, loadbool + 1, "LOADBOOL skip pair must stay adjacent");

        let jump_pc = new_pc(2);
        assert_eq!(
            relative_target(jump_pc, &code.instructions[jump_pc], code.instructions.len()),
            Some(alternate_entry),
            "the incoming edge must still target the skipped instruction"
        );
    }

    #[test]
    fn jump_into_loadkx_extraarg_still_falls_back() {
        let instructions = vec![
            inst(Opcode::LoadKx, 0, 0),
            inst(Opcode::ExtraArg, 0, 0),
            inst(Opcode::Jmp, -2, -1),
            inst(Opcode::Return0, 0, 0),
        ];
        assert!(reorder_basic_blocks(&instructions, &[], 4, 0x51A9_EB01).is_none());
    }

    #[test]
    fn block_shuffle_relocates_edges_and_adds_dead_cfg() {
        let instructions = vec![
            inst(Opcode::Jmp, 2, -1),
            inst(Opcode::LoadK, 0, -1),
            inst(Opcode::Jmp, 1, -1),
            inst(Opcode::LoadK, 1, -1),
            inst(Opcode::Return0, 0, 0),
        ];
        let code = reorder_basic_blocks(&instructions, &[], 4, 0xC0FFEE)
            .expect("three or more basic blocks should be shuffled");
        assert!(code.instructions.len() > instructions.len());
        for (pc, inst) in code.instructions.iter().enumerate() {
            if is_relative_jump(inst.opcode) {
                let target = pc as i64 + 1 + inst.b as i64;
                assert!(target >= 0 && target <= code.instructions.len() as i64);
            }
        }
        let again = reorder_basic_blocks(&instructions, &[], 4, 0xC0FFEE).unwrap();
        assert_eq!(
            code.instructions.iter().map(|inst| (inst.opcode as u8, inst.a, inst.b, inst.c)).collect::<Vec<_>>(),
            again.instructions.iter().map(|inst| (inst.opcode as u8, inst.a, inst.b, inst.c)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn minimal_closures_are_inflated_and_eliminate_terminal_return_crib() {
        // 1. 空闭包 `function() end`（原仅 1 条 ReturnNone，0 常量）
        let empty_closure = vec![ci(VmOp::ReturnNone, 0, 0, 0)];
        let mut extra_consts = Vec::new();
        let inflated = inflate_small_custom_proto(empty_closure, 0, &mut extra_consts, 0x1357_2468);
        assert!(inflated.len() >= 20, "空闭包必须膨胀为多基本块指令流");
        assert_eq!(extra_consts.len(), 3, "必须注入 3 个全非零尾数有限浮点常量");
        for &bits in &extra_consts {
            assert!(bits.to_le_bytes().iter().all(|&b| b != 0), "注入常量不得含全零尾数字节");
        }
        // 末尾不得再是固定 ReturnNone/ReturnOne
        assert!(
            !inflated.last().unwrap().op.is_terminator(),
            "膨胀后最后一条指令不得再是固定 Return 终结符"
        );
        // 所有 Branch/Jump 偏移必须落在合法指令边界内，且同时存在前向与后向边
        let mut has_forward = false;
        let mut has_backward = false;
        for (pc, inst) in inflated.iter().enumerate() {
            if let Some(off) = inst.op.branch_offset(inst.b as u32, inst.c as u32) {
                let target = pc as i64 + 1 + off as i64;
                assert!(target >= 0 && (target as usize) < inflated.len());
                if off > 0 { has_forward = true; }
                if off < 0 { has_backward = true; }
            }
        }
        assert!(has_forward && has_backward, "膨胀后的最小闭包必须同时含前向与后向跳转边");
        assert!(
            inflated.iter().any(|i| i.op == VmOp::Noop),
            "最小闭包不透明谓词必须织入 VmOp::Noop 运行期状态调制指令"
        );
    }

    #[test]
    fn block_fission_and_cfg_hubs_flatten_clean_cfg() {
        // 构造一个具备 >= 3 个原始基本块且含 >= 6 Unit 块的函数，验证方案 1+2+4 下 Block Fission + 4 路 Dispatcher Hub
        let orig = vec![
            inst(Opcode::LoadK, 0, -1),
            inst(Opcode::LoadK, 1, -1),
            inst(Opcode::Jmp, 2, -1),
            inst(Opcode::Add, 0, 1),
            inst(Opcode::Move, 2, 0),
            inst(Opcode::LoadK, 0, -1),
            inst(Opcode::Sub, 2, 0),
            inst(Opcode::Add, 2, 1),
            inst(Opcode::Move, 1, 2),
            inst(Opcode::Jmp, 1, -1),
            inst(Opcode::Move, 3, 2),
            inst(Opcode::Return, 2, 0),
        ];
        let reordered = reorder_basic_blocks(&orig, &[], 4, 0xCAFE_BABE)
            .expect("Block Fission 应将 >= 3 块函数裂解为更多微基本块并重排");
        let lowered = lower_to_custom_with_splits(
            &reordered.instructions,
            &[],
            &std::collections::HashMap::new(),
        )
        .unwrap();
        assert!(lowered.len() >= 24);
        let mut extra_consts = Vec::new();
        let woven = weave_custom_cfg_hubs(
            lowered.clone(),
            &orig,
            Some(&reordered.source_pc),
            2,
            &mut extra_consts,
            0xCAFE_BABE,
        );
        assert_eq!(extra_consts.len(), 4, "应注入 4 个有序全非零尾数状态常量");
        for &bits in &extra_consts {
            assert!(bits.to_le_bytes().iter().all(|&b| b != 0));
        }
        assert!(
            woven.len() >= lowered.len() + 30,
            "weave_custom_cfg_hubs 应编织 Entry + 4 路 Dispatcher Hub + Decoy 块"
        );
        let mut cond_branches = 0usize;
        for (pc, ci_inst) in woven.iter().enumerate() {
            if ci_inst.op == VmOp::Branch {
                cond_branches += 1;
            }
            if let Some(off) = ci_inst.op.branch_offset(ci_inst.b as u32, ci_inst.c as u32) {
                let target = pc as i64 + 1 + off as i64;
                assert!(
                    target >= 0 && (target as usize) < woven.len(),
                    "所有 Hub/Pad/Gate/Core 跳转目标必须落在合法指令范围内"
                );
            }
        }
        assert!(cond_branches >= 5, "4 路 Dispatcher Hub + Entry + Decoy 至少引入 5 条条件分支");
        assert!(
            woven.iter().any(|i| i.op == VmOp::Noop),
            "4 路 Dispatcher Hub 与入口谓词必须织入 VmOp::Noop 运行期状态调制指令"
        );
    }
}
