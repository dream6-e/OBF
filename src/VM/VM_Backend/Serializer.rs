use crate::BytecodeCompiler::ir::chunk::{Chunk, Constant};
use crate::BytecodeCompiler::ir::instruction::Instruction;
use crate::BytecodeCompiler::ir::opcode::Opcode;
use crate::VM::VM_Backend::Context::VmContext;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng, rngs::StdRng};

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
        let mut bytes = Vec::new();

        Self::write_string(&mut bytes, chunk.name.as_bytes());

        bytes.extend_from_slice(&chunk.line_defined.to_le_bytes());
        bytes.extend_from_slice(&chunk.last_line_defined.to_le_bytes());

        bytes.push(chunk.upvalue_count);
        bytes.push(chunk.param_count);
        bytes.push(chunk.is_vararg);
        bytes.push(chunk.max_stack);

        let inst_count = instructions.len() as u32;
        bytes.extend_from_slice(&inst_count.to_le_bytes());

        for inst in instructions {
            let mapped_op = ctx.opcode_map[inst.opcode as usize];
            bytes.push(mapped_op);
            bytes.push(inst.a);
            bytes.extend_from_slice(&inst.b.to_le_bytes());
            bytes.extend_from_slice(&inst.c.to_le_bytes());
        }

        let const_count = chunk.constants.len() as u32;
        bytes.extend_from_slice(&const_count.to_le_bytes());

        for constant in &chunk.constants {
            match constant {
                Constant::Nil => bytes.push(0),
                Constant::Boolean(b) => {
                    bytes.push(1);
                    bytes.push(if *b { 1 } else { 0 });
                }
                Constant::Number(n) => {
                    bytes.push(2);
                    bytes.extend_from_slice(&n.to_bits().to_le_bytes());
                }
                Constant::String(s) => {
                    bytes.push(3);
                    Self::write_string(&mut bytes, s);
                }
            }
        }

        let p_count = chunk.protos.len() as u32;
        bytes.extend_from_slice(&p_count.to_le_bytes());
        for (index, proto) in chunk.protos.iter().enumerate() {
            let child_seed = seed
                .wrapping_add((index as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15))
                .rotate_left(17);
            bytes.extend(Self::serialize_proto(proto, ctx, child_seed));
        }

        let lines: Vec<i32> = if let Some(code) = &reordered {
            if chunk.lines.len() == chunk.instructions.len() {
                code.source_pc.iter().map(|&pc| chunk.lines[pc]).collect()
            } else {
                chunk.lines.clone()
            }
        } else {
            chunk.lines.clone()
        };
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

    // 在不可达区追加由运行态 TEST 守卫分流的克隆死块。两条路径均是自环 NOP，
    // 不参与业务控制流；所有合法出口显式越过整个诱饵区。
    let mut fake_jumps = Vec::new();
    let fake_count = rng.random_range(1..=3);
    for _ in 0..fake_count {
        let start = output.len();
        let reg_limit = usize::from(max_stack).max(1);
        let reg = rng.random_range(0..reg_limit) as u8;
        let cond = rng.random_range(0..=1) as i32;
        output.push(make_instruction(Opcode::Test, reg, 0, cond, 0));
        source_pc.push(0);
        output.push(make_instruction(Opcode::Jmp, 0, 0, -1, 0));
        source_pc.push(0);
        output.push(make_instruction(Opcode::Jmp, 0, 0, -1, 0));
        source_pc.push(0);
        let path1 = output.len();
        output.push(make_instruction(Opcode::Move, reg, i32::from(reg), 0, 0));
        source_pc.push(0);
        let loop1 = output.len();
        output.push(make_instruction(Opcode::Jmp, 0, 0, -1, 0));
        source_pc.push(0);
        let path2 = output.len();
        output.push(make_instruction(Opcode::Move, reg, i32::from(reg), 0, 0));
        source_pc.push(0);
        let loop2 = output.len();
        output.push(make_instruction(Opcode::Jmp, 0, 0, -1, 0));
        source_pc.push(0);
        fake_jumps.extend([(start + 1, path1), (start + 2, path2), (loop1, path1), (loop2, path2)]);
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
}
