//! Lua 5.1 Proto → Kryvex 自定义混合栈/寄存器 ISA。
//!
//! 编译器仍可复用 Lua 5.1 风格的前端和临时 Proto，但进入 VM 载荷前会在这里
//! 完整降级：自定义指令只使用 90..139 的独立 opcode 区，不会把 MOVE/LOADK/
//! GETTABLE/CALL/RETURN 等标准 opcode 原样交给运行时。算术/表达式先压入 VM
//! 的装箱值栈，再由独立操作和寄存器回写指令消费；测试与跳转合为直接分支；
//! 调用则拆成参数包、调用、结果收集三阶段。

use crate::BytecodeCompiler::ir::chunk::Chunk;
use crate::BytecodeCompiler::ir::instruction::Instruction;
use crate::BytecodeCompiler::ir::opcode::Opcode;

pub const LEGACY_OPCODE_COUNT: usize = 90;
pub const CUSTOM_OPCODE_BASE: usize = LEGACY_OPCODE_COUNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VmOp {
    PushReg = 0,
    PushConst = 1,
    PushRk = 2,
    PushRange = 3,
    PushBool = 4,
    PopReg = 5,
    Drop = 6,
    ClearRegs = 7,
    GetUpvalue = 8,
    SetUpvalue = 9,
    GetGlobal = 10,
    SetGlobal = 11,
    GetIndex = 12,
    SetIndex = 13,
    NewTable = 14,
    Add = 15,
    Sub = 16,
    Mul = 17,
    Div = 18,
    Mod = 19,
    Pow = 20,
    Neg = 21,
    Not = 22,
    Len = 23,
    Equal = 24,
    Less = 25,
    LessEqual = 26,
    Concat = 27,
    Branch = 28,
    BranchSetTrue = 29,
    BranchSetFalse = 30,
    Jump = 31,
    ForInit = 32,
    ForNext = 33,
    IteratorNext = 34,
    CallPack = 35,
    CallExecute = 36,
    CallCollect = 37,
    TailInvoke = 38,
    ReturnNone = 39,
    ReturnOne = 40,
    ReturnRange = 41,
    SetList = 42,
    CloseUpvalues = 43,
    MakeClosure = 44,
    CaptureLocal = 45,
    CaptureUpvalue = 46,
    Varargs = 47,
    Noop = 48,
}

pub const CUSTOM_OPCODE_COUNT: usize = VmOp::Noop as usize + 1;
pub const VM_OPCODE_COUNT: usize = CUSTOM_OPCODE_BASE + CUSTOM_OPCODE_COUNT;

impl VmOp {
    #[must_use]
    pub const fn global_id(self) -> usize {
        CUSTOM_OPCODE_BASE + self as usize
    }

    #[must_use]
    pub fn from_global(id: u8) -> Option<Self> {
        let local = (id as usize).checked_sub(CUSTOM_OPCODE_BASE)?;
        Some(match local {
            0 => Self::PushReg,
            1 => Self::PushConst,
            2 => Self::PushRk,
            3 => Self::PushRange,
            4 => Self::PushBool,
            5 => Self::PopReg,
            6 => Self::Drop,
            7 => Self::ClearRegs,
            8 => Self::GetUpvalue,
            9 => Self::SetUpvalue,
            10 => Self::GetGlobal,
            11 => Self::SetGlobal,
            12 => Self::GetIndex,
            13 => Self::SetIndex,
            14 => Self::NewTable,
            15 => Self::Add,
            16 => Self::Sub,
            17 => Self::Mul,
            18 => Self::Div,
            19 => Self::Mod,
            20 => Self::Pow,
            21 => Self::Neg,
            22 => Self::Not,
            23 => Self::Len,
            24 => Self::Equal,
            25 => Self::Less,
            26 => Self::LessEqual,
            27 => Self::Concat,
            28 => Self::Branch,
            29 => Self::BranchSetTrue,
            30 => Self::BranchSetFalse,
            31 => Self::Jump,
            32 => Self::ForInit,
            33 => Self::ForNext,
            34 => Self::IteratorNext,
            35 => Self::CallPack,
            36 => Self::CallExecute,
            37 => Self::CallCollect,
            38 => Self::TailInvoke,
            39 => Self::ReturnNone,
            40 => Self::ReturnOne,
            41 => Self::ReturnRange,
            42 => Self::SetList,
            43 => Self::CloseUpvalues,
            44 => Self::MakeClosure,
            45 => Self::CaptureLocal,
            46 => Self::CaptureUpvalue,
            47 => Self::Varargs,
            48 => Self::Noop,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn has_register_a(self) -> bool {
        matches!(
            self,
            Self::PushReg
                | Self::PopReg
                | Self::ClearRegs
                | Self::GetUpvalue
                | Self::SetUpvalue
                | Self::GetGlobal
                | Self::SetGlobal
                | Self::BranchSetTrue
                | Self::BranchSetFalse
                | Self::ForInit
                | Self::ForNext
                | Self::IteratorNext
                | Self::CallPack
                | Self::ReturnOne
                | Self::ReturnRange
                | Self::SetList
                | Self::CloseUpvalues
                | Self::MakeClosure
                | Self::Varargs
        )
    }

    /// 每条指令三个字段的定制解释；RK 保留 Lua 前端的寄存器/常量引用形式，
    /// 但只出现在自定义的 PushRk 指令上。
    #[must_use]
    pub const fn has_register_b(self) -> bool {
        matches!(self, Self::PushRange | Self::BranchSetTrue | Self::BranchSetFalse | Self::CaptureLocal)
    }

    #[must_use]
    pub const fn has_register_c(self) -> bool {
        matches!(self, Self::PushRange)
    }

    #[must_use]
    pub const fn has_rk_b(self) -> bool {
        matches!(self, Self::PushRk)
    }

    #[must_use]
    pub const fn has_constant_b(self) -> bool {
        matches!(self, Self::PushConst | Self::GetGlobal | Self::SetGlobal)
    }

    #[must_use]
    pub const fn branch_offset(self, b: u32, c: u32) -> Option<i32> {
        match self {
            Self::Branch | Self::Jump | Self::ForInit | Self::ForNext => Some(b as i32),
            Self::BranchSetTrue | Self::BranchSetFalse | Self::IteratorNext => Some(c as i32),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_terminator(self) -> bool {
        matches!(
            self,
            Self::TailInvoke | Self::ReturnNone | Self::ReturnOne | Self::ReturnRange
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustomInstruction {
    pub op: VmOp,
    pub a: u8,
    pub b: i32,
    pub c: i32,
    /// 来自重排后 Proto 的指令索引；用于把调试行数扩展到新指令流长度。
    pub source_pc: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowerError(pub String);

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LowerError {}

fn error(pc: usize, message: &str) -> LowerError {
    LowerError(format!("自定义 VM 指令降级失败（Proto PC {pc}）：{message}"))
}

fn is_test(op: Opcode) -> bool {
    matches!(op, Opcode::Eq | Opcode::Lt | Opcode::Le | Opcode::Test | Opcode::TestSet)
}

fn source_jump_target(pc: usize, jump: &Instruction, len: usize) -> Result<usize, LowerError> {
    let target = pc as i64 + 1 + jump.b as i64;
    if !(0..=len as i64).contains(&target) {
        return Err(error(pc, "相对跳转目标越界"));
    }
    Ok(target as usize)
}

fn mapped_delta(from_custom_pc: usize, target_source_pc: usize, starts: &[usize]) -> Result<i32, LowerError> {
    let target = *starts
        .get(target_source_pc)
        .ok_or_else(|| error(target_source_pc, "分支目标没有对应的自定义指令边界"))?;
    let delta = target as i64 - (from_custom_pc as i64 + 1);
    i32::try_from(delta).map_err(|_| error(target_source_pc, "重映射后的分支偏移超出 i32"))
}

fn emit(out: &mut Vec<CustomInstruction>, op: VmOp, a: u8, b: i32, c: i32, source_pc: usize) {
    out.push(CustomInstruction { op, a, b, c, source_pc });
}

fn rk(value: i32) -> i32 {
    value
}

fn expansion_lengths(instructions: &[Instruction], protos: &[Chunk]) -> Result<Vec<usize>, LowerError> {
    let len = instructions.len();
    let mut sizes = vec![0usize; len];
    let mut owned = vec![false; len];
    let mut pc = 0usize;
    while pc < len {
        if owned[pc] {
            pc += 1;
            continue;
        }
        let inst = &instructions[pc];
        let op = inst.opcode;
        sizes[pc] = match op {
            Opcode::Move | Opcode::LoadK | Opcode::NewTable => 2,
            Opcode::LoadBool => 2 + usize::from(inst.c != 0),
            Opcode::LoadNil
            | Opcode::GetUpval
            | Opcode::SetUpval
            | Opcode::GetGlobal
            | Opcode::SetGlobal
            | Opcode::Close
            | Opcode::VarArg
            | Opcode::ForLoop
            | Opcode::ForPrep
            | Opcode::Jmp => 1,
            Opcode::GetTable | Opcode::SetTable => 4,
            Opcode::SelfOp => 6,
            Opcode::Add | Opcode::Sub | Opcode::Mul | Opcode::Div | Opcode::Mod | Opcode::Pow => 4,
            Opcode::Unm | Opcode::Not | Opcode::Len => 3,
            Opcode::Concat => 3,
            Opcode::Eq | Opcode::Lt | Opcode::Le => {
                if pc + 1 >= len || instructions[pc + 1].opcode != Opcode::Jmp {
                    return Err(error(pc, "比较指令没有紧邻的 JMP，无法合成直接分支"));
                }
                owned[pc + 1] = true;
                4
            }
            Opcode::Test => {
                if pc + 1 >= len || instructions[pc + 1].opcode != Opcode::Jmp {
                    return Err(error(pc, "TEST 没有紧邻的 JMP，无法合成直接分支"));
                }
                owned[pc + 1] = true;
                2
            }
            Opcode::TestSet => {
                if pc + 1 >= len || instructions[pc + 1].opcode != Opcode::Jmp {
                    return Err(error(pc, "TESTSET 没有紧邻的 JMP，无法合成直接分支"));
                }
                owned[pc + 1] = true;
                if inst.a == 255 { 2 } else { 1 }
            }
            Opcode::Call => 3,
            Opcode::TailCall => 2,
            Opcode::Return => 1,
            Opcode::TForLoop => {
                if pc + 1 >= len || instructions[pc + 1].opcode != Opcode::Jmp {
                    return Err(error(pc, "迭代器测试没有紧邻的 JMP"));
                }
                owned[pc + 1] = true;
                1
            }
            Opcode::SetList => {
                if inst.c == 0 {
                    if pc + 1 >= len {
                        return Err(error(pc, "SETLIST 缺少扩展参数"));
                    }
                    owned[pc + 1] = true;
                }
                1
            }
            Opcode::Closure => {
                let child = protos
                    .get(usize::try_from(inst.b).map_err(|_| error(pc, "闭包原型索引无效"))?)
                    .ok_or_else(|| error(pc, "闭包原型索引越界"))?;
                let captures = child.upvalue_count as usize;
                if captures > 0 {
                    if pc + captures >= len {
                        return Err(error(pc, "闭包捕获描述不完整"));
                    }
                    if instructions[pc + 1..=pc + captures]
                        .iter()
                        .any(|capture| !matches!(capture.opcode, Opcode::Move | Opcode::GetUpval))
                    {
                        return Err(error(pc, "闭包捕获描述只能由 MOVE/GETUPVAL 组成"));
                    }
                    for capture_pc in pc + 1..=pc + captures {
                        owned[capture_pc] = true;
                    }
                    pc += captures;
                }
                1 + captures
            }
            Opcode::LoadKx => {
                if pc + 1 >= len || instructions[pc + 1].opcode != Opcode::ExtraArg {
                    return Err(error(pc, "LOADKX 缺少 EXTRAARG"));
                }
                owned[pc + 1] = true;
                2
            }
            Opcode::ExtraArg => return Err(error(pc, "孤立的 EXTRAARG")),
            other => return Err(error(pc, &format!("尚未定义 Lua 前端 opcode {other:?} 的降级"))),
        };
        pc += 1;
    }
    Ok(sizes)
}

/// 将一条 Lua 风格 Proto 指令流完整编译为自定义 VM 指令流。
///
/// 重排发生在调用本函数之前。这里先计算每条源指令对应的新 PC，再重新定位
/// 所有跳转；比较/TEST 与其后 JMP、以及 TFORLOOP/JMP 被合为一条条件分支，
/// 不会把 Lua 5.1 的「测试后跳过下一条」协议带进最终载荷。
pub fn lower_to_custom(instructions: &[Instruction], protos: &[Chunk]) -> Result<Vec<CustomInstruction>, LowerError> {
    let source_len = instructions.len();
    let sizes = expansion_lengths(instructions, protos)?;
    let mut starts = vec![0usize; source_len + 1];
    for pc in 0..source_len {
        starts[pc + 1] = starts[pc]
            .checked_add(sizes[pc])
            .ok_or_else(|| error(pc, "自定义指令计数溢出"))?;
    }

    let mut out = Vec::with_capacity(starts[source_len]);
    let mut pc = 0usize;
    while pc < source_len {
        let inst = &instructions[pc];
        let a = inst.a;
        let b = inst.b;
        let c = inst.c;
        let line_pc = pc;
        match inst.opcode {
            Opcode::Move => {
                emit(&mut out, VmOp::PushReg, b as u8, 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
            }
            Opcode::LoadK => {
                emit(&mut out, VmOp::PushConst, 0, b, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
            }
            Opcode::LoadKx => {
                let extra = instructions.get(pc + 1).ok_or_else(|| error(pc, "LOADKX 缺少扩展常量索引"))?;
                emit(&mut out, VmOp::PushConst, 0, extra.b, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
                pc += 1;
            }
            Opcode::LoadBool => {
                emit(&mut out, VmOp::PushBool, u8::from(b != 0), 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
                if c != 0 {
                    let target_source = pc + 1 + c as usize;
                    let jump_pc = out.len();
                    let offset = mapped_delta(jump_pc, target_source, &starts)?;
                    emit(&mut out, VmOp::Jump, 0, offset, 0, line_pc);
                }
            }
            Opcode::LoadNil => emit(&mut out, VmOp::ClearRegs, a, b - a as i32, 0, line_pc),
            Opcode::GetUpval => emit(&mut out, VmOp::GetUpvalue, a, b, 0, line_pc),
            Opcode::GetGlobal => emit(&mut out, VmOp::GetGlobal, a, b, 0, line_pc),
            Opcode::GetTable => {
                emit(&mut out, VmOp::PushReg, b as u8, 0, 0, line_pc);
                emit(&mut out, VmOp::PushRk, 0, rk(c), 0, line_pc);
                emit(&mut out, VmOp::GetIndex, 0, 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
            }
            Opcode::SetGlobal => emit(&mut out, VmOp::SetGlobal, a, b, 0, line_pc),
            Opcode::SetUpval => emit(&mut out, VmOp::SetUpvalue, a, b, 0, line_pc),
            Opcode::SetTable => {
                emit(&mut out, VmOp::PushReg, a, 0, 0, line_pc);
                emit(&mut out, VmOp::PushRk, 0, rk(b), 0, line_pc);
                emit(&mut out, VmOp::PushRk, 0, rk(c), 0, line_pc);
                emit(&mut out, VmOp::SetIndex, 0, 0, 0, line_pc);
            }
            Opcode::NewTable => {
                emit(&mut out, VmOp::NewTable, 0, 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
            }
            Opcode::SelfOp => {
                // 先保存原接收者，再取方法；A/B 可重叠也不会让 A 覆盖后的方法值
                // 被误当成 SELF 的第二返回寄存器。
                emit(&mut out, VmOp::PushReg, b as u8, 0, 0, line_pc);
                emit(&mut out, VmOp::PushReg, b as u8, 0, 0, line_pc);
                emit(&mut out, VmOp::PushRk, 0, rk(c), 0, line_pc);
                emit(&mut out, VmOp::GetIndex, 0, 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a.wrapping_add(1), 0, 0, line_pc);
            }
            Opcode::Add | Opcode::Sub | Opcode::Mul | Opcode::Div | Opcode::Mod | Opcode::Pow => {
                emit(&mut out, VmOp::PushRk, 0, rk(b), 0, line_pc);
                emit(&mut out, VmOp::PushRk, 0, rk(c), 0, line_pc);
                let operation = match inst.opcode {
                    Opcode::Add => VmOp::Add,
                    Opcode::Sub => VmOp::Sub,
                    Opcode::Mul => VmOp::Mul,
                    Opcode::Div => VmOp::Div,
                    Opcode::Mod => VmOp::Mod,
                    Opcode::Pow => VmOp::Pow,
                    _ => unreachable!(),
                };
                emit(&mut out, operation, 0, 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
            }
            Opcode::Unm | Opcode::Not | Opcode::Len => {
                emit(&mut out, VmOp::PushReg, b as u8, 0, 0, line_pc);
                let operation = match inst.opcode {
                    Opcode::Unm => VmOp::Neg,
                    Opcode::Not => VmOp::Not,
                    Opcode::Len => VmOp::Len,
                    _ => unreachable!(),
                };
                emit(&mut out, operation, 0, 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
            }
            Opcode::Concat => {
                emit(&mut out, VmOp::PushRange, 0, b, c, line_pc);
                emit(&mut out, VmOp::Concat, (c - b + 1) as u8, 0, 0, line_pc);
                emit(&mut out, VmOp::PopReg, a, 0, 0, line_pc);
            }
            Opcode::Jmp => {
                let target_source = source_jump_target(pc, inst, source_len)?;
                let jump_pc = out.len();
                let offset = mapped_delta(jump_pc, target_source, &starts)?;
                emit(&mut out, VmOp::Jump, 0, offset, 0, line_pc);
            }
            Opcode::Eq | Opcode::Lt | Opcode::Le => {
                let jump = &instructions[pc + 1];
                let target_source = source_jump_target(pc + 1, jump, source_len)?;
                emit(&mut out, VmOp::PushRk, 0, rk(b), 0, line_pc);
                emit(&mut out, VmOp::PushRk, 0, rk(c), 0, line_pc);
                let operation = match inst.opcode {
                    Opcode::Eq => VmOp::Equal,
                    Opcode::Lt => VmOp::Less,
                    Opcode::Le => VmOp::LessEqual,
                    _ => unreachable!(),
                };
                emit(&mut out, operation, 0, 0, 0, line_pc);
                let branch_pc = out.len();
                let offset = mapped_delta(branch_pc, target_source, &starts)?;
                emit(&mut out, VmOp::Branch, u8::from(a != 0), offset, 0, line_pc);
                pc += 1;
            }
            Opcode::Test => {
                let jump = &instructions[pc + 1];
                let target_source = source_jump_target(pc + 1, jump, source_len)?;
                emit(&mut out, VmOp::PushReg, a, 0, 0, line_pc);
                let branch_pc = out.len();
                let offset = mapped_delta(branch_pc, target_source, &starts)?;
                emit(&mut out, VmOp::Branch, u8::from(c != 0), offset, 0, line_pc);
                pc += 1;
            }
            Opcode::TestSet => {
                let jump = &instructions[pc + 1];
                let target_source = source_jump_target(pc + 1, jump, source_len)?;
                if a == 255 {
                    emit(&mut out, VmOp::PushReg, b as u8, 0, 0, line_pc);
                    let branch_pc = out.len();
                    let offset = mapped_delta(branch_pc, target_source, &starts)?;
                    emit(&mut out, VmOp::Branch, u8::from(c != 0), offset, 0, line_pc);
                } else {
                    let branch_pc = out.len();
                    let offset = mapped_delta(branch_pc, target_source, &starts)?;
                    emit(
                        &mut out,
                        if c != 0 { VmOp::BranchSetTrue } else { VmOp::BranchSetFalse },
                        a,
                        b,
                        offset,
                        line_pc,
                    );
                }
                pc += 1;
            }
            Opcode::Call => {
                emit(&mut out, VmOp::CallPack, a, b, c, line_pc);
                emit(&mut out, VmOp::CallExecute, 0, 0, 0, line_pc);
                emit(&mut out, VmOp::CallCollect, 0, 0, 0, line_pc);
            }
            Opcode::TailCall => {
                emit(&mut out, VmOp::CallPack, a, b, 0, line_pc);
                emit(&mut out, VmOp::TailInvoke, 0, 0, 0, line_pc);
            }
            Opcode::Return => {
                if b == 1 {
                    emit(&mut out, VmOp::ReturnNone, 0, 0, 0, line_pc);
                } else if b == 2 {
                    emit(&mut out, VmOp::ReturnOne, a, 0, 0, line_pc);
                } else {
                    emit(&mut out, VmOp::ReturnRange, a, if b == 0 { 0 } else { b - 1 }, 0, line_pc);
                }
            }
            Opcode::ForLoop | Opcode::ForPrep => {
                let target_source = source_jump_target(pc, inst, source_len)?;
                let jump_pc = out.len();
                let offset = mapped_delta(jump_pc, target_source, &starts)?;
                emit(
                    &mut out,
                    if inst.opcode == Opcode::ForPrep { VmOp::ForInit } else { VmOp::ForNext },
                    a,
                    offset,
                    0,
                    line_pc,
                );
            }
            Opcode::TForLoop => {
                let jump = &instructions[pc + 1];
                let target_source = source_jump_target(pc + 1, jump, source_len)?;
                let branch_pc = out.len();
                let offset = mapped_delta(branch_pc, target_source, &starts)?;
                emit(&mut out, VmOp::IteratorNext, a, c, offset, line_pc);
                pc += 1;
            }
            Opcode::SetList => {
                let mut block = c;
                if c == 0 {
                    // 旧式前端以一个附属字承载 SETLIST 的扩展块号；遵循 VM
                    // 中程读取的 A 字段约定，同时兼容正规的 EXTRAARG(Bx) 编码。
                    let extra = &instructions[pc + 1];
                    block = if extra.opcode == Opcode::ExtraArg { extra.b } else { extra.a as i32 };
                    pc += 1;
                }
                emit(&mut out, VmOp::SetList, a, b, block, line_pc);
            }
            Opcode::Close => emit(&mut out, VmOp::CloseUpvalues, a, 0, 0, line_pc),
            Opcode::Closure => {
                let child_index = usize::try_from(b).map_err(|_| error(pc, "闭包原型索引无效"))?;
                let captures = protos[child_index].upvalue_count as usize;
                emit(&mut out, VmOp::MakeClosure, a, b, captures as i32, line_pc);
                for offset in 1..=captures {
                    let desc = &instructions[pc + offset];
                    match desc.opcode {
                        Opcode::Move => emit(&mut out, VmOp::CaptureLocal, 0, desc.b, 0, pc + offset),
                        Opcode::GetUpval => emit(&mut out, VmOp::CaptureUpvalue, 0, desc.b, 0, pc + offset),
                        _ => return Err(error(pc + offset, "闭包捕获描述 opcode 非法")),
                    }
                }
                pc += captures;
            }
            Opcode::VarArg => emit(&mut out, VmOp::Varargs, a, b, 0, line_pc),
            Opcode::ExtraArg => return Err(error(pc, "未消费的 EXTRAARG")),
            other => return Err(error(pc, &format!("尚未定义 Lua 前端 opcode {other:?} 的降级"))),
        }
        pc += 1;
    }

    if out.len() != starts[source_len] {
        return Err(LowerError(format!(
            "自定义 VM 降级长度不一致：预期 {}，实际 {}",
            starts[source_len], out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BytecodeCompiler::ir::chunk::Chunk;

    fn inst(opcode: Opcode, a: u8, b: i32, c: i32) -> Instruction {
        Instruction { data: 0, opcode, a, b, c, line: 1, v_opcode: None, is_junk: false }
    }

    #[test]
    fn custom_opcode_space_is_disjoint_from_lua51_frontend() {
        assert_eq!(CUSTOM_OPCODE_BASE, 90);
        assert_eq!(VM_OPCODE_COUNT, 139);
        for local in 0..CUSTOM_OPCODE_COUNT {
            let global = (CUSTOM_OPCODE_BASE + local) as u8;
            assert!(VmOp::from_global(global).is_some());
        }
        assert!(VmOp::from_global(89).is_none());
        assert!(VmOp::from_global(VM_OPCODE_COUNT as u8).is_none());
    }

    #[test]
    fn arithmetic_and_table_ops_lower_to_mixed_stack_program() {
        let source = vec![
            inst(Opcode::Move, 1, 0, 0),
            inst(Opcode::Add, 2, 1, 130),
            inst(Opcode::GetTable, 3, 2, 128),
            inst(Opcode::Return, 3, 2, 0),
        ];
        let lowered = lower_to_custom(&source, &[]).unwrap();
        let ops: Vec<VmOp> = lowered.iter().map(|item| item.op).collect();
        assert_eq!(
            ops,
            vec![
                VmOp::PushReg,
                VmOp::PopReg,
                VmOp::PushRk,
                VmOp::PushRk,
                VmOp::Add,
                VmOp::PopReg,
                VmOp::PushReg,
                VmOp::PushRk,
                VmOp::GetIndex,
                VmOp::PopReg,
                VmOp::ReturnOne,
            ]
        );
        assert!(lowered.iter().all(|item| item.op.global_id() >= CUSTOM_OPCODE_BASE));
    }

    #[test]
    fn compare_jump_pair_becomes_direct_branch_with_relocated_target() {
        let source = vec![
            inst(Opcode::Eq, 1, 0, 1),
            inst(Opcode::Jmp, 0, 1, 0),
            inst(Opcode::LoadBool, 2, 0, 0),
            inst(Opcode::Return, 2, 2, 0),
        ];
        let lowered = lower_to_custom(&source, &[]).unwrap();
        assert_eq!(lowered[0].op, VmOp::PushRk);
        assert_eq!(lowered[1].op, VmOp::PushRk);
        assert_eq!(lowered[2].op, VmOp::Equal);
        assert_eq!(lowered[3].op, VmOp::Branch);
        assert_eq!(lowered[3].b, 2);
        assert_eq!(lowered[4].op, VmOp::PushBool);
        assert_eq!(lowered[5].op, VmOp::PopReg);
    }

    #[test]
    fn closure_captures_are_explicit_custom_descriptors() {
        let child = Chunk {
            name: String::new(),
            line_defined: 0,
            last_line_defined: 0,
            upvalue_count: 2,
            param_count: 0,
            is_vararg: 0,
            max_stack: 2,
            instructions: vec![],
            constants: vec![],
            protos: vec![],
            lines: vec![],
            locals: vec![],
            upvalues: vec![],
        };
        let source = vec![
            inst(Opcode::Closure, 1, 0, 0),
            inst(Opcode::Move, 0, 2, 0),
            inst(Opcode::GetUpval, 0, 0, 0),
            inst(Opcode::Return, 1, 2, 0),
        ];
        let lowered = lower_to_custom(&source, &[child]).unwrap();
        assert_eq!(lowered[0].op, VmOp::MakeClosure);
        assert_eq!(lowered[0].c, 2);
        assert_eq!(lowered[1].op, VmOp::CaptureLocal);
        assert_eq!(lowered[1].b, 2);
        assert_eq!(lowered[2].op, VmOp::CaptureUpvalue);
        assert_eq!(lowered[3].op, VmOp::ReturnOne);
    }

    #[test]
    fn call_is_lowered_to_explicit_argument_frame_protocol() {
        let source = vec![
            inst(Opcode::Call, 0, 2, 2),
            inst(Opcode::Return, 0, 2, 0),
        ];
        let lowered = lower_to_custom(&source, &[]).unwrap();
        assert_eq!(lowered[0].op, VmOp::CallPack);
        assert_eq!((lowered[0].a, lowered[0].b, lowered[0].c), (0, 2, 2));
        assert_eq!(lowered[1].op, VmOp::CallExecute);
        assert_eq!(lowered[2].op, VmOp::CallCollect);
    }

    #[test]
    fn loadnil_uses_a_shift_safe_range_width() {
        let lowered = lower_to_custom(&[inst(Opcode::LoadNil, 2, 5, 0)], &[]).unwrap();
        assert_eq!(lowered.len(), 1);
        assert_eq!(lowered[0].op, VmOp::ClearRegs);
        assert_eq!((lowered[0].a, lowered[0].b), (2, 3));
    }

    #[test]
    fn selfop_saves_receiver_before_writing_overlapping_destination() {
        let lowered = lower_to_custom(&[inst(Opcode::SelfOp, 1, 1, 128)], &[]).unwrap();
        let ops: Vec<VmOp> = lowered.iter().map(|item| item.op).collect();
        assert_eq!(
            ops,
            vec![
                VmOp::PushReg,
                VmOp::PushReg,
                VmOp::PushRk,
                VmOp::GetIndex,
                VmOp::PopReg,
                VmOp::PopReg,
            ]
        );
        assert_eq!((lowered[0].a, lowered[1].a), (1, 1));
        assert_eq!((lowered[4].a, lowered[5].a), (1, 2));
    }

    #[test]
    fn zero_capture_closure_does_not_consume_the_following_instruction() {
        let child = Chunk {
            name: String::new(),
            line_defined: 0,
            last_line_defined: 0,
            upvalue_count: 0,
            param_count: 0,
            is_vararg: 0,
            max_stack: 2,
            instructions: vec![],
            constants: vec![],
            protos: vec![],
            lines: vec![],
            locals: vec![],
            upvalues: vec![],
        };
        let source = vec![
            inst(Opcode::Closure, 0, 0, 0),
            inst(Opcode::Return, 0, 2, 0),
        ];
        let lowered = lower_to_custom(&source, &[child]).unwrap();
        assert_eq!(lowered[0].op, VmOp::MakeClosure);
        assert_eq!(lowered[0].c, 0);
        assert_eq!(lowered[1].op, VmOp::ReturnOne);
    }

    #[test]
    fn iterator_test_and_jump_are_one_relocated_instruction() {
        let source = vec![
            inst(Opcode::TForLoop, 0, 0, 1),
            inst(Opcode::Jmp, 0, -2, 0),
            inst(Opcode::Return, 0, 1, 0),
        ];
        let lowered = lower_to_custom(&source, &[]).unwrap();
        assert_eq!(lowered[0].op, VmOp::IteratorNext);
        assert_eq!((lowered[0].a, lowered[0].b, lowered[0].c), (0, 1, -1));
        assert_eq!(lowered[1].op, VmOp::ReturnNone);
    }
}
