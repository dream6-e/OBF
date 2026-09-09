//! Seed-ISA v1: every custom opcode handler shape expressed as data.
//!
//! P0 replaces the readable per-opcode Lua handler bodies with compact
//! numeric routines executed by one small generic seed loop (`SEED`). The
//! loop is fixed per target; per-handler distinctiveness lives only in the
//! routine tables. This module owns the instruction encoding, the label
//! assembler, the build-time validator, the emission routines, and the Lua
//! loop template.
//!
//! Encoding: each instruction is a `Vec<u32>`; the first word is the op tag
//! (1..=12). Operand references pack as `kind * 1_000_000 + idx * 1000 + off`:
//!
//! | kind | meaning                                  | idx / off              |
//! |-----:|------------------------------------------|------------------------|
//! |    0 | TEMP scratch slot                        | slot 0..=15 / must be 0 |
//! |    1 | REG dynamic register read                | site slot 0..=2 / +off |
//! |    2 | KONST constant read                      | must be 3 / +off       |
//! |    3 | INT small integer literal                | value 0..=999999       |
//! |    4 | PSEUDO site alias                        | 2..=9, never 0/1        |
//! |    5 | SCONST string-pool read                  | < image pool / 0       |
//! |    6 | NIL literal                              | must be 0 / must be 0  |
//! |    7 | HELPER call target                       | < image pool / 0       |
//! |    8 | OPVAL raw site slot                      | < site width / 0       |
//!
//! `MOV` passes values through untouched while `T` normalizes its source to
//! a boolean; mixing them up corrupts falsy returns, so the distinction is
//! pinned by direct differential vectors on both runners.
//!
//! The site block is a trailing-trimmed lane prefix (lanes 1..=N per op).
//! Kinds 0/1 (`pc`/`fid`) of PSEUDO are rejected everywhere: control state
//! can only flow out through RET actions, never in through forged references.
//! PSEUDO 8/9 read the frame's upvalue table and varargs pack.
//!
//! ALU sub-ops are raw mirrors of the classic operators: no type checks, so
//! string coercion, metamethods and raised errors match the classic handler
//! bodies exactly (the operation performed is the same Lua expression).
//!
//! The Lua loop reports failures as `seedfail:<code>` with numeric codes
//! (the template carries exactly one string literal); the codes are:
//!
//! | code | meaning                          | code | meaning                |
//! |-----:|----------------------------------|-----:|------------------------|
//! |    1 | retired (empty is falloff now)   |   19 | helper out of range    |
//! |    2 | ip fell off the routine          |   20 | opval out of range     |
//! |    3 | instruction is not a table       |   21 | NEW length rejected    |
//! |    4 | unknown op tag                   |   22 | ALU sub-op rejected    |
//! |    5 | instruction arity                |   23 | retired (ALU is raw)   |
//! |    6 | reference not a number           |   24 | retired (ALU is raw)   |
//! |    7 | reference kind out of range      |   25 | CALL arg count         |
//! |    8 | destination not TEMP             |   26 | CALL target not fn     |
//! |    9 | TEMP read out of range           |   27 | CALL mode rejected     |
//! |   10 | REG shape rejected               |   28 | helper raised          |
//! |   11 | REG site slot not number         |   29 | spread needs 1 arg     |
//! |   12 | KONST shape rejected             |   30 | spread arg not table   |
//! |   13 | KONST site slot not number       |   31 | spread too many        |
//! |   14 | INT out of range                 |   32 | branch target          |
//! |   15 | forged pc/fid pseudo             |   33 | retired (cond uses 8)  |
//! |   16 | PSEUDO out of range              |   34 | RET action rejected    |
//! |   17 | sconst out of range              |   35 | step budget exhausted  |
//! |   18 | NIL shape rejected               |   36 | store/load index       |

use super::*;

/// Op tags.
pub(crate) const OP_MOV: u32 = 1;
pub(crate) const OP_T: u32 = 2;
pub(crate) const OP_NEW: u32 = 3;
pub(crate) const OP_ALU: u32 = 4;
pub(crate) const OP_CALL: u32 = 5;
pub(crate) const OP_BR: u32 = 6;
pub(crate) const OP_RET: u32 = 7;
/// v1 op tags: register/table write channels plus a raw raise.
pub(crate) const OP_STORE: u32 = 8;
pub(crate) const OP_LOAD: u32 = 9;
pub(crate) const OP_IDX: u32 = 10;
pub(crate) const OP_SET: u32 = 11;
pub(crate) const OP_RAISE: u32 = 12;

/// Reference kinds.
pub(crate) const KIND_TMP: u32 = 0;
pub(crate) const KIND_REG: u32 = 1;
pub(crate) const KIND_KONST: u32 = 2;
pub(crate) const KIND_INT: u32 = 3;
pub(crate) const KIND_PSEUDO: u32 = 4;
pub(crate) const KIND_SCONST: u32 = 5;
pub(crate) const KIND_NIL: u32 = 6;
pub(crate) const KIND_HELPER: u32 = 7;
pub(crate) const KIND_OPVAL: u32 = 8;

/// ALU sub-ops for the 5th word of ALU (always an INT ref).
pub(crate) const ALU_ADD: u32 = 0;
pub(crate) const ALU_SUB: u32 = 1;
pub(crate) const ALU_MUL: u32 = 2;
pub(crate) const ALU_DIV: u32 = 3;
pub(crate) const ALU_MOD: u32 = 4;
pub(crate) const ALU_POW: u32 = 5;
pub(crate) const ALU_UNM: u32 = 6;
pub(crate) const ALU_FDIV: u32 = 7;
pub(crate) const ALU_EQ: u32 = 8;
/// v1 ALU sub-ops: raw mirrors of the classic operators. NOT/LEN ignore
/// their second operand (it is still read, so arity stays uniform).
pub(crate) const ALU_CONCAT: u32 = 9;
pub(crate) const ALU_LT: u32 = 10;
pub(crate) const ALU_LE: u32 = 11;
pub(crate) const ALU_NOT: u32 = 12;
pub(crate) const ALU_LEN: u32 = 13;

/// CALL modes for the 4th word of CALL (always an INT ref).
pub(crate) const CALL_PLAIN: u32 = 0;
pub(crate) const CALL_SPREAD: u32 = 1;
pub(crate) const CALL_PACK: u32 = 2;

/// RET actions (raw numbers, not refs).
pub(crate) const RET_FALLTHROUGH: u32 = 0;
pub(crate) const RET_GOTO: u32 = 1;
pub(crate) const RET_VALUE: u32 = 2;
/// v1 RET action: tail-call frame replacement (multi-value channel).
pub(crate) const RET_TAILENTER: u32 = 3;

/// Site block width: at most 9 lanes `{a,b,c,k,j,skip1,pc,ups,va}`.
pub(crate) const SITE_WIDTH: usize = 9;
/// TEMP scratch slots per seed invocation.
pub(crate) const TEMP_SLOTS: u32 = 16;
/// Largest INT literal (keeps refs exactly 7 decimal digits).
pub(crate) const INT_MAX: u32 = 999_999;
/// Largest CALL argument count.
pub(crate) const CALL_MAX_ARGS: usize = 8;
/// Largest REG/KONST post-offset.
pub(crate) const OFF_MAX: u32 = 255;

/// Locked v1 string-pool contents (SCONST indices).
pub(crate) const STAB_STRS: [&str; 7] = [
    "n",
    "__iter",
    "__call",
    "__obf_proto_u",
    "__obf_proto_nu",
    "function",
    "table",
];
/// Locked v1 helper-pool names in emission order (HELPER indices).
pub(crate) const SEEDH_NAMES: [&str; 15] = [
    "CV", "SV", "Lookup", "Call", "Make", "TN", "TS", "MT", "RG", "G", "W", "P", "Freeze", "TY",
    "NX",
];
pub(crate) const SN_EMIT: usize = 7;
pub(crate) const HN_EMIT: usize = 15;

/// A packed operand reference (`kind * 1_000_000 + idx * 1000 + off`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SeedRef(pub u32);

impl SeedRef {
    pub(crate) fn tmp(slot: u32) -> Self {
        Self(KIND_TMP * 1_000_000 + slot * 1000)
    }
    pub(crate) fn reg(site: u32, off: u32) -> Self {
        Self(KIND_REG * 1_000_000 + site * 1000 + off)
    }
    pub(crate) fn konst(off: u32) -> Self {
        Self(KIND_KONST * 1_000_000 + 3 * 1000 + off)
    }
    pub(crate) fn int(value: u32) -> Self {
        Self(KIND_INT * 1_000_000 + value * 1000)
    }
    pub(crate) fn pseudo(slot: u32) -> Self {
        Self(KIND_PSEUDO * 1_000_000 + slot * 1000)
    }
    pub(crate) fn sconst(ix: u32) -> Self {
        Self(KIND_SCONST * 1_000_000 + ix * 1000)
    }
    pub(crate) fn nilr() -> Self {
        Self(KIND_NIL * 1_000_000)
    }
    pub(crate) fn helper(ix: u32) -> Self {
        Self(KIND_HELPER * 1_000_000 + ix * 1000)
    }
    pub(crate) fn opval(slot: u32) -> Self {
        Self(KIND_OPVAL * 1_000_000 + slot * 1000)
    }
    /// Decode into `(kind, idx, off)`.
    pub(crate) fn decode(self) -> (u32, u32, u32) {
        (self.0 / 1_000_000, self.0 / 1000 % 1000, self.0 % 1000)
    }
}

/// One seed instruction: op tag followed by operand words.
pub(crate) type SeedInstr = Vec<u32>;

/// Assembler input: labels resolve to 1-based Lua instruction indices.
#[derive(Clone, Debug)]
pub(crate) enum AsmItem {
    Label(String),
    Instr(SeedInstr),
    Jif { cond: u32, label: String },
    Jmp { label: String },
}

fn asm_ins(words: Vec<u32>) -> AsmItem {
    AsmItem::Instr(words)
}

fn asm_lab(name: &str) -> AsmItem {
    AsmItem::Label(name.to_owned())
}

fn asm_jif(cond: u32, label: &str) -> AsmItem {
    AsmItem::Jif {
        cond,
        label: label.to_owned(),
    }
}

fn asm_jmp(label: &str) -> AsmItem {
    AsmItem::Jmp {
        label: label.to_owned(),
    }
}

/// Fail-closed construction/validation errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SeedError {
    UndefinedLabel(String),
    DuplicateLabel(String),
    Empty,
    BadOp(u32),
    BadArity { op: u32, len: usize },
    BadRef(u32),
    BadTarget(usize),
    ForbiddenPseudo(u32),
    Falloff,
    TooManyArgs(usize),
    RetAction(u32),
}

/// Assemble labelled items into a routine. `Jif` becomes `[BR, cond, target]`
/// and `Jmp` becomes `[BR, target]`; targets are 1-based Lua indices.
pub(crate) fn assemble(items: &[AsmItem]) -> Result<Vec<SeedInstr>, SeedError> {
    let mut labels: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut index = 0usize;
    for item in items {
        match item {
            AsmItem::Label(name) => {
                if labels.insert(name.as_str(), index + 1).is_some() {
                    return Err(SeedError::DuplicateLabel(name.clone()));
                }
            }
            AsmItem::Instr(_) | AsmItem::Jif { .. } | AsmItem::Jmp { .. } => index += 1,
        }
    }
    let mut prog = Vec::new();
    for item in items {
        match item {
            AsmItem::Label(_) => {}
            AsmItem::Instr(ins) => prog.push(ins.clone()),
            AsmItem::Jif { cond, label } => {
                let target = labels
                    .get(label.as_str())
                    .ok_or_else(|| SeedError::UndefinedLabel(label.clone()))?;
                prog.push(vec![OP_BR, *cond, *target as u32]);
            }
            AsmItem::Jmp { label } => {
                let target = labels
                    .get(label.as_str())
                    .ok_or_else(|| SeedError::UndefinedLabel(label.clone()))?;
                prog.push(vec![OP_BR, *target as u32]);
            }
        }
    }
    Ok(prog)
}

/// Image-dependent limits the validator checks references against.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SeedLimits {
    pub siten: usize,
    pub sn: usize,
    pub hn: usize,
}

fn check_dst(word: u32) -> Result<(), SeedError> {
    let (kind, idx, off) = SeedRef(word).decode();
    if kind != KIND_TMP || idx >= TEMP_SLOTS || off != 0 {
        return Err(SeedError::BadRef(word));
    }
    Ok(())
}

fn check_ref(word: u32, lim: &SeedLimits) -> Result<(), SeedError> {
    let (kind, idx, off) = SeedRef(word).decode();
    let ok = match kind {
        KIND_TMP => idx < TEMP_SLOTS && off == 0,
        KIND_REG => idx <= 2 && off <= OFF_MAX,
        KIND_KONST => idx == 3 && off <= OFF_MAX,
        KIND_INT => idx <= INT_MAX && off == 0,
        KIND_PSEUDO => {
            if idx == 0 || idx == 1 {
                return Err(SeedError::ForbiddenPseudo(word));
            }
            idx <= 9 && off == 0
        }
        KIND_SCONST => (idx as usize) < lim.sn && off == 0,
        KIND_NIL => idx == 0 && off == 0,
        KIND_HELPER => (idx as usize) < lim.hn && off == 0,
        KIND_OPVAL => (idx as usize) < lim.siten && off == 0,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(SeedError::BadRef(word))
    }
}

/// STORE/LOAD indices must be loop counters, literals or site slots; anything
/// dynamic-by-value (REG reads, helper results) is rejected at build time.
/// The template re-checks numeric shape for corrupt data.
fn check_store_idx(word: u32, lim: &SeedLimits) -> Result<(), SeedError> {
    let (kind, idx, off) = SeedRef(word).decode();
    let ok = match kind {
        KIND_TMP => idx < TEMP_SLOTS && off == 0,
        KIND_INT => idx <= INT_MAX && off == 0,
        KIND_OPVAL => (idx as usize) < lim.siten && off == 0,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(SeedError::BadRef(word))
    }
}

fn check_target(word: u32, len: usize) -> Result<(), SeedError> {
    if word >= 1 && (word as usize) <= len {
        Ok(())
    } else {
        Err(SeedError::BadTarget(word as usize))
    }
}

/// Validate a routine structurally: op tags, arities, reference shapes and
/// ranges, branch targets, and the no-falloff tail rule (the last instruction
/// must be RET, an unconditional jump, or RAISE which never returns).
/// v1 emission uses `{ siten: 9, sn: 7, hn: 15 }`.
pub(crate) fn validate(prog: &[SeedInstr], lim: &SeedLimits) -> Result<(), SeedError> {
    if prog.is_empty() {
        return Err(SeedError::Empty);
    }
    for ins in prog {
        let (&op, _) = ins
            .split_first()
            .ok_or(SeedError::BadArity { op: 0, len: 0 })?;
        match op {
            OP_MOV | OP_T | OP_NEW => {
                if ins.len() != 3 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                check_dst(ins[1])?;
                check_ref(ins[2], lim)?;
            }
            OP_ALU => {
                if ins.len() != 5 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                check_dst(ins[1])?;
                check_ref(ins[2], lim)?;
                check_ref(ins[3], lim)?;
                let (kind, sub, off) = SeedRef(ins[4]).decode();
                if kind != KIND_INT || sub > ALU_LEN || off != 0 {
                    return Err(SeedError::BadRef(ins[4]));
                }
            }
            OP_CALL => {
                if ins.len() < 5 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                if ins[4] as usize > CALL_MAX_ARGS {
                    return Err(SeedError::TooManyArgs(ins[4] as usize));
                }
                if ins.len() != 5 + ins[4] as usize {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                check_dst(ins[1])?;
                check_ref(ins[2], lim)?;
                let (kind, mode, off) = SeedRef(ins[3]).decode();
                if kind != KIND_INT || mode > CALL_PACK || off != 0 {
                    return Err(SeedError::BadRef(ins[3]));
                }
                for arg in &ins[5..] {
                    check_ref(*arg, lim)?;
                }
            }
            OP_BR => {
                if ins.len() == 2 {
                    check_target(ins[1], prog.len())?;
                } else if ins.len() == 3 {
                    let (kind, idx, off) = SeedRef(ins[1]).decode();
                    if kind != KIND_TMP || idx >= TEMP_SLOTS || off != 0 {
                        return Err(SeedError::BadRef(ins[1]));
                    }
                    check_target(ins[2], prog.len())?;
                } else {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
            }
            OP_RET => {
                if ins.len() < 2 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                if ins[1] > RET_TAILENTER {
                    return Err(SeedError::RetAction(ins[1]));
                }
                if ins.len() == 2 {
                    if ins[1] != RET_FALLTHROUGH {
                        return Err(SeedError::BadArity { op, len: ins.len() });
                    }
                } else if ins.len() == 3 {
                    if ins[1] == RET_FALLTHROUGH || ins[1] == RET_TAILENTER {
                        return Err(SeedError::BadArity { op, len: ins.len() });
                    }
                    check_ref(ins[2], lim)?;
                } else if ins.len() == 5 {
                    if ins[1] != RET_TAILENTER {
                        return Err(SeedError::BadArity { op, len: ins.len() });
                    }
                    check_ref(ins[2], lim)?;
                    check_ref(ins[3], lim)?;
                    check_ref(ins[4], lim)?;
                } else {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
            }
            OP_STORE => {
                if ins.len() != 3 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                check_store_idx(ins[1], lim)?;
                check_ref(ins[2], lim)?;
            }
            OP_LOAD => {
                if ins.len() != 3 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                check_dst(ins[1])?;
                check_store_idx(ins[2], lim)?;
            }
            OP_IDX => {
                if ins.len() != 4 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                check_dst(ins[1])?;
                check_ref(ins[2], lim)?;
                check_ref(ins[3], lim)?;
            }
            OP_SET => {
                if ins.len() != 4 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
                check_ref(ins[1], lim)?;
                check_ref(ins[2], lim)?;
                check_ref(ins[3], lim)?;
            }
            OP_RAISE => {
                if ins.len() != 1 {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
            }
            _ => return Err(SeedError::BadOp(op)),
        }
    }
    let last = prog.last().expect("nonempty routine");
    let tail_ok = last[0] == OP_RET || last[0] == OP_RAISE || (last[0] == OP_BR && last.len() == 2);
    if !tail_ok {
        return Err(SeedError::Falloff);
    }
    Ok(())
}

/// Jump routine: `RET GOTO site.j`. The fetched `j` operand is already scaled
/// (classic emission rewrites `pc=j*4+1;` to `pc=j;`), so the routine just
/// forwards it through the action channel.
pub(crate) fn routine_jump() -> Result<Vec<SeedInstr>, SeedError> {
    assemble(&[AsmItem::Instr(vec![OP_RET, RET_GOTO, SeedRef::opval(4).0])])
}

/// Test routine: `if not R[a] then RET GOTO site.skip1 else RET FALLTHROUGH`.
/// Classic emission rewrites the body to `pc=skip1`, so the skip-chain value
/// comes from the dispatch-provided site slot.
pub(crate) fn routine_test() -> Result<Vec<SeedInstr>, SeedError> {
    assemble(&[
        AsmItem::Instr(vec![OP_T, SeedRef::tmp(0).0, SeedRef::reg(0, 0).0]),
        AsmItem::Jif {
            cond: SeedRef::tmp(0).0,
            label: "pass".to_owned(),
        },
        AsmItem::Instr(vec![OP_RET, RET_GOTO, SeedRef::opval(5).0]),
        AsmItem::Label("pass".to_owned()),
        AsmItem::Instr(vec![OP_RET, RET_FALLTHROUGH]),
    ])
}

/// Return routine: `RET VALUE R[a]` (MOV passes the raw value through;
/// T would booleanize it and corrupt `return 0` / `return false`).
pub(crate) fn routine_return() -> Result<Vec<SeedInstr>, SeedError> {
    assemble(&[
        AsmItem::Instr(vec![OP_MOV, SeedRef::tmp(0).0, SeedRef::reg(0, 0).0]),
        AsmItem::Instr(vec![OP_RET, RET_VALUE, SeedRef::tmp(0).0]),
    ])
}

/// v1: routine data for an op on a target, or `None` when the op is not
/// supported there (Lua 5.1 has no FloorDivide/Export/Freeze). Every routine
/// is validated against the emission limits before it is returned, so a
/// malformed table entry panics at build time instead of shipping.
pub(crate) fn routine_for(target: Target, op: Opcode) -> Option<Vec<SeedInstr>> {
    use SeedRef as SR;
    if !op.supported(target) {
        return None;
    }
    let luau = target.is_luau();
    let plain = SR::int(CALL_PLAIN).0;
    let prog: Vec<SeedInstr> = match op {
        Opcode::Move => vec![
            vec![OP_STORE, SR::opval(0).0, SR::reg(1, 0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Constant => vec![
            vec![OP_STORE, SR::opval(0).0, SR::konst(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Nil => vec![
            vec![OP_STORE, SR::opval(0).0, SR::nilr().0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::NewCell => vec![
            vec![OP_NEW, SR::tmp(0).0, SR::int(0).0],
            vec![OP_SET, SR::tmp(0).0, SR::int(1).0, SR::reg(1, 0).0],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::ReadCell => vec![
            vec![
                OP_CALL,
                SR::tmp(0).0,
                SR::helper(0).0,
                plain,
                1,
                SR::reg(1, 0).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::WriteCell => vec![
            vec![
                OP_CALL,
                SR::tmp(0).0,
                SR::helper(1).0,
                plain,
                2,
                SR::reg(0, 0).0,
                SR::reg(1, 0).0,
            ],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::ReadUpvalue => vec![
            vec![OP_IDX, SR::tmp(0).0, SR::pseudo(8).0, SR::opval(1).0],
            vec![
                OP_CALL,
                SR::tmp(1).0,
                SR::helper(0).0,
                plain,
                1,
                SR::tmp(0).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(1).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::WriteUpvalue => vec![
            vec![OP_IDX, SR::tmp(0).0, SR::pseudo(8).0, SR::opval(1).0],
            vec![
                OP_CALL,
                SR::tmp(1).0,
                SR::helper(1).0,
                plain,
                2,
                SR::tmp(0).0,
                SR::reg(0, 0).0,
            ],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::ReadGlobal => vec![
            vec![OP_IDX, SR::tmp(0).0, SR::helper(9).0, SR::konst(0).0],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::WriteGlobal => vec![
            vec![OP_SET, SR::helper(9).0, SR::konst(0).0, SR::reg(0, 0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::NewTable => vec![
            vec![OP_NEW, SR::tmp(0).0, SR::int(0).0],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::GetTable => vec![
            vec![OP_IDX, SR::tmp(0).0, SR::reg(1, 0).0, SR::reg(2, 0).0],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::SetTable => vec![
            vec![OP_SET, SR::reg(0, 0).0, SR::reg(1, 0).0, SR::reg(2, 0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Method => vec![
            vec![
                OP_CALL,
                SR::tmp(0).0,
                SR::helper(2).0,
                plain,
                2,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::NewPack => vec![
            vec![OP_NEW, SR::tmp(0).0, SR::int(0).0],
            vec![OP_SET, SR::tmp(0).0, SR::sconst(0).0, SR::int(0).0],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Push => vec![
            vec![OP_MOV, SR::tmp(0).0, SR::reg(0, 0).0],
            vec![OP_IDX, SR::tmp(1).0, SR::tmp(0).0, SR::sconst(0).0],
            vec![
                OP_ALU,
                SR::tmp(2).0,
                SR::tmp(1).0,
                SR::int(1).0,
                SR::int(ALU_ADD).0,
            ],
            vec![OP_SET, SR::tmp(0).0, SR::sconst(0).0, SR::tmp(2).0],
            vec![OP_IDX, SR::tmp(3).0, SR::tmp(0).0, SR::sconst(0).0],
            vec![OP_SET, SR::tmp(0).0, SR::tmp(3).0, SR::reg(1, 0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Extend => assemble(&[
            asm_ins(vec![OP_MOV, SR::tmp(0).0, SR::reg(0, 0).0]),
            asm_ins(vec![OP_MOV, SR::tmp(1).0, SR::reg(1, 0).0]),
            asm_ins(vec![OP_IDX, SR::tmp(2).0, SR::tmp(0).0, SR::sconst(0).0]),
            asm_ins(vec![OP_IDX, SR::tmp(3).0, SR::tmp(1).0, SR::sconst(0).0]),
            // The classic `for j=1,x.n` limit coerces like `TN` (numbers pass,
            // numeric strings convert, anything else errors), so the loop
            // bound goes through the same helper. The final `v.n=n+x.n` keeps
            // the raw `x.n`: `+` coerces exactly like the classic statement.
            asm_ins(vec![
                OP_CALL,
                SR::tmp(9).0,
                SR::helper(5).0,
                plain,
                1,
                SR::tmp(3).0,
            ]),
            asm_ins(vec![OP_MOV, SR::tmp(4).0, SR::int(1).0]),
            asm_lab("loop"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(5).0,
                SR::tmp(4).0,
                SR::tmp(9).0,
                SR::int(ALU_LE).0,
            ]),
            asm_jif(SR::tmp(5).0, "body"),
            asm_jmp("done"),
            asm_lab("body"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(7).0,
                SR::tmp(2).0,
                SR::tmp(4).0,
                SR::int(ALU_ADD).0,
            ]),
            asm_ins(vec![OP_IDX, SR::tmp(6).0, SR::tmp(1).0, SR::tmp(4).0]),
            asm_ins(vec![OP_SET, SR::tmp(0).0, SR::tmp(7).0, SR::tmp(6).0]),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(4).0,
                SR::tmp(4).0,
                SR::int(1).0,
                SR::int(ALU_ADD).0,
            ]),
            asm_jmp("loop"),
            asm_lab("done"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(8).0,
                SR::tmp(2).0,
                SR::tmp(3).0,
                SR::int(ALU_ADD).0,
            ]),
            asm_ins(vec![OP_SET, SR::tmp(0).0, SR::sconst(0).0, SR::tmp(8).0]),
            asm_ins(vec![OP_RET, RET_FALLTHROUGH]),
        ])
        .expect("extend routine must assemble"),
        Opcode::Extract => vec![
            vec![OP_IDX, SR::tmp(0).0, SR::reg(1, 0).0, SR::opval(2).0],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Varargs => vec![
            vec![OP_MOV, SR::tmp(0).0, SR::pseudo(9).0],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Call => vec![
            vec![
                OP_CALL,
                SR::tmp(0).0,
                SR::helper(3).0,
                plain,
                2,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Closure => assemble(&[
            asm_ins(vec![OP_IDX, SR::tmp(0).0, SR::helper(11).0, SR::opval(3).0]),
            asm_ins(vec![OP_NEW, SR::tmp(1).0, SR::int(0).0]),
            asm_ins(vec![OP_IDX, SR::tmp(2).0, SR::tmp(0).0, SR::sconst(4).0]),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(3).0,
                SR::tmp(2).0,
                SR::int(1).0,
                SR::int(ALU_SUB).0,
            ]),
            asm_ins(vec![OP_MOV, SR::tmp(4).0, SR::int(0).0]),
            asm_lab("loop"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(5).0,
                SR::tmp(4).0,
                SR::tmp(3).0,
                SR::int(ALU_LE).0,
            ]),
            asm_jif(SR::tmp(5).0, "body"),
            asm_jmp("mk"),
            asm_lab("body"),
            asm_ins(vec![OP_IDX, SR::tmp(6).0, SR::tmp(0).0, SR::sconst(3).0]),
            asm_ins(vec![OP_IDX, SR::tmp(7).0, SR::tmp(6).0, SR::tmp(4).0]),
            asm_ins(vec![OP_IDX, SR::tmp(8).0, SR::tmp(7).0, SR::int(1).0]),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(9).0,
                SR::tmp(8).0,
                SR::int(1).0,
                SR::int(ALU_EQ).0,
            ]),
            asm_jif(SR::tmp(9).0, "isup"),
            asm_ins(vec![OP_IDX, SR::tmp(10).0, SR::tmp(7).0, SR::int(2).0]),
            asm_ins(vec![OP_LOAD, SR::tmp(11).0, SR::tmp(10).0]),
            asm_ins(vec![OP_SET, SR::tmp(1).0, SR::tmp(4).0, SR::tmp(11).0]),
            asm_jmp("cont"),
            asm_lab("isup"),
            asm_ins(vec![OP_IDX, SR::tmp(10).0, SR::tmp(7).0, SR::int(2).0]),
            asm_ins(vec![OP_IDX, SR::tmp(13).0, SR::pseudo(8).0, SR::tmp(10).0]),
            asm_ins(vec![OP_SET, SR::tmp(1).0, SR::tmp(4).0, SR::tmp(13).0]),
            asm_lab("cont"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(4).0,
                SR::tmp(4).0,
                SR::int(1).0,
                SR::int(ALU_ADD).0,
            ]),
            asm_jmp("loop"),
            asm_lab("mk"),
            asm_ins(vec![
                OP_CALL,
                SR::tmp(14).0,
                SR::helper(4).0,
                plain,
                2,
                SR::opval(3).0,
                SR::tmp(1).0,
            ]),
            asm_ins(vec![OP_STORE, SR::opval(0).0, SR::tmp(14).0]),
            asm_ins(vec![OP_RET, RET_FALLTHROUGH]),
        ])
        .expect("closure routine must assemble"),
        Opcode::Clear => assemble(&[
            asm_ins(vec![OP_MOV, SR::tmp(0).0, SR::opval(0).0]),
            asm_lab("loop"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(1).0,
                SR::tmp(0).0,
                SR::opval(1).0,
                SR::int(ALU_LE).0,
            ]),
            asm_jif(SR::tmp(1).0, "body"),
            asm_jmp("done"),
            asm_lab("body"),
            asm_ins(vec![OP_STORE, SR::tmp(0).0, SR::nilr().0]),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::tmp(0).0,
                SR::int(1).0,
                SR::int(ALU_ADD).0,
            ]),
            asm_jmp("loop"),
            asm_lab("done"),
            asm_ins(vec![OP_RET, RET_FALLTHROUGH]),
        ])
        .expect("clear routine must assemble"),
        Opcode::Add => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_ADD).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Subtract => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_SUB).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Multiply => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_MUL).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Divide => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_DIV).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::FloorDivide => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_FDIV).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Modulo => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_MOD).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Power => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_POW).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Concat => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_CONCAT).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Equal => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_EQ).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Less => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_LT).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::LessEqual => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::reg(2, 0).0,
                SR::int(ALU_LE).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Not => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::int(0).0,
                SR::int(ALU_NOT).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Negate => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::int(0).0,
                SR::int(ALU_UNM).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Length => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(1, 0).0,
                SR::int(0).0,
                SR::int(ALU_LEN).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::NumberPrepare => {
            let mut items = vec![
                asm_ins(vec![
                    OP_CALL,
                    SR::tmp(0).0,
                    SR::helper(5).0,
                    plain,
                    1,
                    SR::reg(0, 0).0,
                ]),
                asm_ins(vec![
                    OP_CALL,
                    SR::tmp(1).0,
                    SR::helper(5).0,
                    plain,
                    1,
                    SR::reg(0, 1).0,
                ]),
                asm_ins(vec![
                    OP_CALL,
                    SR::tmp(2).0,
                    SR::helper(5).0,
                    plain,
                    1,
                    SR::reg(0, 2).0,
                ]),
                asm_ins(vec![
                    OP_ALU,
                    SR::tmp(3).0,
                    SR::tmp(0).0,
                    SR::nilr().0,
                    SR::int(ALU_EQ).0,
                ]),
                asm_jif(SR::tmp(3).0, "bail"),
                asm_ins(vec![
                    OP_ALU,
                    SR::tmp(3).0,
                    SR::tmp(1).0,
                    SR::nilr().0,
                    SR::int(ALU_EQ).0,
                ]),
                asm_jif(SR::tmp(3).0, "bail"),
                asm_ins(vec![
                    OP_ALU,
                    SR::tmp(3).0,
                    SR::tmp(2).0,
                    SR::nilr().0,
                    SR::int(ALU_EQ).0,
                ]),
                asm_jif(SR::tmp(3).0, "bail"),
                asm_ins(vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0]),
                asm_ins(vec![
                    OP_ALU,
                    SR::tmp(5).0,
                    SR::opval(0).0,
                    SR::int(1).0,
                    SR::int(ALU_ADD).0,
                ]),
                asm_ins(vec![OP_STORE, SR::tmp(5).0, SR::tmp(1).0]),
                asm_ins(vec![
                    OP_ALU,
                    SR::tmp(6).0,
                    SR::tmp(5).0,
                    SR::int(1).0,
                    SR::int(ALU_ADD).0,
                ]),
                asm_ins(vec![OP_STORE, SR::tmp(6).0, SR::tmp(2).0]),
            ];
            if !luau {
                // Lua 5.1 starts the control variable one step early.
                items.push(asm_ins(vec![
                    OP_ALU,
                    SR::tmp(4).0,
                    SR::tmp(0).0,
                    SR::tmp(2).0,
                    SR::int(ALU_SUB).0,
                ]));
                items.push(asm_ins(vec![OP_STORE, SR::opval(0).0, SR::tmp(4).0]));
            }
            items.push(asm_ins(vec![OP_RET, RET_FALLTHROUGH]));
            items.push(asm_lab("bail"));
            items.push(asm_ins(vec![OP_RAISE]));
            assemble(&items).expect("numberprepare routine must assemble")
        }
        Opcode::NumberStep => vec![
            vec![
                OP_ALU,
                SR::tmp(0).0,
                SR::reg(0, 0).0,
                SR::reg(0, 2).0,
                SR::int(ALU_ADD).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::NumberTest => assemble(&[
            asm_ins(vec![OP_MOV, SR::tmp(0).0, SR::reg(1, 0).0]),
            asm_ins(vec![OP_MOV, SR::tmp(1).0, SR::reg(1, 1).0]),
            asm_ins(vec![OP_MOV, SR::tmp(2).0, SR::reg(1, 2).0]),
            // `s>0` is `0<s`: identical semantics, same metamethod call.
            asm_ins(vec![
                OP_ALU,
                SR::tmp(3).0,
                SR::int(0).0,
                SR::tmp(2).0,
                SR::int(ALU_LT).0,
            ]),
            asm_jif(SR::tmp(3).0, "pos"),
            // `v>=n` is `n<=v`.
            asm_ins(vec![
                OP_ALU,
                SR::tmp(4).0,
                SR::tmp(1).0,
                SR::tmp(0).0,
                SR::int(ALU_LE).0,
            ]),
            asm_ins(vec![OP_STORE, SR::opval(0).0, SR::tmp(4).0]),
            asm_jmp("done"),
            asm_lab("pos"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(4).0,
                SR::tmp(0).0,
                SR::tmp(1).0,
                SR::int(ALU_LE).0,
            ]),
            asm_ins(vec![OP_STORE, SR::opval(0).0, SR::tmp(4).0]),
            asm_lab("done"),
            asm_ins(vec![OP_RET, RET_FALLTHROUGH]),
        ])
        .expect("numbertest routine must assemble"),
        Opcode::IteratorPrepare => {
            if !luau {
                vec![
                    vec![OP_SET, SR::reg(0, 0).0, SR::sconst(0).0, SR::int(3).0],
                    vec![OP_RET, RET_FALLTHROUGH],
                ]
            } else {
                assemble(&[
                    asm_ins(vec![OP_MOV, SR::tmp(0).0, SR::reg(0, 0).0]),
                    asm_ins(vec![OP_IDX, SR::tmp(1).0, SR::tmp(0).0, SR::int(1).0]),
                    asm_ins(vec![
                        OP_CALL,
                        SR::tmp(2).0,
                        SR::helper(13).0,
                        plain,
                        1,
                        SR::tmp(1).0,
                    ]),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(2).0,
                        SR::sconst(5).0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "tail"),
                    asm_ins(vec![
                        OP_CALL,
                        SR::tmp(4).0,
                        SR::helper(7).0,
                        plain,
                        1,
                        SR::tmp(1).0,
                    ]),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(4).0,
                        SR::nilr().0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "mtok"),
                    asm_ins(vec![
                        OP_CALL,
                        SR::tmp(2).0,
                        SR::helper(13).0,
                        plain,
                        1,
                        SR::tmp(4).0,
                    ]),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(2).0,
                        SR::sconst(6).0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "mtok"),
                    asm_ins(vec![OP_RAISE]),
                    asm_lab("mtok"),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(4).0,
                        SR::nilr().0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "itnil"),
                    asm_ins(vec![
                        OP_CALL,
                        SR::tmp(5).0,
                        SR::helper(8).0,
                        plain,
                        2,
                        SR::tmp(4).0,
                        SR::sconst(1).0,
                    ]),
                    asm_jmp("itchk"),
                    asm_lab("itnil"),
                    asm_ins(vec![OP_MOV, SR::tmp(5).0, SR::nilr().0]),
                    asm_lab("itchk"),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(5).0,
                        SR::nilr().0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "elif1"),
                    // `ar=Z(it(v))` runs through the Call helper: it packs
                    // every return exactly like the classic inline form.
                    asm_ins(vec![OP_NEW, SR::tmp(6).0, SR::int(0).0]),
                    asm_ins(vec![OP_SET, SR::tmp(6).0, SR::sconst(0).0, SR::int(1).0]),
                    asm_ins(vec![OP_SET, SR::tmp(6).0, SR::int(1).0, SR::tmp(1).0]),
                    asm_ins(vec![
                        OP_CALL,
                        SR::tmp(7).0,
                        SR::helper(3).0,
                        plain,
                        2,
                        SR::tmp(5).0,
                        SR::tmp(6).0,
                    ]),
                    asm_ins(vec![OP_MOV, SR::tmp(0).0, SR::tmp(7).0]),
                    asm_ins(vec![OP_IDX, SR::tmp(8).0, SR::tmp(0).0, SR::int(1).0]),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(8).0,
                        SR::nilr().0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "raise2"),
                    asm_jmp("tail"),
                    asm_lab("raise2"),
                    asm_ins(vec![OP_RAISE]),
                    asm_lab("elif1"),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(4).0,
                        SR::nilr().0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "elif2"),
                    asm_ins(vec![
                        OP_CALL,
                        SR::tmp(10).0,
                        SR::helper(8).0,
                        plain,
                        2,
                        SR::tmp(4).0,
                        SR::sconst(2).0,
                    ]),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(10).0,
                        SR::nilr().0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "elif2"),
                    asm_jmp("tail"),
                    asm_lab("elif2"),
                    asm_ins(vec![
                        OP_CALL,
                        SR::tmp(2).0,
                        SR::helper(13).0,
                        plain,
                        1,
                        SR::tmp(1).0,
                    ]),
                    asm_ins(vec![
                        OP_ALU,
                        SR::tmp(3).0,
                        SR::tmp(2).0,
                        SR::sconst(6).0,
                        SR::int(ALU_EQ).0,
                    ]),
                    asm_jif(SR::tmp(3).0, "mkthen"),
                    asm_ins(vec![OP_RAISE]),
                    asm_lab("mkthen"),
                    asm_ins(vec![OP_NEW, SR::tmp(0).0, SR::int(0).0]),
                    asm_ins(vec![OP_SET, SR::tmp(0).0, SR::sconst(0).0, SR::int(3).0]),
                    asm_ins(vec![OP_SET, SR::tmp(0).0, SR::int(1).0, SR::helper(14).0]),
                    asm_ins(vec![OP_SET, SR::tmp(0).0, SR::int(2).0, SR::tmp(1).0]),
                    asm_lab("tail"),
                    asm_ins(vec![OP_SET, SR::tmp(0).0, SR::sconst(0).0, SR::int(3).0]),
                    asm_ins(vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0]),
                    asm_ins(vec![OP_RET, RET_FALLTHROUGH]),
                ])
                .expect("iteratorprepare routine must assemble")
            }
        }
        Opcode::IteratorNext => vec![
            vec![OP_MOV, SR::tmp(0).0, SR::reg(1, 0).0],
            vec![OP_IDX, SR::tmp(1).0, SR::tmp(0).0, SR::int(1).0],
            vec![OP_IDX, SR::tmp(2).0, SR::tmp(0).0, SR::int(2).0],
            vec![OP_IDX, SR::tmp(3).0, SR::tmp(0).0, SR::int(3).0],
            vec![OP_NEW, SR::tmp(4).0, SR::int(0).0],
            vec![OP_SET, SR::tmp(4).0, SR::sconst(0).0, SR::int(2).0],
            vec![OP_SET, SR::tmp(4).0, SR::int(1).0, SR::tmp(2).0],
            vec![OP_SET, SR::tmp(4).0, SR::int(2).0, SR::tmp(3).0],
            vec![
                OP_CALL,
                SR::tmp(5).0,
                SR::helper(3).0,
                plain,
                2,
                SR::tmp(1).0,
                SR::tmp(4).0,
            ],
            vec![OP_IDX, SR::tmp(6).0, SR::tmp(5).0, SR::int(1).0],
            vec![OP_SET, SR::tmp(0).0, SR::int(3).0, SR::tmp(6).0],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(5).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::SetList => assemble(&[
            asm_ins(vec![OP_MOV, SR::tmp(0).0, SR::reg(1, 0).0]),
            asm_ins(vec![OP_MOV, SR::tmp(1).0, SR::reg(2, 0).0]),
            asm_ins(vec![OP_IDX, SR::tmp(2).0, SR::tmp(0).0, SR::sconst(0).0]),
            asm_ins(vec![
                OP_CALL,
                SR::tmp(3).0,
                SR::helper(5).0,
                plain,
                1,
                SR::tmp(2).0,
            ]),
            asm_ins(vec![OP_MOV, SR::tmp(4).0, SR::reg(0, 0).0]),
            asm_ins(vec![OP_MOV, SR::tmp(5).0, SR::int(1).0]),
            asm_lab("loop"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(6).0,
                SR::tmp(5).0,
                SR::tmp(3).0,
                SR::int(ALU_LE).0,
            ]),
            asm_jif(SR::tmp(6).0, "body"),
            asm_jmp("done"),
            asm_lab("body"),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(7).0,
                SR::tmp(1).0,
                SR::tmp(5).0,
                SR::int(ALU_ADD).0,
            ]),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(8).0,
                SR::tmp(7).0,
                SR::int(1).0,
                SR::int(ALU_SUB).0,
            ]),
            asm_ins(vec![OP_IDX, SR::tmp(9).0, SR::tmp(0).0, SR::tmp(5).0]),
            asm_ins(vec![OP_SET, SR::tmp(4).0, SR::tmp(8).0, SR::tmp(9).0]),
            asm_ins(vec![
                OP_ALU,
                SR::tmp(5).0,
                SR::tmp(5).0,
                SR::int(1).0,
                SR::int(ALU_ADD).0,
            ]),
            asm_jmp("loop"),
            asm_lab("done"),
            asm_ins(vec![OP_RET, RET_FALLTHROUGH]),
        ])
        .expect("setlist routine must assemble"),
        Opcode::ToString => vec![
            vec![
                OP_CALL,
                SR::tmp(0).0,
                SR::helper(6).0,
                plain,
                1,
                SR::reg(1, 0).0,
            ],
            vec![OP_STORE, SR::opval(0).0, SR::tmp(0).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Export => vec![
            vec![OP_MOV, SR::tmp(0).0, SR::reg(0, 0).0],
            vec![OP_MOV, SR::tmp(1).0, SR::reg(1, 0).0],
            vec![OP_MOV, SR::tmp(2).0, SR::reg(2, 0).0],
            vec![OP_IDX, SR::tmp(3).0, SR::tmp(0).0, SR::int(1).0],
            vec![OP_SET, SR::tmp(1).0, SR::tmp(2).0, SR::tmp(3).0],
            vec![OP_SET, SR::tmp(0).0, SR::int(1).0, SR::nilr().0],
            vec![OP_SET, SR::tmp(0).0, SR::int(2).0, SR::tmp(1).0],
            vec![OP_SET, SR::tmp(0).0, SR::int(3).0, SR::tmp(2).0],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
        Opcode::Jump => routine_jump().expect("jump routine must assemble"),
        Opcode::Test => routine_test().expect("test routine must assemble"),
        Opcode::Return => routine_return().expect("return routine must assemble"),
        Opcode::TailCall => assemble(&[
            asm_ins(vec![OP_MOV, SR::tmp(0).0, SR::reg(0, 0).0]),
            asm_ins(vec![OP_MOV, SR::tmp(1).0, SR::reg(1, 0).0]),
            asm_ins(vec![OP_IDX, SR::tmp(2).0, SR::helper(10).0, SR::tmp(0).0]),
            asm_ins(vec![OP_T, SR::tmp(3).0, SR::tmp(2).0]),
            asm_jif(SR::tmp(3).0, "enter"),
            // The else branch runs through the Call helper: `W[fn]` misses
            // there too, so it computes exactly `Z(fn(U(ar,1,ar.n)))`.
            asm_ins(vec![
                OP_CALL,
                SR::tmp(4).0,
                SR::helper(3).0,
                plain,
                2,
                SR::tmp(0).0,
                SR::tmp(1).0,
            ]),
            asm_ins(vec![OP_RET, RET_VALUE, SR::tmp(4).0]),
            asm_lab("enter"),
            asm_ins(vec![OP_IDX, SR::tmp(5).0, SR::tmp(2).0, SR::int(1).0]),
            asm_ins(vec![OP_IDX, SR::tmp(6).0, SR::tmp(2).0, SR::int(2).0]),
            asm_ins(vec![
                OP_RET,
                RET_TAILENTER,
                SR::tmp(5).0,
                SR::tmp(1).0,
                SR::tmp(6).0,
            ]),
        ])
        .expect("tailcall routine must assemble"),
        Opcode::Freeze => vec![
            vec![
                OP_CALL,
                SR::tmp(0).0,
                SR::helper(12).0,
                plain,
                1,
                SR::reg(0, 0).0,
            ],
            vec![OP_RET, RET_FALLTHROUGH],
        ],
    };
    validate(
        &prog,
        &SeedLimits {
            siten: SITE_WIDTH,
            sn: SN_EMIT,
            hn: HN_EMIT,
        },
    )
    .unwrap_or_else(|err| panic!("seed routine {} must validate: {err:?}", op.name()));
    Some(prog)
}

/// Emit a routine as a Lua table literal: `{{7,1,8004000},...}`.
pub(crate) fn routine_lua(prog: &[SeedInstr]) -> String {
    let mut s = String::from("{");
    for (i, ins) in prog.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('{');
        for (j, w) in ins.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            s.push_str(&w.to_string());
        }
        s.push('}');
    }
    s.push('}');
    s
}

/// The seed-loop template. `{FDIV}` is the only per-target line (`MF(x/y)` on
/// Lua 5.1, `x//y` on Luau). The loop uses only module-scope helpers
/// (`E`, `TY`, `MF`, `PC`, `U`, `Z`) so no plaintext global survives.
const SEED_LOOP: &str = r#"local SEED=function(prog,site,expect)
local TNUM,TFUN,TTAB,SN,HN,tmp=TY(0),TY(E),TY(STAB),#STAB,#SEEDH,{};
local seedfail=function(m)E("seedfail:"..m)end;
local refd=function(re)
if TY(re)~=TNUM or re<0 then seedfail(6)end;
local vo=re%1000;local t1=(re-vo)/1000;local vi=t1%1000;local kind=(t1-vi)/1000;
if kind<0 or kind>8 or kind%1~=0 then seedfail(7)end;
return kind,vi,vo end;
local rv=function(re)
local kind,vi,vo=refd(re);
if kind==0 then if vi>15 or vo~=0 then seedfail(9)end;return tmp[vi];
elseif kind==1 then if vi>2 or vo>255 or vo%1~=0 then seedfail(10)end;local sl=site[vi+1];if TY(sl)~=TNUM then seedfail(11)end;return R[RX(sl+vo)];
elseif kind==2 then if vi~=3 or vo>255 or vo%1~=0 then seedfail(12)end;local sl=site[4];if TY(sl)~=TNUM then seedfail(13)end;return K[sl+vo];
elseif kind==3 then if vi>999999 or vo~=0 then seedfail(14)end;return vi;
elseif kind==4 then if vi==0 or vi==1 then seedfail(15)end;if vi>9 or vo~=0 then seedfail(16)end;return site[vi];
elseif kind==5 then if vi>=SN or vo~=0 then seedfail(17)end;return STAB[vi+1];
elseif kind==6 then if vi~=0 or vo~=0 then seedfail(18)end;return nil;
elseif kind==7 then if vi>=HN or vo~=0 then seedfail(19)end;return SEEDH[vi+1];
else if vi>=9 or vo~=0 then seedfail(20)end;return site[vi+1];end end;
local dstc=function(re)
local kind,vi,vo=refd(re);
if kind~=0 or vi>15 or vo~=0 then seedfail(8)end;
return vi end;
local stix=function(i)if TY(i)~=TNUM or i%1~=0 then seedfail(36)end;return i end;
local tgtc=function(t)if TY(t)~=TNUM or t<1 or t>#prog or t%1~=0 then seedfail(32)end;return t end;
local ip=1;for n=1,100000 do
if ip<1 or ip>#prog then seedfail(2)end;
local q=prog[ip];
if TY(q)~=TTAB then seedfail(3)end;
local op=q[1];
if op==1 then
if #q~=3 then seedfail(5)end;
tmp[dstc(q[2])]=rv(q[3]);ip=ip+1;
elseif op==2 then
if #q~=3 then seedfail(5)end;
local v=rv(q[3]);tmp[dstc(q[2])]=(v~=nil and v~=false);ip=ip+1;
elseif op==3 then
if #q~=3 then seedfail(5)end;
local l=rv(q[3]);
if TY(l)~=TNUM then seedfail(21)end;
tmp[dstc(q[2])]={};ip=ip+1;
elseif op==4 then
if #q~=5 then seedfail(5)end;
local ok5,oi5,oo5=refd(q[5]);
if ok5~=3 or oi5>13 or oo5~=0 then seedfail(22)end;
local x,y=rv(q[3]),rv(q[4]);
local r;
if oi5==0 then r=x+y;
elseif oi5==1 then r=x-y;
elseif oi5==2 then r=x*y;
elseif oi5==3 then r=x/y;
elseif oi5==4 then r=x%y;
elseif oi5==5 then r=x^y;
elseif oi5==6 then r=-x;
elseif oi5==7 then r={FDIV};
elseif oi5==8 then r=(x==y);
elseif oi5==9 then r=x..y;
elseif oi5==10 then r=x<y;
elseif oi5==11 then r=x<=y;
elseif oi5==12 then r=not x;
else r=#x;end;
tmp[dstc(q[2])]=r;
ip=ip+1;
elseif op==5 then
local nargs=q[5];
if TY(nargs)~=TNUM or nargs<0 or nargs>8 or nargs%1~=0 then seedfail(25)end;
if #q~=5+nargs then seedfail(5)end;
local dv=dstc(q[2]);
local f=rv(q[3]);if TY(f)~=TFUN then seedfail(26)end;
local mk,mv,mo=refd(q[4]);if mk~=3 or mv>2 or mo~=0 then seedfail(27)end;
local ag={};for i=1,nargs do ag[i]=rv(q[5+i])end;
if mv==0 then tmp[dv]=f(U(ag,1,nargs));
elseif mv==1 then if nargs~=1 then seedfail(29)end;local t=ag[1];if TY(t)~=TTAB then seedfail(30)end;local m=t.n;if m==nil then m=#t end;if m>8 then seedfail(31)end;tmp[dv]=f(U(t,1,m));
else tmp[dv]=f(Z(U(ag,1,nargs)));end;
ip=ip+1;
elseif op==6 then
if #q==2 then ip=tgtc(q[2]);
elseif #q==3 then local cv,t=dstc(q[2]),tgtc(q[3]);if tmp[cv] then ip=t else ip=ip+1 end;
else seedfail(5)end;
elseif op==7 then
local a=q[2];
if a~=0 and a~=1 and a~=2 and a~=3 then seedfail(34)end;
expect=expect or 0;if expect~=9 and a~=expect then E()end;
if #q==2 then if a~=0 then seedfail(5)end;return nil,0;
elseif #q==3 then if a==0 or a==3 then seedfail(5)end;return rv(q[3]),a;
elseif #q==5 then if a~=3 then seedfail(5)end;return rv(q[3]),rv(q[4]),rv(q[5]),a;
else seedfail(5)end;
elseif op==8 then
if #q~=3 then seedfail(5)end;
local si=rv(q[2]);R[RX(stix(si))]=rv(q[3]);ip=ip+1;
elseif op==9 then
if #q~=3 then seedfail(5)end;
local li=rv(q[3]);tmp[dstc(q[2])]=R[RX(stix(li))];ip=ip+1;
elseif op==10 then
if #q~=4 then seedfail(5)end;
tmp[dstc(q[2])]=rv(q[3])[rv(q[4])];ip=ip+1;
elseif op==11 then
if #q~=4 then seedfail(5)end;
rv(q[2])[rv(q[3])]=rv(q[4]);ip=ip+1;
elseif op==12 then
if #q~=1 then seedfail(5)end;
E();ip=ip+1;
else seedfail(4)end;
end seedfail(35);end;"#;

/// Emit the full seed-loop statement for a target:
/// `local SEED=function(prog,site,expect)...end;` (spliced inside H,
/// R/RX/K arrive as H-locals so arms carry only the site block).
pub(crate) fn seed_loop_lua(target: Target) -> String {
    let fdiv = if target.is_luau() { "x//y" } else { "MF(x/y)" };
    SEED_LOOP.replace("{FDIV}", fdiv)
}

/// Bit for an op in the routine-table usage mask.
pub(crate) fn seed_op_bit(op: Opcode) -> u64 {
    1u64 << (op as usize)
}

/// v1: seed prelude with a per-image routine table plus populated pools.
/// `used` carries one bit per opcode (`seed_op_bit`); unused slots emit `0`.
pub(crate) fn seed_prelude_lua_v1(target: Target, seed: u64, used: u64) -> String {
    let mut slots = Vec::with_capacity(Opcode::ALL.len());
    for (index, op) in Opcode::ALL.iter().copied().enumerate() {
        debug_assert_eq!(op as usize, index);
        let bit = seed_op_bit(op);
        match (used & bit != 0, routine_for(target, op)) {
            (true, Some(prog)) => slots.push(routine_lua(&prog)),
            _ => slots.push("0".to_owned()),
        }
    }
    let stab = STAB_STRS
        .iter()
        .enumerate()
        .map(|(ix, s)| {
            // Dynamic keys must use the post-`shorten` spellings: the field
            // pass only rewrites static dot/constructor markers, never the
            // string literals the seed routines index with.
            let spelling = match *s {
                "__obf_proto_u" => crate::vm::fields::short_field("u", target, seed),
                "__obf_proto_nu" => crate::vm::fields::short_field("nu", target, seed),
                _ => Ok(s.to_string()),
            }
            .unwrap_or_else(|err| panic!("seed STAB field {ix} must shorten: {err:?}"));
            format!("\"{spelling}\"")
        })
        .collect::<Vec<_>>()
        .join(",");
    let seedh = SEEDH_NAMES.join(",");
    // STAB/SEEDH/SEEDT stay top-level; the loop is spliced inside H (see
    // emit.rs) so SEED closes over H-locals R/RX/K and the pools.
    format!(
        r"local STAB={{{}}};
local SEEDH={{{}}};
local SEEDT={{{}}};
",
        stab,
        seedh,
        slots.join(","),
    )
}

/// v1: fragment arm for an op on a target, or `None` when the op is not
/// supported there. SEED is an H-local closing over R/RX/K, so the arm
/// carries only a trailing-trimmed lane-prefix site block.
pub(crate) fn seed_arm_lua_for(target: Target, op: Opcode) -> Option<String> {
    if !op.supported(target) {
        return None;
    }
    // SEEDT slots are positional in a 1-based Lua array: op N's routine is the
    // (N+1)-th constructor entry (holes are 0, never nil, so length is exact).
    let i = op as usize + 1;
    // Trailing-trimmed sites: each arm carries only the lanes its routine
    // reads (trailing unused lanes omitted). The lane-subset test pins
    // routine-lane-use ⊆ arm-lanes for every (target, op), so trimming
    // can never silently starve a routine (fail-closed by construction).
    let site = match op {
        Opcode::Nil
        | Opcode::NewTable
        | Opcode::NewPack
        | Opcode::NumberPrepare
        | Opcode::NumberStep
        | Opcode::IteratorPrepare
        | Opcode::Return
        | Opcode::Freeze => "{a}",
        Opcode::Move
        | Opcode::NewCell
        | Opcode::ReadCell
        | Opcode::WriteCell
        | Opcode::Push
        | Opcode::Extend
        | Opcode::Clear
        | Opcode::Not
        | Opcode::Negate
        | Opcode::Length
        | Opcode::NumberTest
        | Opcode::IteratorNext
        | Opcode::ToString
        | Opcode::TailCall => "{a,b}",
        Opcode::GetTable
        | Opcode::SetTable
        | Opcode::Method
        | Opcode::Extract
        | Opcode::Call
        | Opcode::Add
        | Opcode::Subtract
        | Opcode::Multiply
        | Opcode::Divide
        | Opcode::FloorDivide
        | Opcode::Modulo
        | Opcode::Power
        | Opcode::Concat
        | Opcode::Equal
        | Opcode::Less
        | Opcode::LessEqual
        | Opcode::SetList
        | Opcode::Export => "{a,b,c}",
        Opcode::Constant | Opcode::ReadGlobal | Opcode::WriteGlobal => "{a,0,0,k}",
        Opcode::ReadUpvalue | Opcode::WriteUpvalue => "{a,b,0,0,0,0,0,ups}",
        Opcode::Closure => "{a,0,0,k,0,0,0,ups}",
        Opcode::Test => "{a,0,0,0,0,skip1,pc}",
        Opcode::Jump => "{0,0,0,0,j,skip1,pc}",
        Opcode::Varargs => "{a,0,0,0,0,0,0,0,va}",
    };
    if matches!(op, Opcode::TailCall) {
        return Some(format!(
            "local v1,v2,v3,act=SEED(SEEDT[{i}],{site},9);act=act or v2;\
             if act==3 then fid,args,ups=v1,v2,v3;break;\
             elseif act==2 then return v1;else E()end;"
        ));
    }
    // Frame state arrives via H-locals; the expected action rides as the
    // trailing argument (nil means 0, 9 disables the check for Test and
    // TailCall). SEED returns value-first so Jump/Return need no locals.
    Some(match op {
        Opcode::Jump => format!("pc=SEED(SEEDT[{i}],{site},1);"),
        Opcode::Test => format!(
            "local av,act=SEED(SEEDT[{i}],{site},9);if act==1 then pc=av elseif act~=0 then E()end;"
        ),
        Opcode::Return => {
            format!("return SEED(SEEDT[{i}],{site},2);")
        }
        _ => format!("SEED(SEEDT[{i}],{site});"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lim() -> SeedLimits {
        SeedLimits {
            siten: SITE_WIDTH,
            sn: 0,
            hn: 0,
        }
    }

    #[test]
    fn seed_ref_roundtrips_through_decode() {
        assert_eq!(SeedRef::tmp(3).decode(), (0, 3, 0));
        assert_eq!(SeedRef::reg(2, 9).decode(), (1, 2, 9));
        assert_eq!(SeedRef::konst(1).decode(), (2, 3, 1));
        assert_eq!(SeedRef::int(7).decode(), (3, 7, 0));
        assert_eq!(SeedRef::opval(6).decode(), (8, 6, 0));
        assert_eq!(SeedRef::tmp(0).0, 0);
        assert_eq!(SeedRef::opval(4).0, 8_004_000);
        assert_eq!(SeedRef::reg(0, 0).0, 1_000_000);
    }

    #[test]
    fn seed_asm_resolves_forward_and_backward_labels() {
        let prog = assemble(&[
            AsmItem::Instr(vec![OP_T, SeedRef::tmp(0).0, SeedRef::reg(0, 0).0]),
            AsmItem::Jif {
                cond: SeedRef::tmp(0).0,
                label: "done".to_owned(),
            },
            AsmItem::Instr(vec![OP_RET, RET_GOTO, SeedRef::opval(5).0]),
            AsmItem::Label("done".to_owned()),
            AsmItem::Instr(vec![OP_RET, RET_FALLTHROUGH]),
        ])
        .unwrap();
        assert_eq!(
            prog,
            vec![
                vec![2, 0, 1_000_000],
                vec![6, 0, 4],
                vec![7, 1, 8_005_000],
                vec![7, 0],
            ]
        );
        let back = assemble(&[
            AsmItem::Label("top".to_owned()),
            AsmItem::Instr(vec![OP_MOV, SeedRef::tmp(0).0, SeedRef::nilr().0]),
            AsmItem::Jmp {
                label: "top".to_owned(),
            },
        ])
        .unwrap();
        assert_eq!(back, vec![vec![1, 0, 6_000_000], vec![6, 1]]);
    }

    #[test]
    fn seed_asm_rejects_duplicate_and_undefined_labels() {
        assert_eq!(
            assemble(&[
                AsmItem::Label("x".to_owned()),
                AsmItem::Label("x".to_owned()),
                AsmItem::Instr(vec![OP_RET, RET_FALLTHROUGH]),
            ]),
            Err(SeedError::DuplicateLabel("x".to_owned()))
        );
        assert_eq!(
            assemble(&[AsmItem::Jmp {
                label: "nope".to_owned()
            }]),
            Err(SeedError::UndefinedLabel("nope".to_owned()))
        );
        assert_eq!(
            assemble(&[AsmItem::Jif {
                cond: SeedRef::tmp(0).0,
                label: "nope".to_owned()
            }]),
            Err(SeedError::UndefinedLabel("nope".to_owned()))
        );
    }

    #[test]
    fn seed_routine_data_goldens() {
        assert_eq!(routine_lua(&routine_jump().unwrap()), "{{7,1,8004000}}");
        assert_eq!(
            routine_lua(&routine_test().unwrap()),
            "{{2,0,1000000},{6,0,4},{7,1,8005000},{7,0}}"
        );
        assert_eq!(
            routine_lua(&routine_return().unwrap()),
            "{{1,0,1000000},{7,2,0}}"
        );
    }

    #[test]
    fn seed_slice1_routines_validate() {
        for r in [routine_jump(), routine_test(), routine_return()] {
            validate(&r.unwrap(), &lim()).unwrap();
        }
    }

    #[test]
    fn seed_validate_accepts_all_op_shapes() {
        let wide = SeedLimits {
            siten: SITE_WIDTH,
            sn: 2,
            hn: 3,
        };
        let ok: Vec<Vec<SeedInstr>> = vec![
            vec![vec![1, 0, 1_000_000], vec![7, 0]],
            vec![vec![2, 1000, 2_003_000], vec![7, 0]],
            vec![vec![3, 0, 3_003_000], vec![7, 0]],
            vec![vec![4, 0, 3_006_000, 3_007_000, 3_000_000], vec![7, 0]],
            vec![vec![4, 0, 3_006_000, 3_007_000, 3_008_000], vec![7, 0]],
            vec![
                vec![5, 0, 7_000_000, 3_000_000, 2, 3_001_000, 3_002_000],
                vec![7, 0],
            ],
            vec![vec![5, 0, 7_001_000, 3_001_000, 0], vec![7, 0]],
            vec![vec![5, 0, 0, 3_002_000, 1, 3_005_000], vec![7, 0]],
            vec![vec![6, 2], vec![7, 0]],
            vec![vec![6, 0, 2], vec![7, 0]],
            vec![vec![7, 2, 8_000_000]],
            vec![vec![1, 0, 4_002_000], vec![7, 0]],
            vec![vec![1, 0, 5_001_000], vec![7, 0]],
            vec![vec![1, 0, 1_002_255], vec![7, 0]],
        ];
        for (i, prog) in ok.iter().enumerate() {
            assert!(validate(prog, &wide).is_ok(), "case {i} rejected: {prog:?}");
        }
    }

    #[test]
    fn seed_validate_rejects_corrupt_routines() {
        let bad: Vec<Vec<SeedInstr>> = vec![
            vec![],
            vec![vec![9]],
            vec![vec![0, 0]],
            vec![vec![1, 0]],
            vec![vec![3, 0]],
            vec![vec![3, 0, 3_003_000, 6_000_000]],
            vec![vec![1, 0, 9_000_000]],
            vec![vec![1, 16_000, 0]],
            vec![vec![1, 1_000_000, 0]],
            vec![vec![1, 1, 0]],
            vec![vec![1, 0, 4_000_000]],
            vec![vec![1, 0, 4_001_000]],
            vec![vec![1, 0, 4_010_000]],
            vec![vec![1, 0, 2_000_000]],
            vec![vec![1, 0, 1_003_000]],
            vec![vec![1, 0, 1_000_256]],
            vec![vec![1, 6_001_000, 0]],
            vec![vec![1, 0, 8_009_000]],
            vec![vec![1, 0, 8_000_001]],
            vec![vec![1, 0, 7_000_000]],
            vec![vec![1, 0, 5_000_000]],
            vec![vec![1, 0, 1_003_000_000]],
            vec![vec![6, 0, 99]],
            vec![vec![6, 0]],
            vec![vec![6, 1_000_000, 1]],
            vec![vec![6, 0, 1], vec![6, 0, 1]],
            vec![vec![1, 0, 0]],
            vec![vec![5, 0, 7_000_000, 3_000_000, 9]],
            vec![vec![5, 0, 7_000_000, 3_003_000, 0]],
            vec![vec![5, 0, 7_000_000, 0, 0]],
            vec![vec![4, 0, 3_001_000, 3_002_000, 0]],
            vec![vec![4, 0, 3_001_000, 3_002_000, 3_014_000]],
            vec![vec![7, 4]],
            vec![vec![7]],
            vec![vec![7, 1]],
            vec![vec![7, 0, 0]],
        ];
        for (i, prog) in bad.iter().enumerate() {
            assert!(
                validate(prog, &lim()).is_err(),
                "case {i} accepted: {prog:?}"
            );
        }
        assert_eq!(
            validate(&[vec![1, 0, 4_000_000], vec![7, 0]], &lim()),
            Err(SeedError::ForbiddenPseudo(4_000_000))
        );
        assert_eq!(
            validate(&[vec![1, 0, 4_001_000], vec![7, 0]], &lim()),
            Err(SeedError::ForbiddenPseudo(4_001_000))
        );
    }

    #[test]
    fn seed_template_is_dual_target_clean() {
        let lua51 = seed_loop_lua(Target::Lua51);
        let luau = seed_loop_lua(Target::Luau);
        assert!(lua51.starts_with("local SEED=function(prog,site,expect)"));
        assert!(luau.starts_with("local SEED=function(prog,site,expect)"));
        // Floordiv must be per-target: Lua 5.1 has no `//` operator.
        assert!(!lua51.contains("//"), "lua51 template uses //");
        assert!(lua51.contains("MF("), "lua51 template lacks floor");
        assert!(luau.contains("//"), "luau template lacks //");
        assert!(!luau.contains("MF("), "luau template uses MF");
        // Both must carry the fail-closed budget and validator.
        for (name, body) in [("lua51", lua51.as_str()), ("luau", luau.as_str())] {
            assert!(body.contains("seedfail"), "{name} lacks seedfail");
            assert!(body.contains("100000"), "{name} lacks budget");
        }
    }

    #[test]
    fn seed_routine_lane_use_is_within_trimmed_arm_sites() {
        // Every trimmed arm site is a lane PREFIX (lanes 1..=N); every packed
        // ref word (>= 1_000_000) decodes to the site lane it reads, while raw
        // words (tags/targets/actions/counts, all < 1M) decode to kind 0 (no
        // lane). If a routine touched a trimmed lane the arm would feed it the
        // wrong slot and diverge silently -- this test fails closed instead.
        for target in [Target::Lua51, Target::Luau] {
            for op in Opcode::ALL {
                let routine = match routine_for(target, *op) {
                    Some(r) => r,
                    None => {
                        assert!(seed_arm_lua_for(target, *op).is_none());
                        continue;
                    }
                };
                let arm = seed_arm_lua_for(target, *op).unwrap();
                let open = arm.find('{').unwrap();
                let close = arm[open..].find('}').unwrap() + open;
                let lanes_present = arm[open + 1..close].split(',').count() as u32;
                for ins in &routine {
                    for word in ins {
                        let (kind, idx, _) = SeedRef(*word).decode();
                        let lane = match kind {
                            KIND_REG | KIND_OPVAL => Some(idx + 1),
                            KIND_KONST => Some(4),
                            KIND_PSEUDO => Some(idx),
                            _ => None,
                        };
                        if let Some(lane) = lane {
                            assert!(
                                (1..=lanes_present).contains(&lane),
                                "{target:?} {}: routine reads lane {lane} but arm carries {lanes_present}",
                                op.name(),
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn seed_template_stays_under_size_cap() {
        for target in [Target::Lua51, Target::Luau] {
            let body = seed_loop_lua(target);
            assert!(
                body.len() <= 12_000,
                "{target} seed loop is {}B over cap",
                body.len()
            );
        }
    }

    #[test]
    fn seed_validate_accepts_v1_op_shapes() {
        let wide = SeedLimits {
            siten: 9,
            sn: 7,
            hn: 15,
        };
        let ok: Vec<Vec<SeedInstr>> = vec![
            vec![vec![8, 3_005_000, 1_000_000], vec![7, 0]],
            vec![vec![8, 0, 3_001_000], vec![7, 0]],
            vec![vec![8, 8_000_000, 6_000_000], vec![7, 0]],
            vec![vec![9, 0, 3_002_000], vec![7, 0]],
            vec![vec![9, 1000, 0], vec![7, 0]],
            vec![vec![10, 0, 1000, 3_001_000], vec![7, 0]],
            vec![vec![10, 0, 4_008_000, 8_001_000], vec![7, 0]],
            vec![vec![11, 1000, 3_001_000, 3_002_000], vec![7, 0]],
            vec![vec![12], vec![7, 0]],
            vec![vec![7, 3, 0, 1000, 2000]],
            vec![vec![4, 0, 3_001_000, 3_002_000, 3_009_000], vec![7, 0]],
            vec![vec![4, 0, 3_001_000, 3_002_000, 3_010_000], vec![7, 0]],
            vec![vec![4, 0, 3_001_000, 3_002_000, 3_011_000], vec![7, 0]],
            vec![vec![4, 0, 3_001_000, 3_000_000, 3_012_000], vec![7, 0]],
            vec![vec![4, 0, 3_001_000, 3_000_000, 3_013_000], vec![7, 0]],
            vec![vec![1, 0, 4_008_000], vec![7, 0]],
            vec![vec![1, 0, 4_009_000], vec![7, 0]],
            vec![vec![1, 0, 8_008_000], vec![7, 0]],
        ];
        for (i, prog) in ok.iter().enumerate() {
            assert!(
                validate(prog, &wide).is_ok(),
                "v1 case {i} rejected: {prog:?}"
            );
        }
    }

    #[test]
    fn seed_validate_rejects_v1_malformations() {
        let wide = SeedLimits {
            siten: 9,
            sn: 7,
            hn: 15,
        };
        // Each case pins the exact variant so a wrong-reason reject still fails.
        assert_eq!(
            validate(&[vec![8, 3_001_000], vec![7, 0]], &wide),
            Err(SeedError::BadArity { op: 8, len: 2 })
        );
        assert_eq!(
            validate(&[vec![8, 1_000_000, 0], vec![7, 0]], &wide),
            Err(SeedError::BadRef(1_000_000))
        );
        assert_eq!(
            validate(&[vec![9, 0], vec![7, 0]], &wide),
            Err(SeedError::BadArity { op: 9, len: 2 })
        );
        assert_eq!(
            validate(&[vec![9, 0, 7_000_000], vec![7, 0]], &wide),
            Err(SeedError::BadRef(7_000_000))
        );
        assert_eq!(
            validate(&[vec![10, 0, 1000], vec![7, 0]], &wide),
            Err(SeedError::BadArity { op: 10, len: 3 })
        );
        assert_eq!(
            validate(&[vec![11, 0, 1000], vec![7, 0]], &wide),
            Err(SeedError::BadArity { op: 11, len: 3 })
        );
        assert_eq!(
            validate(&[vec![12, 3_001_000], vec![7, 0]], &wide),
            Err(SeedError::BadArity { op: 12, len: 2 })
        );
        assert_eq!(
            validate(&[vec![7, 3, 0], vec![7, 0]], &wide),
            Err(SeedError::BadArity { op: 7, len: 3 })
        );
        assert_eq!(
            validate(&[vec![7, 4, 0]], &wide),
            Err(SeedError::RetAction(4))
        );
        assert_eq!(
            validate(
                &[vec![4, 0, 3_001_000, 3_002_000, 3_014_000], vec![7, 0]],
                &wide
            ),
            Err(SeedError::BadRef(3_014_000))
        );
    }

    #[test]
    fn seed_emission_routines_all_validate() {
        for target in [Target::Lua51, Target::Luau] {
            for op in Opcode::ALL.iter().copied() {
                assert_eq!(
                    routine_for(target, op).is_some(),
                    op.supported(target),
                    "{target} {}: routine coverage mismatch",
                    op.name()
                );
            }
        }
    }
}
