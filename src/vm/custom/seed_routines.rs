//! Seed-ISA v1 routine data: the per-opcode numeric programs that the generic
//! `SEED` loop (see [`super::seed`]) executes for one custom handler shape.
//!
//! This module owns only the *data*: `routine_for` returns the assembled,
//! pre-validated instruction words for one `(target, opcode)` pair, plus the
//! three hand-written routines (`routine_jump`/`routine_test`/`routine_return`)
//! that the emission paths pin explicitly. Encoding, the label assembler, the
//! build-time validator and the Lua emitters stay in [`super::seed`]; every
//! routine here is validated before it is returned, so a malformed table entry
//! panics at build time instead of shipping. Split out of `seed.rs` with zero
//! change to the emitted script.

use super::seed::*;
use super::Target;
use crate::bytecode::custom::Opcode;

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
