//! Seed-ISA v0: every custom opcode handler shape expressed as data.
//!
//! P0 replaces the 47 readable per-opcode Lua handler bodies with compact
//! numeric routines executed by one small generic seed loop (`SEED`). The
//! loop is fixed per target; per-handler distinctiveness lives only in the
//! routine tables. This module owns the instruction encoding, the label
//! assembler, the build-time validator, the fixed slice routines, and the
//! Lua loop template.
//!
//! Encoding: each instruction is a `Vec<u32>`; the first word is the op tag
//! (1..=7). Operand references pack as `kind * 1_000_000 + idx * 1000 + off`:
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
//! The site block is always 7 numbers: `{a,b,c,k,j,skip1,pc}`. Kinds 0/1
//! (`pc`/`fid`) of PSEUDO are rejected everywhere: control state can only
//! flow out through RET actions, never in through forged references.
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
//! |    5 | instruction arity                |   23 | ALU operand not number |
//! |    6 | reference not a number           |   24 | floordiv by zero       |
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
//! |   18 | NIL shape rejected               |      |                        |

use super::*;

/// Op tags.
pub(crate) const OP_MOV: u32 = 1;
pub(crate) const OP_T: u32 = 2;
pub(crate) const OP_NEW: u32 = 3;
pub(crate) const OP_ALU: u32 = 4;
pub(crate) const OP_CALL: u32 = 5;
pub(crate) const OP_BR: u32 = 6;
pub(crate) const OP_RET: u32 = 7;

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

/// CALL modes for the 4th word of CALL (always an INT ref).
pub(crate) const CALL_PLAIN: u32 = 0;
pub(crate) const CALL_SPREAD: u32 = 1;
pub(crate) const CALL_PACK: u32 = 2;

/// RET actions (raw numbers, not refs).
pub(crate) const RET_FALLTHROUGH: u32 = 0;
pub(crate) const RET_GOTO: u32 = 1;
pub(crate) const RET_VALUE: u32 = 2;

/// Site block width: `{a,b,c,k,j,skip1,pc}`.
pub(crate) const SITE_WIDTH: usize = 7;
/// TEMP scratch slots per seed invocation.
pub(crate) const TEMP_SLOTS: u32 = 16;
/// Largest INT literal (keeps refs exactly 7 decimal digits).
pub(crate) const INT_MAX: u32 = 999_999;
/// Largest CALL argument count.
pub(crate) const CALL_MAX_ARGS: usize = 8;
/// Largest REG/KONST post-offset.
pub(crate) const OFF_MAX: u32 = 255;

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

fn check_target(word: u32, len: usize) -> Result<(), SeedError> {
    if word >= 1 && (word as usize) <= len {
        Ok(())
    } else {
        Err(SeedError::BadTarget(word as usize))
    }
}

/// Validate a routine structurally: op tags, arities, reference shapes and
/// ranges, branch targets, and the no-falloff tail rule (the last instruction
/// must be RET or an unconditional jump). Slice-1 emission uses
/// `{ siten: 7, sn: 0, hn: 0 }`.
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
                if kind != KIND_INT || sub > ALU_EQ || off != 0 {
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
                if ins[1] > RET_VALUE {
                    return Err(SeedError::RetAction(ins[1]));
                }
                if ins.len() == 2 {
                    if ins[1] != RET_FALLTHROUGH {
                        return Err(SeedError::BadArity { op, len: ins.len() });
                    }
                } else if ins.len() == 3 {
                    if ins[1] == RET_FALLTHROUGH {
                        return Err(SeedError::BadArity { op, len: ins.len() });
                    }
                    check_ref(ins[2], lim)?;
                } else {
                    return Err(SeedError::BadArity { op, len: ins.len() });
                }
            }
            _ => return Err(SeedError::BadOp(op)),
        }
    }
    let last = prog.last().expect("nonempty routine");
    let tail_ok = last[0] == OP_RET || (last[0] == OP_BR && last.len() == 2);
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
// T would booleanize it and corrupt `return 0` / `return false`).
pub(crate) fn routine_return() -> Result<Vec<SeedInstr>, SeedError> {
    assemble(&[
        AsmItem::Instr(vec![OP_MOV, SeedRef::tmp(0).0, SeedRef::reg(0, 0).0]),
        AsmItem::Instr(vec![OP_RET, RET_VALUE, SeedRef::tmp(0).0]),
    ])
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
const SEED_LOOP: &str = r#"local SEED=function(prog,site,R,RX,K,STAB,SEEDH)
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
else if vi>=7 or vo~=0 then seedfail(20)end;return site[vi+1];end end;
local dstc=function(re)
local kind,vi,vo=refd(re);
if kind~=0 or vi>15 or vo~=0 then seedfail(8)end;
return vi end;
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
if ok5~=3 or oi5>8 or oo5~=0 then seedfail(22)end;
local x,y=rv(q[3]),rv(q[4]);
if oi5==8 then tmp[dstc(q[2])]=(x==y);
else
if TY(x)~=TNUM or TY(y)~=TNUM then seedfail(23)end;
local r;
if oi5==0 then r=x+y;
elseif oi5==1 then r=x-y;
elseif oi5==2 then r=x*y;
elseif oi5==3 then r=x/y;
elseif oi5==4 then r=x%y;
elseif oi5==5 then r=x^y;
elseif oi5==6 then r=-x;
else if y==0 then seedfail(24)end;r={FDIV};end;
tmp[dstc(q[2])]=r;end;
ip=ip+1;
elseif op==5 then
local nargs=q[5];
if TY(nargs)~=TNUM or nargs<0 or nargs>8 or nargs%1~=0 then seedfail(25)end;
if #q~=5+nargs then seedfail(5)end;
local dv=dstc(q[2]);
local f=rv(q[3]);if TY(f)~=TFUN then seedfail(26)end;
local mk,mv,mo=refd(q[4]);if mk~=3 or mv>2 or mo~=0 then seedfail(27)end;
local ag={};for i=1,nargs do ag[i]=rv(q[5+i])end;
if mv==0 then local ok,res=PC(f,U(ag,1,nargs));if not ok then seedfail(28)end;tmp[dv]=res;
elseif mv==1 then if nargs~=1 then seedfail(29)end;local t=ag[1];if TY(t)~=TTAB then seedfail(30)end;local m=#t;if m>8 then seedfail(31)end;local ok,res=PC(f,U(t,1,m));if not ok then seedfail(28)end;tmp[dv]=res;
else local ok,res=PC(f,Z(U(ag,1,nargs)));if not ok then seedfail(28)end;tmp[dv]=res;end;
ip=ip+1;
elseif op==6 then
if #q==2 then ip=tgtc(q[2]);
elseif #q==3 then local cv,t=dstc(q[2]),tgtc(q[3]);if tmp[cv] then ip=t else ip=ip+1 end;
else seedfail(5)end;
elseif op==7 then
local a=q[2];
if a~=0 and a~=1 and a~=2 then seedfail(34)end;
if #q==2 then if a~=0 then seedfail(5)end;return 0,nil;
elseif #q==3 then if a==0 then seedfail(5)end;return a,rv(q[3]);
else seedfail(5)end;
else seedfail(4)end;
end seedfail(35);end;"#;

/// Emit the full seed-loop statement for a target:
/// `local SEED=function(prog,site,R,RX,K,STAB,SEEDH)...end;`
pub(crate) fn seed_loop_lua(target: Target) -> String {
    let fdiv = if target.is_luau() { "x//y" } else { "MF(x/y)" };
    SEED_LOOP.replace("{FDIV}", fdiv)
}

fn checked_routine(routine: Result<Vec<SeedInstr>, SeedError>, name: &str) -> Vec<SeedInstr> {
    let prog = routine.unwrap_or_else(|err| panic!("seed {name} routine must assemble: {err:?}"));
    validate(
        &prog,
        &SeedLimits {
            siten: SITE_WIDTH,
            sn: 0,
            hn: 0,
        },
    )
    .unwrap_or_else(|err| panic!("seed {name} routine must validate: {err:?}"));
    prog
}

/// Emit the seed prelude for the interpreter module scope: the loop, the
/// fixed slice routines, and the (empty in slice 1) string/helper pools.
pub(crate) fn seed_prelude_lua(target: Target) -> String {
    let jump = checked_routine(routine_jump(), "jump");
    let test = checked_routine(routine_test(), "test");
    let ret = checked_routine(routine_return(), "return");
    format!(
        "{}\nlocal SEEDJ,SEEDT,SEEDR={},{},{};\nlocal STAB,SEEDH={{}},{{}};\n",
        seed_loop_lua(target),
        routine_lua(&jump),
        routine_lua(&test),
        routine_lua(&ret),
    )
}

/// Emit the post-binding fragment arm for migrated control ops, or `None` to
/// keep the classic handler body. The site block always splices the full
/// context `{a,b,c,k,j,skip1,pc}` with `0` for operands the op lacks.
pub(crate) fn seed_arm_lua(op: Opcode) -> Option<String> {
    match op {
        Opcode::Jump => Some(
            "local act,av=SEED(SEEDJ,{0,0,0,0,j,skip1,pc},R,RX,F.__obf_proto_k,STAB,SEEDH);if act~=1 then E()end;pc=av;"
                .to_owned(),
        ),
        Opcode::Test => Some(
            "local act,av=SEED(SEEDT,{a,0,0,0,0,skip1,pc},R,RX,F.__obf_proto_k,STAB,SEEDH);if act==1 then pc=av elseif act~=0 then E()end;"
                .to_owned(),
        ),
        Opcode::Return => Some(
            "local act,av=SEED(SEEDR,{a,0,0,0,0,skip1,pc},R,RX,F.__obf_proto_k,STAB,SEEDH);if act~=2 then E()end;return av;"
                .to_owned(),
        ),
        _ => None,
    }
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
            vec![vec![1, 0, 8_007_000]],
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
            vec![vec![4, 0, 3_001_000, 3_002_000, 3_009_000]],
            vec![vec![7, 3]],
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
        assert!(lua51.starts_with("local SEED=function(prog,site,R,RX,K,STAB,SEEDH)"));
        assert!(luau.starts_with("local SEED=function(prog,site,R,RX,K,STAB,SEEDH)"));
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
}
