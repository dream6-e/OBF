//! OBF v2: a native-independent, fixed-width register instruction set.
//! Header and records are little endian; instructions are exactly four bytes.
//! No native words, AUX records, compression, encryption or randomized sections.

use crate::ast::{BinaryOperator as B, UnaryOperator as U};
use crate::ir::{self, Capture, Constant, Instruction as I, Terminator as T};
use crate::{Diagnostic, Target};
use std::collections::BTreeSet;

pub const HEADER_SIZE: usize = 32;
pub const INSTRUCTION_SIZE: usize = 4;
pub const VERSION: u8 = 2;
pub const ISA_VERSION: u32 = 1;
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ITEMS: usize = 1_000_000;
pub const MAX_FUNCTIONS: usize = 65_536;

macro_rules! opcodes {
    ($($name:ident),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
        #[repr(u8)]
        pub enum Opcode { $($name),+ }
        impl Opcode {
            pub const ALL: &'static [Self] = &[$(Self::$name),+];
            pub fn from_byte(value: u8) -> Option<Self> { Self::ALL.get(value as usize).copied() }
            pub fn name(self) -> &'static str { match self { $(Self::$name => stringify!($name)),+ } }
        }
    }
}

// Stable v1 ISA numbers: never reorder; incompatible changes need a new ISA.
opcodes!(
    Move,
    Constant,
    Nil,
    NewCell,
    ReadCell,
    WriteCell,
    ReadUpvalue,
    WriteUpvalue,
    ReadGlobal,
    WriteGlobal,
    NewTable,
    GetTable,
    SetTable,
    Method,
    NewPack,
    Push,
    Extend,
    Extract,
    Varargs,
    Call,
    Closure,
    Clear,
    Add,
    Subtract,
    Multiply,
    Divide,
    FloorDivide,
    Modulo,
    Power,
    Concat,
    Equal,
    Less,
    LessEqual,
    Not,
    Negate,
    Length,
    NumberPrepare,
    NumberStep,
    NumberTest,
    IteratorPrepare,
    IteratorNext,
    SetList,
    ToString,
    Export,
    Jump,
    Test,
    Return,
    TailCall,
    Freeze
);

impl Opcode {
    pub fn supported(self, target: Target) -> bool {
        target.is_luau() || !matches!(self, Self::FloorDivide | Self::Export | Self::Freeze)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Word(pub [u8; 4]);
impl Word {
    pub fn opcode(self) -> Result<Opcode, Diagnostic> {
        Opcode::from_byte(self.0[0]).ok_or_else(|| Diagnostic::new("unknown custom opcode"))
    }
    pub fn a(self) -> usize {
        usize::from(self.0[1])
    }
    pub fn b(self) -> usize {
        usize::from(self.0[2])
    }
    pub fn c(self) -> usize {
        usize::from(self.0[3])
    }
    pub fn bx(self) -> usize {
        self.b() | self.c() << 8
    }
    pub fn ax(self) -> usize {
        self.a() | self.bx() << 8
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Prototype {
    pub parent: Option<usize>,
    pub registers: u16,
    pub parameters: u8,
    pub flags: u8,
    pub captures: Vec<Capture>,
    pub constants: Vec<Constant>,
    pub code: Vec<Word>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Program {
    pub target: Target,
    pub entry: usize,
    pub prototypes: Vec<Prototype>,
}

fn error(message: &str) -> Diagnostic {
    Diagnostic::new(format!("custom bytecode: {message}"))
}
fn narrow(value: usize) -> Result<u8, Diagnostic> {
    u8::try_from(value).map_err(|_| error("8-bit operand overflow"))
}
fn abc(op: Opcode, a: usize, b: usize, c: usize) -> Result<Word, Diagnostic> {
    Ok(Word([op as u8, narrow(a)?, narrow(b)?, narrow(c)?]))
}
fn abx(op: Opcode, a: usize, index: usize) -> Result<Word, Diagnostic> {
    let index = u16::try_from(index).map_err(|_| error("16-bit index overflow"))?;
    abc(op, a, usize::from(index & 255), usize::from(index >> 8))
}
fn jump(index: usize) -> Result<Word, Diagnostic> {
    if index >= 1 << 24 {
        return Err(error("24-bit jump overflow"));
    }
    abc(Opcode::Jump, index & 255, index >> 8 & 255, index >> 16)
}

/// Resolve IR block labels, select custom opcodes, and serialize a validated
/// program. Branches lower to TEST + two ordinary 4-byte JUMPs, never AUX data.
pub fn encode(module: &ir::Module) -> Result<Vec<u8>, Diagnostic> {
    if module.functions.is_empty() || module.functions.len() > MAX_FUNCTIONS {
        return Err(error("function count exceeds format limit"));
    }
    let mut prototypes = Vec::new();
    let mut total = 0usize;
    let mut constant_bytes = 0usize;
    for f in &module.functions {
        if f.constants.len() > 65_536 || f.captures.len() > 256 {
            return Err(error("IR pool exceeds format limit"));
        }
        for c in &f.constants {
            constant_bytes = constant_bytes.saturating_add(match c {
                Constant::String(s) => s.len(),
                Constant::Method(s) => s.len(),
                _ => 0,
            });
            if constant_bytes > MAX_BYTES {
                return Err(error("IR constant bytes exceed safety limit"));
            }
        }
        let mut offsets = Vec::new();
        let mut size = 0usize;
        for block in &f.blocks {
            offsets.push(size);
            size = size
                .checked_add(block.instructions.len())
                .and_then(|n| {
                    n.checked_add(if matches!(block.terminator, T::Branch { .. }) {
                        3
                    } else {
                        1
                    })
                })
                .ok_or_else(|| error("instruction count overflow"))?;
            if size > MAX_ITEMS {
                return Err(error("instruction count exceeds safety limit"));
            }
        }
        total = total
            .checked_add(size + f.constants.len() + f.captures.len())
            .ok_or_else(|| error("IR record count overflow"))?;
        if total > MAX_ITEMS {
            return Err(error("IR record count exceeds safety limit"));
        }
        let mut code = Vec::with_capacity(size);
        for block in &f.blocks {
            for instruction in &block.instructions {
                code.push(select(instruction)?);
            }
            let label = |id: usize| {
                offsets
                    .get(id)
                    .copied()
                    .ok_or_else(|| error("invalid IR block target"))
            };
            match block.terminator {
                T::Jump(id) => code.push(jump(label(id)?)?),
                T::Branch {
                    condition,
                    then_block,
                    else_block,
                } => {
                    code.push(abc(Opcode::Test, condition.into(), 0, 0)?);
                    code.push(jump(label(then_block)?)?);
                    code.push(jump(label(else_block)?)?);
                }
                T::Return(reg) => code.push(abc(Opcode::Return, reg.into(), 0, 0)?),
                T::TailCall {
                    function,
                    arguments,
                } => code.push(abc(Opcode::TailCall, function.into(), arguments.into(), 0)?),
                T::Unreachable => return Err(error("unterminated IR block")),
            }
        }
        prototypes.push(Prototype {
            parent: f.parent,
            registers: f.registers,
            parameters: narrow(usize::from(f.parameters))?,
            flags: u8::from(f.variadic)
                | u8::from(f.legacy_arg_slot) << 1
                | u8::from(f.legacy_arg_table) << 2,
            captures: f.captures.clone(),
            constants: f.constants.clone(),
            code,
        });
    }
    serialize(&Program {
        target: module.target,
        entry: module.entry,
        prototypes,
    })
}

fn select(instruction: &I) -> Result<Word, Diagnostic> {
    use Opcode as O;
    let r = |r: u16| usize::from(r);
    match *instruction {
        I::Constant(a, k) => abx(O::Constant, r(a), k),
        I::Nil(a) => abc(O::Nil, r(a), 0, 0),
        I::Move(a, b) => abc(O::Move, r(a), r(b), 0),
        I::NewCell(a, b) => abc(O::NewCell, r(a), r(b), 0),
        I::ReadCell(a, b) => abc(O::ReadCell, r(a), r(b), 0),
        I::WriteCell(a, b) => abc(O::WriteCell, r(a), r(b), 0),
        I::ReadUpvalue(a, u) => abc(O::ReadUpvalue, r(a), r(u), 0),
        I::WriteUpvalue(u, a) => abc(O::WriteUpvalue, r(a), r(u), 0),
        I::ReadGlobal(a, k) => abx(O::ReadGlobal, r(a), k),
        I::WriteGlobal(k, a) => abx(O::WriteGlobal, r(a), k),
        I::NewTable(a) => abc(O::NewTable, r(a), 0, 0),
        I::GetTable(a, b, c) => abc(O::GetTable, r(a), r(b), r(c)),
        I::SetTable(a, b, c) => abc(O::SetTable, r(a), r(b), r(c)),
        I::Method(a, b, c) => abc(O::Method, r(a), r(b), r(c)),
        I::NewPack(a) => abc(O::NewPack, r(a), 0, 0),
        I::Push(a, b) => abc(O::Push, r(a), r(b), 0),
        I::Extend(a, b) => abc(O::Extend, r(a), r(b), 0),
        I::Extract(a, b, c) => abc(O::Extract, r(a), r(b), r(c)),
        I::Varargs(a) => abc(O::Varargs, r(a), 0, 0),
        I::Call(a, b, c) => abc(O::Call, r(a), r(b), r(c)),
        I::Closure(a, f) => abx(O::Closure, r(a), f),
        I::Clear(a, b) => abc(O::Clear, r(a), r(b), 0),
        I::Binary(op, a, b, c) => {
            let opcode = match op {
                B::Add => O::Add,
                B::Subtract => O::Subtract,
                B::Multiply => O::Multiply,
                B::Divide => O::Divide,
                B::FloorDivide => O::FloorDivide,
                B::Modulo => O::Modulo,
                B::Power => O::Power,
                B::Concat => O::Concat,
                B::Equal => O::Equal,
                B::Less => O::Less,
                B::LessEqual => O::LessEqual,
                _ => return Err(error("binary operator requires prior IR desugaring")),
            };
            abc(opcode, r(a), r(b), r(c))
        }
        I::Unary(op, a, b) => abc(
            match op {
                U::Not => O::Not,
                U::Negate => O::Negate,
                U::Length => O::Length,
                U::BitNot => {
                    return Err(error(
                        "bitwise-not is not a source operator in these targets",
                    ))
                }
            },
            r(a),
            r(b),
            0,
        ),
        I::NumberPrepare(a) => abc(O::NumberPrepare, r(a), 0, 0),
        I::NumberStep(a) => abc(O::NumberStep, r(a), 0, 0),
        I::NumberTest(a, b) => abc(O::NumberTest, r(a), r(b), 0),
        I::IteratorPrepare(a) => abc(O::IteratorPrepare, r(a), 0, 0),
        I::IteratorNext(a, b) => abc(O::IteratorNext, r(a), r(b), 0),
        I::SetList(a, b, c) => abc(O::SetList, r(a), r(b), r(c)),
        I::ToString(a, b) => abc(O::ToString, r(a), r(b), 0),
        I::Export(a, b, c) => abc(O::Export, r(a), r(b), r(c)),
        I::Freeze(a) => abc(O::Freeze, r(a), 0, 0),
    }
}

pub fn checksum(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &v in bytes {
        a = (a + u32::from(v)) % 65_521;
        b = (b + a) % 65_521;
    }
    a | b << 16
}
fn u16_bytes(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn u32_bytes(out: &mut Vec<u8>, v: usize) -> Result<(), Diagnostic> {
    let v = u32::try_from(v).map_err(|_| error("32-bit length overflow"))?;
    out.extend_from_slice(&v.to_le_bytes());
    Ok(())
}
fn bytes(out: &mut Vec<u8>, v: &[u8]) -> Result<(), Diagnostic> {
    if out.len().saturating_add(v.len()).saturating_add(4) > MAX_BYTES {
        return Err(error("file size exceeds safety limit"));
    }
    u32_bytes(out, v.len())?;
    out.extend_from_slice(v);
    Ok(())
}

pub fn serialize(program: &Program) -> Result<Vec<u8>, Diagnostic> {
    validate(program)?;
    let mut out = Vec::from(*b"OBF\x02");
    out.extend_from_slice(&[if program.target.is_luau() { 0x75 } else { 0x51 }, 1, 4, 0]);
    u32_bytes(&mut out, HEADER_SIZE)?;
    u32_bytes(&mut out, 0)?;
    u32_bytes(&mut out, program.prototypes.len())?;
    u32_bytes(&mut out, program.entry)?;
    out.extend_from_slice(&ISA_VERSION.to_le_bytes());
    u32_bytes(&mut out, 0)?;
    for p in &program.prototypes {
        out.extend_from_slice(&p.parent.map_or(u32::MAX, |p| p as u32).to_le_bytes());
        u16_bytes(&mut out, p.registers);
        out.extend_from_slice(&[p.parameters, p.flags]);
        u16_bytes(&mut out, p.captures.len() as u16);
        u16_bytes(&mut out, 0);
        u32_bytes(&mut out, p.constants.len())?;
        u32_bytes(&mut out, p.code.len())?;
        for capture in &p.captures {
            let (tag, index) = match *capture {
                Capture::Local(r) => (0, r),
                Capture::Upvalue(u) => (1, u),
            };
            out.extend_from_slice(&[tag, narrow(index.into())?]);
        }
        for constant in &p.constants {
            match constant {
                Constant::Nil => out.push(0),
                Constant::Boolean(b) => out.extend_from_slice(&[1, u8::from(*b)]),
                Constant::Number(n) => {
                    out.push(2);
                    out.extend_from_slice(&n.to_le_bytes());
                }
                Constant::String(s) => {
                    out.push(3);
                    bytes(&mut out, s)?;
                }
                Constant::Integer(i) => {
                    out.push(4);
                    out.extend_from_slice(&i.to_le_bytes());
                }
                Constant::Method(s) => {
                    out.push(5);
                    bytes(&mut out, s.as_bytes())?;
                }
            }
        }
        for word in &p.code {
            out.extend_from_slice(&word.0);
        }
        if out.len() > MAX_BYTES {
            return Err(error("file size exceeds safety limit"));
        }
    }
    let len = out.len() as u32;
    out[12..16].copy_from_slice(&len.to_le_bytes());
    let sum = checksum(&out[HEADER_SIZE..]);
    out[28..32].copy_from_slice(&sum.to_le_bytes());
    Ok(out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Diagnostic> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| error("length overflow"))?;
        let s = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| Diagnostic::byte("truncated custom bytecode", self.pos))?;
        self.pos = end;
        Ok(s)
    }
    fn byte(&mut self) -> Result<u8, Diagnostic> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Diagnostic> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, Diagnostic> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<Vec<u8>, Diagnostic> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

pub fn decode(data: &[u8], target: Target) -> Result<Program, Diagnostic> {
    let mut reader = Reader {
        bytes: data,
        pos: 0,
    };
    decode_inner(&mut reader, target).map_err(|mut error| {
        if error.offset.is_none() {
            error.offset = Some(reader.pos);
        }
        error
    })
}

fn decode_inner(r: &mut Reader<'_>, target: Target) -> Result<Program, Diagnostic> {
    let data = r.bytes;
    if data.len() > MAX_BYTES {
        return Err(error("file size exceeds safety limit"));
    }
    if r.take(4)? != b"OBF\x02" {
        return Err(error("bad magic/version"));
    }
    if r.byte()? != if target.is_luau() { 0x75 } else { 0x51 } {
        return Err(error("target mismatch"));
    }
    if r.take(3)? != [1, 4, 0] {
        return Err(error("unsupported endianness, width or flags"));
    }
    if r.u32()? as usize != HEADER_SIZE || r.u32()? as usize != data.len() {
        return Err(error("invalid header/file size"));
    }
    let count = r.u32()? as usize;
    let entry = r.u32()? as usize;
    if count == 0 || count > MAX_FUNCTIONS {
        return Err(error("prototype count exceeds safety limit"));
    }
    if r.u32()? != ISA_VERSION {
        return Err(error("unsupported ISA version"));
    }
    if r.u32()? != checksum(&data[HEADER_SIZE..]) {
        return Err(error("payload checksum mismatch"));
    }
    let mut prototypes = Vec::new();
    let mut total = 0usize;
    for _ in 0..count {
        let parent = r.u32()?;
        let parent = (parent != u32::MAX).then_some(parent as usize);
        let registers = r.u16()?;
        let parameters = r.byte()?;
        let flags = r.byte()?;
        let nc = r.u16()? as usize;
        if nc > 256 || r.u16()? != 0 {
            return Err(error("bad capture count or reserved field"));
        }
        let nk = r.u32()? as usize;
        let ni = r.u32()? as usize;
        if nk > 65_536 || ni > MAX_ITEMS || nk + ni + nc > MAX_ITEMS.saturating_sub(total) {
            return Err(error("record count exceeds safety limit"));
        }
        total += nk + ni + nc;
        let mut captures = Vec::new();
        for _ in 0..nc {
            let tag = r.byte()?;
            let index = u16::from(r.byte()?);
            captures.push(match tag {
                0 => Capture::Local(index),
                1 => Capture::Upvalue(index),
                _ => return Err(error("bad capture tag")),
            });
        }
        let mut constants = Vec::new();
        for _ in 0..nk {
            constants.push(match r.byte()? {
                0 => Constant::Nil,
                1 => {
                    let b = r.byte()?;
                    if b > 1 {
                        return Err(error("invalid boolean"));
                    }
                    Constant::Boolean(b == 1)
                }
                2 => Constant::Number(u64::from_le_bytes(r.take(8)?.try_into().unwrap())),
                3 => Constant::String(r.string()?),
                4 => Constant::Integer(i64::from_le_bytes(r.take(8)?.try_into().unwrap())),
                5 => Constant::Method(
                    String::from_utf8(r.string()?).map_err(|_| error("invalid method UTF-8"))?,
                ),
                _ => return Err(error("unknown constant tag")),
            });
        }
        let code = r
            .take(ni * 4)?
            .chunks_exact(4)
            .map(|s| Word(s.try_into().unwrap()))
            .collect();
        prototypes.push(Prototype {
            parent,
            registers,
            parameters,
            flags,
            captures,
            constants,
            code,
        });
    }
    if r.pos != data.len() {
        return Err(error("trailing bytes"));
    }
    let program = Program {
        target,
        entry,
        prototypes,
    };
    validate(&program)?;
    Ok(program)
}

pub fn validate(program: &Program) -> Result<(), Diagnostic> {
    if program.entry != 0
        || program.prototypes.is_empty()
        || program.prototypes.len() > MAX_FUNCTIONS
    {
        return Err(error("invalid entry or prototype count"));
    }
    let mut total = 0usize;
    let mut byte_work = 0usize;
    for (id, p) in program.prototypes.iter().enumerate() {
        if p.registers == 0
            || p.registers > 256
            || u16::from(p.parameters) > p.registers
            || p.captures.len() > 256
            || p.constants.len() > 65_536
            || p.code.is_empty()
            || p.flags & !7 != 0
            || p.flags & 4 != 0 && p.flags & 2 == 0
            || p.flags & 2 != 0
                && (p.flags & 1 == 0
                    || program.target.is_luau()
                    || u16::from(p.parameters) >= p.registers)
            || (id == 0 && (p.parent.is_some() || !p.captures.is_empty() || p.flags & 2 != 0))
            || (id != 0 && p.parent.is_none_or(|parent| parent >= id))
        {
            return Err(error("invalid prototype header"));
        }
        total = total
            .checked_add(p.code.len() + p.constants.len() + p.captures.len())
            .ok_or_else(|| error("record count overflow"))?;
        if total > MAX_ITEMS {
            return Err(error("record count exceeds safety limit"));
        }
        for capture in &p.captures {
            let parent = &program.prototypes[p
                .parent
                .ok_or_else(|| error("entry captures are invalid"))?];
            if match *capture {
                Capture::Local(r) => r >= parent.registers,
                Capture::Upvalue(u) => usize::from(u) >= parent.captures.len(),
            } {
                return Err(error("capture source out of range"));
            }
        }
        for constant in &p.constants {
            match constant {
                Constant::Integer(_) if !program.target.is_luau() => {
                    return Err(error("integer constant in Lua 5.1 program"))
                }
                Constant::String(s) => byte_work = byte_work.saturating_add(s.len()),
                Constant::Method(s) => {
                    if s.is_empty()
                        || !(s.as_bytes()[0].is_ascii_alphabetic() || s.starts_with('_'))
                        || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        || crate::lexer::is_keyword(s, program.target)
                    {
                        return Err(error("invalid method identifier"));
                    }
                    byte_work = byte_work.saturating_add(s.len());
                }
                _ => {}
            }
            if byte_work > MAX_BYTES {
                return Err(error("constant bytes exceed safety limit"));
            }
        }
        for (pc, &word) in p.code.iter().enumerate() {
            validate_word(program, id, pc, word)?;
        }
        let last = p.code.last().unwrap().opcode()?;
        if !matches!(last, Opcode::Jump | Opcode::Return | Opcode::TailCall) {
            return Err(error("function may fall off its instruction stream"));
        }
    }
    Ok(())
}

fn validate_word(program: &Program, id: usize, pc: usize, w: Word) -> Result<(), Diagnostic> {
    use Opcode::*;
    let p = &program.prototypes[id];
    let op = w.opcode()?;
    let (a, b, c) = (w.a(), w.b(), w.c());
    let m = usize::from(p.registers);
    if !op.supported(program.target) {
        return Err(error("opcode is unavailable for this target"));
    }
    let reg = |r: usize| r < m;
    let string = |k: usize| {
        matches!(
            p.constants.get(k),
            Some(ir::Constant::String(_) | ir::Constant::Method(_))
        )
    };
    let valid = match op {
        Jump => w.ax() < p.code.len(),
        Constant => reg(a) && w.bx() < p.constants.len(),
        ReadGlobal | WriteGlobal => reg(a) && string(w.bx()),
        Closure => {
            reg(a)
                && program
                    .prototypes
                    .get(w.bx())
                    .is_some_and(|child| child.parent == Some(id))
        }
        ReadUpvalue | WriteUpvalue => reg(a) && b < p.captures.len() && c == 0,
        Extract => reg(a) && reg(b) && c > 0,
        Clear => reg(a) && reg(b) && a <= b && c == 0,
        NumberPrepare | NumberStep => a + 2 < m && b == 0 && c == 0,
        NumberTest => reg(a) && b + 2 < m && c == 0,
        Test => reg(a) && b == 0 && c == 0 && pc + 2 < p.code.len(),
        Varargs => reg(a) && b == 0 && c == 0 && p.flags & 1 != 0,
        Nil | NewTable | NewPack | IteratorPrepare | Return | Freeze => reg(a) && b == 0 && c == 0,
        Move | NewCell | ReadCell | WriteCell | Push | Extend | Not | Negate | Length
        | IteratorNext | ToString | TailCall => reg(a) && reg(b) && c == 0,
        GetTable | SetTable | Method | Call | Add | Subtract | Multiply | Divide | FloorDivide
        | Modulo | Power | Concat | Equal | Less | LessEqual | SetList | Export => {
            reg(a) && reg(b) && reg(c)
        }
    };
    if !valid {
        return Err(Diagnostic::new(format!(
            "custom bytecode: invalid operands for {} at prototype {id}, instruction {pc}",
            op.name()
        )));
    }
    Ok(())
}

impl Program {
    pub fn opcodes(&self) -> BTreeSet<Opcode> {
        self.prototypes
            .iter()
            .flat_map(|p| &p.code)
            .filter_map(|w| Opcode::from_byte(w.0[0]))
            .collect()
    }
    pub fn methods(&self) -> BTreeSet<&str> {
        self.prototypes
            .iter()
            .flat_map(|p| &p.constants)
            .filter_map(|c| {
                if let Constant::Method(s) = c {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect()
    }
    pub fn report(&self) -> super::BytecodeReport {
        super::BytecodeReport {
            target: self.target,
            version: VERSION,
            type_version: None,
            strings: self
                .prototypes
                .iter()
                .flat_map(|p| &p.constants)
                .filter(|c| matches!(c, Constant::String(_) | Constant::Method(_)))
                .count(),
            prototypes: self.prototypes.len(),
            instructions: self.prototypes.iter().map(|p| p.code.len()).sum(),
            constants: self.prototypes.iter().map(|p| p.constants.len()).sum(),
            main_prototype: self.entry,
        }
    }
}
