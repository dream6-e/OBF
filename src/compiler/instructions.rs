use std::fmt;
use rand::{SeedableRng, Rng};
use rand::rngs::StdRng;
use std::cell::Cell;

pub fn get_global_seed() -> u64 {
    264765718
}

#[derive(Clone, Copy, Debug)]
pub struct InstructionLayout {
    pub size_op: u32,
    pub size_a: u32,
    pub size_b: u32,
    pub size_c: u32,
    pub size_bx: u32,
    pub pos_op: u32,
    pub pos_a: u32,
    pub pos_b: u32,
    pub pos_c: u32,
    pub pos_bx: u32,
    pub xor_key: u32,
    pub max_sbx: i32,
    pub op_encode_map: [u8; 90],
    pub op_decode_map: [OpCode; 90],
}

impl InstructionLayout {
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let size_op = rng.random_range(7..=8);
        let size_a = 8;
        let size_bx = 32 - size_op - size_a;
        let size_b = size_bx / 2;
        let size_c = size_bx - size_b;
        let mut blocks = vec![0, 1, 2];
        for i in (1..3).rev() {
            let j = rng.random_range(0..=i);
            blocks.swap(i, j);
        }
        let sizes = [size_op, size_a, size_bx];
        let mut block_positions = [0; 3];
        let mut current_pos = 0;
        for &b in &blocks {
            block_positions[b] = current_pos;
            current_pos += sizes[b];
        }
        let pos_op = block_positions[0];
        let pos_a = block_positions[1];
        let pos_bx = block_positions[2];
        let b_first = rng.random::<bool>();
        let (pos_b, pos_c) = if b_first {
            (pos_bx, pos_bx + size_b)
        } else {
            (pos_bx + size_c, pos_bx)
        };
        let xor_key = rng.random::<u32>();
        let max_sbx = ((1 << (size_bx - 1)) - 1) as i32;
        let mut op_encode_map = [0u8; 90];
        for i in 0..90 {
            op_encode_map[i] = i as u8;
        }
        for i in (1..90).rev() {
            let j = rng.random_range(0..=i);
            op_encode_map.swap(i, j);
        }
        let mut op_decode_map = [OpCode::Move; 90];
        for (i, &encoded) in op_encode_map.iter().enumerate() {
            let op = unsafe { std::mem::transmute::<u8, OpCode>(i as u8) };
            op_decode_map[encoded as usize] = op;
        }
        Self {
            size_op,
            size_a,
            size_b,
            size_c,
            size_bx,
            pos_op,
            pos_a,
            pos_b,
            pos_c,
            pos_bx,
            xor_key,
            max_sbx,
            op_encode_map,
            op_decode_map,
        }
    }

    pub fn encode_opcode(&self, op: OpCode) -> u8 {
        self.op_encode_map[op as usize]
    }

    pub fn decode_opcode(&self, val: u8) -> Option<OpCode> {
        if (val as usize) < 90 {
            Some(self.op_decode_map[val as usize])
        } else {
            None
        }
    }
}

thread_local! {
    pub static ACTIVE_LAYOUT: Cell<InstructionLayout> = Cell::new(InstructionLayout::from_seed(get_global_seed()));
}

pub const MAXARG_BX: u32 = 65535;
pub const MAXARG_SBX: i32 = 32767;
pub const MAXARG_A: u32 = 255;
pub const MAXARG_B: u32 = 255;
pub const MAXARG_C: u32 = 255;
pub const MAXSTACK: u32 = 127;
pub const BITRK: u32 = 128;
pub const MAXINDEXRK: u32 = 127;
pub const NO_REG: u32 = MAXARG_A;
pub const NO_JUMP: i32 = -1;
pub const LFIELDS_PER_FLUSH: u32 = 50;
pub const LUAI_MAXVARS: u32 = 245;
pub const LUAI_MAXUPVALUES: u32 = 60;

#[must_use]
pub const fn is_k(x: u32) -> bool {
    x & BITRK != 0
}

#[must_use]
pub const fn rk_as_k(idx: u32) -> u32 {
    idx | BITRK
}

#[must_use]
pub const fn index_k(rk: u32) -> u32 {
    rk & !BITRK
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Move = 0,
    LoadK = 1,
    LoadBool = 2,
    LoadNil = 3,
    GetUpval = 4,
    GetGlobal = 5,
    GetTable = 6,
    SetGlobal = 7,
    SetUpval = 8,
    SetTable = 9,
    NewTable = 10,
    OpSelf = 11,
    Add = 12,
    Sub = 13,
    Mul = 14,
    Div = 15,
    Mod = 16,
    Pow = 17,
    Unm = 18,
    Not = 19,
    Len = 20,
    Concat = 21,
    Jmp = 22,
    Eq = 23,
    Lt = 24,
    Le = 25,
    Test = 26,
    TestSet = 27,
    Call = 28,
    TailCall = 29,
    Return = 30,
    ForLoop = 31,
    ForPrep = 32,
    TForLoop = 33,
    SetList = 34,
    Close = 35,
    Closure = 36,
    VarArg = 37,
    IDiv = 38,
    BAnd = 39,
    BOr = 40,
    BXor = 41,
    Shl = 42,
    Shr = 43,
    BNot = 44,
    LoadKx = 45,
    ExtraArg = 46,
    TForCall = 47,
    TForPrep = 48,
    GetImport = 49,
    NameCall = 50,
    FastCall = 51,
    FastCall1 = 52,
    FastCall2 = 53,
    GetTableStr = 54,
    SetTableStr = 55,
    GetGlobalStr = 56,
    SetGlobalStr = 57,
    AddInt = 58,
    SubInt = 59,
    MulInt = 60,
    DivInt = 61,
    ModInt = 62,
    AddEq = 63,
    SubEq = 64,
    MulEq = 65,
    DivEq = 66,
    ModEq = 67,
    PowEq = 68,
    EqInt = 69,
    LtInt = 70,
    LeInt = 71,
    EqStr = 72,
    LtStr = 73,
    LeStr = 74,
    TestInt = 75,
    TestStr = 76,
    NewTableArray = 77,
    NewTableHash = 78,
    GetTableConst = 79,
    SetTableConst = 80,
    JmpIf = 81,
    JmpIfNot = 82,
    JmpEq = 83,
    JmpNe = 84,
    Return0 = 85,
    Return1 = 86,
    Return2 = 87,
    Move1 = 88,
    Move2 = 89,
}

pub const NUM_OPCODES: u32 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpMode {
    IABC,
    IABx,
    IAsBx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpArgMask {
    N,
    U,
    R,
    K,
}

impl OpCode {
    #[must_use]
    pub fn from_u8(n: u8) -> Option<Self> {
        if n < NUM_OPCODES as u8 {
            Some(unsafe { std::mem::transmute(n) })
        } else {
            None
        }
    }

    #[must_use]
    pub fn is_test_mode(self) -> bool {
        matches!(
            self,
            Self::Eq | Self::Lt | Self::Le | Self::Test | Self::TestSet |
            Self::EqInt | Self::LtInt | Self::LeInt | Self::EqStr | Self::LtStr |
            Self::LeStr | Self::TestInt | Self::TestStr | Self::JmpIf | Self::JmpIfNot |
            Self::JmpEq | Self::JmpNe
        )
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::LoadK => "LOADK",
            Self::LoadBool => "LOADBOOL",
            Self::LoadNil => "LOADNIL",
            Self::GetUpval => "GETUPVAL",
            Self::GetGlobal => "GETGLOBAL",
            Self::GetTable => "GETTABLE",
            Self::SetGlobal => "SETGLOBAL",
            Self::SetUpval => "SETUPVAL",
            Self::SetTable => "SETTABLE",
            Self::NewTable => "NEWTABLE",
            Self::OpSelf => "SELF",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Unm => "UNM",
            Self::Not => "NOT",
            Self::Len => "LEN",
            Self::Concat => "CONCAT",
            Self::Jmp => "JMP",
            Self::Eq => "EQ",
            Self::Lt => "LT",
            Self::Le => "LE",
            Self::Test => "TEST",
            Self::TestSet => "TESTSET",
            Self::Call => "CALL",
            Self::TailCall => "TAILCALL",
            Self::Return => "RETURN",
            Self::ForLoop => "FORLOOP",
            Self::ForPrep => "FORPREP",
            Self::TForLoop => "TFORLOOP",
            Self::SetList => "SETLIST",
            Self::Close => "CLOSE",
            Self::Closure => "CLOSURE",
            Self::VarArg => "VARARG",
            Self::IDiv => "IDIV",
            Self::BAnd => "BAND",
            Self::BOr => "BOR",
            Self::BXor => "BXOR",
            Self::Shl => "SHL",
            Self::Shr => "SHR",
            Self::BNot => "BNOT",
            Self::LoadKx => "LOADKX",
            Self::ExtraArg => "EXTRAARG",
            Self::TForCall => "TFORCALL",
            Self::TForPrep => "TFORPREP",
            Self::GetImport => "GETIMPORT",
            Self::NameCall => "NAMECALL",
            Self::FastCall => "FASTCALL",
            Self::FastCall1 => "FASTCALL1",
            Self::FastCall2 => "FASTCALL2",
            Self::GetTableStr => "GETTABLESTR",
            Self::SetTableStr => "SETTABLESTR",
            Self::GetGlobalStr => "GETGLOBALSTR",
            Self::SetGlobalStr => "SETGLOBALSTR",
            Self::AddInt => "ADDINT",
            Self::SubInt => "SUBINT",
            Self::MulInt => "MULINT",
            Self::DivInt => "DIVINT",
            Self::ModInt => "MODINT",
            Self::AddEq => "ADDEQ",
            Self::SubEq => "SUBEQ",
            Self::MulEq => "MULEQ",
            Self::DivEq => "DIVEQ",
            Self::ModEq => "MODEQ",
            Self::PowEq => "POWEQ",
            Self::EqInt => "EQINT",
            Self::LtInt => "LTINT",
            Self::LeInt => "LEINT",
            Self::EqStr => "EQSTR",
            Self::LtStr => "LTSTR",
            Self::LeStr => "LESTR",
            Self::TestInt => "TESTINT",
            Self::TestStr => "TESTSTR",
            Self::NewTableArray => "NEWTABLEARRAY",
            Self::NewTableHash => "NEWTABLEHASH",
            Self::GetTableConst => "GETTABLECONST",
            Self::SetTableConst => "SETTABLECONST",
            Self::JmpIf => "JMPIF",
            Self::JmpIfNot => "JMPIFNOT",
            Self::JmpEq => "JMPEQ",
            Self::JmpNe => "JMPNE",
            Self::Return0 => "RETURN0",
            Self::Return1 => "RETURN1",
            Self::Return2 => "RETURN2",
            Self::Move1 => "MOVE1",
            Self::Move2 => "MOVE2",
        }
    }

    #[must_use]
    pub fn mode(self) -> OpMode {
        match self {
            Self::Jmp | Self::ForLoop | Self::ForPrep | Self::TForPrep |
            Self::JmpIf | Self::JmpIfNot | Self::JmpEq | Self::JmpNe => OpMode::IAsBx,
            Self::LoadK | Self::GetGlobal | Self::SetGlobal | Self::Closure |
            Self::LoadKx | Self::ExtraArg | Self::GetImport | Self::GetGlobalStr |
            Self::SetGlobalStr => OpMode::IABx,
            _ => OpMode::IABC,
        }
    }

    #[must_use]
    pub fn b_mode(self) -> OpArgMask {
        match self {
            Self::LoadK | Self::GetGlobal | Self::SetGlobal | Self::SetTable |
            Self::Add | Self::Sub | Self::Mul | Self::Div | Self::Mod | Self::Pow |
            Self::Eq | Self::Lt | Self::Le | Self::IDiv | Self::BAnd | Self::BOr |
            Self::BXor | Self::Shl | Self::Shr | Self::GetGlobalStr | Self::SetGlobalStr |
            Self::AddEq | Self::SubEq | Self::MulEq | Self::DivEq | Self::ModEq |
            Self::PowEq | Self::GetTableConst | Self::SetTableConst => OpArgMask::K,
            Self::Move | Self::LoadNil | Self::Unm | Self::Not | Self::Len |
            Self::Concat | Self::Jmp | Self::Test | Self::TestSet | Self::ForLoop |
            Self::ForPrep | Self::GetTable | Self::OpSelf | Self::BNot | Self::NameCall |
            Self::GetTableStr | Self::SetTableStr | Self::AddInt | Self::SubInt |
            Self::MulInt | Self::DivInt | Self::ModInt | Self::EqInt | Self::LtInt |
            Self::LeInt | Self::EqStr | Self::LtStr | Self::LeStr | Self::TestInt |
            Self::TestStr | Self::JmpIf | Self::JmpIfNot | Self::JmpEq | Self::JmpNe |
            Self::Move1 | Self::Move2 => OpArgMask::R,
            Self::LoadBool | Self::GetUpval | Self::SetUpval | Self::NewTable |
            Self::Call | Self::TailCall | Self::Return | Self::SetList | Self::Closure |
            Self::VarArg | Self::ExtraArg | Self::TForCall | Self::GetImport |
            Self::FastCall | Self::FastCall1 | Self::FastCall2 | Self::NewTableArray |
            Self::NewTableHash => OpArgMask::U,
            Self::TForLoop | Self::Close | Self::LoadKx | Self::TForPrep |
            Self::Return0 | Self::Return1 | Self::Return2 => OpArgMask::N,
        }
    }

    #[must_use]
    pub fn c_mode(self) -> OpArgMask {
        match self {
            Self::GetTable | Self::OpSelf | Self::SetTable | Self::Add | Self::Sub |
            Self::Mul | Self::Div | Self::Mod | Self::Pow | Self::Eq | Self::Lt |
            Self::Le | Self::IDiv | Self::BAnd | Self::BOr | Self::BXor | Self::Shl |
            Self::Shr | Self::NameCall | Self::GetTableStr | Self::SetTableStr |
            Self::GetTableConst | Self::SetTableConst => OpArgMask::K,
            Self::Concat | Self::AddInt | Self::SubInt | Self::MulInt | Self::DivInt |
            Self::ModInt | Self::EqInt | Self::LtInt | Self::LeInt | Self::EqStr |
            Self::LtStr | Self::LeStr => OpArgMask::R,
            Self::LoadBool | Self::NewTable | Self::Call | Self::TailCall |
            Self::SetList | Self::Test | Self::TestSet | Self::TForLoop | Self::VarArg |
            Self::TForCall | Self::NewTableArray | Self::NewTableHash => OpArgMask::U,
            _ => OpArgMask::N,
        }
    }

    #[must_use]
    pub fn sets_register_a(self) -> bool {
        !matches!(
            self,
            Self::SetGlobal | Self::SetUpval | Self::SetTable | Self::Jmp |
            Self::Eq | Self::Lt | Self::Le | Self::Return | Self::SetList |
            Self::Close | Self::TForLoop | Self::TForCall | Self::SetTableStr |
            Self::SetGlobalStr | Self::SetTableConst | Self::JmpIf | Self::JmpIfNot |
            Self::JmpEq | Self::JmpNe | Self::Return0 | Self::Return1 | Self::Return2
        )
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Instruction(u32);

impl Instruction {
    #[must_use]
    pub fn abc(op: OpCode, a: u32, b: u32, c: u32) -> Self {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let mask_op = (1 << layout.size_op) - 1;
            let mask_a = (1 << layout.size_a) - 1;
            let mask_b = (1 << layout.size_b) - 1;
            let mask_c = (1 << layout.size_c) - 1;
            let encoded_op = layout.encode_opcode(op) as u32;
            let val = ((encoded_op & mask_op) << layout.pos_op)
                | ((a & mask_a) << layout.pos_a)
                | ((b & mask_b) << layout.pos_b)
                | ((c & mask_c) << layout.pos_c);
            Self(val ^ layout.xor_key)
        })
    }

    #[must_use]
    pub fn a_bx(op: OpCode, a: u32, bx: u32) -> Self {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let mask_op = (1 << layout.size_op) - 1;
            let mask_a = (1 << layout.size_a) - 1;
            let mask_bx = (1 << layout.size_bx) - 1;
            let encoded_op = layout.encode_opcode(op) as u32;
            let val = ((encoded_op & mask_op) << layout.pos_op)
                | ((a & mask_a) << layout.pos_a)
                | ((bx & mask_bx) << layout.pos_bx);
            Self(val ^ layout.xor_key)
        })
    }

    #[must_use]
    pub fn a_sbx(op: OpCode, a: u32, sbx: i32) -> Self {
        let encoded = ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            (sbx + layout.max_sbx) as u32
        });
        Self::a_bx(op, a, encoded)
    }

    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    #[must_use]
    pub fn opcode(self) -> OpCode {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let val = self.0 ^ layout.xor_key;
            let op = (val >> layout.pos_op) & ((1 << layout.size_op) - 1);
            layout.decode_opcode(op as u8).unwrap_or(OpCode::Move)
        })
    }

    #[must_use]
    pub fn a(self) -> u32 {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let val = self.0 ^ layout.xor_key;
            (val >> layout.pos_a) & ((1 << layout.size_a) - 1)
        })
    }

    #[must_use]
    pub fn b(self) -> u32 {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let val = self.0 ^ layout.xor_key;
            (val >> layout.pos_b) & ((1 << layout.size_b) - 1)
        })
    }

    #[must_use]
    pub fn c(self) -> u32 {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let val = self.0 ^ layout.xor_key;
            (val >> layout.pos_c) & ((1 << layout.size_c) - 1)
        })
    }

    #[must_use]
    pub fn bx(self) -> u32 {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let val = self.0 ^ layout.xor_key;
            (val >> layout.pos_bx) & ((1 << layout.size_bx) - 1)
        })
    }

    #[must_use]
    pub fn sbx(self) -> i32 {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            self.bx() as i32 - layout.max_sbx
        })
    }

    pub fn set_a(&mut self, a: u32) {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let mut val = self.0 ^ layout.xor_key;
            let mask = (1 << layout.size_a) - 1;
            val = (val & !(mask << layout.pos_a)) | ((a & mask) << layout.pos_a);
            self.0 = val ^ layout.xor_key;
        });
    }

    pub fn set_b(&mut self, b: u32) {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let mut val = self.0 ^ layout.xor_key;
            let mask = (1 << layout.size_b) - 1;
            val = (val & !(mask << layout.pos_b)) | ((b & mask) << layout.pos_b);
            self.0 = val ^ layout.xor_key;
        });
    }

    pub fn set_c(&mut self, c: u32) {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let mut val = self.0 ^ layout.xor_key;
            let mask = (1 << layout.size_c) - 1;
            val = (val & !(mask << layout.pos_c)) | ((c & mask) << layout.pos_c);
            self.0 = val ^ layout.xor_key;
        });
    }

    pub fn set_sbx(&mut self, sbx: i32) {
        ACTIVE_LAYOUT.with(|layout_cell| {
            let layout = layout_cell.get();
            let encoded = (sbx + layout.max_sbx) as u32;
            let mut val = self.0 ^ layout.xor_key;
            let mask = (1 << layout.size_bx) - 1;
            val = (val & !(mask << layout.pos_bx)) | ((encoded & mask) << layout.pos_bx);
            self.0 = val ^ layout.xor_key;
        });
    }
}

impl fmt::Debug for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Instruction({} A={} B={} C={} Bx={} sBx={})",
            self.opcode().name(),
            self.a(),
            self.b(),
            self.c(),
            self.bx(),
            self.sbx()
        )
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.opcode().name())
    }
}