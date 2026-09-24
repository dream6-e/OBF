#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Move = 0,
    LoadK,
    LoadBool,
    LoadNil,
    GetUpval,
    GetGlobal,
    GetTable,
    SetGlobal,
    SetUpval,
    SetTable,
    NewTable,
    SelfOp,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Unm,
    Not,
    Len,
    Concat,
    Jmp,
    Eq,
    Lt,
    Le,
    Test,
    TestSet,
    Call,
    TailCall,
    Return,
    ForLoop,
    ForPrep,
    TForLoop,
    SetList,
    Close,
    Closure,
    VarArg,
    IDiv,
    BAnd,
    BOr,
    BXor,
    Shl,
    Shr,
    BNot,
    LoadKx,
    ExtraArg,
    TForCall,
    TForPrep,
    GetImport,
    NameCall,
    FastCall,
    FastCall1,
    FastCall2,
    GetTableStr,
    SetTableStr,
    GetGlobalStr,
    SetGlobalStr,
    AddInt,
    SubInt,
    MulInt,
    DivInt,
    ModInt,
    AddEq,
    SubEq,
    MulEq,
    DivEq,
    ModEq,
    PowEq,
    EqInt,
    LtInt,
    LeInt,
    EqStr,
    LtStr,
    LeStr,
    TestInt,
    TestStr,
    NewTableArray,
    NewTableHash,
    GetTableConst,
    SetTableConst,
    JmpIf,
    JmpIfNot,
    JmpEq,
    JmpNe,
    Return0,
    Return1,
    Return2,
    Move1,
    Move2,
}

impl Opcode {
    pub fn from_u8(val: u8) -> Option<Opcode> {
        if val < 90 {
            Some(unsafe { std::mem::transmute(val) })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub enum VOpcode {
    Standard { original: Opcode, v_index: u16 },
    Mutated { a_part: u16, b_part: u16 },
    SuperOperator { sub_opcodes: Vec<Opcode>, v_index: u16 },
    FakeBranchTrap,
}

impl VOpcode {
    pub fn generate_mapping(_seed: u32) -> Self {
        VOpcode::FakeBranchTrap
    }
}