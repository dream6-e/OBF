//! 编译器内部的数据结构：表达式上下文、函数状态、块上下文、常量键。

use std::collections::HashMap;

use crate::compiler::instructions::NO_JUMP;
use crate::compiler::proto::Proto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] 
pub(crate) enum ExprKind {
    Void,
    Nil,
    True,
    False,
    K,
    KNum,
    Local,
    Upval,
    Global,
    Indexed,
    Jmp,
    Relocable,
    NonReloc,
    Call,
    VarArg,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExprContext {
    pub kind: ExprKind,
    pub info: i32,
    pub aux: i32,
    pub nval: f64,
    pub t: i32,
    pub f: i32,
}
impl ExprContext {
    pub(super) fn void() -> Self {
        Self {
            kind: ExprKind::Void,
            info: 0,
            aux: 0,
            nval: 0.0,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    pub(super) fn new(kind: ExprKind, info: i32) -> Self {
        Self {
            kind,
            info,
            aux: 0,
            nval: 0.0,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    pub(super) fn number(val: f64) -> Self {
        Self {
            kind: ExprKind::KNum,
            info: 0,
            aux: 0,
            nval: val,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    pub(super) fn has_jumps(&self) -> bool {
        self.t != self.f
    }
    pub(super) fn is_numeral(&self) -> bool {
        self.kind == ExprKind::KNum && self.t == NO_JUMP && self.f == NO_JUMP
    }
}
#[derive(Debug, Clone)]
pub(crate) struct UpvalDesc {
    pub in_stack: bool,
    pub index: u8,
    pub name: String,
}
#[allow(dead_code)] 
pub(super) struct BlockContext {
    pub(super) num_active_vars: u8,
    pub(super) has_upval: bool,
    pub(super) is_breakable: bool,
    pub(super) break_list: i32,
    pub(super) continue_list: i32,
}
#[derive(Hash, Eq, PartialEq)]
pub(super) enum ConstantKey {
    Num(u64),
    Bool(bool),
    Str(Vec<u8>),
}
#[allow(dead_code)] 
pub(crate) struct FuncState {
    pub proto: Proto,
    pub free_reg: u8,
    pub num_active_vars: u8,
    pub upvalues: Vec<UpvalDesc>,
    pub(super) active_vars: Vec<u16>,
    pub(super) blocks: Vec<BlockContext>,
    pub jpc: i32,
    pub last_target: i32,
    pub(super) nil_k: Option<u32>,
    pub(super) constant_index: HashMap<ConstantKey, u32>,
}
impl FuncState {
    pub(super) fn new(source: &str) -> Self {
        Self {
            proto: Proto::new(source),
            free_reg: 0,
            num_active_vars: 0,
            upvalues: Vec::new(),
            active_vars: Vec::new(),
            blocks: Vec::new(),
            jpc: NO_JUMP,
            last_target: -1,
            nil_k: None,
            constant_index: HashMap::new(),
        }
    }
    pub(crate) fn pc(&self) -> usize {
        self.proto.code.len()
    }
}
