use std::rc::Rc;
use super::value::Val;
pub type ProtoRef = Rc<Proto>;

pub const VARARG_HASARG: u8 = 1;
pub const VARARG_ISVARARG: u8 = 2;
pub const VARARG_NEEDSARG: u8 = 4;

#[derive(Debug, Clone)]
pub struct LocalVar {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
}

#[derive(Debug, Clone)]
pub struct Proto {
    pub code: Vec<u32>,
    pub constants: Vec<Val>,
    pub protos: Vec<ProtoRef>,
    pub line_info: Vec<u32>,
    pub local_vars: Vec<LocalVar>,
    pub upvalue_names: Vec<String>,
    pub source: String,
    pub line_defined: u32,
    pub last_line_defined: u32,
    pub num_upvalues: u8,
    pub num_params: u8,
    pub is_vararg: u8,
    pub max_stack_size: u8,
    pub string_pool: Vec<(u32, Vec<u8>)>,
}

impl Proto {
    #[must_use]
    pub fn new(_source: &str) -> Self {
        Self {
            code: Vec::new(),
            constants: Vec::new(),
            protos: Vec::new(),
            line_info: Vec::new(),
            local_vars: Vec::new(),
            upvalue_names: Vec::new(),
            source: "@KRYVEX\x20".to_string(),
            line_defined: 0,
            last_line_defined: 0,
            num_upvalues: 0,
            num_params: 0,
            is_vararg: 0,
            max_stack_size: 2, 
            string_pool: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_new_defaults() {
        let p = Proto::new("test");
        assert_eq!(p.source, "@KRYVEX\x20");
        assert!(p.code.is_empty());
        assert!(p.constants.is_empty());
        assert!(p.protos.is_empty());
        assert!(p.line_info.is_empty());
        assert!(p.local_vars.is_empty());
        assert!(p.upvalue_names.is_empty());
        assert_eq!(p.line_defined, 0);
        assert_eq!(p.last_line_defined, 0);
        assert_eq!(p.num_upvalues, 0);
        assert_eq!(p.num_params, 0);
        assert_eq!(p.is_vararg, 0);
        assert_eq!(p.max_stack_size, 2);
        assert!(p.string_pool.is_empty());
    }

    #[test]
    fn vararg_flags() {
        assert_eq!(VARARG_HASARG, 1);
        assert_eq!(VARARG_ISVARARG, 2);
        assert_eq!(VARARG_NEEDSARG, 4);
        assert_eq!(VARARG_HASARG | VARARG_ISVARARG, 3);
        assert_eq!(VARARG_ISVARARG | VARARG_NEEDSARG, 6);
    }

    #[test]
    fn local_var_construction() {
        let var = LocalVar {
            name: "x".into(),
            start_pc: 0,
            end_pc: 10,
        };
        assert_eq!(var.name, "x");
        assert_eq!(var.start_pc, 0);
        assert_eq!(var.end_pc, 10);
    }

    #[test]
    fn proto_with_code() {
        use crate::compiler::instructions::{Instruction, OpCode};
        let mut p = Proto::new("test");
        let instr = Instruction::abc(OpCode::Return, 0, 1, 0);
        p.code.push(instr.raw());
        p.line_info.push(1);
        assert_eq!(p.code.len(), 1);
        assert_eq!(p.line_info.len(), 1);
        let decoded = Instruction::from_raw(p.code[0]);
        assert_eq!(decoded.opcode(), OpCode::Return);
    }

    #[test]
    fn proto_with_constants() {
        let mut p = Proto::new("test");
        p.constants.push(Val::Nil);
        p.constants.push(Val::Bool(true));
        p.constants.push(Val::Num(3.0));
        assert_eq!(p.constants.len(), 3);
    }

    #[test]
    fn proto_nested() {
        let inner = ProtoRef::new(Proto::new("inner"));
        let mut outer = Proto::new("outer");
        outer.protos.push(inner);
        assert_eq!(outer.protos.len(), 1);
        assert_eq!(outer.protos[0].source, "@KRYVEX\x20");
    }

    #[test]
    fn proto_ref_sharing() {
        let p = ProtoRef::new(Proto::new("shared"));
        let p2 = ProtoRef::clone(&p);
        #[cfg(not(feature = "send"))]
        assert_eq!(std::rc::Rc::strong_count(&p), 2);
        #[cfg(feature = "send")]
        assert_eq!(std::sync::Arc::strong_count(&p), 2);
        assert_eq!(p2.source, "@KRYVEX\x20");
    }
}
