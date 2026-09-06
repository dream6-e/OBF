mod c48_freeze;
use crate::bytecode::custom::Opcode;
mod c00_move;
mod c01_constant;
mod c02_nil;
mod c03_newcell;
mod c04_readcell;
mod c05_writecell;
mod c06_readupvalue;
mod c07_writeupvalue;
mod c08_readglobal;
mod c09_writeglobal;
mod c10_newtable;
mod c11_gettable;
mod c12_settable;
mod c13_method;
mod c14_newpack;
mod c15_push;
mod c16_extend;
mod c17_extract;
mod c18_varargs;
mod c19_call;
mod c20_closure;
mod c21_clear;
mod c22_add;
mod c23_subtract;
mod c24_multiply;
mod c25_divide;
mod c26_floordivide;
mod c27_modulo;
mod c28_power;
mod c29_concat;
mod c30_equal;
mod c31_less;
mod c32_lessequal;
mod c33_not;
mod c34_negate;
mod c35_length;
mod c36_numberprepare;
mod c37_numberstep;
mod c38_numbertest;
mod c39_iteratorprepare;
mod c40_iteratornext;
mod c41_setlist;
mod c42_tostring;
mod c43_export;
mod c44_jump;
mod c45_test;
mod c46_return;
mod c47_tailcall;
pub(super) fn code(op: Opcode) -> Option<&'static str> {
    match op {
        Opcode::Move => Some(c00_move::code()),
        Opcode::Constant => Some(c01_constant::code()),
        Opcode::Nil => Some(c02_nil::code()),
        Opcode::NewCell => Some(c03_newcell::code()),
        Opcode::ReadCell => Some(c04_readcell::code()),
        Opcode::WriteCell => Some(c05_writecell::code()),
        Opcode::ReadUpvalue => Some(c06_readupvalue::code()),
        Opcode::WriteUpvalue => Some(c07_writeupvalue::code()),
        Opcode::ReadGlobal => Some(c08_readglobal::code()),
        Opcode::WriteGlobal => Some(c09_writeglobal::code()),
        Opcode::NewTable => Some(c10_newtable::code()),
        Opcode::GetTable => Some(c11_gettable::code()),
        Opcode::SetTable => Some(c12_settable::code()),
        Opcode::Method => Some(c13_method::code()),
        Opcode::NewPack => Some(c14_newpack::code()),
        Opcode::Push => Some(c15_push::code()),
        Opcode::Extend => Some(c16_extend::code()),
        Opcode::Extract => Some(c17_extract::code()),
        Opcode::Varargs => Some(c18_varargs::code()),
        Opcode::Call => Some(c19_call::code()),
        Opcode::Closure => Some(c20_closure::code()),
        Opcode::Clear => Some(c21_clear::code()),
        Opcode::Add => Some(c22_add::code()),
        Opcode::Subtract => Some(c23_subtract::code()),
        Opcode::Multiply => Some(c24_multiply::code()),
        Opcode::Divide => Some(c25_divide::code()),
        Opcode::FloorDivide => Some(c26_floordivide::code()),
        Opcode::Modulo => Some(c27_modulo::code()),
        Opcode::Power => Some(c28_power::code()),
        Opcode::Concat => Some(c29_concat::code()),
        Opcode::Equal => Some(c30_equal::code()),
        Opcode::Less => Some(c31_less::code()),
        Opcode::LessEqual => Some(c32_lessequal::code()),
        Opcode::Not => Some(c33_not::code()),
        Opcode::Negate => Some(c34_negate::code()),
        Opcode::Length => Some(c35_length::code()),
        Opcode::NumberPrepare => Some(c36_numberprepare::code()),
        Opcode::NumberStep => Some(c37_numberstep::code()),
        Opcode::NumberTest => Some(c38_numbertest::code()),
        Opcode::IteratorPrepare => Some(c39_iteratorprepare::code()),
        Opcode::IteratorNext => Some(c40_iteratornext::code()),
        Opcode::SetList => Some(c41_setlist::code()),
        Opcode::ToString => Some(c42_tostring::code()),
        Opcode::Export => Some(c43_export::code()),
        Opcode::Jump => Some(c44_jump::code()),
        Opcode::Test => Some(c45_test::code()),
        Opcode::Return => Some(c46_return::code()),
        Opcode::Freeze => Some(c48_freeze::code()),
        Opcode::TailCall => Some(c47_tailcall::code()),
    }
}
