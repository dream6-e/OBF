//! 表达式代码生成：`impl Compiler` 的表达式半边（exp2reg / infix / postfix / prefix …），
//! 以及 `compile_expr`、函数实参、表构造器等自由函数。

use std::collections::HashMap;

use crate::compiler::ast::Block;
use crate::compiler::error::{LuaError, LuaResult, SyntaxError};
use crate::compiler::instructions::{
    BITRK, Instruction, LFIELDS_PER_FLUSH, LUAI_MAXUPVALUES, LUAI_MAXVARS, MAXARG_BX, MAXARG_C,
    MAXINDEXRK, MAXSTACK, NO_JUMP, NO_REG, OpCode, is_k,
};
use crate::compiler::lexer::Lexer;
use crate::compiler::parser;
use crate::compiler::proto::{
    LocalVar, Proto, ProtoRef, VARARG_HASARG, VARARG_ISVARARG, VARARG_NEEDSARG,
};
use crate::compiler::value::Val;

use super::emit::Compiler;
use super::stat::{compile_block, compile_funcbody};
use super::types::{ExprContext, ExprKind, FuncState};

impl Compiler {
    pub(crate) fn discharge_vars(&mut self, e: &mut ExprContext, line: u32) {
        match e.kind {
            ExprKind::Local => {
                e.kind = ExprKind::NonReloc;
            }
            ExprKind::Upval => {
                let pc = self.emit_abc(OpCode::GetUpval, 0, e.info as u32, 0, line);
                e.info = pc as i32;
                e.kind = ExprKind::Relocable;
            }
            ExprKind::Global => {
                let pc = self.emit_abx(OpCode::GetGlobal, 0, e.info as u32, line);
                e.info = pc as i32;
                e.kind = ExprKind::Relocable;
            }
            ExprKind::Indexed => {
                let table_reg = e.info as u32;
                let key_rk = e.aux as u32;
                self.free_reg(key_rk);
                self.free_reg(table_reg);
                let pc = self.emit_abc(OpCode::GetTable, 0, table_reg, key_rk, line);
                e.info = pc as i32;
                e.kind = ExprKind::Relocable;
            }
            ExprKind::Call | ExprKind::VarArg => {
                self.set_one_ret(e);
            }
            _ => {} 
        }
    }
    pub(super) fn set_one_ret(&mut self, e: &mut ExprContext) {
        if e.kind == ExprKind::Call {
            let mut instr = self.get_instruction(e.info as usize);
            instr.set_c(2);
            self.set_instruction(e.info as usize, instr);
            e.kind = ExprKind::NonReloc;
            #[allow(clippy::cast_possible_wrap)]
            {
                e.info = instr.a() as i32;
            }
        } else if e.kind == ExprKind::VarArg {
            let mut instr = self.get_instruction(e.info as usize);
            instr.set_b(2); 
            self.set_instruction(e.info as usize, instr);
            e.kind = ExprKind::Relocable;
        }
    }
    pub(crate) fn exp2nextreg(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        self.discharge_vars(e, line);
        self.free_expr(e);
        let reg = self.alloc_reg()?;
        self.exp2reg(e, reg, line);
        Ok(())
    }
    pub(crate) fn exp2anyreg(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<u32> {
        self.discharge_vars(e, line);
        if e.kind == ExprKind::NonReloc {
            if !e.has_jumps() {
                return Ok(e.info as u32);
            }
            if e.info as u32 >= u32::from(self.fs().num_active_vars) {
                self.exp2reg(e, e.info as u32, line);
                return Ok(e.info as u32);
            }
        }
        self.exp2nextreg(e, line)?;
        Ok(e.info as u32)
    }
    #[allow(clippy::cast_sign_loss)]
    pub(crate) fn exp2reg(&mut self, e: &mut ExprContext, reg: u32, line: u32) {
        self.discharge2reg(e, reg, line);
        if e.kind == ExprKind::Jmp {
            let mut e_t = e.t;
            self.concat_jumps(&mut e_t, e.info);
            e.t = e_t;
        }
        if e.has_jumps() {
            let mut p_f = NO_JUMP; 
            let mut p_t = NO_JUMP; 
            if self.need_value(e.t) || self.need_value(e.f) {
                let fj = if e.kind == ExprKind::Jmp {
                    NO_JUMP
                } else {
                    self.emit_jump(line) as i32
                };
                p_f = self.code_label(reg, 0, 1, line) as i32; 
                p_t = self.code_label(reg, 1, 0, line) as i32; 
                self.patch_to_here(fj);
            }
            let final_pc = self.get_label();
            let dt_f = if p_f == NO_JUMP {
                final_pc
            } else {
                p_f as usize
            };
            let dt_t = if p_t == NO_JUMP {
                final_pc
            } else {
                p_t as usize
            };
            self.patch_list_aux(e.f, final_pc, reg, dt_f);
            self.patch_list_aux(e.t, final_pc, reg, dt_t);
        }
        e.f = NO_JUMP;
        e.t = NO_JUMP;
        e.info = reg as i32;
        e.kind = ExprKind::NonReloc;
    }
    pub(super) fn discharge2reg(&mut self, e: &mut ExprContext, reg: u32, line: u32) {
        self.discharge_vars(e, line);
        match e.kind {
            ExprKind::Nil => {
                self.emit_nil(reg, 1, line);
            }
            ExprKind::False | ExprKind::True => {
                let bool_val = u32::from(e.kind == ExprKind::True);
                self.emit_abc(OpCode::LoadBool, reg, bool_val, 0, line);
            }
            ExprKind::K => {
                self.emit_abx(OpCode::LoadK, reg, e.info as u32, line);
            }
            ExprKind::KNum => {
                let k = self.number_constant(e.nval).unwrap_or(0); 
                self.emit_abx(OpCode::LoadK, reg, k, line);
            }
            ExprKind::Relocable => {
                let mut instr = self.get_instruction(e.info as usize);
                instr.set_a(reg);
                self.set_instruction(e.info as usize, instr);
            }
            ExprKind::NonReloc => {
                if reg != e.info as u32 {
                    self.emit_abc(OpCode::Move, reg, e.info as u32, 0, line);
                }
            }
            _ => {
                return;
            }
        }
        e.info = reg as i32;
        e.kind = ExprKind::NonReloc;
    }
    pub(super) fn discharge2anyreg(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        if e.kind != ExprKind::NonReloc {
            self.reserve_regs(1)?;
            let reg = u32::from(self.fs().free_reg) - 1;
            self.discharge2reg(e, reg, line);
        }
        Ok(())
    }
    pub(crate) fn exp2rk(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<u32> {
        self.exp2val(e, line);
        match e.kind {
            ExprKind::True | ExprKind::False | ExprKind::Nil
                if self.fs().proto.constants.len() <= MAXINDEXRK as usize =>
            {
                let k = match e.kind {
                    ExprKind::Nil => self.nil_constant()?,
                    ExprKind::True => self.add_constant(Val::Bool(true))?,
                    _ => self.add_constant(Val::Bool(false))?, 
                };
                e.info = k as i32;
                e.kind = ExprKind::K;
                return Ok(k | BITRK);
            }
            ExprKind::K if (e.info as u32) <= MAXINDEXRK => {
                return Ok(e.info as u32 | BITRK);
            }
            ExprKind::KNum => {
                let k = self.number_constant(e.nval)?;
                if k <= MAXINDEXRK {
                    e.info = k as i32;
                    e.kind = ExprKind::K;
                    return Ok(k | BITRK);
                }
            }
            _ => {}
        }
        let reg = self.exp2anyreg(e, line)?;
        Ok(reg)
    }
    pub(crate) fn free_expr(&mut self, e: &ExprContext) {
        if e.kind == ExprKind::NonReloc {
            self.free_reg(e.info as u32);
        }
    }
    pub(crate) fn storevar(
        &mut self,
        var: &ExprContext,
        ex: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        match var.kind {
            ExprKind::Local => {
                self.free_expr(ex);
                self.exp2reg(ex, var.info as u32, line);
            }
            ExprKind::Upval => {
                let e = self.exp2anyreg(ex, line)?;
                self.emit_abc(OpCode::SetUpval, e, var.info as u32, 0, line);
            }
            ExprKind::Global => {
                let e = self.exp2anyreg(ex, line)?;
                self.emit_abx(OpCode::SetGlobal, e, var.info as u32, line);
            }
            ExprKind::Indexed => {
                let e = self.exp2rk(ex, line)?;
                self.emit_abc(OpCode::SetTable, var.info as u32, var.aux as u32, e, line);
            }
            _ => {
                return Err(self.syntax_error("invalid assignment target"));
            }
        }
        self.free_expr(ex);
        Ok(())
    }
    pub(crate) fn compile_condition(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<i32> {
        if e.kind == ExprKind::Nil {
            e.kind = ExprKind::False;
        }
        self.goiftrue(e, line)?;
        Ok(e.f)
    }
    pub(crate) fn goiftrue(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        self.discharge_vars(e, line);
        let pc = match e.kind {
            ExprKind::K | ExprKind::KNum | ExprKind::True => {
                NO_JUMP 
            }
            ExprKind::False => self.emit_jump(line) as i32,
            ExprKind::Jmp => {
                self.invertjump(e);
                e.info
            }
            _ => self.jumponcond(e, false, line)?,
        };
        let mut f = e.f;
        self.concat_jumps(&mut f, pc);
        e.f = f;
        self.patch_to_here(e.t);
        e.t = NO_JUMP;
        Ok(())
    }
    pub(crate) fn goiffalse(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        self.discharge_vars(e, line);
        let pc = match e.kind {
            ExprKind::Nil | ExprKind::False => {
                NO_JUMP 
            }
            ExprKind::True => self.emit_jump(line) as i32,
            ExprKind::Jmp => e.info,
            _ => self.jumponcond(e, true, line)?,
        };
        let mut t = e.t;
        self.concat_jumps(&mut t, pc);
        e.t = t;
        self.patch_to_here(e.f);
        e.f = NO_JUMP;
        Ok(())
    }
    pub(super) fn get_jump_control(&self, pc: usize) -> usize {
        if pc >= 1 {
            let prev = self.get_instruction(pc - 1);
            if prev.opcode().is_test_mode() {
                return pc - 1;
            }
        }
        pc
    }
    pub(super) fn invertjump(&mut self, e: &ExprContext) {
        let jmp_pc = e.info as usize;
        let ctrl_pc = self.get_jump_control(jmp_pc);
        let mut instr = self.get_instruction(ctrl_pc);
        let a = instr.a();
        instr.set_a(u32::from(a == 0));
        self.set_instruction(ctrl_pc, instr);
    }
    pub(super) fn jumponcond(&mut self, e: &mut ExprContext, cond: bool, line: u32) -> LuaResult<i32> {
        if e.kind == ExprKind::Relocable {
            let instr = self.get_instruction(e.info as usize);
            if instr.opcode() == OpCode::Not {
                self.fs_mut().proto.code.pop();
                self.fs_mut().proto.line_info.pop();
                let cond_val = u32::from(!cond);
                self.emit_abc(OpCode::Test, instr.b(), 0, cond_val, line);
                return Ok(self.emit_jump(line) as i32);
            }
        }
        self.discharge2anyreg(e, line)?;
        self.free_expr(e);
        let cond_val = u32::from(cond);
        self.emit_abc(OpCode::TestSet, NO_REG, e.info as u32, cond_val, line);
        Ok(self.emit_jump(line) as i32)
    }
    pub(crate) fn exp2val(&mut self, e: &mut ExprContext, line: u32) {
        if e.has_jumps() {
            drop(self.exp2anyreg(e, line));
        } else {
            self.discharge_vars(e, line);
        }
    }
    pub(crate) fn set_multret(&mut self, e: &mut ExprContext) {
        if e.kind == ExprKind::Call {
            let mut instr = self.get_instruction(e.info as usize);
            instr.set_c(0); 
            self.set_instruction(e.info as usize, instr);
        } else if e.kind == ExprKind::VarArg {
            let mut instr = self.get_instruction(e.info as usize);
            instr.set_b(0); 
            instr.set_a(u32::from(self.fs().free_reg));
            self.set_instruction(e.info as usize, instr);
            self.reserve_regs(1).ok(); 
            e.kind = ExprKind::Relocable;
        }
    }
    pub(crate) fn set_indexed(
        &mut self,
        table: &mut ExprContext,
        key: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        table.aux = self.exp2rk(key, line)? as i32;
        table.kind = ExprKind::Indexed;
        Ok(())
    }
    pub(crate) fn code_self(
        &mut self,
        e: &mut ExprContext,
        key: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        self.exp2anyreg(e, line)?;
        self.free_expr(e);
        let func = u32::from(self.fs().free_reg);
        self.reserve_regs(2)?;
        let key_rk = self.exp2rk(key, line)?;
        self.emit_abc(OpCode::OpSelf, func, e.info as u32, key_rk, line);
        self.free_expr(key);
        e.info = func as i32;
        e.kind = ExprKind::NonReloc;
        Ok(())
    }
    pub(super) fn const_fold(op: OpCode, e1: &mut ExprContext, e2: &ExprContext) -> bool {
        if !e1.is_numeral() || !e2.is_numeral() {
            return false;
        }
        let v1 = e1.nval;
        let v2 = e2.nval;
        let r = match op {
            OpCode::Add => v1 + v2,
            OpCode::Sub => v1 - v2,
            OpCode::Mul => v1 * v2,
            OpCode::Div => {
                if v2 == 0.0 {
                    return false;
                }
                v1 / v2
            }
            OpCode::Mod => {
                if v2 == 0.0 {
                    return false;
                }
                (v1 / v2).floor().mul_add(-v2, v1)
            }
            OpCode::Pow => v1.powf(v2),
            OpCode::Unm => -v1,
            _ => return false,
        };
        if r.is_nan() {
            return false;
        }
        e1.nval = r;
        true
    }
    pub(crate) fn code_arith(
        &mut self,
        op: OpCode,
        e1: &mut ExprContext,
        e2: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        if Self::const_fold(op, e1, e2) {
            return Ok(());
        }
        if op == OpCode::Concat {
            self.exp2nextreg(e2, line)?;
            self.exp2anyreg(e1, line)?;
        }
        let (b, c) = if op == OpCode::Unm || op == OpCode::Not || op == OpCode::Len {
            let b = self.exp2anyreg(e1, line)?;
            (b, 0)
        } else if op == OpCode::Concat {
            let b = e1.info as u32;
            let c = e2.info as u32;
            self.free_expr(e2);
            self.free_expr(e1);
            (b, c)
        } else {
            let c = self.exp2rk(e2, line)?;
            let b = self.exp2rk(e1, line)?;
            (b, c)
        };
        if op != OpCode::Concat {
            self.free_expr(e2);
            self.free_expr(e1);
        }
        e1.info = self.emit_abc(op, 0, b, c, line) as i32;
        e1.kind = ExprKind::Relocable;
        Ok(())
    }
    pub(crate) fn code_comp(
        &mut self,
        op: OpCode,
        cond: u32,
        e1: &mut ExprContext,
        e2: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        let mut b = self.exp2rk(e1, line)?;
        let mut c = self.exp2rk(e2, line)?;
        self.free_expr(e2);
        self.free_expr(e1);
        let mut cond = cond;
        if cond == 0 && op != OpCode::Eq {
            std::mem::swap(&mut b, &mut c);
            cond = 1;
        }
        self.emit_abc(op, cond, b, c, line);
        let jmp = self.emit_jump(line);
        e1.info = jmp as i32;
        e1.kind = ExprKind::Jmp;
        e1.t = NO_JUMP;
        e1.f = NO_JUMP;
        Ok(())
    }
    pub(crate) fn infix(
        &mut self,
        op: crate::compiler::ast::BinOp,
        e: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        match op {
            crate::compiler::ast::BinOp::And => {
                self.goiftrue(e, line)?;
            }
            crate::compiler::ast::BinOp::Or => {
                self.goiffalse(e, line)?;
            }
            crate::compiler::ast::BinOp::Concat => {
                self.exp2nextreg(e, line)?;
            }
            _ => {
                if !e.is_numeral() {
                    self.exp2rk(e, line)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn postfix(
        &mut self,
        op: crate::compiler::ast::BinOp,
        e1: &mut ExprContext,
        e2: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        match op {
            crate::compiler::ast::BinOp::And => {
                debug_assert!(e1.t == NO_JUMP);
                self.discharge_vars(e2, line);
                let mut f = e2.f;
                self.concat_jumps(&mut f, e1.f);
                e2.f = f;
                *e1 = *e2;
            }
            crate::compiler::ast::BinOp::Or => {
                debug_assert!(e1.f == NO_JUMP);
                self.discharge_vars(e2, line);
                let mut t = e2.t;
                self.concat_jumps(&mut t, e1.t);
                e2.t = t;
                *e1 = *e2;
            }
            crate::compiler::ast::BinOp::Concat => {
                self.exp2val(e2, line);
                if e2.kind == ExprKind::Relocable {
                    let instr = self.get_instruction(e2.info as usize);
                    if instr.opcode() == OpCode::Concat {
                        self.free_expr(e1);
                        let mut merged = self.get_instruction(e2.info as usize);
                        merged.set_b(e1.info as u32);
                        self.set_instruction(e2.info as usize, merged);
                        e1.kind = ExprKind::Relocable;
                        e1.info = e2.info;
                        return Ok(());
                    }
                }
                self.exp2nextreg(e2, line)?;
                self.code_arith(OpCode::Concat, e1, e2, line)?;
            }
            crate::compiler::ast::BinOp::Add => self.code_arith(OpCode::Add, e1, e2, line)?,
            crate::compiler::ast::BinOp::Sub => self.code_arith(OpCode::Sub, e1, e2, line)?,
            crate::compiler::ast::BinOp::Mul => self.code_arith(OpCode::Mul, e1, e2, line)?,
            crate::compiler::ast::BinOp::Div => self.code_arith(OpCode::Div, e1, e2, line)?,
            crate::compiler::ast::BinOp::Mod => self.code_arith(OpCode::Mod, e1, e2, line)?,
            crate::compiler::ast::BinOp::Pow => self.code_arith(OpCode::Pow, e1, e2, line)?,
            crate::compiler::ast::BinOp::Eq => self.code_comp(OpCode::Eq, 1, e1, e2, line)?,
            crate::compiler::ast::BinOp::Ne => self.code_comp(OpCode::Eq, 0, e1, e2, line)?,
            crate::compiler::ast::BinOp::Lt => self.code_comp(OpCode::Lt, 1, e1, e2, line)?,
            crate::compiler::ast::BinOp::Le => self.code_comp(OpCode::Le, 1, e1, e2, line)?,
            crate::compiler::ast::BinOp::Gt => self.code_comp(OpCode::Lt, 0, e1, e2, line)?,
            crate::compiler::ast::BinOp::Ge => self.code_comp(OpCode::Le, 0, e1, e2, line)?,
        }
        Ok(())
    }
    pub(crate) fn prefix(
        &mut self,
        op: crate::compiler::ast::UnOp,
        e: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        let mut e2 = ExprContext::number(0.0);
        match op {
            crate::compiler::ast::UnOp::Neg => {
                if e.kind == ExprKind::K {
                    self.exp2anyreg(e, line)?;
                }
                self.code_arith(OpCode::Unm, e, &mut e2, line)?;
            }
            crate::compiler::ast::UnOp::Not => {
                self.code_not(e, line)?;
            }
            crate::compiler::ast::UnOp::Len => {
                self.exp2anyreg(e, line)?;
                self.code_arith(OpCode::Len, e, &mut e2, line)?;
            }
        }
        Ok(())
    }
    pub(super) fn code_not(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
        self.discharge_vars(e, line);
        match e.kind {
            ExprKind::Nil | ExprKind::False => {
                e.kind = ExprKind::True;
            }
            ExprKind::K | ExprKind::KNum | ExprKind::True => {
                e.kind = ExprKind::False;
            }
            ExprKind::Jmp => {
                self.invertjump(e);
            }
            ExprKind::Relocable | ExprKind::NonReloc => {
                self.discharge2anyreg(e, line)?;
                self.free_expr(e);
                e.info = self.emit_abc(OpCode::Not, 0, e.info as u32, 0, line) as i32;
                e.kind = ExprKind::Relocable;
            }
            _ => {} 
        }
        std::mem::swap(&mut e.t, &mut e.f);
        self.remove_values(e.f);
        self.remove_values(e.t);
        Ok(())
    }
    pub(crate) fn get_label(&mut self) -> usize {
        let pc = self.fs().pc();
        self.fs_mut().last_target = pc as i32;
        pc
    }
    pub(crate) fn code_setlist(&mut self, base: u32, nelems: u32, tostore: u32, line: u32) {
        let c = (nelems - 1) / LFIELDS_PER_FLUSH + 1;
        let b = if tostore == 0 { 0 } else { tostore };
        if c <= MAXARG_C {
            self.emit_abc(OpCode::SetList, base, b, c, line);
        } else {
            self.emit_abc(OpCode::SetList, base, b, 0, line);
            self.emit(Instruction::from_raw(c), line);
        }
        self.fs_mut().free_reg = (base + 1) as u8;
    }
    pub(crate) fn enter_function(&mut self, source: &str) {
        let fs = FuncState::new(source);
        self.func_states.push(fs);
    }
    #[allow(clippy::expect_used)]
    pub(crate) fn leave_function(&mut self) -> Proto {
        self.emit_abc(OpCode::Return, 0, 1, 0, self.current_line);
        self.remove_locals(0);
        let mut fs = self
            .func_states
            .pop()
            .expect("cannot leave global function");
        fs.proto.upvalue_names = fs.upvalues.iter().map(|uv| uv.name.clone()).collect();
        fs.proto
    }
    #[allow(clippy::expect_used)]
    pub(super) fn finish_main(&mut self) -> Proto {
        self.emit_abc(OpCode::Return, 0, 1, 0, self.current_line);
        self.remove_locals(0);
        let mut fs = self
            .func_states
            .pop()
            .expect("cannot finish without main function");
        fs.proto.upvalue_names = fs.upvalues.iter().map(|uv| uv.name.clone()).collect();
        fs.proto
    }
}

pub(super) fn compile_expr(compiler: &mut Compiler, expr: &crate::compiler::ast::Expr) -> LuaResult<ExprContext> {
    use crate::compiler::ast::Expr;
    let line = expr.span().line;
    compiler.current_line = line;
    match expr {
        Expr::Nil(_) => Ok(ExprContext::new(ExprKind::Nil, 0)),
        Expr::True(_) => Ok(ExprContext::new(ExprKind::True, 0)),
        Expr::False(_) => Ok(ExprContext::new(ExprKind::False, 0)),
        Expr::Number(n, _) => Ok(ExprContext::number(*n)),
        Expr::Str(s, _) => {
            let k = compiler.string_constant(s)?;
            Ok(ExprContext::new(ExprKind::K, k as i32))
        }
        Expr::VarArg(_) => {
            compiler.fs_mut().proto.is_vararg &= !VARARG_NEEDSARG;
            let pc = compiler.emit_abc(OpCode::VarArg, 0, 1, 0, line);
            Ok(ExprContext::new(ExprKind::VarArg, pc as i32))
        }
        Expr::Name(name, _) => compiler.resolve_var(name),
        Expr::BinOp {
            op, left, right, ..
        } => {
            let mut e1 = compile_expr(compiler, left)?;
            compiler.infix(*op, &mut e1, line)?;
            let mut e2 = compile_expr(compiler, right)?;
            compiler.postfix(*op, &mut e1, &mut e2, line)?;
            Ok(e1)
        }
        Expr::UnOp { op, operand, .. } => {
            let mut e = compile_expr(compiler, operand)?;
            compiler.prefix(*op, &mut e, line)?;
            Ok(e)
        }
        Expr::Index { table, key, .. } => {
            let mut t = compile_expr(compiler, table)?;
            compiler.exp2anyreg(&mut t, line)?;
            let mut k = compile_expr(compiler, key)?;
            compiler.set_indexed(&mut t, &mut k, line)?;
            Ok(t)
        }
        Expr::Field { table, field, .. } => {
            let mut t = compile_expr(compiler, table)?;
            compiler.exp2anyreg(&mut t, line)?;
            let k_idx = compiler.string_constant(field.as_bytes())?;
            let mut k = ExprContext::new(ExprKind::K, k_idx as i32);
            compiler.set_indexed(&mut t, &mut k, line)?;
            Ok(t)
        }
        Expr::MethodCall {
            table,
            method,
            args,
            ..
        } => {
            let mut obj = compile_expr(compiler, table)?;
            compiler.exp2anyreg(&mut obj, line)?;
            let k = compiler.string_constant(method.as_bytes())?;
            let mut key = ExprContext::new(ExprKind::K, k as i32);
            compiler.code_self(&mut obj, &mut key, line)?;
            compile_funcargs(compiler, &mut obj, args, line)?;
            Ok(obj)
        }
        Expr::Call { func, args, .. } => {
            let mut f = compile_expr(compiler, func)?;
            compiler.exp2nextreg(&mut f, line)?;
            compile_funcargs(compiler, &mut f, args, line)?;
            Ok(f)
        }
        Expr::FuncDef { body, .. } => compile_funcbody(compiler, body, false, line),
        Expr::TableCtor { fields, .. } => compile_table_ctor(compiler, fields, line),
        Expr::Paren(inner, _) => {
            let mut e = compile_expr(compiler, inner)?;
            compiler.discharge_vars(&mut e, line);
            Ok(e)
        }
    }
}
pub(super) fn compile_funcargs(
    compiler: &mut Compiler,
    func: &mut ExprContext,
    args: &[crate::compiler::ast::Expr],
    line: u32,
) -> LuaResult<()> {
    let base = func.info as u32;
    if args.is_empty() {
    } else {
        for (i, arg) in args.iter().enumerate() {
            let mut e = compile_expr(compiler, arg)?;
            if i == args.len() - 1 {
                if e.kind == ExprKind::Call || e.kind == ExprKind::VarArg {
                    compiler.set_multret(&mut e);
                    let pc = compiler.emit_abc(OpCode::Call, base, 0, 2, line);
                    func.info = pc as i32;
                    func.kind = ExprKind::Call;
                    compiler.fs_mut().free_reg = (base + 1) as u8;
                    return Ok(());
                }
            }
            compiler.exp2nextreg(&mut e, line)?;
        }
    }
    let nparams = u32::from(compiler.fs().free_reg) - (base + 1);
    let pc = compiler.emit_abc(OpCode::Call, base, nparams + 1, 2, line);
    func.info = pc as i32;
    func.kind = ExprKind::Call;
    compiler.fs_mut().free_reg = (base + 1) as u8;
    Ok(())
}
pub(super) fn compile_table_ctor(
    compiler: &mut Compiler,
    fields: &[crate::compiler::ast::TableField],
    line: u32,
) -> LuaResult<ExprContext> {
    use crate::compiler::ast::TableField;
    let pc = compiler.emit_abc(OpCode::NewTable, 0, 0, 0, line);
    let mut t = ExprContext::new(ExprKind::Relocable, pc as i32);
    compiler.exp2nextreg(&mut t, line)?;
    let table_reg = t.info as u32;
    let mut na: u32 = 0; 
    let mut nh: u32 = 0; 
    let mut tostore: u32 = 0; 
    let last_value_idx = fields
        .iter()
        .rposition(|f| matches!(f, TableField::ValueField { .. }));
    for (i, field) in fields.iter().enumerate() {
        match field {
            TableField::ValueField { value, .. } => {
                na += 1;
                tostore += 1;
                let is_last = last_value_idx == Some(i);
                let mut val_e = compile_expr(compiler, value)?;
                if is_last && is_multret_expr(value) {
                    compiler.set_multret(&mut val_e);
                    compiler.code_setlist(table_reg, na, 0, line); 
                    na -= 1; 
                    tostore = 0;
                } else {
                    compiler.exp2nextreg(&mut val_e, line)?;
                    if tostore >= LFIELDS_PER_FLUSH {
                        compiler.code_setlist(table_reg, na, tostore, line);
                        tostore = 0;
                    }
                }
            }
            TableField::NameField { name, value, .. } => {
                nh += 1;
                let k = compiler.string_constant(name.as_bytes())?;
                let mut key_e = ExprContext::new(ExprKind::K, k as i32);
                let key_rk = compiler.exp2rk(&mut key_e, line)?;
                let mut val_e = compile_expr(compiler, value)?;
                let val_rk = compiler.exp2rk(&mut val_e, line)?;
                compiler.emit_abc(OpCode::SetTable, table_reg, key_rk, val_rk, line);
                compiler.free_expr(&val_e);
                compiler.free_expr(&key_e);
            }
            TableField::IndexField { key, value, .. } => {
                nh += 1;
                let mut key_e = compile_expr(compiler, key)?;
                let key_rk = compiler.exp2rk(&mut key_e, line)?;
                let mut val_e = compile_expr(compiler, value)?;
                let val_rk = compiler.exp2rk(&mut val_e, line)?;
                compiler.emit_abc(OpCode::SetTable, table_reg, key_rk, val_rk, line);
                compiler.free_expr(&val_e);
                compiler.free_expr(&key_e);
            }
        }
    }
    if tostore > 0 {
        compiler.code_setlist(table_reg, na, tostore, line);
    }
    let mut instr = compiler.get_instruction(pc);
    instr.set_b(int2fb(na));
    instr.set_c(int2fb(nh));
    compiler.set_instruction(pc, instr);
    Ok(t)
}
pub(super) fn is_multret_expr(expr: &crate::compiler::ast::Expr) -> bool {
    matches!(
        expr,
        crate::compiler::ast::Expr::Call { .. }
            | crate::compiler::ast::Expr::MethodCall { .. }
            | crate::compiler::ast::Expr::VarArg(..)
    )
}
pub(crate) fn int2fb(mut x: u32) -> u32 {
    if x < 8 {
        return x;
    }
    let mut e = 0u32;
    while x >= 16 {
        x = (x + 1) >> 1;
        e += 1;
    }
    ((e + 1) << 3) | (x - 8)
}
