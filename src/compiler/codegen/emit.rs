//! `Compiler` 结构体与它的「后端」半边：指令发射与回填、常量池、
//! 寄存器分配、局部变量 / upvalue / 块作用域管理。

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

use super::types::{BlockContext, ConstantKey, ExprContext, ExprKind, FuncState, UpvalDesc};

pub struct Compiler {
    pub(super) func_states: Vec<FuncState>,
    pub(super) source_name: String,
    pub(crate) current_line: u32,
}
#[allow(dead_code)] 
impl Compiler {
    pub(super) fn new(source_name: &str) -> Self {
        let fs = FuncState::new(source_name);
        Self {
            func_states: vec![fs],
            source_name: source_name.to_string(),
            current_line: 1,
        }
    }
    #[allow(clippy::expect_used)]
    pub(crate) fn fs(&self) -> &FuncState {
        self.func_states
            .last()
            .expect("compiler must have at least one function state")
    }
    #[allow(clippy::expect_used)]
    pub(crate) fn fs_mut(&mut self) -> &mut FuncState {
        self.func_states
            .last_mut()
            .expect("compiler must have at least one function state")
    }
    pub(super) fn syntax_error(&self, msg: &str) -> LuaError {
        LuaError::Syntax(SyntaxError {
            message: msg.to_string(),
            source: self.source_name.clone(),
            line: self.current_line,
            raw_message: None,
        })
    }
    pub(crate) fn emit(&mut self, instr: Instruction, line: u32) -> usize {
        self.discharge_jpc();
        let fs = self.fs_mut();
        let pc = fs.proto.code.len();
        fs.proto.code.push(instr.raw());
        fs.proto.line_info.push(line);
        pc
    }
    pub(crate) fn emit_abc(&mut self, op: OpCode, a: u32, b: u32, c: u32, line: u32) -> usize {
        self.emit(Instruction::abc(op, a, b, c), line)
    }
    pub(crate) fn emit_nil(&mut self, from: u32, n: u32, line: u32) {
        let fs = self.fs();
        let pc = fs.pc();
        let last_target = fs.last_target;
        if (pc as i32) > last_target {
            if pc == 0 {
                return;
            }
            let prev = self.get_instruction(pc - 1);
            if prev.opcode() == OpCode::LoadNil {
                let pfrom = prev.a();
                let pto = prev.b();
                if pfrom <= from && from <= pto + 1 {
                    if from + n - 1 > pto {
                        let mut updated = prev;
                        updated.set_b(from + n - 1);
                        self.set_instruction(pc - 1, updated);
                    }
                    return;
                }
            }
        }
        self.emit_abc(OpCode::LoadNil, from, from + n - 1, 0, line);
    }
    pub(crate) fn emit_abx(&mut self, op: OpCode, a: u32, bx: u32, line: u32) -> usize {
        self.emit(Instruction::a_bx(op, a, bx), line)
    }
    #[allow(dead_code)]
    pub(crate) fn emit_asbx(&mut self, op: OpCode, a: u32, sbx: i32, line: u32) -> usize {
        self.emit(Instruction::a_sbx(op, a, sbx), line)
    }
    pub(crate) fn get_instruction(&self, pc: usize) -> Instruction {
        Instruction::from_raw(self.fs().proto.code[pc])
    }
    pub(crate) fn set_instruction(&mut self, pc: usize, instr: Instruction) {
        self.fs_mut().proto.code[pc] = instr.raw();
    }
    pub(crate) fn emit_jump(&mut self, line: u32) -> usize {
        let jpc = self.fs().jpc;
        let fs = self.fs_mut();
        fs.jpc = NO_JUMP;
        let pc = self.emit_asbx(OpCode::Jmp, 0, NO_JUMP, line);
        self.concat_jumps_result(pc, jpc)
    }
    pub(crate) fn patch_jump(&mut self, pc: usize, target: usize) {
        let offset = target as i32 - pc as i32 - 1;
        let mut instr = self.get_instruction(pc);
        instr.set_sbx(offset);
        self.set_instruction(pc, instr);
    }
    pub(super) fn get_jump_target(&self, pc: usize) -> i32 {
        let offset = self.get_instruction(pc).sbx();
        if offset == NO_JUMP {
            return NO_JUMP;
        }
        (pc as i32) + 1 + offset
    }
    pub(super) fn concat_jumps_result(&mut self, l1: usize, l2: i32) -> usize {
        if l2 == NO_JUMP {
            return l1;
        }
        let l1_i32 = l1 as i32;
        if l1_i32 == NO_JUMP {
            return l2 as usize;
        }
        let mut list = l1_i32;
        loop {
            let next = self.get_jump_target(list as usize);
            if next == NO_JUMP {
                self.patch_jump(list as usize, l2 as usize);
                break;
            }
            list = next;
        }
        l1
    }
    pub(crate) fn concat_jumps(&mut self, l1: &mut i32, l2: i32) {
        if l2 == NO_JUMP {
            return;
        }
        if *l1 == NO_JUMP {
            *l1 = l2;
        } else {
            let mut list = *l1;
            loop {
                let next = self.get_jump_target(list as usize);
                if next == NO_JUMP {
                    self.patch_jump(list as usize, l2 as usize);
                    break;
                }
                list = next;
            }
        }
    }
    pub(crate) fn patch_list(&mut self, list: i32, target: usize) {
        if target == self.fs().pc() {
            self.patch_to_here(list);
        } else {
            self.patch_list_aux(list, target, NO_REG, target);
        }
    }
    pub(crate) fn patch_to_here(&mut self, list: i32) {
        let jpc = self.fs().jpc;
        let mut merged = jpc;
        self.concat_jumps(&mut merged, list);
        self.fs_mut().jpc = merged;
    }
    pub(super) fn discharge_jpc(&mut self) {
        let jpc = self.fs().jpc;
        if jpc != NO_JUMP {
            let pc = self.fs().pc();
            self.patch_list_aux(jpc, pc, NO_REG, pc);
            self.fs_mut().jpc = NO_JUMP;
        }
    }
    pub(super) fn need_value(&self, mut list: i32) -> bool {
        while list != NO_JUMP {
            let ctrl = self.get_jump_control(list as usize);
            let instr = self.get_instruction(ctrl);
            if instr.opcode() != OpCode::TestSet {
                return true;
            }
            list = self.get_jump_target(list as usize);
        }
        false
    }
    pub(super) fn patch_test_reg(&mut self, node: usize, reg: u32) -> bool {
        let ctrl = self.get_jump_control(node);
        let instr = self.get_instruction(ctrl);
        if instr.opcode() != OpCode::TestSet {
            return false;
        }
        if reg != NO_REG && reg != instr.b() {
            let mut patched = instr;
            patched.set_a(reg);
            self.set_instruction(ctrl, patched);
        } else {
            let replacement = Instruction::abc(OpCode::Test, instr.b(), 0, instr.c());
            self.set_instruction(ctrl, replacement);
        }
        true
    }
    pub(super) fn remove_values(&mut self, mut list: i32) {
        while list != NO_JUMP {
            self.patch_test_reg(list as usize, NO_REG);
            list = self.get_jump_target(list as usize);
        }
    }
    pub(super) fn patch_list_aux(&mut self, mut list: i32, vtarget: usize, reg: u32, dtarget: usize) {
        while list != NO_JUMP {
            let next = self.get_jump_target(list as usize);
            if self.patch_test_reg(list as usize, reg) {
                self.patch_jump(list as usize, vtarget);
            } else {
                self.patch_jump(list as usize, dtarget);
            }
            list = next;
        }
    }
    pub(super) fn code_label(&mut self, reg: u32, b: u32, jump: u32, line: u32) -> usize {
        self.get_label();
        self.emit_abc(OpCode::LoadBool, reg, b, jump, line)
    }
    pub(crate) fn add_constant(&mut self, val: Val) -> LuaResult<u32> {
        let key = match val {
            Val::Num(n) => ConstantKey::Num(n.to_bits()),
            Val::Bool(b) => ConstantKey::Bool(b),
            _ => {
                let fs = self.fs_mut();
                let idx = fs.proto.constants.len();
                if idx > MAXARG_BX as usize {
                    return Err(self.syntax_error("constant table overflow"));
                }
                fs.proto.constants.push(val);
                #[allow(clippy::cast_possible_truncation)]
                return Ok(idx as u32);
            }
        };
        let fs = self.fs_mut();
        if let Some(&idx) = fs.constant_index.get(&key) {
            return Ok(idx);
        }
        let idx = fs.proto.constants.len();
        if idx > MAXARG_BX as usize {
            return Err(self.syntax_error("constant table overflow"));
        }
        fs.proto.constants.push(val);
        #[allow(clippy::cast_possible_truncation)]
        let idx = idx as u32;
        fs.constant_index.insert(key, idx);
        Ok(idx)
    }
    pub(crate) fn string_constant(&mut self, s: &[u8]) -> LuaResult<u32> {
        let key = ConstantKey::Str(s.to_vec());
        let fs = self.fs_mut();
        if let Some(&idx) = fs.constant_index.get(&key) {
            return Ok(idx);
        }
        let idx = fs.proto.constants.len();
        if idx > MAXARG_BX as usize {
            return Err(self.syntax_error("constant table overflow"));
        }
        fs.proto.constants.push(Val::Nil);
        #[allow(clippy::cast_possible_truncation)]
        let idx = idx as u32;
        fs.proto.string_pool.push((idx, s.to_vec()));
        fs.constant_index.insert(key, idx);
        Ok(idx)
    }
    pub(crate) fn number_constant(&mut self, n: f64) -> LuaResult<u32> {
        self.add_constant(Val::Num(n))
    }
    pub(crate) fn nil_constant(&mut self) -> LuaResult<u32> {
        if let Some(idx) = self.fs().nil_k {
            return Ok(idx);
        }
        let fs = self.fs_mut();
        let idx = fs.proto.constants.len();
        if idx > MAXARG_BX as usize {
            return Err(self.syntax_error("constant table overflow"));
        }
        fs.proto.constants.push(Val::Nil);
        #[allow(clippy::cast_possible_truncation)]
        let idx = idx as u32;
        self.fs_mut().nil_k = Some(idx);
        Ok(idx)
    }
    pub(crate) fn alloc_reg(&mut self) -> LuaResult<u32> {
        self.check_stack(1)?;
        let reg = u32::from(self.fs().free_reg);
        self.fs_mut().free_reg += 1;
        Ok(reg)
    }
    pub(crate) fn reserve_regs(&mut self, n: u32) -> LuaResult<()> {
        self.check_stack(n)?;
        self.fs_mut().free_reg += n as u8;
        Ok(())
    }
    pub(crate) fn free_reg(&mut self, reg: u32) {
        let fs = self.fs();
        if reg >= u32::from(fs.num_active_vars) && !is_k(reg) {
            let fs = self.fs_mut();
            if u32::from(fs.free_reg) > 0 && reg == u32::from(fs.free_reg) - 1 {
                fs.free_reg -= 1;
            }
        }
    }
    pub(super) fn check_stack(&mut self, n: u32) -> LuaResult<()> {
        let new_stack = u32::from(self.fs().free_reg) + n;
        if new_stack > MAXSTACK {
            return Err(self.syntax_error("function or expression too complex"));
        }
        let fs = self.fs_mut();
        if new_stack > u32::from(fs.proto.max_stack_size) {
            fs.proto.max_stack_size = new_stack as u8;
        }
        Ok(())
    }
    pub(super) fn search_local(&self, name: &str) -> Option<u8> {
        let fs = self.fs();
        for i in (0..fs.num_active_vars).rev() {
            let var_idx = fs.active_vars[i as usize];
            if fs.proto.local_vars[var_idx as usize].name == name {
                return Some(i);
            }
        }
        None
    }
    pub(super) fn search_upvalue(&self, name: &str) -> Option<u8> {
        let fs = self.fs();
        for (i, uv) in fs.upvalues.iter().enumerate() {
            if uv.name == name {
                #[allow(clippy::cast_possible_truncation)]
                return Some(i as u8);
            }
        }
        None
    }
    pub(super) fn add_upvalue(
        &mut self,
        fs_idx: usize,
        name: &str,
        in_stack: bool,
        index: u8,
    ) -> LuaResult<u8> {
        let fs = &mut self.func_states[fs_idx];
        for (i, uv) in fs.upvalues.iter().enumerate() {
            if uv.in_stack == in_stack && uv.index == index {
                #[allow(clippy::cast_possible_truncation)]
                return Ok(i as u8);
            }
        }
        let idx = fs.upvalues.len();
        if idx >= LUAI_MAXUPVALUES as usize {
            return Err(self.syntax_error("too many upvalues"));
        }
        fs.upvalues.push(UpvalDesc {
            in_stack,
            index,
            name: name.to_string(),
        });
        fs.proto.num_upvalues = fs.upvalues.len() as u8;
        #[allow(clippy::cast_possible_truncation)]
        Ok(idx as u8)
    }
    pub(crate) fn resolve_var(&mut self, name: &str) -> LuaResult<ExprContext> {
        if let Some(reg) = self.search_local(name) {
            return Ok(ExprContext::new(ExprKind::Local, i32::from(reg)));
        }
        if let Some(idx) = self.search_upvalue(name) {
            return Ok(ExprContext::new(ExprKind::Upval, i32::from(idx)));
        }
        let current_idx = self.func_states.len() - 1;
        if current_idx > 0 {
            if let Some(uv_idx) = self.resolve_var_aux(current_idx, name)? {
                return Ok(ExprContext::new(ExprKind::Upval, i32::from(uv_idx)));
            }
        }
        let k = self.string_constant(name.as_bytes())?;
        Ok(ExprContext {
            kind: ExprKind::Global,
            info: k as i32,
            aux: 0,
            nval: 0.0,
            t: NO_JUMP,
            f: NO_JUMP,
        })
    }
    pub(super) fn resolve_var_aux(&mut self, fs_idx: usize, name: &str) -> LuaResult<Option<u8>> {
        if fs_idx == 0 {
            return Ok(None); 
        }
        let parent_idx = fs_idx - 1;
        let parent_fs = &self.func_states[parent_idx];
        for i in (0..parent_fs.num_active_vars).rev() {
            let var_idx = parent_fs.active_vars[i as usize];
            if parent_fs.proto.local_vars[var_idx as usize].name == name {
                Self::mark_upval(&mut self.func_states[parent_idx], i);
                let uv_idx = self.add_upvalue(fs_idx, name, true, i)?;
                return Ok(Some(uv_idx));
            }
        }
        let parent_fs = &self.func_states[parent_idx];
        for (i, uv) in parent_fs.upvalues.iter().enumerate() {
            if uv.name == name {
                #[allow(clippy::cast_possible_truncation)]
                let uv_idx = self.add_upvalue(fs_idx, name, false, i as u8)?;
                return Ok(Some(uv_idx));
            }
        }
        if let Some(parent_uv) = self.resolve_var_aux(parent_idx, name)? {
            let uv_idx = self.add_upvalue(fs_idx, name, false, parent_uv)?;
            return Ok(Some(uv_idx));
        }
        Ok(None) 
    }
    pub(crate) fn new_local(&mut self, name: &str) -> LuaResult<u16> {
        let fs = self.fs_mut();
        if fs.active_vars.len() >= LUAI_MAXVARS as usize {
            return Err(self.syntax_error("too many local variables"));
        }
        let idx = fs.proto.local_vars.len();
        fs.proto.local_vars.push(LocalVar {
            name: name.to_string(),
            start_pc: 0,
            end_pc: 0,
        });
        #[allow(clippy::cast_possible_truncation)]
        let idx16 = idx as u16;
        fs.active_vars.push(idx16);
        Ok(idx16)
    }
    pub(crate) fn activate_locals(&mut self, n: u32) {
        let fs = self.fs_mut();
        let pc = fs.proto.code.len();
        let start_idx = fs.active_vars.len() - n as usize;
        for i in 0..n as usize {
            let var_idx = fs.active_vars[start_idx + i] as usize;
            if var_idx < fs.proto.local_vars.len() {
                fs.proto.local_vars[var_idx].start_pc = pc as u32;
            }
        }
        fs.num_active_vars += n as u8;
    }
    pub(crate) fn remove_locals(&mut self, to_level: u8) {
        let fs = self.fs_mut();
        let pc = fs.proto.code.len() as u32;
        while fs.num_active_vars > to_level {
            fs.num_active_vars -= 1;
            if let Some(var_idx) = fs.active_vars.pop() {
                if (var_idx as usize) < fs.proto.local_vars.len() {
                    fs.proto.local_vars[var_idx as usize].end_pc = pc;
                }
            }
        }
    }
    pub(crate) fn enter_block(&mut self, is_breakable: bool) {
        let num_active = self.fs().num_active_vars;
        self.fs_mut().blocks.push(BlockContext {
            num_active_vars: num_active,
            has_upval: false,
            is_breakable,
            break_list: NO_JUMP,
            continue_list: NO_JUMP,
        });
    }
    pub(crate) fn leave_block(&mut self) {
        if let Some(block) = self.fs_mut().blocks.pop() {
            self.remove_locals(block.num_active_vars);
            self.fs_mut().free_reg = self.fs().num_active_vars;
            if block.has_upval {
                let level = u32::from(block.num_active_vars);
                self.emit_abc(OpCode::Close, level, 0, 0, self.current_line);
            }
            if block.is_breakable {
                let pc = self.fs().pc();
                self.patch_list(block.break_list, pc);
            }
        }
    }
    pub(super) fn mark_upval(fs: &mut FuncState, level: u8) {
        for block in fs.blocks.iter_mut().rev() {
            if block.num_active_vars <= level {
                block.has_upval = true;
                return;
            }
        }
    }
    pub(crate) fn add_break_jump(&mut self, jump_pc: i32) -> LuaResult<()> {
        let fs = self.fs_mut();
        for block in fs.blocks.iter_mut().rev() {
            if block.is_breakable {
                let mut bl = block.break_list;
                if bl == NO_JUMP {
                    block.break_list = jump_pc;
                } else {
                    loop {
                        let instr = Instruction::from_raw(fs.proto.code[bl as usize]);
                        let next_offset = instr.sbx();
                        if next_offset == NO_JUMP {
                            let offset = jump_pc - bl - 1;
                            let mut patched = instr;
                            patched.set_sbx(offset);
                            fs.proto.code[bl as usize] = patched.raw();
                            break;
                        }
                        bl = bl + 1 + next_offset;
                    }
                }
                return Ok(());
            }
        }
        Err(self.syntax_error("no loop to break"))
    }
    pub(crate) fn add_continue_jump(&mut self, jump_pc: i32) -> LuaResult<()> {
        let fs = self.fs_mut();
        for block in fs.blocks.iter_mut().rev() {
            if block.is_breakable {
                let mut bl = block.continue_list;
                if bl == NO_JUMP {
                    block.continue_list = jump_pc;
                } else {
                    loop {
                        let instr = Instruction::from_raw(fs.proto.code[bl as usize]);
                        let next_offset = instr.sbx();
                        if next_offset == NO_JUMP {
                            let offset = jump_pc - bl - 1;
                            let mut patched = instr;
                            patched.set_sbx(offset);
                            fs.proto.code[bl as usize] = patched.raw();
                            break;
                        }
                        bl = bl + 1 + next_offset;
                    }
                }
                return Ok(());
            }
        }
        Err(self.syntax_error("no loop to continue"))
    }
}
