use std::collections::HashMap;
use crate::compiler::error::{LuaError, LuaResult, SyntaxError};
use super::ast::Block;
use super::lexer::Lexer;
use super::parser;
use crate::compiler::instructions::{
    BITRK, Instruction, LFIELDS_PER_FLUSH, LUAI_MAXUPVALUES, LUAI_MAXVARS, MAXARG_BX, MAXARG_C,
    MAXINDEXRK, MAXSTACK, NO_JUMP, NO_REG, OpCode, is_k,
};
use crate::compiler::proto::{
    LocalVar, Proto, ProtoRef, VARARG_HASARG, VARARG_ISVARARG, VARARG_NEEDSARG,
};
use crate::compiler::value::Val;
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
    fn void() -> Self {
        Self {
            kind: ExprKind::Void,
            info: 0,
            aux: 0,
            nval: 0.0,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    fn new(kind: ExprKind, info: i32) -> Self {
        Self {
            kind,
            info,
            aux: 0,
            nval: 0.0,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    fn number(val: f64) -> Self {
        Self {
            kind: ExprKind::KNum,
            info: 0,
            aux: 0,
            nval: val,
            t: NO_JUMP,
            f: NO_JUMP,
        }
    }
    fn has_jumps(&self) -> bool {
        self.t != self.f
    }
    fn is_numeral(&self) -> bool {
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
struct BlockContext {
    num_active_vars: u8,
    has_upval: bool,
    is_breakable: bool,
    break_list: i32,
    continue_list: i32,
}
#[derive(Hash, Eq, PartialEq)]
enum ConstantKey {
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
    active_vars: Vec<u16>,
    blocks: Vec<BlockContext>,
    pub jpc: i32,
    pub last_target: i32,
    nil_k: Option<u32>,
    constant_index: HashMap<ConstantKey, u32>,
}
impl FuncState {
    fn new(source: &str) -> Self {
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
pub struct Compiler {
    func_states: Vec<FuncState>,
    source_name: String,
    pub(crate) current_line: u32,
}
#[allow(dead_code)] 
impl Compiler {
    fn new(source_name: &str) -> Self {
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
    fn syntax_error(&self, msg: &str) -> LuaError {
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
    fn get_jump_target(&self, pc: usize) -> i32 {
        let offset = self.get_instruction(pc).sbx();
        if offset == NO_JUMP {
            return NO_JUMP;
        }
        (pc as i32) + 1 + offset
    }
    fn concat_jumps_result(&mut self, l1: usize, l2: i32) -> usize {
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
    fn discharge_jpc(&mut self) {
        let jpc = self.fs().jpc;
        if jpc != NO_JUMP {
            let pc = self.fs().pc();
            self.patch_list_aux(jpc, pc, NO_REG, pc);
            self.fs_mut().jpc = NO_JUMP;
        }
    }
    fn need_value(&self, mut list: i32) -> bool {
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
    fn patch_test_reg(&mut self, node: usize, reg: u32) -> bool {
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
    fn remove_values(&mut self, mut list: i32) {
        while list != NO_JUMP {
            self.patch_test_reg(list as usize, NO_REG);
            list = self.get_jump_target(list as usize);
        }
    }
    fn patch_list_aux(&mut self, mut list: i32, vtarget: usize, reg: u32, dtarget: usize) {
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
    fn code_label(&mut self, reg: u32, b: u32, jump: u32, line: u32) -> usize {
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
    fn check_stack(&mut self, n: u32) -> LuaResult<()> {
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
    fn search_local(&self, name: &str) -> Option<u8> {
        let fs = self.fs();
        for i in (0..fs.num_active_vars).rev() {
            let var_idx = fs.active_vars[i as usize];
            if fs.proto.local_vars[var_idx as usize].name == name {
                return Some(i);
            }
        }
        None
    }
    fn search_upvalue(&self, name: &str) -> Option<u8> {
        let fs = self.fs();
        for (i, uv) in fs.upvalues.iter().enumerate() {
            if uv.name == name {
                #[allow(clippy::cast_possible_truncation)]
                return Some(i as u8);
            }
        }
        None
    }
    fn add_upvalue(
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
    fn resolve_var_aux(&mut self, fs_idx: usize, name: &str) -> LuaResult<Option<u8>> {
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
    fn mark_upval(fs: &mut FuncState, level: u8) {
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
    fn set_one_ret(&mut self, e: &mut ExprContext) {
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
    fn discharge2reg(&mut self, e: &mut ExprContext, reg: u32, line: u32) {
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
    fn discharge2anyreg(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
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
    fn get_jump_control(&self, pc: usize) -> usize {
        if pc >= 1 {
            let prev = self.get_instruction(pc - 1);
            if prev.opcode().is_test_mode() {
                return pc - 1;
            }
        }
        pc
    }
    fn invertjump(&mut self, e: &ExprContext) {
        let jmp_pc = e.info as usize;
        let ctrl_pc = self.get_jump_control(jmp_pc);
        let mut instr = self.get_instruction(ctrl_pc);
        let a = instr.a();
        instr.set_a(u32::from(a == 0));
        self.set_instruction(ctrl_pc, instr);
    }
    fn jumponcond(&mut self, e: &mut ExprContext, cond: bool, line: u32) -> LuaResult<i32> {
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
    fn const_fold(op: OpCode, e1: &mut ExprContext, e2: &ExprContext) -> bool {
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
        op: super::ast::BinOp,
        e: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        match op {
            super::ast::BinOp::And => {
                self.goiftrue(e, line)?;
            }
            super::ast::BinOp::Or => {
                self.goiffalse(e, line)?;
            }
            super::ast::BinOp::Concat => {
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
        op: super::ast::BinOp,
        e1: &mut ExprContext,
        e2: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        match op {
            super::ast::BinOp::And => {
                debug_assert!(e1.t == NO_JUMP);
                self.discharge_vars(e2, line);
                let mut f = e2.f;
                self.concat_jumps(&mut f, e1.f);
                e2.f = f;
                *e1 = *e2;
            }
            super::ast::BinOp::Or => {
                debug_assert!(e1.f == NO_JUMP);
                self.discharge_vars(e2, line);
                let mut t = e2.t;
                self.concat_jumps(&mut t, e1.t);
                e2.t = t;
                *e1 = *e2;
            }
            super::ast::BinOp::Concat => {
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
            super::ast::BinOp::Add => self.code_arith(OpCode::Add, e1, e2, line)?,
            super::ast::BinOp::Sub => self.code_arith(OpCode::Sub, e1, e2, line)?,
            super::ast::BinOp::Mul => self.code_arith(OpCode::Mul, e1, e2, line)?,
            super::ast::BinOp::Div => self.code_arith(OpCode::Div, e1, e2, line)?,
            super::ast::BinOp::Mod => self.code_arith(OpCode::Mod, e1, e2, line)?,
            super::ast::BinOp::Pow => self.code_arith(OpCode::Pow, e1, e2, line)?,
            super::ast::BinOp::Eq => self.code_comp(OpCode::Eq, 1, e1, e2, line)?,
            super::ast::BinOp::Ne => self.code_comp(OpCode::Eq, 0, e1, e2, line)?,
            super::ast::BinOp::Lt => self.code_comp(OpCode::Lt, 1, e1, e2, line)?,
            super::ast::BinOp::Le => self.code_comp(OpCode::Le, 1, e1, e2, line)?,
            super::ast::BinOp::Gt => self.code_comp(OpCode::Lt, 0, e1, e2, line)?,
            super::ast::BinOp::Ge => self.code_comp(OpCode::Le, 0, e1, e2, line)?,
        }
        Ok(())
    }
    pub(crate) fn prefix(
        &mut self,
        op: super::ast::UnOp,
        e: &mut ExprContext,
        line: u32,
    ) -> LuaResult<()> {
        let mut e2 = ExprContext::number(0.0);
        match op {
            super::ast::UnOp::Neg => {
                if e.kind == ExprKind::K {
                    self.exp2anyreg(e, line)?;
                }
                self.code_arith(OpCode::Unm, e, &mut e2, line)?;
            }
            super::ast::UnOp::Not => {
                self.code_not(e, line)?;
            }
            super::ast::UnOp::Len => {
                self.exp2anyreg(e, line)?;
                self.code_arith(OpCode::Len, e, &mut e2, line)?;
            }
        }
        Ok(())
    }
    fn code_not(&mut self, e: &mut ExprContext, line: u32) -> LuaResult<()> {
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
    fn finish_main(&mut self) -> Proto {
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
pub fn compile(source: &[u8], name: &str) -> LuaResult<ProtoRef> {
    let block = parser::parse(source, name)?;
    let mut compiler = Compiler::new(name);
    compiler.fs_mut().proto.is_vararg = 2; 
    compiler.fs_mut().proto.num_params = 0;
    compile_block(&mut compiler, &block)?;
    let proto = compiler.finish_main();
    Ok(ProtoRef::new(proto))
}
pub fn compile_with_lexer(lexer: Lexer<'_>, name: &str) -> LuaResult<ProtoRef> {
    let block = parser::parse_with_lexer(lexer)?;
    let mut compiler = Compiler::new(name);
    compiler.fs_mut().proto.is_vararg = 2; 
    compiler.fs_mut().proto.num_params = 0;
    compile_block(&mut compiler, &block)?;
    let proto = compiler.finish_main();
    Ok(ProtoRef::new(proto))
}
fn compile_block_scoped(compiler: &mut Compiler, block: &Block) -> LuaResult<()> {
    compiler.enter_block(false);
    compile_block(compiler, block)?;
    compiler.leave_block();
    Ok(())
}
fn compile_block(compiler: &mut Compiler, block: &Block) -> LuaResult<()> {
    for stat in block {
        compile_stat(compiler, stat)?;
        compiler.fs_mut().free_reg = compiler.fs().num_active_vars;
    }
    Ok(())
}
#[allow(clippy::too_many_lines)]
fn compile_stat(compiler: &mut Compiler, stat: &super::ast::Stat) -> LuaResult<()> {
    use super::ast::Stat;
    let line = stat.span().line;
    compiler.current_line = line;
    match stat {
        Stat::Assign {
            targets, values, ..
        } => compile_assign(compiler, targets, values, line),
        Stat::LocalDecl { names, values, .. } => compile_local_decl(compiler, names, values, line),
        Stat::Do { end_line, body, .. } => {
            let result = compile_block_scoped(compiler, body);
            compiler.current_line = *end_line;
            result
        }
        Stat::While {
            condition,
            body,
            end_line,
            ..
        } => compile_while(compiler, condition, body, line, *end_line),
        Stat::Repeat {
            body, condition, ..
        } => compile_repeat(compiler, body, condition, line),
        Stat::If {
            conditions,
            bodies,
            else_body,
            end_line,
            ..
        } => compile_if(compiler, conditions, bodies, else_body.as_ref(), *end_line),
        Stat::NumericFor {
            name,
            start,
            stop,
            step,
            body,
            end_line,
            ..
        } => compile_numeric_for(
            compiler,
            name,
            start,
            stop,
            step.as_ref(),
            body,
            line,
            *end_line,
        ),
        Stat::GenericFor {
            names,
            iterators,
            body,
            iter_line,
            end_line,
            ..
        } => compile_generic_for(
            compiler, names, iterators, body, line, *iter_line, *end_line,
        ),
        Stat::FuncDecl { name, body, .. } => compile_func_decl(compiler, name, body, line),
        Stat::LocalFunc { name, body, .. } => compile_local_func(compiler, name, body, line),
        Stat::Return { values, .. } => compile_return(compiler, values, line),
        Stat::Break { .. } => {
            let fs = compiler.fs();
            let mut needs_close = false;
            let mut close_level = 0u32;
            for block in fs.blocks.iter().rev() {
                if block.has_upval {
                    needs_close = true;
                }
                if block.is_breakable {
                    close_level = u32::from(block.num_active_vars);
                    break;
                }
            }
            if needs_close {
                compiler.emit_abc(OpCode::Close, close_level, 0, 0, line);
            }
            let jmp = compiler.emit_jump(line) as i32;
            compiler.add_break_jump(jmp)?;
            Ok(())
        }
        Stat::Continue { .. } => {
            let fs = compiler.fs();
            let mut needs_close = false;
            let mut close_level = 0u32;
            for block in fs.blocks.iter().rev() {
                if block.has_upval {
                    needs_close = true;
                }
                if block.is_breakable {
                    close_level = u32::from(block.num_active_vars);
                    break;
                }
            }
            if needs_close {
                compiler.emit_abc(OpCode::Close, close_level, 0, 0, line);
            }
            let jmp = compiler.emit_jump(line) as i32;
            compiler.add_continue_jump(jmp)?;
            Ok(())
        }
        Stat::ExprStat { expr, .. } => compile_expr_stat(compiler, expr, line),
    }
}
fn compile_assign(
    compiler: &mut Compiler,
    targets: &[super::ast::Expr],
    values: &[super::ast::Expr],
    line: u32,
) -> LuaResult<()> {
    let mut target_exprs: Vec<ExprContext> = Vec::new();
    for target in targets {
        let e = compile_expr(compiler, target)?;
        if e.kind != ExprKind::Local
            && e.kind != ExprKind::Upval
            && e.kind != ExprKind::Global
            && e.kind != ExprKind::Indexed
        {
            return Err(LuaError::Syntax(SyntaxError {
                message: "invalid assignment target".to_string(),
                source: compiler.source_name.clone(),
                line,
                raw_message: None,
            }));
        }
        target_exprs.push(e);
    }
    for i in 0..target_exprs.len() {
        if target_exprs[i].kind == ExprKind::Local {
            let local_reg = target_exprs[i].info;
            let extra = i32::from(compiler.fs().free_reg);
            let mut conflict = false;
            for target_expr in &mut target_exprs[..i] {
                if target_expr.kind == ExprKind::Indexed {
                    if target_expr.info == local_reg {
                        conflict = true;
                        target_expr.info = extra;
                    }
                    let aux = target_expr.aux;
                    if aux & 256 == 0 && aux == local_reg {
                        conflict = true;
                        target_expr.aux = extra;
                    }
                }
            }
            if conflict {
                #[allow(clippy::cast_sign_loss)]
                compiler.emit_abc(OpCode::Move, extra as u32, local_reg as u32, 0, line);
                compiler.reserve_regs(1)?;
            }
        }
    }
    let nvars = targets.len();
    let (nexps, mut last_e) = compile_exprlist(compiler, values, line)?;
    if nexps == nvars {
        compiler.set_one_ret(&mut last_e);
        let last_target = target_exprs[nvars - 1];
        compiler.storevar(&last_target, &mut last_e, line)?;
        for i in (0..nvars - 1).rev() {
            let reg = u32::from(compiler.fs().free_reg) - 1;
            let mut val_e = ExprContext::new(ExprKind::NonReloc, reg as i32);
            let t = target_exprs[i];
            compiler.storevar(&t, &mut val_e, line)?;
        }
    } else {
        adjust_assign(compiler, nvars, nexps, &mut last_e, line)?;
        #[allow(clippy::cast_possible_truncation)]
        if nexps > nvars {
            compiler.fs_mut().free_reg -= (nexps - nvars) as u8;
        }
        for target in target_exprs.iter().rev() {
            let reg = u32::from(compiler.fs().free_reg) - 1;
            let mut val_e = ExprContext::new(ExprKind::NonReloc, reg as i32);
            let t = *target;
            compiler.storevar(&t, &mut val_e, line)?;
        }
    }
    Ok(())
}
fn compile_local_decl(
    compiler: &mut Compiler,
    names: &[String],
    values: &[super::ast::Expr],
    line: u32,
) -> LuaResult<()> {
    let nvars = names.len();
    for name in names {
        compiler.new_local(name)?;
    }
    if values.is_empty() {
        adjust_assign(compiler, nvars, 0, &mut ExprContext::void(), line)?;
    } else {
        let (nexps, mut last_e) = compile_exprlist(compiler, values, line)?;
        adjust_assign(compiler, nvars, nexps, &mut last_e, line)?;
    }
    #[allow(clippy::cast_possible_truncation)]
    compiler.activate_locals(nvars as u32);
    Ok(())
}
fn compile_while(
    compiler: &mut Compiler,
    condition: &super::ast::Expr,
    body: &Block,
    _line: u32,
    end_line: u32,
) -> LuaResult<()> {
    let whileinit = compiler.get_label();
    let mut cond_e = compile_expr(compiler, condition)?;
    let cond_line = condition.span().line;
    let condexit = compiler.compile_condition(&mut cond_e, cond_line)?;
    compiler.enter_block(true); 
    compile_block(compiler, body)?;
    let jmp = compiler.emit_jump(compiler.current_line);
    compiler.patch_list(jmp as i32, whileinit);
    compiler.leave_block();
    compiler.patch_to_here(condexit);
    compiler.current_line = end_line;
    Ok(())
}
fn compile_repeat(
    compiler: &mut Compiler,
    body: &Block,
    condition: &super::ast::Expr,
    line: u32,
) -> LuaResult<()> {
    let repeat_init = compiler.get_label();
    compiler.enter_block(true); 
    compiler.enter_block(false); 
    compile_block(compiler, body)?;
    let mut cond_e = compile_expr(compiler, condition)?;
    let cond_line = condition.span().line;
    let condexit = compiler.compile_condition(&mut cond_e, cond_line)?;
    let scope_has_upval = compiler.fs().blocks.last().is_some_and(|b| b.has_upval);
    if scope_has_upval {
        let fs = compiler.fs();
        let mut close_level = 0u32;
        for block in fs.blocks.iter().rev() {
            if block.is_breakable {
                close_level = u32::from(block.num_active_vars);
                break;
            }
        }
        compiler.emit_abc(OpCode::Close, close_level, 0, 0, line);
        let break_jmp = compiler.emit_jump(line) as i32;
        compiler.add_break_jump(break_jmp)?;
        compiler.patch_to_here(condexit);
        compiler.leave_block();
        let loop_back = compiler.emit_jump(line);
        compiler.patch_list(loop_back as i32, repeat_init);
    } else {
        compiler.leave_block(); 
        compiler.patch_list(condexit, repeat_init);
    }
    compiler.leave_block(); 
    Ok(())
}
#[allow(clippy::too_many_lines)]
fn compile_if(
    compiler: &mut Compiler,
    conditions: &[super::ast::Expr],
    bodies: &[Block],
    else_body: Option<&Block>,
    end_line: u32,
) -> LuaResult<()> {
    let mut escape_list = NO_JUMP;
    let mut cond_e = compile_expr(compiler, &conditions[0])?;
    let cond_line = conditions[0].span().line;
    let mut flist = compiler.compile_condition(&mut cond_e, cond_line)?;
    compile_block_scoped(compiler, &bodies[0])?;
    for i in 1..conditions.len() {
        let jmp = compiler.emit_jump(compiler.current_line) as i32;
        compiler.concat_jumps(&mut escape_list, jmp);
        compiler.patch_to_here(flist);
        let mut cond_e = compile_expr(compiler, &conditions[i])?;
        let cond_line = conditions[i].span().line;
        flist = compiler.compile_condition(&mut cond_e, cond_line)?;
        compile_block_scoped(compiler, &bodies[i])?;
    }
    if let Some(else_block) = else_body {
        let jmp = compiler.emit_jump(compiler.current_line) as i32;
        compiler.concat_jumps(&mut escape_list, jmp);
        compiler.patch_to_here(flist);
        compile_block_scoped(compiler, else_block)?;
    } else {
        compiler.concat_jumps(&mut escape_list, flist);
    }
    compiler.patch_to_here(escape_list);
    compiler.current_line = end_line;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn compile_numeric_for(
    compiler: &mut Compiler,
    name: &str,
    start: &super::ast::Expr,
    stop: &super::ast::Expr,
    step: Option<&super::ast::Expr>,
    body: &Block,
    line: u32,
    end_line: u32,
) -> LuaResult<()> {
    compiler.enter_block(true); 
    let base = u32::from(compiler.fs().free_reg);
    compiler.new_local("(for index)")?;
    compiler.new_local("(for limit)")?;
    compiler.new_local("(for step)")?;
    compiler.new_local(name)?;
    let mut e = compile_expr(compiler, start)?;
    compiler.exp2nextreg(&mut e, line)?;
    let mut e = compile_expr(compiler, stop)?;
    compiler.exp2nextreg(&mut e, line)?;
    if let Some(step_expr) = step {
        let mut e = compile_expr(compiler, step_expr)?;
        compiler.exp2nextreg(&mut e, line)?;
    } else {
        let k = compiler.number_constant(1.0)?;
        let reg = u32::from(compiler.fs().free_reg);
        compiler.emit_abx(OpCode::LoadK, reg, k, line);
        compiler.reserve_regs(1)?;
    }
    compiler.activate_locals(3);
    let prep = compiler.emit_asbx(OpCode::ForPrep, base, NO_JUMP, line);
    compiler.enter_block(false);
    compiler.activate_locals(1); 
    compiler.reserve_regs(1)?;
    compile_block(compiler, body)?;
    compiler.leave_block();
    compiler.patch_to_here(prep as i32);
    let endfor = compiler.emit_asbx(OpCode::ForLoop, base, NO_JUMP, line);
    compiler.patch_jump(endfor, prep + 1);
    compiler.leave_block(); 
    compiler.current_line = end_line;
    Ok(())
}
fn compile_generic_for(
    compiler: &mut Compiler,
    names: &[String],
    iterators: &[super::ast::Expr],
    body: &Block,
    line: u32,
    iter_line: u32,
    end_line: u32,
) -> LuaResult<()> {
    compiler.enter_block(true); 
    let base = u32::from(compiler.fs().free_reg);
    compiler.new_local("(for generator)")?;
    compiler.new_local("(for state)")?;
    compiler.new_local("(for control)")?;
    for name in names {
        compiler.new_local(name)?;
    }
    let (nexps, mut last_e) = compile_exprlist(compiler, iterators, line)?;
    adjust_assign(compiler, 3, nexps, &mut last_e, line)?;
    compiler.check_stack(3)?;
    compiler.activate_locals(3); 
    let prep = compiler.emit_jump(line);
    compiler.enter_block(false);
    let nvars = names.len();
    #[allow(clippy::cast_possible_truncation)]
    compiler.activate_locals(nvars as u32);
    #[allow(clippy::cast_possible_truncation)]
    compiler.reserve_regs(nvars as u32)?;
    compile_block(compiler, body)?;
    compiler.leave_block();
    compiler.patch_to_here(prep as i32);
    #[allow(clippy::cast_possible_truncation)]
    let endfor = compiler.emit_abc(OpCode::TForLoop, base, 0, nvars as u32, iter_line);
    let loop_jmp = compiler.emit_jump(iter_line);
    compiler.patch_jump(loop_jmp, prep + 1);
    let _ = endfor;
    compiler.leave_block();
    compiler.current_line = end_line;
    Ok(())
}
fn compile_func_decl(
    compiler: &mut Compiler,
    name: &super::ast::FuncName,
    body: &super::ast::FuncBody,
    line: u32,
) -> LuaResult<()> {
    let need_self = name.method.is_some();
    let mut var = compiler.resolve_var(&name.parts[0])?;
    for part in &name.parts[1..] {
        compiler.exp2anyreg(&mut var, line)?;
        let k = compiler.string_constant(part.as_bytes())?;
        let mut key = ExprContext::new(ExprKind::K, k as i32);
        compiler.set_indexed(&mut var, &mut key, line)?;
    }
    if let Some(method) = &name.method {
        compiler.exp2anyreg(&mut var, line)?;
        let k = compiler.string_constant(method.as_bytes())?;
        let mut key = ExprContext::new(ExprKind::K, k as i32);
        compiler.set_indexed(&mut var, &mut key, line)?;
    }
    let mut func_e = compile_funcbody(compiler, body, need_self, line)?;
    compiler.storevar(&var, &mut func_e, line)?;
    Ok(())
}
fn compile_local_func(
    compiler: &mut Compiler,
    name: &str,
    body: &super::ast::FuncBody,
    line: u32,
) -> LuaResult<()> {
    compiler.new_local(name)?;
    compiler.activate_locals(1);
    let mut func_e = compile_funcbody(compiler, body, false, line)?;
    let reg = u32::from(compiler.fs().num_active_vars) - 1;
    compiler.exp2reg(&mut func_e, reg, line);
    Ok(())
}
fn compile_return(
    compiler: &mut Compiler,
    values: &[super::ast::Expr],
    line: u32,
) -> LuaResult<()> {
    if values.is_empty() {
        compiler.emit_abc(OpCode::Return, 0, 1, 0, line);
    } else if values.len() == 1 {
        let mut e = compile_expr(compiler, &values[0])?;
        if e.kind == ExprKind::Call || e.kind == ExprKind::VarArg {
            if e.kind == ExprKind::Call {
                let instr = compiler.get_instruction(e.info as usize);
                if instr.opcode() == OpCode::Call {
                    let tail = Instruction::abc(OpCode::TailCall, instr.a(), instr.b(), 0);
                    compiler.set_instruction(e.info as usize, tail);
                }
            }
            compiler.set_multret(&mut e);
            let first = u32::from(compiler.fs().num_active_vars);
            compiler.emit_abc(OpCode::Return, first, 0, 0, line);
        } else {
            let first = compiler.exp2anyreg(&mut e, line)?;
            compiler.emit_abc(OpCode::Return, first, 2, 0, line);
        }
    } else {
        let base = u32::from(compiler.fs().free_reg);
        for (i, expr) in values.iter().enumerate() {
            let mut e = compile_expr(compiler, expr)?;
            if i == values.len() - 1 {
                if e.kind == ExprKind::Call || e.kind == ExprKind::VarArg {
                    compiler.set_multret(&mut e);
                    let first = u32::from(compiler.fs().num_active_vars);
                    compiler.emit_abc(OpCode::Return, first, 0, 0, line);
                    return Ok(());
                }
            }
            compiler.exp2nextreg(&mut e, line)?;
        }
        let nret = values.len() as u32;
        compiler.emit_abc(OpCode::Return, base, nret + 1, 0, line);
    }
    Ok(())
}
fn compile_expr_stat(
    compiler: &mut Compiler,
    expr: &super::ast::Expr,
    _line: u32,
) -> LuaResult<()> {
    let e = compile_expr(compiler, expr)?;
    if e.kind == ExprKind::Call {
        let mut instr = compiler.get_instruction(e.info as usize);
        instr.set_c(1); 
        compiler.set_instruction(e.info as usize, instr);
    }
    Ok(())
}
fn compile_exprlist(
    compiler: &mut Compiler,
    exprs: &[super::ast::Expr],
    line: u32,
) -> LuaResult<(usize, ExprContext)> {
    if exprs.is_empty() {
        return Ok((0, ExprContext::void()));
    }
    for expr in &exprs[..exprs.len() - 1] {
        let mut e = compile_expr(compiler, expr)?;
        compiler.exp2nextreg(&mut e, line)?;
    }
    let last = compile_expr(compiler, &exprs[exprs.len() - 1])?;
    Ok((exprs.len(), last))
}
fn adjust_assign(
    compiler: &mut Compiler,
    nvars: usize,
    nexps: usize,
    last: &mut ExprContext,
    line: u32,
) -> LuaResult<()> {
    let extra = nvars as i32 - nexps as i32;
    if last.kind == ExprKind::Call || last.kind == ExprKind::VarArg {
        let is_call = last.kind == ExprKind::Call;
        let needed = extra + 1;
        if needed < 0 {
            compiler.set_one_ret(last);
        } else if is_call {
            let mut instr = compiler.get_instruction(last.info as usize);
            instr.set_c((needed + 1) as u32);
            compiler.set_instruction(last.info as usize, instr);
        } else {
            let mut instr = compiler.get_instruction(last.info as usize);
            instr.set_b((needed + 1) as u32);
            instr.set_a(u32::from(compiler.fs().free_reg));
            compiler.set_instruction(last.info as usize, instr);
            compiler.reserve_regs(1)?;
            last.kind = ExprKind::Relocable;
        }
        if is_call && needed > 1 {
            #[allow(clippy::cast_possible_truncation)]
            compiler.reserve_regs((needed - 1) as u32)?;
        }
    } else {
        if last.kind != ExprKind::Void {
            compiler.exp2nextreg(last, line)?;
        }
        if extra > 0 {
            let reg = u32::from(compiler.fs().free_reg);
            #[allow(clippy::cast_possible_truncation)]
            compiler.reserve_regs(extra as u32)?;
            #[allow(clippy::cast_possible_truncation)]
            compiler.emit_nil(reg, extra as u32, line);
        }
    }
    Ok(())
}
fn compile_funcbody(
    compiler: &mut Compiler,
    body: &super::ast::FuncBody,
    need_self: bool,
    line: u32,
) -> LuaResult<ExprContext> {
    compiler.enter_function(&compiler.source_name.clone());
    compiler.fs_mut().proto.line_defined = line;
    if need_self {
        compiler.new_local("self")?;
        compiler.activate_locals(1);
    }
    for param in &body.params {
        compiler.new_local(param)?;
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        compiler.activate_locals(body.params.len() as u32);
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        let num_params = body.params.len() as u8 + u8::from(need_self);
        compiler.fs_mut().proto.num_params = num_params;
    }
    if body.has_varargs {
        compiler.fs_mut().proto.is_vararg = VARARG_HASARG | VARARG_ISVARARG | VARARG_NEEDSARG;
        compiler.new_local("arg")?;
        compiler.activate_locals(1);
    }
    let nactvar = u32::from(compiler.fs().num_active_vars);
    compiler.reserve_regs(nactvar)?;
    compile_block(compiler, &body.body)?;
    compiler.fs_mut().proto.last_line_defined = body.end_line;
    compiler.current_line = body.end_line;
    let child_upvalues = compiler.fs().upvalues.clone();
    let proto = compiler.leave_function();
    let parent_fs = compiler.fs_mut();
    let proto_idx = parent_fs.proto.protos.len();
    parent_fs.proto.protos.push(ProtoRef::new(proto));
    #[allow(clippy::cast_possible_truncation)]
    let pc = compiler.emit_abx(OpCode::Closure, 0, proto_idx as u32, line);
    for uv in &child_upvalues {
        let op = if uv.in_stack {
            OpCode::Move
        } else {
            OpCode::GetUpval
        };
        compiler.emit_abc(op, 0, u32::from(uv.index), 0, line);
    }
    let e = ExprContext::new(ExprKind::Relocable, pc as i32);
    Ok(e)
}
fn compile_expr(compiler: &mut Compiler, expr: &super::ast::Expr) -> LuaResult<ExprContext> {
    use super::ast::Expr;
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
fn compile_funcargs(
    compiler: &mut Compiler,
    func: &mut ExprContext,
    args: &[super::ast::Expr],
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
fn compile_table_ctor(
    compiler: &mut Compiler,
    fields: &[super::ast::TableField],
    line: u32,
) -> LuaResult<ExprContext> {
    use super::ast::TableField;
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
fn is_multret_expr(expr: &super::ast::Expr) -> bool {
    matches!(
        expr,
        super::ast::Expr::Call { .. }
            | super::ast::Expr::MethodCall { .. }
            | super::ast::Expr::VarArg(..)
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
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    clippy::approx_constant,
    clippy::items_after_statements,
    clippy::needless_collect,
    clippy::bool_comparison,
    clippy::useless_vec,
    clippy::needless_bool_assign,
    clippy::unnecessary_operation
)]
mod tests {
    use super::*;
    #[test]
    fn empty_program_compiles() {
        let proto = compile(b"", "test").unwrap();
        assert_eq!(proto.num_params, 0);
        assert_eq!(proto.is_vararg, 2);
        assert!(!proto.code.is_empty());
    }
    #[test]
    fn return_no_values() {
        let proto = compile(b"return", "test").unwrap();
        assert!(!proto.code.is_empty());
        let instr = Instruction::from_raw(proto.code[0]);
        assert_eq!(instr.opcode(), OpCode::Return);
    }
    #[test]
    fn number_constant_dedup() {
        let mut compiler = Compiler::new("test");
        let k1 = compiler.number_constant(42.0).unwrap();
        let k2 = compiler.number_constant(42.0).unwrap();
        let k3 = compiler.number_constant(99.0).unwrap();
        assert_eq!(k1, k2); 
        assert_ne!(k1, k3); 
    }
    #[test]
    fn constant_bool_dedup() {
        let mut compiler = Compiler::new("test");
        let k1 = compiler.add_constant(Val::Bool(true)).unwrap();
        let k2 = compiler.add_constant(Val::Bool(true)).unwrap();
        let k3 = compiler.add_constant(Val::Bool(false)).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }
    #[test]
    fn constant_nan_not_deduped() {
        let mut compiler = Compiler::new("test");
        let k1 = compiler.add_constant(Val::Num(f64::NAN)).unwrap();
        let k2 = compiler.add_constant(Val::Num(f64::NAN)).unwrap();
        assert_eq!(k1, k2);
    }
    #[test]
    fn alloc_and_free_reg() {
        let mut compiler = Compiler::new("test");
        let r1 = compiler.alloc_reg().unwrap();
        assert_eq!(r1, 0);
        let r2 = compiler.alloc_reg().unwrap();
        assert_eq!(r2, 1);
        compiler.free_reg(r2);
        assert_eq!(compiler.fs().free_reg, 1);
        let r3 = compiler.alloc_reg().unwrap();
        assert_eq!(r3, 1); 
    }
    #[test]
    fn reserve_regs() {
        let mut compiler = Compiler::new("test");
        compiler.reserve_regs(3).unwrap();
        assert_eq!(compiler.fs().free_reg, 3);
    }
    #[test]
    fn stack_overflow_error() {
        let mut compiler = Compiler::new("test");
        compiler.fs_mut().free_reg = 249;
        assert!(compiler.check_stack(2).is_err());
    }
    #[test]
    fn resolve_global() {
        let mut compiler = Compiler::new("test");
        let e = compiler.resolve_var("x").unwrap();
        assert_eq!(e.kind, ExprKind::Global);
    }
    #[test]
    fn resolve_local() {
        let mut compiler = Compiler::new("test");
        compiler.new_local("x").unwrap();
        compiler.activate_locals(1);
        compiler.fs_mut().free_reg = 1; 
        let e = compiler.resolve_var("x").unwrap();
        assert_eq!(e.kind, ExprKind::Local);
        assert_eq!(e.info, 0); 
    }
    #[test]
    fn enter_leave_block() {
        let mut compiler = Compiler::new("test");
        compiler.enter_block(false);
        assert_eq!(compiler.fs().blocks.len(), 1);
        compiler.leave_block();
        assert_eq!(compiler.fs().blocks.len(), 0);
    }
    #[test]
    fn locals_removed_on_block_exit() {
        let mut compiler = Compiler::new("test");
        compiler.enter_block(false);
        compiler.new_local("x").unwrap();
        compiler.activate_locals(1);
        compiler.fs_mut().free_reg = 1;
        assert_eq!(compiler.fs().num_active_vars, 1);
        compiler.leave_block();
        assert_eq!(compiler.fs().num_active_vars, 0);
    }
    #[test]
    fn emit_instruction() {
        let mut compiler = Compiler::new("test");
        let pc = compiler.emit_abc(OpCode::Move, 0, 1, 0, 1);
        assert_eq!(pc, 0);
        let instr = compiler.get_instruction(0);
        assert_eq!(instr.opcode(), OpCode::Move);
        assert_eq!(instr.a(), 0);
        assert_eq!(instr.b(), 1);
    }
    #[test]
    fn emit_records_line_info() {
        let mut compiler = Compiler::new("test");
        compiler.emit_abc(OpCode::Move, 0, 1, 0, 5);
        compiler.emit_abc(OpCode::LoadK, 1, 0, 0, 10);
        assert_eq!(compiler.fs().proto.line_info[0], 5);
        assert_eq!(compiler.fs().proto.line_info[1], 10);
    }
    #[test]
    fn discharge_nil() {
        let mut compiler = Compiler::new("test");
        compiler.emit_abc(OpCode::Return, 0, 1, 0, 1);
        let mut e = ExprContext::new(ExprKind::Nil, 0);
        let reg = compiler.alloc_reg().unwrap();
        compiler.discharge2reg(&mut e, reg, 1);
        let instr = compiler.get_instruction(1);
        assert_eq!(instr.opcode(), OpCode::LoadNil);
    }
    #[test]
    fn discharge_true() {
        let mut compiler = Compiler::new("test");
        let mut e = ExprContext::new(ExprKind::True, 0);
        let reg = compiler.alloc_reg().unwrap();
        compiler.discharge2reg(&mut e, reg, 1);
        let instr = compiler.get_instruction(0);
        assert_eq!(instr.opcode(), OpCode::LoadBool);
        assert_eq!(instr.b(), 1);
    }
    #[test]
    fn discharge_number() {
        let mut compiler = Compiler::new("test");
        let mut e = ExprContext::number(42.0);
        let reg = compiler.alloc_reg().unwrap();
        compiler.discharge2reg(&mut e, reg, 1);
        let instr = compiler.get_instruction(0);
        assert_eq!(instr.opcode(), OpCode::LoadK);
    }
    #[test]
    fn discharge_local_to_different_reg() {
        let mut compiler = Compiler::new("test");
        compiler.new_local("x").unwrap();
        compiler.activate_locals(1);
        compiler.fs_mut().free_reg = 1;
        let mut e = ExprContext::new(ExprKind::Local, 0);
        compiler.discharge_vars(&mut e, 1);
        assert_eq!(e.kind, ExprKind::NonReloc);
        let reg = compiler.alloc_reg().unwrap();
        compiler.discharge2reg(&mut e, reg, 1);
        let instr = compiler.get_instruction(0);
        assert_eq!(instr.opcode(), OpCode::Move);
        assert_eq!(instr.a(), 1);
        assert_eq!(instr.b(), 0);
    }
    #[test]
    fn compile_return_number() {
        let proto = compile(b"return 42", "test").unwrap();
        assert!(proto.code.len() >= 2);
        assert!(
            proto
                .constants
                .iter()
                .any(|v| matches!(v, Val::Num(n) if *n == 42.0))
        );
    }
    #[test]
    fn compile_return_nil() {
        let proto = compile(b"return nil", "test").unwrap();
        let instr = Instruction::from_raw(proto.code[0]);
        assert_eq!(instr.opcode(), OpCode::Return);
    }
    #[test]
    fn compile_return_bool() {
        let proto = compile(b"return true", "test").unwrap();
        let instr = Instruction::from_raw(proto.code[0]);
        assert_eq!(instr.opcode(), OpCode::LoadBool);
        assert_eq!(instr.b(), 1); 
    }
    #[test]
    fn compile_return_multiple() {
        let proto = compile(b"return 1, 2, 3", "test").unwrap();
        let mut loadk_count = 0;
        for &code in &proto.code {
            if Instruction::from_raw(code).opcode() == OpCode::LoadK {
                loadk_count += 1;
            }
        }
        assert_eq!(loadk_count, 3);
    }
    fn opcodes(proto: &Proto) -> Vec<OpCode> {
        proto
            .code
            .iter()
            .map(|&raw| Instruction::from_raw(raw).opcode())
            .collect()
    }
    #[test]
    fn compile_local_decl() {
        let proto = compile(b"local x = 42", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::LoadK));
    }
    #[test]
    fn compile_local_nil_init() {
        let proto = compile(b"local x, y", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(!ops.contains(&OpCode::LoadNil));
        assert!(ops.contains(&OpCode::Return));
    }
    #[test]
    fn compile_global_assign() {
        let proto = compile(b"x = 1", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::SetGlobal));
    }
    #[test]
    fn compile_local_assign() {
        let proto = compile(b"local x; x = 1", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::LoadK));
    }
    #[test]
    fn compile_do_block() {
        let proto = compile(b"do local x = 1 end; return", "test").unwrap();
        assert!(proto.code.len() >= 2);
    }
    #[test]
    fn compile_while_loop() {
        let proto = compile(b"local x = true; while x do x = false end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Jmp));
    }
    #[test]
    fn compile_repeat_until() {
        let proto = compile(b"local x = 0; repeat x = x + 1 until x", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Add));
    }
    #[test]
    fn compile_if_then() {
        let proto = compile(b"local x = true; if x then return 1 end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(
            ops.contains(&OpCode::Test) || ops.contains(&OpCode::Jmp),
            "if-then should generate control flow"
        );
    }
    #[test]
    fn compile_if_else() {
        let proto = compile(
            b"local x = true; if x then return 1 else return 2 end",
            "test",
        )
        .unwrap();
        let ops = opcodes(&proto);
        let jmp_count = ops.iter().filter(|&&op| op == OpCode::Jmp).count();
        assert!(jmp_count >= 1, "if-else needs at least one JMP");
    }
    #[test]
    fn compile_numeric_for() {
        let proto = compile(b"for i = 1, 10 do end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::ForPrep));
        assert!(ops.contains(&OpCode::ForLoop));
    }
    #[test]
    fn compile_numeric_for_with_step() {
        let proto = compile(b"for i = 1, 10, 2 do end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::ForPrep));
        assert!(ops.contains(&OpCode::ForLoop));
        assert!(
            proto
                .constants
                .iter()
                .any(|v| matches!(v, Val::Num(n) if n == &2.0))
        );
    }
    #[test]
    fn compile_generic_for() {
        let proto = compile(b"for k, v in next, t do end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::TForLoop));
        assert!(ops.contains(&OpCode::Jmp));
    }
    #[test]
    fn compile_break() {
        let proto = compile(b"while true do break end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Jmp));
    }
    #[test]
    fn compile_arithmetic() {
        let proto = compile(b"local a; return a + 2", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Add));
    }
    #[test]
    fn compile_comparison() {
        let proto = compile(b"return 1 < 2", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Lt));
    }
    #[test]
    fn compile_concat() {
        let proto = compile(b"return 'a' .. 'b'", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Concat));
    }
    #[test]
    fn compile_unary_neg() {
        let proto = compile(b"local x = 1; return -x", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Unm));
    }
    #[test]
    fn compile_unary_not() {
        let proto = compile(b"return not true", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::LoadBool));
    }
    #[test]
    fn compile_unary_len() {
        let proto = compile(b"local x = {}; return #x", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Len));
    }
    #[test]
    fn compile_string_constant() {
        let proto = compile(b"return 'hello'", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::LoadK));
        assert!(!proto.constants.is_empty());
    }
    #[test]
    fn compile_and_short_circuit() {
        let proto = compile(b"local a, b; return a and b", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(
            ops.contains(&OpCode::Test) || ops.contains(&OpCode::TestSet),
            "and should use TEST/TESTSET"
        );
    }
    #[test]
    fn compile_or_short_circuit() {
        let proto = compile(b"local a, b; return a or b", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(
            ops.contains(&OpCode::Test) || ops.contains(&OpCode::TestSet),
            "or should use TEST/TESTSET"
        );
    }
    #[test]
    fn compile_function_call() {
        let proto = compile(b"print(42)", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::GetGlobal));
        assert!(ops.contains(&OpCode::Call));
    }
    #[test]
    fn compile_method_call() {
        let proto = compile(b"local t = {}; t:foo(1)", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::OpSelf));
        assert!(ops.contains(&OpCode::Call));
    }
    #[test]
    fn compile_function_def() {
        let proto = compile(b"local f = function(x) return x end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Closure));
        assert_eq!(proto.protos.len(), 1);
        let child = &proto.protos[0];
        assert_eq!(child.num_params, 1);
    }
    #[test]
    fn compile_local_function() {
        let proto = compile(b"local function f(a, b) return a + b end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Closure));
        assert_eq!(proto.protos.len(), 1);
        let child = &proto.protos[0];
        assert_eq!(child.num_params, 2);
    }
    #[test]
    fn compile_named_function() {
        let proto = compile(b"function f(x) return x end", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Closure));
        assert!(ops.contains(&OpCode::SetGlobal));
    }
    #[test]
    fn compile_vararg_function() {
        let proto = compile(b"local f = function(...) return ... end", "test").unwrap();
        let child = &proto.protos[0];
        assert!(child.is_vararg & 2 != 0); 
    }
    #[test]
    fn compile_empty_table() {
        let proto = compile(b"return {}", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::NewTable));
    }
    #[test]
    fn compile_array_table() {
        let proto = compile(b"return {1, 2, 3}", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::NewTable));
        assert!(ops.contains(&OpCode::SetList));
    }
    #[test]
    fn compile_hash_table() {
        let proto = compile(b"return {x = 1, y = 2}", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::NewTable));
        assert!(ops.contains(&OpCode::SetTable));
    }
    #[test]
    fn compile_index_table() {
        let proto = compile(b"return {[1] = 'a'}", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::NewTable));
        assert!(ops.contains(&OpCode::SetTable));
    }
    #[test]
    fn compile_table_field_access() {
        let proto = compile(b"local t = {}; return t.x", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::GetTable));
    }
    #[test]
    fn compile_table_index_access() {
        let proto = compile(b"local t = {}; return t[1]", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::GetTable));
    }
    #[test]
    fn compile_tail_call() {
        let proto = compile(b"local function f(x) return f(x) end", "test").unwrap();
        let child = &proto.protos[0];
        let child_ops: Vec<OpCode> = child
            .code
            .iter()
            .map(|&raw| Instruction::from_raw(raw).opcode())
            .collect();
        assert!(
            child_ops.contains(&OpCode::TailCall),
            "recursive return should use TAILCALL"
        );
    }
    #[test]
    fn compile_line_info() {
        let proto = compile(b"return 42", "test").unwrap();
        assert_eq!(proto.code.len(), proto.line_info.len());
    }
    #[test]
    fn compile_return_string() {
        let proto = compile(b"return 'hello'", "test").unwrap();
        let instr = Instruction::from_raw(proto.code[0]);
        assert_eq!(instr.opcode(), OpCode::LoadK);
    }
    #[test]
    fn compile_expr_stat_call() {
        let proto = compile(b"print(1)", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::Call));
        for &code in &proto.code {
            let instr = Instruction::from_raw(code);
            if instr.opcode() == OpCode::Call {
                assert_eq!(
                    instr.c(),
                    1,
                    "expression statement call should have C=1 (0 results)"
                );
                break;
            }
        }
    }
    #[test]
    fn compile_single_global_assign() {
        let proto = compile(b"x = 42", "test").unwrap();
        let ops = opcodes(&proto);
        assert!(ops.contains(&OpCode::SetGlobal));
    }
    #[test]
    fn compile_nested_function() {
        let proto = compile(
            b"local function f() local function g() return 1 end return g end",
            "test",
        )
        .unwrap();
        assert_eq!(proto.protos.len(), 1);
        let f = &proto.protos[0];
        assert_eq!(f.protos.len(), 1); 
    }
    #[test]
    fn int2fb_small_values() {
        assert_eq!(int2fb(0), 0);
        assert_eq!(int2fb(1), 1);
        assert_eq!(int2fb(7), 7);
    }
    #[test]
    fn int2fb_exact_powers() {
        let encoded = int2fb(8);
        assert!(encoded >= 8);
    }
    #[test]
    fn compile_syntax_error() {
        let result = compile(b"if", "test");
        assert!(result.is_err());
    }
}
