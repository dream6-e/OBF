//! 语句代码生成：入口 `compile` / `compile_with_lexer`，以及赋值、局部声明、
//! while / repeat / if / for、函数定义、return、函数体等语句的编译。

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
use super::expr::{compile_expr, is_multret_expr};
use super::types::{ExprContext, ExprKind, FuncState};

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
pub(super) fn compile_block_scoped(compiler: &mut Compiler, block: &Block) -> LuaResult<()> {
    compiler.enter_block(false);
    compile_block(compiler, block)?;
    compiler.leave_block();
    Ok(())
}
pub(super) fn compile_block(compiler: &mut Compiler, block: &Block) -> LuaResult<()> {
    for stat in block {
        compile_stat(compiler, stat)?;
        compiler.fs_mut().free_reg = compiler.fs().num_active_vars;
    }
    Ok(())
}
#[allow(clippy::too_many_lines)]
pub(super) fn compile_stat(compiler: &mut Compiler, stat: &crate::compiler::ast::Stat) -> LuaResult<()> {
    use crate::compiler::ast::Stat;
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
pub(super) fn compile_assign(
    compiler: &mut Compiler,
    targets: &[crate::compiler::ast::Expr],
    values: &[crate::compiler::ast::Expr],
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
pub(super) fn compile_local_decl(
    compiler: &mut Compiler,
    names: &[String],
    values: &[crate::compiler::ast::Expr],
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
pub(super) fn compile_while(
    compiler: &mut Compiler,
    condition: &crate::compiler::ast::Expr,
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
pub(super) fn compile_repeat(
    compiler: &mut Compiler,
    body: &Block,
    condition: &crate::compiler::ast::Expr,
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
pub(super) fn compile_if(
    compiler: &mut Compiler,
    conditions: &[crate::compiler::ast::Expr],
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
pub(super) fn compile_numeric_for(
    compiler: &mut Compiler,
    name: &str,
    start: &crate::compiler::ast::Expr,
    stop: &crate::compiler::ast::Expr,
    step: Option<&crate::compiler::ast::Expr>,
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
pub(super) fn compile_generic_for(
    compiler: &mut Compiler,
    names: &[String],
    iterators: &[crate::compiler::ast::Expr],
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
pub(super) fn compile_func_decl(
    compiler: &mut Compiler,
    name: &crate::compiler::ast::FuncName,
    body: &crate::compiler::ast::FuncBody,
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
pub(super) fn compile_local_func(
    compiler: &mut Compiler,
    name: &str,
    body: &crate::compiler::ast::FuncBody,
    line: u32,
) -> LuaResult<()> {
    compiler.new_local(name)?;
    compiler.activate_locals(1);
    let mut func_e = compile_funcbody(compiler, body, false, line)?;
    let reg = u32::from(compiler.fs().num_active_vars) - 1;
    compiler.exp2reg(&mut func_e, reg, line);
    Ok(())
}
pub(super) fn compile_return(
    compiler: &mut Compiler,
    values: &[crate::compiler::ast::Expr],
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
pub(super) fn compile_expr_stat(
    compiler: &mut Compiler,
    expr: &crate::compiler::ast::Expr,
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
pub(super) fn compile_exprlist(
    compiler: &mut Compiler,
    exprs: &[crate::compiler::ast::Expr],
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
pub(super) fn adjust_assign(
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
pub(super) fn compile_funcbody(
    compiler: &mut Compiler,
    body: &crate::compiler::ast::FuncBody,
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
