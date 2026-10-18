//! 运行期自定义混合栈/寄存器 ISA 的处理器。
use super::environment::global_lookup_body;
use super::{OpcodeBuilder, OpcodeConfig, OpcodesRng};
use crate::VM::VM_Backend::CustomIsa::VmOp;

fn handler<'a>(
    m: &[Vec<u32>],
    op: VmOp,
    cfg: &'a OpcodeConfig,
    rng: &'a mut OpcodesRng,
) -> OpcodeBuilder<'a> {
    OpcodeBuilder::new(m[op.global_id()].clone(), cfg, rng)
}

fn emit_binary(
    out: &mut String,
    m: &[Vec<u32>],
    cfg: &OpcodeConfig,
    rng: &mut OpcodesRng,
    op: VmOp,
    operator: &str,
) {
    let mut h = handler(m, op, cfg, rng);
    let s = h.cfg.vstack.clone();
    out.push_str(&h.build(&format!(
        "{{U0}}=#{s}; {{U1}}={s}[{{U0}}-1][1]; {{U2}}={s}[{{U0}}][1]; {s}[{{U0}}]=nil/*MICRO_SEP*/{s}[{{U0}}-1][1]={{U1}}{operator}{{U2}}",
        s = s, operator = operator
    )));
}

fn emit_unary(
    out: &mut String,
    m: &[Vec<u32>],
    cfg: &OpcodeConfig,
    rng: &mut OpcodesRng,
    op: VmOp,
    operator: &str,
) {
    let mut h = handler(m, op, cfg, rng);
    let s = h.cfg.vstack.clone();
    out.push_str(&h.build(&format!(
        "{{U0}}=#{s}; {{U1}}={s}[{{U0}}][1]/*MICRO_SEP*/{s}[{{U0}}][1]={operator}{{U1}}",
        s = s, operator = operator
    )));
}

pub fn generate(m: &[Vec<u32>], cfg: &OpcodeConfig, rng: &mut OpcodesRng) -> String {
    let mut out = String::new();

    let mut push_reg = handler(m, VmOp::PushReg, cfg, rng);
    let a = push_reg.raw_inst(2);
    let vstack = push_reg.cfg.vstack.clone();
    let stk = push_reg.cfg.stk.clone();
    out.push_str(&push_reg.build(&format!("{vstack}[#{vstack}+1]={{{stk}[{a}]}}", vstack = vstack, stk = stk, a = a)));

    let mut push_const = handler(m, VmOp::PushConst, cfg, rng);
    let b = push_const.raw_inst(3);
    let vstack = push_const.cfg.vstack.clone();
    let consts = push_const.cfg.consts.clone();
    out.push_str(&push_const.build(&format!("{vstack}[#{vstack}+1]={{{consts}[{b}-127]}}", vstack = vstack, consts = consts, b = b)));

    let mut push_rk = handler(m, VmOp::PushRk, cfg, rng);
    let value = push_rk.rk(3);
    let vstack = push_rk.cfg.vstack.clone();
    out.push_str(&push_rk.build(&format!("{{U0}}={value}/*MICRO_SEP*/{vstack}[#{vstack}+1]={{{{U0}}}}", vstack = vstack, value = value)));

    let mut push_range = handler(m, VmOp::PushRange, cfg, rng);
    let b = push_range.raw_inst(3);
    let c = push_range.raw_inst(4);
    let j = push_range.rng.name();
    let vstack = push_range.cfg.vstack.clone();
    let stk = push_range.cfg.stk.clone();
    out.push_str(&push_range.build(&format!(
        "for {j}={b},{c} do {vstack}[#{vstack}+1]={{{stk}[{j}]}} end",
        j = j, b = b, c = c, vstack = vstack, stk = stk
    )));

    let mut push_bool = handler(m, VmOp::PushBool, cfg, rng);
    let a = push_bool.raw_inst(2);
    let vstack = push_bool.cfg.vstack.clone();
    out.push_str(&push_bool.build(&format!("{{U0}}=({a}~=0)/*MICRO_SEP*/{vstack}[#{vstack}+1]={{{{U0}}}}", vstack = vstack, a = a)));

    let mut pop_reg = handler(m, VmOp::PopReg, cfg, rng);
    let a = pop_reg.raw_inst(2);
    let vstack = pop_reg.cfg.vstack.clone();
    let stk = pop_reg.cfg.stk.clone();
    out.push_str(&pop_reg.build(&format!(
        "{{U0}}=#{vstack}; {{U1}}={vstack}[{{U0}}][1]; {vstack}[{{U0}}]=nil/*MICRO_SEP*/{stk}[{a}]={{U1}}",
        vstack = vstack, stk = stk, a = a
    )));

    let mut drop_value = handler(m, VmOp::Drop, cfg, rng);
    let n = drop_value.rng.name();
    let vstack = drop_value.cfg.vstack.clone();
    out.push_str(&drop_value.build(&format!("local {n}=#{vstack}; {vstack}[{n}]=nil", n = n, vstack = vstack)));

    let mut clear = handler(m, VmOp::ClearRegs, cfg, rng);
    let a = clear.raw_inst(2);
    let b = clear.raw_inst(3);
    let j = clear.rng.name();
    let stk = clear.cfg.stk.clone();
    out.push_str(&clear.build(&format!("for {j}={a},{a}+{b} do {stk}[{j}]=nil end", j = j, a = a, b = b, stk = stk)));

    let mut get_up = handler(m, VmOp::GetUpvalue, cfg, rng);
    let a = get_up.raw_inst(2);
    let b = get_up.raw_inst(3);
    let stk = get_up.cfg.stk.clone();
    let up = get_up.cfg.upvals.clone();
    out.push_str(&get_up.build(&format!("{stk}[{a}]={up}[{b}+1][1][{up}[{b}+1][2]]", stk = stk, a = a, up = up, b = b)));

    let mut set_up = handler(m, VmOp::SetUpvalue, cfg, rng);
    let a = set_up.raw_inst(2);
    let b = set_up.raw_inst(3);
    let stk = set_up.cfg.stk.clone();
    let up = set_up.cfg.upvals.clone();
    out.push_str(&set_up.build(&format!("{up}[{b}+1][1][{up}[{b}+1][2]]={stk}[{a}]", up = up, b = b, stk = stk, a = a)));

    let mut get_global = handler(m, VmOp::GetGlobal, cfg, rng);
    let a = get_global.raw_inst(2);
    let b = get_global.raw_inst(3);
    out.push_str(&get_global.build(&global_lookup_body(&b, &a)));

    let mut set_global = handler(m, VmOp::SetGlobal, cfg, rng);
    let a = set_global.raw_inst(2);
    let b = set_global.raw_inst(3);
    let stk = set_global.cfg.stk.clone();
    let consts = set_global.cfg.consts.clone();
    let env = set_global.cfg.env.clone();
    out.push_str(&set_global.build(&format!(
        "local k={{GN}}({consts}[{b}-127]); local e={env}; e[k]={stk}[{a}]",
        consts = consts, b = b, env = env, stk = stk, a = a
    )));

    let mut get_index = handler(m, VmOp::GetIndex, cfg, rng);
    let s = get_index.cfg.vstack.clone();
    out.push_str(&get_index.build(&format!(
        "{{U0}}=#{s}; {{U1}}={s}[{{U0}}-1][1]; {{U2}}={s}[{{U0}}][1]; {s}[{{U0}}]=nil/*MICRO_SEP*/{s}[{{U0}}-1][1]={{U1}}[{{U2}}]",
        s = s
    )));

    let mut set_index = handler(m, VmOp::SetIndex, cfg, rng);
    let s = set_index.cfg.vstack.clone();
    out.push_str(&set_index.build(&format!(
        "{{U0}}=#{s}; {{U1}}={s}[{{U0}}][1]; {{U2}}={s}[{{U0}}-1][1]; {s}[{{U0}}]=nil; {s}[{{U0}}-1]=nil/*MICRO_SEP*/{s}[{{U0}}-2][1][{{U2}}]={{U1}}; {s}[{{U0}}-2]=nil",
        s = s
    )));

    let mut new_table = handler(m, VmOp::NewTable, cfg, rng);
    let vstack = new_table.cfg.vstack.clone();
    out.push_str(&new_table.build(&format!("{{U0}}={{}}/*MICRO_SEP*/{vstack}[#{vstack}+1]={{{{U0}}}}", vstack = vstack)));

    emit_binary(&mut out, m, cfg, rng, VmOp::Add, "+");
    emit_binary(&mut out, m, cfg, rng, VmOp::Sub, "-");
    emit_binary(&mut out, m, cfg, rng, VmOp::Mul, "*");
    emit_binary(&mut out, m, cfg, rng, VmOp::Div, "/");
    emit_binary(&mut out, m, cfg, rng, VmOp::Mod, "%");
    emit_binary(&mut out, m, cfg, rng, VmOp::Pow, "^");

    emit_unary(&mut out, m, cfg, rng, VmOp::Neg, "-");
    emit_unary(&mut out, m, cfg, rng, VmOp::Not, "not ");
    emit_unary(&mut out, m, cfg, rng, VmOp::Len, "#");

    let mut equal = handler(m, VmOp::Equal, cfg, rng);
    let s = equal.cfg.vstack.clone();
    out.push_str(&equal.build(&format!("{{U0}}=#{s}; {{U1}}={s}[{{U0}}-1][1]; {{U2}}={s}[{{U0}}][1]; {s}[{{U0}}]=nil/*MICRO_SEP*/{s}[{{U0}}-1][1]=({{U1}}=={{U2}})", s = s)));

    let mut less = handler(m, VmOp::Less, cfg, rng);
    let s = less.cfg.vstack.clone();
    out.push_str(&less.build(&format!("{{U0}}=#{s}; {{U1}}={s}[{{U0}}-1][1]; {{U2}}={s}[{{U0}}][1]; {s}[{{U0}}]=nil/*MICRO_SEP*/{s}[{{U0}}-1][1]=({{U1}}<{{U2}})", s = s)));

    let mut less_equal = handler(m, VmOp::LessEqual, cfg, rng);
    let s = less_equal.cfg.vstack.clone();
    out.push_str(&less_equal.build(&format!("{{U0}}=#{s}; {{U1}}={s}[{{U0}}-1][1]; {{U2}}={s}[{{U0}}][1]; {s}[{{U0}}]=nil/*MICRO_SEP*/{s}[{{U0}}-1][1]=({{U1}}<={{U2}})", s = s)));

    let mut concat = handler(m, VmOp::Concat, cfg, rng);
    let s = concat.cfg.vstack.clone();
    let a = concat.raw_inst(2);
    let j = concat.rng.name();
    let j2 = concat.rng.name();
    out.push_str(&concat.build(&format!(
        "{{U0}}=#{s}; {{U1}}={{U0}}-{a}+1; {{U2}}={s}[{{U0}}][1]; for {j}={{U0}}-1,{{U1}},-1 do {{U2}}={s}[{j}][1]..{{U2}} end/*MICRO_SEP*/{s}[{{U1}}][1]={{U2}}; for {j2}={{U1}}+1,{{U0}} do {s}[{j2}]=nil end",
        s = s, a = a, j = j, j2 = j2
    )));

    let mut branch = handler(m, VmOp::Branch, cfg, rng);
    let a = branch.raw_inst(2);
    let b = branch.raw_inst(3);
    let s = branch.cfg.vstack.clone();
    let pc = branch.cfg.pc.clone();
    out.push_str(&branch.build(&format!(
        "{{U0}}=#{s}; {{U1}}={s}[{{U0}}][1]; {s}[{{U0}}]=nil/*MICRO_SEP*/if (({{U1}}~=nil and {{U1}}~=false)==({a}~=0)) then {pc}={pc}+{b} end",
        s = s, a = a, pc = pc, b = b
    )));

    for (op, polarity) in [(VmOp::BranchSetTrue, true), (VmOp::BranchSetFalse, false)] {
        let mut branch_set = handler(m, op, cfg, rng);
        let a = branch_set.raw_inst(2);
        let b = branch_set.raw_inst(3);
        let c = branch_set.raw_inst(4);
        let stk = branch_set.cfg.stk.clone();
        let pc = branch_set.cfg.pc.clone();
        let cond_check = if polarity { "{U0}" } else { "not {U0}" };
        out.push_str(&branch_set.build(&format!(
            "{{U0}}=({stk}[{b}]~=nil and {stk}[{b}]~=false)/*MICRO_SEP*/if {cond_check} then {stk}[{a}]={stk}[{b}]; {pc}={pc}+{c} end",
            cond_check = cond_check, stk = stk, a = a, b = b, pc = pc, c = c
        )));
    }

    let mut jump = handler(m, VmOp::Jump, cfg, rng);
    let b = jump.raw_inst(3);
    let pc = jump.cfg.pc.clone();
    out.push_str(&jump.build(&format!("{pc}={pc}+{b}", pc = pc, b = b)));

    let mut for_init = handler(m, VmOp::ForInit, cfg, rng);
    let a = for_init.raw_inst(2);
    let b = for_init.raw_inst(3);
    let stk = for_init.cfg.stk.clone();
    let pc = for_init.cfg.pc.clone();
    let q = for_init.rng.name();
    let init = for_init.rng.name();
    let limit = for_init.rng.name();
    let step = for_init.rng.name();
    let errors = &for_init.cfg.numeric_for_errors;
    let init_error = format!("{}{{NATIVE_ERROR}}({},0)", errors[0].0, errors[0].1);
    let limit_error = format!("{}{{NATIVE_ERROR}}({},0)", errors[1].0, errors[1].1);
    let step_error = format!("{}{{NATIVE_ERROR}}({},0)", errors[2].0, errors[2].1);
    out.push_str(&for_init.build(&format!(
        "local {init}={{NATIVE_TONUMBER}}({stk}[{a}]); if {init}==nil then {init_error} end; local {limit}={{NATIVE_TONUMBER}}({stk}[{a}+1]); if {limit}==nil then {limit_error} end; local {step}={{NATIVE_TONUMBER}}({stk}[{a}+2]); if {step}==nil then {step_error} end; {stk}[{a}]={init}-{step}; {stk}[{a}+1]={limit}; {stk}[{a}+2]={step}; local {q}={{{limit},{step}}}; {stk}[-{a}-1]={q}/*MICRO_SEP*/{pc}={pc}+{b}",
        stk = stk, a = a, step = step, init = init, limit = limit, q = q, pc = pc, b = b,
        init_error = init_error, limit_error = limit_error, step_error = step_error
    )));

    let mut for_next = handler(m, VmOp::ForNext, cfg, rng);
    let a = for_next.raw_inst(2);
    let b = for_next.raw_inst(3);
    let stk = for_next.cfg.stk.clone();
    let pc = for_next.cfg.pc.clone();
    let q = for_next.rng.name();
    let step = for_next.rng.name();
    let index = for_next.rng.name();
    let limit = for_next.rng.name();
    out.push_str(&for_next.build(&format!(
        "local {q}={stk}[-{a}-1]; local {limit}={q}[1]; local {step}={q}[2]; local {index}={stk}[{a}]+{step}; {stk}[{a}]={index}; if ({step}>0 and {index}<={limit}) or ({step}<=0 and {index}>={limit}) then {stk}[{a}+3]={index}; {pc}={pc}+{b} end",
        q = q, stk = stk, a = a, limit = limit, step = step, index = index, pc = pc, b = b
    )));

    let (cf_base, cf_want, cf_n, cf_fn, cf_args, cf_res) = (
        rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
    );
    let (cm_proto, cm_upv, cm_fenv) = (rng.name(), rng.name(), rng.name());
    let (t_fn, t_num, t_tbl) = (cfg.type_fn.clone(), cfg.type_num.clone(), cfg.type_tbl.clone());

    let mut iterator = handler(m, VmOp::IteratorNext, cfg, rng);
    let a = iterator.raw_inst(2);
    let b = iterator.raw_inst(3);
    let c = iterator.raw_inst(4);
    let stk = iterator.cfg.stk.clone();
    let pc = iterator.cfg.pc.clone();
    let registry = iterator.cfg.closure_env_registry.clone();
    let execute = iterator.cfg.execute.clone();
    let native_type = iterator.cfg.native_type.clone();
    let frame = iterator.cfg.frame.clone();
    let res = iterator.rng.name();
    let iter_fn = iterator.rng.name();
    let meta = iterator.rng.name();
    let j = iterator.rng.name();
    out.push_str(&iterator.build(&format!(
        "local {iter_fn}={stk}[{a}]; local {meta}; if {native_type}({iter_fn})=={tfn} then {meta}={registry}[{iter_fn}] end; local {res}; if {meta} then {res}=zm({execute}({meta}.{cm_proto},{meta}.{cm_fenv},{meta}.{cm_upv},{iter_fn},{frame},{stk}[{a}+1],{stk}[{a}+2])) else {res}=zm({iter_fn}({stk}[{a}+1],{stk}[{a}+2])) end; for {j}=1,{b} do {stk}[{a}+2+{j}]={res}[{j}] end; if {stk}[{a}+3]~=nil then {stk}[{a}+2]={stk}[{a}+3]; {pc}={pc}+{c} end",
        res = res, stk = stk, a = a, j = j, b = b, pc = pc, c = c,
        iter_fn = iter_fn, registry = registry, meta = meta, execute = execute,
        native_type = native_type, frame = frame, tfn = t_fn,
        cm_proto = cm_proto, cm_fenv = cm_fenv, cm_upv = cm_upv
    )));

    let mut call_pack = handler(m, VmOp::CallPack, cfg, rng);
    let a = call_pack.raw_inst(2);
    let b = call_pack.raw_inst(3);
    let c = call_pack.raw_inst(4);
    let stk = call_pack.cfg.stk.clone();
    let top = call_pack.cfg.top.clone();
    let vs = call_pack.cfg.vstack.clone();
    let n = call_pack.rng.name();
    let j = call_pack.rng.name();
    out.push_str(&call_pack.build(&format!(
        "local {n}={b}>0 and {b}-1 or {top}-{a}; if {n}<0 then {n}=0 end; {{U0}}={{{cf_base}={a},{cf_want}={c},{cf_n}={n},{cf_fn}={stk}[{a}],{cf_args}={{}}}}; for {j}=1,{n} do {{U0}}.{cf_args}[{j}]={stk}[{a}+{j}] end; if {b}==0 then {top}={a} end/*MICRO_SEP*/{vs}[#{vs}+1]={{{{U0}}}}",
        n = n, b = b, top = top, a = a, c = c, j = j, stk = stk, vs = vs,
        cf_base = cf_base, cf_want = cf_want, cf_n = cf_n, cf_fn = cf_fn, cf_args = cf_args
    )));

    let mut call_execute = handler(m, VmOp::CallExecute, cfg, rng);
    let vs = call_execute.cfg.vstack.clone();
    let registry = call_execute.cfg.closure_env_registry.clone();
    let execute = call_execute.cfg.execute.clone();
    let frame = call_execute.cfg.frame.clone();
    let env_key = call_execute.cfg.frame_env_key.clone();
    let parent_key = call_execute.cfg.frame_parent_key.clone();
    let function_key = call_execute.cfg.frame_function_key.clone();
    let native_type = call_execute.cfg.native_type.clone();
    let native_getfenv = call_execute.cfg.native_getfenv.clone();
    let native_setfenv = call_execute.cfg.native_setfenv.clone();
    let n = call_execute.rng.name();
    let q = call_execute.rng.name();
    let meta = call_execute.rng.name();
    let target = call_execute.rng.name();
    let new_env = call_execute.rng.name();
    let level = call_execute.rng.name();
    let depth = call_execute.rng.name();
    let active_frame = call_execute.rng.name();
    let current_fn = call_execute.rng.name();
    out.push_str(&call_execute.build(&format!(
        "local {n}=#{vs}; local {q}={vs}[{n}][1]; local {meta}; if {native_type}({q}.{cf_fn})=={tfn} then {meta}={registry}[{q}.{cf_fn}] end; if {meta} then {q}.{cf_res}=zm({execute}({meta}.{cm_proto},{meta}.{cm_fenv},{meta}.{cm_upv},{q}.{cf_fn},{frame},unpack({q}.{cf_args},1,{q}.{cf_n}))) elseif {native_getfenv} and {q}.{cf_fn}=={native_getfenv} then local {level}={q}.{cf_args}[1]; if {level}==nil then {level}=1 end; if {native_type}({level})=={tnum} then if {level}==0 then {q}.{cf_res}=zm({native_getfenv}(0)) elseif {level}>=1 and {level}%1==0 then local {active_frame}={frame}; local {depth}={level}; while {depth}>1 and {active_frame} do {active_frame}={active_frame}[{parent_key}]; {depth}={depth}-1 end; if {active_frame} then {q}.{cf_res}=zm({active_frame}[{env_key}]) else {q}.{cf_res}=zm({native_getfenv}({level})) end else {q}.{cf_res}=zm({native_getfenv}({level})) end else if {native_type}({level})=={tfn} and {registry}[{level}] then {q}.{cf_res}=zm({registry}[{level}].{cm_fenv}) else {q}.{cf_res}=zm({native_getfenv}({level})) end end elseif {native_setfenv} and {q}.{cf_fn}=={native_setfenv} then local {target}={q}.{cf_args}[1]; local {new_env}={q}.{cf_args}[2]; if {native_type}({target})=={tnum} then if {target}==0 then {q}.{cf_res}=zm({native_setfenv}(0,{new_env})) elseif {native_type}({new_env})~={ttbl} then {q}.{cf_res}=zm({native_setfenv}({target},{new_env})) elseif {target}>=1 and {target}%1==0 then local {active_frame}={frame}; local {depth}={target}; while {depth}>1 and {active_frame} do {active_frame}={active_frame}[{parent_key}]; {depth}={depth}-1 end; if {active_frame} then {active_frame}[{env_key}]={new_env}; local {current_fn}={active_frame}[{function_key}]; if {current_fn} then local {meta}={registry}[{current_fn}]; if {meta} then {meta}.{cm_fenv}={new_env} end end; {q}.{cf_res}=zm({current_fn} or {execute}) else {q}.{cf_res}=zm({native_setfenv}({target},{new_env})) end else {q}.{cf_res}=zm({native_setfenv}({target},{new_env})) end elseif {native_type}({target})=={tfn} and {registry}[{target}] then if {native_type}({new_env})~={ttbl} then {q}.{cf_res}=zm({native_setfenv}({target},{new_env})) else {meta}={registry}[{target}]; {meta}.{cm_fenv}={new_env}; local {active_frame}={frame}; while {active_frame} do if {active_frame}[{function_key}]=={target} then {active_frame}[{env_key}]={new_env} end; {active_frame}={active_frame}[{parent_key}] end; {q}.{cf_res}=zm({target}) end else {q}.{cf_res}=zm({native_setfenv}({target},{new_env})) end else {q}.{cf_res}=zm({q}.{cf_fn}(unpack({q}.{cf_args},1,{q}.{cf_n}))) end",
        n = n, vs = vs, q = q, registry = registry, execute = execute, frame = frame,
        env_key = env_key, parent_key = parent_key, function_key = function_key,
        native_type = native_type, native_getfenv = native_getfenv, native_setfenv = native_setfenv,
        meta = meta, target = target, new_env = new_env, level = level, depth = depth,
        active_frame = active_frame, current_fn = current_fn,
        cf_fn = cf_fn, cf_args = cf_args, cf_n = cf_n, cf_res = cf_res,
        cm_proto = cm_proto, cm_fenv = cm_fenv, cm_upv = cm_upv,
        tfn = t_fn, tnum = t_num, ttbl = t_tbl
    )));

    let mut call_collect = handler(m, VmOp::CallCollect, cfg, rng);
    let vs = call_collect.cfg.vstack.clone();
    let stk = call_collect.cfg.stk.clone();
    let top = call_collect.cfg.top.clone();
    let count_field = call_collect.cfg.vararg_count.clone();
    let res = call_collect.rng.name();
    let j = call_collect.rng.name();
    let base = call_collect.rng.name();
    let want = call_collect.rng.name();
    let count = call_collect.rng.name();
    out.push_str(&call_collect.build(&format!(
        "{{U0}}=#{vs}; {{U1}}={vs}[{{U0}}][1]; {vs}[{{U0}}]=nil/*MICRO_SEP*/local {res}={{U1}}.{cf_res}; local {base}={{U1}}.{cf_base}; local {want}={{U1}}.{cf_want}; if {want}>0 then for {j}=1,{want}-1 do {stk}[{base}+{j}-1]={res}[{j}] end else local {count}={res}.{count_field}; {top}={base}-1; for {j}=1,{count} do {stk}[{base}+{j}-1]={res}[{j}]; {top}={top}+1 end end",
        vs = vs, res = res, base = base, want = want, j = j, stk = stk,
        count = count, count_field = count_field, top = top,
        cf_res = cf_res, cf_base = cf_base, cf_want = cf_want
    )));

    let close_ups = "if {STK}.{OPEN_UPS} then for reg, uv_obj in {NATIVE_PAIRS}({STK}.{OPEN_UPS}) do uv_obj[1] = {uv_obj[1][uv_obj[2]]}; uv_obj[2] = 1; end; {STK}.{OPEN_UPS} = nil; end; ";
    let mut tail = handler(m, VmOp::TailInvoke, cfg, rng);
    let vs = tail.cfg.vstack.clone();
    let registry = tail.cfg.closure_env_registry.clone();
    let execute = tail.cfg.execute.clone();
    let native_type = tail.cfg.native_type.clone();
    let frame = tail.cfg.frame.clone();
    let parent_key = tail.cfg.frame_parent_key.clone();
    let env_key = tail.cfg.frame_env_key.clone();
    let function_key = tail.cfg.frame_function_key.clone();
    let native_getfenv = tail.cfg.native_getfenv.clone();
    let native_setfenv = tail.cfg.native_setfenv.clone();
    let n = tail.rng.name();
    let q = tail.rng.name();
    let meta = tail.rng.name();
    let res = tail.rng.name();
    let target = tail.rng.name();
    let new_env = tail.rng.name();
    let level = tail.rng.name();
    let depth = tail.rng.name();
    let active_frame = tail.rng.name();
    let current_fn = tail.rng.name();
    let count_field = tail.cfg.vararg_count.clone();
    let body = format!(
        "{close}local {n}=#{vs}; local {q}={vs}[{n}][1]; local {meta}; if {native_type}({q}.{cf_fn})=={tfn} then {meta}={registry}[{q}.{cf_fn}] end; local {res}; if {meta} then {res}=zm({execute}({meta}.{cm_proto},{meta}.{cm_fenv},{meta}.{cm_upv},{q}.{cf_fn},{frame}[{parent_key}],unpack({q}.{cf_args},1,{q}.{cf_n}))) elseif {native_getfenv} and {q}.{cf_fn}=={native_getfenv} then local {level}={q}.{cf_args}[1]; if {level}==nil then {level}=1 end; if {native_type}({level})=={tnum} then if {level}==0 then {res}=zm({native_getfenv}(0)) elseif {level}>=1 and {level}%1==0 then local {active_frame}={frame}; local {depth}={level}; while {depth}>1 and {active_frame} do {active_frame}={active_frame}[{parent_key}]; {depth}={depth}-1 end; if {active_frame} then {res}=zm({active_frame}[{env_key}]) else {res}=zm({native_getfenv}({level})) end else {res}=zm({native_getfenv}({level})) end else if {native_type}({level})=={tfn} and {registry}[{level}] then {res}=zm({registry}[{level}].{cm_fenv}) else {res}=zm({native_getfenv}({level})) end end elseif {native_setfenv} and {q}.{cf_fn}=={native_setfenv} then local {target}={q}.{cf_args}[1]; local {new_env}={q}.{cf_args}[2]; if {native_type}({target})=={tnum} then if {target}==0 then {res}=zm({native_setfenv}(0,{new_env})) elseif {native_type}({new_env})~={ttbl} then {res}=zm({native_setfenv}({target},{new_env})) elseif {target}>=1 and {target}%1==0 then local {active_frame}={frame}; local {depth}={target}; while {depth}>1 and {active_frame} do {active_frame}={active_frame}[{parent_key}]; {depth}={depth}-1 end; if {active_frame} then {active_frame}[{env_key}]={new_env}; local {current_fn}={active_frame}[{function_key}]; if {current_fn} then local {meta}={registry}[{current_fn}]; if {meta} then {meta}.{cm_fenv}={new_env} end end; {res}=zm({current_fn} or {execute}) else {res}=zm({native_setfenv}({target},{new_env})) end else {res}=zm({native_setfenv}({target},{new_env})) end elseif {native_type}({target})=={tfn} and {registry}[{target}] then if {native_type}({new_env})~={ttbl} then {res}=zm({native_setfenv}({target},{new_env})) else {meta}={registry}[{target}]; {meta}.{cm_fenv}={new_env}; local {active_frame}={frame}; while {active_frame} do if {active_frame}[{function_key}]=={target} then {active_frame}[{env_key}]={new_env} end; {active_frame}={active_frame}[{parent_key}] end; {res}=zm({target}) end else {res}=zm({native_setfenv}({target},{new_env})) end else {res}=zm({q}.{cf_fn}(unpack({q}.{cf_args},1,{q}.{cf_n}))) end; {vs}[{n}]=nil; {{STOREBACK}} return {{RET2}}({res},1,{res}.{count_field})",
        close = close_ups, n = n, vs = vs, q = q, res = res, count_field = count_field,
        registry = registry, execute = execute, native_type = native_type, frame = frame,
        parent_key = parent_key, env_key = env_key, function_key = function_key,
        native_getfenv = native_getfenv, native_setfenv = native_setfenv,
        meta = meta, target = target, new_env = new_env, level = level, depth = depth,
        active_frame = active_frame, current_fn = current_fn,
        cf_fn = cf_fn, cf_args = cf_args, cf_n = cf_n,
        cm_proto = cm_proto, cm_fenv = cm_fenv, cm_upv = cm_upv,
        tfn = t_fn, tnum = t_num, ttbl = t_tbl
    );
    out.push_str(&tail.build(&body));

    let mut ret_none = handler(m, VmOp::ReturnNone, cfg, rng);
    out.push_str(&ret_none.build(&format!("{}{{STOREBACK}} return {{RET0}}()", close_ups)));

    let mut ret_one = handler(m, VmOp::ReturnOne, cfg, rng);
    let a = ret_one.raw_inst(2);
    let stk = ret_one.cfg.stk.clone();
    out.push_str(&ret_one.build(&format!("{}{{STOREBACK}} return {{RET1}}({stk}[{a}])", close_ups, stk = stk, a = a)));

    let mut ret_range = handler(m, VmOp::ReturnRange, cfg, rng);
    let a = ret_range.raw_inst(2);
    let b = ret_range.raw_inst(3);
    let stk = ret_range.cfg.stk.clone();
    let top = ret_range.cfg.top.clone();
    let count = ret_range.rng.name();
    out.push_str(&ret_range.build(&format!(
        "{}{{STOREBACK}} local {count}={b}>0 and {b} or {top}-{a}+1; return {{RET2}}({stk},{a},{a}+{count}-1)",
        close_ups, count = count, b = b, top = top, a = a, stk = stk
    )));

    let mut set_list = handler(m, VmOp::SetList, cfg, rng);
    let a = set_list.raw_inst(2);
    let b = set_list.raw_inst(3);
    let c = set_list.raw_inst(4);
    let stk = set_list.cfg.stk.clone();
    let top = set_list.cfg.top.clone();
    let j = set_list.rng.name();
    out.push_str(&set_list.build(&format!(
        "{{U0}}={b}>0 and {b} or {top}-{a}; if {{U0}}<0 then {{U0}}=0 end; {{U1}}=({c}-1)*50/*MICRO_SEP*/for {j}=1,{{U0}} do {stk}[{a}][{{U1}}+{j}]={stk}[{a}+{j}] end; if {b}==0 then {top}={a} end",
        b = b, top = top, a = a, c = c, j = j, stk = stk
    )));

    let mut close = handler(m, VmOp::CloseUpvalues, cfg, rng);
    let a = close.raw_inst(2);
    let stk = close.cfg.stk.clone();
    out.push_str(&close.build(&format!(
        "if {stk}.{{OPEN_UPS}} then for reg, uv_obj in {{NATIVE_PAIRS}}({stk}.{{OPEN_UPS}}) do if reg >= {a} then uv_obj[1]={{uv_obj[1][uv_obj[2]]}}; uv_obj[2]=1; {stk}.{{OPEN_UPS}}[reg]=nil end end end",
        stk = stk, a = a
    )));

    let mut make_closure = handler(m, VmOp::MakeClosure, cfg, rng);
    let a = make_closure.raw_inst(2);
    let b = make_closure.raw_inst(3);
    let c = make_closure.raw_inst(4);
    let stk = make_closure.cfg.stk.clone();
    let up = make_closure.cfg.upvals.clone();
    let protos = make_closure.cfg.protos.clone();
    let pc = make_closure.cfg.pc.clone();
    let insts = make_closure.cfg.insts.clone();
    let p = make_closure.rng.name();
    let uv = make_closure.rng.name();
    let j = make_closure.rng.name();
    // Generator 在最终魔数/链偏移注入时识别这个固定伪指令变量名，
    // 并同步改写下方与 CaptureLocal handler aliases 的比较。
    let uv_inst = "uv_inst".to_string();
    let reg = make_closure.rng.name();
    let check_local = m[VmOp::CaptureLocal.global_id()]
        .iter()
        .map(|alias| format!("{uv_inst}[1] == {alias}", uv_inst = uv_inst, alias = alias))
        .collect::<Vec<_>>()
        .join(" or ");
    let execute = make_closure.cfg.execute.clone();
    let env = make_closure.cfg.env.clone();
    let registry = make_closure.cfg.closure_env_registry.clone();
    let native_type = make_closure.cfg.native_type.clone();
    let closure_fn = make_closure.rng.name();
    let closure_meta = make_closure.rng.name();
    let closure_body = format!(
        "local {p}={protos}[{b}+1]; if {native_type}({p})=={tfn} then {p}={p}(); {protos}[{b}+1]={p} end; local {uv}={{}}; {stk}.{{OPEN_UPS}}={stk}.{{OPEN_UPS}} or {{}}; for {j}=1,{c} do local {uv_inst} = {insts}[{pc}]; {pc}={pc}+1; if {check_local} then local {reg}={uv_inst}[3]; if not {stk}.{{OPEN_UPS}}[{reg}] then {stk}.{{OPEN_UPS}}[{reg}]={{{stk},{reg}}} end; {uv}[{j}]={stk}.{{OPEN_UPS}}[{reg}] else {uv}[{j}]={up}[{uv_inst}[3]+1] end end; local {closure_fn}; {closure_fn}=function(...) return {execute}({p},{registry}[{closure_fn}].{cm_fenv},{uv},{closure_fn},nil,...) end; local {closure_meta}={{{cm_proto}={p},{cm_upv}={uv},{cm_fenv}={env}}}; {registry}[{closure_fn}]={closure_meta}; {stk}[{a}]={closure_fn}",
        p = p, protos = protos, b = b, uv = uv, stk = stk, j = j, c = c, uv_inst = uv_inst,
        insts = insts, pc = pc, check_local = check_local, reg = reg, up = up, a = a,
        execute = execute, env = env, registry = registry, native_type = native_type,
        closure_fn = closure_fn, closure_meta = closure_meta,
        tfn = t_fn, cm_proto = cm_proto, cm_upv = cm_upv, cm_fenv = cm_fenv
    );
    out.push_str(&make_closure.build(&closure_body));

    // 捕获描述只由 MakeClosure 消费。独立执行时按空操作处理，避免损坏字节码将
    // 描述字当成寄存器指令后改变 VM 状态。
    for op in [VmOp::CaptureLocal, VmOp::CaptureUpvalue] {
        let mut no_op = handler(m, op, cfg, rng);
        out.push_str(&no_op.build(""));
    }

    // VmOp::Noop 作为运行期动态状态不变量调制指令：读取当前运行期 PC、求值栈深度 #vstack、
    // 变参个数 varargs_len、活动寄存器表 stk 及原型密钥 ld_key，在真不变量分支下对栈顶值
    // 叠加恒等零偏置（使静态常量传播/折叠无法穿透 Noop），伪分支下混入运行期 PC 与密钥扰动。
    let mut noop = handler(m, VmOp::Noop, cfg, rng);
    let s = noop.cfg.vstack.clone();
    let pc_v = noop.cfg.pc.clone();
    let vlen = noop.cfg.varargs_len.clone();
    let stk_t = noop.cfg.stk.clone();
    let ntype = noop.cfg.native_type.clone();
    let ttbl = noop.cfg.type_tbl.clone();
    let ld = noop.cfg.ld_key.clone();
    out.push_str(&noop.build(&format!(
        "{{U0}}=#{s}; if {{U0}}>0 then {{U1}}={s}[{{U0}}][1]; {{U2}}=(({pc}+{{U0}}+{vlen})%2) end/*MICRO_SEP*/if {{U0}}>0 then if {nt}({stk})=={tt} and ({pc}+{{U0}})>0 then {s}[{{U0}}][1]={{U1}}+{{U2}}-(({pc}+#{s}+{vlen})%2) else {s}[{{U0}}][1]={{U1}}-{pc}-{ld} end end",
        s = s, pc = pc_v, vlen = vlen, nt = ntype, stk = stk_t, tt = ttbl, ld = ld
    )));

    let mut varargs = handler(m, VmOp::Varargs, cfg, rng);
    let a = varargs.raw_inst(2);
    let b = varargs.raw_inst(3);
    let stk = varargs.cfg.stk.clone();
    let top = varargs.cfg.top.clone();
    let args = varargs.cfg.varargs.clone();
    let len = varargs.cfg.varargs_len.clone();
    let j = varargs.rng.name();
    out.push_str(&varargs.build(&format!(
        "if {b}>0 then for {j}=1,{b}-1 do {stk}[{a}+{j}-1]={args}[{j}] end else {top}={a}-1; for {j}=1,{len} do {stk}[{a}+{j}-1]={args}[{j}]; {top}={top}+1 end; end",
        b = b, j = j, stk = stk, a = a, args = args, top = top, len = len
    )));

    out
}
