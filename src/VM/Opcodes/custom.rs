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
    let n = h.rng.name();
    let x = h.rng.name();
    let y = h.rng.name();
    out.push_str(&h.build(&format!(
        "local {n}=#{s}; local {x}={s}[{n}-1][1]; local {y}={s}[{n}][1]; {s}[{n}-1][1]={x}{operator}{y}; {s}[{n}]=nil",
        n = n, s = s, x = x, y = y, operator = operator
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
    let n = h.rng.name();
    let v = h.rng.name();
    let expression = format!("{operator}{v}", operator = operator, v = v);
    out.push_str(&h.build(&format!(
        "local {n}=#{s}; local {v}={s}[{n}][1]; {s}[{n}][1]={expression}",
        n = n, s = s, v = v, expression = expression
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
    out.push_str(&push_const.build(&format!("{vstack}[#{vstack}+1]={{{consts}[{b}+1]}}", vstack = vstack, consts = consts, b = b)));

    let mut push_rk = handler(m, VmOp::PushRk, cfg, rng);
    let value = push_rk.rk(3);
    let vstack = push_rk.cfg.vstack.clone();
    out.push_str(&push_rk.build(&format!("{vstack}[#{vstack}+1]={{{value}}}", vstack = vstack, value = value)));

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
    out.push_str(&push_bool.build(&format!("{vstack}[#{vstack}+1]={{{a}~=0}}", vstack = vstack, a = a)));

    let mut pop_reg = handler(m, VmOp::PopReg, cfg, rng);
    let a = pop_reg.raw_inst(2);
    let n = pop_reg.rng.name();
    let vstack = pop_reg.cfg.vstack.clone();
    let stk = pop_reg.cfg.stk.clone();
    out.push_str(&pop_reg.build(&format!(
        "local {n}=#{vstack}; {stk}[{a}]={vstack}[{n}][1]; {vstack}[{n}]=nil",
        n = n, vstack = vstack, stk = stk, a = a
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
        "local k={consts}[{b}+1]; local e={env}; e[k]={stk}[{a}]",
        consts = consts, b = b, env = env, stk = stk, a = a
    )));

    let mut get_index = handler(m, VmOp::GetIndex, cfg, rng);
    let s = get_index.cfg.vstack.clone();
    let n = get_index.rng.name();
    let k = get_index.rng.name();
    let t = get_index.rng.name();
    let value = get_index.rng.name();
    out.push_str(&get_index.build(&format!(
        "local {n}=#{s}; local {k}={s}[{n}][1]; local {t}={s}[{n}-1][1]; local {value}={t}[{k}]; {s}[{n}-1][1]={value}; {s}[{n}]=nil",
        n = n, s = s, k = k, t = t, value = value
    )));

    let mut set_index = handler(m, VmOp::SetIndex, cfg, rng);
    let s = set_index.cfg.vstack.clone();
    let n = set_index.rng.name();
    let k = set_index.rng.name();
    let t = set_index.rng.name();
    let v = set_index.rng.name();
    out.push_str(&set_index.build(&format!(
        "local {n}=#{s}; local {v}={s}[{n}][1]; local {k}={s}[{n}-1][1]; local {t}={s}[{n}-2][1]; {t}[{k}]={v}; {s}[{n}]=nil; {s}[{n}-1]=nil; {s}[{n}-2]=nil",
        n = n, s = s, v = v, k = k, t = t
    )));

    let mut new_table = handler(m, VmOp::NewTable, cfg, rng);
    let vstack = new_table.cfg.vstack.clone();
    out.push_str(&new_table.build(&format!("{vstack}[#{vstack}+1]={{{{}}}}", vstack = vstack)));

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
    let n = equal.rng.name();
    let x = equal.rng.name();
    let y = equal.rng.name();
    out.push_str(&equal.build(&format!("local {n}=#{s}; local {x}={s}[{n}-1][1]; local {y}={s}[{n}][1]; {s}[{n}-1][1]=({x}=={y}); {s}[{n}]=nil", n = n, s = s, x = x, y = y)));

    let mut less = handler(m, VmOp::Less, cfg, rng);
    let s = less.cfg.vstack.clone();
    let n = less.rng.name();
    let x = less.rng.name();
    let y = less.rng.name();
    out.push_str(&less.build(&format!("local {n}=#{s}; local {x}={s}[{n}-1][1]; local {y}={s}[{n}][1]; {s}[{n}-1][1]=({x}<{y}); {s}[{n}]=nil", n = n, s = s, x = x, y = y)));

    let mut less_equal = handler(m, VmOp::LessEqual, cfg, rng);
    let s = less_equal.cfg.vstack.clone();
    let n = less_equal.rng.name();
    let x = less_equal.rng.name();
    let y = less_equal.rng.name();
    out.push_str(&less_equal.build(&format!("local {n}=#{s}; local {x}={s}[{n}-1][1]; local {y}={s}[{n}][1]; {s}[{n}-1][1]=({x}<={y}); {s}[{n}]=nil", n = n, s = s, x = x, y = y)));

    let mut concat = handler(m, VmOp::Concat, cfg, rng);
    let s = concat.cfg.vstack.clone();
    let a = concat.raw_inst(2);
    let n = concat.rng.name();
    let first = concat.rng.name();
    let last = concat.rng.name();
    let j = concat.rng.name();
    let value = concat.rng.name();
    out.push_str(&concat.build(&format!(
        "local {n}=#{s}; local {first}={n}-{a}+1; local {last}={n}; local {value}={s}[{last}][1]; for {j}={last}-1,{first},-1 do {value}={s}[{j}][1]..{value} end; {s}[{first}][1]={value}; for {j}={first}+1,{last} do {s}[{j}]=nil end",
        n = n, s = s, first = first, a = a, last = last, value = value, j = j
    )));

    let mut branch = handler(m, VmOp::Branch, cfg, rng);
    let a = branch.raw_inst(2);
    let b = branch.raw_inst(3);
    let n = branch.rng.name();
    let v = branch.rng.name();
    let s = branch.cfg.vstack.clone();
    let pc = branch.cfg.pc.clone();
    out.push_str(&branch.build(&format!(
        "local {n}=#{s}; local {v}={s}[{n}][1]; {s}[{n}]=nil; if (({v}~=nil and {v}~=false)==({a}~=0)) then {pc}={pc}+{b} end",
        n = n, s = s, v = v, a = a, pc = pc, b = b
    )));

    for (op, polarity) in [(VmOp::BranchSetTrue, true), (VmOp::BranchSetFalse, false)] {
        let mut branch_set = handler(m, op, cfg, rng);
        let a = branch_set.raw_inst(2);
        let b = branch_set.raw_inst(3);
        let c = branch_set.raw_inst(4);
        let stk = branch_set.cfg.stk.clone();
        let pc = branch_set.cfg.pc.clone();
        let condition = if polarity {
            format!("({s}[{b}]~=nil and {s}[{b}]~=false)", s = stk, b = b)
        } else {
            format!("not ({s}[{b}]~=nil and {s}[{b}]~=false)", s = stk, b = b)
        };
        out.push_str(&branch_set.build(&format!(
            "if {condition} then {stk}[{a}]={stk}[{b}]; {pc}={pc}+{c} end",
            condition = condition, stk = stk, a = a, b = b, pc = pc, c = c
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
        "local {init}={{NATIVE_TONUMBER}}({stk}[{a}]); if {init}==nil then {init_error} end; local {limit}={{NATIVE_TONUMBER}}({stk}[{a}+1]); if {limit}==nil then {limit_error} end; local {step}={{NATIVE_TONUMBER}}({stk}[{a}+2]); if {step}==nil then {step_error} end; {stk}[{a}]={init}-{step}; {stk}[{a}+1]={limit}; {stk}[{a}+2]={step}; local {q}={{{limit},{step}}}; {stk}[-{a}-1]={q}; {pc}={pc}+{b}",
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
        "local {iter_fn}={stk}[{a}]; local {meta}; if {native_type}({iter_fn})=='function' then {meta}={registry}[{iter_fn}] end; local {res}; if {meta} then {res}=zm({execute}({meta}.proto,{meta}.fenvironment,{meta}.upvalues,{iter_fn},{frame},{stk}[{a}+1],{stk}[{a}+2])) else {res}=zm({iter_fn}({stk}[{a}+1],{stk}[{a}+2])) end; for {j}=1,{b} do {stk}[{a}+2+{j}]={res}[{j}] end; if {stk}[{a}+3]~=nil then {stk}[{a}+2]={stk}[{a}+3]; {pc}={pc}+{c} end",
        res = res, stk = stk, a = a, j = j, b = b, pc = pc, c = c,
        iter_fn = iter_fn, registry = registry, meta = meta, execute = execute,
        native_type = native_type, frame = frame
    )));

    let mut call_pack = handler(m, VmOp::CallPack, cfg, rng);
    let a = call_pack.raw_inst(2);
    let b = call_pack.raw_inst(3);
    let c = call_pack.raw_inst(4);
    let stk = call_pack.cfg.stk.clone();
    let top = call_pack.cfg.top.clone();
    let vs = call_pack.cfg.vstack.clone();
    let n = call_pack.rng.name();
    let q = call_pack.rng.name();
    let j = call_pack.rng.name();
    out.push_str(&call_pack.build(&format!(
        "local {n}={b}>0 and {b}-1 or {top}-{a}; if {n}<0 then {n}=0 end; local {q}={{base={a},want={c},n={n},fn={stk}[{a}],args={{}}}}; for {j}=1,{n} do {q}.args[{j}]={stk}[{a}+{j}] end; if {b}==0 then {top}={a} end; {vs}[#{vs}+1]={{{q}}}",
        n = n, b = b, top = top, a = a, q = q, c = c, j = j, stk = stk, vs = vs
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
        "local {n}=#{vs}; local {q}={vs}[{n}][1]; local {meta}; if {native_type}({q}.fn)=='function' then {meta}={registry}[{q}.fn] end; if {meta} then {q}.result=zm({execute}({meta}.proto,{meta}.fenvironment,{meta}.upvalues,{q}.fn,{frame},unpack({q}.args,1,{q}.n))) elseif {native_getfenv} and {q}.fn=={native_getfenv} then local {level}={q}.args[1]; if {level}==nil then {level}=1 end; if {native_type}({level})=='number' then if {level}==0 then {q}.result=zm({native_getfenv}(0)) elseif {level}>=1 and {level}%1==0 then local {active_frame}={frame}; local {depth}={level}; while {depth}>1 and {active_frame} do {active_frame}={active_frame}[{parent_key}]; {depth}={depth}-1 end; if {active_frame} then {q}.result=zm({active_frame}[{env_key}]) else {q}.result=zm({native_getfenv}({level})) end else {q}.result=zm({native_getfenv}({level})) end else if {native_type}({level})=='function' and {registry}[{level}] then {q}.result=zm({registry}[{level}].fenvironment) else {q}.result=zm({native_getfenv}({level})) end end elseif {native_setfenv} and {q}.fn=={native_setfenv} then local {target}={q}.args[1]; local {new_env}={q}.args[2]; if {native_type}({target})=='number' then if {target}==0 then {q}.result=zm({native_setfenv}(0,{new_env})) elseif {native_type}({new_env})~='table' then {q}.result=zm({native_setfenv}({target},{new_env})) elseif {target}>=1 and {target}%1==0 then local {active_frame}={frame}; local {depth}={target}; while {depth}>1 and {active_frame} do {active_frame}={active_frame}[{parent_key}]; {depth}={depth}-1 end; if {active_frame} then {active_frame}[{env_key}]={new_env}; local {current_fn}={active_frame}[{function_key}]; if {current_fn} then local {meta}={registry}[{current_fn}]; if {meta} then {meta}.fenvironment={new_env} end end; {q}.result=zm({current_fn} or {execute}) else {q}.result=zm({native_setfenv}({target},{new_env})) end else {q}.result=zm({native_setfenv}({target},{new_env})) end elseif {native_type}({target})=='function' and {registry}[{target}] then if {native_type}({new_env})~='table' then {q}.result=zm({native_setfenv}({target},{new_env})) else {meta}={registry}[{target}]; {meta}.fenvironment={new_env}; local {active_frame}={frame}; while {active_frame} do if {active_frame}[{function_key}]=={target} then {active_frame}[{env_key}]={new_env} end; {active_frame}={active_frame}[{parent_key}] end; {q}.result=zm({target}) end else {q}.result=zm({native_setfenv}({target},{new_env})) end else {q}.result=zm({q}.fn(unpack({q}.args,1,{q}.n))) end",
        n = n, vs = vs, q = q, registry = registry, execute = execute, frame = frame,
        env_key = env_key, parent_key = parent_key, function_key = function_key,
        native_type = native_type, native_getfenv = native_getfenv, native_setfenv = native_setfenv,
        meta = meta, target = target, new_env = new_env, level = level, depth = depth,
        active_frame = active_frame, current_fn = current_fn
    )));

    let mut call_collect = handler(m, VmOp::CallCollect, cfg, rng);
    let vs = call_collect.cfg.vstack.clone();
    let stk = call_collect.cfg.stk.clone();
    let top = call_collect.cfg.top.clone();
    let count_field = call_collect.cfg.vararg_count.clone();
    let n = call_collect.rng.name();
    let q = call_collect.rng.name();
    let res = call_collect.rng.name();
    let j = call_collect.rng.name();
    let base = call_collect.rng.name();
    let want = call_collect.rng.name();
    let count = call_collect.rng.name();
    out.push_str(&call_collect.build(&format!(
        "local {n}=#{vs}; local {q}={vs}[{n}][1]; local {res}={q}.result; local {base}={q}.base; local {want}={q}.want; if {want}>0 then for {j}=1,{want}-1 do {stk}[{base}+{j}-1]={res}[{j}] end else local {count}={res}.{count_field}; {top}={base}-1; for {j}=1,{count} do {stk}[{base}+{j}-1]={res}[{j}]; {top}={top}+1 end end; {vs}[{n}]=nil",
        n = n, vs = vs, q = q, res = res, base = base, want = want, j = j, stk = stk,
        count = count, count_field = count_field, top = top
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
        "{close}local {n}=#{vs}; local {q}={vs}[{n}][1]; local {meta}; if {native_type}({q}.fn)=='function' then {meta}={registry}[{q}.fn] end; local {res}; if {meta} then {res}=zm({execute}({meta}.proto,{meta}.fenvironment,{meta}.upvalues,{q}.fn,{frame}[{parent_key}],unpack({q}.args,1,{q}.n))) elseif {native_getfenv} and {q}.fn=={native_getfenv} then local {level}={q}.args[1]; if {level}==nil then {level}=1 end; if {native_type}({level})=='number' then if {level}==0 then {res}=zm({native_getfenv}(0)) elseif {level}>=1 and {level}%1==0 then local {active_frame}={frame}; local {depth}={level}; while {depth}>1 and {active_frame} do {active_frame}={active_frame}[{parent_key}]; {depth}={depth}-1 end; if {active_frame} then {res}=zm({active_frame}[{env_key}]) else {res}=zm({native_getfenv}({level})) end else {res}=zm({native_getfenv}({level})) end else if {native_type}({level})=='function' and {registry}[{level}] then {res}=zm({registry}[{level}].fenvironment) else {res}=zm({native_getfenv}({level})) end end elseif {native_setfenv} and {q}.fn=={native_setfenv} then local {target}={q}.args[1]; local {new_env}={q}.args[2]; if {native_type}({target})=='number' then if {target}==0 then {res}=zm({native_setfenv}(0,{new_env})) elseif {native_type}({new_env})~='table' then {res}=zm({native_setfenv}({target},{new_env})) elseif {target}>=1 and {target}%1==0 then local {active_frame}={frame}; local {depth}={target}; while {depth}>1 and {active_frame} do {active_frame}={active_frame}[{parent_key}]; {depth}={depth}-1 end; if {active_frame} then {active_frame}[{env_key}]={new_env}; local {current_fn}={active_frame}[{function_key}]; if {current_fn} then local {meta}={registry}[{current_fn}]; if {meta} then {meta}.fenvironment={new_env} end end; {res}=zm({current_fn} or {execute}) else {res}=zm({native_setfenv}({target},{new_env})) end else {res}=zm({native_setfenv}({target},{new_env})) end elseif {native_type}({target})=='function' and {registry}[{target}] then if {native_type}({new_env})~='table' then {res}=zm({native_setfenv}({target},{new_env})) else {meta}={registry}[{target}]; {meta}.fenvironment={new_env}; local {active_frame}={frame}; while {active_frame} do if {active_frame}[{function_key}]=={target} then {active_frame}[{env_key}]={new_env} end; {active_frame}={active_frame}[{parent_key}] end; {res}=zm({target}) end else {res}=zm({native_setfenv}({target},{new_env})) end else {res}=zm({q}.fn(unpack({q}.args,1,{q}.n))) end; {vs}[{n}]=nil; {{STOREBACK}} return {{RET2}}({res},1,{res}.{count_field})",
        close = close_ups, n = n, vs = vs, q = q, res = res, count_field = count_field,
        registry = registry, execute = execute, native_type = native_type, frame = frame,
        parent_key = parent_key, env_key = env_key, function_key = function_key,
        native_getfenv = native_getfenv, native_setfenv = native_setfenv,
        meta = meta, target = target, new_env = new_env, level = level, depth = depth,
        active_frame = active_frame, current_fn = current_fn
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
    let n = set_list.rng.name();
    let offset = set_list.rng.name();
    out.push_str(&set_list.build(&format!(
        "local {n}={b}>0 and {b} or {top}-{a}; if {n}<0 then {n}=0 end; local {offset}=({c}-1)*50; for {j}=1,{n} do {stk}[{a}][{offset}+{j}]={stk}[{a}+{j}] end; if {b}==0 then {top}={a} end",
        n = n, b = b, top = top, a = a, offset = offset, c = c, j = j, stk = stk
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
        "local {p}={protos}[{b}+1]; if {native_type}({p})=='function' then {p}={p}(); {protos}[{b}+1]={p} end; local {uv}={{}}; {stk}.{{OPEN_UPS}}={stk}.{{OPEN_UPS}} or {{}}; for {j}=1,{c} do local {uv_inst} = {insts}[{pc}]; {pc}={pc}+1; if {check_local} then local {reg}={uv_inst}[3]; if not {stk}.{{OPEN_UPS}}[{reg}] then {stk}.{{OPEN_UPS}}[{reg}]={{{stk},{reg}}} end; {uv}[{j}]={stk}.{{OPEN_UPS}}[{reg}] else {uv}[{j}]={up}[{uv_inst}[3]+1] end end; local {closure_fn}; {closure_fn}=function(...) return {execute}({p},{registry}[{closure_fn}].fenvironment,{uv},{closure_fn},nil,...) end; local {closure_meta}={{proto={p},upvalues={uv},fenvironment={env}}}; {registry}[{closure_fn}]={closure_meta}; {stk}[{a}]={closure_fn}",
        p = p, protos = protos, b = b, uv = uv, stk = stk, j = j, c = c, uv_inst = uv_inst,
        insts = insts, pc = pc, check_local = check_local, reg = reg, up = up, a = a,
        execute = execute, env = env, registry = registry, native_type = native_type,
        closure_fn = closure_fn, closure_meta = closure_meta
    );
    out.push_str(&make_closure.build(&closure_body));

    // 捕获描述只由 MakeClosure 消费。独立执行时按空操作处理，避免损坏字节码将
    // 描述字当成寄存器指令后改变 VM 状态。
    for op in [VmOp::CaptureLocal, VmOp::CaptureUpvalue, VmOp::Noop] {
        let mut no_op = handler(m, op, cfg, rng);
        out.push_str(&no_op.build(""));
    }

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
