//! Semantics-preserving split of the VM instruction loop into tail-returning helpers.
//!
//! The existing frame setup remains in `execute`; the unchanged instruction loop moves
//! into a nested function, and a tiny randomized router forwards every return value.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LoopForm {
    While,
    Repeat,
}

/// Build a per-output flow shape without consuming the generator's existing RNG stream.
pub(super) fn wrap_for_build(
    setup: &str,
    body: &str,
    has_handlers: bool,
    chunk_name: &str,
    execute_name: &str,
    vm_seed: u64,
    handler_count: usize,
) -> String {
    let style_seed = vm_seed ^ (handler_count as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let suffix = |name: &str| format!("{}_{}", execute_name, name);
    wrap_dispatcher(
        setup,
        body,
        has_handlers,
        if style_seed & 1 == 0 {
            LoopForm::Repeat
        } else {
            LoopForm::While
        },
        chunk_name,
        &suffix("dispatch_core"),
        &suffix("dispatch_route"),
        &suffix("dispatch_gate"),
        &suffix("dispatch_index"),
        style_seed & 2 != 0,
        style_seed,
    )
}

/// Emit the inner dispatcher and its return-preserving route inside `execute`.
/// `body` is the original instruction-loop body; it is not reordered or rewritten.
pub(super) fn wrap_dispatcher(
    setup: &str,
    body: &str,
    has_handlers: bool,
    loop_form: LoopForm,
    chunk_name: &str,
    core_name: &str,
    route_name: &str,
    gate_name: &str,
    index_name: &str,
    invert_route: bool,
    flow_seed: u64,
) -> String {
    let step_name = format!("{}_dispatch_step", core_name);
    let exit_a = format!("{}_return_a", route_name);
    let exit_b = format!("{}_return_b", route_name);
    let state_name = format!("{}_state", route_name);
    let base = (flow_seed as u32) & 0x3FFF_FF00;
    let state = |offset: u32| format!("0X{:X}", base + offset);
    let (s0, s1, s2, s3, s4, s5, s6, s7) = (
        state(0x11),
        state(0x27),
        state(0x3D),
        state(0x53),
        state(0x69),
        state(0x7F),
        state(0x95),
        state(0xAB),
    );

    // Keep setup in its original position; the nested step closure captures its locals.
    let loop_body = if !has_handlers {
        // Preserve the previous empty-tree behavior: enter once, break, and return no values.
        "while true do break end".to_string()
    } else {
        let (open, close) = match loop_form {
            LoopForm::While => ("while not ((true or false)==false) do ", " end;"),
            LoopForm::Repeat => ("repeat ", " until (false and not true) or false;"),
        };
        format!("{}{}{}", open, body, close)
    };
    let core_body = format!(
        "{setup}local function {step}(...) {loop_body} end; return {step}(...);",
        setup = setup,
        step = step_name,
        loop_body = loop_body,
    );

    // Two state-machine entry paths converge only through return-preserving relays.
    let start_test = if invert_route {
        format!("not {}", gate_name)
    } else {
        gate_name.to_string()
    };
    let route_form = match loop_form {
        LoopForm::While => LoopForm::Repeat,
        LoopForm::Repeat => LoopForm::While,
    };
    let (route_open, route_close) = match route_form {
        LoopForm::While => ("while not ((true or false)==false) do", "end;"),
        LoopForm::Repeat => ("repeat", "until (false and not true) or false;"),
    };

    format!(
        r#"local function {core}(...) {core_body} end;
local function {exit_a}(...) return {core}(...) end;
local function {exit_b}({gate},...)
  if {gate} and not (false or false) then return {exit_a}(...)
  elseif not {gate} or (false and {gate}) then return {core}(...)
  else return {exit_a}(...) end
end;
local function {route}(...)
  local {gate}=({chunk}~=nil and true) or false;
  local {state}={start} and {s0} or {s1};
  {route_open}
    if {state}=={s0} then
      if {gate} and not (false or false) then {state}={s2}
      elseif not {gate} or (false and {gate}) then {state}={s3} else break end
    elseif {state}=={s1} then
      if not {gate} or (false and {gate}) then {state}={s5}
      elseif {gate} and not (false or false) then {state}={s4} else break end
    elseif {state}=={s2} then
      repeat {state}={s6} until (false and not {gate}) or true
    elseif {state}=={s3} then {state}={s7}
    elseif {state}=={s4} then {state}={s6}
    elseif {state}=={s5} then
      for {index}=0X1,0X1 do
        if not {gate} or (false and {gate}) then {state}={s7}
        elseif {gate} and (true or false) then {state}={s6}
        else {state}={s7} end; break
      end
    elseif {state}=={s6} then return {exit_a}(...)
    elseif {state}=={s7} then return {exit_b}({gate},...)
    else break end
  {route_close}
  return {exit_a}(...)
end;
return {route}(...);"#,
        core = core_name,
        core_body = core_body,
        exit_a = exit_a,
        exit_b = exit_b,
        route = route_name,
        gate = gate_name,
        chunk = chunk_name,
        state = state_name,
        index = index_name,
        start = start_test,
        s0 = s0,
        s1 = s1,
        s2 = s2,
        s3 = s3,
        s4 = s4,
        s5 = s5,
        s6 = s6,
        s7 = s7,
        route_open = route_open,
        route_close = route_close,
    )
}

#[cfg(test)]
mod tests {
    use super::{LoopForm, wrap_dispatcher};
    use crate::compressor::Compressor;
    use std::process::Command;

    fn run_lua(lua: &std::path::Path, code: &str, name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("kryvex_flow_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(name);
        std::fs::write(&path, code).expect("write flow test");
        let output = Command::new(lua).arg(&path).output().expect("run Lua 5.1");
        assert!(
            output.status.success(),
            "Lua 5.1 failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            code
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn split_dispatcher_preserves_order_break_and_multiple_returns() {
        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }

        for form in [LoopForm::While, LoopForm::Repeat] {
            for invert in [false, true] {
                let setup = "local flow_bias=0;";
                let loop_body = "local total=flow_bias; for i=1,4 do total=total+i; if i==2 then break end end; if chunk and chunk.stop then break end; if chunk then return total,chunk.label,nil,... else return total,\"none\",nil,... end;";
                let core = "flow_core";
                let route = "flow_route";
                let gate = "flow_gate";
                let index = "flow_index";
                let flow_seed = (u64::from(invert) << 1) | u64::from(form == LoopForm::Repeat);
                let wrapped = wrap_dispatcher(
                    setup, loop_body, true, form, "chunk", core, route, gate, index, invert,
                    flow_seed,
                );
                assert!(wrapped.matches("local function").count() >= 5);
                for keyword in [
                    "while", "repeat", "for ", "break", "elseif", "not", "and", "or", "return",
                ] {
                    assert!(wrapped.contains(keyword), "missing Lua keyword: {keyword}");
                }
                let source = format!(
                    "local function original(chunk, ...) local flow_bias=0; while true do {body} end end; \
                     local function transformed(chunk, ...) {wrapped} end; \
                     local a,b,c,d,e,f=original({{stop=false,label='ok'}},'x',nil,'z'); \
                     local x,y,z,u,v,w=transformed({{stop=false,label='ok'}},'x',nil,'z'); \
                     assert(a==x and b==y and c==z and d==u and e==v and f==w); \
                     local g,h,j=original({{stop=true,label='early'}}); \
                     local m,n,o=transformed({{stop=true,label='early'}}); \
                     assert(g==m and h==n and j==o); \
                     local p,q,r=original(nil); local s,t,u=transformed(nil); \
                     assert(p==s and q==t and r==u); io.write('FLOW_OK')",
                    body = loop_body,
                    wrapped = wrapped,
                );
                let compressed = Compressor::compress(&source)
                    .expect("compressor should accept split dispatcher syntax");
                assert_eq!(
                    run_lua(&lua, &source, "source.lua"),
                    "FLOW_OK",
                    "untransformed source should preserve the reference behavior"
                );
                assert_eq!(
                    run_lua(&lua, &compressed, "compressed.lua"),
                    "FLOW_OK",
                    "compressed split dispatcher must preserve all return values and breaks"
                );
            }
        }
    }
}
