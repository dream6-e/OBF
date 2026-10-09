//! Semantics-preserving relay dispatch for VM instruction cases.
//!
//! The frame setup remains in `execute`; opcode cases are independent functions in a
//! protocol table, each returning its next PC to the iterative driver. A second small
//! protocol relay routes entry/exit paths without a central opcode switch.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LoopForm {
    While,
    Repeat,
}

const RELAY_SETUP_OPEN: &str = "\u{1}ARENA_RELAY_SETUP_OPEN\u{2}";
const RELAY_SETUP_CLOSE: &str = "\u{3}ARENA_RELAY_SETUP_CLOSE\u{4}";

/// Build the two-level protocol lookup and independent function for each distinct case.
/// The setup block is hoisted by `wrap_dispatcher` before the iterative driver is emitted.
pub(super) fn build_relay_dispatch(
    entries: &[(u32, String)],
    pc: &str,
    top: &str,
    r1: &str,
    r2: &str,
    r3: &str,
    route_op: &str,
    bias: &str,
    execute_name: &str,
    vm_seed: u64,
) -> String {
    let suffix = format!("{}_relay", execute_name);
    let routes = format!("{}_routes", suffix);
    let cases = format!("{}_cases", suffix);
    let fallback = format!("{}_fallback", suffix);
    let next_pc = format!("{}_pc", suffix);
    let result1 = format!("{}_r1", suffix);
    let result2 = format!("{}_r2", suffix);
    let result3 = format!("{}_r3", suffix);
    let _ = top;

    let mut unique: Vec<(u32, String)> = Vec::new();
    let mut used_codes = Vec::new();
    let mut route_entries = Vec::with_capacity(entries.len());
    for (index, (opcode, body)) in entries.iter().enumerate() {
        let protocol = if let Some((protocol, _)) = unique.iter().find(|(_, old)| old == body) {
            *protocol
        } else {
            let mut code = protocol_code(vm_seed, *opcode, index);
            while used_codes.contains(&code) {
                code = code.wrapping_add(0x9E37_79B9);
            }
            used_codes.push(code);
            unique.push((code, body.clone()));
            code
        };
        route_entries.push((*opcode, protocol));
    }

    let mut setup = format!("local {routes}, {cases} = {{}},{{}};");
    for (protocol, body) in &unique {
        let fallthrough = if ends_with_return_statement(body) {
            String::new()
        } else {
            let separator = if body.trim().is_empty() || body.trim_end().ends_with(';') { "" } else { ";" };
            format!("{separator}return {pc},{r1},{r2},{r3};", pc = pc, r1 = r1, r2 = r2, r3 = r3, separator = separator)
        };
        setup.push_str(&format!(
            "{cases}[0X{protocol:08X}]=function(op,inst_A,inst_B,inst_C) local rk1,rk2;local {r1},{r2},{r3};{body}{fallthrough} end;",
            cases = cases,
            protocol = protocol,
            r1 = r1,
            r2 = r2,
            r3 = r3,
            body = body,
            fallthrough = fallthrough,
        ));
    }
    for (opcode, protocol) in route_entries {
        setup.push_str(&format!(
            "{routes}[0X{opcode:X}]=0X{protocol:08X};",
            routes = routes,
            opcode = opcode,
            protocol = protocol,
        ));
    }
    setup.push_str(&format!(
        "local {fallback}=function() return {pc},nil,nil,nil end;",
        fallback = fallback,
        pc = pc,
    ));

    let dispatch = format!(
        "local {next_pc},{result1},{result2},{result3}={cases}[{routes}[{route_op}-{bias}] or 0X0] or {fallback};{next_pc},{result1},{result2},{result3}={next_pc}(op,inst_A,inst_B,inst_C);if {next_pc}==true then {r1}=true else {pc}={next_pc};{r1},{r2},{r3}={result1},{result2},{result3} end;",
        next_pc = next_pc,
        result1 = result1,
        result2 = result2,
        result3 = result3,
        cases = cases,
        routes = routes,
        route_op = route_op,
        bias = bias,
        fallback = fallback,
        r1 = r1,
        r2 = r2,
        r3 = r3,
        pc = pc,
    );
    format!("{open}{setup}{close}{dispatch}", open = RELAY_SETUP_OPEN, setup = setup, close = RELAY_SETUP_CLOSE, dispatch = dispatch)
}

fn protocol_code(seed: u64, opcode: u32, index: usize) -> u32 {
    let mut value = (seed as u32)
        ^ opcode.rotate_left((index as u32) & 31)
        ^ (index as u32 + 1).wrapping_mul(0x9E37_79B9);
    value ^= value >> 16;
    value = value.wrapping_mul(0x7FEB_352D);
    value ^= value >> 15;
    value = value.wrapping_mul(0x846C_A68B);
    value ^= value >> 16;
    value
}

fn ends_with_return_statement(body: &str) -> bool {
    let trimmed = body.trim().trim_end_matches(';').trim_end();
    let Some(position) = trimmed.rfind("return") else {
        return false;
    };
    !trimmed[position + "return".len()..]
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|word| word == "end")
}

fn extract_relay_setup(body: &str) -> (String, String) {
    let Some(open) = body.find(RELAY_SETUP_OPEN) else {
        return (String::new(), body.to_string());
    };
    let setup_start = open + RELAY_SETUP_OPEN.len();
    let Some(close) = body[setup_start..].find(RELAY_SETUP_CLOSE).map(|n| setup_start + n) else {
        return (String::new(), body.to_string());
    };
    let setup = body[setup_start..close].to_string();
    let rest_start = close + RELAY_SETUP_CLOSE.len();
    let mut rest = String::with_capacity(body.len() - (rest_start - open));
    rest.push_str(&body[..open]);
    rest.push_str(&body[rest_start..]);
    (setup, rest)
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
    let (relay_setup, body) = extract_relay_setup(body);
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
        "{setup}{relay_setup}local function {step}(...) {loop_body} end; return {step}(...);",
        setup = setup,
        relay_setup = relay_setup,
        step = step_name,
        loop_body = loop_body,
    );

    // Each route node is a function returning the next randomized protocol code.
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
        LoopForm::While => ("while not ((true or false)==false) and ", " do end;"),
        LoopForm::Repeat => ("repeat", "until "),
    };
    let route_test = format!("{}~={s6} and {}~={s7}", state_name, state_name, s6 = s6, s7 = s7);
    let route_step = format!("{}=__ROUTES__({},...);", state_name, gate_name);
    let route_loop = match route_form {
        LoopForm::While => format!(
            "{open}{test} do {step} end;",
            open = route_open,
            test = route_test,
            step = route_step,
        ),
        LoopForm::Repeat => format!(
            "{open} {step} {close}({test});",
            open = route_open,
            step = route_step,
            close = route_close,
            test = format!("{}=={s6} or {}=={s7}", state_name, state_name, s6 = s6, s7 = s7),
        ),
    };
    let relay_name = format!("{}_protocols", route_name);

    format!(
        r#"local function {core}(...) {core_body} end;
local function {exit_a}(...) return {core}(...) end;
local function {exit_b}(...) return {core}(...) end;
local {relay}={{}};
{relay}[{s0}]=function({gate},...) if {gate} and not (false or false) then return {s2} end return {s3} end;
{relay}[{s1}]=function({gate},...) if not {gate} or (false and {gate}) then return {s5} end return {s4} end;
{relay}[{s2}]=function({gate},...) local {index}; repeat {index}={s6} until (false and not {gate}) or true; return {index} end;
{relay}[{s3}]=function(...) return {s7} end;
{relay}[{s4}]=function(...) return {s6} end;
{relay}[{s5}]=function({gate},...) local {index},{next_state}; for {index}=0X1,0X1 do if not {gate} or (false and {gate}) then {next_state}={s7} end; if {gate} and (true or false) then {next_state}={s6} end; break end; return {next_state} or {s7} end;
{relay}[{s6}]=function({gate},...) return {exit_a}(...) end;
{relay}[{s7}]=function({gate},...) return {exit_b}(...) end;
local function {route}(...)
  local {gate}=({chunk}~=nil and true) or false;
  local {state}={start} and {s0} or {s1};
  {route_loop}
  return {relay}[{state}]({gate},...)
end;
return {route}(...);"#,
        core = core_name,
        core_body = core_body,
        exit_a = exit_a,
        exit_b = exit_b,
        relay = relay_name,
        route = route_name,
        gate = gate_name,
        chunk = chunk_name,
        state = state_name,
        index = index_name,
        next_state = format!("{}_next", state_name),
        start = start_test,
        s0 = s0,
        s1 = s1,
        s2 = s2,
        s3 = s3,
        s4 = s4,
        s5 = s5,
        s6 = s6,
        s7 = s7,
        route_loop = route_loop.replace("__ROUTES__", &format!("{}[{}]", relay_name, state_name)),
    )
}

#[cfg(test)]
mod tests {
    use super::{LoopForm, build_relay_dispatch, wrap_dispatcher};
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
                    "while", "repeat", "for ", "break", "not", "and", "or", "return",
                ] {
                    assert!(wrapped.contains(keyword), "missing Lua keyword: {keyword}");
                }
                assert!(wrapped.contains("_protocols["));
                assert!(!wrapped.contains("elseif"), "route states must use function relays, not a switch chain");
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

    #[test]
    fn protocol_cases_return_pc_and_preserve_fallthrough() {
        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }
        let first = "value=value+inst_A;pc=pc+inst_A;top=top+1;".to_string();
        let entries = vec![
            (0x101, first.clone()),
            (0x202, "value=value+inst_B;pc=pc+inst_B;top=top+2;".to_string()),
            (0x303, "return true;".to_string()),
            (0x404, first),
            (0x505, "if inst_A>0 then r1=true;r2=value;r3=inst_A end".to_string()),
        ];
        let dispatch = build_relay_dispatch(
            &entries, "pc", "top", "r1", "r2", "r3", "route_op", "bias", "relay_test", 0x1234,
        );
        let body = format!(
            "pc=pc+1;local route_op=op+bias;local rk1,rk2;local r1,r2,r3;{dispatch}return pc,top,value,r1,r2,r3;"
        );
        let setup = "local pc=10;local top=0;local value=0;local bias=7;local op,inst_A,inst_B,inst_C=...;";
        let wrapped = wrap_dispatcher(
            setup, &body, true, LoopForm::While, "chunk", "relay_core", "relay_route",
            "relay_gate", "relay_index", false, 0x5678,
        );
        assert!(!wrapped.contains("if op=="), "opcode dispatch must not be a comparison tree");
        assert!(wrapped.contains("relay_test_relay_cases"));
        let source = format!(
            "local chunk={{}};local function run(...) {wrapped} end; \
             local a,b,c,d=run(0x101,3,0,0);assert(a==14 and b==1 and c==3 and d==nil); \
             local e,f,g,h=run(0x202,0,4,0);assert(e==15 and f==2 and g==4 and h==nil); \
             local i,j,k,l=run(0x303,0,0,0);assert(i==11 and j==0 and k==0 and l==true); \
             local m,n,o,p=run(0x999,0,0,0);assert(m==11 and n==0 and o==0 and p==nil); \
             local q,r,s,t,u,v=run(0x505,9,0,0);assert(q==11 and s==0 and t==true and u==0 and v==9);io.write('RELAY_OK')",
            wrapped = wrapped,
        );
        let compressed = Compressor::compress(&source).expect("compress relay code");
        assert_eq!(run_lua(&lua, &source, "relay_source.lua"), "RELAY_OK");
        assert_eq!(run_lua(&lua, &compressed, "relay_compressed.lua"), "RELAY_OK");
    }
}
