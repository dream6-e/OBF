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
) -> String {
    let core_body = if !has_handlers {
        // Preserve the previous empty-tree behavior: enter once, break, and return no values.
        "while true do break end".to_string()
    } else {
        let (loop_open, loop_close) = match loop_form {
            LoopForm::While => ("while not ((true or false)==false) do ", " end;"),
            LoopForm::Repeat => ("repeat ", " until (false and not true) or false;"),
        };
        format!("{}{}{}{}", setup, loop_open, body, loop_close)
    };

    let first_test = if invert_route {
        format!("not {}", gate_name)
    } else {
        gate_name.to_string()
    };
    let second_test = if invert_route {
        gate_name.to_string()
    } else {
        format!("not {}", gate_name)
    };

    format!(
        "local function {core}(...) {core_body} end; \
         local function {route}(...) \
           local {gate}=({chunk}~=nil and true) or false; \
           for {index}=0X1,0X1 do \
             if {first} then return {core}(...) \
             elseif {second} then return {core}(...) \
             else break end \
           end; \
           return {core}(...) \
         end; \
         return {route}(...);",
        core = core_name,
        core_body = core_body,
        route = route_name,
        gate = gate_name,
        chunk = chunk_name,
        index = index_name,
        first = first_test,
        second = second_test,
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
                let loop_body = "local total=0; for i=1,4 do total=total+i; if i==2 then break end end; if chunk and chunk.stop then break end; if chunk then return total,chunk.label,nil else return total,\"none\",nil end;";
                let core = "flow_core";
                let route = "flow_route";
                let gate = "flow_gate";
                let index = "flow_index";
                let wrapped = wrap_dispatcher(
                    "", loop_body, true, form, "chunk", core, route, gate, index, invert,
                );
                let source = format!(
                    "local function original(chunk) while true do {body} end end; \
                     local function transformed(chunk, ...) {wrapped} end; \
                     local a,b,c=original({{stop=false,label='ok'}}); \
                     local x,y,z=transformed({{stop=false,label='ok'}}); \
                     assert(a==x and b==y and c==z); \
                     local d,e,f=original({{stop=true,label='early'}}); \
                     local u,v,w=transformed({{stop=true,label='early'}}); \
                     assert(d==u and e==v and f==w); \
                     local g,h,j=original(nil); local p,q,r=transformed(nil); \
                     assert(g==p and h==q and j==r); io.write('FLOW_OK')",
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
