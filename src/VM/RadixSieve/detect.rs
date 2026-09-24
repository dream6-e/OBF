#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LuaVersion {
    Lua,
    Luau,
}

pub fn detect_version(code: &str) -> LuaVersion {
    if code.contains("--!strict") || code.contains("::") || code.contains("type ") {
        LuaVersion::Luau
    } else {
        LuaVersion::Lua
    }
}