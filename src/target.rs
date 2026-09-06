use std::fmt;
use std::str::FromStr;

/// Source/bytecode dialect selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Lua51,
    Luau,
}

impl Target {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lua51 => "lua51",
            Self::Luau => "luau",
        }
    }

    pub const fn is_luau(self) -> bool {
        matches!(self, Self::Luau)
    }

    /// Conservative name-allocation policy, not the lexer keyword grammar.
    /// Contextual words remain legal identifiers when parsing input. Standard
    /// and Roblox host names are never introduced or renamed by this pass.
    pub(crate) fn is_reserved_name(self, name: &str) -> bool {
        const COMMON: &[&str] = &[
            "self",
            "arg",
            "_G",
            "_ENV",
            "_VERSION",
            "assert",
            "error",
            "print",
            "warn",
            "pcall",
            "xpcall",
            "pairs",
            "ipairs",
            "next",
            "select",
            "type",
            "tonumber",
            "tostring",
            "unpack",
            "rawequal",
            "rawget",
            "rawset",
            "getmetatable",
            "setmetatable",
            "getfenv",
            "setfenv",
            "getgenv",
            "getrenv",
            "getgc",
            "getreg",
            "getregistry",
            "load",
            "loadstring",
            "loadfile",
            "dofile",
            "require",
            "debug",
            "collectgarbage",
            "gcinfo",
            "coroutine",
            "math",
            "string",
            "table",
            "os",
        ];
        const LUA51: &[&str] = &["io", "package", "module", "newproxy"];
        const LUAU: &[&str] = &[
            "type",
            "export",
            "const",
            "continue",
            "typeof",
            "read",
            "write",
            "bit32",
            "utf8",
            "buffer",
            "vector",
            "rawlen",
            "newproxy",
            "settings",
            "UserSettings",
            "game",
            "Game",
            "workspace",
            "Workspace",
            "script",
            "shared",
            "plugin",
            "Enum",
            "Instance",
            "task",
            "wait",
            "spawn",
            "delay",
            "tick",
            "time",
            "elapsedTime",
            "DateTime",
            "Vector2",
            "Vector3",
            "Vector2int16",
            "Vector3int16",
            "CFrame",
            "Color3",
            "BrickColor",
            "UDim",
            "UDim2",
            "Ray",
            "Rect",
            "Region3",
            "Region3int16",
            "NumberRange",
            "NumberSequence",
            "NumberSequenceKeypoint",
            "ColorSequence",
            "ColorSequenceKeypoint",
            "TweenInfo",
            "Axes",
            "Faces",
            "PhysicalProperties",
            "Random",
            "RaycastParams",
            "OverlapParams",
            "DockWidgetPluginGuiInfo",
            "PathWaypoint",
            "Font",
            "Content",
            "SecurityCapabilities",
        ];
        crate::lexer::is_keyword(name, self)
            || COMMON.contains(&name)
            || if self.is_luau() {
                LUAU.contains(&name)
            } else {
                LUA51.contains(&name)
            }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Target {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lua51" | "lua5.1" | "5.1" => Ok(Self::Lua51),
            "luau" | "roblox" => Ok(Self::Luau),
            _ => Err(format!(
                "unknown target '{value}'; expected 'lua51' or 'luau'"
            )),
        }
    }
}
