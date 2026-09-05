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
