use super::{OpcodeBuilder, OpcodeConfig, OpcodesRng};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

pub const BUILTIN_NAMES: &[&str] = &[
    "print", "type", "tostring", "tonumber", "pairs", "ipairs", "next", "select",
    "unpack", "pcall", "xpcall", "error", "assert", "setmetatable", "getmetatable",
    "rawget", "rawset", "rawequal", "rawlen", "require", "collectgarbage", "loadstring",
    "newproxy", "game", "workspace", "script", "wait", "spawn", "delay", "tick",
    "typeof", "warn", "task", "math", "string", "table", "coroutine", "os", "debug",
    "bit32", "utf8", "shared", "_G", "Instance", "Enum", "Vector3", "CFrame", "Color3",
    "UDim2", "Vector2",
];

pub const BUILTIN_OP_BASE: usize = 90;
pub const BUILTIN_OP_COUNT: usize = BUILTIN_NAMES.len();
pub const TOTAL_OPCODES: usize = BUILTIN_OP_BASE + BUILTIN_OP_COUNT;

pub fn slot_permutation(seed: u64) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..BUILTIN_NAMES.len()).collect();
    let mut rng = StdRng::seed_from_u64(seed ^ 0x9E3779B97F4A7C15);
    for i in (1..perm.len()).rev() {
        let j = rng.random_range(0..=i);
        perm.swap(i, j);
    }
    perm
}

pub fn generate(m: &[Vec<u32>], cfg: &OpcodeConfig, rng: &mut OpcodesRng, perm: &[usize]) -> String {
    let mut out = String::new();
    for (i, _name) in BUILTIN_NAMES.iter().enumerate() {
        let slot = perm[i];
        let op_index = BUILTIN_OP_BASE + slot;
        let mapped = m.get(op_index).cloned().unwrap_or_default();
        let mut h = OpcodeBuilder::new(mapped, cfg, rng);
        let a = h.raw_inst(2);
        out.push_str(&h.build(&format!("{{STK}}[{}] = {{BUILTINREG}}[{}]", a, slot + 1)));
    }
    out
}
