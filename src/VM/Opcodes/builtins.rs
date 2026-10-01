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
        let s_idx = super::ident(rng, (slot + 1) as u32);
        let variant = rng.next_range(0, 2) == 0;
        let tv = if variant { Some(rng.name()) } else { None };
        let mut h = OpcodeBuilder::new(mapped, cfg, rng);
        let a = h.raw_inst(2);
        let body = if let Some(tv) = tv {
            format!("local {tv} = {{BUILTINREG}}[{s_idx}]; {{STK}}[{a}] = {tv}")
        } else {
            format!("{{STK}}[{a}] = {{BUILTINREG}}[{s_idx}]")
        };
        out.push_str(&h.build(&body));
    }
    out
}

/// 融合指令分两族：builtin-load + LOADK + CALL 三合一，以及 builtin-load + GETTABLE 二合一。
pub const FUSED_OP_BASE: usize = TOTAL_OPCODES;
pub const FUSED_OP_COUNT: usize = BUILTIN_NAMES.len() * 2;

/// 仅为本产物中实际触发融合的槽位生成 handler，避免扩张 BST 分发树。
pub fn generate_fused(
    m: &[Vec<u32>; FUSED_OP_COUNT],
    cfg: &OpcodeConfig,
    rng: &mut OpcodesRng,
    perm: &[usize],
    used: &std::collections::HashSet<usize>,
) -> String {
    let mut out = String::new();
    let n_builtins = BUILTIN_NAMES.len();
    for (i, _name) in BUILTIN_NAMES.iter().enumerate() {
        let slot = perm[i];
        if used.contains(&slot) && !m[slot].is_empty() {
            let mut h = OpcodeBuilder::new(m[slot].clone(), cfg, rng);
            let a = h.raw_inst(2);
            let c = h.raw_inst(4);
            let fj = h.rng.name();
            let s1 = super::ident(h.rng, (slot + 1) as u32);
            let one = super::ident(h.rng, 1);
            let two = super::ident(h.rng, 2);
            out.push_str(&h.build(&format!(
                "{{STK}}[{a}] = {{BUILTINREG}}[{s1}]; {{STK}}[{a}+{one}] = {{CONSTS}}[{c}+1]; for {fj}={a}+2, {{TOP}} do {{STK}}[{fj}]=nil end; zm({{STK}}[{a}]({{STK}}[{a}+1])); {{STK}}[{a}]=nil; {{PC}} = {{PC}} + {two}",
                a=a,c=c,s1=s1,fj=fj,one=one,two=two
            )));
        }
        let family2 = n_builtins + slot;
        if used.contains(&family2) && !m[family2].is_empty() {
            let mut h = OpcodeBuilder::new(m[family2].clone(), cfg, rng);
            let a = h.raw_inst(2);
            let key = h.rk(4);
            let bv = h.rng.name();
            let s1 = super::ident(h.rng, (slot + 1) as u32);
            let one = super::ident(h.rng, 1);
            out.push_str(&h.build(&format!(
                "local {bv} = {{BUILTINREG}}[{s1}]; {{STK}}[{a}] = {bv}[{key}]; {{PC}} = {{PC}} + {one}",
                bv=bv,s1=s1,a=a,key=key,one=one
            )));
        }
    }
    out
}
