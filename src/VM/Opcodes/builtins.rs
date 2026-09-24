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

/// 融合指令（SuperOperator）的操作码区间，紧跟在 builtin-load 之后。
///
/// 第 `slot` 个内建全局对应的融合指令把这三条：
///
/// ```text
///   GetGlobal/GetGlobalStr  A, Bx=name   （已被特化成 builtin-load）
///   LoadK                   A+1, Bx=arg
///   Call                    A, B=2, C=1  （1 个实参、0 个返回值）
/// ```
///
/// 压成一条：handler 自己完成「取内建全局 → 压常量实参 → 调用并丢弃返回值」，
/// 然后 `pc += 2` 跳过两个死槽。**死槽仍然占位**，所以所有跳转偏移都不用重算。
///
/// 前提（由 `rewrite_chunk` 保证）：两个死槽不是任何跳转的目标，
/// 且前一条指令不会把控制转移到死槽上。
pub const FUSED_OP_BASE: usize = TOTAL_OPCODES;
pub const FUSED_OP_COUNT: usize = BUILTIN_NAMES.len();

/// 生成融合指令的 handler。语义与上面三条逐条等价（对照
/// `environment.rs` 的 builtin-load、`load_store.rs` 的 LoadK、
/// `control_flow.rs` 的 Call 在 B=2、C=1 时的展开结果）。
/// `used` 是本程序里**真正发生过融合**的 slot 集合。
///
/// 只给用到的 slot 生成 handler：50 个 slot 各带 3~6 个别名，全量生成会给分发树
/// 白加约 200 个条目，而分发是带不透明谓词的二叉搜索 —— 每条指令都要付这个代价。
/// 实测 `primes.lua` / `strings.lua` 一组都没融合，却因为这个慢了 7% 左右。
pub fn generate_fused(
    m: &[Vec<u32>; FUSED_OP_COUNT],
    cfg: &OpcodeConfig,
    rng: &mut OpcodesRng,
    perm: &[usize],
    used: &std::collections::HashSet<usize>,
) -> String {
    let mut out = String::new();
    for (i, _name) in BUILTIN_NAMES.iter().enumerate() {
        let slot = perm[i];
        if !used.contains(&slot) {
            continue;
        }
        let mapped = m[slot].clone();
        if mapped.is_empty() {
            continue;
        }
        let mut h = OpcodeBuilder::new(mapped, cfg, rng);
        let a = h.raw_inst(2);
        let c = h.raw_inst(4);
        out.push_str(&h.build(&format!(
            "{{STK}}[{a}] = {{BUILTINREG}}[{s1}]; {{STK}}[{a}+1] = {{CONSTS}}[{c}+1];              for __fj={a}+2, {{TOP}} do {{STK}}[__fj]=nil end;              zm({{STK}}[{a}]({{STK}}[{a}+1])); {{STK}}[{a}]=nil; {{PC}} = {{PC}} + 2",
            a = a,
            c = c,
            s1 = slot + 1
        )));
    }
    out
}
