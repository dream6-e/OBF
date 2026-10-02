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
        let s_idx = format!(
            "({}({}, {})+1)",
            cfg.builtin_bxor,
            "inst_B",
            cfg.builtin_mask
        );
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

/// 融合指令分五族：builtin-load + LOADK + CALL 三合一、builtin-load + GETTABLE 二合一，
/// 以及目标二新增的「取字段 + 调用」两族：SELF(A,B,C)+CALL(A,2,1)（零参方法调用）与
/// GETTABLE(A,B,C)+CALL(A,1,1)（零参点调用）。后两族与 builtin 槽位无关，
/// 各占一个额外索引（`FUSED_OP_COUNT - 2` / `FUSED_OP_COUNT - 1`）。
pub const FUSED_OP_BASE: usize = TOTAL_OPCODES;
pub const FUSED_OP_COUNT: usize = BUILTIN_NAMES.len() * 2 + 2;

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
            let s1 = format!("({}({}, {})+1)", cfg.builtin_bxor, h.raw_inst(3), cfg.builtin_mask);
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
            let s1 = format!("({}({}, {})+1)", cfg.builtin_bxor, h.raw_inst(3), cfg.builtin_mask);
            let one = super::ident(h.rng, 1);
            out.push_str(&h.build(&format!(
                "local {bv} = {{BUILTINREG}}[{s1}]; {{STK}}[{a}] = {bv}[{key}]; {{PC}} = {{PC}} + {one}",
                bv=bv,s1=s1,a=a,key=key,one=one
            )));
        }
    }
    // 族三：SELF(A,B,C) + CALL(A,2,1) —— 零参方法调用（取字段 + 调用二合一）。
    // 语义布局与 GETTABLE 一致：逻辑 B=表、逻辑 C=键；写侧按魔数奇偶预交换，
    // DC 惰性解码器按同一奇偶换回（与族一/族二同一机制）。
    let family3 = n_builtins * 2;
    if used.contains(&family3) && !m[family3].is_empty() {
        let mut h = OpcodeBuilder::new(m[family3].clone(), cfg, rng);
        let a = h.raw_inst(2);
        let tab = h.rk(3);
        let key = h.rk(4);
        let fv = h.rng.name();
        let sv = h.rng.name();
        let fj = h.rng.name();
        let one = super::ident(h.rng, 1);
        let two = super::ident(h.rng, 2);
        out.push_str(&h.build(&format!(
            "local {fv} = {tab}[{key}]; local {sv} = {tab}; {{STK}}[{a}] = {fv}; {{STK}}[{a}+{one}] = {sv}; for {fj}={a}+{two}, {{TOP}} do {{STK}}[{fj}]=nil end; zm({fv}({sv})); {{STK}}[{a}]=nil; {{PC}} = {{PC}} + {one}",
            fv=fv, sv=sv, tab=tab, key=key, a=a, fj=fj, one=one, two=two
        )));
    }
    // 族四：GETTABLE(A,B,C) + CALL(A,1,1) —— 零参点调用（取字段 + 调用二合一）。
    let family4 = n_builtins * 2 + 1;
    if used.contains(&family4) && !m[family4].is_empty() {
        let mut h = OpcodeBuilder::new(m[family4].clone(), cfg, rng);
        let a = h.raw_inst(2);
        let tab = h.rk(3);
        let key = h.rk(4);
        let fj = h.rng.name();
        let one = super::ident(h.rng, 1);
        let two = super::ident(h.rng, 2);
        out.push_str(&h.build(&format!(
            "{{STK}}[{a}] = {tab}[{key}]; for {fj}={a}+{two}, {{TOP}} do {{STK}}[{fj}]=nil end; zm({{STK}}[{a}]()); {{STK}}[{a}]=nil; {{PC}} = {{PC}} + {one}",
            a=a, tab=tab, key=key, fj=fj, one=one, two=two
        )));
    }
    out
}
