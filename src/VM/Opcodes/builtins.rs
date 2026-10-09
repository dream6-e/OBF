use super::{OpcodeBuilder, OpcodeConfig, OpcodesRng};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use crate::VM::VM_Backend::CustomIsa::VM_OPCODE_COUNT;

pub const BUILTIN_NAMES: &[&str] = &[
    "print", "type", "tostring", "tonumber", "pairs", "ipairs", "next", "select",
    "unpack", "pcall", "xpcall", "error", "assert", "setmetatable", "getmetatable",
    "rawget", "rawset", "rawequal", "rawlen", "require", "collectgarbage", "loadstring",
    "newproxy", "game", "workspace", "script", "wait", "spawn", "delay", "tick",
    "typeof", "warn", "task", "math", "string", "table", "coroutine", "os", "debug",
    "bit32", "utf8", "shared", "_G", "Instance", "Enum", "Vector3", "CFrame", "Color3",
    "UDim2", "Vector2",
];

pub const BUILTIN_OP_BASE: usize = VM_OPCODE_COUNT;
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

/// 融合指令先保留两组 builtin 槽位与四个既有通用族，随后追加性能型超级指令。
pub const FUSED_OP_BASE: usize = TOTAL_OPCODES;
pub const FUSED_SUPER_BASE: usize = BUILTIN_NAMES.len() * 2 + 4;
pub const FUSED_ARITH_BASE: usize = FUSED_SUPER_BASE;
pub const FUSED_ARITH_COUNT: usize = 6;
pub const FUSED_TABLE_GET: usize = FUSED_ARITH_BASE + FUSED_ARITH_COUNT;
pub const FUSED_TABLE_SET: usize = FUSED_TABLE_GET + 1;
pub const FUSED_OP_COUNT: usize = FUSED_TABLE_SET + 1;

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
    // 族五：GETTABLE(A,B,C) + EQ(cond, A, RK) —— 取字段 + 比较（目标二第 2 条）。
    // 线上布局：A=打包值（低 8 位=目标寄存器、次 9 位=比较另一侧的 RK、次 1 位=EQ 的
    // 条件位、高位=gap 即「比较记录相对本记录的条数」，总计 26 位，双精度整数运算精确）；
    // B=表寄存器；C=键 RK。语义与原两条逐位等价：写回 STK[A]、按
    // (v==other)~=(cond~=0) 决定落在原 EQ 之后那条 JMP 上（照常执行它）还是越过它。
    let family5 = n_builtins * 2 + 2;
    if used.contains(&family5) && !m[family5].is_empty() {
        let mut h = OpcodeBuilder::new(m[family5].clone(), cfg, rng);
        let tab = h.reg(3);
        let key = h.rk(4);
        let pa = h.raw_inst(2);
        let a_names: Vec<String> = (0..6).map(|_| h.rng.name()).collect();
        let (v, dr, rkv, cd, gp, ot) = (a_names[0].clone(), a_names[1].clone(), a_names[2].clone(), a_names[3].clone(), a_names[4].clone(), a_names[5].clone());
        let (r1, r2) = (h.rng.name(), h.rng.name());
        let (c256, c512, c127) = (super::ident(h.rng, 0x100), super::ident(h.rng, 0x200), super::ident(h.rng, 0x7F));
        let (c2, c17, c18) = (super::ident(h.rng, 2), super::ident(h.rng, 0x20000), super::ident(h.rng, 0x40000));
        let one = super::ident(h.rng, 1);
        out.push_str(&h.build(&format!(
            "local {v}={tab}[{key}]; local {dr}={pai}%{c256}; local {r1}={pai}-{dr}; \
             local {rkv}=({r1}/{c256})%{c512}; local {r2}={r1}-{rkv}*{c256}; \
             local {cd}=({r2}/{c17})%{c2}; local {gp}=({r2}-{cd}*{c17})/{c18}; \
             local {ot}; if {rkv}>{c127} then {ot}={{CONSTS}}[{rkv}-{c127}] else {ot}={{STK}}[{rkv}] end; \
             {{STK}}[{dr}]={v}; \
             if (({v}=={ot})~=({cd}~=0X0)) then {{PC}}={{PC}}+{gp}+{one} else {{PC}}={{PC}}+{gp} end",
            v = v, tab = tab, key = key, dr = dr, r1 = r1, rkv = rkv, r2 = r2, cd = cd, gp = gp, ot = ot,
            pai = pa, c256 = c256, c512 = c512, c127 = c127, c2 = c2, c17 = c17, c18 = c18, one = one)));
    }
    // 族六：计算式跳转（目标三第 2 条 + 第 3 条）——JMP 的落点不再以明文偏移落盘。
    // 线上：A=真实后继的**密文**、B=诱饵后继的密文、C=逐站点盐；
    // handler 用运行期值（PC 与本原型 pf_ld，见 execute 入口写槽）现算两支密钥，
    // 解出两个绝对落点，再用一个「只有运行期才知道」的恒真条件选真实后继：
    //   真分支的判据 bx(k,k)==0 只在 k 的**运行期取值**下成立，静态读者要读出
    //   下一条是谁，必须先复刻密钥推导与整条指令解码（等于模拟）。
    // 诱饵后继指向本原型尾部的死指令段（只有运行期才知道那条边永不走），
    // 使那段垃圾在静态 CFG 上获得一条真实入边（目标三第 3 条）。
    let family6 = n_builtins * 2 + 3;
    if used.contains(&family6) && !m[family6].is_empty() {
        let mut h = OpcodeBuilder::new(m[family6].clone(), cfg, rng);
        let e1 = h.raw_inst(2);
        let e2 = h.raw_inst(3);
        let sa = h.raw_inst(4);
        let k1 = h.rng.name();
        let ld = cfg.ld_key.clone();
        let bx = cfg.builtin_bxor.clone();
        out.push_str(&h.build(&format!(
            // 键 = (运行期 PC ^ 本原型 pf_ld) ^ 记录盐：两个候选目标共用同一把键
            // （不取模——纯异或，热路径零额外算术开销；两候选仍同样不可静态分辨）。
            "local {k1}={bx}({bx}({{PC}},{ld}),{sa}); \
             if {bx}({k1},{k1})==0X0 then {{PC}}={bx}({e1},{k1}) else {{PC}}={bx}({e2},{k1}) end",
            k1 = k1, e1 = e1, e2 = e2, sa = sa, ld = ld, bx = bx)));
    }

    // 性能型超级指令：custom ISA 的 PushRk, PushRk, arithmetic, PopReg
    // 序列合为一次 STK 写入，GetTable/SetTable 的 Push* + Index + Pop 序列同理。
    // rewrite 阶段仍保留被吞记录为死槽并原样推进 PC，控制流和记录偏移不变。
    const ARITHMETIC: [&str; FUSED_ARITH_COUNT] = ["+", "-", "*", "/", "%", "^"];
    for (offset, operator) in ARITHMETIC.iter().enumerate() {
        let family = FUSED_ARITH_BASE + offset;
        if !used.contains(&family) || m[family].is_empty() {
            continue;
        }
        let mut h = OpcodeBuilder::new(m[family].clone(), cfg, rng);
        let a = h.raw_inst(2);
        let left = h.rk(3);
        let right = h.rk(4);
        let skip = super::ident(h.rng, 3);
        out.push_str(&h.build(&format!(
            "{{STK}}[{a}] = {left} {operator} {right}; {{PC}} = {{PC}} + {skip}",
            a = a, left = left, operator = operator, right = right, skip = skip
        )));
    }

    if used.contains(&FUSED_TABLE_GET) && !m[FUSED_TABLE_GET].is_empty() {
        let mut h = OpcodeBuilder::new(m[FUSED_TABLE_GET].clone(), cfg, rng);
        let a = h.raw_inst(2);
        let table_reg = h.raw_inst(3);
        let table = h.rng.name();
        // 与原序列相同，先读取表寄存器，再解析 RK 键。
        h.pre_statements.push_str(&format!("local {table}={{STK}}[{table_reg}]; "));
        let key = h.rk(4);
        let skip = super::ident(h.rng, 3);
        out.push_str(&h.build(&format!(
            "{{STK}}[{a}] = {table}[{key}]; {{PC}} = {{PC}} + {skip}",
            a = a, table = table, key = key, skip = skip
        )));
    }

    if used.contains(&FUSED_TABLE_SET) && !m[FUSED_TABLE_SET].is_empty() {
        let mut h = OpcodeBuilder::new(m[FUSED_TABLE_SET].clone(), cfg, rng);
        let table_reg = h.raw_inst(2);
        let table = h.rng.name();
        // 保持原 SetTable 的求值次序：表、键、值，然后执行赋值。
        h.pre_statements.push_str(&format!("local {table}={{STK}}[{table_reg}]; "));
        let key = h.rk(3);
        let value = h.rk(4);
        let skip = super::ident(h.rng, 3);
        out.push_str(&h.build(&format!(
            "{table}[{key}] = {value}; {{PC}} = {{PC}} + {skip}",
            table = table, key = key, value = value, skip = skip
        )));
    }
    out
}
