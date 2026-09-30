//! ⑤ 库级常量 KDF 派生 + 常量混淆公共件（自 Generator_util 拆分，守 80KB 上限）。
//!
//! - `kdf_pow2` / `kdf_m32`：2^bits 不以裸大幂字面量发射——拆成 ≤0X100 的小因子
//!   乘积，因子洗牌、乘法树随机加括号，逐构建形态不同、运行期值不变。
//! - `obf_const`：链公式特征乘子的逐站点算术变形。
//! - `WeldCache`：焊接缓存（3 张缓存表 + 焊接语句发射器）。

use super::Generator_util::{CipherKeys, GenRng};

/// ⑤ 库级魔数 KDF 派生：2^bits 不以裸大幂字面量出现——逐构建把指数拆成
/// ≤8 位的段（因子全部 ≤ 0X100，0X100/0X80 是通用字节常量，不构成指纹），
/// 因子顺序洗牌、乘法树随机加括号，形态逐构建变化，运行期求值不变。
pub(crate) fn kdf_pow2(rng: &mut GenRng, bits: u32) -> String {
    let mut rem = bits;
    let mut fs: Vec<u64> = Vec::new();
    while rem > 0 {
        let take = if rem >= 8 {
            match rng.range(0, 4) { 0 => 7, 1 => 6, 2 => 5, _ => 8 }
        } else { rem };
        fs.push(1u64 << take);
        rem -= take;
    }
    rng.shuffle(&mut fs);
    fn join(rng: &mut GenRng, fs: &[u64]) -> String {
        if fs.len() == 1 { return format!("0X{:X}", fs[0]); }
        let cut = rng.range(1, fs.len());
        format!("({}*{})", join(rng, &fs[..cut]), join(rng, &fs[cut..]))
    }
    join(rng, &fs)
}
/// ⑤ u32 模数 2^32 派生（同上机制）
pub(super) fn kdf_m32(rng: &mut GenRng) -> String { kdf_pow2(rng, 32) }


pub fn obf_const(rng: &mut GenRng, v: u64) -> String {
    let hi = if v > 2 { (v - 1).min(0xFFFF) } else { 1 };
    let a = rng.range(1, hi as usize + 1) as u64;
    let b = rng.range(1, 0x10000) as u64;
    // 链公式的特征乘子永不以裸值出现——它们是解码器家族的指纹常量，
    // 裸值可被直接 grep 对齐；通用模数/小常量保留自然形态。
    // ⑤：2^32/2^31 亦属可 grep 的库级指纹，与链公式乘子同等待遇
    let distinctive = matches!(v, 0x101 | 0x1001 | 0x45D9 | 0x1_0001 | 0x11 | 0x1_0000_0000 | 0x8000_0000);
    let r = rng.range(0, 3);
    match (distinctive, r) {
        (false, 0) => format!("0X{:X}", v),
        (_, 1) => format!("(0X{:X}+0X{:X})", v - a, a),
        _ => format!("(0X{:X}-0X{:X})", v + b, b),
    }
}

/// 焊接缓存：3 张缓存表 + 焊接语句发射器。
pub(super) struct WeldCache { pub tables: Vec<String>, used: std::collections::HashSet<u32>, dpool: Vec<char>, di: usize }
impl WeldCache {
    pub fn new(rng: &mut GenRng) -> Self {
        Self { tables: vec![rng.name(), rng.name(), rng.name()], used: std::collections::HashSet::new(),
               // 焊接目标名单独池：与游标机字母池（emkqjwcgzh）完全不相交，
               // 杜绝同作用域内焊接值被游标遮蔽（cb 混合模数曾因此被除数替换）。
               dpool: "uvnpdftybl".chars().collect(), di: rng.range(0, 10) }
    }
    /// 取下一个焊接目标单字母（循环复用→同字母反复承载不同状态）。
    pub fn dst(&mut self) -> String {
        let c = self.dpool[self.di % self.dpool.len()];
        self.di += 1;
        c.to_string()
    }
    pub fn declare(&self) -> String {
        format!("local {a},{b},{c}={{}},{{}},{{}}; ", a = self.tables[0], b = self.tables[1], c = self.tables[2])
    }
    fn key(&mut self, rng: &mut GenRng) -> u32 {
        loop {
            let k = rng.range(0x0200_0000, 0x7FFF_FFFF) as u32;
            if self.used.insert(k) { return k; }
        }
    }
    /// 焊接语句：`if not T[k] then dst=C+((value)-C); T[k]=dst else dst=(T[k]) end;`
    /// 三种拼写（两臂换序 / 存储拆出）。C 为校验常数；被缓存值必须是真值（数字）。
    /// **dst 由调用方按作用域声明并复用**（局部数压到 1——同一字母在同一作用域
    /// 里反复承载不同状态，命名维度彻底消失；也避开 Lua5.1 单函数 200 局部上限）。
    pub fn weld(&mut self, rng: &mut GenRng, dst: &str, value: &str) -> String {
        let d = dst;
        let k = self.key(rng);
        let kf = rng.format_num(k as i64);
        let t = self.tables[rng.range(0, self.tables.len())].clone();
        let c = rng.range64(0x1000_0000, 0x7FFF_FFFF);
        let cs = rng.format_num(c);
        match rng.range(0, 3) {
            0 => format!("if not {t}[{k}] then {d}={cs}+(({v})-{cs}); {t}[{k}]={d} else {d}=({t}[{k}]) end; ",
                         d = d, t = t, k = kf, cs = cs, v = value),
            1 => format!("if {t}[{k}] then {d}=({t}[{k}]) else {d}={cs}+(({v})-{cs}); {t}[{k}]={d} end; ",
                         d = d, t = t, k = kf, cs = cs, v = value),
            _ => format!("if not {t}[{k}] then {t}[{k}]={cs}+(({v})-{cs}) end; {d}=({t}[{k}]); ",
                         d = d, t = t, k = kf, cs = cs, v = value),
        }
    }
}

// ── ② 密钥 token 化运输 ────────────────────────────────────────────────
//
// 目标：产物里**不存在「一组 8 个密钥字」的数值形态**。每个字拆成
// (X = 真值 ^ 掩码, 掩码) 两个算式分开落盘，真值在运行期由 P 表里的异或
// 实现现算——P[g1][bx] 本身是运行期建起来的（qT8c 字节表 + 闭包），
// 想静态折叠出密钥，必须先复刻那张表、函数调用与 double 取整语义。
//
// 装配循环由**运行期指纹** h 在两条等价形态间选路（for 递增 / while 递减）：
// 两条路径逐位同结果，换宿主只换路径不换密钥；静态读者连「哪些数配成一对」
// 都读不出（槽位顺序洗牌，取用点只出现洗牌后的槽号）。

/// token 化的一组密钥字：`decl` 要在簇作用域内发射，`fetch[i]` 即 key[i] 的
/// 取用表达式（真值在运行期现算后落进一张洗牌过的表）。
pub struct KeyTokens {
    pub decl: String,
    pub fetch: Vec<String>,
    /// 真值表名（供用毕销毁等场合引用）
    pub kw: String,
    /// 装配辅料名（X 表/掩码表/槽位表/异或实现）：装配完成即无用，调用方可销毁
    pub aux: Vec<String>,
    /// 该簇的异或实现名（后续同簇的 token 化值复用同一个，少一个局部名）
    pub op: String,
    /// 运行期指纹变量名（同簇其它等价选路复用）
    pub h: String,
}

/// 把一组 u32（密钥字 / 盐 / kind）拆成 token：返回 (声明片段, 取用表达式)。
/// `op` 为 P 表里的异或实现名。
pub fn token_value(rng: &mut GenRng, keys: &CipherKeys, v: u32, op: &str, h: &str) -> (String, String) {
    let t = rng.name();
    let m = rng.next();
    let x = rng.obfuscate_num((v ^ m) as i64, 1, keys);
    let me = rng.obfuscate_num(m as i64, 1, keys);
    // 掩码半边上叠 +h-h（自抵消）：中间值逐宿主不同，结果不变
    let decl = format!("local {t}={op}({x},{me}+({h}-{h})); ", t = t, op = op, x = x, me = me, h = h);
    (decl, t)
}

/// token 化到**指定名字**上（声明 `local <name>=…`）：给「用毕要统一销毁」的
/// 场合（boot 域）用，名字由调用方指定，销毁语句才能指到同一个变量。
pub fn token_value_as(rng: &mut GenRng, keys: &CipherKeys, v: u32, op: &str, h: &str, name: &str) -> String {
    let m = rng.next();
    let x = rng.obfuscate_num((v ^ m) as i64, 1, keys);
    let me = rng.obfuscate_num(m as i64, 1, keys);
    format!("local {n}={op}({x},{me}+({h}-{h})); ", n = name, op = op, x = x, me = me, h = h)
}

/// 装配辅料用毕销毁：赋一个「合法表达式里自然缺失的值」，不出现 `=nil` 字面量。
pub fn dispose_stmt(rng: &mut GenRng, names: &[String]) -> String {
    let mut out = String::new();
    for n in names {
        // 赋一个「合法表达式里自然缺失的值」（空表取随机键）——不出现 =nil 字面量
        out.push_str(&format!("{n}=({{}})[{k}]; ", n = n, k = format!("0X{:X}", rng.range(0x1000, 0xFFFFFF))));
    }
    out
}

/// 一组 8 个密钥字的 token 化运输。
pub fn key_tokens(rng: &mut GenRng, keys: &CipherKeys, words: &[u32; 8], h: &str) -> KeyTokens {
    let kw = rng.name();   // 真值表（运行期现算）
    let xt = rng.name();   // X 值表
    let mt = rng.name();   // 掩码表
    let pt = rng.name();   // 槽位置换表
    let op = rng.name();   // 异或实现
    let (i, j) = (rng.name(), rng.name());
    let mut masks: Vec<u32> = Vec::with_capacity(8);
    for _ in 0..8 { masks.push(rng.next()); }
    let xs: Vec<String> = (0..8).map(|k| rng.obfuscate_num((words[k] ^ masks[k]) as i64, 1, keys)).collect();
    let ms: Vec<String> = (0..8).map(|k| rng.obfuscate_num(masks[k] as i64, 1, keys)).collect();
    // 槽位洗牌：真值落位与 key 序号解耦（引用侧同步用洗牌后的槽号）
    let mut slots: Vec<usize> = (1..=8).collect();
    rng.shuffle(&mut slots);
    let slot_lits: Vec<String> = slots.iter().map(|s| rng.obfuscate_num(*s as i64, 1, keys)).collect();
    let decl = format!(
        "local {kw}={{}}; local {xt}={{{xs}}}; local {mt}={{{ms}}}; local {pt}={{{ps}}}; \
         local {op}={p}[{g1}][{bx}]; \
         if ({h}%0X2)==0X0 then for {i}=0X1,0X8 do local {j}={pt}[{i}]; {kw}[{j}]={op}({xt}[{i}],{mt}[{i}]) end \
         else {i}=0X0; while {i}<0X8 do {i}={i}+0X1; local {j}={pt}[{i}]; {kw}[{j}]={op}({xt}[{i}],{mt}[{i}]) end end; ",
        kw = kw, xt = xt, mt = mt, pt = pt, op = op, h = h,
        xs = xs.join(","), ms = ms.join(","), ps = slot_lits.join(","),
        p = keys.tbl_p, g1 = rng.format_num(keys.grp1 as i64), bx = rng.format_num(keys.key_bx as i64),
        i = i, j = j
    );
    let fetch = slot_lits.iter().map(|s| format!("{}[{}]", kw, s)).collect();
    KeyTokens {
        decl, fetch, kw: kw.clone(),
        aux: vec![xt.clone(), mt.clone(), pt.clone(), op.clone()],
        op: op.clone(), h: h.to_string(),
    }
}

/// ⑰ 每簇一个自包含簇：`local a,b,c; do … end;` —— 簇内声明（含 token 表、
/// 游标机局部）随块结束释放，壳函数活动局部数不被撑爆（lua5.1 单函数 200 上限），
/// 簇外的取用点（解密器等）以 upvalue 捕获。
pub fn cluster_scope(outs: &[String], body: &str) -> String {
    format!("local {}; do {} end; ", outs.join(","), body)
}
