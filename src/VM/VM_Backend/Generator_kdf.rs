//! ⑤ 库级常量 KDF 派生 + 常量混淆公共件（自 Generator_util 拆分，守 80KB 上限）。
//!
//! - `kdf_pow2` / `kdf_m32`：2^bits 不以裸大幂字面量发射——拆成 ≤0X100 的小因子
//!   乘积，因子洗牌、乘法树随机加括号，逐构建形态不同、运行期值不变。
//! - `obf_const`：链公式特征乘子的逐站点算术变形。
//! - `WeldCache`：焊接缓存（3 张缓存表 + 焊接语句发射器）。

use super::Generator_util::GenRng;

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
