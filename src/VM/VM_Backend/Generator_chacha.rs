//! ChaCha8 流加密内核 + 状态布局（第 2 项：注入次序 / counter 乱序 / 轮数）。
//!
//! 从 Generator_util.rs 拆出（守单文件 80 KB 上限），内核行为与拆分前一致。
//! `ChaChaLayout` 承载「形态随机化」参数，读写两侧同参——它只改变状态字的摆放
//! 位置、counter 的步进序列与轮数，不改变可解性：
//!
//! - **注入次序**：全状态置换 ρ——16 个状态字各自落到随机物理位置。Lua 侧按 ρ
//!   摆表、按 ρ 取 QR 元组、按 ρ⁻¹ 取输出字；Rust 侧同样先摆再算。数学上与标准
//!   ChaCha 逐位相同（只是换了标签），但产物里「4 个 sigma + 8 个密钥字 +
//!   counter + 3 个 nonce」这种一眼可辨的排列、以及 {1,6,11,16} 这类
//!   对角线元组常量都不再出现。
//! - **counter 乱序**：counter 走 `ctr_{k+1}=(ctr_k+step)%2^32`，步长取奇数 ⇒
//!   在 2^32 上单射，任意块数下 counter 都不重复（唯一性由构造保证，不是
//!   「随便洗牌」）。
//! - **轮数**：从 {8,10,12} 逐簇取（同一簇读写一致），产物不再固定 ChaCha8。

use super::Generator_util::GenRng;

/// ChaCha 的 4 个 sigma 常量（产物里不出现本值，见 Generator_kdf 的逐簇还原）
pub(super) const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// 轮数池：逐簇取（8 = ChaCha8 / 10 = ChaCha10 / 12 = ChaCha12）
const ROUND_SET: [u32; 3] = [8, 10, 12];

fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

/// 逐簇状态布局：全状态置换 ρ + 轮数 + counter 起始/步进。
#[derive(Clone, Copy)]
pub(super) struct ChaChaLayout {
    /// 逻辑下标 i → 物理位置 rho[i]（0-based）
    pub rho: [usize; 16],
    pub rounds: u32,
    pub ctr0: u32,
    pub step: u32,
}

/// 列组 / 对角组的逻辑元组（0-based；与标准 ChaCha 一致）
pub(super) const QR_TUPLES: [(usize, usize, usize, usize); 8] = [
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),
];

impl ChaChaLayout {
    pub(super) fn new(rng: &mut GenRng) -> Self {
        let mut rho: Vec<usize> = (0..16).collect();
        rng.shuffle(&mut rho);
        let rounds = ROUND_SET[rng.range(0, ROUND_SET.len())];
        // 步长奇数：线性序列在 2^32 上单射，counter 不重复
        let step = rng.next() | 1;
        Self { rho: rho.try_into().unwrap_or([0usize; 16]), rounds, ctr0: rng.next(), step }
    }

    /// 物理位置 p → 逻辑下标
    pub(super) fn inv(&self) -> [usize; 16] {
        let mut m = [0usize; 16];
        for i in 0..16 { m[self.rho[i]] = i; }
        m
    }

}

/// 一个 ChaCha 块（含 feed-forward），按布局摆位/取字。逻辑字 i 参与的标准
/// QR 元组映射为 (ρa, ρb, ρc, ρd)——数学上与标准 ChaCha 逐位等价。
fn block(key: &[u32; 8], nonce: [u32; 3], counter: u32, ly: &ChaChaLayout) -> [u8; 64] {
    let logical: [u32; 16] = [
        SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3],
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2],
    ];
    let mut s = [0u32; 16];
    for i in 0..16 { s[ly.rho[i]] = logical[i]; }
    let orig = s;
    for _ in 0..(ly.rounds / 2) {
        for &(a, b, c, d) in QR_TUPLES.iter() {
            qr(&mut s, ly.rho[a], ly.rho[b], ly.rho[c], ly.rho[d]);
        }
    }
    for i in 0..16 { s[i] = s[i].wrapping_add(orig[i]); }
    let mut out = [0u8; 64];
    for i in 0..16 { out[i * 4..i * 4 + 4].copy_from_slice(&s[ly.rho[i]].to_le_bytes()); }
    out
}

/// 第 3 项 D：**单根派生**的 KDF（Rust 侧基准实现，Lua 侧同式）。
///
/// `key_g[w] = derive_word(K0[w], g, w)`：先与组号绑定的常数异或、两次旋转后
/// 再异或，取高低 16 位各乘一个小常数（乘积 ≤ 2^34，double 精确）归约到 32 位，
/// 最后按字序号再异或。所有中间量 < 2^53，Lua 侧用同一算式（异或走 32 位异或
/// 实现、旋转走算术旋转）逐位复现。
pub(super) fn derive_word(x: u32, g: u32, w: u32) -> u32 {
    let t = x ^ 0x9E37_79B9u32.wrapping_mul(g.wrapping_add(1));
    let t = t.rotate_left(13) ^ t.rotate_left(7);
    let lo = t & 0xFFFF;
    let hi = t >> 16;
    let a = 0x1F3A5u32.wrapping_add(g.wrapping_mul(0x9E37));
    let b = 0x2C1B3u32.wrapping_add(g.wrapping_mul(0x4F17));
    let c = 0x13F7u32.wrapping_mul(g.wrapping_add(1));
    let y = lo.wrapping_mul(a).wrapping_add(hi.wrapping_mul(b)).wrapping_add(c) & 0xFFFF_FFFF;
    y ^ 0x85EB_CA6Bu32.wrapping_mul(w.wrapping_add(1))
}

/// 第 3 项 D：**单根派生的唯一规格**——读写两侧都只准从这里取值，杜绝漂移。
/// 组 g 的 8 个密钥字 = `dw(k0[w-1], g, w)`（w = 1..8）；
/// 盐/两个 kind 取根的前三个字，字序号 9/10/11。
pub(super) const ROOT_SALT_I: usize = 0;
pub(super) const ROOT_SALT_W: u32 = 9;
pub(super) const ROOT_KSTR_I: usize = 1;
pub(super) const ROOT_KSTR_W: u32 = 10;
pub(super) const ROOT_KNUM_I: usize = 2;
pub(super) const ROOT_KNUM_W: u32 = 11;

pub(super) struct GroupKeys {
    pub key: [u32; 8],
    pub salt: u32,
    pub kstr: u32,
    pub knum: u32,
}

/// 组密钥 = KDF(K0, g)：密钥字 w 用根的第 w 个字；盐/两个 kind 用根的第 1/2/3 个字。
pub(super) fn group_keys(k0: &[u32; 8], g: u32) -> GroupKeys {
    let mut key = [0u32; 8];
    for (w, v) in key.iter_mut().enumerate() {
        *v = derive_word(k0[w], g, w as u32 + 1);
    }
    GroupKeys {
        key,
        salt: derive_word(k0[ROOT_SALT_I], g, ROOT_SALT_W),
        kstr: derive_word(k0[ROOT_KSTR_I], g, ROOT_KSTR_W),
        knum: derive_word(k0[ROOT_KNUM_I], g, ROOT_KNUM_W),
    }
}

/// 第 3 项 D：根密钥 K0 ← **原生流**（Native Stream）。另起一条原生流实例、
/// 独立种子，取 32 字节密钥流（加密全零即密钥流本身）折成 8 个 u32。
/// 产物里落盘的只有这份根（且是 token 化掩码形态），四组密钥材料全部由
/// 它在运行期经 KDF 现算——不再有「每组一套密钥材料」可循。
pub(super) fn native_root(nat: &super::Generator_native::LegacyRootNative, seeds: &[u8]) -> [u32; 8] {
    let ks = nat.keystream(seeds, 32);
    let mut k0 = [0u32; 8];
    for w in 0..8 {
        k0[w] = u32::from_le_bytes([ks[w * 4], ks[w * 4 + 1], ks[w * 4 + 2], ks[w * 4 + 3]]);
    }
    k0
}

/// 块反馈（第 3 项 C：链式）——把本块已解明文的前 8 字节按 1/256/2^16/… 权
/// 折进 32 位（权 32 位内循环）。读写两侧同式：Lua 侧同一循环用 `%2^32` 归约。
fn feed(block_plain: &[u8]) -> u32 {
    let mut f = 0u32;
    let mut w = 1u32;
    for &p in block_plain.iter().take(8) {
        f = f.wrapping_add((p as u32).wrapping_mul(w));
        w = w.wrapping_mul(256);
    }
    f
}

/// 与生成 Lua 逐位一致的加解密：`c_i = p_i XOR ks_i`；**counter 链式推进**——
/// 第 j+1 块的 counter = 第 j 块 counter + step + fold(第 j 块已解明文)，所以
/// 「解第 j+1 块」必须先拿到第 j 块的明文（第 3 项 C）。末块不足 64 字节时
/// fold 只吃该块实际持有的明文字节，两侧一致。
pub(super) fn stream_xor(key: &[u32; 8], nonce: [u32; 3], data: &[u8], ly: &ChaChaLayout) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut ctr = ly.ctr0;
    let mut i = 0usize;
    while i < data.len() {
        let blk = block(key, nonce, ctr, ly);
        let start = i;
        for &b in blk.iter() {
            if i >= data.len() { break; }
            out.push(data[i] ^ b);
            i += 1;
        }
        ctr = ctr.wrapping_add(ly.step).wrapping_add(feed(&data[start..i]));
    }
    out
}

/// Lua 侧状态表字面量：输入逻辑序 16 个字（字符串表达式），按**物理位置序**输出
/// `{…}`——产物里读到的是一串乱序的表达式，摆位规则只有 ρ 知道。
pub(super) fn state_literal(ly: &ChaChaLayout, logical: &[String; 16]) -> String {
    let mut slots: Vec<&str> = vec![""; 16];
    for i in 0..16 { slots[ly.rho[i]] = &logical[i]; }
    format!("{{{}}}", slots.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 第 3 项 C：链式自洽——**先解后喂**（写侧喂明文、读侧喂已解明文）。
    /// 这里照 Lua 读侧的解密循环重写一遍：解出的明文字节才是下一块 counter 的
    /// 反馈源，因此 `stream_xor` 本身不是自逆的（自逆的是无反馈的流）。
    fn chained_decrypt(key: &[u32; 8], nonce: [u32; 3], ct: &[u8], ly: &ChaChaLayout) -> Vec<u8> {
        let mut out = Vec::with_capacity(ct.len());
        let mut ctr = ly.ctr0;
        let mut i = 0usize;
        while i < ct.len() {
            let blk = block(key, nonce, ctr, ly);
            let start = i;
            while i < ct.len() && i < start + 64 {
                out.push(ct[i] ^ blk[i - start]);
                i += 1;
            }
            ctr = ctr.wrapping_add(ly.step).wrapping_add(feed(&out[start..i]));
        }
        out
    }

    /// 链式流：加密 → 按读侧规则解密 → 回原文；且第 2 块流必须与「无反馈」流不同
    #[test]
    fn chained_stream_roundtrip_and_feedback() {
        let key = [0x03020100u32, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                   0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c];
        let nonce = [0x11223344, 0x55667788, 0x99aabbcc];
        let ly = ChaChaLayout { rho: std::array::from_fn(|i| i), rounds: 8, ctr0: 0x1234_5678, step: 0x9E37_79B1 };
        let data: Vec<u8> = (0..200u32).map(|i| (i.wrapping_mul(37) % 251) as u8).collect();
        let ct = stream_xor(&key, nonce, &data, &ly);
        assert_eq!(chained_decrypt(&key, nonce, &ct, &ly), data, "链式读侧解回原文");
        // 第 1 块与「无反馈」一致（反馈从第 2 块开始生效）
        let b0 = block(&key, nonce, ly.ctr0, &ly);
        for i in 0..64 { assert_eq!(ct[i], data[i] ^ b0[i]); }
        // 第 2 块必须与「只加 step、不喂反馈」的流不同（反馈确实参与）
        let b1 = block(&key, nonce, ly.ctr0.wrapping_add(ly.step), &ly);
        let mut differ = false;
        for i in 0..64 { if ct[64 + i] != data[64 + i] ^ b1[i] { differ = true; } }
        assert!(differ, "第 2 块流与无反馈流相同 ⇒ 反馈没生效");
    }

    /// 恒等置换 + 8 轮 = 标准 ChaCha8（自校验：布局机制不改变密码学结果）
    #[test]
    fn identity_layout_matches_standard() {
        let key = [0x03020100u32, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                   0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c];
        let nonce = [0x03020100, 0x07060504, 0x0b0a0908];
        let ly = ChaChaLayout { rho: std::array::from_fn(|i| i), rounds: 8, ctr0: 0, step: 1 };
        let rs = stream_xor(&key, nonce, &[0u8; 64], &ly);
        let mut log = [0u32; 16];
        log[..4].copy_from_slice(&SIGMA);
        log[4..12].copy_from_slice(&key);
        log[12] = 0;
        log[13..].copy_from_slice(&nonce);
        let mut s = log;
        let orig = s;
        for _ in 0..4 {
            for &(a, b, c, d) in QR_TUPLES.iter() { qr(&mut s, a, b, c, d); }
        }
        for i in 0..16 { s[i] = s[i].wrapping_add(orig[i]); }
        let expect: Vec<u8> = s.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(rs, expect);
    }
}
