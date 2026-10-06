//! 源码封存（`--seal` / `--open`，2026-10-06 新增）
//!
//! 定位：**在混淆之前**把源码以密文形式存放/传输，读取时在内存里解封再进流水线。
//! 只影响「源码文件怎么躺着」，不改产物格式、不改五步流水线。
//!
//! 为什么不是「把源码加密后喂给编译器」：第 ① 步要把源码编译成字节码，编译器必须
//! 看到明文；所以加密只能做在存放态，进流水线时内存内解密。产物侧本来就没有源码
//! 明文（字符串走 ChaCha、标识符被 VM 重写、数字进加密常量池；实测源码标记在产物与
//! 全部中间产物里 0 命中）。
//!
//! 容器格式（二进制，头部 49 B + 标签 16 B + 密文）：
//! ```text
//!   偏移  长度  内容
//!   0     8     魔数（由掩码常量现场还原，二进制里不落明文标记）
//!   8     1     版本 = 1
//!   9     4     口令派生迭代次数（u32 LE）
//!   13    16    盐（随机）
//!   29    12    一次性数（随机）
//!   41    8     明文长度（u64 LE）
//!   49    16    标签 = HMAC-SHA256(mac_key, 头部‖密文) 前 16 字节
//!   65    n     密文 = ChaCha20(enc_key, nonce, 明文)
//! ```
//! 密钥派生：`h = SHA256(pass‖salt)`，随后迭代 `iters` 次
//! `h = SHA256(h‖pass‖salt‖i)`；`enc_key = h`，`mac_key = SHA256(enc_key‖标签域分隔串)`。
//! 口令错/文件损坏都会在标签校验处失败，绝不进入编译。

pub mod primitives;

use rand::{Rng, RngCore};

use primitives::{chacha20, hmac_sha256, sha256};

/// 默认口令派生迭代次数（发布用）；测试用小值以便快速跑。
pub const DEFAULT_ITERS: u32 = 300_000;

const VERSION: u8 = 1;
const HEADER_LEN: usize = 49;
const TAG_LEN: usize = 16;

/// 容器魔数：由掩码常量现场还原，不在源码/二进制里留下可识别的明文标记。
const MAGIC_SALT: [u8; 8] = [0x2B, 0x77, 0x91, 0xC4, 0x5E, 0x38, 0xA0, 0x6D];
const MAGIC_MASK: [u8; 8] = [0x64, 0x13, 0xE2, 0xB1, 0x0A, 0x59, 0xD7, 0x2E];

fn magic() -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = MAGIC_SALT[i] ^ MAGIC_MASK[i];
    }
    out
}

/// 该字节串是否是我们封存的容器
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_LEN + TAG_LEN && bytes[..8] == magic() && bytes[8] == VERSION
}

/// 派生密钥
fn derive_key(pass: &str, salt: &[u8; 16], iters: u32) -> [u8; 32] {
    let pb = pass.as_bytes();
    let mut buf = Vec::with_capacity(pb.len() * 2 + 16 + 1);
    buf.extend_from_slice(pb);
    buf.extend_from_slice(salt);
    let mut h = sha256(&buf);
    for i in 0..iters {
        buf.clear();
        buf.extend_from_slice(&h);
        buf.extend_from_slice(pb);
        buf.extend_from_slice(salt);
        buf.push((i & 0xFF) as u8);
        h = sha256(&buf);
    }
    h
}

fn mac_key(enc_key: &[u8; 32]) -> [u8; 32] {
    let mut label = Vec::with_capacity(32 + 12);
    label.extend_from_slice(enc_key);
    label.extend_from_slice(&[0x53, 0x45, 0x41, 0x4C, 0x2F, 0x4D, 0x41, 0x43, 0x2D, 0x31, 0x00, 0x1F]);
    sha256(&label)
}

/// 封存明文源码，返回容器字节
pub fn seal_with_iters(plain: &[u8], pass: &str, iters: u32) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let enc_key = derive_key(pass, &salt, iters);
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&magic());
    header.push(VERSION);
    header.extend_from_slice(&iters.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&(plain.len() as u64).to_le_bytes());
    debug_assert_eq!(header.len(), HEADER_LEN);

    let cipher = chacha20(&enc_key, &nonce, plain);

    let mut mac_input = Vec::with_capacity(HEADER_LEN + cipher.len());
    mac_input.extend_from_slice(&header);
    mac_input.extend_from_slice(&cipher);
    let tag = hmac_sha256(&mac_key(&enc_key), &mac_input);

    let mut out = header;
    out.extend_from_slice(&tag[..TAG_LEN]);
    out.extend_from_slice(&cipher);
    out
}

/// 封存（默认迭代次数）
pub fn seal(plain: &[u8], pass: &str) -> Vec<u8> {
    seal_with_iters(plain, pass, DEFAULT_ITERS)
}

/// 解封；口令错、格式不符、内容被改动都返回 Err（不会产出半截明文）
pub fn open_with_limit(sealed: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    if sealed.len() < HEADER_LEN + TAG_LEN {
        return Err("封存文件不完整（长度不足）".into());
    }
    if sealed[..8] != magic() {
        return Err("不是本工具的封存文件（魔数不符）".into());
    }
    if sealed[8] != VERSION {
        return Err(format!("封存文件版本不支持：{}", sealed[8]));
    }
    let iters = u32::from_le_bytes([sealed[9], sealed[10], sealed[11], sealed[12]]);
    if iters == 0 || iters > 50_000_000 {
        return Err("封存文件头部异常（迭代次数越界）".into());
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&sealed[13..29]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[29..41]);
    let len = u64::from_le_bytes([
        sealed[41], sealed[42], sealed[43], sealed[44], sealed[45], sealed[46], sealed[47], sealed[48],
    ]) as usize;
    let cipher = &sealed[HEADER_LEN + TAG_LEN..];
    if cipher.len() != len {
        return Err("封存文件长度与头部不符（可能被截断）".into());
    }
    let stored_tag = &sealed[HEADER_LEN..HEADER_LEN + TAG_LEN];

    let enc_key = derive_key(pass, &salt, iters);
    let mac_input = &sealed[..HEADER_LEN + TAG_LEN + cipher.len() - cipher.len()];
    let _ = mac_input; // 头部与密文拼接：直接用切片拼接更直观
    let mut joined = Vec::with_capacity(HEADER_LEN + cipher.len());
    joined.extend_from_slice(&sealed[..HEADER_LEN]);
    joined.extend_from_slice(cipher);
    let tag = hmac_sha256(&mac_key(&enc_key), &joined);

    // 定长比较
    let mut diff = 0u8;
    for i in 0..TAG_LEN {
        diff |= stored_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err("口令不正确或文件已损坏".into());
    }

    let mut plain = chacha20(&enc_key, &nonce, cipher);
    plain.truncate(len);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITERS: u32 = 64;

    #[test]
    fn roundtrip_ok() {
        let src = b"-- \xe4\xb8\xad\xe6\x96\x87\xe6\xb3\xa8\xe9\x87\x8a\nprint \"hello\"\nlocal t={a=1}\n";
        let sealed = seal_with_iters(src, "s3cret-pass", ITERS);
        assert!(is_sealed(&sealed), "应当识别为封存文件");
        let back = open_with_limit(&sealed, "s3cret-pass").expect("解封应成功");
        assert_eq!(back, src);
    }

    #[test]
    fn sealed_bytes_contain_no_plaintext() {
        let marker = "PLAINTEXT_MARKER_ZZ9";
        let src = format!("local s = \"{}\" print(s)", marker);
        let sealed = seal_with_iters(src.as_bytes(), "pw", ITERS);
        let hay = String::from_utf8_lossy(&sealed);
        assert!(!hay.contains(marker), "封存结果不得包含明文标记");
        assert!(!hay.contains("local"), "封存结果不得包含源码片段");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let sealed = seal_with_iters(b"print(1)", "right", ITERS);
        let err = open_with_limit(&sealed, "wrong").unwrap_err();
        assert!(err.contains("口令"), "错误信息应提示口令: {err}");
    }

    #[test]
    fn tampering_fails() {
        let mut sealed = seal_with_iters(b"print(1)", "pw", ITERS);
        let n = sealed.len();
        sealed[n - 1] ^= 0x01;
        assert!(open_with_limit(&sealed, "pw").is_err(), "改动密文必须被标签拦住");

        let mut sealed2 = seal_with_iters(b"print(1)", "pw", ITERS);
        sealed2[20] ^= 0x40; // 改盐
        assert!(open_with_limit(&sealed2, "pw").is_err(), "改动头部必须被标签拦住");
    }

    #[test]
    fn truncated_and_foreign_inputs_fail() {
        let sealed = seal_with_iters(b"print(1)", "pw", ITERS);
        assert!(open_with_limit(&sealed[..40], "pw").is_err());
        assert!(open_with_limit(b"print(1)", "pw").is_err());
        assert!(!is_sealed(b"print(1)"), "普通源码不应被识别为封存文件");
    }

    #[test]
    fn fresh_salt_and_nonce_each_time() {
        let a = seal_with_iters(b"print(1)", "pw", ITERS);
        let b = seal_with_iters(b"print(1)", "pw", ITERS);
        assert_ne!(a, b, "同一输入两次封存必须不同（随机盐/一次性数）");
    }

    #[test]
    fn empty_input_roundtrip() {
        let sealed = seal_with_iters(b"", "pw", ITERS);
        assert_eq!(open_with_limit(&sealed, "pw").unwrap(), Vec::<u8>::new());
    }
}
