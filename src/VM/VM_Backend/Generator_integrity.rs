//! 状态完整性校验的构建期原语（改进 1：消除同源校验）。
//!
//! 旧实现把“期望状态”以可静态读回的形式（明文/可抵消装饰）直接发射进产物，
//! 校验式与被校验对象同源——读一行常量即可通过全部状态检查。现在产物只保留
//! 单向摘要（逐构建随机 S-box + 每块独立 salt），还原状态须做原像搜索。

use super::Generator_util::{CipherKeys, GenRng};

/// 路径状态的单向摘要。Lua 镜像（5.1 double 精确域，字节自低位起）：
///   h = salt % 2^32; 每字节 b: h = (h * 0x10D + sbox[b+1]) % 2^32
/// 乘法混合上界 (2^32-1)*0x10D < 2^41，全程 % 2^32，double 精确。
pub(super) fn state_digest(v: u32, salt: u32, sbox: &[u32; 256]) -> u32 {
    let mut h = salt as u64 % 0x1_0000_0000;
    let mut x = v as u64;
    for _ in 0..4 {
        let b = (x % 256) as usize;
        h = (h.wrapping_mul(0x10D) + sbox[b] as u64) % 0x1_0000_0000;
        x /= 256;
    }
    h as u32
}

/// 发射 S-box 表与摘要函数（每产物一次，头部作用域）。
pub(super) fn emit_state_digest(sbox_var: &str, fn_name: &str, sbox: &[u32; 256]) -> String {
    let entries = sbox
        .iter()
        .map(|v| format!("0X{:X}", v))
        .collect::<Vec<_>>()
        .join(",");
    let mut body = String::from("local h=sl%0X100000000;local x=v%0X100000000;local b;");
    for _ in 0..3 {
        body.push_str(&format!(
            "b=x%0X100;h=(h*0X10D+{s}[b+1])%0X100000000;x=(x-b)/0X100;",
            s = sbox_var
        ));
    }
    body.push_str(&format!("h=(h*0X10D+{s}[x+1])%0X100000000;return h end;", s = sbox_var));
    format!(
        "local {sbox_var}={{{entries}}};local function {fn_name}(v,sl) {body}"
    )
}

/// 冷块入口的状态校验语句：对运行态算摘要并与构建期摘要常量比对。
/// salt 与摘要常量都以运行时查表装饰发射——装饰可抵消，但抵消后得到的是
/// 摘要而非状态本身，单向性不受影响。失配只置共享投毒旗，不早退。
pub(super) fn cold_state_check(
    rng: &mut GenRng,
    keys: &CipherKeys,
    st: u32,
    sbox: &[u32; 256],
    dg_fn: &str,
    psn: &str,
    self_var: &str,
    state_key: &str,
) -> String {
    let salt = rng.range64(0, 0xFFFF_FFFF) as u32;
    let salt_obf = rng.obfuscate_num(salt as i64, 1, keys);
    let expect = state_digest(st, salt, sbox);
    let expect_obf = rng.obfuscate_num(expect as i64, 1, keys);
    format!(
        "{psn}={psn} or ({dg}({self_var}[{state_key}],{salt})~={expect});",
        psn = psn, dg = dg_fn, self_var = self_var, state_key = state_key,
        salt = salt_obf, expect = expect_obf
    )
}

#[cfg(test)]
mod tests {
    use super::super::Generator_util::GenRng;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn state_digest_lua_matches_rust() {
        // 构建期 Rust 摘要必须与发射的 Lua 函数逐位一致（5.1 double 精确域）。
        let mut rng = GenRng::new(0);
        let mut sbox = [0u32; 256];
        for v in sbox.iter_mut() {
            *v = rng.range64(0, 0xFFFF_FFFF) as u32;
        }
        let mut checks = String::new();
        for _ in 0..24 {
            let (v, s) = (rng.range64(0, 0xFFFF_FFFF) as u32, rng.range64(0, 0xFFFF_FFFF) as u32);
            let e = super::state_digest(v, s, &sbox);
            checks.push_str(&format!("assert(D(0X{v:X},0X{s:X})==0X{e:X}) ", v = v, s = s, e = e));
        }
        // 非退化抽样：固定 salt，不同状态值的摘要必须大多不同。
        let d0 = super::state_digest(0, 0x1234_5678, &sbox);
        let differ = (1..64u32).filter(|&i| super::state_digest(i, 0x1234_5678, &sbox) != d0).count();
        assert!(differ >= 60, "digest degenerate: {}/64 differ", differ);
        let script = format!("{} {} print('DIGEST_OK')", super::emit_state_digest("SB", "D", &sbox), checks);
        let lua = Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        let out = Command::new(lua).arg("-e").arg(&script).output().expect("run bundled Lua 5.1");
        assert!(out.status.success(), "digest Lua failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("DIGEST_OK"));
    }
}
