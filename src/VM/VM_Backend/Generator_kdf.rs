//! ⑤ 库级常量 KDF 派生 + 常量混淆公共件（自 Generator_util 拆分，守 80KB 上限）。
//!
//! - `kdf_pow2` / `kdf_m32`：直接发射数值字面量，不再拆成可静态折叠的乘积。
//! - `obf_const`：保留调用接口，直接发射常量字面量。
//! - `WeldCache`：焊接缓存（3 张缓存表 + 焊接语句发射器）。

use super::Generator_util::{CipherKeys, GenRng, Transport};

/// 造 n 条互不相通的常量运输线（改进 4：密钥隔离；改进 5：反抵消）。
/// 每条线独立组号 + 线内扰动（tx/ta 非零，防止退回裸 xor/加法的可抵消形态）；
/// `avoid` 里的值（已有辅助槽位）不再复用为组号。
pub fn build_transports(rng: &mut GenRng, n: usize, avoid: &[u64]) -> Vec<Transport> {
    let mut out: Vec<Transport> = Vec::with_capacity(n);
    for _ in 0..n {
        let grp = loop {
            let g = rng.range(0x10, 0x7F) as u64;
            if !avoid.contains(&g) && !out.iter().any(|t| t.grp == g) { break g; }
        };
        let kk = rng.distinct(2, 0x10, 0x7F);
        // 扰动域与折叠器对齐：tx < 2^27 保证 xor 线参数恒 < 2^31（可被
        // fold_const_keycalls 折掉，热路径零运行时代价）；ta ∈ [2^30, 2^31)
        // 使 add 线参数恒非负（同样可折）。两者均为奇数非零，防退回旧形态。
        out.push(Transport {
            grp,
            kx: kk[0],
            kadd: kk[1],
            tx: (rng.range64(1, 0x0800_0000) | 1) as u32,
            ta: (rng.range64(0x4000_0000, 0x7FFF_FFFF) | 1) as u32,
        });
    }
    out
}

/// P 表里发射全部运输线槽位：xor 线 = 双层异或叠线扰动，add 线 = 和减扰动。
/// 闭包形态按线洗牌（参数换位/操作数换位），没有可整表套用的单一等式。
pub fn emit_transport_slots(rng: &mut GenRng, keys: &CipherKeys, fn_bx: &str) -> String {
    let mut out = String::new();
    for t in &keys.transports {
        let g = format!("0X{:X}", t.grp);
        let (kx, ka) = (format!("0X{:X}", t.kx), format!("0X{:X}", t.kadd));
        let (tx, ta) = (format!("0X{:X}", t.tx), format!("0X{:X}", t.ta));
        let p = &keys.tbl_p;
        let xor_body = match rng.range(0, 3) {
            0 => format!("function(a,b)return {f}({f}(a,b),{tx})end", f = fn_bx, tx = tx),
            1 => format!("function(b,a)return {f}({tx},{f}(a,b))end", f = fn_bx, tx = tx),
            _ => format!("function(a,b)return {f}({tx},{f}(b,a))end", f = fn_bx, tx = tx),
        };
        let add_body = match rng.range(0, 3) {
            0 => format!("function(a,b)return a+b-{ta} end", ta = ta),
            1 => format!("function(b,a)return b+a-{ta} end", ta = ta),
            _ => format!("function(a,b)return a-{ta}+b end", ta = ta),
        };
        out.push_str(&format!("{p}[{g}]={{}};{p}[{g}][{kx}]={xor_body};{p}[{g}][{ka}]={add_body};",
            p = p, g = g, kx = kx, ka = ka, xor_body = xor_body, add_body = add_body));
    }
    out
}

/// 选一条运输线运密钥：返回 (组, 键, 线扰动)。管线里运输线恒非空。
fn pick_xor_transport(rng: &mut GenRng, keys: &CipherKeys) -> (u64, u64, u32) {
    let t = &keys.transports[rng.range(0, keys.transports.len())];
    (t.grp, t.kx, t.tx)
}

/// 直接发射 2^bits 的数值字面量，避免乘法因子表达式。
pub(crate) fn kdf_pow2(_rng: &mut GenRng, bits: u32) -> String {
    let value = 1u64.checked_shl(bits).expect("kdf_pow2 bits must be below 64");
    numeric_literal(value)
}

/// 大于 24 位的数用十进制，避免打包数值处理对长十六进制字面量的限制。
fn numeric_literal(value: u64) -> String {
    if value <= 0xFF_FFFF {
        format!("0X{:X}", value)
    } else {
        value.to_string()
    }
}

/// u32 模数 2^32，直接使用数值字面量。
pub(super) fn kdf_m32(rng: &mut GenRng) -> String { kdf_pow2(rng, 32) }

/// 保留公共调用接口，常量直接输出，不再生成和差恒等式。
pub fn obf_const(_rng: &mut GenRng, v: u64) -> String {
    numeric_literal(v)
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
    /// 缓存未命中时直接写入 value，命中时读取已缓存值。
    /// **dst 由调用方按作用域声明并复用**（局部数压到 1——同一字母在同一作用域
    /// 里反复承载不同状态，命名维度彻底消失；也避开 Lua5.1 单函数 200 局部上限）。
    pub fn weld(&mut self, rng: &mut GenRng, dst: &str, value: &str) -> String {
        let d = dst;
        let k = self.key(rng);
        let kf = rng.format_num(k as i64);
        let t = self.tables[rng.range(0, self.tables.len())].clone();
        match rng.range(0, 3) {
            0 => format!("if not {t}[{k}] then {d}=({v}); {t}[{k}]={d} else {d}=({t}[{k}]) end; ",
                         d = d, t = t, k = kf, v = value),
            1 => format!("if {t}[{k}] then {d}=({t}[{k}]) else {d}=({v}); {t}[{k}]={d} end; ",
                         d = d, t = t, k = kf, v = value),
            _ => format!("if not {t}[{k}] then {t}[{k}]=({v}) end; {d}=({t}[{k}]); ",
                         d = d, t = t, k = kf, v = value),
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
pub fn token_value(rng: &mut GenRng, keys: &CipherKeys, v: u32, op: &str, tx: u32, h: &str) -> (String, String) {
    let t = rng.name();
    let m = rng.next();
    // 运输线异或闭包带线扰动 tx：X 半边补偿 ^tx，(X, 掩码) 不再直接抵消。
    let x = rng.obfuscate_num((v ^ m ^ tx) as i64, 1, keys);
    let me = rng.obfuscate_num(m as i64, 1, keys);
    // 掩码半边上叠 +h-h（自抵消）：中间值逐宿主不同，结果不变
    let decl = format!("local {t}={op}({x},{me}+({h}-{h})); ", t = t, op = op, x = x, me = me, h = h);
    (decl, t)
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

/// 一组 8 个密钥字的 token 化运输。运输线随机挑选：op 是该线的异或闭包
/// （带线扰动 tx），X 半边逐字补偿 ^tx——(X, 掩码) 对不再满足裸异或抵消，
/// 且不同簇可选到不同线，密钥运输不再共用单一选择器。
pub fn key_tokens(rng: &mut GenRng, keys: &CipherKeys, words: &[u32; 8], h: &str) -> KeyTokens {
    let kw = rng.name();   // 真值表（运行期现算）
    let xt = rng.name();   // X 值表
    let mt = rng.name();   // 掩码表
    let pt = rng.name();   // 槽位置换表
    let op = rng.name();   // 异或实现
    let (i, j) = (rng.name(), rng.name());
    let (tg, tk, tx) = pick_xor_transport(rng, keys);
    let mut masks: Vec<u32> = Vec::with_capacity(8);
    for _ in 0..8 { masks.push(rng.next()); }
    let xs: Vec<String> = (0..8).map(|k| rng.obfuscate_num((words[k] ^ masks[k] ^ tx) as i64, 1, keys)).collect();
    let ms: Vec<String> = (0..8).map(|k| rng.obfuscate_num(masks[k] as i64, 1, keys)).collect();
    // 槽位洗牌：真值落位与 key 序号解耦（引用侧同步用洗牌后的槽号）
    let mut slots: Vec<usize> = (1..=8).collect();
    rng.shuffle(&mut slots);
    let slot_lits: Vec<String> = slots.iter().map(|s| rng.obfuscate_num(*s as i64, 1, keys)).collect();
    let decl = format!(
        "local {kw}={{}}; local {xt}={{{xs}}}; local {mt}={{{ms}}}; local {pt}={{{ps}}}; \
         local {op}={p}[{tg}][{tk}]; \
         if ({h}%0X2)==0X0 then for {i}=0X1,0X8 do local {j}={pt}[{i}]; {kw}[{j}]={op}({xt}[{i}],{mt}[{i}]) end \
         else {i}=0X0; while {i}<0X8 do {i}={i}+0X1; local {j}={pt}[{i}]; {kw}[{j}]={op}({xt}[{i}],{mt}[{i}]) end end; ",
        kw = kw, xt = xt, mt = mt, pt = pt, op = op, h = h,
        xs = xs.join(","), ms = ms.join(","), ps = slot_lits.join(","),
        p = keys.tbl_p, tg = rng.format_num(tg as i64), tk = rng.format_num(tk as i64),
        i = i, j = j
    );
    let fetch = slot_lits.iter().map(|s| format!("{}[{}]", kw, s)).collect();
    KeyTokens {
        decl, fetch, kw: kw.clone(),
        aux: vec![xt.clone(), mt.clone(), pt.clone(), op.clone()],
        op: op.clone(), h: h.to_string(),
    }
}

/// 第 3 项 D：**KDF 的 Lua 侧发射**（与 `Generator_chacha::derive_word` 逐位同式）。
///
/// `kdf(x,g,w)`：x 先与组号绑定的常数异或（走 32 位异或实现），两次算术旋转后再
/// 异或，取高低 16 位各乘一个小常数（乘积 ≤ 2^34，double 精确）归约到 2^32，
/// 最后按字序号再异或。所有中间量 < 2^53，与 Rust 侧同结果。
pub fn kdf_fn_decl(rng: &mut GenRng, keys: &CipherKeys, kdf: &str, xor32: &str, rot: &str, m32: &str) -> String {
    let (lo, t, lo2, hi2, a, b, c, y, k1, k2) =
        (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
    format!(
        "local function {kdf}(x,g,w) local {lo}=x%0X10000; local {t}={xor32}(x,({k1}*(g+0X1))%{m32}); \
         {t}={xor32}({rot}({t},0XD),{rot}({t},0X7)); \
         local {lo2}={t}%0X10000; local {hi2}=({t}-{lo2})/0X10000; \
         local {a}=0X1F3A5+g*0X9E37; local {b}=0X2C1B3+g*0X4F17; local {c}=0X13F7*(g+0X1); \
         local {y}=({lo2}*{a}+{hi2}*{b}+{c})%{m32}; \
         return {xor32}({y},({k2}*(w+0X1))%{m32}) end; ",
        kdf = kdf, xor32 = xor32, rot = rot, m32 = m32,
        lo = lo, t = t, lo2 = lo2, hi2 = hi2, a = a, b = b, c = c, y = y,
        k1 = rng.obfuscate_num(0x9E37_79B9u32 as i64, 1, keys),
        k2 = rng.obfuscate_num(0x85EB_CA6Bu32 as i64, 1, keys))
}

/// 第 3 项 D：单根 K0 的 token 化运输（与 `key_tokens` 同机制，但只发射一次）。
/// `fetch[i]` 即 K0 第 i 个字（1-based）的取用表达式。
pub fn root_tokens(rng: &mut GenRng, keys: &CipherKeys, root: &[u32; 8], h: &str) -> KeyTokens {
    key_tokens(rng, keys, root, h)
}

/// 第 3 项 D：一簇的派生块——由根 K0 现算本组 8 个密钥字 + 盐 + 两个 kind。
/// 输出：`kw[i]` 为第 i 个密钥字（i = 1..8）、`salt`/`knum`/`kstr` 三个标量，
/// 都是运行期 KDF 值，产物里没有任何一组密钥以数据形态出现。
pub struct DerivedGroup {
    pub decl: String,
    pub kw: String,
    pub fetch: Vec<String>,
    pub salt: String,
    pub knum: String,
    pub kstr: String,
}

pub fn derive_group(rng: &mut GenRng, keys: &CipherKeys, kdf: &str, root_fetch: &[String], g: usize) -> DerivedGroup {
    let kw = rng.name();
    let ge = rng.format_num(g as i64);
    // 8 个密钥字：发射顺序洗牌、下标使用运行时查表表示（读不出「第几个字配哪个槽」）
    let mut idx: Vec<usize> = (1..=8).collect();
    rng.shuffle(&mut idx);
    let mut decl = format!("local {kw}={{}}; ", kw = kw);
    for i in idx {
        decl.push_str(&format!(
            "{kw}[{ni}]={kdf}({root},{g},{ni}); ",
            kw = kw, ni = rng.obfuscate_num(i as i64, 1, keys), kdf = kdf,
            root = root_fetch[i - 1], g = ge));
    }
    // 三个标量严格照 `Generator_chacha::group_keys` 的规格：盐=根[0]/w9、
    // kstr=根[1]/w10、knum=根[2]/w11（发射顺序洗牌，但取用点与值不变）
    let salt = rng.name();
    let knum = rng.name();
    let kstr = rng.name();
    let mut scal: Vec<(String, u32, usize)> =
        vec![(salt.clone(), 9, 0), (knum.clone(), 11, 2), (kstr.clone(), 10, 1)];
    rng.shuffle(&mut scal);
    for (nm, w, ri) in scal {
        decl.push_str(&format!(
            "local {nm}={kdf}({root},{g},{w}); ",
            nm = nm, kdf = kdf, root = root_fetch[ri], g = ge, w = rng.obfuscate_num(w as i64, 1, keys)));
    }
    let fetch = (1..=8).map(|i| format!("{}[{}]", kw, rng.obfuscate_num(i as i64, 1, keys))).collect();
    DerivedGroup { decl, kw, fetch, salt, knum, kstr }
}

/// ⑰ 每簇一个自包含簇：`local a,b,c; do … end;` —— 簇内声明（含 token 表、
/// 游标机局部）随块结束释放，壳函数活动局部数不被撑爆（lua5.1 单函数 200 上限），
/// 簇外的取用点（解密器等）以 upvalue 捕获。
pub fn cluster_scope(outs: &[String], body: &str) -> String {
    format!("local {}; do {} end; ", outs.join(","), body)
}

#[cfg(test)]
mod tests {
    use super::super::Generator_util::{CipherKeys, GenRng};
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn transport_slots_roundtrip_in_lua() {
        // 发射的运输线闭包必须与构建期编码互逆：xor 线 (v^m^tx, m) → v，
        // add 线 (v-m+ta, m) → v；且线参数非零、组号互异。
        let mut rng = GenRng::new(0);
        let transports = super::build_transports(&mut rng, 6, &[0x46, 0x11]);
        for t in &transports {
            assert!(t.tx != 0 && t.ta != 0);
            assert!(transports.iter().filter(|o| o.grp == t.grp).count() == 1);
            assert!(t.kx != t.kadd);
        }
        let keys = CipherKeys {
            grp1: 0x46, grp2: 0x11, key_ba: 0x63,
            key_bs: 0x53, key_ba2: 0x71, key_bs2: 0x22,
            tbl_p: "P".to_string(), transports,
        };
        let slots = super::emit_transport_slots(&mut rng, &keys, "bx");
        let mut checks = String::new();
        for t in &keys.transports {
            for _ in 0..6 {
                let v = rng.next();
                let m = rng.range64(0x10000000, 0x3FFFFFFF) as u32;
                let ax = v ^ m ^ t.tx;
                checks.push_str(&format!(
                    "assert(P[0X{g:X}][0X{kx:X}](0X{a:X},0X{m:X})==0X{v:X}) ",
                    g = t.grp, kx = t.kx, a = ax, m = m, v = v));
                let aa = v as i64 - m as i64 + t.ta as i64;
                let aa_s = if aa < 0 { format!("-0X{:X}", aa.unsigned_abs()) } else { format!("0X{:X}", aa) };
                checks.push_str(&format!(
                    "assert(P[0X{g:X}][0X{ka:X}]({a},0X{m:X})==0X{v:X}) ",
                    g = t.grp, ka = t.kadd, a = aa_s, m = m, v = v));
            }
        }
        let bx = "local function bx(a,b) local r,p=0,1;while a>0 or b>0 do local ra,rb=a%2,b%2;if ra~=rb then r=r+p end;a=(a-ra)/2;b=(b-rb)/2;p=p*2 end;return r end;";
        let script = format!("local P={{}}; {bx} {slots} {checks} print('TRANSPORT_OK')",
            bx = bx, slots = slots, checks = checks);
        let lua = Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        let out = Command::new(lua).arg("-e").arg(&script).output().expect("run bundled Lua 5.1");
        assert!(out.status.success(), "transport Lua failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("TRANSPORT_OK"));
    }
}
