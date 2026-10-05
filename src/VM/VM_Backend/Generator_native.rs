//! Lua 原生密钥流（Native Stream）。
//!
//! 设计目标：**密钥材料不以数据形态落盘，解密只有靠 Lua 运行期才能完成**。
//!
//! - 落盘的只是「种子碎片」（数字/字符，混写拼写），运行期才用 Lua 原生操作合成；
//! - S-box 不是常量表，而是生成代码在运行期用 Fisher-Yates **现场构造**出来的
//!   （表内容由种子与双状态耦合洗牌决定，静态读产物读不到 S-box）；
//! - 每字节掩码由双残数态、位置与前一密文字节共同驱动，再查 S-box；
//! - **运行期指纹**（`tostring(function() end)` 的地址串、`collectgarbage("count")`、
//!   宿主原生报错文本）只用于两处：
//!   ① 选择**等价**的代码形态（不同 Lua 宿主走不同分支，解出的明文完全一致）；
//!   ② 参与自抵消混入（`+h-h`），让运行期中间值逐宿主/逐次运行都不同。
//!   因此不同 Lua 版本 / Roblox 执行器 / 不同次运行都能正确解密，
//!   但想用 Python 复现，必须先把 Lua 的 tostring/collectgarbage/pcall 语义
//!   与宿主报错文本格式逐位实现出来。
//!   指纹代码里不出现任何字符串常量（类型名/选项名/探针消息全部运行期取用）。
//!
//! 数学必须与生成的 Lua 逐位一致：范围全部 < 2^53，double 精确。

use super::Generator_util::GenRng;

/// 共享状态范围。乘积上限保持在 Lua 5.1 double 的精确整数域内。
pub const NMOD: u64 = 0x7FFF_FF01;

/// 项目自定义的耦合残数流。每轮的乘数取决于另一状态字，
/// 状态同时吸收位置与前一密文字节；不是固定乘加型 LCG。
pub struct Native {
    pub i1: u64, pub i2: u64,
    pub m1: u64, pub m2: u64, pub m3: u64, pub m4: u64,
    pub m5: u64, pub m6: u64, pub m7: u64, pub m8: u64,
}

impl Native {
    pub fn new(rng: &mut GenRng) -> Self {
        // 保持旧 Native 构造器的 12 次抽样顺序与范围，使 Native 派生的 UniStream
        // 参数变化不会推进/扰动后续 RNG 流；随机材料映射到新耦合更新参数。
        let odd = |rng: &mut GenRng, lo: i64, hi: i64| -> u64 {
            ((rng.range64(lo, hi) as u64) | 1).max(3)
        };
        let a1 = odd(rng, 3, 0x7FFF);
        let c1 = rng.range64(1, 0x7FFF) as u64;
        let a2 = odd(rng, 3, 0x7FFF);
        let c2 = rng.range64(1, 0x7FFF) as u64;
        let pf = odd(rng, 3, 0xFFFF);
        let pa = rng.range64(1, 0xFFFF) as u64;
        let pf2 = odd(rng, 3, 0xFFFF);
        let pa2 = rng.range64(1, 0xFFFF) as u64;
        let i1 = rng.range64(1, 0xFFFF) as u64;
        let i2 = rng.range64(1, 0xFFFF) as u64;
        let za = odd(rng, 3, 0xFFFF);
        let zc = rng.range64(1, 0xFFFF) as u64;
        Self {
            i1: (i1 + za * 0x1_0000) % NMOD,
            i2: (i2 + zc * 0x1_0000) % NMOD,
            m1: a1, m2: c1, m3: a2, m4: c2,
            m5: pf, m6: pa, m7: pf2, m8: pa2,
        }
    }

    /// 两个残数态的耦合更新。最大中间值低于 2^50，Rust/Lua 双方都精确。
    #[inline]
    pub fn mix_pair(&self, s1: u64, s2: u64, tweak: u64, feedback: u64) -> (u64, u64) {
        let t = tweak % NMOD;
        let x = (s1 * ((s2 % 0x1_0000) + self.m1)
            + s2 * self.m2 + t * self.m3 + feedback * self.m4 + self.i1) % NMOD;
        let y = (s2 * ((x % 0x1_0000) + self.m5)
            + x * self.m6 + t * self.m7 + feedback * self.m8 + self.i2) % NMOD;
        (x, y)
    }

    /// 种子折叠：顺序与反序字节成对进入耦合更新。
    fn fold(&self, seeds: &[u8]) -> (u64, u64) {
        let (mut s1, mut s2) = (self.i1, self.i2);
        let n = seeds.len();
        for i in 0..n {
            let feedback = seeds[i] as u64 + (seeds[n - 1 - i] as u64) * 256;
            (s1, s2) = self.mix_pair(s1, s2, (i + 1) as u64, feedback);
        }
        (s1, s2)
    }

    /// 运行期现场构造 256 项置换表。洗牌驱动器也使用同一耦合态。
    pub fn sbox(&self, seeds: &[u8]) -> [u8; 256] {
        let mut sb = [0u8; 256];
        for (i, slot) in sb.iter_mut().enumerate() { *slot = i as u8; }
        let (mut s1, mut s2) = self.fold(seeds);
        for i in (1..256).rev() {
            let feedback = (i as u64) * 257;
            (s1, s2) = self.mix_pair(s1, s2, i as u64, feedback);
            let mixed = (s1 % 0x1_0000) * (s2 % 0x1_0000)
                + s1 * 3 + s2 * 5 + i as u64;
            let j = (mixed % (i as u64 + 1)) as usize;
            sb.swap(i, j);
        }
        sb
    }

    /// 一条新流的初始状态。
    pub fn state(&self, seeds: &[u8]) -> NState {
        let (s1, s2) = self.fold(seeds);
        NState { s1, s2, pos: 0, prev: 0 }
    }

    /// UniStream 每个条目按全流偏移派生独立状态，再做若干耦合预热轮。
    pub fn state_at_offset(&self, seeds: &[u8], offset: u64, salt: u64, rounds: u64) -> NState {
        let (mut s1, mut s2) = self.fold(seeds);
        (s1, s2) = self.mix_pair(s1, s2, offset, salt);
        for _ in 0..rounds { (s1, s2) = self.mix_pair(s1, s2, 1, 0); }
        NState { s1, s2, pos: 0, prev: 0 }
    }

    /// 取下一字节的掩码。反馈只读前一密文，写读两侧可同步重建。
    pub fn next_key(&self, sb: &[u8; 256], st: &mut NState) -> u8 {
        let tweak = st.pos + 1;
        (st.s1, st.s2) = self.mix_pair(st.s1, st.s2, tweak, st.prev);
        let ix = (st.s1 % 256 + (st.s2 % 256) * 3
            + (st.pos % 256) * 5 + st.prev * 7) % 256;
        st.pos += 1;
        sb[ix as usize]
    }

    /// 加密一串（新开流）。返回 (密文, 收尾状态)。
    pub fn encrypt(&self, seeds: &[u8], sb: &[u8; 256], data: &[u8]) -> (Vec<u8>, NState) {
        let mut st = self.state(seeds);
        let out = self.encrypt_cont(sb, &mut st, data);
        (out, st)
    }

    /// 加密一串（续流，状态跨段保持）。
    pub fn encrypt_cont(&self, sb: &[u8; 256], st: &mut NState, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &p in data {
            let key = self.next_key(sb, st) as u64;
            let c = ((p as u64) + key) % 256;
            st.prev = c;
            out.push(c as u8);
        }
        out
    }

    /// 解密一串（Rust 侧自检用；与生成的 Lua 逐位一致）。
    pub fn decrypt_cont(&self, sb: &[u8; 256], st: &mut NState, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &cipher in data {
            let key = self.next_key(sb, st) as u64;
            let p = ((cipher as u64) + 256 - key) % 256;
            st.prev = cipher as u64;
            out.push(p as u8);
        }
        out
    }
}

pub struct NState {
    pub s1: u64,
    pub s2: u64,
    pub pos: u64,
    pub prev: u64,
}

/// 只供常量池根 K0 派生保持既有 ChaCha 输入不变。
/// VM/sandbox payload、UniStream 不得使用此兼容实现。
pub struct LegacyRootNative {
    a1: u64, c1: u64, a2: u64, c2: u64,
    pf: u64, pa: u64, pf2: u64, pa2: u64,
    i1: u64, i2: u64, za: u64, zc: u64,
}

impl LegacyRootNative {
    pub fn new(rng: &mut GenRng) -> Self {
        let odd = |rng: &mut GenRng, lo: i64, hi: i64| -> u64 {
            ((rng.range64(lo, hi) as u64) | 1).max(3)
        };
        Self {
            a1: odd(rng, 3, 0x7FFF), c1: rng.range64(1, 0x7FFF) as u64,
            a2: odd(rng, 3, 0x7FFF), c2: rng.range64(1, 0x7FFF) as u64,
            pf: odd(rng, 3, 0xFFFF), pa: rng.range64(1, 0xFFFF) as u64,
            pf2: odd(rng, 3, 0xFFFF), pa2: rng.range64(1, 0xFFFF) as u64,
            i1: rng.range64(1, 0xFFFF) as u64, i2: rng.range64(1, 0xFFFF) as u64,
            za: odd(rng, 3, 0xFFFF), zc: rng.range64(1, 0xFFFF) as u64,
        }
    }

    fn fold(&self, seeds: &[u8]) -> (u64, u64) {
        let (mut x1, mut x2) = (self.i1 % NMOD, self.i2 % NMOD);
        let n = seeds.len();
        for i in 0..n {
            x1 = (x1 * self.pf + seeds[i] as u64 + self.pa) % NMOD;
            x2 = (x2 * self.pf2 + seeds[n - 1 - i] as u64 + self.pa2) % NMOD;
        }
        (x1, x2)
    }

    fn sbox(&self, seeds: &[u8]) -> [u8; 256] {
        let mut sb = [0u8; 256];
        for (i, slot) in sb.iter_mut().enumerate() { *slot = i as u8; }
        let (x1, _) = self.fold(seeds);
        let mut z = (x1 * self.za + self.zc) % NMOD;
        for i in (1..256).rev() {
            z = (z * self.a1 + self.c1) % NMOD;
            sb.swap(i, (z % (i as u64 + 1)) as usize);
        }
        sb
    }

    /// The original Native derivation is retained solely as the ChaCha K0 input.
    pub fn keystream(&self, seeds: &[u8], len: usize) -> Vec<u8> {
        let sb = self.sbox(seeds);
        let (mut s1, mut s2) = self.fold(seeds);
        let mut pos = 0u64;
        let mut prev = 0u64;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            s1 = (s1 * self.a1 + self.c1) % NMOD;
            s2 = (s2 * self.a2 + self.c2) % NMOD;
            let idx = ((s1 % 256) + (s2 % 256) + pos + prev) % 256;
            let c = sb[idx as usize] as u64;
            out.push(c as u8);
            pos += 1;
            prev = c;
        }
        out
    }
}

/// 运行期指纹：三路宿主熵（函数地址串 / GC 计数 / 宿主原生报错文本）折叠成 h。
/// 返回 (前置代码, 变量名)。指纹只进「等价分支选择」与「自抵消混入」，
/// 不参与明文运算——换宿主只换路径，不换结果。
///
/// **不落任何字符串常量**：既没有 `string.char(字节表)`，也没有类型名字面量。
/// - 类型名比对走 `type(tostring(0X0))`（求值结果就是宿主自己给出的 "string"）；
/// - `collectgarbage` 的选项名在运行期从宿主串里现取字符拼出
///   （`tostring(function()end)` 形如 "function: 0x…"，c/o/u/n/t 的字节位在这里固定，
///   宿主给什么串就取什么字符，取不出就整路跳过）；
/// - 第三路不再自造消息，直接用宿主自己的索引/调用/算术/连接错误文本（逐宿主不同）；
/// - 块内库成员按**调用点个数**决定形态：超过两次的统一 local 化（逐产物随机
///   局部名、分条声明、顺序洗牌），取用点只出现局部名，`string.sub(` 不再排成一列；
///   只有一两次调用的（string.byte/math.floor）保持直呼，不凭空多出绑定。
/// 三路都 fail-open：某一路在宿主上取不到就跳过，汇编出的 h 只影响等价选路，
/// 两种选路逐位同结果，所以跳过不影响可解性；想让 Python 侧算 h，仍必须把
/// tostring/collectgarbage/pcall 与错误消息格式逐位复刻出来。
pub fn emit_fingerprint(rng: &mut GenRng) -> (String, String) {
    let h = rng.name();
    let ok = rng.name();
    let v = rng.name();
    let i = rng.name();
    let okc = rng.name();
    let c = rng.name();
    let mok = rng.name();
    let m = rng.name();
    let q = rng.name();
    let j = rng.name();
    let hm = format!("0X{:X}", NMOD);
    let (r1, r2, r3) = (rng.range64(3, 0x1_0000), rng.range64(3, 0x1_0000), rng.range64(3, 0x1_0000));
    let (p1, p2, p3) = (rng.format_num(r1), rng.format_num(r2), rng.format_num(r3));
    // 位置下标与错误探针实参直接使用数值字面量。
    let xnum = |rng: &mut GenRng, v: u32| -> String { rng.format_num(v as i64) };
    // 类型名比较臂池：三种写法求值都是宿主给出的 "string"（值不同、语义同）
    let tstr = |rng: &mut GenRng| -> String {
        match rng.range(0, 3) {
            0 => "@TYPE@(@TSTR@(0X0))".to_string(),
            1 => "@TYPE@(@TSTR@({}))".to_string(),
            _ => "@TYPE@(@TSTR@(true))".to_string(),
        }
    };
    // "count" 的五个字符在宿主串 "function: 0x…" 里的字节位：c=4 o=7 u=2 n=8/3 t=5
    // （n 有两处，逐产物随机挑一处，取用点看不出固定模板）
    let n_idx = if rng.range(0, 2) == 0 { 8 } else { 3 };
    let sub = |rng: &mut GenRng, idx: u32| -> String {
        format!("@SUB@({v},{a},{a})", v = v, a = xnum(rng, idx))
    };
    let opt = [4u32, 7, 2, n_idx, 5]
        .iter()
        .map(|&ix| sub(rng, ix))
        .collect::<Vec<_>>()
        .join("..");
    // 第三路错误族池：索引 / 调用 / 算术 / 连接——宿主报错文本各不相同
    let o1 = xnum(rng, 1);
    let err_body = match rng.range(0, 4) {
        0 => format!("local {q}; return {q}[{o}]", q = q, o = o1),
        1 => format!("local {q}; return {q}({o})", q = q, o = o1),
        2 => format!("local {q}; return {q}+{o}", q = q, o = o1),
        _ => format!("local {q}; return {q}..{o}", q = q, o = o1),
    };
    let (t1, t3) = (tstr(rng), tstr(rng));
    // 第一路/第三路的折叠循环逐产物换形态（for 递增 / while 递增）
    let loop3 = if rng.range(0, 2) == 0 {
        format!("for {j}=0X1,#{m} do {h}=({h}*{p3}+@BYTE@({m},{j}))%{hm} end; ",
                j = j, m = m, h = h, p3 = p3, hm = hm)
    } else {
        format!("local {j}=0X0; while {j}<#{m} do {j}={j}+0X1; {h}=({h}*{p3}+@BYTE@({m},{j}))%{hm} end; ",
                j = j, m = m, h = h, p3 = p3, hm = hm)
    };
    // 库成员先全部写成占位符，装配完按**调用点个数**决定形态：超过两次的
    // 统一 local 化（逐产物随机局部名，声明散在同一 do 块开头、顺序洗牌），
    // 取用点只出现局部名——不再把 `string.sub(` 一字排开写五遍；不超过两次的
    // 保持直呼，免得为省一两处反而多出一个显眼的绑定。
    let mut src = format!(
        "local {h}=0X0; do @ALIAS@local {ok},{v}=@PCALL@(function() return @TSTR@(function() end) end); \
           if {ok} and @TYPE@({v})=={t1} then for {i}=0X1,#{v} do {h}=({h}*{p1}+@BYTE@({v},{i}))%{hm} end; \
              local {okc},{c}=@PCALL@(collectgarbage,{opt}); \
              if {okc} and @TYPE@({c})==@TYPE@(0X0) then {h}=({h}*{p2}+@FLOOR@({c}))%{hm} end; end; \
           local {mok},{m}=@PCALL@(function() {eb} end); \
           if @TYPE@({m})=={t3} then {l3} end; \
         end; ",
        h = h, ok = ok, v = v, t1 = t1,
        i = i, p1 = p1, hm = hm,
        okc = okc, c = c, opt = opt, p2 = p2,
        mok = mok, m = m, eb = err_body, t3 = t3, l3 = loop3
    );
    let mut aliases: Vec<(String, &str)> = Vec::new();
    for (marker, lib) in [
        ("@SUB@", "string.sub"),
        ("@TYPE@", "type"),
        ("@PCALL@", "pcall"),
        ("@BYTE@", "string.byte"),
        ("@FLOOR@", "math.floor"),
        ("@TSTR@", "tostring"),
    ] {
        if src.matches(marker).count() > 2 {
            let a = rng.name();
            aliases.push((a.clone(), lib));
            src = src.replace(marker, &a);
        } else {
            src = src.replace(marker, lib);
        }
    }
    rng.shuffle(&mut aliases);
    let alias_decl: String = aliases.iter().map(|(a, lib)| format!("local {}={}; ", a, lib)).collect();
    let src = src.replace("@ALIAS@", &alias_decl);
    (src, h)
}

/// 解密内核三件套：声明 / 初始化函数 / 步进函数。
pub struct Kernel {
    /// 外层作用域声明（局部名，闭包按 upvalue 捕获）
    pub decl: String,
    /// 初始化函数名：`local function kinit(T)` —— T 是密钥字节表（1..16）。
    /// 可重复调用：每调一次就从头起流（载荷分段解码需要）。
    pub init_fn: String,
    /// 每字节步进函数名（`local function f(v) ... return 明文 end`）
    pub step: String,
    /// 运行期构造出来的 S-box 表名（upvalue，供别的自建流直接复用）
    pub sb: String,
    /// 折叠出的两条起始状态名（upvalue，供对每串另起偏移的自建流复用）
    pub st1: String,
    pub st2: String,
}

/// 生成解密内核。种子表由 `init_fn` 的形参传入（调用方给 `s.k` 之类的已就位表）。
pub fn emit_decrypt_kernel(rng: &mut GenRng, nat: &Native, tag: &str) -> Kernel {
    emit_kernel_ex(rng, nat, tag, true)
}

/// 只建 S-box（不发射全局步进函数）：给「每串各自起流」的场合用。
pub fn emit_sbox_builder(rng: &mut GenRng, nat: &Native, tag: &str) -> Kernel {
    emit_kernel_ex(rng, nat, tag, false)
}

fn emit_kernel_ex(rng: &mut GenRng, nat: &Native, tag: &str, with_step: bool) -> Kernel {
    let (fp_src, h) = emit_fingerprint(rng);
    let sb = rng.name();
    let st1 = rng.name();
    let st2 = rng.name();
    let pos = rng.name();
    let prev = rng.name();
    let i = rng.name();
    let j = rng.name();
    let x = rng.name();
    let y = rng.name();
    let f = rng.name();
    let v = rng.name();
    let seedv = rng.name();
    let ix = rng.name();
    let k = rng.name();

    let num = |rng: &mut GenRng, v: u64| rng.format_num(v as i64);
    let nmod = format!("0X{:X}", NMOD);
    let low = "0X10000";
    let (m1, m2, m3, m4, m5, m6, m7, m8, i1, i2) = (
        num(rng, nat.m1), num(rng, nat.m2), num(rng, nat.m3), num(rng, nat.m4),
        num(rng, nat.m5), num(rng, nat.m6), num(rng, nat.m7), num(rng, nat.m8),
        num(rng, nat.i1), num(rng, nat.i2),
    );

    // Rust/Lua 完全同式：每个种子字节与反向位置的字节成对混入。
    let fold_src = format!(
        "local {x}={i1}; local {y}={i2}; for {i}=0X1,#{seedv} do \
         local {f}={seedv}[{i}]+{seedv}[#{seedv}+0X1-{i}]*0X100; \
         local {ix}=({x}*(({y}%{low})+{m1})+{y}*{m2}+{i}*{m3}+{f}*{m4}+{i1})%{nm}; \
         local {k}=({y}*(({ix}%{low})+{m5})+{ix}*{m6}+{i}*{m7}+{f}*{m8}+{i2})%{nm}; \
         {x}={ix}; {y}={k}; end; ",
        x = x, y = y, i = i, seedv = seedv, f = f, ix = ix, k = k,
        i1 = i1, i2 = i2, m1 = m1, m2 = m2, m3 = m3, m4 = m4,
        m5 = m5, m6 = m6, m7 = m7, m8 = m8, low = low, nm = nmod);

    let mk_loop = |rng: &mut GenRng, while_form: bool| -> String {
        let init = format!("for {i}=0X0,0XFF do {sb}[{i}+0X1]={i} end; ", i = i, sb = sb);
        let body = format!(
            "local {f}={i}*0X101; local {ix}=({x}*(({y}%{low})+{m1})+{y}*{m2}+{i}*{m3}+{f}*{m4}+{i1})%{nm}; \
             local {k}=({y}*(({ix}%{low})+{m5})+{ix}*{m6}+{i}*{m7}+{f}*{m8}+{i2})%{nm}; \
             {x}={ix}; {y}={k}; {j}=(({x}%{low})*({y}%{low})+{x}*0X3+{y}*0X5+{i})%({i}+0X1); \
             local tmp={sb}[{i}+0X1]; {sb}[{i}+0X1]={sb}[{j}+0X1]; {sb}[{j}+0X1]=tmp; ",
            i = i, f = f, x = x, y = y, ix = ix, k = k, j = j, sb = sb,
            m1 = m1, m2 = m2, m3 = m3, m4 = m4, m5 = m5, m6 = m6, m7 = m7, m8 = m8,
            i1 = i1, i2 = i2, low = low, nm = nmod);
        if while_form {
            format!("{init}{i}=0XFF; while {i}>=0X1 do {body}{i}={i}-0X1 end; ", init = init, i = i, body = body)
        } else {
            format!("{init}for {i}=0XFF,0X1,-0X1 do {body}end; ", init = init, i = i, body = body)
        }
    };
    let l0 = mk_loop(rng, false);
    let l1 = mk_loop(rng, true);
    let pick_raw = rng.range64(2, 0xFFFFF);
    let pick = rng.format_num(pick_raw);
    let build = format!("if ({h}%0X2)==0X0 then {a} else {b} end; ", h = h, a = l0, b = l1);
    let pickv = rng.name();
    let decl = format!(
        "local {sb},{st1},{st2},{pos},{prev}; {fp_src}local {pickv}={pick}; ",
        sb = sb, st1 = st1, st2 = st2, pos = pos, prev = prev,
        fp_src = fp_src, pickv = pickv, pick = pick);

    let init_fn = rng.name();
    let init_def = format!(
        "local function {kf}({seedv}) {sb}={{}}; local {i},{j},{f},{ix},{k},{x},{y}; {fold} \
         {st1}={x}; {st2}={y}; {build} {pos}=0X0; {prev}=0X0; end; ",
        kf = init_fn, seedv = seedv, sb = sb, i = i, j = j, f = f, ix = ix, k = k,
        x = x, y = y, fold = fold_src, build = build, st1 = st1, st2 = st2, pos = pos, prev = prev);

    let step = format!(
        "local function {fn}({v}) local tw=({pos}+0X1)%{nm}; \
         local nx=({st1}*(({st2}%{low})+{m1})+{st2}*{m2}+tw*{m3}+{prev}*{m4}+{i1})%{nm}; \
         local ny=({st2}*((nx%{low})+{m5})+nx*{m6}+tw*{m7}+{prev}*{m8}+{i2})%{nm}; \
         {st1}=nx; {st2}=ny; local {ix}=({st1}%0X100+({st2}%0X100)*0X3+({pos}%0X100)*0X5+{prev}*0X7)%0X100; \
         local {k}={sb}[{ix}+0X1]; {pos}={pos}+0X1; {prev}={v}; return ({v}+0X100-{k})%0X100 end; ",
        fn = f, v = v, pos = pos, nm = nmod, st1 = st1, st2 = st2, prev = prev,
        ix = ix, k = k, sb = sb, low = low, m1 = m1, m2 = m2, m3 = m3, m4 = m4,
        m5 = m5, m6 = m6, m7 = m7, m8 = m8, i1 = i1, i2 = i2);
    let _ = tag;
    let body = if with_step { format!("{decl}{init_def}{step}") } else { format!("{decl}{init_def}") };
    Kernel {
        decl: body, init_fn: init_fn.clone(), step: if with_step { f.clone() } else { String::new() },
        sb: sb.clone(), st1: st1.clone(), st2: st2.clone(),
    }
}

#[cfg(test)]
mod custom_stream_tests {
    use super::*;

    fn sample_native() -> Native {
        Native { i1: 0x12345, i2: 0x6789A, m1: 0x113, m2: 0x527, m3: 0xA31, m4: 0xD27,
            m5: 0x1B3, m6: 0x733, m7: 0xC15, m8: 0xE57 }
    }

    #[test]
    fn coupled_stream_round_trips_across_continuations() {
        let nat = sample_native();
        let seeds = *b"0123456789ABCDEF";
        let sb = nat.sbox(&seeds);
        let input: Vec<u8> = (0..=255).chain(0..=255).collect();
        let mut enc_state = nat.state(&seeds);
        let mut cipher = nat.encrypt_cont(&sb, &mut enc_state, &input[..173]);
        cipher.extend(nat.encrypt_cont(&sb, &mut enc_state, &input[173..]));
        let mut dec_state = nat.state(&seeds);
        let mut plain = nat.decrypt_cont(&sb, &mut dec_state, &cipher[..99]);
        plain.extend(nat.decrypt_cont(&sb, &mut dec_state, &cipher[99..]));
        assert_eq!(plain, input);
        assert_ne!(cipher, input);
    }

    #[test]
    fn offset_streams_diverge_and_round_trip() {
        let nat = sample_native();
        let seeds = *b"0123456789ABCDEF";
        let sb = nat.sbox(&seeds);
        let input = b"same plaintext";
        let mut a = nat.state_at_offset(&seeds, 12, 0x1234, 9);
        let mut b = nat.state_at_offset(&seeds, 57, 0x1234, 9);
        let ct_a = nat.encrypt_cont(&sb, &mut a, input);
        let ct_b = nat.encrypt_cont(&sb, &mut b, input);
        assert_ne!(ct_a, ct_b);
        let mut dec = nat.state_at_offset(&seeds, 12, 0x1234, 9);
        assert_eq!(nat.decrypt_cont(&sb, &mut dec, &ct_a), input);
    }

    #[test]
    fn emitted_lua_kernel_matches_rust_cipher_byte_for_byte() {
        use crate::VM::VM_Backend::Generator_util::GenRng;
        use std::path::Path;
        use std::process::Command;

        let lua = Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() { return; }
        let nat = sample_native();
        let seeds = *b"0123456789ABCDEF";
        let sb = nat.sbox(&seeds);
        let plain: Vec<u8> = (0..=255).collect();
        let (cipher, _) = nat.encrypt(&seeds, &sb, &plain);
        let mut rng = GenRng::new(0xC0FF_EE12);
        let kernel = emit_decrypt_kernel(&mut rng, &nat, "test");
        let table = |bytes: &[u8]| bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(",");
        let script = format!(
            "local seed={{{}}}; {} {}(seed); local c={{{}}}; local p={{{}}}; for i=1,#c do assert({}(c[i])==p[i],i) end; print('NATIVE_OK')",
            table(&seeds), kernel.decl, kernel.init_fn, table(&cipher), table(&plain), kernel.step);
        let out = Command::new(lua).arg("-e").arg(script).output().expect("run bundled Lua 5.1");
        assert!(out.status.success(), "Lua kernel failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("NATIVE_OK"));
    }
}
