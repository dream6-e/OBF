//! Lua 原生密钥流（Native Stream）。
//!
//! 设计目标：**密钥材料不以数据形态落盘，解密只有靠 Lua 运行期才能完成**。
//!
//! - 落盘的只是「种子碎片」（数字/字符，混写拼写），运行期才用 Lua 原生操作合成；
//! - S-box 不是常量表，而是生成代码在运行期用 Fisher-Yates **现场构造**出来的
//!   （表内容由种子 + LCG 决定，静态读产物读不到 S-box）；
//! - 每字节密钥 = 两条 LCG 状态 + 位置 + 前一密文字节 混合后查 S-box，
//!   没有闭式密钥流公式，也没有固定周期；
//! - **运行期指纹**（`tostring(function() end)` 的地址串、`collectgarbage("count")`、
//!   `pcall(error)` 的消息串）只用于两处：
//!   ① 选择**等价**的代码形态（不同 Lua 宿主走不同分支，解出的明文完全一致）；
//!   ② 参与自抵消混入（`+h-h`），让运行期中间值逐宿主/逐次运行都不同。
//!   因此不同 Lua 版本 / Roblox 执行器 / 不同次运行都能正确解密，
//!   但想用 Python 复现，必须先把 Lua 的 tostring/collectgarbage/pcall 语义
//!   逐位实现出来。
//!
//! 数学必须与生成的 Lua 逐位一致：范围全部 < 2^53，double 精确。

use super::Generator_util::GenRng;

/// 模数：奇数、< 2^31（x*a < 2^47，double 精确）
pub const NMOD: u64 = 0x7FFF_FF01;

pub struct Native {
    pub a1: u64,
    pub c1: u64,
    pub a2: u64,
    pub c2: u64,
    pub pf: u64,
    pub pa: u64,
    pub pf2: u64,
    pub pa2: u64,
    pub i1: u64,
    pub i2: u64,
    pub za: u64,
    pub zc: u64,
}

impl Native {
    pub fn new(rng: &mut GenRng) -> Self {
        let odd = |rng: &mut GenRng, lo: i64, hi: i64| -> u64 { ((rng.range64(lo, hi) as u64) | 1).max(3) };
        Self {
            a1: odd(rng, 3, 0x7FFF),
            c1: (rng.range64(1, 0x7FFF) as u64),
            a2: odd(rng, 3, 0x7FFF),
            c2: (rng.range64(1, 0x7FFF) as u64),
            pf: odd(rng, 3, 0xFFFF),
            pa: (rng.range64(1, 0xFFFF) as u64),
            pf2: odd(rng, 3, 0xFFFF),
            pa2: (rng.range64(1, 0xFFFF) as u64),
            i1: (rng.range64(1, 0xFFFF) as u64),
            i2: (rng.range64(1, 0xFFFF) as u64),
            za: odd(rng, 3, 0xFFFF),
            zc: (rng.range64(1, 0xFFFF) as u64),
        }
    }

    /// 种子折叠：与 Lua 侧同一个循环式（Rust 侧 16 字节固定长）。
    fn fold(&self, seeds: &[u8]) -> (u64, u64) {
        let (mut x1, mut x2) = (self.i1 % NMOD, self.i2 % NMOD);
        let n = seeds.len();
        for i in 0..n {
            x1 = (x1.wrapping_mul(self.pf).wrapping_add(seeds[i] as u64).wrapping_add(self.pa)) % NMOD;
            let b = seeds[n - 1 - i] as u64;
            x2 = (x2.wrapping_mul(self.pf2).wrapping_add(b).wrapping_add(self.pa2)) % NMOD;
        }
        (x1, x2)
    }

    /// 运行期 S-box（Fisher-Yates）：与生成的 Lua 构造代码逐位一致。
    pub fn sbox(&self, seeds: &[u8]) -> [u8; 256] {
        let mut sb = [0u8; 256];
        for i in 0..256 {
            sb[i] = i as u8;
        }
        let (x1, _) = self.fold(seeds);
        let mut z = (x1.wrapping_mul(self.za).wrapping_add(self.zc)) % NMOD;
        let mut i = 255usize;
        while i >= 1 {
            z = (z.wrapping_mul(self.a1).wrapping_add(self.c1)) % NMOD;
            let j = (z % (i as u64 + 1)) as usize;
            sb.swap(i, j);
            i -= 1;
        }
        sb
    }

    /// 逐字节密钥流状态
    pub fn state(&self, seeds: &[u8]) -> NState {
        let (s1, s2) = self.fold(seeds);
        NState { s1, s2, pos: 0, prev: 0 }
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
        for &b in data {
            st.s1 = (st.s1.wrapping_mul(self.a1).wrapping_add(self.c1)) % NMOD;
            st.s2 = (st.s2.wrapping_mul(self.a2).wrapping_add(self.c2)) % NMOD;
            let idx = ((st.s1 % 256) + (st.s2 % 256) + st.pos + st.prev) % 256;
            let k = sb[idx as usize] as u64;
            let c = ((b as u64) + k) % 256;
            st.pos += 1;
            st.prev = c;
            out.push(c as u8);
        }
        out
    }

    /// 解密一串（Rust 侧自检用；与生成的 Lua 逐位一致）。
    pub fn decrypt_cont(&self, sb: &[u8; 256], st: &mut NState, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &c in data {
            st.s1 = (st.s1.wrapping_mul(self.a1).wrapping_add(self.c1)) % NMOD;
            st.s2 = (st.s2.wrapping_mul(self.a2).wrapping_add(self.c2)) % NMOD;
            let idx = ((st.s1 % 256) + (st.s2 % 256) + st.pos + st.prev) % 256;
            let k = sb[idx as usize] as u64;
            let b = ((c as u64) + 256 - k) % 256;
            st.pos += 1;
            st.prev = c as u64;
            out.push(b as u8);
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

/// 运行期指纹：只用 Lua 侧存在、Python 侧需要完整复刻宿主语义的量。
/// 返回 (前置代码, 变量名)。指纹只进「等价分支选择」与「自抵消混入」，
/// 不参与明文运算——换宿主只换路径，不换结果。
pub fn emit_fingerprint(rng: &mut GenRng) -> (String, String) {
    let h = rng.name();
    let ok = rng.name();
    let v = rng.name();
    let i = rng.name();
    let okc = rng.name();
    let c = rng.name();
    let m = rng.name();
    let mok = rng.name();
    let hm = format!("0X{:X}", NMOD);
    let (r1, r2, r3) = (rng.range64(3, 0x1_0000), rng.range64(3, 0x1_0000), rng.range64(3, 0x1_0000));
    let (p1, p2, p3) = (rng.format_num(r1), rng.format_num(r2), rng.format_num(r3));
    // 零字符串字面量：类型名与库参数一律用 string.char(数字) 现拼
    let ch = |rng: &mut GenRng, s: &str| -> String {
        let mut parts: Vec<String> = Vec::new();
        for b in s.bytes() {
            let f = rng.format_num(b as i64);
            parts.push(f);
        }
        format!("string.char({})", parts.join(","))
    };
    let tstr = ch(rng, "string");
    let tcnt = ch(rng, "count");
    let terr = ch(rng, "x");
    let src = format!(
        "local {h}=0X0; do \
           local {ok},{v}=pcall(function() return tostring(function() end) end); \
           if {ok} and type({v})==type({tstr}) then for {i}=0X1,#{v} do {h}=({h}*{p1}+string.byte({v},{i}))%{hm} end end; \
           local {okc},{c}=pcall(collectgarbage,{tcnt}); \
           if {okc} and type({c})==type(0X0) then {h}=({h}*{p2}+math.floor({c}))%{hm} end; \
           local {mok},{m}=pcall(function() error({terr}) end); \
           if type({m})==type({tstr}) then for {i}=0X1,#{m} do {h}=({h}*{p3}+string.byte({m},{i}))%{hm} end end; \
         end; ",
        h = h,
        ok = ok,
        v = v,
        i = i,
        okc = okc,
        c = c,
        mok = mok,
        m = m,
        p1 = p1,
        p2 = p2,
        p3 = p3,
        hm = hm,
        tstr = tstr,
        tcnt = tcnt
    );
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
    let z = rng.name();
    let i = rng.name();
    let j = rng.name();
    let x1 = rng.name();
    let x2 = rng.name();
    let f = rng.name();
    let ix = rng.name();
    let k = rng.name();
    let t = rng.name();
    let v = rng.name();
    let seedv = rng.name();

    let num = |rng: &mut GenRng, v: u64| rng.format_num(v as i64);
    let nmod = format!("0X{:X}", NMOD);

    // 折叠两条种子（同式与 Rust 侧 fold 一致）
    let fold_src = format!(
        "local {x1}={i1}; local {x2}={i2}; for {i}=0X1,#{seedv} do \
           {x1}=({x1}*{pf}+{seedv}[{i}]+{pa})%{nm}; \
           {x2}=({x2}*{pf2}+{seedv}[#{seedv}+0X1-{i}]+{pa2})%{nm}; end; ",
        x1 = x1,
        x2 = x2,
        i = i,
        i1 = num(rng, nat.i1),
        i2 = num(rng, nat.i2),
        pf = num(rng, nat.pf),
        pa = num(rng, nat.pa),
        pf2 = num(rng, nat.pf2),
        pa2 = num(rng, nat.pa2),
        nm = nmod,
        seedv = seedv
    );

    // S-box 现场构造：两套等价形态（for 递减 / while 递减），由指纹选路；
    // 循环内混入 +h-h（自抵消，运行期值逐宿主不同，结果不变）。
    let mk_loop = |rng: &mut GenRng, while_form: bool| -> String {
        let init = format!("for {i}=0X0,0XFF do {sb}[{i}+0X1]={i} end; {z}=({x1}*{za}+{zc})%{nm}; ",
            i = i, sb = sb, z = z, x1 = x1, za = num(rng, nat.za), zc = num(rng, nat.zc), nm = nmod);
        let body = format!(
            "{z}=({z}*{a1}+{c1}+{h}-{h})%{nm}; {j}={z}%({i}+0X1); {t}={sb}[{i}+0X1]; {sb}[{i}+0X1]={sb}[{j}+0X1]; {sb}[{j}+0X1]={t}; ",
            z = z, a1 = num(rng, nat.a1), c1 = num(rng, nat.c1), h = h, nm = nmod,
            j = j, i = i, t = t, sb = sb
        );
        if while_form {
            format!(
                "{init}{i}=0XFF; while {i}>=0X1 do {body}{i}={i}-0X1 end; ",
                init = init, i = i, body = body
            )
        } else {
            format!("{init}for {i}=0XFF,0X1,-0X1 do {body}end; ", init = init, i = i, body = body)
        }
    };
    let l0 = mk_loop(rng, false);
    let l1 = mk_loop(rng, true);
    let pick_r = rng.range64(2, 0xFFFFF);
    let pick = rng.format_num(pick_r);
    let build = format!(
        "if ({h}%0X2)==0X0 then {a} else {b} end; ",
        h = h,
        a = l0,
        b = l1
    );

    let pickv = rng.name();
    let decl = format!(
        "local {sb},{st1},{st2},{pos},{prev};{fp_src}local {pickv}={pick}; ",
        sb = sb,
        st1 = st1,
        st2 = st2,
        pos = pos,
        prev = prev,
        fp_src = fp_src,
        pickv = pickv,
        pick = pick
    );

    let init_fn = rng.name();
    let init_def = format!(
        "local function {kf}({seedv}) {sb}={{}}; local {z},{i},{j},{t}; {fold}{build}local {st1v},{st2v}={x1},{x2}; {st1}={st1v}%{nm}; {st2}={st2v}%{nm}; {pos}=0X0; {prev}=0X0; end; ",
        kf = init_fn,
        seedv = seedv,
        sb = sb,
        z = z,
        i = i,
        j = j,
        t = t,
        fold = fold_src,
        build = build,
        st1v = rng.name(),
        st2v = rng.name(),
        x1 = x1,
        x2 = x2,
        st1 = st1,
        st2 = st2,
        nm = nmod,
        pos = pos,
        prev = prev
    );

    let step = format!(
        "local function {f}({v}) {st1}=({st1}*{a1}+{c1})%{nm}; {st2}=({st2}*{a2}+{c2})%{nm}; \
         local {ix}=({st1}%0X100+{st2}%0X100+{pos}+{prev})%0X100; local {k}={sb}[{ix}+0X1]; \
         {pos}={pos}+0X1; {prev}={v}; return ({v}-{k})%0X100 end; ",
        f = f,
        v = v,
        st1 = st1,
        a1 = num(rng, nat.a1),
        c1 = num(rng, nat.c1),
        nm = nmod,
        st2 = st2,
        a2 = num(rng, nat.a2),
        c2 = num(rng, nat.c2),
        ix = ix,
        pos = pos,
        prev = prev,
        k = k,
        sb = sb
    );
    let _ = tag;
    // 步进函数必须与声明同处一个作用域（闭包按 upvalue 捕获状态）
    let body = if with_step { format!("{decl}{init_def}{step}") } else { format!("{decl}{init_def}") };
    Kernel { decl: body, init_fn: init_fn.clone(), step: if with_step { f.clone() } else { String::new() }, sb: sb.clone(), st1: st1.clone(), st2: st2.clone() }
}
