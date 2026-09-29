//! ㉓ 统一流加密（UniStream）：④⑤⑥ 三线并流的惰性解密流。
//! 从 Generator_util.rs 拆出（80 KB 规则）——输出与功能不变。

use crate::VM::VM_Backend::Generator::GenRng;

// 位置相关双字节混合的「位置」维度升级为全流坐标，同一字符在不同串/不同位置
// 密文全不同。落盘形态：密文只以**数字**出现（字节表字面量，十进制/0X/拆和式
// 混写），产物里零 `""` 字面量；解码器用 `string.char()`（无参=空串，同样零
// 字面量）累积。取用形态=焊接式惰性解密：`if not U[k] then U[k]=D({c…},off) end;`
// 第一次走到才解，第二次起缓存直通（逻辑上无分支）。

pub struct UniStream {
    pub tbl: String,
    pub dec: String,
    // ㉓.2 高频数字（256/模数/LCG a、c）提升为壳内局部常量，取用点只引名字
    k_b: String, k_m: String, k_a: String, k_c: String, k_p: String, k_q: String,
    a: u64, c: u64, m: u64, seed: u64, q0: u64, q1: u64,
    // ㉓.5 自循环：d_mul/d_rounds 串起始推导；fb_mul/fb_add 明文反馈
    d_mul: u64, d_rounds: u64, fb_mul: u64, fb_add: u64,
    cur: u64,
    enc: Vec<u8>,
    entries: Vec<(Vec<u8>, usize)>, // (密文字节, 全流偏移)
    used: std::collections::HashSet<u32>,
}

impl UniStream {
    pub fn new(rng: &mut GenRng) -> Self {
        let m = 0x7FFFFF01u64; // 奇数 < 2^31：x*a < 2^47，double 精确
        let a = (rng.range(3, 0x1_0000) as u64) | 1;
        let c = rng.range(1, 0x1_0000) as u64;
        let seed = rng.range(1, 0x7FFF_FFFF) as u64;
        let q0 = rng.range(1, 256) as u64;
        let q1 = rng.range(1, 256) as u64;
        let d_mul = rng.range(1, 0x1_0000) as u64;
        let d_rounds = rng.range(4, 16) as u64;
        let fb_mul = (rng.range(1, 0x4000) as u64) | 1;   // < 2^14：x+p*P+Q < 2^32，double 精确
        let fb_add = rng.range(1, 0x1_0000) as u64;
        Self { tbl: rng.name(), dec: rng.name(),
               k_b: rng.name(), k_m: rng.name(), k_a: rng.name(), k_c: rng.name(),
               k_p: rng.name(), k_q: rng.name(),
               a, c, m, seed, q0, q1, d_mul, d_rounds, fb_mul, fb_add,
               cur: seed, enc: Vec::new(), entries: Vec::new(), used: std::collections::HashSet::new() }
    }
    fn key(&mut self, rng: &mut GenRng) -> u32 {
        loop {
            let k = rng.range(0x0200_0000, 0x7FFF_FFFF) as u32;
            if self.used.insert(k) { return k; }
        }
    }
    /// 登记一个明文：加密后占一段新偏移。返回条目号。
    /// ㉓.5 自循环流：每串起始状态 = (seed + off*d_mul)%m 再走 d_rounds 步推导；
    /// 逐字节：步进→取键流→加密→**把明文反馈进状态**。解第 j+1 字节必须先有
    /// 第 j 字节的明文——不存在可直写的线性密钥流公式。
    pub fn register(&mut self, plain: &str) -> usize {
        let b = plain.as_bytes();
        let off = self.enc.len();
        let mut x = (self.seed + (off as u64) * self.d_mul) % self.m;
        for _ in 0..self.d_rounds {
            x = (x.wrapping_mul(self.a).wrapping_add(self.c)) % self.m;
        }
        let mut ciph = Vec::with_capacity(b.len());
        for (j, &p) in b.iter().enumerate() {
            x = (x.wrapping_mul(self.a).wrapping_add(self.c)) % self.m;
            let g = (off + j + 1) as u64;
            let ks = ((x % 256) + self.q0 * (g % 256) + self.q1) % 256;
            ciph.push((((p as u64) + ks) % 256) as u8);
            x = (x + (p as u64) * self.fb_mul + self.fb_add) % self.m; // 明文反馈
        }
        self.enc.extend(std::iter::repeat(0u8).take(b.len())); // 仅占偏移
        self.entries.push((ciph, off));
        self.entries.len() - 1
    }
    /// 字节数字的混写形态：十进制 / 0X 大写 / (A+B)%256 拆和。
    fn byte_num(&self, rng: &mut GenRng, v: u8) -> String {
        match rng.range(0, 3) {
            0 => format!("{}", v),
            1 => format!("0X{:X}", v),
            _ => {
                let a = rng.range(0, 256);
                let b = ((v as usize) + 256 - a) % 256;
                // ㉓.2 取模基数引常量名，不再裸写 256
                format!("({}+{})%{}", a, b, self.k_b)
            }
        }
    }
    fn plain_num(&self, v: u64) -> String {
        if v > 0x1000 && self.cur % 2 == 0 { format!("0X{:X}", v) } else { format!("{}", v) }
    }
    /// 取用形态：返回 (惰性解密语句, 取串表达式)。密文纯数字，零字面量。
    pub fn fetch(&mut self, rng: &mut GenRng, id: usize) -> (String, String) {
        let (cipher, off) = self.entries[id].clone();
        let k = self.key(rng);
        let kf = rng.format_num(k as i64);
        let bytes: Vec<String> = cipher.iter().map(|b| self.byte_num(rng, *b)).collect();
        let of = self.plain_num(off as u64);
        let stmt = match rng.range(0, 3) {
            0 => format!("if not {t}[{k}] then {t}[{k}]={d}({{{b}}},{o}) end; ",
                         t = self.tbl, k = kf, d = self.dec, b = bytes.join(","), o = of),
            1 => format!("if {t}[{k}] then else {t}[{k}]={d}({{{b}}},{o}) end; ",
                         t = self.tbl, k = kf, d = self.dec, b = bytes.join(","), o = of),
            _ => format!("if not {t}[{k}] then repeat {t}[{k}]={d}({{{b}}},{o}); break until false end; ",
                         t = self.tbl, k = kf, d = self.dec, b = bytes.join(","), o = of),
        };
        (stmt, format!("{}[{}]", self.tbl, kf))
    }
    /// ㉓.2 数字伪装：恒等变形（差式/和式/直值），正数、无下划线、0X 大写。
    /// ㉚④：v==0 禁走差式——(d-d) 是同字面量自抵消暴露形态，零值退直值。
    fn mask_num(&self, rng: &mut GenRng, v: u64) -> String {
        match rng.range(0, 3) {
            0 => format!("{}", v),
            1 => format!("0X{:X}", v),
            _ if v == 0 => format!("0X{:X}", v),
            _ => {
                let d = rng.range(1, 0x1000) as u64;
                if rng.range(0, 2) == 0 {
                    format!("(0X{:X}-0X{:X})", v + d, d)
                } else {
                    format!("({}-{})", v + d, d)
                }
            }
        }
    }
    /// 表 + 解码器声明（壳内一次；零字符串字面量）。
    /// ㉓.6 抗识别化：算式全部拆成单步碎片方法（任一语句都不含完整的
    /// LCG/键流/反馈形状），控制流改为键表+程序表**间接派发**——程序表是
    /// 一串随机数键，派发循环逐键取方法执行，循环回卷由其中一枚「回卷方法」
    /// 改写游标完成；无 if/elseif 状态链，静态读不出在算什么。
    pub fn emit_prelude(&self, rng: &mut GenRng) -> String {
        let (tb, of) = (rng.name(), rng.name());
        let (sv, drv, pl, dp, fv) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        // 状态表字段（含三枚中转槽 u/v/w、垃圾槽 z、游标 pc）
        let (f_n, f_i, f_g, f_d, f_o, f_k) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (f_u, f_v, f_w, f_z, f_pc) = (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        // 方法键去重池
        let mut used: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut nk = |rng: &mut GenRng| -> u32 {
            loop { let k = rng.range(0x0200_0000, 0x7FFF_FFFF) as u32; if used.insert(k) { return k; } }
        };
        let bnum = |rng: &mut GenRng, v: u32| -> String {
            if rng.range(0, 2) == 0 { format!("0X{:X}", v) } else { format!("{}", v) }
        };
        // 碎片方法：推进拆两段、键流拆两段、反馈拆两段，中转走槽
        let mn: Vec<String> = (0..13).map(|_| rng.name()).collect();
        let mk: Vec<u32> = (0..13).map(|_| nk(rng)).collect();
        let t = sv.clone();
        let defs_src: Vec<String> = vec![
            format!("{d}.{m}=function(_, {t}) {t}.{u}={t}.{n}*{ka} end; ", d = drv, t = t, m = mn[0], u = f_u, n = f_n, ka = self.k_a),
            format!("{d}.{m}=function(_, {t}) {t}.{n}=({t}.{u}+{kc})%{km} end; ", d = drv, t = t, m = mn[1], u = f_u, n = f_n, kc = self.k_c, km = self.k_m),
            format!("{d}.{m}=function(_, {t}) {t}.{v}=({t}.{g}+{t}.{i}+0X1)%{kb} end; ", d = drv, t = t, m = mn[2], v = f_v, g = f_g, i = f_i, kb = self.k_b),
            format!("{d}.{m}=function(_, {t}) {t}.{w}={t}.{n}%{kb} end; ", d = drv, t = t, m = mn[3], w = f_w, n = f_n, kb = self.k_b),
            format!("{d}.{m}=function(_, {t}) {t}.{k}=({t}.{w}+{q0}*{t}.{v}+{q1})%{kb} end; ", d = drv, t = t, m = mn[4], k = f_k, w = f_w, v = f_v, kb = self.k_b, q0 = self.plain_num(self.q0), q1 = self.plain_num(self.q1)),
            format!("{d}.{m}=function(_, {t}) {t}.{u}=({t}.{d2}[{t}.{i}+0X1]-{t}.{k})%{kb} end; ", d = drv, t = t, m = mn[5], u = f_u, d2 = f_d, i = f_i, k = f_k, kb = self.k_b),
            format!("{d}.{m}=function(_, {t}) {t}.{o}={t}.{o}..string.char({t}.{u}) end; ", d = drv, t = t, m = mn[6], o = f_o, u = f_u),
            format!("{d}.{m}=function(_, {t}) {t}.{v}={t}.{u}*{kp} end; ", d = drv, t = t, m = mn[7], v = f_v, u = f_u, kp = self.k_p),
            format!("{d}.{m}=function(_, {t}) {t}.{n}=({t}.{n}+{t}.{v}+{kq})%{km} end; ", d = drv, t = t, m = mn[8], n = f_n, v = f_v, kq = self.k_q, km = self.k_m),
            format!("{d}.{m}=function(_, {t}) {t}.{i}={t}.{i}+0X1 end; ", d = drv, t = t, m = mn[9], i = f_i),
            format!("{d}.{m}=function(_, {t}) {t}.{z}=(({t}.{z} or 0X0)+{t}.{n})%{kb} end; ", d = drv, t = t, m = mn[10], z = f_z, n = f_n, kb = self.k_b),
            format!("{d}.{m}=function(_, {t}) {t}.{w}=({t}.{w}+{t}.{i})-{t}.{i} end; ", d = drv, t = t, m = mn[11], w = f_w, i = f_i),
            String::new(), // 回卷方法稍后装配（依赖程序表长度）
        ];
        // 程序表：推导段（d_rounds 个推进对）+ 字节段（含两枚垃圾步）
        let mut prog: Vec<u32> = Vec::new();
        for _ in 0..self.d_rounds { prog.push(mk[0]); prog.push(mk[1]); }
        let loop_at = prog.len(); // 回卷目标（派发侧 +1 前的值）
        for &idx in &[0usize, 1, 2, 3, 4, 5, 10, 6, 7, 8, 11, 9] { prog.push(mk[idx]); }
        prog.push(mk[12]);
        let end_at = prog.len() + rng.range(5, 60);
        // 回卷方法：未读完 → 游标回字节段首；读完 → 游标越界（派发落空退出）
        let chk = format!("{d}.{m}=function(_, {t}) if {t}.{i}<#{t}.{d2} then {t}.{pc}={lv} else {t}.{pc}={ev} end end; ",
            d = drv, m = mn[12], t = t, i = f_i, d2 = f_d, pc = f_pc,
            lv = self.mask_num(rng, loop_at as u64), ev = self.mask_num(rng, end_at as u64));
        let mut defs = defs_src;
        defs[12] = chk;
        rng.shuffle(&mut defs);
        // 键表（条目洗牌）与程序表字面量
        let mut disp: Vec<String> = (0..13).map(|j| format!("[{}]={}.{}", bnum(rng, mk[j]), drv, mn[j])).collect();
        rng.shuffle(&mut disp);
        let prog_lit = prog.iter().map(|k| bnum(rng, *k)).collect::<Vec<_>>().join(",");
        // 常量局部：洗牌落位 + 伪装值
        let mut consts = vec![
            format!("local {}={}; ", self.k_b, self.mask_num(rng, 256)),
            format!("local {}={}; ", self.k_m, self.mask_num(rng, self.m)),
            format!("local {}={}; ", self.k_a, self.mask_num(rng, self.a)),
            format!("local {}={}; ", self.k_c, self.mask_num(rng, self.c)),
            format!("local {}={}; ", self.k_p, self.mask_num(rng, self.fb_mul)),
            format!("local {}={}; ", self.k_q, self.mask_num(rng, self.fb_add)),
        ];
        rng.shuffle(&mut consts);
        // 状态表构造（字段顺序也洗牌）
        let mut flds = vec![
            format!("{}=(({seed}+{of}*{dm})%{mm})", f_n, seed = self.mask_num(rng, self.seed), of = of, dm = self.mask_num(rng, self.d_mul), mm = self.k_m),
            format!("{}=0X0", f_i),
            format!("{}={}", f_g, of),
            format!("{}={}", f_d, tb),
            format!("{}=string.char()", f_o),
            format!("{}=0X1", f_pc),
        ];
        rng.shuffle(&mut flds);
        format!(
            "{consts}local {tt}={{}}; local {d}={{}}; {defs}local {pl}={{{prog}}}; local {dp}={{{disp}}}; local function {dec}({tb},{of}) local {s}={{ {flds} }}; while true do local {fv}={dp}[{pl}[{s}.{pc}]]; if {fv} then {fv}({d},{s}) {s}.{pc}={s}.{pc}+0X1 else break end end; if ({kb}-{kb})~=0X0 then {d}.{j}({d},{s}) end; return {s}.{o} end; ",
            consts = consts.join(""), tt = self.tbl, d = drv, defs = defs.join(""),
            pl = pl, prog = prog_lit, dp = dp, disp = disp.join(","),
            dec = self.dec, tb = tb, of = of, s = sv, flds = flds.join(","),
            fv = fv, pc = f_pc, kb = self.k_b, j = mn[10], o = f_o)
    }
}
