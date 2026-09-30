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
    k_b: String, k_m: String,
    seed: u64, d_mul: u64, d_rounds: u64,
    // 原生流（Native Stream）内核：参数 + 种子表 + 运行期 S-box 的 Rust 镜像
    nat: crate::VM::VM_Backend::Generator_native::Native,
    stbl: [u8; 16],
    sbox: [u8; 256],
    cur: u64,
    enc: Vec<u8>,
    entries: Vec<(Vec<u8>, usize)>, // (密文字节, 全流偏移)
    used: std::collections::HashSet<u32>,
}

impl UniStream {
    pub fn new(rng: &mut GenRng) -> Self {
        let nat = crate::VM::VM_Backend::Generator_native::Native::new(rng);
        let seed = rng.range(1, 0x7FFF_FFFF) as u64;
        let d_mul = rng.range(1, 0x1_0000) as u64;
        let d_rounds = rng.range(4, 16) as u64;
        // 种子表：16 个字节值由 seed 逐位铺开（运行期以混写数字落盘，
        // S-box 由这份种子**现场构造**，产物里不存在 S-box 数据）
        let mut stbl = [0u8; 16];
        {
            // splitmix 式逐字铺开：16 字节互不重复，单字节不泄露种子结构
            let mut v = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03;
            for b in stbl.iter_mut() {
                v ^= v >> 30;
                v = v.wrapping_mul(0xBF58_476D_1CE4_E5B9);
                v ^= v >> 27;
                v = v.wrapping_mul(0x94D0_49BB_1331_11EB);
                *b = (v ^ (v >> 31)) as u8;
            }
        }
        let sbox = nat.sbox(&stbl);
        Self { tbl: rng.name(), dec: rng.name(),
               k_b: rng.name(), k_m: rng.name(),
               seed, d_mul, d_rounds, nat, stbl, sbox,
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
        self.register_bytes(plain.as_bytes())
    }
    /// 同上，但吃原始字节（字母表/数字映射表里有 0XFF 这类非 UTF-8 字节）。
    pub fn register_bytes(&mut self, plain: &[u8]) -> usize {
        let b = plain;
        let off = self.enc.len();
        // 起始状态 = 种子表折叠值 + 偏移混合；再走 d_rounds 步推导
        // （与运行期机器里 warmup 段逐位一致）
        let base = self.nat.state(&self.stbl);
        let mut s1 = (base.s1 + (off as u64) * self.d_mul) % crate::VM::VM_Backend::Generator_native::NMOD;
        let mut s2 = (base.s2 + (off as u64) * self.d_mul) % crate::VM::VM_Backend::Generator_native::NMOD;
        for _ in 0..self.d_rounds {
            s1 = (s1.wrapping_mul(self.nat.a1).wrapping_add(self.nat.c1)) % crate::VM::VM_Backend::Generator_native::NMOD;
            s2 = (s2.wrapping_mul(self.nat.a2).wrapping_add(self.nat.c2)) % crate::VM::VM_Backend::Generator_native::NMOD;
        }
        let mut pos: u64 = 0;
        let mut prev: u64 = 0;
        let mut ciph = Vec::with_capacity(b.len());
        for &p in b.iter() {
            s1 = (s1.wrapping_mul(self.nat.a1).wrapping_add(self.nat.c1)) % crate::VM::VM_Backend::Generator_native::NMOD;
            s2 = (s2.wrapping_mul(self.nat.a2).wrapping_add(self.nat.c2)) % crate::VM::VM_Backend::Generator_native::NMOD;
            let idx = ((s1 % 256) + (s2 % 256) + pos + prev) % 256;
            let k = self.sbox[idx as usize] as u64;
            let c = ((p as u64) + k) % 256;
            pos += 1;
            prev = c;
            ciph.push(c as u8);
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
    /// 密钥流形状），控制流改为键表+程序表**间接派发**——程序表是
    /// 一串随机数键，派发循环逐键取方法执行，循环回卷由其中一枚「回卷方法」
    /// 改写游标完成；无 if/elseif 状态链，静态读不出在算什么。
    ///
    /// 密钥流内核（原生流）：S-box 由种子表在**运行期现场构造**（Fisher-Yates），
    /// 每字节密钥 = 双 LCG 状态 + 位置 + 前一密文字节 混合后查该 S-box；
    /// 每串各自按偏移起流，互不相关。
    pub fn emit_prelude(&self, rng: &mut GenRng) -> String {
        use crate::VM::VM_Backend::Generator_native::{NMOD, emit_sbox_builder};
        // S-box 构造件（指纹 + kinit）；sb / st1 / st2 作为 upvalue 供方法与解码器复用
        let kern = emit_sbox_builder(rng, &self.nat, "uni");
        let (sb, fold1, fold2) = (kern.sb.clone(), kern.st1.clone(), kern.st2.clone());

        // 种子表：混写数字落盘（运行期据此折叠 + 造 S-box）
        let stbl_name = rng.name();
        let mut seed_lits: Vec<String> = Vec::new();
        for i in 0..16 {
            let v = self.stbl[i] as u64;
            seed_lits.push(self.mask_num(rng, v));
        }
        // 注意：种子表字节顺序参与折叠（顺序敏感），不可洗牌。
        let kdm = rng.name();
        // ㉓.2 高频数字（256/模数）提升为**壳函数作用域**局部常量：解密器/方法/壳内
        // 各取用点（嵌套函数里的密文数组换算）都只引名字；种子倍数只在机器内部用，
        // 与内核局部一起留在 do 块里。
        let kb_decl = format!("local {}={}; local {}={}; ",
            self.k_b, self.mask_num(rng, 256), self.k_m, self.mask_num(rng, NMOD));
        let mut consts = vec![
            format!("local {}={}; ", kdm, self.mask_num(rng, self.d_mul)),
        ];
        rng.shuffle(&mut consts);
        let stbl_src = format!("{consts}local {stbl_name}={{{lits}}}; {call}; ",
            consts = consts.join(""), stbl_name = stbl_name, lits = seed_lits.join(","),
            call = format!("{}({})", kern.init_fn, stbl_name));

        let tt = self.tbl.clone();
        let drv = rng.name();
        let (sv, pl, dp, fv, pc, o, of, tb) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        // 状态表字段（含中转槽 ix/k、垃圾槽 z/w）
        let (f_s1, f_s2, f_ix, f_k, f_pos, f_prev, f_d2, f_z, f_w) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let mut used: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut nk = |rng: &mut GenRng| -> u32 {
            loop { let k = rng.range(0x0200_0000, 0x7FFF_FFFF) as u32; if used.insert(k) { return k; } }
        };
        let bnum = |rng: &mut GenRng, v: u32| -> String {
            if rng.range(0, 2) == 0 { format!("0X{:X}", v) } else { format!("{}", v) }
        };
        let mn: Vec<String> = (0..10).map(|_| rng.name()).collect();
        let mk: Vec<u32> = (0..10).map(|_| nk(rng)).collect();
        let t = sv.clone();
        let num = |rng: &mut GenRng, v: u64| self.mask_num(rng, v);
        let (a1, c1, a2, c2, mm, bb) = (
            num(rng, self.nat.a1), num(rng, self.nat.c1),
            num(rng, self.nat.a2), num(rng, self.nat.c2),
            self.k_m.clone(), self.k_b.clone(),
        );
        let defs_src: Vec<String> = vec![
            format!("{d}.{m}=function(_,{t}) {t}.{s1}=({t}.{s1}*{a1}+{c1})%{mm} end; ", d = drv, t = t, m = mn[0], s1 = f_s1, a1 = a1, c1 = c1, mm = mm),
            format!("{d}.{m}=function(_,{t}) {t}.{s2}=({t}.{s2}*{a2}+{c2})%{mm} end; ", d = drv, t = t, m = mn[1], s2 = f_s2, a2 = a2, c2 = c2, mm = mm),
            format!("{d}.{m}=function(_,{t}) {t}.{ix}=({t}.{s1}%{bb}+{t}.{s2}%{bb}+{t}.{pos}+{t}.{prev})%{bb} end; ", d = drv, t = t, m = mn[2], ix = f_ix, s1 = f_s1, s2 = f_s2, pos = f_pos, prev = f_prev, bb = bb),
            format!("{d}.{m}=function(_,{t}) {t}.{k}={sb}[{t}.{ix}+0X1] end; ", d = drv, t = t, m = mn[3], k = f_k, sb = sb, ix = f_ix),
            format!("{d}.{m}=function(_,{t}) {t}.{o}={t}.{o}..string.char(({t}.{d2}[{t}.{pos}+0X1]-{t}.{k})%{bb}) end; ", d = drv, t = t, m = mn[4], o = o, d2 = f_d2, pos = f_pos, k = f_k, bb = bb),
            format!("{d}.{m}=function(_,{t}) {t}.{prev}={t}.{d2}[{t}.{pos}+0X1] end; ", d = drv, t = t, m = mn[5], prev = f_prev, d2 = f_d2, pos = f_pos),
            format!("{d}.{m}=function(_,{t}) {t}.{pos}={t}.{pos}+0X1 end; ", d = drv, t = t, m = mn[6], pos = f_pos),
            format!("{d}.{m}=function(_,{t}) {t}.{z}=(({t}.{z} or 0X0)+{t}.{s1})%{bb} end; ", d = drv, t = t, m = mn[7], z = f_z, s1 = f_s1, bb = bb),
            format!("{d}.{m}=function(_,{t}) {t}.{w}=({t}.{w}+{t}.{pos})-{t}.{pos} end; ", d = drv, t = t, m = mn[8], w = f_w, pos = f_pos),
            String::new(), // 回卷方法稍后装配（依赖程序表长度）
        ];
        // 程序表：推导段（d_rounds 个推进对）+ 字节段（含两枚垃圾步）
        let mut prog: Vec<u32> = Vec::new();
        for _ in 0..self.d_rounds { prog.push(mk[0]); prog.push(mk[1]); }
        let loop_at = prog.len() + 1; // `pc` 是 1-based 游标
        for &idx in &[0usize, 1, 2, 3, 4, 5, 6, 7, 8] { prog.push(mk[idx]); }
        prog.push(mk[9]);
        let end_at = prog.len() + rng.range(5, 60);
        let chk = format!("{d}.{m}=function(_,{t}) if {t}.{pos}<#{t}.{d2} then {t}.{pc}={lv} else {t}.{pc}={ev} end end; ",
            d = drv, m = mn[9], t = t, pos = f_pos, d2 = f_d2, pc = pc,
            lv = self.mask_num(rng, (loop_at - 1) as u64), ev = self.mask_num(rng, end_at as u64));
        let mut defs = defs_src;
        defs[9] = chk;
        rng.shuffle(&mut defs);
        let mut disp: Vec<String> = (0..10).map(|j| format!("[{}]={}.{}", bnum(rng, mk[j]), drv, mn[j])).collect();
        rng.shuffle(&mut disp);
        let prog_lit = prog.iter().map(|k| bnum(rng, *k)).collect::<Vec<_>>().join(",");
        // 状态表构造（字段顺序也洗牌）
        let mut flds = vec![
            format!("{}=({}+({}*{})%{})%{mm}", f_s1, fold1, of, kdm, mm, mm = mm),
            format!("{}=({}+({}*{})%{})%{mm}", f_s2, fold2, of, kdm, mm, mm = mm),
            format!("{}=0X0", f_ix),
            format!("{}=0X0", f_k),
            format!("{}=0X0", f_pos),
            format!("{}=0X0", f_prev),
            format!("{}={}", f_d2, tb),
            format!("{}=string.char()", o),
            format!("{}=0X0", f_z),
            format!("{}=0X0", f_w),
            format!("{}=0X1", pc),
        ];
        rng.shuffle(&mut flds);
        format!(
            // 整段前导落在独立 do 块内：块内局部（内核/常量/方法名/程序表/调度表/
            // 状态字段名）随块结束释放——壳函数活动局部数不被撑爆（lua5.1 上限 200），
            // 解密器与各方法以 upvalue 捕获它们，块外只暴露解密器一个名字。
            "{kbd}local {dec}; do {kdecl}{stbl}{tt}={{}}; local {d}={{}}; {defs}local {pl}={{{prog}}}; local {dp}={{{disp}}}; {dec}=function({tb},{of}) local {s}={{ {flds} }}; while true do local {fv}={dp}[{pl}[{s}.{pc}]]; if {fv} then {fv}({d},{s}) {s}.{pc}={s}.{pc}+0X1 else break end end; if {s}.{prv} > {kb} then {d}.{j}({d},{s}) end; return {s}.{o} end; end; ",
            kbd = kb_decl, kdecl = kern.decl, stbl = stbl_src, tt = tt, d = drv, defs = defs.join(""),
            pl = pl, prog = prog_lit, dp = dp, disp = disp.join(","),
            dec = self.dec, tb = tb, of = of, s = sv, flds = flds.join(","),
            fv = fv, pc = pc, kb = self.k_b, prv = f_prev, j = mn[7], o = o)
    }
}
