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
    // ㉓.2 高频数字（256/模数）提升为壳内局部常量，取用点只引名字
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
        // 每串按全流偏移/盐派生状态，且与生成 Lua 的耦合预热完全相同。
        let mut st = self.nat.state_at_offset(&self.stbl, off as u64, self.d_mul, self.d_rounds);
        let ciph = self.nat.encrypt_cont(&self.sbox, &mut st, b);
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
    /// 注册数值 for 的标准 Lua 5.1 错误文本；调用侧拿到惰性解密语句与取值表达式，
    /// 生成产物中只保留 UniStream 密文，不泄露错误消息明文。
    pub fn register_numeric_for_errors(&mut self, rng: &mut GenRng) -> [(String, String); 3] {
        [
            "'for' initial value must be a number",
            "'for' limit must be a number",
            "'for' step must be a number",
        ]
        .map(|message| {
            let id = self.register(message);
            self.fetch(rng, id)
        })
    }
    /// ㉓.2 数字字面量格式：逐构建随机选择十进制或大写十六进制，不做纯算术伪装。
    fn mask_num(&self, rng: &mut GenRng, v: u64) -> String {
        if rng.range(0, 2) == 0 {
            format!("{}", v)
        } else {
            format!("0X{:X}", v)
        }
    }
    /// 表 + 解码器声明（壳内一次；零字符串字面量）。
    /// ㉓.6 抗识别化：算式全部拆成单步碎片方法（任一语句都不含完整的
    /// 密钥流形状），控制流改为键表+程序表**间接派发**——程序表是
    /// 一串随机数键，派发循环逐键取方法执行，循环回卷由其中一枚「回卷方法」
    /// 改写游标完成；无 if/elseif 状态链，静态读不出在算什么。
    ///
    /// 密钥流内核（原生流）：S-box 由种子表在**运行期现场构造**（耦合 Fisher-Yates），
    /// 每字节掩码由双状态、位置与前一密文字节共同驱动；每串按偏移/盐起流。
    pub fn emit_prelude(&self, rng: &mut GenRng) -> String {
        use crate::VM::VM_Backend::Generator_native::{emit_sbox_builder, NMOD};

        // 内核声明负责指纹等价分支及运行期 S-box；状态/字节处理在下方与 Rust 镜像同式。
        let kern = emit_sbox_builder(rng, &self.nat, "uni");
        let (sb, fold1, fold2) = (kern.sb.clone(), kern.st1.clone(), kern.st2.clone());
        let stbl_name = rng.name();
        let seed_lits: Vec<String> = self.stbl.iter()
            .map(|v| self.mask_num(rng, *v as u64)).collect();
        let kdm = rng.name();
        let kb_decl = format!("local {}={}; local {}={}; ",
            self.k_b, self.mask_num(rng, 256), self.k_m, self.mask_num(rng, NMOD));
        let consts = format!("local {}={}; ", kdm, self.mask_num(rng, self.d_mul));
        let stbl_src = format!("{consts}local {stbl_name}={{{lits}}}; {call}; ",
            consts = consts, stbl_name = stbl_name, lits = seed_lits.join(","),
            call = format!("{}({})", kern.init_fn, stbl_name));

        let tt = self.tbl.clone();
        let drv = rng.name();
        let (sv, pl, dp, fv, pc, o, of, tb) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (f_s1, f_s2, f_tw, f_fb, f_ix, f_k, f_pos, f_prev, f_d2, f_z, f_w) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name(),
             rng.name(), rng.name(), rng.name(), rng.name(), rng.name());

        let mut used: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut fresh_key = |rng: &mut GenRng| -> u32 {
            loop {
                let k = rng.range(0x0200_0000, 0x7FFF_FFFF) as u32;
                if used.insert(k) { return k; }
            }
        };
        let method_names: Vec<String> = (0..11).map(|_| rng.name()).collect();
        let method_keys: Vec<u32> = (0..11).map(|_| fresh_key(rng)).collect();
        let bnum = |rng: &mut GenRng, v: u32| -> String {
            if rng.range(0, 2) == 0 { format!("0X{:X}", v) } else { format!("{}", v) }
        };
        let num = |rng: &mut GenRng, v: u64| self.mask_num(rng, v);
        let (m1, m2, m3, m4, m5, m6, m7, m8, i1, i2, mm, bb) = (
            num(rng, self.nat.m1), num(rng, self.nat.m2),
            num(rng, self.nat.m3), num(rng, self.nat.m4),
            num(rng, self.nat.m5), num(rng, self.nat.m6),
            num(rng, self.nat.m7), num(rng, self.nat.m8),
            num(rng, self.nat.i1), num(rng, self.nat.i2),
            self.k_m.clone(), self.k_b.clone(),
        );

        // Methods: offset prep, coupled transition, warmup prep, byte prep,
        // index, S-box lookup, output, ciphertext feedback, cursor, decoys, loop check.
        let mut defs: Vec<String> = vec![
            format!("{d}.{m}=function(_,{t}) {t}.{w}=({t}.{w}+0X1)-0X1 end; ",
                d=drv,m=method_names[0],t=sv,w=f_w),
            format!("{d}.{m}=function(_,{t}) local x={t}.{s1}; local y={t}.{s2}; local tw={t}.{tw}%{mm}; local fb={t}.{fb}; local nx=(x*((y%0X10000)+{m1})+y*{m2}+tw*{m3}+fb*{m4}+{i1})%{mm}; local ny=(y*((nx%0X10000)+{m5})+nx*{m6}+tw*{m7}+fb*{m8}+{i2})%{mm}; {t}.{s1}=nx; {t}.{s2}=ny end; ",
                d=drv,m=method_names[1],t=sv,s1=f_s1,s2=f_s2,tw=f_tw,fb=f_fb,mm=mm,
                m1=m1,m2=m2,m3=m3,m4=m4,m5=m5,m6=m6,m7=m7,m8=m8,i1=i1,i2=i2),
            format!("{d}.{m}=function(_,{t}) {t}.{tw}=0X1; {t}.{fb}=0X0 end; ",
                d=drv,m=method_names[2],t=sv,tw=f_tw,fb=f_fb),
            format!("{d}.{m}=function(_,{t}) {t}.{tw}={t}.{pos}+0X1; {t}.{fb}={t}.{prev} end; ",
                d=drv,m=method_names[3],t=sv,tw=f_tw,pos=f_pos,fb=f_fb,prev=f_prev),
            format!("{d}.{m}=function(_,{t}) {t}.{ix}=({t}.{s1}%{bb}+({t}.{s2}%{bb})*0X3+({t}.{pos}%{bb})*0X5+{t}.{prev}*0X7)%{bb} end; ",
                d=drv,m=method_names[4],t=sv,ix=f_ix,s1=f_s1,s2=f_s2,pos=f_pos,prev=f_prev,bb=bb),
            format!("{d}.{m}=function(_,{t}) {t}.{k}={sb}[{t}.{ix}+0X1] end; ",
                d=drv,m=method_names[5],t=sv,k=f_k,sb=sb,ix=f_ix),
            format!("{d}.{m}=function(_,{t}) {t}.{o}={t}.{o}..string.char(({t}.{d2}[{t}.{pos}+0X1]+{bb}-{t}.{k})%{bb}) end; ",
                d=drv,m=method_names[6],t=sv,o=o,d2=f_d2,pos=f_pos,k=f_k,bb=bb),
            format!("{d}.{m}=function(_,{t}) {t}.{prev}={t}.{d2}[{t}.{pos}+0X1] end; ",
                d=drv,m=method_names[7],t=sv,prev=f_prev,d2=f_d2,pos=f_pos),
            format!("{d}.{m}=function(_,{t}) {t}.{pos}={t}.{pos}+0X1 end; ",
                d=drv,m=method_names[8],t=sv,pos=f_pos),
            format!("{d}.{m}=function(_,{t}) {t}.{z}=({t}.{z}+{t}.{s1})%{bb}; {t}.{w}=({t}.{w}+{t}.{pos})-{t}.{pos} end; ",
                d=drv,m=method_names[9],t=sv,z=f_z,s1=f_s1,bb=bb,w=f_w,pos=f_pos),
            String::new(),
        ];

        // 初始化：先把全流 offset 与 salt 混入；随后 d_rounds 轮 (1,0) 耦合预热。
        let mut prog: Vec<u32> = vec![method_keys[0], method_keys[1], method_keys[2]];
        for _ in 0..self.d_rounds { prog.push(method_keys[1]); }
        let loop_at = prog.len() + 1;
        for &idx in &[3usize, 1, 4, 5, 6, 7, 8, 9, 10] {
            prog.push(method_keys[idx]);
        }
        let end_at = prog.len() + rng.range(5, 60);
        defs[10] = format!("{d}.{m}=function(_,{t}) if {t}.{pos}<#{t}.{d2} then {t}.{pc}={loop_at} else {t}.{pc}={end_at} end end; ",
            d=drv,m=method_names[10],t=sv,pos=f_pos,d2=f_d2,pc=pc,
            loop_at=self.mask_num(rng,(loop_at-1) as u64),end_at=self.mask_num(rng,end_at as u64));
        rng.shuffle(&mut defs);
        let mut disp: Vec<String> = (0..11)
            .map(|j| format!("[{}]={}.{}", bnum(rng,method_keys[j]),drv,method_names[j]))
            .collect();
        rng.shuffle(&mut disp);
        let prog_lit = prog.iter().map(|k| bnum(rng,*k)).collect::<Vec<_>>().join(",");

        let mut flds = vec![
            format!("{}={}",f_s1,fold1), format!("{}={}",f_s2,fold2),
            format!("{}={}",f_tw,of), format!("{}={}",f_fb,kdm),
            format!("{}=0X0",f_ix), format!("{}=0X0",f_k),
            format!("{}=0X0",f_pos), format!("{}=0X0",f_prev),
            format!("{}={}",f_d2,tb), format!("{}=string.char()",o),
            format!("{}=0X0",f_z), format!("{}=0X0",f_w), format!("{}=0X1",pc),
        ];
        rng.shuffle(&mut flds);
        format!(
            "{kbd}local {dec}; do {kdecl}{stbl}{tt}={{}}; local {d}={{}}; {defs}local {pl}={{{prog}}}; local {dp}={{{disp}}}; {dec}=function({tb},{of}) local {s}={{{flds}}}; while true do local {fv}={dp}[{pl}[{s}.{pc}]]; if {fv} then {fv}({d},{s}); {s}.{pc}={s}.{pc}+0X1 else break end end; if {s}.{z}>{bb} then {d}.{noop}({d},{s}) end; return {s}.{o} end; end; ",
            kbd=kb_decl,kdecl=kern.decl,stbl=stbl_src,tt=tt,d=drv,defs=defs.join(""),
            pl=pl,prog=prog_lit,dp=dp,disp=disp.join(","),dec=self.dec,tb=tb,of=of,
            s=sv,flds=flds.join(","),fv=fv,pc=pc,z=f_z,bb=self.k_b,noop=method_names[9],o=o)
    }
}

#[cfg(test)]
mod custom_unistream_tests {
    use super::UniStream;
    use crate::VM::VM_Backend::Generator_util::GenRng;
    use std::path::Path;
    use std::process::Command;

    fn table(bytes: &[u8]) -> String {
        bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
    }

    #[test]
    fn emitted_unistream_matches_rust_cipher_for_offset_entries() {
        let lua = Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() { return; }
        let mut rng = GenRng::new(0x51_7EA_123);
        let mut stream = UniStream::new(&mut rng);
        let first: Vec<u8> = (0..=255).collect();
        let second: Vec<u8> = b"offset-bound entry with binary tail\0\xFF".to_vec();
        let id0 = stream.register_bytes(&first);
        let id1 = stream.register_bytes(&second);
        let (stmt0, expr0) = stream.fetch(&mut rng, id0);
        let (stmt1, expr1) = stream.fetch(&mut rng, id1);
        let prelude = stream.emit_prelude(&mut rng);
        let script = format!(
            "{prelude}{stmt0} local a={expr0}; {stmt1} local b={expr1}; local pa={{{pa}}}; local pb={{{pb}}}; assert(#a==#pa and #b==#pb); for i=1,#pa do assert(string.byte(a,i)==pa[i],i) end; for i=1,#pb do assert(string.byte(b,i)==pb[i],i) end; print('UNISTREAM_OK')",
            prelude=prelude,stmt0=stmt0,expr0=expr0,stmt1=stmt1,expr1=expr1,
            pa=table(&first),pb=table(&second));
        let out = Command::new(lua).arg("-e").arg(script).output().expect("run bundled Lua 5.1");
        assert!(out.status.success(), "UniStream Lua failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("UNISTREAM_OK"));
    }

    #[test]
    fn numeric_for_error_texts_are_lazily_emitted_without_plaintext() {
        let lua = Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() { return; }
        let expected = [
            "'for' initial value must be a number",
            "'for' limit must be a number",
            "'for' step must be a number",
        ];
        let mut rng = GenRng::new(0xF04_5EA_123);
        let mut stream = UniStream::new(&mut rng);
        let entries = stream.register_numeric_for_errors(&mut rng);
        let mut script = stream.emit_prelude(&mut rng);
        for (stmt, expr) in entries {
            script.push_str(&stmt);
            script.push_str(&format!("print({expr});"));
        }
        for message in expected {
            assert!(!script.contains(message), "plaintext message in emitted UniStream");
        }
        let out = Command::new(lua).arg("-e").arg(script).output().expect("run bundled Lua 5.1");
        assert!(out.status.success(), "numeric-for UniStream failed: {}", String::from_utf8_lossy(&out.stderr));
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let actual: Vec<_> = stdout.lines().collect();
        assert_eq!(actual, expected.to_vec());
    }
}
