//! MB 自解压外壳：DP/LZ 压缩 + base85 编码 + 一层自己解压自己的 Lua 外壳。
//!
//! 算法来自用户上传的 `压缩.rs`（要求：只用算法本身，不要原版的水印与错误码文本）。
//! 相对原版这里的差异：
//!   * 自带 sfc64 随机源，不依赖仓库里没有的 `crate::random`；
//!   * `wrap` 不再返回 `Result<_, Diagnostic>`，压不出收益时返回 `None`；
//!   * 交付前做「词法单行化 + 局部名随机化」（产物要保持极少的物理行数，
//!     VM 里的反美化守卫依赖这一点）；
//!   * 去掉原版的 `"XXS ..."` 标记与 e1..e9 错误码文本。

#![allow(dead_code)]

/// ⑥ 位置权重伪装式：字节拼装 X*256+Y 的 256 是高/低字节位置权重，值必须
/// 保持 256——用三种恒等式随机伪装（差式/差拆式/和式），P() 求值序不变
fn w256() -> String {
    let r = &mut rand::rng();
    match rand::Rng::random_range(r, 0..3) {
        0 => { let k: u32 = rand::Rng::random_range(r, 0x1100..0xFFFFF); format!("(0X{:X} - 0X{:X})", k, k - 0x100) }
        1 => { let k: u32 = rand::Rng::random_range(r, 0x1100..0xFFFFF); format!("(0X{:X} - (0X{:X} + 0XF))", k, k - 0x100 - 0xF) }
        _ => { let a: u32 = rand::Rng::random_range(r, 0x10..0xF0); format!("(0X{:X} + 0X{:X})", a, 0x100 - a) }
    }
}

// ────────────────────────── 内部随机源 ──────────────────────────

/// sfc64。只为「种子化 cost 模型 / 置换 base85 字母表 / 外壳里的随机名」服务，
/// 不承担任何保密职责（载荷的保密由 VM 那侧的 ChaCha 负责）。
struct Rng {
    a: u64,
    b: u64,
    c: u64,
    k: u64,
}

impl Rng {
    fn seeded(seed: u64) -> Self {
        let mut s = seed ^ 0x2545_F491_4F6C_DD1D;
        let mut step = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let (a, b, c) = (step(), step(), step());
        Self { a, b, c, k: 1 }
    }

    fn next(&mut self) -> u64 {
        let tmp = self.a.wrapping_add(self.b).wrapping_add(self.k);
        self.k = self.k.wrapping_add(1);
        self.a = self.b ^ (self.b >> 11);
        self.b = self.c.wrapping_add(self.c << 3);
        self.c = tmp.rotate_left(24).wrapping_add(self.c);
        tmp
    }

    fn index(&mut self, n: u32) -> u32 {
        (self.next() % n as u64) as u32
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.index((i + 1) as u32) as usize;
            v.swap(i, j);
        }
    }

    /// 1–2 字符的标识符（与仓库其它生成器同一风格）。
    fn name(&mut self) -> String {
        const HEAD: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        const TAIL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
        let n = 1 + (self.index(3) != 0) as usize;
        let mut s = String::with_capacity(n);
        s.push(HEAD[self.index(HEAD.len() as u32) as usize] as char);
        for _ in 1..n {
            s.push(TAIL[self.index(TAIL.len() as u32) as usize] as char);
        }
        s
    }
}

/// 一个 LZ token：裸字节，或引用 `stride` 之前开始的 `span` 个字节。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Raw,
    Link { stride: u16, span: u32 },
}

const MAX_SPAN: usize = 4096;
const MAX_STRIDE: usize = 65535;

/// 每个位置最多检查多少个相同 hash 的历史位置。1 MB 以下、偏重压缩率的取值。
const MAX_CANDIDATES: usize = 96;

/// 4 字节 hash。Link 最短是 3，但 4-byte hash 对 Lua 文本的过滤效果明显更好；
/// 最后不足 4 字节的位置用 3-byte hash 单独处理。
const HASH_BITS: usize = 17;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NONE: usize = usize::MAX;

#[inline]
fn length_bytes(base: u32) -> u32 {
    base / 255 + 1
}

#[inline]
fn hash4(input: &[u8], pos: usize) -> usize {
    let value = (input[pos] as u32)
        | ((input[pos + 1] as u32) << 8)
        | ((input[pos + 2] as u32) << 16)
        | ((input[pos + 3] as u32) << 24);
    // 简单整数 avalanche，作为 LZ hash 足够。
    let mut x = value;
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    (x as usize) & (HASH_SIZE - 1)
}

#[inline]
fn hash3(input: &[u8], pos: usize) -> usize {
    let value =
        (input[pos] as u32) | ((input[pos + 1] as u32) << 8) | ((input[pos + 2] as u32) << 16);
    let mut x = value;
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    (x as usize) & (HASH_SIZE - 1)
}
/// DP/LZ 压缩器。两个字段是 cost 模型（bit 计），默认值就是原算法的 9 / 17。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compressor {
    pub raw_bits: u32,
    pub link_base_bits: u32,
}

impl Default for Compressor {
    fn default() -> Self {
        Self {
            raw_bits: 9,
            link_base_bits: 17,
        }
    }
}

impl Compressor {
    /// 种子化：只在 ±1 bit 内扰动 cost 模型。正确性与这无关，变的只是等价解之间的选择。
    pub fn seeded(seed: u64) -> Self {
        let mut rng = Rng::seeded(seed ^ 0x7368_656c_6c5f_6c7a);
        // (8..=10) / (16..=18)：只在 ±1 bit 内动 cost 模型，只影响等价解之间的选择。
        let raw_bits = (9i64 + rng.index(3) as i64 - 1) as u32;
        let link_base_bits = (17i64 + rng.index(3) as i64 - 1) as u32;
        Self {
            raw_bits,
            link_base_bits,
        }
    }

    pub fn compress(input: &[u8]) -> Vec<u8> {
        Self::default().compress_with(input)
    }

    pub fn compress_with(&self, input: &[u8]) -> Vec<u8> {
        let len = input.len();
        if len == 0 {
            return Vec::new();
        }

        // costs[i]: 压缩 input[0..i] 的最低估算 bit cost；links[i]: 到达 i 的最后一步。
        let mut costs = vec![u32::MAX; len + 1];
        let mut links = vec![Step::Raw; len + 1];
        costs[0] = 0;

        // Hash chain：head* 是该 hash 最近一次出现位置，prev*[pos] 是同 hash 的上一个位置。
        let mut head4 = vec![NONE; HASH_SIZE];
        let mut prev4 = vec![NONE; len];
        let mut head3 = vec![NONE; HASH_SIZE];
        let mut prev3 = vec![NONE; len];
        // 复用同一块 scratch（每轮 1..=peak_span 都会被本轮重写，不存在陈旧读）。
        let mut optimal_strides = vec![0u16; MAX_SPAN + 1];

        for i in 0..len {
            // ---- RAW ----
            if costs[i] != u32::MAX {
                let raw_cost = costs[i].saturating_add(self.raw_bits);
                if raw_cost < costs[i + 1] {
                    costs[i + 1] = raw_cost;
                    links[i + 1] = Step::Raw;
                }
            }

            let mut peak_span = 0usize;

            // ---- LINK：优先 4-byte hash chain ----
            if costs[i] != u32::MAX && i + 3 <= len {
                let max_span = MAX_SPAN.min(len - i);
                if max_span >= 4 {
                    let h = hash4(input, i);
                    let mut candidate = head4[h];
                    let mut checked = 0usize;
                    while candidate != NONE && checked < MAX_CANDIDATES {
                        debug_assert!(candidate < i);
                        let stride = i - candidate;
                        // 链从新到旧，一旦超过 MAX_STRIDE 后面的只会更老，直接停。
                        if stride > MAX_STRIDE {
                            break;
                        }
                        // hash 有碰撞，所以仍然验证前 4 字节。
                        if input[candidate..candidate + 4] == input[i..i + 4] {
                            let mut span = 4usize;
                            while span < max_span && input[candidate + span] == input[i + span] {
                                span += 1;
                            }
                            // 只有刷新最长匹配才回填：candidate B 匹配 50，那它对 21..50
                            // 同样是合法引用。
                            if span > peak_span {
                                let stride_u16 = stride as u16;
                                for l in (peak_span + 1)..=span {
                                    optimal_strides[l] = stride_u16;
                                }
                                peak_span = span;
                                if peak_span == max_span {
                                    break;
                                }
                            }
                        }
                        candidate = prev4[candidate];
                        checked += 1;
                    }
                }

                // ---- 3-byte fallback ----
                // 没找到 >=4 的匹配时才查 3-byte 链；已找到时 span=3 用同一个 stride 即可。
                if peak_span < 4 {
                    let h = hash3(input, i);
                    let mut candidate = head3[h];
                    let mut checked = 0usize;
                    while candidate != NONE && checked < MAX_CANDIDATES {
                        let stride = i - candidate;
                        if stride > MAX_STRIDE {
                            break;
                        }
                        if input[candidate..candidate + 3] == input[i..i + 3] {
                            let mut span = 3usize;
                            while span < max_span && input[candidate + span] == input[i + span] {
                                span += 1;
                            }
                            if span > peak_span {
                                let stride_u16 = stride as u16;
                                for l in (peak_span + 1)..=span {
                                    optimal_strides[l] = stride_u16;
                                }
                                peak_span = span;
                                if peak_span == max_span {
                                    break;
                                }
                            }
                        }
                        candidate = prev3[candidate];
                        checked += 1;
                    }
                }

                // ---- 完整 DP：3..=peak_span 全都参与，不剪枝 ----
                for span_l in 3..=peak_span {
                    let stride = optimal_strides[span_l];
                    if stride == 0 {
                        continue;
                    }
                    let base = (span_l - 3) as u32;
                    let link_cost =
                        costs[i].saturating_add(self.link_base_bits + 8 * length_bytes(base));
                    let next_pos = i + span_l;
                    if link_cost < costs[next_pos] {
                        costs[next_pos] = link_cost;
                        links[next_pos] = Step::Link {
                            stride,
                            span: span_l as u32,
                        };
                    }
                }
            }

            // 插入当前位置：必须在搜索之后，否则当前位置匹配到自己、stride 变 0。
            if i + 4 <= len {
                let h = hash4(input, i);
                prev4[i] = head4[h];
                head4[h] = i;
            }
            if i + 3 <= len {
                let h = hash3(input, i);
                prev3[i] = head3[h];
                head3[h] = i;
            }
        }

        // ---- 重建最佳路径 ----
        let mut route = Vec::new();
        let mut cursor = len;
        while cursor > 0 {
            match links[cursor] {
                Step::Raw => {
                    route.push(Step::Raw);
                    cursor -= 1;
                }
                Step::Link { stride, span } => {
                    route.push(Step::Link { stride, span });
                    cursor -= span as usize;
                }
            }
        }
        route.reverse();

        // ---- 输出：每 8 个 token 一个 header，bit=1 是 Raw ----
        let mut output = Vec::with_capacity(len);
        let mut route_head = 0usize;
        let mut read_head = 0usize;
        while route_head < route.len() {
            let mut header = 0u8;
            let mut payload = Vec::with_capacity(32);
            for bit in 0..8 {
                if route_head >= route.len() {
                    break;
                }
                match route[route_head] {
                    Step::Raw => {
                        header |= 1 << bit;
                        payload.push(input[read_head]);
                        read_head += 1;
                    }
                    Step::Link { stride, span } => {
                        payload.push((stride >> 8) as u8);
                        payload.push(stride as u8);
                        let mut base = span - 3;
                        while base >= 255 {
                            payload.push(255);
                            base -= 255;
                        }
                        payload.push(base as u8);
                        read_head += span as usize;
                    }
                }
                route_head += 1;
            }
            output.push(header);
            output.extend_from_slice(&payload);
        }
        debug_assert_eq!(read_head, input.len());
        output
    }
}

/// 外壳头部：5 字节解压长度 + 2×2 字节折叠初值 + 2×2 字节期望值。

const HEADER_LEN: usize = 13;
const ADLER_MOD: u64 = 65_447;

/// z85 的 85 枚可打印符号（RFC1924 base85 的同族变体）：不含 `"` `'` `\` `[` `]` ⇒ 长括号字面量里零转义，
/// 也永远不会出现 `]]`。这里再按种子做一次置换，使通用 base85 解码器读不出来。
pub fn base85_alphabet(seed: u64) -> [u8; 85] {
    // z85 的符号集。它与 RFC1924 的 base85 只差标点：刻意不含 `"` `'` `\` `[` `]` `.` `/`
    // `:` `,`，因为负载要裸写进 `[[ ]]` 长括号字面量——能拼出 `]]` 或需要转义的符号一律不要。
    const Z85: &[u8; 85] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let mut alphabet = *Z85;
    let mut rng = Rng::seeded(seed ^ 0x7368_656c_6c5f_6238);
    rng.shuffle(&mut alphabet);
    alphabet
}

/// 4 字节一组（末尾零填充到 4 的倍数）编码成大端 5 字符组。
fn base85_encode(data: &[u8], alphabet: &[u8; 85]) -> Vec<u8> {
    let groups = data.len().div_ceil(4);
    let mut out = Vec::with_capacity(groups * 5);
    for index in 0..groups {
        let mut value = 0u64;
        for offset in 0..4 {
            let byte = data.get(index * 4 + offset).copied().unwrap_or(b'\0'); // 零填充：长度在头部已给出，多出来的字节被忽略
            value = (value << 8) | u64::from(byte);
        }
        let mut digits = [0u8; 5];
        for slot in (0..5).rev() {
            digits[slot] = (value % 85) as u8;
            value /= 85;
        }
        for digit in digits {
            out.push(alphabet[digit as usize]);
        }
    }
    out
}

fn fold_lanes(data: &[u8], a: u64, c: u64) -> (u64, u64) {
    let (mut a, mut c) = (a, c);
    for &byte in data {
        a = (a + u64::from(byte)) % ADLER_MOD;
        c = (c + a) % ADLER_MOD;
    }
    (a, c)
}

fn push_be(out: &mut Vec<u8>, value: u64, bytes: usize) {
    for index in (0..bytes).rev() {
        out.push(((value >> (8 * index)) & 0xff) as u8);
    }
}


/// 压缩 + base85 之后的负载，以及它的尺寸账（供报告与门使用）。
#[derive(Clone, Debug)]
pub struct Shell {
    /// 成品脚本：一层自解码外壳，`loadstring` 出原脚本再执行。
    pub script: String,
    pub source_bytes: usize,
    pub compressed_bytes: usize,
    pub encoded_bytes: usize,
}

/// 把已经生成好的最终脚本包一层压缩外壳。
///
/// 压不出收益（负载 + 固定开销不比原文小）时返回 `None`，调用方回退到未压缩产物。
/// 原版还会先把输入按目标解析一遍，这里省掉：调用方拿到的本来就是已经跑过
/// 解析/改写管线的脚本，交付前我们另外用 lua5.1 与 luau 各过一遍语法。
pub fn wrap(source: &str, seed: u64) -> Option<Shell> {
    let data = source.as_bytes();
    if data.is_empty() {
        return None;
    }
    let compressor = Compressor::seeded(seed);
    let body = compressor.compress_with(data);

    // 头：长度（5B）+ 折叠初值（2B + 2B）+ 期望值（2B + 2B）。初值取自种子，
    // 于是把别的种子的负载插进这份外壳会在 loadstring 之前死掉。
    // 两枚初值都落在 1..=65,446 ⇒ 与 Lua 侧每步 `% 65447` 的取值域一致。
    let a_init = 1 + seed % (ADLER_MOD - 1);
    let c_init = 1 + (seed >> 32) % (ADLER_MOD - 1);
    let (a_end, c_end) = fold_lanes(data, a_init, c_init);
    let mut stream = Vec::with_capacity(HEADER_LEN + body.len());
    push_be(&mut stream, data.len() as u64, 5);
    push_be(&mut stream, a_init, 2);
    push_be(&mut stream, c_init, 2);
    push_be(&mut stream, a_end, 2);
    push_be(&mut stream, c_end, 2);
    stream.extend_from_slice(&body);

    let alphabet = base85_alphabet(seed);
    let encoded: Vec<u8> = base85_encode(&stream, &alphabet);
    let payload = String::from_utf8(encoded).ok()?;
    // 1024 是外壳正文的量级；比原文不小就没必要套。
    if payload.len() + 1024 >= data.len() {
        return None;
    }

    let mut rng = Rng::seeded(seed ^ 0x9E37_79B9_7F4A_7C15);
    let script = finalize(&emit_shell(&payload, &alphabet), &mut rng);
    Some(Shell {
        script,
        source_bytes: data.len(),
        compressed_bytes: stream.len(),
        encoded_bytes: payload.len(),
    })
}

// ──────────────── 外壳交付前的单行化 + 局部名随机化 ────────────────
//
// 产物要保持「极少的物理行数」：VM 里的反美化守卫就是拿「同一物理行上定义的函数
// linedefined 必然相等」当判据的，外壳一旦留着换行就会把它自己判死。
// 顺手把外壳里的局部名全部换掉：原版外壳是逐行写死的可读形态，局部名固定成
// Q/Z/Y/u/k 这种，等于把「这里在解压」写在脸上。

#[derive(PartialEq, Clone, Copy)]
enum Kind {
    Ident,
    Num,
    Str,
    Punct,
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >= 0xF0 {
        4
    } else if b >= 0xE0 {
        3
    } else if b >= 0xC0 {
        2
    } else {
        1
    }
}

/// 把源码切成 token：字符串/长字符串整段保留，注释丢弃，其余按标识符/数字/符号分。
fn tokenize(src: &str) -> Vec<(Kind, String)> {
    let b = src.as_bytes();
    let mut out: Vec<(Kind, String)> = Vec::with_capacity(src.len() / 3);
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            i += 1;
            continue;
        }
        if c == b'-' && i + 1 < b.len() && b[i + 1] == b'-' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'"' || c == b'\'' {
            let q = c;
            let start = i;
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == q {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let end = i.min(b.len());
            out.push((Kind::Str, src[start..end].to_string()));
            continue;
        }
        if c == b'[' {
            let mut j = i + 1;
            let mut eq = 0usize;
            while j < b.len() && b[j] == b'=' {
                eq += 1;
                j += 1;
            }
            if j < b.len() && b[j] == b'[' {
                let start = i;
                i = j + 1;
                while i < b.len() {
                    if b[i] == b']' {
                        let mut k2 = i + 1;
                        let mut e2 = 0usize;
                        while k2 < b.len() && b[k2] == b'=' {
                            e2 += 1;
                            k2 += 1;
                        }
                        if k2 < b.len() && b[k2] == b']' && e2 == eq {
                            i = k2 + 1;
                            break;
                        }
                    }
                    i += 1;
                }
                let end = i.min(b.len());
                out.push((Kind::Str, src[start..end].to_string()));
                continue;
            }
        }
        if c == b'_' || c.is_ascii_alphabetic() {
            let start = i;
            while i < b.len() && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            out.push((Kind::Ident, src[start..i].to_string()));
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < b.len() {
                let d = b[i];
                if d.is_ascii_alphanumeric() || d == b'_' {
                    i += 1;
                    continue;
                }
                // `.` 属于数字，但 `..` 是连接符，要留给标点分支
                if d == b'.' && !(i + 1 < b.len() && b[i + 1] == b'.') {
                    i += 1;
                    continue;
                }
                break;
            }
            out.push((Kind::Num, src[start..i].to_string()));
            continue;
        }
        let n = utf8_len(c);
        let end = (i + n).min(b.len());
        out.push((Kind::Punct, src[i..end].to_string()));
        i = end;
    }
    out
}

/// 收齐外壳里 `local` / `for` / `function(...)` 声明出来的名字（不碰字段名与全局名）。
fn collect_locals(toks: &[(Kind, String)]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < toks.len() {
        if toks[i].0 != Kind::Ident {
            i += 1;
            continue;
        }
        match toks[i].1.as_str() {
            "local" => {
                let mut j = i + 1;
                if j < toks.len() && toks[j].0 == Kind::Ident && toks[j].1 == "function" {
                    j += 1;
                }
                loop {
                    if j >= toks.len() || toks[j].0 != Kind::Ident {
                        break;
                    }
                    names.push(toks[j].1.clone());
                    j += 1;
                    if j < toks.len() && toks[j].0 == Kind::Punct && toks[j].1 == "," {
                        j += 1;
                        continue;
                    }
                    break;
                }
            }
            "for" => {
                let mut j = i + 1;
                loop {
                    if j >= toks.len() {
                        break;
                    }
                    if toks[j].0 == Kind::Ident && toks[j].1 != "in" {
                        names.push(toks[j].1.clone());
                        j += 1;
                        if j < toks.len() && toks[j].0 == Kind::Punct && toks[j].1 == "," {
                            j += 1;
                            continue;
                        }
                        break;
                    }
                    break;
                }
            }
            "function" => {
                let mut j = i + 1;
                if j < toks.len() && toks[j].0 == Kind::Ident {
                    j += 1; // function 名字（外壳里没有，防御性跳过）
                }
                if j < toks.len() && toks[j].0 == Kind::Punct && toks[j].1 == "(" {
                    j += 1;
                    loop {
                        if j >= toks.len() {
                            break;
                        }
                        if toks[j].0 == Kind::Ident {
                            names.push(toks[j].1.clone());
                            j += 1;
                            if j < toks.len() && toks[j].0 == Kind::Punct && toks[j].1 == "," {
                                j += 1;
                                continue;
                            }
                            break;
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    names
}

/// 单行化 + 局部名随机化。字符串与字段名原样保留。
/// Lua 5.1 全部保留字（finalize 的随机短名必须避开）。
const KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in",
    "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
];

fn finalize(dev: &str, rng: &mut Rng) -> String {
    let toks = tokenize(dev);
    let locals = collect_locals(&toks);

    let mut used: std::collections::HashSet<String> = toks
        .iter()
        .filter(|t| t.0 == Kind::Ident)
        .map(|t| t.1.clone())
        .collect();
    let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for name in locals {
        if map.contains_key(&name) {
            continue;
        }
        let mut fresh = rng.name();
        // 短名（1~3 字符）会撞 Lua 关键字（in/or/if/do/and/end/for/nil/not），
        // 撞上就是必坏的产物（`local in=0` 语法错）——关键字视同已占用。
        while KEYWORDS.contains(&fresh.as_str()) || used.contains(&fresh) {
            fresh = rng.name();
        }
        used.insert(fresh.clone());
        map.insert(name, fresh);
    }

    let mut out = String::with_capacity(dev.len());
    let mut prev: Option<(Kind, String)> = None;
    for (kind, text) in toks {
        let text = if kind == Kind::Ident {
            map.get(&text).cloned().unwrap_or(text)
        } else {
            text
        };
        if let Some((pk, _)) = &prev {
            let need = matches!(
                (pk, kind),
                (Kind::Ident, Kind::Ident)
                    | (Kind::Ident, Kind::Num)
                    | (Kind::Num, Kind::Ident)
                    | (Kind::Num, Kind::Num)
            ) || (*pk == Kind::Num && text.starts_with('.'));
            if need {
                out.push(' ');
            }
        }
        out.push_str(&text);
        prev = Some((kind, text));
    }
    out
}


/// 外壳正文（**开发形态**：多行、缩进、名字固定，便于 diff 与读）。
///
/// 交付前会过一遍 [`finalize`]：词法单行化 + 局部名随机化。外壳里所有库函数都经
/// 捕获表 `G` 取（`G.string.byte` / `G.assert` / `G.pcall` …），因此除了 `getfenv`
/// 与 `_G` 没有任何全局名——它们不参与改名，字段名也不改，改名只落在 `local` /
/// `for` / 函数参数这些真正的局部名上。`loadstring` 的名字在运行期由数字拼出来，
/// 成品里查不到这个词。
///
/// 逐行 push，不用 `format!`，免得 Lua 的 `{}` 要写成 `{{}}` 这类可读性灾难。
fn emit_shell(payload: &str, alphabet: &[u8; 85]) -> String {
    let alphabet_text = std::str::from_utf8(alphabet).expect("base85 alphabet is ASCII");
    let mut out = String::with_capacity(payload.len() + 2048);
    let line = |depth: usize, text: &str, out: &mut String| {
        out.push('\t');
        for _ in 1..depth {
            out.push('\t');
        }
        out.push_str(text);
        out.push('\n');
    };
    // VM 的固定环境捕获（finalizer 会把它连同其它显式绑定一起改成随机短名）。
    line(0, "local G=(getfenv and getfenv(1))or _G;", &mut out);
    out.push_str("return (function(...)\n");
    line(1, "local Q, Z, Y, u, k, W = G.string.byte, G.string.char, G.unpack or G.table.unpack, G.assert, G.tostring, G.type;", &mut out);
    // loader 名必须**运行期**拼出来：`is_rename_barrier` 里有 `load`/`loadstring`，而
    // `static_string` 连字面量拼接都会解析（`G["load".."string"]` 一样被当成反射名）。
    // 与 VM 把 `debug`/`loadstring` 当参数穿过审计捕获的做法同源，顺带让成品里查不到这两个词。
    line(1, "local R = G[Z(108, 111, 97, 100, 115, 116, 114, 105, 110, 103)] or G[Z(108, 111, 97, 100)];", &mut out);
    line(1, "local V = {};", &mut out);
    line(1, &format!("local D = [=[{alphabet_text}]=];"), &mut out);
    line(
        1,
        "local S = {[0] = 1, 85, 7225, 614125, 52200625};",
        &mut out,
    );
    line(1, "local T = {[0] = 1, 256, 65536, 16777216};", &mut out);
    // 环境探针：借参考件这块的格式，内容换成本外壳真正需要的前置检查。被 hook 坏的
    // string.char/string.byte 会让整份解码静默错位，而缺 loader（或它不在捕获表里）会在
    // 最后一步才炸——都在这里先死，报错更好读。
    line(1, "local L = 0;", &mut out);
    line(1, "do", &mut out);
    line(2, "local O = {65, 97, 255, 0};", &mut out);
    line(2, "for p = 1, 4 do", &mut out);
    line(3, "local c = Z(O[p]);", &mut out);
    line(
        3,
        "if not c or Q(c, 1, 1) ~= O[p] then L = 1; break; end;",
        &mut out,
    );
    line(2, "end;", &mut out);
    line(2, "if L == 0 and not (R and Y) then L = 2; end;", &mut out);
    line(1, "end;", &mut out);
    // 探针失败按 `L` 分档：e1 = `string.byte`/`string.char` 往返被 hook 坏，e2 = 没有 loader 或没有 unpack。
    line(
        1,
        "if L ~= 0 then G.error() end;",
        &mut out,
    );
    line(1, &format!("local E = [=[{payload}]=];"), &mut out);
    // 数字表按 D 的位置建：D 是种子置换过的 85 字符 ⇒ 通用 base85 解码器读不出来。
    line(1, "for p = 1, 85 do V[Q(D, p, p)] = p - 1; end;", &mut out);
    // 5 字符 -> 4 字节，逐组展开成字节表 b（大端，与 S/T 两张幂表一致）。
    line(1, "local b, n = {}, 0;", &mut out);
    line(1, "for p = 1, #E, 5 do", &mut out);
    line(2, "local v = 0;", &mut out);
    line(2, "for q = 0, 4 do", &mut out);
    line(3, "local d = V[Q(E, p + q, p + q)];", &mut out);
    // e3：符号不在置换过的数字表里（负载被改写，或贴进来的文本不属于本字母表）。
    line(3, "if not d then G.error() end;", &mut out);
    line(3, "v = v * 85 + d;", &mut out);
    line(2, "end;", &mut out);
    line(2, "for q = 3, 0, -1 do", &mut out);
    line(3, "local w = v - v % T[q];", &mut out);
    line(3, "w = w / T[q];", &mut out);
    line(3, "n = n + 1;", &mut out);
    line(3, "b[n] = w;", &mut out);
    line(3, "v = v - w * T[q];", &mut out);
    line(2, "end;", &mut out);
    line(1, "end;", &mut out);
    // 头部：5 字节长度 + 折叠初值 2+2 + 期望值 2+2；长度上界挡住被改坏的头部引起的巨量分配。
    line(1, "local z, w = n, 0;", &mut out);
    line(1, "local P = function()", &mut out);
    line(2, "w = w + 1;", &mut out);
    // e4：负载被截断，游标越过长度假设。
    line(2, "if w > z then G.error() end;", &mut out);
    line(2, "return b[w];", &mut out);
    line(1, "end;", &mut out);
    line(1, "local M = 0;", &mut out);
    line(1, &format!("for _ = 1, 5 do M = M * {} + P(); end;", w256()), &mut out);
    // e5：头部长度域非法（0 或超过 64 MiB）。
    line(
        1,
        "if M < 0 or M > 67108864 then G.error() end;",
        &mut out,
    );
    line(
        1,
        &format!("local a, c = P() * {} + P(), P() * {} + P();", w256(), w256()),
        &mut out,
    );
    line(
        1,
        &format!("local ea, ec = P() * {} + P(), P() * {} + P();", w256(), w256()),
        &mut out,
    );
    // token 流：每 8 个一个 header，bit=1 是裸字节，bit=0 是 Link（大端 stride + 255 进位的 span）。
    line(1, "local d, o = {}, 0;", &mut out);
    line(1, "while o < M do", &mut out);
    line(2, "local h = P();", &mut out);
    line(2, "for _ = 1, 8 do", &mut out);
    line(3, "if h % 2 == 1 then", &mut out);
    line(4, "o = o + 1;", &mut out);
    line(4, "local v = P();", &mut out);
    line(4, "d[o] = v;", &mut out);
    line(4, "a = (a + v) % 65447;", &mut out);
    line(4, "c = (c + a) % 65447;", &mut out);
    line(3, "else", &mut out);
    line(4, &format!("local s = P() * {} + P();", w256()), &mut out);
    // e6：distance 越界（<=0 或超过已产出长度）。
    line(
        4,
        "if s < 1 or s > o then G.error() end;",
        &mut out,
    );
    line(4, "local p = 3;", &mut out);
    line(4, "repeat", &mut out);
    line(5, "local t = P();", &mut out);
    line(5, "p = p + t;", &mut out);
    line(4, "until t < 255;", &mut out);
    // e7：span 会把输出推过目标长度 M。
    line(4, "if o + p > M then G.error() end;", &mut out);
    line(4, "for _ = 1, p do", &mut out);
    line(5, "o = o + 1;", &mut out);
    line(5, "local v = d[o - s];", &mut out);
    // e8：链接指向还没产出的位置。
    line(5, "if not v then G.error() end;", &mut out);
    line(5, "d[o] = v;", &mut out);
    line(5, "a = (a + v) % 65447;", &mut out);
    line(5, "c = (c + a) % 65447;", &mut out);
    line(4, "end;", &mut out);
    line(3, "end;", &mut out);
    line(3, "h = h - h % 2;", &mut out);
    line(3, "h = h / 2;", &mut out);
    line(3, "if o >= M then break; end;", &mut out);
    line(2, "end;", &mut out);
    line(1, "end;", &mut out);
    // e9：长度或 keyed Adler 两 lane 与头部期望值不符（篡改，或换了种子的负载）。
    line(
        1,
        "if o ~= M or a ~= ea or c ~= ec then G.error() end;",
        &mut out,
    );
    // 负载表与解码表先释放，再拼字符串：参考件用一记 pcall 副作用做到同一件事，这里直接置 nil。
    line(1, "b = nil;", &mut out);
    line(1, "local N, x = \"\", #d;", &mut out);
    line(1, "for p = 1, x, 7997 do", &mut out);
    line(2, "local q = p + 7996;", &mut out);
    line(2, "if q > x then q = x; end;", &mut out);
    line(2, "N = N .. Z(Y(d, p, q));", &mut out);
    line(1, "end;", &mut out);
    line(1, "d = nil;", &mut out);
    line(
        1,
        "local ok, f = G.pcall(R, N);",
        &mut out,
    );
    line(1, "u(ok and f and W(f) == \"function\");", &mut out);
    line(1, "return f(...);", &mut out);
    out.push_str("end)(...);\n");
    out
}
