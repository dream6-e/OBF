//! XXS 压缩外壳：`vm_*.out.lua` 生成**之后**再加的一层。
//!
//! 这一层不属于 OBF 容器，也不属于私有镜像：它只是把已经生成的最终脚本再压一次、
//! base85 成一段字面量，并配一个自解码的 `loadstring` 外壳。因此它**不升 ISA**，
//! `tools/test-matrix.sh` 里既有的 golden / 体积 / 审计步骤一字未动（新步骤是追加的）。
//!
//! ## 压缩器（算法来自用户提供的那份 DP/LZ `Compressor`，按本项目改写）
//! 逐步保留的原始设计：`Step::{Raw, Link{stride, span}}` 两种 token；`MAX_SPAN = 4096`、
//! `MAX_STRIDE = 65535`、`MAX_CANDIDATES = 96`（每位置最多回看 96 个同 hash 的历史位置）、
//! `HASH_BITS = 17` 的 4 字节 hash（末尾不足 4 字节处用 3 字节 hash 单独兜底，使 `span == 3`
//! 的短匹配仍能找到）；cost 模型仍是「Raw 9 bit / Link `17 + 8 * length_bytes(span - 3)` bit」，
//! `optimal_strides` 只在新峰长时回填、**不做 span 剪枝**（3..=peak_span 全部参与 DP），
//! 插入链一定在搜索之后（否则匹配到自己、stride 变 0）。输出格式也保持原样：每 8 个 token
//! 一个 header 字节，bit=1 为 Raw（跟一字节），bit=0 为 Link（大端 stride 两字节 + `span-3`
//! 的 255 进位变长）。
//!
//! 改写的只有四处，都写在这里以免被读成「原样照搬」：
//! 1. **成本旋钮可由种子扰动**（`raw_bits` / `link_base_bits` 在 ±1 bit 内取值）。它只改变
//!    等价代价之间的**选择**，不改变任何正确性条件：解码器读的仍是同一套 token。目的是让
//!    外壳的分块形状随种子变，而不是每个种子都产出同一份 LZ 解析。
//! 2. `optimal_strides` 从「每个位置新建一个 4097 项 Vec」改成整份复用一块缓冲——每轮
//!    `1..=peak_span` 都被本轮写过，所以不存在读到陈旧值的可能（原实现每位置 memset 8 KB，
//!    112 KB 输入要写 ~900 MB，纯浪费）。
//! 3. 头部由外壳补上（原算法没有）：5 字节长度 + 4 字节折叠初值 + 4 字节期望值，见
//!    [`wrap`] 的格式说明；解压边读边算 Adler 两 lane 折叠，`loadstring` 之前必校验。
//! 4. 压缩流按 4 字节一组零填充后再 base85（不做「尾组按余数变长」那种常见写法），因为长度在头部
//!    已经给出，多出来的至多 3 字节解码后被忽略 ⇒ 解码器少一条特殊路径。
//!
//! ## 外壳格式（参考用户提供的那份 `return (function() ... end)()(...)` 装载器）
//! 借的是**格式**：同一族局部别名行、逐字符建数字值的 `for p = 1, 85` 表（参考件是 `for O = 0, 255`
//! 的全字节表，这里只需要 85 枚符号）、开头的环境探针块、5 字符 →
//! 数值的那张 `[0]=1` 幂表、`P()` 闭包读一字节即进位（越界直接 `error`）、7997 一块的
//! `string.char(unpack(d, p, q))` 串接、`loadstring(C, "XXS" .. string.rep(" ", 4))`（**只传两参**：
//! 参考件的第三参是 5.2 的 `mode`，Luau 的 `loadstring` 只吃两参）、`assert(..., "XXS decompression error: ...")`。
//! 里面**不是**它的算法（那份是 rANS/算术编码 + 位读取；这里是上面的 DP/LZ 与按字节 token）。
//! 参考件里 `pcall(loadstring, setmetatable({}, {__tostring = function() d = nil end}), nil, nil)`
//! 那一记「用报错触发的副作用来释放表」的写法没有照搬：直接置 nil 即可，语义相同、少一次
//! 假调用。所有 `Luraph` 字样按要求改成 `XXS`。
//!
//! ## 两端一致性
//! 实测（`toolchains/bin/lua5.1` / `toolchains/bin/luau`）：5.1 有 `loadstring`/`unpack`，
//! Luau 有 `loadstring`/`unpack`/`table.unpack` 而 `load` 为 nil ⇒ 外壳只写
//! `loadstring or load` 与 `unpack or table.unpack`，全程只用 `+ - * / %` 与查表，
//! **不需要 `bit`、不需要 `string.pack`**，两个目标跑同一份代码。base85 值域 85^5 < 2^53 ⇒
//! double 精确，`math.floor` 也不需要（拆字节用 `T = {[0]=1, 256, 65536, 16777216}` 这张幂表做
//! 除法取余，参考件同一手法）。字母表取 z85 的 85 枚符号（不含 `"` `'` `\` `[` `]`），所以负载既是
//! 长括号字面量里的裸文本（零转义），也不可能提前闭合 `]]`；再按种子做一次置换，
//! 现成的 base85 解码器就认不出来了。

use crate::random::Prng;
use crate::{Diagnostic, Target};

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
        let mut rng = Prng::sfc(seed ^ 0x7368_656c_6c5f_6c7a);
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
const ADLER_MOD: u64 = 65_521;

/// z85 的 85 枚可打印符号（RFC1924 base85 的同族变体）：不含 `"` `'` `\` `[` `]` ⇒ 长括号字面量里零转义，
/// 也永远不会出现 `]]`。这里再按种子做一次置换，使通用 base85 解码器读不出来。
pub fn base85_alphabet(seed: u64) -> [u8; 85] {
    // z85 的符号集。它与 RFC1924 的 base85 只差标点：刻意不含 `"` `'` `\` `[` `]` `.` `/`
    // `:` `,`，因为负载要裸写进 `[[ ]]` 长括号字面量——能拼出 `]]` 或需要转义的符号一律不要。
    const Z85: &[u8; 85] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let mut alphabet = *Z85;
    let mut rng = Prng::sfc(seed ^ 0x7368_656c_6c5f_6238);
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
    pub tokens: usize,
}

impl Shell {
    pub fn ratio(&self) -> f64 {
        self.script.len() as f64 / self.source_bytes.max(1) as f64
    }
}

/// 把已经生成好的最终脚本再包一层压缩外壳。
///
/// `target` 只用于先把输入按该目标解析一遍（外壳不改脚本内容，但要保证包进去的东西本身
/// 合法）；压缩/编码过程与目标无关，两端跑同一份解码器。
pub fn wrap(source: &str, target: Target, seed: u64) -> Result<Shell, Diagnostic> {
    crate::check(source, target)?;
    let data = source.as_bytes();
    if data.is_empty() {
        return Err(Diagnostic::new("XXS shell: empty script"));
    }
    let compressor = Compressor::seeded(seed);
    let body = compressor.compress_with(data);
    let tokens = count_tokens(&body);

    // 头：长度（5B）+ 折叠初值（2B + 2B）+ 期望值（2B + 2B）。初值取自种子，
    // 于是把别的种子的负载插进这份外壳会在 loadstring 之前死掉。
    // 两枚初值都落在 1..=65,520 ⇒ 与 Lua 侧每步 `% 65521` 的取值域一致。
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
    let payload = String::from_utf8(encoded).expect("base85 alphabet is ASCII");
    if payload.len() + 1024 >= data.len() {
        return Err(Diagnostic::new(format!(
            "XXS shell: no gain on {} B input ({} B payload); refusing to add a wrapper that grows the script",
            data.len(),
            payload.len()
        )));
    }

    let script = emit_shell(&payload, &alphabet);
    Ok(Shell {
        script,
        source_bytes: data.len(),
        compressed_bytes: stream.len(),
        encoded_bytes: payload.len(),
        tokens,
    })
}

fn count_tokens(stream: &[u8]) -> usize {
    // header 之后每 8 token 一个 header 字节；token 数只用于报告。
    let mut head = HEADER_LEN;
    let mut tokens = 0usize;
    while head < stream.len() {
        let header = stream[head];
        head += 1;
        for bit in 0..8 {
            if head >= stream.len() {
                break;
            }
            if header & (1 << bit) != 0 {
                head += 1;
            } else {
                head += 2;
                while head < stream.len() && stream[head] == 255 {
                    head += 1;
                }
                head += 1;
            }
            tokens += 1;
        }
    }
    tokens
}

/// 外壳正文。格式镜像用户提供的那份装载器（别名行、`for O = 0, 255` 式的字符表、环境
/// 探针块、`[0] = 1` 幂表、7997 一块的 `string.char(unpack(...))` 串接、
/// `loadstring(chunk, "XXS    ")`、`assert(..., "XXS decompression error: ...")`）；
/// 解码算法是本模块的 DP/LZ token 流。逐行 push，不用 `format!`，免得 Lua 的 `{}` 要写成
/// `{{}}` 这类可读性灾难（K3 那批踩过一次四重括号）。
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
    out.push_str("return (function(...)\n");
    line(1, "local G, Z, Y, u, k, W, R = string.byte, string.char, unpack or table.unpack, assert, tostring, type, loadstring or load;", &mut out);
    line(1, "local V = {};", &mut out);
    line(1, &format!("local D = [=[{alphabet_text}]=];"), &mut out);
    line(
        1,
        "local S = {[0] = 1, 85, 7225, 614125, 52200625};",
        &mut out,
    );
    line(1, "local T = {[0] = 1, 256, 65536, 16777216};", &mut out);
    // 环境探针：借参考件这块的格式，内容换成本外壳真正需要的前置检查。被 hook 坏的
    // string.char/string.byte 会让整份解码静默错位，所以在碰负载之前先试出来。
    line(1, "local L = 0;", &mut out);
    line(1, "do", &mut out);
    line(2, "local O = {65, 97, 255, 0};", &mut out);
    line(2, "for p = 1, 4 do", &mut out);
    line(3, "local c = Z(O[p]);", &mut out);
    line(
        3,
        "if not c or G(c, 1, 1) ~= O[p] then L = 1; break; end;",
        &mut out,
    );
    line(2, "end;", &mut out);
    line(2, "if L == 0 and not (R and Y) then L = 2; end;", &mut out);
    line(1, "end;", &mut out);
    line(1, "if L ~= 0 then error(\"XXS shell error: unsupported environment (\" .. L .. \")\", 0) end;", &mut out);
    line(1, &format!("local E = [=[{payload}]=];"), &mut out);
    // 数字表按 D 的位置建：D 是种子置换过的 85 字符 ⇒ 通用 base85 解码器读不出来。
    line(1, "for p = 1, 85 do V[G(D, p, p)] = p - 1; end;", &mut out);
    // 5 字符 -> 4 字节，逐组展开成字节表 b（大端，与 S/T 两张幂表一致）。
    line(1, "local b, n = {}, 0;", &mut out);
    line(1, "for p = 1, #E, 5 do", &mut out);
    line(2, "local v = 0;", &mut out);
    line(2, "for q = 0, 4 do", &mut out);
    line(3, "local d = V[G(E, p + q, p + q)];", &mut out);
    line(
        3,
        "if not d then error(\"XXS shell error: symbol outside the digit table\", 0) end;",
        &mut out,
    );
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
    line(
        2,
        "if w > z then error(\"XXS shell error: truncated stream\", 0) end;",
        &mut out,
    );
    line(2, "return b[w];", &mut out);
    line(1, "end;", &mut out);
    line(1, "local M = 0;", &mut out);
    line(1, "for _ = 1, 5 do M = M * 256 + P(); end;", &mut out);
    line(
        1,
        "if M < 0 or M > 67108864 then error(\"XXS shell error: bad length\", 0) end;",
        &mut out,
    );
    line(
        1,
        "local a, c = P() * 256 + P(), P() * 256 + P();",
        &mut out,
    );
    line(
        1,
        "local ga, gc = P() * 256 + P(), P() * 256 + P();",
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
    line(4, "a = (a + v) % 65521;", &mut out);
    line(4, "c = (c + a) % 65521;", &mut out);
    line(3, "else", &mut out);
    line(4, "local s = P() * 256 + P();", &mut out);
    line(
        4,
        "if s < 1 or s > o then error(\"XXS shell error: bad link distance\", 0) end;",
        &mut out,
    );
    line(4, "local p = 3;", &mut out);
    line(4, "repeat", &mut out);
    line(5, "local t = P();", &mut out);
    line(5, "p = p + t;", &mut out);
    line(4, "until t < 255;", &mut out);
    line(
        4,
        "if o + p > M then error(\"XXS shell error: link past the end\", 0) end;",
        &mut out,
    );
    line(4, "for _ = 1, p do", &mut out);
    line(5, "o = o + 1;", &mut out);
    line(5, "local v = d[o - s];", &mut out);
    line(
        5,
        "if not v then error(\"XXS shell error: bad link source\", 0) end;",
        &mut out,
    );
    line(5, "d[o] = v;", &mut out);
    line(5, "a = (a + v) % 65521;", &mut out);
    line(5, "c = (c + a) % 65521;", &mut out);
    line(4, "end;", &mut out);
    line(3, "end;", &mut out);
    line(3, "h = h - h % 2;", &mut out);
    line(3, "h = h / 2;", &mut out);
    line(3, "if o >= M then break; end;", &mut out);
    line(2, "end;", &mut out);
    line(1, "end;", &mut out);
    line(1, "if o ~= M or a ~= ga or c ~= gc then error(\"XXS shell error: integrity mismatch\", 0) end;", &mut out);
    // 负载表与解码表先释放，再拼字符串：参考件用一记 pcall 副作用做到同一件事，这里直接置 nil。
    line(1, "b = nil;", &mut out);
    line(1, "local C, m = \"\", #d;", &mut out);
    line(1, "for p = 1, m, 7997 do", &mut out);
    line(2, "local q = p + 7996;", &mut out);
    line(2, "if q > m then q = m; end;", &mut out);
    line(2, "C = C .. Z(Y(d, p, q));", &mut out);
    line(1, "end;", &mut out);
    line(1, "d = nil;", &mut out);
    line(
        1,
        "local ok, f = pcall(R, C, \"XXS\" .. string.rep(\" \", 4));",
        &mut out,
    );
    line(1, "u(ok and f and W(f) == \"function\", \"XXS decompression error: \" .. k(ok and f or f) .. \" (does your environment support load/loadstring?)\");", &mut out);
    line(1, "return f(...);", &mut out);
    out.push_str("end)(...);\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: usize) -> Vec<u8> {
        // 像 Lua 源码那样有重复片段与短行的输入，压缩器要能吃到 Link。
        let line = b"local x = x + 1; if a[b] ~= c then return 1 end;\n";
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(line);
            out.extend_from_slice(format!("-- pad {}\n", out.len() % 977).as_bytes());
        }
        out.truncate(len);
        out
    }

    #[test]
    fn token_stream_decodes_back_byte_for_byte() {
        for seed in [0u64, 1, 735, 7001, u64::MAX] {
            for len in [0usize, 1, 2, 3, 4, 5, 17, 300, 4096, 40_000] {
                let data = sample(len);
                let packed = Compressor::seeded(seed).compress_with(&data);
                let unpacked = decode_reference(&data.len(), &packed);
                assert_eq!(unpacked, data, "seed {seed} len {len}");
            }
        }
    }

    /// 独立实现的 token 流读取器（与 Lua 侧同一套规则），用来证明编码可逆。
    fn decode_reference(want: &usize, stream: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(*want);
        let mut head = 0usize;
        while out.len() < *want && head < stream.len() {
            let header = stream[head];
            head += 1;
            for bit in 0..8 {
                if out.len() >= *want || head >= stream.len() {
                    break;
                }
                if header & (1 << bit) != 0 {
                    out.push(stream[head]);
                    head += 1;
                } else {
                    let stride =
                        ((u16::from(stream[head]) << 8) | u16::from(stream[head + 1])) as usize;
                    head += 2;
                    let mut span = 3usize;
                    loop {
                        let byte = stream[head];
                        head += 1;
                        span += usize::from(byte);
                        if byte != 255 {
                            break;
                        }
                    }
                    let start = out.len() - stride;
                    for offset in 0..span {
                        let byte = out[start + offset];
                        out.push(byte);
                    }
                }
            }
        }
        out
    }

    #[test]
    fn alphabet_is_quote_and_bracket_safe() {
        for seed in [0u64, 1, 735, 999_983, u64::MAX] {
            let alphabet = base85_alphabet(seed);
            assert_eq!(alphabet.len(), 85);
            let mut sorted = alphabet;
            sorted.sort_unstable();
            let mut deduped = sorted.to_vec();
            deduped.dedup();
            assert_eq!(deduped.len(), 85, "seed {seed}: digits repeat");
            for hostile in [b'"', b'\'', b'\\', b'[', b']'] {
                assert!(
                    !alphabet.contains(&hostile),
                    "seed {seed}: {hostile} would break a long-bracket literal"
                );
            }
            // The payload must never contain `]]` (it would close the literal early).
            assert!(
                !deduped.windows(2).any(|pair| pair == b"]]"),
                "seed {seed}: `]]` is encodable"
            );
            assert_ne!(base86_like_compare(seed), base86_like_compare(seed ^ 1));
        }
    }

    fn base86_like_compare(seed: u64) -> [u8; 85] {
        base85_alphabet(seed)
    }

    #[test]
    fn base85_groups_roundtrip_through_u64() {
        let alphabet = base85_alphabet(735);
        for len in [0usize, 1, 3, 4, 5, 8, 4099] {
            let data: Vec<u8> = (0..len).map(|index| (index * 37 + 11) as u8).collect();
            let text = base85_encode(&data, &alphabet);
            assert_eq!(
                text.len() % 5,
                0,
                "padded encoding keeps whole 5-char groups"
            );
            // 与 Lua 侧同一套权重：5 字符 -> 一个 <= 85^5 的数 -> 4 个大端字节。
            let mut out = Vec::new();
            for chunk in text.chunks(5) {
                let mut value = 0u64;
                for &byte in chunk {
                    let digit = alphabet.iter().position(|&at| at == byte).unwrap() as u64;
                    value = value * 85 + digit;
                }
                for offset in (0..4).rev() {
                    out.push(((value >> (8 * offset)) & 0xff) as u8);
                }
            }
            out.truncate(len);
            assert_eq!(out, data, "len {len}");
            // 85^5 < 2^53: the Lua double path below stays exact by construction.
            assert!(85u64.pow(5) < (1u64 << 53));
        }
    }

    #[test]
    fn header_length_and_fold_are_big_endian() {
        let mut out = Vec::new();
        push_be(&mut out, 0x01_02_03_04_05, 5);
        assert_eq!(out, vec![1, 2, 3, 4, 5]);
        let (a, c) = fold_lanes(b"abc", 1, 0);
        // a 累加字节、c 累加 a：手写一遍确认两 lane 的定义与 Lua 侧逐字一致。
        //   'a'=97: a=1+97=98,  c=0+98=98
        //   'b'=98: a=98+98=196, c=98+196=294
        //   'c'=99: a=196+99=295, c=294+295=589
        assert_eq!((a, c), (295, 589), "Adler lanes must match the Lua decoder");
        assert!(
            a < ADLER_MOD && c < ADLER_MOD,
            "lanes stay inside the 2-byte field"
        );
        // 初值取自种子 => 别的种子的负载塞进这份外壳，折叠对不上（在 loadstring 之前死）。
        assert_ne!(fold_lanes(b"abc", 1, 0), fold_lanes(b"abc", 2, 0));
    }
}
