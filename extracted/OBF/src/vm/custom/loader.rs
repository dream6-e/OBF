//! K20 运行期分段装载（T2 ③「打散」）。
//!
//! 在 K20 之前，壳的全部能力都在一处成形：payload 表字面量一次写出所有
//! 字段，静态读一遍字面量就能拿到全量 handler 集，`setmetatable` 的实参也
//! 是唯一一处挂钩点。本模块把「装载」从一处拆成多点：可搬迁字段不再出现在
//! 字面量里，而是由入口状态机各阶段之间的注入点分多次 `VMS[k]=function...end`
//! 装进壳表；同一键允许先装 A 再装 B（两份等价写法，最后一次生效，静态看不出
//! 哪份生效）。每个装载点同时折叠一句 `ck=ck+k`，run 段末比对总和，因此删除、
//! 复制或替换任一装载语句都会 fail-closed。
//!
//! 设计约束（都在下面的构造过程里强制执行）：
//! * 装载必须发生在该键第一次被读之前，因此候选字段要携带「首次读注入点序号」；
//!   规划器只会把字段装进序号不大于该点的槽位，且严格递增。
//! * 搬迁后的字段体会从「表字面量作用域」移到「入口体内」，那里壳句柄被入口
//!   局部变量遮蔽，所以任何自由引用壳句柄（`t.`）的字段一律保持烘入，不搬迁。
//! * B 写法只允许使用下面 `RESPPELLINGS` 白名单里的逐字对，每一对都在 Rust 侧
//!   穷举证明过等价（乘法交换/结合律、`a~=b` 与 `not(a==b)`），不引入新常量，
//!   也不重复求值任何表达式。

/// 入口状态机里的注入点数量。槽位 `i` 表示「在第 `i` 条阶段调用之前」，
/// 执行顺序即槽位顺序；run 段末的折叠检查不算装载槽位。
pub(crate) const SLOTS: usize = 11;

/// 一次装载计划的结果。
pub(crate) struct Scatter {
    /// 仍然烘入 payload 表字面量的字段（保持原相对顺序）。
    pub(crate) kept: Vec<String>,
    /// 每个注入点要插入的语句文本，可能为空串。
    pub(crate) blobs: Vec<String>,
    /// 装载语句条数（静态验收线用）。
    pub(crate) sites: usize,
    /// 被搬出字面量的键数。
    pub(crate) installed: usize,
    /// 运行期折叠检查的期望值：所有装载点的键之和。
    pub(crate) fold: u64,
    /// 逐装载点的 `(键, 装载槽位, 首次读取槽位)`，门用它检查拓扑合法性。
    pub(crate) plan: Vec<(u64, usize, usize)>,
    /// K6 第二步：装载点分成的组数（2..=4，种子化）。
    pub(crate) groups: usize,
    /// 逐装载点的折叠写法编号（与 `plan` 同序）：0 = `ck=ck+K`，
    /// 1 = `ck=K+ck`，2 = `ck=ck+(K)`。三种写法是同一次加法，checkpoint
    /// 期望值不变。
    pub(crate) forms: Vec<usize>,
}

/// 等价改写白名单：`(原始子串, 等价子串)`。两份实现互为等价写法，命中即可
/// 生成变体 B。每一对都是纯代数恒等式，不重复求值、不引入新数字，其等价性由
/// `k20_respelling_pairs_are_provably_equivalent` 门穷举证明。
/// K6 第二步把同一手法从两处扩到十三个新字面对（覆盖十七个站点）：加数交换（`x=y+z` 与 `x=z+y`）、
/// 不等式两边同加（`p>N-n` 与 `p+n>N`）、上取整换写法（`MF((n+m-1)/m)` 与
/// `1+MF((n-1)/m)`，m 为 8/8192）、Lua 的 floor-mod 与负数取模
/// （`(4-(k)%4)%4` 与 `(-k)%4`）、以及用前一步算出的中间量替换同式
/// （`k2=(j-j%256)/256` 与 `k2=(j-a)/256`，`a=j%256` 紧邻在前且未被改写）。
const RESPPELLINGS: [(&str, &str); 15] = [
    // 水印打包：同一个多项式的两种结合顺序（对 a,b,c,d 各自线性，见门证明）。
    (
        "return((a*256+b)*256+c)*256+d;",
        "return d+(c+(b+a*256)*256)*256;",
    ),
    // 探测字段：257 拆成 1+256，纯算术恒等；同一字段里的循环计数 `b=b+1`
    // 一并交换（加数交换）。
    (
        "a=(a*257+SB(A,b))%(2147483600+47);b=b+1",
        "a=(a+a*256+SB(A,b))%(2147483600+47);b=1+b",
    ),
    // LZW 字典回填两处：`prev*256+pf` / `prev*256+first` 的加数交换。
    ("DP[nx]=prev*256+pf", "DP[nx]=pf+prev*256"),
    ("DP[nx]=prev*256+first", "DP[nx]=first+prev*256"),
    // LZW 段长守卫：两边同加 total。
    ("if total+sn>lim then E()end", "if sn>lim-total then E()end"),
    // LZW 读取守卫：`p>N-n` 两边同加 n。
    ("if p>N-n then E()end", "if p+n>N then E()end"),
    // base86 字节数/块数上取整：`MF((n+m-1)/m)` 与 `1+MF((n-1)/m)`
    // （math.floor 语义下对所有整数 n 成立，含 n=0）。
    ("bl=MF((bits+7)/8)", "bl=1+MF((bits-1)/8)"),
    ("cc=MF((n+8191)/8192)", "cc=1+MF((n-1)/8192)"),
    // 帧校验对齐量：Lua 的 % 是 floor-mod，`(4-(k)%4)%4 == (-k)%4`。
    ("pad=(4-(16+n)%4)%4", "pad=(-(16+n))%4"),
    // 帧校验累加（FNV 形）：模内加数交换。
    ("left=(left*257+byte)%65497", "left=(byte+left*257)%65497"),
    (
        "right=(right*263+byte+left)%65497",
        "right=(byte+left+right*263)%65497",
    ),
    // 操作数解码：j/k2 的高位拆分改用紧邻前一步算出的余数局部量。
    ("k2=(j-j%256)/256", "k2=(j-a)/256"),
    ("c=(k2-k2%256)/256", "c=(k2-b)/256"),
    // 校验字段：`x+2<L` 与 `x<L-2`（L 是原型计数字段，两侧各读一次）。
    ("a+2<F.__obf_proto_m", "a<F.__obf_proto_m-2"),
    ("b+2<F.__obf_proto_m", "b<F.__obf_proto_m-2"),
];

/// 模板改写白名单（K6 第二步）：`~N` 是槽位号捕获（一段数字），替换串里的
/// `~N` 回指同一捕获。K16 槽位改写把少数站点变成了 `g[NN]` 形态，槽位号随
/// 种子变化，字面量对覆盖不住；这四条模板的等价性仍是加数交换
/// （捕获本身只是下标，不参与代数），与字面量对一同由
/// `k20_new_respelling_pairs_are_provably_equivalent` 门证明。
const TEMPLATE_RESPPELLINGS: [(&str, &str); 4] = [
    // varint 读数的 128 位拼接：`v=v+w%128*128`。
    ("g[~1]=g[~1]+g[~2]%128*128", "g[~1]=g[~2]%128*128+g[~1]"),
    // 捕获池走的父原型上值累加：`TU=TU+P.__obf_proto_nu`。
    ("TU=TU+g[~1].__obf_proto_nu", "TU=g[~1].__obf_proto_nu+TU"),
    // 载荷校验和的三个位对：`(d[i]+d[i+1]*87)`。
    ("g[~1][~2]+g[~1][~3]*87", "g[~1][~3]*87+g[~1][~2]"),
    // 三段 base86 的解码累加：`vv=vv+cc*mm`。
    ("g[~1]=g[~1]+g[~2]*g[~3]", "g[~1]=g[~2]*g[~3]+g[~1]"),
];

/// 把 `if L~=R then` 形式的守卫改成 `if not(L==R) then`（K18 的否定形式族）。
/// 只处理括号深度 0、且两侧都是单个标识符或数字的情况，保证不重复求值。
fn respell_guards(body: &str) -> (String, usize) {
    let mut out = String::with_capacity(body.len());
    let bytes = body.as_bytes();
    let mut i = 0usize;
    let mut depth = 0i32;
    let mut hits = 0usize;
    while i < body.len() {
        let c = bytes[i];
        match c {
            b'(' | b'{' => depth += 1,
            b')' | b'}' => depth -= 1,
            _ => {}
        }
        if depth == 0 && body[i..].starts_with("if ") {
            if let Some((rhs, consumed)) = simple_unequal(&body[i + 3..]) {
                let (lhs, rhs) = rhs;
                out.push_str("if not(");
                out.push_str(lhs);
                out.push_str("==");
                out.push_str(rhs);
                out.push_str(") then");
                i += 3 + consumed;
                hits += 1;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    (out, hits)
}

/// 识别 `<atom>~=<atom> then`，返回两侧与消耗长度。
fn is_atom_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// 取出一段「单个标识符或数字」字面量，返回它与消耗长度。带下标/括号的表达式
/// 一律不匹配，避免把复杂左值卷进改写。
fn atom(s: &str) -> Option<(&str, usize)> {
    let bytes = s.as_bytes();
    let mut n = 0usize;
    while n < bytes.len() && is_atom_byte(bytes[n]) {
        n += 1;
    }
    if n == 0 {
        None
    } else {
        Some((&s[..n], n))
    }
}

fn simple_unequal(rest: &str) -> Option<((&str, &str), usize)> {
    let (lhs, used) = atom(rest)?;
    if !rest[used..].starts_with("~=") {
        return None;
    }
    let (rhs, used2) = atom(&rest[used + 2..])?;
    let tail = used + 2 + used2;
    if !rest[tail..].starts_with(" then") {
        return None;
    }
    Some(((lhs, rhs), tail + " then".len()))
}

// Generated payload strings can contain arbitrary alphabet text such as `t.`
// or `VMS`; only identifiers in Lua code are shell-handle captures.
fn has_shell_capture(body: &str) -> bool {
    let bytes = body.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if matches!(bytes[index], b'\'' | b'"') {
            let quote = bytes[index];
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else {
                    let done = bytes[index] == quote;
                    index += 1;
                    if done {
                        break;
                    }
                }
            }
            continue;
        }
        if is_atom_byte(bytes[index]) && !bytes[index].is_ascii_digit() {
            let start = index;
            while index < bytes.len() && is_atom_byte(bytes[index]) {
                index += 1;
            }
            let name = &body[start..index];
            if name == "VMS" {
                return true;
            }
            if name == "t" {
                let mut next = index;
                while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                    next += 1;
                }
                if bytes.get(next) == Some(&b'.') {
                    return true;
                }
            }
            continue;
        }
        index += 1;
    }
    false
}

/// 从一个字段文本 `[k]=function(...) ... end[,?]` 中取出键与函数文本。
fn split_field(field: &str) -> Option<(u64, String)> {
    let rest = field.strip_prefix('[')?;
    let close = rest.find("]=")?;
    let key: u64 = rest[..close].parse().ok()?;
    let body = rest[close + 2..].trim_start();
    if !body.starts_with("function(") {
        return None;
    }
    let body = body.strip_suffix(',').unwrap_or(body).to_owned();
    if !body.ends_with("end") {
        return None;
    }
    Some((key, body))
}

/// 规划一次打散：把候选字段按槽位搬出字面量，必要时同一键装两份等价写法。
///
/// `candidates` 是 `(首次读取槽位, 是否允许同键装两份, 字段文本)`，字段文本形如
/// `[k]=function(...)end,`，
/// 键由规划器自己解析。没进候选池的字段（入口、解释器、prelude、forms/validate
/// 以及任何被 K16 壳句柄读数的字段）一律保持烘入。
pub(crate) fn scatter(
    mut candidates: Vec<(usize, bool, String)>,
    structure: &mut crate::random::Prng,
) -> Scatter {
    let mut kept = Vec::new();
    let mut blobs = vec![String::new(); SLOTS];
    let mut sites = 0usize;
    let mut installed = 0usize;
    let mut fold = 0u64;
    let mut plan = Vec::new();
    // 变体 B 只给「小字段」复制，避免整段 handler 体积翻倍；阈值按经验值定，
    // 只影响装载点数与体积，不影响正确性。
    const DUPLICATE_LIMIT: usize = 1_200;

    // 读得越早的字段越要先装：先按种子打乱候选（同读取槽位内的相对顺序因此
    // 是种子化的），再按槽位稳定排序；装载槽位用轮转计数器分配，保证装载点
    // 铺满前若干个区域而不是挤在其中一处。
    structure.shuffle(&mut candidates);
    candidates.sort_by_key(|(slot, _, _)| *slot);
    // K6 第二步：装载点分成 2..=4 组（种子化）。每组有自己的槽位轮转游标
    // （起点种子化，因此不同组的装载点铺在不同的槽位带）和自己的折叠写法
    // （`ck=ck+K` / `ck=K+ck` / `ck=ck+(K)` 之一，三种是同一次加法，
    // checkpoint 的期望值不变）。组按槽位排序后的轮询方式分配，写法因此
    // 在装载点之间交替出现而不是连成一片。
    let groups = 2 + structure.index(3) as usize;
    let mut group_cursor: Vec<usize> = (0..groups).map(|_| structure.index(SLOTS)).collect();
    let group_form: Vec<usize> = (0..groups).map(|_| structure.index(3) as usize).collect();
    let mut forms = Vec::new();
    for (idx, (slot, doublable, field)) in candidates.into_iter().enumerate() {
        let group = idx % groups;
        let form = group_form[group];
        let Some((key, body)) = split_field(&field) else {
            kept.push(field);
            continue;
        };
        // 搬迁后字段体里任何对壳句柄的自由引用都会指向入口局部变量，
        // 语义静默改变；这种字段永不搬迁。
        if has_shell_capture(&body) {
            kept.push(field);
            continue;
        }
        // 最晚的装载槽位就是读它的那一个（装载语句插在调用之前）；槽位 0 之前
        // 没有任何阶段执行过，所以只有 read_slot >= 1 的字段才搬得动。
        let last = slot.min(SLOTS - 1);
        if last == 0 {
            kept.push(field);
            continue;
        }
        let (variant_b, respelled) = respell_body(&body);
        installed += 1;
        let pick = {
            let raw = group_cursor[group] % SLOTS;
            group_cursor[group] += 1;
            raw.min(last)
        };
        // `doublable` 关掉「同键两份」：带审计环境探测的字段（键推导探测、
        // base86 段探测）一旦复制，`scope` 审计里的十二处探测就不止十二处，
        // 那条 fail-closed 门必须保持精确计数。
        if doublable && respelled > 0 && body.len() <= DUPLICATE_LIMIT && last >= 1 {
            // 同一键装两份：先 A 后 B，B 紧贴在读取之前生效，A 从此不再生效。
            // 同一组的两份用同一种折叠写法。
            let b = last;
            let a = pick.min(b - 1);
            push_install(
                &mut blobs, &mut fold, &mut sites, &mut plan, &mut forms, a, last, key, form, &body,
            );
            push_install(
                &mut blobs, &mut fold, &mut sites, &mut plan, &mut forms, b, last, key, form,
                &variant_b,
            );
            continue;
        }
        push_install(
            &mut blobs, &mut fold, &mut sites, &mut plan, &mut forms, pick, last, key, form,
            &variant_b,
        );
    }
    Scatter {
        kept,
        blobs,
        sites,
        installed,
        fold,
        plan,
        groups,
        forms,
    }
}

/// 把一条装载语句写进槽位文本，并折叠该键。`form` 选择折叠写法
/// （0 = `ck=ck+K`，1 = `ck=K+ck`，2 = `ck=ck+(K)`）——三种是同一次加法。
#[allow(clippy::too_many_arguments)]
fn push_install(
    blobs: &mut [String],
    fold: &mut u64,
    sites: &mut usize,
    plan: &mut Vec<(u64, usize, usize)>,
    forms: &mut Vec<usize>,
    slot: usize,
    read_slot: usize,
    key: u64,
    form: usize,
    body: &str,
) {
    debug_assert!(slot < SLOTS, "install slot out of range");
    debug_assert!(slot <= read_slot, "install after first read");
    debug_assert!(form < 3, "fold form out of range");
    let fold_stmt = match form {
        1 => format!("ck={key}+ck;"),
        2 => format!("ck=ck+({key});"),
        _ => format!("ck=ck+{key};"),
    };
    // `;` 收尾：装载语句与后面的 `ck` 累加必须各自成语句，字段体本身以 `end`
    // 结尾，少了分隔符会粘成 `endck`。
    blobs[slot].push_str(&format!("VMS[{key}]={body};{fold_stmt}"));
    *fold = fold.wrapping_add(key);
    *sites += 1;
    plan.push((key, slot, read_slot));
    forms.push(form);
}

/// 生成等价的第二写法：先套白名单逐字对（同一字段里出现几次改几次），
/// 再套槽位号模板对，最后机械改写守卫的否定形式。返回变体文本与命中次数
/// （0 表示没有可用对，此时不做双份装载）。
fn respell_body(body: &str) -> (String, usize) {
    let mut out = body.to_owned();
    let mut hits = 0usize;
    for (from, to) in RESPPELLINGS {
        // 白名单两侧互不包含（变体 B 的文本里不会出现形态 A），因此可以
        // 从上次命中之后继续找，直到改完字段里的全部出现。
        let mut search_from = 0usize;
        while let Some(at_rel) = out[search_from..].find(from) {
            let at = search_from + at_rel;
            out.replace_range(at..at + from.len(), to);
            search_from = at + to.len();
            hits += 1;
        }
    }
    for (pattern, replacement) in TEMPLATE_RESPPELLINGS {
        let (templated, template_hits) = apply_template(&out, pattern, replacement);
        if template_hits > 0 {
            out = templated;
            hits += template_hits;
        }
    }
    let (guard_free, guard_hits) = respell_guards(&out);
    if guard_hits > 0 {
        return (guard_free, hits + guard_hits);
    }
    (out, hits)
}

/// 把模板模式解析成「字面量段 / `~N` 捕获段」序列。
fn parse_template(pattern: &str) -> Result<Vec<TplSeg>, String> {
    let mut segs = Vec::new();
    let mut lit = String::new();
    let mut i = 0usize;
    while i < pattern.len() {
        if pattern[i..].starts_with('~') {
            if !lit.is_empty() {
                segs.push(TplSeg::Lit(lit.clone()));
                lit.clear();
            }
            let next = pattern.as_bytes().get(i + 1);
            let Some(digit) = next.and_then(|b| b.checked_sub(b'0')) else {
                return Err("template hole without a digit".to_owned());
            };
            segs.push(TplSeg::Hole(digit as usize));
            i += 2;
        } else {
            lit.push(pattern.as_bytes()[i] as char);
            i += 1;
        }
    }
    if !lit.is_empty() {
        segs.push(TplSeg::Lit(lit));
    }
    Ok(segs)
}

#[derive(Clone)]
enum TplSeg {
    Lit(String),
    Hole(usize),
}

/// 在 `text` 里找 `pattern` 的全部出现并替换。捕获段吃掉一段数字；同一编号
/// 的捕获必须吃进相同的数字串。字符串字面量（引号内）一律跳过——载荷里可能
/// 含有任意字母表文本，匹配进字符串就会破坏载荷。
fn apply_template(text: &str, pattern: &str, replacement: &str) -> (String, usize) {
    let segs = match parse_template(pattern) {
        Ok(s) => s,
        Err(_) => return (text.to_owned(), 0),
    };
    let repl_segs = parse_template(replacement).expect("replacement reuses the same grammar");
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut hits = 0usize;
    while i < text.len() {
        // 跳过字符串字面量（含转义）。
        let c = bytes[i];
        if c == b'\'' || c == b'"' {
            let quote = c;
            let start = i;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else {
                    i += 1;
                    if bytes[i - 1] == quote {
                        break;
                    }
                }
            }
            out.push_str(&text[start..i]);
            continue;
        }
        // 尝试在 i 处匹配模板。捕获按编号直接寻址，先按最大编号开槽。
        let max_hole = segs
            .iter()
            .filter_map(|s| match s {
                TplSeg::Hole(n) => Some(*n),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let mut captures: Vec<Option<String>> = vec![None; max_hole + 1];
        let mut pos = i;
        let mut matched = true;
        for seg in &segs {
            match seg {
                TplSeg::Lit(lit) => {
                    if !text[pos..].starts_with(lit.as_str()) {
                        matched = false;
                        break;
                    }
                    pos += lit.len();
                }
                TplSeg::Hole(n) => {
                    let mut j = pos;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                    if j == pos {
                        matched = false;
                        break;
                    }
                    let cap = text[pos..j].to_owned();
                    match captures.get_mut(*n) {
                        Some(None) => captures[*n] = Some(cap),
                        Some(Some(prev)) if prev != &cap => {
                            matched = false;
                            break;
                        }
                        _ => {}
                    }
                    pos = j;
                }
            }
        }
        if matched {
            for seg in &repl_segs {
                match seg {
                    TplSeg::Lit(lit) => out.push_str(lit),
                    TplSeg::Hole(n) => {
                        out.push_str(captures[*n].as_ref().expect("hole was captured"))
                    }
                }
            }
            i = pos;
            hits += 1;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    (out, hits)
}

impl Scatter {
    /// 某个注入点要插入的语句文本。
    pub(crate) fn blob(&self, slot: usize) -> &str {
        self.blobs.get(slot).map(String::as_str).unwrap_or("")
    }
}

/// 由装载点列表重建折叠期望值，供门校验生成器与壳内常量一致。
pub(crate) fn fold_of(keys: &[u64]) -> u64 {
    keys.iter().fold(0u64, |acc, key| acc.wrapping_add(*key))
}

#[cfg(test)]
mod capture_scan_tests {
    use super::has_shell_capture;

    #[test]
    fn payload_text_cannot_fake_a_shell_handle_capture() {
        assert!(!has_shell_capture(
            "function()local s='noise:t.more:VMS[9]' return s end"
        ));
        assert!(has_shell_capture("function()return t.e end"));
        assert!(has_shell_capture("function()return VMS[9]()end"));
    }
}
