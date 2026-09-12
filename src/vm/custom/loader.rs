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
}

/// 等价改写白名单：`(原始子串, 等价子串)`。两份实现互为等价写法，命中即可
/// 生成变体 B。每一对都是纯代数恒等式，不重复求值、不引入新数字，其等价性由
/// `k20_respelling_pairs_are_provably_equivalent` 门穷举证明。
const RESPPELLINGS: [(&str, &str); 2] = [
    // 水印打包：同一个多项式的两种结合顺序（对 a,b,c,d 各自线性，见门证明）。
    (
        "return((a*256+b)*256+c)*256+d;",
        "return d+(c+(b+a*256)*256)*256;",
    ),
    // 探测字段：257 拆成 1+256，纯算术恒等。
    (
        "a=(a*257+SB(A,b))%2147483647;",
        "a=(a+a*256+SB(A,b))%2147483647;",
    ),
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
    let mut cursor = 0usize;
    for (slot, doublable, field) in candidates {
        let Some((key, body)) = split_field(&field) else {
            kept.push(field);
            continue;
        };
        // 搬迁后字段体里任何对壳句柄的自由引用都会指向入口局部变量，
        // 语义静默改变；这种字段永不搬迁。
        if body.contains("t.") || body.contains("VMS") {
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
            let raw = cursor % SLOTS;
            cursor += 1;
            raw.min(last)
        };
        // `doublable` 关掉「同键两份」：带审计环境探测的字段（键推导探测、
        // base86 段探测）一旦复制，`scope` 审计里的十二处探测就不止十二处，
        // 那条 fail-closed 门必须保持精确计数。
        if doublable && respelled > 0 && body.len() <= DUPLICATE_LIMIT && last >= 1 {
            // 同一键装两份：先 A 后 B，B 紧贴在读取之前生效，A 从此不再生效。
            let b = last;
            let a = pick.min(b - 1);
            push_install(
                &mut blobs, &mut fold, &mut sites, &mut plan, a, last, key, &body,
            );
            push_install(
                &mut blobs, &mut fold, &mut sites, &mut plan, b, last, key, &variant_b,
            );
            continue;
        }
        push_install(
            &mut blobs, &mut fold, &mut sites, &mut plan, pick, last, key, &variant_b,
        );
    }
    Scatter {
        kept,
        blobs,
        sites,
        installed,
        fold,
        plan,
    }
}

/// 把一条装载语句写进槽位文本，并折叠该键。
#[allow(clippy::too_many_arguments)]
fn push_install(
    blobs: &mut [String],
    fold: &mut u64,
    sites: &mut usize,
    plan: &mut Vec<(u64, usize, usize)>,
    slot: usize,
    read_slot: usize,
    key: u64,
    body: &str,
) {
    debug_assert!(slot < SLOTS, "install slot out of range");
    debug_assert!(slot <= read_slot, "install after first read");
    // `;` 收尾：装载语句与后面的 `ck` 累加必须各自成语句，字段体本身以 `end`
    // 结尾，少了分隔符会粘成 `endck`。
    blobs[slot].push_str(&format!("VMS[{key}]={body};ck=ck+{key};"));
    *fold = fold.wrapping_add(key);
    *sites += 1;
    plan.push((key, slot, read_slot));
}

/// 生成等价的第二写法：先套白名单逐字对，再机械改写守卫的否定形式。
/// 返回变体文本与命中次数（0 表示没有可用对，此时不做双份装载）。
fn respell_body(body: &str) -> (String, usize) {
    let mut out = body.to_owned();
    let mut hits = 0usize;
    for (from, to) in RESPPELLINGS {
        while let Some(at) = out.find(from) {
            out.replace_range(at..at + from.len(), to);
            hits += 1;
            // 白名单两侧互不包含，命中后不会再次匹配同一条。
            break;
        }
    }
    let (guard_free, guard_hits) = respell_guards(&out);
    if guard_hits > 0 {
        return (guard_free, hits + guard_hits);
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
