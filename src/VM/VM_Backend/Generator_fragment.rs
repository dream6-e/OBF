//! 外壳碎片化：把巨型方法体切成"碎函数 + 单次调用树"（对齐 luraph14.9 §3.3/§3.5/§6.2）。
//!
//! 只做**结构改写**：从方法体里挑一段连续的语句，切成若干碎片，每片变成一个新的
//! 兄弟方法（在外层表里，`名字=function(self,…)`），原位置改成一个**单次调用**的
//! 微状态机：`while true do if S==v1 then 调1 elseif … else break end end`。
//! 数据流靠形参 + 返回值延续（`a,b=self:碎片(a,b)`），语义不变。
//!
//! 为什么能靠名字判断活跃性：外壳刚生成时所有标识符都来自 `GenRng::name()`，
//! 它在整个构建里**全局去重** —— "某个名字在后面还出现"就等于"那个变量还被用到"。
//!
//! 四条安全线（任一条不满足，该语句块就不搬）：
//!   1. 不得有本层的 `return`（搬进新函数会变成"从新函数返回"）；
//!   2. 不得有不在嵌套循环内的 `break`（会变成从新函数/状态机跳出）；
//!   3. `local` 声明的名字不得在块外再出现（搬走后外层看不见）；
//!   4. 不得含嵌套 `function`：闭包可能比碎片活得久，写回时机对不上。
//! 另外 `...` 一律不搬（新函数看不到调用者的 `...`）。

use std::collections::HashSet;

use super::Generator_util::GenRng;

/// 外壳条目：(方法名, self 形参名, 其余形参, 方法体)
pub type Entry = (String, String, Vec<String>, String);

#[derive(Default, Debug, Clone, Copy)]
pub struct FragStats {
    /// 被切过的方法数
    pub bodies: usize,
    /// 新生成的碎片方法数
    pub frags: usize,
    /// 生成的状态机个数
    pub machines: usize,
}

/// 方法体短于此值不切。
const MIN_BODY: usize = 900;
/// 单个碎片的目标长度区间。
const MIN_FRAG: usize = 80;
const MAX_FRAG: usize = 220;
/// 每个方法最多切出几片（控制体积增长）。
const MAX_PER_BODY: usize = 8;
/// 单个碎片的形参上限（超过就整块不搬，保持调用点短）。
const MAX_ARGS: usize = 24;

const KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local",
    "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
];

fn is_kw(w: &str) -> bool {
    KEYWORDS.contains(&w)
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn skip_string(b: &[u8], i: usize) -> usize {
    let quote = b[i];
    let mut j = i + 1;
    while j < b.len() {
        if b[j] == b'\\' {
            j += 2;
            continue;
        }
        if b[j] == quote {
            return j + 1;
        }
        j += 1;
    }
    b.len()
}

/// `[=*[` 长串：返回内容之后的位置；不是长串返回 None。
fn long_bracket(b: &[u8], i: usize) -> Option<usize> {
    if i >= b.len() || b[i] != b'[' {
        return None;
    }
    let mut j = i + 1;
    while j < b.len() && b[j] == b'=' {
        j += 1;
    }
    if j >= b.len() || b[j] != b'[' {
        return None;
    }
    let level = j - i - 1;
    let mut k = j + 1;
    while k < b.len() {
        if b[k] == b']' {
            let mut m = k + 1;
            let mut eq = 0;
            while m < b.len() && b[m] == b'=' {
                eq += 1;
                m += 1;
            }
            if eq == level && m < b.len() && b[m] == b']' {
                return Some(m + 1);
            }
        }
        k += 1;
    }
    Some(b.len())
}

/// 按**顶层 `;`** 切语句块。`;` 在 Lua 里永远是语句分隔符，切点必然合法
/// （漏切只会得到更大的块）。
fn split_chunks(body: &str) -> Vec<(usize, usize)> {
    let b = body.as_bytes();
    let mut out: Vec<(usize, usize)> = Vec::new();
    let (mut bracket, mut block, mut expect_do) = (0i32, 0i32, 0i32);
    let mut start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b'-' && i + 1 < b.len() && b[i + 1] == b'-' {
            let mut j = i + 2;
            while j < b.len() && b[j] != b'\n' {
                j += 1;
            }
            i = j;
            continue;
        }
        if c == b'[' {
            if let Some(end) = long_bracket(b, i) {
                i = end;
                continue;
            }
        }
        if c == b'"' || c == b'\'' {
            i = skip_string(b, i);
            continue;
        }
        if c == b'(' || c == b'[' || c == b'{' {
            bracket += 1;
            i += 1;
            continue;
        }
        if c == b')' || c == b']' || c == b'}' {
            bracket -= 1;
            i += 1;
            continue;
        }
        if is_ident_start(c) {
            let s0 = i;
            while i < b.len() && is_ident_char(b[i]) {
                i += 1;
            }
            match &body[s0..i] {
                "function" | "if" | "repeat" => block += 1,
                "for" | "while" => {
                    block += 1;
                    expect_do += 1;
                }
                "do" => {
                    if expect_do > 0 {
                        expect_do -= 1;
                    } else {
                        block += 1;
                    }
                }
                "end" | "until" => block -= 1,
                _ => {}
            }
            continue;
        }
        if c == b';' && bracket == 0 && block == 0 {
            out.push((start, i + 1));
            start = i + 1;
        }
        i += 1;
    }
    if start < body.len() && !body[start..].trim().is_empty() {
        out.push((start, body.len()));
    }
    out
}

struct ChunkInfo {
    local_return: bool,
    stray_break: bool,
    has_vararg: bool,
    has_nested_fn: bool,
    declared: Vec<String>,
    idents: HashSet<String>,
}

fn inspect(src: &str) -> ChunkInfo {
    let b = src.as_bytes();
    let mut stack: Vec<u8> = Vec::new();
    let mut info = ChunkInfo {
        local_return: false,
        stray_break: false,
        has_vararg: false,
        has_nested_fn: false,
        declared: Vec::new(),
        idents: HashSet::new(),
    };
    let in_fn = |st: &Vec<u8>| st.iter().any(|&k| k == b'f');
    let in_loop = |st: &Vec<u8>| st.iter().any(|&k| k == b'l');
    let mut i = 0usize;
    // `while c do` / `for … do` 里的 `do` 不是新的块，需要和 `while`/`for` 配对消掉
    let mut expect_do = 0i32;
    while i < b.len() {
        let c = b[i];
        if c == b'-' && i + 1 < b.len() && b[i + 1] == b'-' {
            let mut j = i + 2;
            while j < b.len() && b[j] != b'\n' {
                j += 1;
            }
            i = j;
            continue;
        }
        if c == b'[' {
            if let Some(end) = long_bracket(b, i) {
                i = end;
                continue;
            }
        }
        if c == b'"' || c == b'\'' {
            i = skip_string(b, i);
            continue;
        }
        if c == b'.' && i + 2 < b.len() && b[i + 1] == b'.' && b[i + 2] == b'.' {
            info.has_vararg = true;
            i += 3;
            continue;
        }
        if !is_ident_start(c) {
            i += 1;
            continue;
        }
        let s0 = i;
        while i < b.len() && is_ident_char(b[i]) {
            i += 1;
        }
        let w = &src[s0..i];
        if is_kw(w) {
            match w {
                "function" => {
                    // `src` 本身已经是一个方法体，所以任意 function token 都是
                    // 相对它的内层闭包；移动后会改变被捕获变量的 cell，整块跳过。
                    info.has_nested_fn = true;
                    stack.push(b'f');
                }
                "if" => stack.push(b'o'),
                "do" => {
                    if expect_do > 0 {
                        expect_do -= 1;
                    } else {
                        stack.push(b'o');
                    }
                }
                "repeat" => stack.push(b'l'),
                "for" | "while" => {
                    stack.push(b'l');
                    expect_do += 1;
                }
                "end" | "until" => {
                    stack.pop();
                }
                "return" => {
                    if !in_fn(&stack) {
                        info.local_return = true;
                    }
                }
                "break" => {
                    if !in_loop(&stack) {
                        info.stray_break = true;
                    }
                }
                "local" => {
                    if !in_fn(&stack) && stack.is_empty() {
                        let mut j = i;
                        while j < b.len() && b[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if src[j..].starts_with("function") {
                            let mut k = j + 8;
                            while k < b.len() && b[k].is_ascii_whitespace() {
                                k += 1;
                            }
                            let k0 = k;
                            while k < b.len() && is_ident_char(b[k]) {
                                k += 1;
                            }
                            if k > k0 {
                                info.declared.push(src[k0..k].to_string());
                            }
                        } else {
                            loop {
                                while j < b.len() && b[j].is_ascii_whitespace() {
                                    j += 1;
                                }
                                let k0 = j;
                                while j < b.len() && is_ident_char(b[j]) {
                                    j += 1;
                                }
                                if j == k0 {
                                    break;
                                }
                                info.declared.push(src[k0..j].to_string());
                                while j < b.len() && b[j].is_ascii_whitespace() {
                                    j += 1;
                                }
                                if j < b.len() && b[j] == b',' {
                                    j += 1;
                                    continue;
                                }
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        info.idents.insert(w.to_string());
    }
    info
}

/// 片段里被**赋值**的可见名字（`a = …` / `a,b = …`）。
/// 只有这些需要作为返回值写回；只读的名字传进去就够了。
fn written_names(src: &str, visible: &HashSet<String>, self_var: &str) -> HashSet<String> {
    let b = src.as_bytes();
    let mut out: HashSet<String> = HashSet::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'=' {
            i += 1;
            continue;
        }
        if i + 1 < b.len() && b[i + 1] == b'=' {
            i += 2;
            continue;
        }
        // `==` / `~=` / `<` `>` 等已排除；看左边是不是名字列表
        let mut j = i;
        while j > 0 && b[j - 1].is_ascii_whitespace() {
            j -= 1;
        }
        if j == 0 || !is_ident_char(b[j - 1]) {
            i += 1;
            continue;
        }
        // 向左收集 `name (, name)*`
        let mut names: Vec<String> = Vec::new();
        let mut k = j;
        loop {
            while k > 0 && b[k - 1].is_ascii_whitespace() {
                k -= 1;
            }
            let e = k;
            while k > 0 && is_ident_char(b[k - 1]) {
                k -= 1;
            }
            if k == e {
                break;
            }
            names.push(src[k..e].to_string());
            while k > 0 && b[k - 1].is_ascii_whitespace() {
                k -= 1;
            }
            if k > 0 && b[k - 1] == b',' {
                k -= 1;
                continue;
            }
            break;
        }
        for n in names {
            if n != self_var && visible.contains(&n) {
                out.insert(n);
            }
        }
        i += 1;
    }
    out
}

fn word_appears(text: &str, name: &str) -> bool {
    let b = text.as_bytes();
    let nb = name.as_bytes();
    if nb.is_empty() || b.len() < nb.len() {
        return false;
    }
    let mut from = 0usize;
    while let Some(p) = text[from..].find(name) {
        let at = from + p;
        let before_ok = at == 0 || !is_ident_char(b[at - 1]);
        let after = at + nb.len();
        let after_ok = after >= b.len() || !is_ident_char(b[after]);
        if before_ok && after_ok {
            return true;
        }
        from = at + 1;
        if from >= b.len() {
            break;
        }
    }
    false
}

/// 对**单个方法体**做碎片化：碎片写进 `added`，方法体原地改写。
/// 返回 (碎片数, 状态机数)。
///
/// 做法：在方法体里找最长的一段"可搬"语句区，把区里相邻的语句切成碎片
/// （默认一块一片，短块可以拼两片），**连续两片以上**用微状态机串起来，
/// 孤立的一片就用一次普通调用。
pub fn frag_body(
    body: &mut String,
    self_var: &str,
    params: &[String],
    added: &mut Vec<Entry>,
    rng: &mut GenRng,
) -> (usize, usize) {
    if body.len() < MIN_BODY {
        return (0, 0);
    }
    let chunks = split_chunks(body);
    if chunks.len() < 6 {
        return (0, 0);
    }
    let infos: Vec<ChunkInfo> = chunks.iter().map(|&(a, b)| inspect(&body[a..b])).collect();
    // 硬性不可搬：本层 return / 游离 break / vararg / 嵌套 function
    let hard_bad: Vec<bool> = infos
        .iter()
        .map(|i| i.local_return || i.stray_break || i.has_vararg || i.has_nested_fn)
        .collect();

    // 最长的一段连续"非硬性不可搬"区
    let (mut best_a, mut best_b, mut best_sz) = (0usize, 0usize, 0usize);
    let mut i = 0usize;
    while i < chunks.len() {
        if hard_bad[i] {
            i += 1;
            continue;
        }
        let mut j = i;
        let mut sz = 0usize;
        while j < chunks.len() && !hard_bad[j] {
            sz += chunks[j].1 - chunks[j].0;
            j += 1;
        }
        if sz > best_sz {
            best_sz = sz;
            best_a = i;
            best_b = j;
        }
        i = j;
    }
    if best_sz < MIN_FRAG {
        return (0, 0);
    }

    // 窗口之外可见的名字：形参 + 窗口之前 `local` 出来的（窗口内的 local 不外泄）
    let mut visible: HashSet<String> = params.iter().cloned().collect();
    for info in infos.iter().take(best_a) {
        for d in &info.declared {
            visible.insert(d.clone());
        }
    }
    let used_with = |vis: &HashSet<String>, lo: usize, hi: usize| -> Vec<String> {
        let mut used: Vec<String> = Vec::new();
        for k in lo..hi {
            for id in &infos[k].idents {
                if id != self_var && vis.contains(id) && !used.contains(id) {
                    used.push(id.clone());
                }
            }
        }
        used.sort();
        used
    };
    let used_of = |lo: usize, hi: usize| -> Vec<String> { used_with(&visible, lo, hi) };

    // 选碎片：从 best_a 起，一块一片；短块可并两片；形参超限就跳过该块。
    let mut frag_of: Vec<Option<(usize, usize)>> = vec![None; chunks.len()];
    let mut taken = 0usize;
    let mut k = best_a;
    while k < best_b && taken < MAX_PER_BODY {
        let mut size = chunks[k].1 - chunks[k].0;
        let mut hi = k + 1;
        if size + 200 < MIN_FRAG && k + 1 < best_b {
            let two = size + (chunks[k + 1].1 - chunks[k + 1].0);
            if two <= MAX_FRAG * 2 {
                size = two;
                hi = k + 2;
            }
        }
        let ok = !group_leaks(body, &chunks, &infos, k, hi) && used_of(k, hi).len() <= MAX_ARGS;
        if ok {
            frag_of[k] = Some((k, hi));
            taken += 1;
            k = hi;
        } else {
            k += 1;
        }
    }
    if taken == 0 {
        return (0, 0);
    }

    // 输出：按块走，碎片位替换成调用；相邻碎片 ≥2 用微状态机串起来
    let added_before = added.len();
    let mut out = String::with_capacity(body.len() + taken * 120);
    let mut idx = 0usize;
    let mut frags = 0usize;
    let mut machines = 0usize;
    while idx < chunks.len() {
        if let Some((lo, hi)) = frag_of[idx] {
            // 收集连续碎片
            let mut run: Vec<(usize, usize)> = vec![(lo, hi)];
            let mut next = hi;
            while next < chunks.len() {
                match frag_of[next] {
                    Some((a, b)) => {
                        run.push((a, b));
                        next = b;
                    }
                    None => break,
                }
            }
            let mut calls: Vec<String> = Vec::with_capacity(run.len());
            for &(a, b) in &run {
                let used = used_with(&visible, a, b);
                // 只把**被赋值**的名字作为返回值写回（只读的传进去就够）；
                // 返回值顺序必须与调用点左侧完全一致，否则会张冠李戴。
                let written =
                    written_names(&body[chunks[a].0..chunks[b - 1].1], &visible, self_var);
                let ret: Vec<&String> = used.iter().filter(|u| written.contains(*u)).collect();
                let fname = rng.name();
                let mut fbody = String::with_capacity(chunks[b - 1].1 - chunks[a].0 + 24);
                fbody.push_str(body[chunks[a].0..chunks[b - 1].1].trim_end());
                if !ret.is_empty() {
                    fbody.push_str(" return ");
                    fbody.push_str(&ret.iter().map(|r| r.as_str()).collect::<Vec<_>>().join(","));
                }
                added.push((fname.clone(), self_var.to_string(), used.clone(), fbody));
                calls.push(match (ret.is_empty(), used.is_empty()) {
                    (_, true) => format!("{}:{}()", self_var, fname),
                    (true, false) => format!("{}:{}({})", self_var, fname, used.join(",")),
                    (false, false) => format!(
                        "{}={}:{}({})",
                        ret.iter().map(|r| r.as_str()).collect::<Vec<_>>().join(","),
                        self_var,
                        fname,
                        used.join(",")
                    ),
                });
            }
            frags += calls.len();
            if !calls.is_empty() {
                // 每个碎片组都用微状态机（即使只有一片也保留状态/退出分支），
                // 让控制流形态向目标靠近，而不改业务步骤。
                let st = rng.name();
                let mut states: Vec<String> = Vec::with_capacity(calls.len() + 1);
                let mut seen_states = HashSet::new();
                while states.len() <= calls.len() {
                    let value = rng.range(0x1000, 0xFFFFF);
                    if seen_states.insert(value) {
                        states.push(format!("0X{:X}", value));
                    }
                }
                out.push_str(&format!("local {}={};while true do ", st, states[0]));
                for (n, call) in calls.iter().enumerate() {
                    let cur = &states[n];
                    let head = if n == 0 { "if" } else { "elseif" };
                    // 反条件空块：`if S~=<v> then else 调用 end` —— S 此刻等于 v，
                    // 于是走 else 分支执行调用，与 luraph §6.6 同源。
                    out.push_str(&format!(
                        "{} {}=={} then if {}~={} then else {} end;",
                        head, st, cur, st, cur, call
                    ));
                    if n + 1 == calls.len() {
                        out.push_str("break ");
                    } else {
                        out.push_str(&format!("{}={};", st, states[n + 1]));
                    }
                }
                out.push_str(&format!("else {}={};break end end;", st, states[0]));
                machines += 1;
            }
            for info in infos.iter().take(next).skip(idx) {
                for d in &info.declared {
                    visible.insert(d.clone());
                }
            }
            idx = next;
        } else {
            out.push_str(&body[chunks[idx].0..chunks[idx].1]);
            for d in &infos[idx].declared {
                visible.insert(d.clone());
            }
            idx += 1;
        }
    }

    if frags == 0 {
        added.truncate(added_before);
        return (0, 0);
    }
    *body = out;
    (frags, machines)
}

/// 对已登记的外壳条目做碎片化（方法体较小的那些通常达不到 MIN_BODY，直接跳过）。
pub fn fragment(entries: &mut Vec<Entry>, rng: &mut GenRng) -> FragStats {
    let mut stats = FragStats::default();
    let mut added: Vec<Entry> = Vec::new();
    for (_, self_var, params, body) in entries.iter_mut() {
        let mut changed = false;
        for _ in 0..3 {
            let (f, m) = frag_body(body, self_var, params, &mut added, rng);
            if f == 0 {
                break;
            }
            changed = true;
            stats.frags += f;
            stats.machines += m;
        }
        if changed {
            stats.bodies += 1;
        }
    }
    entries.extend(added);
    stats
}

/// 组 [lo,hi) 里 `local` 出来的名字是否漏到组外。
fn group_leaks(
    body: &str,
    chunks: &[(usize, usize)],
    infos: &[ChunkInfo],
    lo: usize,
    hi: usize,
) -> bool {
    let head = &body[..chunks[lo].0];
    let tail = &body[chunks[hi - 1].1..];
    for info in infos.iter().take(hi).skip(lo) {
        for d in &info.declared {
            if word_appears(head, d) || word_appears(tail, d) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::split_chunks;

    #[test]
    fn splits_only_top_level_semicolons() {
        let src = "a=1; if x then b=';'; c=(function() return 2 end)() end; d=3;";
        let chunks = split_chunks(src);
        let parts: Vec<&str> = chunks.iter().map(|&(a, b)| &src[a..b]).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "a=1;");
        assert!(parts[1].starts_with(" if x then"));
        assert_eq!(parts[2], " d=3;");
    }

    #[test]
    fn ignores_semicolons_inside_long_strings_and_comments() {
        let src = "a=[=[one; two]=]; -- comment; ignored\nb=2;";
        let chunks = split_chunks(src);
        let parts: Vec<&str> = chunks.iter().map(|&(a, b)| &src[a..b]).collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("one; two"));
        assert_eq!(parts[1], " -- comment; ignored\nb=2;");
    }
}
