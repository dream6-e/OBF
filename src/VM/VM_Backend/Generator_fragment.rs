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
    all_locals: HashSet<String>,
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
        all_locals: HashSet::new(),
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
                "for" => {
                    stack.push(b'l');
                    expect_do += 1;
                    let mut j = i;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    loop {
                        let k0 = j;
                        while j < b.len() && is_ident_char(b[j]) {
                            j += 1;
                        }
                        if j == k0 || &src[k0..j] == "in" {
                            break;
                        }
                        info.all_locals.insert(src[k0..j].to_string());
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
                "while" => {
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
                    let mut j = i;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if src[j..].starts_with("function") {
                        j += 8;
                        while j < b.len() && b[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        let k0 = j;
                        while j < b.len() && is_ident_char(b[j]) {
                            j += 1;
                        }
                        if j > k0 {
                            let name = src[k0..j].to_string();
                            info.all_locals.insert(name.clone());
                            if stack.is_empty() {
                                info.declared.push(name);
                            }
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
                            let name = src[k0..j].to_string();
                            info.all_locals.insert(name.clone());
                            if stack.is_empty() {
                                info.declared.push(name);
                            }
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

#[derive(Clone)]
struct LexTok {
    text: String,
    start: usize,
    end: usize,
    word: bool,
}

/// 最小 Lua 词法扫描：字符串与注释不参与关键字/块匹配。
fn lex_code(src: &str) -> Vec<LexTok> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i] == b'-' && i + 1 < b.len() && b[i + 1] == b'-' {
            let mut j = i + 2;
            if j < b.len() && b[j] == b'[' {
                if let Some(end) = long_bracket(b, j) {
                    i = end;
                    continue;
                }
            }
            while j < b.len() && b[j] != b'\n' {
                j += 1;
            }
            i = j;
            continue;
        }
        if b[i] == b'[' {
            if let Some(end) = long_bracket(b, i) {
                i = end;
                continue;
            }
        }
        if b[i] == b'\'' || b[i] == b'"' {
            i = skip_string(b, i);
            continue;
        }
        let start = i;
        if is_ident_start(b[i]) {
            i += 1;
            while i < b.len() && is_ident_char(b[i]) {
                i += 1;
            }
            out.push(LexTok {
                text: src[start..i].to_string(),
                start,
                end: i,
                word: true,
            });
        } else {
            i += 1;
            out.push(LexTok {
                text: src[start..i].to_string(),
                start,
                end: i,
                word: false,
            });
        }
    }
    out
}

#[derive(Clone)]
struct FunctionSpan {
    function_start: usize,
    function_end: usize,
    params: Vec<String>,
    body_start: usize,
    body_end: usize,
}

/// 返回当前 source 直接包含的函数体范围；嵌套函数由递归调用负责，避免重叠改写。
fn direct_function_bodies(src: &str) -> Vec<FunctionSpan> {
    let toks = lex_code(src);
    let mut result = Vec::new();
    let mut i = 0usize;
    while i < toks.len() {
        if toks[i].text != "function" || !toks[i].word {
            i += 1;
            continue;
        }
        // 函数名只能包含标识符、点和冒号；第一个 `(` 是参数表起点。
        let mut open = i + 1;
        while open < toks.len() && toks[open].text != "(" {
            if toks[open].text == ";" || toks[open].text == "=" {
                break;
            }
            open += 1;
        }
        if open >= toks.len() || toks[open].text != "(" {
            i += 1;
            continue;
        }
        let mut paren = 1i32;
        let mut close = open + 1;
        while close < toks.len() && paren > 0 {
            match toks[close].text.as_str() {
                "(" => paren += 1,
                ")" => paren -= 1,
                _ => {}
            }
            close += 1;
        }
        if paren != 0 {
            i += 1;
            continue;
        }
        let params = toks[open + 1..close - 1]
            .iter()
            .filter(|t| t.word && !is_kw(&t.text))
            .map(|t| t.text.clone())
            .collect();
        let body_start = toks[close - 1].end;

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Block {
            Function,
            If,
            LoopPending,
            Loop,
            Do,
            Repeat,
        }
        let mut stack = vec![Block::Function];
        let mut j = close;
        let mut body_end = None;
        while j < toks.len() {
            if !toks[j].word {
                j += 1;
                continue;
            }
            match toks[j].text.as_str() {
                "function" => stack.push(Block::Function),
                "if" => stack.push(Block::If),
                "for" | "while" => stack.push(Block::LoopPending),
                "do" => {
                    if stack.last() == Some(&Block::LoopPending) {
                        *stack.last_mut().unwrap() = Block::Loop;
                    } else {
                        stack.push(Block::Do);
                    }
                }
                "repeat" => stack.push(Block::Repeat),
                "end" => {
                    stack.pop();
                    if stack.is_empty() {
                        body_end = Some((toks[j].start, j + 1));
                        break;
                    }
                }
                "until" => {
                    if stack.last() == Some(&Block::Repeat) {
                        stack.pop();
                    }
                }
                _ => {}
            }
            j += 1;
        }
        if let Some((end_start, after_idx)) = body_end {
            if body_start <= end_start {
                result.push(FunctionSpan {
                    function_start: toks[i].start,
                    function_end: toks[after_idx - 1].end,
                    params,
                    body_start,
                    body_end: end_start,
                });
            }
            i = after_idx;
        } else {
            i += 1;
        }
    }
    result
}

const SAFE_GLOBALS: &[&str] = &[
    "_ENV",
    "_G",
    "assert",
    "bit32",
    "buffer",
    "collectgarbage",
    "coroutine",
    "dofile",
    "error",
    "game",
    "getmetatable",
    "ipairs",
    "load",
    "loadfile",
    "math",
    "next",
    "os",
    "pairs",
    "pcall",
    "print",
    "rawequal",
    "rawget",
    "rawlen",
    "rawset",
    "require",
    "select",
    "setmetatable",
    "shared",
    "string",
    "table",
    "task",
    "tonumber",
    "tostring",
    "type",
    "unpack",
    "utf8",
    "warn",
    "workspace",
    "xpcall",
    "Enum",
    "Instance",
    "Vector3",
    "CFrame",
    "Color3",
    "UDim2",
    "BrickColor",
    "Ray",
    "TweenInfo",
];

/// 取嵌套函数定义点之前可见的参数/局部名。仅吸收完整的顶层分号语句，
/// 避免把 `local f=function(...)` 正在初始化的 f 错当成闭包可见变量。
fn visible_at(src: &str, pos: usize, inherited: &HashSet<String>) -> HashSet<String> {
    let prefix = &src[..pos.min(src.len())];
    let chunks = split_chunks(prefix);
    let mut visible = inherited.clone();
    for (index, &(a, b)) in chunks.iter().enumerate() {
        let complete = b < prefix.len() || prefix[..b].trim_end().ends_with(';');
        if !complete && index + 1 == chunks.len() {
            continue;
        }
        visible.extend(inspect(&prefix[a..b]).declared);
    }
    visible
}

/// 只提升能解析出捕获集合的函数体。属性名不算词法变量；
/// 未知标识符一律当作外层捕获，只有定义点可见时才允许显式传递。
fn scope_captures_resolved(
    src: &str,
    params: &[String],
    inherited: &HashSet<String>,
    self_var: &str,
) -> bool {
    let chunks = split_chunks(src);
    if chunks.len() < 6 {
        return false;
    }
    let infos: Vec<ChunkInfo> = chunks.iter().map(|&(a, b)| inspect(&src[a..b])).collect();
    // nested function 子树由递归层负责；当前层只验证函数体自己的词法引用。
    let nested = direct_function_bodies(src);
    let mut visible: HashSet<String> = inherited.clone();
    visible.extend(params.iter().cloned());
    visible.insert(self_var.to_string());
    for info in &infos {
        // 函数声明前的局部绑定属于当前作用域；其余子树局部不能冒充当前层捕获。
        visible.extend(info.declared.iter().cloned());
        if !info.has_nested_fn {
            visible.extend(info.all_locals.iter().cloned());
        }
    }
    let toks = lex_code(src);
    let mut properties = HashSet::new();
    for i in 1..toks.len() {
        if toks[i].word && matches!(toks[i - 1].text.as_str(), "." | ":") {
            properties.insert(toks[i].text.clone());
        }
    }
    let mut nested_index = 0usize;
    for t in &toks {
        while nested_index < nested.len() && nested[nested_index].function_end <= t.start {
            nested_index += 1;
        }
        if nested_index < nested.len()
            && nested[nested_index].function_start <= t.start
            && t.start < nested[nested_index].function_end
        {
            continue;
        }
        if !t.word || is_kw(&t.text) || properties.contains(&t.text) {
            continue;
        }
        if matches!(t.text.as_str(), "getfenv" | "setfenv" | "debug") {
            return false;
        }
        if !visible.contains(&t.text) && !SAFE_GLOBALS.contains(&t.text.as_str()) {
            return false;
        }
    }
    !params.iter().any(|p| p == self_var)
        && !infos
            .iter()
            .any(|i| i.declared.iter().any(|n| n == self_var))
}

/// 递归遍历既有闭包；捕获集可解析时，把安全块的 upvalue 显式作为兄弟方法形参。
/// `budget` 是可提升的碎片数上限，控制外壳增长。
fn fragment_nested_functions(
    src: &str,
    self_var: &str,
    inherited: &HashSet<String>,
    added: &mut Vec<Entry>,
    rng: &mut GenRng,
    budget: &mut usize,
    depth: usize,
) -> String {
    if *budget == 0 || depth >= 5 {
        return src.to_string();
    }
    let spans = direct_function_bodies(src);
    let mut out = String::with_capacity(src.len() + 128);
    let mut cursor = 0usize;
    let mut changed = false;
    for span in spans {
        let start = span.body_start;
        let end = span.body_end;
        if start < cursor || end > src.len() {
            continue;
        }
        let function_outer = visible_at(src, span.function_start, inherited);
        let mut child_visible = function_outer.clone();
        child_visible.extend(span.params.iter().cloned());
        let mut inner = fragment_nested_functions(
            &src[start..end],
            self_var,
            &child_visible,
            added,
            rng,
            budget,
            depth + 1,
        );
        let mut lift_params = span.params.clone();
        for name in &function_outer {
            if name != self_var && !lift_params.contains(name) {
                lift_params.push(name.clone());
            }
        }
        if *budget > 0 && scope_captures_resolved(&inner, &lift_params, &function_outer, self_var) {
            let before = added.len();
            let original = inner.clone();
            let (frags, _) = frag_body(&mut inner, self_var, &lift_params, added, rng);
            if frags > *budget {
                added.truncate(before);
                inner = original;
            } else {
                *budget -= frags;
            }
        }
        out.push_str(&src[cursor..start]);
        out.push_str(&inner);
        cursor = end;
        changed |= inner != src[start..end];
        if *budget == 0 {
            break;
        }
    }
    if !changed {
        return src.to_string();
    }
    out.push_str(&src[cursor..]);
    out
}

/// 对尚未登记的入口方法体，尝试把闭包内安全片段提升为外层兄弟方法。
pub fn fragment_nested_body(
    body: &mut String,
    self_var: &str,
    added: &mut Vec<Entry>,
    rng: &mut GenRng,
    budget: usize,
) -> usize {
    let mut remaining = budget;
    let before = added.len();
    let mut visible = HashSet::new();
    visible.insert(self_var.to_string());
    *body = fragment_nested_functions(body, self_var, &visible, added, rng, &mut remaining, 0);
    added.len() - before
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
    let mut nested_budget = 16usize;
    for (_, self_var, params, body) in entries.iter_mut() {
        let mut visible: HashSet<String> = params.iter().cloned().collect();
        visible.insert(self_var.clone());
        *body = fragment_nested_functions(
            body,
            self_var,
            &visible,
            &mut added,
            rng,
            &mut nested_budget,
            0,
        );
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
    use super::{fragment_nested_body, split_chunks};
    use crate::VM::VM_Backend::Generator_util::GenRng;
    use std::process::Command;

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

    #[test]
    fn nested_local_scope_lifts_to_sibling_methods_and_preserves_behavior() {
        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }
        let mut nested_body = String::from("local calc=function(v) local x=v;");
        for _ in 0..200 {
            nested_body.push_str("x=x+1;");
        }
        nested_body.push_str("return x end; return calc(17);");
        let source = format!(
            "local S={{}};local entry=function(S){} end;print(entry(S));",
            nested_body
        );
        let mut transformed_body = nested_body.clone();
        let mut added = Vec::new();
        let lifted = fragment_nested_body(
            &mut transformed_body,
            "S",
            &mut added,
            &mut GenRng::new(1),
            8,
        );
        assert!(
            lifted > 0,
            "expected nested logic to become sibling methods"
        );
        assert!(!added.is_empty());
        let mut transformed = String::from("local S={};");
        for (name, self_var, params, body) in &added {
            let mut args = vec![self_var.clone()];
            args.extend(params.iter().cloned());
            transformed.push_str(&format!(
                "S[{name:?}]=function({}) {} end;",
                args.join(","),
                body
            ));
        }
        transformed.push_str(&format!(
            "S.entry=function(S){} end;print(S:entry());",
            transformed_body
        ));

        let dir = std::env::temp_dir().join(format!("kryvex_fragment_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create fragment test directory");
        let original_path = dir.join("original.lua");
        let transformed_path = dir.join("transformed.lua");
        std::fs::write(&original_path, source).expect("write original Lua source");
        std::fs::write(&transformed_path, transformed).expect("write transformed Lua source");
        let run = |path: &std::path::Path| {
            let result = Command::new(&lua).arg(path).output().expect("run Lua 5.1");
            assert!(
                result.status.success(),
                "Lua 5.1 failed: {}\n{}",
                String::from_utf8_lossy(&result.stderr),
                std::fs::read_to_string(path).unwrap_or_default()
            );
            String::from_utf8_lossy(&result.stdout).into_owned()
        };
        assert_eq!(run(&original_path), run(&transformed_path));
    }

    #[test]
    fn lifts_captured_upvalues_as_explicit_params_and_writes_them_back() {
        let mut nested_body = String::from("local outer=7;local calc=function(v) local x=v;");
        for _ in 0..200 {
            nested_body.push_str("x=x+outer;outer=outer+1;");
        }
        nested_body.push_str("return x+outer end; return calc(17);");
        let source = format!(
            "local S={{}};local entry=function(S){} end;print(entry(S));",
            nested_body
        );
        let mut transformed_body = nested_body.clone();
        let mut added = Vec::new();
        let lifted = fragment_nested_body(
            &mut transformed_body,
            "S",
            &mut added,
            &mut GenRng::new(2),
            8,
        );
        assert!(
            lifted > 0,
            "visible outer upvalue should be passed explicitly"
        );
        assert!(added
            .iter()
            .any(|entry| entry.2.contains(&"outer".to_string())));
        let mut transformed = String::from("local S={};");
        for (name, self_var, params, body) in &added {
            let mut args = vec![self_var.clone()];
            args.extend(params.iter().cloned());
            transformed.push_str(&format!(
                "S[{name:?}]=function({}) {} end;",
                args.join(","),
                body
            ));
        }
        transformed.push_str(&format!(
            "S.entry=function(S){} end;print(S:entry());",
            transformed_body
        ));

        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("kryvex_capture_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create capture test directory");
        let original_path = dir.join("original.lua");
        let transformed_path = dir.join("transformed.lua");
        std::fs::write(&original_path, source).expect("write original Lua source");
        std::fs::write(&transformed_path, transformed).expect("write transformed Lua source");
        let run = |path: &std::path::Path| {
            let result = Command::new(&lua).arg(path).output().expect("run Lua 5.1");
            assert!(
                result.status.success(),
                "Lua 5.1 failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            String::from_utf8_lossy(&result.stdout).into_owned()
        };
        assert_eq!(run(&original_path), run(&transformed_path));
    }
}
