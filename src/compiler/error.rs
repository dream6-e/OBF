use std::fmt;
use std::fs;
use std::cell::RefCell;
use std::collections::HashMap;

pub type LuaResult<T> = Result<T, LuaError>;

#[derive(Debug)]
pub enum LuaError {
    Syntax(SyntaxError),
    Semantic(SemanticError),
    Runtime(RuntimeError),
    Multiple(Vec<LuaError>),
    Memory,
    ErrorHandler,
    Io(std::io::Error),
    Yield(u32),
}

#[derive(Debug)]
pub struct SyntaxError {
    pub message: String,
    pub source: String,
    pub line: u32,
    pub raw_message: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct SemanticError {
    pub message: String,
    pub source: String,
    pub line: u32,
    pub token: Option<String>,
}

#[derive(Debug)]
pub struct RuntimeError {
    pub message: String,
    pub level: u32,
    pub traceback: Vec<TraceEntry>,
}

#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub source: String,
    pub line: u32,
    pub name: Option<String>,
}

thread_local! {
    static ACTIVE_SOURCE: RefCell<Option<String>> = RefCell::new(None);
}

pub fn set_active_source(source: String) {
    ACTIVE_SOURCE.with(|s| {
        *s.borrow_mut() = Some(source);
    });
}

impl RuntimeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            level: 0,
            traceback: vec![],
        }
    }
}

pub fn runtime_error(message: impl Into<String>) -> LuaError {
    LuaError::Runtime(RuntimeError::new(message))
}

fn get_file_lines(source: &str, target_line: u32) -> Vec<(u32, String)> {
    let mut lines = Vec::new();
    let filepath = source.strip_prefix('@').unwrap_or(source);
    
    let content_opt = if source == "compressor_parser" {
        ACTIVE_SOURCE.with(|s| s.borrow().clone())
    } else {
        fs::read_to_string(filepath).ok()
    };

    if let Some(content) = content_opt {
        let all_lines: Vec<&str> = content.lines().collect();
        let target_idx = (target_line.saturating_sub(1)) as usize;
        
        if target_idx < all_lines.len() {
            let mut prev_non_empty = None;
            for i in (0..target_idx).rev() {
                if !all_lines[i].trim().is_empty() {
                    prev_non_empty = Some((i + 1, all_lines[i].to_string()));
                    break;
                }
            }
            
            let mut next_non_empty = None;
            for i in (target_idx + 1)..all_lines.len() {
                if !all_lines[i].trim().is_empty() {
                    next_non_empty = Some((i + 1, all_lines[i].to_string()));
                    break;
                }
            }
            
            if let Some((p_num, p_text)) = prev_non_empty {
                lines.push((p_num as u32, p_text));
                if p_num as u32 + 1 < target_line {
                    lines.push((0, "...".to_string()));
                }
            }
            
            lines.push((target_line, all_lines[target_idx].to_string()));
            
            if let Some((n_num, n_text)) = next_non_empty {
                if target_line + 1 < n_num as u32 {
                    lines.push((0, "...".to_string()));
                }
                lines.push((n_num as u32, n_text));
            }
        } else {
            lines.push((target_line, all_lines.last().unwrap_or(&"").to_string()));
        }
    } else {
        lines.push((target_line, "<在磁盘上找不到该文件，无法提供源码上下文>".to_string()));
    }
    lines
}

fn format_line_context(text: &str, token_opt: Option<&str>) -> (String, usize, usize) {
    let chars: Vec<char> = text.chars().collect();
    let mut target_pos = 0;
    let mut target_len = 1;

    if let Some(tok) = token_opt {
        let tok_chars: Vec<char> = tok.chars().collect();
        if !tok_chars.is_empty() && chars.len() >= tok_chars.len() {
            for i in (0..=(chars.len() - tok_chars.len())).rev() {
                if &chars[i..i + tok_chars.len()] == &tok_chars[..] {
                    target_pos = i;
                    target_len = tok_chars.len();
                    break;
                }
            }
        }
    } else {
        target_pos = text.chars().take_while(|c| c.is_whitespace()).count();
        target_len = text.trim_start().split_whitespace().next().unwrap_or(" ").chars().count().max(1);
    }

    if chars.len() > 80 {
        let start = target_pos.saturating_sub(30);
        let end = (start + 75).min(chars.len());
        
        let mut s = String::new();
        if start > 0 { s.push_str("..."); }
        s.push_str(&chars[start..end].iter().collect::<String>());
        if end < chars.len() { s.push_str("..."); }

        let visual_padding = if start > 0 { target_pos - start + 3 } else { target_pos };
        (s, visual_padding, target_len)
    } else {
        (text.to_string(), target_pos, target_len)
    }
}

fn exp_part_format(raw: &str) -> String {
    let r = raw.trim_matches(|c| c == '\'' || c == '"');
    match r {
        "end" => "结束标识符 'end'".to_string(),
        "then" => "条件体关键字 'then'".to_string(),
        "do" => "循环体关键字 'do'".to_string(),
        "}" => "右大括号 '}'".to_string(),
        ")" => "右圆括号 ')'".to_string(),
        "]" => "右中括号 ']'".to_string(),
        "=" => "赋值符号 '='".to_string(),
        "in" => "迭代关键字 'in'".to_string(),
        "," => "逗号 ','".to_string(),
        "function" => "函数 'function'".to_string(),
        "local" => "本地声明 'local'".to_string(),
        "if" => "条件分支 'if'".to_string(),
        "while" => "循环 'while'".to_string(),
        "for" => "循环 'for'".to_string(),
        "repeat" => "循环 'repeat'".to_string(),
        "<name>" => "合法的变量名".to_string(),
        _ => format!("'{}'", r),
    }
}

type DiffPatch = Option<(u32, String, String)>;

fn analyze_syntax_smart(msg: &str, context: &[(u32, String)], err_line: u32) -> (String, String, String, Option<String>, DiffPatch, u32) {
    let (real_prev_line, prev_line_num) = context
        .iter()
        .filter(|(l, _)| *l > 0 && *l < err_line)
        .last()
        .map(|(l, s)| (s.trim(), *l))
        .unwrap_or(("", 0));
        
    let curr_line = context.iter().find(|(l, _)| *l == err_line).map(|(_, s)| s.trim()).unwrap_or("");
    let m_lower = msg.to_lowercase();

    if msg.starts_with("Expected '") {
        if let Some((expected_part, got_part)) = msg.strip_prefix("Expected '").unwrap().split_once("', got '") {
            let exp = expected_part;
            let fnd = got_part.trim_end_matches('\'');
            let title = format!("语法缺失：期望获得 `{}`", exp_part_format(exp));
            let note = format!("解析器在当前位置期望获得 `{}`, 但却发现了 `{}` 阻断了解析流。", exp_part_format(exp), fnd);
            let help = format!("请检查此处代码，添加 `{}` 以修复代码完整性。", exp);
            return (title, note, help, Some(fnd.to_string()), None, err_line);
        }
    }

    if m_lower.contains("unfinished string") || m_lower.contains("unfinished long string") {
        let dbl_quotes = curr_line.chars().filter(|&c| c == '"').count();
        let sgl_quotes = curr_line.chars().filter(|&c| c == '\'').count();
        let missing = if dbl_quotes % 2 != 0 { "\"" } else { "'" };
        let new_line = format!("{}{}", curr_line, missing);
        return (
            "未闭合的字符串字面量".into(),
            "解析器在当前行扫描到了未成对的引号，这会导致后续的代码被意外当作字符串吞噬。".into(),
            "在字符串末尾补全缺失的引号:".into(),
            None,
            Some((err_line, curr_line.to_string(), new_line)),
            err_line
        );
    }

    let typo_map = [
        ("loca", "local"), ("loacl", "local"),
        ("functio", "function"), ("functon", "function"),
        ("retrun", "return"), ("retun", "return"),
        ("whil", "while"), ("ture", "true"), ("fals", "false"),
    ];

    for (wrong, right) in typo_map.iter() {
        if real_prev_line == *wrong || real_prev_line.ends_with(&format!(" {}", wrong)) {
            let new_line = real_prev_line.replacen(wrong, *right, 1);
            return (
                "关键字拼写错误".into(),
                format!("解析器试图在此建立语法节点，但发现代码的 `{}` 可能是 `{}` 的拼写错误，导致解析链断裂。", wrong, right),
                format!("修复拼写错误的关键字 `{}`:", wrong),
                Some(wrong.to_string()),
                Some((prev_line_num, real_prev_line.to_string(), new_line)),
                prev_line_num
            );
        }
        if curr_line == *wrong || curr_line.starts_with(&format!("{} ", wrong)) {
            let new_line = curr_line.replacen(wrong, *right, 1);
            return (
                "关键字拼写错误".into(),
                format!("检测到疑似拼写错误的关键字 `{}`，导致无法匹配预期的语法规则。", wrong),
                format!("修复拼写错误的关键字 `{}`:", wrong),
                Some(wrong.to_string()),
                Some((err_line, curr_line.to_string(), new_line)),
                err_line
            );
        }
    }

    if let Some(exp_pos) = m_lower.find("expected") {
        let exp_part = msg[..exp_pos].trim().trim_matches(|c| c == '\'' || c == '"');
        let rest = &msg[exp_pos + "expected".len()..];

        let mut close_target = None;
        let mut close_line = None;
        if let Some(close_pos) = rest.find("(to close ") {
            let close_str = &rest[close_pos + "(to close ".len()..];
            if let Some(at_line_pos) = close_str.find(" at line ") {
                let target = close_str[..at_line_pos].trim().trim_matches(|c| c == '\'' || c == '"');
                close_target = Some(target.to_string());
                let line_str = &close_str[at_line_pos + " at line ".len()..];
                if let Some(end_paren) = line_str.find(')') {
                    if let Ok(l) = line_str[..end_paren].trim().parse::<u32>() {
                        close_line = Some(l);
                    }
                }
            }
        }

        let mut near_part = None;
        if let Some(near_pos) = rest.find("near ") {
            let raw_near = rest[near_pos + "near ".len()..].trim().trim_matches(|c| c == '\'' || c == '"');
            near_part = Some(raw_near.to_string());
        }

        let fnd = near_part.unwrap_or_else(|| "<eof>".to_string());

        if let Some(target) = close_target {
            let title = format!("结构断层：未闭合的 `{}`", exp_part_format(&target));
            let note = format!(
                "编译器尝试闭合在第 {} 行声明的 `{}`, 但在当前行遇到了非预期的 `{}`。",
                close_line.unwrap_or(0), exp_part_format(&target), fnd
            );
            let help = format!("在此处补充 `{}`，以闭合在第 {} 行声明的代码块。", exp_part, close_line.unwrap_or(0));
            return (title, note, help, Some(fnd), None, err_line);
        } else {
            let mut title = format!("语法链断裂：缺少 `{}`", exp_part_format(exp_part));
            let mut note = format!("编译器在此处期望获得 `{}`, 但却发现了 `{}` 阻断了解析流。", exp_part_format(exp_part), fnd);
            let mut help = format!("尝试在此处添加 `{}` 以修复语法。", exp_part);
            let mut diff = None;
            let mut effective_line = err_line;

            if exp_part == "=" || exp_part == "'='" {
                if !real_prev_line.is_empty() && !curr_line.is_empty() && !curr_line.contains('=') {
                    help = format!("智能推断：你可能由于换行漏掉了赋值符号 `=`。");
                    diff = Some((err_line, curr_line.to_string(), format!("= {}", curr_line)));
                }
            } 
            else if exp_part == "<name>" {
                title = format!("非法标识符：期望合法的变量名，却碰到了 `{}`", fnd);
                note = format!("解析器试图在此处读取一个变量名，但遇到了字面量 `{}`。Lua 变量名必须以字母或下划线开头。", fnd);
                
                if real_prev_line.ends_with(",") {
                    help = "多余的逗号：逗号导致编译器持续等待下一个变量名。".to_string();
                    diff = Some((prev_line_num, real_prev_line.to_string(), real_prev_line.trim_end_matches(',').to_string()));
                    effective_line = prev_line_num;
                } else if fnd.chars().all(|c| c.is_ascii_digit()) {
                    help = format!("纯数字 `{}` 无法作为变量名。如果是连续声明想赋值，请将它前面的 `,` 改为 `=`。", fnd);
                } else if curr_line.contains("function ") {
                    help = format!("函数名或参数包含无效标识符。请确保 `{}` 被替换为合法名称。", fnd);
                } else {
                    help = format!("请将 `{}` 替换为合法的英文字母标识符。", fnd);
                }
            }

            return (title, note, help, Some(fnd), diff, effective_line);
        }
    }

    if let Some((_, found)) = msg.split_once("unexpected symbol near ") {
        let f = found.trim().trim_matches(|c| c == '\'' || c == '"');
        let is_num = f.chars().all(|c| c.is_ascii_digit() || c == '.');
        
        let title = format!("无法识别的非法符号 `{}`", f);
        let note = if is_num {
            format!("词法分析器(Lexer) 在此处捕捉到了游离的数字 `{}`。在 AST 语法树中，单独的数字无法被解析为有效指令。", f)
        } else {
            format!("执行流被意外的标识符 `{}` 阻断。这通常意味着此前的语句结构被破坏。", f)
        };

        let mut help = "检查是否存在拼写错误、非法中文字符或漏掉了运算符。".to_string();
        let mut diff = None;
        
        if is_num && (real_prev_line.starts_with("local") || real_prev_line.contains(",")) {
            help = "智能推断：此处不应出现孤立数字。是否由于换行导致赋值断开？".to_string();
            diff = Some((err_line, curr_line.to_string(), format!("= {}", curr_line)));
        }

        return (title, note, help, Some(f.to_string()), diff, err_line);
    }

    ("语法解析失败".into(), format!("底层异常信息: {}", msg), "请仔细比对标准 Lua or Luau 语法排查。".into(), None, None, err_line)
}

fn analyze_semantic_smart(msg: &str, err_line: u32) -> (String, String, String, Option<String>, DiffPatch, u32) {
    let m = msg.to_lowercase();
    if m.contains("break") {
        ("非法的控制流转移".into(), "检测到 `break` 语句位于循环体外部。".into(), "请移除该语句或将其包裹在 for/while/repeat 块内。".into(), Some("break".into()), None, err_line)
    } else if m.contains("limit") {
        ("编译器限制".into(), "代码结构过于复杂，超出了当前 AST 节点的处理极限。".into(), "建议重构代码，减少嵌套深度或拆分大型函数。".into(), None, None, err_line)
    } else {
        ("AST 语义校验失败".into(), msg.to_string(), "请根据报错信息检查逻辑合法性。".into(), None, None, err_line)
    }
}

fn dynamic_runtime_analyzer(msg: &str) -> (String, String, String) {
    if msg.contains("attempt to index") {
        ("空指针异常 (Nil Dereference)".into(), "试图访问 nil 值的属性。".into(), "请在访问前确保对象已初始化。".into())
    } else if msg.contains("attempt to call") {
        ("无效调用".into(), "目标变量不是函数。".into(), "请检查变量名拼写。".into())
    } else {
        ("运行异常".into(), msg.to_string(), "查看堆栈信息定位。".into())
    }
}

pub fn chunkid(source: &str) -> String {
    let s = source.strip_prefix('@').unwrap_or(source).strip_prefix('=').unwrap_or(source);
    let first = s.split('\n').next().unwrap_or(s);
    if first.len() > 40 { format!("{}...", &first[..37]) } else { first.to_string() }
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let context = get_file_lines(&self.source, self.line);
        let (title, note, help, token_opt, diff_opt, effective_line) = analyze_syntax_smart(&self.message, &context, self.line);
        
        writeln!(f, "\x1b[1;31merror[E0277]\x1b[0m: \x1b[1m{}\x1b[0m", title)?;
        writeln!(f, "\x1b[1;34m  --> \x1b[0m{}:{}", chunkid(&self.source), effective_line)?;
        writeln!(f, "\x1b[1;34m   |\x1b[0m")?;
        
        for (l, text) in &context {
            if *l == 0 { writeln!(f, "\x1b[1;34m... |\x1b[0m")?; }
            else if *l == effective_line {
                let (snippet, padding, m_len) = format_line_context(text, token_opt.as_deref());
                writeln!(f, "\x1b[1;34m{:>3} |\x1b[0m {}", l, snippet)?;
                writeln!(f, "\x1b[1;34m   |\x1b[0m \x1b[1;31m{}{}\x1b[0m \x1b[1;31m报错位置\x1b[0m", " ".repeat(padding), "^".repeat(m_len))?;
            } else {
                let (snippet, _, _) = format_line_context(text, None);
                writeln!(f, "\x1b[1;34m{:>3} |\x1b[0m \x1b[38;5;244m{}\x1b[0m", l, snippet)?;
            }
        }
        
        writeln!(f, "\x1b[1;34m   |\x1b[0m")?;
        writeln!(f, "\x1b[1;36m   = note\x1b[0m: {}", note)?;
        write!(f, "\x1b[1;32mhelp\x1b[0m: {}", help)?;

        if let Some((diff_line, old_text, new_text)) = diff_opt {
            writeln!(f, "\n\x1b[1;34m   |\x1b[0m")?;
            writeln!(f, "\x1b[1;34m{:>3}\x1b[0m \x1b[1;31m- {}\x1b[0m", diff_line, old_text)?;
            writeln!(f, "\x1b[1;34m{:>3}\x1b[0m \x1b[1;32m+ {}\x1b[0m", diff_line, new_text)?;
            writeln!(f, "\x1b[1;34m   |\x1b[0m")?;
        } else {
            writeln!(f)?;
        }
        Ok(())
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let context = get_file_lines(&self.source, self.line);
        let (title, note, help, token_opt, diff_opt, effective_line) = analyze_semantic_smart(&self.message, self.line);
        
        writeln!(f, "\x1b[1;93merror[E0308]\x1b[0m: \x1b[1m{}\x1b[0m", title)?;
        writeln!(f, "\x1b[1;34m  --> \x1b[0m{}:{}", chunkid(&self.source), effective_line)?;
        writeln!(f, "\x1b[1;34m   |\x1b[0m")?;
        
        for (l, text) in &context {
            if *l == 0 { writeln!(f, "\x1b[1;34m... |\x1b[0m")?; }
            else if *l == effective_line {
                let (snippet, padding, m_len) = format_line_context(text, token_opt.as_deref().or(self.token.as_deref()));
                writeln!(f, "\x1b[1;34m{:>3} |\x1b[0m {}", l, snippet)?;
                writeln!(f, "\x1b[1;34m   |\x1b[0m \x1b[1;93m{}{}\x1b[0m \x1b[1;93m语义异常\x1b[0m", " ".repeat(padding), "^".repeat(m_len))?;
            } else {
                let (snippet, _, _) = format_line_context(text, None);
                writeln!(f, "\x1b[1;34m{:>3} |\x1b[0m \x1b[38;5;244m{}\x1b[0m", l, snippet)?;
            }
        }
        
        writeln!(f, "\x1b[1;34m   |\x1b[0m")?;
        writeln!(f, "\x1b[1;36m   = note\x1b[0m: {}", note)?;
        write!(f, "\x1b[1;32mhelp\x1b[0m: {}", help)?;

        if let Some((diff_line, old_text, new_text)) = diff_opt {
            writeln!(f, "\n\x1b[1;34m   |\x1b[0m")?;
            writeln!(f, "\x1b[1;34m{:>3}\x1b[0m \x1b[1;31m- {}\x1b[0m", diff_line, old_text)?;
            writeln!(f, "\x1b[1;34m{:>3}\x1b[0m \x1b[1;32m+ {}\x1b[0m", diff_line, new_text)?;
            writeln!(f, "\x1b[1;34m   |\x1b[0m")?;
        } else {
            writeln!(f)?;
        }
        Ok(())
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (title, note, help) = dynamic_runtime_analyzer(&self.message);
        writeln!(f, "\x1b[1;31mpanic[R0042]\x1b[0m: \x1b[1m{}\x1b[0m\n\x1b[1;31m  --> \x1b[0m{}\n\x1b[1;34m   |\x1b[0m\n\x1b[1;36m   = note\x1b[0m: {}\n\x1b[1;32mhelp\x1b[0m: {}", title, self.message, note, help)?;
        if !self.traceback.is_empty() {
            writeln!(f, "\n\x1b[1m堆栈追踪:\x1b[0m")?;
            for (i, entry) in self.traceback.iter().enumerate() { writeln!(f, "  {:>2}: {}", i, entry)?; }
        }
        Ok(())
    }
}

impl fmt::Display for TraceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\x1b[4m{}\x1b[0m:{}", self.source, self.line)?;
        if let Some(name) = &self.name { write!(f, " (函数 '{}')", name)?; }
        Ok(())
    }
}

impl fmt::Display for LuaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(e) => write!(f, "{e}"),
            Self::Semantic(e) => write!(f, "{e}"),
            Self::Runtime(e) => write!(f, "{e}"),
            Self::Multiple(errors) => {
                writeln!(f, "\x1b[1;91m编译中止：共发现 {} 个错误。\x1b[0m", errors.len())?;
                for (i, err) in errors.iter().enumerate() {
                    writeln!(f, "{}", err)?;
                    if i < errors.len() - 1 { writeln!(f, "\x1b[38;5;238m{}\x1b[0m", "-".repeat(40))?; }
                }
                Ok(())
            },
            Self::Memory => write!(f, "\x1b[1;31m[ FATAL ]\x1b[0m 内存溢出"),
            Self::ErrorHandler => write!(f, "\x1b[1;31m[ FATAL ]\x1b[0m 错误处理异常"),
            Self::Io(e) => write!(f, "\x1b[1;31m[ IO_ERR ]\x1b[0m {}", e),
            Self::Yield(_) => write!(f, "\x1b[1;31m[ EXEC_ERR ]\x1b[0m 非法挂起"),
        }
    }
}

impl std::error::Error for LuaError {}
impl From<std::io::Error> for LuaError { fn from(err: std::io::Error) -> Self { Self::Io(err) } }
impl From<SyntaxError> for LuaError { fn from(err: SyntaxError) -> Self { Self::Syntax(err) } }
impl From<SemanticError> for LuaError { fn from(err: SemanticError) -> Self { Self::Semantic(err) } }
impl From<RuntimeError> for LuaError { fn from(err: RuntimeError) -> Self { Self::Runtime(err) } }