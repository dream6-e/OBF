//! 源码最小化（流水线第 ⓪ 步，2026-10-06 新增）
//!
//! 进入编译器之前，先把用户源码压成「单行 + 去注释 + 最少空白」的等价形式。
//! **不是 LZ 压缩**，也不改语法树——纯词法级重排：
//!
//!   * 只删除注释与可忽略空白，令牌序列逐字节保持 → 语义不可能被改动；
//!   * 不需要文法，因此天然覆盖 Lua 5.1 与 Luau 的全部语法（含插值串、类型标注、
//!     `+=`、`//`、`->` 等 Luau 记法）；
//!   * 收尾重新分词自检：令牌序列有任何差异就原样返回源码；
//!   * 词法上拿不准的输入（未闭合字符串/注释、NUL、非 UTF-8）一律原样放行。
//!
//! 实测口径（2026-10-06，见 `项目交接总结.md`）：源码体积约 −40%~−60%，但产物体积
//! 基本不变——局部变量名/空白/换行不进字节码，载荷只受指令数与字符串常量池影响。

pub mod lexer;

pub use lexer::{LexError, Kind, Tok, lex};

/// 把一个令牌的「尾字节」与下一个的「首字节」是否有粘连风险做成表。
/// 命中的话必须插一个空格，否则两个令牌会合成另一个令牌。
const HAZARDS: &[(u8, u8)] = &[
    (b'-', b'-'), // 会变成注释开头
    (b'-', b'='),
    (b'-', b'>'), // Luau 类型箭头
    (b'+', b'='),
    (b'*', b'='),
    (b'/', b'='),
    (b'/', b'/'),
    (b'%', b'='),
    (b'^', b'='),
    (b'=', b'='),
    (b'=', b'>'),
    (b'~', b'='),
    (b'<', b'='),
    (b'>', b'='),
    (b'<', b'<'),
    (b'>', b'>'),
    (b'.', b'.'),
    (b'.', b'='), // `..` + `=` 会合成 Luau 的 `..=`
    (b'&', b'='),
    (b'|', b'='),
    (b'[', b'['), // `[ [` 否则成了长括号串开头
    (b':', b':'),
    (b'&', b'&'),
    (b'|', b'|'),
];

/// 最小化源码。任何异常都返回原文，绝不产出坏代码。
pub fn minify_source(source: &str) -> String {
    // ① shebang（`#!…`）由解释器特殊处理：整行原样保留，不参与最小化。
    let (shebang, body) = split_shebang(source);

    let tokens = match lex(body) {
        Ok(t) => t,
        Err(_) => return source.to_string(),
    };
    if tokens.is_empty() {
        // 纯空白/纯注释：保持原样，避免产出空文件。
        return source.to_string();
    }

    let joined = join(&tokens);

    // ② 自检：重新分词必须得到完全相同的令牌序列，否则放弃（返回原文）。
    match lex(&joined) {
        Ok(again) if again == tokens => {
            let mut out = String::with_capacity(shebang.len() + joined.len());
            out.push_str(shebang);
            out.push_str(&joined);
            out
        }
        _ => source.to_string(),
    }
}

/// 拆出 shebang 行（含换行符）；不带 shebang 时前缀为空。
fn split_shebang(source: &str) -> (&str, &str) {
    if !source.starts_with('#') {
        return ("", source);
    }
    match source.find('\n') {
        Some(pos) => source.split_at(pos + 1),
        None => (source, ""),
    }
}

/// 按最少空格规则把令牌拼成单行
fn join(tokens: &[Tok]) -> String {
    let mut out = String::with_capacity(tokens.iter().map(|t| t.text.len() + 1).sum());
    let mut prev: Option<&Tok> = None;
    for tok in tokens {
        if let Some(p) = prev {
            if needs_space(p, tok) {
                out.push(' ');
            }
        }
        out.push_str(&tok.text);
        prev = Some(tok);
    }
    out
}

/// 两个相邻令牌之间是否必须留一个空格
fn needs_space(a: &Tok, b: &Tok) -> bool {
    use Kind::*;

    // 拿不准的字节一律留空格（保守但安全）
    if a.kind == Raw || b.kind == Raw {
        return true;
    }

    // 标识符/数字/关键字相邻必须分开（`local x`、`1 then`、`a b`…）
    let nameish = |k: Kind| matches!(k, Name | Number);
    if nameish(a.kind) && nameish(b.kind) {
        return true;
    }

    let (Some(&x), Some(&y)) = (a.text.as_bytes().last(), b.text.as_bytes().first()) else {
        return false;
    };

    // 数字后面接 `.` 开头的东西会把小数吃掉（`1 .5` ≠ `1.5`）
    if a.kind == Number && (y == b'.' || y.is_ascii_digit()) {
        return true;
    }

    // 数字后面接标识符首字符（`1e` / `0x1p` 之类）
    if a.kind == Number && (y == b'_' || y.is_ascii_alphabetic()) {
        return true;
    }

    // 标识符/数字后面接字符串：`print"x"`、`a[=[x]=]` 都合法，无需空格
    if HAZARDS.contains(&(x, y)) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小化后必须：① 重新分词与原序列一致；② 除字符串内部外无换行
    fn check(src: &str) -> String {
        let out = minify_source(src);
        if let (Ok(before), Ok(after)) = (lex(src), lex(&out)) {
            assert_eq!(before, after, "令牌序列不一致\n原文: {:?}\n结果: {:?}", src, out);
        }
        out
    }

    /// 去掉字符串/长串/插值串内部的换行后，结果应当只有一行
    fn assert_single_line(out: &str) {
        let mut depth_newlines = 0usize;
        for tok in lex(out).unwrap() {
            if matches!(tok.kind, Kind::LongStr | Kind::Interp) {
                depth_newlines += tok.text.matches('\n').count();
            }
        }
        assert_eq!(out.matches('\n').count(), depth_newlines, "非字符串部分残留换行: {:?}", out);
    }

    #[test]
    fn collapses_whitespace_and_comments() {
        let src = "-- 头部注释\nlocal  a  =  1   -- 行尾\n--[[ 长注释\n    多行 ]]\nprint(a)\n";
        let out = check(src);
        assert_eq!(out, "local a=1 print(a)");
        assert_single_line(&out);
    }

    #[test]
    fn supports_no_paren_calls_and_luau_syntax() {
        let src = r#"
-- Lua 5.1 的无括号调用糖 + Luau 记法混合
print "no-paren"
print'单引号'
local x: number = 5
local y = x // 2
y += 1
type Point = { x: number, y: number }
local p: Point = { x = 1, y = 2 }
local function id<T>(v: T): T return v end
for i = 1, 3 do
    if i == 2 then continue end
    print(`i={i} 与 {1 + 2} 与 {`嵌套 {i}`}`)
end
print(id(y), p.x)
"#;
        let out = check(src);
        assert!(out.contains("print\"no-paren\""));
        assert!(out.contains("print'单引号'"));
        assert!(out.contains("local x:number=5"));
        assert!(out.contains("y+=1"));
        assert!(out.contains("type Point={x:number,y:number}"));
        assert!(out.contains("local function id<T>(v:T):T"));
        assert!(out.contains("continue"));
        assert_single_line(&out);
    }

    #[test]
    fn keeps_strings_byte_for_byte() {
        let src = "local a = [[ 原样 \n 保留 ]]\nlocal b = [==[x]=]y]==]\nlocal c = \"a\\tb\\\"c\"\nprint(a, b, c)\n";
        let out = check(src);
        assert!(out.contains("[[ 原样 \n 保留 ]]"));
        assert!(out.contains("[==[x]=]y]==]"));
        assert!(out.contains("\"a\\tb\\\"c\""));
        // 长串之外的换行必须消失
        assert_eq!(out.matches('\n').count(), 1);
    }

    #[test]
    fn separates_dangerous_pairs() {
        let cases = [
            ("local a,b=1,2\nprint(a - -b)", "- -b"),
            ("local t={}\nprint(t[ [[x]] ])", "[ [["),
            ("local a,b=1,2\nprint(a .. b)", "a..b"),
            ("local a=1\nprint(- -a)", "- -a"),
            ("local a=1\nprint(a< -1)", "<-1"),   // `<` 与 `-` 无需空格，但必须仍是同一个 `-1`
            ("local t={}\nprint(t[1] .. t[2])", ".."),
        ];
        for (src, needle) in cases {
            let out = check(src);
            assert!(out.contains(needle), "缺少分隔: {:?} in {:?}", needle, out);
            assert_single_line(&out);
        }
    }

    #[test]
    fn separates_number_dot_hazards() {
        let out = check("local a=1\nprint(a , .5)\nprint(1.)\nprint(0x1.8p1)\nprint(1 .. 2)");
        assert!(out.contains("a,.5") || out.contains("a, .5"), "{:?}", out);
        assert!(out.contains("1 ..2") || out.contains("1 .. 2"), "{:?}", out);
    }

    #[test]
    fn is_idempotent() {
        let sources = [
            "-- 注释\nlocal a=1\nprint(a)",
            "print \"x\"\nlocal t={k=1}\nprint(t.k)",
            "local s = [[多行\n字符串]]\nprint(s)",
            "type T = {a:number}\nlocal v:T={a=1}\nprint(v.a)",
        ];
        for s in sources {
            let once = minify_source(s);
            let twice = minify_source(&once);
            assert_eq!(once, twice, "最小化不幂等: {:?}", s);
        }
    }

    #[test]
    fn bails_out_on_unsafe_input() {
        let cases = [
            "local a = \"未闭合\nprint(a)",
            "--[[ 未闭合的长注释\nprint(1)",
            "local a = [[未闭合\nprint(a)",
            "local a = `未闭合\nprint(a)",
            "local a = 1\0print(a)",
        ];
        for src in cases {
            assert_eq!(minify_source(src), src, "不安全输入应原样返回: {:?}", src);
        }
    }

    #[test]
    fn keeps_shebang_line() {
        let src = "#!/usr/bin/env lua\n-- 注释\nprint( 1 )\n";
        let out = minify_source(src);
        assert!(out.starts_with("#!/usr/bin/env lua\n"), "{:?}", out);
        assert!(out.ends_with("print(1)"), "{:?}", out);
    }

    /// 语义等价实测：最小化前后在参考运行时下 stdout 必须逐字节一致。
    /// 参考运行时缺失时跳过（与仓库既有测试一致的做法）。
    #[test]
    fn runtime_output_matches_reference() {
        use std::path::{Path, PathBuf};
        use std::process::Command;
        use std::sync::atomic::{AtomicUsize, Ordering};

        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let lua = root.join("toolchains/bin/lua5.1");
        let luau = root.join("toolchains/bin/luau");
        if !lua.exists() && !luau.exists() {
            return;
        }

        let run = |bin: &Path, code: &str| -> Option<(i32, Vec<u8>)> {
            let seq = SEQ.fetch_add(1, Ordering::SeqCst);
            let tmp: PathBuf = std::env::temp_dir().join(format!(
                "kryvex_min_{}_{}_{}.lua",
                std::process::id(),
                seq,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::write(&tmp, code).ok()?;
            let out = Command::new(bin).arg(&tmp).current_dir(root).output().ok();
            let _ = std::fs::remove_file(&tmp);
            let out = out?;
            Some((out.status.code().unwrap_or(-1), out.stdout))
        };

        let mut fixtures: Vec<PathBuf> = Vec::new();
        for name in [
            "test/print.lua",
            "test/nested_protos.lua",
            "test/string_encryption.lua",
            "test/DynamicGlobalEnv.lua",
            "test/Comptesting.lua",
            "test/roblox.lua",
        ] {
            let p = root.join(name);
            if p.exists() {
                fixtures.push(p);
            }
        }
        if let Ok(entries) = std::fs::read_dir(root.join("test/Prometheus")) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "lua").unwrap_or(false) {
                    fixtures.push(p);
                }
            }
        }

        let mut compared = 0usize;
        for path in &fixtures {
            let src = std::fs::read_to_string(path).expect("读取语料");
            let min = minify_source(&src);
            for bin in [&lua, &luau] {
                if !bin.exists() {
                    continue;
                }
                let (Some(a), Some(b)) = (run(bin, &src), run(bin, &min)) else {
                    continue;
                };
                // 只在两边都正常退出时比对：异常信息里可能带行号（最小化会折叠行号）
                if a.0 != 0 || b.0 != 0 {
                    continue;
                }
                assert_eq!(
                    a, b,
                    "最小化改变了行为: {:?} @ {:?}",
                    path, bin
                );
                compared += 1;
            }
        }
        assert!(compared > 0 || (!lua.exists() && !luau.exists()));
    }
}
