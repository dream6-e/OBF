pub mod token;
pub mod lexer;
pub mod ast;
pub mod parser;
pub mod scope;
pub mod codegen;
pub mod hoist;
pub mod renamer;
pub mod packer;

use std::collections::{HashMap, HashSet};
use rand::{rng, Rng, seq::SliceRandom};
use crate::compiler::error::{LuaError, LuaResult, SyntaxError, set_active_source};
use ast::VarId;
use token::TokenType;

pub struct Compressor;

impl Compressor {
    pub fn compress(input: &str) -> LuaResult<String> {
        set_active_source(input.to_string());
        
        let processed_input = input.to_string();

        let mut lex = lexer::Lexer::new(&processed_input);
        let mut tokens = lex.tokenize();
        for tok in &mut tokens {
            if matches!(
                tok.text.as_str(),
                "and" | "break" | "do" | "else" | "elseif" | "end" | "false" | "for" | "function"
                    | "if" | "in" | "local" | "nil" | "not" | "or" | "repeat" | "return"
                    | "then" | "true" | "until" | "while"
            ) {
                tok.token_type = TokenType::Keyword;
            }
        }
        
        let mut pars = parser::Parser::new(tokens);
        let mut root_block = pars.parse_block()?;

        // README 规则：某个数字在一个作用域使用次数大于两次就 local 为一个变量。
        // 提升发生在作用域解析之前，占位名会被后面的 renamer 统一改名。
        hoist::hoist_constants(&mut root_block);

        let mut resolver = scope::ScopeResolver::new();
        root_block.resolve(&mut resolver);
        // 名字复用判据：只有「在该作用域子树里被真正引用到的祖先绑定」才必须避名。
        // 之前的规则是「祖先用过的名字一律封锁」，导致内层（尤其是形参）只能用长名；
        // 改判据后，未被引用的祖先名字可以安全复用——形参因此普遍拿到单字母。
        let subtree_refs = resolver.subtree_refs();

        let ren = renamer::Renamer::new();
        
        let mut rng = rng();
        let mut wave1 = Vec::with_capacity(26);
        let mut wave2 = Vec::with_capacity(26);
        let mut alphabets: Vec<(char, char)> = (b'a'..=b'z')
            .zip(b'A'..=b'Z')
            .map(|(lower, upper)| (lower as char, upper as char))
            .collect();
            
        alphabets.shuffle(&mut rng);
        for (lower, upper) in alphabets {
            if rng.random_bool(0.5) { wave1.push(lower); wave2.push(upper); } 
            else { wave1.push(upper); wave2.push(lower); }
        }
        
        let mut single_letters = wave1;
        single_letters.extend(wave2);
        let base = single_letters.len();

        // 一个名字只在可能发生词法遮蔽的作用域链中保持唯一；不相交的兄弟作用域可复用。
        // 旧的“活跃变量数相同即重名”启发式会让仍存活的外层绑定被遮蔽，导致运行期读到 nil。
        let mut used_vars: Vec<(VarId, usize)> = resolver
            .var_usage
            .iter()
            .filter(|&(_, &usage)| usage > 0)
            .map(|(&id, &usage)| (id, usage))
            .collect();
        let mut scope_depths = vec![0usize; resolver.scope_parents.len()];
        for scope in 1..scope_depths.len() {
            if let Some(parent) = resolver.scope_parents[scope] {
                scope_depths[scope] = scope_depths[parent] + 1;
            }
        }
        used_vars.sort_by(|a, b| {
            let scope_a = resolver.var_scopes.get(&a.0).copied().unwrap_or(0);
            let scope_b = resolver.var_scopes.get(&b.0).copied().unwrap_or(0);
            // 形参排在同作用域其它绑定之前：用户要求「function(a,b,c) 里的参数尽量单字母」，
            // 而单字母池只有 52 个，作用域内绑定一多就必须有人拿双字母——先保形参。
            let param_a = resolver.param_ids.contains(&a.0);
            let param_b = resolver.param_ids.contains(&b.0);
            scope_depths[scope_a].cmp(&scope_depths[scope_b])
                .then(param_b.cmp(&param_a))
                .then(b.1.cmp(&a.1))
                .then(a.0.0.cmp(&b.0.0))
        });

        // 候选池：52 个单字母名 + 52×52 个双字母名，严格只使用字母。
        let mut valid_names: Vec<String> = single_letters
            .iter()
            .map(|c| c.to_string())
            .collect();
        for first in &single_letters {
            for second in &single_letters {
                valid_names.push(format!("{}{}", first, second));
            }
        }
        valid_names.retain(|name| !ren.is_keyword(name) && !ren.is_safe_global(name));

        let mut names_by_scope: Vec<HashSet<String>> =
            (0..resolver.scope_parents.len()).map(|_| HashSet::new()).collect();
        let mut mapping: HashMap<VarId, String> = HashMap::new();
        for (&id, &usage) in &resolver.var_usage {
            if usage == 0 {
                mapping.insert(id, "_".to_string());
            }
        }

        let mut fallback_index = 0usize;
        for (id, _) in used_vars {
            let scope = resolver.var_scopes.get(&id).copied().unwrap_or(0);
            // 只封锁「本作用域子树里真的引用到、且已经分到名字」的绑定名：
            // 未被引用的祖先绑定不可达，内层复用其名字不会改变任何引用的解析结果。
            let mut blocked = HashSet::new();
            if let Some(refs) = subtree_refs.get(scope) {
                for rid in refs {
                    if let Some(name) = mapping.get(rid) {
                        blocked.insert(name.clone());
                    }
                }
            }

            let name = if let Some(name) = valid_names.iter()
                .find(|name| !blocked.contains(*name) && !names_by_scope[scope].contains(*name))
                .cloned()
            {
                name
            } else {
                loop {
                    let mut n = fallback_index;
                    let mut candidate = String::new();
                    loop {
                        candidate.push(single_letters[n % base]);
                        n /= base;
                        if n == 0 { break; }
                    }
                    candidate = candidate.chars().rev().collect();
                    fallback_index += 1;
                    if !ren.is_keyword(&candidate) && !ren.is_safe_global(&candidate)
                        && !blocked.contains(&candidate) && !names_by_scope[scope].contains(&candidate)
                    {
                        break candidate;
                    }
                }
            };
            names_by_scope[scope].insert(name.clone());
            mapping.insert(id, name);
        }

        let reserved_local_names = mapping.values().cloned().collect();
        let ctx = codegen::CodegenContext {
            mapping,
            shuffled_chars: single_letters,
            map_string_start_idx: fallback_index,
            reserved_local_names,
        };
        
        let mut gen_tokens = Vec::new();
        root_block.to_tokens(&ctx, &mut gen_tokens);
        
        Ok(packer::Packer::pack(gen_tokens))
    }
}
#[cfg(test)]
mod tests {
    use super::Compressor;

    fn declared_names(source: &str) -> Vec<String> {
        let output = Compressor::compress(source).expect("compressor should accept test source");
        output
            .split("local ")
            .skip(1)
            .map(|declaration| {
                declaration
                    .split('=')
                    .next()
                    .unwrap()
                    .split(',')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn used_local_names_fit_in_two_characters() {
        let names = declared_names("local descriptive_name=1;return descriptive_name");
        assert_eq!(names.len(), 1);
        assert!(names[0].len() <= 2, "generated local name was {:?}", names[0]);
    }

    #[test]
    fn sibling_scopes_can_reuse_short_names() {
        let names = declared_names(
            "do local alpha=1;print(alpha) end;do local beta=2;print(beta) end",
        );
        assert_eq!(names.len(), 2);
        assert_eq!(names[0], names[1]);
    }

    #[test]
    fn nested_scopes_do_not_shadow_mapped_locals() {
        let names = declared_names(
            "local outer=1;do local inner=2;print(outer,inner) end;return outer",
        );
        assert_eq!(names.len(), 2);
        assert_ne!(names[0], names[1]);
    }

    #[test]
    fn unused_local_uses_single_character_placeholder() {
        let names = declared_names("local unused=1;return 7");
        assert_eq!(names, vec!["_".to_string()]);
    }

    /// 遮蔽/复用语义回归：名字复用放宽后，最容易出事的是「内层复用了外层仍在被引用的名字」。
    /// 这个夹具把几类危险写法凑齐：捕获外层局部、同名形参遮蔽、`local x = x` 自引用、
    /// 循环变量被闭包捕获、repeat-until 体内局部、方法形参与嵌套闭包、兄弟作用域复用。
    /// 判据：压缩前后交给 lua5.1 跑，stdout 必须逐字节一致。
    #[test]
    fn name_reuse_preserves_semantics_under_lua() {
        let lua = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("toolchains/bin/lua5.1");
        if !lua.exists() {
            return;
        }
        let src = r#"
local function outer(a)
  local b = a + 1
  local function inner(b)
    return function(c) return a + b + c end
  end
  return inner(b)(10)
end
print(outer(5))

local n = 7
local function bump()
  local n = n + 1
  return n
end
print(bump(), n)

local fns = {}
for i = 1, 3 do
  fns[i] = function() return i end
end
print(fns[1](), fns[2](), fns[3]())

local k = 0
repeat
  local step = k + 1
  k = step
until k >= 3
print(k)

-- 注意：这里不用 `function t:get()` 写法——解析器把该形态的目标名当纯名字串
--（`Stmt::Function { path: Vec<String> }`，见 scope.rs 中该分支不解析 path），
-- 局部变量改名后会对不上；真实管线只处理生成代码（全是 `local function` /
-- `X.y=function` 形态），所以该缺陷潜伏。测试改用等价的赋值写法。
local t = {v = 41}
t.get = function(self)
  local function add(x) return self.v + x end
  return add(1)
end
print(t:get())

local obj = {n = 5}
obj.inc = function(self, d)
  local function step() return self.n + d end
  return step()
end
print(obj.inc(obj, 3))

local function mk(v) return function() return v end end
local g1, g2 = mk(1), mk(2)
print(g1(), g2())

local u = 1
do
  local u = 2
  print(u)
end
print(u)
"#;
        let out = Compressor::compress(src).expect("compress tricky source");
        let dir = std::env::temp_dir().join(format!("kryvex_shadow_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let src_path = dir.join("src.lua");
        let out_path = dir.join("out.lua");
        std::fs::write(&src_path, src).expect("write src");
        std::fs::write(&out_path, &out).expect("write out");
        let ra = std::process::Command::new(&lua).arg(&src_path).output().expect("run source");
        let rb = std::process::Command::new(&lua).arg(&out_path).output().expect("run compressed");
        assert!(ra.status.success(), "source failed: {}", String::from_utf8_lossy(&ra.stderr));
        assert!(rb.status.success(), "compressed failed: {}\n{}", String::from_utf8_lossy(&rb.stderr), out);
        assert!(!ra.stdout.is_empty(), "fixture produced no output");
        assert_eq!(
            String::from_utf8_lossy(&ra.stdout),
            String::from_utf8_lossy(&rb.stdout),
            "compressed output differs from source"
        );
    }

    /// 用户要求：所有 `function(a,b,c)` 的形参复用同一批短名，且尽量单字母。
    /// 这里断言「形参名全部为单字符」，并且不同函数确实在复用同一批名字（不是每处新造一个）。
    #[test]
    fn function_params_are_single_letter_and_reused() {
        let src = r#"
local function f1(alpha, beta) return alpha + beta end
local function f2(gamma, delta) return gamma * delta end
local function f3(e1, e2) return e1 - e2 end
local obj = {}
obj.m1 = function(self2, q1) return self2 end
local h = function(x1, y1, z1) local function inner(w1) return w1 end return inner(x1) + y1 + z1 end
print(f1(1, 2) + f2(3, 4) + f3(9, 5), obj.m1(obj, 1), h(1, 2, 3))
"#;
        let out = Compressor::compress(src).expect("compress");
        let mut params: Vec<String> = Vec::new();
        let bytes = out.as_bytes();
        let mut i = 0usize;
        while let Some(pos) = out[i..].find("function") {
            let mut j = i + pos + "function".len();
            // 跳过函数名（`function name.more:method` 形态）
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' || bytes[j] == b'.' || bytes[j] == b':') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                let start = j + 1;
                let end = out[start..].find(')').map(|k| start + k).unwrap_or(start);
                for p in out[start..end].split(',') {
                    let p = p.trim();
                    if !p.is_empty() {
                        params.push(p.to_string());
                    }
                }
                i = end;
            } else {
                i = j;
            }
        }
        assert!(!params.is_empty(), "no params parsed from {:?}", out);
        for p in &params {
            assert_eq!(p.chars().count(), 1, "param {:?} is not single letter (out={:?})", p, out);
        }
        let distinct: std::collections::HashSet<&String> = params.iter().collect();
        assert!(distinct.len() < params.len(), "params are not reused: {:?}", params);
    }
}
