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
            scope_depths[scope_a].cmp(&scope_depths[scope_b])
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
            let mut blocked = HashSet::new();
            let mut parent = resolver.scope_parents[scope];
            while let Some(parent_scope) = parent {
                blocked.extend(names_by_scope[parent_scope].iter().cloned());
                parent = resolver.scope_parents[parent_scope];
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
}
