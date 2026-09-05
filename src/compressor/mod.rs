pub mod token;
pub mod lexer;
pub mod ast;
pub mod parser;
pub mod scope;
pub mod codegen;
pub mod renamer;
pub mod packer;

use std::collections::HashMap;
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
        
        let mut resolver = scope::ScopeResolver::new();
        root_block.resolve(&mut resolver);
        
        let ren = renamer::Renamer::new();
        let mut mapping = HashMap::new();
        
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
        
        let mut alloc_usage: HashMap<usize, usize> = HashMap::new();
        for (id, alloc_idx) in &resolver.var_alloc {
            let usage = resolver.var_usage.get(id).copied().unwrap_or(0);
            if usage > 0 {
                *alloc_usage.entry(*alloc_idx).or_insert(0) += usage;
            }
        }

        let mut alloc_indices: Vec<usize> = alloc_usage.keys().copied().collect();
        alloc_indices.sort_by_key(|&idx| std::cmp::Reverse(alloc_usage.get(&idx).copied().unwrap_or(0)));

        let mut alloc_to_optimized = HashMap::new();
        for (opt_idx, &alloc_idx) in alloc_indices.iter().enumerate() {
            alloc_to_optimized.insert(alloc_idx, opt_idx);
        }
        
        let required_names = alloc_indices.len();
        let mut valid_names = Vec::new();
        let mut name_counter = 0;
        
        while valid_names.len() < required_names {
            let mut n = name_counter;
            let mut candidate = String::new();
            loop {
                candidate.push(single_letters[n % base]);
                n /= base;
                if n == 0 { break; }
            }
            let candidate: String = candidate.chars().rev().collect();
            name_counter += 1;
            if ren.is_keyword(&candidate) || ren.is_safe_global(&candidate) { continue; }
            valid_names.push(candidate);
        }
        
        for (id, alloc_idx) in resolver.var_alloc {
            let usage = resolver.var_usage.get(&id).copied().unwrap_or(0);
            if usage == 0 {
                mapping.insert(id, "_".to_string());
            } else if let Some(&opt_idx) = alloc_to_optimized.get(&alloc_idx) {
                mapping.insert(id, valid_names[opt_idx].clone());
            }
        }
        
        let ctx = codegen::CodegenContext {
            mapping,
            shuffled_chars: single_letters,
            map_string_start_idx: name_counter,
        };
        
        let mut gen_tokens = Vec::new();
        root_block.to_tokens(&ctx, &mut gen_tokens);
        
        Ok(packer::Packer::pack(gen_tokens))
    }
}