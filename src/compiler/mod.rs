#![allow(unused)]
pub mod ast;
pub mod codegen;
pub mod lexer;
pub mod parser;
pub mod token;
pub mod error; 
pub mod instructions;
pub mod proto;
pub mod value;
pub mod vm_stubs;
pub mod dump;
pub use codegen::{compile, compile_with_lexer};
