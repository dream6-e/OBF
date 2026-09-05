//! Core library for the OBF toolchain.
//!
//! The project deliberately depends only on `std`; pinned reference Lua and
//! Luau implementations are used as an external compatibility oracle in the
//! test matrix.

pub mod ast;
pub mod bytecode;
pub mod diagnostic;
pub mod lexer;
pub mod minify;
pub mod parser;
pub mod target;
pub mod vm;

pub use diagnostic::Diagnostic;
pub use target::Target;

/// Lex and parse a source chunk for the selected language into an owned AST.
pub fn parse(source: &str, target: Target) -> Result<ast::Chunk, Diagnostic> {
    parser::parse_source(source, target)
}

/// Lex and validate a source chunk for the selected language.
pub fn check(source: &str, target: Target) -> Result<(), Diagnostic> {
    parse(source, target).map(|_| ())
}

/// Validate and minify a source chunk into a single physical line.
pub fn minify(source: &str, target: Target) -> Result<String, Diagnostic> {
    let tokens = lexer::lex(source, target)?;
    parser::parse_lexed(source, &tokens, target)?;
    minify::minify(source, &tokens, target)
}
