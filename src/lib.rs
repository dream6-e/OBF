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
mod random;
pub mod scope;
pub mod target;
pub mod vm;

pub use diagnostic::Diagnostic;
pub use minify::Options as MinifyOptions;
pub use target::Target;

/// Lex and parse a source chunk for the selected language into an owned AST.
pub fn parse(source: &str, target: Target) -> Result<ast::Chunk, Diagnostic> {
    parser::parse_source(source, target)
}

/// Lex and validate a source chunk for the selected language.
pub fn check(source: &str, target: Target) -> Result<(), Diagnostic> {
    parse(source, target).map(|_| ())
}

/// Validate, randomly rename safe local bindings to 1-2 letters, and emit a
/// single physical line. Use `MinifyOptions::seeded` for reproducible output.
/// Known reflection/environment access conservatively disables renaming.
pub fn minify(source: &str, target: Target) -> Result<String, Diagnostic> {
    minify_with_options(source, target, MinifyOptions::default())
}

/// Use `rename_locals: false` for lexical-only compression, including when
/// dynamically supplied host code can observe local/upvalue names.
pub fn minify_with_options(
    source: &str,
    target: Target,
    options: MinifyOptions,
) -> Result<String, Diagnostic> {
    minify::with_options(source, target, options)
}
