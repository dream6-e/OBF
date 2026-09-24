//! Lua 5.1 源码 → `Proto`（字节码原型）的编译器。
//!
//! 原先是一个 91 KB 的单文件 `codegen.rs`，超出仓库「单个 `.rs` 不超过 80 KB」的约定，
//! 按职责拆成下面 5 个子模块。**代码是原样搬移的，没有改动任何编译逻辑**，
//! 只是把原先「同文件内私有」的项放宽成 `pub(super)` 以便跨子模块访问，
//! 并把 `super::ast` 之类的相对路径改成 `crate::compiler::ast` 绝对路径。
//!
//! | 子模块 | 内容 |
//! |---|---|
//! | `types` | 表达式上下文 / 函数状态 / 块上下文 / 常量键 |
//! | `emit`  | `Compiler` 结构体 + 指令发射、常量池、寄存器与作用域 |
//! | `expr`  | 表达式代码生成 |
//! | `stat`  | 语句代码生成（含对外入口 `compile`） |
//! | `tests` | 单元测试 |

mod emit;
mod expr;
mod stat;
mod types;

#[cfg(test)]
mod tests;

pub use emit::Compiler;
pub use stat::{compile, compile_with_lexer};
pub(crate) use expr::int2fb;
pub(crate) use types::{ExprContext, ExprKind, FuncState, UpvalDesc};
