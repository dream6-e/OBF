//! 常量局部化（README 规则：某个数字在一个作用域使用次数大于两次就 local 为一个变量）。
//!
//! 命中范围：同一个函数体内的数字字面量（含其嵌套块，但不跨函数边界——嵌套函数里的
//! 使用各自结算）。提升后在最外层块首合并成一条 `local A=...,B=...`，块内引用改读局部名。
//! 数字是常量，读写语义完全不变；收益只来自「声明一次 + 引用更短」。
//!
//! 两条安全线：
//!   1. 只提升真正省字节的项（收益公式见 `worth_hoisting`），且值为 0/1 的短常量不参与
//!      （它们会被 RadixSieve 规范化成 1 个字符，提升反而变大）。
//!   2. 插入点所在函数若已声明较多局部，直接放弃提升——Lua 每函数活跃局部上限 200，
//!      payload 顶层函数已接近该上限（见 `项目交接总结.md`），多一枚就会整份产物编译失败。

use std::collections::{HashMap, HashSet};

use super::ast::{Block, Call, Expr, LastStmt, LocalVar, PrefixExpr, Stmt, TableField, Var, VarId};

/// 使用次数下限：大于两次。
const MIN_COUNT: usize = 3;
/// 每个函数最多提升的常量个数（控制局部变量增量的上限）。
const MAX_PER_FUNCTION: usize = 12;
/// 函数体内既有局部声明数超过此值就不再提升，给 Lua 的 200 活跃局部上限留余量。
const LOCAL_BUDGET: usize = 170;
/// 引用名按最终会被改名成 2 个字符估算（保守）。
const NAME_LEN: usize = 2;

#[derive(Debug, Default, Clone, Copy)]
pub struct HoistStats {
    pub hoisted_literals: usize,
    pub functions_touched: usize,
}

/// 判断某个字面量是否值得提升：命中次数得多到能覆盖「声明成本 + 引用成本」。
fn worth_hoisting(count: usize, lit_len: usize) -> bool {
    if count < MIN_COUNT {
        return false;
    }
    let before = count * lit_len;
    // 声明 `local A=0X44` 里属于这一项的部分：名字 + `=` + 字面量
    let declare = NAME_LEN + 1 + lit_len;
    let after = declare + count * NAME_LEN;
    before > after
}

/// 值为 0/1 的十六进制字面量会被 `codegen` 规范化成一个字符，不参与提升。
fn is_normalized_short(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 3 || bytes[0] != b'0' || !(bytes[1] == b'X' || bytes[1] == b'x') {
        return false;
    }
    let digits = &text[2..];
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    matches!(u64::from_str_radix(digits, 16), Ok(0) | Ok(1))
}

pub fn hoist_constants(root: &mut Block) -> HoistStats {
    let mut stats = HoistStats::default();
    hoist_in_function(root, 0, &mut stats);
    stats
}

/// 对「一个函数体块」做一次提升，然后递归处理它内部嵌套的函数体。
fn hoist_in_function(block: &mut Block, param_count: usize, stats: &mut HoistStats) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    count_numbers(block, &mut counts);

    let mut candidates: Vec<(String, usize)> = counts
        .into_iter()
        .filter(|(text, count)| !is_normalized_short(text) && worth_hoisting(*count, text.len()))
        .collect();
    // 收益大的优先（同等收益时按字面量排序，保证同一输入下结果稳定）
    candidates.sort_by(|a, b| {
        let save_a = (a.1 - 1) * a.0.len() - a.1 * NAME_LEN;
        let save_b = (b.1 - 1) * b.0.len() - b.1 * NAME_LEN;
        save_b.cmp(&save_a).then(a.0.cmp(&b.0))
    });
    candidates.truncate(MAX_PER_FUNCTION);

    if !candidates.is_empty() && param_count + count_declared_locals(block) <= LOCAL_BUDGET {
        let mut used_names = HashSet::new();
        collect_names(block, &mut used_names);

        let mut vars = Vec::with_capacity(candidates.len());
        let mut exprs = Vec::with_capacity(candidates.len());
        let mut rename: HashMap<String, String> = HashMap::new();
        for (text, _) in candidates {
            let name = fresh_name(&used_names, vars.len());
            used_names.insert(name.clone());
            rename.insert(text.clone(), name.clone());
            vars.push(LocalVar { name, id: VarId(0) });
            exprs.push(Expr::Number(text));
        }

        replace_numbers(block, &rename);
        block.stmts.insert(0, Stmt::LocalAssign(vars, exprs));
        stats.hoisted_literals += rename.len();
        stats.functions_touched += 1;
    }

    visit_nested_functions(block, &mut |body| hoist_in_function(body, param_count_of(body), stats));
}

fn param_count_of(_body: &Block) -> usize {
    // 形参已在函数体作用域外，这里用 0 起算：预算是「既有局部总量」的粗粒度上界，
    // 形参数量级很小，忽略它只会让门槛更宽松，不会突破 200 上限。
    0
}

/// 占位名：只需在解析期唯一，最终名由 renamer 统一分配。
fn fresh_name(used: &HashSet<String>, index: usize) -> String {
    let mut n = index;
    loop {
        let name = format!("_h{}", n);
        if !used.contains(&name) {
            return name;
        }
        n += 1;
    }
}

/// 统计该函数子树里的局部声明数（保守上界，用于 200 上限保护）。
fn count_declared_locals(block: &Block) -> usize {
    let mut total = 0usize;
    count_locals_in_block(block, &mut total);
    total
}

fn count_locals_in_block(block: &Block, total: &mut usize) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::LocalAssign(vars, _) => *total += vars.len(),
            Stmt::LocalFunction { block, .. } => {
                *total += 1;
                count_locals_in_block(block, total);
            }
            Stmt::Do(b) => count_locals_in_block(b, total),
            Stmt::While(_, b) => count_locals_in_block(b, total),
            Stmt::Repeat(b, _) => count_locals_in_block(b, total),
            Stmt::If { then_block, else_ifs, else_block, .. } => {
                count_locals_in_block(then_block, total);
                for (_, b) in else_ifs {
                    count_locals_in_block(b, total);
                }
                if let Some(b) = else_block {
                    count_locals_in_block(b, total);
                }
            }
            Stmt::For { block, .. } => count_locals_in_block(block, total),
            Stmt::ForIn { block, .. } => count_locals_in_block(block, total),
            Stmt::Function { block, .. } => count_locals_in_block(block, total),
            _ => {}
        }
    }
}

/// 统计本函数子树内的数字字面量（不进入嵌套函数体）。
fn count_numbers(block: &Block, counts: &mut HashMap<String, usize>) {
    for stmt in &block.stmts {
        count_numbers_in_stmt(stmt, counts);
    }
    if let Some(last) = &block.last_stmt {
        match last {
            LastStmt::Return(exprs) => {
                for e in exprs {
                    count_numbers_in_expr(e, counts);
                }
            }
            LastStmt::Break => {}
        }
    }
}

fn count_numbers_in_stmt(stmt: &Stmt, counts: &mut HashMap<String, usize>) {
    match stmt {
        Stmt::Assign(vars, exprs) => {
            for v in vars {
                count_numbers_in_var(v, counts);
            }
            for e in exprs {
                count_numbers_in_expr(e, counts);
            }
        }
        Stmt::Call(call) => count_numbers_in_call(call, counts),
        Stmt::Do(b) => count_numbers(b, counts),
        Stmt::While(cond, b) => {
            count_numbers_in_expr(cond, counts);
            count_numbers(b, counts);
        }
        Stmt::Repeat(b, cond) => {
            count_numbers(b, counts);
            count_numbers_in_expr(cond, counts);
        }
        Stmt::If { cond, then_block, else_ifs, else_block } => {
            count_numbers_in_expr(cond, counts);
            count_numbers(then_block, counts);
            for (c, b) in else_ifs {
                count_numbers_in_expr(c, counts);
                count_numbers(b, counts);
            }
            if let Some(b) = else_block {
                count_numbers(b, counts);
            }
        }
        Stmt::For { init, limit, step, block, .. } => {
            count_numbers_in_expr(init, counts);
            count_numbers_in_expr(limit, counts);
            if let Some(s) = step {
                count_numbers_in_expr(s, counts);
            }
            count_numbers(block, counts);
        }
        Stmt::ForIn { exprs, block, .. } => {
            for e in exprs {
                count_numbers_in_expr(e, counts);
            }
            count_numbers(block, counts);
        }
        // 函数体是独立作用域：数字由该函数自己结算，这里跨过。
        Stmt::Function { .. } | Stmt::LocalFunction { .. } => {}
        Stmt::LocalAssign(_, exprs) => {
            for e in exprs {
                count_numbers_in_expr(e, counts);
            }
        }
    }
}

fn count_numbers_in_expr(expr: &Expr, counts: &mut HashMap<String, usize>) {
    match expr {
        Expr::Number(text) => {
            *counts.entry(text.clone()).or_insert(0) += 1;
        }
        Expr::Nil | Expr::Boolean(_) | Expr::String(_) | Expr::Vararg => {}
        Expr::FuncDef(_, _, _) => {}
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    TableField::List(e) => count_numbers_in_expr(e, counts),
                    TableField::Rec(k, v) => {
                        count_numbers_in_expr(k, counts);
                        count_numbers_in_expr(v, counts);
                    }
                }
            }
        }
        Expr::BinOp(_, lhs, rhs) => {
            count_numbers_in_expr(lhs, counts);
            count_numbers_in_expr(rhs, counts);
        }
        Expr::UnOp(_, e) => count_numbers_in_expr(e, counts),
        Expr::Prefix(p) => count_numbers_in_prefix(p, counts),
    }
}

fn count_numbers_in_prefix(prefix: &PrefixExpr, counts: &mut HashMap<String, usize>) {
    match prefix {
        PrefixExpr::Var(v) => count_numbers_in_var(v, counts),
        PrefixExpr::Call(call) => count_numbers_in_call(call, counts),
        PrefixExpr::Paren(e) => count_numbers_in_expr(e, counts),
    }
}

fn count_numbers_in_var(var: &Var, counts: &mut HashMap<String, usize>) {
    match var {
        Var::Name(_, _) => {}
        Var::Index(prefix, expr) => {
            count_numbers_in_prefix(prefix, counts);
            count_numbers_in_expr(expr, counts);
        }
        Var::Member(prefix, _) => count_numbers_in_prefix(prefix, counts),
    }
}

fn count_numbers_in_call(call: &Call, counts: &mut HashMap<String, usize>) {
    match call {
        Call::Normal(prefix, args) => {
            count_numbers_in_prefix(prefix, counts);
            for a in args {
                count_numbers_in_expr(a, counts);
            }
        }
        Call::Method(prefix, _, args) => {
            count_numbers_in_prefix(prefix, counts);
            for a in args {
                count_numbers_in_expr(a, counts);
            }
        }
    }
}

/// 收集子树里出现过的所有名字（含嵌套函数），保证占位名不会与既有名字相撞。
fn collect_names(block: &Block, names: &mut HashSet<String>) {
    for stmt in &block.stmts {
        collect_names_in_stmt(stmt, names);
    }
    if let Some(LastStmt::Return(exprs)) = &block.last_stmt {
        for e in exprs {
            collect_names_in_expr(e, names);
        }
    }
}

fn collect_names_in_stmt(stmt: &Stmt, names: &mut HashSet<String>) {
    match stmt {
        Stmt::Assign(vars, exprs) => {
            for v in vars {
                collect_names_in_var(v, names);
            }
            for e in exprs {
                collect_names_in_expr(e, names);
            }
        }
        Stmt::Call(call) => collect_names_in_call(call, names),
        Stmt::Do(b) => collect_names(b, names),
        Stmt::While(cond, b) => {
            collect_names_in_expr(cond, names);
            collect_names(b, names);
        }
        Stmt::Repeat(b, cond) => {
            collect_names(b, names);
            collect_names_in_expr(cond, names);
        }
        Stmt::If { cond, then_block, else_ifs, else_block } => {
            collect_names_in_expr(cond, names);
            collect_names(then_block, names);
            for (c, b) in else_ifs {
                collect_names_in_expr(c, names);
                collect_names(b, names);
            }
            if let Some(b) = else_block {
                collect_names(b, names);
            }
        }
        Stmt::For { var, init, limit, step, block } => {
            names.insert(var.name.clone());
            collect_names_in_expr(init, names);
            collect_names_in_expr(limit, names);
            if let Some(s) = step {
                collect_names_in_expr(s, names);
            }
            collect_names(block, names);
        }
        Stmt::ForIn { vars, exprs, block } => {
            for v in vars {
                names.insert(v.name.clone());
            }
            for e in exprs {
                collect_names_in_expr(e, names);
            }
            collect_names(block, names);
        }
        Stmt::Function { path, method, params, block, .. } => {
            for p in path {
                names.insert(p.clone());
            }
            if let Some(m) = method {
                names.insert(m.clone());
            }
            for p in params {
                names.insert(p.name.clone());
            }
            collect_names(block, names);
        }
        Stmt::LocalFunction { var, params, block, .. } => {
            names.insert(var.name.clone());
            for p in params {
                names.insert(p.name.clone());
            }
            collect_names(block, names);
        }
        Stmt::LocalAssign(vars, exprs) => {
            for v in vars {
                names.insert(v.name.clone());
            }
            for e in exprs {
                collect_names_in_expr(e, names);
            }
        }
    }
}

fn collect_names_in_expr(expr: &Expr, names: &mut HashSet<String>) {
    match expr {
        Expr::Nil | Expr::Boolean(_) | Expr::Number(_) | Expr::String(_) | Expr::Vararg => {}
        Expr::FuncDef(params, _, block) => {
            for p in params {
                names.insert(p.name.clone());
            }
            collect_names(block, names);
        }
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    TableField::List(e) => collect_names_in_expr(e, names),
                    TableField::Rec(k, v) => {
                        collect_names_in_expr(k, names);
                        collect_names_in_expr(v, names);
                    }
                }
            }
        }
        Expr::BinOp(_, lhs, rhs) => {
            collect_names_in_expr(lhs, names);
            collect_names_in_expr(rhs, names);
        }
        Expr::UnOp(_, e) => collect_names_in_expr(e, names),
        Expr::Prefix(p) => collect_names_in_prefix(p, names),
    }
}

fn collect_names_in_prefix(prefix: &PrefixExpr, names: &mut HashSet<String>) {
    match prefix {
        PrefixExpr::Var(v) => collect_names_in_var(v, names),
        PrefixExpr::Call(call) => collect_names_in_call(call, names),
        PrefixExpr::Paren(e) => collect_names_in_expr(e, names),
    }
}

fn collect_names_in_var(var: &Var, names: &mut HashSet<String>) {
    match var {
        Var::Name(name, _) => {
            names.insert(name.clone());
        }
        Var::Index(prefix, expr) => {
            collect_names_in_prefix(prefix, names);
            collect_names_in_expr(expr, names);
        }
        Var::Member(prefix, member) => {
            names.insert(member.clone());
            collect_names_in_prefix(prefix, names);
        }
    }
}

fn collect_names_in_call(call: &Call, names: &mut HashSet<String>) {
    match call {
        Call::Normal(prefix, args) => {
            collect_names_in_prefix(prefix, names);
            for a in args {
                collect_names_in_expr(a, names);
            }
        }
        Call::Method(prefix, method, args) => {
            names.insert(method.clone());
            collect_names_in_prefix(prefix, names);
            for a in args {
                collect_names_in_expr(a, names);
            }
        }
    }
}

/// 把命中的数字字面量替换成局部变量引用（跨过嵌套函数体）。
fn replace_numbers(block: &mut Block, rename: &HashMap<String, String>) {
    for stmt in &mut block.stmts {
        replace_numbers_in_stmt(stmt, rename);
    }
    if let Some(last) = &mut block.last_stmt {
        if let LastStmt::Return(exprs) = last {
            for e in exprs {
                replace_numbers_in_expr(e, rename);
            }
        }
    }
}

fn replace_numbers_in_stmt(stmt: &mut Stmt, rename: &HashMap<String, String>) {
    match stmt {
        Stmt::Assign(vars, exprs) => {
            for v in vars {
                replace_numbers_in_var(v, rename);
            }
            for e in exprs {
                replace_numbers_in_expr(e, rename);
            }
        }
        Stmt::Call(call) => replace_numbers_in_call(call, rename),
        Stmt::Do(b) => replace_numbers(b, rename),
        Stmt::While(cond, b) => {
            replace_numbers_in_expr(cond, rename);
            replace_numbers(b, rename);
        }
        Stmt::Repeat(b, cond) => {
            replace_numbers(b, rename);
            replace_numbers_in_expr(cond, rename);
        }
        Stmt::If { cond, then_block, else_ifs, else_block } => {
            replace_numbers_in_expr(cond, rename);
            replace_numbers(then_block, rename);
            for (c, b) in else_ifs {
                replace_numbers_in_expr(c, rename);
                replace_numbers(b, rename);
            }
            if let Some(b) = else_block {
                replace_numbers(b, rename);
            }
        }
        Stmt::For { init, limit, step, block, .. } => {
            replace_numbers_in_expr(init, rename);
            replace_numbers_in_expr(limit, rename);
            if let Some(s) = step {
                replace_numbers_in_expr(s, rename);
            }
            replace_numbers(block, rename);
        }
        Stmt::ForIn { exprs, block, .. } => {
            for e in exprs {
                replace_numbers_in_expr(e, rename);
            }
            replace_numbers(block, rename);
        }
        Stmt::Function { .. } | Stmt::LocalFunction { .. } => {}
        Stmt::LocalAssign(_, exprs) => {
            for e in exprs {
                replace_numbers_in_expr(e, rename);
            }
        }
    }
}

fn replace_numbers_in_expr(expr: &mut Expr, rename: &HashMap<String, String>) {
    match expr {
        Expr::Number(text) => {
            if let Some(name) = rename.get(text) {
                let replacement = Expr::Prefix(Box::new(PrefixExpr::Var(Var::Name(
                    name.clone(),
                    VarId(0),
                ))));
                *expr = replacement;
            }
        }
        Expr::Nil | Expr::Boolean(_) | Expr::String(_) | Expr::Vararg => {}
        Expr::FuncDef(_, _, _) => {}
        Expr::Table(fields) => {
            for f in fields {
                match f {
                    TableField::List(e) => replace_numbers_in_expr(e, rename),
                    TableField::Rec(k, v) => {
                        replace_numbers_in_expr(k, rename);
                        replace_numbers_in_expr(v, rename);
                    }
                }
            }
        }
        Expr::BinOp(_, lhs, rhs) => {
            replace_numbers_in_expr(lhs, rename);
            replace_numbers_in_expr(rhs, rename);
        }
        Expr::UnOp(_, e) => replace_numbers_in_expr(e, rename),
        Expr::Prefix(p) => replace_numbers_in_prefix(p, rename),
    }
}

fn replace_numbers_in_prefix(prefix: &mut PrefixExpr, rename: &HashMap<String, String>) {
    match prefix {
        PrefixExpr::Var(v) => replace_numbers_in_var(v, rename),
        PrefixExpr::Call(call) => replace_numbers_in_call(call, rename),
        PrefixExpr::Paren(e) => replace_numbers_in_expr(e, rename),
    }
}

fn replace_numbers_in_var(var: &mut Var, rename: &HashMap<String, String>) {
    match var {
        Var::Name(_, _) => {}
        Var::Index(prefix, expr) => {
            replace_numbers_in_prefix(prefix, rename);
            replace_numbers_in_expr(expr, rename);
        }
        Var::Member(prefix, _) => replace_numbers_in_prefix(prefix, rename),
    }
}

fn replace_numbers_in_call(call: &mut Call, rename: &HashMap<String, String>) {
    match call {
        Call::Normal(prefix, args) => {
            replace_numbers_in_prefix(prefix, rename);
            for a in args {
                replace_numbers_in_expr(a, rename);
            }
        }
        Call::Method(prefix, _, args) => {
            replace_numbers_in_prefix(prefix, rename);
            for a in args {
                replace_numbers_in_expr(a, rename);
            }
        }
    }
}

/// 找出本函数体内**直接**嵌套的函数体，逐个回调（更深层的由回调自身递归）。
fn visit_nested_functions(block: &mut Block, f: &mut impl FnMut(&mut Block)) {
    for stmt in &mut block.stmts {
        visit_nested_functions_in_stmt(stmt, f);
    }
    if let Some(LastStmt::Return(exprs)) = &mut block.last_stmt {
        for e in exprs {
            visit_nested_functions_in_expr(e, f);
        }
    }
}

fn visit_nested_functions_in_stmt(stmt: &mut Stmt, f: &mut impl FnMut(&mut Block)) {
    match stmt {
        Stmt::Assign(vars, exprs) => {
            for v in vars {
                visit_nested_functions_in_var(v, f);
            }
            for e in exprs {
                visit_nested_functions_in_expr(e, f);
            }
        }
        Stmt::Call(call) => visit_nested_functions_in_call(call, f),
        Stmt::Do(b) => visit_nested_functions(b, f),
        Stmt::While(cond, b) => {
            visit_nested_functions_in_expr(cond, f);
            visit_nested_functions(b, f);
        }
        Stmt::Repeat(b, cond) => {
            visit_nested_functions(b, f);
            visit_nested_functions_in_expr(cond, f);
        }
        Stmt::If { cond, then_block, else_ifs, else_block } => {
            visit_nested_functions_in_expr(cond, f);
            visit_nested_functions(then_block, f);
            for (c, b) in else_ifs {
                visit_nested_functions_in_expr(c, f);
                visit_nested_functions(b, f);
            }
            if let Some(b) = else_block {
                visit_nested_functions(b, f);
            }
        }
        Stmt::For { init, limit, step, block, .. } => {
            visit_nested_functions_in_expr(init, f);
            visit_nested_functions_in_expr(limit, f);
            if let Some(s) = step {
                visit_nested_functions_in_expr(s, f);
            }
            visit_nested_functions(block, f);
        }
        Stmt::ForIn { exprs, block, .. } => {
            for e in exprs {
                visit_nested_functions_in_expr(e, f);
            }
            visit_nested_functions(block, f);
        }
        Stmt::Function { block, .. } => f(block),
        Stmt::LocalFunction { block, .. } => f(block),
        Stmt::LocalAssign(_, exprs) => {
            for e in exprs {
                visit_nested_functions_in_expr(e, f);
            }
        }
    }
}

fn visit_nested_functions_in_expr(expr: &mut Expr, f: &mut impl FnMut(&mut Block)) {
    match expr {
        Expr::FuncDef(_, _, block) => f(block),
        Expr::Nil | Expr::Boolean(_) | Expr::Number(_) | Expr::String(_) | Expr::Vararg => {}
        Expr::Table(fields) => {
            for field in fields {
                match field {
                    TableField::List(e) => visit_nested_functions_in_expr(e, f),
                    TableField::Rec(k, v) => {
                        visit_nested_functions_in_expr(k, f);
                        visit_nested_functions_in_expr(v, f);
                    }
                }
            }
        }
        Expr::BinOp(_, lhs, rhs) => {
            visit_nested_functions_in_expr(lhs, f);
            visit_nested_functions_in_expr(rhs, f);
        }
        Expr::UnOp(_, e) => visit_nested_functions_in_expr(e, f),
        Expr::Prefix(p) => visit_nested_functions_in_prefix(p, f),
    }
}

fn visit_nested_functions_in_prefix(prefix: &mut PrefixExpr, f: &mut impl FnMut(&mut Block)) {
    match prefix {
        PrefixExpr::Var(v) => visit_nested_functions_in_var(v, f),
        PrefixExpr::Call(call) => visit_nested_functions_in_call(call, f),
        PrefixExpr::Paren(e) => visit_nested_functions_in_expr(e, f),
    }
}

fn visit_nested_functions_in_var(var: &mut Var, f: &mut impl FnMut(&mut Block)) {
    match var {
        Var::Name(_, _) => {}
        Var::Index(prefix, expr) => {
            visit_nested_functions_in_prefix(prefix, f);
            visit_nested_functions_in_expr(expr, f);
        }
        Var::Member(prefix, _) => visit_nested_functions_in_prefix(prefix, f),
    }
}

fn visit_nested_functions_in_call(call: &mut Call, f: &mut impl FnMut(&mut Block)) {
    match call {
        Call::Normal(prefix, args) => {
            visit_nested_functions_in_prefix(prefix, f);
            for a in args {
                visit_nested_functions_in_expr(a, f);
            }
        }
        Call::Method(prefix, _, args) => {
            visit_nested_functions_in_prefix(prefix, f);
            for a in args {
                visit_nested_functions_in_expr(a, f);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compressor::{lexer::Lexer, parser::Parser, token::TokenType};

    fn parse(source: &str) -> Block {
        let mut lex = Lexer::new(source);
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
        Parser::new(tokens).parse_block().expect("测试源码应可解析")
    }

    /// 直接属于该函数体的数字字面量（不进入嵌套函数）。
    fn outer_numbers(block: &Block) -> Vec<String> {
        let mut counts = HashMap::new();
        count_numbers(block, &mut counts);
        let mut v: Vec<String> = counts.into_keys().collect();
        v.sort();
        v
    }

    #[test]
    fn hoists_number_used_more_than_twice() {
        let mut block = parse("local t={0X1234,0X1234,0X1234,0X1234,0X1234};return t");
        let stats = hoist_constants(&mut block);
        assert_eq!(stats.hoisted_literals, 1);
        assert_eq!(count_declared_locals(&block), 2, "原有 local t 之外应新增一条提升声明");
        // 表内引用已变成局部名，只剩提升声明里的那一个字面量
        assert_eq!(outer_numbers(&block), vec!["0X1234".to_string()]);
    }

    #[test]
    fn leaves_rare_number_alone() {
        let mut block = parse("local t={0X11AA,0X22BB};return t");
        let stats = hoist_constants(&mut block);
        assert_eq!(stats.hoisted_literals, 0);
    }

    #[test]
    fn does_not_hoist_short_normalized_constants() {
        // 0X0/0X1 由 codegen 规范化成一个字符，提升只会变大
        let mut block = parse("local t={0X0,0X0,0X0,0X0,0X0,0X0};return t");
        let stats = hoist_constants(&mut block);
        assert_eq!(stats.hoisted_literals, 0);
    }

    #[test]
    fn nested_function_is_scored_separately() {
        let mut block = parse(
            "local function f() return 0X1234,0X1234,0X1234,0X1234,0X1234 end;return f",
        );
        let stats = hoist_constants(&mut block);
        assert_eq!(stats.hoisted_literals, 1);
        assert_eq!(stats.functions_touched, 1);
        // 提升只发生在嵌套函数内部：外层块不应多出 LocalAssign
        let outer_locals = block
            .stmts
            .iter()
            .filter(|s| matches!(s, Stmt::LocalAssign(_, _)))
            .count();
        assert_eq!(outer_locals, 0);
        assert_eq!(count_declared_locals(&block), 2, "f 自身 + f 内部的一条提升声明");
        let mut inside = Vec::new();
        let mut nested_local_decls = 0usize;
        visit_nested_functions(&mut block, &mut |body| {
            inside.extend(outer_numbers(body));
            nested_local_decls += body
                .stmts
                .iter()
                .filter(|s| matches!(s, Stmt::LocalAssign(_, _)))
                .count();
        });
        // 返回值里的 5 处引用已变成局部名，只剩提升声明里的那一个字面量
        assert_eq!(inside, vec!["0X1234".to_string()]);
        assert_eq!(nested_local_decls, 1, "提升声明应落在嵌套函数体内");
    }

    #[test]
    fn placeholder_names_never_collide_with_existing_names() {
        let mut block = parse("local _h0=1;local t={0X1234,0X1234,0X1234,0X1234,0X1234};return _h0,t");
        hoist_constants(&mut block);
        let mut names = HashSet::new();
        collect_names(&block, &mut names);
        assert!(names.contains("_h1"), "占位名应避开 _h0：{names:?}");
    }

    #[test]
    fn keeps_syntax_and_scope_intact_for_block_local() {
        // 提升声明落在最外层块首，块内嵌套语句都能读到同一个值
        let mut block = parse(
            "local acc=0;for i=1,3 do if i>1 then acc=acc+0X270F end end;return acc+0X270F",
        );
        let stats = hoist_constants(&mut block);
        assert_eq!(stats.hoisted_literals, 0, "只出现两次时保持原样");
        let mut counts = HashMap::new();
        count_numbers(&block, &mut counts);
        assert_eq!(counts.get("0X270F"), Some(&2));
        let mut block2 = parse(
            "local acc=0;for i=1,3 do if i>1 then acc=acc+0X270F end end;return acc+0X270F+0X270F",
        );
        let stats = hoist_constants(&mut block2);
        assert_eq!(stats.hoisted_literals, 1);
    }
}
