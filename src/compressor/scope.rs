use std::collections::HashMap;
use super::ast::{Block, LastStmt, Stmt, Expr, PrefixExpr, Var, Call, LocalVar, VarId};

pub struct ScopeResolver {
    scopes: Vec<HashMap<String, VarId>>,
    scope_var_counts: Vec<usize>,
    next_id: usize,
    pub var_alloc: HashMap<VarId, usize>,
    pub var_usage: HashMap<VarId, usize>,
}

impl ScopeResolver {
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::new()],
            scope_var_counts: vec![0],
            next_id: 1,
            var_alloc: HashMap::new(),
            var_usage: HashMap::new(),
        }
    }

    pub fn enter_scope(&mut self) {
        self.scopes.push(HashMap::new());
        self.scope_var_counts.push(0);
    }

    pub fn exit_scope(&mut self) {
        self.scopes.pop();
        self.scope_var_counts.pop();
    }

    pub fn declare_local(&mut self, name: &str) -> VarId {
        let id = VarId(self.next_id);
        self.next_id += 1;
        
        let active_vars: usize = self.scope_var_counts.iter().sum();
        self.var_alloc.insert(id, active_vars);
        self.var_usage.insert(id, 0);
        
        if let Some(count) = self.scope_var_counts.last_mut() {
            *count += 1;
        }

        if let Some(current) = self.scopes.last_mut() {
            current.insert(name.to_string(), id);
        }
        id
    }

    pub fn resolve_var(&self, name: &str) -> Option<VarId> {
        for scope in self.scopes.iter().rev() {
            if let Some(&id) = scope.get(name) {
                return Some(id);
            }
        }
        None
    }

    pub fn record_usage(&mut self, id: VarId) {
        if let Some(count) = self.var_usage.get_mut(&id) {
            *count += 1;
        }
    }

    pub fn max_id(&self) -> usize {
        self.next_id - 1
    }
}

impl Block {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        r.enter_scope();
        for s in &mut self.stmts {
            s.resolve(r);
        }
        if let Some(l) = &mut self.last_stmt {
            l.resolve(r);
        }
        r.exit_scope();
    }

    pub fn resolve_no_scope_bracket(&mut self, r: &mut ScopeResolver) {
        for s in &mut self.stmts {
            s.resolve(r);
        }
        if let Some(l) = &mut self.last_stmt {
            l.resolve(r);
        }
    }
}

impl LastStmt {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            LastStmt::Return(exprs) => {
                for e in exprs {
                    e.resolve(r);
                }
            }
            LastStmt::Break => {}
        }
    }
}

impl Stmt {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            Stmt::Assign(vars, exprs) => {
                for v in vars {
                    v.resolve(r);
                }
                for e in exprs {
                    e.resolve(r);
                }
            }
            Stmt::Call(call) => {
                call.resolve(r);
            }
            Stmt::Do(block) => {
                block.resolve(r);
            }
            Stmt::While(cond, block) => {
                cond.resolve(r);
                block.resolve(r);
            }
            Stmt::Repeat(block, cond) => {
                r.enter_scope();
                block.resolve_no_scope_bracket(r);
                cond.resolve(r);
                r.exit_scope();
            }
            Stmt::If { cond, then_block, else_ifs, else_block } => {
                cond.resolve(r);
                then_block.resolve(r);
                for (c, b) in else_ifs {
                    c.resolve(r);
                    b.resolve(r);
                }
                if let Some(b) = else_block {
                    b.resolve(r);
                }
            }
            Stmt::For { var, init, limit, step, block } => {
                init.resolve(r);
                limit.resolve(r);
                if let Some(s) = step {
                    s.resolve(r);
                }
                r.enter_scope();
                var.id = r.declare_local(&var.name);
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::ForIn { vars, exprs, block } => {
                for e in exprs {
                    e.resolve(r);
                }
                r.enter_scope();
                for v in vars {
                    v.id = r.declare_local(&v.name);
                }
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::Function { path: _, method: _, params, is_vararg: _, block } => {
                r.enter_scope();
                for p in params {
                    p.id = r.declare_local(&p.name);
                }
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::LocalFunction { var, params, is_vararg: _, block } => {
                var.id = r.declare_local(&var.name);
                r.enter_scope();
                for p in params {
                    p.id = r.declare_local(&p.name);
                }
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::LocalAssign(vars, exprs) => {
                for e in exprs {
                    e.resolve(r);
                }
                for v in vars {
                    v.id = r.declare_local(&v.name);
                }
            }
        }
    }
}

impl Expr {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            Expr::Nil | Expr::Boolean(_) | Expr::Number(_) | Expr::String(_) | Expr::Vararg => {}
            Expr::FuncDef(params, _, block) => {
                r.enter_scope();
                for p in params {
                    p.id = r.declare_local(&p.name);
                }
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Expr::Table(fields) => {
                for f in fields {
                    match f {
                        super::ast::TableField::List(e) => e.resolve(r),
                        super::ast::TableField::Rec(k, v) => {
                            k.resolve(r);
                            v.resolve(r);
                        }
                    }
                }
            }
            Expr::BinOp(_, lhs, rhs) => {
                lhs.resolve(r);
                rhs.resolve(r);
            }
            Expr::UnOp(_, e) => {
                e.resolve(r);
            }
            Expr::Prefix(p) => {
                p.resolve(r);
            }
        }
    }
}

impl PrefixExpr {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            PrefixExpr::Var(v) => v.resolve(r),
            PrefixExpr::Call(c) => c.resolve(r),
            PrefixExpr::Paren(e) => e.resolve(r),
        }
    }
}

impl Var {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            Var::Name(name, id) => {
                if let Some(resolved_id) = r.resolve_var(name) {
                    *id = resolved_id;
                    r.record_usage(resolved_id);
                }
            }
            Var::Index(prefix, expr) => {
                prefix.resolve(r);
                expr.resolve(r);
            }
            Var::Member(prefix, _) => {
                prefix.resolve(r);
            }
        }
    }
}

impl Call {
    pub fn resolve(&mut self, r: &mut ScopeResolver) {
        match self {
            Call::Normal(prefix, args) => {
                prefix.resolve(r);
                for a in args {
                    a.resolve(r);
                }
            }
            Call::Method(prefix, _, args) => {
                prefix.resolve(r);
                for a in args {
                    a.resolve(r);
                }
            }
        }
    }
}