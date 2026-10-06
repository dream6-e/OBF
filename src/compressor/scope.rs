use std::collections::{HashMap, HashSet};
use super::ast::{Block, LastStmt, Stmt, Expr, PrefixExpr, Var, Call, LocalVar, VarId};

pub struct ScopeResolver {
    scopes: Vec<HashMap<String, VarId>>,
    scope_var_counts: Vec<usize>,
    next_id: usize,
    pub var_alloc: HashMap<VarId, usize>,
    pub var_usage: HashMap<VarId, usize>,
    pub var_scopes: HashMap<VarId, usize>,
    pub scope_parents: Vec<Option<usize>>,
    scope_stack: Vec<usize>,
    /// 每个作用域**直接**引用到的绑定 id（外层绑定记在最内层作用域上，再上滚）。
    /// 名字分配据此判断「某祖先的名字能否被内层复用」：只有被真正引用的才必须避开。
    scope_refs: Vec<HashSet<VarId>>,
    /// 形参绑定 id：分配名字时优先拿最短名（用户要求：形参尽量单字母）。
    pub param_ids: HashSet<VarId>,
}

impl ScopeResolver {
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::new()],
            scope_var_counts: vec![0],
            next_id: 1,
            var_alloc: HashMap::new(),
            var_usage: HashMap::new(),
            var_scopes: HashMap::new(),
            scope_parents: vec![None],
            scope_stack: vec![0],
            scope_refs: vec![HashSet::new()],
            param_ids: HashSet::new(),
        }
    }

    pub fn enter_scope(&mut self) {
        let parent = *self.scope_stack.last().expect("scope stack must not be empty");
        let id = self.scope_parents.len();
        self.scope_parents.push(Some(parent));
        self.scope_stack.push(id);
        self.scopes.push(HashMap::new());
        self.scope_var_counts.push(0);
        self.scope_refs.push(HashSet::new());
    }

    pub fn exit_scope(&mut self) {
        self.scope_stack.pop();
        self.scopes.pop();
        self.scope_var_counts.pop();
    }

    pub fn declare_local(&mut self, name: &str) -> VarId {
        let id = VarId(self.next_id);
        self.next_id += 1;
        
        let active_vars: usize = self.scope_var_counts.iter().sum();
        self.var_alloc.insert(id, active_vars);
        self.var_usage.insert(id, 0);
        self.var_scopes.insert(id, *self.scope_stack.last().expect("scope stack must not be empty"));
        
        if let Some(count) = self.scope_var_counts.last_mut() {
            *count += 1;
        }

        if let Some(current) = self.scopes.last_mut() {
            current.insert(name.to_string(), id);
        }
        id
    }

    /// 形态⑧：形参重名遮蔽——同名参数复用同一 VarId，改名后仍为 `function(X,X)`。
    /// 仅参数走此入口：同函数内名字解析本就指向末参，共享 id 语义等价；
    /// 局部变量不能复用（闭包按位置捕获首个绑定的语义会被破坏）。
    pub fn declare_param(&mut self, name: &str) -> VarId {
        if let Some(cur) = self.scopes.last() {
            if let Some(&id) = cur.get(name) {
                self.record_usage(id);
                self.param_ids.insert(id);
                return id;
            }
        }
        let id = self.declare_local(name);
        self.param_ids.insert(id);
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

    /// 记下「当前作用域引用到了哪个绑定」。
    pub fn record_ref(&mut self, id: VarId) {
        if let Some(&cur) = self.scope_stack.last() {
            if let Some(set) = self.scope_refs.get_mut(cur) {
                set.insert(id);
            }
        }
    }

    /// 把直接引用集合上滚到全部祖先，得到「该作用域子树里引用到的所有绑定 id」。
    /// 只被引用到的祖先绑定才需要在内层避名；没被引用的名字可以安全复用（形参复用靠它）。
    pub fn subtree_refs(&self) -> Vec<HashSet<VarId>> {
        let mut out = self.scope_refs.clone();
        for scope in (1..out.len()).rev() {
            if let Some(parent) = self.scope_parents.get(scope).copied().flatten() {
                let child = out[scope].clone();
                out[parent].extend(child);
            }
        }
        out
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
                    p.id = r.declare_param(&p.name);
                }
                block.resolve_no_scope_bracket(r);
                r.exit_scope();
            }
            Stmt::LocalFunction { var, params, is_vararg: _, block } => {
                var.id = r.declare_local(&var.name);
                r.enter_scope();
                for p in params {
                    p.id = r.declare_param(&p.name);
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
                    p.id = r.declare_param(&p.name);
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
                    r.record_ref(resolved_id);
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