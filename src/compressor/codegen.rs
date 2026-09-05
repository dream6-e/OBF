use std::collections::HashMap;
use std::cell::RefCell;
use super::token::{Token, TokenType};
use super::ast::{Block, LastStmt, Stmt, Expr, PrefixExpr, Var, Call, LocalVar, TableField, VarId};

thread_local! {
    static RECURSION_DEPTH: RefCell<usize> = RefCell::new(0);
    static STRING_MAPPING: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
}

fn is_reserved_member(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "byte"
            | "char"
            | "find"
            | "format"
            | "gmatch"
            | "gsub"
            | "len"
            | "lower"
            | "match"
            | "rep"
            | "reverse"
            | "sub"
            | "upper"
            | "pack"
            | "unpack"
            | "insert"
            | "concat"
            | "remove"
            | "sort"
            | "move"
            | "abs"
            | "acos"
            | "asin"
            | "atan"
            | "atan2"
            | "ceil"
            | "cos"
            | "cosh"
            | "deg"
            | "exp"
            | "floor"
            | "fmod"
            | "frexp"
            | "ldexp"
            | "log"
            | "log10"
            | "max"
            | "min"
            | "modf"
            | "pow"
            | "rad"
            | "random"
            | "randomseed"
            | "sin"
            | "sinh"
            | "sqrt"
            | "tan"
            | "tanh"
            | "tointeger"
            | "type"
            | "ult"
            | "create"
            | "resume"
            | "running"
            | "status"
            | "wrap"
            | "yield"
            | "isyieldable"
            | "close"
            | "flush"
            | "input"
            | "lines"
            | "open"
            | "output"
            | "popen"
            | "read"
            | "tmpfile"
            | "write"
            | "clock"
            | "date"
            | "difftime"
            | "execute"
            | "exit"
            | "getenv"
            | "setlocale"
            | "time"
            | "tmpname"
            | "getregistry"
            | "getmetatable"
            | "setmetatable"
            | "getuservalue"
            | "setuservalue"
            | "upvalueid"
            | "upvaluejoin"
            | "arshift"
            | "band"
            | "bnot"
            | "bor"
            | "btest"
            | "bxor"
            | "extract"
            | "replace"
            | "lshift"
            | "rshift"
            | "classname"
            | "name"
            | "parent"
            | "value"
            | "cframe"
            | "position"
            | "size"
            | "color"
            | "anchored"
            | "cancollide"
            | "material"
            | "transparency"
            | "reflectance"
            | "brickcolor"
            | "shape"
            | "localplayer"
            | "character"
            | "humanoid"
            | "workspace"
            | "players"
            | "replicatedstorage"
            | "serverscriptservice"
            | "serverstorage"
            | "httpservice"
            | "tweenservice"
            | "runservice"
            | "userinputservice"
            | "contextactionservice"
            | "guiservice"
            | "startergui"
            | "starterpack"
            | "starterplayer"
            | "findfirstchild"
            | "findfirstchildofclass"
            | "findfirstchildwhichisa"
            | "waitforchild"
            | "clone"
            | "destroy"
            | "clearallchildren"
            | "getchildren"
            | "getdescendants"
            | "isa"
            | "getattribute"
            | "setattribute"
            | "getattributes"
            | "connect"
            | "disconnect"
            | "fire"
            | "fireserver"
            | "fireclient"
            | "fireallclients"
            | "invoke"
            | "invokeserver"
            | "getservice"
            | "getplayers"
            | "kick"
            | "loadanimation"
            | "play"
            | "stop"
            | "wait"
            | "once"
            | "task"
            | "delay"
            | "spawn"
            | "defer"
            | "tick"
    )
}

pub struct CodegenContext {
    pub mapping: HashMap<VarId, String>,
    pub shuffled_chars: Vec<char>,
    pub map_string_start_idx: usize,
}

impl CodegenContext {
    pub fn map_string(&self, name: &str) -> String {
        if name.is_empty() {
            return name.to_string();
        }
        if matches!(
            name,
            "self"
                | "_G"
                | "_VERSION"
                | "assert"
                | "collectgarbage"
                | "dofile"
                | "error"
                | "getfenv"
                | "getmetatable"
                | "ipairs"
                | "load"
                | "loadfile"
                | "loadstring"
                | "module"
                | "next"
                | "pairs"
                | "pcall"
                | "print"
                | "rawequal"
                | "rawget"
                | "rawlen"
                | "rawset"
                | "require"
                | "select"
                | "setfenv"
                | "setmetatable"
                | "tonumber"
                | "tostring"
                | "type"
                | "unpack"
                | "xpcall"
                | "coroutine"
                | "debug"
                | "io"
                | "math"
                | "os"
                | "package"
                | "string"
                | "table"
                | "utf8"
                | "bit32"
                | "_ENV"
                | "game"
                | "workspace"
                | "script"
                | "shared"
                | "delay"
                | "spawn"
                | "tick"
                | "warn"
                | "typeof"
                | "task"
                | "Vector3"
                | "Vector2"
                | "CFrame"
                | "Instance"
                | "Color3"
                | "UDim2"
                | "UDim"
                | "continue"
                | "raknet"
        ) {
            return name.to_string();
        }
        let is_valid_id = name.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !is_valid_id {
            return name.to_string();
        }
        STRING_MAPPING.with(|map| {
            let mut map = map.borrow_mut();
            if let Some(mapped) = map.get(name) {
                return mapped.clone();
            }

            let valid_chars: Vec<char> = self.shuffled_chars.iter().copied().filter(|&c| c.is_ascii_alphabetic()).collect();
            let chars = if valid_chars.is_empty() {
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect::<Vec<_>>()
            } else {
                valid_chars
            };
            let base = chars.len();

            let mut index = map.len() + self.map_string_start_idx;
            let mut mapped_name = String::new();
            loop {
                mapped_name.push(chars[index % base]);
                index /= base;
                if index == 0 {
                    break;
                }
            }
            let rev_name: String = mapped_name.chars().rev().collect();
            let final_name = match rev_name.as_str() {
                "and" | "break" | "do" | "else" | "elseif" | "end" | "false" | "for" | "function"
                | "goto" | "if" | "in" | "local" | "nil" | "not" | "or" | "repeat" | "return"
                | "then" | "true" | "until" | "while" => {
                    format!("{}{}", rev_name, chars[0])
                }
                _ => rev_name,
            };

            map.insert(name.to_string(), final_name.clone());
            final_name
        })
    }
}

impl Block {
    pub fn to_tokens(&self, ctx: &CodegenContext, tokens: &mut Vec<Token>) {
        let is_top_level = RECURSION_DEPTH.with(|depth| {
            let mut d = depth.borrow_mut();
            let top = *d == 0;
            *d += 1;
            top
        });

        if is_top_level {
            STRING_MAPPING.with(|map| map.borrow_mut().clear());
        }

        for s in &self.stmts {
            s.to_tokens(ctx, tokens);
        }
        if let Some(l) = &self.last_stmt {
            l.to_tokens(ctx, tokens);
        }

        RECURSION_DEPTH.with(|depth| {
            let mut d = depth.borrow_mut();
            if *d > 0 {
                *d -= 1;
            }
        });
    }
}

impl LastStmt {
    pub fn to_tokens(&self, ctx: &CodegenContext, tokens: &mut Vec<Token>) {
        match self {
            LastStmt::Return(exprs) => {
                tokens.push(Token { text: "return".to_string(), token_type: TokenType::Keyword });
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    e.to_tokens(ctx, tokens);
                }
            }
            LastStmt::Break => {
                tokens.push(Token { text: "break".to_string(), token_type: TokenType::Keyword });
            }
        }
    }
}

impl Stmt {
    pub fn to_tokens(&self, ctx: &CodegenContext, tokens: &mut Vec<Token>) {
        match self {
            Stmt::Assign(vars, exprs) => {
                for (i, v) in vars.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    v.to_tokens(ctx, tokens);
                }
                tokens.push(Token { text: "=".to_string(), token_type: TokenType::Symbol });
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    e.to_tokens(ctx, tokens);
                }
            }
            Stmt::Call(call) => {
                call.to_tokens(ctx, tokens);
            }
            Stmt::Do(block) => {
                tokens.push(Token { text: "do".to_string(), token_type: TokenType::Keyword });
                block.to_tokens(ctx, tokens);
                tokens.push(Token { text: "end".to_string(), token_type: TokenType::Keyword });
            }
            Stmt::While(cond, block) => {
                tokens.push(Token { text: "while".to_string(), token_type: TokenType::Keyword });
                cond.to_tokens(ctx, tokens);
                tokens.push(Token { text: "do".to_string(), token_type: TokenType::Keyword });
                block.to_tokens(ctx, tokens);
                tokens.push(Token { text: "end".to_string(), token_type: TokenType::Keyword });
            }
            Stmt::Repeat(block, cond) => {
                tokens.push(Token { text: "repeat".to_string(), token_type: TokenType::Keyword });
                block.to_tokens(ctx, tokens);
                tokens.push(Token { text: "until".to_string(), token_type: TokenType::Keyword });
                cond.to_tokens(ctx, tokens);
            }
            Stmt::If { cond, then_block, else_ifs, else_block } => {
                tokens.push(Token { text: "if".to_string(), token_type: TokenType::Keyword });
                cond.to_tokens(ctx, tokens);
                tokens.push(Token { text: "then".to_string(), token_type: TokenType::Keyword });
                then_block.to_tokens(ctx, tokens);
                for (c, b) in else_ifs {
                    tokens.push(Token { text: "elseif".to_string(), token_type: TokenType::Keyword });
                    c.to_tokens(ctx, tokens);
                    tokens.push(Token { text: "then".to_string(), token_type: TokenType::Keyword });
                    b.to_tokens(ctx, tokens);
                }
                if let Some(b) = else_block {
                    tokens.push(Token { text: "else".to_string(), token_type: TokenType::Keyword });
                    b.to_tokens(ctx, tokens);
                }
                tokens.push(Token { text: "end".to_string(), token_type: TokenType::Keyword });
            }
            Stmt::For { var, init, limit, step, block } => {
                tokens.push(Token { text: "for".to_string(), token_type: TokenType::Keyword });
                var.to_tokens(ctx, tokens);
                tokens.push(Token { text: "=".to_string(), token_type: TokenType::Symbol });
                init.to_tokens(ctx, tokens);
                tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                limit.to_tokens(ctx, tokens);
                if let Some(s) = step {
                    tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    s.to_tokens(ctx, tokens);
                }
                tokens.push(Token { text: "do".to_string(), token_type: TokenType::Keyword });
                block.to_tokens(ctx, tokens);
                tokens.push(Token { text: "end".to_string(), token_type: TokenType::Keyword });
            }
            Stmt::ForIn { vars, exprs, block } => {
                tokens.push(Token { text: "for".to_string(), token_type: TokenType::Keyword });
                for (i, v) in vars.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    v.to_tokens(ctx, tokens);
                }
                tokens.push(Token { text: "in".to_string(), token_type: TokenType::Keyword });
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    e.to_tokens(ctx, tokens);
                }
                tokens.push(Token { text: "do".to_string(), token_type: TokenType::Keyword });
                block.to_tokens(ctx, tokens);
                tokens.push(Token { text: "end".to_string(), token_type: TokenType::Keyword });
            }
            Stmt::Function { path, method, params, is_vararg, block } => {
                tokens.push(Token { text: "function".to_string(), token_type: TokenType::Keyword });
                for (i, p) in path.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ".".to_string(), token_type: TokenType::Symbol });
                    }
                    let mapped_p = if p.len() > 4 && !is_reserved_member(p) {
                        ctx.map_string(p)
                    } else {
                        p.clone()
                    };
                    tokens.push(Token { text: mapped_p, token_type: TokenType::Identifier });
                }
                if let Some(m) = method {
                    tokens.push(Token { text: ":".to_string(), token_type: TokenType::Symbol });
                    let mapped_m = if m.len() > 4 && !is_reserved_member(m) {
                        ctx.map_string(m)
                    } else {
                        m.clone()
                    };
                    tokens.push(Token { text: mapped_m, token_type: TokenType::Identifier });
                }
                tokens.push(Token { text: "(".to_string(), token_type: TokenType::Symbol });
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    p.to_tokens(ctx, tokens);
                }
                if *is_vararg {
                    if !params.is_empty() {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    tokens.push(Token { text: "...".to_string(), token_type: TokenType::Symbol });
                }
                tokens.push(Token { text: ")".to_string(), token_type: TokenType::Symbol });
                block.to_tokens(ctx, tokens);
                tokens.push(Token { text: "end".to_string(), token_type: TokenType::Keyword });
            }
            Stmt::LocalFunction { var, params, is_vararg, block } => {
                tokens.push(Token { text: "local".to_string(), token_type: TokenType::Keyword });
                tokens.push(Token { text: "function".to_string(), token_type: TokenType::Keyword });
                var.to_tokens(ctx, tokens);
                tokens.push(Token { text: "(".to_string(), token_type: TokenType::Symbol });
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    p.to_tokens(ctx, tokens);
                }
                if *is_vararg {
                    if !params.is_empty() {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    tokens.push(Token { text: "...".to_string(), token_type: TokenType::Symbol });
                }
                tokens.push(Token { text: ")".to_string(), token_type: TokenType::Symbol });
                block.to_tokens(ctx, tokens);
                tokens.push(Token { text: "end".to_string(), token_type: TokenType::Keyword });
            }
            Stmt::LocalAssign(vars, exprs) => {
                tokens.push(Token { text: "local".to_string(), token_type: TokenType::Keyword });
                for (i, v) in vars.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    v.to_tokens(ctx, tokens);
                }
                if !exprs.is_empty() {
                    tokens.push(Token { text: "=".to_string(), token_type: TokenType::Symbol });
                    for (i, e) in exprs.iter().enumerate() {
                        if i > 0 {
                            tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                        }
                        e.to_tokens(ctx, tokens);
                    }
                }
            }
        }
    }
}

impl LocalVar {
    pub fn to_tokens(&self, ctx: &CodegenContext, tokens: &mut Vec<Token>) {
        let mut mapped_name = if self.id != VarId(0) {
            ctx.mapping.get(&self.id).cloned().unwrap_or_else(|| ctx.map_string(&self.name))
        } else {
            ctx.map_string(&self.name)
        };

        if mapped_name == "_" {
            mapped_name = if self.id != VarId(0) {
                ctx.map_string(&format!("_UNUSED_VAR_{}", self.id.0))
            } else {
                ctx.map_string("_UNUSED_GLOBAL_")
            };
        }

        tokens.push(Token { text: mapped_name, token_type: TokenType::Identifier });
    }
}

impl Expr {
    pub fn to_tokens(&self, ctx: &CodegenContext, tokens: &mut Vec<Token>) {
        match self {
            Expr::Nil => {
                tokens.push(Token { text: "nil".to_string(), token_type: TokenType::Keyword });
            }
            Expr::Boolean(b) => {
                let text = if *b { "true" } else { "false" };
                tokens.push(Token { text: text.to_string(), token_type: TokenType::Keyword });
            }
            Expr::Number(n) => {
                tokens.push(Token { text: n.clone(), token_type: TokenType::Number });
            }
            Expr::String(s) => {
                tokens.push(Token { text: s.clone(), token_type: TokenType::StringLiteral });
            }
            Expr::Vararg => {
                tokens.push(Token { text: "...".to_string(), token_type: TokenType::Symbol });
            }
            Expr::FuncDef(params, is_vararg, block) => {
                tokens.push(Token { text: "function".to_string(), token_type: TokenType::Keyword });
                tokens.push(Token { text: "(".to_string(), token_type: TokenType::Symbol });
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    p.to_tokens(ctx, tokens);
                }
                if *is_vararg {
                    if !params.is_empty() {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    tokens.push(Token { text: "...".to_string(), token_type: TokenType::Symbol });
                }
                tokens.push(Token { text: ")".to_string(), token_type: TokenType::Symbol });
                block.to_tokens(ctx, tokens);
                tokens.push(Token { text: "end".to_string(), token_type: TokenType::Keyword });
            }
            Expr::Table(fields) => {
                tokens.push(Token { text: "{".to_string(), token_type: TokenType::Symbol });
                for (i, f) in fields.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    match f {
                        TableField::List(e) => {
                            e.to_tokens(ctx, tokens);
                        }
                        TableField::Rec(k, v) => {
                            match k {
                                Expr::String(s) if !s.contains('"') && !s.contains('\'') && s.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') => {
                                    let mapped_s = if s.len() > 4 && !is_reserved_member(s) {
                                        ctx.map_string(s)
                                    } else {
                                        s.clone()
                                    };
                                    tokens.push(Token { text: mapped_s, token_type: TokenType::Identifier });
                                }
                                _ => {
                                    tokens.push(Token { text: "[".to_string(), token_type: TokenType::Symbol });
                                    k.to_tokens(ctx, tokens);
                                    tokens.push(Token { text: "]".to_string(), token_type: TokenType::Symbol });
                                }
                            }
                            tokens.push(Token { text: "=".to_string(), token_type: TokenType::Symbol });
                            v.to_tokens(ctx, tokens);
                        }
                    }
                }
                tokens.push(Token { text: "}".to_string(), token_type: TokenType::Symbol });
            }
            Expr::BinOp(op, lhs, rhs) => {
                lhs.to_tokens(ctx, tokens);
                let t_type = if op == "and" || op == "or" { TokenType::Keyword } else { TokenType::Symbol };
                tokens.push(Token { text: op.clone(), token_type: t_type });
                rhs.to_tokens(ctx, tokens);
            }
            Expr::UnOp(op, e) => {
                let t_type = if op == "not" { TokenType::Keyword } else { TokenType::Symbol };
                tokens.push(Token { text: op.clone(), token_type: t_type });
                e.to_tokens(ctx, tokens);
            }
            Expr::Prefix(p) => {
                p.to_tokens(ctx, tokens);
            }
        }
    }
}

impl PrefixExpr {
    pub fn to_tokens(&self, ctx: &CodegenContext, tokens: &mut Vec<Token>) {
        match self {
            PrefixExpr::Var(v) => v.to_tokens(ctx, tokens),
            PrefixExpr::Call(c) => c.to_tokens(ctx, tokens),
            PrefixExpr::Paren(e) => {
                tokens.push(Token { text: "(".to_string(), token_type: TokenType::Symbol });
                e.to_tokens(ctx, tokens);
                tokens.push(Token { text: ")".to_string(), token_type: TokenType::Symbol });
            }
        }
    }
}

impl Var {
    pub fn to_tokens(&self, ctx: &CodegenContext, tokens: &mut Vec<Token>) {
        match self {
            Var::Name(name, id) => {
                let mut mapped_name = if *id != VarId(0) {
                    ctx.mapping.get(id).cloned().unwrap_or_else(|| ctx.map_string(name))
                } else {
                    ctx.map_string(name)
                };

                if mapped_name == "_" {
                    mapped_name = if *id != VarId(0) {
                        ctx.map_string(&format!("_UNUSED_VAR_{}", id.0))
                    } else {
                        ctx.map_string("_UNUSED_GLOBAL_")
                    };
                }

                tokens.push(Token { text: mapped_name, token_type: TokenType::Identifier });
            }
            Var::Index(prefix, expr) => {
                prefix.to_tokens(ctx, tokens);
                tokens.push(Token { text: "[".to_string(), token_type: TokenType::Symbol });
                expr.to_tokens(ctx, tokens);
                tokens.push(Token { text: "]".to_string(), token_type: TokenType::Symbol });
            }
            Var::Member(prefix, member) => {
                prefix.to_tokens(ctx, tokens);
                tokens.push(Token { text: ".".to_string(), token_type: TokenType::Symbol });
                let mapped_member = if member.len() > 4 && !is_reserved_member(member) {
                    ctx.map_string(member)
                } else {
                    member.clone()
                };
                tokens.push(Token { text: mapped_member, token_type: TokenType::Identifier });
            }
        }
    }
}

impl Call {
    pub fn to_tokens(&self, ctx: &CodegenContext, tokens: &mut Vec<Token>) {
        match self {
            Call::Normal(prefix, args) => {
                prefix.to_tokens(ctx, tokens);
                tokens.push(Token { text: "(".to_string(), token_type: TokenType::Symbol });
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    a.to_tokens(ctx, tokens);
                }
                tokens.push(Token { text: ")".to_string(), token_type: TokenType::Symbol });
            }
            Call::Method(prefix, method, args) => {
                prefix.to_tokens(ctx, tokens);
                tokens.push(Token { text: ":".to_string(), token_type: TokenType::Symbol });
                let mapped_method = if method.len() > 4 && !is_reserved_member(method) {
                    ctx.map_string(method)
                } else {
                    method.clone()
                };
                tokens.push(Token { text: mapped_method, token_type: TokenType::Identifier });
                tokens.push(Token { text: "(".to_string(), token_type: TokenType::Symbol });
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        tokens.push(Token { text: ",".to_string(), token_type: TokenType::Symbol });
                    }
                    a.to_tokens(ctx, tokens);
                }
                tokens.push(Token { text: ")".to_string(), token_type: TokenType::Symbol });
            }
        }
    }
}