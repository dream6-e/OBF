//! Lexical value binding analysis for Lua 5.1 and Luau.
//!
//! Binding IDs identify declarations, not spellings. Type names, field names
//! and method names are not value bindings. Luau `typeof` expressions and
//! qualified type prefixes do refer to values. Type-function bodies are
//! inspected conservatively but never renamed by this first-stage pass.

use crate::ast::*;
use crate::random::Prng;
use crate::{Diagnostic, Target};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ITEMS: usize = 1_000_000;
const MAX_WORK: usize = 8_000_000;

pub type ScopeId = usize;
pub type BindingId = usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeKind {
    Chunk,
    Block,
    Function,
    TypeFunction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingKind {
    Local,
    LocalFunction,
    Parameter,
    NumericFor,
    GenericFor,
    ImplicitSelf,
    ImplicitArg,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreserveReason {
    Exported,
    Implicit,
    Reserved,
    TypeFunction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scope {
    pub parent: Option<ScopeId>,
    /// The enclosing function scope, or the chunk scope for top-level code.
    pub function: ScopeId,
    pub kind: ScopeKind,
    pub span: Span,
    pub bindings: Vec<BindingId>,
    /// Includes transitive captures needed by nested functions.
    pub upvalues: BTreeSet<BindingId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalBinding {
    pub name: String,
    pub declaration: Option<Span>,
    pub kind: BindingKind,
    pub scope: ScopeId,
    pub references: usize,
    pub captured: bool,
    pub preserve: Option<PreserveReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reference {
    pub name: String,
    pub span: Span,
    pub scope: ScopeId,
    /// `None` denotes a global value reference, never a field/type name.
    pub binding: Option<BindingId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Analysis {
    pub scopes: Vec<Scope>,
    pub bindings: Vec<LocalBinding>,
    pub references: Vec<Reference>,
    pub globals: BTreeSet<String>,
    /// Known reflection/environment access makes automatic renaming unsafe.
    /// A nonempty set causes the minifier to retain all local spellings.
    pub rename_barriers: BTreeSet<String>,
    // Globals and type names, not spellings of locals being replaced.
    reserved: BTreeSet<String>,
    barrier_locations: Vec<Span>,
}

/// Parse source and resolve its lexical value bindings with bounded work.
pub fn analyze(source: &str, target: Target) -> Result<Analysis, Diagnostic> {
    let chunk = crate::parse(source, target)?;
    analyze_chunk(&chunk)
}

pub(crate) fn analyze_chunk(chunk: &Chunk) -> Result<Analysis, Diagnostic> {
    let mut walker = Walker {
        target: chunk.target,
        result: Analysis {
            scopes: vec![Scope {
                parent: None,
                function: 0,
                kind: ScopeKind::Chunk,
                span: chunk.span,
                bindings: Vec::new(),
                upvalues: BTreeSet::new(),
            }],
            bindings: Vec::new(),
            references: Vec::new(),
            globals: BTreeSet::new(),
            rename_barriers: BTreeSet::new(),
            reserved: BTreeSet::new(),
            barrier_locations: Vec::new(),
        },
        visible: BTreeMap::new(),
        current: 0,
        opaque: 0,
        tasks: vec![Task::Block(&chunk.block)],
    };
    // Use a work stack: long left-associated expressions must not translate
    // into an unbounded native recursion in a second frontend pass.
    let mut work = 0usize;
    while let Some(task) = walker.tasks.pop() {
        work = work
            .checked_add(1)
            .ok_or_else(|| Diagnostic::new("scope analysis work count overflow"))?;
        if work > MAX_WORK || walker.tasks.len() > MAX_WORK {
            return Err(Diagnostic::new("scope analysis exceeds safety limit"));
        }
        walker.visit(task)?;
    }
    Ok(walker.result)
}

#[derive(Clone, Copy)]
struct FunctionVisit<'a> {
    body: &'a FunctionBody,
    method: bool,
    local: Option<(&'a Name, bool)>,
    type_function: bool,
}

enum Task<'a> {
    Block(&'a Block),
    ScopedBlock(&'a Block),
    Statement(&'a Statement),
    Expression(&'a Expression),
    Type(&'a TypeExpression),
    Function(FunctionVisit<'a>),
    Declare(&'a Name, BindingKind, bool),
    Implicit(&'static str, BindingKind),
    Enter(ScopeKind, Span),
    Leave,
    EndOpaque,
}

struct Walker<'a> {
    target: Target,
    result: Analysis,
    visible: BTreeMap<String, Vec<BindingId>>,
    current: ScopeId,
    opaque: usize,
    tasks: Vec<Task<'a>>,
}

impl<'a> Walker<'a> {
    fn visit(&mut self, task: Task<'a>) -> Result<(), Diagnostic> {
        match task {
            Task::Block(block) => {
                self.tasks
                    .extend(block.statements.iter().rev().map(Task::Statement));
            }
            Task::ScopedBlock(block) => {
                self.enter(ScopeKind::Block, block.span)?;
                self.tasks.push(Task::Leave);
                self.tasks.push(Task::Block(block));
            }
            Task::Statement(statement) => self.statement(statement)?,
            Task::Expression(expression) => self.expression(expression)?,
            Task::Type(value) => self.type_expression(value)?,
            Task::Function(function) => self.function(function),
            Task::Declare(name, kind, exported) => {
                self.declare(&name.value, Some(name.span), kind, exported)?;
            }
            Task::Implicit(name, kind) => self.declare(name, None, kind, false)?,
            Task::Enter(kind, span) => self.enter(kind, span)?,
            Task::Leave => self.leave()?,
            Task::EndOpaque => {
                self.opaque = self
                    .opaque
                    .checked_sub(1)
                    .ok_or_else(|| Diagnostic::new("unbalanced type-function scope"))?;
            }
        }
        Ok(())
    }

    fn statement(&mut self, statement: &'a Statement) -> Result<(), Diagnostic> {
        match &statement.kind {
            StatementKind::Empty | StatementKind::Break | StatementKind::Continue => {}
            StatementKind::Assignment { targets, values } => {
                self.expressions(values);
                self.expressions(targets);
            }
            StatementKind::CompoundAssignment { target, value, .. } => {
                self.tasks.push(Task::Expression(value));
                self.tasks.push(Task::Expression(target));
            }
            StatementKind::Call(value) => self.tasks.push(Task::Expression(value)),
            StatementKind::Local {
                bindings,
                values,
                exported,
                ..
            } => {
                // All annotations and initializers see the OLD environment,
                // including closures in `local f = function() return f end`.
                self.declarations(bindings, BindingKind::Local, *exported);
                self.expressions(values);
                self.annotations(bindings);
            }
            StatementKind::LocalFunction {
                name,
                body,
                exported,
                ..
            } => self.tasks.push(Task::Function(FunctionVisit {
                body,
                method: false,
                local: Some((name, *exported)),
                type_function: false,
            })),
            StatementKind::Function { name, body } => {
                if let Some(root) = name.path.first() {
                    self.reference(root)?;
                }
                for field in name.path.iter().skip(1).chain(name.method.iter()) {
                    self.inspect_name(&field.value, field.span);
                }
                self.tasks.push(Task::Function(FunctionVisit {
                    body,
                    method: name.method.is_some(),
                    local: None,
                    type_function: false,
                }));
            }
            StatementKind::Do(block) => self.tasks.push(Task::ScopedBlock(block)),
            StatementKind::While { condition, body } => {
                self.tasks.push(Task::ScopedBlock(body));
                self.tasks.push(Task::Expression(condition));
            }
            StatementKind::Repeat { body, condition } => {
                self.tasks.push(Task::Leave);
                self.tasks.push(Task::Expression(condition));
                self.tasks.push(Task::Block(body));
                self.tasks
                    .push(Task::Enter(ScopeKind::Block, statement.span));
            }
            StatementKind::If {
                branches,
                else_block,
            } => {
                if let Some(block) = else_block {
                    self.tasks.push(Task::ScopedBlock(block));
                }
                for branch in branches.iter().rev() {
                    self.tasks.push(Task::ScopedBlock(&branch.body));
                    self.tasks.push(Task::Expression(&branch.condition));
                }
            }
            StatementKind::NumericFor {
                binding,
                initial,
                limit,
                step,
                body,
            } => {
                self.tasks.push(Task::Leave);
                self.tasks.push(Task::ScopedBlock(body));
                self.tasks
                    .push(Task::Declare(&binding.name, BindingKind::NumericFor, false));
                self.tasks
                    .push(Task::Enter(ScopeKind::Block, statement.span));
                if let Some(step) = step {
                    self.tasks.push(Task::Expression(step));
                }
                self.tasks.push(Task::Expression(limit));
                self.tasks.push(Task::Expression(initial));
                self.optional_type(&binding.annotation);
            }
            StatementKind::GenericFor {
                bindings,
                values,
                body,
            } => {
                self.tasks.push(Task::Leave);
                self.tasks.push(Task::ScopedBlock(body));
                self.declarations(bindings, BindingKind::GenericFor, false);
                self.tasks
                    .push(Task::Enter(ScopeKind::Block, statement.span));
                self.expressions(values);
                self.annotations(bindings);
            }
            StatementKind::Return(values) => self.expressions(values),
            StatementKind::TypeAlias {
                name,
                generics,
                value,
                ..
            } => {
                self.reserve(&name.value);
                self.tasks.push(Task::Type(value));
                self.generics(generics);
            }
            StatementKind::TypeFunction { name, body, .. } => {
                self.reserve(&name.value);
                self.tasks.push(Task::Function(FunctionVisit {
                    body,
                    method: false,
                    local: None,
                    type_function: true,
                }));
            }
        }
        Ok(())
    }

    fn function(&mut self, visit: FunctionVisit<'a>) {
        let body = visit.body;
        if visit.type_function {
            // Preserve the type-function body AND any outside binding it
            // mentions. Do not pretend to resolve its separate type runtime.
            self.opaque += 1;
            self.tasks.push(Task::EndOpaque);
        }
        self.tasks.push(Task::Leave);
        self.tasks.push(Task::ScopedBlock(&body.body));
        if !self.target.is_luau() && body.has_vararg {
            // The pinned 5.1.5 runtime enables LUA_COMPAT_VARARG. Its implicit
            // `arg` local is introduced AFTER the explicit parameters.
            self.tasks
                .push(Task::Implicit("arg", BindingKind::ImplicitArg));
        }
        self.declarations(&body.parameters, BindingKind::Parameter, false);
        if visit.method {
            self.tasks
                .push(Task::Implicit("self", BindingKind::ImplicitSelf));
        }
        self.tasks.push(Task::Enter(
            if visit.type_function {
                ScopeKind::TypeFunction
            } else {
                ScopeKind::Function
            },
            body.span,
        ));
        if let Some((name, exported)) = visit.local {
            self.tasks
                .push(Task::Declare(name, BindingKind::LocalFunction, exported));
        }
        // Luau parses the entire signature in the enclosing value scope:
        // neither the new parameters nor a recursive local function is in
        // scope yet, even inside return-type `typeof(...)` expressions.
        self.optional_type(&body.return_type);
        self.optional_type(&body.vararg);
        self.annotations(&body.parameters);
        self.generics(&body.generics);
        for attribute in body.attributes.iter().rev() {
            self.expressions(&attribute.arguments);
        }
    }

    fn expression(&mut self, expression: &'a Expression) -> Result<(), Diagnostic> {
        match &expression.kind {
            ExpressionKind::Name(name) => self.reference(name)?,
            ExpressionKind::Nil
            | ExpressionKind::Boolean(_)
            | ExpressionKind::Number(_)
            | ExpressionKind::String(_)
            | ExpressionKind::Vararg => {}
            ExpressionKind::InterpolatedString { expressions, .. } => {
                self.expressions(expressions);
            }
            ExpressionKind::Function(body) => self.tasks.push(Task::Function(FunctionVisit {
                body,
                method: false,
                local: None,
                type_function: false,
            })),
            ExpressionKind::Table(fields) => {
                for field in fields.iter().rev() {
                    match field {
                        TableField::List(value) => self.tasks.push(Task::Expression(value)),
                        TableField::Record { value, .. } => {
                            self.tasks.push(Task::Expression(value));
                        }
                        TableField::Computed { key, value, .. } => {
                            self.tasks.push(Task::Expression(value));
                            self.tasks.push(Task::Expression(key));
                        }
                    }
                }
            }
            ExpressionKind::IfExpression {
                branches,
                else_expression,
            } => {
                self.tasks.push(Task::Expression(else_expression));
                for branch in branches.iter().rev() {
                    self.tasks.push(Task::Expression(&branch.value));
                    self.tasks.push(Task::Expression(&branch.condition));
                }
            }
            ExpressionKind::Unary { expression, .. } | ExpressionKind::Group(expression) => {
                self.tasks.push(Task::Expression(expression));
            }
            ExpressionKind::Binary { left, right, .. } => {
                self.tasks.push(Task::Expression(right));
                self.tasks.push(Task::Expression(left));
            }
            ExpressionKind::TypeAssertion {
                expression,
                asserted,
            } => {
                self.tasks.push(Task::Type(asserted));
                self.tasks.push(Task::Expression(expression));
            }
            ExpressionKind::TypeInstantiation {
                expression,
                arguments,
            } => {
                self.type_arguments(arguments);
                self.tasks.push(Task::Expression(expression));
            }
            ExpressionKind::Field { table, field } => {
                self.inspect_name(&field.value, field.span);
                self.tasks.push(Task::Expression(table));
            }
            ExpressionKind::Index { table, index } => {
                if let Some(name) = static_string(index, self.target) {
                    self.inspect_name(&name, index.span);
                }
                self.tasks.push(Task::Expression(index));
                self.tasks.push(Task::Expression(table));
            }
            ExpressionKind::Call {
                function,
                method,
                arguments,
            } => {
                if let Some(method) = method {
                    self.inspect_name(&method.value, method.span);
                }
                self.expressions(arguments);
                self.tasks.push(Task::Expression(function));
            }
        }
        Ok(())
    }

    fn type_expression(&mut self, value: &'a TypeExpression) -> Result<(), Diagnostic> {
        match &value.kind {
            TypeKind::Nil | TypeKind::BooleanSingleton(_) | TypeKind::StringSingleton(_) => {}
            TypeKind::Named { path, arguments } => {
                for name in path {
                    self.reserve(&name.value);
                }
                if path.len() > 1 {
                    if let Some(prefix) = path.first() {
                        self.reference(prefix)?;
                    }
                }
                self.type_arguments(arguments);
            }
            TypeKind::Typeof(expression) => self.tasks.push(Task::Expression(expression)),
            TypeKind::Table(fields) => {
                for field in fields.iter().rev() {
                    match field {
                        TypeField::Property { value, .. }
                        | TypeField::StringProperty { value, .. }
                        | TypeField::Array { value, .. } => self.tasks.push(Task::Type(value)),
                        TypeField::Indexer { key, value, .. } => {
                            self.tasks.push(Task::Type(value));
                            self.tasks.push(Task::Type(key));
                        }
                    }
                }
            }
            TypeKind::Function {
                generics,
                parameters,
                returns,
            } => {
                self.tasks.push(Task::Type(returns));
                for parameter in parameters.iter().rev() {
                    // Type signature labels do not introduce value bindings.
                    self.tasks.push(Task::Type(&parameter.value));
                }
                self.generics(generics);
            }
            TypeKind::Group(value) | TypeKind::Optional(value) | TypeKind::Variadic(value) => {
                self.tasks.push(Task::Type(value));
            }
            TypeKind::Tuple(values) | TypeKind::Union(values) | TypeKind::Intersection(values) => {
                self.tasks.extend(values.iter().rev().map(Task::Type));
            }
            TypeKind::GenericPack(name) => self.reserve(&name.value),
        }
        Ok(())
    }

    fn expressions(&mut self, values: &'a [Expression]) {
        self.tasks.extend(values.iter().rev().map(Task::Expression));
    }

    fn declarations(&mut self, bindings: &'a [Binding], kind: BindingKind, exported: bool) {
        self.tasks.extend(
            bindings
                .iter()
                .rev()
                .map(|binding| Task::Declare(&binding.name, kind, exported)),
        );
    }

    fn annotations(&mut self, bindings: &'a [Binding]) {
        for binding in bindings.iter().rev() {
            self.optional_type(&binding.annotation);
        }
    }

    fn optional_type(&mut self, value: &'a Option<TypeExpression>) {
        if let Some(value) = value {
            self.tasks.push(Task::Type(value));
        }
    }

    fn generics(&mut self, parameters: &'a [GenericParameter]) {
        for parameter in parameters.iter().rev() {
            self.reserve(&parameter.name.value);
            self.optional_type(&parameter.default);
        }
    }

    fn type_arguments(&mut self, arguments: &'a [TypeArgument]) {
        for argument in arguments.iter().rev() {
            let (TypeArgument::Type(value) | TypeArgument::Pack(value)) = argument;
            self.tasks.push(Task::Type(value));
        }
    }

    fn enter(&mut self, kind: ScopeKind, span: Span) -> Result<(), Diagnostic> {
        if self.result.scopes.len() >= MAX_ITEMS {
            return Err(Diagnostic::new("scope count exceeds safety limit"));
        }
        let id = self.result.scopes.len();
        let function = if matches!(kind, ScopeKind::Function | ScopeKind::TypeFunction) {
            id
        } else {
            self.result.scopes[self.current].function
        };
        self.result.scopes.push(Scope {
            parent: Some(self.current),
            function,
            kind,
            span,
            bindings: Vec::new(),
            upvalues: BTreeSet::new(),
        });
        self.current = id;
        Ok(())
    }

    fn leave(&mut self) -> Result<(), Diagnostic> {
        let scope = &self.result.scopes[self.current];
        for &binding in scope.bindings.iter().rev() {
            let name = &self.result.bindings[binding].name;
            let stack = self
                .visible
                .get_mut(name)
                .ok_or_else(|| Diagnostic::new("missing lexical binding stack"))?;
            if stack.pop() != Some(binding) {
                return Err(Diagnostic::new("unbalanced lexical binding stack"));
            }
            if stack.is_empty() {
                self.visible.remove(name);
            }
        }
        self.current = scope
            .parent
            .ok_or_else(|| Diagnostic::new("cannot leave chunk scope"))?;
        Ok(())
    }

    fn declare(
        &mut self,
        name: &str,
        declaration: Option<Span>,
        kind: BindingKind,
        exported: bool,
    ) -> Result<(), Diagnostic> {
        if self.result.bindings.len() >= MAX_ITEMS {
            return Err(Diagnostic::new("binding count exceeds safety limit"));
        }
        if let Some(span) = declaration {
            self.inspect_name(name, span);
        }
        let preserve = if declaration.is_none() {
            Some(PreserveReason::Implicit)
        } else if exported {
            Some(PreserveReason::Exported)
        } else if self.opaque != 0 {
            Some(PreserveReason::TypeFunction)
        } else if self.target.is_reserved_name(name) {
            Some(PreserveReason::Reserved)
        } else {
            None
        };
        let id = self.result.bindings.len();
        self.result.bindings.push(LocalBinding {
            name: name.to_owned(),
            declaration,
            kind,
            scope: self.current,
            references: 0,
            captured: false,
            preserve,
        });
        self.result.scopes[self.current].bindings.push(id);
        self.visible.entry(name.to_owned()).or_default().push(id);
        Ok(())
    }

    fn reference(&mut self, name: &Name) -> Result<(), Diagnostic> {
        if self.result.references.len() >= MAX_ITEMS {
            return Err(Diagnostic::new("reference count exceeds safety limit"));
        }
        self.inspect_name(&name.value, name.span);
        let binding = self
            .visible
            .get(&name.value)
            .and_then(|stack| stack.last())
            .copied();
        if let Some(id) = binding {
            let local = &mut self.result.bindings[id];
            local.references = local
                .references
                .checked_add(1)
                .ok_or_else(|| Diagnostic::new("binding reference count overflow"))?;
            if self.opaque != 0 && local.preserve.is_none() {
                local.preserve = Some(PreserveReason::TypeFunction);
            }
            let owner = self.result.scopes[local.scope].function;
            let mut function = self.result.scopes[self.current].function;
            local.captured |= function != owner;
            while function != owner {
                self.result.scopes[function].upvalues.insert(id);
                let parent = self.result.scopes[function]
                    .parent
                    .ok_or_else(|| Diagnostic::new("invalid upvalue scope ancestry"))?;
                function = self.result.scopes[parent].function;
            }
        } else {
            self.result.globals.insert(name.value.clone());
            self.reserve(&name.value);
        }
        self.result.references.push(Reference {
            name: name.value.clone(),
            span: name.span,
            scope: self.current,
            binding,
        });
        Ok(())
    }

    fn reserve(&mut self, name: &str) {
        self.result.reserved.insert(name.to_owned());
    }

    fn inspect_name(&mut self, name: &str, span: Span) {
        if is_rename_barrier(name) {
            self.result.rename_barriers.insert(name.to_owned());
            self.result.barrier_locations.push(span);
        }
    }
}

fn is_rename_barrier(name: &str) -> bool {
    matches!(
        name,
        "debug"
            | "_G"
            | "_ENV"
            | "getfenv"
            | "setfenv"
            | "getgenv"
            | "getrenv"
            | "getreg"
            | "getregistry"
            | "getgc"
            | "load"
            | "loadstring"
            | "loadfile"
            | "dofile"
            | "getlocal"
            | "setlocal"
            | "getupvalue"
            | "getupvalues"
            | "setupvalue"
            | "getstack"
            | "setstack"
            | "getinfo"
            | "getproto"
            | "getprotos"
            | "getconstants"
            | "setconstant"
            | "sethook"
            | "dump"
    )
}

// Recognize only literal strings/groups/concatenations used as field keys.
// This is hazard detection, NOT a constant-folding transformation. Arbitrary
// dynamically supplied host reflection still requires `--no-rename`.
fn static_string(expression: &Expression, target: Target) -> Option<String> {
    let mut tasks = vec![expression];
    let mut bytes = Vec::new();
    while let Some(expression) = tasks.pop() {
        match &expression.kind {
            ExpressionKind::String(raw) => {
                bytes.extend(crate::minify::literal_bytes(raw, target).ok()?);
            }
            ExpressionKind::InterpolatedString {
                strings,
                expressions,
            } if expressions.is_empty() => {
                let segment = strings.first()?;
                bytes.extend(
                    crate::minify::literal_bytes(&format!("`{}`", segment.value), target).ok()?,
                );
            }
            ExpressionKind::Group(inner) => tasks.push(inner),
            ExpressionKind::Binary {
                operator: BinaryOperator::Concat,
                left,
                right,
            } => {
                tasks.push(right);
                tasks.push(left);
            }
            _ => return None,
        }
        if bytes.len() > 64 {
            return None;
        }
    }
    String::from_utf8(bytes).ok()
}

pub(crate) struct RenamePlan {
    names: Vec<Option<String>>,
}

impl Analysis {
    pub(crate) fn rename_plan(&self, target: Target, seed: u64) -> Result<RenamePlan, Diagnostic> {
        if !self.rename_barriers.is_empty() {
            return Ok(RenamePlan {
                names: vec![None; self.bindings.len()],
            });
        }
        self.random_short_plan(target, seed)
    }

    /// Only for the crate-owned, fully assembled VM template. Do not expose
    /// this as a user-source "force rename" switch. The sole permitted
    /// environment operation must have the exact audited AST shape, and ALL
    /// barrier occurrences must be its three unbound value references.
    pub(crate) fn generated_vm_plan(
        &self,
        chunk: &Chunk,
        seed: u64,
    ) -> Result<RenamePlan, Diagnostic> {
        let mut captures = chunk.block.statements.iter().filter_map(|statement| {
            let StatementKind::Local {
                bindings,
                values,
                exported: false,
                is_const: false,
            } = &statement.kind
            else {
                return None;
            };
            if bindings.len() == 1
                && bindings[0].name.value == "G"
                && bindings[0].annotation.is_none()
                && values.len() == 1
                && is_vm_environment(&values[0])
            {
                Some(values[0].span)
            } else {
                None
            }
        });
        let capture = captures.next().ok_or_else(|| {
            Diagnostic::new("generated VM is missing its audited environment capture")
        })?;
        if captures.next().is_some()
            || self.barrier_locations.len() != 3
            || self
                .barrier_locations
                .iter()
                .any(|span| span.start < capture.start || span.end > capture.end)
            || self
                .rename_barriers
                .iter()
                .any(|name| !matches!(name.as_str(), "getfenv" | "_G"))
            || self.references.iter().any(|reference| {
                matches!(reference.name.as_str(), "getfenv" | "_G") && reference.binding.is_some()
            })
        {
            return Err(Diagnostic::new(
                "generated VM contains an unaudited reflection/environment access",
            ));
        }
        if self
            .bindings
            .iter()
            .any(|binding| binding.declaration.is_some() && binding.preserve.is_some())
        {
            return Err(Diagnostic::new("generated VM contains a protected explicit binding; refusing partial random renaming"));
        }
        self.random_short_plan(chunk.target, seed)
    }

    fn random_short_plan(&self, target: Target, seed: u64) -> Result<RenamePlan, Diagnostic> {
        let mut names: Vec<Option<String>> = vec![None; self.bindings.len()];
        let mut reserved = self.reserved.clone();
        // Reuse old spellings ONLY for locals that will ALL be simultaneously
        // replaced. Retained locals, globals and types remain unavailable.
        reserved.extend(
            self.bindings
                .iter()
                .filter(|binding| binding.preserve.is_some())
                .map(|binding| binding.name.clone()),
        );
        let mut order: Vec<_> = (0..self.bindings.len())
            .filter(|&id| self.bindings[id].preserve.is_none())
            .collect();
        order.sort_by_key(|&id| {
            let binding = &self.bindings[id];
            (
                std::cmp::Reverse(binding.references),
                binding.declaration.map_or(usize::MAX, |span| span.start),
                id,
            )
        });

        let mut single = Vec::new();
        let mut double = Vec::new();
        for first in b'a'..=b'z' {
            single.push(char::from(first).to_string());
            for second in b'a'..=b'z' {
                double.push(format!("{}{}", char::from(first), char::from(second)));
            }
        }
        for pool in [&mut single, &mut double] {
            pool.retain(|name| !reserved.contains(name) && !target.is_reserved_name(name));
        }
        // Independent stream: dispatcher/template choices cannot consume the
        // random state used to allocate final variable names.
        let domain = if target.is_luau() {
            0x6e61_6d65_0000_0735
        } else {
            0x6e61_6d65_0000_0051
        };
        let mut random = Prng::new(seed ^ domain);
        random.shuffle(&mut single);
        random.shuffle(&mut double);
        single.extend(double);
        let mut available = single;
        if order.len() > available.len() {
            return Err(Diagnostic::new(format!(
                "1-2 letter variable name pool exhausted: {} bindings require distinct names, only {} are safe; use --no-rename or split the source",
                order.len(), available.len()
            )));
        }
        let mut assigned: Vec<BindingId> = Vec::new();
        for id in order {
            let original = &self.bindings[id].name;
            if let Some(index) = available.iter().position(|name| name != original) {
                // At most 702 candidates. Ordered removal keeps one-letter
                // priority for frequent bindings, while each pool is shuffled.
                names[id] = Some(available.remove(index));
            } else {
                // A greedy allocation can leave the last binding its own old
                // name. Repair with a safe two-way swap instead of spuriously
                // reporting exhaustion when a full derangement exists.
                let remaining = available
                    .pop()
                    .ok_or_else(|| Diagnostic::new("1-2 letter variable name pool exhausted"))?;
                let previous = assigned
                    .iter()
                    .rev()
                    .copied()
                    .find(|&previous| self.bindings[previous].name != remaining)
                    .ok_or_else(|| {
                        Diagnostic::new(
                            "1-2 letter variable name pool cannot rename every binding without retaining an original name",
                        )
                    })?;
                names[id] = names[previous].take();
                names[previous] = Some(remaining);
            }
            assigned.push(id);
        }
        Ok(RenamePlan { names })
    }

    pub(crate) fn verify_renamed(
        &self,
        other: &Analysis,
        plan: &RenamePlan,
    ) -> Result<(), Diagnostic> {
        let same_scopes = self.scopes.len() == other.scopes.len()
            && self.scopes.iter().zip(&other.scopes).all(|(a, b)| {
                a.parent == b.parent
                    && a.function == b.function
                    && a.kind == b.kind
                    && a.bindings == b.bindings
                    && a.upvalues == b.upvalues
            });
        let same_bindings = self.bindings.len() == other.bindings.len()
            && self
                .bindings
                .iter()
                .zip(&other.bindings)
                .enumerate()
                .all(|(id, (a, b))| {
                    plan.names[id].as_deref().unwrap_or(&a.name) == b.name
                        && a.kind == b.kind
                        && a.scope == b.scope
                        && a.references == b.references
                        && a.captured == b.captured
                });
        let same_references = self.references.len() == other.references.len()
            && self.references.iter().zip(&other.references).all(|(a, b)| {
                let expected = a
                    .binding
                    .and_then(|id| plan.names[id].as_deref())
                    .unwrap_or(&a.name);
                a.binding == b.binding && a.scope == b.scope && expected == b.name
            });
        if same_scopes && same_bindings && same_references && self.globals == other.globals {
            Ok(())
        } else {
            Err(Diagnostic::new(
                "safe minification changed lexical bindings; refusing output",
            ))
        }
    }
}

impl RenamePlan {
    pub(crate) fn apply(
        &self,
        source: &str,
        analysis: &Analysis,
    ) -> Result<Option<String>, Diagnostic> {
        let mut edits = Vec::new();
        for (id, name) in self.names.iter().enumerate() {
            if name.is_some() {
                if let Some(span) = analysis.bindings[id].declaration {
                    edits.push((span, id));
                }
            }
        }
        for reference in &analysis.references {
            if let Some(id) = reference.binding {
                if self.names[id].is_some() {
                    edits.push((reference.span, id));
                }
            }
        }
        if edits.is_empty() {
            return Ok(None);
        }
        edits.sort_by_key(|(span, _)| (span.start, span.end));
        let mut result = String::with_capacity(source.len());
        let mut cursor = 0usize;
        for (span, id) in edits {
            if span.start < cursor
                || source.get(span.start..span.end) != Some(analysis.bindings[id].name.as_str())
            {
                return Err(Diagnostic::byte(
                    "invalid or overlapping rename span",
                    span.start,
                ));
            }
            let prefix = source
                .get(cursor..span.start)
                .ok_or_else(|| Diagnostic::byte("invalid rename boundary", span.start))?;
            let name = self.names[id]
                .as_ref()
                .ok_or_else(|| Diagnostic::byte("missing replacement name", span.start))?;
            result.push_str(prefix);
            result.push_str(name);
            cursor = span.end;
        }
        result.push_str(
            source
                .get(cursor..)
                .ok_or_else(|| Diagnostic::byte("invalid final rename boundary", cursor))?,
        );
        Ok(Some(result))
    }
}

// Match only `(getfenv and getfenv(0)) or _G`, not an arbitrary environment
// alias, call, field access, dynamically assembled key, or method invocation.
fn is_vm_environment(expression: &Expression) -> bool {
    let ExpressionKind::Binary {
        operator: BinaryOperator::Or,
        left,
        right,
    } = &expression.kind
    else {
        return false;
    };
    if !is_name(right, "_G") {
        return false;
    }
    let ExpressionKind::Group(inner) = &left.kind else {
        return false;
    };
    let ExpressionKind::Binary {
        operator: BinaryOperator::And,
        left,
        right,
    } = &inner.kind
    else {
        return false;
    };
    if !is_name(left, "getfenv") {
        return false;
    }
    let ExpressionKind::Call {
        function,
        method: None,
        arguments,
    } = &right.kind
    else {
        return false;
    };
    is_name(function, "getfenv")
        && arguments.len() == 1
        && matches!(&arguments[0].kind, ExpressionKind::Number(value) if value == "0")
}

fn is_name(expression: &Expression, expected: &str) -> bool {
    matches!(&expression.kind, ExpressionKind::Name(name) if name.value == expected)
}
