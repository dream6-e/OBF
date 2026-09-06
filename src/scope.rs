//! Lexical value binding analysis for Lua 5.1 and Luau.
//!
//! Binding IDs identify declarations, not spellings. Type names, field names
//! and method names are not value bindings. Luau `typeof` expressions and
//! qualified type prefixes do refer to values. Type-function bodies are
//! inspected conservatively but never renamed by this first-stage pass.

use crate::ast::*;
use crate::{Diagnostic, Target};
use std::collections::{BTreeMap, BTreeSet};

mod rename;

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
    /// Final-name uniqueness group, without changing lexical visibility.
    /// Parameters/for variables share a group with their direct body locals.
    pub name_scope: ScopeId,
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
    pub is_const: bool,
    pub preserve: Option<PreserveReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reference {
    pub name: String,
    pub span: Span,
    pub scope: ScopeId,
    /// `None` denotes a global value reference, never a field/type name.
    pub binding: Option<BindingId>,
    /// True only for assignment to the value binding, not its table fields.
    pub is_write: bool,
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
    // Reference ordinal when each declaration becomes active. Byte offsets
    // are insufficient: initializers/signatures are visited before binding.
    activations: Vec<usize>,
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
                name_scope: 0,
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
            activations: Vec::new(),
        },
        visible: BTreeMap::new(),
        current: 0,
        opaque_boundaries: Vec::new(),
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
    local: Option<(&'a Name, bool, bool)>,
    type_function: bool,
}

enum Task<'a> {
    Block(&'a Block),
    ScopedBlock(&'a Block),
    BodyBlock(&'a Block),
    Statement(&'a Statement),
    Expression(&'a Expression),
    AssignmentTarget(&'a Expression),
    Type(&'a TypeExpression),
    Function(FunctionVisit<'a>),
    Declare(&'a Name, BindingKind, bool, bool),
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
    // A type function cannot reference bindings created before its signature.
    opaque_boundaries: Vec<usize>,
    tasks: Vec<Task<'a>>,
}

impl<'a> Walker<'a> {
    fn visit(&mut self, task: Task<'a>) -> Result<(), Diagnostic> {
        match task {
            Task::Block(block) => {
                self.tasks
                    .extend(block.statements.iter().rev().map(Task::Statement));
            }
            Task::ScopedBlock(block) => self.scoped_block(block, false)?,
            Task::BodyBlock(block) => self.scoped_block(block, true)?,
            Task::Statement(statement) => self.statement(statement)?,
            Task::Expression(expression) => self.expression(expression)?,
            Task::AssignmentTarget(expression) => {
                if let ExpressionKind::Name(name) = &expression.kind {
                    self.reference(name, true)?;
                } else {
                    self.expression(expression)?;
                }
            }
            Task::Type(value) => self.type_expression(value)?,
            Task::Function(function) => self.function(function),
            Task::Declare(name, kind, exported, is_const) => {
                self.declare(&name.value, Some(name.span), kind, exported, is_const)?;
            }
            Task::Implicit(name, kind) => self.declare(name, None, kind, false, false)?,
            Task::Enter(kind, span) => self.enter(kind, span)?,
            Task::Leave => self.leave()?,
            Task::EndOpaque => {
                self.opaque_boundaries
                    .pop()
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
                self.tasks
                    .extend(targets.iter().rev().map(Task::AssignmentTarget));
            }
            StatementKind::CompoundAssignment { target, value, .. } => {
                self.tasks.push(Task::Expression(value));
                self.tasks.push(Task::AssignmentTarget(target));
            }
            StatementKind::Call(value) => self.tasks.push(Task::Expression(value)),
            StatementKind::Local {
                bindings,
                values,
                exported,
                is_const,
            } => {
                // All annotations and initializers see the OLD environment,
                // including closures in `local f = function() return f end`.
                self.declarations(bindings, BindingKind::Local, *exported, *is_const);
                self.expressions(values);
                self.annotations(bindings);
            }
            StatementKind::LocalFunction {
                name,
                body,
                exported,
                is_const,
            } => self.tasks.push(Task::Function(FunctionVisit {
                body,
                method: false,
                local: Some((name, *exported, *is_const)),
                type_function: false,
            })),
            StatementKind::Function { name, body } => {
                if let Some(root) = name.path.first() {
                    self.reference(root, name.path.len() == 1 && name.method.is_none())?;
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
                self.tasks.push(Task::BodyBlock(body));
                self.tasks.push(Task::Declare(
                    &binding.name,
                    BindingKind::NumericFor,
                    false,
                    false,
                ));
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
                self.tasks.push(Task::BodyBlock(body));
                self.declarations(bindings, BindingKind::GenericFor, false, false);
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
            // The pinned parser forbids captures from outside the type
            // function, including in its signature. Preserve its own locals.
            self.opaque_boundaries.push(self.result.bindings.len());
            self.tasks.push(Task::EndOpaque);
        }
        self.tasks.push(Task::Leave);
        self.tasks.push(Task::BodyBlock(&body.body));
        if !self.target.is_luau() && body.has_vararg {
            // The pinned 5.1.5 runtime enables LUA_COMPAT_VARARG. Its implicit
            // `arg` local is introduced AFTER the explicit parameters.
            self.tasks
                .push(Task::Implicit("arg", BindingKind::ImplicitArg));
        }
        self.declarations(&body.parameters, BindingKind::Parameter, false, false);
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
        if let Some((name, exported, is_const)) = visit.local {
            self.tasks.push(Task::Declare(
                name,
                BindingKind::LocalFunction,
                exported,
                is_const,
            ));
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
            ExpressionKind::Name(name) => self.reference(name, false)?,
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
                type_arguments,
                arguments,
            } => {
                if let Some(method) = method {
                    self.inspect_name(&method.value, method.span);
                }
                self.expressions(arguments);
                self.type_arguments(type_arguments);
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
                        self.reference(prefix, false)?;
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

    fn declarations(
        &mut self,
        bindings: &'a [Binding],
        kind: BindingKind,
        exported: bool,
        is_const: bool,
    ) {
        self.tasks.extend(
            bindings
                .iter()
                .rev()
                .map(|binding| Task::Declare(&binding.name, kind, exported, is_const)),
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

    fn scoped_block(&mut self, block: &'a Block, share_names: bool) -> Result<(), Diagnostic> {
        let parent_group = self.result.scopes[self.current].name_scope;
        self.enter(ScopeKind::Block, block.span)?;
        if share_names {
            self.result.scopes[self.current].name_scope = parent_group;
        }
        self.tasks.push(Task::Leave);
        self.tasks.push(Task::Block(block));
        Ok(())
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
            name_scope: id,
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
        is_const: bool,
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
        } else if !self.opaque_boundaries.is_empty() {
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
            is_const,
            preserve,
        });
        self.result.activations.push(self.result.references.len());
        self.result.scopes[self.current].bindings.push(id);
        self.visible.entry(name.to_owned()).or_default().push(id);
        Ok(())
    }

    fn reference(&mut self, name: &Name, is_write: bool) -> Result<(), Diagnostic> {
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
            if self
                .opaque_boundaries
                .last()
                .is_some_and(|&start| id < start)
            {
                return Err(Diagnostic::byte(
                    format!(
                        "type function cannot reference outer local '{}'",
                        name.value
                    ),
                    name.span.start,
                ));
            }
            let local = &mut self.result.bindings[id];
            if is_write && local.is_const {
                return Err(Diagnostic::byte(
                    format!("constant '{}' may not be reassigned", name.value),
                    name.span.start,
                ));
            }
            local.references = local
                .references
                .checked_add(1)
                .ok_or_else(|| Diagnostic::new("binding reference count overflow"))?;
            if !self.opaque_boundaries.is_empty() && local.preserve.is_none() {
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
            is_write,
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
        // The default AST backend stores the whole VM as section functions of
        // the payload table in `local x={};return setmetatable({...},x):m()`,
        // so the audited environment capture is a statement of one of THOSE
        // function bodies. Explicit native-backend VMs keep the capture at the
        // chunk top level. Collect all locations; the single-capture rule
        // below is unchanged.
        let mut statements: Vec<&Statement> = chunk.block.statements.iter().collect();
        for statement in &chunk.block.statements {
            let StatementKind::Return(values) = &statement.kind else {
                continue;
            };
            let Some(ExpressionKind::Call {
                function: invoked,
                method: Some(_),
                ..
            }) = values.first().map(|value| &value.kind)
            else {
                continue;
            };
            // `... :m()` resolves the entry function stored in the payload
            // table; the invoked function is `setmetatable({...},x)`.
            let ExpressionKind::Call {
                function,
                method: None,
                type_arguments,
                arguments,
            } = &invoked.kind
            else {
                continue;
            };
            if !type_arguments.is_empty() {
                continue;
            }
            if !matches!(&function.kind, ExpressionKind::Name(name) if name.value == "setmetatable")
            {
                continue;
            }
            let Some(ExpressionKind::Table(fields)) = arguments.first().map(|value| &value.kind)
            else {
                continue;
            };
            for field in fields {
                let value = match field {
                    TableField::Computed { value, .. } | TableField::Record { value, .. } => value,
                    TableField::List(_) => continue,
                };
                if let ExpressionKind::Function(body) = &value.kind {
                    statements.extend(body.body.statements.iter());
                }
            }
        }
        let mut captures = statements.iter().filter_map(|statement| {
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
        // The custom backend additionally carries exactly three audited
        // environment probes (one per key-share function); the explicit
        // native backend carries none. Anything in between is unaudited.
        let probes: Vec<Span> = statements
            .iter()
            .filter_map(|statement| {
                let StatementKind::Local {
                    bindings,
                    values,
                    exported: false,
                    is_const: false,
                } = &statement.kind
                else {
                    return None;
                };
                (bindings.len() == 1
                    && bindings[0].annotation.is_none()
                    && values.len() == 1
                    && is_vm_probe(&values[0], chunk.target))
                .then(|| values[0].span)
            })
            .collect();
        let probed = probes.len() == 3;
        if !probed && !probes.is_empty() {
            return Err(Diagnostic::new(
                "generated VM must carry exactly three audited environment probes or none",
            ));
        }
        // Barrier accounting: three getfenv/_G occurrences inside the capture
        // span, plus (when probed) three debug/loadstring occurrences inside
        // each probe span. Every other barrier location is unaudited.
        let outside: Vec<Span> = self
            .barrier_locations
            .iter()
            .copied()
            .filter(|span| span.start < capture.start || span.end > capture.end)
            .collect();
        // Each audited probe contributes three barrier occurrences on Luau
        // (debug x2, loadstring) and four on Lua 5.1, where the `getinfo`
        // FIELD NAME is itself a listed executor-reflection barrier.
        let per_probe = if chunk.target.is_luau() { 3 } else { 4 };
        if captures.next().is_some()
            || self.barrier_locations.len() != 3 + per_probe * probes.len()
            || outside.len() != per_probe * probes.len()
            || outside.iter().any(|span| {
                !probes
                    .iter()
                    .any(|probe| span.start >= probe.start && span.end <= probe.end)
            })
            || self.rename_barriers.iter().any(|name| {
                let allowed = match name.as_str() {
                    "getfenv" | "_G" => true,
                    "debug" | "loadstring" => probed,
                    // Lua 5.1 probes spell the debug field `getinfo`, a
                    // listed executor-reflection barrier name in its own
                    // right; allow it only inside the audited probes.
                    "getinfo" => probed && !chunk.target.is_luau(),
                    _ => false,
                };
                !allowed
            })
            || self.references.iter().any(|reference| {
                matches!(
                    reference.name.as_str(),
                    "getfenv" | "_G" | "debug" | "loadstring"
                ) && reference.binding.is_some()
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
        rename::plan(self, target, seed)
    }

    pub(crate) fn verify_renamed(
        &self,
        other: &Analysis,
        plan: &RenamePlan,
    ) -> Result<(), Diagnostic> {
        if plan.names.len() != self.bindings.len() {
            return Err(Diagnostic::new(
                "invalid rename plan length; refusing output",
            ));
        }
        let same_scopes = self.scopes.len() == other.scopes.len()
            && self.scopes.iter().zip(&other.scopes).all(|(a, b)| {
                a.parent == b.parent
                    && a.function == b.function
                    && a.kind == b.kind
                    && a.name_scope == b.name_scope
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
                        && a.is_const == b.is_const
                });
        let same_references = self.references.len() == other.references.len()
            && self.references.iter().zip(&other.references).all(|(a, b)| {
                let expected = a
                    .binding
                    .and_then(|id| plan.names[id].as_deref())
                    .unwrap_or(&a.name);
                a.binding == b.binding
                    && a.scope == b.scope
                    && a.is_write == b.is_write
                    && expected == b.name
            });
        if same_scopes
            && same_bindings
            && same_references
            && self.globals == other.globals
            && self.activations == other.activations
        {
            // Graph identity alone misses collisions between unused locals.
            rename::verify_names(other, plan)
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
/// Audited environment probe used by the custom backend's three key-share
/// functions: exactly `debug and debug.<info|getinfo>(loadstring, <"s"|"S">)`
/// (Luau: debug.info; Lua 5.1: debug.getinfo). Any other spelling, target
/// mismatch, extra argument or bound local is unaudited and rejected.
fn is_vm_probe(expression: &Expression, target: Target) -> bool {
    let ExpressionKind::Binary {
        operator: BinaryOperator::And,
        left,
        right,
    } = &expression.kind
    else {
        return false;
    };
    if !is_name(left, "debug") {
        return false;
    }
    let ExpressionKind::Call {
        function,
        method: None,
        type_arguments,
        arguments,
    } = &right.kind
    else {
        return false;
    };
    if !type_arguments.is_empty() || arguments.len() != 2 {
        return false;
    }
    let ExpressionKind::Field { table, field } = &function.kind else {
        return false;
    };
    if !is_name(table, "debug") {
        return false;
    }
    let (name, tag) = if target.is_luau() {
        ("info", "s")
    } else {
        ("getinfo", "S")
    };
    if field.value != name || !is_name(&arguments[0], "loadstring") {
        return false;
    }
    matches!(&arguments[1].kind, ExpressionKind::String(raw)
        if crate::minify::literal_bytes(raw, target).ok().as_deref() == Some(tag.as_bytes()))
}

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
        type_arguments,
        arguments,
    } = &right.kind
    else {
        return false;
    };
    is_name(function, "getfenv")
        && type_arguments.is_empty()
        && arguments.len() == 1
        && matches!(&arguments[0].kind, ExpressionKind::Number(value) if value == "0")
}

fn is_name(expression: &Expression, expected: &str) -> bool {
    matches!(&expression.kind, ExpressionKind::Name(name) if name.value == expected)
}
