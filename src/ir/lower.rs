use super::*;
use crate::ast::{
    BinaryOperator as B, ExpressionKind as E, StatementKind as S, UnaryOperator as U,
};
use crate::scope::{Analysis, BindingId, BindingKind, ScopeKind};
use std::collections::{BTreeMap, BTreeSet};

const MAX_WORK: usize = 1_000_000;
const MAX_DEPTH: usize = 64;

pub(super) fn lower(chunk: &ast::Chunk) -> Result<Module, Diagnostic> {
    let analysis = crate::scope::analyze_chunk(chunk)?;
    // These operations observe the physical interpreter stack/environment,
    // not virtual source frames. Never silently substitute native compilation.
    if let Some(barrier) = analysis
        .rename_barriers
        .iter()
        .find(|name| !matches!(name.as_str(), "_G" | "_ENV"))
    {
        return Err(Diagnostic::new(format!("AST VM cannot preserve reflective operation '{barrier}'; use the explicit native backend only if its documented limits are acceptable")));
    }
    let declarations = analysis
        .bindings
        .iter()
        .enumerate()
        .filter_map(|(id, b)| b.declaration.map(|s| (s.start, id)))
        .collect();
    let references = analysis
        .references
        .iter()
        .map(|r| (r.span.start, r.binding))
        .collect();
    let function_scopes = analysis
        .scopes
        .iter()
        .enumerate()
        .filter(|(_, s)| s.kind == ScopeKind::Function)
        .map(|(id, s)| ((s.span.start, s.span.end), id))
        .collect();
    let mut compiler = Compiler {
        analysis: &analysis,
        declarations,
        references,
        function_scopes,
        module: Module {
            target: chunk.target,
            entry: 0,
            functions: vec![],
        },
        work: 0,
        depth: 0,
    };
    let mut ctx = Context::new(0, None, 0, true, vec![]);
    compiler.module.functions.push(ctx.function.clone());
    if chunk.block.statements.iter().any(|s| {
        matches!(
            s.kind,
            S::Local { exported: true, .. }
                | S::LocalFunction { exported: true, .. }
                | S::TypeAlias { exported: true, .. }
                | S::TypeFunction { exported: true, .. }
        )
    }) {
        let reg = ctx.alloc(chunk.span)?;
        ctx.emit(Instruction::NewTable(reg));
        ctx.exports = Some(reg);
    }
    compiler.block(&mut ctx, &chunk.block, false)?;
    compiler.finish(&mut ctx)?;
    compiler.module.functions[0] = ctx.function;
    Ok(compiler.module)
}

#[derive(Clone, Copy)]
enum Place {
    Cell(Register),
    Upvalue(u16),
    Global(ConstantId),
    Table(Operand, Operand),
}

/// Locals used directly as native register operands are read at the consuming
/// operation; compound expressions/upvalues/globals are evaluated into temps.
/// This matters when another operand invokes a closure that writes a local.
#[derive(Clone, Copy)]
enum Operand {
    Value(Register),
    Cell(Register),
}

struct Loop {
    exit: BlockId,
    again: BlockId,
    break_mark: Register,
    continue_mark: Register,
    repeat_continues: Option<Vec<ast::Span>>,
}

struct Context {
    id: FunctionId,
    function: Function,
    current: BlockId,
    next: Register,
    cells: BTreeMap<BindingId, Register>,
    upvalues: BTreeMap<BindingId, u16>,
    constants: BTreeMap<Constant, ConstantId>,
    loops: Vec<Loop>,
    exports: Option<Register>,
    export_cells: BTreeSet<Register>,
    lua51_zero_constant: Option<u64>,
}
impl Context {
    fn new(
        id: usize,
        parent: Option<usize>,
        parameters: u16,
        variadic: bool,
        captures: Vec<Capture>,
    ) -> Self {
        Self {
            id,
            function: Function {
                parent,
                parameters,
                variadic,
                legacy_arg_slot: false,
                legacy_arg_table: false,
                registers: 1,
                captures,
                constants: vec![],
                blocks: vec![Block {
                    instructions: vec![],
                    terminator: Terminator::Unreachable,
                }],
            },
            current: 0,
            next: 0,
            cells: BTreeMap::new(),
            upvalues: BTreeMap::new(),
            constants: BTreeMap::new(),
            loops: vec![],
            exports: None,
            export_cells: BTreeSet::new(),
            lua51_zero_constant: None,
        }
    }
    fn alloc(&mut self, span: ast::Span) -> Result<Register, Diagnostic> {
        if self.next >= 256 {
            return Err(Diagnostic::byte(
                "AST IR exceeds 256 live registers; split the expression/function",
                span.start,
            ));
        }
        let reg = self.next;
        self.next += 1;
        self.function.registers = self.function.registers.max(self.next);
        Ok(reg)
    }
    fn emit(&mut self, i: Instruction) {
        self.function.blocks[self.current].instructions.push(i);
    }
    fn open(&self) -> bool {
        matches!(
            self.function.blocks[self.current].terminator,
            Terminator::Unreachable
        )
    }
    fn new_block(&mut self) -> BlockId {
        let id = self.function.blocks.len();
        self.function.blocks.push(Block {
            instructions: vec![],
            terminator: Terminator::Unreachable,
        });
        id
    }
    fn terminate(&mut self, t: Terminator) {
        self.function.blocks[self.current].terminator = t;
    }
    fn jump(&mut self, to: BlockId) {
        if self.open() {
            self.terminate(Terminator::Jump(to));
        }
    }
    fn release(&mut self, mark: Register) {
        if self.open() && mark < self.function.registers {
            self.emit(Instruction::Clear(mark, self.function.registers - 1));
        }
        self.next = mark;
    }
    fn constant(&mut self, value: Constant) -> Result<ConstantId, Diagnostic> {
        if let Some(&id) = self.constants.get(&value) {
            return Ok(id);
        }
        if self.function.constants.len() >= 65_536 {
            return Err(Diagnostic::new(
                "AST IR constant pool exceeds 65536 entries",
            ));
        }
        let id = self.function.constants.len();
        self.constants.insert(value.clone(), id);
        self.function.constants.push(value);
        Ok(id)
    }
    fn load(&mut self, value: Constant, span: ast::Span) -> Result<Register, Diagnostic> {
        let r = self.alloc(span)?;
        let k = self.constant(value)?;
        self.emit(Instruction::Constant(r, k));
        Ok(r)
    }
    fn location(&self, id: BindingId) -> Result<Place, Diagnostic> {
        if let Some(&r) = self.cells.get(&id) {
            Ok(Place::Cell(r))
        } else if let Some(&u) = self.upvalues.get(&id) {
            Ok(Place::Upvalue(u))
        } else {
            Err(Diagnostic::new(
                "AST IR binding has no local/upvalue location",
            ))
        }
    }
    fn operand(&mut self, operand: Operand) -> Result<Register, Diagnostic> {
        match operand {
            Operand::Value(r) => Ok(r),
            Operand::Cell(cell) => {
                let r = self.alloc(ast::Span::default())?;
                self.emit(Instruction::ReadCell(r, cell));
                Ok(r)
            }
        }
    }
    fn direct_local(&self, p: Place) -> Option<Register> {
        match p {
            Place::Cell(r) if !self.export_cells.contains(&r) => Some(r),
            _ => None,
        }
    }
    fn read(&mut self, dst: Register, p: Place) -> Result<(), Diagnostic> {
        let instruction = match p {
            Place::Cell(r) => Instruction::ReadCell(dst, r),
            Place::Upvalue(u) => Instruction::ReadUpvalue(dst, u),
            Place::Global(k) => Instruction::ReadGlobal(dst, k),
            Place::Table(t, k) => Instruction::GetTable(dst, self.operand(t)?, self.operand(k)?),
        };
        self.emit(instruction);
        Ok(())
    }
    fn write(&mut self, p: Place, value: Register) -> Result<(), Diagnostic> {
        let instruction = match p {
            Place::Cell(r) => Instruction::WriteCell(r, value),
            Place::Upvalue(u) => Instruction::WriteUpvalue(u, value),
            Place::Global(k) => Instruction::WriteGlobal(k, value),
            Place::Table(t, k) => Instruction::SetTable(self.operand(t)?, self.operand(k)?, value),
        };
        self.emit(instruction);
        Ok(())
    }
}

struct Compiler<'a> {
    analysis: &'a Analysis,
    declarations: BTreeMap<usize, BindingId>,
    references: BTreeMap<usize, Option<BindingId>>,
    function_scopes: BTreeMap<(usize, usize), usize>,
    module: Module,
    work: usize,
    depth: usize,
}
impl Compiler<'_> {
    fn charge(&mut self, span: ast::Span) -> Result<(), Diagnostic> {
        self.work += 1;
        if self.work > MAX_WORK {
            return Err(Diagnostic::byte(
                "AST IR work safety limit exceeded",
                span.start,
            ));
        }
        Ok(())
    }
    fn enter(&mut self, span: ast::Span) -> Result<(), Diagnostic> {
        self.charge(span)?;
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Diagnostic::byte(
                "AST IR nesting safety limit exceeded",
                span.start,
            ));
        }
        Ok(())
    }
    fn finish(&mut self, ctx: &mut Context) -> Result<(), Diagnostic> {
        if ctx.open() {
            let r = ctx.alloc(ast::Span::default())?;
            ctx.emit(Instruction::NewPack(r));
            if let Some(exports) = ctx.exports {
                ctx.emit(Instruction::Freeze(exports));
                ctx.emit(Instruction::Push(r, exports));
            }
            ctx.terminate(Terminator::Return(r));
        }
        // Dead blocks still have explicit terminators; no hidden fallthrough.
        for b in &mut ctx.function.blocks {
            if matches!(b.terminator, Terminator::Unreachable) {
                return Err(Diagnostic::new("internal unterminated IR block"));
            }
        }
        Ok(())
    }
    fn bind(&self, ctx: &mut Context, name: &ast::Name) -> Result<Register, Diagnostic> {
        let id = *self
            .declarations
            .get(&name.span.start)
            .ok_or_else(|| Diagnostic::byte("missing binding declaration", name.span.start))?;
        let reg = ctx.alloc(name.span)?;
        ctx.cells.insert(id, reg);
        Ok(reg)
    }
    fn name(&self, ctx: &mut Context, name: &ast::Name) -> Result<Place, Diagnostic> {
        match self.references.get(&name.span.start) {
            Some(Some(id)) => ctx.location(*id),
            Some(None) => Ok(Place::Global(
                ctx.constant(Constant::String(name.value.as_bytes().to_vec()))?,
            )),
            None => Err(Diagnostic::byte(
                "missing value reference in IR lowering",
                name.span.start,
            )),
        }
    }
    fn function(
        &mut self,
        parent: &Context,
        body: &ast::FunctionBody,
    ) -> Result<FunctionId, Diagnostic> {
        self.enter(body.span)?;
        let scope = *self
            .function_scopes
            .get(&(body.span.start, body.span.end))
            .ok_or_else(|| Diagnostic::byte("missing function scope", body.span.start))?;
        if self.module.functions.len() >= 65_536 {
            return Err(Diagnostic::byte(
                "AST IR prototype limit exceeded",
                body.span.start,
            ));
        }
        let mut captures = Vec::new();
        let mut upvalues = BTreeMap::new();
        for &id in &self.analysis.scopes[scope].upvalues {
            let capture = match parent.location(id)? {
                Place::Cell(r) => Capture::Local(r),
                Place::Upvalue(u) => Capture::Upvalue(u),
                _ => unreachable!(),
            };
            if captures.len() >= 256 {
                return Err(Diagnostic::byte(
                    "AST IR upvalue limit exceeded",
                    body.span.start,
                ));
            }
            upvalues.insert(id, captures.len() as u16);
            captures.push(capture);
        }
        let id = self.module.functions.len();
        let mut child = Context::new(id, Some(parent.id), 0, body.has_vararg, captures);
        child.upvalues = upvalues;
        for &binding in &self.analysis.scopes[scope].bindings {
            let b = &self.analysis.bindings[binding];
            match b.kind {
                BindingKind::Parameter | BindingKind::ImplicitSelf => {
                    child.function.parameters += 1
                }
                BindingKind::ImplicitArg => {
                    child.function.legacy_arg_slot = true;
                    child.function.legacy_arg_table = true;
                }
                _ => return Err(Diagnostic::new("unexpected function parameter binding")),
            }
            let reg = child.alloc(body.span)?;
            child.cells.insert(binding, reg);
        }
        self.module.functions.push(child.function.clone());
        self.block(&mut child, &body.body, false)?;
        self.finish(&mut child)?;
        self.module.functions[id] = child.function;
        self.depth -= 1;
        Ok(id)
    }
    fn block(
        &mut self,
        ctx: &mut Context,
        block: &ast::Block,
        scoped: bool,
    ) -> Result<(), Diagnostic> {
        self.enter(block.span)?;
        let mark = ctx.next;
        for s in &block.statements {
            if !ctx.open() {
                ctx.current = ctx.new_block();
            }
            self.statement(ctx, s)?;
        }
        if scoped {
            ctx.release(mark);
        }
        self.depth -= 1;
        Ok(())
    }
    fn statement(&mut self, ctx: &mut Context, s: &ast::Statement) -> Result<(), Diagnostic> {
        self.enter(s.span)?;
        let mark = ctx.next;
        match &s.kind {
            S::Empty | S::TypeAlias { .. } | S::TypeFunction { .. } => {}
            S::Local {
                bindings,
                values,
                exported,
                ..
            } => {
                let mut regs = Vec::new();
                for b in bindings {
                    regs.push(self.bind(ctx, &b.name)?);
                }
                let keep = ctx.next;
                let pack = self.values(ctx, values)?;
                let tmp = ctx.alloc(s.span)?;
                for (i, (b, &reg)) in bindings.iter().zip(&regs).enumerate() {
                    ctx.emit(Instruction::Extract(tmp, pack, (i + 1) as u16));
                    ctx.emit(Instruction::NewCell(reg, tmp));
                    if *exported {
                        self.export(ctx, reg, &b.name)?;
                    }
                }
                ctx.release(keep);
            }
            S::LocalFunction {
                name,
                body,
                exported,
                ..
            } => {
                let reg = self.bind(ctx, name)?;
                let keep = ctx.next;
                let tmp = ctx.alloc(s.span)?;
                ctx.emit(Instruction::Nil(tmp));
                ctx.emit(Instruction::NewCell(reg, tmp));
                let id = self.function(ctx, body)?;
                ctx.emit(Instruction::Closure(tmp, id));
                ctx.emit(Instruction::WriteCell(reg, tmp));
                if *exported {
                    self.export(ctx, reg, name)?;
                }
                ctx.release(keep);
            }
            S::Assignment { targets, values } => {
                self.assignment(ctx, targets, values, s.span)?;
                ctx.release(mark);
            }
            S::CompoundAssignment {
                target,
                operator,
                value,
            } => {
                let place = self.place(ctx, target)?;
                let old = ctx.alloc(s.span)?;
                let direct = ctx.direct_local(place).is_some() && *operator != B::Concat;
                if !direct {
                    ctx.read(old, place)?;
                }
                let rhs = self.expression(ctx, value, false)?;
                if direct {
                    ctx.read(old, place)?;
                }
                ctx.emit(Instruction::Binary(*operator, old, old, rhs));
                ctx.write(place, old)?;
                ctx.release(mark);
            }
            S::Function { name, body } => {
                let root = name
                    .path
                    .first()
                    .ok_or_else(|| Diagnostic::new("empty function name"))?;
                let place = if name.path.len() == 1 && name.method.is_none() {
                    self.name(ctx, root)?
                } else {
                    let table = ctx.alloc(root.span)?;
                    let p = self.name(ctx, root)?;
                    ctx.read(table, p)?;
                    let fields: Vec<_> =
                        name.path.iter().skip(1).chain(name.method.iter()).collect();
                    for field in &fields[..fields.len() - 1] {
                        let key = ctx.load(
                            Constant::String(field.value.as_bytes().to_vec()),
                            field.span,
                        )?;
                        ctx.emit(Instruction::GetTable(table, table, key));
                    }
                    let field = fields.last().unwrap();
                    let key = ctx.load(
                        Constant::String(field.value.as_bytes().to_vec()),
                        field.span,
                    )?;
                    Place::Table(Operand::Value(table), Operand::Value(key))
                };
                let id = self.function(ctx, body)?;
                let tmp = ctx.alloc(s.span)?;
                ctx.emit(Instruction::Closure(tmp, id));
                ctx.write(place, tmp)?;
                ctx.release(mark);
            }
            S::Call(e) => {
                self.expression(ctx, e, false)?;
                ctx.release(mark);
            }
            S::Do(block) => self.block(ctx, block, true)?,
            S::If {
                branches,
                else_block,
            } => {
                let join = ctx.new_block();
                for branch in branches {
                    let yes = ctx.new_block();
                    let no = ctx.new_block();
                    let cond = self.condition(ctx, &branch.condition)?;
                    ctx.terminate(Terminator::Branch {
                        condition: cond,
                        then_block: yes,
                        else_block: no,
                    });
                    ctx.next = mark;
                    ctx.current = yes;
                    self.block(ctx, &branch.body, true)?;
                    ctx.jump(join);
                    ctx.current = no;
                    ctx.next = mark;
                }
                if let Some(block) = else_block {
                    self.block(ctx, block, true)?;
                }
                ctx.jump(join);
                ctx.current = join;
                ctx.release(mark);
            }
            S::While { condition, body } => {
                let test = ctx.new_block();
                let yes = ctx.new_block();
                let exit = ctx.new_block();
                ctx.jump(test);
                ctx.current = test;
                let cond = self.condition(ctx, condition)?;
                ctx.terminate(Terminator::Branch {
                    condition: cond,
                    then_block: yes,
                    else_block: exit,
                });
                ctx.next = mark;
                ctx.loops.push(Loop {
                    exit,
                    again: test,
                    break_mark: mark,
                    continue_mark: mark,
                    repeat_continues: None,
                });
                ctx.current = yes;
                self.block(ctx, body, true)?;
                ctx.jump(test);
                ctx.loops.pop();
                ctx.current = exit;
                ctx.release(mark);
            }
            S::Repeat { body, condition } => {
                let start = ctx.new_block();
                let test = ctx.new_block();
                let again = ctx.new_block();
                let exit = ctx.new_block();
                ctx.jump(start);
                ctx.current = start;
                ctx.loops.push(Loop {
                    exit,
                    again: test,
                    break_mark: mark,
                    continue_mark: mark,
                    repeat_continues: Some(vec![]),
                });
                for stmt in &body.statements {
                    if !ctx.open() {
                        ctx.current = ctx.new_block();
                    }
                    ctx.loops.last_mut().unwrap().continue_mark = ctx.next;
                    self.statement(ctx, stmt)?;
                }
                ctx.jump(test);
                ctx.current = test;
                let cond = self.condition(ctx, condition)?;
                let loop_info = ctx.loops.pop().unwrap();
                if let Some(span) = loop_info
                    .repeat_continues
                    .unwrap()
                    .into_iter()
                    .min_by_key(|span| span.start)
                {
                    // The earliest possible skip suffices. Scan only until's
                    // indexed references once, not every reference per continue.
                    for (_, binding) in self
                        .references
                        .range(condition.span.start..condition.span.end)
                    {
                        self.work += 1;
                        if binding.is_some_and(|id| {
                            self.analysis.bindings[id].declaration.is_some_and(|d| {
                                d.start > span.start && d.start < condition.span.start
                            })
                        }) {
                            return Err(Diagnostic::byte("AST IR continue may skip a local initialization used by repeat/until",span.start));
                        }
                    }
                    self.charge(condition.span)?;
                }
                ctx.terminate(Terminator::Branch {
                    condition: cond,
                    then_block: exit,
                    else_block: again,
                });
                ctx.current = again;
                ctx.release(mark);
                ctx.jump(start);
                ctx.current = exit;
                ctx.release(mark);
            }
            S::NumericFor {
                binding,
                initial,
                limit,
                step,
                body,
            } => {
                let base = ctx.alloc(s.span)?;
                ctx.alloc(s.span)?;
                ctx.alloc(s.span)?;
                let keep = ctx.next;
                let i = self.expression(ctx, initial, false)?;
                ctx.emit(Instruction::Move(base, i));
                ctx.release(keep);
                let n = self.expression(ctx, limit, false)?;
                ctx.emit(Instruction::Move(base + 1, n));
                ctx.release(keep);
                let st = if let Some(step) = step {
                    self.expression(ctx, step, false)?
                } else {
                    ctx.load(Constant::number(1.0), s.span)?
                };
                ctx.emit(Instruction::Move(base + 2, st));
                ctx.release(keep);
                ctx.emit(Instruction::NumberPrepare(base));
                let cond = ctx.alloc(s.span)?;
                let local = self.bind(ctx, &binding.name)?;
                let live = ctx.next;
                let test = ctx.new_block();
                let yes = ctx.new_block();
                let advance = ctx.new_block();
                let exit = ctx.new_block();
                ctx.jump(test);
                ctx.current = test;
                if !self.module.target.is_luau() {
                    ctx.emit(Instruction::NumberStep(base));
                }
                ctx.emit(Instruction::NumberTest(cond, base));
                ctx.terminate(Terminator::Branch {
                    condition: cond,
                    then_block: yes,
                    else_block: exit,
                });
                ctx.current = yes;
                ctx.emit(Instruction::NewCell(local, base));
                ctx.loops.push(Loop {
                    exit,
                    again: advance,
                    break_mark: mark,
                    continue_mark: live,
                    repeat_continues: None,
                });
                self.block(ctx, body, true)?;
                ctx.jump(advance);
                ctx.loops.pop();
                ctx.current = advance;
                if self.module.target.is_luau() {
                    ctx.emit(Instruction::NumberStep(base));
                }
                ctx.jump(test);
                ctx.current = exit;
                ctx.release(mark);
            }
            S::GenericFor {
                bindings,
                values,
                body,
            } => {
                let iterator = self.values(ctx, values)?;
                ctx.emit(Instruction::IteratorPrepare(iterator));
                let result = ctx.alloc(s.span)?;
                let first = ctx.alloc(s.span)?;
                let test_value = ctx.alloc(s.span)?;
                let nil = ctx.alloc(s.span)?;
                ctx.emit(Instruction::Nil(nil));
                let mut regs = Vec::new();
                for b in bindings {
                    regs.push(self.bind(ctx, &b.name)?);
                }
                let live = ctx.next;
                let test = ctx.new_block();
                let yes = ctx.new_block();
                let exit = ctx.new_block();
                ctx.jump(test);
                ctx.current = test;
                ctx.emit(Instruction::IteratorNext(result, iterator));
                ctx.emit(Instruction::Extract(first, result, 1));
                ctx.emit(Instruction::Binary(B::Equal, test_value, first, nil));
                ctx.terminate(Terminator::Branch {
                    condition: test_value,
                    then_block: exit,
                    else_block: yes,
                });
                ctx.current = yes;
                for (i, &reg) in regs.iter().enumerate() {
                    ctx.emit(Instruction::Extract(first, result, (i + 1) as u16));
                    ctx.emit(Instruction::NewCell(reg, first));
                }
                ctx.loops.push(Loop {
                    exit,
                    again: test,
                    break_mark: mark,
                    continue_mark: live,
                    repeat_continues: None,
                });
                self.block(ctx, body, true)?;
                ctx.jump(test);
                ctx.loops.pop();
                ctx.current = exit;
                ctx.release(mark);
            }
            S::Break | S::Continue => {
                let is_continue = matches!(s.kind, S::Continue);
                let l = ctx.loops.last_mut().ok_or_else(|| {
                    Diagnostic::byte("loop control outside IR loop", s.span.start)
                })?;
                if is_continue {
                    if let Some(spans) = &mut l.repeat_continues {
                        spans.push(s.span);
                    }
                }
                let (to, clear) = if is_continue {
                    (l.again, l.continue_mark)
                } else {
                    (l.exit, l.break_mark)
                };
                ctx.release(clear);
                ctx.terminate(Terminator::Jump(to));
                ctx.next = mark;
            }
            S::Return(values) => {
                if let [ast::Expression {
                    kind: E::Call { .. },
                    ..
                }] = values.as_slice()
                {
                    let (function, arguments) = self.call_parts(ctx, &values[0])?;
                    ctx.terminate(Terminator::TailCall {
                        function,
                        arguments,
                    });
                } else {
                    let r = self.values(ctx, values)?;
                    ctx.terminate(Terminator::Return(r));
                }
            }
        }
        self.depth -= 1;
        Ok(())
    }
    fn export(
        &mut self,
        ctx: &mut Context,
        cell: Register,
        name: &ast::Name,
    ) -> Result<(), Diagnostic> {
        let table = ctx
            .exports
            .ok_or_else(|| Diagnostic::new("export outside module"))?;
        let key = ctx.load(Constant::String(name.value.as_bytes().to_vec()), name.span)?;
        ctx.emit(Instruction::Export(cell, table, key));
        ctx.export_cells.insert(cell);
        Ok(())
    }
    fn auto(&mut self, ctx: &mut Context, e: &ast::Expression) -> Result<Operand, Diagnostic> {
        self.enter(e.span)?;
        let result = self.auto_inner(ctx, e);
        self.depth -= 1;
        result
    }
    fn auto_inner(
        &mut self,
        ctx: &mut Context,
        e: &ast::Expression,
    ) -> Result<Operand, Diagnostic> {
        match &e.kind {
            E::Name(n) => {
                let p = self.name(ctx, n)?;
                if let Some(cell) = ctx.direct_local(p) {
                    return Ok(Operand::Cell(cell));
                }
            }
            E::Group(inner)
            | E::TypeAssertion {
                expression: inner, ..
            }
            | E::TypeInstantiation {
                expression: inner, ..
            } => return self.auto(ctx, inner),
            _ => {}
        }
        Ok(Operand::Value(self.expression(ctx, e, false)?))
    }
    fn place(&mut self, ctx: &mut Context, e: &ast::Expression) -> Result<Place, Diagnostic> {
        match &e.kind {
            E::Name(n) => self.name(ctx, n),
            E::Field { table, field } => {
                let t = self.auto(ctx, table)?;
                let k = ctx.load(
                    Constant::String(field.value.as_bytes().to_vec()),
                    field.span,
                )?;
                Ok(Place::Table(t, Operand::Value(k)))
            }
            E::Index { table, index } => {
                let t = self.auto(ctx, table)?;
                let k = self.auto(ctx, index)?;
                Ok(Place::Table(t, k))
            }
            _ => Err(Diagnostic::byte(
                "invalid IR assignment target",
                e.span.start,
            )),
        }
    }
    fn assignment(
        &mut self,
        ctx: &mut Context,
        targets: &[ast::Expression],
        values: &[ast::Expression],
        span: ast::Span,
    ) -> Result<(), Diagnostic> {
        if targets.is_empty() || values.is_empty() || targets.len() > 255 {
            return Err(Diagnostic::byte(
                "assignment exceeds 255 results",
                span.start,
            ));
        }
        let mut places = Vec::new();
        for target in targets {
            let place = self.place(ctx, target)?;
            if !self.module.target.is_luau() {
                // Lua 5.1 stores right-to-left. A later local LHS freezes any
                // preceding indexed LHS operand that aliases that register.
                if let Some(cell) = ctx.direct_local(place) {
                    for earlier in &mut places {
                        self.charge(target.span)?;
                        if let Place::Table(t, k) = earlier {
                            for operand in [t, k] {
                                if matches!(*operand,Operand::Cell(r) if r==cell) {
                                    *operand = Operand::Value(ctx.operand(*operand)?);
                                }
                            }
                        }
                    }
                }
            }
            places.push(place);
        }
        if !self.module.target.is_luau() {
            let pack = self.values(ctx, values)?;
            let tmp = ctx.alloc(span)?;
            for (i, &place) in places.iter().enumerate().rev() {
                ctx.emit(Instruction::Extract(tmp, pack, (i + 1) as u16));
                ctx.write(place, tmp)?;
            }
            return Ok(());
        }
        // Luau writes nonconflicting locals as their RHS is computed; table,
        // global/upvalue writes follow, then conflicting/multret local writes.
        // Match the pinned compiler's syntactic conflict analysis, without
        // importing any of its native instructions or optimization passes.
        let mut assigned = BTreeSet::new();
        let mut deferred = BTreeSet::new();
        let mut reference_work = 0usize;
        let mut refs = |expr: &ast::Expression, assigned: &BTreeSet<Register>| {
            for (_, binding) in self.references.range(expr.span.start..expr.span.end) {
                reference_work += 1;
                if let Some(reg) = binding.and_then(|id| ctx.cells.get(&id)) {
                    if assigned.contains(reg) {
                        deferred.insert(*reg);
                    }
                }
            }
        };
        for (i, &p) in places.iter().enumerate() {
            if let Some(r) = ctx.direct_local(p) {
                if let Some(v) = values.get(i) {
                    refs(v, &assigned);
                }
                assigned.insert(r);
            }
        }
        for (i, &p) in places.iter().enumerate() {
            if ctx.direct_local(p).is_none() {
                if let Some(v) = values.get(i) {
                    refs(v, &assigned);
                }
            }
        }
        for v in values.iter().skip(places.len()) {
            refs(v, &assigned);
        }
        self.work += reference_work;
        self.charge(span)?;
        for &p in &places {
            if let Place::Table(t, k) = p {
                for op in [t, k] {
                    if let Operand::Cell(r) = op {
                        if assigned.contains(&r) {
                            deferred.insert(r);
                        }
                    }
                }
            }
        }
        let mut results = Vec::new();
        let mut early = vec![false; places.len()];
        for (i, value) in values.iter().enumerate() {
            if i >= places.len() {
                self.expression(ctx, value, false)?;
                continue;
            }
            if i + 1 == values.len() && places.len() > values.len() {
                let pack = self.values(ctx, std::slice::from_ref(value))?;
                for n in 1..=places.len() - i {
                    let r = ctx.alloc(span)?;
                    ctx.emit(Instruction::Extract(r, pack, n as u16));
                    results.push(Operand::Value(r));
                }
            } else if let Some(cell) = ctx.direct_local(places[i]) {
                let r = self.expression(ctx, value, false)?;
                results.push(Operand::Value(r));
                if !deferred.contains(&cell) {
                    ctx.write(places[i], r)?;
                    early[i] = true;
                }
            } else {
                results.push(self.auto(ctx, value)?);
            }
        }
        for (i, &place) in places.iter().enumerate() {
            if ctx.direct_local(place).is_none() {
                let r = ctx.operand(results[i])?;
                ctx.write(place, r)?;
            }
        }
        for (i, &place) in places.iter().enumerate() {
            if ctx.direct_local(place).is_some() && !early[i] {
                let r = ctx.operand(results[i])?;
                ctx.write(place, r)?;
            }
        }
        Ok(())
    }
    fn values(
        &mut self,
        ctx: &mut Context,
        values: &[ast::Expression],
    ) -> Result<Register, Diagnostic> {
        let span = values.first().map_or(ast::Span::default(), |e| e.span);
        let pack = ctx.alloc(span)?;
        ctx.emit(Instruction::NewPack(pack));
        let keep = ctx.next;
        for (i, e) in values.iter().enumerate() {
            let multi = i + 1 == values.len() && multret(e);
            let value = self.expression(ctx, e, multi)?;
            ctx.emit(if multi {
                Instruction::Extend(pack, value)
            } else {
                Instruction::Push(pack, value)
            });
            ctx.release(keep);
        }
        Ok(pack)
    }
    fn call_parts(
        &mut self,
        ctx: &mut Context,
        e: &ast::Expression,
    ) -> Result<(Register, Register), Diagnostic> {
        let E::Call {
            function,
            method,
            arguments,
            ..
        } = &e.kind
        else {
            return Err(Diagnostic::new("expected call expression"));
        };
        let late = method.is_some() && self.module.target.is_luau();
        let object = if late {
            self.auto(ctx, function)?
        } else {
            Operand::Value(self.expression(ctx, function, false)?)
        };
        let f = ctx.alloc(e.span)?;
        let key = if let Some(method) = method {
            Some(ctx.load(Constant::Method(method.value.clone()), method.span)?)
        } else {
            None
        };
        let args = ctx.alloc(e.span)?;
        ctx.emit(Instruction::NewPack(args));
        if !late {
            let object = ctx.operand(object)?;
            if let Some(key) = key {
                ctx.emit(Instruction::Method(f, object, key));
                ctx.emit(Instruction::Push(args, object));
            } else {
                ctx.emit(Instruction::Move(f, object));
            }
        }
        let keep = ctx.next;
        for (i, arg) in arguments.iter().enumerate() {
            let multi = i + 1 == arguments.len() && multret(arg);
            let value = self.expression(ctx, arg, multi)?;
            ctx.emit(if multi {
                Instruction::Extend(args, value)
            } else {
                Instruction::Push(args, value)
            });
            ctx.release(keep);
        }
        if late {
            let object = ctx.operand(object)?;
            ctx.emit(Instruction::Method(f, object, key.unwrap()));
            let full = ctx.alloc(e.span)?;
            ctx.emit(Instruction::NewPack(full));
            ctx.emit(Instruction::Push(full, object));
            ctx.emit(Instruction::Extend(full, args));
            Ok((f, full))
        } else {
            Ok((f, args))
        }
    }

    fn constant_truth(&mut self, e: &ast::Expression) -> Result<Option<bool>, Diagnostic> {
        self.enter(e.span)?;
        let result = match &e.kind {
            E::Nil => Some(false),
            E::Boolean(v) => Some(*v),
            E::String(_) => Some(true),
            E::Group(inner) => self.constant_truth(inner)?,
            E::Unary {
                operator: U::Not,
                expression,
            } => self.constant_truth(expression)?.map(|v| !v),
            _ => self.fold_number(e, 0)?.map(|_| true),
        };
        self.depth -= 1;
        Ok(result)
    }
    fn condition(
        &mut self,
        ctx: &mut Context,
        e: &ast::Expression,
    ) -> Result<Register, Diagnostic> {
        // Lua 5.1's truth-only literal conditions do not intern a numeric K.
        // In particular, `if 0 then` must not determine a later -0 constant.
        if !self.module.target.is_luau() {
            if let Some(truth) = self.constant_truth(e)? {
                return ctx.load(Constant::Boolean(truth), e.span);
            }
        }
        self.expression(ctx, e, false)
    }
    fn expression(
        &mut self,
        ctx: &mut Context,
        e: &ast::Expression,
        multi: bool,
    ) -> Result<Register, Diagnostic> {
        self.enter(e.span)?;
        let dst = ctx.alloc(e.span)?;
        let keep = ctx.next;
        if !self.module.target.is_luau() {
            if let Some(mut value) = self.fold_number(e, 0)? {
                // Lua 5.1's numeric constant interning treats -0 and +0 as
                // the same key: the first emitted source constant wins.
                if value == 0.0 {
                    if let Some(bits) = ctx.lua51_zero_constant {
                        value = f64::from_bits(bits);
                    } else {
                        ctx.lua51_zero_constant = Some(value.to_bits());
                    }
                }
                let k = ctx.constant(Constant::number(value))?;
                ctx.emit(Instruction::Constant(dst, k));
                ctx.release(keep);
                self.depth -= 1;
                return Ok(dst);
            }
        }
        match &e.kind {
            E::Nil => ctx.emit(Instruction::Nil(dst)),
            E::Boolean(v) => {
                let k = ctx.constant(Constant::Boolean(*v))?;
                ctx.emit(Instruction::Constant(dst, k));
            }
            E::Number(v) => {
                let k = ctx.constant(number(v, self.module.target, e.span)?)?;
                ctx.emit(Instruction::Constant(dst, k));
            }
            E::String(v) => {
                let k = ctx.constant(Constant::String(
                    crate::minify::literal_bytes(v, self.module.target).map_err(Diagnostic::new)?,
                ))?;
                ctx.emit(Instruction::Constant(dst, k));
            }
            E::Name(n) => {
                let p = self.name(ctx, n)?;
                ctx.read(dst, p)?;
            }
            E::Group(inner)
            | E::TypeAssertion {
                expression: inner, ..
            }
            | E::TypeInstantiation {
                expression: inner, ..
            } => {
                let value = self.expression(ctx, inner, false)?;
                ctx.emit(Instruction::Move(dst, value));
            }
            E::Vararg => {
                ctx.function.legacy_arg_table = false;
                ctx.emit(Instruction::Varargs(dst));
                if !multi {
                    ctx.emit(Instruction::Extract(dst, dst, 1));
                }
            }
            E::Function(body) => {
                let id = self.function(ctx, body)?;
                ctx.emit(Instruction::Closure(dst, id));
            }
            E::Field { table, field } => {
                let table = self.expression(ctx, table, false)?;
                let key = ctx.load(
                    Constant::String(field.value.as_bytes().to_vec()),
                    field.span,
                )?;
                ctx.emit(Instruction::GetTable(dst, table, key));
            }
            E::Index { table, index } => {
                let t = self.auto(ctx, table)?;
                let k = self.auto(ctx, index)?;
                let t = ctx.operand(t)?;
                let k = ctx.operand(k)?;
                ctx.emit(Instruction::GetTable(dst, t, k));
            }
            E::Call { .. } => {
                let (f, args) = self.call_parts(ctx, e)?;
                ctx.emit(Instruction::Call(dst, f, args));
                if !multi {
                    ctx.emit(Instruction::Extract(dst, dst, 1));
                }
            }
            E::Unary {
                operator,
                expression,
            } => {
                if *operator == U::Negate
                    && matches!(&expression.kind,E::Number(n) if n.ends_with('i'))
                {
                    let E::Number(raw) = &expression.kind else {
                        unreachable!()
                    };
                    let Constant::Integer(n) = number(raw, self.module.target, expression.span)?
                    else {
                        unreachable!()
                    };
                    let k = ctx.constant(Constant::Integer(n.wrapping_neg()))?;
                    ctx.emit(Instruction::Constant(dst, k));
                } else {
                    let v = self.expression(ctx, expression, false)?;
                    ctx.emit(Instruction::Unary(*operator, dst, v));
                }
            }
            E::Binary {
                operator,
                left,
                right,
            } => {
                let l = if matches!(operator, B::And | B::Or | B::Concat) {
                    Operand::Value(self.expression(ctx, left, false)?)
                } else {
                    self.auto(ctx, left)?
                };
                if matches!(operator, B::And | B::Or) {
                    let l = ctx.operand(l)?;
                    ctx.emit(Instruction::Move(dst, l));
                    let rhs = ctx.new_block();
                    let join = ctx.new_block();
                    let (yes, no) = if *operator == B::And {
                        (rhs, join)
                    } else {
                        (join, rhs)
                    };
                    ctx.terminate(Terminator::Branch {
                        condition: dst,
                        then_block: yes,
                        else_block: no,
                    });
                    ctx.next = keep;
                    ctx.current = rhs;
                    let r = self.expression(ctx, right, false)?;
                    ctx.emit(Instruction::Move(dst, r));
                    ctx.release(keep);
                    ctx.jump(join);
                    ctx.current = join;
                } else {
                    let r = self.auto(ctx, right)?;
                    let l = ctx.operand(l)?;
                    let r = ctx.operand(r)?;
                    match operator {
                        B::NotEqual => {
                            ctx.emit(Instruction::Binary(B::Equal, dst, l, r));
                            ctx.emit(Instruction::Unary(U::Not, dst, dst));
                        }
                        B::Greater => ctx.emit(Instruction::Binary(B::Less, dst, r, l)),
                        B::GreaterEqual => ctx.emit(Instruction::Binary(B::LessEqual, dst, r, l)),
                        _ => ctx.emit(Instruction::Binary(*operator, dst, l, r)),
                    }
                }
            }
            E::IfExpression {
                branches,
                else_expression,
            } => {
                let join = ctx.new_block();
                for branch in branches {
                    let yes = ctx.new_block();
                    let no = ctx.new_block();
                    let c = self.condition(ctx, &branch.condition)?;
                    ctx.terminate(Terminator::Branch {
                        condition: c,
                        then_block: yes,
                        else_block: no,
                    });
                    ctx.next = keep;
                    ctx.current = yes;
                    let v = self.expression(ctx, &branch.value, false)?;
                    ctx.emit(Instruction::Move(dst, v));
                    ctx.release(keep);
                    ctx.jump(join);
                    ctx.current = no;
                    ctx.next = keep;
                }
                let v = self.expression(ctx, else_expression, false)?;
                ctx.emit(Instruction::Move(dst, v));
                ctx.release(keep);
                ctx.jump(join);
                ctx.current = join;
            }
            E::Table(fields) => self.table(ctx, dst, fields, e.span)?,
            E::InterpolatedString {
                strings,
                expressions,
            } => {
                // The reference evaluates ALL arguments before tostring.
                let mut args = Vec::new();
                for arg in expressions {
                    args.push(self.expression(ctx, arg, false)?);
                }
                let first = strings
                    .first()
                    .ok_or_else(|| Diagnostic::byte("invalid interpolation", e.span.start))?;
                let k = ctx.constant(Constant::String(
                    crate::minify::literal_bytes(&format!("`{}`", first.value), self.module.target)
                        .map_err(Diagnostic::new)?,
                ))?;
                ctx.emit(Instruction::Constant(dst, k));
                let tmp = ctx.alloc(e.span)?;
                for (i, &arg) in args.iter().enumerate() {
                    ctx.emit(Instruction::ToString(tmp, arg));
                    ctx.emit(Instruction::Binary(B::Concat, dst, dst, tmp));
                    let part = strings.get(i + 1).ok_or_else(|| {
                        Diagnostic::byte("missing interpolation segment", e.span.start)
                    })?;
                    let k = ctx.constant(Constant::String(
                        crate::minify::literal_bytes(
                            &format!("`{}`", part.value),
                            self.module.target,
                        )
                        .map_err(Diagnostic::new)?,
                    ))?;
                    ctx.emit(Instruction::Constant(tmp, k));
                    ctx.emit(Instruction::Binary(B::Concat, dst, dst, tmp));
                }
            }
        }
        ctx.release(keep);
        self.depth -= 1;
        Ok(dst)
    }
    fn fold_number(
        &mut self,
        e: &ast::Expression,
        depth: usize,
    ) -> Result<Option<f64>, Diagnostic> {
        self.charge(e.span)?;
        if depth >= MAX_DEPTH {
            return Err(Diagnostic::byte(
                "numeric folding nesting limit exceeded",
                e.span.start,
            ));
        }
        let value = match &e.kind {
            E::Number(raw) => {
                if let Constant::Number(bits) = number(raw, self.module.target, e.span)? {
                    Some(f64::from_bits(bits))
                } else {
                    None
                }
            }
            E::Group(inner) => self.fold_number(inner, depth + 1)?,
            E::Unary {
                operator: U::Negate,
                expression,
            } => self.fold_number(expression, depth + 1)?.map(|n| -n),
            E::Binary {
                operator,
                left,
                right,
            } if matches!(
                operator,
                B::Add | B::Subtract | B::Multiply | B::Divide | B::Modulo | B::Power
            ) =>
            {
                let Some(a) = self.fold_number(left, depth + 1)? else {
                    return Ok(None);
                };
                let Some(b) = self.fold_number(right, depth + 1)? else {
                    return Ok(None);
                };
                if matches!(operator, B::Divide | B::Modulo) && b == 0.0 {
                    return Ok(None);
                }
                let n = match operator {
                    B::Add => a + b,
                    B::Subtract => a - b,
                    B::Multiply => a * b,
                    B::Divide => a / b,
                    B::Modulo => a - (a / b).floor() * b,
                    B::Power => a.powf(b),
                    _ => unreachable!(),
                };
                if n.is_nan() {
                    None
                } else {
                    Some(n)
                }
            }
            _ => None,
        };
        Ok(value)
    }
    fn table(
        &mut self,
        ctx: &mut Context,
        dst: Register,
        fields: &[ast::TableField],
        span: ast::Span,
    ) -> Result<(), Diagnostic> {
        ctx.emit(Instruction::NewTable(dst));
        let pack = ctx.alloc(span)?;
        ctx.emit(Instruction::NewPack(pack));
        let start = ctx.alloc(span)?;
        let keep = ctx.next;
        let mut index = 1usize;
        let mut pending = 0usize;
        let flush = |ctx: &mut Context, index: usize| -> Result<(), Diagnostic> {
            let k = ctx.constant(Constant::number(index as f64))?;
            ctx.emit(Instruction::Constant(start, k));
            ctx.emit(Instruction::SetList(dst, pack, start));
            ctx.emit(Instruction::NewPack(pack));
            Ok(())
        };
        for (i, field) in fields.iter().enumerate() {
            self.charge(span)?;
            let list = matches!(field, ast::TableField::List(_));
            if pending > 0
                && ((self.module.target.is_luau() && (!list || pending == 16))
                    || (!self.module.target.is_luau() && pending == 50))
            {
                flush(ctx, index)?;
                index += pending;
                pending = 0;
            }
            match field {
                ast::TableField::List(e) => {
                    let multi = i + 1 == fields.len() && multret(e);
                    let value = self.expression(ctx, e, multi)?;
                    ctx.emit(if multi {
                        Instruction::Extend(pack, value)
                    } else {
                        Instruction::Push(pack, value)
                    });
                    pending += 1;
                }
                ast::TableField::Record { name, value, .. } => {
                    let key =
                        ctx.load(Constant::String(name.value.as_bytes().to_vec()), name.span)?;
                    let value = self.expression(ctx, value, false)?;
                    ctx.emit(Instruction::SetTable(dst, key, value));
                }
                ast::TableField::Computed { key, value, .. } => {
                    let key = self.auto(ctx, key)?;
                    let value = self.auto(ctx, value)?;
                    let key = ctx.operand(key)?;
                    let value = ctx.operand(value)?;
                    ctx.emit(Instruction::SetTable(dst, key, value));
                }
            }
            ctx.release(keep);
        }
        if pending > 0 {
            flush(ctx, index)?;
        }
        Ok(())
    }
}

fn multret(e: &ast::Expression) -> bool {
    matches!(e.kind, E::Call { .. } | E::Vararg)
}

fn number(raw: &str, target: Target, span: ast::Span) -> Result<Constant, Diagnostic> {
    let s = raw.replace('_', "");
    let invalid = || {
        Diagnostic::byte(
            "numeric literal cannot be represented by the AST bytecode backend",
            span.start,
        )
    };
    if let Some(digits) = s.strip_suffix('i') {
        if !target.is_luau() {
            return Err(invalid());
        }
        let (digits, base, pattern) = if digits.starts_with("0x") || digits.starts_with("0X") {
            (&digits[2..], 16, true)
        } else if digits.starts_with("0b") || digits.starts_with("0B") {
            (&digits[2..], 2, true)
        } else {
            (digits, 10, false)
        };
        let value = u64::from_str_radix(digits, base).map_err(|_| invalid())?;
        // Unlike hexadecimal/binary bit patterns, decimal tokens must fit i64.
        if !pattern && value > i64::MAX as u64 {
            return Err(invalid());
        }
        return Ok(Constant::Integer(value as i64));
    }
    let value = if s.starts_with("0b") || s.starts_with("0B") {
        // Fixed Luau parses ordinary binary/hex integers with strtoull.
        u64::from_str_radix(&s[2..], 2)
            .map(|n| n as f64)
            .map_err(|_| invalid())?
    } else if s.starts_with("0x") || s.starts_with("0X") {
        let digits = &s[2..];
        if target.is_luau() {
            u64::from_str_radix(digits, 16)
                .map(|n| n as f64)
                .map_err(|_| invalid())?
        } else {
            // Lua 5.1's lexer only retains alphanumeric characters after 0x;
            // strtod supports more spellings than source numeral tokens do.
            if raw.contains(['.', '+', '-']) {
                return Err(invalid());
            }
            hex_float(digits).ok_or_else(invalid)?
        }
    } else {
        s.parse::<f64>().map_err(|_| invalid())?
    };
    Ok(Constant::number(value))
}

/// Correctly rounded binary64 parsing for Lua 5.1's hexadecimal literals,
/// including overflow, subnormals, ties-to-even and huge zero exponents.
fn hex_float(raw: &str) -> Option<f64> {
    let mut parts = raw.split(['p', 'P']);
    let mantissa = parts.next()?;
    let mut exp = 0i64;
    if let Some(text) = parts.next() {
        let (negative, text) = if let Some(s) = text.strip_prefix('-') {
            (true, s)
        } else {
            (false, text.strip_prefix('+').unwrap_or(text))
        };
        if text.is_empty() {
            return None;
        }
        for c in text.bytes() {
            if !c.is_ascii_digit() {
                return None;
            }
            exp = (exp * 10 + i64::from(c - b'0')).min(1_000_000_000);
        }
        if negative {
            exp = -exp;
        }
    }
    if parts.next().is_some() {
        return None;
    }
    let mut whole = 0i64;
    let mut seen_dot = false;
    let mut count = 0usize;
    for c in mantissa.chars() {
        if c == '.' {
            if seen_dot {
                return None;
            }
            seen_dot = true;
        } else {
            c.to_digit(16)?;
            count += 1;
            if !seen_dot {
                whole += 1;
            }
        }
    }
    if count == 0 {
        return None;
    }
    let mut leading = 0i64;
    let mut started = false;
    let mut exponent = 0i64;
    let mut precision = 0usize;
    let mut consumed = 0usize;
    let mut value = 0u64;
    let mut guard = false;
    let mut sticky = false;
    for digit in mantissa.chars().filter(|&c| c != '.') {
        let d = digit.to_digit(16)?;
        for shift in (0..4).rev() {
            let bit = d >> shift & 1;
            if !started {
                if bit == 0 {
                    leading += 1;
                    continue;
                }
                exponent = exp + whole * 4 - leading - 1;
                if exponent > 1023 {
                    return Some(f64::INFINITY);
                }
                if exponent < -1075 {
                    return Some(0.0);
                }
                precision = if exponent >= -1022 {
                    53
                } else {
                    (exponent + 1075) as usize
                };
                started = true;
            }
            if consumed < precision {
                value = (value << 1) | u64::from(bit);
            } else if consumed == precision {
                guard = bit != 0;
            } else {
                sticky |= bit != 0;
            }
            consumed += 1;
        }
    }
    if !started {
        return Some(0.0);
    }
    if consumed < precision {
        value <<= precision - consumed;
    }
    if guard && (sticky || value & 1 != 0) {
        value += 1;
    }
    if exponent < -1022 {
        return Some(f64::from_bits(value));
    }
    if value == 1u64 << 53 {
        value >>= 1;
        exponent += 1;
    }
    if exponent > 1023 {
        return Some(f64::INFINITY);
    }
    Some(f64::from_bits(
        ((exponent + 1023) as u64) << 52 | (value & ((1u64 << 52) - 1)),
    ))
}
