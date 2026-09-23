//! K4 第二步：用户程序 IR 层的函数结构变换（确定性、无种子）。
//!
//! 在 lowering 之后、编码之前运行，因此公共 `.obf`（按文档与种子无关）和
//! 逐种子 wire image 走同一份变换后的 IR。两个通道：
//!
//! * **严格内联**——把「唯一调用点」的被调函数体拼进调用方。拒绝式条件：
//!   被调函数非变参、无捕获、无共享闭包、无子原型，代码里不出现
//!   `Closure/Varargs/Export/Freeze/ReadUpvalue/WriteUpvalue`，终止器无
//!   `TailCall`；闭包值的流向（单块直线数据流）必须恰好被一个 `Call`
//!   消费，不得逃逸到表/全局/upvalue/实参/返回/混包，也不得被 tail-call。
//!   闭包恰好一处、且身份曾驻留的单元格在其余块里没有别的读取、没被子
//!   捕获或导出时，连同被调函数一起删除；否则保留函数与闭包，只拼接调用点。
//! * **确定性兄弟重排**——按 `(深度, 原索引散列, 原索引)` 重排原型森林，
//!   入口保持在 0，父序先于子序（编码器的硬约束）。
//!
//! 本批次边界（明确不做，见 项目交接总结.md K4 行）：IR 外提（需要完整
//! 值流证明）；跨块闭包调用点的内联（直线数据流只覆盖单块）；tail-call
//! 位置的内联（拼接形态不同）；种子驱动变体（公共 .obf 与种子无关是既有
//! 文档约束）。

use super::{Block, Capture, Function, Instruction, Module, Terminator};
use crate::Diagnostic;
use std::collections::BTreeSet;

const MAX_REGISTERS: u16 = 256;

/// 入口：lower 之后、encode 之前。
pub fn transform(module: &mut Module) -> Result<(), Diagnostic> {
    inline(module)?;
    reorder(module)?;
    validate_invariants(module)
}

// ---------------------------------------------------------------------------
// 严格内联
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// 只拼接调用点；被调函数与闭包保留。
    Keep,
    /// 拼接调用点，并删除闭包链与被调函数（全部使用可证明收敛于该调用）。
    Remove,
}

/// 追踪结束的原因：`Reject` 表示程序合法但不满足内联条件（跳过即可，
/// 不是编译错误）；`Bad` 是内部不变量被破坏（fail-closed）。
enum TraceErr {
    Reject,
    Bad(Diagnostic),
}

impl From<Diagnostic> for TraceErr {
    fn from(d: Diagnostic) -> Self {
        TraceErr::Bad(d)
    }
}

#[derive(Clone, Copy)]
struct CallSite {
    block: usize,
    index: usize,
    dst: u16,
    f: u16,
    args: u16,
    /// 给 `f` 装上闭包身份的那条指令（Remove 模式要一并摘掉）。
    def_index: usize,
}

/// 单块直线追踪的结果。
struct Flow {
    site: Option<CallSite>,
    /// 身份被非调用指令「观察」（算术/逻辑/条件/循环基址）：行为依赖该值，
    /// 因此禁止 Remove（拼接本身不受影响）。
    observed: bool,
    /// 全模块 `Closure(_, c)` 条数（编码约束下都应在 parent 里）。
    births: usize,
    /// 出生点（块, 指令）。
    birth: Option<(usize, usize)>,
    /// 追踪窗口内身份曾驻留的单元格寄存器（Remove 模式要逐一确认无别用）。
    identity_cells: Vec<u16>,
}

fn inline(module: &mut Module) -> Result<(), Diagnostic> {
    let mut i = 1usize;
    while i < module.functions.len() {
        match choose(module, i)? {
            Some(mode) => {
                splice(module, i, mode)?;
                // Remove 模式已经删掉函数 i，索引整体左移：不前进。
                if mode != Mode::Remove {
                    i += 1;
                }
            }
            None => i += 1,
        }
    }
    Ok(())
}

fn choose(module: &Module, c: usize) -> Result<Option<Mode>, Diagnostic> {
    let callee = &module.functions[c];
    // 结构拒绝：变参/共享/legacy 槽/捕获/子原型/危险指令与终止器。
    if callee.variadic
        || callee.shared_closure
        || callee.legacy_arg_slot
        || !callee.captures.is_empty()
    {
        return Ok(None);
    }
    for block in &callee.blocks {
        for op in &block.instructions {
            match op {
                Instruction::Closure(_, _)
                | Instruction::Varargs(_)
                | Instruction::Export(_, _, _)
                | Instruction::Freeze(_)
                | Instruction::ReadUpvalue(_, _)
                | Instruction::WriteUpvalue(_, _) => return Ok(None),
                _ => {}
            }
        }
        if matches!(block.terminator, Terminator::TailCall { .. }) {
            return Ok(None);
        }
    }
    let flow = match trace_closure(module, c) {
        Ok(flow) => flow,
        Err(TraceErr::Reject) => return Ok(None),
        Err(TraceErr::Bad(e)) => return Err(e),
    };
    let Some(site) = flow.site else {
        return Ok(None);
    };
    let parent = callee.parent.unwrap();
    let caller = &module.functions[parent];
    if caller.registers as usize + callee.registers as usize > MAX_REGISTERS as usize {
        return Ok(None);
    }
    // Remove：闭包恰好一处、无任何观测使用、身份单元格在别处无读取/捕获/导出。
    if flow.births == 1 && !flow.observed {
        let chain_cell = cell_of_def(module, parent, &site);
        let birth_index = flow.birth.unwrap().1;
        let cells_ok = flow
            .identity_cells
            .iter()
            .copied()
            .chain(chain_cell)
            .all(|fcell| cell_unused_elsewhere(module, parent, fcell, &site, birth_index));
        if cells_ok {
            return Ok(Some(Mode::Remove));
        }
    }
    Ok(Some(Mode::Keep))
}

/// def 指令若是从单元格读出的（`ReadCell(f, fcell)`），返回该单元格。
fn cell_of_def(module: &Module, parent: usize, site: &CallSite) -> Option<u16> {
    let op = &module.functions[parent].blocks[site.block].instructions[site.def_index];
    match *op {
        Instruction::ReadCell(_, src) => Some(src),
        _ => None,
    }
}

/// Remove 模式的单元格审计：该单元格在追踪窗口（出生点到调用点，单块
/// 直线）之外没有别的读取、没被宿主的子函数捕获、没被导出。
fn cell_unused_elsewhere(
    module: &Module,
    host: usize,
    fcell: u16,
    site: &CallSite,
    birth_index: usize,
) -> bool {
    let f = &module.functions[host];
    for (b, block) in f.blocks.iter().enumerate() {
        for (ix, op) in block.instructions.iter().enumerate() {
            if b == site.block && ix >= birth_index && ix <= site.index {
                continue;
            }
            match *op {
                Instruction::ReadCell(_, src) if src == fcell => return false,
                Instruction::GetTable(_, t, _) if t == fcell => return false,
                Instruction::Export(r, _, _) if r == fcell => return false,
                _ => {}
            }
        }
    }
    for g in 1..module.functions.len() {
        if module.functions[g].parent != Some(host) {
            continue;
        }
        for cap in &module.functions[g].captures {
            if matches!(
                cap,
                Capture::Local(r) | Capture::RecursiveLocal(r)
                    if *r == fcell
            ) {
                return false;
            }
        }
    }
    true
}

/// 从每个出生点所在块做直线追踪（出生点都在 parent 里）。
fn trace_closure(module: &Module, c: usize) -> Result<Flow, TraceErr> {
    let parent = module.functions[c]
        .parent
        .ok_or_else(|| Diagnostic::new("K4 inliner: callee without parent"))?;
    let mut births = Vec::new();
    for (fid, f) in module.functions.iter().enumerate() {
        for (b, block) in f.blocks.iter().enumerate() {
            for (ix, op) in block.instructions.iter().enumerate() {
                if matches!(op, Instruction::Closure(_, t) if *t == c) {
                    if fid != parent {
                        return Err(TraceErr::Bad(Diagnostic::new(
                            "K4 inliner: closure of a child outside its parent",
                        )));
                    }
                    births.push((b, ix));
                }
            }
        }
    }
    if births.is_empty() {
        return Ok(Flow {
            site: None,
            observed: false,
            births: 0,
            birth: None,
            identity_cells: Vec::new(),
        });
    }
    let mut flow = Flow {
        site: None,
        observed: false,
        births: births.len(),
        birth: births.first().copied(),
        identity_cells: Vec::new(),
    };
    for (b, ix) in &births {
        trace_block(module, parent, *b, *ix, &mut flow)?;
    }
    Ok(flow)
}

struct State {
    reg: Vec<bool>,
    cell: Vec<bool>,
    pack: Vec<bool>,
    empty: Vec<bool>,
}

/// 从块 `b` 的指令 `start`（出生点）之后开始直线追踪闭包身份。
fn trace_block(
    module: &Module,
    host: usize,
    b: usize,
    start: usize,
    flow: &mut Flow,
) -> Result<(), TraceErr> {
    let host_f = &module.functions[host];
    let width = host_f.registers.max(1) as usize;
    let mut st = State {
        reg: vec![false; width],
        cell: vec![false; width],
        pack: vec![false; width],
        empty: vec![false; width],
    };
    // 出生点本身不在扫描窗口里（skip(start + 1)），身份从这里诞生。
    let birth_reg = match host_f.blocks[b].instructions[start] {
        Instruction::Closure(r, _) => r,
        _ => unreachable!("birth is a closure instruction"),
    };
    st.reg[birth_reg as usize] = true;
    let mut def: Option<usize> = Some(start);
    let mut consumed = false;
    let mut site: Option<CallSite> = None;

    macro_rules! kill {
        ($r:expr) => {
            let r = $r as usize;
            if r < st.reg.len() {
                st.reg[r] = false;
                st.cell[r] = false;
                st.pack[r] = false;
                st.empty[r] = false;
            }
        };
    }
    macro_rules! note_cell {
        ($r:expr) => {
            let r = $r;
            if !flow.identity_cells.contains(&r) {
                flow.identity_cells.push(r);
            }
        };
    }

    for (i, op) in host_f.blocks[b]
        .instructions
        .iter()
        .enumerate()
        .skip(start + 1)
    {
        match *op {
            Instruction::Closure(_, _) => {
                // 追踪窗口内出现同被调的第二个闭包：两条身份链无法区分。
                return Err(TraceErr::Reject);
            }
            Instruction::Constant(r, _)
            | Instruction::Nil(r)
            | Instruction::NewTable(r)
            | Instruction::Varargs(r)
            | Instruction::ReadGlobal(r, _)
            | Instruction::ReadUpvalue(r, _) => {
                kill!(r);
            }
            Instruction::Move(r, src) => {
                let had = st.reg[src as usize];
                kill!(r);
                if had {
                    st.reg[r as usize] = true;
                    def = Some(i);
                }
            }
            Instruction::NewCell(r, src) => {
                let had = st.reg[src as usize];
                kill!(r);
                if had {
                    st.cell[r as usize] = true;
                    note_cell!(r);
                }
            }
            Instruction::ReadCell(r, src) => {
                let had = st.cell[src as usize];
                kill!(r);
                if had {
                    st.reg[r as usize] = true;
                    def = Some(i);
                }
            }
            Instruction::WriteCell(r, src) => {
                let had = st.reg[src as usize];
                kill!(r);
                if had {
                    st.cell[r as usize] = true;
                    note_cell!(r);
                }
            }
            Instruction::WriteUpvalue(_, r) => {
                if st.reg[r as usize] || st.pack[r as usize] {
                    return Err(TraceErr::Reject);
                }
            }
            Instruction::WriteGlobal(_, r)
            | Instruction::SetTable(_, _, r)
            | Instruction::Export(r, _, _)
            | Instruction::Freeze(r) => {
                if st.reg[r as usize] || st.pack[r as usize] {
                    return Err(TraceErr::Reject);
                }
            }
            Instruction::GetTable(r, _, _) => {
                kill!(r);
            }
            Instruction::Method(r, _, _) => {
                kill!(r);
            }
            Instruction::NewPack(r) => {
                kill!(r);
                st.empty[r as usize] = true;
            }
            Instruction::Push(r, src) => {
                let held = st.pack[r as usize];
                let had = st.reg[src as usize];
                let was_empty = st.empty[r as usize];
                st.empty[r as usize] = false;
                // 身份包再推任何值、或身份被推进已有元素的包：元素位置不再
                // 唯一可辨，任何后续 Extract 都可能取出闭包 —— 直接拒绝。
                if held || (had && !was_empty) {
                    return Err(TraceErr::Reject);
                }
                st.pack[r as usize] = had;
            }
            Instruction::Extend(r, src) => {
                if st.reg[r as usize]
                    || st.pack[r as usize]
                    || st.reg[src as usize]
                    || st.pack[src as usize]
                {
                    return Err(TraceErr::Reject);
                }
                st.empty[r as usize] = false;
                st.pack[r as usize] = false;
            }
            Instruction::Extract(r, src, n) => {
                let had = st.pack[src as usize] && n == 1;
                kill!(r);
                if had {
                    st.reg[r as usize] = true;
                    def = Some(i);
                }
            }
            Instruction::Call(dst, f, args) => {
                if st.reg[args as usize] || st.pack[args as usize] {
                    return Err(TraceErr::Reject);
                }
                if st.reg[f as usize] {
                    if consumed || site.is_some() || flow.site.is_some() {
                        return Err(TraceErr::Reject);
                    }
                    consumed = true;
                    site = Some(CallSite {
                        block: b,
                        index: i,
                        dst,
                        f,
                        args,
                        def_index: def.unwrap_or(i),
                    });
                }
                kill!(dst);
                st.reg[f as usize] = false;
                kill!(args);
            }
            Instruction::Clear(a, bb) => {
                for r in a..=bb {
                    kill!(r);
                }
            }
            Instruction::Binary(_, r, l, rr) => {
                let mut obs = st.reg[l as usize];
                obs |= st.reg[rr as usize];
                kill!(r);
                if obs {
                    flow.observed = true;
                    st.reg[l as usize] = false;
                    st.reg[rr as usize] = false;
                }
            }
            Instruction::Unary(_, r, l)
            | Instruction::NumberTest(r, l)
            | Instruction::IteratorNext(r, l)
            | Instruction::ToString(r, l) => {
                let obs = st.reg[l as usize];
                kill!(r);
                if obs {
                    flow.observed = true;
                    st.reg[l as usize] = false;
                }
            }
            Instruction::NumberPrepare(r)
            | Instruction::NumberStep(r)
            | Instruction::IteratorPrepare(r)
            | Instruction::SetList(_, r, _) => {
                if st.reg[r as usize] || st.pack[r as usize] {
                    flow.observed = true;
                }
            }
        }
    }
    match host_f.blocks[b].terminator {
        Terminator::Jump(_) => {}
        Terminator::Branch { condition, .. } => {
            if st.reg[condition as usize] {
                flow.observed = true;
            }
        }
        Terminator::Return(r) => {
            if st.reg[r as usize] || st.pack[r as usize] {
                return Err(TraceErr::Reject);
            }
        }
        Terminator::TailCall {
            function,
            arguments,
        } => {
            if st.reg[function as usize] {
                return Err(TraceErr::Reject);
            }
            if st.reg[arguments as usize] || st.pack[arguments as usize] {
                return Err(TraceErr::Reject);
            }
        }
        Terminator::Unreachable => {
            return Err(TraceErr::Bad(Diagnostic::new(
                "K4 inliner: unterminated block in the traced host",
            )));
        }
    }
    if let Some(site) = site {
        if flow.site.is_some() {
            return Err(TraceErr::Reject);
        }
        flow.site = Some(site);
    }
    Ok(())
}

/// 拼接：把被调函数体在调用点展开。`remove_callee` 时同时摘掉闭包链并删除
/// 被调函数（删除后所有更大的 FunctionId 重编号）。
fn splice(module: &mut Module, c: usize, mode: Mode) -> Result<(), Diagnostic> {
    let parent = module.functions[c].parent.unwrap();
    let flow = match trace_closure(module, c) {
        Ok(flow) => flow,
        Err(TraceErr::Reject) => {
            return Err(Diagnostic::new(
                "K4 inliner: eligibility changed before splice",
            ))
        }
        Err(TraceErr::Bad(e)) => return Err(e),
    };
    let site = flow
        .site
        .clone()
        .expect("splice called without an eligible call site");
    let callee = module.functions[c].clone();
    let m = callee.registers as usize;
    let base = module.functions[parent].registers;
    if base as usize + m > MAX_REGISTERS as usize {
        return Err(Diagnostic::new("K4 inliner: register budget exceeded"));
    }

    // 常量池合并（按值去重），并登记新寄存器预算。
    let mut cmap = Vec::with_capacity(callee.constants.len());
    {
        let caller = &mut module.functions[parent];
        caller.registers = base + m as u16;
        for k in &callee.constants {
            let id = match caller.constants.iter().position(|e| e == k) {
                Some(id) => id,
                None => {
                    caller.constants.push(k.clone());
                    caller.constants.len() - 1
                }
            };
            cmap.push(id);
        }
    }
    let remap_reg = |r: u16| base + r;

    // 拆分调用块：Call 处换成「参数绑定 + 被调入口块」，其余后缀移入 cont 块。
    let (b, i, dst, freg, args, p) = (
        site.block,
        site.index,
        site.dst,
        site.f,
        site.args,
        callee.parameters,
    );
    let (suffix, term) = {
        let blk = &mut module.functions[parent].blocks[b];
        debug_assert!(matches!(
            blk.instructions[i],
            Instruction::Call(a, f2, c2) if a == dst && f2 == freg && c2 == args
        ));
        blk.instructions.remove(i);
        (
            blk.instructions.split_off(i),
            std::mem::replace(&mut blk.terminator, Terminator::Unreachable),
        )
    };
    let offset = module.functions[parent].blocks.len();
    let cont = offset + callee.blocks.len() - 1;

    // 被调块 1.. 依次追加（寄存器/常量/块号重映射，Return 变 写回+跳 cont）。
    for cb in &callee.blocks[1..] {
        let mut instrs = remap_block(&cb.instructions, &remap_reg, &cmap);
        let term = match &cb.terminator {
            Terminator::Jump(x) => Terminator::Jump(offset + x - 1),
            Terminator::Branch {
                condition,
                then_block,
                else_block,
            } => Terminator::Branch {
                condition: remap_reg(*condition),
                then_block: offset + then_block - 1,
                else_block: offset + else_block - 1,
            },
            Terminator::Return(r) => {
                instrs.push(Instruction::Move(dst, remap_reg(*r)));
                Terminator::Jump(cont)
            }
            Terminator::TailCall { .. } | Terminator::Unreachable => {
                return Err(Diagnostic::new("K4 inliner: unexpected callee terminator"));
            }
        };
        module.functions[parent].blocks.push(Block {
            instructions: instrs,
            terminator: term,
        });
    }
    module.functions[parent].blocks.push(Block {
        instructions: suffix,
        terminator: term,
    });
    // 调用块收尾：参数绑定 + 被调入口块。
    {
        let blk = &mut module.functions[parent].blocks[b];
        for j in 0..p {
            blk.instructions
                .push(Instruction::Extract(freg, args, j + 1));
            blk.instructions
                .push(Instruction::NewCell(base + j as u16, freg));
        }
        let first = &callee.blocks[0];
        blk.instructions
            .extend(remap_block(&first.instructions, &remap_reg, &cmap));
        blk.terminator = match &first.terminator {
            Terminator::Jump(x) => Terminator::Jump(offset + x - 1),
            Terminator::Branch {
                condition,
                then_block,
                else_block,
            } => Terminator::Branch {
                condition: remap_reg(*condition),
                then_block: offset + then_block - 1,
                else_block: offset + else_block - 1,
            },
            Terminator::Return(r) => {
                blk.instructions.push(Instruction::Move(dst, remap_reg(*r)));
                Terminator::Jump(cont)
            }
            Terminator::TailCall { .. } | Terminator::Unreachable => {
                return Err(Diagnostic::new("K4 inliner: unexpected callee terminator"));
            }
        };
    }

    if mode == Mode::Remove {
        // 摘掉闭包链：def 指令、出生指令、出生后紧邻的 `WriteCell(fcell, x)`。
        // 先以不可变视图算出删除集合（原始坐标），再降序删除。
        let birth = flow.birth.unwrap();
        let dels = {
            let blk: &Vec<Instruction> = &module.functions[parent].blocks[b].instructions;
            let mut dels = BTreeSet::new();
            dels.insert(site.def_index);
            dels.insert(birth.1);
            if let Some(Instruction::WriteCell(_, src)) = blk.get(birth.1 + 1) {
                let br = match blk[birth.1] {
                    Instruction::Closure(r, _) => r,
                    _ => unreachable!("birth is a closure instruction"),
                };
                if *src == br {
                    dels.insert(birth.1 + 1);
                }
            }
            dels
        };
        {
            let blk = &mut module.functions[parent].blocks[b];
            for &idx in dels.iter().rev() {
                blk.instructions.remove(idx);
            }
        }
        // 删除被调函数并重编号所有 FunctionId（> c 的全部 -1）。
        module.functions.remove(c);
        for f in &mut module.functions {
            if let Some(p2) = &mut f.parent {
                if *p2 > c {
                    *p2 -= 1;
                }
            }
            for blk in &mut f.blocks {
                for op in &mut blk.instructions {
                    if let Instruction::Closure(_, fid) = op {
                        if *fid > c {
                            *fid -= 1;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn remap_block(
    ops: &[Instruction],
    remap_reg: &impl Fn(u16) -> u16,
    cmap: &[usize],
) -> Vec<Instruction> {
    ops.iter()
        .map(|op| remap_instruction(op, remap_reg, cmap))
        .collect()
}

/// 指令重映射：所有寄存器走 `remap_reg`，常量 id 走 `cmap`。被调函数里
/// 不可能出现 `Closure`（结构拒绝），出现即内部错误。
fn remap_instruction(op: &Instruction, remap: &impl Fn(u16) -> u16, cmap: &[usize]) -> Instruction {
    match *op {
        Instruction::Constant(r, k) => Instruction::Constant(remap(r), cmap[k]),
        Instruction::Nil(r) => Instruction::Nil(remap(r)),
        Instruction::Move(a, b) => Instruction::Move(remap(a), remap(b)),
        Instruction::NewCell(a, b) => Instruction::NewCell(remap(a), remap(b)),
        Instruction::ReadCell(a, b) => Instruction::ReadCell(remap(a), remap(b)),
        Instruction::WriteCell(a, b) => Instruction::WriteCell(remap(a), remap(b)),
        Instruction::ReadUpvalue(r, u) => Instruction::ReadUpvalue(remap(r), u),
        Instruction::WriteUpvalue(u, r) => Instruction::WriteUpvalue(u, remap(r)),
        Instruction::ReadGlobal(r, k) => Instruction::ReadGlobal(remap(r), cmap[k]),
        Instruction::WriteGlobal(k, r) => Instruction::WriteGlobal(cmap[k], remap(r)),
        Instruction::NewTable(r) => Instruction::NewTable(remap(r)),
        Instruction::GetTable(a, b, c2) => Instruction::GetTable(remap(a), remap(b), remap(c2)),
        Instruction::SetTable(a, b, c2) => Instruction::SetTable(remap(a), remap(b), remap(c2)),
        Instruction::Method(a, b, c2) => Instruction::Method(remap(a), remap(b), remap(c2)),
        Instruction::NewPack(r) => Instruction::NewPack(remap(r)),
        Instruction::Push(a, b) => Instruction::Push(remap(a), remap(b)),
        Instruction::Extend(a, b) => Instruction::Extend(remap(a), remap(b)),
        Instruction::Extract(a, b, n) => Instruction::Extract(remap(a), remap(b), n),
        Instruction::Varargs(r) => Instruction::Varargs(remap(r)),
        Instruction::Call(a, b, c2) => Instruction::Call(remap(a), remap(b), remap(c2)),
        Instruction::Closure(_, _) => {
            unreachable!("K4 inliner: callee must not contain closures")
        }
        Instruction::Clear(a, b) => Instruction::Clear(remap(a), remap(b)),
        Instruction::Binary(op, a, b, c2) => Instruction::Binary(op, remap(a), remap(b), remap(c2)),
        Instruction::Unary(op, a, b) => Instruction::Unary(op, remap(a), remap(b)),
        Instruction::NumberPrepare(r) => Instruction::NumberPrepare(remap(r)),
        Instruction::NumberStep(r) => Instruction::NumberStep(remap(r)),
        Instruction::NumberTest(a, b) => Instruction::NumberTest(remap(a), remap(b)),
        Instruction::IteratorPrepare(r) => Instruction::IteratorPrepare(remap(r)),
        Instruction::IteratorNext(a, b) => Instruction::IteratorNext(remap(a), remap(b)),
        Instruction::SetList(a, b, c2) => Instruction::SetList(remap(a), remap(b), remap(c2)),
        Instruction::ToString(a, b) => Instruction::ToString(remap(a), remap(b)),
        Instruction::Export(a, b, c2) => Instruction::Export(remap(a), remap(b), remap(c2)),
        Instruction::Freeze(r) => Instruction::Freeze(remap(r)),
    }
}

// ---------------------------------------------------------------------------
// 确定性兄弟重排
// ---------------------------------------------------------------------------

/// splitmix64 单步：原索引 -> 确定性散列。与种子无关，保证公共 .obf 稳定。
fn order_hash(orig: usize) -> u64 {
    let mut z = (orig as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z ^= z >> 30;
    z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn reorder(module: &mut Module) -> Result<(), Diagnostic> {
    let n = module.functions.len();
    if n <= 1 {
        return Ok(());
    }
    let mut children = vec![Vec::new(); n];
    for (i, f) in module.functions.iter().enumerate().skip(1) {
        children[f.parent.unwrap()].push(i);
    }
    let mut depth = vec![0usize; n];
    let mut stack = vec![0usize];
    while let Some(u) = stack.pop() {
        for &v in &children[u] {
            depth[v] = depth[u] + 1;
            stack.push(v);
        }
    }
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| (depth[i], order_hash(i), i));
    debug_assert_eq!(order[0], 0, "entry must stay first");
    let mut map = vec![0usize; n];
    for (new, &old) in order.iter().enumerate() {
        map[old] = new;
    }
    let functions: Vec<Function> = order
        .iter()
        .map(|&old| {
            let mut f = module.functions[old].clone();
            if let Some(p) = f.parent {
                f.parent = Some(map[p]);
            }
            for block in &mut f.blocks {
                for op in &mut block.instructions {
                    if let Instruction::Closure(_, fid) = op {
                        *fid = map[*fid];
                    }
                }
            }
            f
        })
        .collect();
    module.functions = functions;
    module.entry = map[module.entry];
    debug_assert_eq!(module.entry, 0);
    Ok(())
}

// ---------------------------------------------------------------------------
// fail-closed 不变量
// ---------------------------------------------------------------------------

/// 变换后的模块必须满足编码器的全部结构约束；任何一条不满足都让编译失败，
/// 而不是把坏 IR 写进公共字节。
fn validate_invariants(module: &Module) -> Result<(), Diagnostic> {
    let bad = |why: &str| Err(Diagnostic::new(format!("K4 transform: {why}")));
    if module.functions.is_empty() || module.entry != 0 {
        return bad("entry must be function 0");
    }
    for (i, f) in module.functions.iter().enumerate() {
        if i == 0 {
            if f.parent.is_some() {
                return bad("entry has a parent");
            }
        } else {
            let p = f
                .parent
                .ok_or_else(|| Diagnostic::new("K4 transform: function without parent"))?;
            if p >= i {
                return bad("parent must be indexed before its child");
            }
        }
        if f.registers == 0 || f.registers > MAX_REGISTERS {
            return bad("register count out of range");
        }
        if f.captures.len() > 256 {
            return bad("too many captures");
        }
        if f.constants.len() > 65_536 {
            return bad("constant pool out of range");
        }
        for block in &f.blocks {
            for op in block.instructions.iter() {
                let regs: Vec<u16> = match op {
                    Instruction::Constant(r, _)
                    | Instruction::Nil(r)
                    | Instruction::Varargs(r)
                    | Instruction::NewTable(r)
                    | Instruction::NewPack(r)
                    | Instruction::ReadGlobal(r, _)
                    | Instruction::ReadUpvalue(r, _)
                    | Instruction::NumberPrepare(r)
                    | Instruction::NumberStep(r)
                    | Instruction::IteratorPrepare(r)
                    | Instruction::Freeze(r) => vec![*r],
                    Instruction::Move(a, b)
                    | Instruction::NewCell(a, b)
                    | Instruction::ReadCell(a, b)
                    | Instruction::WriteCell(a, b)
                    | Instruction::Push(a, b)
                    | Instruction::Extend(a, b)
                    | Instruction::Clear(a, b)
                    | Instruction::NumberTest(a, b)
                    | Instruction::IteratorNext(a, b)
                    | Instruction::ToString(a, b) => vec![*a, *b],
                    Instruction::WriteUpvalue(_, r) => vec![*r],
                    Instruction::WriteGlobal(_, r) => vec![*r],
                    Instruction::GetTable(a, b, c2)
                    | Instruction::SetTable(a, b, c2)
                    | Instruction::Method(a, b, c2)
                    | Instruction::Call(a, b, c2)
                    | Instruction::SetList(a, b, c2)
                    | Instruction::Export(a, b, c2)
                    | Instruction::Binary(_, a, b, c2) => vec![*a, *b, *c2],
                    Instruction::Extract(a, b, _) => vec![*a, *b],
                    Instruction::Unary(_, a, b) => vec![*a, *b],
                    Instruction::Closure(r, fid) => {
                        if *fid >= module.functions.len() {
                            return bad("closure references a missing prototype");
                        }
                        if module.functions[*fid].parent != Some(i) {
                            return bad("closure of a foreign child");
                        }
                        vec![*r]
                    }
                };
                for r in regs {
                    if r >= f.registers {
                        return bad("register out of range");
                    }
                }
                match op {
                    Instruction::Constant(_, k)
                    | Instruction::ReadGlobal(_, k)
                    | Instruction::WriteGlobal(k, _) => {
                        if *k >= f.constants.len() {
                            return bad("constant id out of range");
                        }
                    }
                    Instruction::ReadUpvalue(_, u) | Instruction::WriteUpvalue(u, _) => {
                        if *u as usize >= f.captures.len() {
                            return bad("upvalue id out of range");
                        }
                    }
                    Instruction::Extract(_, _, n) if *n == 0 => {
                        return bad("extract index must be 1-based");
                    }
                    _ => {}
                }
            }
            match &block.terminator {
                Terminator::Unreachable => return bad("unterminated block"),
                Terminator::Jump(b) if *b >= f.blocks.len() => {
                    return bad("block successor out of range");
                }
                Terminator::Branch {
                    then_block,
                    else_block,
                    ..
                } => {
                    if *then_block >= f.blocks.len() || *else_block >= f.blocks.len() {
                        return bad("block successor out of range");
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 单元测试（纯结构；双目标语义门在 vm::custom::tests::k4 与全矩阵）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir;
    use crate::Target;

    fn module(source: &str) -> Module {
        ir::compile(source, Target::Lua51).unwrap()
    }

    fn plain_module(source: &str) -> Module {
        ir::lower(&crate::parse(source, Target::Lua51).unwrap()).unwrap()
    }

    /// 入口里剩余的 `Call` 条数（内联成功应减少/归零）。
    fn entry_calls(m: &Module) -> usize {
        m.functions[0]
            .blocks
            .iter()
            .flat_map(|b| b.instructions.iter())
            .filter(|op| matches!(op, Instruction::Call(_, _, _)))
            .count()
    }

    fn closure_exists(m: &Module, c: usize) -> bool {
        m.functions.iter().any(|f| {
            f.blocks.iter().any(|b| {
                b.instructions
                    .iter()
                    .any(|op| matches!(op, Instruction::Closure(_, t) if *t == c))
            })
        })
    }

    #[test]
    fn inliner_splices_sole_use_callee_and_removes_it() {
        let src = "local function add(x) return x + 10 end\nlocal r = add(3)\nreturn r\n";
        let m = module(src);
        // 被调函数被删除：只剩入口。
        assert_eq!(m.functions.len(), 1, "callee should be removed");
        assert_eq!(entry_calls(&m), 0, "call site must be spliced away");
        // 被调常量 10 并入入口常量池。
        assert!(m.functions[0].constants.iter().any(|c| matches!(
            c,
            crate::ir::Constant::Number(bits) if f64::from_bits(*bits) == 10.0
        )));
    }

    #[test]
    fn inliner_keeps_callee_when_value_is_observed() {
        // `not add` 观察了闭包值：只能 Keep（拼接但不删函数）。
        let src = "local function add(x) return x + 10 end\nlocal flag = not add\nlocal r = add(3)\nreturn r\n";
        let m = module(src);
        assert_eq!(m.functions.len(), 2, "observed closure keeps the callee");
        assert_eq!(entry_calls(&m), 0, "the single call must still be spliced");
        assert!(closure_exists(&m, 1));
    }

    #[test]
    fn inliner_rejects_captures_varargs_children_and_second_calls() {
        // 捕获：闭包引用外层变量。
        let src =
            "local k = 5\nlocal function add(x) return x + k end\nlocal r = add(1)\nreturn r\n";
        let m = module(src);
        assert_eq!(m.functions.len(), 2, "capturing callee must not be inlined");
        assert!(entry_calls(&m) >= 1);
        // 变参。
        let src = "local function va(...) return ... end\nlocal r = va(1)\nreturn r\n";
        let m = module(src);
        assert_eq!(m.functions.len(), 2, "variadic callee must not be inlined");
        assert!(entry_calls(&m) >= 1);
        // 子原型。
        let src =
            "local function mk() return function() return 1 end end\nlocal r = mk()\nreturn r\n";
        let m = module(src);
        assert!(
            m.functions.len() >= 2,
            "callee with children must not be inlined"
        );
        assert!(entry_calls(&m) >= 1);
        // 两次调用。
        let src = "local function add(x) return x + 1 end\nlocal a = add(1)\nlocal b = add(2)\nreturn a + b\n";
        let m = module(src);
        assert_eq!(
            m.functions.len(),
            2,
            "multi-call callee must not be inlined"
        );
        assert!(entry_calls(&m) >= 2);
    }

    #[test]
    fn inliner_leaves_tail_calls_alone() {
        // `return add(3)` 降低为 TailCall，不是可内联的调用点。
        let src = "local function add(x) return x + 10 end\nreturn add(3)\n";
        let m = module(src);
        assert_eq!(m.functions.len(), 2, "tail-called callee stays");
    }

    #[test]
    fn reorder_keeps_entry_first_and_parents_before_children() {
        let src = concat!(
            "local function a() return 1 end\n",
            "local function b() return a() + 1 end\n",
            "local function c() return b() + 1 end\n",
            "local function d() return c() + 1 end\n",
            "local function e() return d() + 1 end\n",
            "local function f() return e() + 1 end\n",
            "return f()\n",
        );
        let m = module(src);
        assert_eq!(m.functions.len(), 7);
        assert_eq!(m.entry, 0);
        for (i, f) in m.functions.iter().enumerate().skip(1) {
            assert!(f.parent.unwrap() < i, "parent before child at {i}");
        }
        // 重排真的发生：原型顺序指纹（每函数的指令总数序列）与 lowering 原序不同。
        let fingerprint = |fs: &[Function]| -> Vec<usize> {
            fs.iter()
                .map(|f| {
                    f.blocks.iter().map(|b| b.instructions.len()).sum::<usize>()
                        + f.constants.len() * 1000
                })
                .collect()
        };
        let plain = plain_module(src);
        assert_ne!(
            fingerprint(&plain.functions),
            fingerprint(&m.functions),
            "reorder should change the prototype order"
        );
        // 确定性：再来一遍结果相同。
        let again = module(src);
        assert_eq!(fingerprint(&m.functions), fingerprint(&again.functions));
    }

    #[test]
    fn transform_is_deterministic_without_seed() {
        let src = concat!(
            "local function a(x) return x * 2 end\n",
            "local function b(x) return a(x) + 1 end\n",
            "local t = {}\n",
            "for i = 1, 3 do t[i] = b(i) end\n",
            "return t[2]\n",
        );
        let a = ir::compile(src, Target::Lua51).unwrap();
        let b = ir::compile(src, Target::Lua51).unwrap();
        assert_eq!(a, b);
        let l = ir::compile(src, Target::Luau).unwrap();
        let r = ir::compile(src, Target::Luau).unwrap();
        assert_eq!(l, r);
    }

    #[test]
    fn inlined_programs_preserve_constants_and_register_bounds() {
        let src = "local function mix(a, b) local t = a * b return t + a - b end\nlocal x = mix(6, 7)\nlocal y = x + 2\nreturn x + y\n";
        let m = module(src);
        for f in &m.functions {
            assert!(f.registers <= 256);
            for block in &f.blocks {
                for op in &block.instructions {
                    if let Instruction::Constant(r, k) = op {
                        assert!(*k < f.constants.len());
                        let _ = r;
                    }
                }
            }
        }
        // 单用调用被拼接，被调函数删除。
        assert_eq!(m.functions.len(), 1);
        assert_eq!(entry_calls(&m), 0);
    }
}
