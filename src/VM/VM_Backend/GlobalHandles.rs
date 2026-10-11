//! 外部 API 名 handle 映射（构建期 IR 变换）。
//!
//! 背景：源码里的全局名（外部 API 名/全局变量名）编译后是 GETGLOBAL/SETGLOBAL
//! 指令引用的**名字字符串常量**，与用户字符串字面量同池加密——主常量池被整池
//! 恢复时，API 名一目了然。
//!
//! 本 pass 在字节码序列化前做三件事：
//! 1. 收集所有原型里 GETGLOBAL/SETGLOBAL 家族引用的名字，逐名分配随机 32 位
//!    handle（全程序唯一）；
//! 2. 把这些指令的常量操作数改写为「新补的数字常量槽（值=handle）」——线上
//!    字节码从此只含数字，不再含名字；
//! 3. 原型内只被全局指令引用的孤儿名字槽替换为诱饵数字（名字彻底离池）；
//!    仍被其他指令引用的名字（如 `_G["print"]` 的字面量用法）按普通字符串保留。
//!
//! 返回 `(handle, 名字字节)` 注册表（按 handle 排序，确定性），经
//! `VmContext.global_names` 传给 Generator：Generator 在产物里发射**独立名字
//! 保险库 + 解码器**（复用既有单根 KDF，独立组号，每次取用现解、不落明文缓存），
//! 运行期 GETGLOBAL/SETGLOBAL 的键经解码器现解。

use crate::BytecodeCompiler::ir::chunk::{Chunk, Constant};
use crate::BytecodeCompiler::ir::opcode::Opcode;
use rand::Rng;
use std::collections::HashMap;

/// handle 取值区间：与其他「看起来像句柄」的魔数同带，池内数字外观一致。
const HANDLE_LO: u32 = 0x0100_0000;
const HANDLE_HI: u32 = 0x7FFF_FFFF;

/// 全局名引用的指令族（本编译器前端只会产出 GetGlobal/SetGlobal，
/// Str 变体为防御性覆盖）。
fn is_global_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::GetGlobal | Opcode::SetGlobal | Opcode::GetGlobalStr | Opcode::SetGlobalStr
    )
}

/// 对整个原型树应用 handle 映射；返回 (handle, 名字) 注册表。
/// 无全局名引用时返回空表（Generator 侧跳过保险库发射）。
pub fn apply_global_handles(root: &mut Chunk) -> Vec<(u32, Vec<u8>)> {
    let mut rng = rand::rng();
    let mut handles: HashMap<Vec<u8>, u32> = HashMap::new();
    collect(root, &mut handles, &mut rng);
    if handles.is_empty() {
        return Vec::new();
    }
    rewrite(root, &handles, &mut rng);
    let mut out: Vec<(u32, Vec<u8>)> = handles.into_iter().map(|(name, h)| (h, name)).collect();
    out.sort_by_key(|(h, _)| *h);
    out
}

fn fresh_handle(used: &HashMap<Vec<u8>, u32>, rng: &mut impl Rng) -> u32 {
    loop {
        let h = rng.random_range(HANDLE_LO..HANDLE_HI);
        if !used.values().any(|&v| v == h) {
            return h;
        }
    }
}

fn collect(chunk: &Chunk, handles: &mut HashMap<Vec<u8>, u32>, rng: &mut impl Rng) {
    for inst in &chunk.instructions {
        if is_global_op(inst.opcode) {
            if let Some(Constant::String(name)) = chunk.constants.get(inst.b as usize) {
                if !handles.contains_key(name) {
                    let h = fresh_handle(handles, rng);
                    handles.insert(name.clone(), h);
                }
            }
        }
    }
    for proto in &chunk.protos {
        collect(proto, handles, rng);
    }
}

/// RK 编码：操作数值 >= 128 表示常量槽 (v-128)（见 OpcodeBuilder::rk）。
fn rk_ref(refs: &mut [usize], v: i32) {
    if v >= 128 {
        let s = (v - 128) as usize;
        if s < refs.len() {
            refs[s] += 1;
        }
    }
}

/// 保守统计常量槽引用：宁可多保一个字符串，不可误删。
/// 显式常量索引字段按其指令族记账；Closure/ExtraArg/LoadKx 的非数
/// 字段（原型索引/扩展参数）不记；其余字段按 RK 近似。
fn count_refs(chunk: &Chunk) -> Vec<usize> {
    let mut refs = vec![0usize; chunk.constants.len()];
    for inst in &chunk.instructions {
        match inst.opcode {
            Opcode::LoadK | Opcode::GetImport => {
                if inst.b >= 0 && (inst.b as usize) < refs.len() {
                    refs[inst.b as usize] += 1;
                }
            }
            Opcode::GetGlobal
            | Opcode::SetGlobal
            | Opcode::GetGlobalStr
            | Opcode::SetGlobalStr => {
                if inst.b >= 0 && (inst.b as usize) < refs.len() {
                    refs[inst.b as usize] += 1;
                }
            }
            Opcode::NameCall | Opcode::GetTableStr | Opcode::SetTableStr => {
                if inst.c >= 0 && (inst.c as usize) < refs.len() {
                    refs[inst.c as usize] += 1;
                }
                rk_ref(&mut refs, inst.b);
            }
            Opcode::Closure | Opcode::ExtraArg | Opcode::LoadKx => {}
            _ => {
                rk_ref(&mut refs, inst.b);
                rk_ref(&mut refs, inst.c);
            }
        }
    }
    refs
}

fn rewrite(chunk: &mut Chunk, handles: &HashMap<Vec<u8>, u32>, rng: &mut impl Rng) {
    // ① 找出要改写的指令（先收集再动常量池，避免借冲突）
    let mut fixes: Vec<(usize, usize, u32)> = Vec::new();
    for (pc, inst) in chunk.instructions.iter().enumerate() {
        if is_global_op(inst.opcode) {
            if let Some(Constant::String(name)) = chunk.constants.get(inst.b as usize) {
                if let Some(&h) = handles.get(name) {
                    fixes.push((pc, inst.b as usize, h));
                }
            }
        }
    }
    // ② 逐条：补 handle 数字槽，改指向
    for (pc, old_idx, h) in &fixes {
        chunk.constants.push(Constant::Number(*h as f64));
        let new_idx = chunk.constants.len() - 1;
        chunk.instructions[*pc].b = new_idx as i32;
        let _ = old_idx;
    }
    // ③ 改写后的引用统计；孤儿名字槽换成诱饵数字
    let refs = count_refs(chunk);
    let mut seen: Vec<usize> = Vec::new();
    for (_, old_idx, _) in &fixes {
        if seen.contains(old_idx) {
            continue;
        }
        seen.push(*old_idx);
        if refs[*old_idx] == 0 {
            let decoy = rng.random_range(HANDLE_LO..HANDLE_HI) as f64;
            chunk.constants[*old_idx] = Constant::Number(decoy);
        }
    }
    for proto in &mut chunk.protos {
        rewrite(proto, handles, rng);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BytecodeCompiler::ir::instruction::Instruction;

    fn inst(op: Opcode, a: u8, b: i32, c: i32) -> Instruction {
        Instruction {
            data: 0,
            opcode: op,
            a,
            b,
            c,
            line: 0,
            v_opcode: None,
            is_junk: false,
        }
    }

    fn chunk(constants: Vec<Constant>, instructions: Vec<Instruction>) -> Chunk {
        Chunk {
            name: "test".into(),
            line_defined: 0,
            last_line_defined: 0,
            upvalue_count: 0,
            param_count: 0,
            is_vararg: 0,
            max_stack: 8,
            instructions,
            constants,
            protos: Vec::new(),
            lines: Vec::new(),
            locals: Vec::new(),
            upvalues: Vec::new(),
        }
    }

    #[test]
    fn global_names_become_handles_and_orphans_decoyed() {
        // k0="print"（仅 GETGLOBAL 用）, k1="hello"（仅 LOADK 用）, k2="math"（GETGLOBAL+SETGLOBAL 用）
        let mut c = chunk(
            vec![
                Constant::String(b"print".to_vec()),
                Constant::String(b"hello".to_vec()),
                Constant::String(b"math".to_vec()),
            ],
            vec![
                inst(Opcode::GetGlobal, 1, 0, 0),
                inst(Opcode::LoadK, 2, 1, 0),
                inst(Opcode::GetGlobal, 3, 2, 0),
                inst(Opcode::SetGlobal, 3, 2, 0),
            ],
        );
        let reg = apply_global_handles(&mut c);
        assert_eq!(reg.len(), 2);
        // 注册表含 print/math，不含 hello
        let names: Vec<&[u8]> = reg.iter().map(|(_, n)| n.as_slice()).collect();
        assert!(names.contains(&(b"print".as_slice())));
        assert!(names.contains(&(b"math".as_slice())));
        assert!(!names.contains(&(b"hello".as_slice())));
        // handle 唯一且在区间内
        assert_ne!(reg[0].0, reg[1].0);
        for (h, _) in &reg {
            assert!((HANDLE_LO..HANDLE_HI).contains(h));
        }
        // 槽 0（print）变诱饵数字；槽 1（hello）仍是字符串
        assert!(matches!(c.constants[0], Constant::Number(_)));
        assert!(matches!(c.constants[1], Constant::String(_)));
        // GETGLOBAL/SETGLOBAL 指向新的数字槽（值=handle）
        let h_print = reg.iter().find(|(_, n)| n == b"print").unwrap().0;
        let h_math = reg.iter().find(|(_, n)| n == b"math").unwrap().0;
        let b0 = c.instructions[0].b as usize;
        assert_eq!(c.constants[b0], Constant::Number(h_print as f64));
        let b3 = c.instructions[3].b as usize;
        assert_eq!(c.constants[b3], Constant::Number(h_math as f64));
        // LOADK "hello" 未被动
        assert_eq!(c.instructions[1].b, 1);
    }

    #[test]
    fn name_also_used_as_value_is_kept() {
        // "print" 同时被 GETGLOBAL 与 LOADK 引用 → 字符串保留，指令仍改指 handle
        let mut c = chunk(
            vec![Constant::String(b"print".to_vec())],
            vec![inst(Opcode::GetGlobal, 1, 0, 0), inst(Opcode::LoadK, 2, 0, 0)],
        );
        let reg = apply_global_handles(&mut c);
        assert_eq!(reg.len(), 1);
        assert!(matches!(c.constants[0], Constant::String(_)));
        let b0 = c.instructions[0].b as usize;
        assert_eq!(c.constants[b0], Constant::Number(reg[0].0 as f64));
        assert_eq!(c.instructions[1].b, 0);
    }

    #[test]
    fn nested_proto_and_no_globals() {
        // 子原型里有全局引用；主原型没有
        let inner = chunk(
            vec![Constant::String(b"io".to_vec())],
            vec![inst(Opcode::GetGlobal, 1, 0, 0)],
        );
        let mut c = chunk(vec![], vec![inst(Opcode::Return, 0, 0, 0)]);
        c.protos.push(inner);
        let reg = apply_global_handles(&mut c);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg[0].1, b"io".to_vec());
        assert!(matches!(c.protos[0].constants[0], Constant::Number(_)));
        // 无全局引用时返回空表
        let mut c2 = chunk(vec![], vec![inst(Opcode::Return, 0, 0, 0)]);
        assert!(apply_global_handles(&mut c2).is_empty());
    }
}
