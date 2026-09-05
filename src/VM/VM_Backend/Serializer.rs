use crate::BytecodeCompiler::ir::chunk::{Chunk, Constant};
use crate::VM::VM_Backend::Context::VmContext;

pub struct Serializer;

impl Serializer {
    pub fn serialize(chunk: &Chunk, ctx: &VmContext) -> Vec<u8> {
        let mut bytes = Vec::new();

        Self::write_string(&mut bytes, chunk.name.as_bytes());
        
        bytes.extend_from_slice(&chunk.line_defined.to_le_bytes());
        bytes.extend_from_slice(&chunk.last_line_defined.to_le_bytes());
        
        bytes.push(chunk.upvalue_count);
        bytes.push(chunk.param_count);
        bytes.push(chunk.is_vararg);
        bytes.push(chunk.max_stack);

        let inst_count = chunk.instructions.len() as u32;
        bytes.extend_from_slice(&inst_count.to_le_bytes());

        for inst in &chunk.instructions {
            let mapped_op = ctx.opcode_map[inst.opcode as usize];
            bytes.push(mapped_op);
            bytes.push(inst.a);
            bytes.extend_from_slice(&inst.b.to_le_bytes());
            bytes.extend_from_slice(&inst.c.to_le_bytes());
        }

        let const_count = chunk.constants.len() as u32;
        bytes.extend_from_slice(&const_count.to_le_bytes());

        for constant in &chunk.constants {
            match constant {
                Constant::Nil => {
                    bytes.push(0);
                }
                Constant::Boolean(b) => {
                    bytes.push(1);
                    bytes.push(if *b { 1 } else { 0 });
                }
                Constant::Number(n) => {
                    bytes.push(2);
                    bytes.extend_from_slice(&n.to_bits().to_le_bytes());
                }
                Constant::String(s) => {
                    bytes.push(3);
                    Self::write_string(&mut bytes, s);
                }
            }
        }

        let p_count = chunk.protos.len() as u32;
        bytes.extend_from_slice(&p_count.to_le_bytes());
        for p in &chunk.protos {
            bytes.extend(&Self::serialize(p, ctx));
        }

        let l_count = chunk.lines.len() as u32;
        bytes.extend_from_slice(&l_count.to_le_bytes());
        for l in &chunk.lines {
            bytes.extend_from_slice(&l.to_le_bytes());
        }

        let loc_count = chunk.locals.len() as u32;
        bytes.extend_from_slice(&loc_count.to_le_bytes());
        for loc in &chunk.locals {
            Self::write_string(&mut bytes, loc.name.as_bytes());
            bytes.extend_from_slice(&loc.start_pc.to_le_bytes());
            bytes.extend_from_slice(&loc.end_pc.to_le_bytes());
        }

        let upv_count = chunk.upvalues.len() as u32;
        bytes.extend_from_slice(&upv_count.to_le_bytes());
        for upv in &chunk.upvalues {
            Self::write_string(&mut bytes, upv.as_bytes());
        }

        bytes
    }

    fn write_string(bytes: &mut Vec<u8>, s_bytes: &[u8]) {
        let len = s_bytes.len() as u32;
        bytes.extend_from_slice(&len.to_le_bytes());
        if len > 0 {
            bytes.extend_from_slice(s_bytes);
        }
    }
}