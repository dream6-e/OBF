use crate::BytecodeCompiler::ir::chunk::{Chunk, Constant, Local};
use crate::BytecodeCompiler::ir::instruction::Instruction;
use crate::BytecodeCompiler::ir::opcode::Opcode;
use std::string::String;
use rand::{SeedableRng, Rng};
use rand::rngs::StdRng;

#[derive(Clone, Copy, Debug)]
pub struct InstructionLayout {
    pub size_op: u32,
    pub size_a: u32,
    pub size_b: u32,
    pub size_c: u32,
    pub size_bx: u32,
    pub pos_op: u32,
    pub pos_a: u32,
    pub pos_b: u32,
    pub pos_c: u32,
    pub pos_bx: u32,
    pub xor_key: u32,
    pub max_sbx: i32,
    pub op_encode_map: [u8; 90],
    pub op_decode_map: [Opcode; 90],
}

impl InstructionLayout {
    pub fn from_seed(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let size_op = rng.random_range(7..=8);
        let size_a = 8;
        let size_bx = 32 - size_op - size_a;
        let size_b = size_bx / 2;
        let size_c = size_bx - size_b;
        let mut blocks = vec![0, 1, 2];
        for i in (1..3).rev() {
            let j = rng.random_range(0..=i);
            blocks.swap(i, j);
        }
        let sizes = [size_op, size_a, size_bx];
        let mut block_positions = [0; 3];
        let mut current_pos = 0;
        for &b in &blocks {
            block_positions[b] = current_pos;
            current_pos += sizes[b];
        }
        let pos_op = block_positions[0];
        let pos_a = block_positions[1];
        let pos_bx = block_positions[2];
        let b_first = rng.random::<bool>();
        let (pos_b, pos_c) = if b_first {
            (pos_bx, pos_bx + size_b)
        } else {
            (pos_bx + size_c, pos_bx)
        };
        let xor_key = rng.random::<u32>();
        let max_sbx = ((1 << (size_bx - 1)) - 1) as i32;
        let mut op_encode_map = [0u8; 90];
        for i in 0..90 {
            op_encode_map[i] = i as u8;
        }
        for i in (1..90).rev() {
            let j = rng.random_range(0..=i);
            op_encode_map.swap(i, j);
        }
        let mut op_decode_map = [Opcode::Move; 90];
        for (i, &encoded) in op_encode_map.iter().enumerate() {
            let op = unsafe { std::mem::transmute::<u8, Opcode>(i as u8) };
            op_decode_map[encoded as usize] = op;
        }
        Self {
            size_op,
            size_a,
            size_b,
            size_c,
            size_bx,
            pos_op,
            pos_a,
            pos_b,
            pos_c,
            pos_bx,
            xor_key,
            max_sbx,
            op_encode_map,
            op_decode_map,
        }
    }

    pub fn decode_opcode(&self, val: u8) -> Option<Opcode> {
        if (val as usize) < 90 {
            Some(self.op_decode_map[val as usize])
        } else {
            None
        }
    }
}

pub struct Deserializer {
    data: Vec<u8>,
    pos: usize,
    big_endian: bool,
    size_size_t: u8,
    size_number: u8,
    layout: Option<InstructionLayout>,
    global_strings: Vec<Vec<u8>>,
    global_numbers: Vec<f64>,
}

impl Deserializer {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: 0,
            big_endian: false,
            size_size_t: 4,
            size_number: 8,
            layout: None,
            global_strings: Vec::new(),
            global_numbers: Vec::new(),
        }
    }

    #[inline(always)]
    fn read_bytes(&mut self, len: usize) -> Vec<u8> {
        if self.pos + len > self.data.len() {
            panic!("Unexpected EOF");
        }
        let res = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        res
    }

    fn read_u8(&mut self) -> u8 {
        self.read_bytes(1)[0]
    }

    fn read_u8_dec(&mut self, k1: &mut u8, k2: &mut u8, k3: &mut u8, k4: &mut u8) -> u8 {
        let enc = self.read_u8();
        let mut dec = enc.wrapping_sub(0x42);
        dec = dec ^ *k4;
        dec = dec.rotate_right((*k3 % 8) as u32);
        dec = dec.wrapping_add(*k2);
        dec = dec ^ *k1;
        let orig = dec;
        
        *k1 = k1.wrapping_add(orig).rotate_left(1).wrapping_add(0x1B);
        *k2 = k2.wrapping_mul(3).wrapping_add(enc).rotate_right(2);
        *k3 = *k3 ^ k1.wrapping_sub(*k4);
        *k4 = k4.wrapping_add(*k2).rotate_left(3);
        
        orig
    }

    fn read_i32_dec(&mut self, k1: &mut u8, k2: &mut u8, k3: &mut u8, k4: &mut u8) -> i32 {
        let mut b = [0u8; 4];
        for i in 0..4 { b[i] = self.read_u8_dec(k1, k2, k3, k4); }
        if self.big_endian {
            i32::from_be_bytes(b)
        } else {
            i32::from_le_bytes(b)
        }
    }

    fn read_u64_dec(&mut self, k1: &mut u8, k2: &mut u8, k3: &mut u8, k4: &mut u8) -> u64 {
        let mut b = [0u8; 8];
        for i in 0..8 { b[i] = self.read_u8_dec(k1, k2, k3, k4); }
        if self.big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        }
    }

    fn read_size_t_dec(&mut self, k1: &mut u8, k2: &mut u8, k3: &mut u8, k4: &mut u8) -> usize {
        if self.size_size_t == 8 {
            let mut b = [0u8; 8];
            for i in 0..8 { b[i] = self.read_u8_dec(k1, k2, k3, k4); }
            if self.big_endian {
                u64::from_be_bytes(b) as usize
            } else {
                u64::from_le_bytes(b) as usize
            }
        } else {
            self.read_i32_dec(k1, k2, k3, k4) as usize
        }
    }

    fn read_f64_dec(&mut self, k1: &mut u8, k2: &mut u8, k3: &mut u8, k4: &mut u8) -> f64 {
        let mut b = [0u8; 8];
        for i in 0..8 { b[i] = self.read_u8_dec(k1, k2, k3, k4); }
        let bits = if self.big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        };
        f64::from_bits(bits)
    }

    fn read_u32(&mut self) -> u32 {
        let b = self.read_bytes(4);
        if self.big_endian {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
    }

    fn read_i32(&mut self) -> i32 {
        self.read_u32() as i32
    }

    fn read_size_t(&mut self) -> usize {
        if self.size_size_t == 8 {
            let b = self.read_bytes(8);
            if self.big_endian {
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) as usize
            } else {
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) as usize
            }
        } else {
            self.read_u32() as usize
        }
    }

    fn read_f64(&mut self) -> f64 {
        let b = self.read_bytes(8);
        let bits = if self.big_endian {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        };
        f64::from_bits(bits)
    }

    fn read_string_bytes(&mut self) -> Vec<u8> {
        let size = self.read_size_t();
        if size == 0 {
            return Vec::new();
        }
        let bytes = self.read_bytes(size);
        bytes[0..bytes.len() - 1].to_vec()
    }

    fn read_string_utf8(&mut self) -> String {
        let bytes = self.read_string_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn decode_file(&mut self) -> Chunk {
        let header = self.read_bytes(16);
        if &header[0..7] != b"\x1bKRYVEX" {
            panic!("Invalid Lua Header");
        }
        if header[7] != 0xCC {
            panic!("Corrupted Header");
        }
        if header[8] != 0x3F {
            panic!("Unsupported Format");
        }
        if header[9] != 0x9D {
            panic!("Unsupported Version");
        }
        self.big_endian = header[10] == 0;
        self.size_size_t = header[12];
        self.size_number = header[14];
        if self.read_u8() != b'\n' {
            panic!("Missing Header Newline Divider");
        }
        let seed = crate::compiler::instructions::get_global_seed();
        let layout = InstructionLayout::from_seed(seed);
        self.layout = Some(layout);
        crate::compiler::instructions::ACTIVE_LAYOUT.with(|layout_cell| {
            layout_cell.set(unsafe { std::mem::transmute(layout) });
        });
        let mut unescaped_body = Vec::with_capacity(self.data.len() - self.pos);
        while self.pos < self.data.len() {
            let byte = self.read_u8();
            if byte == 0x1B {
                if self.pos < self.data.len() {
                    let next_byte = self.read_u8();
                    match next_byte {
                        0x01 => unescaped_body.push(0x0A),
                        0x02 => unescaped_body.push(0x0D),
                        0x03 => unescaped_body.push(0x1B),
                        _ => {
                            unescaped_body.push(0x1B);
                            unescaped_body.push(next_byte);
                        }
                    }
                } else {
                    unescaped_body.push(0x1B);
                }
            } else if byte == b'\n' && self.pos == self.data.len() {
                break;
            } else {
                unescaped_body.push(byte);
            }
        }
        self.data = unescaped_body;
        self.pos = 0;
        let mut k1 = 0x5A_u8;
        let mut k2 = 0x3C_u8;
        let mut k3 = 0x99_u8;
        let mut k4 = 0x1F_u8;
        let str_count = self.read_i32_dec(&mut k1, &mut k2, &mut k3, &mut k4);
        for _ in 0..str_count {
            let key = self.read_i32_dec(&mut k1, &mut k2, &mut k3, &mut k4) as u32;
            let size = self.read_size_t_dec(&mut k1, &mut k2, &mut k3, &mut k4);
            if size == 0 {
                self.global_strings.push(Vec::new());
            } else {
                let mut b = vec![0; size];
                for i in 0..size { b[i] = self.read_u8_dec(&mut k1, &mut k2, &mut k3, &mut k4); }
                let mut final_str = b[0..size-1].to_vec();
                for (i, byte) in final_str.iter_mut().enumerate() {
                    let k_byte = (key >> ((i % 4) * 8)) as u8;
                    *byte = byte.wrapping_sub(i as u8) ^ k_byte;
                }
                self.global_strings.push(final_str);
            }
        }
        let num_count = self.read_i32_dec(&mut k1, &mut k2, &mut k3, &mut k4);
        for _ in 0..num_count {
            let key = self.read_u64_dec(&mut k1, &mut k2, &mut k3, &mut k4);
            let mut enc_n_bits = self.read_f64_dec(&mut k1, &mut k2, &mut k3, &mut k4).to_bits();
            enc_n_bits ^= key;
            self.global_numbers.push(f64::from_bits(enc_n_bits));
        }
        self.decode_chunk()
    }

    fn decode_chunk(&mut self) -> Chunk {
        let name = self.read_string_utf8();
        let line_defined = self.read_i32();
        let last_line_defined = self.read_i32();
        let upvalue_count = self.read_u8();
        let param_count = self.read_u8();
        let is_vararg = self.read_u8();
        let max_stack = self.read_u8();
        let instructions = self.decode_instructions();
        let constants = self.decode_constants();
        let protos = self.decode_protos();
        let lines = self.decode_lines();
        let locals = self.decode_locals();
        let upvalues = self.decode_upvalues();
        Chunk {
            name,
            line_defined,
            last_line_defined,
            upvalue_count,
            param_count,
            is_vararg,
            max_stack,
            instructions,
            constants,
            protos,
            lines,
            locals,
            upvalues,
        }
    }

    fn decode_instructions(&mut self) -> Vec<Instruction> {
        let count = self.read_i32();
        let mut insts = Vec::with_capacity(count as usize);
        let layout = self.layout.expect("Layout not initialized");
        for _ in 0..count {
            let data = self.read_u32();
            let val = data ^ layout.xor_key;
            let op_val = ((val >> layout.pos_op) & ((1 << layout.size_op) - 1)) as u8;
            let opcode_decoded = layout.decode_opcode(op_val).expect("Unknown Opcode");
            let a = ((val >> layout.pos_a) & ((1 << layout.size_a) - 1)) as u8;
            let b_val = (val >> layout.pos_b) & ((1 << layout.size_b) - 1);
            let c_val = (val >> layout.pos_c) & ((1 << layout.size_c) - 1);
            let bx_val = (val >> layout.pos_bx) & ((1 << layout.size_bx) - 1);
            let b = b_val as i32;
            let c = c_val as i32;
            let bx = bx_val as i32;
            let sbx = bx - layout.max_sbx;
            let (final_b, final_c) = match opcode_decoded {
                Opcode::Jmp | Opcode::ForLoop | Opcode::ForPrep | Opcode::TForPrep |
                Opcode::JmpIf | Opcode::JmpIfNot | Opcode::JmpEq | Opcode::JmpNe => (sbx, -1),
                Opcode::LoadK | Opcode::GetGlobal | Opcode::SetGlobal | Opcode::Closure |
                Opcode::LoadKx | Opcode::ExtraArg | Opcode::GetImport | Opcode::GetGlobalStr |
                Opcode::SetGlobalStr => (bx, -1),
                _ => (b, c),
            };
            insts.push(Instruction {
                data,
                opcode: opcode_decoded,
                a,
                b: final_b,
                c: final_c,
                line: 0,
                v_opcode: None,
                is_junk: false,
            });
        }
        insts
    }

    fn decode_constants(&mut self) -> Vec<Constant> {
        let count = self.read_i32();
        let mut consts = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let const_type = self.read_u8();
            let constant = match const_type {
                0x11 => Constant::Nil,
                0x2A => Constant::Boolean(self.read_u8() != 0),
                0x4C => {
                    let idx = self.read_i32() as usize;
                    Constant::Number(self.global_numbers[idx])
                },
                0x8F => {
                    let idx = self.read_i32() as usize;
                    Constant::String(self.global_strings[idx].clone())
                },
                _ => panic!("Invalid Constant"),
            };
            consts.push(constant);
        }
        consts
    }

    fn decode_protos(&mut self) -> Vec<Chunk> {
        let count = self.read_i32();
        let mut protos = Vec::with_capacity(count as usize);
        for _ in 0..count {
            protos.push(self.decode_chunk());
        }
        protos
    }

    fn decode_lines(&mut self) -> Vec<i32> {
        let count = self.read_i32();
        let mut lines = Vec::with_capacity(count as usize);
        for _ in 0..count {
            lines.push(self.read_i32());
        }
        lines
    }

    fn decode_locals(&mut self) -> Vec<Local> {
        let count = self.read_i32();
        let mut locals = Vec::with_capacity(count as usize);
        for _ in 0..count {
            locals.push(Local {
                name: self.read_string_utf8(),
                start_pc: self.read_i32(),
                end_pc: self.read_i32(),
            });
        }
        locals
    }

    fn decode_upvalues(&mut self) -> Vec<String> {
        let count = self.read_i32();
        let mut upvalues = Vec::with_capacity(count as usize);
        for _ in 0..count {
            upvalues.push(self.read_string_utf8());
        }
        upvalues
    }
}