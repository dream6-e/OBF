use super::proto::Proto;
use super::value::Val;
use rand::{rng, Rng};

pub const LUA_SIGNATURE: &[u8] = b"\x1bKRYVEX";
const LUAC_VERSION: u8 = 0x9D;
const LUAC_FORMAT: u8 = 0x3F;
const ENDIANNESS: u8 = 1;
const SIZEOF_INT: u8 = 4;
const SIZEOF_SIZE_T: u8 = 8;
const SIZEOF_INSTRUCTION: u8 = 4;
const SIZEOF_LUA_NUMBER: u8 = 8;
const INTEGRAL_FLAG: u8 = 0x7A;
const LUA_TNIL: u8 = 0x11;
const LUA_TBOOLEAN: u8 = 0x2A;
const LUA_TNUMBER: u8 = 0x4C;
const LUA_TSTRING: u8 = 0x8F;

struct DumpState {
    buf: Vec<u8>,
    strip: bool,
}

impl DumpState {
    fn new(strip: bool) -> Self {
        Self { buf: Vec::with_capacity(256), strip }
    }

    fn dump_byte(&mut self, b: u8) { self.buf.push(b); }
    fn dump_int(&mut self, n: i32) { self.buf.extend_from_slice(&n.to_le_bytes()); }
    fn dump_size(&mut self, n: u64) { self.buf.extend_from_slice(&n.to_le_bytes()); }
    fn dump_number(&mut self, n: f64) { self.buf.extend_from_slice(&n.to_le_bytes()); }
    fn dump_block(&mut self, data: &[u8]) { self.buf.extend_from_slice(data); }

    fn dump_string(&mut self, s: Option<&[u8]>) {
        match s {
            None => self.dump_size(0),
            Some(data) => {
                self.dump_size(data.len() as u64 + 1);
                self.dump_block(data);
                self.dump_byte(0);
            }
        }
    }

    fn dump_header(&mut self) {
        self.dump_block(LUA_SIGNATURE);
        self.dump_byte(0xCC);
        self.dump_byte(LUAC_FORMAT);
        self.dump_byte(LUAC_VERSION);
        self.dump_byte(ENDIANNESS);
        self.dump_byte(SIZEOF_INT);
        self.dump_byte(SIZEOF_SIZE_T);
        self.dump_byte(SIZEOF_INSTRUCTION);
        self.dump_byte(SIZEOF_LUA_NUMBER);
        self.dump_byte(INTEGRAL_FLAG);
    }

    fn dump_code(&mut self, proto: &Proto) {
        self.dump_int(proto.code.len() as i32);
        for &instr in &proto.code {
            self.buf.extend_from_slice(&instr.to_le_bytes());
        }
    }

    fn dump_constants(&mut self, proto: &Proto, strings: &[Vec<u8>], numbers: &[f64]) {
        self.dump_int(proto.constants.len() as i32);
        for (i, val) in proto.constants.iter().enumerate() {
            match val {
                Val::Nil => {
                    if let Some(s) = proto.string_pool.iter().find(|(idx, _)| *idx == i as u32) {
                        self.dump_byte(LUA_TSTRING);
                        let pos = strings.iter().position(|x| x == &s.1).unwrap();
                        self.dump_int(pos as i32);
                    } else {
                        self.dump_byte(LUA_TNIL);
                    }
                }
                Val::Bool(b) => {
                    self.dump_byte(LUA_TBOOLEAN);
                    self.dump_byte(if *b { 1 } else { 0 });
                }
                Val::Num(n) => {
                    self.dump_byte(LUA_TNUMBER);
                    let pos = numbers.iter().position(|x| x.to_bits() == n.to_bits()).unwrap();
                    self.dump_int(pos as i32);
                }
            }
        }
        self.dump_int(proto.protos.len() as i32);
        for child in &proto.protos {
            self.dump_function(child, strings, numbers);
        }
    }

    fn dump_debug(&mut self, _proto: &Proto) {
        self.dump_int(0);
        self.dump_int(0);
        self.dump_int(0);
    }

    fn dump_function(&mut self, proto: &Proto, strings: &[Vec<u8>], numbers: &[f64]) {
        self.dump_string(Some(proto.source.as_bytes()));
        self.dump_int(proto.line_defined as i32);
        self.dump_int(proto.last_line_defined as i32);
        self.dump_byte(proto.num_upvalues);
        self.dump_byte(proto.num_params);
        self.dump_byte(proto.is_vararg);
        self.dump_byte(proto.max_stack_size);
        self.dump_code(proto);
        self.dump_constants(proto, strings, numbers);
        self.dump_debug(proto);
    }
}

fn collect_consts(proto: &Proto, strings: &mut Vec<Vec<u8>>, numbers: &mut Vec<f64>) {
    for (i, val) in proto.constants.iter().enumerate() {
        match val {
            Val::Num(n) => {
                if !numbers.iter().any(|x| x.to_bits() == n.to_bits()) {
                    numbers.push(*n);
                }
            }
            Val::Nil => {
                if let Some(s) = proto.string_pool.iter().find(|(idx, _)| *idx == i as u32) {
                    if !strings.contains(&s.1) {
                        strings.push(s.1.clone());
                    }
                }
            }
            _ => {}
        }
    }
    for child in &proto.protos {
        collect_consts(child, strings, numbers);
    }
}

pub fn dump(proto: &Proto, strip: bool) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut numbers = Vec::new();
    collect_consts(proto, &mut strings, &mut numbers);

    let mut header_state = DumpState::new(strip);
    header_state.dump_header();
    let mut final_result = header_state.buf;

    final_result.push(b'\n');

    let mut pool_state = DumpState::new(strip);
    pool_state.dump_int(strings.len() as i32);
    let mut r = rng();
    for s in &strings {
        let key: u32 = r.random();
        pool_state.dump_int(key as i32);
        let mut enc_s = s.clone();
        for (i, b) in enc_s.iter_mut().enumerate() {
            let k_byte = (key >> ((i % 4) * 8)) as u8;
            *b = (*b ^ k_byte).wrapping_add(i as u8);
        }
        pool_state.dump_string(Some(&enc_s));
    }
    pool_state.dump_int(numbers.len() as i32);
    for n in &numbers {
        let key: u64 = r.random();
        pool_state.dump_size(key);
        let enc_n = n.to_bits() ^ key;
        pool_state.dump_number(f64::from_bits(enc_n));
    }

    let mut pool_bytes = pool_state.buf;
    let mut k1 = 0x5A_u8;
    let mut k2 = 0x3C_u8;
    let mut k3 = 0x99_u8;
    let mut k4 = 0x1F_u8;
    for b in pool_bytes.iter_mut() {
        let orig = *b;
        let mut enc = orig;
        enc = enc ^ k1;
        enc = enc.wrapping_sub(k2);
        enc = enc.rotate_left((k3 % 8) as u32);
        enc = enc ^ k4;
        enc = enc.wrapping_add(0x42);
        *b = enc;
        k1 = k1.wrapping_add(orig).rotate_left(1).wrapping_add(0x1B);
        k2 = k2.wrapping_mul(3).wrapping_add(enc).rotate_right(2);
        k3 = k3 ^ k1.wrapping_sub(k4);
        k4 = k4.wrapping_add(k2).rotate_left(3);
    }

    let mut body_state = DumpState::new(strip);
    body_state.dump_block(&pool_bytes);
    body_state.dump_function(proto, &strings, &numbers);
    
    let body_bytes = body_state.buf;

    for &byte in &body_bytes {
        match byte {
            0x1B => {
                final_result.push(0x1B);
                final_result.push(0x03);
            }
            0x0A => {
                final_result.push(0x1B);
                final_result.push(0x01);
            }
            0x0D => {
                final_result.push(0x1B);
                final_result.push(0x02);
            }
            _ => {
                final_result.push(byte);
            }
        }
    }

    final_result.push(b'\n');

    final_result
}