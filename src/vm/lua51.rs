use super::prng::Prng;
use crate::{Diagnostic, Target};
use std::fmt::Write;

const SIGNATURE: &[u8; 4] = b"\x1bLua";
const OPCODE_COUNT: usize = 38;
const PRIVATE_DATA_OPCODE: usize = 38;

#[derive(Clone, Debug)]
enum Constant {
    Nil,
    Boolean(bool),
    Number(f64),
    String(Vec<u8>),
}

#[derive(Clone, Debug)]
struct Instruction {
    opcode: usize,
    a: u32,
    b: u32,
    c: u32,
    bx: u32,
    sbx: i32,
    raw: u32,
}

#[derive(Clone, Debug)]
struct Prototype {
    upvalues: u8,
    parameters: u8,
    vararg: u8,
    max_stack: u8,
    constants: Vec<Constant>,
    code: Vec<Instruction>,
    children: Vec<Prototype>,
}

#[derive(Clone)]
struct FlatPrototype {
    upvalues: u8,
    parameters: u8,
    vararg: u8,
    max_stack: u8,
    constants: Vec<Constant>,
    code: Vec<Instruction>,
    children: Vec<usize>,
}

#[derive(Clone, Copy)]
struct Header {
    little_endian: bool,
    int_size: usize,
    size_t_size: usize,
    number_size: usize,
}

pub fn virtualize(data: &[u8], seed: u64) -> Result<String, Diagnostic> {
    // Reuse the strict public inspector before decoding data into the VM IR.
    crate::bytecode::lua51::inspect(data)?;
    let main = decode(data)?;
    let mut flat = Vec::new();
    let main_id = flatten(&main, &mut flat);

    let mut prng = Prng::new(seed);
    let opcode_ids = prng.unique_opcodes(OPCODE_COUNT + 1);
    let mut branch_order: Vec<_> = (0..OPCODE_COUNT).collect();
    prng.shuffle(&mut branch_order);

    let bytecode = encode_private_bytecode(&flat, main_id, &opcode_ids)?;
    let mut source = String::new();
    source.push_str("local Z=function(...)return{n=select('#',...),...}end;");
    source.push_str("local U=unpack or table.unpack;local G=(getfenv and getfenv(0))or _G;");
    emit_private_decoder(
        &mut source,
        &bytecode,
        &mut prng,
        opcode_ids[0],
        opcode_ids[4],
    );
    source.push_str("local H;H=function(fid,args,ups,env)local F=P[fid];local R={};");
    source.push_str("for j=0,F.m-1 do R[j]={}end;for j=0,F.p-1 do R[j][1]=args[j+1]end;");
    source.push_str("local va={n=math.max(0,args.n-F.p)};for j=1,va.n do va[j]=args[F.p+j]end;");
    source.push_str("local top=F.p-1;local pc=1;local C=F.c;local K=F.k;");
    source.push_str("local rv=function(j)local b=R[j];return b and b[1]end;");
    source
        .push_str("local sv=function(j,v)local b=R[j];if b then b[1]=v else R[j]={[1]=v}end end;");
    source.push_str("local rk=function(j)if j>=256 then return K[j-256]else return rv(j)end end;");
    source.push_str("local falsy=function(v)return v==nil or v==false end;");
    source.push_str("local close=function(a)for j=a,F.m-1 do local b=R[j];if b then R[j]={[1]=b[1]}end end end;");
    source.push_str("local branch=function(ok) local j=C[pc];pc=pc+1;if ok then if j[2]>0 then close(j[2]-1)end;pc=pc+j[6]end end;");
    source.push_str("while true do local i=C[pc];if not i then error('invalid private pc '..pc,0)end;pc=pc+1;local o=i[1];");

    for (position, opcode) in branch_order.iter().copied().enumerate() {
        source.push_str(if position == 0 { "if " } else { "elseif " });
        source.push_str(&prng.dispatch_condition(opcode_ids[opcode], false));
        source.push_str(" then ");
        source.push_str(handler(opcode));
    }
    source.push_str("else error('invalid private opcode '..tostring(o),0)end end end;");
    source.push_str("return H(M,Z(...),{},G)");

    crate::minify(&source, Target::Lua51)
        .map_err(|error| error.context("generated Lua 5.1 VM failed internal validation"))
}

fn handler(opcode: usize) -> &'static str {
    super::opcode::lua51(opcode)
}

fn encode_private_bytecode(
    prototypes: &[FlatPrototype],
    main: usize,
    opcode_ids: &[u16],
) -> Result<Vec<u8>, Diagnostic> {
    let main = checked_u32(main, "main prototype")?;
    let count = checked_u32(prototypes.len(), "prototype count")?;
    let mut output = super::binary::Writer::new(0x51, main, count);

    for prototype in prototypes {
        output.u8(prototype.upvalues);
        output.u8(prototype.parameters);
        output.u8(prototype.vararg);
        output.u8(prototype.max_stack);
        output.u32(checked_u32(prototype.constants.len(), "constant count")?);
        for constant in &prototype.constants {
            match constant {
                Constant::Nil => output.u8(0),
                Constant::Boolean(value) => {
                    output.u8(1);
                    output.u8(u8::from(*value));
                }
                Constant::Number(value) => {
                    output.u8(2);
                    output.number(*value)?;
                }
                Constant::String(value) => {
                    output.u8(3);
                    output.bytes(value)?;
                }
            }
        }
        output.u32(checked_u32(prototype.children.len(), "child count")?);
        for child in &prototype.children {
            output.u32(checked_u32(*child, "child prototype")?);
        }
        output.u32(checked_u32(prototype.code.len(), "instruction count")?);
        for instruction in &prototype.code {
            let private = *opcode_ids
                .get(instruction.opcode)
                .ok_or_else(|| Diagnostic::new("invalid internal Lua 5.1 opcode"))?;
            output.u16(private);
            output.u32(instruction.a);
            output.u32(instruction.b);
            output.u32(instruction.c);
            output.u32(instruction.bx);
            output.i32(instruction.sbx);
            output.u32(instruction.raw);
        }
    }
    output.finish()
}

fn checked_u32(value: usize, label: &str) -> Result<u32, Diagnostic> {
    u32::try_from(value).map_err(|_| Diagnostic::new(format!("{label} exceeds private format")))
}

fn emit_private_decoder(
    output: &mut String,
    bytecode: &[u8],
    prng: &mut Prng,
    move_opcode: u16,
    getup_opcode: u16,
) {
    output.push_str("local MOVE_OP=");
    output.push_str(&prng.integer_literal(u64::from(move_opcode), false));
    output.push_str(";local GETUP_OP=");
    output.push_str(&prng.integer_literal(u64::from(getup_opcode), false));
    output.push_str(";local B=");
    emit_byte_string(output, bytecode);
    output.push_str(
        ";local bp=1;local b8=function()local v=string.byte(B,bp);if not v then error('truncated private bytecode',0)end;bp=bp+1;return v end;\
         local b16=function()local a,b=b8(),b8();return a+b*256 end;\
         local b32=function()local a,b,c,d=b8(),b8(),b8(),b8();return a+b*256+c*65536+d*16777216 end;\
         local bi32=function()local v=b32();if v>=2147483648 then return v-4294967296 else return v end end;local bc=function()local v=b32();if v>1000000 then error('private count limit exceeded',0)end;return v end;\
         local bs=function()local n=b32();if bp+n-1>#B then error('truncated private bytes',0)end;local v=string.sub(B,bp,bp+n-1);bp=bp+n;return v end;\
         local bn=function()local t=b8();if t==0 then local v=tonumber(bs());if not v then error('invalid private number',0)end;return v elseif t==1 then return 0/0 elseif t==2 then return 1/0 elseif t==3 then return -1/0 else error('invalid private number tag',0)end end;\
         if b8()~=79 or b8()~=66 or b8()~=70 or b8()~=1 or b8()~=81 then error('invalid Lua 5.1 private bytecode',0)end;\
         local bl=b32();local ck=b32();local ps=bp;if #B-ps+1~=bl then error('invalid private bytecode length',0)end;local s1,s2=1,0;for j=ps,#B do s1=(s1+string.byte(B,j))%65521;s2=(s2+s1)%65521 end;if s1+s2*65536~=ck then error('private bytecode checksum failed',0)end;\
         local M=b32();local np=bc();local P={};for id=0,np-1 do local F={k={},q={},c={}};F.u=b8();F.p=b8();F.v=b8();F.m=b8();\
         local nk=bc();for j=0,nk-1 do local t=b8();if t==0 then F.k[j]=nil elseif t==1 then F.k[j]=b8()~=0 elseif t==2 then F.k[j]=bn() elseif t==3 then F.k[j]=bs() else error('invalid private constant',0)end end;\
         local nq=bc();for j=0,nq-1 do F.q[j]=b32()end;local nc=bc();for j=1,nc do F.c[j]={b16(),b32(),b32(),b32(),b32(),bi32(),b32()}end;P[id]=F end;\
         if bp~=#B+1 then error('trailing private bytecode',0)end;B=nil;",
    );
}

pub(super) fn emit_byte_string(output: &mut String, value: &[u8]) {
    output.push('"');
    for &byte in value {
        match byte {
            b'"' => output.push_str("\\\""),
            b'\\' => output.push_str("\\\\"),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'\t' => output.push_str("\\t"),
            32..=126 => output.push(byte as char),
            _ => write!(output, "\\{byte:03}").unwrap(),
        }
    }
    output.push('"');
}

fn flatten(prototype: &Prototype, output: &mut Vec<FlatPrototype>) -> usize {
    let children = prototype
        .children
        .iter()
        .map(|child| flatten(child, output))
        .collect();
    let id = output.len();
    output.push(FlatPrototype {
        upvalues: prototype.upvalues,
        parameters: prototype.parameters,
        vararg: prototype.vararg,
        max_stack: prototype.max_stack,
        constants: prototype.constants.clone(),
        code: prototype.code.clone(),
        children,
    });
    id
}

fn decode(data: &[u8]) -> Result<Prototype, Diagnostic> {
    let mut reader = Reader::new(data);
    if reader.take(4, "signature")? != SIGNATURE {
        return Err(reader.error("invalid Lua 5.1 signature"));
    }
    if reader.byte("version")? != 0x51 || reader.byte("format")? != 0 {
        return Err(reader.error("unsupported Lua chunk"));
    }
    let endian = reader.byte("endianness")?;
    let header = Header {
        little_endian: endian == 1,
        int_size: reader.byte("int size")? as usize,
        size_t_size: reader.byte("size_t size")? as usize,
        number_size: {
            let instruction_size = reader.byte("instruction size")?;
            if instruction_size != 4 {
                return Err(reader.error("unsupported instruction size"));
            }
            reader.byte("number size")? as usize
        },
    };
    reader.byte("integral number flag")?;
    read_prototype(&mut reader, header)
}

fn read_prototype(reader: &mut Reader<'_>, header: Header) -> Result<Prototype, Diagnostic> {
    reader.lua_string(header, "source")?;
    reader.uint(header.int_size, header.little_endian, "line")?;
    reader.uint(header.int_size, header.little_endian, "last line")?;
    let upvalues = reader.byte("upvalue count")?;
    let parameters = reader.byte("parameter count")?;
    let vararg = reader.byte("vararg flags")?;
    let max_stack = reader.byte("max stack")?;

    let code_count = reader.count(header, "code count")?;
    let mut words = Vec::with_capacity(code_count);
    for _ in 0..code_count {
        words.push(reader.uint(4, header.little_endian, "instruction")? as u32);
    }
    let mut code = Vec::with_capacity(words.len());
    let mut data_word = false;
    for word in words {
        if data_word {
            code.push(Instruction {
                opcode: PRIVATE_DATA_OPCODE,
                a: 0,
                b: 0,
                c: 0,
                bx: 0,
                sbx: 0,
                raw: word,
            });
            data_word = false;
            continue;
        }
        let opcode = (word & 0x3f) as usize;
        if opcode >= OPCODE_COUNT {
            return Err(reader.error(format!("invalid opcode {opcode}")));
        }
        let a = (word >> 6) & 0xff;
        let c = (word >> 14) & 0x1ff;
        let b = (word >> 23) & 0x1ff;
        let bx = (word >> 14) & 0x3ffff;
        let sbx = bx as i32 - 131_071;
        if opcode == 34 && c == 0 {
            data_word = true;
        }
        code.push(Instruction {
            opcode,
            a,
            b,
            c,
            bx,
            sbx,
            raw: word,
        });
    }
    if data_word {
        return Err(reader.error("SETLIST is missing its data word"));
    }

    let constant_count = reader.count(header, "constant count")?;
    let mut constants = Vec::with_capacity(constant_count);
    for _ in 0..constant_count {
        constants.push(match reader.byte("constant tag")? {
            0 => Constant::Nil,
            1 => Constant::Boolean(reader.byte("boolean")? != 0),
            3 => Constant::Number(reader.number(header)?),
            4 => Constant::String(
                reader
                    .lua_string(header, "string")?
                    .ok_or_else(|| reader.error("null string constant"))?
                    .to_vec(),
            ),
            tag => return Err(reader.error(format!("unsupported constant tag {tag}"))),
        });
    }

    let child_count = reader.count(header, "prototype count")?;
    let mut children = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        children.push(read_prototype(reader, header)?);
    }

    let lines = reader.count(header, "line count")?;
    reader.take(lines * header.int_size, "line table")?;
    let locals = reader.count(header, "local count")?;
    for _ in 0..locals {
        reader.lua_string(header, "local name")?;
        reader.take(header.int_size * 2, "local range")?;
    }
    let names = reader.count(header, "upvalue name count")?;
    for _ in 0..names {
        reader.lua_string(header, "upvalue name")?;
    }

    Ok(Prototype {
        upvalues,
        parameters,
        vararg,
        max_stack,
        constants,
        code,
        children,
    })
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn byte(&mut self, label: &str) -> Result<u8, Diagnostic> {
        Ok(self.take(1, label)?[0])
    }

    fn take(&mut self, count: usize, label: &str) -> Result<&'a [u8], Diagnostic> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| self.error(format!("{label} overflow")))?;
        if end > self.data.len() {
            return Err(self.error(format!("truncated {label}")));
        }
        let value = &self.data[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn uint(&mut self, size: usize, little: bool, label: &str) -> Result<u64, Diagnostic> {
        let bytes = self.take(size, label)?;
        let mut value = 0u64;
        if little {
            for (index, byte) in bytes.iter().enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
        } else {
            for byte in bytes {
                value = (value << 8) | u64::from(*byte);
            }
        }
        Ok(value)
    }

    fn count(&mut self, header: Header, label: &str) -> Result<usize, Diagnostic> {
        let value = self.uint(header.int_size, header.little_endian, label)?;
        usize::try_from(value).map_err(|_| self.error(format!("{label} is too large")))
    }

    fn number(&mut self, header: Header) -> Result<f64, Diagnostic> {
        let bytes = self.take(header.number_size, "number")?;
        match (header.number_size, header.little_endian) {
            (8, true) => Ok(f64::from_le_bytes(bytes.try_into().expect("8 bytes"))),
            (8, false) => Ok(f64::from_be_bytes(bytes.try_into().expect("8 bytes"))),
            (4, true) => Ok(f32::from_le_bytes(bytes.try_into().expect("4 bytes")) as f64),
            (4, false) => Ok(f32::from_be_bytes(bytes.try_into().expect("4 bytes")) as f64),
            _ => Err(self.error("unsupported lua_Number size")),
        }
    }

    fn lua_string(&mut self, header: Header, label: &str) -> Result<Option<&'a [u8]>, Diagnostic> {
        let size = self.uint(header.size_t_size, header.little_endian, label)? as usize;
        if size == 0 {
            return Ok(None);
        }
        let value = self.take(size, label)?;
        Ok(Some(&value[..value.len() - 1]))
    }

    fn error(&self, message: impl Into<String>) -> Diagnostic {
        Diagnostic::byte(message, self.offset)
    }
}
