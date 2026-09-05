use super::prng::Prng;
use crate::{Diagnostic, Target};
use std::collections::BTreeSet;
use std::fmt::Write;

const OPCODE_COUNT: usize = 91;
const PRIVATE_DATA_OPCODE: usize = 91;

#[derive(Clone, Debug)]
enum Constant {
    Nil,
    Boolean(bool),
    Number(f64),
    String(Vec<u8>),
    Import(u32),
    Table(Vec<(usize, Option<i32>)>),
    Closure(usize),
    Vector([f64; 4]),
    Integer { negative: bool, magnitude: u64 },
    ClassShape(Vec<usize>),
}

#[derive(Clone, Debug)]
struct Instruction {
    opcode: usize,
    raw: u32,
}

#[derive(Clone, Debug)]
struct Prototype {
    max_stack: u8,
    parameters: u8,
    upvalues: u8,
    vararg: u8,
    flags: u8,
    code: Vec<Instruction>,
    constants: Vec<Constant>,
    children: Vec<usize>,
}

struct Chunk {
    prototypes: Vec<Prototype>,
    main: usize,
}

pub fn virtualize(data: &[u8], seed: u64) -> Result<String, Diagnostic> {
    crate::bytecode::luau::inspect(data)?;
    let chunk = decode(data)?;

    let mut prng = Prng::new(seed ^ 0x6c75_6175_0000_0735);
    let opcode_ids = prng.unique_opcodes(OPCODE_COUNT + 1);
    let mut present = [false; OPCODE_COUNT];
    for instruction in chunk
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.code)
    {
        if instruction.opcode < OPCODE_COUNT {
            present[instruction.opcode] = true;
        }
    }
    let mut branch_order: Vec<_> = (0..OPCODE_COUNT)
        .filter(|opcode| present[*opcode])
        .collect();
    prng.shuffle(&mut branch_order);

    let bytecode = encode_private_bytecode(&chunk.prototypes, chunk.main, &opcode_ids)?;
    let mut source = String::new();
    source.push_str("local Z=function(...)return{n=select('#',...),...}end;");
    source.push_str(
        "local U=(table and table.unpack)or unpack;local G=(getfenv and getfenv(0))or _G;local E=error;",
    );
    emit_private_decoder(
        &mut source,
        &bytecode,
        &chunk.prototypes,
        &mut prng,
        opcode_ids[70],
    );
    source.push_str(
        "local IK=function(F,env)if F.k then return F.k end;local k={};F.k=k;\
         for j=0,F.z-1 do local d=F.d[j];local t=d[1];\
         if t==1 then k[j]=d[2]elseif t==2 or t==8 then k[j]=d[2]elseif t==3 then k[j]=d[2]\
         elseif t==7 then local v=env.vector;k[j]=(v and v.create and v.create(d[2],d[3],d[4],d[5]))or{x=d[2],y=d[3],z=d[4],w=d[5]}end end;\
         for j=0,F.z-1 do local d=F.d[j];local t=d[1];if t==4 then k[j]={i=d[2]}\
         elseif t==5 then local x={};for n=2,#d do local e=d[n];local v=e[2]==0 and 0 or k[e[2]-1];x[k[e[1]]]=v end;k[j]=x;\
         elseif t==6 then k[j]={p=d[2]}elseif t==10 then local x={};for n=2,#d do x[k[d[n]]]=false end;k[j]=x end end;return k end;",
    );
    source.push_str("local FM={};local H;H=function(fid,args,ups,env)local F=P[fid];local K=IK(F,env);local imp=function(q)local x=env;local n=math.floor(q/1073741824);if n>0 then x=x[K[math.floor(q/1048576)%1024]]end;if n>1 then x=x[K[math.floor(q/1024)%1024]]end;if n>2 then x=x[K[q%1024]]end;return x end;local R={};");
    source.push_str("for j=0,F.m-1 do R[j]={}end;for j=0,F.p-1 do R[j][1]=args[j+1]end;");
    source.push_str("local va={n=math.max(0,args.n-F.p)};for j=1,va.n do va[j]=args[F.p+j]end;");
    source.push_str("local top=F.p-1;local pc=1;local C=F.c;");
    source.push_str("local rv=function(j)local x=R[j];return x and x[1]end;local sv=function(j,v)local x=R[j];if x then x[1]=v else R[j]={[1]=v}end end;");
    source.push_str("local fs=function(v)return v==nil or v==false end;local sel=function(c,a,b)if c then return a else return b end end;local close=function(a)for j=a,F.m-1 do local x=R[j];if x then R[j]={[1]=x[1]}end end end;");
    source.push_str(
        "local clone=function(x)local y={};for a,b in pairs(x)do y[a]=b end;return y end;",
    );
    source.push_str("local mk=function(id,cu)local f=function(...)return H(id,Z(...),cu,env)end;FM[f]=id;return f end;");
    source.push_str("local call=function(a,b,c)local n=b==0 and(top-a)or(b-1);local q={n=n};for j=1,n do q[j]=rv(a+j)end;local z=Z(rv(a)(U(q,1,n)));if c==0 then for j=1,z.n do sv(a+j-1,z[j])end;top=a+z.n-1 else for j=1,c-1 do sv(a+j-1,z[j])end end end;");
    source.push_str("while true do local i=C[pc];if not i then E()end;pc=pc+1;local o=i[1];");

    for (position, opcode) in branch_order.iter().copied().enumerate() {
        source.push_str(if position == 0 { "if " } else { "elseif " });
        source.push_str(&prng.dispatch_condition(opcode_ids[opcode], true));
        source.push_str(" then ");
        source.push_str(handler(opcode));
    }
    source.push_str("else E()end end end;");
    source.push_str("return H(M,Z(...),{},G)");

    crate::minify(&source, Target::Luau)
        .map_err(|error| error.context("generated Luau VM failed internal validation"))
}

fn handler(opcode: usize) -> &'static str {
    super::opcode::luau(opcode)
}

fn encode_private_bytecode(
    prototypes: &[Prototype],
    main: usize,
    opcode_ids: &[u16],
) -> Result<Vec<u8>, Diagnostic> {
    let main = checked_u32(main, "main prototype")?;
    let count = checked_u32(prototypes.len(), "prototype count")?;
    let mut output = super::binary::Writer::new(0x75, main, count);

    for prototype in prototypes {
        output.u8(prototype.max_stack);
        output.u8(prototype.parameters);
        output.u8(prototype.upvalues);
        output.u8(prototype.vararg);
        output.u8(prototype.flags);
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
                Constant::Import(value) => {
                    output.u8(4);
                    output.u32(*value);
                }
                Constant::Table(entries) => {
                    output.u8(5);
                    output.u32(checked_u32(entries.len(), "table entry count")?);
                    for (key, value) in entries {
                        output.u32(checked_u32(*key, "table key constant")?);
                        let encoded = value
                            .filter(|index| *index >= 0)
                            .and_then(|index| index.checked_add(1))
                            .unwrap_or(0);
                        output.u32(encoded as u32);
                    }
                }
                Constant::Closure(id) => {
                    output.u8(6);
                    output.u32(checked_u32(*id, "closure prototype")?);
                }
                Constant::Vector(value) => {
                    output.u8(7);
                    for component in value {
                        output.number(*component)?;
                    }
                }
                Constant::Integer {
                    negative,
                    magnitude,
                } => {
                    output.u8(8);
                    output.u8(u8::from(*negative));
                    output.bytes(magnitude.to_string().as_bytes())?;
                }
                Constant::ClassShape(members) => {
                    output.u8(10);
                    output.u32(checked_u32(members.len(), "class member count")?);
                    for member in members {
                        output.u32(checked_u32(*member, "class member constant")?);
                    }
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
                .ok_or_else(|| Diagnostic::new("invalid internal Luau opcode"))?;
            output.u16(private);
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
    prototypes: &[Prototype],
    prng: &mut Prng,
    capture_opcode: u16,
) {
    output.push_str("local OC=");
    output.push_str(&prng.integer_literal(u64::from(capture_opcode), true));
    output.push_str(";local B=");
    super::lua51::emit_byte_string(output, bytecode);
    output.push_str(
        ";local bp=1;local b8=function()local v=string.byte(B,bp);if not v then E()end;bp=bp+1;return v end;\
         local b16=function()local a,b=b8(),b8();return a+b*256 end;\
         local b32=function()local a,b,c,d=b8(),b8(),b8(),b8();return a+b*256+c*65536+d*16777216 end;\
         local bc=function()local v=b32();if v>1000000 then E()end;return v end;\
         local bs=function()local n=b32();if bp+n-1>#B then E()end;local v=string.sub(B,bp,bp+n-1);bp=bp+n;return v end;\
         local bn=function()local t=b8();if t==0 then local v=tonumber(bs());if not v then E()end;return v elseif t==1 then return 0/0 elseif t==2 then return 1/0 elseif t==3 then return -1/0 else E()end end;\
         if b8()~=79 or b8()~=66 or b8()~=70 or b8()~=1 or b8()~=117 then E()end;\
         local bl=b32();local ck=b32();local ps=bp;if #B-ps+1~=bl then E()end;local s1,s2=1,0;for j=ps,#B do s1=(s1+string.byte(B,j))%65521;s2=(s2+s1)%65521 end;if s1+s2*65536~=ck then E()end;\
         local M=b32();local np=bc();local P={};for id=0,np-1 do local F={d={},q={},c={},n={}};F.m=b8();F.p=b8();F.u=b8();F.v=b8();F.f=b8();F.z=bc();\
         for j=0,F.z-1 do local t=b8();if t==0 then F.d[j]={0}elseif t==1 then F.d[j]={1,b8()~=0}elseif t==2 then F.d[j]={2,bn()}elseif t==3 then F.d[j]={3,bs()}elseif t==4 then F.d[j]={4,b32()}\
         elseif t==5 then local e={5};local n=bc();for x=1,n do e[#e+1]={b32(),b32()}end;F.d[j]=e elseif t==6 then F.d[j]={6,b32()}\
         elseif t==7 then F.d[j]={7,bn(),bn(),bn(),bn()}elseif t==8 then local s=b8();local v=tonumber(bs());if not v then E()end;if s~=0 then v=-v end;F.d[j]={8,v}\
         elseif t==10 then local e={10};local n=bc();for x=1,n do e[#e+1]=b32()end;F.d[j]=e else E()end end;\
         local nq=bc();for j=0,nq-1 do F.q[j]=b32()end;local nc=bc();for j=1,nc do local o=b16();local w=b32();local d=math.floor(w/65536);local e=math.floor(w/256)%16777216;if d>=32768 then d=d-65536 end;if e>=8388608 then e=e-16777216 end;F.c[j]={o,math.floor(w/256)%256,math.floor(w/65536)%256,math.floor(w/16777216)%256,d,e,w}end;P[id]=F end;\
         if bp~=#B+1 then E()end;B=nil;",
    );
    output.push_str("local W={};");
    for (id, prototype) in prototypes.iter().enumerate() {
        write!(output, "W[{id}]={{").unwrap();
        emit_namecall_wrappers(output, prototype);
        output.push_str("};");
    }
    output.push_str("for id,w in pairs(W)do P[id].n=w end;W=nil;");
}

fn emit_namecall_wrappers(output: &mut String, prototype: &Prototype) {
    let mut emitted = BTreeSet::new();
    for (position, instruction) in prototype.code.iter().enumerate() {
        if !matches!(instruction.opcode, 20 | 85) {
            continue;
        }
        let Some(aux) = prototype.code.get(position + 1) else {
            continue;
        };
        let index = if instruction.opcode == 85 {
            (aux.raw & 0xffff) as usize
        } else {
            aux.raw as usize
        };
        if !emitted.insert(index) {
            continue;
        }
        let Some(Constant::String(name)) = prototype.constants.get(index) else {
            continue;
        };
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        if !is_luau_identifier(name) {
            continue;
        }
        write!(output, "[{index}]=function(s,...)return s:{name}(...)end,").unwrap();
    }
}

fn is_luau_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !matches!(
            value,
            "and"
                | "break"
                | "do"
                | "else"
                | "elseif"
                | "end"
                | "false"
                | "for"
                | "function"
                | "if"
                | "in"
                | "local"
                | "nil"
                | "not"
                | "or"
                | "repeat"
                | "return"
                | "then"
                | "true"
                | "until"
                | "while"
        )
}

fn decode(data: &[u8]) -> Result<Chunk, Diagnostic> {
    let mut reader = Reader::new(data);
    let version = reader.byte("version")?;
    let type_version = if version >= 4 {
        reader.byte("type version")?
    } else {
        0
    };

    let string_count = reader.var_usize("string count")?;
    let mut strings = Vec::with_capacity(string_count);
    for _ in 0..string_count {
        let length = reader.var_usize("string length")?;
        strings.push(reader.take(length, "string")?.to_vec());
    }
    if type_version == 3 {
        while reader.byte("userdata type index")? != 0 {
            reader.string_ref(string_count, "userdata type name")?;
        }
    }

    let prototype_count = reader.var_usize("prototype count")?;
    let mut prototypes = Vec::with_capacity(prototype_count);
    for _ in 0..prototype_count {
        prototypes.push(read_prototype(
            &mut reader,
            version,
            type_version,
            &strings,
            prototype_count,
        )?);
    }
    let main = reader.var_usize("main prototype")?;
    Ok(Chunk { prototypes, main })
}

fn read_prototype(
    reader: &mut Reader<'_>,
    version: u8,
    type_version: u8,
    strings: &[Vec<u8>],
    prototype_count: usize,
) -> Result<Prototype, Diagnostic> {
    let declared_end = if version >= 12 {
        let size = reader.var_usize("prototype size")?;
        Some(reader.offset + size)
    } else {
        None
    };
    let max_stack = reader.byte("max stack")?;
    let parameters = reader.byte("parameters")?;
    let upvalues = reader.byte("upvalues")?;
    let vararg = reader.byte("vararg")?;
    let flags = if version >= 4 {
        reader.byte("flags")?
    } else {
        0
    };
    if version >= 4 {
        let size = reader.var_usize("type info size")?;
        reader.take(size, "type info")?;
        let _ = type_version;
    }

    let word_count = reader.var_usize("code words")?;
    let mut words = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        words.push(reader.u32("instruction")?);
    }
    let mut code = Vec::with_capacity(word_count);
    let mut cursor = 0;
    while cursor < words.len() {
        let word = words[cursor];
        let opcode = (word & 0xff) as usize;
        if opcode >= OPCODE_COUNT {
            return Err(reader.error(format!("invalid Luau opcode {opcode}")));
        }
        code.push(decode_instruction(opcode, word));
        cursor += 1;
        if has_aux(opcode) {
            let raw = *words
                .get(cursor)
                .ok_or_else(|| reader.error("instruction is missing AUX word"))?;
            code.push(Instruction {
                opcode: PRIVATE_DATA_OPCODE,
                raw,
            });
            cursor += 1;
        }
    }

    let constant_count = reader.var_usize("constant count")?;
    let mut constants = Vec::with_capacity(constant_count);
    for _ in 0..constant_count {
        let constant = match reader.byte("constant tag")? {
            0 => Constant::Nil,
            1 => Constant::Boolean(reader.byte("boolean")? != 0),
            2 => Constant::Number(reader.f64("number")?),
            3 => Constant::String(
                reader
                    .string_ref(strings.len(), "string constant")?
                    .and_then(|index| strings.get(index))
                    .ok_or_else(|| reader.error("null string constant"))?
                    .clone(),
            ),
            4 => Constant::Import(reader.u32("import")?),
            5 => {
                let count = reader.var_usize("table keys")?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push((reader.var_usize("table key")?, None));
                }
                Constant::Table(entries)
            }
            6 => Constant::Closure(reader.var_usize("closure prototype")?),
            7 => Constant::Vector([
                reader.f32("vector x")? as f64,
                reader.f32("vector y")? as f64,
                reader.f32("vector z")? as f64,
                reader.f32("vector w")? as f64,
            ]),
            8 => {
                let count = reader.var_usize("table keys")?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push((
                        reader.var_usize("table key")?,
                        Some(reader.i32("table value")?),
                    ));
                }
                Constant::Table(entries)
            }
            9 => Constant::Integer {
                negative: reader.byte("integer sign")? != 0,
                magnitude: reader.var_u64("integer magnitude")?,
            },
            10 => {
                let class_name = reader.var_usize("class name")?;
                let properties = reader.var_usize("class properties")?;
                let methods = reader.var_usize("class methods")?;
                let mut members = Vec::with_capacity(1 + properties + methods);
                members.push(class_name);
                for _ in 0..properties + methods {
                    members.push(reader.var_usize("class member")?);
                }
                Constant::ClassShape(members)
            }
            11 => Constant::Vector([
                reader.f64("vector x")?,
                reader.f64("vector y")?,
                reader.f64("vector z")?,
                reader.f64("vector w")?,
            ]),
            tag => return Err(reader.error(format!("unsupported constant tag {tag}"))),
        };
        constants.push(constant);
    }

    let child_count = reader.var_usize("children")?;
    let mut children = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        let child = reader.var_usize("child")?;
        if child >= prototype_count {
            return Err(reader.error("child prototype is out of range"));
        }
        children.push(child);
    }
    reader.var_usize("line defined")?;
    reader.string_ref(strings.len(), "debug name")?;

    if reader.byte("line info")? != 0 {
        let gap = reader.byte("line gap")? as usize;
        reader.take(word_count, "relative line info")?;
        let intervals = if word_count == 0 {
            0
        } else {
            ((word_count - 1) >> gap) + 1
        };
        reader.take(intervals * 4, "absolute line info")?;
    }
    if reader.byte("debug info")? != 0 {
        let locals = reader.var_usize("locals")?;
        for _ in 0..locals {
            reader.string_ref(strings.len(), "local name")?;
            reader.var_usize("local start")?;
            reader.var_usize("local end")?;
            reader.byte("local register")?;
        }
        let names = reader.var_usize("upvalue names")?;
        for _ in 0..names {
            reader.string_ref(strings.len(), "upvalue name")?;
        }
    }
    if version >= 11 {
        let feedback = reader.var_usize("feedback")?;
        for _ in 0..feedback {
            reader.byte("feedback type")?;
            reader.var_usize("feedback pc")?;
        }
    }
    if version >= 12 && flags & 8 != 0 {
        reader.var_u64("cost")?;
    }
    if let Some(end) = declared_end {
        if reader.offset > end {
            return Err(reader.error("prototype exceeds declared size"));
        }
        reader.offset = end;
    }

    Ok(Prototype {
        max_stack,
        parameters,
        upvalues,
        vararg,
        flags,
        code,
        constants,
        children,
    })
}

fn decode_instruction(opcode: usize, word: u32) -> Instruction {
    Instruction { opcode, raw: word }
}

fn has_aux(opcode: usize) -> bool {
    matches!(
        opcode,
        7 | 8
            | 12
            | 15
            | 16
            | 20
            | 27..=32
            | 53
            | 55
            | 58
            | 60
            | 66
            | 74
            | 75
            | 77..=80
            | 83..=88
            | 90
    )
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

    fn u32(&mut self, label: &str) -> Result<u32, Diagnostic> {
        Ok(u32::from_le_bytes(
            self.take(4, label)?.try_into().expect("four bytes"),
        ))
    }

    fn i32(&mut self, label: &str) -> Result<i32, Diagnostic> {
        Ok(i32::from_le_bytes(
            self.take(4, label)?.try_into().expect("four bytes"),
        ))
    }

    fn f32(&mut self, label: &str) -> Result<f32, Diagnostic> {
        Ok(f32::from_le_bytes(
            self.take(4, label)?.try_into().expect("four bytes"),
        ))
    }

    fn f64(&mut self, label: &str) -> Result<f64, Diagnostic> {
        Ok(f64::from_le_bytes(
            self.take(8, label)?.try_into().expect("eight bytes"),
        ))
    }

    fn var_u64(&mut self, label: &str) -> Result<u64, Diagnostic> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.byte(label)?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(self.error(format!("{label} varint overflow")))
    }

    fn var_usize(&mut self, label: &str) -> Result<usize, Diagnostic> {
        usize::try_from(self.var_u64(label)?)
            .map_err(|_| self.error(format!("{label} is too large")))
    }

    fn string_ref(&mut self, count: usize, label: &str) -> Result<Option<usize>, Diagnostic> {
        let value = self.var_usize(label)?;
        if value == 0 {
            Ok(None)
        } else if value - 1 < count {
            Ok(Some(value - 1))
        } else {
            Err(self.error(format!("{label} is out of range")))
        }
    }

    fn error(&self, message: impl Into<String>) -> Diagnostic {
        Diagnostic::byte(message, self.offset)
    }
}
