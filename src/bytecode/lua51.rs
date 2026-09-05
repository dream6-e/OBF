use super::BytecodeReport;
use crate::{Diagnostic, Target};

const SIGNATURE: &[u8; 4] = b"\x1bLua";
const MAX_ITEMS: usize = 1_000_000;
const MAX_DEPTH: usize = 200;

const OPCODES: [&str; 38] = [
    "MOVE",
    "LOADK",
    "LOADBOOL",
    "LOADNIL",
    "GETUPVAL",
    "GETGLOBAL",
    "GETTABLE",
    "SETGLOBAL",
    "SETUPVAL",
    "SETTABLE",
    "NEWTABLE",
    "SELF",
    "ADD",
    "SUB",
    "MUL",
    "DIV",
    "MOD",
    "POW",
    "UNM",
    "NOT",
    "LEN",
    "CONCAT",
    "JMP",
    "EQ",
    "LT",
    "LE",
    "TEST",
    "TESTSET",
    "CALL",
    "TAILCALL",
    "RETURN",
    "FORLOOP",
    "FORPREP",
    "TFORLOOP",
    "SETLIST",
    "CLOSE",
    "CLOSURE",
    "VARARG",
];

#[derive(Clone, Copy)]
struct Header {
    little_endian: bool,
    int_size: usize,
    size_t_size: usize,
    instruction_size: usize,
    number_size: usize,
}

#[derive(Default)]
struct Totals {
    prototypes: usize,
    instructions: usize,
    constants: usize,
}

pub fn inspect(data: &[u8]) -> Result<BytecodeReport, Diagnostic> {
    let mut reader = Reader::new(data);
    if reader.take(4, "signature")? != SIGNATURE {
        return Err(Diagnostic::byte("invalid Lua bytecode signature", 0));
    }
    let version = reader.byte("version")?;
    if version != 0x51 {
        return Err(reader.error(format!(
            "unsupported Lua bytecode version 0x{version:02x}; expected 0x51"
        )));
    }
    let format = reader.byte("format")?;
    if format != 0 {
        return Err(reader.error(format!("unsupported Lua bytecode format {format}")));
    }
    let endian = reader.byte("endianness")?;
    if endian > 1 {
        return Err(reader.error("invalid endianness flag"));
    }
    let header = Header {
        little_endian: endian == 1,
        int_size: reader.byte("sizeof(int)")? as usize,
        size_t_size: reader.byte("sizeof(size_t)")? as usize,
        instruction_size: reader.byte("sizeof(Instruction)")? as usize,
        number_size: reader.byte("sizeof(lua_Number)")? as usize,
    };
    let integral = reader.byte("lua_Number integral flag")?;
    if integral > 1 {
        return Err(reader.error("invalid lua_Number integral flag"));
    }
    validate_size(header.int_size, "int", &reader)?;
    validate_size(header.size_t_size, "size_t", &reader)?;
    if header.instruction_size != 4 {
        return Err(reader.error(format!(
            "unsupported instruction width {}; Lua 5.1 uses 4",
            header.instruction_size
        )));
    }
    if !matches!(header.number_size, 4 | 8) {
        return Err(reader.error(format!(
            "unsupported lua_Number width {}",
            header.number_size
        )));
    }

    let mut totals = Totals::default();
    read_prototype(&mut reader, header, 0, &mut totals)?;
    if !reader.is_eof() {
        return Err(reader.error(format!(
            "{} trailing byte(s) after main prototype",
            reader.remaining()
        )));
    }

    Ok(BytecodeReport {
        target: Target::Lua51,
        version,
        type_version: None,
        strings: 0, // Lua 5.1 stores strings inline, not in a shared table.
        prototypes: totals.prototypes,
        instructions: totals.instructions,
        constants: totals.constants,
        main_prototype: 0,
    })
}

fn validate_size(size: usize, name: &str, reader: &Reader<'_>) -> Result<(), Diagnostic> {
    if matches!(size, 1 | 2 | 4 | 8) {
        Ok(())
    } else {
        Err(reader.error(format!("unsupported {name} width {size}")))
    }
}

fn read_prototype(
    reader: &mut Reader<'_>,
    header: Header,
    depth: usize,
    totals: &mut Totals,
) -> Result<(), Diagnostic> {
    if depth > MAX_DEPTH {
        return Err(reader.error("prototype nesting limit exceeded"));
    }
    totals.prototypes = totals
        .prototypes
        .checked_add(1)
        .ok_or_else(|| reader.error("prototype count overflow"))?;

    reader.lua_string(header, "prototype source")?;
    reader.uint(header.int_size, header.little_endian, "line defined")?;
    reader.uint(header.int_size, header.little_endian, "last line defined")?;
    reader.take(4, "prototype metadata")?; // nups, params, vararg, maxstack

    let code_count = reader.count(header, "instruction count", header.instruction_size)?;
    totals.instructions = totals
        .instructions
        .checked_add(code_count)
        .ok_or_else(|| reader.error("instruction count overflow"))?;
    for _ in 0..code_count {
        let word = reader.uint(4, header.little_endian, "instruction")? as u32;
        let opcode = (word & 0x3f) as usize;
        if opcode >= OPCODES.len() {
            return Err(reader.error(format!("invalid Lua 5.1 opcode {opcode}")));
        }
    }

    let constant_count = reader.count(header, "constant count", 1)?;
    totals.constants = totals
        .constants
        .checked_add(constant_count)
        .ok_or_else(|| reader.error("constant count overflow"))?;
    for _ in 0..constant_count {
        let tag = reader.byte("constant tag")?;
        match tag {
            0 => {}
            1 => {
                let value = reader.byte("boolean constant")?;
                if value > 1 {
                    return Err(reader.error("invalid boolean constant"));
                }
            }
            3 => {
                reader.take(header.number_size, "number constant")?;
            }
            4 => {
                reader
                    .lua_string(header, "string constant")?
                    .ok_or_else(|| reader.error("string constant cannot be null"))?;
            }
            _ => return Err(reader.error(format!("unknown Lua 5.1 constant tag {tag}"))),
        }
    }

    let child_count = reader.count(header, "child prototype count", 1)?;
    for _ in 0..child_count {
        read_prototype(reader, header, depth + 1, totals)?;
    }

    let line_count = reader.count(header, "line information count", header.int_size)?;
    reader.take(
        line_count
            .checked_mul(header.int_size)
            .ok_or_else(|| reader.error("line information size overflow"))?,
        "line information",
    )?;

    let local_count = reader.count(header, "local variable count", 1)?;
    for _ in 0..local_count {
        reader
            .lua_string(header, "local variable name")?
            .ok_or_else(|| reader.error("local variable name cannot be null"))?;
        reader.uint(header.int_size, header.little_endian, "local start pc")?;
        reader.uint(header.int_size, header.little_endian, "local end pc")?;
    }

    let upvalue_count = reader.count(header, "upvalue name count", 1)?;
    for _ in 0..upvalue_count {
        reader
            .lua_string(header, "upvalue name")?
            .ok_or_else(|| reader.error("upvalue name cannot be null"))?;
    }
    Ok(())
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
            .ok_or_else(|| self.error(format!("{label} size overflow")))?;
        if end > self.data.len() {
            return Err(self.error(format!("truncated {label}")));
        }
        let result = &self.data[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn uint(&mut self, size: usize, little_endian: bool, label: &str) -> Result<u64, Diagnostic> {
        let bytes = self.take(size, label)?;
        let mut value = 0u64;
        if little_endian {
            for (shift, byte) in bytes.iter().enumerate() {
                value |= u64::from(*byte) << (shift * 8);
            }
        } else {
            for byte in bytes {
                value = (value << 8) | u64::from(*byte);
            }
        }
        Ok(value)
    }

    fn count(
        &mut self,
        header: Header,
        label: &str,
        minimum_item_size: usize,
    ) -> Result<usize, Diagnostic> {
        let value = self.uint(header.int_size, header.little_endian, label)?;
        let count =
            usize::try_from(value).map_err(|_| self.error(format!("{label} is too large")))?;
        if count > MAX_ITEMS {
            return Err(self.error(format!("{label} exceeds safety limit {MAX_ITEMS}")));
        }
        if minimum_item_size > 0 && count > self.remaining() / minimum_item_size {
            return Err(self.error(format!("{label} exceeds remaining input")));
        }
        Ok(count)
    }

    fn lua_string(&mut self, header: Header, label: &str) -> Result<Option<&'a [u8]>, Diagnostic> {
        let encoded = self.uint(header.size_t_size, header.little_endian, label)?;
        let size = usize::try_from(encoded)
            .map_err(|_| self.error(format!("{label} length is too large")))?;
        if size == 0 {
            return Ok(None);
        }
        if size > self.remaining() {
            return Err(self.error(format!("truncated {label}")));
        }
        let bytes = self.take(size, label)?;
        if bytes.last() != Some(&0) {
            return Err(self.error(format!("{label} is missing its NUL terminator")));
        }
        Ok(Some(&bytes[..bytes.len() - 1]))
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    fn is_eof(&self) -> bool {
        self.offset == self.data.len()
    }

    fn error(&self, message: impl Into<String>) -> Diagnostic {
        Diagnostic::byte(message, self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_or_truncated_headers() {
        assert!(inspect(b"not lua").is_err());
        assert!(inspect(b"\x1bLua\x51").is_err());
    }

    #[test]
    fn exposes_all_lua51_opcodes() {
        assert_eq!(OPCODES.len(), 38);
        assert_eq!(OPCODES[37], "VARARG");
    }
}
