use super::BytecodeReport;
use crate::{Diagnostic, Target};

const MIN_VERSION: u8 = 3;
const MAX_VERSION: u8 = 14;
const CLASSES_VERSION: u8 = 100;
const MIN_TYPE_VERSION: u8 = 1;
const MAX_TYPE_VERSION: u8 = 3;
const MAX_ITEMS: usize = 1_000_000;
const MAX_STRING_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct Totals {
    instructions: usize,
    constants: usize,
}

pub fn inspect(data: &[u8]) -> Result<BytecodeReport, Diagnostic> {
    let mut reader = Reader::new(data);
    let version = reader.byte("bytecode version")?;
    if version == 0 {
        let message = String::from_utf8_lossy(reader.take(reader.remaining(), "compiler error")?);
        return Err(Diagnostic::byte(
            format!("Luau compiler error bytecode: {message}"),
            1,
        ));
    }
    if !(MIN_VERSION..=MAX_VERSION).contains(&version) && version != CLASSES_VERSION {
        return Err(reader.error(format!(
            "unsupported Luau bytecode version {version}; expected {MIN_VERSION}..={MAX_VERSION} or {CLASSES_VERSION}"
        )));
    }

    let type_version = if version >= 4 {
        let value = reader.byte("type encoding version")?;
        if !(MIN_TYPE_VERSION..=MAX_TYPE_VERSION).contains(&value) {
            return Err(reader.error(format!("unsupported Luau type encoding version {value}")));
        }
        Some(value)
    } else {
        None
    };

    let string_count = reader.count("string count")?;
    let mut total_string_bytes = 0usize;
    for _ in 0..string_count {
        let length = reader.count("string length")?;
        total_string_bytes = total_string_bytes
            .checked_add(length)
            .ok_or_else(|| reader.error("string table size overflow"))?;
        if total_string_bytes > MAX_STRING_BYTES {
            return Err(reader.error("string table exceeds safety limit"));
        }
        reader.take(length, "string data")?;
    }

    if type_version == Some(3) {
        loop {
            let index = reader.byte("userdata type index")?;
            if index == 0 {
                break;
            }
            reader.string_ref(string_count, "userdata type name")?;
        }
    }

    let prototype_count = reader.count("prototype count")?;
    let mut totals = Totals::default();
    for prototype in 0..prototype_count {
        read_prototype(
            &mut reader,
            version,
            type_version,
            string_count,
            prototype_count,
            prototype,
            &mut totals,
        )?;
    }

    let main = reader.count("main prototype id")?;
    if main >= prototype_count {
        return Err(reader.error(format!(
            "main prototype id {main} is outside prototype table of size {prototype_count}"
        )));
    }
    if !reader.is_eof() {
        return Err(reader.error(format!(
            "{} trailing byte(s) after main prototype id",
            reader.remaining()
        )));
    }

    Ok(BytecodeReport {
        target: Target::Luau,
        version,
        type_version,
        strings: string_count,
        prototypes: prototype_count,
        instructions: totals.instructions,
        constants: totals.constants,
        main_prototype: main,
    })
}

#[allow(clippy::too_many_arguments)]
fn read_prototype(
    reader: &mut Reader<'_>,
    version: u8,
    type_version: Option<u8>,
    string_count: usize,
    prototype_count: usize,
    prototype_index: usize,
    totals: &mut Totals,
) -> Result<(), Diagnostic> {
    let declared_end = if version >= 12 {
        let size = reader.count("prototype byte size")?;
        let end = reader
            .offset
            .checked_add(size)
            .ok_or_else(|| reader.error("prototype byte size overflow"))?;
        if end > reader.data.len() {
            return Err(reader.error("prototype byte size exceeds remaining input"));
        }
        Some(end)
    } else {
        None
    };

    let max_stack = reader.byte("max stack size")?;
    let parameters = reader.byte("parameter count")?;
    let upvalues = reader.byte("upvalue count")? as usize;
    let vararg = reader.byte("vararg flag")?;
    if vararg > 1 {
        return Err(reader.error(format!(
            "prototype {prototype_index} has invalid vararg flag {vararg}"
        )));
    }
    if parameters > max_stack {
        return Err(reader.error(format!(
            "prototype {prototype_index} has more parameters than stack slots"
        )));
    }

    let flags = if version >= 4 {
        let flags = reader.byte("prototype flags")?;
        let type_size = reader.count("type information size")?;
        reader.take(type_size, "type information")?;
        if type_version.is_none() {
            return Err(reader.error("missing type encoding version"));
        }
        flags
    } else {
        0
    };

    let code_count = reader.count("instruction word count")?;
    let code_bytes = code_count
        .checked_mul(4)
        .ok_or_else(|| reader.error("instruction data size overflow"))?;
    reader.take(code_bytes, "instruction data")?;
    totals.instructions = totals
        .instructions
        .checked_add(code_count)
        .ok_or_else(|| reader.error("total instruction count overflow"))?;

    let constant_count = reader.count("constant count")?;
    totals.constants = totals
        .constants
        .checked_add(constant_count)
        .ok_or_else(|| reader.error("total constant count overflow"))?;
    for constant_index in 0..constant_count {
        let tag = reader.byte("constant tag")?;
        match tag {
            0 => {}
            1 => {
                let value = reader.byte("boolean constant")?;
                if value > 1 {
                    return Err(reader.error("invalid boolean constant"));
                }
            }
            2 => {
                reader.take(8, "number constant")?;
            }
            3 => {
                reader.string_ref(string_count, "string constant")?;
            }
            4 => {
                reader.take(4, "import constant")?;
            }
            5 => {
                let keys = reader.count("table key count")?;
                for _ in 0..keys {
                    let key = reader.count("table key constant id")?;
                    if key >= constant_count {
                        return Err(reader.error(format!(
                            "table key constant id {key} is outside constant table"
                        )));
                    }
                }
            }
            6 => {
                let id = reader.count("closure prototype id")?;
                if id >= prototype_count || id >= prototype_index {
                    return Err(reader.error(format!(
                        "closure prototype id {id} does not refer to an earlier prototype"
                    )));
                }
            }
            7 => {
                reader.take(16, "vector constant")?;
            }
            8 if version >= 7 => {
                let keys = reader.count("pre-filled table key count")?;
                for _ in 0..keys {
                    let key = reader.count("pre-filled table key id")?;
                    if key >= constant_count {
                        return Err(
                            reader.error("pre-filled table key id is outside constant table")
                        );
                    }
                    let value = reader.i32("pre-filled table value id")?;
                    if value >= 0 && value as usize >= constant_index {
                        return Err(reader
                            .error("pre-filled table value must refer to an earlier constant"));
                    }
                }
            }
            9 if version >= 8 => {
                let negative = reader.byte("integer sign")?;
                if negative > 1 {
                    return Err(reader.error("invalid integer sign"));
                }
                reader.var_u64("integer magnitude")?;
            }
            10 if version >= 10 => {
                let class_name = reader.count("class name constant id")?;
                if class_name >= constant_count {
                    return Err(reader.error("class name id is outside constant table"));
                }
                let properties = reader.count("class property count")?;
                let methods = reader.count("class method count")?;
                let members = properties
                    .checked_add(methods)
                    .ok_or_else(|| reader.error("class member count overflow"))?;
                if members > MAX_ITEMS {
                    return Err(reader.error("class member count exceeds safety limit"));
                }
                for _ in 0..members {
                    let member = reader.count("class member name constant id")?;
                    if member >= constant_count {
                        return Err(reader.error("class member name id is outside constant table"));
                    }
                }
            }
            11 if version >= 13 => {
                reader.take(32, "double-precision vector constant")?;
            }
            _ => {
                return Err(reader.error(format!(
                    "constant {constant_index} has unsupported tag {tag} for bytecode version {version}"
                )));
            }
        }
    }

    let child_count = reader.count("child prototype count")?;
    for _ in 0..child_count {
        let child = reader.count("child prototype id")?;
        if child >= prototype_count || child >= prototype_index {
            return Err(reader.error(format!(
                "child prototype id {child} does not refer to an earlier prototype"
            )));
        }
    }

    reader.count("line defined")?;
    reader.string_ref(string_count, "debug name")?;

    let has_line_info = reader.byte("line information flag")?;
    if has_line_info > 1 {
        return Err(reader.error("invalid line information flag"));
    }
    if has_line_info == 1 {
        let gap_log2 = reader.byte("line gap log2")? as usize;
        if gap_log2 >= usize::BITS as usize {
            return Err(reader.error("line gap shift is too large"));
        }
        reader.take(code_count, "relative line information")?;
        let intervals = if code_count == 0 {
            0
        } else {
            ((code_count - 1) >> gap_log2) + 1
        };
        let absolute_bytes = intervals
            .checked_mul(4)
            .ok_or_else(|| reader.error("absolute line information size overflow"))?;
        reader.take(absolute_bytes, "absolute line information")?;
    }

    let has_debug_info = reader.byte("debug information flag")?;
    if has_debug_info > 1 {
        return Err(reader.error("invalid debug information flag"));
    }
    if has_debug_info == 1 {
        let locals = reader.count("local variable count")?;
        for _ in 0..locals {
            reader.string_ref(string_count, "local variable name")?;
            let start = reader.count("local start pc")?;
            let end = reader.count("local end pc")?;
            if start > end || end > code_count {
                return Err(reader.error("invalid local variable pc range"));
            }
            reader.byte("local variable register")?;
        }
        let debug_upvalues = reader.count("debug upvalue count")?;
        if debug_upvalues != upvalues {
            return Err(reader.error(format!(
                "debug upvalue count {debug_upvalues} does not match prototype count {upvalues}"
            )));
        }
        for _ in 0..debug_upvalues {
            reader.string_ref(string_count, "upvalue name")?;
        }
    }

    if version >= 11 {
        let feedback_slots = reader.count("feedback slot count")?;
        for _ in 0..feedback_slots {
            let slot_type = reader.byte("feedback slot type")?;
            if slot_type != 0 {
                return Err(reader.error(format!("unsupported feedback slot type {slot_type}")));
            }
            let pc = reader.count("feedback slot pc")?;
            if pc >= code_count {
                return Err(reader.error("feedback slot pc is outside instruction data"));
            }
        }
    }

    if version >= 12 && flags & (1 << 3) != 0 {
        reader.var_u64("prototype cost")?;
    }

    if let Some(end) = declared_end {
        if reader.offset > end {
            return Err(reader.error(format!(
                "prototype {prototype_index} exceeds its declared byte size"
            )));
        }
        // Versioned payloads may append fields that an older inspector does
        // not understand; the enclosing byte size lets us skip them safely.
        reader.offset = end;
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
        let value = &self.data[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn count(&mut self, label: &str) -> Result<usize, Diagnostic> {
        let value = self.var_u64(label)?;
        let count =
            usize::try_from(value).map_err(|_| self.error(format!("{label} is too large")))?;
        if count > MAX_ITEMS && !label.contains("length") && !label.contains("size") {
            return Err(self.error(format!("{label} exceeds safety limit {MAX_ITEMS}")));
        }
        Ok(count)
    }

    fn var_u64(&mut self, label: &str) -> Result<u64, Diagnostic> {
        let mut result = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            let byte = self.byte(label)?;
            let part = u64::from(byte & 0x7f);
            if shift == 63 && part > 1 {
                return Err(self.error(format!("{label} varint overflow")));
            }
            result |= part << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
        Err(self.error(format!("{label} varint is too long")))
    }

    fn i32(&mut self, label: &str) -> Result<i32, Diagnostic> {
        let bytes = self.take(4, label)?;
        Ok(i32::from_le_bytes(bytes.try_into().expect("four bytes")))
    }

    fn string_ref(
        &mut self,
        string_count: usize,
        label: &str,
    ) -> Result<Option<usize>, Diagnostic> {
        let encoded = self.count(label)?;
        if encoded == 0 {
            return Ok(None);
        }
        let index = encoded - 1;
        if index >= string_count {
            return Err(self.error(format!(
                "{label} id {encoded} is outside string table of size {string_count}"
            )));
        }
        Ok(Some(index))
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    fn is_eof(&self) -> bool {
        self.remaining() == 0
    }

    fn error(&self, message: impl Into<String>) -> Diagnostic {
        Diagnostic::byte(message, self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_unknown_versions() {
        assert!(inspect(&[]).is_err());
        assert!(inspect(&[2]).is_err());
        assert!(inspect(&[10]).is_err());
    }

    #[test]
    fn reports_compiler_error_blob() {
        let error = inspect(b"\0syntax error").unwrap_err();
        assert!(error.message.contains("syntax error"));
    }
}
