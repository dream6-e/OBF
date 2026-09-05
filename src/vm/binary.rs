use crate::Diagnostic;

const HEADER_SIZE: usize = 13;
const ADLER_MODULUS: u32 = 65_521;

/// Writer for the executable private bytecode container embedded in VM output.
///
/// All integers use a fixed little-endian representation so the generated
/// target-language decoder is independent of the host compiler architecture.
pub struct Writer {
    data: Vec<u8>,
}

impl Writer {
    pub fn new(target: u8, main: u32, prototypes: u32) -> Self {
        let mut writer = Self { data: Vec::new() };
        writer.data.extend_from_slice(b"OBF");
        writer.u8(1); // private bytecode format version
        writer.u8(target);
        writer.u32(0); // payload byte length, patched by finish
        writer.u32(0); // Adler-32 payload checksum, patched by finish
        writer.u32(main);
        writer.u32(prototypes);
        writer
    }

    pub fn u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    pub fn i32(&mut self, value: i32) {
        self.data.extend_from_slice(&value.to_le_bytes());
    }

    pub fn bytes(&mut self, value: &[u8]) -> Result<(), Diagnostic> {
        let length = u32::try_from(value.len())
            .map_err(|_| Diagnostic::new("private bytecode byte string exceeds u32"))?;
        self.u32(length);
        self.data.extend_from_slice(value);
        Ok(())
    }

    pub fn number(&mut self, value: f64) -> Result<(), Diagnostic> {
        if value.is_nan() {
            self.u8(1);
        } else if value == f64::INFINITY {
            self.u8(2);
        } else if value == f64::NEG_INFINITY {
            self.u8(3);
        } else {
            self.u8(0);
            self.bytes(format!("{value:?}").as_bytes())?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<Vec<u8>, Diagnostic> {
        let payload_length = self
            .data
            .len()
            .checked_sub(HEADER_SIZE)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| Diagnostic::new("private bytecode payload exceeds u32"))?;
        let checksum = adler32(&self.data[HEADER_SIZE..]);
        self.data[5..9].copy_from_slice(&payload_length.to_le_bytes());
        self.data[9..13].copy_from_slice(&checksum.to_le_bytes());
        Ok(self.data)
    }
}

fn adler32(data: &[u8]) -> u32 {
    let mut first = 1u32;
    let mut second = 0u32;
    for byte in data {
        first = (first + u32::from(*byte)) % ADLER_MODULUS;
        second = (second + first) % ADLER_MODULUS;
    }
    first | (second << 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_versioned_checked_container() {
        let mut writer = Writer::new(0x51, 3, 7);
        writer.u16(0x1234);
        let result = writer.finish().unwrap();
        assert_eq!(&result[..5], b"OBF\x01\x51");
        assert_eq!(u32::from_le_bytes(result[5..9].try_into().unwrap()), 10);
        assert_eq!(
            u32::from_le_bytes(result[9..13].try_into().unwrap()),
            adler32(&result[13..])
        );
    }
}
