use super::*;
use std::collections::HashMap;

/// Private bytecode-compression envelope. Compression precedes both ChaCha8
/// domains, so ciphertext never enters the LZW dictionary. The inner domain
/// protects only the bitstream; frame-v2-authenticated header fields remain
/// available for bounded context derivation and allocation.
pub(crate) const COMPRESSION_MAGIC: [u8; 4] = *b"LZW\x01";
pub(crate) const COMPRESSION_HEADER: usize = 16;
pub(crate) const COMPRESSION_CHUNK: usize = 8_192;
pub(crate) const COMPRESSION_LIMIT: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompressionHeader {
    pub(crate) original_len: usize,
    pub(crate) bit_len: usize,
    pub(crate) body_len: usize,
    pub(crate) checksum: u32,
    pub(crate) chunks: usize,
}

fn bad(message: &str) -> Diagnostic {
    Diagnostic::new(format!("LZW bytecode frame: {message}"))
}

fn push_u32(out: &mut Vec<u8>, value: usize) -> Result<(), Diagnostic> {
    let value = u32::try_from(value).map_err(|_| bad("32-bit field overflow"))?;
    out.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn u32_at(bytes: &[u8], offset: usize) -> usize {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

/// Validate the clear, frame-v2-covered compression header without touching
/// the inner-ChaCha8-encrypted bitstream. This is safe for context derivation.
pub(crate) fn compression_header(bytes: &[u8]) -> Result<CompressionHeader, Diagnostic> {
    if bytes.len() < COMPRESSION_HEADER || bytes[..4] != COMPRESSION_MAGIC {
        return Err(bad("bad magic or truncated header"));
    }
    let original_len = u32_at(bytes, 4);
    let bit_len = u32_at(bytes, 8);
    let checksum = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    if original_len == 0 || original_len > COMPRESSION_LIMIT {
        return Err(bad("original length out of range"));
    }
    if bit_len == 0 || bit_len.div_ceil(8) != bytes.len() - COMPRESSION_HEADER {
        return Err(bad("bitstream length mismatch"));
    }
    // This revision promises a strict size reduction. Incompressible input is
    // rejected instead of silently being mislabeled or emitted larger.
    if bytes.len() >= original_len {
        return Err(bad("frame is not smaller than its original image"));
    }
    Ok(CompressionHeader {
        original_len,
        bit_len,
        body_len: bytes.len() - COMPRESSION_HEADER,
        checksum,
        chunks: original_len.div_ceil(COMPRESSION_CHUNK),
    })
}

struct BitWriter {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bits: 0,
        }
    }

    fn write(&mut self, value: usize, width: usize) {
        debug_assert!(width == 0 || value < (1usize << width));
        for bit in 0..width {
            if self.bits % 8 == 0 {
                self.bytes.push(0);
            }
            if value & (1 << bit) != 0 {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 1 << (self.bits % 8);
            }
            self.bits += 1;
        }
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    bits: usize,
    position: usize,
}

impl<'a> BitReader<'a> {
    fn read(&mut self, width: usize) -> Result<usize, Diagnostic> {
        let end = self
            .position
            .checked_add(width)
            .filter(|end| *end <= self.bits)
            .ok_or_else(|| bad("truncated code bits"))?;
        let mut value = 0usize;
        for shift in 0..width {
            let position = self.position + shift;
            value |= usize::from((self.bytes[position / 8] >> (position % 8)) & 1) << shift;
        }
        self.position = end;
        Ok(value)
    }
}

fn reference_width(code_index: usize) -> usize {
    if code_index <= 1 {
        0
    } else {
        usize::BITS as usize - (code_index - 1).leading_zeros() as usize
    }
}

/// Standard Welch dictionary construction. Only code packing differs:
/// literals 0..31 use a short prefix, other literals keep their byte value,
/// and dictionary references encode their bounded offset. Dictionaries reset
/// at exact 8 KiB output boundaries to cap target memory and traversal work.
fn lzw_codes(input: &[u8]) -> Vec<u16> {
    debug_assert!(!input.is_empty() && input.len() <= COMPRESSION_CHUNK);
    let mut dictionary: HashMap<Vec<u8>, u16> = HashMap::new();
    for byte in 0..=u8::MAX {
        dictionary.insert(vec![byte], u16::from(byte));
    }
    let mut next = 256u16;
    let mut prefix = vec![input[0]];
    let mut codes = Vec::new();
    for &byte in &input[1..] {
        let mut candidate = prefix.clone();
        candidate.push(byte);
        if dictionary.contains_key(&candidate) {
            prefix = candidate;
        } else {
            codes.push(dictionary[&prefix]);
            dictionary.insert(candidate, next);
            next += 1;
            prefix.clear();
            prefix.push(byte);
        }
    }
    codes.push(dictionary[&prefix]);
    codes
}

fn pack_codes(writer: &mut BitWriter, codes: &[u16]) {
    for (index, &code) in codes.iter().enumerate() {
        let code = usize::from(code);
        if code >= 256 {
            // Prefix 00. At code index i, a valid standard-LZW reference is
            // in 256..=255+i (including the KwKwK special entry), so exactly
            // ceil(log2(i)) offset bits are sufficient and canonical.
            writer.write(0, 2);
            let width = reference_width(index);
            debug_assert!(index > 0 && code - 256 < index);
            writer.write(code - 256, width);
        } else if code < 32 {
            // Prefix bits 0,1 followed by a five-bit literal.
            writer.write(2, 2);
            writer.write(code, 5);
        } else {
            // Prefix bit 1 followed by the full literal byte.
            writer.write(1, 1);
            writer.write(code, 8);
        }
    }
}

/// Losslessly compress a private semantic image. Independent standard-LZW
/// dictionaries reset every 8 KiB, while their canonical code bits remain one
/// continuous stream. The frame is returned only when strictly smaller.
pub(crate) fn compress_bytecode(input: &[u8]) -> Result<Vec<u8>, Diagnostic> {
    if input.is_empty() || input.len() > COMPRESSION_LIMIT {
        return Err(bad("input length out of range"));
    }
    let mut writer = BitWriter::new();
    for chunk in input.chunks(COMPRESSION_CHUNK) {
        pack_codes(&mut writer, &lzw_codes(chunk));
    }
    let mut out = Vec::with_capacity(COMPRESSION_HEADER + writer.bytes.len());
    out.extend_from_slice(&COMPRESSION_MAGIC);
    push_u32(&mut out, input.len())?;
    push_u32(&mut out, writer.bits)?;
    out.extend_from_slice(&custom::checksum(input).to_le_bytes());
    out.extend_from_slice(&writer.bytes);
    compression_header(&out)?;
    Ok(out)
}

fn decode_lzw_chunk(reader: &mut BitReader<'_>, output_len: usize) -> Result<Vec<u8>, Diagnostic> {
    let mut prefixes: Vec<u16> = Vec::with_capacity(output_len.saturating_sub(1));
    let mut suffixes: Vec<u8> = Vec::with_capacity(output_len.saturating_sub(1));
    let mut previous: Option<u16> = None;
    let mut previous_first = 0u8;
    let mut out = Vec::with_capacity(output_len);
    let mut stack = Vec::new();
    let mut code_index = 0usize;

    while out.len() < output_len {
        let first_tag = reader.read(1)?;
        let code = if first_tag == 1 {
            let literal = reader.read(8)?;
            if literal < 32 {
                return Err(bad("non-canonical full-width literal"));
            }
            literal
        } else if reader.read(1)? == 1 {
            reader.read(5)?
        } else {
            if code_index == 0 {
                return Err(bad("first code is a dictionary reference"));
            }
            256 + reader.read(reference_width(code_index))?
        };
        let next = 256 + prefixes.len();
        if code > next || code >= u16::MAX as usize {
            return Err(bad("dictionary reference out of range"));
        }
        let special = code == next;
        if special {
            let previous = previous.ok_or_else(|| bad("orphan special dictionary code"))?;
            prefixes.push(previous);
            suffixes.push(previous_first);
        }

        stack.clear();
        let mut cursor = code;
        let mut steps = 0usize;
        while cursor >= 256 {
            let slot = cursor - 256;
            let (&prefix, &suffix) = prefixes
                .get(slot)
                .zip(suffixes.get(slot))
                .ok_or_else(|| bad("missing dictionary entry"))?;
            stack.push(suffix);
            cursor = usize::from(prefix);
            steps += 1;
            if steps > output_len - out.len() {
                return Err(bad("dictionary chain exceeds output bound"));
            }
        }
        let first = u8::try_from(cursor).map_err(|_| bad("invalid dictionary root"))?;
        stack.push(first);
        if !special {
            if let Some(previous) = previous {
                prefixes.push(previous);
                suffixes.push(first);
            }
        }
        if previous.is_some() && prefixes.len() != next + 1 - 256 {
            return Err(bad("dictionary growth mismatch"));
        }
        previous = Some(code as u16);
        previous_first = first;
        if out.len() + stack.len() > output_len {
            return Err(bad("chunk output exceeds declared length"));
        }
        out.extend(stack.iter().rev().copied());
        code_index += 1;
    }
    Ok(out)
}

/// Strict inverse of `compress_bytecode`. Dictionary references, canonical
/// packing, exact per-reset output, complete bit consumption, zero padding and
/// the final Adler-32 must all agree before bytes are exposed.
pub(crate) fn decompress_bytecode(frame: &[u8]) -> Result<Vec<u8>, Diagnostic> {
    let header = compression_header(frame)?;
    let body = &frame[COMPRESSION_HEADER..];
    let padding = body.len() * 8 - header.bit_len;
    if padding > 7 || padding > 0 && body[body.len() - 1] >> (8 - padding) != 0 {
        return Err(bad("non-zero bit padding"));
    }
    let mut reader = BitReader {
        bytes: body,
        bits: header.bit_len,
        position: 0,
    };
    let mut out = Vec::with_capacity(header.original_len);
    while out.len() < header.original_len {
        let remaining = header.original_len - out.len();
        out.extend_from_slice(&decode_lzw_chunk(
            &mut reader,
            remaining.min(COMPRESSION_CHUNK),
        )?);
    }
    if reader.position != header.bit_len || out.len() != header.original_len {
        return Err(bad("bitstream or output not consumed exactly"));
    }
    if custom::checksum(&out) != header.checksum {
        return Err(bad("decompressed checksum mismatch"));
    }
    Ok(out)
}

/// Integrity-covered context for the independent inner ChaCha8 domain. The
/// bounded frame header remains clear long enough to enforce allocation
/// limits, while every header field and the exact encrypted body length affect
/// runtime key/nonce derivation.
pub(crate) fn compression_cipher_context(header: CompressionHeader) -> u32 {
    (header.original_len as u64 * 31
        + header.bit_len as u64 * 17
        + u64::from(header.checksum) * 7
        + header.chunks as u64 * 13
        + header.body_len as u64)
        .rem_euclid(4_294_967_296) as u32
}

pub(crate) fn apply_compression_cipher(
    frame: &mut [u8],
    shares: &[u64; 3],
    permutation: u64,
    target: Target,
    params: &ChaChaParams,
) -> Result<(), Diagnostic> {
    let header = compression_header(frame)?;
    let body = chacha8_xor(
        &frame[COMPRESSION_HEADER..],
        shares,
        permutation,
        compression_cipher_context(header),
        CHACHA8_INNER_DOMAIN,
        target,
        params,
    );
    frame[COMPRESSION_HEADER..].copy_from_slice(&body);
    Ok(())
}

pub(crate) fn apply_compression_cipher_feedback(
    frame: &mut [u8],
    shares: &[u64; 3],
    permutation: u64,
    target: Target,
    params: &ChaChaParams,
    encrypt: bool,
) -> Result<(), Diagnostic> {
    let header = compression_header(frame)?;
    let body = if encrypt {
        chacha8_feedback_encrypt(
            &frame[COMPRESSION_HEADER..],
            shares,
            permutation,
            compression_cipher_context(header),
            CHACHA8_INNER_DOMAIN,
            target,
            params,
        )
    } else {
        chacha8_feedback_decrypt(
            &frame[COMPRESSION_HEADER..],
            shares,
            permutation,
            compression_cipher_context(header),
            CHACHA8_INNER_DOMAIN,
            target,
            params,
        )
    };
    frame[COMPRESSION_HEADER..].copy_from_slice(&body);
    Ok(())
}
