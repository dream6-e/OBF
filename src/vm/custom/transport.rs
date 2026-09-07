use super::*;

/// Base86 alphabet: printable ASCII 35..=121 excluding backslash (92) --
/// 86 characters, all safe inside double-quoted Lua string literals.
pub(crate) fn base86_alphabet() -> Vec<u8> {
    (35u8..=121).filter(|&byte| byte != 92).collect()
}

/// Encode bytes as base86 text: every 4-byte little-endian group becomes 5
/// alphabet characters (least significant digit first); a 1..3-byte tail
/// becomes 2..4 characters. All arithmetic stays below 2^53 so the emitted
/// target decoder reproduces the decode in plain doubles.
pub(crate) fn base86_encode(bytes: &[u8]) -> String {
    let alphabet = base86_alphabet();
    debug_assert_eq!(alphabet.len(), 86);
    let mut out = String::new();
    for chunk in bytes.chunks(4) {
        let mut value = 0u64;
        for (index, &byte) in chunk.iter().enumerate() {
            value |= u64::from(byte) << (8 * index);
        }
        let digits = if chunk.len() == 4 { 5 } else { chunk.len() + 1 };
        for _ in 0..digits {
            out.push(alphabet[(value % 86) as usize] as char);
            value /= 86;
        }
    }
    out
}

/// Decode base86 text produced by `base86_encode`, mirroring the validation
/// of the emitted segment decoders exactly: alphabet range, tail length,
/// 32-bit group bound and tail width bound are all checked.
pub(crate) fn base86_decode(text: &str) -> Result<Vec<u8>, Diagnostic> {
    let bad = |message: &str| Diagnostic::new(format!("base86: {message}"));
    let value_of = |byte: u8| -> Result<u64, Diagnostic> {
        if byte == 92 || !(35..=121).contains(&byte) {
            return Err(bad("character outside the alphabet"));
        }
        Ok(u64::from(if byte > 92 { byte - 36 } else { byte - 35 }))
    };
    let bytes = text.as_bytes();
    if bytes.len() % 5 == 1 {
        return Err(bad("dangling single character"));
    }
    let mut out = Vec::new();
    for group in bytes.chunks(5) {
        let mut value = 0u64;
        let mut multiplier = 1u64;
        for &byte in group {
            value += value_of(byte)? * multiplier;
            multiplier *= 86;
        }
        if group.len() == 5 {
            if value > u64::from(u32::MAX) {
                return Err(bad("group value overflows 32 bits"));
            }
            for _ in 0..4 {
                out.push((value % 256) as u8);
                value /= 256;
            }
        } else {
            let width = group.len() - 1;
            if value > (1u64 << (8 * width)) - 1 {
                return Err(bad("tail value overflows its byte width"));
            }
            for _ in 0..width {
                out.push((value % 256) as u8);
                value /= 256;
            }
        }
    }
    Ok(out)
}

/// The three base86 segment literals of a generated VM script: the longest
/// alphabet-only string literals (short literals such as format strings or
/// probe tags never pass the length and alphabet filters).
pub(crate) fn segment_literals(source: &str, target: Target) -> Result<Vec<Vec<u8>>, Diagnostic> {
    let mut candidates = Vec::new();
    for token in crate::lexer::lex(source, target)? {
        if token.kind != crate::lexer::TokenKind::String {
            continue;
        }
        let value = crate::minify::literal_bytes(token.text(source), target)
            .map_err(|error| Diagnostic::new(format!("generated VM blob: {error}")))?;
        if value.len() >= 12
            && value.len() % 5 != 1
            && value
                .iter()
                .all(|&byte| (35..=121).contains(&byte) && byte != 92)
        {
            candidates.push(value);
        }
    }
    if candidates.len() < 3 {
        return Err(Diagnostic::new(
            "generated VM is missing its three payload segments",
        ));
    }
    candidates.sort_by_key(|literal| std::cmp::Reverse(literal.len()));
    candidates.truncate(3);
    Ok(candidates)
}

/// Reassemble the outer ciphertext of a generated VM script: try the six
/// segment orders, base86-decode, remove the outer stream and validate the
/// dynamic block frame, then accept the unique order whose inner image
/// carries the magic and target byte.
/// The order itself is derived nowhere -- it is validated, not stored.
pub(crate) fn embedded_outer_ciphertext(
    source: &str,
    target: Target,
    seed: u64,
) -> Result<Vec<u8>, Diagnostic> {
    let segments = segment_literals(source, target)?;
    let params = cipher_params(seed);
    let shares = cipher_shares(&wrapper_keys(seed), &params);
    let expected = if target.is_luau() { 0x75u8 } else { 0x51 };
    let permutations = [
        [0usize, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut winners = Vec::new();
    for permutation in permutations {
        let mut text = Vec::new();
        for index in permutation {
            text.extend_from_slice(&segments[index]);
        }
        let Ok(stream) = base86_decode(&String::from_utf8_lossy(&text)) else {
            continue;
        };
        // The decoded stream must open with the fixed transport watermark;
        // everything after it is the outer ciphertext body. The watermark
        // also pins which segment is stream-first, so it strengthens the
        // order resolution on top of the full-image Adler gate.
        if !stream.starts_with(b"XXS:") {
            continue;
        }
        let cipher = &stream[4..];
        let blocked = outer_cipher(cipher, &shares, perm_term(seed), &params);
        let Ok(mut compressed) =
            decrypt_block_transport(&blocked, &shares, perm_term(seed), &block_params(seed))
        else {
            continue;
        };
        if apply_compression_cipher(&mut compressed, &wrapper_keys(seed), &params).is_err() {
            continue;
        }
        let Ok(plain) = decompress_bytecode(&compressed) else {
            continue;
        };
        // A segment order is accepted only after both transport ciphers, the
        // dynamic block frame, inner stream, strict LZW frame and semantic
        // image Adler gate agree.
        let recorded = plain
            .get(28..32)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
        if plain.starts_with(b"OBF\x02")
            && plain.get(4) == Some(&expected)
            && plain.get(32..).is_some()
            && recorded == Some(custom::checksum(&plain[32..]))
        {
            winners.push(cipher.to_vec());
        }
    }
    if winners.len() != 1 {
        return Err(Diagnostic::new(
            "generated VM payload segments do not resolve to a unique order",
        ));
    }
    Ok(winners.pop().unwrap())
}

/// Extract the embedded payload after removing the outer stream and block
/// envelope. The strict LZW frame remains present and its body remains
/// protected by the independent inner stream.
pub fn extract_embedded(source: &str, target: Target, seed: u64) -> Result<Vec<u8>, Diagnostic> {
    let cipher = embedded_outer_ciphertext(source, target, seed)?;
    let params = cipher_params(seed);
    let shares = cipher_shares(&wrapper_keys(seed), &params);
    let permutation = perm_term(seed);
    let blocked = outer_cipher(&cipher, &shares, permutation, &params);
    decrypt_block_transport(&blocked, &shares, permutation, &block_params(seed))
}

/// Verification helper: resolve the generated script's segmented payload,
/// remove both transport ciphers and the independent compressed-body stream,
/// then strictly decompress it. The result is the private, seed-specific ISA8
/// semantic wire image; it intentionally does not equal the public canonical
/// `.obf` bytes supplied to `emit`.
pub fn decrypt_embedded(source: &str, target: Target, seed: u64) -> Result<Vec<u8>, Diagnostic> {
    let mut payload = extract_embedded(source, target, seed)?;
    apply_compression_cipher(&mut payload, &wrapper_keys(seed), &cipher_params(seed))?;
    decompress_bytecode(&payload)
}
