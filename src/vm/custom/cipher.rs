use super::*;

/// Per-generation cipher parameters ("the cipher algorithm varies every
/// build"): Lehmer multiplier drawn from three full-period primitives mod
/// 2^31-1 (independently for the outer blob cipher and the constant-pool
/// layer), the structural mixing constant, the per-probe derivation round
/// counts and the constant-layer round count. All drawn from a dedicated
/// seeded stream; the generated Lua side emits the identical values, and
/// every product stays below 2^53 (65539 * (2^31-2) < 2^47).
pub(crate) struct CipherParams {
    pub(crate) outer: u64,
    pub(crate) constant: u64,
    pub(crate) mix: u64,
    pub(crate) probe_rounds: [u32; 3],
    pub(crate) constant_rounds: u32,
}

pub(crate) fn cipher_params(seed: u64) -> CipherParams {
    const MULTIPLIERS: [u64; 3] = [16_807, 48_271, 65_539];
    const MIXES: [u64; 4] = [31, 33, 37, 41];
    let mut random = crate::random::Prng::new(seed ^ 0x616c_676f_7661_7237);
    let pick = |random: &mut crate::random::Prng, table: &[u64]| {
        table[(random.next_u64() % table.len() as u64) as usize]
    };
    CipherParams {
        outer: pick(&mut random, &MULTIPLIERS),
        constant: pick(&mut random, &MULTIPLIERS),
        mix: pick(&mut random, &MIXES),
        probe_rounds: [
            3 + (random.next_u64() % 7) as u32,
            3 + (random.next_u64() % 7) as u32,
            3 + (random.next_u64() % 7) as u32,
        ],
        constant_rounds: 9 + (random.next_u64() % 5) as u32,
    }
}

/// Structural inputs each audited probe function receives from the entry:
/// pairs of payload-table numeric keys (prelude/interpreter, validator/
/// helpers, and the first two probe keys). The same pairs feed the Rust-side
/// share derivation, keeping both ends bit-identical without ever storing a
/// share in the script.
pub(crate) fn cipher_probe_inputs(keys: &[u64]) -> [(u64, u64); 3] {
    [(keys[0], keys[4]), (keys[2], keys[3]), (keys[5], keys[6])]
}

/// Three key shares for the payload cipher, each COMPUTED at run time inside
/// one audited probe function from its structural input pair: mix 31*a+b,
/// then 3/5/7 Lehmer rounds (one more pair of rounds per probe). No share
/// literal exists anywhere in the generated script; the Rust cipher runs the
/// identical derivation.
pub(crate) fn cipher_shares(keys: &[u64], params: &CipherParams) -> [u64; 3] {
    let inputs = cipher_probe_inputs(keys);
    let mut shares = [0u64; 3];
    for (index, share) in shares.iter_mut().enumerate() {
        let (a, b) = inputs[index];
        let mut state = (a * params.mix + b) % 2_147_483_647;
        for _ in 0..params.probe_rounds[index] {
            state = params.outer * state % 2_147_483_647;
        }
        *share = state;
    }
    shares
}

/// Combined keystream seed: the three dynamically computed shares plus the
/// ciphertext length (31*#B on the Lua side). Every operand stays below 2^53,
/// so the generated decoder reproduces this value exactly.
pub(crate) fn cipher_state(shares: &[u64; 3], length: usize, mix: u64) -> u64 {
    1 + (shares[0] + shares[1] + shares[2] + mix * length as u64) % 2_147_483_646
}

/// Symmetric byte cipher over a Lehmer keystream (48271 mod 2147483647; the
/// combined seed is 1 + (s1+s2+s3+31*#B) mod 2147483646). Every intermediate
/// stays below 2^53, so the Lua-side double arithmetic in the generated
/// decoder reproduces this stream bit-for-bit. This raises the embedded
/// blob's entropy; it is obfuscation, NOT a cryptographic primitive.
pub(crate) fn lehmer_cipher(bytes: &[u8], shares: &[u64; 3], multiplier: u64, mix: u64) -> Vec<u8> {
    let mut state = cipher_state(shares, bytes.len(), mix);
    bytes
        .iter()
        .map(|&byte| {
            state = multiplier * state % 2_147_483_647;
            byte ^ (state % 256) as u8
        })
        .collect()
}

/// Byte ranges of every constant-record payload (all bytes after the type
/// tag: boolean value byte, number/integer 8 bytes, string content -- the
/// u32 string length stays plaintext as frame metadata) inside a canonical
/// `.obf` image, in file order. Bounded parsing: any truncation, bad count
/// or unknown tag is a diagnostic, never a panic. The framing (tags and
/// string lengths) is readable on both plaintext and encrypted images, so
/// the same scan locates the ranges for encryption and decryption.
pub(crate) fn constant_ranges(
    bytes: &[u8],
    target: Target,
) -> Result<Vec<std::ops::Range<usize>>, Diagnostic> {
    let bad = |message: &str| Diagnostic::new(format!("constant scan: {message}"));
    let u16at = |off: usize| u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
    let u32at = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    if bytes.len() < 32 || &bytes[..4] != b"OBF\x02" {
        return Err(bad("bad magic"));
    }
    let expected = if target.is_luau() { 0x75u8 } else { 0x51 };
    if bytes[4] != expected {
        return Err(bad("target mismatch"));
    }
    let np = u32at(16) as usize;
    if np == 0 || np > 65536 {
        return Err(bad("prototype count out of range"));
    }
    let mut position = 32usize;
    let mut ranges = Vec::new();
    let room = |position: usize, extra: usize| -> Result<(), Diagnostic> {
        position
            .checked_add(extra)
            .filter(|end| *end <= bytes.len())
            .map(|_| ())
            .ok_or_else(|| bad("truncated image"))
    };
    for _ in 0..np {
        room(position, 24)?;
        let upvalues = u16at(position + 8) as usize;
        let constants = u32at(position + 12) as usize;
        let code = u32at(position + 20) as usize;
        if upvalues > 256 || constants > 65536 {
            return Err(bad("prototype counts out of range"));
        }
        position += 24 + upvalues * 2;
        for _ in 0..constants {
            room(position, 1)?;
            let tag = bytes[position];
            position += 1;
            match tag {
                0 => {}
                1 => {
                    room(position, 1)?;
                    ranges.push(position..position + 1);
                    position += 1;
                }
                2 | 4 => {
                    room(position, 8)?;
                    ranges.push(position..position + 8);
                    position += 8;
                }
                3 | 5 => {
                    // The u32 length stays plaintext so the frame itself is
                    // scannable on both plaintext and ciphertext images
                    // (symmetric apply); only the content is encrypted.
                    room(position, 4)?;
                    let length = u32at(position) as usize;
                    room(position, 4 + length)?;
                    ranges.push(position + 4..position + 4 + length);
                    position += 4 + length;
                }
                _ => return Err(bad("unknown constant tag")),
            }
        }
        room(position, code)?;
        position += code;
    }
    if position != bytes.len() {
        return Err(bad("trailing bytes"));
    }
    Ok(ranges)
}

/// Keystream seed of the independent constant-pool cipher, derived from a
/// DIFFERENT structural key pair (wrapper keys 4/7) than the outer blob
/// cipher shares, advanced by 11 Lehmer rounds and mixed with the image
/// length. Never stored in the script; the target parser derives the same
/// value from the two structural keys the entry passes in.
pub(crate) fn constant_cipher_state(keys: &[u64], length: usize, params: &CipherParams) -> u64 {
    let mut state = (keys[4] * params.mix + keys[7]) % 2_147_483_647;
    for _ in 0..params.constant_rounds {
        state = params.constant * state % 2_147_483_647;
    }
    1 + (state + params.mix * length as u64) % 2_147_483_646
}

/// Symmetric constant-pool cipher: XOR every constant payload byte with the
/// Lehmer keystream (continuing across records in file order) and patch the
/// header Adler-32 over the transformed image. Applying it twice restores
/// the canonical bytes; the generated decoder runs the identical stream.
pub(crate) fn apply_constant_cipher(
    bytes: &mut [u8],
    keys: &[u64],
    target: Target,
    params: &CipherParams,
) -> Result<(), Diagnostic> {
    let ranges = constant_ranges(bytes, target)?;
    let mut state = constant_cipher_state(keys, bytes.len(), params);
    for range in ranges {
        for byte in &mut bytes[range] {
            state = params.constant * state % 2_147_483_647;
            *byte ^= (state % 256) as u8;
        }
    }
    let sum = custom::checksum(&bytes[32..]);
    bytes[28..32].copy_from_slice(&sum.to_le_bytes());
    Ok(())
}
