use super::*;

/// Keystream primitive families (A2): every layer independently draws one
/// of three arithmetic stream shapes so a static replay must first
/// identify the family, then its parameters, before any keystream byte
/// can be reproduced. All operands stay below 2^53 (65539 * (2^31-2) <
/// 2^47; 1664525 * (2^32-1) < 2^53) so the Lua-side double arithmetic is
/// bit-identical.
#[derive(Clone, Copy)]
pub(crate) struct StreamParams {
    pub(crate) family: u64,
    /// Family 0/1: Lehmer multiplier. Family 1: first of the dual pair.
    pub(crate) multiplier: u64,
    /// Family 1: second Lehmer multiplier. Family 2: LCG multiplier.
    pub(crate) second: u64,
    /// Family 2: odd additive constant.
    pub(crate) add: u64,
}

pub(crate) struct Keystream {
    params: StreamParams,
    state: u64,
    state2: u64,
}

impl Keystream {
    pub(crate) fn new(params: StreamParams, state: u64) -> Self {
        // Dual-family second state derives from the first at run time on
        // the Lua side (1+(st*7+31)%2147483646); mirror it exactly.
        let state2 = 1 + (state * 7 + 31) % 2_147_483_646;
        Self {
            params,
            state,
            state2,
        }
    }

    pub(crate) fn next(&mut self) -> u8 {
        match self.params.family {
            0 => {
                self.state = self.params.multiplier * self.state % 2_147_483_647;
                (self.state % 256) as u8
            }
            1 => {
                self.state = self.params.multiplier * self.state % 2_147_483_647;
                self.state2 = self.params.second * self.state2 % 2_147_483_647;
                (((self.state + self.state2) % 2_147_483_647) % 256) as u8
            }
            _ => {
                self.state = (self.params.second * self.state + self.params.add) % 4_294_967_296;
                ((self.state - self.state % 16_777_216) / 16_777_216) as u8
            }
        }
    }
}

/// Per-generation cipher parameters ("the cipher algorithm varies every
/// build"): each layer (outer blob cipher, constant-pool cipher)
/// independently draws a stream family and its parameters, plus the
/// structural mixing constant, the per-probe derivation round counts and
/// the constant-layer round count. All drawn from a dedicated seeded
/// stream; the generated Lua side emits the identical values.
pub(crate) struct CipherParams {
    pub(crate) outer: u64,
    pub(crate) outer_stream: StreamParams,
    pub(crate) constant: u64,
    pub(crate) constant_stream: StreamParams,
    pub(crate) mix: u64,
    pub(crate) probe_rounds: [u32; 3],
    pub(crate) constant_rounds: u32,
}

pub(crate) fn cipher_params(seed: u64) -> CipherParams {
    const MULTIPLIERS: [u64; 3] = [16_807, 48_271, 65_539];
    const MIXES: [u64; 4] = [31, 33, 37, 41];
    // Odd, spectrally decent mod-2^32 multipliers whose product with any
    // 2^32 state stays below 2^53 (exact Lua doubles).
    const LCG32_MULTIPLIERS: [u64; 3] = [40_503, 69_069, 1_664_525];
    let mut random = crate::random::Prng::new(seed ^ 0x616c_676f_7661_7237);
    let pick = |random: &mut crate::random::Prng, table: &[u64]| {
        table[(random.next_u64() % table.len() as u64) as usize]
    };
    let stream = |random: &mut crate::random::Prng, lehmer: u64| {
        let family = random.next_u64() % 3;
        let second = if family == 1 {
            // Dual pair: a DIFFERENT Lehmer multiplier.
            let others: [u64; 2] = if lehmer == MULTIPLIERS[0] {
                [MULTIPLIERS[1], MULTIPLIERS[2]]
            } else if lehmer == MULTIPLIERS[1] {
                [MULTIPLIERS[0], MULTIPLIERS[2]]
            } else {
                [MULTIPLIERS[0], MULTIPLIERS[1]]
            };
            others[(random.next_u64() % 2) as usize]
        } else {
            // Family 2 (LCG mod 2^32) multiplier; unused by family 0.
            pick(random, &LCG32_MULTIPLIERS)
        };
        StreamParams {
            family,
            multiplier: lehmer,
            second,
            add: 1 + 2 * (random.next_u64() % 1_073_741_824),
        }
    };
    let outer = pick(&mut random, &MULTIPLIERS);
    let constant = pick(&mut random, &MULTIPLIERS);
    CipherParams {
        outer,
        outer_stream: stream(&mut random, outer),
        constant,
        constant_stream: stream(&mut random, constant),
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

/// Combined keystream seed: the three dynamically computed shares, the
/// cross-stage permutation term (B1: derived at run time from the rebuilt
/// opcode-renumbering table, so the payload key cannot exist without the
/// forms field's output) and the ciphertext length (31*#B on the Lua
/// side). Every operand stays below 2^53, so the generated decoder
/// reproduces this value exactly.
pub(crate) fn cipher_state(shares: &[u64; 3], perm_term: u64, length: usize, mix: u64) -> u64 {
    1 + (shares[0] + shares[1] + shares[2] + perm_term + mix * length as u64) % 2_147_483_646
}

/// Three distinct permutation slots (indices into the 64 canonical opcode
/// slots) drawn from a dedicated salted stream; the entry combines the
/// rebuilt renumbering table at these positions into the payload seed's
/// cross-stage term. Exposed so tests can reproduce the exact value.
pub(crate) fn perm_indices(seed: u64) -> [usize; 3] {
    let mut random = crate::random::Prng::new(seed ^ 0x7874_6572_6d37_7333);
    let mut used = std::collections::BTreeSet::new();
    let mut picks = [0usize; 3];
    for pick in &mut picks {
        loop {
            let index = (random.next_u64() % 64) as usize;
            if used.insert(index) {
                *pick = index;
                break;
            }
        }
    }
    picks
}

/// The payload cipher's cross-stage term: 1 + (PT[i1]*31 + PT[i2]*7 +
/// PT[i3]) over the per-seed opcode permutation. Mirror of the entry's
/// `local pv=...` line; PT is only available at run time AFTER the forms
/// field rebuilt it from the packed string.
pub(crate) fn perm_term(seed: u64) -> u64 {
    let perm = opcode_permutation(seed, 64);
    let [a, b, c] = perm_indices(seed);
    1 + (u64::from(perm[a]) * 31 + u64::from(perm[b]) * 7 + u64::from(perm[c])) % 2_147_483_646
}

/// Cross-stage term of the constant-pool cipher (B1): two framing bytes
/// of the embedded image -- the first byte of the first prototype header
/// (offset 32) and the final code byte. Both sit OUTSIDE every encrypted
/// constant range (headers, tags, lengths and code stay plaintext), so
/// the term is identical on the plaintext image at encryption time and
/// on the constant-encrypted image the runtime decrypt hands to the
/// parser: the constant-layer key cannot exist without a correctly
/// outer-decrypted blob.
pub(crate) fn constant_cross_term(bytes: &[u8]) -> u64 {
    let head = u64::from(bytes[32]);
    let tail = u64::from(bytes[bytes.len() - 1]);
    head * 31 + tail
}

/// Symmetric byte cipher over the family keystream (the combined seed is
/// 1 + (s1+s2+s3+pv+31*#B) mod 2147483646). Every intermediate stays
/// below 2^53, so the Lua-side double arithmetic in the generated
/// decoder reproduces this stream bit-for-bit. This raises the embedded
/// blob's entropy; it is obfuscation, NOT a cryptographic primitive.
pub(crate) fn outer_cipher(
    bytes: &[u8],
    shares: &[u64; 3],
    perm_term: u64,
    params: &CipherParams,
) -> Vec<u8> {
    let mut stream = Keystream::new(
        params.outer_stream,
        cipher_state(shares, perm_term, bytes.len(), params.mix),
    );
    bytes.iter().map(|&byte| byte ^ stream.next()).collect()
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

/// Keystream seed of the independent constant-pool cipher: a structural
/// key pair (wrapper keys 4/7) advanced by seeded Lehmer rounds, mixed
/// with the image length AND the cross-stage framing term (B1: two bytes
/// only available on a correctly outer-decrypted image). Never stored in
/// the script; the target cluster derives the same value.
pub(crate) fn constant_cipher_state(
    keys: &[u64],
    cross_term: u64,
    length: usize,
    params: &CipherParams,
) -> u64 {
    let mut state = (keys[4] * params.mix + keys[7]) % 2_147_483_647;
    for _ in 0..params.constant_rounds {
        state = params.constant * state % 2_147_483_647;
    }
    1 + (state + cross_term + params.mix * length as u64) % 2_147_483_646
}

/// Symmetric constant-pool cipher: XOR every constant payload byte with the
/// family keystream (continuing across records in file order) and patch the
/// header Adler-32 over the transformed image. Applying it twice restores
/// the canonical bytes; the generated decoder runs the identical stream.
pub(crate) fn apply_constant_cipher(
    bytes: &mut [u8],
    keys: &[u64],
    target: Target,
    params: &CipherParams,
) -> Result<(), Diagnostic> {
    let ranges = constant_ranges(bytes, target)?;
    // The term reads framing bytes that encryption leaves untouched, so
    // deriving it here (before the loop) matches the runtime's read of
    // the decrypted image exactly.
    let cross_term = constant_cross_term(bytes);
    let mut stream = Keystream::new(
        params.constant_stream,
        constant_cipher_state(keys, cross_term, bytes.len(), params),
    );
    for range in ranges {
        for byte in &mut bytes[range] {
            *byte ^= stream.next();
        }
    }
    let sum = custom::checksum(&bytes[32..]);
    bytes[28..32].copy_from_slice(&sum.to_le_bytes());
    Ok(())
}
