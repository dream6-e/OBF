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

/// Versioned block-transport envelope layered between the compressed-body
/// stream and the outer byte stream. The public OBF format is unaffected.
pub(crate) const BLOCK_TRANSPORT_VERSION: u64 = 1;
pub(crate) const BLOCK_TRANSPORT_HEADER: usize = 16;

/// One round of the custom 32-bit generalized Feistel network. No inverse of
/// the round function itself is required; decryption walks the same rounds in
/// reverse. The three function families are deliberately different arithmetic
/// shapes, but all operations remain exact in a Lua double.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlockRound {
    pub(crate) family: u64,
    pub(crate) a: u64,
    pub(crate) b: u64,
    pub(crate) c: u64,
    pub(crate) position: u64,
    pub(crate) key_a: u64,
    pub(crate) key_b: u64,
    pub(crate) salt: u64,
}

/// Per-seed block schedule. Only these algorithm parameters are emitted; the
/// two key states are reconstructed at runtime from the three audited shares,
/// the opcode-permutation term and the encrypted frame length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockParams {
    pub(crate) rounds: Vec<BlockRound>,
    pub(crate) key_coefficients: [[u64; 5]; 2],
    pub(crate) key_salts: [u64; 2],
    pub(crate) iv_salts: [u64; 2],
    pub(crate) descriptor_salt: u64,
    pub(crate) cookie_salt: u64,
    pub(crate) tag_salt: u64,
    pub(crate) padding_salt: u64,
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
/// build"): the outer blob and compressed-body layers independently draw a
/// stream family and its parameters, plus the structural mixing constant,
/// probe derivation rounds and inner-layer rounds. All values come from a
/// dedicated seeded stream; generated Lua emits the identical arithmetic.
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

/// Seed-specific 7..=10-round block schedule. Every schedule contains all
/// three round-function families, while order and coefficients vary. Keeping
/// this on a dedicated random stream means future transport revisions do not
/// silently perturb the existing byte/constant keystream parameters.
pub(crate) fn block_params(seed: u64) -> BlockParams {
    let mut random = crate::random::Prng::new(seed ^ 0x626c_6f63_6b37_7631);
    let word = |random: &mut crate::random::Prng| 1 + random.next_u64() % 65_535;
    let odd = |random: &mut crate::random::Prng| 3 + 2 * (random.next_u64() % 31);
    let count = 7 + (random.next_u64() % 4) as usize;
    let mut families: Vec<u64> = (0..count).map(|index| (index % 3) as u64).collect();
    random.shuffle(&mut families);
    let rounds = families
        .into_iter()
        .map(|family| BlockRound {
            family,
            a: word(&mut random),
            b: word(&mut random),
            c: word(&mut random),
            position: word(&mut random),
            key_a: word(&mut random),
            key_b: word(&mut random),
            salt: word(&mut random),
        })
        .collect();
    let mut coefficients = [[0u64; 5]; 2];
    for row in &mut coefficients {
        for value in row {
            *value = odd(&mut random);
        }
    }
    BlockParams {
        rounds,
        key_coefficients: coefficients,
        key_salts: [
            random.next_u64() % 2_147_483_646,
            random.next_u64() % 2_147_483_646,
        ],
        iv_salts: [word(&mut random), word(&mut random)],
        descriptor_salt: word(&mut random),
        cookie_salt: random.next_u64() % 4_294_967_296,
        tag_salt: random.next_u64() % 4_294_967_296,
        padding_salt: word(&mut random),
    }
}

/// Padded ciphertext length for the private transport envelope. The sixteen
/// encrypted framing bytes carry version/schedule, original length, a dynamic
/// cookie and a keyed integrity tag.
pub(crate) fn block_transport_len(payload_len: usize) -> Result<usize, Diagnostic> {
    payload_len
        .checked_add(BLOCK_TRANSPORT_HEADER + 3)
        .map(|length| length / 4 * 4)
        .ok_or_else(|| Diagnostic::new("block transport length overflow"))
}

/// Two large runtime key states. Values are kept modulo 2^31-1 rather than
/// serialized as 16-bit words, so neither state appears as a literal; each
/// round derives its own 16-bit subkey from both states.
pub(crate) fn block_key_states(
    shares: &[u64; 3],
    perm_term: u64,
    ciphertext_len: usize,
    params: &BlockParams,
) -> [u64; 2] {
    let inputs = [
        shares[0],
        shares[1],
        shares[2],
        perm_term,
        ciphertext_len as u64,
    ];
    let mut states = [0u64; 2];
    for index in 0..2 {
        let value = inputs
            .iter()
            .zip(params.key_coefficients[index])
            .fold(params.key_salts[index], |sum, (&input, coefficient)| {
                sum + input * coefficient
            });
        states[index] = 1 + value % 2_147_483_646;
    }
    states
}

fn block_descriptor(keys: [u64; 2], params: &BlockParams) -> u64 {
    let high = (keys[0] + keys[1] + params.descriptor_salt) % 256;
    BLOCK_TRANSPORT_VERSION + params.rounds.len() as u64 * 256 + 4 * 65_536 + high * 16_777_216
}

fn block_cookie(length: usize, descriptor: u64, keys: [u64; 2], params: &BlockParams) -> u64 {
    (length as u64
        + descriptor * 257
        + (keys[0] % 65_536) * 65_536
        + (keys[1] % 65_536) * 17
        + params.cookie_salt)
        % 4_294_967_296
}

fn block_tag(
    payload: &[u8],
    descriptor: u64,
    cookie: u64,
    keys: [u64; 2],
    params: &BlockParams,
) -> u64 {
    (u64::from(custom::checksum(payload))
        + cookie * 263
        + descriptor * 31
        + (keys[0] % 65_536) * 65_536
        + keys[1] % 65_536
        + params.tag_salt)
        % 4_294_967_296
}

fn block_round_value(value: u64, keys: [u64; 2], block: u64, round: BlockRound) -> u64 {
    let subkey =
        (keys[0] * round.key_a + keys[1] * round.key_b + round.salt + block * round.position)
            % 65_536;
    match round.family {
        0 => (value * value + value * round.a + subkey + block * round.b) % 65_536,
        1 => {
            let low = value % 256;
            let high = (value - low) / 256;
            (low * round.a
                + high * round.b
                + low * high * round.c
                + subkey
                + block * round.position)
                % 65_536
        }
        _ => {
            let first = (value * round.a + subkey + block * round.b) % 65_536;
            (first * first + first * round.c + subkey + block * round.position) % 65_536
        }
    }
}

fn push_u32(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&(value as u32).to_le_bytes());
}

/// Encrypt the compressed, inner-stream-protected semantic frame into chained
/// four-byte blocks. Addition modulo 2^16 replaces bit operators so the same
/// generalized Feistel network runs on stock Lua 5.1 and Luau.
pub(crate) fn encrypt_block_transport(
    payload: &[u8],
    shares: &[u64; 3],
    perm_term: u64,
    params: &BlockParams,
) -> Result<Vec<u8>, Diagnostic> {
    let total = block_transport_len(payload.len())?;
    if payload.len() > 16_777_216 || total > 16_777_232 {
        return Err(Diagnostic::new("block transport payload exceeds limit"));
    }
    let keys = block_key_states(shares, perm_term, total, params);
    let descriptor = block_descriptor(keys, params);
    let cookie = block_cookie(payload.len(), descriptor, keys, params);
    let tag = block_tag(payload, descriptor, cookie, keys, params);
    let mut frame = Vec::with_capacity(total);
    push_u32(&mut frame, descriptor);
    push_u32(&mut frame, payload.len() as u64);
    push_u32(&mut frame, cookie);
    push_u32(&mut frame, tag);
    frame.extend_from_slice(payload);
    let padding = total - frame.len();
    for index in 1..=padding {
        frame.push(((keys[0] + keys[1] * index as u64 + params.padding_salt) % 256) as u8);
    }
    debug_assert_eq!(frame.len(), total);

    let mut chain_left = (keys[0] + keys[1] * 3 + params.iv_salts[0]) % 65_536;
    let mut chain_right = (keys[1] + keys[0] * 5 + params.iv_salts[1]) % 65_536;
    let mut out = Vec::with_capacity(total);
    for (index, chunk) in frame.chunks_exact(4).enumerate() {
        let mut left = (u64::from(u16::from_le_bytes([chunk[0], chunk[1]])) + chain_left) % 65_536;
        let mut right =
            (u64::from(u16::from_le_bytes([chunk[2], chunk[3]])) + chain_right) % 65_536;
        for &round in &params.rounds {
            let value = block_round_value(right, keys, index as u64, round);
            (left, right) = (right, (left + value) % 65_536);
        }
        out.extend_from_slice(&(left as u16).to_le_bytes());
        out.extend_from_slice(&(right as u16).to_le_bytes());
        chain_left = left;
        chain_right = right;
    }
    Ok(out)
}

/// Reverse the block envelope and verify version, round count, exact padded
/// length, dynamic cookie, integrity tag and every padding byte before exposing
/// the inner image. A wrong seed or any malformed frame is a Diagnostic.
pub(crate) fn decrypt_block_transport(
    ciphertext: &[u8],
    shares: &[u64; 3],
    perm_term: u64,
    params: &BlockParams,
) -> Result<Vec<u8>, Diagnostic> {
    let bad = |message: &str| Diagnostic::new(format!("block transport: {message}"));
    if ciphertext.len() < BLOCK_TRANSPORT_HEADER
        || ciphertext.len() % 4 != 0
        || ciphertext.len() > 16_777_232
    {
        return Err(bad("invalid ciphertext length"));
    }
    let keys = block_key_states(shares, perm_term, ciphertext.len(), params);
    let mut chain_left = (keys[0] + keys[1] * 3 + params.iv_salts[0]) % 65_536;
    let mut chain_right = (keys[1] + keys[0] * 5 + params.iv_salts[1]) % 65_536;
    let mut frame = Vec::with_capacity(ciphertext.len());
    for (index, chunk) in ciphertext.chunks_exact(4).enumerate() {
        let cipher_left = u64::from(u16::from_le_bytes([chunk[0], chunk[1]]));
        let cipher_right = u64::from(u16::from_le_bytes([chunk[2], chunk[3]]));
        let mut left = cipher_left;
        let mut right = cipher_right;
        for &round in params.rounds.iter().rev() {
            let old_right = left;
            let value = block_round_value(old_right, keys, index as u64, round);
            let old_left = (right + 65_536 - value) % 65_536;
            left = old_left;
            right = old_right;
        }
        left = (left + 65_536 - chain_left) % 65_536;
        right = (right + 65_536 - chain_right) % 65_536;
        frame.extend_from_slice(&(left as u16).to_le_bytes());
        frame.extend_from_slice(&(right as u16).to_le_bytes());
        chain_left = cipher_left;
        chain_right = cipher_right;
    }
    let u32_at = |offset: usize| {
        u64::from(u32::from_le_bytes(
            frame[offset..offset + 4].try_into().unwrap(),
        ))
    };
    let descriptor = u32_at(0);
    let length = usize::try_from(u32_at(4)).map_err(|_| bad("payload length overflow"))?;
    if length > 16_777_216
        || block_transport_len(length).map_err(|_| bad("length overflow"))? != frame.len()
    {
        return Err(bad("framed length mismatch"));
    }
    if descriptor != block_descriptor(keys, params) {
        return Err(bad("version or schedule mismatch"));
    }
    let cookie = u32_at(8);
    if cookie != block_cookie(length, descriptor, keys, params) {
        return Err(bad("dynamic cookie mismatch"));
    }
    let tag = u32_at(12);
    let payload = frame[BLOCK_TRANSPORT_HEADER..BLOCK_TRANSPORT_HEADER + length].to_vec();
    if tag != block_tag(&payload, descriptor, cookie, keys, params) {
        return Err(bad("integrity tag mismatch"));
    }
    for (offset, &byte) in frame[BLOCK_TRANSPORT_HEADER + length..].iter().enumerate() {
        let expected =
            ((keys[0] + keys[1] * (offset as u64 + 1) + params.padding_salt) % 256) as u8;
        if byte != expected {
            return Err(bad("padding mismatch"));
        }
    }
    Ok(payload)
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

/// Keystream seed shared by the independent inner transport stream: a
/// structural key pair (wrapper keys 4/7) advanced by seeded Lehmer rounds,
/// mixed with the protected body length and a caller-supplied integrity-covered
/// frame term. The final state is never stored in the generated script.
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
