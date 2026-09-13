use super::*;

/// Source-witness share schedule. These parameters are emitted only as inputs
/// to runtime derivation; none is a final ChaCha8 key word.
pub(crate) struct CipherParams {
    pub(crate) outer: u64,
    pub(crate) mix: u64,
    pub(crate) probe_rounds: [u32; 3],
}

pub(crate) fn cipher_params(seed: u64) -> CipherParams {
    const MULTIPLIERS: [u64; 3] = [16_807, 48_271, 65_539];
    const MIXES: [u64; 4] = [31, 33, 37, 41];
    let mut random = crate::random::Prng::sfc(seed ^ 0x616c_676f_7661_7237);
    CipherParams {
        outer: MULTIPLIERS[random.index(MULTIPLIERS.len())],
        mix: MIXES[random.index(MIXES.len())],
        probe_rounds: [
            3 + random.index(7) as u32,
            3 + random.index(7) as u32,
            3 + random.index(7) as u32,
        ],
    }
}

/// Version-two transport framing. ChaCha8 supplies confidentiality; this
/// compact envelope independently authenticates its descriptor, exact length,
/// dynamic cookie, payload checksum/tag and every deterministic padding byte.
pub(crate) const TRANSPORT_FRAME_VERSION: u64 = 2;
pub(crate) const TRANSPORT_FRAME_HEADER: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FrameParams {
    pub(crate) key_coefficients: [[u64; 5]; 2],
    pub(crate) key_salts: [u64; 2],
    pub(crate) descriptor_salt: u64,
    pub(crate) cookie_salt: u64,
    pub(crate) tag_salt: u64,
    pub(crate) padding_salt: u64,
}

pub(crate) fn frame_params(seed: u64) -> FrameParams {
    let mut random = crate::random::Prng::sfc(seed ^ 0x6672_616d_6532_5f32);
    let odd = |random: &mut crate::random::Prng| 3 + 2 * random.index(31) as u64;
    let mut key_coefficients = [[0u64; 5]; 2];
    for row in &mut key_coefficients {
        for coefficient in row {
            *coefficient = odd(&mut random);
        }
    }
    FrameParams {
        key_coefficients,
        key_salts: [
            random.index(2_147_483_646) as u64,
            random.index(2_147_483_646) as u64,
        ],
        descriptor_salt: random.index(65_536) as u64,
        cookie_salt: random.index(4_294_967_296) as u64,
        tag_salt: random.index(4_294_967_296) as u64,
        padding_salt: random.index(65_536) as u64,
    }
}

pub(crate) fn transport_frame_len(payload_len: usize) -> Result<usize, Diagnostic> {
    payload_len
        .checked_add(TRANSPORT_FRAME_HEADER + 3)
        .map(|length| length / 4 * 4)
        .ok_or_else(|| Diagnostic::new("transport frame length overflow"))
}

pub(crate) fn frame_key_states(
    shares: &[u64; 3],
    permutation: u64,
    frame_len: usize,
    params: &FrameParams,
) -> [u64; 2] {
    let inputs = [
        shares[0],
        shares[1],
        shares[2],
        permutation,
        frame_len as u64,
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

fn frame_descriptor(keys: [u64; 2], params: &FrameParams) -> u64 {
    TRANSPORT_FRAME_VERSION
        + (TRANSPORT_FRAME_HEADER as u64) * 256
        + ((keys[0] + keys[1] + params.descriptor_salt) % 65_536) * 65_536
}

fn frame_cookie(length: usize, descriptor: u64, keys: [u64; 2], params: &FrameParams) -> u64 {
    (length as u64
        + descriptor * 257
        + (keys[0] % 65_536) * 65_536
        + (keys[1] % 65_536) * 17
        + params.cookie_salt)
        % 4_294_967_296
}

fn frame_tag(
    payload: &[u8],
    descriptor: u64,
    cookie: u64,
    keys: [u64; 2],
    params: &FrameParams,
) -> u64 {
    let mut left = (keys[0] + params.tag_salt) % 65_521;
    let mut right = (keys[1] + params.cookie_salt) % 65_521;
    for &byte in payload {
        left = (left * 257 + u64::from(byte)) % 65_521;
        right = (right * 263 + u64::from(byte) + left) % 65_521;
    }
    (left + right * 65_521 + cookie * 17 + descriptor * 31) % 4_294_967_296
}

fn push_u32(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&(value as u32).to_le_bytes());
}

pub(crate) fn seal_transport_frame(
    payload: &[u8],
    shares: &[u64; 3],
    permutation: u64,
    params: &FrameParams,
) -> Result<Vec<u8>, Diagnostic> {
    let total = transport_frame_len(payload.len())?;
    if payload.len() > 16_777_216 || total > 16_777_232 {
        return Err(Diagnostic::new("transport frame payload exceeds limit"));
    }
    let keys = frame_key_states(shares, permutation, total, params);
    let descriptor = frame_descriptor(keys, params);
    let cookie = frame_cookie(payload.len(), descriptor, keys, params);
    let tag = frame_tag(payload, descriptor, cookie, keys, params);
    let mut frame = Vec::with_capacity(total);
    push_u32(&mut frame, descriptor);
    push_u32(&mut frame, payload.len() as u64);
    push_u32(&mut frame, cookie);
    push_u32(&mut frame, tag);
    frame.extend_from_slice(payload);
    for index in 1..=total - frame.len() {
        frame.push(((keys[0] + keys[1] * index as u64 + params.padding_salt) % 256) as u8);
    }
    Ok(frame)
}

pub(crate) fn open_transport_frame(
    frame: &[u8],
    shares: &[u64; 3],
    permutation: u64,
    params: &FrameParams,
) -> Result<Vec<u8>, Diagnostic> {
    let bad = |message: &str| Diagnostic::new(format!("transport frame: {message}"));
    if frame.len() < TRANSPORT_FRAME_HEADER || frame.len() % 4 != 0 || frame.len() > 16_777_232 {
        return Err(bad("invalid framed length"));
    }
    let keys = frame_key_states(shares, permutation, frame.len(), params);
    let u32_at = |offset: usize| {
        u64::from(u32::from_le_bytes(
            frame[offset..offset + 4].try_into().unwrap(),
        ))
    };
    let descriptor = u32_at(0);
    let length = usize::try_from(u32_at(4)).map_err(|_| bad("payload length overflow"))?;
    if length > 16_777_216
        || transport_frame_len(length).map_err(|_| bad("length overflow"))? != frame.len()
    {
        return Err(bad("framed length mismatch"));
    }
    if descriptor != frame_descriptor(keys, params) {
        return Err(bad("version or descriptor mismatch"));
    }
    let cookie = u32_at(8);
    if cookie != frame_cookie(length, descriptor, keys, params) {
        return Err(bad("dynamic cookie mismatch"));
    }
    let payload = frame[TRANSPORT_FRAME_HEADER..TRANSPORT_FRAME_HEADER + length].to_vec();
    if u32_at(12) != frame_tag(&payload, descriptor, cookie, keys, params) {
        return Err(bad("integrity tag mismatch"));
    }
    for (offset, &byte) in frame[TRANSPORT_FRAME_HEADER + length..].iter().enumerate() {
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
/// helpers, and the first two probe keys).
pub(crate) fn cipher_probe_inputs(keys: &[u64]) -> [(u64, u64); 3] {
    [(keys[0], keys[4]), (keys[2], keys[3]), (keys[5], keys[6])]
}

/// Names the Luau key probe appends to the `debug.info(loadstring, "s")`
/// transcript. The emitted script never spells them out: the prelude
/// concatenates the hidden-name pool locals in exactly this order at run time
/// (see [`probe_transcript_unit`]), and [`runtime_probe_witness`] folds the
/// value derived from this same list, so the two sides cannot drift apart.
pub(crate) const PROBE_TRANSCRIPT_NAMES: [&str; 6] =
    ["buffer", "bit32", "table", "freeze", "debug", "info"];

/// Prelude unit key holding the assembled transcript local.
pub(crate) const PROBE_TRANSCRIPT_UNIT: &str = "PTS";

/// Lua51 fold body: the transcript is the raw `debug.getinfo` source field.
pub(crate) const PROBE_BODY_LUA51: &str = "DB and GI(LS,\"S\");A=A and A.source;";

/// Everything the emitter needs for the assembled Luau transcript: the prelude
/// unit it defines, the extra probe parameter it is threaded through (the
/// probes are sibling table entries and cannot see prelude locals), and the
/// probe body folding it onto the debug-source transcript.
pub(crate) struct ProbeTranscript {
    pub(crate) unit: &'static str,
    pub(crate) definition: String,
    pub(crate) argument: String,
    pub(crate) body: String,
}

/// Build the prelude statement, the extra probe parameter and the probe body
/// for the run-time assembled transcript, from the prelude's hidden-name
/// locals, so no library or reflection name reaches the output.
pub(crate) fn probe_transcript_unit(
    var_of: &std::collections::BTreeMap<&str, String>,
) -> ProbeTranscript {
    let unit = PROBE_TRANSCRIPT_UNIT;
    let suffix = PROBE_TRANSCRIPT_NAMES
        .map(|name| var_of[name].clone())
        .join("..\"|\"..");
    ProbeTranscript {
        unit,
        definition: format!("local {unit}={suffix};"),
        argument: format!(",{unit}"),
        body: format!("DB and GI(LS,\"s\");A=A..{unit};"),
    }
}

fn probe_transcript(target: Target) -> String {
    if target.is_luau() {
        format!("[C]{}", PROBE_TRANSCRIPT_NAMES.join("|"))
    } else {
        "=[C]".to_owned()
    }
}

pub(crate) fn runtime_probe_witness(target: Target) -> u64 {
    let source = probe_transcript(target);
    source.as_bytes().iter().fold(0u64, |state, &byte| {
        (state * 257 + u64::from(byte)) % 2_147_483_647
    })
}

pub(crate) fn cipher_shares_with_witnesses(
    keys: &[u64],
    params: &CipherParams,
    witnesses: [u64; 3],
) -> [u64; 3] {
    let inputs = cipher_probe_inputs(keys);
    let mut shares = [0u64; 3];
    for (index, share) in shares.iter_mut().enumerate() {
        let (a, b) = inputs[index];
        let mut state = (a * params.mix + b) % 2_147_483_647;
        for _ in 0..params.probe_rounds[index] {
            state = params.outer * state % 2_147_483_647;
        }
        *share = 1 + (state + witnesses[index] * params.mix) % 2_147_483_646;
    }
    shares
}

pub(crate) fn cipher_shares(keys: &[u64], params: &CipherParams, target: Target) -> [u64; 3] {
    cipher_shares_with_witnesses(keys, params, [runtime_probe_witness(target); 3])
}

#[cfg(test)]
pub(crate) fn runtime_control_mask(shares: &[u64; 3]) -> u64 {
    shares.iter().sum::<u64>() % 65_520
}

/// The six base86 digits of the entry's key-term descriptor (K3-FULL). They used to
/// be three *slots of the renumbering table*, which the entry rebuilt and published as
/// a 64-entry table; the script now carries only the six-symbol witness and the
/// permutation itself survives only as the dispatch arm keys.
pub(crate) fn perm_digits(seed: u64) -> [u64; 6] {
    let mut random = crate::random::Prng::sfc(seed ^ 0x7874_6572_6d37_7333);
    std::array::from_fn(|_| random.index(86) as u64)
}

pub(crate) fn perm_term(seed: u64) -> u64 {
    let d = perm_digits(seed);
    // 87, not the alphabet size: the fold must not spell a radix constant in the
    // emitted script (see `perm_digits` and product_audit check1).
    let fold = |pair: &[u64]| pair[0] + pair[1] * 87;
    1 + (fold(&d[0..2]) * 31 + fold(&d[2..4]) * 7 + fold(&d[4..6])) % 2_147_483_646
}
