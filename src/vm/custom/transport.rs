use super::*;

/// K9a transport alphabet: per-image base86 over bytes 28..=126 (99
/// values). The extremes {28, 29, 125, 126} are forced in, so the span is
/// always 99 and the contiguity self-check bit stays dead; further drops
/// and the full order are seed-picked. The Lua decoder reads the baked ALPHA
/// literal, so no arithmetic digit mapping (and no 35/92/121 literals)
/// survives in the output. `pub` so the product audit can derive the same
/// set from the golden's seed (same test-supportive precedent as the
/// decrypt/extract helpers).
///
/// `BASE86_QUOTE_HOSTILE` is excluded by construction rather than by luck:
/// those three bytes are the only alphabet members whose *embedding* costs two
/// source characters (`\"`, `'`, `\\`), and with a 99-wide pool each of them
/// lands in the alphabet ~86% of the time, i.e. roughly 70 escapes per 6 KiB
/// segment. Dropping them from the pool keeps the radix at exactly 86 symbols
/// (so group widths, the 86^5 > 2^32 headroom and the decoder's shape are all
/// untouched) and pays for it by dropping 3 fewer random pool bytes.
pub(crate) const BASE86_POOL_LO: u8 = 28;
pub(crate) const BASE86_POOL_HI: u8 = 126;
pub(crate) const BASE86_QUOTE_HOSTILE: [u8; 3] = [b'"', b'\'', b'\\'];
pub(crate) const BASE86_DROPS: usize = 10;

pub fn base86_image_alphabet(seed: u64) -> [u8; 86] {
    let mut rng = crate::random::Prng::sfc(seed ^ 0x3861_6c70_6861_6265);
    let mut pool: Vec<u8> = (BASE86_POOL_LO..=BASE86_POOL_HI)
        .filter(|byte| !matches!(*byte, 28 | 29 | 125 | 126))
        .filter(|byte| !BASE86_QUOTE_HOSTILE.contains(byte))
        .collect();
    rng.shuffle(&mut pool);
    pool.truncate(pool.len() - BASE86_DROPS);
    let mut alphabet: Vec<u8> = vec![28, 29, 125, 126];
    alphabet.extend_from_slice(&pool);
    assert_eq!(alphabet.len(), 86, "K9a: alphabet pool miscounted");
    rng.shuffle(&mut alphabet);
    alphabet.try_into().unwrap()
}

/// Powers of the radix; 86^6 < 2^39, so every group value (and every Lua
/// double the emitted decoder touches) stays far below 2^53.
const BASE86_POWERS: [u64; 7] = [1, 86, 7396, 636056, 54700816, 4704270176, 404567234336];

fn base86_le_value(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (index, &byte) in bytes.iter().enumerate() {
        value |= u64::from(byte) << (8 * index);
    }
    value
}

/// K9a padded group value: payload `w` (< 2^(8k)) plus a random multiple of
/// the byte capacity inside the redundant headroom (86^width covers more
/// than k bytes for every width including tails, exactly the T9-iv room the
/// radix-85 analysis exploits). The decoder truncates by emitting exactly k
/// bytes, so padding is invisible downstream and the overflow ratio no
/// longer matches any clean theory.
fn base86_padded(
    payload: u64,
    width_chars: usize,
    payload_bytes: usize,
    rng: &mut crate::random::Prng,
) -> u64 {
    let cap = 1u64 << (8 * payload_bytes);
    debug_assert!(payload < cap, "K9a: payload exceeds its byte width");
    let pmax = (BASE86_POWERS[width_chars] - 1 - payload) / cap;
    let pad = if pmax == 0 {
        0
    } else {
        rng.index(pmax as usize + 1) as u64
    };
    payload + pad * cap
}

fn base86_emit(out: &mut String, alphabet: &[u8; 86], mut value: u64, width: usize) {
    for _ in 0..width {
        out.push(alphabet[(value % 86) as usize] as char);
        value /= 86;
    }
    debug_assert_eq!(value, 0, "K9a: group value exceeds its width");
}

/// K9a mixed-group encoder: a 4-char length prefix (part byte count, padded
/// like any 4-char group), then byte-driven mixed 4/5/6-char groups (3/4/4
/// bytes) with the width chained off the previous RAW group value, then a
/// 2/3-char tail for a 1/2-byte remainder. No length rule survives (totals
/// are arbitrary), and every group carries random high padding the decoder
/// truncates. The pad stream comes from the caller's image rng: one stream
/// across the three parts, never restarted per part.
pub(crate) fn base86_encode_mixed(
    part: &[u8],
    alphabet: &[u8; 86],
    rng: &mut crate::random::Prng,
) -> String {
    assert!(
        part.len() < (1usize << 24),
        "K9a: part exceeds the 3-byte length prefix"
    );
    let mut out = String::new();
    let prefix = base86_padded(part.len() as u64, 4, 3, rng);
    base86_emit(&mut out, alphabet, prefix, 4);
    let mut prev = prefix;
    let mut done = 0usize;
    let total = part.len();
    while total - done > 4 {
        let width = [4usize, 5, 6][(prev % 3) as usize];
        let take = if width == 4 { 3 } else { 4 };
        let value = base86_padded(base86_le_value(&part[done..done + take]), width, take, rng);
        base86_emit(&mut out, alphabet, value, width);
        prev = value;
        done += take;
    }
    match total - done {
        4 => {
            let width = [5usize, 6][(prev % 3) as usize % 2];
            let value = base86_padded(base86_le_value(&part[done..done + 4]), width, 4, rng);
            base86_emit(&mut out, alphabet, value, width);
        }
        3 => {
            let value = base86_padded(base86_le_value(&part[done..done + 3]), 4, 3, rng);
            base86_emit(&mut out, alphabet, value, 4);
        }
        2 => {
            let value = base86_padded(base86_le_value(&part[done..done + 2]), 3, 2, rng);
            base86_emit(&mut out, alphabet, value, 3);
        }
        1 => {
            let value = base86_padded(base86_le_value(&part[done..done + 1]), 2, 1, rng);
            base86_emit(&mut out, alphabet, value, 2);
        }
        0 => {}
        _ => unreachable!("K9a: bad tail remainder"),
    }
    out
}

fn base86_take(
    digit: &[Option<u64>; 256],
    bytes: &[u8],
    pos: &mut usize,
    width: usize,
) -> Result<u64, Diagnostic> {
    if *pos + width > bytes.len() {
        return Err(Diagnostic::new("base86: truncated group"));
    }
    let mut value = 0u64;
    let mut mult = 1u64;
    for i in 0..width {
        let d = digit[bytes[*pos + i] as usize]
            .ok_or_else(|| Diagnostic::new("base86: character outside the image alphabet"))?;
        value += d * mult;
        mult *= 86;
    }
    *pos += width;
    Ok(value)
}

fn base86_push_bytes(out: &mut Vec<u8>, mut value: u64, count: usize) {
    for _ in 0..count {
        out.push((value % 256) as u8);
        value /= 256;
    }
}

/// K9a decoder: mirrors the emitted Lua segment functions exactly (length
/// prefix, chained mixed widths, truncated tails, exact end-of-string).
/// Any deviation -- bad digit, truncation, trailing characters -- fails
/// closed; over-range values are legal padding, never an error (T9-iv).
/// `pub` so integration tests corrupt and re-verify payloads with the same
/// decoder the pipeline uses (same test-supportive precedent as the
/// alphabet and literal parsers).
pub fn base86_decode_mixed(text: &str, alphabet: &[u8; 86]) -> Result<Vec<u8>, Diagnostic> {
    let mut digit: [Option<u64>; 256] = [None; 256];
    for (index, &byte) in alphabet.iter().enumerate() {
        digit[byte as usize] = Some(index as u64);
    }
    let bytes = text.as_bytes();
    let mut pos = 0usize;
    let prefix = base86_take(&digit, bytes, &mut pos, 4)?;
    let total = (prefix % (1u64 << 24)) as usize;
    let mut prev = prefix;
    let mut out = Vec::with_capacity(total.min(bytes.len()));
    while total - out.len() > 4 {
        let width = [4usize, 5, 6][(prev % 3) as usize];
        let take = if width == 4 { 3 } else { 4 };
        let value = base86_take(&digit, bytes, &mut pos, width)?;
        base86_push_bytes(&mut out, value, take);
        prev = value;
    }
    match total - out.len() {
        4 => {
            let width = [5usize, 6][(prev % 3) as usize % 2];
            let value = base86_take(&digit, bytes, &mut pos, width)?;
            base86_push_bytes(&mut out, value, 4);
        }
        3 => {
            let value = base86_take(&digit, bytes, &mut pos, 4)?;
            base86_push_bytes(&mut out, value, 3);
        }
        2 => {
            let value = base86_take(&digit, bytes, &mut pos, 3)?;
            base86_push_bytes(&mut out, value, 2);
        }
        1 => {
            let value = base86_take(&digit, bytes, &mut pos, 2)?;
            base86_push_bytes(&mut out, value, 1);
        }
        0 => {}
        _ => unreachable!("K9a: bad tail remainder"),
    }
    if pos != bytes.len() {
        return Err(Diagnostic::new("base86: trailing characters"));
    }
    Ok(out)
}

/// K9a Lua embedding: escape exactly the classes `"..."` cannot hold raw
/// (`"` -> `\"`, `\` -> `\\`, bytes < 32 or >= 127 -> a decimal escape, spelled
/// as shortly as its follower allows -- see `push_decimal_escape`); the rest is
/// emitted raw. The high-byte arm is load-bearing: pushing a byte >= 128 as
/// `char` would UTF-8-encode it into two bytes (caught by the K7 vector
/// harness). The emitted decoder reads post-escape bytes via SB(), so
/// embedding is invisible to it; the product audit unescapes with the same
/// rules, and `slot_rewrite` is escape-aware.
pub(crate) fn lua_escape_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 16);
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            34 => out.push_str("\\\""),
            92 => out.push_str("\\\\"),
            0..=31 | 127..=255 => crate::minify::push_decimal_escape(
                &mut out,
                byte,
                crate::minify::next_byte_is_digit(bytes, index),
            ),
            _ => out.push(byte as char),
        }
    }
    out
}

/// Split `value` into two positive addends, both outside the audit's nice
/// set (rejection-sampled from the image stream; deterministic). K9a hides
/// the byte width (256) and the length modulus (2^24) behind such opaque
/// pairs; the radix (86) is split by the caller into [2, 84], which the
/// nice set never touches. K7 additionally splits (2^32 + c)/2^33 for modulus
/// spellings, so the reject list covers the audit's full nice set (the big
/// entries are unreachable for K9a's small values: zero behavior change).
const NICE_FULL: [u64; 17] = [
    85, 7225, 614125, 52200625, 86, 7396, 636056, 54700816, 256, 65535, 65536, 16777216,
    2147483648, 2147483647, 4294967295, 4294967296, 4294967297,
];

/// An opaque-split part is "nice" (recognizable to an analyst) exactly when
/// it lands in [`NICE_FULL`]. Shared with the K7 sandwich sampler so every
/// noise literal in every spelling passes one predicate.
pub(crate) fn is_nice_part(value: u64) -> bool {
    NICE_FULL.contains(&value)
}

pub(crate) fn opaque_split(rng: &mut crate::random::Prng, value: u64) -> (u64, u64) {
    debug_assert!(value > 2, "K9a: opaque split needs headroom");
    loop {
        let a = 1 + rng.index(value as usize - 1) as u64;
        let b = value - a;
        if !is_nice_part(a) && !is_nice_part(b) {
            return (a, b);
        }
    }
}

/// The three payload segment literals of a generated VM script: decoded
/// string literals at least 12 bytes long whose bytes all belong to the
/// image alphabet, longest three win. The baked ALPHA table is emitted as
/// eight sub-12 fragments so it can never enter the top three; short
/// literals such as format strings or probe tags never reach it either. No
/// divisibility rule: mixed groups make length residues meaningless (T9).
pub(crate) fn segment_literals(
    source: &str,
    target: Target,
    seed: u64,
) -> Result<Vec<Vec<u8>>, Diagnostic> {
    let alphabet = base86_image_alphabet(seed);
    let mut member = [false; 256];
    for &byte in &alphabet {
        member[byte as usize] = true;
    }
    let mut candidates = Vec::new();
    for token in crate::lexer::lex(source, target)? {
        if token.kind != crate::lexer::TokenKind::String {
            continue;
        }
        let value = crate::minify::literal_bytes(token.text(source), target)
            .map_err(|error| Diagnostic::new(format!("generated VM blob: {error}")))?;
        if value.len() >= 12 && value.iter().all(|&byte| member[byte as usize]) {
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

/// Reassemble the outer ciphertext: try all six segment orders, base86-decode,
/// apply the outer ChaCha8 domain, authenticate frame v2, apply the independent
/// inner domain and accept only the unique strict LZW/semantic image. Segment
/// order is validated rather than stored.
pub(crate) fn embedded_outer_ciphertext(
    source: &str,
    target: Target,
    seed: u64,
) -> Result<Vec<u8>, Diagnostic> {
    let segments = segment_literals(source, target, seed)?;
    let alphabet = base86_image_alphabet(seed);
    let params = cipher_params(seed);
    let chacha = chacha_params(seed);
    let frame_params = frame_params(seed);
    let shares = cipher_shares(&wrapper_keys(seed), &params, target);
    let permutation_term = perm_term(seed);
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
        // K9a: each segment is self-contained (own length prefix, chained
        // widths reset per segment), so decode per segment and concatenate
        // the decoded bytes; one undecodable segment kills the order.
        let mut stream = Vec::new();
        let mut ok = true;
        for index in permutation {
            match base86_decode_mixed(&String::from_utf8_lossy(&segments[index]), &alphabet) {
                Ok(bytes) => stream.extend_from_slice(&bytes),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        // The decoded stream must open with the fixed transport watermark;
        // everything after it is the outer ciphertext body. The watermark
        // also pins which segment is stream-first, so it strengthens the
        // order resolution on top of the full-image Adler gate.
        if !stream.starts_with(b"XXS:") {
            continue;
        }
        let cipher = &stream[4..];
        let frame = chacha8_feedback_decrypt(
            cipher,
            &shares,
            permutation_term,
            cipher.len() as u32,
            CHACHA8_OUTER_DOMAIN,
            target,
            &chacha,
        );
        let Ok(mut compressed) =
            open_transport_frame(&frame, &shares, permutation_term, &frame_params)
        else {
            continue;
        };
        if apply_compression_cipher_feedback(
            &mut compressed,
            &shares,
            permutation_term,
            target,
            &chacha,
            false,
        )
        .is_err()
        {
            continue;
        }
        let Ok(plain) = decompress_bytecode(&compressed) else {
            continue;
        };
        // Accept an order only after both ChaCha8 domains, frame v2, strict
        // LZW and the semantic image Adler gate all agree.
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

/// Extract the embedded payload after the anti-hook-bound outer ChaCha8 pass
/// and strict transport frame are removed. The LZW body is still protected by
/// the independently domain-separated inner ChaCha8 pass.
pub fn extract_embedded(source: &str, target: Target, seed: u64) -> Result<Vec<u8>, Diagnostic> {
    let cipher = embedded_outer_ciphertext(source, target, seed)?;
    let params = cipher_params(seed);
    let shares = cipher_shares(&wrapper_keys(seed), &params, target);
    let permutation = perm_term(seed);
    let frame = chacha8_feedback_decrypt(
        &cipher,
        &shares,
        permutation,
        cipher.len() as u32,
        CHACHA8_OUTER_DOMAIN,
        target,
        &chacha_params(seed),
    );
    open_transport_frame(&frame, &shares, permutation, &frame_params(seed))
}

/// Verification helper: remove both ChaCha8 domains, authenticate frame v2,
/// then strictly decompress the private seed-specific semantic wire image.
pub fn decrypt_embedded(source: &str, target: Target, seed: u64) -> Result<Vec<u8>, Diagnostic> {
    let mut payload = extract_embedded(source, target, seed)?;
    let params = cipher_params(seed);
    let shares = cipher_shares(&wrapper_keys(seed), &params, target);
    apply_compression_cipher_feedback(
        &mut payload,
        &shares,
        perm_term(seed),
        target,
        &chacha_params(seed),
        false,
    )?;
    decompress_bytecode(&payload)
}
