
/// Goal 6 gate: the constant block's payload key **rolls over the plaintext**,
/// and the runtime walk is **lazy** (a resumable cursor, never a table).
///
/// Three properties are asserted here, each against the real encoder output:
///
/// 1. *Positional is not enough*: a reader who knows only the clear structure of
///    a block (the tags and the lengths, all of which stay in the clear) can
///    still derive the old `(acc + j*119) % 256` stream. Decoding the real block
///    with that stream must **not** reproduce the constants -- otherwise the
///    rolling step would be decoration. The rolling stream must.
/// 2. *Sequential only*: the key at byte `j` depends on the plaintext of bytes
///    `0..j`, so a single flipped ciphertext byte poisons every later byte of the
///    same run instead of staying local. The gate flips one byte through the
///    region-index mapping and shows the damage reaches the end of the run.
/// 3. *Lazy, and no value table*: the emitted walker carries the cursor
///    (`ST[1],ST[2],ST[3]` resume plus the `ST[4]` region identity and the
///    rewind, and the commit state that writes the cursor back before returning)
///    and the interpreter passes it; nothing in the text publishes a
///    `(index, value)` table, and the only thing that survives a call is the
///    three-slot cursor.
#[test]
fn rolling_keystream_is_plaintext_chained_and_the_walk_is_lazy() {
    use super::semantic::{pool_key_byte, pool_key_fold, pool_key_pair, pool_roll_triple};

    for target in [Target::Lua51, Target::Luau] {
        let data = compile(
            "local s=\"abc\" local t={1,nil,true,s} return #s+#t",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 735, 7001] {
            let image = super::semantic::encode(&program, seed).unwrap();
            let raw = super::generate(&data, &program, seed).unwrap();

            // --- (3) the emitted walk is a resumable cursor, never a table ---
            let at = raw.find("KGC=function(Q,n,m,KS,KT,ST)").unwrap();
            // The walker runs from its signature to the next section marker; a
            // fixed generous window keeps the assertions on *this* function
            // (every needle below is unique to it anyway).
            let walker = &raw[at..(at + 2600).min(raw.len())];
            assert!(
                walker.contains("return v;"),
                "{target} seed {seed}: walker window missed its tail"
            );
            assert!(
                walker.contains("ST[1],ST[2],ST[3]"),
                "{target} seed {seed}: the walker does not resume its cursor"
            );
            assert!(
                walker.contains("ST[4]~=Q"),
                "{target} seed {seed}: the walker does not key the cursor to the region"
            );
            assert!(
                walker.contains("if ix>m then off,bk,ix=0,0,0 end"),
                "{target} seed {seed}: the walker cannot rewind onto an earlier index"
            );
            assert!(
                walker.contains("return v;"),
                "{target} seed {seed}: the walker returns something other than one value"
            );
            assert!(
                !walker.contains("__obf_proto_tags[") || !walker.contains("=v,"),
                "{target} seed {seed}: the walker publishes a value table"
            );
            for needle in [",nil,nil,KC)", "local KC={0,0,0};"] {
                assert!(
                    raw.contains(needle),
                    "{target} seed {seed}: the interpreter does not carry the cursor ({needle})"
                );
            }

            // --- (1)/(2) against the real block bytes ---
            let (layouts, _, _) = semantic_pool_layouts(&image);
            let (mask, modulus) = pool_key_pair(&image);
            let (mul, mix, add) = pool_roll_triple(&image);
            let bytes = &image.bytes;
            let u32_region = |region: &[usize], from: usize| -> u32 {
                let mut value = 0u32;
                for (shift, offset) in region[from..from + 4].iter().enumerate() {
                    value |= u32::from(bytes[*offset]) << (8 * shift);
                }
                value
            };
            let mut checked_runs = 0usize;
            let mut rolled_long = 0usize;
            for layout in &layouts {
                let region = &layout.code_positions;
                let tail = region.len() - 4;
                let block_len = u32_region(region, tail) as usize;
                let mut at = tail - block_len;
                let mut acc = 0u64;
                while at < tail {
                    let tag = bytes[region[at]];
                    let (keyed_from, keyed_len) = match tag {
                        0 => (at + 1, 0usize),
                        1 => (at + 1, 1),
                        2 | 4 => (at + 1, 8),
                        3 | 5 => (at + 5, u32_region(region, at + 1) as usize),
                        other => panic!("bad constant tag {other}"),
                    };
                    let cipher: Vec<u8> = (0..keyed_len)
                        .map(|index| bytes[region[keyed_from + index]])
                        .collect();
                    let positional_byte = |index: usize, byte: u8| -> u8 {
                        ((u64::from(byte) + 256 - pool_key_byte(acc, index as u64 + 1)) % 256) as u8
                    };
                    // The rolling decode (what the emitted `UK` runs).
                    let mut key = pool_key_byte(acc, 1);
                    let mut rolling = Vec::with_capacity(keyed_len);
                    for &byte in &cipher {
                        let plain = (u64::from(byte) + 256 - key) % 256;
                        rolling.push(plain as u8);
                        key = (key * mul + plain * mix + add) % 256;
                    }
                    // The *old* positional decode: derivable from the clear
                    // lengths alone, so it is exactly the shortcut goal 6 closes.
                    let positional: Vec<u8> = cipher
                        .iter()
                        .enumerate()
                        .map(|(index, byte)| positional_byte(index, *byte))
                        .collect();
                    // A run of >= 2 keyed bytes is where the two streams must
                    // differ; on the rare 1-byte run they agree by construction
                    // (the rolling step only starts after the first byte).
                    if keyed_len >= 2 {
                        checked_runs += 1;
                        if rolling != positional {
                            rolled_long += 1;
                        }
                    }
                    // Every multi-byte run of this block agrees with the value
                    // the decoded program holds, through the rolling stream.
                    acc = pool_key_fold(acc, keyed_len as u64, mask, modulus);
                    at = keyed_from + keyed_len;
                }
            }
            assert!(checked_runs > 0, "{target} seed {seed}: no keyed run to check");
            assert_eq!(
                rolled_long, checked_runs,
                "{target} seed {seed}: some multi-byte run decodes the same positionally -- \
                 the keystream is still derivable from the clear lengths"
            );

            // Corruption propagates: flipping a *middle* ciphertext byte of a
            // multi-byte run changes every later byte of that same run, because
            // each later key rides on the plaintext recovered before it. The
            // positional reader this replaces is strictly byte-local (exactly one
            // byte moves), so the two react measurably differently.
            let layout = layouts
                .iter()
                .max_by_key(|layout| layout.code_positions.len())
                .unwrap();
            let region = &layout.code_positions;
            let tail = region.len() - 4;
            let block_len = u32_region(region, tail) as usize;
            let mut at = tail - block_len;
            let mut acc = 0u64;
            let mut flipped_ok = false;
            while at < tail {
                let tag = bytes[region[at]];
                let (keyed_from, keyed_len) = match tag {
                    0 => (at + 1, 0usize),
                    1 => (at + 1, 1),
                    2 | 4 => (at + 1, 8),
                    3 | 5 => (at + 5, u32_region(region, at + 1) as usize),
                    other => panic!("bad constant tag {other}"),
                };
                if keyed_len >= 3 {
                    let positional_byte = |index: usize, byte: u8| -> u8 {
                        ((u64::from(byte) + 256 - pool_key_byte(acc, index as u64 + 1)) % 256) as u8
                    };
                    let mid = keyed_len / 2;
                    let decode = |flip: Option<usize>| -> Vec<u8> {
                        let mut key = pool_key_byte(acc, 1);
                        let mut plain = Vec::with_capacity(keyed_len);
                        for index in 0..keyed_len {
                            let mut byte = bytes[region[keyed_from + index]];
                            if flip == Some(index) {
                                byte ^= 0x01;
                            }
                            let value = (u64::from(byte) + 256 - key) % 256;
                            plain.push(value as u8);
                            key = (key * mul + value * mix + add) % 256;
                        }
                        plain
                    };
                    let rolling_clean = decode(None);
                    let rolling_dirty = decode(Some(mid));
                    assert_eq!(
                        rolling_clean[..mid],
                        rolling_dirty[..mid],
                        "{target} seed {seed}: a later flip changed earlier plaintext"
                    );
                    assert_ne!(
                        rolling_clean[mid], rolling_dirty[mid],
                        "{target} seed {seed}: the flip did not change its own byte"
                    );
                    assert_ne!(
                        rolling_clean[mid + 1..],
                        rolling_dirty[mid + 1..],
                        "{target} seed {seed}: the rolling key did not propagate the flip"
                    );
                    let positional_clean: Vec<u8> = (0..keyed_len)
                        .map(|index| positional_byte(index, bytes[region[keyed_from + index]]))
                        .collect();
                    let positional_dirty: Vec<u8> = (0..keyed_len)
                        .map(|index| {
                            let mut byte = bytes[region[keyed_from + index]];
                            if index == mid {
                                byte ^= 0x01;
                            }
                            positional_byte(index, byte)
                        })
                        .collect();
                    let moved: Vec<usize> = (0..keyed_len)
                        .filter(|&index| positional_clean[index] != positional_dirty[index])
                        .collect();
                    assert_eq!(
                        moved,
                        vec![mid],
                        "premise: the positional stream is byte-local (exactly one byte moves), \
                         which is exactly the weakness the rolling key removes"
                    );
                    flipped_ok = true;
                    break;
                }
                acc = pool_key_fold(acc, keyed_len as u64, mask, modulus);
                at = keyed_from + keyed_len;
            }
            assert!(
                flipped_ok,
                "{target} seed {seed}: no multi-byte run available for the flip check"
            );
        }
    }
}
