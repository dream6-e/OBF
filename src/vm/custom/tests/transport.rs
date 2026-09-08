#[test]
fn bounded_lzw_roundtrips_exactly_and_rejects_malformed_frames() {
    let mut inputs = vec![
        (0..460u32)
            .map(|index| (index % 17) as u8)
            .collect::<Vec<_>>(),
        (0..16_401u32)
            .map(|index| {
                if index % 11 < 7 {
                    (index % 32) as u8
                } else {
                    index.wrapping_mul(2_654_435_761).to_le_bytes()[3]
                }
            })
            .collect(),
    ];
    for target in [Target::Lua51, Target::Luau] {
        let data = custom::encode(
            &crate::ir::compile("local function f(x)return x+1 end return f(41)", target).unwrap(),
        )
        .unwrap();
        inputs.push(
            semantic::encode(&custom::decode(&data, target).unwrap(), 735)
                .unwrap()
                .bytes,
        );
    }
    for input in inputs {
        let compressed = compress_bytecode(&input).unwrap();
        assert!(compressed.len() < input.len());
        assert_eq!(decompress_bytecode(&compressed).unwrap(), input);
        for end in 0..compressed.len() {
            assert!(decompress_bytecode(&compressed[..end]).is_err());
        }
        for index in 0..compressed.len() {
            let mut damaged = compressed.clone();
            damaged[index] ^= 1;
            assert!(
                decompress_bytecode(&damaged).is_err(),
                "LZW corruption at byte {index} was accepted"
            );
        }
    }
    let mut random = crate::random::Prng::new(0x6c7a_775f_7261_7731);
    let incompressible: Vec<u8> = (0..COMPRESSION_CHUNK)
        .map(|_| random.next_u64().to_le_bytes()[0])
        .collect();
    assert!(compress_bytecode(&incompressible).is_err());

    // Fuzz-like, structurally plausible envelopes exercise the bit reader and
    // dictionary without relying only on immediate bad-magic rejection. A
    // zero Adler value is impossible for non-empty output, so even a random
    // stream that happens to decode to the exact bound must fail closed.
    for _ in 0..256 {
        let body_len = 1 + (random.next_u64() as usize % 256);
        let padding = random.next_u64() as usize % 8;
        let mut malformed = Vec::with_capacity(COMPRESSION_HEADER + body_len);
        malformed.extend_from_slice(&COMPRESSION_MAGIC);
        malformed.extend_from_slice(
            &u32::try_from(COMPRESSION_HEADER + body_len + 1)
                .unwrap()
                .to_le_bytes(),
        );
        malformed.extend_from_slice(&u32::try_from(body_len * 8 - padding).unwrap().to_le_bytes());
        malformed.extend_from_slice(&0u32.to_le_bytes());
        malformed.extend((0..body_len).map(|_| random.next_u64().to_le_bytes()[0]));
        assert!(decompress_bytecode(&malformed).is_err());
    }

    // Feed malformed compression frames through freshly recomputed inner
    // ChaCha8, frame-v2, and outer-ChaCha8 transports. This bypasses upstream gates
    // on purpose and proves the generated Lua inverse itself still fails
    // closed before the user chunk can print anything.
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("print('MUST_NOT_RUN')", target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let image = semantic::encode(&program, 735).unwrap();
        let frame = compress_bytecode(&image.bytes).unwrap();
        let mut corruptions = Vec::new();
        let mut bad_checksum = frame.clone();
        bad_checksum[12] ^= 1;
        corruptions.push(bad_checksum);
        let mut bad_body = frame;
        bad_body[COMPRESSION_HEADER] ^= 1;
        corruptions.push(bad_body);
        for (kind, malformed) in corruptions.into_iter().enumerate() {
            let raw = super::emit::generate_from_compression_frame(
                &program,
                735,
                image.clone(),
                malformed,
            )
            .unwrap();
            let output = finalize(&raw, target, 735).unwrap();
            let workspace = native::Workspace::new();
            let path = workspace.0.join("invalid_compression.lua");
            fs::write(&path, output).unwrap();
            assert!(native::compile(target, &path).status.success());
            let runner = if target.is_luau() { "luau" } else { "lua5.1" };
            let result = Command::new(native::root().join("toolchains/bin").join(runner))
                .arg(path)
                .output()
                .unwrap();
            assert!(
                !result.status.success(),
                "{target} LZW corruption {kind} ran"
            );
            assert!(
                result.stdout.is_empty(),
                "{target} LZW corruption {kind} leaked output"
            );
        }
    }
}

#[test]
fn chacha8_matches_published_vector_and_roundtrips_both_domains() {
    let expected = [
        0x2fef_003e, 0xd640_5f89, 0xe8b8_5b7f, 0xa1a5_091f,
        0xc30e_842c, 0x3b7f_9ace, 0x88e1_1b18, 0x1e1a_71ef,
        0x72e1_4c98, 0x416f_21b9, 0x6753_449f, 0x1956_6d45,
        0xa342_4a31, 0x01b0_86da, 0xb8fd_7b38, 0x42fe_0c0e,
    ];
    assert_eq!(chacha8_block([0; 8], 0, [0; 3]), expected);

    let payload: Vec<u8> = (0..513u32)
        .map(|index| index.wrapping_mul(2_654_435_761).to_le_bytes()[3])
        .collect();
    let mut outputs = BTreeSet::new();
    for target in [Target::Lua51, Target::Luau] {
        for seed in [0u64, 1, 735, u64::MAX] {
            let cipher = cipher_params(seed);
            let shares = cipher_shares(&wrapper_keys(seed), &cipher, target);
            let permutation = perm_term(seed);
            let params = chacha_params(seed);
            for domain in [CHACHA8_OUTER_DOMAIN, CHACHA8_INNER_DOMAIN] {
                let encrypted = chacha8_xor(
                    &payload,
                    &shares,
                    permutation,
                    0x0102_0304,
                    domain,
                    target,
                    &params,
                );
                assert_ne!(encrypted, payload);
                assert_eq!(
                    chacha8_xor(
                        &encrypted,
                        &shares,
                        permutation,
                        0x0102_0304,
                        domain,
                        target,
                        &params,
                    ),
                    payload
                );
                outputs.insert(encrypted);
            }
            let guard = runtime_attestation(target);
            let outer = chacha_material(
                &shares,
                permutation,
                0x0102_0304,
                CHACHA8_OUTER_DOMAIN,
                guard,
                &params,
            );
            let inner = chacha_material(
                &shares,
                permutation,
                0x0102_0304,
                CHACHA8_INNER_DOMAIN,
                guard,
                &params,
            );
            let changed = chacha_material(
                &shares,
                permutation,
                0x0102_0305,
                CHACHA8_OUTER_DOMAIN,
                guard,
                &params,
            );
            let wrong_guard = chacha_material(
                &shares,
                permutation,
                0x0102_0304,
                CHACHA8_OUTER_DOMAIN,
                guard.wrapping_add(1),
                &params,
            );
            assert_ne!(outer, inner);
            assert_ne!(outer, changed);
            assert_ne!(outer, wrong_guard);
        }
    }
    assert_eq!(outputs.len(), 16);
}

#[test]
fn frame_v2_roundtrips_and_rejects_every_outer_ciphertext_byte() {
    let payload: Vec<u8> = (0..513u32)
        .map(|index| index.wrapping_mul(2_654_435_761).to_le_bytes()[3])
        .collect();
    let mut frames = BTreeSet::new();
    for seed in 0..=15u64 {
        let target = if seed % 2 == 0 { Target::Lua51 } else { Target::Luau };
        let cipher = cipher_params(seed);
        let shares = cipher_shares(&wrapper_keys(seed), &cipher, target);
        let permutation = perm_term(seed);
        let params = frame_params(seed);
        let frame = seal_transport_frame(&payload, &shares, permutation, &params).unwrap();
        assert_eq!(frame.len(), transport_frame_len(payload.len()).unwrap());
        assert_eq!(
            open_transport_frame(&frame, &shares, permutation, &params).unwrap(),
            payload
        );
        frames.insert(frame.clone());

        let chacha = chacha_params(seed);
        let encrypted = chacha8_xor(
            &frame,
            &shares,
            permutation,
            frame.len() as u32,
            CHACHA8_OUTER_DOMAIN,
            target,
            &chacha,
        );
        let wrong_attestation = chacha8_xor_with_attestation(
            &encrypted,
            &shares,
            permutation,
            encrypted.len() as u32,
            CHACHA8_OUTER_DOMAIN,
            runtime_attestation(target).wrapping_add(1),
            &chacha,
        );
        assert!(open_transport_frame(
            &wrong_attestation,
            &shares,
            permutation,
            &params,
        )
        .is_err());
        for index in 0..encrypted.len() {
            let mut damaged = encrypted.clone();
            damaged[index] ^= 1;
            let opened = chacha8_xor(
                &damaged,
                &shares,
                permutation,
                damaged.len() as u32,
                CHACHA8_OUTER_DOMAIN,
                target,
                &chacha,
            );
            assert!(
                open_transport_frame(&opened, &shares, permutation, &params).is_err(),
                "outer ciphertext corruption at byte {index} was accepted"
            );
        }
        let mut wrong = shares;
        wrong[0] ^= 1;
        assert!(open_transport_frame(&frame, &wrong, permutation, &params).is_err());
        assert!(open_transport_frame(&frame, &shares, permutation + 1, &params).is_err());
        assert!(open_transport_frame(&frame, &shares, permutation, &frame_params(seed + 1)).is_err());
    }
    assert!(frames.len() >= 12);

    let seed = 735;
    let cipher = cipher_params(seed);
    let shares = cipher_shares(&wrapper_keys(seed), &cipher, Target::Lua51);
    let permutation = perm_term(seed);
    let params = frame_params(seed);
    for length in 0..=19usize {
        let plain: Vec<u8> = (0..length).map(|index| (index * 37 + length) as u8).collect();
        let frame = seal_transport_frame(&plain, &shares, permutation, &params).unwrap();
        assert_eq!(frame.len(), (length + 16 + 3) / 4 * 4);
        assert_eq!(open_transport_frame(&frame, &shares, permutation, &params).unwrap(), plain);
    }
    assert!(open_transport_frame(&[], &shares, permutation, &params).is_err());
    assert!(transport_frame_len(usize::MAX).is_err());
}

#[test]
fn runtime_probe_witness_is_required_by_every_share_and_control_mask() {
    assert_ne!(
        runtime_probe_witness(Target::Lua51),
        runtime_probe_witness(Target::Luau)
    );
    let payload: Vec<u8> = (0..257u32)
        .map(|index| index.wrapping_mul(2_654_435_761).to_le_bytes()[2])
        .collect();
    for target in [Target::Lua51, Target::Luau] {
        for seed in [0u64, 735, u64::MAX] {
            let keys = wrapper_keys(seed);
            let cipher = cipher_params(seed);
            let witness = runtime_probe_witness(target);
            let witnesses = [witness; 3];
            let shares = cipher_shares_with_witnesses(&keys, &cipher, witnesses);
            assert_eq!(shares, cipher_shares(&keys, &cipher, target));
            let mask = runtime_control_mask(&shares);
            let permutation = perm_term(seed);
            let framing = frame_params(seed);
            let encrypted =
                seal_transport_frame(&payload, &shares, permutation, &framing).unwrap();

            for changed in 0..3 {
                let mut wrong_witnesses = witnesses;
                wrong_witnesses[changed] += 1;
                let wrong =
                    cipher_shares_with_witnesses(&keys, &cipher, wrong_witnesses);
                for index in 0..3 {
                    assert_eq!(
                        wrong[index] != shares[index],
                        index == changed,
                        "{target} seed {seed}: witness/share coupling {changed}->{index}"
                    );
                }
                let wrong_mask = runtime_control_mask(&wrong);
                assert_ne!(wrong_mask, mask);
                assert_ne!(
                    wrong_mask % 2,
                    mask % 2,
                    "{target} seed {seed}: witness did not switch physical state pair"
                );
                assert!(
                    open_transport_frame(&encrypted, &wrong, permutation, &framing).is_err(),
                    "{target} seed {seed}: wrong runtime witness opened payload"
                );
            }
        }
    }
}

#[test]
fn emitted_probe_transcript_masks_interpreter_control_states() {
    let source = "local function f(x)return x+3 end print(f(4),f(9))";
    let transcript =
        "a=0;b=1;while b<=#A do a=(a*257+SB(A,b))%2147483647;b=b+1 end";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 735] {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(raw.matches(transcript).count(), 3);
            assert_eq!(raw.matches("return 1+(x+a*").count(), 3);
            assert!(raw.contains("P.__obf_proto_control=(c1+c2+c3)%65520"));
            assert!(
                raw.matches("+P.__obf_proto_control)%65521").count() >= 10,
                "{target} seed {seed}: runtime mask missing from represented states"
            );
            assert!(
                raw.matches("P.__obf_proto_control%2==0").count() >= 5
                    && raw.matches("P.__obf_proto_control%2~=0").count() >= 2,
                "{target} seed {seed}: witness bit does not select physical state pairs"
            );
            if target.is_luau() {
                assert!(!raw.contains("A=A and A.source"));
            } else {
                assert_eq!(raw.matches("A=A and A.source").count(), 3);
            }
            let output = emit(&data, target, seed).unwrap();
            assert!(!output.contains("__obf_proto_control"));
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
    }
}

#[test]
fn cipher_key_is_derived_dynamically_and_never_appears_in_plaintext() {
    // Shares and final ChaCha8 material are COMPUTED at run time from script
    // structure, target source witnesses, domain/context, and attestation;
    // none of the resulting material may appear as a numeric literal (or, for
    // the large values, any digit run at all) in the output.
    for (target, fixture) in [
        (
            Target::Lua51,
            include_str!("../../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../../tests/fixtures/vm_luau.lua"),
        ),
    ] {
        for seed in [0u64, 1, 735, 7351, u64::MAX] {
            let data = compile(fixture, target).unwrap();
            let output = emit(&data, target, seed).unwrap();
            let keys = wrapper_keys(seed);
            let params = cipher_params(seed);
            let semantic = wire(&data, target, seed);
            let shares = cipher_shares(&keys, &params, target);
            let pv = perm_term(seed);
            let compressed = compress_bytecode(&semantic).unwrap();
            let compressed_header = compression_header(&compressed).unwrap();
            let frame_len = transport_frame_len(compressed.len()).unwrap();
            let frame_keys = frame_key_states(&shares, pv, frame_len, &frame_params(seed));
            let chacha = chacha_params(seed);
            let guard = runtime_attestation(target);
            let outer = chacha_material(
                &shares,
                pv,
                frame_len as u32,
                CHACHA8_OUTER_DOMAIN,
                guard,
                &chacha,
            );
            let inner = chacha_material(
                &shares,
                pv,
                compression_cipher_context(compressed_header),
                CHACHA8_INNER_DOMAIN,
                guard,
                &chacha,
            );
            let runtime_values = [
                runtime_probe_witness(target).to_string(),
                runtime_control_mask(&shares).to_string(),
                guard.to_string(),
            ];
            assert_ne!(frame_keys[0], frame_keys[1]);
            assert_ne!(outer, inner);
            let mut secrets = vec![
                shares[0].to_string(),
                shares[1].to_string(),
                shares[2].to_string(),
                pv.to_string(),
                frame_keys[0].to_string(),
                frame_keys[1].to_string(),
                outer.counter.to_string(),
                inner.counter.to_string(),
            ];
            secrets.extend(outer.key.into_iter().chain(inner.key).map(|word| word.to_string()));
            secrets.extend(outer.nonce.into_iter().chain(inner.nonce).map(|word| word.to_string()));
            for secret in &secrets {
                assert!(
                    !output.contains(secret.as_str()),
                    "{target} seed {seed}: cipher key material {secret} leaked"
                );
            }
            for token in crate::lexer::lex(&output, target).unwrap() {
                if token.kind != crate::lexer::TokenKind::Number {
                    continue;
                }
                let text = token.text(&output);
                assert!(
                    secrets
                        .iter()
                        .chain(&runtime_values)
                        .all(|secret| secret != text),
                    "{target} seed {seed}: numeric literal {text} leaks key material"
                );
            }
            // The same seed reproduces the exact script/private image, while
            // a wrong seed must fail dynamic frame v2.
            assert_eq!(emit(&data, target, seed).unwrap(), output);
            assert_eq!(
                decrypt_embedded(&output, target, seed).unwrap(),
                wire(&data, target, seed)
            );
            assert!(
                decrypt_embedded(&output, target, seed.wrapping_add(1)).is_err(),
                "{target} seed {seed}: wrong seed opened frame v2"
            );
        }
    }
}

#[test]
fn compressed_body_cipher_is_an_independent_second_layer() {
    let source = "local s='OBF_UNIQUE_SECRET_7351' local n=3.25 print(s,n)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let seed = 735;
        let output = emit(&data, target, seed).unwrap();
        let encrypted_frame = extract_embedded(&output, target, seed).unwrap();
        let semantic = wire(&data, target, seed);
        let plain_frame = compress_bytecode(&semantic).unwrap();
        let header = compression_header(&encrypted_frame).unwrap();

        // The bounded frame header remains available for allocation and key
        // derivation, but every code bit is protected by the independent
        // inner ChaCha8 body after outer ChaCha8 and frame v2 are removed.
        assert_eq!(
            &encrypted_frame[..COMPRESSION_HEADER],
            &plain_frame[..COMPRESSION_HEADER]
        );
        assert_ne!(
            &encrypted_frame[COMPRESSION_HEADER..],
            &plain_frame[COMPRESSION_HEADER..]
        );
        assert_eq!(header.original_len, semantic.len());
        assert!(encrypted_frame.len() < semantic.len());
        let secret = b"OBF_UNIQUE_SECRET_7351";
        assert!(!encrypted_frame.windows(secret.len()).any(|w| w == secret));
        let number = 3.25f64.to_le_bytes();
        assert!(!encrypted_frame.windows(8).any(|w| w == number));

        let cipher = cipher_params(seed);
        let shares = cipher_shares(&wrapper_keys(seed), &cipher, target);
        let pv = perm_term(seed);
        let mut opened = encrypted_frame.clone();
        apply_compression_cipher(&mut opened, &shares, pv, target, &chacha_params(seed)).unwrap();
        assert_eq!(opened, plain_frame);
        assert_eq!(decompress_bytecode(&opened).unwrap(), semantic);
        assert_eq!(decrypt_embedded(&output, target, seed).unwrap(), semantic);

        // The same clear frame with a wrong inner key never yields partial or
        // replacement bytes: strict bit parsing/checksum rejects it.
        let mut wrong = encrypted_frame;
        let wrong_cipher = cipher_params(seed + 1);
        let wrong_shares = cipher_shares(&wrapper_keys(seed + 1), &wrong_cipher, target);
        apply_compression_cipher(
            &mut wrong,
            &wrong_shares,
            perm_term(seed + 1),
            target,
            &chacha_params(seed + 1),
        )
        .unwrap();
        assert!(decompress_bytecode(&wrong).is_err());
    }
}

#[test]
fn compression_frame_is_seed_independent_but_its_inner_stream_is_not() {
    let data = compile("local a='const' return a", Target::Lua51).unwrap();
    let semantic = wire(&data, Target::Lua51, 735);
    let plain = compress_bytecode(&semantic).unwrap();
    for seed in [0, 1, 735, u64::MAX] {
        let cipher = cipher_params(seed);
        let shares = cipher_shares(&wrapper_keys(seed), &cipher, Target::Lua51);
        let permutation = perm_term(seed);
        let mut encrypted = plain.clone();
        apply_compression_cipher(
            &mut encrypted,
            &shares,
            permutation,
            Target::Lua51,
            &chacha_params(seed),
        )
        .unwrap();
        assert_eq!(
            &encrypted[..COMPRESSION_HEADER],
            &plain[..COMPRESSION_HEADER]
        );
        assert_ne!(
            &encrypted[COMPRESSION_HEADER..],
            &plain[COMPRESSION_HEADER..]
        );
        apply_compression_cipher(
            &mut encrypted,
            &shares,
            permutation,
            Target::Lua51,
            &chacha_params(seed),
        )
        .unwrap();
        assert_eq!(encrypted, plain);
    }
}

#[test]
fn m7_structural_variants_vary_across_seeds_and_stay_reproducible() {
    // Token-level, name-agnostic detection works on the FINAL output
    // (the finalizer renames every explicit local).
    let forms = |output: &str, target: Target| -> (usize, usize, usize, usize) {
        let tokens = crate::lexer::lex(output, target).unwrap();
        let text = |index: usize| tokens[index].text(output);
        let kind = |index: usize| tokens[index].kind;
        let mut dispatch = [false; 4];
        let mut bound = [false; 3];
        let mut call = 0usize;
        let userdata = [
            output.contains("==\"userdata\""),
            output.contains("\"userdata\"=="),
        ];
        for index in 0..tokens.len() {
            // name==number / number==name / not(name~=number) /
            if index + 2 < tokens.len() {
                if kind(index) == crate::lexer::TokenKind::Identifier
                    && text(index + 1) == "=="
                    && kind(index + 2) == crate::lexer::TokenKind::Number
                {
                    dispatch[0] = true;
                }
                if kind(index) == crate::lexer::TokenKind::Number
                    && text(index + 1) == "=="
                    && kind(index + 2) == crate::lexer::TokenKind::Identifier
                {
                    dispatch[1] = true;
                }
            }
            if index + 4 < tokens.len()
                && text(index) == "not"
                && text(index + 1) == "("
                && kind(index + 2) == crate::lexer::TokenKind::Identifier
                && text(index + 3) == "~="
                && kind(index + 4) == crate::lexer::TokenKind::Number
            {
                dispatch[2] = true;
            }
            if index + 4 < tokens.len()
                && kind(index) == crate::lexer::TokenKind::Identifier
                && text(index + 1) == "-"
                && kind(index + 2) == crate::lexer::TokenKind::Number
                && text(index + 3) == "=="
                && text(index + 4) == "0"
            {
                dispatch[3] = true;
            }
            // Bound-check spellings over the operand bound.
            if index + 2 < tokens.len() {
                if kind(index) == crate::lexer::TokenKind::Identifier
                    && text(index + 1) == ">"
                    && text(index + 2) == "255"
                {
                    bound[0] = true;
                }
                if text(index) == "255"
                    && text(index + 1) == "<"
                    && kind(index + 2) == crate::lexer::TokenKind::Identifier
                {
                    bound[1] = true;
                }
                if text(index) == "<=" && text(index + 1) == "255" {
                    bound[2] = true;
                }
            }
            // Call-wrapper inversion: `if not <name> then return`.
            if index + 4 < tokens.len()
                && text(index) == "if"
                && text(index + 1) == "not"
                && kind(index + 2) == crate::lexer::TokenKind::Identifier
                && text(index + 3) == "then"
                && text(index + 4) == "return"
            {
                call = 1;
            }
        }
        (
            dispatch.iter().filter(|&&hit| hit).count(),
            bound.iter().filter(|&&hit| hit).count(),
            call,
            userdata.iter().filter(|&&hit| hit).count(),
        )
    };
    // UNION across seeds and targets: a family counts as observed if
    // ANY output exhibits it (a single output may carry only one of the
    // mutually exclusive spellings).
    let mut dispatch_total = 0usize;
    let mut bound_total = 0usize;
    let mut call_total = 0usize;
    let mut userdata_seen = [false; 2];
    for (target, fixture) in [
        (
            Target::Lua51,
            include_str!("../../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../../tests/fixtures/vm_luau.lua"),
        ),
    ] {
        let data = compile(fixture, target).unwrap();
        for seed in 0..=15u64 {
            let output = emit(&data, target, seed).unwrap();
            // Reproducibility with structural variants enabled.
            assert_eq!(emit(&data, target, seed).unwrap(), output);
            let (dispatch, bound, call, _userdata) = forms(&output, target);
            dispatch_total |= dispatch;
            bound_total |= bound;
            call_total |= call;
            if output.contains("==\"userdata\"") {
                userdata_seen[0] = true;
            }
            if output.contains("\"userdata\"==") {
                userdata_seen[1] = true;
            }
        }
    }
    assert!(
        dispatch_total >= 3,
        "dispatch variant families: {dispatch_total}"
    );
    assert_eq!(bound_total, 3, "bound variant families: {bound_total}");
    assert_eq!(call_total, 1, "call-wrapper inversion never observed");
    assert!(
        userdata_seen == [true, true],
        "userdata guard orders: {userdata_seen:?}"
    );
}

#[test]
fn field_layout_is_fully_unanchored_with_separator_and_prelude_variants() {
    // No payload field keeps a fixed file position: the entry and the
    // interpreter fields shuffle with everything else, each field's
    // separator is independently `,` or `;`, and the prelude's capture
    // statements (plus the return/destructure order) reshuffle per seed.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut entry_ranks = BTreeSet::new();
        let mut interpreter_ranks = BTreeSet::new();
        let mut first_statements = BTreeSet::new();
        let mut semicolon_outputs = 0usize;
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            // Ranks among every globally shuffled numeric field plus entry.
            let tokens = crate::lexer::lex(&raw, target).unwrap();
            let mut starts = Vec::new();
            for index in 0..tokens.len().saturating_sub(4) {
                if tokens[index].text(&raw) == "["
                    && tokens[index + 2].text(&raw) == "]"
                    && tokens[index + 3].text(&raw) == "="
                    && tokens[index + 4].text(&raw) == "function"
                {
                    starts.push(tokens[index + 1].text(&raw).to_owned());
                }
            }
            assert!((26..=29).contains(&starts.len()), "{target} seed {seed}");
            let keys = wrapper_keys(seed);
            let interpreter_key = keys[4].to_string();
            entry_ranks.insert(starts.iter().position(|k| k.starts_with('"')).unwrap());
            interpreter_ranks.insert(starts.iter().position(|k| *k == interpreter_key).unwrap());
            // The interpreter is never pinned to the last slot by
            // construction alone; across seeds it must move.
            if raw.contains("end;[") || raw.contains("end;\n[") || raw.contains("end;}") {
                semicolon_outputs += 1;
            }
            // Prelude: the environment capture is fixed-first (every
            // hidden-name lookup flows through it); the char pool's
            // slot assignment varies, and SC always precedes its only
            // dependent.
            let prelude_at = raw
                .find(&format!("[{}]=function()", keys[0]))
                .expect("prelude opener");
            let rest = &raw[prelude_at..];
            let pool_at = rest.find("local s={").expect("char pool");
            let head = rest[pool_at + "local s={function()return\"".len()..]
                .chars()
                .next()
                .unwrap();
            first_statements.insert(head.to_string());
            let sc_at = raw.find("local SC=G[").expect("SC capture");
            let z_at = raw
                .find("local Z=function(...)return{n=SC(")
                .expect("Z capture");
            assert!(sc_at < z_at, "{target} seed {seed}: Z before SC");
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(
            entry_ranks.len() >= 4,
            "{target}: entry pinned, {} ranks",
            entry_ranks.len()
        );
        assert!(
            interpreter_ranks.len() >= 4,
            "{target}: interpreter pinned, {} ranks",
            interpreter_ranks.len()
        );
        assert!(
            first_statements.len() >= 3,
            "{target}: prelude order pinned"
        );
        assert!(
            semicolon_outputs >= 10,
            "{target}: separators do not vary ({semicolon_outputs}/12)"
        );
        // The fully shuffled layout still runs the program verbatim.
        let workspace = native::Workspace::new();
        let path = workspace.0.join("unanchored.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn global_names_are_hidden_behind_a_character_function_pool() {
    // No captured global name is spelled out: string, math, error,
    // tonumber, type, loadstring, debug, ... are resolved through
    // G[name], where each name is assembled from single-character
    // functions in a seeded-shuffled pool (random slot assignment and
    // per-name format: direct concat or a table-driven helper). Only
    // the audited environment capture (getfenv/_G) and the outer
    // setmetatable call keep their plaintext spelling.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut pool_heads = BTreeSet::new();
        let mut formats = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            // Pool present with per-seed slot assignment, both assembly
            // formats appear across seeds.
            let pool_at = raw.find("local s={").expect("char pool");
            pool_heads.insert(
                raw[pool_at + "local s={function()return\"".len()..]
                    .chars()
                    .next()
                    .unwrap(),
            );
            if raw.contains("()..s[") {
                formats.insert("direct");
            }
            if raw.contains("C(s,{") {
                formats.insert("helper");
            }
            assert!(raw.contains("local G=(getfenv and getfenv(1))or _G;"));
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(emit(&data, target, seed).unwrap(), output);
            // Name-token scan of the final script: identifiers only,
            // so packed/segment literals cannot false-positive.
            let tokens = crate::lexer::lex(&output, target).unwrap();
            let mut seen: std::collections::BTreeMap<&str, usize> = Default::default();
            for token in &tokens {
                if token.kind == crate::lexer::TokenKind::Identifier {
                    *seen.entry(token.text(&output)).or_default() += 1;
                }
            }
            for name in [
                "string",
                "math",
                "error",
                "tonumber",
                "type",
                "select",
                "tostring",
                "next",
                "unpack",
                "loadstring",
                "debug",
                "getinfo",
                "info",
                "rawget",
                "rawequal",
                "getmetatable",
                "floor",
                "concat",
                "char",
                "byte",
                "format",
                "table",
                "integer",
                "fromstring",
                "freeze",
            ] {
                assert_eq!(
                    seen.get(name),
                    None,
                    "{target} seed {seed}: plaintext global {name}"
                );
            }
            assert_eq!(seen.get("setmetatable"), Some(&1), "outer wrapper call");
            assert_eq!(seen.get("getfenv"), Some(&2), "audited capture");
            assert_eq!(seen.get("_G"), Some(&1), "audited capture");
            // Differential: the payload is untouched canonical bytes.
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(
            pool_heads.len() >= 3,
            "{target}: pool slot assignment pinned"
        );
        assert_eq!(formats.len(), 2, "{target}: assembly format pinned");
        // The hidden-name script still runs the program verbatim.
        let workspace = native::Workspace::new();
        let path = workspace.0.join("hidden_names.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn core_logic_flows_through_scratch_table_slots() {
    // Every non-recursive core stage keeps its data in one scratch table
    // g[key]: per-variable fixed random keys (per seed), the value
    // constantly changing, and the table cleared before the field returns.
    // The interpreter's own frame registers stay local -- it recurses
    // through nested frames -- but its SETUP intermediates are slotted.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut key_sets = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            // Three segments, forms, decode, validate, parse core, the
            // validation loop and SETUP remain slotted. The compact ChaCha8
            // frame inverse intentionally keeps no redundant scratch copy.
            let tables = raw.matches("local g={};").count();
            assert_eq!(tables, 9, "{target} seed {seed}: {tables} scratch tables");
            let clears = raw.matches("g=nil;").count();
            assert_eq!(clears, 5, "{target} seed {seed}: {clears} clears");
            // No slotted field still declares its data as locals: the
            // parse core and segments no longer spell `local P=`, `local
            // st=` style stage locals (frame locals of the interpreter
            // remain by design).
            assert!(!raw.contains("local P={};local work=0;"));
            assert!(!raw.contains("local S=\""));
            let mut keys = std::collections::BTreeSet::new();
            for token in crate::lexer::lex(&raw, target).unwrap() {
                if token.kind == crate::lexer::TokenKind::Number {
                    let text = token.text(&raw);
                    if (1..=99).contains(&text.parse::<u64>().unwrap_or(0)) {
                        keys.insert(text.to_owned());
                    }
                }
            }
            assert!(keys.len() >= 8, "{target} seed {seed}: thin key set");
            key_sets.insert(keys);
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(
            key_sets.len() >= 6,
            "{:?}: scratch keys pinned across seeds",
            target
        );
        // The slotted stages still run the program verbatim.
        let workspace = native::Workspace::new();
        let path = workspace.0.join("slotted.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn stages_are_flattened_into_seeded_state_machines() {
    // Control-flow flattening remains on the base86 segments, parse core,
    // interpreter and contextual token decoders. ChaCha8 itself is instead
    // decomposed into independently shuffled algorithmic functions.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut state_sets = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            // Eight machines: three segments, parse core, interpreter
            // fetch/dispatch, and the shared recipe/edge token machines.
            assert_eq!(raw.matches("while true do").count(), 8);
            assert_eq!(raw.matches("local RD=function(v,l,n,s,f)").count(), 1);
            assert_eq!(raw.matches("local ED=function(v,l,f,ek)").count(), 1);
            assert!(
                raw.matches("repeat v=").count() >= 34,
                "token machines must carry dense nested dead paths"
            );
            // Split functions: frame setup, prototype header, upvalue
            // wiring, constant pool.
            assert!(raw.contains("local SETUP=function(fid,args)"));
            assert!(raw.contains("local PH=function()"));
            assert!(raw.contains("local PU=function()"));
            assert!(raw.contains("local PK=function()"));
            assert!(raw.contains("local F,R,va=SETUP(fid,args);"));
            // Graph fetch dynamically derives successors and the recipe id,
            // then routes that id into the random semantic fragment pool.
            assert_eq!(raw.matches("I=code[pc];if I==nil then E()end;").count(), 1);
            let fetch = "next1=ED(I[2],pc,fid,0);skip1=ED(I[3],pc,fid,1);rid=RD(I[1],pc,next1,skip1,fid);sid=";
            assert_eq!(raw.matches(fetch).count(), 1);
            let fetch_at = raw.find(fetch).unwrap();
            assert!(raw[fetch_at..].starts_with(fetch));
            assert!(raw[fetch_at..raw.len().min(fetch_at + 180)].contains(";pc=next1;w="));
            // Collect this seed's three-digit state numbers.
            let mut found = std::collections::BTreeSet::new();
            for token in crate::lexer::lex(&raw, target).unwrap() {
                if token.kind == crate::lexer::TokenKind::Number {
                    let text = token.text(&raw);
                    if text.len() == 3 && !text.starts_with('0') {
                        found.insert(text.to_owned());
                    }
                }
            }
            assert!(
                found.len() >= 10,
                "{target} seed {seed}: only {} state-like numbers",
                found.len()
            );
            state_sets.insert(found);
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(
            state_sets.len() >= 6,
            "{:?}: state numbering pinned across seeds",
            target
        );
        // The flattened stages still run the program verbatim.
        let workspace = native::Workspace::new();
        let path = workspace.0.join("flattened.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn decoder_splits_into_seeded_random_sections() {
    // The transport inverse, bounded LZW stages, semantic readers and parse
    // core are sibling payload fields at independently shuffled positions.
    // Depending on the seed the bit reader is either its own field or fused
    // with the LZW dictionary field; semantic readers independently use one or
    // two fields. Entry wiring alone carries the dependency order.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut lzw_shapes = BTreeSet::new();
        let mut reader_shapes = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            let keys = wrapper_keys(seed);
            assert!(raw.contains(&format!(
                "[{}]=function(B,s1,s2,s3,pv,CC,AH,CB,E,SB,SS,NCH,TC,MF,X8,AD,L32,DBG,GI,LS)",
                keys[1]
            )));
            assert!(raw.contains(&format!(
                "[{}]=function(C,s1,s2,s3,pv,CC,AH,CB,LD,E,SB,SS,NCH,TC,MF,X8,AD,L32,DBG,GI,LS)",
                keys[23]
            )));
            assert!(raw.contains(&format!("[{}]=function", keys[22])));
            assert!(raw.contains(&format!(
                "[{}]=function(B,E,SB,SF,NCH,TC,MF,IF,AD,b8,b16,b32,take,str,pos,num)",
                keys[20]
            )));
            assert!(raw.contains("function()return bp end"));
            assert!(!raw.contains("bp~=#B+1"));

            let split_lzw = raw.contains(&format!("[{}]=function", keys[21]));
            let split_readers = raw.contains(&format!("[{}]=function", keys[17]));
            lzw_shapes.insert(split_lzw);
            reader_shapes.insert(split_readers);

            // Wiring order must be block/outer inverse -> LZW helper(s) ->
            // compression frame -> semantic reader(s) -> semantic core.
            let wiring_at = raw.find("local C=VMS[").expect("transport wiring");
            let wiring_end = wiring_at + raw[wiring_at..].find("local P,np,entry=VMS[").unwrap();
            let wiring = &raw[wiring_at..wiring_end];
            let lzw_at = wiring.find("local LD=VMS[").expect("LZW wiring");
            let body_at = wiring.find("local B=VMS[").expect("frame wiring");
            assert!(lzw_at < body_at);
            if split_lzw {
                assert!(wiring.find("local BR=VMS[").unwrap() < lzw_at);
            } else {
                assert!(!wiring.contains("local BR=VMS["));
            }
            assert_eq!(
                wiring.matches("=VMS[").count(),
                4 + usize::from(split_lzw) + usize::from(split_readers)
            );
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert_eq!(lzw_shapes.len(), 2, "{target}: LZW split pinned");
        assert_eq!(reader_shapes.len(), 2, "{target}: reader split pinned");
        let workspace = native::Workspace::new();
        let path = workspace.0.join("random_sections.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn dispatch_chains_split_into_seeded_subchains() {
    // Three dispatch dimensions: operand validation is partitioned by `o %
    // groups`, recipe-to-entry routing by `rid % groups`, and the global
    // semantic fragment pool by `sid % groups`. Every sub-chain keeps its own
    // fail-closed else; group counts and arm layouts vary per seed.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut topologies = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            // Bounds chain: inside the vld closure, up to its final gate
            // (the verdict local itself is a scratch slot now, so anchor
            // on the gate's shape rather than a spelled-out name).
            let vld_at = raw
                .find("return function(o,a,b,c,j,k,at,F,P,id)")
                .expect("bounds closure");
            let vld_end = vld_at + raw[vld_at..].find("E()end;return true").unwrap();
            let bounds = &raw[vld_at..vld_end];
            // Interpreter chain: from the fetch line to the H return.
            // Anchor on the hoisted fetch locals: with the
            // fetch/dispatch phase machine the chain may sit before or
            // after the fetch line in the text.
            let f5_at = raw
                .find("local I,rid,sid,next1,skip1,o,a,b,c,k,j;local w=")
                .expect("interpreter phase machine");
            let f5_end = f5_at + raw[f5_at..].find("return H").unwrap();
            let interp = &raw[f5_at..f5_end];
            let mut chain_groups = Vec::new();
            for (chain, selector) in [(bounds, "o%"), (interp, "rid%"), (interp, "sid%")] {
                let mut modulus = None;
                let mut selectors = 0usize;
                let mut at = 0usize;
                while let Some(found) = chain[at..].find(selector) {
                    let value_at = at + found + selector.len();
                    let digits = chain[value_at..]
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .count();
                    let value: u8 = chain[value_at..value_at + digits].parse().unwrap();
                    assert!((2..=4).contains(&value), "selector modulus {value}");
                    match modulus {
                        Some(seen) => assert_eq!(seen, value, "mixed sub-chain moduli"),
                        None => modulus = Some(value),
                    }
                    selectors += 1;
                    at = value_at;
                }
                let groups = modulus.expect("no sub-chain selector");
                assert_eq!(selectors, groups as usize, "one selector per group");
                chain_groups.push(groups);
            }
            assert_ne!(chain_groups[0], 0);
            topologies.insert((chain_groups[0], chain_groups[1], chain_groups[2]));
            // Same seed must reproduce the identical topology.
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
        }
        assert!(
            topologies.len() >= 3,
            "{target}: only {} dispatch topologies across 12 seeds",
            topologies.len()
        );
        // The split chains still execute the program verbatim.
        let workspace = native::Workspace::new();
        let path = workspace.0.join("split_dispatch.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}
