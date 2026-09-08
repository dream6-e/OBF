#[test]
fn semantic_recipe_and_edge_tokens_use_contextual_runtime_stages() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("local function f(x)return x+1 end print(f(4),f(9))", target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 1, 735, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            assert_eq!(
                image.token_layers.len(),
                super::semantic::RECIPE_TOKEN_STAGES
            );
            for layer in image.token_layers {
                assert_eq!(layer.multiplier % 2, 1);
                assert_eq!(
                    u32::from(layer.multiplier) * u32::from(layer.inverse) % 65_536,
                    1
                );
            }
            let recipe = image.recipes.iter().find(|recipe| recipe.live).unwrap().id;
            let mut tokens = BTreeSet::new();
            for context in 0..64u16 {
                let label = 1 + context * 17;
                let next = context * 29;
                let skip = context * 43;
                let prototype = context % image.prototype_order.len() as u16;
                let token = super::semantic::encode_recipe_token(
                    recipe,
                    label,
                    next,
                    skip,
                    prototype,
                    &image.token_layers,
                );
                assert_eq!(
                    super::semantic::decode_recipe_token(
                        token,
                        label,
                        next,
                        skip,
                        prototype,
                        &image.token_layers,
                    ),
                    recipe
                );
                tokens.insert(token);
            }
            assert!(
                tokens.len() >= 56,
                "{target} seed {seed}: recipe token is insufficiently contextual"
            );

            assert_eq!(image.edge_layers.len(), super::semantic::EDGE_TOKEN_STAGES);
            for layer in image.edge_layers {
                assert_eq!(layer.multiplier % 2, 1);
                assert_eq!(
                    u32::from(layer.multiplier) * u32::from(layer.inverse) % 65_536,
                    1
                );
            }
            let mut edge_tokens = BTreeSet::new();
            let mut encoded_edges = 0usize;
            for context in 0..64u16 {
                let source = 1 + context * 31;
                let prototype = context % image.prototype_order.len() as u16;
                let kind = context % 2;
                let token = super::semantic::encode_edge_token(
                    0x4321,
                    source,
                    prototype,
                    kind,
                    &image.edge_layers,
                );
                assert_eq!(
                    super::semantic::decode_edge_token(
                        token,
                        source,
                        prototype,
                        kind,
                        &image.edge_layers,
                    ),
                    0x4321
                );
                encoded_edges += usize::from(token != 0x4321);
                edge_tokens.insert(token);
            }
            assert!(encoded_edges >= 56, "edge labels remained plaintext");
            assert!(
                edge_tokens.len() >= 56,
                "{target} seed {seed}: edge token is insufficiently contextual"
            );
        }
    }
}

#[test]
fn live_recipe_descriptors_are_validation_equivalent_but_not_semantic_truth() {
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
        let program = custom::decode(&data, target).unwrap();
        let mut camouflage_layouts = BTreeSet::new();
        for seed in [0u64, 1, 735, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            let live: Vec<_> = image.recipes.iter().filter(|recipe| recipe.live).collect();
            assert!(image.camouflaged_live_recipes > live.len() / 3);
            assert!(image.camouflaged_live_ops * 20 >= image.live_recipe_ops * 9);
            let mut layout = Vec::new();
            for recipe in live {
                assert_eq!(recipe.descriptor_ops.len(), recipe.execute_ops.len());
                for (&descriptor, &actual) in recipe.descriptor_ops.iter().zip(&recipe.execute_ops)
                {
                    assert_eq!(
                        super::semantic::descriptor_class(descriptor),
                        super::semantic::descriptor_class(actual)
                    );
                    assert_eq!(
                        custom::encoding_form(descriptor),
                        custom::encoding_form(actual)
                    );
                    assert_eq!(
                        super::emit::validation(descriptor),
                        super::emit::validation(actual)
                    );
                    assert_eq!(
                        matches!(
                            descriptor,
                            Opcode::Jump | Opcode::Test | Opcode::Return | Opcode::TailCall
                        ),
                        matches!(
                            actual,
                            Opcode::Jump | Opcode::Test | Opcode::Return | Opcode::TailCall
                        )
                    );
                    if descriptor != actual {
                        layout.push((descriptor as u8, actual as u8));
                    }
                }
            }
            assert!(layout.len() >= 32, "{target} seed {seed}: thin camouflage");
            camouflage_layouts.insert(layout);
        }
        assert!(
            camouflage_layouts.len() >= 3,
            "{target}: live descriptor camouflage is seed-pinned"
        );
    }
}

#[test]
fn semantic_wire_uses_superoperators_random_graphs_and_reordered_prototypes() {
    // This is the regression for the static recovery report. The embedded
    // image must not be a canonically ordered stream with merely permuted
    // opcode numbers: use sites are recipe records, most straight-line words
    // participate in multi-primitive superoperators, successors and recipes
    // use separate context tokens, reachable neutral bundles split entries and
    // selected edges, records are physically shuffled behind random labels,
    // sibling ids are reordered, and a synthetic unreachable prototype subtree
    // breaks count/tree isomorphism.
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
        let program = custom::decode(&data, target).unwrap();
        assert_eq!(data[6], 0, "public .obf files remain encoding zero");
        assert_eq!(u32::from_le_bytes(data[24..28].try_into().unwrap()), 2);
        let identity: Vec<usize> = (0..program.prototypes.len()).collect();
        let mut wires = BTreeSet::new();
        let mut orders = BTreeSet::new();
        let mut saw_nonidentity_order = false;
        let mut saw_four_word_recipe = false;
        for seed in [0u64, 1, 2, 3, 735, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            let again = super::semantic::encode(&program, seed).unwrap();
            assert_eq!(
                again.bytes, image.bytes,
                "semantic lowering is nondeterministic"
            );
            assert_eq!(&image.bytes[..4], b"OBF\x02");
            assert_eq!(image.bytes[4], data[4]);
            assert_eq!(image.bytes[6], super::semantic::WIRE_INSTRUCTION_ENCODING);
            assert_eq!(
                u32::from_le_bytes(image.bytes[24..28].try_into().unwrap()),
                super::semantic::WIRE_ISA_VERSION
            );
            assert_ne!(image.bytes, data);
            assert_eq!(
                image.canonical_words,
                program
                    .prototypes
                    .iter()
                    .map(|prototype| prototype.code.len())
                    .sum::<usize>()
            );
            assert!(image.bundles < image.canonical_words);
            assert!(
                image.bundled_words >= image.canonical_words / 3,
                "{target} seed {seed}: only {}/{} words were superoperator members",
                image.bundled_words,
                image.canonical_words
            );
            assert!(image
                .recipes
                .iter()
                .any(|recipe| recipe.execute_ops.len() > 1));
            saw_four_word_recipe |= image
                .recipes
                .iter()
                .any(|recipe| recipe.execute_ops.len() == 4);
            let live: Vec<_> = image.recipes.iter().filter(|recipe| recipe.live).collect();
            assert_eq!(
                image.live_recipe_ops,
                live.iter().map(|recipe| recipe.execute_ops.len()).sum()
            );
            assert_eq!(
                image.camouflaged_live_recipes,
                live.iter()
                    .filter(|recipe| recipe.descriptor_ops != recipe.execute_ops)
                    .count()
            );
            assert_eq!(
                image.camouflaged_live_ops,
                live.iter()
                    .map(|recipe| {
                        recipe
                            .descriptor_ops
                            .iter()
                            .zip(&recipe.execute_ops)
                            .filter(|(descriptor, actual)| descriptor != actual)
                            .count()
                    })
                    .sum()
            );
            assert!(
                image.camouflaged_live_ops * 20 >= image.live_recipe_ops * 9,
                "{target} seed {seed}: live descriptor camouflage {}/{} is too sparse",
                image.camouflaged_live_ops,
                image.live_recipe_ops
            );
            for recipe in live {
                assert_eq!(recipe.descriptor_ops.len(), recipe.execute_ops.len());
                for (&descriptor, &actual) in recipe.descriptor_ops.iter().zip(&recipe.execute_ops)
                {
                    assert_eq!(
                        super::semantic::descriptor_class(descriptor),
                        super::semantic::descriptor_class(actual)
                    );
                    assert_eq!(
                        custom::encoding_form(descriptor),
                        custom::encoding_form(actual)
                    );
                }
            }
            assert!(
                image.reachable_decoy_bundles >= program.prototypes.len() * 2,
                "{target} seed {seed}: too few reachable neutral bundles"
            );
            assert!(image.reachable_decoy_words >= image.reachable_decoy_bundles);
            assert!(!image.neutral_decoy_recipe_ids.is_empty());
            assert!(
                image
                    .neutral_decoy_recipe_ids
                    .is_subset(&image.referenced_recipe_ids),
                "neutral decoy recipes must be graph referenced"
            );
            assert!(image.recipes.iter().all(|recipe| {
                !image.neutral_decoy_recipe_ids.contains(&recipe.id) || recipe.live
            }));
            assert!(
                image.shuffled_records >= program.prototypes.len() / 2,
                "{target} seed {seed}: too few shuffled prototype record sets"
            );
            assert!((2..=4).contains(&image.decoy_prototypes));
            assert_eq!(
                image.prototype_order.len(),
                program.prototypes.len() + image.decoy_prototypes
            );
            assert_eq!(
                u32::from_le_bytes(image.bytes[16..20].try_into().unwrap()) as usize,
                image.prototype_order.len()
            );
            let real_order: Vec<usize> = image
                .prototype_order
                .iter()
                .copied()
                .filter(|old| *old < program.prototypes.len())
                .collect();
            assert_eq!(real_order.len(), program.prototypes.len());
            saw_nonidentity_order |= real_order != identity;
            orders.insert(real_order);
            assert!(
                wires.insert(image.bytes.clone()),
                "two seeds emitted one wire"
            );

            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), image.bytes);
        }
        assert!(saw_four_word_recipe, "{target}: no four-primitive recipe");
        assert!(
            saw_nonidentity_order,
            "{target}: prototype ids stayed canonical"
        );
        assert!(
            orders.len() >= 3,
            "{target}: prototype order has little seed variety"
        );

        // The structural transformation is semantics preserving on the same
        // broad corpus used for opcode coverage.
        let workspace = native::Workspace::new();
        let path = workspace.0.join("semantic_wire.lua");
        fs::write(&path, fixture).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn global_function_segment_pool_is_decoder_coupled_interleaved_and_exact() {
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
        let program = custom::decode(&data, target).unwrap();
        let mut physical_orders = BTreeSet::new();
        for seed in [0u64, 1, 2, 735, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            assert_eq!(
                image.code_segments,
                image.prototype_segment_counts.iter().sum::<usize>()
            );
            assert!(
                image
                    .prototype_segment_counts
                    .iter()
                    .all(|&count| count == 2),
                "{target} seed {seed}: prototype segment count was not exactly two"
            );
            assert!(
                image.segments_interleaved,
                "{target} seed {seed}: global pool stayed owner-grouped"
            );
            assert_eq!(image.segment_physical_ids.len(), image.code_segments);
            assert_eq!(image.segment_physical_owners.len(), image.code_segments);
            assert_eq!(image.segment_next_ids.len(), image.code_segments);
            physical_orders.insert(image.segment_physical_ids.clone());

            let (layouts, segments) = semantic_layouts(&image);
            assert_eq!(segments.len(), image.code_segments);
            assert_eq!(layouts.len(), image.prototype_order.len());
            assert_eq!(image.segment_root_ids.len(), layouts.len());
            let ids = segments
                .iter()
                .map(|segment| segment.id)
                .collect::<BTreeSet<_>>();
            assert_eq!(ids, (1..=segments.len()).collect());
            for (index, segment) in segments.iter().enumerate() {
                assert!(!segment.payload.is_empty());
                assert_eq!(image.segment_physical_ids[index], segment.id);
                assert_eq!(image.segment_physical_owners[index], segment.owner);
                assert_eq!(image.segment_next_ids[index], segment.next);
                assert_eq!(
                    segment.next,
                    if segment.id % 2 == 1 {
                        segment.id + 1
                    } else {
                        0
                    }
                );
            }
            for (prototype, layout) in layouts.iter().enumerate() {
                assert_eq!(
                    layout.segment_count,
                    image.prototype_segment_counts[prototype]
                );
                let expected_root = prototype * 2 + 1;
                assert_eq!(image.segment_root_ids[prototype], expected_root);
                assert_eq!(
                    usize::from(super::semantic::decode_segment_root(
                        layout.root_token,
                        prototype as u16,
                        &image,
                    )),
                    expected_root
                );
                let split =
                    super::semantic::code_segment_split(layout.code_len, prototype as u16, &image);
                assert!(split > 0 && split < layout.code_len);
                let code = semantic_code(&image, prototype);
                assert_eq!(code.len(), layout.code_len);
                assert!(u16::from_le_bytes(code[..2].try_into().unwrap()) > 0);
            }
        }
        assert!(
            physical_orders.len() >= 4,
            "{target}: segment pool has little seed diversity"
        );
    }
}

#[test]
fn operand_features_are_split_into_separate_shuffled_fields() {
    // The operand-form map (`[0]=3,[1]=4,...` sequential-key literal),
    // the varint reader with its `if f==1 elseif f==2 ...` shape chain
    // and the per-opcode bounds arms used to be one field's static
    // signature. They must now be three separate payload fields, with
    // the form map rebuilt from a per-seed rotated packed string.
    for target in [Target::Lua51, Target::Luau] {
        let source = "local function add(a,b)return a+b end print(add(1,2))";
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut packed_strings = BTreeSet::new();
        for seed in [0u64, 1, 735, u64::MAX] {
            let raw = generate(&data, &program, seed).unwrap();
            let keys = wrapper_keys(seed);
            assert!(!raw.contains("local FM={"), "{target} seed {seed}");
            assert!(raw.contains(&format!("[{}]=function(E,SB)", keys[13])));
            assert!(raw.contains(&format!("[{}]=function(E,SB,FM)", keys[14])));
            assert!(raw.contains(&format!("[{}]=function(E)", keys[15])));
            assert!(raw.contains(&format!(
                "[{}]=function(P,np,SB,E,dec,vld,PT,FM,NX)",
                keys[2]
            )));
            assert!(raw.contains(&format!("VMS[{}](E,SB)", keys[13])));
            // The packed form strings are the only short `g[key]="..."`
            // literals in the raw script (segment fields carry long
            // base86 text); their bytes must rotate with the seed.
            let mut at = 0usize;
            while let Some(found) = raw[at..].find("g[") {
                let base = at + found;
                let mut digits = base + 2;
                let bytes = raw.as_bytes();
                while digits < bytes.len() && bytes[digits].is_ascii_digit() {
                    digits += 1;
                }
                if raw[digits..].starts_with("]=\"") {
                    let start = digits + 3;
                    if let Some(end) = raw[start..].find('"').map(|n| n + start) {
                        if end - start <= 96 {
                            packed_strings.insert(raw[start..end].to_owned());
                        }
                        at = end;
                        continue;
                    }
                }
                at = base + 2;
            }
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(
            packed_strings.len() >= 2,
            "{target}: packed form strings identical across seeds"
        );
        // The split layout still runs the program unchanged.
        let workspace = native::Workspace::new();
        let path = workspace.0.join("split_features.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn full_code_randomization_layout_and_cipher_vary_per_seed() {
    // Full code randomization: payload fields (including every
    // decryption/probe/segment function) are emitted in a seeded
    // shuffled textual order, and the cipher parameters (Lehmer
    // multiplier, mixing constant) are drawn per seed. Across seeds the
    // layouts and parameters must differ; per seed everything must stay
    // byte-reproducible.
    let mut layouts = std::collections::BTreeSet::new();
    let mut multipliers = std::collections::BTreeSet::new();
    let mut mixes = std::collections::BTreeSet::new();
    let mut compression_shapes = std::collections::BTreeSet::new();
    let mut chacha_schedules = std::collections::BTreeSet::new();
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
        for seed in 0..=11u64 {
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(emit(&data, target, seed).unwrap(), output);
            // Textual order of the numeric-keyed payload fields.
            let tokens = crate::lexer::lex(&output, target).unwrap();
            let mut order = Vec::new();
            for index in 0..tokens.len().saturating_sub(4) {
                if tokens[index].text(&output) == "["
                    && tokens[index + 1].kind == crate::lexer::TokenKind::Number
                    && tokens[index + 2].text(&output) == "]"
                    && tokens[index + 3].text(&output) == "="
                    && tokens[index + 4].text(&output) == "function"
                {
                    order.push(tokens[index + 1].text(&output).to_owned());
                }
            }
            assert!(
                (25..=28).contains(&order.len()),
                "{target} seed {seed}: {} fields",
                order.len()
            );
            let keys = wrapper_keys(seed);
            assert!(order.contains(&keys[22].to_string()));
            assert!(order.contains(&keys[23].to_string()));
            compression_shapes.insert(order.contains(&keys[21].to_string()));
            layouts.insert((format!("{target:?}"), order));
            let cipher = cipher_params(seed);
            multipliers.insert(cipher.outer);
            mixes.insert(cipher.mix);
            chacha_schedules.insert(format!("{:?}", chacha_params(seed)));
        }
    }
    // 24 outputs (12 seeds x 2 targets) must not share layouts.
    assert!(
        layouts.len() >= 20,
        "only {} distinct layouts across 24 outputs",
        layouts.len()
    );
    assert_eq!(multipliers.len(), 3, "multiplier variety: {multipliers:?}");
    assert!(mixes.len() >= 3, "mixing constant variety: {mixes:?}");
    assert!(chacha_schedules.len() >= 10, "ChaCha8 schedule variety");
    assert_eq!(
        compression_shapes.len(),
        2,
        "LZW helpers did not vary between two and three fields"
    );
}

#[test]
fn opaque_true_false_branches_carry_real_but_unreachable_instructions() {
    // Both user-requested forms, detected on the FINAL renamed output:
    //  - the entry body wrapped as `if <tautology> then <real chain>
    //    else <decoy>` (or the flipped `if <contradiction>` form);
    //  - dead elseif arms in the F3/F5 dispatch chains keyed on opcode
    //    numbers 200..=254, which can never occur (real opcodes stay
    //    below 64 and F3 rejects unknown opcodes through the FM gate).
    // The decoy branches carry real instructions; the native-parity
    // differentials prove they never execute.
    const TRUTHY: [&str; 4] = [
        "48271%2==1",
        "2147483647>2147483646",
        "65536%256==0",
        "16777216%2==0",
    ];
    const FALSY: [&str; 4] = [
        "48271%2==0",
        "2147483647>2147483647",
        "65536%256==1",
        "16777216%2==1",
    ];
    let mut truthy_wraps = 0usize;
    let mut falsy_wraps = 0usize;
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
        for seed in 0..=7u64 {
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(emit(&data, target, seed).unwrap(), output);
            // Dead dispatch arms: an identifier/number equality where
            // the number sits in the impossible 200..=254 band.
            let tokens = crate::lexer::lex(&output, target).unwrap();
            let mut dead_arms = 0usize;
            // Numeric literals appear in decimal, hex or digit-grouped
            // binary spellings (integer_literal variants).
            let numeric = |text: &str| -> Option<u32> {
                let (radix, digits) = if let Some(rest) = text.strip_prefix("0x") {
                    (16, rest)
                } else if let Some(rest) = text.strip_prefix("0b") {
                    (2, rest)
                } else {
                    (10, text)
                };
                u32::from_str_radix(&digits.replace('_', ""), radix).ok()
            };
            for index in 0..tokens.len().saturating_sub(5) {
                let band = |token: usize| {
                    tokens[token].kind == crate::lexer::TokenKind::Number
                        && numeric(tokens[token].text(&output))
                            .is_some_and(|value| (200..=254).contains(&value))
                };
                if tokens[index + 1].text(&output) == "=="
                    && ((tokens[index].kind == crate::lexer::TokenKind::Identifier
                        && band(index + 2))
                        || (band(index)
                            && tokens[index + 2].kind == crate::lexer::TokenKind::Identifier))
                {
                    dead_arms += 1;
                }
                // not(A~=K) spelling.
                if tokens[index].text(&output) == "not"
                    && tokens[index + 1].text(&output) == "("
                    && tokens[index + 2].kind == crate::lexer::TokenKind::Identifier
                    && tokens[index + 3].text(&output) == "~="
                    && band(index + 4)
                {
                    dead_arms += 1;
                }
                // A-K==0 spelling.
                if tokens[index].kind == crate::lexer::TokenKind::Identifier
                    && tokens[index + 1].text(&output) == "-"
                    && band(index + 2)
                    && tokens[index + 3].text(&output) == "=="
                    && tokens[index + 4].text(&output) == "0"
                {
                    dead_arms += 1;
                }
            }
            assert!(
                dead_arms >= 2,
                "{target} seed {seed}: {dead_arms} dead arms"
            );
            // Entry opaque guard: exactly one pool predicate wraps the
            // entry, in either the tautology or the contradiction form.
            let truthy = TRUTHY.iter().filter(|p| output.contains(*p)).count();
            let falsy = FALSY.iter().filter(|p| output.contains(*p)).count();
            assert_eq!(truthy + falsy, 1, "{target} seed {seed}");
            truthy_wraps += truthy;
            falsy_wraps += falsy;
        }
    }
    assert!(truthy_wraps > 0 && falsy_wraps > 0, "both forms must occur");
}

#[test]
fn generation_respects_the_documented_size_budget() {
    // ISA10 keeps the existing 85/94 kB structural ceilings for seed diversity,
    // and adds a stronger fixed-seed contract: each checked-in compressed
    // golden must be strictly smaller than its ISA7 uncompressed predecessor.
    // Raise neither comparison silently.
    for (target, fixture, budget, golden_seed, isa7_size) in [
        (
            Target::Lua51,
            include_str!("../../../../tests/fixtures/vm_lua51.lua"),
            85_000usize,
            7001u64,
            83_640usize,
        ),
        (
            Target::Luau,
            include_str!("../../../../tests/fixtures/vm_luau.lua"),
            94_000usize,
            7351u64,
            92_116usize,
        ),
    ] {
        let data = compile(fixture, target).unwrap();
        for seed in [0u64, 735, 7001, 7351, u64::MAX] {
            let output = emit(&data, target, seed).unwrap();
            assert!(
                output.len() <= budget,
                "{target} seed {seed}: {} bytes exceeds the {} byte budget",
                output.len(),
                budget
            );
        }
        let golden = emit(&data, target, golden_seed).unwrap();
        assert!(
            golden.len() < isa7_size,
            "{target} compressed golden {}B is not below ISA7 {}B",
            golden.len(),
            isa7_size
        );
    }
}

#[test]
fn transport_watermark_is_present_checked_and_never_spelled_out() {
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
        let output = emit(&data, target, 735).unwrap();
        // The hidden check must not leak the watermark text itself.
        assert!(!output.contains("XXS:"));
        // Exactly one segment is stream-first: its decode opens with
        // the fixed watermark bytes.
        let segments = segment_literals(&output, target).unwrap();
        let stamped = segments
            .iter()
            .filter(|literal| {
                base86_decode(&String::from_utf8_lossy(literal))
                    .is_ok_and(|bytes| bytes.starts_with(b"XXS:"))
            })
            .count();
        assert_eq!(stamped, 1, "{target}");
        // The split functions carry no watermark spelling: W1 is a
        // byte packer, W2 holds only the packed u32 as a number.
        let expected = u32::from_be_bytes(*b"XXS:").to_string();
        assert!(output.contains(&expected));
        // Extraction strips the watermark; full roundtrip still holds.
        assert_eq!(
            decrypt_embedded(&output, target, 735).unwrap(),
            wire(&data, target, 735)
        );
    }
}

#[test]
fn base86_codec_roundtrips_and_rejects_invalid_text() {
    for length in 0..40usize {
        let bytes: Vec<u8> = (0..length)
            .map(|index| ((index * 31 + length * 7) % 256) as u8)
            .collect();
        let text = base86_encode(&bytes);
        assert!(text
            .bytes()
            .all(|byte| (35..=121).contains(&byte) && byte != 92));
        assert_eq!(base86_decode(&text).unwrap(), bytes);
    }
    let big: Vec<u8> = (0..5000u32)
        .map(|index| (index.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let text = base86_encode(&big);
    assert_eq!(base86_decode(&text).unwrap(), big);
    // dangling single character (tail length 1)
    assert!(base86_decode("9").is_err());
    // characters outside the alphabet: quote, backslash, space, 7-bit edge
    for bad in ["\"9", "\\9", " 9", "\u{7f}9"] {
        assert!(base86_decode(bad).is_err(), "{bad:?}");
    }
    // five max-digit characters exceed 32 bits
    assert!(base86_decode("xxxxx").is_err());
    // a 4-character tail encoding more than 3 bytes
    assert!(base86_decode("zzzz").is_err());
}

#[test]
fn embedded_payload_is_high_entropy_ciphertext_and_seed_dependent() {
    fn entropy(bytes: &[u8]) -> f64 {
        let mut counts = [0u64; 256];
        for &byte in bytes {
            counts[usize::from(byte)] += 1;
        }
        let total = f64::from(bytes.len() as u32);
        counts
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let probability = count as f64 / total;
                -probability * probability.log2()
            })
            .sum()
    }
    let ciphertext = |source: &str, target: Target| {
        // Reassemble the outer ciphertext from the three base86 segment
        // literals (order resolved and validated, not stored).
        embedded_outer_ciphertext(source, target, 735).unwrap()
    };
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
        let output = emit(&data, target, 735).unwrap();
        assert_eq!(
            decrypt_embedded(&output, target, 735).unwrap(),
            wire(&data, target, 735)
        );
        assert_ne!(emit(&data, target, 736).unwrap(), output);
        let encrypted = ciphertext(&output, target);
        assert_ne!(&encrypted[..4], b"OBF\x02");
        let (plain, cipher) = (entropy(&data), entropy(&encrypted));
        assert!(cipher > plain, "{target}: {cipher} <= {plain}");
        assert!(cipher > 7.5, "{target}: entropy {cipher}");
    }
}

#[test]
fn semantic_descriptors_and_fragments_poison_dictionary_only_translation() {
    // ISA6 live descriptors are validation-equivalent camouflage rather than
    // execution truth, while unreferenced poison descriptors remain fully
    // well-formed with mismatched bodies. Actual recipe semantics are split
    // into shuffled random-id fragments. A static translator must therefore
    // recover reachability and the fragment transition graph instead of
    // expanding the encrypted dictionary as ground truth.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut decoy_id_sets = BTreeSet::new();
        for seed in 0..=5u64 {
            let image = super::semantic::encode(&program, seed).unwrap();
            assert_eq!(
                super::semantic::encode(&program, seed).unwrap().bytes,
                image.bytes
            );
            assert_ne!(image.bytes, data, "semantic wire must not be canonical");

            let ids: BTreeSet<u16> = image.recipes.iter().map(|recipe| recipe.id).collect();
            assert_eq!(ids.len(), image.recipes.len(), "recipe ids must be unique");
            assert!(!ids.contains(&0), "zero is reserved as a null label/id");
            let decoys: Vec<_> = image.recipes.iter().filter(|recipe| !recipe.live).collect();
            assert_eq!(decoys.len(), 4, "one fixed decoy cohort per image");
            for recipe in &decoys {
                assert_ne!(recipe.descriptor_ops, recipe.execute_ops);
                assert!(!image.referenced_recipe_ids.contains(&recipe.id));
                assert!(recipe.descriptor_ops.iter().all(|op| !matches!(
                    op,
                    Opcode::Jump | Opcode::Test | Opcode::Return | Opcode::TailCall
                )));
            }
            assert!(image
                .recipes
                .iter()
                .filter(|recipe| recipe.live)
                .all(|recipe| image.referenced_recipe_ids.contains(&recipe.id)));
            decoy_id_sets.insert(decoys.iter().map(|recipe| recipe.id).collect::<Vec<_>>());

            // Every id has one entry route, but actual semantics live in a
            // globally shuffled fragment pool. All multi-op recipes are split;
            // 3/4-op recipes also retain at least one fused two-op fragment.
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            let fragments = raw.matches(" then a,b,c=I[").count();
            let multi = image
                .recipes
                .iter()
                .filter(|recipe| recipe.execute_ops.len() > 1)
                .count();
            let operations: usize = image
                .recipes
                .iter()
                .map(|recipe| recipe.execute_ops.len())
                .sum();
            assert!(fragments >= image.recipes.len() + multi);
            assert!(fragments <= operations);
            if image
                .recipes
                .iter()
                .any(|recipe| recipe.execute_ops.len() >= 3)
            {
                assert!(fragments < operations, "no fused fragment was emitted");
            }
            assert!((2..=4).contains(&raw.matches("sid%").count()));
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), image.bytes);
        }
        assert!(
            decoy_id_sets.len() >= 4,
            "{target}: decoy ids are seed-pinned"
        );

        let workspace = native::Workspace::new();
        let path = workspace.0.join("semantic_decoys.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn split_chacha8_sections_and_cross_stage_terms_couple_the_pipeline() {
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut schedules = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            schedules.insert(format!("{:?}", chacha_params(seed)));
            let keys = wrapper_keys(seed);
            assert!(raw.contains(&format!("[{}]=function(MF,X8)", keys[CHACHA_WORD_FIELD])));
            assert!(raw.contains(&format!("[{}]=function(X,R)", keys[CHACHA_QUARTER_FIELD])));
            assert!(raw.contains(&format!("[{}]=function(Q)", keys[CHACHA_BLOCK_FIELD])));
            assert!(raw.contains(&format!("[{}]=function(B,s1,s2,s3,pv,ctx,d,aw,CB", keys[CHACHA_STREAM_FIELD])));
            assert!(raw.contains(&format!("[{}]=function(AH,CC,CB,X8", keys[ANTI_HOOK_FIELD])));
            assert!(raw.contains("1634760805,857760878,2036477234,1797285236"));
            assert!(raw.contains("for i=1,4 do Q(x,1,5,9,13)"));
            assert!(raw.contains("Z[1]~=804192318"));
            assert_eq!(raw.matches("local aw=AH(AH,CC,CB,X8").count(), 2);

            let [i0, i1, i2] = perm_indices(seed);
            let pv_line = format!("local pv=1+(PT[{i0}]*31+PT[{i1}]*7+PT[{i2}])%2147483646;");
            let pv_at = raw.find(&pv_line).expect("entry permutation term");
            let outer_call = raw
                .find("c1,c2,c3,pv,CC,AH,CB,E,SB")
                .expect("outer ChaCha8 call passes dynamic inputs");
            assert!(pv_at < outer_call);
            let inner_call = raw
                .find(&format!("local B=VMS[{}](C,c1,c2,c3,pv,CC,AH,CB", keys[23]))
                .expect("inner ChaCha8 call");
            assert!(outer_call < inner_call);
            assert!(raw.contains("ctx=(n*31+bits*17+cs*7+cc*13+bl)%4294967296"));
            assert!(raw.contains("ctx*d)%4294967296"));
            assert!(raw.contains("q=d==1 and"));
            if target.is_luau() {
                assert!(raw.contains(r#"if A~="[C]" or B~="[C]""#));
            } else {
                assert!(raw.contains(r#"A.what=="C" and B.what=="C""#));
            }
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(schedules.len() >= 10, "{target}: ChaCha salts pinned");
        let workspace = native::Workspace::new();
        let path = workspace.0.join("chacha_coupled.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}
