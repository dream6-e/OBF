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

            let (layouts, _captures, _constants, segments) = semantic_pool_layouts(&image);
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
fn per_prototype_operand_abi_breaks_the_static_slot_handler_bridge() {
    // The ISA11 report recovered every real operation from one global rule:
    // `I[6+3*i..8+3*i] -> a/b/c -> actual-op marker -> plaintext handler`.
    // ISA12 gives each prototype a heterogeneous physical operand profile,
    // returns operands in four binding orders, and emits no actual-op marker.
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
        let mut parameter_sets = BTreeSet::new();
        for seed in [0u64, 1, 2, 3, 735, 7001, 7351, u64::MAX] {
            let image = semantic::encode(&program, seed).unwrap();
            let abi = operand_layout(seed);
            parameter_sets.insert(format!("{abi:?}"));

            assert!(OPERAND_LAYOUT_UNIQUE_SPAN >= OPERAND_LAYOUT_PRIVATE_PROTOTYPE_LIMIT);
            let all_profiles = (0..OPERAND_LAYOUT_PRIVATE_PROTOTYPE_LIMIT)
                .map(|prototype| abi.profile(prototype))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                all_profiles.len(),
                OPERAND_LAYOUT_PRIVATE_PROTOTYPE_LIMIT,
                "{target} seed {seed}: full-range prototype profiles collided"
            );
            let checked = image.prototype_order.len();
            let profiles = (0..checked)
                .map(|prototype| abi.profile(prototype))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                profiles.len(),
                checked,
                "{target} seed {seed}: emitted prototype operand profiles collided"
            );
            if checked >= OPERAND_LAYOUT_FAMILIES {
                assert_eq!(
                    profiles
                        .iter()
                        .map(|profile| profile.0)
                        .collect::<BTreeSet<_>>()
                        .len(),
                    OPERAND_LAYOUT_FAMILIES
                );
            }
            if checked >= OPERAND_LAYOUT_ROTATIONS {
                assert_eq!(
                    profiles
                        .iter()
                        .map(|profile| profile.1)
                        .collect::<BTreeSet<_>>()
                        .len(),
                    OPERAND_LAYOUT_ROTATIONS
                );
            }

            let raw = generate(&data, &program, seed).unwrap();
            assert!(raw.contains("return RD,ED,OG"));
            assert!(!raw.contains("a,b,c=I["));
            assert!(!raw.contains("local base=3+qi*3"));
            assert!(!raw.contains("k=b+c*256;j=a+k*256;o="));

            let operations: usize = image
                .recipes
                .iter()
                .map(|recipe| recipe.execute_ops.len())
                .sum();
            assert_eq!(raw.matches("=OG(fid,I,").count(), operations);
            for form in 0..OPERAND_BINDING_FORMS {
                assert!(
                    raw.contains(&format!("{}=OG(fid,I,", operand_binding_lhs(form))),
                    "{target} seed {seed}: missing binding form {form}"
                );
            }
            let permutation = opcode_permutation(seed, 64);
            for op in image.recipes.iter().flat_map(|recipe| &recipe.execute_ops) {
                assert!(
                    !raw.contains(&format!(";o={};", permutation[*op as usize])),
                    "{target} seed {seed}: actual opcode marker survived"
                );
            }

            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), image.bytes);
        }
        assert!(
            parameter_sets.len() >= 6,
            "{target}: operand ABI parameters are seed-pinned"
        );
    }
}

#[test]
fn per_prototype_register_abi_lowers_every_primitive_access() {
    // ISA12-B removes the second image-wide bridge left after operand
    // lowering: primitive bodies no longer index one canonical logical R
    // table. The profile is derived once per frame and contains no 256-entry
    // permutation table.
    let mut seed_profiles = BTreeSet::new();
    for seed in [0u64, 1, 2, 3, 735, 7001, 7351, u64::MAX] {
        let abi = register_layout(seed);
        seed_profiles.insert(format!("{abi:?}"));
        assert!(REGISTER_LAYOUT_UNIQUE_SPAN >= REGISTER_LAYOUT_PRIVATE_PROTOTYPE_LIMIT);
        assert_eq!(
            (0..REGISTER_LAYOUT_PRIVATE_PROTOTYPE_LIMIT)
                .map(|prototype| abi.profile(prototype))
                .collect::<BTreeSet<_>>()
                .len(),
            REGISTER_LAYOUT_PRIVATE_PROTOTYPE_LIMIT,
            "seed {seed}: full-range register profiles collided"
        );
        assert_eq!(
            (0..REGISTER_LAYOUT_PRIVATE_PROTOTYPE_LIMIT)
                .map(|prototype| {
                    (
                        abi.physical_key(prototype, 0),
                        abi.physical_key(prototype, 1),
                    )
                })
                .collect::<BTreeSet<_>>()
                .len(),
            REGISTER_LAYOUT_PRIVATE_PROTOTYPE_LIMIT,
            "seed {seed}: full-range physical register mappings repeated"
        );
        assert_eq!(
            (0..REGISTER_LAYOUT_FAMILIES)
                .map(|prototype| abi.profile(prototype).0)
                .collect::<BTreeSet<_>>()
                .len(),
            REGISTER_LAYOUT_FAMILIES,
            "seed {seed}: register layout families are not reached"
        );
        for prototype in [0usize, 1, 2, 3, 126, 256, 4096, 32_766] {
            let physical = (0..REGISTER_LAYOUT_LOGICAL_SLOTS)
                .map(|register| abi.physical_key(prototype, register))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                physical.len(),
                REGISTER_LAYOUT_LOGICAL_SLOTS,
                "seed {seed} prototype {prototype}: physical register collision"
            );
            assert!(physical
                .iter()
                .all(|&key| key < REGISTER_LAYOUT_PHYSICAL_SLOTS));
        }
        let factory = abi.factory_lua();
        assert!(factory.len() < 1_300);
        assert!(!factory.contains('{'), "register map table was embedded");
        assert_eq!(factory.matches("RX=function(r)").count(), 4);
        assert_eq!(factory.matches("RF=function(q,k,v)").count(), 4);
        assert!(factory.contains("if q==k then return v"));
        assert!(factory.contains("if q~=k then return R[RX(q)]"));
        assert!(factory.contains("if p==RX(k)then return v"));
        assert!(factory.contains("if (q+rt)%257==(k+rt)%257 then return v"));
        assert!(factory.contains("return RX,RF"));
    }
    assert!(
        seed_profiles.len() >= 6,
        "register ABI parameters are seed-pinned"
    );

    for target in [Target::Lua51, Target::Luau] {
        for &op in Opcode::ALL.iter().filter(|op| op.supported(target)) {
            let handler = crate::vm::opcode::custom(target, op).unwrap();
            let lowered = lower_register_accesses(handler, target).unwrap();
            let source_accesses = crate::lexer::lex(handler, target)
                .unwrap()
                .windows(2)
                .filter(|tokens| tokens[0].text(handler) == "R" && tokens[1].text(handler) == "[")
                .count();
            let lowered_tokens = crate::lexer::lex(&lowered, target).unwrap();
            let lowered_accesses = lowered_tokens
                .windows(4)
                .filter(|tokens| {
                    tokens[0].text(&lowered) == "R"
                        && tokens[1].text(&lowered) == "["
                        && tokens[2].text(&lowered) == "RX"
                        && tokens[3].text(&lowered) == "("
                })
                .count();
            let all_register_accesses = lowered_tokens
                .windows(2)
                .filter(|tokens| tokens[0].text(&lowered) == "R" && tokens[1].text(&lowered) == "[")
                .count();
            assert_eq!(
                lowered_accesses,
                source_accesses,
                "{target} {}: register accesses were not all lowered",
                op.name()
            );
            assert_eq!(all_register_accesses, lowered_accesses);
        }
        let special = "R[a+1]=R[b+2];R[d[2]]=R[i]";
        assert_eq!(
            lower_register_accesses(special, target).unwrap(),
            "R[RX(a+1)]=R[RX(b+2)];R[RX(d[2])]=R[RX(i)]"
        );
        assert_eq!(
            lower_register_accesses("local s='R[a]';R[a]=1", target).unwrap(),
            "local s='R[a]';R[RX(a)]=1"
        );
        assert!(lower_register_accesses("R[a", target).is_err());

        let fixture = match target {
            Target::Lua51 => include_str!("../../../../tests/fixtures/vm_lua51.lua"),
            Target::Luau => include_str!("../../../../tests/fixtures/vm_luau.lua"),
        };
        let data = compile(fixture, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 735, u64::MAX] {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(raw.matches("local RK=function(fid,R)").count(), 1);
            assert_eq!(raw.matches("local RX,RF=RK(fid,R)").count(), 1);
            assert!(raw.contains("local F,R,va,RX,RF=SETUP(fid,args);"));
            assert!(raw.matches("R[RX(").count() > 30);
            for old in ["R[a]", "R[b]", "R[c]", "R[i]", "R[d[2]]"] {
                assert!(
                    !raw.contains(old),
                    "{target} seed {seed}: canonical register surface {old} survived"
                );
            }
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
        }
    }
}

#[test]
fn carried_value_fusion_rewrites_both_primitive_boundaries() {
    // ISA12-C does not call two concatenated plaintext handlers "fusion".
    // A supported pair must materialize the first result once, keep its
    // logical destination, and route every second-primitive read through RF.
    // RF has an explicit value argument, so false/nil are not lost through a
    // Lua and/or selector. Control and multi-write shapes remain single.
    for target in [Target::Lua51, Target::Luau] {
        let constant = crate::vm::opcode::custom(target, Opcode::Constant).unwrap();
        let not = crate::vm::opcode::custom(target, Opcode::Not).unwrap();
        let fusion = fuse_dataflow_pair(Opcode::Constant, constant, Opcode::Not, not, target)
            .unwrap()
            .expect("constant -> not should fuse");
        assert_eq!(fusion.forwarded_reads, 1);
        assert!(fusion
            .producer
            .starts_with("local __obf_fl=a;local __obf_fk=RX(__obf_fl);local __obf_fv="));
        assert!(fusion.producer.ends_with("R[__obf_fk]=__obf_fv;"));
        assert!(!fusion.producer.contains("R[RX(a)]=F."));
        assert_eq!(fusion.consumer, "R[RX(a)]=not RF(b,__obf_fl,__obf_fv);");

        let set_table = crate::vm::opcode::custom(target, Opcode::SetTable).unwrap();
        let table_fusion = fuse_dataflow_pair(
            Opcode::NewTable,
            crate::vm::opcode::custom(target, Opcode::NewTable).unwrap(),
            Opcode::SetTable,
            set_table,
            target,
        )
        .unwrap()
        .expect("new-table -> set-table should fuse");
        assert_eq!(table_fusion.forwarded_reads, 3);
        assert_eq!(
            table_fusion.consumer.matches(",__obf_fl,__obf_fv)").count(),
            3
        );
        assert!(!table_fusion.consumer.contains("R[a]"));
        assert!(!table_fusion.consumer.contains("R[b]"));
        assert!(!table_fusion.consumer.contains("R[c]"));

        assert!(fuse_dataflow_pair(
            Opcode::Clear,
            crate::vm::opcode::custom(target, Opcode::Clear).unwrap(),
            Opcode::Move,
            crate::vm::opcode::custom(target, Opcode::Move).unwrap(),
            target,
        )
        .unwrap()
        .is_none());
        assert!(fuse_dataflow_pair(
            Opcode::Constant,
            constant,
            Opcode::Return,
            crate::vm::opcode::custom(target, Opcode::Return).unwrap(),
            target,
        )
        .unwrap()
        .is_none());
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
fn compression_reduces_bytecode_while_script_budget_is_independent() {
    // The compression contract compares the complete 16-byte-header LZW frame
    // only with its uncompressed private semantic bytecode. Generated Lua size
    // is a separate regression budget; decoder/ChaCha/anti-hook source is never
    // counted as compressed bytecode and is not compared with an older ISA.
    for (target, fixture, script_budget) in [
        (
            Target::Lua51,
            include_str!("../../../../tests/fixtures/vm_lua51.lua"),
            85_000usize,
        ),
        (
            Target::Luau,
            include_str!("../../../../tests/fixtures/vm_luau.lua"),
            94_000usize,
        ),
    ] {
        let data = compile(fixture, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 735, 7001, 7351, u64::MAX] {
            let semantic = semantic::encode(&program, seed).unwrap().bytes;
            let compressed = compress_bytecode(&semantic).unwrap();
            let frame = compression_header(&compressed).unwrap();
            assert_eq!(frame.original_len, semantic.len());
            assert_eq!(compressed.len(), COMPRESSION_HEADER + frame.body_len);
            assert!(
                compressed.len() < semantic.len(),
                "{target} seed {seed}: LZW frame {}B did not reduce semantic bytecode {}B",
                compressed.len(),
                semantic.len()
            );
            assert_eq!(decompress_bytecode(&compressed).unwrap(), semantic);

            let output = emit(&data, target, seed).unwrap();
            assert!(
                output.len() <= script_budget,
                "{target} seed {seed}: generated script {}B exceeds independent {}B budget",
                output.len(),
                script_budget
            );
        }
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
            // globally shuffled fragment pool. A two-op fragment now exists
            // only when its first result can be carried into reads performed
            // by the second primitive; unsupported neighbors remain singles.
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            let fragments: usize = (0..OPERAND_BINDING_FORMS)
                .map(|form| {
                    raw.matches(&format!("then {}=OG(fid,I,", operand_binding_lhs(form)))
                        .count()
                })
                .sum();
            let fusions = raw.matches("local __obf_fl=a;").count();
            let forwarded_reads = raw.matches(",__obf_fl,__obf_fv)").count();
            let operations: usize = image
                .recipes
                .iter()
                .map(|recipe| recipe.execute_ops.len())
                .sum();
            assert_eq!(raw.matches("=OG(fid,I,").count(), operations);
            assert_eq!(
                fragments + fusions,
                operations,
                "{target} seed {seed}: every fused fragment must replace exactly two primitive boundaries"
            );
            assert!(
                fusions > 8,
                "{target} seed {seed}: only {fusions} fusions could all belong to four poison recipes"
            );
            assert!(forwarded_reads >= fusions);
            assert!((2..=4).contains(&raw.matches("sid%").count()));
            let output = emit(&data, target, seed).unwrap();
            assert!(!output.contains("__obf_fl"));
            assert!(!output.contains("__obf_fv"));
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
            assert!(raw.contains(&format!(
                "[{}]=function(B,s1,s2,s3,pv,ctx,d,aw,CB",
                keys[CHACHA_STREAM_FIELD]
            )));
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

#[test]
fn field_order_permutations_decouple_parser_from_canonical_layout() {
    // ISA13 removes the last image-wide field-order conventions: the record
    // header is no longer `label,next,skip,recipe` everywhere, segment tokens
    // are no longer `id,owner,next` everywhere, and dictionary/metadata/tuple
    // orders vary per seed. Fixed-width slot reads stay in place; only the
    // semantic assignment permutes, recomputed from (id, seed-profile).
    for q in 0..FIELD_RECORD_ORDERS {
        let mut order = factorial_field_at_slot(q, 4);
        order.sort_unstable();
        assert_eq!(order, vec![0, 1, 2, 3], "record quotient {q} is not a permutation");
    }
    assert_eq!(
        (0..FIELD_RECORD_ORDERS)
            .map(|q| factorial_field_at_slot(q, 4))
            .collect::<BTreeSet<_>>()
            .len(),
        FIELD_RECORD_ORDERS,
        "record factorial decode collides"
    );
    assert_eq!(
        (0..FIELD_SEGMENT_ORDERS)
            .map(|q| factorial_field_at_slot(q, 3))
            .collect::<BTreeSet<_>>()
            .len(),
        FIELD_SEGMENT_ORDERS,
        "segment factorial decode collides"
    );
    let seeds: Vec<u64> = (0..12).collect();
    let mut dict_orders = BTreeSet::new();
    let mut meta_u32_orders = BTreeSet::new();
    let mut meta_u16_orders = BTreeSet::new();
    let mut meta_u8_orders = BTreeSet::new();
    let mut tuple_orders = BTreeSet::new();
    for seed in seeds {
        let field = field_layout(seed);
        // Coprime multipliers make the affine quotients bijective, so a pid
        // sweep covers every record order and a slot sweep every segment order.
        assert_eq!(
            (0..FIELD_RECORD_ORDERS)
                .map(|prototype| field.record_quotient(prototype))
                .collect::<BTreeSet<_>>()
                .len(),
            FIELD_RECORD_ORDERS,
            "seed {seed}: record quotients do not cover all 24 orders"
        );
        assert_eq!(
            (1..=FIELD_SEGMENT_ORDERS)
                .map(|slot| field.segment_quotient(slot))
                .collect::<BTreeSet<_>>()
                .len(),
            FIELD_SEGMENT_ORDERS,
            "seed {seed}: segment quotients do not cover all 6 orders"
        );
        assert_eq!(
            (0..FIELD_RECORD_ORDERS)
                .map(|prototype| field.record_field_slots(prototype))
                .collect::<BTreeSet<_>>()
                .len(),
            FIELD_RECORD_ORDERS,
            "seed {seed}: record slot maps collided"
        );
        dict_orders.insert(field.dict_flipped);
        meta_u32_orders.insert(field.meta_u32);
        meta_u16_orders.insert(field.meta_u16);
        meta_u8_orders.insert(field.meta_u8);
        tuple_orders.insert(field.tuple);
    }
    assert_eq!(dict_orders.len(), 2, "dictionary header order pinned");
    assert_eq!(meta_u8_orders.len(), 2, "metadata u8 order pinned");
    assert!(meta_u16_orders.len() >= 4, "metadata u16 orders pinned");
    assert!(tuple_orders.len() >= 4, "tuple slot orders pinned");
    assert!(meta_u32_orders.len() >= 8, "metadata u32 orders pinned");

    for target in [Target::Lua51, Target::Luau] {
        let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut emitted_tuples = BTreeSet::new();
        let mut emitted_meta = BTreeSet::new();
        for seed in [0u64, 1, 735, u64::MAX] {
            let image = semantic::encode(&program, seed).unwrap();
            let field = field_layout(seed);
            assert_eq!(image.field_layout, field);
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            // The canonical record slot-assignment anchor is gone for good:
            // every prototype recomputes its own order.
            assert!(!raw.contains("local label,nextToken,skipToken,token=D16(),D16(),D16(),D16()"));
            // Baked per-image orders must match the seed layout exactly, and
            // must vary across seeds rather than pinning one textual order.
            let tuple_text = field.tuple_construct_lua();
            assert_eq!(raw.matches(&tuple_text).count(), 1, "{target} seed {seed}: tuple");
            emitted_tuples.insert(tuple_text);
            // PH locals are slot-rewritten (`F` -> `g[key]`), but the marked
            // read suffixes survive: verify the marked reads follow the
            // per-image width-group permutations (RT/VMCS are unmarked).
            let read_order = |markers: &[&str], reader: &str| -> Vec<String> {
                let mut found: Vec<(usize, String)> = markers
                    .iter()
                    .map(|marker| {
                        let needle = format!("{marker}={reader}()");
                        let at = raw.find(&needle).unwrap_or_else(|| {
                            panic!("{target} seed {seed}: missing metadata read {needle}")
                        });
                        (at, (*marker).to_owned())
                    })
                    .collect();
                found.sort_unstable();
                found.into_iter().map(|(_, marker)| marker).collect()
            };
            let wide_names = [
                "__obf_proto_parent",
                "__obf_proto_nk",
                "__obf_proto_nc",
            ];
            // meta_u32 field 3 is the unmarked VMCS read; drop it from the
            // expected marked subsequence.
            let expected_wide: Vec<String> = field
                .meta_u32
                .iter()
                .filter(|&&slot| slot < 3)
                .map(|&slot| wide_names[usize::from(slot)].to_owned())
                .collect();
            assert_eq!(
                read_order(&wide_names, "b32"),
                expected_wide,
                "{target} seed {seed}: metadata u32 order"
            );
            let medium_names = ["__obf_proto_m", "__obf_proto_nu"];
            let expected_medium: Vec<String> = field
                .meta_u16
                .iter()
                .filter(|&&slot| slot < 2)
                .map(|&slot| medium_names[usize::from(slot)].to_owned())
                .collect();
            assert_eq!(
                read_order(&medium_names, "b16"),
                expected_medium,
                "{target} seed {seed}: metadata u16 order"
            );
            let narrow_names = ["__obf_proto_p", "__obf_proto_flags"];
            let expected_narrow: Vec<String> = field
                .meta_u8
                .iter()
                .map(|&slot| narrow_names[usize::from(slot)].to_owned())
                .collect();
            assert_eq!(
                read_order(&narrow_names, "b8"),
                expected_narrow,
                "{target} seed {seed}: metadata u8 order"
            );
            emitted_meta.insert(format!("{expected_wide:?}{expected_medium:?}{expected_narrow:?}"));
            // The dictionary head shares the slot-rewritten validator field,
            // so match the read order at the loop head instead of full text.
            let z_at = raw
                .find("for z=1,nr do ")
                .unwrap_or_else(|| panic!("{target} seed {seed}: dictionary loop missing"));
            let window = &raw[z_at..z_at + 64];
            if field.dict_flipped {
                assert!(
                    window.starts_with("for z=1,nr do local n=SB("),
                    "{target} seed {seed}: dictionary head"
                );
            } else {
                assert!(
                    window.starts_with("for z=1,nr do local rid=D16();"),
                    "{target} seed {seed}: dictionary head"
                );
            }
            // Per-prototype/per-segment factorial profiles recompute the maps.
            assert!(raw.contains("local fq=(id*"));
            assert!(raw.contains("ford[fky[fk]+1]=fk"));
            assert!(raw.contains("local sq=(slot*"));
            assert!(raw.contains("sont[skey[sk]+1]=sk"));
            let tuple = field_layout(seed).tuple_slots();
            let fetch = format!(
                "next1=ED(I[{}],pc,fid,0);skip1=ED(I[{}],pc,fid,1);rid=RD(I[{}],pc,next1,skip1,fid);",
                tuple[1], tuple[2], tuple[0]
            );
            assert_eq!(raw.matches(&fetch).count(), 1, "{target} seed {seed}: fetch disagrees");
            // Encoder and generated parser still agree byte for byte.
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(emitted_tuples.len() >= 2, "{target}: tuple order pinned across seeds");
        assert!(emitted_meta.len() >= 2, "{target}: metadata order pinned across seeds");
        let workspace = native::Workspace::new();
        let path = workspace.0.join("field_order.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}

#[test]
fn pool_token_helpers_mirror_segment_masking() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("print(1)", target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 735, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            for wire_slot in [1u16, 2, 917, u16::MAX] {
                for (owner, slot, payload) in
                    [(0u16, 0u16, 0u16), (1, 2, 1022), (255, 256, 65535), (32767, 65535, 42)]
                {
                    let owner_token =
                        super::semantic::encode_pool_owner(owner, wire_slot, &image);
                    assert_eq!(
                        super::semantic::decode_pool_owner(owner_token, wire_slot, &image),
                        owner
                    );
                    let slot_token =
                        super::semantic::encode_pool_slot(slot, owner, wire_slot, &image);
                    assert_eq!(
                        super::semantic::decode_pool_slot(slot_token, owner, wire_slot, &image),
                        slot
                    );
                    let payload_token =
                        super::semantic::encode_pool_payload(payload, slot, owner, &image);
                    assert_eq!(
                        super::semantic::decode_pool_payload(payload_token, slot, owner, &image),
                        payload
                    );
                }
            }
        }
    }
}

#[test]
fn pool_field_profiles_cover_all_six_orders() {
    let mut combos = BTreeSet::new();
    let mut saw_plain = false;
    let mut saw_flipped = false;
    for seed in 0..64u64 {
        let field = field_layout(seed);
        combos.insert((field.pool_mul, field.pool_add));
        if field.pools_flipped {
            saw_flipped = true;
        } else {
            saw_plain = true;
        }
        // The pool multiplier is coprime to 6, so one period covers every
        // quotient and every anonymous-slot permutation exactly once.
        let mut slots = BTreeSet::new();
        for physical_slot in 1..=6usize {
            assert!(field.pool_quotient(physical_slot) < 6);
            assert!(slots.insert(field.pool_field_slots(physical_slot)));
        }
    }
    assert!(combos.len() >= 6, "pool key variety: {combos:?}");
    assert!(saw_plain && saw_flipped, "pool order never flips");
}

#[test]
fn wire_isa_version_is_14() {
    assert_eq!(
        super::semantic::WIRE_ISA_VERSION,
        14,
        "pooled capture/constant images require ISA14"
    );
}

#[test]
fn generated_parser_reads_global_capture_constant_pools() {
    let mut plain = None;
    let mut flipped = None;
    for seed in 0..64u64 {
        if field_layout(seed).pools_flipped {
            flipped.get_or_insert(seed);
        } else {
            plain.get_or_insert(seed);
        }
    }
    let (plain, flipped) = (plain.unwrap(), flipped.unwrap());
    assert_ne!(plain, flipped);
    for target in [Target::Lua51, Target::Luau] {
        for seed in [plain, flipped] {
            let data = compile(
                "local x=1;local function f()return x end print(f())",
                target,
            )
            .unwrap();
            let program = custom::decode(&data, target).unwrap();
            let raw = generate(&data, &program, seed).unwrap();
            for marker in [
                "local TU,TK=0,0;",
                "for slot=1,TU do",
                "for slot=1,TK do",
                "local rec=UT[j]",
                "local rec=KT[j]",
            ] {
                assert!(
                    raw.contains(marker),
                    "{target} seed {seed}: missing pool marker {marker}"
                );
            }
        }
        // Textual branch order is seed-shuffled, so flipped-order agreement
        // between encoder and parser is proven behaviorally: the flipped
        // seed must execute exactly like the native script on both targets.
        let data = compile(
            "local x=1;local function f()return x end print(f())",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = generate(&data, &program, flipped).unwrap();
        let output = finalize(&raw, target, flipped).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join(if target.is_luau() {
            "flipped_pools.luau"
        } else {
            "flipped_pools.lua"
        });
        fs::write(&path, output).unwrap();
        let stdout = native::compile_and_run(target, &path);
        assert_eq!(stdout, b"1\n", "{target}: flipped pools misbehave");
    }
}

