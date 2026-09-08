
fn blob(source: &str, target: Target, seed: u64) -> Vec<u8> {
    let chunk = crate::parse(source, target).unwrap();
    assert!(crate::vm::tests::no_inline_metadata(&chunk));
    // The embedded payload is encrypted; removing the transport layers now
    // yields the private, seed-specific semantic wire image rather than the
    // canonical public `.obf` instruction stream.
    decrypt_embedded(source, target, seed).unwrap()
}

fn wire(data: &[u8], target: Target, seed: u64) -> Vec<u8> {
    let program = custom::decode(data, target).unwrap();
    super::semantic::encode(&program, seed).unwrap().bytes
}

#[test]
fn custom_finalizer_changes_every_explicit_local_and_never_changes_bytecode() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(
            "local function add(a,b)return a+b end print(add(1,2))",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = generate(&data, &program, 735).unwrap();
        let before = crate::scope::analyze(&raw, target).unwrap();
        let mut layouts = BTreeSet::new();
        for seed in [0, 1, 735, u64::MAX] {
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(emit(&data, target, seed).unwrap(), output);
            assert_eq!(blob(&raw, target, 735), wire(&data, target, 735));
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
            assert!(!output.contains(['\r', '\n']));
            // Field shuffling reorders the payload table per seed, so the
            // per-position local comparison runs against the same-seed
            // finalizer output (identical layout, renamed locals) while
            // the distinct-layout check below uses the emitted script.
            let renamed = finalize(&raw, target, seed).unwrap();
            let after = crate::scope::analyze(&renamed, target).unwrap();
            let layout_after = crate::scope::analyze(&output, target).unwrap();
            assert_eq!(before.globals, after.globals);
            let mut groups = BTreeSet::new();
            let mut spellings = BTreeSet::new();
            for (old, new) in before.bindings.iter().zip(&after.bindings) {
                if old.declaration.is_some() {
                    assert_ne!(old.name, new.name);
                    assert!((1..=2).contains(&new.name.len()));
                    assert!(new.name.bytes().all(|b| b.is_ascii_lowercase()));
                    assert!(groups.insert((after.scopes[new.scope].name_scope, new.name.clone())));
                    spellings.insert(new.name.clone());
                } else {
                    assert_eq!(old.name, new.name);
                }
            }
            assert!(groups.len() > 100);
            assert!(spellings.len() < groups.len());
            assert!(layouts.insert(
                layout_after
                    .bindings
                    .iter()
                    .map(|b| b.name.clone())
                    .collect::<Vec<_>>()
            ));
        }
    }
}

fn execute_recipe_ids(
    data: &[u8],
    target: Target,
) -> (super::semantic::SemanticImage, BTreeSet<u16>) {
    let program = custom::decode(data, target).unwrap();
    let image = super::semantic::encode(&program, 735).unwrap();
    let raw = generate(data, &program, 735).unwrap();
    // Instrument the real graph fetch BEFORE the same final whole-output
    // naming/audit pass. This observes ids only after both edge and recipe
    // token machines have run.
    let fetch_probe =
        "next1=ED(I[2],pc,fid,0);skip1=ED(I[3],pc,fid,1);rid=RD(I[1],pc,next1,skip1,fid);";
    assert_eq!(raw.matches(fetch_probe).count(), 1);
    let raw = raw
        .replace(
            fetch_probe,
            "next1=ED(I[2],pc,fid,0);skip1=ED(I[3],pc,fid,1);rid=RD(I[1],pc,next1,skip1,fid);Probe[rid]=true;",
        )
        .replace(
        "return U(result,1,result.n)",
        "for id in ProbePairs(Probe)do ProbePrint('recipe:'..id)end;return U(result,1,result.n)",
    );
    let raw = format!("local Probe={{}};local ProbePrint,ProbePairs=print,pairs;{raw}");
    let output = finalize(&raw, target, 735).unwrap();
    let work = native::Workspace::new();
    let path = work.0.join("coverage.lua");
    fs::write(&path, output).unwrap();
    let stdout = native::compile_and_run(target, &path);
    let recipes: std::collections::BTreeMap<u16, &super::semantic::SemanticRecipe> = image
        .recipes
        .iter()
        .map(|recipe| (recipe.id, recipe))
        .collect();
    let executed: BTreeSet<u16> = String::from_utf8(stdout)
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("recipe:"))
        .map(|id| id.parse::<u16>().unwrap())
        .collect();
    assert!(
        executed.iter().all(|id| recipes[id].live),
        "an unreferenced poison recipe executed"
    );
    (image, executed)
}

fn execute_coverage(data: &[u8], target: Target) -> BTreeSet<Opcode> {
    let (image, recipe_ids) = execute_recipe_ids(data, target);
    let recipes: std::collections::BTreeMap<u16, &super::semantic::SemanticRecipe> = image
        .recipes
        .iter()
        .map(|recipe| (recipe.id, recipe))
        .collect();
    recipe_ids
        .iter()
        .flat_map(|id| recipes[id].execute_ops.iter().copied())
        .collect()
}

#[test]
fn reachable_neutral_decoy_bundles_execute_but_poison_recipes_do_not() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("local x=4 print(x+3)", target).unwrap();
        let (image, executed) = execute_recipe_ids(&data, target);
        assert!(image.reachable_decoy_bundles >= 2);
        assert!(
            image
                .neutral_decoy_recipe_ids
                .iter()
                .any(|id| executed.contains(id)),
            "{target}: root entry did not traverse its neutral decoy chain"
        );
        assert!(image
            .recipes
            .iter()
            .filter(|recipe| !recipe.live)
            .all(|recipe| !executed.contains(&recipe.id)));

        // A frame already occupying all 256 slots cannot gain the private
        // scratch register. Its reachable bundles must use the audited self-
        // move fallback and still preserve target behavior.
        let mut full_frame = custom::decode(&data, target).unwrap();
        full_frame.prototypes[0].registers = 256;
        let full_image = super::semantic::encode(&full_frame, 735).unwrap();
        assert!(full_image.neutral_decoy_recipe_ids.iter().all(|id| {
            full_image
                .recipes
                .iter()
                .find(|recipe| recipe.id == *id)
                .is_some_and(|recipe| recipe.execute_ops == [Opcode::Move])
        }));
        let raw = generate(&data, &full_frame, 735).unwrap();
        let output = finalize(&raw, target, 735).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join("full_frame_neutral.lua");
        fs::write(&path, output).unwrap();
        assert_eq!(native::compile_and_run(target, &path), b"7\n");
    }
}

#[test]
fn every_supported_opcode_is_actually_executed_in_the_target_runtime() {
    for (target, corpora) in [
        (
            Target::Lua51,
            [
                include_str!("../../../../tests/fixtures/vm_lua51.lua"),
                include_str!("../../../../tests/fixtures/scope_lua51.lua"),
            ],
        ),
        (
            Target::Luau,
            [
                include_str!("../../../../tests/fixtures/vm_luau.lua"),
                include_str!("../../../../tests/fixtures/scope_luau.lua"),
            ],
        ),
    ] {
        let mut executed = BTreeSet::new();
        for corpus in corpora {
            executed.extend(execute_coverage(&compile(corpus, target).unwrap(), target));
        }
        // TOSTRING is directly useful in handwritten Lua 5.1 IR as well as
        // Luau interpolation; prove its value, not a synthetic no-op hit.
        let mut module = ir::compile("return", target).unwrap();
        let f = &mut module.functions[0];
        f.registers = 7;
        f.constants = vec![
            ir::Constant::number(42.0),
            ir::Constant::String(b"42".to_vec()),
            ir::Constant::String(b"assert".to_vec()),
        ];
        f.blocks = vec![ir::Block {
            instructions: vec![
                I::Constant(0, 0),
                I::ToString(1, 0),
                I::Constant(2, 1),
                I::Binary(crate::ast::BinaryOperator::Equal, 3, 1, 2),
                I::ReadGlobal(4, 2),
                I::NewPack(5),
                I::Push(5, 3),
                I::Call(6, 4, 5),
                I::NewPack(0),
            ],
            terminator: T::Return(0),
        }];
        executed.extend(execute_coverage(&custom::encode(&module).unwrap(), target));
        let expected: BTreeSet<_> = Opcode::ALL
            .iter()
            .copied()
            .filter(|op| op.supported(target))
            .collect();
        assert_eq!(executed, expected, "unexecuted custom opcode on {target}");
    }
}

#[derive(Clone, Debug)]
struct SemanticPrototypeLayout {
    header: usize,
    code_positions: Vec<usize>,
    code_len: usize,
    records: usize,
    segment_count: usize,
    root_token: u16,
    root_token_position: usize,
}

#[derive(Clone, Debug)]
struct SemanticSegmentLayout {
    physical_slot: usize,
    id_token_position: usize,
    id: usize,
    owner_token_position: usize,
    owner: usize,
    next_token_position: usize,
    next: usize,
    payload: std::ops::Range<usize>,
}

fn semantic_layouts(
    image: &super::semantic::SemanticImage,
) -> (Vec<SemanticPrototypeLayout>, Vec<SemanticSegmentLayout>) {
    let bytes = &image.bytes;
    let u16_at = |offset: usize| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let u32_at = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let prototypes = u32_at(16) as usize;
    let mut position = 32usize;
    let mut layouts = Vec::with_capacity(prototypes);
    for _ in 0..prototypes {
        let header = position;
        let captures = usize::from(u16_at(header + 8));
        let segment_count = 2;
        let root_token_position = header + 10;
        let root_token = u16_at(root_token_position);
        let constants = u32_at(header + 12) as usize;
        let records = u32_at(header + 16) as usize;
        let code_len = u32_at(header + 20) as usize;
        position = header + 24 + captures * 2;
        for _ in 0..constants {
            let tag = bytes[position];
            position += 1;
            position += match tag {
                0 => 0,
                1 => 1,
                2 | 4 => 8,
                3 | 5 => {
                    let len = u32_at(position) as usize;
                    4 + len
                }
                _ => panic!("unknown constant tag in generated semantic image"),
            };
        }
        layouts.push(SemanticPrototypeLayout {
            header,
            code_positions: Vec::with_capacity(code_len),
            code_len,
            records,
            segment_count,
            root_token,
            root_token_position,
        });
    }
    let mut segments = Vec::with_capacity(prototypes * 2);
    for physical_slot in 1..=prototypes * 2 {
        let id_token_position = position;
        let token = u16_at(position);
        position += 2;
        let id = usize::from(super::semantic::decode_segment_id(
            token,
            physical_slot as u16,
            image,
        ));
        assert!((1..=prototypes * 2).contains(&id));
        let owner = (id - 1) / 2;
        let owner_token_position = position;
        let owner_token = u16_at(position);
        position += 2;
        assert_eq!(
            usize::from(super::semantic::decode_segment_owner(
                owner_token,
                id as u16,
                physical_slot as u16,
                image,
            )),
            owner
        );
        let next_token_position = position;
        let next_token = u16_at(position);
        position += 2;
        let next = usize::from(super::semantic::decode_segment_next(
            next_token,
            id as u16,
            owner as u16,
            image,
        ));
        let part = (id - 1) % 2;
        let split =
            super::semantic::code_segment_split(layouts[owner].code_len, owner as u16, image);
        let length = if part == 0 {
            split
        } else {
            layouts[owner].code_len - split
        };
        let payload = position..position + length;
        position += length;
        segments.push(SemanticSegmentLayout {
            physical_slot,
            id_token_position,
            id,
            owner_token_position,
            owner,
            next_token_position,
            next,
            payload,
        });
    }
    assert_eq!(position, bytes.len());
    let by_id = segments
        .iter()
        .map(|segment| (segment.id, segment))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(by_id.len(), segments.len());
    for (owner, layout) in layouts.iter_mut().enumerate() {
        let mut id = usize::from(super::semantic::decode_segment_root(
            layout.root_token,
            owner as u16,
            image,
        ));
        for _ in 0..layout.segment_count {
            let segment = by_id[&id];
            assert_eq!(segment.owner, owner);
            layout.code_positions.extend(segment.payload.clone());
            id = segment.next;
        }
        assert_eq!(id, 0);
        assert_eq!(layout.code_positions.len(), layout.code_len);
    }
    (layouts, segments)
}

fn semantic_code(image: &super::semantic::SemanticImage, prototype: usize) -> Vec<u8> {
    let layout = &semantic_layouts(image).0[prototype];
    layout
        .code_positions
        .iter()
        .map(|&position| image.bytes[position])
        .collect()
}

fn mutate_semantic_code(
    image: &super::semantic::SemanticImage,
    prototype: usize,
    mutate: impl FnOnce(&mut [u8]),
) -> super::semantic::SemanticImage {
    let layout = semantic_layouts(image).0.remove(prototype);
    let mut code = layout
        .code_positions
        .iter()
        .map(|&position| image.bytes[position])
        .collect::<Vec<_>>();
    mutate(&mut code);
    let mut damaged = image.clone();
    for (&position, byte) in layout.code_positions.iter().zip(code) {
        damaged.bytes[position] = byte;
    }
    damaged
}

fn repair_semantic_checksum(bytes: &mut [u8]) {
    let checksum = custom::checksum(&bytes[custom::HEADER_SIZE..]);
    bytes[28..32].copy_from_slice(&checksum.to_le_bytes());
}

#[test]
fn target_decoder_rejects_corrupt_semantic_graph_before_user_code_runs() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("print('MUST_NOT_RUN')", target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let image = super::semantic::encode(&program, 735).unwrap();
        let first_layout = semantic_layouts(&image).0.remove(0);
        let code_len = first_layout.code_len;
        let records = first_layout.records;
        let code_bytes = semantic_code(&image, 0);
        assert!(code_len > 20 && records > 0);
        let recipes = u16::from_le_bytes(code_bytes[..2].try_into().unwrap()) as usize;
        assert!(recipes >= 2);
        let mut cursor = 2;
        let first_recipe = cursor;
        let mut dictionary = BTreeSet::new();
        for _ in 0..recipes {
            dictionary.insert(u16::from_le_bytes(
                code_bytes[cursor..cursor + 2].try_into().unwrap(),
            ));
            let len = usize::from(code_bytes[cursor + 2]);
            assert!((1..=4).contains(&len));
            cursor += 3 + len;
        }
        let start_label = cursor;
        let first_record = start_label + 2;
        assert!(first_record + 8 <= code_len);
        let second_recipe = first_recipe + 3 + usize::from(code_bytes[first_recipe + 2]);
        let recipe_operands: std::collections::BTreeMap<u16, usize> = image
            .recipes
            .iter()
            .map(|recipe| {
                let operands = recipe
                    .descriptor_ops
                    .iter()
                    .map(|&op| match custom::encoding_form(op) {
                        1 | 2 => 1,
                        3 | 4 => 2,
                        _ => 3,
                    })
                    .sum();
                (recipe.id, operands)
            })
            .collect();
        let mut record_cursor = first_record;
        let mut record_labels = BTreeSet::new();
        for _ in 0..records {
            let label = u16::from_le_bytes(
                code_bytes[record_cursor..record_cursor + 2]
                    .try_into()
                    .unwrap(),
            );
            record_labels.insert(label);
            let next_token = u16::from_le_bytes(
                code_bytes[record_cursor + 2..record_cursor + 4]
                    .try_into()
                    .unwrap(),
            );
            let skip_token = u16::from_le_bytes(
                code_bytes[record_cursor + 4..record_cursor + 6]
                    .try_into()
                    .unwrap(),
            );
            let recipe_token = u16::from_le_bytes(
                code_bytes[record_cursor + 6..record_cursor + 8]
                    .try_into()
                    .unwrap(),
            );
            let next =
                super::semantic::decode_edge_token(next_token, label, 0, 0, &image.edge_layers);
            let skip =
                super::semantic::decode_edge_token(skip_token, label, 0, 1, &image.edge_layers);
            let rid = super::semantic::decode_recipe_token(
                recipe_token,
                label,
                next,
                skip,
                0,
                &image.token_layers,
            );
            record_cursor += 8;
            for _ in 0..recipe_operands[&rid] {
                while code_bytes[record_cursor] >= 128 {
                    record_cursor += 1;
                }
                record_cursor += 1;
            }
        }
        assert_eq!(record_cursor, code_len);

        let mut corruptions = Vec::new();
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[first_recipe + 2] = 0; // empty recipe
        }));
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            let duplicate = code[first_recipe..first_recipe + 2].to_vec();
            code[second_recipe..second_recipe + 2].copy_from_slice(&duplicate); // duplicate id
        }));
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[start_label..start_label + 2].fill(0); // null entry label
        }));
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[first_record..first_record + 2].fill(0); // null record label
        }));
        let label = u16::from_le_bytes(
            code_bytes[first_record..first_record + 2]
                .try_into()
                .unwrap(),
        );
        let unknown_label = (1..=u16::MAX)
            .find(|label| !record_labels.contains(label))
            .unwrap();
        let edge_token =
            super::semantic::encode_edge_token(unknown_label, label, 0, 0, &image.edge_layers);
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[first_record + 2..first_record + 4].copy_from_slice(&edge_token.to_le_bytes());
            // decoded successor is absent
        }));
        let next_token = u16::from_le_bytes(
            code_bytes[first_record + 2..first_record + 4]
                .try_into()
                .unwrap(),
        );
        let skip_token = u16::from_le_bytes(
            code_bytes[first_record + 4..first_record + 6]
                .try_into()
                .unwrap(),
        );
        let next = super::semantic::decode_edge_token(next_token, label, 0, 0, &image.edge_layers);
        let skip = super::semantic::decode_edge_token(skip_token, label, 0, 1, &image.edge_layers);
        let unknown = (1..=u16::MAX).find(|id| !dictionary.contains(id)).unwrap();
        let token = super::semantic::encode_recipe_token(
            unknown,
            label,
            next,
            skip,
            0,
            &image.token_layers,
        );
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[first_record + 6..first_record + 8].copy_from_slice(&token.to_le_bytes());
        }));

        for (kind, mut bad) in corruptions.into_iter().enumerate() {
            repair_semantic_checksum(&mut bad.bytes);
            let raw = super::emit::generate_from_semantic_image(&program, 735, bad).unwrap();
            let output = finalize(&raw, target, 735).unwrap();
            let work = native::Workspace::new();
            let path = work.0.join("invalid_semantic.lua");
            fs::write(&path, output).unwrap();
            assert!(native::compile(target, &path).status.success());
            let runner = if target.is_luau() { "luau" } else { "lua5.1" };
            let result = Command::new(native::root().join("toolchains/bin").join(runner))
                .arg(&path)
                .output()
                .unwrap();
            assert!(!result.status.success(), "{target} corruption {kind} ran");
            assert!(
                result.stdout.is_empty(),
                "{target} corruption {kind} leaked output"
            );
        }
    }
}

#[test]
fn target_decoder_rejects_corrupt_semantic_prototype_metadata() {
    let source =
        "local function f(n)if n>0 then return f(n-1)end return 3 end print('MUST_NOT_RUN',f(2))";
    let target = Target::Luau;
    let data = compile(source, target).unwrap();
    let program = custom::decode(&data, target).unwrap();
    let image = super::semantic::encode(&program, 735).unwrap();
    let old_child = program
        .prototypes
        .iter()
        .position(|prototype| !prototype.captures.is_empty())
        .expect("fixture must contain a captured child");
    let child_id = image
        .prototype_order
        .iter()
        .position(|old| *old == old_child)
        .expect("real child missing after semantic reorder");
    let (layouts, segments) = semantic_layouts(&image);
    let child = layouts[child_id].header;
    assert!(child + 26 <= image.bytes.len());
    let captures = u16::from_le_bytes(image.bytes[child + 8..child + 10].try_into().unwrap());
    assert!(captures > 0, "fixture must exercise capture metadata");

    let mut corruptions = Vec::new();
    let mut bad = image.clone();
    bad.bytes[32..36].copy_from_slice(&0u32.to_le_bytes()); // root has a parent
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes[child..child + 4].copy_from_slice(&u32::MAX.to_le_bytes()); // child lacks parent
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes[child + 7] |= 0x80; // unknown prototype flag
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes[child + 24] = 3; // unknown capture tag
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes[child + 25] = 255; // capture index outside parent frame
    corruptions.push(bad);
    let mut bad = image.clone();
    let terminal_root = super::semantic::encode_segment_root(2, 0, &image);
    bad.bytes[layouts[0].root_token_position..layouts[0].root_token_position + 2]
        .copy_from_slice(&terminal_root.to_le_bytes()); // root has no two-node chain
    corruptions.push(bad);
    let mut bad = image.clone();
    let foreign_root = super::semantic::encode_segment_root(3, 0, &image);
    bad.bytes[layouts[0].root_token_position..layouts[0].root_token_position + 2]
        .copy_from_slice(&foreign_root.to_le_bytes()); // root belongs to another owner
    corruptions.push(bad);
    let mut bad = image.clone();
    let duplicate = super::semantic::encode_segment_id(
        segments[0].id as u16,
        segments[1].physical_slot as u16,
        &image,
    );
    bad.bytes[segments[1].id_token_position..segments[1].id_token_position + 2]
        .copy_from_slice(&duplicate.to_le_bytes()); // duplicate id also leaves one id missing
    corruptions.push(bad);
    let mut bad = image.clone();
    let out_of_range =
        super::semantic::encode_segment_id(0, segments[0].physical_slot as u16, &image);
    bad.bytes[segments[0].id_token_position..segments[0].id_token_position + 2]
        .copy_from_slice(&out_of_range.to_le_bytes());
    corruptions.push(bad);
    let root_segment = segments
        .iter()
        .find(|segment| segment.id == 1)
        .expect("root segment missing");
    let next_position = root_segment.next_token_position;
    let mut bad = image.clone();
    let cycle = super::semantic::encode_segment_next(1, 1, 0, &image);
    bad.bytes[next_position..next_position + 2].copy_from_slice(&cycle.to_le_bytes());
    corruptions.push(bad);
    let mut bad = image.clone();
    let wrong_owner = super::semantic::encode_segment_next(3, 1, 0, &image);
    bad.bytes[next_position..next_position + 2].copy_from_slice(&wrong_owner.to_le_bytes());
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes[segments[0].payload.start] ^= 1; // pooled code corruption
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes.pop(); // truncated final segment payload
    let bad_len = bad.bytes.len() as u32;
    bad.bytes[12..16].copy_from_slice(&bad_len.to_le_bytes());
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes.push(0); // global pool has an unconsumed trailing byte
    let bad_len = bad.bytes.len() as u32;
    bad.bytes[12..16].copy_from_slice(&bad_len.to_le_bytes());
    corruptions.push(bad);

    for (kind, mut bad) in corruptions.into_iter().enumerate() {
        repair_semantic_checksum(&mut bad.bytes);
        let raw = super::emit::generate_from_semantic_image(&program, 735, bad).unwrap();
        let output = finalize(&raw, target, 735).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join("invalid_semantic_proto.luau");
        fs::write(&path, output).unwrap();
        assert!(native::compile(target, &path).status.success());
        let result = Command::new(native::root().join("toolchains/bin/luau"))
            .arg(path)
            .output()
            .unwrap();
        assert!(!result.status.success(), "prototype corruption {kind} ran");
        assert!(
            result.stdout.is_empty(),
            "prototype corruption {kind} leaked output"
        );
    }
}

#[test]
fn target_decoder_rejects_every_global_segment_graph_corruption_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("print('MUST_NOT_RUN')", target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let image = super::semantic::encode(&program, 917).unwrap();
        let (layouts, segments) = semantic_layouts(&image);
        assert!(layouts.len() >= 2 && segments.len() >= 4);
        let root = segments
            .iter()
            .find(|segment| segment.id == 1)
            .expect("root segment missing");
        let root_next = root.next_token_position;
        let terminal = segments
            .iter()
            .find(|segment| segment.id == 2)
            .expect("terminal segment missing");
        let mut corruptions = Vec::new();

        let mut bad = image.clone();
        let terminal_root = super::semantic::encode_segment_root(2, 0, &image);
        bad.bytes[layouts[0].root_token_position..layouts[0].root_token_position + 2]
            .copy_from_slice(&terminal_root.to_le_bytes());
        corruptions.push(("non-root", bad));

        let mut bad = image.clone();
        let duplicate_root = super::semantic::encode_segment_root(1, 1, &image);
        bad.bytes[layouts[1].root_token_position..layouts[1].root_token_position + 2]
            .copy_from_slice(&duplicate_root.to_le_bytes());
        corruptions.push(("duplicate-root", bad));

        let mut bad = image.clone();
        let duplicate_id = super::semantic::encode_segment_id(
            segments[0].id as u16,
            segments[1].physical_slot as u16,
            &image,
        );
        bad.bytes[segments[1].id_token_position..segments[1].id_token_position + 2]
            .copy_from_slice(&duplicate_id.to_le_bytes());
        corruptions.push(("duplicate-and-missing-id", bad));

        let mut bad = image.clone();
        let out_of_range =
            super::semantic::encode_segment_id(0, segments[0].physical_slot as u16, &image);
        bad.bytes[segments[0].id_token_position..segments[0].id_token_position + 2]
            .copy_from_slice(&out_of_range.to_le_bytes());
        corruptions.push(("out-of-range-id", bad));

        let mut bad = image.clone();
        let segment = &segments[0];
        let claimed_owner = ((segment.owner + 1) % layouts.len()) as u16;
        let wrong_owner_token = super::semantic::encode_segment_owner(
            claimed_owner,
            segment.id as u16,
            segment.physical_slot as u16,
            &image,
        );
        bad.bytes[segment.owner_token_position..segment.owner_token_position + 2]
            .copy_from_slice(&wrong_owner_token.to_le_bytes());
        corruptions.push(("wrong-owner-token", bad));

        let mut bad = image.clone();
        let cycle = super::semantic::encode_segment_next(1, 1, 0, &image);
        bad.bytes[root_next..root_next + 2].copy_from_slice(&cycle.to_le_bytes());
        corruptions.push(("cycle", bad));

        let mut bad = image.clone();
        let nonzero_terminal = super::semantic::encode_segment_next(1, 2, 0, &image);
        bad.bytes[terminal.next_token_position..terminal.next_token_position + 2]
            .copy_from_slice(&nonzero_terminal.to_le_bytes());
        corruptions.push(("nonzero-terminal-next", bad));

        let mut bad = image.clone();
        let foreign_owner = super::semantic::encode_segment_next(3, 1, 0, &image);
        bad.bytes[root_next..root_next + 2].copy_from_slice(&foreign_owner.to_le_bytes());
        corruptions.push(("wrong-owner", bad));

        let mut bad = image.clone();
        let wrong_total = (layouts[0].code_len as u32 + 1).to_le_bytes();
        bad.bytes[layouts[0].header + 20..layouts[0].header + 24].copy_from_slice(&wrong_total);
        corruptions.push(("wrong-total-length", bad));

        let mut bad = image.clone();
        bad.bytes.pop();
        let length = bad.bytes.len() as u32;
        bad.bytes[12..16].copy_from_slice(&length.to_le_bytes());
        corruptions.push(("truncated", bad));

        let mut bad = image.clone();
        bad.bytes.push(0);
        let length = bad.bytes.len() as u32;
        bad.bytes[12..16].copy_from_slice(&length.to_le_bytes());
        corruptions.push(("trailing", bad));

        for (kind, mut bad) in corruptions {
            repair_semantic_checksum(&mut bad.bytes);
            let raw = super::emit::generate_from_semantic_image(&program, 917, bad).unwrap();
            let output = finalize(&raw, target, 917).unwrap();
            let workspace = native::Workspace::new();
            let path = workspace.0.join(if target.is_luau() {
                "invalid_segments.luau"
            } else {
                "invalid_segments.lua"
            });
            fs::write(&path, output).unwrap();
            assert!(
                native::compile(target, &path).status.success(),
                "{target} {kind}"
            );
            let runner = if target.is_luau() { "luau" } else { "lua5.1" };
            let result = Command::new(native::root().join("toolchains/bin").join(runner))
                .arg(path)
                .output()
                .unwrap();
            assert!(!result.status.success(), "{target} {kind} ran");
            assert!(result.stdout.is_empty(), "{target} {kind} leaked output");
        }
    }
}

#[test]
fn whole_output_is_a_setmetatable_method_call_over_split_section_functions() {
    use crate::ast::{ExpressionKind, StatementKind, TableField};
    for target in [Target::Lua51, Target::Luau] {
        // `forwards` is true exactly when the chunk itself reads `...`;
        // only then does the wrapper method call forward varargs.
        for (source, forwards) in [
            ("local a=2 print(a*21)", false),
            ("local a,b=... print((a or 0)+(b or 0))", true),
        ] {
            let data = compile(source, target).unwrap();
            let output = emit(&data, target, 735).unwrap();
            assert_eq!(emit(&data, target, 735).unwrap(), output);
            let chunk = crate::parser::parse_source(&output, target).unwrap();
            let statements = &chunk.block.statements;
            assert_eq!(statements.len(), 2, "{target}: {output}");
            // local <short>={}
            let StatementKind::Local {
                bindings, values, ..
            } = &statements[0].kind
            else {
                panic!("{target}: {output}");
            };
            assert_eq!(bindings.len(), 1);
            let wrapper_name = bindings[0].name.value.clone();
            assert!((1..=2).contains(&wrapper_name.len()));
            assert!(wrapper_name.bytes().all(|byte| byte.is_ascii_lowercase()));
            assert!(matches!(&values[0].kind, ExpressionKind::Table(fields) if fields.is_empty()));
            // return setmetatable({sections},<wrapper local>):<random letter>(...)
            let StatementKind::Return(returned) = &statements[1].kind else {
                panic!("{target}: {output}");
            };
            assert_eq!(returned.len(), 1);
            let ExpressionKind::Call {
                function,
                method,
                type_arguments,
                arguments,
            } = &returned[0].kind
            else {
                panic!("{target}: {output}");
            };
            assert!(type_arguments.is_empty());
            let Some(method) = method else {
                panic!("{target}: {output}");
            };
            assert!((1..=2).contains(&method.value.len()));
            assert!(method.value.bytes().all(|byte| byte.is_ascii_lowercase()));
            assert!(!crate::lexer::is_keyword(&method.value, target));
            assert_eq!(arguments.len(), usize::from(forwards));
            if forwards {
                assert!(matches!(arguments[0].kind, ExpressionKind::Vararg));
            }
            let ExpressionKind::Call {
                function: setmetatable,
                method: None,
                type_arguments: setmetatable_types,
                arguments: setmetatable_arguments,
            } = &function.kind
            else {
                panic!("{target}: {output}");
            };
            assert!(setmetatable_types.is_empty());
            assert!(matches!(
                &setmetatable.kind,
                ExpressionKind::Name(name) if name.value == "setmetatable"
            ));
            assert_eq!(setmetatable_arguments.len(), 2);
            match &setmetatable_arguments[1].kind {
                ExpressionKind::Name(reference) => assert_eq!(reference.value, wrapper_name),
                _ => panic!("{target}: {output}"),
            }
            // The payload table has one string-keyed entry and a seed-variable
            // numeric field count. Five additional globally shuffled fields
            // compose word operations, quarter round, ChaCha8 block,
            // stream/KDF and anti-hook attestation.
            let ExpressionKind::Table(fields) = &setmetatable_arguments[0].kind else {
                panic!("{target}: {output}");
            };
            assert!((25..=27).contains(&fields.len()), "{target}: {output}");
            let mut numeric_keys = std::collections::BTreeSet::new();
            let mut entries = 0;
            for field in fields {
                let TableField::Computed { key, value, .. } = field else {
                    panic!("{target}: {output}");
                };
                let ExpressionKind::Function(body) = &value.kind else {
                    panic!("{target}: {output}");
                };
                match &key.kind {
                    ExpressionKind::Number(raw) => {
                        assert!(numeric_keys.insert(raw.clone()), "{target}: {output}");
                    }
                    ExpressionKind::String(raw) => {
                        entries += 1;
                        assert_eq!(
                            crate::minify::literal_bytes(raw, target).unwrap(),
                            method.value.as_bytes(),
                            "{target}: {output}"
                        );
                        // entry receives (self) plus the forwarded chunk varargs
                        assert!(body.has_vararg);
                        assert_eq!(body.parameters.len(), 1);
                    }
                    _ => panic!("{target}: {output}"),
                }
            }
            assert_eq!(entries, 1);
            assert!((24..=26).contains(&numeric_keys.len()));
            // The wrapper is not just structural: it runs the program.
            let workspace = native::Workspace::new();
            let path = workspace.0.join("wrapped.lua");
            fs::write(&path, source).unwrap();
            let expected = native::compile_and_run(target, &path);
            fs::write(&path, &output).unwrap();
            assert_eq!(expected, native::compile_and_run(target, &path));
        }
    }
}
