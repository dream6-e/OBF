
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
    // token machines have run. Tuple slots follow the per-image field order.
    let tuple = super::lowering::field_layout(735).tuple_slots();
    let fetch_probe = format!(
        "next1=ED(I[{}],pc,fid,0);skip1=ED(I[{}],pc,fid,1);rid=RD(I[{}],pc,next1,skip1,fid);",
        tuple[1], tuple[2], tuple[0]
    );
    assert_eq!(raw.matches(&fetch_probe).count(), 1);
    let raw = raw
        .replace(
            &fetch_probe,
            &format!("{fetch_probe}Probe[rid]=true;"),
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
fn semantic_code(image: &super::semantic::SemanticImage, prototype: usize) -> Vec<u8> {
    let layout = &semantic_pool_layouts(image).0[prototype];
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
    let layout = semantic_pool_layouts(image).0.remove(prototype);
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
        let first_layout = semantic_pool_layouts(&image).0.remove(0);
        let code_len = first_layout.code_len;
        let records = first_layout.records;
        let code_bytes = semantic_code(&image, 0);
        assert!(code_len > 20 && records > 0);
        let recipes = u16::from_le_bytes(code_bytes[..2].try_into().unwrap()) as usize;
        assert!(recipes >= 2);
        let field = image.field_layout;
        let flipped = field.dict_flipped;
        let mut cursor = 2;
        let first_recipe = cursor;
        let mut dictionary = BTreeSet::new();
        for _ in 0..recipes {
            let (rid, len) = if flipped {
                (
                    u16::from_le_bytes(code_bytes[cursor + 1..cursor + 3].try_into().unwrap()),
                    usize::from(code_bytes[cursor]),
                )
            } else {
                (
                    u16::from_le_bytes(code_bytes[cursor..cursor + 2].try_into().unwrap()),
                    usize::from(code_bytes[cursor + 2]),
                )
            };
            dictionary.insert(rid);
            assert!((1..=4).contains(&len));
            cursor += 3 + len;
        }
        let start_label = cursor;
        let first_record = start_label + 2;
        assert!(first_record + 8 <= code_len);
        let first_len = usize::from(code_bytes[first_recipe + if flipped { 0 } else { 2 }]);
        let second_recipe = first_recipe + 3 + first_len;
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
        // Record header slots follow the per-prototype factorial profile.
        let record_slots = field.record_field_slots(0);
        let slot_at = |base: usize, slot: usize| {
            u16::from_le_bytes(code_bytes[base + slot * 2..base + slot * 2 + 2].try_into().unwrap())
        };
        let mut record_cursor = first_record;
        let mut record_labels = BTreeSet::new();
        for _ in 0..records {
            let label = slot_at(record_cursor, record_slots[0]);
            record_labels.insert(label);
            let next_token = slot_at(record_cursor, record_slots[1]);
            let skip_token = slot_at(record_cursor, record_slots[2]);
            let recipe_token = slot_at(record_cursor, record_slots[3]);
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

        let len_offset = if flipped { 0 } else { 2 };
        let rid_offset = if flipped { 1 } else { 0 };
        let mut corruptions = Vec::new();
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[first_recipe + len_offset] = 0; // empty recipe
        }));
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            let duplicate = code[first_recipe + rid_offset..first_recipe + rid_offset + 2].to_vec();
            code[second_recipe + rid_offset..second_recipe + rid_offset + 2]
                .copy_from_slice(&duplicate); // duplicate id
        }));
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[start_label..start_label + 2].fill(0); // null entry label
        }));
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            let at = first_record + record_slots[0] * 2;
            code[at..at + 2].fill(0); // null record label
        }));
        let label = slot_at(first_record, record_slots[0]);
        let unknown_label = (1..=u16::MAX)
            .find(|label| !record_labels.contains(label))
            .unwrap();
        let edge_token =
            super::semantic::encode_edge_token(unknown_label, label, 0, 0, &image.edge_layers);
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            let at = first_record + record_slots[1] * 2;
            code[at..at + 2].copy_from_slice(&edge_token.to_le_bytes());
            // decoded successor is absent
        }));
        let next_token = slot_at(first_record, record_slots[1]);
        let skip_token = slot_at(first_record, record_slots[2]);
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
            let at = first_record + record_slots[3] * 2;
            code[at..at + 2].copy_from_slice(&token.to_le_bytes());
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
    let (layouts, pool_captures, _constants, segments) = semantic_pool_layouts(&image);
    let meta = image.field_layout.metadata_positions();
    let child = layouts[child_id].header;
    assert!(child + 26 <= image.bytes.len());
    let captures =
        u16::from_le_bytes(image.bytes[child + meta.captures..child + meta.captures + 2].try_into().unwrap());
    assert!(captures > 0, "fixture must exercise capture metadata");

    let mut corruptions = Vec::new();
    let mut bad = image.clone();
    bad.bytes[32 + meta.parent..36 + meta.parent].copy_from_slice(&0u32.to_le_bytes()); // root has a parent
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes[child + meta.parent..child + meta.parent + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes()); // child lacks parent
    corruptions.push(bad);
    let mut bad = image.clone();
    bad.bytes[child + meta.flags] |= 0x80; // unknown prototype flag
    corruptions.push(bad);
    let child_record = pool_captures
        .iter()
        .find(|record| record.owner == child_id)
        .expect("child prototype must own a pooled capture");
    let mut bad = image.clone();
    let bad_tag = super::semantic::encode_pool_payload(
        3,
        child_record.slot as u16,
        child_record.owner as u16,
        &image,
    );
    bad.bytes[child_record.token_positions[2]..child_record.token_positions[2] + 2]
        .copy_from_slice(&bad_tag.to_le_bytes()); // unknown pooled capture tag
    corruptions.push(bad);
    let mut bad = image.clone();
    let index_overflow = super::semantic::encode_pool_payload(
        256 * 4,
        child_record.slot as u16,
        child_record.owner as u16,
        &image,
    );
    bad.bytes[child_record.token_positions[2]..child_record.token_positions[2] + 2]
        .copy_from_slice(&index_overflow.to_le_bytes()); // pooled capture index overflow
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
        let (layouts, _captures, _constants, segments) = semantic_pool_layouts(&image);
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
        let total_at = layouts[0].header + image.field_layout.metadata_positions().code_len;
        bad.bytes[total_at..total_at + 4].copy_from_slice(&wrong_total);
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

#[test]
fn target_decoder_rejects_field_order_confusion_on_both_targets() {
    // ISA13 fail-closed invariant: wire structures are anonymous fixed-width
    // slots, so any cross-slot confusion must trip a label/token/operand/
    // count gate before user code runs. Each corruption below swaps or
    // reinterprets same-width fields, then repairs only the outer checksum.
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("print('MUST_NOT_RUN')", target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let image = super::semantic::encode(&program, 735).unwrap();
        let field = image.field_layout;
        let (layouts, _captures, _constants, segments) = semantic_pool_layouts(&image);
        let code_bytes = semantic_code(&image, 0);
        let recipes = u16::from_le_bytes(code_bytes[..2].try_into().unwrap()) as usize;
        let len_offset = if field.dict_flipped { 0 } else { 2 };
        let mut cursor = 2usize;
        for _ in 0..recipes {
            let len = usize::from(code_bytes[cursor + len_offset]);
            assert!((1..=4).contains(&len));
            cursor += 3 + len;
        }
        let first_record = cursor + 2;
        let record_slots = field.record_field_slots(0);
        let slot_value = |base: usize, slot: usize| {
            u16::from_le_bytes(code_bytes[base + slot * 2..base + slot * 2 + 2].try_into().unwrap())
        };

        let mut corruptions: Vec<(&str, super::semantic::SemanticImage)> = Vec::new();
        // 1. Record header: swap two same-width slots of the first record.
        let pair = [(0usize, 1usize), (0, 3), (1, 2)]
            .into_iter()
            .find(|&(a, b)| {
                slot_value(first_record, record_slots[a]) != slot_value(first_record, record_slots[b])
            })
            .expect("record slots must differ for a real swap");
        corruptions.push((
            "record-slot-swap",
            mutate_semantic_code(&image, 0, |code| {
                let (x, y) = (record_slots[pair.0] * 2, record_slots[pair.1] * 2);
                for offset in 0..2 {
                    code.swap(first_record + x + offset, first_record + y + offset);
                }
            }),
        ));
        // 2. Segment pool: swap the id and owner tokens of one record.
        {
            assert_ne!(
                image.bytes[segments[0].id_token_position..segments[0].id_token_position + 2],
                image.bytes[segments[0].owner_token_position..segments[0].owner_token_position + 2],
                "segment tokens must differ for a real swap"
            );
            let mut bad = image.clone();
            for offset in 0..2 {
                bad.bytes.swap(
                    segments[0].id_token_position + offset,
                    segments[0].owner_token_position + offset,
                );
            }
            corruptions.push(("segment-token-swap", bad));
        }
        // 3. Dictionary entry: reverse the 3-byte header of one entry.
        {
            let mut at = 2usize;
            for _ in 0..recipes {
                let len = usize::from(code_bytes[at + len_offset]);
                let header = &code_bytes[at..at + 3];
                if header != [header[2], header[1], header[0]] {
                    break;
                }
                at += 3 + len;
            }
            assert!(at < first_record - 2, "no non-palindromic dictionary header");
            corruptions.push((
                "dictionary-header-reversal",
                mutate_semantic_code(&image, 0, |code| {
                    code[at..at + 3].reverse();
                }),
            ));
        }
        // 4. Metadata: swap the parent and code-length u32 slots of the entry.
        {
            let meta = field.metadata_positions();
            let header = layouts[0].header;
            assert_eq!(header, 32);
            assert_ne!(
                image.bytes[header + meta.parent..header + meta.parent + 4],
                image.bytes[header + meta.code_len..header + meta.code_len + 4],
                "entry parent must differ from its code length"
            );
            let mut bad = image.clone();
            for offset in 0..4 {
                bad.bytes.swap(header + meta.parent + offset, header + meta.code_len + offset);
            }
            corruptions.push(("metadata-slot-swap", bad));
        }

        for (kind, mut bad) in corruptions {
            repair_semantic_checksum(&mut bad.bytes);
            let raw = super::emit::generate_from_semantic_image(&program, 735, bad).unwrap();
            let output = finalize(&raw, target, 735).unwrap();
            let workspace = native::Workspace::new();
            let path = workspace.0.join("invalid_field_order.lua");
            fs::write(&path, output).unwrap();
            assert!(
                native::compile(target, &path).status.success(),
                "{target} {kind}: corrupted script must still compile"
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

#[derive(Clone, Debug)]
struct PooledCaptureLayout {
    physical_slot: usize,
    token_positions: [usize; 3],
    owner: usize,
    slot: usize,
    tag: u8,
    index: u8,
}

#[derive(Clone, Debug)]
struct PooledConstantLayout {
    physical_slot: usize,
    token_positions: [usize; 3],
    owner: usize,
    index: usize,
    tag: u16,
    payload: std::ops::Range<usize>,
}

/// Parse one global capture pool at `position`: `total` records of three
/// anonymous u16 slots ([owner, slot, payload]) under the per-record pool
/// factorial profile. Returns the records and the first unconsumed offset.
fn parse_capture_pool(
    image: &super::semantic::SemanticImage,
    layouts: &[SemanticPrototypeLayout],
    capture_total: usize,
    position: usize,
) -> (Vec<PooledCaptureLayout>, usize) {
    let bytes = &image.bytes;
    let field = image.field_layout;
    let meta = field.metadata_positions();
    let u16_at = |offset: usize| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let mut position = position;
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(capture_total.min(bytes.len())); // cap: counts are untrusted until the wire lands;
    for physical_slot in 1..=capture_total {
        let slots = field.pool_field_slots(physical_slot);
        let base = position;
        let owner_position = base + slots[0] * 2;
        let slot_position = base + slots[1] * 2;
        let payload_position = base + slots[2] * 2;
        position = base + 6;
        let wire_slot = physical_slot as u16;
        let owner = usize::from(super::semantic::decode_pool_owner(
            u16_at(owner_position),
            wire_slot,
            image,
        ));
        assert!(
            owner < layouts.len(),
            "capture pool record {physical_slot}: owner {owner} out of range"
        );
        let slot = usize::from(super::semantic::decode_pool_slot(
            u16_at(slot_position),
            owner as u16,
            wire_slot,
            image,
        ));
        let owner_captures =
            usize::from(u16_at(layouts[owner].header + meta.captures));
        assert!(
            slot < owner_captures,
            "capture pool record {physical_slot}: slot {slot} outside owner {owner} nu={owner_captures}"
        );
        let payload = super::semantic::decode_pool_payload(
            u16_at(payload_position),
            slot as u16,
            owner as u16,
            image,
        );
        let tag = (payload % 4) as u8;
        assert!(
            tag <= 2,
            "capture pool record {physical_slot}: bad tag {tag}"
        );
        assert!(
            payload / 4 <= 255,
            "capture pool record {physical_slot}: index overflow"
        );
        let index = (payload / 4) as u8;
        assert!(
            seen.insert((owner, slot)),
            "duplicate capture pool record ({owner},{slot})"
        );
        out.push(PooledCaptureLayout {
            physical_slot,
            token_positions: [owner_position, slot_position, payload_position],
            owner,
            slot,
            tag,
            index,
        });
    }
    (out, position)
}

/// Parse one global constant pool at `position`: `total` records of a
/// three-slot u16 token header ([owner, index, tag]) plus the tag-dependent
/// value payload. Returns the records and the first unconsumed offset.
fn parse_constant_pool(
    image: &super::semantic::SemanticImage,
    layouts: &[SemanticPrototypeLayout],
    constant_total: usize,
    position: usize,
) -> (Vec<PooledConstantLayout>, usize) {
    let bytes = &image.bytes;
    let field = image.field_layout;
    let meta = field.metadata_positions();
    let u16_at = |offset: usize| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let u32_at = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let mut position = position;
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(constant_total.min(bytes.len())); // cap: counts are untrusted until the wire lands;
    for physical_slot in 1..=constant_total {
        let slots = field.pool_field_slots(physical_slot);
        let base = position;
        let owner_position = base + slots[0] * 2;
        let index_position = base + slots[1] * 2;
        let tag_position = base + slots[2] * 2;
        position = base + 6;
        let wire_slot = physical_slot as u16;
        let owner = usize::from(super::semantic::decode_pool_owner(
            u16_at(owner_position),
            wire_slot,
            image,
        ));
        assert!(
            owner < layouts.len(),
            "constant pool record {physical_slot}: owner {owner} out of range"
        );
        let index = usize::from(super::semantic::decode_pool_slot(
            u16_at(index_position),
            owner as u16,
            wire_slot,
            image,
        ));
        let owner_constants =
            u32_at(layouts[owner].header + meta.constants) as usize;
        assert!(
            index < owner_constants,
            "constant pool record {physical_slot}: index {index} outside owner {owner} nk={owner_constants}"
        );
        let tag = super::semantic::decode_pool_payload(
            u16_at(tag_position),
            index as u16,
            owner as u16,
            image,
        );
        assert!(
            tag <= 5,
            "constant pool record {physical_slot}: bad tag {tag}"
        );
        let payload_start = position;
        position += match tag {
            0 => 0,
            1 => 1,
            2 | 4 => 8,
            3 | 5 => {
                let len = u32_at(position) as usize;
                4 + len
            }
            _ => unreachable!("tag range was checked above"),
        };
        assert!(
            seen.insert((owner, index)),
            "duplicate constant pool record ({owner},{index})"
        );
        out.push(PooledConstantLayout {
            physical_slot,
            token_positions: [owner_position, index_position, tag_position],
            owner,
            index,
            tag,
            payload: payload_start..position,
        });
    }
    (out, position)
}

/// ISA14 wire walker: contiguous 24-byte headers (captures/constants live
/// only in the global pools now), then the capture and constant pools in
/// `pools_flipped` order, then the segment graph. Exact consumption of every
/// byte is asserted, exactly like the segment walker it extends.
fn semantic_pool_layouts(
    image: &super::semantic::SemanticImage,
) -> (
    Vec<SemanticPrototypeLayout>,
    Vec<PooledCaptureLayout>,
    Vec<PooledConstantLayout>,
    Vec<SemanticSegmentLayout>,
) {
    let bytes = &image.bytes;
    let field = image.field_layout;
    let meta = field.metadata_positions();
    let u16_at = |offset: usize| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let u32_at = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let prototypes = u32_at(16) as usize;
    let mut position = 32usize;
    let mut layouts = Vec::with_capacity(prototypes);
    let mut capture_total = 0usize;
    let mut constant_total = 0usize;
    for _ in 0..prototypes {
        let header = position;
        let captures = usize::from(u16_at(header + meta.captures));
        let segment_count = 2;
        let root_token_position = header + meta.root;
        let root_token = u16_at(root_token_position);
        let constants = u32_at(header + meta.constants) as usize;
        let records = u32_at(header + meta.records) as usize;
        let code_len = u32_at(header + meta.code_len) as usize;
        capture_total += captures;
        constant_total += constants;
        position = header + 24;
        layouts.push(SemanticPrototypeLayout {
            header,
            code_positions: Vec::with_capacity(code_len.min(bytes.len())),
            code_len,
            records,
            segment_count,
            root_token,
            root_token_position,
        });
    }
    let (captures, constants, mut position) = if field.pools_flipped {
        let (constants, position) =
            parse_constant_pool(image, &layouts, constant_total, position);
        let (captures, position) =
            parse_capture_pool(image, &layouts, capture_total, position);
        (captures, constants, position)
    } else {
        let (captures, position) =
            parse_capture_pool(image, &layouts, capture_total, position);
        let (constants, position) =
            parse_constant_pool(image, &layouts, constant_total, position);
        (captures, constants, position)
    };
    let mut segments = Vec::with_capacity(prototypes * 2);
    for physical_slot in 1..=prototypes * 2 {
        // Segment tokens are anonymous same-width slots; the per-segment
        // factorial profile reassigns their meaning.
        let slots = field.segment_field_slots(physical_slot);
        let base = position;
        let id_token_position = base + slots[0] * 2;
        let owner_token_position = base + slots[1] * 2;
        let next_token_position = base + slots[2] * 2;
        position = base + 6;
        let token = u16_at(id_token_position);
        let id = usize::from(super::semantic::decode_segment_id(
            token,
            physical_slot as u16,
            image,
        ));
        assert!((1..=prototypes * 2).contains(&id));
        let owner = (id - 1) / 2;
        let owner_token = u16_at(owner_token_position);
        assert_eq!(
            usize::from(super::semantic::decode_segment_owner(
                owner_token,
                id as u16,
                physical_slot as u16,
                image,
            )),
            owner
        );
        let next_token = u16_at(next_token_position);
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
    (layouts, captures, constants, segments)
}

#[test]
fn capture_constant_pools_exist_in_wire_image() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(
            "local function f(n)if n>0 then return f(n-1)end return n end print(f(2))",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 735] {
            let image = super::semantic::encode(&program, seed).unwrap();
            let (layouts, captures, constants, segments) = semantic_pool_layouts(&image);
            let meta = image.field_layout.metadata_positions();
            let bytes = &image.bytes;
            let u16_at =
                |offset: usize| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
            let u32_at =
                |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            let expected_captures: usize = layouts
                .iter()
                .map(|layout| usize::from(u16_at(layout.header + meta.captures)))
                .sum();
            let expected_constants: usize = layouts
                .iter()
                .map(|layout| u32_at(layout.header + meta.constants) as usize)
                .sum();
            assert_eq!(
                captures.len(),
                expected_captures,
                "{target} seed {seed}: capture pool total"
            );
            assert!(
                expected_captures > 0,
                "fixture must exercise the capture pool"
            );
            assert_eq!(
                constants.len(),
                expected_constants,
                "{target} seed {seed}: constant pool total"
            );
            for (owner, layout) in layouts.iter().enumerate() {
                let nu = usize::from(u16_at(layout.header + meta.captures));
                let owned: BTreeSet<usize> = captures
                    .iter()
                    .filter(|record| record.owner == owner)
                    .map(|record| record.slot)
                    .collect();
                assert_eq!(
                    owned,
                    (0..nu).collect::<BTreeSet<_>>(),
                    "{target} seed {seed}: owner {owner} capture coverage"
                );
                let nk = u32_at(layout.header + meta.constants) as usize;
                let kowned: BTreeSet<usize> = constants
                    .iter()
                    .filter(|record| record.owner == owner)
                    .map(|record| record.index)
                    .collect();
                assert_eq!(
                    kowned,
                    (0..nk).collect::<BTreeSet<_>>(),
                    "{target} seed {seed}: owner {owner} constant coverage"
                );
                // Pooled values match canonical ground truth. Decoy owners
                // (past the canonical prototype count) carry no captures and
                // only synthetic constants, so they are skipped here.
                let old = image.prototype_order[owner];
                if old >= program.prototypes.len() {
                    assert_eq!(nu, 0, "decoy owner {owner} must not capture");
                    continue;
                }
                for record in captures.iter().filter(|record| record.owner == owner) {
                    let (tag, index) = match program.prototypes[old].captures[record.slot] {
                        ir::Capture::Local(register) => (0, register),
                        ir::Capture::Upvalue(upvalue) => (1, upvalue),
                        ir::Capture::RecursiveLocal(register) => (2, register),
                    };
                    assert_eq!(record.tag, tag, "{target} seed {seed}: capture tag");
                    assert_eq!(
                        usize::from(record.index),
                        usize::from(index),
                        "{target} seed {seed}: capture index"
                    );
                }
                for record in constants.iter().filter(|record| record.owner == owner) {
                    let expected = match program.prototypes[old].constants[record.index] {
                        ir::Constant::Nil => 0,
                        ir::Constant::Boolean(_) => 1,
                        ir::Constant::Number(_) => 2,
                        ir::Constant::String(_) => 3,
                        ir::Constant::Integer(_) => 4,
                        ir::Constant::Method(_) => 5,
                    };
                    assert_eq!(record.tag, expected, "{target} seed {seed}: constant tag");
                }
            }
            assert_eq!(segments.len(), layouts.len() * 2);
        }
    }
}

#[test]
fn pools_shuffle_across_seeds_and_interleave() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(
            "local function f(n)if n>0 then return f(n-1)+g(n-1) else return 1 end end local function g(n)if n>0 then return g(n-1)+f(n-1) else return 2 end end print(f(3),g(3))",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        let canonical_captures: usize = program
            .prototypes
            .iter()
            .map(|prototype| prototype.captures.len())
            .sum();
        let canonical_constants: usize = program
            .prototypes
            .iter()
            .map(|prototype| prototype.constants.len())
            .sum();
        assert!(canonical_captures >= 3, "fixture needs a shufflable pool");
        let mut capture_orders = BTreeSet::new();
        let mut constant_orders = BTreeSet::new();
        for seed in [0u64, 1, 2, 3, 735, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            // Decoys never capture; at most the trailing decoy adds one
            // synthetic numeric constant.
            assert_eq!(
                image.capture_pool_owners.len(),
                canonical_captures,
                "{target} seed {seed}: capture pool total"
            );
            assert!(
                (canonical_constants..=canonical_constants + 1)
                    .contains(&image.constant_pool_owners.len()),
                "{target} seed {seed}: constant pool total"
            );
            assert!(image.pools_interleaved, "{target} seed {seed}: interleave flag");
            capture_orders.insert(
                image
                    .capture_pool_owners
                    .iter()
                    .zip(&image.capture_pool_slots)
                    .map(|(&owner, &slot)| (owner, slot))
                    .collect::<Vec<_>>(),
            );
            constant_orders.insert(
                image
                    .constant_pool_owners
                    .iter()
                    .zip(&image.constant_pool_indices)
                    .map(|(&owner, &index)| (owner, index))
                    .collect::<Vec<_>>(),
            );
        }
        assert!(
            capture_orders.len() >= 2,
            "{target}: capture pool order pinned across seeds"
        );
        assert!(
            constant_orders.len() >= 2,
            "{target}: constant pool order pinned across seeds"
        );
    }
}

#[test]
fn target_decoder_rejects_every_pool_corruption_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(
            "local c=true;local function f(n)if n>0 then return f(n-1)+g(n-1) elseif c then return 1 else return 0 end end local function g(n)if n>0 then return g(n-1)+f(n-1) else return 2 end end print(f(2),g(2),'MUST_NOT_RUN')",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        let image = super::semantic::encode(&program, 917).unwrap();
        let (layouts, captures, constants, _) = semantic_pool_layouts(&image);
        assert!(captures.len() >= 2 && constants.len() >= 4);
        let meta = image.field_layout.metadata_positions();
        let u16_at = |offset: usize| {
            u16::from_le_bytes(image.bytes[offset..offset + 2].try_into().unwrap())
        };
        let u32_at = |offset: usize| {
            u32::from_le_bytes(image.bytes[offset..offset + 4].try_into().unwrap())
        };
        let owner_nu =
            |owner: usize| usize::from(u16_at(layouts[owner].header + meta.captures));
        let owner_nk =
            |owner: usize| u32_at(layouts[owner].header + meta.constants) as usize;
        let mut corruptions = Vec::new();

        // Duplicate capture slot (also leaves the overwritten slot missing).
        let (first, second) = (&captures[0], &captures[1]);
        let mut bad = image.clone();
        let slot = second.physical_slot as u16;
        let owner_token =
            super::semantic::encode_pool_owner(first.owner as u16, slot, &image);
        bad.bytes[second.token_positions[0]..second.token_positions[0] + 2]
            .copy_from_slice(&owner_token.to_le_bytes());
        let slot_token = super::semantic::encode_pool_slot(
            first.slot as u16,
            first.owner as u16,
            slot,
            &image,
        );
        bad.bytes[second.token_positions[1]..second.token_positions[1] + 2]
            .copy_from_slice(&slot_token.to_le_bytes());
        corruptions.push(("duplicate-capture-slot", bad));

        let record = &captures[0];
        let wire_slot = record.physical_slot as u16;
        let owner = record.owner as u16;

        let mut bad = image.clone();
        let out_of_range_owner = super::semantic::encode_pool_owner(
            layouts.len() as u16,
            wire_slot,
            &image,
        );
        bad.bytes[record.token_positions[0]..record.token_positions[0] + 2]
            .copy_from_slice(&out_of_range_owner.to_le_bytes());
        corruptions.push(("capture-owner-out-of-range", bad));

        let mut bad = image.clone();
        let out_of_range_slot = super::semantic::encode_pool_slot(
            owner_nu(record.owner) as u16,
            owner,
            wire_slot,
            &image,
        );
        bad.bytes[record.token_positions[1]..record.token_positions[1] + 2]
            .copy_from_slice(&out_of_range_slot.to_le_bytes());
        corruptions.push(("capture-slot-out-of-range", bad));

        let mut bad = image.clone();
        let bad_tag = super::semantic::encode_pool_payload(3, record.slot as u16, owner, &image);
        bad.bytes[record.token_positions[2]..record.token_positions[2] + 2]
            .copy_from_slice(&bad_tag.to_le_bytes());
        corruptions.push(("capture-bad-tag", bad));

        let mut bad = image.clone();
        let index_overflow =
            super::semantic::encode_pool_payload(256 * 4, record.slot as u16, owner, &image);
        bad.bytes[record.token_positions[2]..record.token_positions[2] + 2]
            .copy_from_slice(&index_overflow.to_le_bytes());
        corruptions.push(("capture-index-overflow", bad));

        // Tag/index pair the pool reader accepts but the per-prototype
        // upvalue wiring must refuse: tag 1 with an index at the parent's
        // capture-count boundary.
        let parent_record = captures
            .iter()
            .find(|record| record.owner != 0)
            .expect("fixture must capture into a child prototype");
        let parent = u32_at(layouts[parent_record.owner].header + meta.parent) as usize;
        let parent_nu = owner_nu(parent);
        let mut bad = image.clone();
        let parent_violation = super::semantic::encode_pool_payload(
            1 + parent_nu as u16 * 4,
            parent_record.slot as u16,
            parent_record.owner as u16,
            &image,
        );
        bad.bytes[parent_record.token_positions[2]..parent_record.token_positions[2] + 2]
            .copy_from_slice(&parent_violation.to_le_bytes());
        corruptions.push(("capture-parent-violation", bad));

        // Duplicate constant index (also leaves the overwritten index missing).
        let (first, second) = (&constants[0], &constants[1]);
        let mut bad = image.clone();
        let slot = second.physical_slot as u16;
        let owner_token =
            super::semantic::encode_pool_owner(first.owner as u16, slot, &image);
        bad.bytes[second.token_positions[0]..second.token_positions[0] + 2]
            .copy_from_slice(&owner_token.to_le_bytes());
        let index_token = super::semantic::encode_pool_slot(
            first.index as u16,
            first.owner as u16,
            slot,
            &image,
        );
        bad.bytes[second.token_positions[1]..second.token_positions[1] + 2]
            .copy_from_slice(&index_token.to_le_bytes());
        corruptions.push(("duplicate-constant-index", bad));

        let record = &constants[0];
        let wire_slot = record.physical_slot as u16;
        let owner = record.owner as u16;

        let mut bad = image.clone();
        let out_of_range_owner = super::semantic::encode_pool_owner(
            layouts.len() as u16,
            wire_slot,
            &image,
        );
        bad.bytes[record.token_positions[0]..record.token_positions[0] + 2]
            .copy_from_slice(&out_of_range_owner.to_le_bytes());
        corruptions.push(("constant-owner-out-of-range", bad));

        let mut bad = image.clone();
        let out_of_range_index = super::semantic::encode_pool_slot(
            owner_nk(record.owner) as u16,
            owner,
            wire_slot,
            &image,
        );
        bad.bytes[record.token_positions[1]..record.token_positions[1] + 2]
            .copy_from_slice(&out_of_range_index.to_le_bytes());
        corruptions.push(("constant-index-out-of-range", bad));

        let mut bad = image.clone();
        let bad_tag =
            super::semantic::encode_pool_payload(6, record.index as u16, owner, &image);
        bad.bytes[record.token_positions[2]..record.token_positions[2] + 2]
            .copy_from_slice(&bad_tag.to_le_bytes());
        corruptions.push(("constant-bad-tag", bad));

        let boolean = constants
            .iter()
            .find(|record| record.tag == 1)
            .expect("fixture must contain a boolean constant");
        assert_eq!(boolean.payload.len(), 1);
        let mut bad = image.clone();
        bad.bytes[boolean.payload.start] = 2; // boolean value outside 0..=1
        corruptions.push(("constant-bool-overflow", bad));

        if !target.is_luau() {
            // Tag 4 (64-bit integer) has no reader on Lua 5.1.
            let mut bad = image.clone();
            let tag4 = super::semantic::encode_pool_payload(
                4,
                record.index as u16,
                owner,
                &image,
            );
            bad.bytes[record.token_positions[2]..record.token_positions[2] + 2]
                .copy_from_slice(&tag4.to_le_bytes());
            corruptions.push(("constant-tag4-on-lua51", bad));
        }

        // A removed pool record shifts every later byte; the fixed pool
        // counts plus the trailing exact-consumption check must refuse it.
        let mut bad = image.clone();
        let base = *captures[0].token_positions.iter().min().unwrap();
        bad.bytes.drain(base..base + 6);
        let length = bad.bytes.len() as u32;
        bad.bytes[12..16].copy_from_slice(&length.to_le_bytes());
        corruptions.push(("removed-pool-record", bad));

        let mut bad = image.clone();
        bad.bytes.push(0); // global pools have an unconsumed trailing byte
        let length = bad.bytes.len() as u32;
        bad.bytes[12..16].copy_from_slice(&length.to_le_bytes());
        corruptions.push(("trailing", bad));

        for (kind, mut bad) in corruptions {
            repair_semantic_checksum(&mut bad.bytes);
            let raw = super::emit::generate_from_semantic_image(&program, 917, bad).unwrap();
            let output = finalize(&raw, target, 917).unwrap();
            let workspace = native::Workspace::new();
            let path = workspace.0.join(if target.is_luau() {
                "invalid_pools.luau"
            } else {
                "invalid_pools.lua"
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
fn empty_capture_pool_roundtrips_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        let source = "print('POOL_OK',40+2)";
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let image = super::semantic::encode(&program, 917).unwrap();
        let (_, captures, constants, _) = semantic_pool_layouts(&image);
        assert!(captures.is_empty(), "{target}: expected an empty capture pool");
        assert!(!constants.is_empty(), "{target}: fixture must pool constants");
        let raw = generate(&data, &program, 917).unwrap();
        let output = finalize(&raw, target, 917).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join(if target.is_luau() {
            "empty_pool.luau"
        } else {
            "empty_pool.lua"
        });
        fs::write(&path, output).unwrap();
        let stdout = native::compile_and_run(target, &path);
        assert_eq!(stdout, b"POOL_OK\t42\n", "{target}: pooled output mismatch");
    }
}

/// Direct seed-op differential vectors: stub register file, constants, site,
/// pools and helpers, then 79 micro-programs covering every op shape,
/// falsy-value preservation, per-target floordiv/mod parity, and 30 fail-closed
/// rejections. Runs unmodified on both runners against the emitted template.
const SEED_DIRECT_VECTORS: &str = r#"
local RXF=function(i)return i+10 end
local K={[5]="k5",[6]="k6",[7]=false}
local R={};R[12]="r12";R[13]=false;R[14]=0;R[15]={7,8};R[16]={}
local SITE={2,3,4,5,6,7,100}
local STAB={"s0","s1",""}
local n3=0
local H={function(a,b)return a+b end,function()return "h1" end,function(p)return p.n..":"..tostring(p[1]) end,function()n3=n3+1;if n3<3 then return 1 end end}
local V={
{"01-mov-int",{{1,0,3005000},{7,2,0}},2,"VAL",5},
{"02-mov-reg",{{1,0,1000000},{7,2,0}},2,"VAL","r12"},
{"03-mov-reg-off",{{1,0,1002001},{7,2,0}},2,"TBL15"},
{"04-mov-konst",{{1,0,2003000},{7,2,0}},2,"VAL","k5"},
{"05-mov-konst-off",{{1,0,2003001},{7,2,0}},2,"VAL","k6"},
{"06-mov-sconst",{{1,0,5001000},{7,2,0}},2,"VAL","s1"},
{"07-mov-nil",{{1,0,6000000},{7,2,0}},2,"NIL"},
{"08-mov-helper-val",{{1,0,7001000},{7,2,0}},2,"FUNC"},
{"09-mov-opval",{{1,0,8003000},{7,2,0}},2,"VAL",5},
{"10-mov-pseudo",{{1,0,4002000},{7,2,0}},2,"VAL",3},
{"11-mov-tmp-chain",{{1,1000,3009000},{1,0,1000},{7,2,0}},2,"VAL",9},
{"12-mov-false",{{1,0,1001000},{7,2,0}},2,"FALSE"},
{"13-mov-zero",{{1,0,1002000},{7,2,0}},2,"VAL",0},
{"14-t-reg-str",{{2,0,1000000},{7,2,0}},2,"VAL",true},
{"15-t-false",{{2,0,1001000},{7,2,0}},2,"FALSE"},
{"16-t-zero",{{2,0,1002000},{7,2,0}},2,"VAL",true},
{"17-t-nil",{{2,0,6000000},{7,2,0}},2,"FALSE"},
{"18-t-konst-false",{{2,0,2003002},{7,2,0}},2,"FALSE"},
{"19-t-int",{{2,0,3000000},{7,2,0}},2,"VAL",true},
{"20-t-empty-str",{{2,0,5002000},{7,2,0}},2,"VAL",true},
{"21-new-len0",{{3,0,3000000},{7,2,0}},2,"TABLE"},
{"22-new-len2",{{3,0,3002000},{7,2,0}},2,"TABLE"},
{"23-new-len-tmp",{{1,1000,3004000},{3,0,1000},{7,2,0}},2,"TABLE"},
{"24-add",{{4,0,3006000,3007000,3000000},{7,2,0}},2,"VAL",13},
{"25-sub",{{4,0,3010000,3004000,3001000},{7,2,0}},2,"VAL",6},
{"26-mul",{{4,0,3006000,3007000,3002000},{7,2,0}},2,"VAL",42},
{"27-div",{{4,0,3007000,3002000,3003000},{7,2,0}},2,"VAL",3.5},
{"28-div-zero",{{4,0,3001000,3000000,3003000},{7,2,0}},2,"INF"},
{"29-mod-pos",{{4,0,3007000,3003000,3004000},{7,2,0}},2,"VAL",1},
{"30-mod-neg",{{4,1000,3007000,3000000,3006000},{4,0,1000,3003000,3004000},{7,2,0}},2,"VAL",2},
{"31-pow",{{4,0,3002000,3010000,3005000},{7,2,0}},2,"VAL",1024},
{"32-unm",{{4,0,3005000,3009000,3006000},{7,2,0}},2,"VAL",-5},
{"33-fdiv-pos",{{4,0,3007000,3002000,3007000},{7,2,0}},2,"VAL",3},
{"34-fdiv-neg",{{4,1000,3007000,3000000,3006000},{4,0,1000,3002000,3007000},{7,2,0}},2,"VAL",-4},
{"35-fdiv-negdiv",{{4,1000,3002000,3000000,3006000},{4,0,3007000,1000,3007000},{7,2,0}},2,"VAL",-4},
{"36-eq-true",{{4,0,3005000,3005000,3008000},{7,2,0}},2,"VAL",true},
{"37-eq-false",{{4,0,3005000,3006000,3008000},{7,2,0}},2,"FALSE"},
{"38-eq-mixed",{{4,0,2003000,3005000,3008000},{7,2,0}},2,"FALSE"},
{"39-alu-tmp-src",{{1,1000,3006000},{4,0,1000,3007000,3000000},{7,2,0}},2,"VAL",13},
{"40-alu-typefail",{{4,0,2003000,3001000,3000000},{7,2,0}},0,"FAIL"},
{"41-alu-fdiv-zero",{{4,0,3007000,3000000,3007000},{7,2,0}},0,"FAIL"},
{"42-alu-badop",{{4,0,3001000,3002000,3009000},{7,0}},0,"FAIL"},
{"43-call-plain",{{5,0,7000000,3000000,2,3006000,3007000},{7,2,0}},2,"VAL",13},
{"44-call-nargs0",{{5,0,7001000,3000000,0},{7,2,0}},2,"VAL","h1"},
{"45-call-tmp-f",{{1,1000,7000000},{5,0,1000,3000000,2,3001000,3002000},{7,2,0}},2,"VAL",3},
{"46-call-spread",{{1,1000,1002001},{5,0,7000000,3001000,1,1000},{7,2,0}},2,"VAL",15},
{"47-call-spread-empty",{{3,0,3000000},{5,1000,7000000,3001000,1,0},{7,2,1000}},0,"FAIL"},
{"48-call-pack",{{5,0,7002000,3002000,1,3005000},{7,2,0}},2,"VAL","1:5"},
{"49-call-badmode",{{5,0,7000000,3003000,0},{7,0}},0,"FAIL"},
{"50-call-nargs9",{{5,0,7000000,3000000,9,3001000,3001000,3001000,3001000,3001000,3001000,3001000,3001000,3001000},{7,0}},0,"FAIL"},
{"51-call-badfn",{{5,0,3005000,3000000,0},{7,0}},0,"FAIL"},
{"52-call-helper-oob",{{5,0,7004000,3000000,0},{7,0}},0,"FAIL"},
{"53-br-jmp-fwd",{{6,3},{7,2,3001000},{7,2,3002000}},2,"VAL",2},
{"54-br-jif-taken",{{2,0,3005000},{6,0,4},{7,2,3001000},{7,2,3002000}},2,"VAL",2},
{"55-br-jif-fall",{{2,0,6000000},{6,0,4},{7,2,3001000},{7,2,3002000}},2,"VAL",1},
{"56-br-jif-zero",{{2,0,3000000},{6,0,4},{7,2,3001000},{7,2,3002000}},2,"VAL",2},
{"57-br-loop",{{5,0,7003000,3000000,0},{2,1000,0},{6,1000,1},{7,2,3009000}},2,"VAL",9},
{"58-br-badtarget",{{6,9},{7,0}},0,"FAIL"},
{"59-br-badcond",{{6,3001000,2},{7,0}},0,"FAIL"},
{"60-br-self-loop",{{6,1}},0,"FAIL"},
{"61-ret-fall",{{7,0}},0,"NIL"},
{"62-ret-goto",{{7,1,3005000}},1,"VAL",5},
{"63-ret-false",{{7,2,1001000}},2,"FALSE"},
{"64-ret-badaction",{{7,3,3001000}},0,"FAIL"},
{"65-bad-op",{{9,0},{7,0}},0,"FAIL"},
{"66-empty-prog",{},0,"FAIL"},
{"67-falloff",{{1,0,3001000}},0,"FAIL"},
{"68-forged-pc",{{1,0,4000000},{7,0}},0,"FAIL"},
{"69-forged-fid",{{1,0,4001000},{7,0}},0,"FAIL"},
{"70-temp-oob",{{1,16000,3001000},{7,0}},0,"FAIL"},
{"71-int-huge",{{1,0,1003000000},{7,0}},0,"FAIL"},
{"72-opval-oob",{{1,0,8007000},{7,0}},0,"FAIL"},
{"73-opval-pc",{{7,2,8006000}},2,"VAL",100},
{"74-pseudo9",{{7,2,4009000}},2,"NIL"},
{"75-reg-idx3",{{1,0,1003000},{7,0}},0,"FAIL"},
{"76-call-arity-short",{{5,0,7000000,3000000,2,3001000},{7,0}},0,"FAIL"},
{"77-mov-len2",{{1,0},{7,2,0}},0,"FAIL"},
{"78-frac-ref",{{1,0,3001000.5},{7,0}},0,"FAIL"},
{"79-sconst-oob",{{1,0,5003000},{7,0}},0,"FAIL"}}
local pass=0
for _,v in ipairs(V) do
local name,prog,expact,marker,expval=v[1],v[2],v[3],v[4],v[5]
local ok,act,av=pcall(SEED,prog,SITE,R,RXF,K,STAB,H)
local good=false
if marker=="FAIL" then good=(not ok)and type(act)=="string" and act:sub(1,9)=="seedfail:"
elseif ok and act==expact then
if marker=="VAL" then good=(av==expval)
elseif marker=="NIL" then good=(av==nil)
elseif marker=="FALSE" then good=(av==false)
elseif marker=="FUNC" then good=(type(av)=="function")
elseif marker=="TABLE" then good=(type(av)=="table")
elseif marker=="TBL15" then good=(av==R[15])
elseif marker=="INF" then good=(av==1/0)
end end
if good then pass=pass+1 else print("VFAIL:"..name..":"..tostring(act)) end
end
print("SEEDOPS PASS "..pass.."/"..#V)
"#;

#[test]
fn seed_control_flow_matches_classic_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(SEED_CONTROL_FIXTURE, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = generate(&data, &program, 735).unwrap();
        let output = finalize(&raw, target, 735).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join("seed_ctrl.lua");
        fs::write(&path, output).unwrap();
        let stdout = native::compile_and_run(target, &path);
        assert_eq!(stdout, b"9\n", "{target}: control-flow output mismatch");
    }
}

#[test]
fn seed_ops_direct_differential_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        let source = format!(
            "local E=function(m)error(m,0)end;local MF=math.floor;local TY=type;local PC=pcall;local U=unpack or table.unpack;local Z=function(...)return {{n=select('#',...),...}}end;\n{}\n{}\n",
            seed_loop_lua(target),
            SEED_DIRECT_VECTORS
        );
        let work = native::Workspace::new();
        let path = work.0.join("seed_ops.lua");
        fs::write(&path, source).unwrap();
        let stdout = native::compile_and_run(target, &path);
        assert_eq!(
            stdout,
            b"SEEDOPS PASS 79/79\n",
            "{target}: direct vectors mismatch: {}",
            String::from_utf8_lossy(&stdout)
        );
    }
}

#[test]
fn seed_routine_corruption_rejected_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(SEED_CONTROL_FIXTURE, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = generate(&data, &program, 735).unwrap();
        assert!(
            raw.contains(
                "local SEEDJ,SEEDT,SEEDR={{7,1,8004000}},{{2,0,1000000},{6,0,4},{7,1,8005000},{7,0}},{{1,0,1000000},{7,2,0}};"
            ),
            "{target}: seed routine data not emitted (migration absent?)"
        );
        let cases: Vec<(&str, String)> = vec![
            ("bad-op", raw.replacen("{{7,1,8004000}}", "{{9,1,8004000}}", 1)),
            ("bad-arity", raw.replacen("{{7,1,8004000}}", "{{7}}", 1)),
            ("bad-target", raw.replacen("{6,0,4}", "{6,0,9}", 1)),
            ("forged-pc", raw.replacen("{2,0,1000000}", "{2,0,4000000}", 1)),
            (
                "drop-tail",
                raw.replacen(
                    "{{2,0,1000000},{6,0,4},{7,1,8005000},{7,0}}",
                    "{{2,0,1000000},{6,0,4},{7,1,8005000}}",
                    1,
                ),
            ),
            ("falloff", raw.replacen("{{7,1,8004000}}", "{{1,0,0}}", 1)),
            (
                "bad-kind",
                raw.replacen("{{7,1,8004000}}", "{{7,1,8004000000}}", 1),
            ),
            (
                "ret-action",
                raw.replacen("{{7,1,8004000}}", "{{7,3,8004000}}", 1),
            ),
        ];
        for (label, src) in &cases {
            assert_ne!(*src, raw, "{target} {label}: surgery hit nothing");
            let output = finalize(src, target, 735).unwrap();
            let work = native::Workspace::new();
            let path = work.0.join(format!("seed_corr_{label}.lua"));
            fs::write(&path, output).unwrap();
            assert!(native::compile(target, &path).status.success());
            let runner = if target.is_luau() { "luau" } else { "lua5.1" };
            let result = Command::new(native::root().join("toolchains/bin").join(runner))
                .arg(&path)
                .output()
                .unwrap();
            assert!(!result.status.success(), "{target} corruption {label} ran");
            assert!(
                result.stdout.is_empty(),
                "{target} corruption {label} leaked output: {:?}",
                result.stdout
            );
        }
    }
}
