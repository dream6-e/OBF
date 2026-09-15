// ISA14 私有镜像的 fail-closed 面：语义图/prototype metadata/全局段图被损坏时，
// 解码器必须在用户代码执行之前死掉，且不泄漏任何输出。
//
// 这些门与 `tests/runtime.rs` 同属一个模块作用域（`include!` 进 `custom::tests`），
// 分成两个文件只为了守那条 80 KiB 源文件上限，不改变任何可见性。

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
            // K3-FULL: every recipe slot is a byte pair (renumbered id, operand form).
            cursor += 3 + 2 * len;
        }
        let start_label = cursor;
        let first_record = start_label + 2;
        assert!(first_record + 8 <= code_len);
        let first_len = usize::from(code_bytes[first_recipe + if flipped { 0 } else { 2 }]);
        let second_recipe = first_recipe + 3 + 2 * first_len;
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
        // Goal 5: the logical code region is `[records][constants block]
        // [u32 block_len]`, so the record stream must cover the region up to
        // the block -- the trailing block itself is validated by `DC` (its
        // own corruption gates live in `tests/runtime.rs`).
        let block_len =
            u32::from_le_bytes(code_bytes[code_len - 4..code_len].try_into().unwrap()) as usize;
        assert!(block_len > 0 && block_len + 4 <= code_len);
        assert_eq!(record_cursor, code_len - 4 - block_len);

        let len_offset = if flipped { 0 } else { 2 };
        let rid_offset = if flipped { 1 } else { 0 };

        let mut corruptions = Vec::new();
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[first_recipe + len_offset] = 0; // empty recipe
        }));
        // K3-FULL: a recipe slot now carries its operand form next to the renumbered
        // id, and the form is bounded before anything is read. Push slot 0's form byte
        // out of range (decoded value 5, above the five shapes) and require the same
        // fail-closed death.
        let first_rid =
            u16::from_le_bytes(code_bytes[first_recipe + rid_offset..first_recipe + rid_offset + 2].try_into().unwrap());
        let form_mask = (u64::from(first_rid) * u64::from(image.mask_mul)
            + u64::from(image.mask_add)
            + u64::from(image.mask_salt))
            % 8;
        corruptions.push(mutate_semantic_code(&image, 0, |code| {
            code[first_recipe + 4] = ((5 + form_mask) % 8) as u8; // form out of range
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
    let (layouts, pool_captures, segments) = semantic_pool_layouts(&image);
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

    // Index of the trailing-slack class in `corruptions` (the push after the
    // truncated-payload one), named so the tripwire below cannot drift onto
    // another class if the list is reordered.
    const UNPINNED_TAIL_SLACK: usize = 11;
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
        if kind == UNPINNED_TAIL_SLACK {
            // Tripwire for a *measured* detection gap, not a waiver: appending a
            // byte past the last section and re-signing the length/checksum fields
            // the repair helper owns leaves nothing for the runtime to notice -
            // section extents are derived from the read cursor, so `pos()` and the
            // declared length move together. K18 tried to close it with a pool-tail
            // census (max consumed extent vs the cursor); it does not fire, because
            // the slack sits outside the pool region. Closing the gap needs a
            // *declared* per-section length compared against the measured one, i.e.
            // an image-format change, which is scheduled with the next private ISA
            // bump. The moment detection lands this assert fails, and the class has
            // to move back into the rejecting set below.
            assert!(
                result.status.success(),
                "prototype corruption {kind} is now detected: move it back into the rejecting set"
            );
            continue;
        }
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
        let (layouts, _captures, segments) = semantic_pool_layouts(&image);
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
