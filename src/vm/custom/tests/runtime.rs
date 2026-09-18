
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
            // K4 adds a layout step in front of the naming pass, and it can add
            // bindings (a hoisted helper and its parameters). The zip below
            // compares bindings one for one, so its baseline is the text the
            // naming pass actually receives -- `finalize_unlaid` is the same
            // stage sequence the shipped pipeline runs after the layout pass.
            let laid = super::layout::restructure(&raw, target, seed).unwrap();
            let before = crate::scope::analyze(&laid, target).unwrap();
            let renamed = super::finalize_unlaid(&laid, target, seed).unwrap();
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
    dseed: u64,
) -> (super::semantic::SemanticImage, BTreeSet<u16>) {
    let program = custom::decode(data, target).unwrap();
    let image = super::semantic::encode(&program, dseed).unwrap();
    let raw = generate(data, &program, dseed).unwrap();
    // Instrument the real graph fetch BEFORE the same final whole-output
    // naming/audit pass. This observes ids only after both edge and recipe
    // token machines have run. Tuple slots follow the per-image field order.
    let tuple = super::lowering::field_layout(dseed).tuple_slots();
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
    let output = finalize(&raw, target, dseed).unwrap();
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

fn execute_coverage(data: &[u8], target: Target, dseed: u64) -> BTreeSet<Opcode> {
    let (image, recipe_ids) = execute_recipe_ids(data, target, dseed);
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
        let (image, executed) = execute_recipe_ids(&data, target, 735);
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
        for dseed in [735u64, 7001, 1, u64::MAX] {
        let mut executed = BTreeSet::new();
        for corpus in corpora {
            executed.extend(execute_coverage(&compile(corpus, target).unwrap(), target, dseed));
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
        executed.extend(execute_coverage(&custom::encode(&module).unwrap(), target, dseed));
        let expected: BTreeSet<_> = Opcode::ALL
            .iter()
            .copied()
            .filter(|op| op.supported(target))
            .collect();
        assert_eq!(executed, expected, "unexecuted custom opcode on {target} seed {dseed}");
        }
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
            // numeric field count. K20 moved most section functions out of the
            // literal: they now arrive through runtime installs in the entry
            // stage arms, so only the bootstrapping fields (environment
            // capture, prelude, head guards, entry, interpreter) stay baked.
            // The census of *both* kinds lives in `scatter.rs`.
            let ExpressionKind::Table(fields) = &setmetatable_arguments[0].kind else {
                panic!("{target}: {output}");
            };
            assert!((5..=8).contains(&fields.len()), "{target}: {output}");
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
            assert!((4..=7).contains(&numeric_keys.len()));
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
        let (layouts, _captures, segments) = semantic_pool_layouts(&image);
        let code_bytes = semantic_code(&image, 0);
        let recipes = u16::from_le_bytes(code_bytes[..2].try_into().unwrap()) as usize;
        let len_offset = if field.dict_flipped { 0 } else { 2 };
        let mut cursor = 2usize;
        for _ in 0..recipes {
            let len = usize::from(code_bytes[cursor + len_offset]);
            assert!((1..=4).contains(&len));
            // K3-FULL: two bytes per recipe slot (renumbered id + operand form).
            cursor += 3 + 2 * len;
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

/// Goal 5: one code-resident constant as the independent wire reader sees it.
#[derive(Clone, Debug, PartialEq)]
struct CodeResidentConstant {
    tag: u8,
    /// Absolute file offset of the entry's tag byte.
    tag_position: usize,
    /// Absolute file offsets of the *keyed* payload bytes, in order.
    payload: Vec<usize>,
    /// Absolute file offset of a string/method entry's clear u32 length prefix.
    length_position: Option<usize>,
    value: ir::Constant,
}

/// Recover a prototype's constants from the tail of its own code region,
/// without the emitted walker.
///
/// Everything here is expressed in *region indices* -- the 0-based positions
/// the emitted walker carries as `at`/`p`/`off`/`z` -- and mapped to file
/// offsets through `layout.code_positions`. That mapping matters: a region is
/// split across segments whose payloads are interleaved with other prototypes'
/// in the file, so a multi-byte field can straddle two segments and must never
/// be read as four consecutive file bytes. The mirror reads the clear u32 block
/// length, unmasks each tag and payload with its independent ordinal-derived
/// subkey, and returns the values. It is the same lazy walk `KGC` performs, so
/// agreement between the two proves the encoder's block layout, the runtime's
/// per-use synthesis and this independent reader all describe one format.
fn parse_code_constants(
    image: &super::semantic::SemanticImage,
    layout: &SemanticPrototypeLayout,
) -> Vec<CodeResidentConstant> {
    let bytes = &image.bytes;
    let region = &layout.code_positions;
    assert!(region.len() >= 4, "code region too short for a constant block");
    // Region index -> file offset for the four bytes of a little-endian u32.
    let u32_at = |from: usize| -> u32 {
        let mut value = 0u32;
        for (shift, offset) in region[from..from + 4].iter().enumerate() {
            value |= u32::from(bytes[*offset]) << (8 * shift);
        }
        value
    };
    let tail = region.len() - 4;
    let block_len = u32_at(tail) as usize;
    assert!(
        block_len + 4 <= region.len(),
        "constant block {block_len} B overflows a {} B code region",
        region.len()
    );
    let (mask, modulus) = super::semantic::pool_key_pair(image);
    let (roll_mul, roll_mix, roll_add) = super::semantic::pool_roll_triple(image);
    let mut at = tail - block_len;
    let mut out = Vec::new();
    while at < tail {
        let tag = bytes[region[at]].wrapping_sub(
            super::semantic::pool_key_byte(
                super::semantic::pool_entry_key(out.len(), mask, modulus),
                0,
            ) as u8,
        );
        let (keyed_from, keyed_len, length_position) = match tag {
            0 => (at + 1, 0usize, None),
            1 => (at + 1, 1, None),
            2 | 4 => (at + 1, 8, None),
            3 | 5 => (at + 5, u32_at(at + 1) as usize, Some(region[at + 1])),
            other => panic!("bad constant tag {other} in the code region"),
        };
        assert!(
            keyed_from + keyed_len <= tail,
            "constant entry runs past its block"
        );
        // Goal 6 rolling inverse: the first byte's key is the entry seed, and
        // every later key rolls over the plaintext byte just recovered -- the
        // same recurrence `UK` runs, written here independently.
        let mut plain = Vec::with_capacity(keyed_len);
        let subkey = super::semantic::pool_entry_key(out.len(), mask, modulus);
        let mut key = super::semantic::pool_key_byte(subkey, 1);
        for index in 0..keyed_len {
            let byte = bytes[region[keyed_from + index]];
            let value = (u64::from(byte) + 256 - key) % 256;
            plain.push(value as u8);
            key = (key * roll_mul + value * roll_mix + roll_add) % 256;
        }
        let value = match tag {
            0 => ir::Constant::Nil,
            1 => ir::Constant::Boolean(plain[0] == 1),
            2 => ir::Constant::Number(u64::from_le_bytes(plain[..8].try_into().unwrap())),
            3 => ir::Constant::String(plain),
            4 => ir::Constant::Integer(i64::from_le_bytes(plain[..8].try_into().unwrap())),
            _ => ir::Constant::Method(String::from_utf8(plain).unwrap()),
        };
        out.push(CodeResidentConstant {
            tag,
            tag_position: region[at],
            payload: region[keyed_from..keyed_from + keyed_len].to_vec(),
            length_position,
            value,
        });
        at = keyed_from + keyed_len;
    }
    assert_eq!(at, tail, "constant block does not end where its length says");
    out
}

/// Wire walker: contiguous 24-byte headers (captures live only in the global
/// capture pool; goal 5 moved the constants into the code regions), then the
/// capture pool, then the segment graph. Exact consumption of every byte is
/// asserted, exactly like the segment walker it extends -- which is also the
/// proof that no constant pool exists any more: a third pool would leave bytes
/// unconsumed.
fn semantic_pool_layouts(
    image: &super::semantic::SemanticImage,
) -> (
    Vec<SemanticPrototypeLayout>,
    Vec<PooledCaptureLayout>,
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
    for _ in 0..prototypes {
        let header = position;
        let captures = usize::from(u16_at(header + meta.captures));
        let segment_count = 2;
        let root_token_position = header + meta.root;
        let root_token = u16_at(root_token_position);
        // Goal 5: the constant count is no longer parsed into a layout total --
        // the block itself is walked (and its entry count checked against this
        // same header field) by `parse_code_constants`.
        let records = u32_at(header + meta.records) as usize;
        let code_len = u32_at(header + meta.code_len) as usize;
        capture_total += captures;
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
    let (captures, mut position) = parse_capture_pool(image, &layouts, capture_total, position);
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
        let owner_token = u16_at(owner_token_position);
        let owner = usize::from(super::semantic::decode_segment_owner(
            owner_token,
            id as u16,
            physical_slot as u16,
            image,
        ));
        assert!(owner < prototypes);
        let next_token = u16_at(next_token_position);
        let next = usize::from(super::semantic::decode_segment_next(
            next_token,
            id as u16,
            owner as u16,
            image,
        ));
        let split =
            super::semantic::code_segment_split(layouts[owner].code_len, owner as u16, image);
        let length = if next != 0 {
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
    (layouts, captures, segments)
}

/// Goal 5 gate: the wire carries exactly one pool (captures) and nothing that
/// reads back as a constant table, while every prototype's constants are
/// *provably* still there -- inside its own code region, recoverable entry by
/// entry through the documented key chain, in constant-index order, and equal to
/// what the decoded program holds. The mirror is the same walk the emitted
/// `KGC` performs, written independently in Rust, so a drift between the
/// encoder's block layout and the runtime's per-use synthesis shows up here
/// instead of at run time.
#[test]
fn capture_pool_mirror_and_code_resident_constants_hold_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(
            "local function f(n)if n>0 then return f(n-1)end return n end print(f(2))",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 735] {
            let image = super::semantic::encode(&program, seed).unwrap();
            let (layouts, captures, segments) = semantic_pool_layouts(&image);
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
            // No constant pool: the captured total is the only pool total the
            // wire can even express, and `semantic_pool_layouts` already proved
            // exact byte consumption past it.
            for (owner, layout) in layouts.iter().enumerate() {
                let nk = u32_at(layout.header + meta.constants) as usize;
                let mirrored = parse_code_constants(&image, layout);
                assert_eq!(
                    mirrored.len(),
                    nk,
                    "{target} seed {seed}: owner {owner} code-resident constant count"
                );
                for (index, constant) in mirrored.iter().enumerate() {
                    assert!(
                        layout.code_positions.contains(&constant.tag_position),
                        "{target} seed {seed}: owner {owner} entry {index} outside its region"
                    );
                }
                // Decoy prototypes carry synthetic constants (a real prototype
                // order position does not exist for them), so only their block
                // shape is pinned; the canonical prototypes must mirror their
                // decoded constants value for value and in index order.
                let old = image.prototype_order[owner];
                if old >= program.prototypes.len() {
                    continue;
                }
                let expected: Vec<ir::Constant> = program.prototypes[old].constants.clone();
                assert_eq!(
                    mirrored.iter().map(|c| c.value.clone()).collect::<Vec<_>>(),
                    expected,
                    "{target} seed {seed}: owner {owner} constants in the code region"
                );
            }
            let _ = expected_captures;
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
                // Decoy owners
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
        let code_constants: usize = program
            .prototypes
            .iter()
            .map(|prototype| prototype.constants.len())
            .sum();
        assert!(canonical_captures >= 3, "fixture needs a shufflable pool");
        assert!(
            code_constants >= 3,
            "fixture needs constants in the code regions"
        );
        let mut capture_orders = BTreeSet::new();
        for seed in [0u64, 1, 2, 3, 735, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            // Decoys never capture, so the pool total is exactly the canonical
            // one; their synthetic constants live in their own code regions.
            assert_eq!(
                image.capture_pool_owners.len(),
                canonical_captures,
                "{target} seed {seed}: capture pool total"
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
        }
        assert!(
            capture_orders.len() >= 2,
            "{target}: capture pool order pinned across seeds"
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
        let (layouts, captures, _) = semantic_pool_layouts(&image);
        assert!(captures.len() >= 2);
        let meta = image.field_layout.metadata_positions();
        let u16_at = |offset: usize| {
            u16::from_le_bytes(image.bytes[offset..offset + 2].try_into().unwrap())
        };
        let u32_at = |offset: usize| {
            u32::from_le_bytes(image.bytes[offset..offset + 4].try_into().unwrap())
        };
        let owner_nu =
            |owner: usize| usize::from(u16_at(layouts[owner].header + meta.captures));
        let mut corruptions = Vec::new();
        // Goal 5: the constant table is gone -- the corruptions below attack the
        // code-resident blocks instead, and every one of them has to fail closed
        // during `DC` (which walks every prototype's block before user code runs).
        let mut blocks: Vec<(usize, Vec<CodeResidentConstant>)> = (0..layouts.len())
            .map(|owner| (owner, parse_code_constants(&image, &layouts[owner])))
            .filter(|(_, constants)| !constants.is_empty())
            .collect();
        assert!(
            blocks.len() >= 2 && blocks.iter().map(|(_, c)| c.len()).sum::<usize>() >= 4,
            "fixture must carry constants in at least two code regions"
        );

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

        let (owner, constants) = blocks.remove(0);
        let region_span = &layouts[owner].code_positions;

        // Tag byte outside 0..=5: the walk's tag dispatch has no arm for it.
        let mut bad = image.clone();
        bad.bytes[constants[0].tag_position] = 6;
        corruptions.push(("code-constant-bad-tag", bad));

        // A string entry whose clear length prefix claims more than the block.
        let string = constants
            .iter()
            .find(|constant| constant.tag == 3 || constant.tag == 5)
            .expect("fixture must contain a string constant");
        let mut bad = image.clone();
        let length_at = string
            .length_position
            .expect("string entry carries a clear length prefix");
        for (shift, offset) in [0usize, 1, 2, 3].iter().enumerate() {
            bad.bytes[length_at + offset] = (0xffffu32 >> (8 * shift)) as u8;
        }
        corruptions.push(("code-constant-length-overflow", bad));

        // A boolean payload outside 0..=1: the value form is validated on the
        // load walk, so this must die before any user code runs.
        let boolean = constants
            .iter()
            .find(|constant| constant.tag == 1)
            .expect("fixture must contain a boolean constant");
        let mut bad = image.clone();
        bad.bytes[boolean.payload[0]] = 2;
        corruptions.push(("code-constant-bool-overflow", bad));

        // The clear block length is one byte short: the walk's extent no longer
        // covers the block, and the code/block split moves with it.
        let mut bad = image.clone();
        let tail = region_span.len() - 4;
        let block_len = u32_at(region_span[tail]);
        let shrunk = (block_len - 1).to_le_bytes();
        for (index, offset) in region_span[tail..tail + 4].iter().enumerate() {
            bad.bytes[*offset] = shrunk[index];
        }
        corruptions.push(("code-constant-block-shrunk", bad));

        if !target.is_luau() {
            // Tag 4 (64-bit integer) has no value form on Lua 5.1.
            let mut bad = image.clone();
            bad.bytes[constants[0].tag_position] = 4;
            corruptions.push(("code-constant-tag4-on-lua51", bad));
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
        let (layouts, captures, _) = semantic_pool_layouts(&image);
        assert!(captures.is_empty(), "{target}: expected an empty capture pool");
        assert!(
            layouts
                .iter()
                .any(|layout| !parse_code_constants(&image, layout).is_empty()),
            "{target}: fixture must carry constants in a code region"
        );
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
const SEED_DIRECT_POOLS: &str = r#"
local STAB={"s0","s1",""}
local n3=0
local SEEDH={function(a,b)return a+b end,function()return "h1" end,function(p)return p.n..":"..tostring(p[1]) end,function()n3=n3+1;if n3<3 then return 1 end end,function()error("boom-raise")end}
local RX=function(i)return i+10 end
local K={[5]="k5",[6]="k6",[7]=false}
local R={};R[12]="r12";R[13]=false;R[14]=0;R[15]={7,8};R[16]={}
local F={__obf_proto_nk=8}
"#;
const SEED_DIRECT_DATA: &str = r#"
local SITE={2,3,4,5,6,7,100}
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
{"40-alu-typefail",{{4,0,2003000,3001000,3000000},{7,2,0}},0,"LUAERR"},
{"41-alu-fdiv-zero",{{4,0,3007000,3000000,3007000},{7,2,0}},2,"INF"},
{"42-alu-badop",{{4,0,3001000,3002000,3014000},{7,0}},0,"FAIL"},
{"43-call-plain",{{5,0,7000000,3000000,2,3006000,3007000},{7,2,0}},2,"VAL",13},
{"44-call-nargs0",{{5,0,7001000,3000000,0},{7,2,0}},2,"VAL","h1"},
{"45-call-tmp-f",{{1,1000,7000000},{5,0,1000,3000000,2,3001000,3002000},{7,2,0}},2,"VAL",3},
{"46-call-spread",{{1,1000,1002001},{5,0,7000000,3001000,1,1000},{7,2,0}},2,"VAL",15},
{"47-call-spread-empty",{{3,0,3000000},{5,1000,7000000,3001000,1,0},{7,2,1000}},0,"LUAERR"},
{"48-call-pack",{{5,0,7002000,3002000,1,3005000},{7,2,0}},2,"VAL","1:5"},
{"49-call-badmode",{{5,0,7000000,3003000,0},{7,0}},0,"FAIL"},
{"50-call-nargs9",{{5,0,7000000,3000000,9,3001000,3001000,3001000,3001000,3001000,3001000,3001000,3001000,3001000},{7,0}},0,"FAIL"},
{"51-call-badfn",{{5,0,3005000,3000000,0},{7,0}},0,"FAIL"},
{"52-call-helper-oob",{{5,0,7005000,3000000,0},{7,0}},0,"FAIL"},
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
{"72-opval-oob",{{1,0,8009000},{7,0}},0,"FAIL"},
{"73-opval-pc",{{7,2,8006000}},2,"VAL",100},
{"74-pseudo9",{{7,2,4009000}},2,"NIL"},
{"75-reg-idx3",{{1,0,1003000},{7,0}},0,"FAIL"},
{"76-call-arity-short",{{5,0,7000000,3000000,2,3001000},{7,0}},0,"FAIL"},
{"77-mov-len2",{{1,0},{7,2,0}},0,"FAIL"},
{"78-frac-ref",{{1,0,3001000.5},{7,0}},0,"FAIL"},
{"79-sconst-oob",{{1,0,5003000},{7,0}},0,"FAIL"},
{"80-ret-expect-ok",{{7,2,3005000}},2,"VAL",5,2},
{"81-ret-expect-mismatch",{{7,2,3005000}},0,"LUAERR",nil,0},
{"82-ret-expect-9-unchecked",{{7,2,3005000}},2,"VAL",5,9},
{"83-ret-expect-nil-means-zero",{{7,2,3005000}},0,"NILEXP"},
{"84-ret-expect-nil-accepts-zero",{{7,0}},0,"NILOK"},
{"85-call-callee-error-propagates",{{5,0,7004000,3000000,0},{7,2,0}},0,"PROP"}}
"#;
const SEED_DIRECT_RUNNER: &str = r#"
local pass=0
for _,v in ipairs(V) do
local name,prog,expact,marker,expval=v[1],v[2],v[3],v[4],v[5]
local ok,av,act=pcall(SEED,prog,SITE,v[6] or 9)
local good=false
if marker=="FAIL" then good=(not ok)and type(av)=="string" and av:sub(1,9)=="seedfail:"
elseif marker=="LUAERR" then good=(not ok)and(type(av)~="string" or av:sub(1,9)~="seedfail:")
elseif marker=="NILEXP" then good=(not pcall(SEED,prog,SITE))
elseif marker=="NILOK" then local ok2,av2,act2=pcall(SEED,prog,SITE);good=ok2 and act2==0 and av2==nil
elseif marker=="PROP" then good=(not ok) and type(av)=="string" and av:find("boom-raise",1,true)~=nil
elseif ok and act==expact then
if marker=="VAL" then good=(av==expval)
elseif marker=="NIL" then good=(av==nil)
elseif marker=="FALSE" then good=(av==false)
elseif marker=="FUNC" then good=(type(av)=="function")
elseif marker=="TABLE" then good=(type(av)=="table")
elseif marker=="TBL15" then good=(av==R[15])
elseif marker=="INF" then good=(av==1/0)
end end
if good then pass=pass+1 else print("VFAIL:"..name..":"..tostring(av).."/"..tostring(act)) end
end
print("SEEDOPS PASS "..pass.."/"..#V)
"#;

#[test]
fn seed_control_flow_matches_classic_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        for dseed in [735u64, 7001, 1, u64::MAX] {
        let data = compile(SEED_CONTROL_FIXTURE, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = generate(&data, &program, dseed).unwrap();
        let output = finalize(&raw, target, dseed).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join("seed_ctrl.lua");
        fs::write(&path, output).unwrap();
        let stdout = native::compile_and_run(target, &path);
        assert_eq!(stdout, b"9\n", "{target} seed {dseed}: control-flow output mismatch");
        }
    }
}

#[test]
fn seed_ops_direct_differential_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        for dseed in [0u64, 1, 2, 3, 735, 7001, 7351, u64::MAX] {
        let source = format!(
            "{}{}\n{}\n{}\n{}\n{}\n{}\n",
            seed_shell_prefix(target),
            SEED_DIRECT_POOLS,
            seed_loop_lua(target, dseed),
            p6_lua_head(dseed, 7, 3, 5),
            SEED_DIRECT_DATA,
            P6_LUA_APPLY,
            SEED_DIRECT_RUNNER
        );
        let work = native::Workspace::new();
        let path = work.0.join("seed_ops.lua");
        fs::write(&path, source).unwrap();
        let stdout = native::compile_and_run(target, &path);
        assert_eq!(
            stdout,
            b"SEEDOPS PASS 85/85\n",
            "{target} seed {dseed}: direct vectors mismatch: {}",
            String::from_utf8_lossy(&stdout)
        );
        }
    }
}
