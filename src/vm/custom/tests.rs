use super::*;
use crate::ir::{self, Instruction as I, Terminator as T};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

mod native {
    use crate as obf;
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/mod.rs"));
}

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
    let fetch_probe = "next1=ED(I[2],pc,fid,0);skip1=ED(I[3],pc,fid,1);rid=RD(I[1],pc,next1,skip1,fid);pc=next1;w=";
    assert_eq!(raw.matches(fetch_probe).count(), 1);
    let raw = raw
        .replace(
            fetch_probe,
            "next1=ED(I[2],pc,fid,0);skip1=ED(I[3],pc,fid,1);rid=RD(I[1],pc,next1,skip1,fid);Probe[rid]=true;pc=next1;w=",
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
        .flat_map(|id| recipes[id].ops.iter().copied())
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
                .is_some_and(|recipe| recipe.ops == [Opcode::Move])
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
                include_str!("../../../tests/fixtures/vm_lua51.lua"),
                include_str!("../../../tests/fixtures/scope_lua51.lua"),
            ],
        ),
        (
            Target::Luau,
            [
                include_str!("../../../tests/fixtures/vm_luau.lua"),
                include_str!("../../../tests/fixtures/scope_luau.lua"),
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

fn semantic_prototype_layouts(bytes: &[u8]) -> Vec<(usize, usize, usize, usize)> {
    let u16_at = |offset: usize| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let u32_at = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let prototypes = u32_at(16) as usize;
    let mut proto = 32usize;
    let mut layouts = Vec::with_capacity(prototypes);
    for _ in 0..prototypes {
        let captures = usize::from(u16_at(proto + 8));
        let constants = u32_at(proto + 12) as usize;
        let records = u32_at(proto + 16) as usize;
        let code_len = u32_at(proto + 20) as usize;
        let mut code = proto + 24 + captures * 2;
        for _ in 0..constants {
            let tag = bytes[code];
            code += 1;
            code += match tag {
                0 => 0,
                1 => 1,
                2 | 4 => 8,
                3 | 5 => {
                    let len = u32_at(code) as usize;
                    4 + len
                }
                _ => panic!("unknown constant tag in generated semantic image"),
            };
        }
        layouts.push((proto, code, code_len, records));
        proto = code + code_len;
    }
    assert_eq!(proto, bytes.len());
    layouts
}

fn semantic_first_code_layout(bytes: &[u8]) -> (usize, usize, usize) {
    let (_, code, code_len, records) = semantic_prototype_layouts(bytes)[0];
    (code, code_len, records)
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
        let (code, code_len, records) = semantic_first_code_layout(&image.bytes);
        assert!(code_len > 20 && records > 0);
        let recipes = u16::from_le_bytes(image.bytes[code..code + 2].try_into().unwrap()) as usize;
        assert!(recipes >= 2);
        let mut cursor = code + 2;
        let first_recipe = cursor;
        let mut dictionary = BTreeSet::new();
        for _ in 0..recipes {
            dictionary.insert(u16::from_le_bytes(
                image.bytes[cursor..cursor + 2].try_into().unwrap(),
            ));
            let len = usize::from(image.bytes[cursor + 2]);
            assert!((1..=4).contains(&len));
            cursor += 3 + len;
        }
        let start_label = cursor;
        let first_record = start_label + 2;
        assert!(first_record + 8 <= code + code_len);
        let second_recipe = first_recipe + 3 + usize::from(image.bytes[first_recipe + 2]);
        let recipe_operands: std::collections::BTreeMap<u16, usize> = image
            .recipes
            .iter()
            .map(|recipe| {
                let operands = recipe
                    .ops
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
                image.bytes[record_cursor..record_cursor + 2]
                    .try_into()
                    .unwrap(),
            );
            record_labels.insert(label);
            let next_token = u16::from_le_bytes(
                image.bytes[record_cursor + 2..record_cursor + 4]
                    .try_into()
                    .unwrap(),
            );
            let skip_token = u16::from_le_bytes(
                image.bytes[record_cursor + 4..record_cursor + 6]
                    .try_into()
                    .unwrap(),
            );
            let recipe_token = u16::from_le_bytes(
                image.bytes[record_cursor + 6..record_cursor + 8]
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
                while image.bytes[record_cursor] >= 128 {
                    record_cursor += 1;
                }
                record_cursor += 1;
            }
        }
        assert_eq!(record_cursor, code + code_len);

        let mut corruptions = Vec::new();
        let mut bad = image.clone();
        bad.bytes[first_recipe + 2] = 0; // empty recipe
        corruptions.push(bad);
        let mut bad = image.clone();
        let duplicate = bad.bytes[first_recipe..first_recipe + 2].to_vec();
        bad.bytes[second_recipe..second_recipe + 2].copy_from_slice(&duplicate); // duplicate id
        corruptions.push(bad);
        let mut bad = image.clone();
        bad.bytes[start_label..start_label + 2].fill(0); // null entry label
        corruptions.push(bad);
        let mut bad = image.clone();
        bad.bytes[first_record..first_record + 2].fill(0); // null record label
        corruptions.push(bad);
        let mut bad = image.clone();
        let label = u16::from_le_bytes(
            bad.bytes[first_record..first_record + 2]
                .try_into()
                .unwrap(),
        );
        let unknown_label = (1..=u16::MAX)
            .find(|label| !record_labels.contains(label))
            .unwrap();
        let edge_token =
            super::semantic::encode_edge_token(unknown_label, label, 0, 0, &bad.edge_layers);
        bad.bytes[first_record + 2..first_record + 4].copy_from_slice(&edge_token.to_le_bytes()); // decoded successor is absent
        corruptions.push(bad);
        let mut bad = image.clone();
        let label = u16::from_le_bytes(
            bad.bytes[first_record..first_record + 2]
                .try_into()
                .unwrap(),
        );
        let next_token = u16::from_le_bytes(
            bad.bytes[first_record + 2..first_record + 4]
                .try_into()
                .unwrap(),
        );
        let skip_token = u16::from_le_bytes(
            bad.bytes[first_record + 4..first_record + 6]
                .try_into()
                .unwrap(),
        );
        let next = super::semantic::decode_edge_token(next_token, label, 0, 0, &bad.edge_layers);
        let skip = super::semantic::decode_edge_token(skip_token, label, 0, 1, &bad.edge_layers);
        let unknown = (1..=u16::MAX).find(|id| !dictionary.contains(id)).unwrap();
        let token =
            super::semantic::encode_recipe_token(unknown, label, next, skip, 0, &bad.token_layers);
        bad.bytes[first_record + 6..first_record + 8].copy_from_slice(&token.to_le_bytes());
        corruptions.push(bad);

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
    let layouts = semantic_prototype_layouts(&image.bytes);
    let child = layouts[child_id].0;
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
            // payload table: thirteen numeric-keyed functions (five
            // sections, three probe/share functions, three base86
            // payload-segment decoders, two split watermark-check
            // functions) and exactly one string-keyed entry function
            // (the called method)
            let ExpressionKind::Table(fields) = &setmetatable_arguments[0].kind else {
                panic!("{target}: {output}");
            };
            assert!((20..=22).contains(&fields.len()), "{target}: {output}");
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
            assert!((19..=21).contains(&numeric_keys.len()));
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
fn cipher_key_is_derived_dynamically_and_never_appears_in_plaintext() {
    // The shares and the combined keystream seed are COMPUTED at run
    // time from the script's own structure; none of them may appear as
    // any numeric literal (or any digit run at all) in the output.
    for (target, fixture) in [
        (
            Target::Lua51,
            include_str!("../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../tests/fixtures/vm_luau.lua"),
        ),
    ] {
        for seed in [0u64, 1, 735, 7351, u64::MAX] {
            let data = compile(fixture, target).unwrap();
            let output = emit(&data, target, seed).unwrap();
            let keys = wrapper_keys(seed);
            let params = cipher_params(seed);
            let semantic = wire(&data, target, seed);
            let shares = cipher_shares(&keys, &params);
            let pv = perm_term(seed);
            let state = cipher_state(&shares, pv, semantic.len(), params.mix);
            let secrets = [
                shares[0].to_string(),
                shares[1].to_string(),
                shares[2].to_string(),
                pv.to_string(),
                state.to_string(),
                constant_cipher_state(
                    &keys,
                    constant_cross_term(&semantic),
                    semantic.len(),
                    &params,
                )
                .to_string(),
            ];
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
                    secrets.iter().all(|secret| secret != text),
                    "{target} seed {seed}: numeric literal {text} leaks key material"
                );
            }
            // The derivation is structural: the same seed must still
            // reproduce the exact same script, and decrypt back to the
            // canonical bytes.
            assert_eq!(emit(&data, target, seed).unwrap(), output);
            assert_eq!(
                decrypt_embedded(&output, target, seed).unwrap(),
                wire(&data, target, seed)
            );
        }
    }
}

#[test]
fn constant_pool_cipher_is_an_independent_second_layer() {
    let source = "local s='OBF_UNIQUE_SECRET_7351' local n=3.25 print(s,n)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let output = emit(&data, target, 735).unwrap();
        let payload = extract_embedded(&output, target, 735).unwrap();
        // Framing stays intact, but the image is no longer canonical:
        // its constant pool is ciphertext and the Adler is patched.
        assert_eq!(&payload[..4], b"OBF\x02");
        assert_ne!(payload, data);
        // With only the outer blob cipher removed, neither the string
        // constant nor the number constant is visible anywhere.
        let secret = b"OBF_UNIQUE_SECRET_7351";
        assert!(!payload.windows(secret.len()).any(|w| w == secret));
        let number = 3.25f64.to_le_bytes();
        assert!(!payload.windows(8).any(|w| w == number));
        // Different seeds derive different constant keystreams.
        let other = emit(&data, target, 736).unwrap();
        let other = extract_embedded(&other, target, 736).unwrap();
        assert_ne!(payload, other);
        // Removing both layers restores the canonical bytes exactly.
        assert_eq!(
            decrypt_embedded(&output, target, 735).unwrap(),
            wire(&data, target, 735)
        );
    }
}

#[test]
fn constant_cipher_scan_rejects_malformed_images() {
    let data = compile("local a='const' return a", Target::Lua51).unwrap();
    let ranges = constant_ranges(&data, Target::Lua51).unwrap();
    assert!(!ranges.is_empty());
    assert!(ranges.iter().all(|range| range.end <= data.len()));
    let corrupted_magic = {
        let mut bytes = data.clone();
        bytes[0] = b'X';
        bytes
    };
    let zeroed_prototypes = {
        let mut bytes = data.clone();
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        bytes
    };
    let unknown_tag = {
        // Proto header at 32: force nu=0/nk=1 so the first constant
        // tag lands at 56, then make it an unknown tag.
        let mut bytes = data.clone();
        bytes[40..42].copy_from_slice(&0u16.to_le_bytes());
        bytes[44..48].copy_from_slice(&1u32.to_le_bytes());
        bytes[56] = 9;
        bytes
    };
    let mut trailing = data.clone();
    trailing.push(0);
    for bytes in [
        Vec::new(),
        b"OBF".to_vec(),
        corrupted_magic,
        zeroed_prototypes,
        unknown_tag,
        trailing,
        data[..data.len() - 1].to_vec(),
        data[..32].to_vec(),
    ] {
        assert!(constant_ranges(&bytes, Target::Lua51).is_err());
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
            include_str!("../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../tests/fixtures/vm_luau.lua"),
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
            // Ranks among all seventeen field starts (sixteen numeric
            // plus the entry method).
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
            assert!((20..=22).contains(&starts.len()), "{target} seed {seed}");
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
            // Slotted fields: decrypt, three segments, forms, decode,
            // validate, parse core, the validation loop and SETUP --
            // exactly ten scratch tables, no silent opt-outs.
            let tables = raw.matches("local g={};").count();
            assert_eq!(tables, 10, "{target} seed {seed}: {tables} scratch tables");
            // Finish-style fields clear the table before returning.
            let clears = raw.matches("g=nil;").count();
            assert_eq!(clears, 6, "{target} seed {seed}: {clears} clears");
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
    // Control-flow flattening: the base86 segments, the outer decrypt,
    // the parse core and the interpreter loop all run as seeded state
    // machines (per-seed state numbers, shuffled branch order, four
    // condition spellings), and the frame setup / per-prototype stages
    // are split into their own functions. No stage keeps a linear
    // loop shape.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut state_sets = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            // Nine machines: three segments, outer decrypt, parse core,
            // interpreter fetch/dispatch, five-stage recipe-token decode, and
            // three-stage edge-token decode. Both token machines are shared by
            // validation and runtime fetch.
            assert_eq!(raw.matches("while true do").count(), 9);
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
            // Graph fetch follows an explicit random-label successor, but
            // first derives the recipe id from a per-record context token.
            assert_eq!(raw.matches("I=code[pc];if I==nil then E()end;").count(), 1);
            assert_eq!(
                raw.matches("next1=ED(I[2],pc,fid,0);skip1=ED(I[3],pc,fid,1);rid=RD(I[1],pc,next1,skip1,fid);pc=next1;")
                    .count(),
                1
            );
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
    // Random decoder sections: the monolithic decoder is flattened
    // into a decrypt field, a seeded 2..4 cluster split of its six
    // helper groups and a parse core -- sibling payload fields at
    // random layout positions, wired through the entry in the fixed
    // dependency order. The stream position stays an upvalue inside
    // the reader cluster; the core checks it through the exported
    // `pos` accessor.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut cluster_counts = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            // Decrypt field and parse core keep their audited roles;
            // between them 2..=4 randomly grouped helper fields.
            assert!(raw.contains(&format!(
                "[{}]=function(B,s1,s2,s3,pv,E,SB,SS,SF,NCH,TC,MF,IF)",
                wrapper_keys(seed)[1]
            )));
            assert!(raw.contains(&format!(
                "[{}]=function(B,E,SB,SF,NCH,TC,MF,IF,b8,b16,b32,take,pos,db8,db32,dstr,dnum)",
                wrapper_keys(seed)[20]
            )));
            assert!(raw.contains("local pos=function()return bp end;"));
            assert!(!raw.contains("bp~=#B+1"));
            let numeric = raw.matches("]=function(").count() - 1;
            let clusters = numeric - 17;
            assert!(
                (2..=4).contains(&clusters),
                "{target} seed {seed}: {clusters} decoder clusters"
            );
            cluster_counts.insert(clusters);
            // Wiring order is the dependency chain: decrypt first, core
            // last, every cluster field called exactly once.
            let wiring_at = raw.find("local B=VMS[").expect("decoder wiring");
            let wiring_end = wiring_at + raw[wiring_at..].find("local P,np,entry=VMS[").unwrap();
            let wiring = &raw[wiring_at..wiring_end];
            assert_eq!(wiring.matches("=VMS[").count(), clusters as usize + 1);
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(
            cluster_counts.len() >= 2,
            "{target}: decoder split pinned ({cluster_counts:?})"
        );
        // The randomly split decoder still runs the program verbatim.
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
    // Two-level dispatch split: operand validation is partitioned by `o %
    // groups`, while semantic superhandlers are partitioned by the 16-bit
    // `rid % groups`. Each sub-chain keeps its own fail-closed else; group
    // counts and arm layouts vary per seed.
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
                .find("local I,rid,next1,skip1,o,a,b,c,k,j;local w=")
                .expect("interpreter phase machine");
            let f5_end = f5_at + raw[f5_at..].find("return H").unwrap();
            let interp = &raw[f5_at..f5_end];
            let mut chain_groups = Vec::new();
            for (chain, selector) in [(bounds, "o%"), (interp, "rid%")] {
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
            topologies.insert((chain_groups[0], chain_groups[1]));
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
            include_str!("../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../tests/fixtures/vm_luau.lua"),
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
            assert!(image.recipes.iter().any(|recipe| recipe.ops.len() > 1));
            saw_four_word_recipe |= image.recipes.iter().any(|recipe| recipe.ops.len() == 4);
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
    for (target, fixture) in [
        (
            Target::Lua51,
            include_str!("../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../tests/fixtures/vm_luau.lua"),
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
            assert!((19..=21).contains(&order.len()), "{target} seed {seed}");
            layouts.insert((format!("{target:?}"), order));
            for multiplier in [16_807u64, 48_271, 65_539] {
                if output.contains(&format!("={multiplier}*"))
                    || output.contains(&format!("*{multiplier}*"))
                {
                    multipliers.insert(multiplier);
                }
            }
            for mix in [31u64, 33, 37, 41] {
                if output.contains(&format!("{mix}*#")) {
                    mixes.insert(mix);
                }
            }
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
            include_str!("../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../tests/fixtures/vm_luau.lua"),
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
    // M7 size budget: the structural variants must not inflate a
    // generated script beyond the documented caps (headroom over the
    // current goldens; raise the caps deliberately, never silently --
    // Semantic virtualization deliberately raised the old M7 ceilings for
    // program-specific superhandlers. ISA5 adds five-stage recipe and
    // three-stage edge machines plus reachable neutral CFG records; keep
    // deliberate bounded headroom over both fixed-seed goldens rather than
    // allowing untracked growth.
    for (target, fixture, budget) in [
        (
            Target::Lua51,
            include_str!("../../../tests/fixtures/vm_lua51.lua"),
            72_000usize,
        ),
        (
            Target::Luau,
            include_str!("../../../tests/fixtures/vm_luau.lua"),
            80_000usize,
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
    }
}

#[test]
fn transport_watermark_is_present_checked_and_never_spelled_out() {
    for (target, fixture) in [
        (
            Target::Lua51,
            include_str!("../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../tests/fixtures/vm_luau.lua"),
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
            include_str!("../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../tests/fixtures/vm_luau.lua"),
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
fn semantic_recipe_decoys_poison_dictionary_only_translation() {
    // Unreferenced recipe descriptors are fully well-formed and pass the
    // target's dictionary validator, but their emitted superhandler bodies
    // deliberately execute a different primitive sequence. Consequently a
    // static translator cannot classify every recipe arm as ground truth;
    // it must first recover reachability from the validated label graph.
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
                assert_ne!(recipe.ops, recipe.execute_ops);
                assert!(!image.referenced_recipe_ids.contains(&recipe.id));
                assert!(recipe.ops.iter().all(|op| !matches!(
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

            // Generator metadata and the encrypted dictionary come from the
            // same deterministic semantic image; all recipe ids therefore
            // have exactly one emitted arm even though only graph-reachable
            // ids can execute.
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            assert_eq!(raw.matches(" then a,b,c=I[").count(), image.recipes.len());
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
fn keystream_families_and_cross_stage_terms_couple_the_pipeline() {
    // A2: each cipher layer independently draws one of three keystream
    // primitive families (Lehmer / dual-Lehmer sum / mod-2^32 LCG on the
    // top byte), so a static replay must identify the family before any
    // keystream byte exists. B1: the payload seed mixes a term derived
    // from the REBUILT renumbering table (forms field output) and the
    // constant-layer seed mixes two framing bytes of the outer-DECRYPTED
    // image -- stage outputs, not static constants.
    let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut outer_families = BTreeSet::new();
        let mut constant_families = BTreeSet::new();
        for seed in 0..=11u64 {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(generate(&data, &program, seed).unwrap(), raw);
            let params = cipher_params(seed);
            outer_families.insert(params.outer_stream.family);
            constant_families.insert(params.constant_stream.family);
            // The decrypt field runs its family step in the XOR loop.
            let dec_at = raw
                .find("]=function(B,s1,s2,s3,pv,E,SB,SS,SF,NCH,TC,MF,IF)")
                .expect("decrypt field signature");
            let dec_end = dec_at
                + raw[dec_at..]
                    .find("\nend")
                    .unwrap_or_else(|| panic!("no end after decrypt field, {target} seed {seed}"))
                + 4;
            let decrypt = &raw[dec_at..dec_end];
            match params.outer_stream.family {
                0 => assert!(
                    decrypt.contains(&format!("={}*", params.outer_stream.multiplier))
                        && decrypt.contains("%2147483647")
                ),
                1 => assert!(
                    decrypt.contains(&format!("={}*", params.outer_stream.multiplier))
                        && decrypt.contains(&format!("={}*", params.outer_stream.second))
                ),
                _ => assert!(decrypt.contains("%4294967296")),
            }
            // The constant cluster runs its own family inside KA.
            let ka_at = raw.find("local KA=function()").expect("KA definition");
            let ka_end = ka_at
                + raw[ka_at..]
                    .find(" end;")
                    .unwrap_or_else(|| panic!("no end after KA, {target} seed {seed}"));
            let ka = &raw[ka_at..ka_end];
            match params.constant_stream.family {
                0 => assert!(ka.contains(&format!("={}*", params.constant_stream.multiplier))),
                1 => assert!(
                    ka.contains(&format!("={}*", params.constant_stream.multiplier))
                        && ka.contains(&format!("={}*", params.constant_stream.second))
                ),
                _ => assert!(ka.contains("%4294967296")),
            }
            // B1 payload term: the entry derives pv from the rebuilt
            // renumbering table at the per-seed slots before decrypting,
            // and the decrypt seed adds it to the three probe shares.
            let [i0, i1, i2] = perm_indices(seed);
            let pv_line = format!("local pv=1+(PT[{i0}]*31+PT[{i1}]*7+PT[{i2}])%2147483646;");
            let pv_at = raw.find(&pv_line).expect("entry permutation term");
            let dec_call = raw
                .find("c1,c2,c3,pv,E,SB")
                .expect("decrypt call passes pv");
            assert!(
                pv_at < dec_call,
                "pv must be derived before the decrypt call"
            );
            assert!(decrypt.contains("s1+s2+s3+pv+"));
            // B1 constant term: two framing bytes of the decrypted image.
            let ka2_at = raw
                .find("local ka2=SB(B,33)*31+SB(B,#B);")
                .expect("constant cross term");
            assert!(dec_call < ka2_at, "ka2 must be read after outer decryption");
            assert!(raw.contains("(ku+ka2+"), "constant seed mixes the term");
            // Family parameters rotate across seeds within each family.
            let output = emit(&data, target, seed).unwrap();
            assert_eq!(blob(&output, target, seed), wire(&data, target, seed));
        }
        assert!(
            outer_families.len() >= 2,
            "{target}: outer keystream family pinned ({outer_families:?})"
        );
        assert!(
            constant_families.len() >= 2,
            "{target}: constant keystream family pinned ({constant_families:?})"
        );
        // The coupled pipeline still runs the program verbatim.
        let workspace = native::Workspace::new();
        let path = workspace.0.join("family_coupled.lua");
        fs::write(&path, source).unwrap();
        let expected = native::compile_and_run(target, &path);
        fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
        assert_eq!(expected, native::compile_and_run(target, &path));
    }
}
