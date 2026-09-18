mod binary;
pub mod compiler;
pub mod custom;
mod fields;
mod lua51;
mod luau;
mod opcode;

use crate::{Diagnostic, Target};

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub seed: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            seed: crate::random::fresh_seed(),
        }
    }
}

/// Default pipeline: owned AST -> typed register IR -> fixed 4-byte OBF v2
/// instructions -> generated VM. Never invokes or falls back to native tools.
pub fn virtualize(source: &[u8], target: Target, options: Options) -> Result<String, Diagnostic> {
    let source = std::str::from_utf8(source).map_err(|e| {
        Diagnostic::byte(format!("source is not valid UTF-8: {e}"), e.valid_up_to())
    })?;
    custom::virtualize(source, target, options.seed)
        .map_err(|error| error.context(format!("AST {target} VM")))
}

/// Explicit compatibility backend: pinned native compiler -> legacy OBF v1.
/// Kept separately so the new AST path never conceals a native fallback.
pub fn virtualize_native(
    source: &[u8],
    target: Target,
    options: Options,
) -> Result<String, Diagnostic> {
    let bytecode = compiler::compile(source, target)?;
    let source = match target {
        Target::Lua51 => lua51::generate(&bytecode, options.seed),
        Target::Luau => luau::generate(&bytecode, options.seed),
    }?;
    // No generated code may be appended after this final whole-output pass.
    crate::minify::finalize_vm(&source, target, options.seed)
        .map_err(|error| error.context(format!("generated {target} VM failed final validation")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Chunk, ExpressionKind, StatementKind, TableField};

    // Root tables may only be empty registries or function-valued maps:
    // Luau numeric-keyed NAMECALL wrappers, plus the custom backend's
    // numeric/string-keyed section and entry functions of the setmetatable
    // payload. Prototype/instruction data must come from the binary decoder,
    // not inline table literals. Never key this test to the old P/W variable
    // spellings, nor reject legitimate wrapper tables.
    pub(super) fn no_inline_metadata(chunk: &Chunk) -> bool {
        chunk.block.statements.iter().all(|statement| {
            let (StatementKind::Local { values, .. } | StatementKind::Assignment { values, .. }) =
                &statement.kind
            else {
                return true;
            };
            values.iter().all(|value| {
                let ExpressionKind::Table(fields) = &value.kind else {
                    return true;
                };
                fields.iter().all(|field| {
                    matches!(field,
                        TableField::Computed { key, value, .. }
                        if matches!(key.kind, ExpressionKind::Number(_) | ExpressionKind::String(_))
                            && matches!(value.kind, ExpressionKind::Function(_))
                    )
                })
            })
        })
    }

    #[test]
    fn metadata_table_check_is_name_independent_and_allows_namecall_wrappers() {
        for target in [Target::Lua51, Target::Luau] {
            for source in [
                "local ab={};ab[0]={};ab[1]={[40]=function(q,...)return q:add(...)end}",
                "local xy='not code: P[0]={1,2,3}'",
            ] {
                assert!(no_inline_metadata(&crate::parse(source, target).unwrap()));
            }
            for source in [
                "local ab={};ab[0]={p=1,c={{2,3,4}}}",
                "local xy={{1,2,3}}",
                "xy[0]={[42]={2,3,4}}",
            ] {
                assert!(!no_inline_metadata(&crate::parse(source, target).unwrap()));
            }
        }
    }

    fn embedded_blob(source: &str, target: Target) -> Vec<u8> {
        let chunk = crate::parse(source, target).unwrap();
        assert!(
            no_inline_metadata(&chunk),
            "VM contains inline prototype/instruction tables"
        );
        let blobs: Vec<_> = chunk
            .block
            .statements
            .iter()
            .filter_map(|statement| {
                let StatementKind::Local { values, .. } = &statement.kind else {
                    return None;
                };
                let [value] = values.as_slice() else {
                    return None;
                };
                let ExpressionKind::String(raw) = &value.kind else {
                    return None;
                };
                let bytes = crate::minify::literal_bytes(raw, target).unwrap();
                bytes.starts_with(b"OBF").then_some(bytes)
            })
            .collect();
        assert_eq!(
            blobs.len(),
            1,
            "VM must contain exactly one serialized private blob"
        );
        let blob = blobs.into_iter().next().unwrap();
        assert!(blob.len() >= 13);
        assert_eq!(blob[3], 1);
        assert_eq!(blob[4], if target.is_luau() { 0x75 } else { 0x51 });
        assert_eq!(
            u32::from_le_bytes(blob[5..9].try_into().unwrap()) as usize,
            blob.len() - 13
        );
        let (mut first, mut second) = (1u32, 0u32);
        for byte in &blob[13..] {
            first = (first + u32::from(*byte)) % 65_521;
            second = (second + first) % 65_521;
        }
        assert_eq!(
            u32::from_le_bytes(blob[9..13].try_into().unwrap()),
            first | (second << 16)
        );
        blob
    }

    #[test]
    fn final_pass_renames_every_explicit_vm_local_but_not_payload_bytes() {
        for (target, fixture) in [
            (
                Target::Lua51,
                include_bytes!("../../tests/fixtures/vm_lua51.lua").as_slice(),
            ),
            (
                Target::Luau,
                include_bytes!("../../tests/fixtures/vm_luau.lua").as_slice(),
            ),
        ] {
            let bytecode = compiler::compile(fixture, target).unwrap();
            let raw = match target {
                Target::Lua51 => lua51::generate(&bytecode, 735),
                Target::Luau => luau::generate(&bytecode, 735),
            }
            .unwrap();
            let before = crate::scope::analyze(&raw, target).unwrap();
            let blob = embedded_blob(&raw, target);
            let mut layouts = std::collections::BTreeSet::new();
            for seed in [0, 1, 42, 735, u64::MAX] {
                let output = crate::minify::finalize_vm(&raw, target, seed).unwrap();
                assert_eq!(
                    output,
                    crate::minify::finalize_vm(&raw, target, seed).unwrap()
                );
                assert_eq!(embedded_blob(&output, target), blob);
                let after = crate::scope::analyze(&output, target).unwrap();
                assert_eq!(before.globals, after.globals);
                assert_eq!(before.bindings.len(), after.bindings.len());
                let mut names = std::collections::BTreeSet::new();
                for (old, new) in before.bindings.iter().zip(&after.bindings) {
                    if old.declaration.is_some() {
                        assert_ne!(old.name, new.name);
                        assert!((1..=2).contains(&new.name.len()));
                        assert!(new.name.bytes().all(|byte| byte.is_ascii_lowercase()));
                        assert!(
                            names.insert((after.scopes[new.scope].name_scope, new.name.clone()))
                        );
                    } else {
                        assert_eq!(old.name, new.name);
                    }
                }
                assert!(
                    names.len() > 100,
                    "test must cover decoder AND late dispatcher/handler locals"
                );
                let spellings: std::collections::BTreeSet<_> =
                    names.iter().map(|(_, name)| name).collect();
                assert!(
                    spellings.len() < names.len(),
                    "VM scopes must actually reuse names"
                );
                // A vector, not a set: equal alphabets may be assigned to
                // different bindings in different seeded layouts.
                assert!(layouts.insert(
                    after
                        .bindings
                        .iter()
                        .map(|binding| binding.name.clone())
                        .collect::<Vec<_>>()
                ));
                assert!(!output.contains(['\r', '\n']));
            }
        }
    }
}
