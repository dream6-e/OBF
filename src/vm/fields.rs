//! Short names for the custom VM's closed, non-escaping prototype schema.
//!
//! Only crate-owned templates opt in with explicit identifier markers. This
//! is NOT a general table-property minifier: user keys, host APIs, metamethods,
//! method adapters and all strings (especially bytecode) retain their bytes.
use crate::lexer::{self, TokenKind};
use crate::random::Prng;
use crate::{Diagnostic, Target};
use std::collections::BTreeMap;

pub(super) const PREFIX: &str = "__obf_proto_";
pub(super) const PROTOTYPE_FIELDS: &[&str] = &[
    "k", "tags", "u", "parent", "m", "p", "flags", "nu", "nk", "nc", "shared", "self", "code",
    "cached",
];

fn error(message: &str) -> Diagnostic {
    Diagnostic::new(format!("generated VM private fields: {message}"))
}

fn names<'a>(
    schema: &[&'a str],
    target: Target,
    seed: u64,
) -> Result<BTreeMap<&'a str, String>, Diagnostic> {
    // A separate deterministic stream: field choices do not consume the
    // local-name stream or change the bytecode, ISA, or section layout.
    let mut random = Prng::new(seed ^ 0x6669_656c_6473_7632);
    let mut pool: Vec<String> = (b'a'..=b'z').map(|c| char::from(c).to_string()).collect();
    let mut pairs = Vec::new();
    for a in b'a'..=b'z' {
        for b in b'a'..=b'z' {
            let name = String::from_utf8(vec![a, b]).unwrap();
            if !lexer::is_keyword(&name, target) {
                pairs.push(name);
            }
        }
    }
    random.shuffle(&mut pool);
    random.shuffle(&mut pairs);
    pool.extend(pairs);
    if schema.len() > pool.len() {
        return Err(error("one/two-letter field pool exhausted"));
    }
    let mut result = BTreeMap::new();
    for &field in schema {
        if result.contains_key(field) {
            return Err(error("duplicate schema field"));
        }
        let index = pool
            .iter()
            .position(|name| name != field)
            .ok_or_else(|| error("cannot allocate a distinct short field name"))?;
        result.insert(field, pool.remove(index));
    }
    Ok(result)
}

/// Run once after decoder, validation, runtime and all handlers/adapters have
/// been assembled, BEFORE final local renaming and separator emission.
/// A bijection is applied to explicitly marked dot fields/constructor keys.
/// A second lex proves every other token and literal is byte-for-byte intact.
pub(super) fn shorten(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    let mapping = names(PROTOTYPE_FIELDS, target, seed)?;
    let tokens = lexer::lex(source, target)?;
    let mut replacements = BTreeMap::new();
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    for (index, token) in tokens.iter().enumerate() {
        let text = token.text(source);
        // Current VM templates never interpolate Lua source. Reject future
        // interpolation rather than silently miss marked fragment accesses.
        if token.kind == TokenKind::String && text.starts_with('`') {
            return Err(error("interpolation in a private VM template"));
        }
        if token.kind != TokenKind::Identifier {
            continue;
        }
        let Some(field) = text.strip_prefix(PREFIX) else {
            continue;
        };
        let previous = index.checked_sub(1).map(|i| tokens[i].text(source));
        // A user-supplied static NAMECALL method may have this exact spelling.
        // It is an external API, not a private property marker.
        if previous == Some(":") {
            continue;
        }
        let record = matches!(previous, Some("{" | "," | ";"))
            && tokens.get(index + 1).is_some_and(|t| t.text(source) == "=");
        if previous != Some(".") && !record {
            return Err(error("marker outside a dot field or constructor key"));
        }
        let name = mapping
            .get(field)
            .ok_or_else(|| error("unknown schema field marker"))?;
        output.push_str(&source[cursor..token.span.start]);
        output.push_str(name);
        cursor = token.span.end;
        replacements.insert(index, name.as_str());
    }
    output.push_str(&source[cursor..]);
    let after = lexer::lex(&output, target)?;
    if after.len() != tokens.len() {
        return Err(error("token count changed"));
    }
    for (index, (before, after)) in tokens.iter().zip(&after).enumerate() {
        let expected = replacements
            .get(&index)
            .copied()
            .unwrap_or_else(|| before.text(source));
        if before.kind != after.kind || expected != after.text(&output) {
            return Err(error("unmarked token or literal changed"));
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn field_pool_is_bijective_seeded_keyword_free_and_bounded() {
        for target in [Target::Lua51, Target::Luau] {
            let mut layouts = BTreeSet::new();
            for seed in [0, 1, 735, u64::MAX] {
                let mapping = names(PROTOTYPE_FIELDS, target, seed).unwrap();
                assert_eq!(mapping, names(PROTOTYPE_FIELDS, target, seed).unwrap());
                assert_eq!(
                    mapping.values().collect::<BTreeSet<_>>().len(),
                    mapping.len()
                );
                for (before, after) in &mapping {
                    assert_ne!(*before, after);
                    assert_eq!(after.len(), 1); // all 14 current fields fit
                    assert!(after.bytes().all(|b| b.is_ascii_lowercase()));
                    assert!(!lexer::is_keyword(after, target));
                }
                assert!(layouts.insert(mapping));
            }
            let fields = (0..100).map(|i| format!("field{i}")).collect::<Vec<_>>();
            let schema = fields.iter().map(String::as_str).collect::<Vec<_>>();
            let mapping = names(&schema, target, 735).unwrap();
            assert_eq!(mapping.values().collect::<BTreeSet<_>>().len(), 100);
            assert!(mapping
                .values()
                .all(|n| (1..=2).contains(&n.len()) && !lexer::is_keyword(n, target)));
            assert!(mapping.values().any(|n| n.len() == 2));
            assert!(names(&["same", "same"], target, 0).is_err());
            assert!(names(&vec!["too_many"; 703], target, 0).is_err());
        }
    }

    #[test]
    fn aliases_constructor_keys_and_field_reads_use_the_same_mapping_only() {
        let source = r#"
            local F={__obf_proto_k={},__obf_proto_tags={},__obf_proto_u={}}
            F.__obf_proto_code='code tags flags __obf_proto_code'
            local alias=F alias.__obf_proto_tags[0]=F.__obf_proto_code
            local user={code='code',tags='tags',__mode='k'}
            assert(alias.__obf_proto_tags[0]==F.__obf_proto_code)
            print(user.code,user.tags,table.concat({string.sub('code',1,4)},','))
            local bytes='\000\255\099\111\100\101' local long=[=[__obf_proto_tags]=]
            return user:__obf_proto_code(),user:tags()
        "#;
        for target in [Target::Lua51, Target::Luau] {
            let mapping = names(PROTOTYPE_FIELDS, target, 735).unwrap();
            let short = shorten(source, target, 735).unwrap();
            crate::parse(&short, target).unwrap();
            assert!(short.contains(&format!(
                "F={{{}={{}},{}={{}},{}={{}}}}",
                mapping["k"], mapping["tags"], mapping["u"]
            )));
            assert!(short.contains(&format!(
                "alias.{}[0]=F.{}",
                mapping["tags"], mapping["code"]
            )));
            for protected in [
                "user.code",
                "user.tags",
                "table.concat",
                "string.sub",
                "__mode='k'",
                "'code tags flags __obf_proto_code'",
                "'\\000\\255\\099\\111\\100\\101'",
                "[=[__obf_proto_tags]=]",
                ":__obf_proto_code()",
                ":tags()",
            ] {
                assert!(short.contains(protected), "{protected}");
            }
            assert_eq!(shorten(&short, target, 735).unwrap(), short);
        }
    }

    #[test]
    fn private_field_markers_fail_closed_outside_the_template_contract() {
        for target in [Target::Lua51, Target::Luau] {
            for source in [
                "local __obf_proto_code=1",
                "return __obf_proto_code",
                "return F.__obf_proto_typo",
                "local F={__obf_proto_typo=1}",
                "return F['key']+__obf_proto_tags",
            ] {
                assert!(shorten(source, target, 0).is_err(), "{source}");
            }
            // Even unknown prefixed NAMECALL spellings remain host APIs.
            assert_eq!(
                shorten("return object:__obf_proto_typo()", target, 0).unwrap(),
                "return object:__obf_proto_typo()"
            );
        }
        assert!(shorten("return `{F.__obf_proto_code}`", Target::Luau, 0).is_err());
    }

    #[test]
    fn complete_vm_changes_only_marked_fields_even_after_final_local_renaming() {
        for (target, source) in [
            (
                Target::Lua51,
                include_str!("../../tests/fixtures/vm_lua51.lua"),
            ),
            (
                Target::Luau,
                include_str!("../../tests/fixtures/vm_luau.lua"),
            ),
        ] {
            let data = crate::vm::custom::compile(source, target).unwrap();
            let program = crate::bytecode::custom::decode(&data, target).unwrap();
            for seed in [0, 1, 735, u64::MAX] {
                let raw = crate::vm::custom::generate(&data, &program, seed).unwrap();
                let mapping = names(PROTOTYPE_FIELDS, target, seed).unwrap();
                let original = crate::minify::finalize_vm(&raw, target, seed).unwrap();
                let output = crate::vm::custom::emit(&data, target, seed).unwrap();
                let before = lexer::lex(&original, target).unwrap();
                let after = lexer::lex(&output, target).unwrap();
                assert_eq!(before.len(), after.len());
                let mut seen = BTreeSet::new();
                for (index, (left, right)) in before.iter().zip(&after).enumerate() {
                    assert_eq!(left.kind, right.kind);
                    let text = left.text(&original);
                    let expected = if left.kind == TokenKind::Identifier
                        && index > 0
                        && before[index - 1].text(&original) != ":"
                    {
                        if let Some(field) = text.strip_prefix(PREFIX) {
                            seen.insert(field);
                            mapping[field].as_str()
                        } else {
                            text
                        }
                    } else {
                        text
                    };
                    // Includes every local/global spelling, punctuation and
                    // literal: only the 14 private schema names can differ.
                    assert_eq!(
                        expected,
                        right.text(&output),
                        "{target} seed={seed} token={index}"
                    );
                }
                assert_eq!(seen, PROTOTYPE_FIELDS.iter().copied().collect());
                assert!(output.len() < original.len());
                let long_fields: BTreeSet<_> = after
                    .windows(2)
                    .filter(|pair| {
                        pair[0].text(&output) == "."
                            && pair[1].kind == TokenKind::Identifier
                            && pair[1].text(&output).len() > 2
                    })
                    .map(|pair| pair[1].text(&output))
                    .collect();
                assert!(long_fields.is_subset(&BTreeSet::from([
                    "unpack",
                    "byte",
                    "sub",
                    "format",
                    "floor",
                    "fromstring",
                    "freeze",
                    "char",
                    "concat",
                    "info",
                    "getinfo",
                    "what"
                ])));
            }
        }
    }
}
