use obf::scope::{self, Analysis};
use obf::{minify_with_options, MinifyOptions, Target};
use std::collections::BTreeSet;

fn randomize(source: &str, target: Target, seed: u64) -> Result<String, obf::Diagnostic> {
    minify_with_options(source, target, MinifyOptions::seeded(seed))
}

fn assert_renamed(before: &Analysis, after: &Analysis) {
    assert_eq!(before.bindings.len(), after.bindings.len());
    assert_eq!(before.globals, after.globals);
    let mut allocated = BTreeSet::new();
    for (old, new) in before.bindings.iter().zip(&after.bindings) {
        assert_eq!(old.kind, new.kind);
        assert_eq!(old.scope, new.scope);
        assert_eq!(old.captured, new.captured);
        if old.preserve.is_some() {
            assert_eq!(old.name, new.name);
        } else {
            assert_ne!(old.name, new.name, "already-short locals must change too");
            assert!((1..=2).contains(&new.name.len()));
            assert!(new.name.bytes().all(|byte| byte.is_ascii_lowercase()));
            assert!(allocated.insert(&new.name));
            assert!(!before.globals.contains(&new.name));
        }
    }
    assert_eq!(before.references.len(), after.references.len());
    for (old, new) in before.references.iter().zip(&after.references) {
        assert_eq!(old.binding, new.binding);
        assert_eq!(old.scope, new.scope);
        if old.binding.is_none() {
            assert_eq!(old.name, new.name);
        }
    }
    for (old, new) in before.scopes.iter().zip(&after.scopes) {
        assert_eq!(old.upvalues, new.upvalues);
    }
}

#[test]
fn all_safe_locals_including_one_and_two_letter_names_are_randomized() {
    let source = "local a,b,c,ab,cd,ef=1,2,3,4,5,6 local function f(q) local z=q+a return function(t) return z+b+c+ab+cd+ef+t end end return f(7)(8)";
    for target in [Target::Lua51, Target::Luau] {
        let before = scope::analyze(source, target).unwrap();
        let mut outputs = BTreeSet::new();
        for seed in [0, 1, 2, 3, 42, 735, 7001, u64::MAX] {
            let output = randomize(source, target, seed).unwrap();
            assert_eq!(output, randomize(source, target, seed).unwrap());
            assert_renamed(&before, &scope::analyze(&output, target).unwrap());
            assert!(
                outputs.insert(output),
                "representative different seeds reused a layout"
            );
        }
    }
}

#[test]
fn letters_are_reused_from_replaced_locals_but_never_from_preserved_names() {
    let source = "a=10 local aa=20 local function inner(aa) local bb=aa return function() return a+bb end end return inner(5)(),aa";
    for target in [Target::Lua51, Target::Luau] {
        let before = scope::analyze(source, target).unwrap();
        for seed in 0..32 {
            let output = randomize(source, target, seed).unwrap();
            assert_renamed(&before, &scope::analyze(&output, target).unwrap());
        }
    }
    let source = "export const a=1 export function ab(q) return a+q end local ordinary=2 print(ordinary,ab(3))";
    let before = scope::analyze(source, Target::Luau).unwrap();
    for seed in 0..16 {
        let output = randomize(source, Target::Luau, seed).unwrap();
        assert_renamed(&before, &scope::analyze(&output, Target::Luau).unwrap());
        assert!(output.contains("export const a=1"));
        assert!(output.contains("export function ab("));
    }
}

#[test]
fn fixed_seeds_reproduce_but_default_api_generations_get_fresh_seeds() {
    let mut source = String::new();
    for index in 0..40 {
        source.push_str(&format!("local originalValue{index}={index} "));
    }
    source.push_str("return originalValue39");
    for target in [Target::Lua51, Target::Luau] {
        let outputs: BTreeSet<_> = (0..12)
            .map(|_| obf::minify(&source, target).unwrap())
            .collect();
        assert_eq!(outputs.len(), 12);
        let options = MinifyOptions::default();
        assert_eq!(
            minify_with_options(&source, target, options).unwrap(),
            randomize(&source, target, options.seed).unwrap()
        );
    }
    let seeds: BTreeSet<_> = (0..64).map(|_| obf::vm::Options::default().seed).collect();
    assert_eq!(seeds.len(), 64);
}

fn all_short_names() -> Vec<String> {
    let mut names = Vec::new();
    for first in b'a'..=b'z' {
        names.push(char::from(first).to_string());
        for second in b'a'..=b'z' {
            names.push(format!("{}{}", char::from(first), char::from(second)));
        }
    }
    names.retain(|name| !matches!(name.as_str(), "do" | "if" | "in" | "or"));
    names
}

// Reserve the entire finite alphabet through GLOBAL references. The allocator
// must respect these even in scopes where the references precede declarations.
fn reserve_except(allowed: &[&str]) -> String {
    all_short_names()
        .into_iter()
        .filter(|name| !allowed.contains(&name.as_str()))
        .map(|name| format!("{name}=0 "))
        .collect()
}

#[test]
fn near_exhaustion_derangement_repairs_the_last_self_assignment() {
    let source = format!(
        "{}local longName=1 local b=2 return longName,b",
        reserve_except(&["a", "b"])
    );
    for target in [Target::Lua51, Target::Luau] {
        for seed in 0..32 {
            let output = randomize(&source, target, seed).unwrap();
            let after = scope::analyze(&output, target).unwrap();
            // The only complete assignment that changes both old names.
            assert_eq!(after.bindings[0].name, "b");
            assert_eq!(after.bindings[1].name, "a");
        }
    }
}

#[test]
fn exhausted_name_space_is_a_diagnostic_not_three_letters_or_unsafe_reuse() {
    let mut too_many = String::new();
    for index in 0..703 {
        too_many.push_str(&format!("do local originalValue{index}=1 end "));
    }
    for target in [Target::Lua51, Target::Luau] {
        let error = randomize(&too_many, target, 0).unwrap_err();
        assert!(error
            .message
            .contains("1-2 letter variable name pool exhausted"));
        assert!(minify_with_options(&too_many, target, MinifyOptions::lexical()).is_ok());
        let reserved = format!("{}local longName=1 return longName", reserve_except(&[]));
        assert!(randomize(&reserved, target, 0)
            .unwrap_err()
            .message
            .contains("pool exhausted"));
        let duplicate = format!(
            "{}do local a=1 end do local a=2 end",
            reserve_except(&["a", "b"])
        );
        assert!(randomize(&duplicate, target, 0)
            .unwrap_err()
            .message
            .contains("cannot rename every binding"));
        let impossible = format!("{}local a=1 return a", reserve_except(&["a"]));
        assert!(randomize(&impossible, target, 0)
            .unwrap_err()
            .message
            .contains("cannot rename every binding"));
    }
}

#[test]
fn user_source_cannot_opt_into_the_generated_vm_environment_exception() {
    let source =
        "local G=(getfenv and getfenv(0))or _G local originalLocal=1 return G,originalLocal";
    for target in [Target::Lua51, Target::Luau] {
        let expected = minify_with_options(source, target, MinifyOptions::lexical()).unwrap();
        for seed in [0, 42, u64::MAX] {
            assert_eq!(randomize(source, target, seed).unwrap(), expected);
        }
    }
}
