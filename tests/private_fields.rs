//! Only the generated VM's closed schema is renamed; public keys stay public.
mod support;
use obf::{bytecode::custom as bc, lexer, vm, Target};
use std::fs;
use std::process::Command;
use support::{compile_and_run, success, Workspace};

const LONG_FIELDS: &[&str] = &[
    "code", "tags", "parent", "flags", "shared", "self", "cached",
];

fn embedded(source: &str, target: Target, seed: u64) -> Vec<u8> {
    // The payload blob is encrypted at generation time; decrypt it with the
    // seed that produced this script and compare against the canonical bytes.
    vm::custom::decrypt_embedded(source, target, seed).unwrap()
}

fn assert_private_names_hidden(output: &str, target: Target) {
    let tokens = lexer::lex(output, target).unwrap();
    for (index, token) in tokens.iter().enumerate() {
        if token.kind != lexer::TokenKind::Identifier {
            continue;
        }
        let prev = index.checked_sub(1).map(|i| tokens[i].text(output));
        if prev == Some(".") {
            assert!(
                !LONG_FIELDS.contains(&token.text(output)),
                "unshortened field: {}",
                token.text(output)
            );
        }
        // Names after ':' are user-provided NAMECALL adapters, not metadata.
        if prev != Some(":") {
            assert!(!token.text(output).starts_with("__obf_proto_"));
        }
    }
    assert!(!output.contains(['\r', '\n']));
}

#[test]
fn prototype_field_shortening_preserves_bytecode_public_keys_and_runtime_output() {
    let source = r#"
        local user={code='code',tags='tags',parent=3,flags=4,shared=5,self=6,cached=7,__obf_proto_code=8}
        local alias=user alias.flags=alias.flags+1
        local value='code tags parent flags shared self cached \000\255'
        print(user.code,user['tags'],alias.parent,user.flags,user.shared,user.self,user.cached,user.__obf_proto_code,#value,string.byte(value,-1))
        local function capture(delta)return function()user.flags=user.flags+delta return user.flags,nil,user.code end end
        print(capture(2)())
        local called=setmetatable({}, {__call=function(_,x)return x+1 end,__index=function(_,key)return key end})
        print(called(3),called.code)
    "#;
    let work = Workspace::new();
    let path = work.0.join("subject.lua");
    for target in [Target::Lua51, Target::Luau] {
        fs::write(&path, source).unwrap();
        let expected = compile_and_run(target, &path);
        let bytes = vm::custom::compile(source, target).unwrap();
        for seed in [0, 1, 735, u64::MAX] {
            let output = vm::custom::emit(&bytes, target, seed).unwrap();
            assert_eq!(output, vm::custom::emit(&bytes, target, seed).unwrap());
            assert_private_names_hidden(&output, target);
            assert_eq!(embedded(&output, target, seed), bytes);
            let decoded = bc::decode(&bytes, target).unwrap();
            assert_eq!(bc::serialize(&decoded).unwrap(), bytes);
            fs::write(&path, output).unwrap();
            assert_eq!(compile_and_run(target, &path), expected);
        }
    }
}

#[test]
fn ordinary_minification_does_not_opt_user_fields_into_the_private_schema() {
    let source = r#"
        local record={code='code',tags='tags',parent=3,flags=4,shared=5,self=6,cached=7,__obf_proto_code=8}
        local alias=record alias.code=alias.tags
        print(record.code,record.tags,record.parent,record.flags,record.shared,record.self,record.cached,record.__obf_proto_code)
    "#;
    let work = Workspace::new();
    let path = work.0.join("public.lua");
    for target in [Target::Lua51, Target::Luau] {
        fs::write(&path, source).unwrap();
        let expected = compile_and_run(target, &path);
        for seed in [0, 735, u64::MAX] {
            let output =
                obf::minify_with_options(source, target, obf::minify::Options::seeded(seed))
                    .unwrap();
            for name in LONG_FIELDS {
                assert!(output.contains(&format!(".{name}")));
            }
            assert!(output.contains(".__obf_proto_code"));
            fs::write(&path, output).unwrap();
            assert_eq!(compile_and_run(target, &path), expected);
        }
    }
}

#[test]
fn static_userdata_namecalls_with_public_or_marker_like_names_are_not_rewritten() {
    let source = r#"
        local object=newproxy(true)
        getmetatable(object).__namecall=function(self,value,...)
            assert(self==object) return value,select('#',...),...
        end
        print(object:code(1,nil,2)) print(object:tags(3,nil,4))
        print(object:__obf_proto_code(5,nil,6)) print(object:__obf_proto_typo(7,nil,8))
        local tableObject={code=function(self,value)return value+1 end,__obf_proto_tags=function(self,value)return value+2 end}
        print(tableObject:code(9),tableObject:__obf_proto_tags(10))
    "#;
    let work = Workspace::new();
    let path = work.0.join("methods.luau");
    fs::write(&path, source).unwrap();
    let expected = compile_and_run(Target::Luau, &path);
    for seed in [0, 735, u64::MAX] {
        let output = vm::custom::virtualize(source, Target::Luau, seed).unwrap();
        assert_private_names_hidden(&output, Target::Luau);
        for method in [
            "code",
            "tags",
            "__obf_proto_code",
            "__obf_proto_tags",
            "__obf_proto_typo",
        ] {
            assert!(output.contains(&format!(":{method}(")), "{method}");
        }
        fs::write(&path, output).unwrap();
        assert_eq!(compile_and_run(Target::Luau, &path), expected);
    }
}

#[test]
fn exported_module_keys_stay_readable_and_unchanged() {
    let source="export const code='code' export const tags='tags' export const parent=3 export const flags=4 export const shared=5 export const cached=6 export const __obf_proto_code=7";
    let work = Workspace::new();
    let module = work.0.join("subject.luau");
    let main = work.0.join("main.luau");
    fs::write(&main,"local m=require('./subject') print(table.isfrozen(m),m.code,m.tags,m.parent,m.flags,m.shared,m.cached,m.__obf_proto_code)").unwrap();
    fs::write(&module, source).unwrap();
    let expected = compile_and_run(Target::Luau, &main);
    for seed in [0, 735, u64::MAX] {
        let output = vm::custom::virtualize(source, Target::Luau, seed).unwrap();
        assert_private_names_hidden(&output, Target::Luau);
        fs::write(&module, output).unwrap();
        assert_eq!(compile_and_run(Target::Luau, &main), expected);
    }
}

#[test]
fn cli_virtualize_compile_wrap_and_isa1_all_use_the_short_field_pipeline() {
    let work = Workspace::new();
    let source = work.0.join("source.lua");
    let file = work.0.join("program.obf");
    fs::write(&source, "local function f(x)return x+1 end print(f(2))").unwrap();
    for target in [Target::Lua51, Target::Luau] {
        let target_name = target.to_string();
        let compiled = success(
            Command::new(env!("CARGO_BIN_EXE_obf"))
                .args(["compile", "--target", &target_name])
                .arg(&source),
        )
        .stdout;
        fs::write(&file, &compiled).unwrap();
        let output = success(
            Command::new(env!("CARGO_BIN_EXE_obf"))
                .args(["virtualize", "--target", &target_name, "--seed", "735"])
                .arg(&source)
                .env("OBF_LUAC51", "/missing-compiler")
                .env("OBF_LUAU_COMPILE", "/missing-compiler"),
        )
        .stdout;
        let wrapped = success(
            Command::new(env!("CARGO_BIN_EXE_obf"))
                .args(["wrap-bytecode", "--target", &target_name, "--seed", "735"])
                .arg(&file),
        )
        .stdout;
        assert_eq!(output, wrapped);
        assert_private_names_hidden(std::str::from_utf8(&output).unwrap(), target);
        assert_eq!(
            embedded(std::str::from_utf8(&output).unwrap(), target, 735),
            compiled
        );
        let mut old = bc::decode(&compiled, target).unwrap();
        old.isa_version = 1;
        for prototype in &mut old.prototypes {
            prototype.flags &= 7;
        }
        let legacy = bc::serialize(&old).unwrap();
        fs::write(&file, &legacy).unwrap();
        let wrapped = success(
            Command::new(env!("CARGO_BIN_EXE_obf"))
                .args(["wrap-bytecode", "--target", &target_name, "--seed", "735"])
                .arg(&file),
        )
        .stdout;
        let wrapped = String::from_utf8(wrapped).unwrap();
        assert_private_names_hidden(&wrapped, target);
        assert_eq!(embedded(&wrapped, target, 735), legacy);
        let script = work.0.join("old.lua");
        fs::write(&script, wrapped).unwrap();
        assert_eq!(compile_and_run(target, &script), b"3\n");
    }
}
