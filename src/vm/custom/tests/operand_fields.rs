// The operand feature split, kept in its own file since `tests/semantic.rs` reached the
// 81,920 B implementation-source ceiling (K3-FULL). The gate below is the one that pins
// the three payload fields staying separate -- and, since K3-FULL, that the parser is
// handed **no** shared form or permutation table any more. `include!` keeps the shared
// module scope, so `compile`/`emit`/`wrapper_keys`/`blob`/`wire` stay in view.

#[test]
fn operand_features_are_split_into_separate_shuffled_fields() {
    // The operand-form map (`[0]=3,[1]=4,...` sequential-key literal),
    // the varint reader with its `if f==1 elseif f==2 ...` shape chain
    // and the per-opcode bounds arms used to be one field's static
    // signature. They are three separate payload fields. Since K3-FULL the first is
    // not a map at all: the form rides in the recipe dictionary, so the parser is
    // handed no shared table either -- which this gate now pins as well.
    let _ = ();
    for target in [Target::Lua51, Target::Luau] {
        let source = "local function add(a,b)return a+b end print(add(1,2))";
        let data = compile(source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut packed_strings = BTreeSet::new();
        for seed in [0u64, 1, 735, u64::MAX] {
            let raw = generate(&data, &program, seed).unwrap();
            let keys = wrapper_keys(seed);
            assert!(!raw.contains("local FM={"), "{target} seed {seed}");
            assert!(!raw.contains("FMt"), "{target} seed {seed}: a shared form table is back");
            assert!(
                !raw.contains("PT,FM") && !raw.contains("FM[op]") && !raw.contains("PT[op]"),
                "{target} seed {seed}: the parser receives a shared opcode table again"
            );
            for key in [keys[13], keys[14], keys[15]] {
                assert_eq!(
                    raw.matches(&format!("[{key}]=function(")).count(),
                    1,
                    "{target} seed {seed}: field {key} is not a single payload field"
                );
            }
            assert!(raw.contains(&format!("[{}]=function(E,SB)", keys[13])));
            assert!(raw.contains(&format!("VMS[{}](E,SB)", keys[13])));
            assert!(raw.contains(&format!("[{}]=function(E,SB)", keys[14])));
            assert!(raw.contains(&format!("[{}]=function(E)", keys[15])));
            assert!(raw.contains(&format!(
                "[{}]=function(P,np,SB,E,dec,vld,NX,SS,NCH,TC,IF,SF,U32,UK,NU)",
                keys[2]
            )));
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

