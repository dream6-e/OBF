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
            // K6 step 2: the first of the three (the 87-checksum field) now
            // carries its three `*87` respellings, so on small programs --
            // where its body falls under the duplicate limit -- it ships as a
            // same-key A/B pair at two install sites. Two copies are the
            // respelled equivalent pair (the three `x+y*87` terms commute);
            // three or more, or zero, would be a planner bug.
            for key in [keys[13], keys[14], keys[15]] {
                let copies = raw.matches(&format!("[{key}]=function(")).count();
                assert!(
                    (1..=2).contains(&copies),
                    "{target} seed {seed}: field {key} has {copies} payload copies"
                );
                if copies == 2 {
                    let a = raw.find(&format!("[{key}]=function(")).unwrap();
                    let b = raw[a + 1..].find(&format!("[{key}]=function(")).unwrap() + a + 1;
                    let (sa, sb) = (
                        &raw[a..a + 400],
                        &raw[b..b + 400],
                    );
                    assert_ne!(
                        sa, sb,
                        "{target} seed {seed}: field {key} copies are identical text"
                    );
                    assert_eq!(
                        sa.matches("*87").count() + sb.matches("*87").count(),
                        6,
                        "{target} seed {seed}: the A/B pair must be the 87-checksum field"
                    );
                }
            }
            assert!(raw.contains(&format!("[{}]=function(E,SB)", keys[13])));
            assert!(raw.contains(&format!("VMS[{}](E,SB)", keys[13])));
            assert!(raw.contains(&format!("[{}]=function(E,SB)", keys[14])));
            if target.is_luau() {
                assert!(raw.contains(&format!("[{}]=function(E,BNE,BW8", keys[15])));
            } else {
                assert!(raw.contains(&format!("[{}]=function(E)", keys[15])));
            }
            // Goal 5: the semantic validator takes the per-use constant
            // synthesizer as its last parameter -- it validates each prototype's
            // code-resident constant block through it during decoding.
            let semantic_tail = if target.is_luau() { ",BL,TY)" } else { ")" };
            assert!(raw.contains(&format!(
                "[{}]=function(P,np,SB,E,dec,vld,NX,SS,NCH,TC,IF,SF,U32,UK,NU,KGC{semantic_tail}",
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

