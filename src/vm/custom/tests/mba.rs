// Goal-3 gates: the micro-op MBA layer (`mba.rs` + the P7 pass in
// `seed_deform.rs`).
//
// The layer rewrites the VM's own integer primitives on the deformed seed
// template. Four things are pinned here:
//
//   1. Every renderer is *exact* over its documented domain, checked by
//      executing the rendered spellings on the real interpreters against the
//      raw operator they replace -- the Rust side never self-certifies.
//   2. The spelling pools are diversified: one drawn form is not the layer
//      (each renderer must produce several distinct shapes per seed stream).
//   3. The template pass actually lands: for every sampled seed and target the
//      audited micro-op sites are gone, the layer's coefficient census is
//      there, and the *validation traps* on unvalidated image fields keep
//      their literal comparisons -- a modular rewrite of a trap would stop
//      firing for adversarial values inside the wrap window.
//   4. The value-operand arms stay raw Lua operators: a probe with string
//      coercion and `__add`/`__eq`/`__lt` metamethods must produce the native
//      result through the shipped VM on both targets.

use crate::random::Prng;

/// Interpreter bindings the rendered spellings draw on: the floor helper on
/// Lua 5.1, `//` on Luau, and the validated `bit32` captures the Luau bit
/// family calls (the interpreter section receives them as parameters).
fn mba_chunk(target: Target) -> String {
    let mut chunk = String::from("local MF=math.floor;");
    if target.is_luau() {
        chunk.push_str("local B32=bit32;local BX,BA,BO,BN=B32.bxor,B32.band,B32.bor,B32.bnot;");
    }
    chunk
}

/// Lint one rendered spelling: no target-foreign construct, no placeholder.
fn mba_lint(rendered: &str, target: Target) {
    if !target.is_luau() {
        assert!(
            !rendered.contains("//"),
            "lua51 spelling uses floordiv: {rendered}"
        );
        assert!(
            !rendered.contains("BX(") && !rendered.contains("BA(") && !rendered.contains("BO("),
            "lua51 spelling draws the bit family: {rendered}"
        );
    }
    if target.is_luau() {
        // The dual-target rule is symmetric: Lua 5.1 has no bit library, Luau
        // has no `MF` helper (the template gate enforces the same split).
        assert!(
            !rendered.contains("MF("),
            "luau spelling uses the lua51 floor helper: {rendered}"
        );
    }
    assert!(
        !rendered.contains("_KEEP_"),
        "renderer left a placeholder: {rendered}"
    );
}

/// Run `chunk` on the target's real interpreter and return stdout.
fn mba_run(target: Target, name: &str, chunk: &str) -> String {
    let workspace = native::Workspace::new();
    let path = workspace.0.join(format!("{name}.lua"));
    fs::write(&path, chunk).unwrap();
    let runner = if target.is_luau() { "luau" } else { "lua5.1" };
    let output = Command::new(native::root().join("toolchains/bin").join(runner))
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{target}: {name} failed on the interpreter:\n{}\n(chunk: {} chars)",
        String::from_utf8_lossy(&output.stderr),
        chunk.len()
    );
    String::from_utf8(output.stdout).unwrap()
}

/// 60 vector pairs (edges first, then seeded random) for the operand pairs.
fn mba_vectors() -> Vec<(u64, u64)> {
    let mut rng = Prng::new(0x6D42_415F_5645_4354);
    let mut pairs = vec![
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (2, 3),
        (15, 1),
        (999, 1),
        (999_999, 1),
        (1, 999_999),
        (65_535, 256),
        (256, 65_535),
        (1 << 20, 1),
        (1 << 20, 1 << 20),
        (1_000_000, 15),
    ];
    while pairs.len() < 60 {
        let hi = 1 + rng.index(1 << 21) as u64;
        let lo = rng.index(hi as usize) as u64;
        pairs.push((hi, lo));
    }
    pairs
}

#[test]
fn mba_arithmetic_spellings_match_the_raw_primitive() {
    let mut rng = Prng::new(0x6D62_615F_6172_6974);
    for target in [Target::Lua51, Target::Luau] {
        let names = MbaNames::emit(target);
        let plain = MbaNames::plain(target);
        let mut chunk = mba_chunk(target);
        let mut asserts = 0usize;
        let mut add_shapes = BTreeSet::new();
        let mut sub_shapes = BTreeSet::new();
        let mut int_shapes = BTreeSet::new();
        let mut mod_shapes = BTreeSet::new();
        for &(a, b) in &mba_vectors() {
            for draw in 0..3 {
                let rendered = add(&mut rng, &names, &a.to_string(), &b.to_string());
                mba_lint(&rendered, target);
                if draw == 0 {
                    add_shapes.insert(rendered.clone());
                }
                chunk.push_str(&format!("assert(({rendered})=={},\"add/{a}/{b}\");", a + b));
                asserts += 1;
            }
            // The untrusted-operand family must stay exact too (it is the one
            // the packed references go through).
            let rendered = add(&mut rng, &plain, &a.to_string(), &b.to_string());
            mba_lint(&rendered, target);
            chunk.push_str(&format!("assert(({rendered})=={},\"addp/{a}/{b}\");", a + b));
            asserts += 1;
            // `sub_nonneg` documents `b <= a`; the equal case and the
            // strictly greater case both go through it.
            let (hi, lo) = (a.max(b), a.min(b));
            for draw in 0..3 {
                let rendered = sub_nonneg(&mut rng, &names, &hi.to_string(), &lo.to_string());
                mba_lint(&rendered, target);
                if draw == 0 {
                    sub_shapes.insert(rendered.clone());
                }
                chunk.push_str(&format!("assert(({rendered})=={},\"sub/{hi}/{lo}\");", hi - lo));
                asserts += 1;
            }
            let rendered = sub_nonneg(&mut rng, &plain, &hi.to_string(), &lo.to_string());
            mba_lint(&rendered, target);
            chunk.push_str(&format!("assert(({rendered})=={},\"subp/{hi}/{lo}\");", hi - lo));
            asserts += 1;
            // `x+c` with the literal folded away, and the integrality probe.
            for c in [1u64, 5, 24, 1000] {
                let rendered = add_const(&mut rng, &names, &a.to_string(), c);
                mba_lint(&rendered, target);
                chunk.push_str(&format!(
                    "assert(({rendered})=={},\"addc/{a}/{c}\");",
                    a + c
                ));
                asserts += 1;
            }
            // `non_integral(x)` is `x % 1 ~= 0`: true exactly for the
            // fractional probes.
            for (x, want) in [
                (a.to_string(), false),
                (format!("({a}+0.5)"), true),
                (format!("({a}-0.5)"), true),
            ] {
                for draw in 0..3 {
                    let rendered = non_integral(&mut rng, &names, &x);
                    mba_lint(&rendered, target);
                    if draw == 0 {
                        int_shapes.insert(rendered.clone());
                    }
                    chunk.push_str(&format!(
                        "assert(({rendered})=={want},\"int/{x}/{draw}\");"
                    ));
                    asserts += 1;
                }
            }
            // `x % k` field extraction: the divisor no longer reads as the
            // packing constant, the value must not move.
            for k in [1u64, 10, 100, 256, 1000] {
                for draw in 0..3 {
                    let rendered = modulo_field(&mut rng, &names, &a.to_string(), k);
                    mba_lint(&rendered, target);
                    if draw == 0 {
                        mod_shapes.insert(rendered.clone());
                    }
                    chunk.push_str(&format!(
                        "assert(({rendered})=={},\"mod/{a}/{k}/{draw}\");",
                        a % k
                    ));
                    asserts += 1;
                }
            }
        }
        assert!(asserts > 900, "{target}: vector census too small: {asserts}");
        for (name, shapes) in [
            ("add", &add_shapes),
            ("sub", &sub_shapes),
            ("non_integral", &int_shapes),
            ("modulo", &mod_shapes),
        ] {
            assert!(
                shapes.len() >= 3,
                "{target}: {name} drew only {} first-draw shapes",
                shapes.len()
            );
        }
        chunk.push_str("print(\"MBA-ARITH-OK\");");
        let stdout = mba_run(target, "mba_arith", &chunk);
        assert!(
            stdout.contains("MBA-ARITH-OK"),
            "{target}: arithmetic vectors failed:\n{stdout}"
        );
    }
}

#[test]
fn mba_predicate_spellings_match_the_raw_comparison() {
    let mut rng = Prng::new(0x6D62_615F_7072_6564);
    let ops = [
        (Cmp::Eq, "=="),
        (Cmp::Ne, "~="),
        (Cmp::Gt, ">"),
        (Cmp::Lt, "<"),
        (Cmp::Ge, ">="),
        (Cmp::Le, "<="),
    ];
    for target in [Target::Lua51, Target::Luau] {
        let names = MbaNames::emit(target);
        let mut chunk = mba_chunk(target);
        let mut asserts = 0usize;
        let mut shapes = BTreeSet::new();
        // The guard corpus is exactly the audited template's shape: small
        // bounded operands against a literal (`vi>15`, `vo>255`, `#q~=3`).
        for bound in [8u64, 15, 16, 255, 999] {
            for c in [0u64, 1, 3, 8, 15, 255] {
                if c > bound {
                    continue;
                }
                let probes = [0, c.saturating_sub(1), c, c + 1, bound];
                for &x in &probes {
                    if x > bound {
                        continue;
                    }
                    for &(op, text) in &ops {
                        for draw in 0..3 {
                            let rendered = compare(&mut rng, &names, &x.to_string(), bound, op, c);
                            mba_lint(&rendered, target);
                            if draw == 0 {
                                shapes.insert(format!("{text}{c}"));
                            }
                            let want = match op {
                                Cmp::Eq => x == c,
                                Cmp::Ne => x != c,
                                Cmp::Gt => x > c,
                                Cmp::Lt => x < c,
                                Cmp::Ge => x >= c,
                                Cmp::Le => x <= c,
                            };
                            chunk.push_str(&format!(
                                "assert(({rendered})=={want},\"cmp/{text}/{x}/{c}/{draw}\");"
                            ));
                            asserts += 1;
                        }
                    }
                }
            }
        }
        assert!(asserts > 700, "{target}: predicate census too small: {asserts}");
        assert!(shapes.len() >= 20, "{target}: predicate corpus too thin");
        chunk.push_str("print(\"MBA-CMP-OK\");");
        let stdout = mba_run(target, "mba_cmp", &chunk);
        assert!(
            stdout.contains("MBA-CMP-OK"),
            "{target}: predicate vectors failed:\n{stdout}"
        );
    }
}

#[test]
fn mba_modulus_and_split_spellings_are_exact_numbers() {
    let mut rng = Prng::new(0x6D62_615F_6D6F_6475);
    let mut chunk = mba_chunk(Target::Lua51);
    let mut modulus_shapes = BTreeSet::new();
    let mut half_shapes = BTreeSet::new();
    for _ in 0..32 {
        let text = modulus(&mut rng);
        mba_lint(&text, Target::Lua51);
        modulus_shapes.insert(text.clone());
        chunk.push_str(&format!("assert(({text})==4294967296,\"mod\");"));
        let text = half(&mut rng);
        mba_lint(&text, Target::Lua51);
        half_shapes.insert(text.clone());
        chunk.push_str(&format!("assert(({text})==2147483648,\"half\");"));
    }
    assert!(modulus_shapes.len() >= 4, "modulus spellings: {modulus_shapes:?}");
    assert!(half_shapes.len() >= 4, "split spellings: {half_shapes:?}");
    chunk.push_str("print(\"MBA-MOD-OK\");");
    let stdout = mba_run(Target::Lua51, "mba_mod", &chunk);
    assert!(stdout.contains("MBA-MOD-OK"), "modulus vectors failed:\n{stdout}");
}

/// The audited micro-op sites, as they still read before the pass.
const MBA_SITES: [&str; 11] = [
    "ip=ip+1",
    "ip=1+ip",
    "vi+1",
    "sl+vo",
    "5+i",
    "5+nargs",
    "(re-vo)",
    "(t1-vi)",
    "re%1000",
    "t1%1000",
    "oi5==0",
];

/// Validation traps on image fields the layer must never touch: their
/// modular spellings are only equivalences inside a bound the trap itself is
/// trying to establish.
const MBA_TRAPS: [&str; 8] = [
    "op==8",
    "op==12",
    "nargs<0",
    "nargs>8",
    "kind<0",
    "kind>8",
    "re<0",
    "t<1",
];

#[test]
fn mba_guarded_fields_never_draw_the_bit_family() {
    // The fractional-reference trap (`78-frac-ref` in the direct
    // differential): the guarded fields are integer *because* their guard
    // says so, and on Luau a `bit32` call on a fractional word raises a raw
    // argument error instead of the fail-closed `seedfail`. The family
    // restriction in `match_guard` is pinned here, on the production
    // `rewrite_guards` path and on the real interpreters.
    let mut rng = Prng::new(0x6D62_615F_6775_6172);
    let ops = [
        (Cmp::Eq, "=="),
        (Cmp::Ne, "~="),
        (Cmp::Gt, ">"),
        (Cmp::Lt, "<"),
        (Cmp::Ge, ">="),
        (Cmp::Le, "<="),
    ];
    // The only names the template reaches through `#`: a table length is an
    // integer by definition, so these guards may keep drawing the bit family.
    let length_reads = ["q", "prog"];
    let counters = ["ip", "i", "n"];
    for target in [Target::Lua51, Target::Luau] {
        let names = MbaNames::emit(target);
        let mut chunk = mba_chunk(target);
        chunk.push_str("local q={1,2,3};local prog={1,2,3};local ip,i,n=0,0,0;");
        let mut bit_shapes = BTreeSet::new();
        let mut bounded = 0usize;
        for ident in length_reads {
            for &(_, text) in &ops {
                for c in [0u64, 1, 3] {
                    let raw = format!("#{ident}{text}{c}");
                    let (drawn, count) = rewrite_guards(&raw, &mut rng, &names);
                    assert_eq!(count, 1, "{target}: guard not rewritten: {raw}");
                    mba_lint(&drawn, target);
                    bit_shapes.insert(drawn.replace(&c.to_string(), "N"));
                    chunk.push_str(&format!("assert(({raw})==({drawn}),\"len/{raw}\");"));
                    bounded += 1;
                }
            }
        }
        for ident in counters {
            chunk.push_str(&format!("{ident}=7;"));
            for &(_, text) in &ops {
                for c in [0u64, 1, 3, 999] {
                    let raw = format!("{ident}{text}{c}");
                    let (drawn, count) = rewrite_guards(&raw, &mut rng, &names);
                    assert_eq!(count, 1, "{target}: guard not rewritten: {raw}");
                    mba_lint(&drawn, target);
                    bit_shapes.insert(drawn.replace(&c.to_string(), "N"));
                    chunk.push_str(&format!("assert(({raw})==({drawn}),\"ctr/{raw}\");"));
                    bounded += 1;
                }
            }
        }
        if target.is_luau() {
            assert!(
                bit_shapes.iter().any(|shape| {
                    shape.contains("BX(") || shape.contains("BA(") || shape.contains("BO(")
                }),
                "luau: the integral-before-guard names never drew the bit family"
            );
        }
        // Guarded fields: integer *and* fractional probes must stay exact, and
        // the drawn spelling must never call the bit captures.
        let fields: Vec<&str> = GUARD_IDENTS
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| !GUARD_BIT_IDENTS.contains(name))
            .collect();
        assert!(fields.len() >= 5, "guard field list shrank: {fields:?}");
        chunk.push_str(&format!("local {};", fields.join(",")));
        let mut field_shapes = BTreeSet::new();
        let mut probes = 0usize;
        for ident in &fields {
            for probe in [
                "0", "1", "2", "15", "16", "0.5", "1.5", "15.5", "-0.5", "2.25",
            ] {
                chunk.push_str(&format!("{ident}={probe};"));
                for &(_, text) in &ops {
                    for c in [0u64, 1, 15] {
                        let raw = format!("{ident}{text}{c}");
                        let (drawn, count) = rewrite_guards(&raw, &mut rng, &names);
                        assert_eq!(count, 1, "{target}: guard not rewritten: {raw}");
                        mba_lint(&drawn, target);
                        for name in ["BX(", "BA(", "BO(", "BN("] {
                            assert!(
                                !drawn.contains(name),
                                "{target}: guarded field {ident} drew {name}: {drawn}"
                            );
                        }
                        field_shapes.insert(drawn.replace(&c.to_string(), "N"));
                        chunk.push_str(&format!(
                            "assert(({raw})==({drawn}),\"field/{ident}/{probe}/{text}{c}\");"
                        ));
                        probes += 1;
                    }
                }
                // The integrality form is the one a fractional word trips.
                for form in ["%1~=0", "%1==0"] {
                    let raw = format!("{ident}{form}");
                    let (drawn, count) = rewrite_guards(&raw, &mut rng, &names);
                    assert_eq!(count, 1, "{target}: integrality guard not rewritten: {raw}");
                    mba_lint(&drawn, target);
                    chunk.push_str(&format!(
                        "assert(({raw})==({drawn}),\"field-int/{ident}/{probe}\");"
                    ));
                    probes += 1;
                }
            }
        }
        assert!(bounded >= 60, "{target}: bounded-guard corpus too small: {bounded}");
        assert!(probes >= 900, "{target}: field corpus too small: {probes}");
        assert!(
            field_shapes.len() >= 30,
            "{target}: field spellings lack diversity: {}",
            field_shapes.len()
        );
        chunk.push_str("print(\"MBA-GUARD-OK\");");
        let stdout = mba_run(target, "mba_guards", &chunk);
        assert!(
            stdout.contains("MBA-GUARD-OK"),
            "{target}: guard vectors failed:\n{stdout}"
        );
    }
}

#[test]
fn mba_layer_rewrites_every_micro_op_site() {
    for target in [Target::Lua51, Target::Luau] {
        for seed in [1u64, 7001, 7351, u64::MAX] {
            let body = seed_loop_lua(target, seed);
            for site in MBA_SITES {
                assert!(
                    !body.contains(site),
                    "{target}/{seed}: micro-op site survived the MBA layer: {site}"
                );
            }
            for trap in MBA_TRAPS {
                assert!(
                    body.contains(trap),
                    "{target}/{seed}: MBA layer touched a validation trap: {trap}"
                );
            }
            // The layer's census: every rewrites carries drawn coefficients
            // (`x*(p+1)-x*p`) and the packed-reference fields are folded
            // through opaquely spelled moduli.
            // Measured across the gate's seeds: 53..72 drawn coefficient
            // products on Lua 5.1 (pure arithmetic) and 31..45 on Luau (where
            // part of the draw is the much shorter bit family), so the floor
            // sits below the observed range and still trips on a starved pass.
            let floor = if target.is_luau() { 25 } else { 45 };
            let drawn = body.matches(")*-").count() + body.matches("*0x").count();
            assert!(
                drawn >= floor,
                "{target}/{seed}: MBA coefficient census moved: {drawn}"
            );
            assert!(
                body.matches('%').count() >= 40,
                "{target}/{seed}: MBA modulus census moved"
            );
            mba_lint(&body, target);
            if target.is_luau() {
                assert!(
                    body.contains("BX(") && body.contains("BA("),
                    "{seed}: the mixed boolean-arithmetic family is missing on Luau"
                );
            }
        }
        // Per-seed variation: the layer is a draw, not a fixed rewrite.
        assert_ne!(
            seed_loop_lua(target, 7001),
            seed_loop_lua(target, 7002),
            "{target}: MBA layer is seed-independent"
        );
    }
}

/// The exactness contract of the value arms. The ALU chain is *not* MBA'd
/// (it runs on arbitrary Lua values), so string coercion and metamethod
/// dispatch must keep producing the native result through the shipped VM.
#[test]
fn mba_value_arms_keep_exact_lua_semantics() {
    let probe = r#"
        local log={}
        local function note(...)
            local n=select('#',...)
            local row={}
            for i=1,n do row[i]=tostring((select(i,...))) end
            log[#log+1]=table.concat(row,":")
        end
        local mt={__add=function(a,b)return (type(a)=="number" and a or a.v)+(type(b)=="number" and b or b.v)end,__unm=function(a)return -a.v end}
        local t=setmetatable({v=40},mt)
        note("coerce","3"+4,"3"*2,12/"4","7"%4,2^10)
        note("meta",t+2,2+t,-t)
        note("cmp",tostring(1==1),tostring(1=="1"),tostring("a"<"b"),tostring(2<=2),tostring(3~=4))
        note("concat","a"..1,true,#"abc")
        print(table.concat(log,"|"))
    "#;
    for target in [Target::Lua51, Target::Luau] {
        let workspace = native::Workspace::new();
        let source_path = workspace.0.join("mba_alu_source.lua");
        fs::write(&source_path, probe).unwrap();
        let runner = if target.is_luau() { "luau" } else { "lua5.1" };
        let native_output = Command::new(native::root().join("toolchains/bin").join(runner))
            .arg(&source_path)
            .output()
            .unwrap();
        assert!(
            native_output.status.success(),
            "{target}: probe does not run natively:\n{}",
            String::from_utf8_lossy(&native_output.stderr)
        );
        let expected = String::from_utf8(native_output.stdout).unwrap();
        for seed in [7001u64, 7351] {
            let emitted = virtualize(probe, target, seed).expect("probe virtualizes");
            let path = workspace.0.join(format!("mba_alu_{seed}.lua"));
            fs::write(&path, &emitted).unwrap();
            let output = Command::new(native::root().join("toolchains/bin").join(runner))
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{target}/{seed}: shipped VM failed:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                expected,
                "{target}/{seed}: value semantics drifted under the MBA layer"
            );
        }
    }
}
