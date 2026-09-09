/// Direct v1 seed-op differential vectors: STORE/LOAD/IDX/SET/RAISE, the raw
/// ALU sub-ops (concat/lt/le/not/len), RET action 3, spread-by-`.n`,
/// numeric-string coercion parity, ups/va site slots, and fail-closed
/// rejections. Runs unmodified on both runners against the emitted template.
const SEED_V1_POOLS: &str = r#"
local STAB={"n","s1","42"}
local SEEDH={function(a,b)return a+b end,function()return "h1" end,function(p)return p.n..":"..tostring(p[1]) end,function(...)return select('#',...)end}
local RX=function(i)return i+10 end
local K={[5]="k5",[6]="k6",[7]=false}
local R={};R[12]="r12";R[13]=false;R[14]=0;R[15]={7,8};R[16]={}
local F={__obf_proto_k=K}
"#;
const SEED_V1_VECTORS: &str = r#"
local UPS={};UPS[3]="u3";UPS[9]="u9"
local VA={n=1,"vargs"}
local SITE={2,3,4,5,6,7,100,UPS,VA}
local V={
{"s1-store-int",{{8,3020000,3007000},{9,0,3020000},{7,2,0}},2,"VAL",7},
{"s2-store-reg-src",{{1,1000,1000000},{8,3021000,1000},{9,0,3021000},{7,2,0}},2,"VAL","r12"},
{"s3-store-opval",{{8,8006000,3009000},{9,0,8006000},{7,2,0}},2,"VAL",9},
{"s4-store-tmp-idx",{{1,1000,3022000},{8,1000,3004000},{9,0,1000},{7,2,0}},2,"VAL",4},
{"s5-store-frac",{{4,0,3007000,3002000,3003000},{8,0,3001000},{7,0}},0,"FAIL"},
{"s6-load-str",{{1,0,1000000},{9,1000,0},{7,0}},0,"FAIL"},
{"s7-load-dst-oob",{{9,16000,3001000},{7,0}},0,"FAIL"},
{"s8-store-arity",{{8,3001000},{7,0}},0,"FAIL"},
{"i1-idx-static",{{1,1000,1002001},{10,0,1000,3001000},{7,2,0}},2,"VAL",7},
{"i2-idx-dynkey",{{1,1000,1002001},{1,2000,3002000},{10,0,1000,2000},{7,2,0}},2,"VAL",8},
{"i3-idx-nil-tab",{{10,0,6000000,3001000},{7,0}},0,"LUAERR"},
{"i4-idx-opval-key",{{1,1000,1002001},{10,0,1000,8000000},{7,2,0}},2,"VAL",8},
{"i5-set-then-idx",{{1,1000,1000004},{11,1000,3001000,3009000},{10,0,1000,3001000},{7,2,0}},2,"VAL",9},
{"i6-set-arity",{{11,1000,3001000},{7,0}},0,"FAIL"},
{"i7-idx-arity",{{10,0,1000},{7,0}},0,"FAIL"},
{"r1-raise",{{12},{7,0}},0,"LUAERR"},
{"r2-raise-arity",{{12,3001000},{7,0}},0,"FAIL"},
{"a1-concat",{{4,0,3001000,5001000,3009000},{7,2,0}},2,"VAL","1s1"},
{"a2-concat-nums",{{4,0,3001000,3002000,3009000},{7,2,0}},2,"VAL","12"},
{"a3-lt-true",{{4,0,3001000,3002000,3010000},{7,2,0}},2,"VAL",true},
{"a4-lt-false",{{4,0,3002000,3001000,3010000},{7,2,0}},2,"FALSE"},
{"a5-le-eq",{{4,0,3002000,3002000,3011000},{7,2,0}},2,"VAL",true},
{"a6-not-false",{{4,0,1001000,3000000,3012000},{7,2,0}},2,"VAL",true},
{"a7-not-val",{{4,0,3001000,3000000,3012000},{7,2,0}},2,"FALSE"},
{"a8-len-str",{{4,0,5001000,3000000,3013000},{7,2,0}},2,"VAL",2},
{"a9-len-tab",{{4,0,1002001,3000000,3013000},{7,2,0}},2,"VAL",2},
{"a10-coerce-add",{{4,0,5002000,3001000,3000000},{7,2,0}},2,"VAL",43},
{"a11-alu-badop14",{{4,0,3001000,3002000,3014000},{7,0}},0,"FAIL"},
{"t1-ret3",{{7,3,3001000,3002000,3003000}},3,"VAL3",1,2,3},
{"t2-ret3-arity4",{{7,3,3001000,3002000},{7,0}},0,"FAIL"},
{"t3-ret3-arity3",{{7,3,3001000},{7,0}},0,"FAIL"},
{"p1-spread-n",{{3,0,3000000},{11,0,3001000,3006000},{11,0,3002000,3007000},{11,0,5000000,3005000},{5,1000,7003000,3001000,1,0},{7,2,1000}},2,"VAL",5},
{"u1-ups",{{10,0,4008000,8001000},{7,2,0}},2,"VAL","u3"},
{"u2-va",{{1,0,4009000},{7,2,0}},2,"VA"},
{"u3-va-store-load",{{8,3025000,4009000},{9,0,3025000},{7,2,0}},2,"VA"},
{"f1-store-str-idx",{{8,1000000,3001000},{7,0}},0,"FAIL"},
{"f2-load-nil-idx",{{9,0,6000000},{7,0}},0,"FAIL"},
{"f3-load-arity",{{9,0},{7,0}},0,"FAIL"},
{"f4-idx-num-tab",{{10,0,3005000,3001000},{7,0}},0,"LUAERR"},
{"f5-set-str-key",{{1,1000,1000004},{11,1000,5000000,3003000},{10,0,1000,5000000},{7,2,0}},2,"VAL",3}}
local pass=0
for _,v in ipairs(V) do
local name,prog,expact,marker=v[1],v[2],v[3],v[4]
local ok,av,aw,ax,a3,a5=pcall(SEED,prog,SITE,9);local act=(expact==3) and a3 or aw
local good=false
if marker=="FAIL" then good=(not ok)and type(av)=="string" and av:sub(1,9)=="seedfail:"
elseif marker=="LUAERR" then good=(not ok)and(type(av)~="string" or av:sub(1,9)~="seedfail:")
elseif ok and act==expact then
if marker=="VAL" then good=(av==v[5])
elseif marker=="VAL3" then good=(av==v[5] and aw==v[6] and ax==v[7])
elseif marker=="VA" then good=(av==VA)
elseif marker=="FALSE" then good=(av==false)
end end
if good then pass=pass+1 else print("V1FAIL:"..name..":"..tostring(av).."/"..tostring(act)) end
end
print("SEEDV1 PASS "..pass.."/"..#V)
"#;

#[test]
fn seed_v1_ops_direct_differential_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        for dseed in [0u64, 735, 7001, u64::MAX] {
        let source = format!(
            "local E=function(m)error(m,0)end;local MF=math.floor;local TY=type;local PC=pcall;local U=unpack or table.unpack;local Z=function(...)return {{n=select('#',...),...}}end;\n{}\n{}\n{}\n",
            SEED_V1_POOLS,
            seed_loop_lua(target, dseed),
            SEED_V1_VECTORS
        );
        let work = native::Workspace::new();
        let path = work.0.join("seed_v1_ops.lua");
        fs::write(&path, source).unwrap();
        let stdout = native::compile_and_run(target, &path);
        assert_eq!(
            stdout,
            b"SEEDV1 PASS 40/40\n",
            "{target} seed {dseed}: v1 vectors mismatch: {}",
            String::from_utf8_lossy(&stdout)
        );
        }
    }
}

#[test]
fn seed_v1_pools_match_locked_consts() {
    let seedh_lit = format!("local SEEDH={{{}}};", SEEDH_NAMES.join(","));
    for target in [Target::Lua51, Target::Luau] {
        for seed in [0u64, 735] {
            let stab_lit = format!(
                "local STAB={{{}}};",
                STAB_STRS
                    .iter()
                    .map(|s| {
                        let spelling = match *s {
                            "__obf_proto_u" =>
                                crate::vm::fields::short_field("u", target, seed).unwrap(),
                            "__obf_proto_nu" =>
                                crate::vm::fields::short_field("nu", target, seed).unwrap(),
                            _ => s.to_string(),
                        };
                        format!("\"{spelling}\"")
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let mut used = 0u64;
            for op in Opcode::ALL.iter().copied() {
                if op.supported(target) {
                    used |= seed_op_bit(op);
                }
            }
            let prelude_ = seed_prelude_lua_v1(target, seed, used);
        assert!(
            prelude_.contains(&stab_lit),
            "{target}: STAB literal diverged from STAB_STRS"
        );
        assert!(
            prelude_.contains(&seedh_lit),
            "{target}: SEEDH literal diverged from SEEDH_NAMES"
        );
        }
    }
}

/// Generalized v1 corruption gate: every emitted routine is integrity-checked
/// at runtime (validator fail-closed) or by its arm post-condition. Eight
/// adaptive structural cases on Jump (small fixture, both targets) plus a
/// bad-op sweep over every routine each corpus emits (Luau only: routine
/// text is target-independent and Lua51's 46 are a subset of the swept set).
#[test]
fn seed_v1_routine_corruption_rejected() {
    fn lit(target: Target, op: Opcode, dseed: u64) -> String {
        routine_lua(
            &routine_for(target, op).expect("supported op must have a routine"),
            dseed,
            op as usize,
        )
    }
    fn run_corrupted(target: Target, label: &str, src: &str, pristine: &str, dseed: u64) {
        assert_ne!(src, pristine, "{target} {label}: surgery hit nothing");
        let output = finalize(src, target, dseed).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join(format!("seed_v1_corr_{label}.lua"));
        fs::write(&path, output).unwrap();
        assert!(native::compile(target, &path).status.success());
        let runner = if target.is_luau() { "luau" } else { "lua5.1" };
        let result = Command::new(native::root().join("toolchains/bin").join(runner))
            .arg(&path)
            .output()
            .unwrap();
        assert!(!result.status.success(), "{target} corruption {label} ran");
        assert!(
            result.stdout.is_empty(),
            "{target} corruption {label} leaked output: {:?}",
            result.stdout
        );
    }
    for target in [Target::Lua51, Target::Luau] {
    for dseed in [735u64, 7001] {
        let data = compile(SEED_CONTROL_FIXTURE, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = generate(&data, &program, dseed).unwrap();
        let jump = lit(target, Opcode::Jump, dseed);
        assert!(raw.contains(&jump), "{target} seed {dseed}: jump routine not emitted");
        let ret = lit(target, Opcode::Return, dseed);
        // SEEDT entries are bare Lua tables (single-tuple routines stay flat),
        // so every surgery below must keep the braces balanced: corruption is
        // caught by the runtime validator or the arm post-condition, never by
        // the parser.
        let cases: Vec<(&str, String)> = vec![
            ("bad-op", raw.replacen(&jump, &jump.replacen("{", "{9,", 1), 1)),
            ("drop-tail", raw.replacen(&jump, "{7}", 1)),
            ("zero-tuple", raw.replacen(&jump, "{0}", 1)),
            ("neg-op", raw.replacen(&jump, &jump.replacen("{", "{-", 1), 1)),
            ("bad-action", raw.replacen(&jump, &jump.replacen("{7,", "{7,9,", 1), 1)),
            // P2: the kind tag lives inside a respelled word, so the
            // corrupted routine is built directly (decimal always lexes):
            // kind 9 with jump's shape is rejected by runtime refd.
            ("bad-kind-tag", raw.replacen(&jump, "{{7,1,9004000}}", 1)),
            ("wrong-action", raw.replacen(&jump, "{1,0}", 1)),
            ("wrong-routine", raw.replacen(&jump, &ret, 1)),
        ];
        for (label, src) in &cases {
            run_corrupted(target, &format!("{label}-s{dseed}"), src, &raw, dseed);
        }
    }
    }
    // Liveness-probed sweep: a corrupted routine can only break the run if
    // the corpus actually executes it. If the corrupted image still succeeds
    // with byte-identical output, the routine is dead in that corpus (record
    // and skip); otherwise the run must fail with no stdout. Every supported
    // routine must be live-covered at least once, so the fixtures are forced
    // to execute the full op set (fail-closed, no magic skip lists).
    fn run_image(target: Target, stem: &str, src: &str, dseed: u64) -> (bool, Vec<u8>) {
        let output = finalize(src, target, dseed).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join(format!("seed_v1_corr_{stem}.lua"));
        fs::write(&path, output).unwrap();
        assert!(native::compile(target, &path).status.success());
        let runner = if target.is_luau() { "luau" } else { "lua5.1" };
        let result = Command::new(native::root().join("toolchains/bin").join(runner))
            .arg(&path)
            .output()
            .unwrap();
        (result.status.success(), result.stdout)
    }
    let target = Target::Luau;
    let corpora = [
        ("vm", include_str!("../../../../tests/fixtures/vm_luau.lua")),
        ("scope", include_str!("../../../../tests/fixtures/scope_luau.lua")),
    ];
    let mut swept = BTreeSet::new();
    let mut live_covered = BTreeSet::new();
    let mut dead = BTreeSet::new();
    for dseed in [735u64, 7001] {
    for (name, fixture) in corpora {
        let data = compile(fixture, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = generate(&data, &program, dseed).unwrap();
        let (pristine_ok, pristine_out) = run_image(target, &format!("{name}-pristine-s{dseed}"), &raw, dseed);
        assert!(pristine_ok, "{name} seed {dseed}: pristine corpus must run clean");
        for op in Opcode::ALL.iter().copied().filter(|op| op.supported(target)) {
            let routine = lit(target, op, dseed);
            if !raw.contains(&routine) {
                continue;
            }
            swept.insert(op);
            let label = format!("sweep-{name}-s{dseed}-{}", op.name());
            let corrupted = routine.replacen("{", "{9,", 1);
            let src = raw.replacen(&routine, &corrupted, 1);
            assert_ne!(src, raw, "{target} {label}: surgery hit nothing");
            let (ok, out) = run_image(target, &label, &src, dseed);
            if ok && out == pristine_out {
                dead.insert((name, op.name()));
                continue;
            }
            live_covered.insert(op);
            assert!(!ok, "{target} corruption {label} ran");
            // Late-executed routines may print a correct prefix before the
            // validator fires; what must never happen is DIVERGENT output.
            assert!(
                pristine_out.starts_with(&out),
                "{target} corruption {label} diverged: {out:?}"
            );
        }
    }
    }
    eprintln!("sweep dead-in-corpus (skipped): {dead:?}");
    let supported: BTreeSet<Opcode> =
        Opcode::ALL.iter().copied().filter(|op| op.supported(target)).collect();
    assert_eq!(swept, supported, "sweep must corrupt every supported routine at least once");
    assert_eq!(
        live_covered, supported,
        "every supported routine must be live-covered at least once"
    );
}


/// P1 number spellings must lex, minify and run identically on both targets:
/// decimal (canonical), `0x` hex in either digit case, and exact scientific
/// forms for round values. Decides what the respeller may emit.
#[test]
fn p1_number_spellings_survive_finalize_on_both_targets() {
    // Number tokens bypass renaming untouched, so the user-source minify path
    // exercises the exact lex/parse/emit/reparse stages spellings depend on
    // (finalize_vm additionally demands a full generated VM around them).
    let src = "local a=0xF4240;local b=0xff;local c=1e5;local d=3e6;local e=1001e3;print(a,b,c,d,e)";
    for target in [Target::Lua51, Target::Luau] {
        let output =
            crate::minify::with_options(src, target, crate::minify::Options::seeded(735)).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join("p1_numspell.lua");
        fs::write(&path, output).unwrap();
        assert!(native::compile(target, &path).status.success());
        assert_eq!(
            native::compile_and_run(target, &path),
            b"1000000\t255\t100000\t3000000\t1001000\n"
        );
    }
}

const P1_DIALECT_SEEDS: [u64; 8] = [0, 1, 42, 735, 7001, 7351, 100, u64::MAX];

/// P1 acceptance: every seed emits a textually distinct template and image
/// (no cross-sample stable fingerprint), deterministically.
#[test]
fn p1_deformation_distinctness_and_determinism() {
    for target in [Target::Lua51, Target::Luau] {
        let mut loops = Vec::new();
        let mut raws = Vec::new();
        for seed in P1_DIALECT_SEEDS {
            let a = seed_loop_lua(target, seed);
            assert_eq!(a, seed_loop_lua(target, seed), "{target} seed {seed}: template varies");
            loops.push(a);
            let data = compile(SEED_CONTROL_FIXTURE, target).unwrap();
            let program = custom::decode(&data, target).unwrap();
            let r1 = generate(&data, &program, seed).unwrap();
            assert_eq!(r1, generate(&data, &program, seed).unwrap(), "{target} seed {seed}: image varies");
            raws.push(r1);
        }
        for i in 0..loops.len() {
            for j in (i + 1)..loops.len() {
                assert_ne!(loops[i], loops[j], "{target}: seeds {} and {} share a template", P1_DIALECT_SEEDS[i], P1_DIALECT_SEEDS[j]);
                assert_ne!(raws[i], raws[j], "{target}: seeds {} and {} share an image", P1_DIALECT_SEEDS[i], P1_DIALECT_SEEDS[j]);
                let li: Vec<_> = loops[i].lines().collect();
                let lj: Vec<_> = loops[j].lines().collect();
                let diff = li.iter().zip(lj.iter()).filter(|(a, b)| a != b).count() + li.len().abs_diff(lj.len());
                assert!(diff >= 10, "{target}: seeds {} and {} differ by {diff} lines", P1_DIALECT_SEEDS[i], P1_DIALECT_SEEDS[j]);
            }
        }
    }
}

/// P2 gate (RED until Batch-2): the same routine reads differently per seed
/// (one big word takes ~6 spellings; 64 seeds miss variation with ~6^-63).
#[test]
fn p2_routine_text_varies_per_seed() {
    for target in [Target::Lua51, Target::Luau] {
        let prog = routine_for(target, Opcode::Jump).expect("jump has a routine");
        let mut texts = BTreeSet::new();
        for seed in 0..64u64 {
            texts.insert(routine_lua(&prog, seed, Opcode::Jump as usize));
        }
        assert!(
            texts.len() >= 2,
            "{target}: jump routine identical across 64 seeds"
        );
    }
}

/// P2 lock: respelled routines decode back to identical words, deterministi-
/// cally. The parser below is test-side and independent (dec / 0x-hex /
/// trailing-zero scientific); agreement with the emitter is real verification.
#[test]
fn p2_routine_text_roundtrips_to_identical_words() {
    fn word(text: &str) -> u32 {
        let value: u64 = if let Some(hex) = text.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).unwrap()
        } else if let Some(e) = text.find('e') {
            text[..e].parse::<u64>().unwrap() * 10u64.pow(text[e + 1..].parse().unwrap())
        } else {
            text.parse().unwrap()
        };
        assert!(value <= u32::MAX as u64, "word out of range: {text}");
        value as u32
    }
    fn table(text: &str) -> Vec<Vec<u32>> {
        let inner = text
            .strip_prefix('{')
            .and_then(|t| t.strip_suffix('}'))
            .unwrap();
        inner
            .split("},{")
            .map(|ins| {
                ins.trim_start_matches('{')
                    .trim_end_matches('}')
                    .split(',')
                    .map(word)
                    .collect()
            })
            .collect()
    }
    for target in [Target::Lua51, Target::Luau] {
        for op in Opcode::ALL {
            let Some(prog) = routine_for(target, *op) else {
                continue;
            };
            for seed in [0u64, 735, 7001, u64::MAX] {
                let text = routine_lua(&prog, seed, *op as usize);
                assert_eq!(
                    text,
                    routine_lua(&prog, seed, *op as usize),
                    "{target} {} seed {seed}: routine text varies",
                    op.name()
                );
                assert_eq!(
                    table(&text),
                    prog,
                    "{target} {} seed {seed}: routine words changed",
                    op.name()
                );
            }
        }
    }
}

/// P2 gate (RED until Batch-2): the Test arm flips between two equivalent
/// forms per seed (both observed over 64 seeds with ~2^-63 miss rate); the
/// site block and call shape never change.
#[test]
fn p2_test_arm_flips_per_seed() {
    for target in [Target::Lua51, Target::Luau] {
        let mut forms = BTreeSet::new();
        for seed in 0..64u64 {
            let arm = seed_arm_lua_for(target, Opcode::Test, seed).unwrap();
            assert!(
                arm.contains("{a,0,0,0,0,skip1,pc}"),
                "{target} seed {seed}: test site changed"
            );
            forms.insert(arm);
        }
        assert_eq!(
            forms.len(),
            2,
            "{target}: test arm takes {} forms over 64 seeds",
            forms.len()
        );
    }
}

/// P2 gate (RED until Batch-2): the TailCall arm permutes its two action
/// checks per seed; site block and value-first guard never change.
#[test]
fn p2_tailcall_arm_permutes_per_seed() {
    for target in [Target::Lua51, Target::Luau] {
        let mut forms = BTreeSet::new();
        for seed in 0..64u64 {
            let arm = seed_arm_lua_for(target, Opcode::TailCall, seed).unwrap();
            assert!(
                arm.contains("SEED(SEEDT[48],{a,b},9);act=act or v2;"),
                "{target} seed {seed}: tailcall head changed"
            );
            forms.insert(arm);
        }
        assert_eq!(
            forms.len(),
            2,
            "{target}: tailcall arm takes {} forms over 64 seeds",
            forms.len()
        );
    }
}

/// P3 gate (RED until Batch-3): CV takes both branch forms over 64 seeds.
#[test]
fn p3_cv_flips_per_seed() {
    let mut forms = BTreeSet::new();
    for seed in 0..64u64 {
        forms.insert(seed_deform::p3_cv_lua(seed));
    }
    assert_eq!(forms.len(), 2, "CV takes {} forms over 64 seeds", forms.len());
}

/// P3 gate (RED until Batch-3): SV takes both branch forms over 64 seeds.
#[test]
fn p3_sv_flips_per_seed() {
    let mut forms = BTreeSet::new();
    for seed in 0..64u64 {
        forms.insert(seed_deform::p3_sv_lua(seed));
    }
    assert_eq!(forms.len(), 2, "SV takes {} forms over 64 seeds", forms.len());
}

/// P3 gate (RED until Batch-3): Lookup method order varies per seed and is
/// always a true permutation (locks), deterministic per seed (lock).
#[test]
fn p3_lookup_order_varies_and_permutes() {
    assert_eq!(seed_deform::p3_lookup_order(0, 735), Vec::<usize>::new());
    assert_eq!(seed_deform::p3_lookup_order(1, 735), vec![0]);
    let mut orders = BTreeSet::new();
    for seed in 0..64u64 {
        let order = seed_deform::p3_lookup_order(4, seed);
        assert_eq!(
            order,
            seed_deform::p3_lookup_order(4, seed),
            "seed {seed}: lookup order varies"
        );
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2, 3], "seed {seed}: not a permutation");
        orders.insert(order);
    }
    assert!(
        orders.len() >= 2,
        "lookup order identical across 64 seeds"
    );
}

/// P3 gate (RED until Batch-3): the reader group varies per seed; every
/// emission keeps all six definitions in dependency-valid order (locks).
#[test]
fn p3_reader_group_varies_and_valid() {
    const DEFS: [&str; 6] = [
        "local b8=function(",
        "local b16=function(",
        "local b32=function(",
        "local take=function(",
        "local str=function(",
        "local pos=function(",
    ];
    fn order_of(text: &str) -> [usize; 6] {
        let mut pos: Vec<(usize, usize)> = DEFS
            .iter()
            .enumerate()
            .map(|(i, d)| (text.find(d).unwrap_or(usize::MAX), i))
            .collect();
        pos.sort_unstable();
        assert!(pos[0].0 != usize::MAX, "reader def missing");
        [pos[0].1, pos[1].1, pos[2].1, pos[3].1, pos[4].1, pos[5].1]
    }
    fn valid(order: &[usize; 6]) -> bool {
        let at = |i: usize| order.iter().position(|&x| x == i).unwrap();
        // b8 < b16, b8 < b32, b32 < str, take < str.
        at(0) < at(1) && at(0) < at(2) && at(2) < at(4) && at(3) < at(4)
    }
    let mut texts = BTreeSet::new();
    for seed in 0..64u64 {
        let text = seed_deform::p3_reader_group_lua(seed);
        assert_eq!(text, seed_deform::p3_reader_group_lua(seed), "seed {seed}: reader group varies");
        assert!(text.starts_with("local bp=1;\n"), "seed {seed}: bp head moved");
        assert!(valid(&order_of(&text)), "seed {seed}: invalid reader order");
        texts.insert(text);
    }
    assert!(texts.len() >= 2, "reader group identical across 64 seeds");
}

/// P3 lock: raw images embed exactly the per-seed CV/SV/reader text.
#[test]
fn p3_helper_wiring_pins_emission() {
    for dseed in [735u64, 7001] {
        let data = compile(SEED_CONTROL_FIXTURE, Target::Lua51).unwrap();
        let program = custom::decode(&data, Target::Lua51).unwrap();
        let raw = generate(&data, &program, dseed).unwrap();
        assert!(
            raw.contains(seed_deform::p3_cv_lua(dseed)),
            "seed {dseed}: CV text missing"
        );
        assert!(
            raw.contains(seed_deform::p3_sv_lua(dseed)),
            "seed {dseed}: SV text missing"
        );
        assert!(
            raw.contains(&seed_deform::p3_reader_group_lua(dseed)),
            "seed {dseed}: reader group text missing"
        );
    }
}

/// P3 lock: the Luau Lookup chain lists every method exactly once, in the
/// seeded permutation order (ud_check form agnostic: only key== literals).
#[test]
fn p3_lookup_wiring_pins_chain_order() {
    // Two colon-calls (mirrors the vm_luau "add" shape) force two Method
    // constants; the gate only generates text, never runs it.
    const TWO_METHODS: &str = "local o={v=0};function o:ma()return 1 end;function o:mb()return 2 end;print(o:ma()+o:mb())";
    for dseed in [735u64, 7001] {
        let data = compile(TWO_METHODS, Target::Luau).unwrap();
        let program = custom::decode(&data, Target::Luau).unwrap();
        let methods: Vec<&str> = program.methods().iter().copied().collect();
        assert!(methods.len() >= 2, "fixture lost its methods");
        let raw = generate(&data, &program, dseed).unwrap();
        assert_eq!(
            raw.matches("key==").count(),
            methods.len(),
            "seed {dseed}: key== count drifted"
        );
        let order = seed_deform::p3_lookup_order(methods.len(), dseed);
        let mut lits = Vec::new();
        for m in &methods {
            let mut lit = String::new();
            crate::vm::lua51::emit_byte_string(&mut lit, m.as_bytes());
            lits.push(format!("key=={lit}"));
        }
        let mut positions = Vec::new();
        for lit in &lits {
            positions.push(raw.find(lit).unwrap_or(usize::MAX));
        }
        assert!(!positions.contains(&usize::MAX), "seed {dseed}: method literal missing");
        let mut ranked = positions.clone();
        ranked.sort_unstable();
        let observed: Vec<usize> = ranked
            .iter()
            .map(|p| positions.iter().position(|q| q == p).unwrap())
            .collect();
        assert_eq!(observed, order, "seed {dseed}: chain order mismatch");
    }
}

/// P4 gate (RED until Batch-4): comparison-duality spellings appear across
/// seeds (`x<y` <-> `y>x`, `x<=y` <-> `y>=x`; exact by language definition).
#[test]
fn p4_dual_forms_appear() {
    let mut gt = false;
    let mut ge = false;
    for seed in 0..64u64 {
        let body = seed_loop_lua(Target::Lua51, seed);
        gt |= body.contains(">x");
        ge |= body.contains(">=x");
    }
    assert!(gt, "y>x never appears across 64 seeds");
    assert!(ge, "y>=x never appears across 64 seeds");
}

/// P4 helper: canonicalize number spellings to decimal values so chain
/// locks compare semantics, immune to the respeller (identifier-embedded
/// digits like `ok5`/`u9` are kept: same boundary rule as the emitter).
fn p4_canon_numbers(text: &str) -> String {
    fn word_byte(c: u8) -> bool {
        matches!(c, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'.')
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let is_start = i == 0 || !word_byte(bytes[i - 1]);
        if is_start && bytes[i] == b'0' && i + 2 < bytes.len() + 1 && text[i..].starts_with("0x") {
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > i + 2 && (j >= bytes.len() || !word_byte(bytes[j])) {
                out.push_str(&u64::from_str_radix(&text[i + 2..j], 16).unwrap().to_string());
                i = j;
                continue;
            }
        }
        if is_start && bytes[i].is_ascii_digit() {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            // Trailing-zero scientific form.
            if j < bytes.len() && bytes[j] == b'e' {
                let mut k = j + 1;
                while k < bytes.len() && bytes[k].is_ascii_digit() {
                    k += 1;
                }
                if k > j + 1 && (k >= bytes.len() || !word_byte(bytes[k])) {
                    let value: u64 = text[i..j].parse::<u64>().unwrap()
                        * 10u64.pow(text[j + 1..k].parse().unwrap());
                    out.push_str(&value.to_string());
                    i = k;
                    continue;
                }
            }
            if j >= bytes.len() || !word_byte(bytes[j]) {
                out.push_str(&text[i..j].parse::<u64>().unwrap().to_string());
                i = j;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
/// P4 gate (RED until Batch-4): operand chains permute (representative
/// witnesses: pinned-prefix tgtc, full arity, kind-range, 3-operand kind-1).
#[test]
fn p4_chain_orders_vary() {
    let mut seen: Vec<BTreeSet<String>> = vec![BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new()];
    let witnesses = ["seedfail(32)", "seedfail(34)", "seedfail(7)", "seedfail(10)"];
    for seed in 0..64u64 {
        let body = seed_loop_lua(Target::Lua51, seed);
        for (set, w) in seen.iter_mut().zip(witnesses) {
            // Skeletons: spelling variation must not pose as order variation.
            set.insert(p4_canon_numbers(body.lines().find(|l| l.contains(w)).unwrap()));
        }
    }
    for (set, w) in seen.iter().zip(witnesses) {
        assert!(set.len() >= 2, "{w} chain fixed across 64 seeds");
    }
}

/// P4 gate (RED until Batch-4): temp-split ALU forms appear (`local uN=x;`
/// before the reduced operation; evaluation order preserved).
#[test]
fn p4_split_forms_appear() {
    let mut seen = false;
    for seed in 0..64u64 {
        seen |= seed_loop_lua(Target::Lua51, seed).contains("local u");
    }
    assert!(seen, "split temps never appear across 64 seeds");
}

/// P4 gate (RED until Batch-4): dead temporaries appear (`local qN=<digit>;`
/// at fixed anchor points; pure literals, never read).
#[test]
fn p4_dead_temps_appear() {
    let mut seen = false;
    for seed in 0..64u64 {
        let body = seed_loop_lua(Target::Lua51, seed);
        seen |= (1..=6).any(|n| body.contains(&format!("local q{n}=")));
    }
    assert!(seen, "dead temps never appear across 64 seeds");
}

/// P4 locks: chain operands preserved, inserted lines well-formed and
/// unique, growth bounded (base 104 lines + <=6 dead temps).
#[test]
fn p4_insertion_locks() {
    for target in [Target::Lua51, Target::Luau] {
        for seed in P1_DIALECT_SEEDS {
            let body = seed_loop_lua(target, seed);
            let lines: Vec<&str> = body.lines().collect();
            assert!(
                (104..=110).contains(&lines.len()),
                "{target} seed {seed}: {} lines",
                lines.len()
            );
            // Every chain row: witness unique, all operands present,
            // pinned prefix in canonical order.
            for chain in seed_deform::P4_CHAINS {
                let hits: Vec<&&str> = lines.iter().filter(|l| l.contains(chain.witness)).collect();
                assert_eq!(hits.len(), 1, "{target} seed {seed}: witness drifted: {}", chain.witness);
                let shape = p4_canon_numbers(hits[0]);
                for op in chain.inner.split(chain.sep) {
                    assert!(
                        shape.contains(&p4_canon_numbers(op)),
                        "{target} seed {seed}: chain lost {op}"
                    );
                }
                let pinned: Vec<&str> = chain.inner.split(chain.sep).take(chain.pinned).collect();
                if !pinned.is_empty() {
                    let head = format!("{}{}", chain.open, pinned.join(chain.sep));
                    assert!(hits[0].contains(&head), "{target} seed {seed}: pin moved: {}", chain.witness);
                }
            }
            for line in &lines {
                // Canonical `local q=prog[ip];` is not a dead temp; only
                // `local q<1..6>=` lines are checked.
                if line.len() > "local q".len()
                    && line.starts_with("local q")
                    && matches!(line.as_bytes()["local q".len()], b'1'..=b'6')
                {
                    let tail = &line["local q".len()..];
                    let ok = tail.len() == 4
                        && tail.as_bytes()[1] == b'='
                        && tail.as_bytes()[2].is_ascii_digit()
                        && tail.as_bytes()[3] == b';';
                    assert!(ok, "{target} seed {seed}: malformed dead temp: {line}");
                }
                if line.contains("local u") {
                    assert!(
                        (line.starts_with("if oi5==") || line.starts_with("elseif oi5=="))
                            && line.contains(" then local u")
                            && line.contains(";r="),
                        "{target} seed {seed}: malformed split: {line}"
                    );
                }
            }
            for n in 1..=10u32 {
                assert!(
                    body.matches(&format!("local u{n}=")).count() <= 1,
                    "{target} seed {seed}: u{n} bound twice"
                );
            }
            for n in 1..=6u32 {
                assert!(
                    body.matches(&format!("local q{n}=")).count() <= 1,
                    "{target} seed {seed}: q{n} bound twice"
                );
            }
        }
    }
}

/// P5 liveness witness: one alternative = (optional prev-line substring,
/// required substrings of the matched line). Unique-span sites witness with
/// the bare variant; shared spans (`#q` checks, `ip=ip+1;`) anchor to a
/// combination-stable co-span so the variant must land on ITS OWN line.
fn p5_witnesses() -> Vec<Vec<(Option<&'static str>, Vec<&'static str>)>> {
    let bare = |v: &'static str| vec![(None, vec![v])];
    vec![
        vec![(Some("op==1 then"), vec!["3~=#q"])],
        vec![(Some("op==2 then"), vec!["3~=#q"])],
        vec![(Some("op==3 then"), vec!["3~=#q"])],
        vec![(Some("op==8 then"), vec!["3~=#q"])],
        vec![(Some("op==9 then"), vec!["3~=#q"])],
        vec![(Some("op==10 then"), vec!["4~=#q"])],
        vec![(Some("op==11 then"), vec!["4~=#q"])],
        bare("if 5~=#q then seedfail(5)end;"),
        bare("if 5+nargs~=#q then seedfail(5)end;"),
        bare("1~=#q"),
        vec![(None, vec!["2==#q", "tgtc(q[2])"])],
        vec![(None, vec!["3==#q", "tgtc(q[3])"])],
        vec![(None, vec!["2==#q", "return nil,0;"])],
        bare("if 0~=a then"),
        vec![(None, vec!["3==#q", "rv(q[3])"])],
        bare("5==#q"),
        bare("if 3~=a then"),
        vec![
            (None, vec!["tmp[dstc(q[2])]=rv(q[3]);ip=1+ip;"]),
            (None, vec!["tmp[w1]=rv(q[3]);ip=1+ip;"]),
        ],
        vec![(None, vec!["local v=rv(q[3]);", ";ip=1+ip;"])],
        vec![
            (None, vec!["tmp[dstc(q[2])]={};ip=1+ip;"]),
            (None, vec!["tmp[w3]={};ip=1+ip;"]),
        ],
        vec![(Some("tmp[dstc(q[2])]=r;"), vec!["ip=1+ip;"])],
        vec![
            (Some("else tmp[dv]=f(Z(U(ag,1,nargs)));end;"), vec!["ip=1+ip;"]),
            (Some("local w6=f(Z(U(ag,1,nargs)));tmp[dv]=w6;"), vec!["ip=1+ip;"]),
        ],
        vec![
            (None, vec!["local si=rv(q[2]);R[RX(stix(si))]=rv(q[3]);ip=1+ip;"]),
            (None, vec!["local si=rv(q[2]);local w12=RX(stix(si));R[w12]=rv(q[3]);ip=1+ip;"]),
        ],
        vec![
            (None, vec!["local li=rv(q[3]);tmp[dstc(q[2])]=R[RX(stix(li))];ip=1+ip;"]),
            (None, vec!["local li=rv(q[3]);local w13=dstc(q[2]);tmp[w13]=R[RX(stix(li))];ip=1+ip;"]),
        ],
        vec![
            (None, vec!["tmp[dstc(q[2])]=rv(q[3])[rv(q[4])];ip=1+ip;"]),
            (None, vec!["local w14=dstc(q[2]);tmp[w14]=rv(q[3])[rv(q[4])];ip=1+ip;"]),
        ],
        vec![
            (None, vec!["rv(q[2])[rv(q[3])]=rv(q[4]);ip=1+ip;"]),
            (None, vec!["local w15=rv(q[2]);w15[rv(q[3])]=rv(q[4]);ip=1+ip;"]),
        ],
        bare("E();ip=1+ip;"),
        bare("TNUM~=TY(l)"),
        bare("TFUN~=TY(f)"),
        bare("1~=nargs"),
        bare("TTAB~=TY(t)"),
        bare("nil==m"),
        bare("8<m"),
        bare("9~=expect"),
        bare("expect~=a"),
        bare("if not tmp[cv] then ip=ip+1 else ip=t end;"),
        bare("local w1=dstc(q[2]);tmp[w1]=rv(q[3]);"),
        bare("local v=rv(q[3]);local w2=dstc(q[2]);tmp[w2]="),
        bare("local w3=dstc(q[2]);tmp[w3]={};"),
        bare("local w4=f(U(ag,1,nargs));tmp[dv]=w4;"),
        bare("local w5=f(U(t,1,m));tmp[dv]=w5;"),
        bare("local w6=f(Z(U(ag,1,nargs)));tmp[dv]=w6;"),
        bare("local w7=rv(q[5+i]);ag[i]=w7"),
        bare("local w8=tgtc(q[2]);ip=w8;"),
        bare("local cv=dstc(q[2]);local t=tgtc(q[3]);"),
        bare("local w9=expect or 0;expect=w9;"),
        bare("local w10=rv(q[3]);return w10,a;"),
        bare("local w11=rv(q[3]);return w11,rv(q[4]),rv(q[5]),a;"),
        bare("local w12=RX(stix(si));R[w12]=rv(q[3]);"),
        bare("local w13=dstc(q[2]);tmp[w13]=R[RX(stix(li))];"),
        bare("local w14=dstc(q[2]);tmp[w14]=rv(q[3])[rv(q[4])];"),
        bare("local w15=rv(q[2]);w15[rv(q[3])]=rv(q[4]);"),
    ]
}

/// P5 gate (RED until Batch-5): every site's variant lands on its own line
/// at least once across 64 seeds (exhaustive over P5_SITES).
#[test]
fn p5_variants_appear() {
    let witnesses = p5_witnesses();
    assert_eq!(witnesses.len(), seed_deform::P5_SITES.len());
    for target in [Target::Lua51, Target::Luau] {
        let mut seen = vec![false; witnesses.len()];
        for seed in 0..64u64 {
            let body = seed_loop_lua(target, seed);
            let lines: Vec<&str> = body.lines().collect();
            for (idx, alts) in witnesses.iter().enumerate() {
                if seen[idx] {
                    continue;
                }
                'scan: for (i, line) in lines.iter().enumerate() {
                    for (prev, subs) in alts {
                        if !subs.iter().all(|sub| line.contains(sub)) {
                            continue;
                        }
                        if let Some(prev) = prev {
                            if i == 0 || !lines[i - 1].contains(prev) {
                                continue;
                            }
                        }
                        seen[idx] = true;
                        break 'scan;
                    }
                }
            }
        }
        let missing: Vec<usize> =
            seen.iter().enumerate().filter(|(_, s)| !**s).map(|(i, _)| i).collect();
        assert!(missing.is_empty(), "P5: variants never landed: {missing:?}");
    }
}

/// P5 lock: shared spans conserve exact totals, unique spans XOR per seed,
/// temps are singular. Location is enforced impl-side (fail-closed needles).
#[test]
fn p5_insertion_locks() {
    for target in [Target::Lua51, Target::Luau] {
        for seed in 0..16u64 {
            let body = seed_loop_lua(target, seed);
            let total = |a: &str, b: &str| body.matches(a).count() + body.matches(b).count();
            assert_eq!(total("#q~=3", "3~=#q"), 5, "P5: q3 drift seed={seed}");
            assert_eq!(total("#q~=4", "4~=#q"), 2, "P5: q4 drift seed={seed}");
            assert_eq!(total("#q==2", "2==#q"), 2, "P5: q2 drift seed={seed}");
            assert_eq!(total("#q==3", "3==#q"), 2, "P5: q3eq drift seed={seed}");
            assert_eq!(total("ip=ip+1;", "ip=1+ip;"), 10, "P5: ip drift seed={seed}");
            for (canon, variant) in [
                ("if #q~=5 then seedfail(5)end;", "if 5~=#q then seedfail(5)end;"),
                ("if #q~=5+nargs then seedfail(5)end;", "if 5+nargs~=#q then seedfail(5)end;"),
                ("if #q~=1 then seedfail(5)end;", "if 1~=#q then seedfail(5)end;"),
                ("if a~=0 then", "if 0~=a then"),
                ("#q==5", "5==#q"),
                ("if a~=3 then", "if 3~=a then"),
                ("TY(l)~=TNUM", "TNUM~=TY(l)"),
                ("TY(f)~=TFUN", "TFUN~=TY(f)"),
                ("nargs~=1", "1~=nargs"),
                ("TY(t)~=TTAB", "TTAB~=TY(t)"),
                ("m==nil", "nil==m"),
                ("m>8", "8<m"),
                ("expect~=9", "9~=expect"),
                ("a~=expect", "expect~=a"),
                (
                    "if tmp[cv] then ip=t else ip=ip+1 end;",
                    "if not tmp[cv] then ip=ip+1 else ip=t end;",
                ),
                ("tmp[dstc(q[2])]=rv(q[3]);", "local w1=dstc(q[2]);tmp[w1]=rv(q[3]);"),
                (
                    "local v=rv(q[3]);tmp[dstc(q[2])]=",
                    "local v=rv(q[3]);local w2=dstc(q[2]);tmp[w2]=",
                ),
                ("tmp[dstc(q[2])]={};", "local w3=dstc(q[2]);tmp[w3]={};"),
                ("tmp[dv]=f(U(ag,1,nargs));", "local w4=f(U(ag,1,nargs));tmp[dv]=w4;"),
                ("tmp[dv]=f(U(t,1,m));", "local w5=f(U(t,1,m));tmp[dv]=w5;"),
                (
                    "tmp[dv]=f(Z(U(ag,1,nargs)));",
                    "local w6=f(Z(U(ag,1,nargs)));tmp[dv]=w6;",
                ),
                ("ag[i]=rv(q[5+i])", "local w7=rv(q[5+i]);ag[i]=w7"),
                ("ip=tgtc(q[2]);", "local w8=tgtc(q[2]);ip=w8;"),
                (
                    "local cv,t=dstc(q[2]),tgtc(q[3]);",
                    "local cv=dstc(q[2]);local t=tgtc(q[3]);",
                ),
                ("expect=expect or 0;", "local w9=expect or 0;expect=w9;"),
                ("return rv(q[3]),a;", "local w10=rv(q[3]);return w10,a;"),
                (
                    "return rv(q[3]),rv(q[4]),rv(q[5]),a;",
                    "local w11=rv(q[3]);return w11,rv(q[4]),rv(q[5]),a;",
                ),
                (
                    "R[RX(stix(si))]=rv(q[3]);",
                    "local w12=RX(stix(si));R[w12]=rv(q[3]);",
                ),
                (
                    "tmp[dstc(q[2])]=R[RX(stix(li))];",
                    "local w13=dstc(q[2]);tmp[w13]=R[RX(stix(li))];",
                ),
                (
                    "tmp[dstc(q[2])]=rv(q[3])[rv(q[4])];",
                    "local w14=dstc(q[2]);tmp[w14]=rv(q[3])[rv(q[4])];",
                ),
                (
                    "rv(q[2])[rv(q[3])]=rv(q[4]);",
                    "local w15=rv(q[2]);w15[rv(q[3])]=rv(q[4]);",
                ),
            ] {
                let canon_n = body.matches(canon).count();
                let variant_n = body.matches(variant).count();
                assert!(
                    (canon_n == 1 && variant_n == 0) || (canon_n == 0 && variant_n == 1),
                    "P5: neither-or-both canon={canon_n} variant={variant_n} seed={seed} {canon:?}"
                );
            }
            for n in 1..=15u32 {
                let defs = body.matches(&format!("local w{n}=")).count();
                assert!(defs <= 1, "P5: temp w{n} defined {defs}x seed={seed}");
            }
        }
    }
}
