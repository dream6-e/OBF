// Split out of `semantic.rs` (2026-09-14, goal-3 batch): the seed-arm
// emission locks below pushed that file past the project's 80 KiB
// source-file ceiling. `include!` splices every `tests/*.rs` into one module,
// so the shared fixture and all helpers stay in scope unchanged.

const SEED_CONTROL_FIXTURE: &str = "local function f(x)if x>0 then return x*2 else return 0-x end end;local r=0;local i=0;while i<5 do r=r+f(i-2);i=i+1 end;print(r)";

#[test]
fn seed_v1_arms_emit_for_all_supported_ops_on_both_targets() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(SEED_CONTROL_FIXTURE, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 735, u64::MAX] {
            let raw = generate(&data, &program, seed).unwrap();
            // SEED is an H-local closing over R/RX/K plus the top-level
            // pools; the loop appears exactly once, inside H.
            assert_eq!(
                raw.matches("local SEED=function(prog,site,expect)").count(),
                1,
                "{target} seed {seed}: loop must appear exactly once"
            );
            assert!(
                raw.find("local STAB=").unwrap() < raw.find("local SEED=function").unwrap(),
                "{target} seed {seed}: STAB must precede the loop for upvalue scope"
            );
            assert!(
                raw.find("local SEEDH=").unwrap() < raw.find("local SEED=function").unwrap(),
                "{target} seed {seed}: SEEDH must precede the loop for upvalue scope"
            );
            assert!(
                raw.find("H=function(fid,args,ups)").unwrap()
                    < raw.find("local SEED=function").unwrap(),
                "{target} seed {seed}: loop must sit inside H for H-local scope"
            );
            assert!(
                raw.contains("local F,R,va,RX,RF,K;"),
                "{target} seed {seed}: H must hoist frame locals for SEED"
            );
            assert!(
                raw.contains("K=F.__obf_proto_k;"),
                "{target} seed {seed}: H must derive K per activation"
            );
            assert!(
                raw.contains("local SEEDT={"),
                "{target} seed {seed}: routine table missing"
            );
            // P6: helper pool emits in permuted order; pin the perm prefix.
            let seedh_perm = seed_deform::p6_seedh_perm(seed, SEEDH_NAMES.len());
            let mut seedh_ordered = vec![""; SEEDH_NAMES.len()];
            for (ix, name) in SEEDH_NAMES.iter().enumerate() {
                seedh_ordered[seedh_perm[ix]] = name;
            }
            let seedh_prefix = format!("local SEEDH={{{},", seedh_ordered[..3].join(","));
            assert!(
                raw.contains(&seedh_prefix),
                "{target} seed {seed}: helper pool missing"
            );
            // Slim arms: frame state arrives via H-locals, the expected
            // action rides as the trailing argument.
            // P6: arm sites permute; pin width + permuted content.
            let jump_site = seed_deform::p6_permute_site("{0,0,0,0,j,skip1,pc}", seed);
            assert!(
                raw.contains(&format!("pc=SEED(SEEDT[45],{jump_site},1);")),
                "{target} seed {seed}: jump arm missing"
            );
            assert!(
                raw.contains(&seed_arm_lua_for(target, Opcode::Test, seed).unwrap()),
                "{target} seed {seed}: test arm missing"
            );
            // K13b: the return arm hands its value through the per-prototype
            // frame-release helper, which drops the activation count and
            // re-locks the words once the prototype goes idle. The wrapper is
            // part of the arm contract: dropping it must fail this pin.
            assert!(
                raw.contains("return LVE(fid,SEED(SEEDT[47],{a},2));"),
                "{target} seed {seed}: return arm missing"
            );
            let abc_site = seed_deform::p6_permute_site("{a,b,c}", seed);
            assert!(
                raw.contains(&format!("SEED(SEEDT[23],{abc_site});")),
                "{target} seed {seed}: default arms missing"
            );
            assert!(
                raw.contains(&format!("SEED(SEEDT[25],{abc_site});")),
                "{target} seed {seed}: default arms missing"
            );
            // SEED returns value-first, so the Test arm binds `local av,act`
            // (its actions branch control flow). The old `local act,av` order
            // silently swaps value/action and must never reappear; every
            // `local av,act` arm must be Test (op 45, slot SEEDT[46]).
            assert!(
                !raw.contains("local act,av=SEED("),
                "{target} seed {seed}: swapped test-arm order survived"
            );
            let fat = raw
                .match_indices("local av,act=SEED(")
                .filter(|(pos, _)| !raw[*pos..].starts_with("local av,act=SEED(SEEDT[46],"))
                .count();
            assert!(fat == 0, "{target} seed {seed}: fat arms survived");
        }
    }
}

const SEED_TAILCALL_FIXTURE: &str =
    "local function f(n) if n==0 then return 0 end return f(n-1) end print(f(10))";

#[test]
fn seed_tailcall_arm_binds_value_first_with_short_return_guard() {
    // TailCall is op 47 (slot SEEDT[48]). Its routine returns either 4
    // values (tailenter) or 2 (immediate value); the arm's `act or v2`
    // guard recovers the action on the short path (regression: without it
    // act binds nil and every immediate tailcall raises).
    for target in [Target::Lua51, Target::Luau] {
        for dseed in [735u64, 7001, 1, u64::MAX] {
            let arm = seed_arm_lua_for(target, Opcode::TailCall, dseed).unwrap();
            let data = compile(SEED_TAILCALL_FIXTURE, target).unwrap();
            let program = custom::decode(&data, target).unwrap();
            let raw = generate(&data, &program, dseed).unwrap();
            assert!(
                raw.contains(&arm),
                "{target} seed {dseed}: tailcall arm missing or reshaped"
            );
            let output = finalize(&raw, target, dseed).unwrap();
            let work = native::Workspace::new();
            let path = work.0.join("seed_tailcall.lua");
            fs::write(&path, output).unwrap();
            assert_eq!(native::compile_and_run(target, &path), b"0\n");
        }
    }
}

const SEED_V1_RESIDUE_SHARED: &[(Opcode, &str)] = &[
    (Opcode::Move, "R[RX(a)]=R[RX(b)];"),
    (Opcode::Constant, "R[RX(a)]=F.__obf_proto_k[k];"),
    (Opcode::Nil, "R[RX(a)]=nil;"),
    (Opcode::NewCell, "R[RX(a)]={R[RX(b)]};"),
    (Opcode::ReadCell, "R[RX(a)]=CV(R[RX(b)]);"),
    (Opcode::WriteCell, "SV(R[RX(a)],R[RX(b)]);"),
    (Opcode::ReadUpvalue, "R[RX(a)]=CV(ups[b]);"),
    (Opcode::WriteUpvalue, "SV(ups[b],R[RX(a)]);"),
    (Opcode::ReadGlobal, "R[RX(a)]=G[F.__obf_proto_k[k]];"),
    (Opcode::WriteGlobal, "G[F.__obf_proto_k[k]]=R[RX(a)];"),
    (Opcode::NewTable, "R[RX(a)]={};"),
    (Opcode::GetTable, "R[RX(a)]=R[RX(b)][R[RX(c)]];"),
    (Opcode::SetTable, "R[RX(a)][R[RX(b)]]=R[RX(c)];"),
    (Opcode::Method, "R[RX(a)]=Lookup(R[RX(b)],R[RX(c)]);"),
    (Opcode::NewPack, "R[RX(a)]={n=0};"),
    (Opcode::Push, "local v=R[RX(a)];v.n=v.n+1;v[v.n]=R[RX(b)];"),
    (
        Opcode::Extend,
        "local v,x=R[RX(a)],R[RX(b)];local n=v.n;for j=1,x.n do v[n+j]=x[j]end;v.n=n+x.n;",
    ),
    (Opcode::Extract, "R[RX(a)]=R[RX(b)][c];"),
    (Opcode::Varargs, "R[RX(a)]=va;"),
    (Opcode::Call, "R[RX(a)]=Call(R[RX(b)],R[RX(c)]);"),
    (
        Opcode::Closure,
        "local child=P[k];local up={};for j=0,child.__obf_proto_nu-1 do local d=child.__obf_proto_u[j];if d[1]~=1 then up[j]=R[RX(d[2])]else up[j]=ups[d[2]]end end;R[RX(a)]=Make(k,up);",
    ),
    (Opcode::Clear, "for j=a,b do R[RX(j)]=nil end;"),
    (Opcode::Add, "R[RX(a)]=R[RX(b)]+R[RX(c)];"),
    (Opcode::Subtract, "R[RX(a)]=R[RX(b)]-R[RX(c)];"),
    (Opcode::Multiply, "R[RX(a)]=R[RX(b)]*R[RX(c)];"),
    (Opcode::Divide, "R[RX(a)]=R[RX(b)]/R[RX(c)];"),
    (Opcode::Modulo, "R[RX(a)]=R[RX(b)]%R[RX(c)];"),
    (Opcode::Power, "R[RX(a)]=R[RX(b)]^R[RX(c)];"),
    (Opcode::Concat, "R[RX(a)]=R[RX(b)]..R[RX(c)];"),
    (Opcode::Equal, "R[RX(a)]=R[RX(b)]==R[RX(c)];"),
    (Opcode::Less, "R[RX(a)]=R[RX(b)]<R[RX(c)];"),
    (Opcode::LessEqual, "R[RX(a)]=R[RX(b)]<=R[RX(c)];"),
    (Opcode::Not, "R[RX(a)]=not R[RX(b)];"),
    (Opcode::Negate, "R[RX(a)]=-R[RX(b)];"),
    (Opcode::Length, "R[RX(a)]=#R[RX(b)];"),
    (Opcode::NumberStep, "R[RX(a)]=R[RX(a)]+R[RX(a+2)];"),
    (
        Opcode::NumberTest,
        "local v,n,s=R[RX(b)],R[RX(b+1)],R[RX(b+2)];if s>0 then R[RX(a)]=v<=n else R[RX(a)]=v>=n end;",
    ),
    (
        Opcode::IteratorNext,
        "local it=R[RX(b)];local v=Call(it[1],{n=2,it[2],it[3]});it[3]=v[1];R[RX(a)]=v;",
    ),
    (
        Opcode::SetList,
        "local v=R[RX(b)];local start=R[RX(c)];for j=1,v.n do R[RX(a)][start+j-1]=v[j]end;",
    ),
    (Opcode::ToString, "R[RX(a)]=TS(R[RX(b)]);"),
    (Opcode::Return, "return R[RX(a)];"),
    (
        Opcode::TailCall,
        "local fn,ar=R[RX(a)],R[RX(b)];local d=W[fn];if d then fid=d[1];args=ar;ups=d[2];break else return Z(fn(U(ar,1,ar.n)))end;",
    ),
];

const SEED_V1_RESIDUE_LUA51: &[(Opcode, &str)] = &[
    (
        Opcode::NumberPrepare,
        "local v,n,s=TN(R[RX(a)]),TN(R[RX(a+1)]),TN(R[RX(a+2)]);if v==nil or n==nil or s==nil then E()end;R[RX(a)]=v;R[RX(a+1)]=n;R[RX(a+2)]=s;R[RX(a)]=v-s;",
    ),
    (Opcode::IteratorPrepare, "R[RX(a)].n=3;"),
];

const SEED_V1_RESIDUE_LUAU: &[(Opcode, &str)] = &[
    (
        Opcode::NumberPrepare,
        "local v,n,s=TN(R[RX(a)]),TN(R[RX(a+1)]),TN(R[RX(a+2)]);if v==nil or n==nil or s==nil then E()end;R[RX(a)]=v;R[RX(a+1)]=n;R[RX(a+2)]=s;",
    ),
    (
        Opcode::IteratorPrepare,
        "local ar=R[RX(a)];local v=ar[1];if TY(v)~='function'then local mt=MT(v);if mt~=nil and TY(mt)~='table'then E()end;local it=mt and RG(mt,'__iter');if it~=nil then ar=Z(it(v));if ar[1]==nil then E()end elseif mt and RG(mt,'__call')~=nil then elseif TY(v)=='table'then ar={n=3,NX,v}else E()end end;ar.n=3;R[RX(a)]=ar;",
    ),
    (Opcode::FloorDivide, "R[RX(a)]=R[RX(b)]//R[RX(c)];"),
    (
        Opcode::Export,
        "local cell=R[RX(a)];R[RX(b)][R[RX(c)]]=cell[1];cell[1]=nil;cell[2]=R[RX(b)];cell[3]=R[RX(c)];",
    ),
    (Opcode::Freeze, "Freeze(R[RX(a)]);"),
];

#[test]
fn seed_v1_migration_leaves_no_classic_handler_text() {
    let corpora = [
        (
            Target::Lua51,
            include_str!("../../../../tests/fixtures/vm_lua51.lua"),
            include_str!("../../../../tests/fixtures/scope_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../../tests/fixtures/vm_luau.lua"),
            include_str!("../../../../tests/fixtures/scope_luau.lua"),
        ),
    ];
    for (target, vm_fixture, scope_fixture) in corpora {
        let mut pins: Vec<&str> = SEED_V1_RESIDUE_SHARED.iter().map(|(_, pin)| *pin).collect();
        pins.extend(
            (if target.is_luau() {
                SEED_V1_RESIDUE_LUAU
            } else {
                SEED_V1_RESIDUE_LUA51
            })
            .iter()
            .map(|(_, pin)| *pin),
        );
        pins.extend(["pc=j;", "then pc=skip1 end", "__obf_fl", "__obf_fv"]);
        for seed in [735u64, u64::MAX] {
            let mut combined = String::new();
            for fixture in [vm_fixture, scope_fixture] {
                let data = compile(fixture, target).unwrap();
                let program = custom::decode(&data, target).unwrap();
                combined.push_str(&generate(&data, &program, seed).unwrap());
            }
            for pin in &pins {
                assert!(
                    !combined.contains(pin),
                    "{target} seed {seed}: classic handler text survived: {pin}"
                );
            }
        }
    }
}
