// K9/K12 operand-lane tests: the per-record affine lane keys, the ISA16
// chain recurrence that feeds decoded record state into them, and the private
// wire version pin. Split out of `tests/semantic.rs` for the 81,920 B source
// ceiling; `include!` keeps the shared test module scope.

#[test]
fn k9_affine_lanes_round_trip_for_all_forms_and_contexts() {
    let bytes = compile("return 1", Target::Lua51).unwrap();
    let program = custom::decode(&bytes, Target::Lua51).unwrap();
    let image = super::semantic::encode(&program, 0x9_0009).unwrap();
    let multipliers = [1u32, 3, 5, 7, 9, 11, 13, 15];
    for token in [0u16, 1, 257, 65535] {
        for prototype in [0u16, 1, 31, 4095] {
            for lane in 0..3u32 {
                let index = super::semantic::k9_index(token, prototype, lane, image.mask_salt);
                assert_eq!(multipliers[index] % 2, 1);
                for value in [0usize, 1, 127, 128, 255] {
                    for chain in [0u32, 1, 4095, super::semantic::K9_CHAIN_MOD - 1] {
                        let wire = super::semantic::k9_affine(
                            value, token, prototype, lane, &image, chain, 256,
                        );
                        let inverse = [1u32, 171, 205, 183, 57, 163, 197, 239][index];
                        let add =
                            super::semantic::k9_add(token, prototype, lane, image.mask_add, chain, 256);
                        assert_eq!(((wire + 256 - add) % 256) * inverse % 256, value as u32);
                    }
                }
            }
        }
    }
}

#[test]
fn wire_isa_version_is_18() {
    assert_eq!(
        super::semantic::WIRE_ISA_VERSION,
        18,
        "K3-FULL requires ISA18: the recipe dictionary now carries the renumbered \
         opcode plus the operand form as a byte pair, so the reader contract changed \
         (the generated parser rebuilds neither a form table nor a permutation table). \
         K13c step 2's ISA17 requirement -- keyed constant payloads, no plaintext \
         constants in the image -- still holds underneath it"
    );
}

// K12/T1: the operand lane key must eat the decoded record prefix, so the
// recovery of record r is not expressible without records 0..r-1. These gates
// pin (a) the recurrence is order-sensitive and never collapses, (b) the
// doubles stay inside the exact-integer bound the emitted toolbox assumes, and
// (c) the Lua parser replays exactly the Rust constants -- drift between the
// two sides is the failure mode, not the arithmetic itself.
#[test]
fn operand_lane_chain_is_order_dependent_and_double_exact() {
    use super::semantic::{
        k9_chain_init, k9_chain_next, K9_CHAIN_MOD, K9_CHAIN_MUL, K9_CHAIN_STEP_MUL,
        K9_CHAIN_TOKEN_MUL, K9_INIT_PROTO_MUL, K9_INIT_ROUTE_MUL, K9_INIT_START_MUL,
    };
    // Same tokens, different order => different tail states (non-commutative).
    let run = |salt: u16, tokens: &[u16]| -> Vec<u32> {
        let mut st = k9_chain_init(3, 7, 11, salt);
        tokens
            .iter()
            .enumerate()
            .map(|(at, &t)| {
                st = k9_chain_next(st, t, at as u32, salt);
                st
            })
            .collect()
    };
    let tokens = [1u16, 7, 4099, 65_535, 2, 3];
    let mut swapped = tokens;
    swapped.swap(1, 4);
    let a = run(9, &tokens);
    let b = run(9, &swapped);
    assert_ne!(a, b, "lane chain must depend on record order");
    assert!(
        a.windows(2).all(|w| w[0] != w[1]) && a.iter().all(|&v| v < K9_CHAIN_MOD),
        "lane chain collapsed: {a:?}"
    );
    // Salt and prototype/route/start seeds all move the chain.
    assert_ne!(a, run(10, &tokens), "salt must enter the chain");
    assert_ne!(
        k9_chain_init(0, 7, 11, 9),
        k9_chain_init(1, 7, 11, 9),
        "prototype id must seed the chain"
    );
    assert_ne!(
        k9_chain_init(0, 8, 11, 9),
        k9_chain_init(0, 7, 11, 9),
        "route count must seed the chain"
    );
    assert_ne!(
        k9_chain_init(0, 7, 12, 9),
        k9_chain_init(0, 7, 11, 9),
        "entry label must seed the chain"
    );
    // Exact-integer bound: the emitted Lua computes the same recurrence with
    // doubles, so the largest intermediate must stay below 2^53.
    let worst = u64::from(K9_CHAIN_MOD - 1) * u64::from(K9_CHAIN_MUL)
        + u64::from(u16::MAX) * u64::from(K9_CHAIN_TOKEN_MUL)
        + 1_048_576 * u64::from(K9_CHAIN_STEP_MUL)
        + u64::from(u16::MAX);
    assert!(worst < 1 << 53, "lane chain exceeds the double exact range: {worst}");
    assert_eq!(K9_CHAIN_MOD % 2, 1, "modulus must be odd");
}

// Drift lock: every constant in the emitted recurrence has to equal the Rust
// constant, and the operand decode has to feed the chain state to AK.

#[test]
fn emitted_runtime_replays_the_operand_lane_chain() {
    use super::semantic::{
        K9_CHAIN_MUL, K9_CHAIN_STEP_MUL, K9_CHAIN_TOKEN_MUL, K9_INIT_PROTO_MUL, K9_INIT_ROUTE_MUL,
        K9_INIT_START_MUL,
    };
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("local t={} for i=1,4 do t[i]=i*3 end print(#t,t[4])", target).unwrap();
        let output = emit(&data, target, 7001).unwrap();
        // The finalizer renames every safe local (stL/AK included) and drops
        // optional semicolons, so the lock uses the numeric shape only: each
        // multiplier has exactly one site unless the recurrence drifted.
        for (fragment, count) in [
            (format!("*{K9_INIT_PROTO_MUL}+"), 1usize),
            (format!("*{K9_INIT_ROUTE_MUL}+"), 1),
            (format!("*{K9_INIT_START_MUL}+"), 1),
            (format!("*{K9_CHAIN_MUL}+"), 1),
            (format!("*{K9_CHAIN_TOKEN_MUL}+"), 1),
            (format!("*{K9_CHAIN_STEP_MUL}+"), 1),
        ] {
            assert_eq!(
                output.matches(fragment.as_str()).count(),
                count,
                "{target}: lane chain shape drifted at {fragment:?}"
            );
        }
        // AK must consume the chain state: its additive term has to close over
        // a reduction (`+<salt>+<state>%<mod>)`) before the parenthesis. Without
        // the fold the window ends immediately with no `%` at all.
        let ak = output.find("*193+").expect("AK lane multiplier term");
        let window = &output[ak..ak + 40];
        let upto = window.find(')').unwrap_or(window.len());
        assert!(
            window[..upto].contains('%'),
            "{target}: AK no longer folds the operand lane chain state"
        );
    }
}

// T4 (K13): the per-prototype instruction words must not exist in plaintext
// while the VM is idle. One shared decode routine `DC` is used twice: the load
// pass decodes+validates every prototype (so malformed images still fail closed
// before user code) and then releases the tables, keeping only the raw chained
// code string; the interpreter materializes a prototype's words on its first
// execution. Asserted on the raw (pre-finalizer) text, where locals keep their
// real names.
#[test]
fn prototype_code_words_are_decoded_lazily_and_released_after_validation() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(
            "local function never() return 42 end local function used(x) return x+1 end print(used(1))",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 7001, 7351, u64::MAX] {
            let raw = generate(&data, &program, seed).unwrap();
            assert_eq!(
                raw.matches("local DC=function(id)").count(),
                1,
                "{target} seed {seed}: decode routine duplicated"
            );
            // The short-circuit guard itself is rewritten into g-slots by the
            // slot pass, so pin the release pair instead: `P[id].__obf_proto_code
            // =SP[2]` must occur exactly twice (hand the raw string to DC, then
            // put it back after validation).
            assert_eq!(
                raw.matches("P[id].__obf_proto_code=SP[2]").count(),
                2,
                "{target} seed {seed}: validate-then-release pair missing"
            );
            assert_eq!(
                raw.matches("DC(id);").count(),
                1,
                "{target} seed {seed}: load pass must call DC once per prototype"
            );
            assert!(
                raw.contains("DC(id);P[id].__obf_proto_code=SP[2];P[id].__obf_proto_routes=nil;"),
                "{target} seed {seed}: load pass must release decoded words after validation"
            );
            assert!(
                raw.contains("if not code[0] then code=DC(fid) end"),
                "{target} seed {seed}: interpreter must decode lazily on first execution"
            );
            assert!(
                raw.contains("return RD,ED,OG,DC;"),
                "{target} seed {seed}: DC must be exported with the token helpers"
            );
        }
    }
}
// K13b (T4 step 2): decoded words must go back to sleep. Every frame
// activation charges LVC[fid]; the last exit for a prototype restores the raw
// chained bytes from the handle DC stashed at code[-1] and drops the route
// array again, so a heap dump taken while a prototype is idle shows no decoded
// words. Pins sit on the pre-finalizer text because the slot/literal passes
// rename these locals in the shipped script.
#[test]
fn prototype_words_relock_when_a_prototype_goes_idle() {
    for target in [Target::Lua51, Target::Luau] {
        // The probe program needs a real tail call (`return g(y)`) so the
        // tail re-entry arm is emitted at all.
        let data = compile(
            "local function g(x) return x end local function f(y) return g(y) end print(f(1))",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 7001, 7351, u64::MAX] {
            let raw = generate(&data, &program, seed).unwrap();
            // One activation counter and one release helper per interpreter.
            assert_eq!(
                raw.matches("local LVC={};local LVE=function(f,v)").count(),
                1,
                "{target} seed {seed}: activation counter duplicated"
            );
            assert!(
                raw.contains(
                    // K13c step 2: the frame's decoded constants are released
                    // with its code, so a re-lock rebuilds them from the keyed
                    // region instead of reading a resident table.
                    "if C[-1]then G.__obf_proto_code=C[-1];G.__obf_proto_routes=nil;G.__obf_proto_k=nil;G.__obf_proto_tags=nil end"
                ),
                "{target} seed {seed}: release must restore the raw bytes and drop the routes"
            );
            // DC mints one re-lock handle per decoded prototype, and the helper
            // holds the only two other `[-1]` uses (test + restore). The g-slot
            // pass rewrites CD into a seed-dependent slot, so pin the mint by
            // its literal left side and count the handles overall.
            assert_eq!(
                raw.matches("code[0]=start;code[-1]").count(),
                1,
                "{target} seed {seed}: re-lock handle must be minted once per decode"
            );
            assert_eq!(
                raw.matches("[-1]").count(),
                3,
                "{target} seed {seed}: re-lock handle needs exactly one mint and two uses"
            );
            assert_eq!(
                raw.matches("LVC[fid]=(LVC[fid] or 0)+1;").count(),
                1,
                "{target} seed {seed}: frame must be charged exactly once per activation"
            );
            // Both frame exits route through the helper: the value-carrying
            // Return arm and the host-side tail-call return.
            assert!(
                raw.matches("return LVE(fid,SEED(SEEDT[").count() >= 1,
                "{target} seed {seed}: Return arm must release before leaving H"
            );
            // Exactly one of the two flipped tail spellings is emitted, and it
            // must release the *outgoing* fid before `fid` is rebound.
            assert_eq!(
                raw.matches("LVE(fid,nil);fid,args,ups=v1,v2,v3;break;").count(),
                1,
                "{target} seed {seed}: tail re-entry must release the outgoing frame"
            );
            // Drift lock for the accounting bug this shape avoids: the tail path
            // rebinds `fid` before breaking, so a release parked after the
            // dispatch loop would charge the callee and leak the caller.
            assert_eq!(
                raw.matches("end;LVE(fid,nil);end;").count(),
                0,
                "{target} seed {seed}: release must not sit at the dispatch-loop tail"
            );
        }
    }
}

// K14: the load-time operand validator dispatches through a seeded binary
// search tree inside each residue bucket instead of one flat `if/elseif` scan.
// Pinned on the pre-finalizer text (the slot pass renames `ok` away in the
// shipped script, so the arms are counted through their ` then g[` slot write).
// Three properties matter: no arm may be dropped or duplicated by the
// restructuring, every node side must bottom out in a fail-closed leaf chain,
// and the topology has to move with the seed -- a fixed tree would be a chain
// with extra steps.
// K13c step 2 (keyed constant pool): the pool walk no longer decodes anything.
// It records `(tag, off, len, key)` per slot -- byte coordinates inside the
// retained keyed region plus the stream position that record's payload was
// keyed at -- hands those coordinates to the owning prototype, and copies the
// *still keyed* region out of the image. `DC` is the only reader that turns a
// record into a value, and the values are dropped again by the load pass and by
// `LVE`, so a constant is never resident outside a materialized frame. Pinned
// on the pre-finalizer text, where the pool locals are slot-rewritten but the
// arithmetic is literal.
//
// The last assertion is not cosmetics: `PK` is compiled as a local function in
// the stage-definition block, so the region bookkeeping must be declared
// *before* those definitions. Declaring it next to the state variable instead
// leaves `KLen` resolving to a global nil inside `PK`, which aborts the script
// with "attempt to compare nil with number" at the first record.
#[test]
fn constant_pool_mirror_holds_coordinates_not_values() {
    for target in [Target::Lua51, Target::Luau] {
        let data = compile(
            "local x=1;local y='s';local q=0.5;local function f()return x end print(f(),y,q)",
            target,
        )
        .unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 7001, 7351, u64::MAX] {
            let raw = generate(&data, &program, seed).unwrap();
            for marker in [
                "KBase=pos();gk=0;",
                "KLen=pos()-KBase;",
                "T[ix]={tg,ko,kl,ka}",
                "__obf_proto_rec=TT",
                "KImg=SS(B,KBase,KBase+KLen-1)",
                "if tg>5 or rec[2]+rec[3]>KLen or rec[4]==nil then E()end",
                "local off,ln,ak=rec[2],rec[3],rec[4]",
                "val=NU(UK(Q,off+1,8,ak),1)",
                "local k=(acc+119)%256;",
                "local KBase,gk,KLen,KImg=1,0,0,nil;",
            ] {
                assert_eq!(
                    raw.matches(marker).count(),
                    1,
                    "{target} seed {seed}: pool plumbing marker {marker:?} appears {} times",
                    raw.matches(marker).count()
                );
            }
            // No decoded value survives in the mirror itself.
            for stale in [
                "T[ix]={tg,val}",
                "T[ix]={tg,ko,pos()-KBase-ko}",
                "OW.__obf_proto_k[ix]=val",
                "OW.__obf_proto_tags[ix]=tg",
                "local val=rec[2]",
                "F.__obf_proto_k[j]=val",
                // The pool walk must not decode: `str`/`num` belong to the
                // record readers elsewhere, never to the constant loop.
                "elseif tg==2 then val=num()",
                "tg==3 or tg==5 then val=str()",
            ] {
                assert_eq!(
                    raw.matches(stale).count(),
                    0,
                    "{target} seed {seed}: constant mirror still holds values ({stale:?})"
                );
            }
            let declared = raw
                .find("local KBase,gk,KLen,KImg=1,0,0,nil;")
                .unwrap();
            let closed_over = raw.find("local PK=function").unwrap();
            assert!(
                declared < closed_over,
                "{target} seed {seed}: region bookkeeping declared after the stage that closes over it"
            );
        }
    }
}

// K13c step 2 (the actual hardening): the durable image must not carry a
// constant payload in plaintext. Before this step every string/number/boolean
// sat in the pool section as its own bytes; now only the keyed region does, so
// an image-only attacker (the threat model of the external T4 finding) gets the
// record *extents* -- which the reader needs to walk -- and nothing else.
//
// The paired text assertion is the anti-drift lock: `NU` (used by `DC`) and
// `fin` (used by the record readers) must be the same bit-exact double
// rebuild, so a constant decoded from the region cannot differ from one decoded
// through the image cursor. Subnormals, NaN, +-inf and -0.0 all ride on that
// equality; neither side is allowed to reassemble a double arithmetically.
#[test]
fn constant_payloads_are_not_plaintext_in_the_image() {
    const NEEDLES: [&str; 4] = ["needle-alpha", "needle-beta-constant", "gamma-string", "delta"];
    for target in [Target::Lua51, Target::Luau] {
        let source = format!(
            "local a,b,c,d={};print(a,b,c,{})",
            NEEDLES
                .iter()
                .map(|s| format!("{s:?}"))
                .collect::<Vec<_>>()
                .join(","),
            if target.is_luau() { "3" } else { "3.0" }
        );
        let data = compile(&source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [0u64, 7001, 7351, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            assert!(
                image.bytes.len() > 64,
                "{target} seed {seed}: empty image makes this check vacuous"
            );
            for needle in NEEDLES {
                let bytes = needle.as_bytes();
                assert!(
                    !image.bytes.windows(bytes.len()).any(|w| w == bytes),
                    "{target} seed {seed}: constant {needle:?} is still plaintext in the image"
                );
            }
            let raw = generate(&data, &program, seed).unwrap();
            let shared = "(1+fr/4503599627370496)*2^(ex-1023)";
            assert_eq!(
                raw.matches(shared).count(),
                2,
                "{target} seed {seed}: the region reader must reuse the cursor reader's \
                 exact `fin` arithmetic (one in `fin`, one in `NU`)"
            );
        }
    }
}

#[test]
fn validator_dispatch_is_a_seeded_binary_search_tree() {
    for (target, file, arms_expected) in [
        (Target::Lua51, "tests/fixtures/vm_lua51.lua", 48usize),
        (Target::Luau, "tests/fixtures/vm_luau.lua", 51usize),
    ] {
        let source =
            fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file))
                .unwrap();
        let data = compile(&source, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let mut shapes = std::collections::BTreeSet::new();
        for seed in [0u64, 7001, 7351, u64::MAX] {
            let raw = generate(&data, &program, seed).unwrap();
            let head = "function(o,a,b,c,j,k,at,F,P,id)";
            let start = raw.find(head).expect("{target}: validator field missing") + head.len();
            let body = &raw[start..start + raw[start..].find(";return true").expect("validator tail")];
            // One arm == one equality test with exactly one predicate write.
            let arms = body.matches(" then g[").count();
            let nodes = body.matches(" then if ").count();
            let leaves = body.matches(" else E()end;").count();
            assert_eq!(
                arms, arms_expected,
                "{target} seed {seed}: validator arms changed shape or count"
            );
            assert!(
                nodes >= 20 && leaves >= nodes,
                "{target} seed {seed}: expected a search tree over {arms} arms, got {nodes} nodes / {leaves} fail-closed leaves"
            );
            assert!(
                body.matches("E()").count() >= leaves,
                "{target} seed {seed}: a tree path without E() would accept malformed operands"
            );
            shapes.insert((nodes, leaves));
        }
        assert!(
            shapes.len() >= 2,
            "{target}: dispatch topology is seed-independent: {shapes:?}"
        );
    }
}

