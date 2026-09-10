// K7 gates: per-target polymorphic word layer + modulus diversification.
//
// Preservation gates (green before and after: K7 is runtime-only, the wire
// image is frozen) and RED->GREEN gates (fail until the toolbox lands).
// The vector-execution harness (real lua5.1/luau over every variant) lives
// at the bottom; it is added together with the emitter.

const K7_PROBE: &str = "local function f(x)return x+3 end print(f(4),f(9))";

/// FNV-1a/64 over bytes (dependency-free image fingerprint).
fn k7_fnv(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn k7_raw(target: Target, seed: u64) -> String {
    let data = compile(K7_PROBE, target).unwrap();
    let program = custom::decode(&data, target).unwrap();
    generate(&data, &program, seed).unwrap()
}

/// True when `text` holds an opaque-split modulus `%(digits+digits)`.
fn k7_has_opaque_modulus(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i] == b'%' && bytes[i + 1] == b'(' {
            let mut j = i + 2;
            let digits0 = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > digits0 && j < bytes.len() && bytes[j] == b'+' {
                j += 1;
                let digits1 = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if j > digits1 && j < bytes.len() && bytes[j] == b')' {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

// K7 changes helper BODIES only: the semantic wire image for fixed
// program/seeds is pinned (observed pre-K7) and must never move.
#[test]
fn k7_wire_image_bytes_are_frozen() {
    for (target, seed, len, hash) in [
        (Target::Lua51, 7001u64, 1159usize, 0x943c3c67c2b2e2ceu64),
        (Target::Luau, 7351u64, 882usize, 0xf2697760790f4e9eu64),
    ] {
        let data = compile(K7_PROBE, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let image = semantic::encode(&program, seed).unwrap();
        assert_eq!(image.bytes.len(), len, "{target} seed {seed}: image length moved");
        assert_eq!(
            k7_fnv(&image.bytes),
            hash,
            "{target} seed {seed}: image bytes moved"
        );
    }
}

// The bit32/buffer method names join the hidden-name pool: a spelled
// occurrence anywhere in the final output is a static anchor (T7). The list
// also carries the reflection names the Luau key probe used to append as a
// string literal (2026-09-10 regression), and the gate runs over both fixed
// goldens too - the template text is what ships, so auditing only the probe
// program would let a literal slip through on the fixture path.
#[test]
fn k7_bit_library_names_are_never_spelled() {
    const WORDS: [&str; 18] = [
        "bit32", "buffer", "bxor", "band", "bor", "bnot", "lrotate", "lshift", "rshift",
        "create", "writeu8", "readu8", "fromstring", "readu32", "table.freeze", "debug.info",
        "getinfo", "loadstring",
    ];
    for (target, golden_path) in [
        (Target::Lua51, concat!(env!("CARGO_MANIFEST_DIR"), "/vm_lua51.out.lua")),
        (Target::Luau, concat!(env!("CARGO_MANIFEST_DIR"), "/vm_luau.out.lua")),
    ] {
        let data = compile(K7_PROBE, target).unwrap();
        let output = emit(&data, target, 4242).unwrap();
        let golden = std::fs::read_to_string(golden_path).unwrap();
        for text in [&output, &golden] {
            for word in WORDS {
                assert!(!text.contains(word), "{target}: {word} spelled in output");
            }
            // The probe transcript is assembled from the hidden-name pool and
            // threaded in as a parameter; `A=A.."` would mean it is a literal.
            assert!(!text.contains("A=A..\""), "{target}: probe transcript is a literal");
        }
        // Luau joins the six pool names with "|" (five separators) exactly
        // once: one shared prelude local, not one copy per probe. Lua 5.1
        // folds only the debug-source field, so it assembles nothing here.
        let joins = golden.matches("..\"|\"..").count();
        assert_eq!(
            joins,
            if target.is_luau() { 5 } else { 0 },
            "{target}: assembled probe transcript moved ({joins} joins)"
        );
    }
}

// RED: the Luau prelude captures bit32 + buffer (libs and methods) through
// hidden names; the word section is threaded those captures.
#[test]
fn k7_luau_word_layer_uses_bit32_and_buffer_captures() {
    let raw = k7_raw(Target::Luau, 7351);
    assert!(
        raw.contains("local B32,BUF=G["),
        "luau prelude lost its bit32/buffer capture unit"
    );
    assert!(
        raw.contains("=function(MF,X8,X8C,BX,BA,BO,BN,LR,SHL,RS,BNE,BW8,BR8,BFS,BR3)"),
        "luau word section is not threaded the capture set"
    );
}

// RED: cold byte-xor closure exists next to the hot one (within-image
// multiplicity: two different X8 variants per image).
#[test]
fn k7_cold_byte_xor_closure_exists() {
    for target in [Target::Lua51, Target::Luau] {
        let raw = k7_raw(target, 7001);
        assert!(raw.contains("local X8="), "{target}: hot X8 gone");
        assert!(raw.contains("local X8C="), "{target}: cold X8C missing");
    }
}

// RED: dual xor/rotate closures with per-site draws in the quarter round.
#[test]
fn k7_dual_word_closures_exist() {
    for target in [Target::Lua51, Target::Luau] {
        let raw = k7_raw(target, 7001);
        assert!(
            raw.contains("CXa,CXb,CRa,CRb"),
            "{target}: dual word closures missing"
        );
    }
}

// RED: u32 modulus spellings mix literal and opaque-split forms per site.
#[test]
fn k7_u32_modulus_spellings_are_diversified() {
    for target in [Target::Lua51, Target::Luau] {
        let raw = k7_raw(target, 7001);
        assert!(
            raw.contains("%4294967296"),
            "{target}: literal modulus spelling gone (expected mixed)"
        );
        assert!(
            k7_has_opaque_modulus(&raw),
            "{target}: no opaque-split modulus spelling"
        );
    }
}

// Preservation: the hot inner-loop byte xor keeps the X8(SB(...)) call
// shape (only the closure body polymorphizes).
#[test]
fn k7_hot_stream_keeps_byte_xor_call_shape() {
    for target in [Target::Lua51, Target::Luau] {
        let raw = k7_raw(target, 7001);
        assert!(
            raw.contains("NCH(X8(X8(ct,y),prev))"),
            "{target}: hot stream call shape moved"
        );
    }
}


// --- emitter unit tests (no interpreter) ---

/// Digit runs inside rendered text (modulus addends use digit-only forms;
// the respeller only runs later at finalize).
fn k7_digit_runs(text: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut current = String::new();
    for byte in text.bytes().chain([b' ']) {
        if byte.is_ascii_digit() {
            current.push(byte as char);
        } else if !current.is_empty() {
            out.push(current.parse().unwrap());
            current.clear();
        }
    }
    out
}

/// 0 = bare literal, 1 = subtraction sandwich, 2 = explicit double modulus
/// (the double check runs first: its outer modulus is the bare literal).
fn k7_spelling_class(rendered: &str) -> u8 {
    if rendered.starts_with("((") {
        2
    } else if rendered.contains("%4294967296") {
        0
    } else {
        assert!(rendered.contains("%(("), "unknown modulus shape: {rendered}");
        1
    }
}

#[test]
fn k7_draws_cover_every_variant_and_spelling() {
    let mut rng = crate::random::Prng::new(0x6b37_6472_6177_7330);
    let mut seen_first = [0usize; 3];
    for _ in 0..300 {
        let (first, second) = draw_dual(&mut rng);
        seen_first[first] += 1;
        assert_ne!(first, second, "dual draw collapsed to one variant");
    }
    assert!(seen_first.iter().all(|&count| count >= 60), "{seen_first:?}");
    let mut spellings = [0usize; 3];
    for _ in 0..300 {
        spellings[k7_spelling_class(&render_addmod(&mut rng, "s+t")) as usize] += 1;
    }
    assert!(spellings.iter().all(|&count| count >= 60), "{spellings:?}");
    let mut atoms = [0usize; 2];
    for _ in 0..300 {
        atoms[usize::from(render_u32_atom(&mut rng) != "4294967296")] += 1;
    }
    assert!(atoms.iter().all(|&count| count >= 100), "{atoms:?}");
}

#[test]
fn k7_modulus_spellings_evaluate_to_u32() {
    let mut rng = crate::random::Prng::new(0x6b37_6d6f_6476_616c);
    let mut classes = [0usize; 3];
    for _ in 0..300 {
        // Digit-free sum: every digit run is a modulus literal.
        let rendered = render_addmod(&mut rng, "s+t");
        let runs = k7_digit_runs(&rendered);
        match k7_spelling_class(&rendered) {
            0 => assert_eq!(runs, vec![4294967296]),
            1 => {
                assert_eq!(runs.len(), 3, "sandwich shape moved: {rendered}");
                assert_eq!(runs[0] + runs[1] - runs[2], 4294967296);
                // The T7 acceptance letter: no noise pair sums to 2^32.
                assert_ne!(runs[0] + runs[1], 4294967296);
                assert_ne!(runs[0] + runs[2], 4294967296);
                assert_ne!(runs[1] + runs[2], 4294967296);
            }
            _ => {
                assert_eq!(runs.len(), 3, "double shape moved: {rendered}");
                assert_eq!(runs[0] + runs[1], 8589934592);
                assert_eq!(runs[2], 4294967296);
            }
        }
        classes[k7_spelling_class(&rendered) as usize] += 1;
        for run in &runs {
            if *run != 4294967296 {
                assert!(!is_nice_part(*run), "opaque addend hit nice: {run}");
            }
        }
    }
    assert!(classes.iter().all(|&count| count >= 60), "{classes:?}");
    for _ in 0..100 {
        let atom = render_u32_atom(&mut rng);
        let runs = k7_digit_runs(&atom);
        if runs == vec![4294967296] {
            continue;
        }
        assert_eq!(runs.len(), 3, "atom sandwich moved: {atom}");
        assert_eq!(runs[0] + runs[1] - runs[2], 4294967296);
        assert_ne!(runs[0] + runs[1], 4294967296);
        assert_ne!(runs[0] + runs[2], 4294967296);
        assert_ne!(runs[1] + runs[2], 4294967296);
        for run in &runs {
            assert!(!is_nice_part(*run), "atom addend hit nice: {run}");
        }
    }
}

#[test]
fn k7_divisors_are_powers_of_two() {
    // The T7 emitter lint: division in toolbox bodies is only ever by a
    // power of two (exact binary-point shift in doubles). `m`/`P`/`p` are
    // 16^j / 2^(32-n) by construction.
    const DIVISORS: [&str; 9] = [
        "2", "16", "256", "65536", "16777216", "m", "P", "p", "16^j",
    ];
    let names = BitNames::emit();
    let mut rng = crate::random::Prng::new(0x6b37_6469_7632_6c74);
    let mut bodies = Vec::new();
    for target in [Target::Lua51, Target::Luau] {
        for variant in 0..3 {
            let (pre, decl) = render_x8(target, variant, "F", &names);
            let (pre32, decl32) = render_x32(target, variant, "F", "t", &names, &mut rng);
            bodies.push(pre);
            bodies.push(decl);
            bodies.push(pre32);
            bodies.push(decl32);
            bodies.push(render_rot(target, variant, "F", &names, &mut rng));
            bodies.push(render_l32(target, variant, "F", &names, &mut rng));
        }
        bodies.push(render_word_section(target, 4242, &mut rng));
    }
    for body in &bodies {
        let bytes = body.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'/' {
                let mut j = i + 1;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                // `16^j` reads as divisor `16` plus exponent: accept the
                // caret form explicitly.
                if &body[i + 1..j] == "16" && bytes.get(j) == Some(&b'^') {
                    j += 2;
                }
                let divisor = &body[i + 1..j];
                assert!(
                    DIVISORS.contains(&divisor),
                    "non-power-of-two divisor /{divisor} in: {body}"
                );
                i = j;
            } else {
                i += 1;
            }
        }
    }
}

#[test]
fn k7_intermediates_stay_below_2p53() {
    const LIM: u64 = 1 << 53;
    // Widest KDF sum: 7 terms below 2^32.
    assert!(7 * (U32_MODULUS - 1) < LIM);
    // Frame check envelope: c*263 dominates (< 2^41 with siblings).
    assert!(297 * U32_MODULUS < LIM);
    // Attestation fold envelope: w*257 plus a byte.
    assert!(258 * U32_MODULUS < LIM);
    // Double-modulus operands and quotient (< 8: exact floor).
    assert!(U32_MODULUS < LIM);
    assert!(8 * 8589934592u64 > 7 * U32_MODULUS);
    // xor/rotate/load bodies never exceed u32.
    assert!(U32_MODULUS - 1 < LIM);
}

#[test]
fn k7_variant_bodies_render() {
    let names = BitNames::emit();
    let mut rng = crate::random::Prng::new(0x6b37_7265_6e64_6572);
    for target in [Target::Lua51, Target::Luau] {
        for variant in 0..3 {
            let (pre, decl) = render_x8(target, variant, "F", &names);
            assert!(decl.contains("return"));
            assert_eq!(target.is_luau() && variant == 1, !pre.is_empty());
            let (pre32, decl32) = render_x32(target, variant, "F", "t", &names, &mut rng);
            assert!(decl32.contains("return"));
            assert_eq!(target.is_luau() && variant == 1, !pre32.is_empty());
            assert!(render_rot(target, variant, "F", &names, &mut rng).contains("return"));
            assert!(render_l32(target, variant, "F", &names, &mut rng).contains("return"));
        }
        let section = render_word_section(target, 4242, &mut rng);
        assert!(section.contains("return Xa,Xb,Ra,Rb end,"));
    }
}

// --- real-interpreter vector harness (the T7 "699 assertions" equivalent:
// 100 vectors x 5 families x 3 variants = 1500 asserts per target) ---

struct K7Vectors {
    x8: Vec<(u8, u8)>,
    x32: Vec<(u32, u32)>,
    rot: Vec<(u32, u32)>,
    add: Vec<Vec<u32>>,
    l32: Vec<(Vec<u8>, usize)>,
}

fn k7_vectors() -> K7Vectors {
    let mut rng = crate::random::Prng::new(0x6b37_7636_6332_3031);
    let mut x8 = vec![
        (0, 0),
        (0, 255),
        (255, 0),
        (255, 255),
        (90, 165),
        (165, 90),
        (1, 1),
        (128, 128),
        (170, 85),
    ];
    while x8.len() < 100 {
        x8.push((rng.index(256) as u8, rng.index(256) as u8));
    }
    let edges32 = [
        0,
        1,
        255,
        256,
        65535,
        65536,
        16777215,
        16777216,
        2147483647,
        2147483648,
        4294967295,
    ];
    let mut x32: Vec<(u32, u32)> = edges32
        .iter()
        .zip(edges32.iter().rev())
        .map(|(&a, &b)| (a, b))
        .collect();
    x32.push((0x12345678, 0x01020304));
    while x32.len() < 100 {
        x32.push((rng.next_u64() as u32, rng.next_u64() as u32));
    }
    let mut rot: Vec<(u32, u32)> = Vec::new();
    for &x in &[0, 1, 4294967295, 2147483648, 0x12345678, 0x01020304] {
        for &n in &[1u32, 7, 8, 12, 16, 24, 31] {
            rot.push((x, n));
        }
    }
    while rot.len() < 100 {
        rot.push((rng.next_u64() as u32, 1 + rng.index(31) as u32));
    }
    let kat = [804192318u32, 505049583, 1123945486, 255, 4294967295, 2147483648];
    let mut add = Vec::new();
    while add.len() < 100 {
        let terms = 2 + rng.index(7);
        let mut words = Vec::new();
        for t in 0..terms {
            words.push(if t < 2 && !add.is_empty() {
                kat[(add.len() + t) % kat.len()]
            } else if rng.index(2) == 0 {
                kat[rng.index(kat.len())]
            } else {
                rng.next_u64() as u32
            });
        }
        add.push(words);
    }
    let mut l32 = vec![
        (vec![0, 0, 0, 0], 1usize),
        (vec![255, 255, 255, 255], 1),
        (vec![34, 92, 0, 255], 1),
        (vec![1, 2, 3, 4], 1),
    ];
    while l32.len() < 100 {
        let mut bytes = vec![rng.next_u64() as u32 as u8, rng.next_u64() as u32 as u8, rng.next_u64() as u32 as u8, rng.next_u64() as u32 as u8];
        let pad_before = rng.index(4);
        let mut padded = Vec::new();
        for _ in 0..pad_before {
            padded.push(rng.next_u64() as u32 as u8);
        }
        padded.append(&mut bytes);
        for _ in 0..rng.index(3) {
            padded.push(rng.next_u64() as u32 as u8);
        }
        l32.push((padded, pad_before + 1));
    }
    K7Vectors { x8, x32, rot, add, l32 }
}

#[test]
fn k7_toolbox_vectors_execute_on_real_interpreters() {
    let vectors = k7_vectors();
    let names = BitNames::emit();
    for target in [Target::Lua51, Target::Luau] {
        let mut rng = crate::random::Prng::new(0x6b37_6861_726e_6573);
        let mut chunk = String::from("local MF=math.floor;local SB=string.byte;");
        if target.is_luau() {
            chunk.push_str("local B32=bit32;local BUF=buffer;local BX=B32.bxor;local BA=B32.band;local BO=B32.bor;local BN=B32.bnot;local LR=B32.lrotate;local SHL=B32.lshift;local RS=B32.rshift;local BNE=BUF.create;local BW8=BUF.writeu8;local BR8=BUF.readu8;local BFS=BUF.fromstring;local BR3=BUF.readu32;");
        }
        for variant in 0..3 {
            let (pre, decl) = render_x8(target, variant, &format!("H8_{variant}"), &names);
            chunk.push_str(&pre);
            chunk.push_str(&decl);
        }
        // Shipped shape: the hot/cold closures are distinct variants; the
        // x32 table build runs at declaration time, hence after the alias.
        chunk.push_str("local X8=H8_0;local X8C=H8_2;");
        for variant in 0..3 {
            let tag = format!("h{variant}");
            let (pre32, decl32) =
                render_x32(target, variant, &format!("H32_{variant}"), &tag, &names, &mut rng);
            chunk.push_str(&pre32);
            chunk.push_str(&decl32);
            chunk.push_str(&render_rot(target, variant, &format!("HR_{variant}"), &names, &mut rng));
            chunk.push_str(&render_l32(target, variant, &format!("HL32_{variant}"), &names, &mut rng));
        }
        // NOTE: both Luau table variants share one prelude table name in
        // shipped code, but the harness renders variant 1 exactly once, so
        // no redeclaration collides here.
        let mut asserts = 0usize;
        for (i, &(a, b)) in vectors.x8.iter().enumerate() {
            let expected = a ^ b;
            for variant in 0..3 {
                chunk.push_str(&format!(
                    "assert(H8_{variant}({a},{b})=={expected},\"x8/{variant}/{i}\");"
                ));
                asserts += 1;
            }
        }
        for (i, &(a, b)) in vectors.x32.iter().enumerate() {
            let expected = a ^ b;
            for variant in 0..3 {
                chunk.push_str(&format!(
                    "assert(H32_{variant}({a},{b})=={expected},\"x32/{variant}/{i}\");"
                ));
                asserts += 1;
            }
        }
        for (i, &(x, n)) in vectors.rot.iter().enumerate() {
            let expected = x.rotate_left(n);
            for variant in 0..3 {
                chunk.push_str(&format!(
                    "assert(HR_{variant}({x},{n})=={expected},\"rot/{variant}/{i}\");"
                ));
                asserts += 1;
            }
        }
        let mut spellings = [0usize; 3];
        for (i, terms) in vectors.add.iter().enumerate() {
            let sum: u64 = terms.iter().map(|&t| u64::from(t)).sum();
            let expected = sum % 4294967296;
            let sum_text = terms
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join("+");
            let rendered = render_addmod(&mut rng, &sum_text);
            spellings[k7_spelling_class(&rendered) as usize] += 1;
            chunk.push_str(&format!("assert({rendered}=={expected},\"add/{i}\");"));
            asserts += 1;
        }
        for (i, (bytes, at)) in vectors.l32.iter().enumerate() {
            let expected = u32::from_le_bytes([bytes[*at - 1], bytes[*at], bytes[*at + 1], bytes[*at + 2]]);
            let literal = lua_escape_string(bytes);
            for variant in 0..3 {
                chunk.push_str(&format!(
                    "assert(HL32_{variant}(\"{literal}\",{at})=={expected},\"l32/{variant}/{i}\");"
                ));
                asserts += 1;
            }
        }
        assert_eq!(asserts, 1300, "vector census moved");
        assert!(
            spellings.iter().all(|&count| count >= 15),
            "{target}: addmod spelling coverage {spellings:?}"
        );
        chunk.push_str("print(\"K7-VECTORS-OK\");");
        let work = native::Workspace::new();
        let path = work.0.join("k7_vectors.lua");
        std::fs::write(&path, &chunk).unwrap();
        assert!(
            native::compile(target, &path).status.success(),
            "{target}: vector chunk failed to compile"
        );
        let runner = if target.is_luau() { "luau" } else { "lua5.1" };
        let output =
            native::success(Command::new(native::root().join("toolchains/bin").join(runner)).arg(&path));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("K7-VECTORS-OK"),
            "{target}: vectors failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// --- collision regressions (the K7 `LS` incident: prelude/entry locals
// must be unique; a duplicate silently crosses values seed-dependently) ---

#[test]
fn k7_entry_destructure_names_are_unique() {
    for target in [Target::Lua51, Target::Luau] {
        for seed in [1u64, 7001, 7351, 4242] {
            let raw = k7_raw(target, seed);
            let anchor = "local c1,c2,c3,Y1,Y2,Y3";
            let at = raw.find(anchor).expect("entry anchor moved");
            let stmt_start = raw[..at].rfind("local ").expect("destructure moved");
            let stmt = raw[stmt_start..at].trim_end().trim_end_matches(';');
            let names: Vec<&str> = stmt
                .strip_prefix("local ")
                .unwrap()
                .split(',')
                .map(str::trim)
                .collect();
            let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
            assert_eq!(
                unique.len(),
                names.len(),
                "{target} seed {seed}: duplicate entry names in {stmt}"
            );
            // The capture set rides along exactly once (nil on Lua 5.1,
            // like IF/Freeze).
            assert_eq!(
                names.iter().filter(|&&name| name == "SHL").count(),
                1,
                "{target} seed {seed}: SHL capture count moved"
            );
            assert_eq!(
                names.iter().filter(|&&name| name == "LS").count(),
                1,
                "{target} seed {seed}: loadstring LS count moved"
            );
        }
    }
}

#[test]
fn k7_word_layer_executes_across_seeds_on_both_targets() {
    // Prelude-unit shuffle order flips per seed; the old `LS` duplicate
    // only bit when the capture unit landed before the REF unit, so this
    // gate runs a spread (including known-bad seed 1) end to end.
    for target in [Target::Lua51, Target::Luau] {
        let data = compile("print(40+2)", target).unwrap();
        for seed in [1u64, 2, 5, 42, 777, 4242, 7001, 7351, 9001, 12345] {
            let output = emit(&data, target, seed).unwrap();
            let work = native::Workspace::new();
            let path = work.0.join("k7_seed.lua");
            std::fs::write(&path, &output).unwrap();
            let runner = if target.is_luau() { "luau" } else { "lua5.1" };
            let run = native::success(
                Command::new(native::root().join("toolchains/bin").join(runner)).arg(&path),
            );
            assert_eq!(
                String::from_utf8_lossy(&run.stdout).trim(),
                "42",
                "{target} seed {seed} mis-executed"
            );
        }
    }
}
