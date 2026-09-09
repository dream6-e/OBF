use super::*;

use std::fmt::Write as _;

/// Global capture/constant pool readers (ISA14). Each pool loop runs
/// exactly its validated total (`TU`/`TK`, accumulated from header
/// metadata), and decodes three anonymous u16 slots per record under the
/// per-record pool factorial profile. Every record is range-checked
/// (owner, slot/index), duplicate-checked, and stored into `CU`/`CK`
/// for the per-prototype slicers. Pool order follows the per-image flip
/// bit the encoder mirrors.
fn pool_loops_lua(
    field_order: FieldLayout,
    pool_add: u16,
    pool_multiplier: u16,
    target: Target,
) -> (String, String) {
    let capture = format!(
        "CU={{}};for slot=1,TU do {pool_decode}local owner=(st[sont[1]]-slot*{pm}-{pa})%65536;if owner>=np then E()end;local sl=(st[sont[2]]-owner*{pm}-slot-{pa})%65536;local OW=P[owner];if sl>=OW.__obf_proto_nu then E()end;local pay=(st[sont[3]]-sl*{pm}-owner-{pa})%65536;local tg=pay%4;local ix=(pay-tg)/4;if tg>2 or ix>255 then E()end;local T=CU[owner];if T==nil then T={{}};CU[owner]=T end;if T[sl]~=nil then E()end;T[sl]={{tg,ix}} end;",
        pool_decode = field_order.pool_decode_lua(),
        pm = pool_multiplier,
        pa = pool_add,
    );
    // Tag 4 (64-bit integer) exists only on Luau; on Lua 5.1 the
    // trailing `else E()end` rejects it at pool time.
    let tag4 = if target.is_luau() {
        " elseif tg==4 then local lo4,hi4=b32(),b32();if not IF then E()end;val=IF(SF('%08x%08x',hi4,lo4),16);if val==nil then E()end;"
    } else {
        ""
    };
    let constant = format!(
        "CK={{}};for slot=1,TK do {pool_decode}local owner=(st[sont[1]]-slot*{pm}-{pa})%65536;if owner>=np then E()end;local ix=(st[sont[2]]-owner*{pm}-slot-{pa})%65536;local OW=P[owner];if ix>=OW.__obf_proto_nk then E()end;local tg=(st[sont[3]]-ix*{pm}-owner-{pa})%65536;local val;if tg==0 then val=nil elseif tg==1 then val=b8();if val>1 then E()end;val=val==1 elseif tg==2 then val=num() elseif tg==3 or tg==5 then val=str(){tag4} else E()end;local T=CK[owner];if T==nil then T={{}};CK[owner]=T end;if T[ix]~=nil then E()end;T[ix]={{tg,val}} end;",
        pool_decode = field_order.pool_decode_lua(),
        pm = pool_multiplier,
        pa = pool_add,
        tag4 = tag4,
    );
    if field_order.pools_flipped {
        (constant, capture)
    } else {
        (capture, constant)
    }
}

pub(crate) fn generate(
    _bytecode: &[u8],
    program: &Program,
    seed: u64,
) -> Result<String, Diagnostic> {
    custom::validate(program)?;
    // The public OBF v2 bytes are never embedded verbatim. Each generated
    // script receives a seed-specific semantic wire image: straight-line
    // instructions become superoperators, records are linked by random
    // labels and physically shuffled, while reordered real prototypes mix
    // with an unreachable synthetic subtree. Record recipe ids are additionally
    // replaced by five-stage context tokens; successors use independent
    // three-stage edge tokens. Live wire descriptors are validation-equivalent
    // camouflage rather than execution truth; the target-side parser accepts
    // only this private ISA13 image.
    let semantic_image = semantic::encode(program, seed)?;
    generate_semantic(program, seed, semantic_image, None)
}

fn generate_semantic(
    program: &Program,
    seed: u64,
    semantic_image: semantic::SemanticImage,
    compression_override: Option<Vec<u8>>,
) -> Result<String, Diagnostic> {
    // Whole-output wrapper, strictly:
    //   local x={};return setmetatable({...},x):<random letter>()
    // The payload table carries ALL code in function form, split into section
    // functions under random numeric keys: [n1] host-capture prelude, [n2]
    // bytecode decoder (decrypts the embedded blob), [n3] operand validation,
    // [n4] runtime helpers, [n5..n7] environment-probing key-share functions,
    // plus three split validator fields (form-table and opcode-renumbering
    // rebuild, varint decode, per-opcode bounds arms) hiding among the
    // shuffle -- the dispatch numbering itself is re-shuffled per seed,
    // [n8] interpreter cluster, plus the entry method at a random letter key.
    // The embedded payload uses two domain-separated ChaCha8 passes. Runtime
    // key/nonce material derives from three source-witness shares, semantic
    // context, domain and anti-hook attestation. Word operations, quarter
    // round, block, KDF/stream and anti-hook are sibling shuffled fields; the
    // entry composes them before opening strict frame v2. The method call
    // resolves the entry directly as an own key of the payload table,
    // receives (self) — or (self,...) when the chunk reads `...` — chains
    // the sections in order and returns the program result. The metatable
    // local is the plain empty table required by the format.
    let method = wrapper_method(program.target, seed);
    let keys = wrapper_keys(seed);
    let params = cipher_params(seed);
    let chacha = chacha_params(seed);
    let frame = frame_params(seed);
    // Per-seed primitive renumbering: every canonical ISA slot maps to a
    // distinct byte used by operand validation and inside unrolled recipe
    // bodies. Semantic use sites contain no opcode byte; their random recipe
    // id selects a program-specific sequence. The Lua side rebuilds this
    // primitive table from the packed forms-field string.
    let perm = opcode_permutation(seed, 64);
    // ISA12 breaks the report's image-wide operand tuple ABI. Every private
    // prototype gets a distinct affine (layout family, component rotation,
    // sparse lane) profile across the full 32,767-id private image limit, while
    // semantic fragments use four result-binding orders and never publish the
    // actual opcode number.
    let operand_abi = operand_layout(seed);
    // ISA12-B independently lowers each logical register reference through a
    // frame-local per-prototype mapper. The target derives this affine profile
    // from `fid`; it never embeds a 256-entry register permutation table.
    let register_abi = register_layout(seed);
    // ISA13 de-documents parser field order. Record slots use a per-prototype
    // factorial profile recomputed from the prototype id; segment tokens use a
    // per-segment profile recomputed from the physical slot. Dictionary,
    // metadata and tuple orders are per-image permutations baked into the
    // generated parser text below.
    let field_order = field_layout(seed);
    let primitive_ops: std::collections::BTreeSet<Opcode> = semantic_image
        .recipes
        .iter()
        .flat_map(|recipe| recipe.descriptor_ops.iter().chain(&recipe.execute_ops))
        .copied()
        .collect();
    let opcode_image: std::collections::BTreeSet<u8> =
        primitive_ops.iter().map(|op| perm[*op as usize]).collect();
    // M7 structural randomization stream: per-handler dispatch comparison
    // variants (one of four equivalent forms, seeded), integer bound-check
    // variants in the decoder/validator, and metamethod dispatch branch
    // variants in the runtime helpers. Reuses the audited native-backend
    // variant machinery; handler order and semantics stay unchanged.
    let mut structure = crate::random::Prng::new(seed ^ 0x6d37_7374_7275_6374);
    // M7: integer bound-check variants (exact equivalence: the operands are
    // always varint-decoded integers, so `x>K`, `K<x` and `not(x<=K)` are
    // interchangeable; no NaN or metamethod semantics can apply).
    let ax = gt(&mut structure, "a", "255");
    let bx = gt(&mut structure, "b", "255");
    let cx = gt(&mut structure, "c", "255");
    let jx = gt(&mut structure, "j", "16777215");
    let kx = gt(&mut structure, "k2", "65535");
    // M7: metamethod-dispatch branch variants. The Call wrapper inverts its
    // cache branch (pure control-flow inversion, no evaluation reorder); the
    // userdata guard flips its (string-only, hence raw and commutative)
    // equality order.
    let call_body = if structure.next_u64() % 2 == 0 {
        "local Call=function(fn,args)local d=W[fn];if d then return H(d[1],args,d[2])else return Z(fn(U(args,1,args.n)))end end;"
    } else {
        "local Call=function(fn,args)local d=W[fn];if not d then return Z(fn(U(args,1,args.n)))end;return H(d[1],args,d[2])end;"
    };
    let ud_check = if structure.next_u64() % 2 == 0 {
        "TY(object)=='userdata'"
    } else {
        "'userdata'==TY(object)"
    };
    // M7 opaque true/false branches with unreachable decoy instructions:
    // the entry body is wrapped as `if <tautology> then <real> else <decoy>`
    // (or the flipped `if <contradiction> then <decoy> else <real>`), and
    // the F3/F5 dispatch chains gain dead elseif arms keyed on opcode
    // numbers that can never occur. Both user-requested forms.
    let (opaque_true, opaque_false) = opaque_pair(&mut structure);
    let entry_flip = structure.next_u64() % 2 == 0;
    // Fake anchors on the entry's dead side: constructions shaped exactly
    // like the pipeline's real key material -- a packed base86 renumbering
    // string of the same 129-byte shape rebuilt into a table, LCG share
    // arithmetic over real table keys, and an Adler-style checksum gate.
    // Nothing downstream ever verifies them; static methodology that
    // anchors on checksums and key derivations has to disprove each decoy
    // before the real one, and executing the branch is impossible.
    let mut fake_packed = String::from("~");
    for _ in 1..129 {
        fake_packed.push(pack86((structure.next_u64() % 86) as u8));
    }
    let (fake_a, fake_b) = {
        let first = structure.next_u64() as usize % keys.len();
        let mut second = structure.next_u64() as usize % keys.len();
        if second == first {
            second = (second + 1) % keys.len();
        }
        (keys[first], keys[second])
    };
    let fake_adler = 1_000_000_000u64 + structure.next_u64() % 3_000_000_000u64;
    let mut entry_decoy = format!(
        "local d1=VMS[{}](E);local d2=VMS[{}](d1,E);if d2 then E()end;\
local d3=\"{fake_packed}\";local d4={{}};for dq=2,#d3,2 do local dx,dy=SB(d3,dq),SB(d3,dq+1);\
d4[(dq-2)/2]=dx-35+(dy-35)*86 end;",
        keys[0], keys[1],
    );
    if structure.next_u64() % 2 == 0 {
        entry_decoy.push_str(&format!(
            "local d5=({fake_a}*31+{fake_b})%2147483647;d5=48271*d5%2147483647;\
d5=65539*d5%2147483647;local d6=1+(d5+31*#d3)%2147483646;"
        ));
    }
    if structure.next_u64() % 2 == 0 {
        entry_decoy.push_str(&format!(
            "local d7,d8=1,0;for dq=1,#d3 do d7=(d7+SB(d3,dq))%65521;d8=(d8+d7)%65521 end;\
if d7+d8*65521~={fake_adler} then E()end;"
        ));
    }
    let f3_decoys = decoy_arms(
        &mut structure,
        2,
        program.target.is_luau(),
        &["ok=j%2==0;", "ok=a+b<511;", "ok=c<256;"],
        &opcode_image,
    );
    let (entry_head, entry_tail) = if entry_flip {
        (
            format!("if {opaque_true} then"),
            format!("else {entry_decoy}end;"),
        )
    } else {
        (
            format!("if {opaque_false} then {entry_decoy}else"),
            "end;".to_owned(),
        )
    };
    let mut s = String::from("local x={};return setmetatable({");
    let header_end = s.len();
    write!(s, "[{}]=function()\n", keys[0]).unwrap();
    // Hidden-name prelude: apart from the audited environment capture
    // (getfenv/_G -- taken at level 1 so hidden-name lookups resolve
    // exactly like bare global names, keeping sandbox tampering of
    // loadstring/debug detectable by the probes) and the outer
    // setmetatable call, no global name is
    // spelled out. Every captured global -- string, math, error, tonumber,
    // type, loadstring, debug, ... -- is resolved through G[name], where
    // each name is assembled at run time from single-character functions
    // in a pool table: the char-to-slot assignment, the per-name index
    // sequence and the assembly format (direct concat vs a table-driven
    // concat helper) are all drawn per seed. The capture statements stay
    // independent (Z reads SC) and shuffle as before; the return and
    // entry-destructuring orders are a separate shuffle.
    s.push_str("\nlocal G=(getfenv and getfenv(1))or _G;");
    let mut hidden: Vec<&str> = vec![
        "select",
        "error",
        "pcall",
        "unpack",
        "string",
        "byte",
        "sub",
        "format",
        "table",
        "concat",
        "char",
        "math",
        "floor",
        "tonumber",
        "type",
        "tostring",
        "next",
        "getmetatable",
        "setmetatable",
        "rawget",
        "rawequal",
        "debug",
        "loadstring",
    ];
    if program.target.is_luau() {
        hidden.extend(["integer", "fromstring", "freeze", "info"]);
    } else {
        hidden.push("getinfo");
    }
    let mut chars: Vec<char> = hidden
        .iter()
        .flat_map(|name| name.chars())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    structure.shuffle(&mut chars);
    let slot: std::collections::BTreeMap<char, usize> = chars
        .iter()
        .enumerate()
        .map(|(index, c)| (*c, index + 1))
        .collect();
    s.push('\n');
    write!(s, "local s={{").unwrap();
    for c in &chars {
        write!(s, "function()return\"{c}\"end,").unwrap();
    }
    s.push_str("};");
    s.push_str("\nlocal C=function(t,d)local r=''for i=1,#d do r=r..t[d[i]]()end return r end;");
    let gv =
        |map: &std::collections::BTreeMap<&str, String>, name: &str| format!("G[{}]", map[name]);
    let mut var_of: std::collections::BTreeMap<&str, String> = Default::default();
    let mut definitions: Vec<String> = Vec::new();
    for (index, name) in hidden.iter().enumerate() {
        let expression = if structure.next_u64() % 100 < 92 {
            let indexes = name
                .chars()
                .map(|c| slot[&c].to_string())
                .collect::<Vec<_>>()
                .join(",");
            format!("C(s,{{{indexes}}})")
        } else {
            name.chars()
                .map(|c| format!("s[{}]()", slot[&c]))
                .collect::<Vec<_>>()
                .join("..")
        };
        definitions.push(format!("v{index}={expression}"));
        var_of.insert(name, format!("v{index}"));
    }
    // Batched local statements keep the pool definitions compact.
    for chunk in definitions.chunks(4) {
        let vars: Vec<&str> = chunk
            .iter()
            .map(|definition| definition.split('=').next().unwrap())
            .collect();
        let expressions: Vec<&str> = chunk
            .iter()
            .map(|definition| &definition[definition.find('=').unwrap() + 1..])
            .collect();
        write!(s, "\nlocal {}={};\n", vars.join(","), expressions.join(",")).unwrap();
    }
    let mut units: Vec<(&str, String)> = vec![
        ("SC", format!("local SC={};", gv(&var_of, "select"))),
        (
            "Z",
            "local Z=function(...)return{n=SC('#',...),...}end;".to_owned(),
        ),
        (
            "U",
            format!(
                "local U={}or G[{}][{}];",
                gv(&var_of, "unpack"),
                var_of["table"],
                var_of["unpack"]
            ),
        ),
        ("E", format!("local E={};", gv(&var_of, "error"))),
        ("PC", format!("local PC={};", gv(&var_of, "pcall"))),
        (
            "SB",
            format!(
                "local SB,SS,SF=G[{0}][{1}],G[{0}][{2}],G[{0}][{3}];",
                var_of["string"], var_of["byte"], var_of["sub"], var_of["format"]
            ),
        ),
        (
            "NCH",
            format!(
                "local NCH,TC=G[{0}][{1}],G[{2}][{3}];",
                var_of["string"], var_of["char"], var_of["table"], var_of["concat"]
            ),
        ),
        (
            "MF",
            format!(
                "local MF,TN,TY,TS,NX,MT,SM,RG,RE=G[{0}][{1}],{2},{3},{4},{5},{6},{7},{8},{9};",
                var_of["math"],
                var_of["floor"],
                gv(&var_of, "tonumber"),
                gv(&var_of, "type"),
                gv(&var_of, "tostring"),
                gv(&var_of, "next"),
                gv(&var_of, "getmetatable"),
                gv(&var_of, "setmetatable"),
                gv(&var_of, "rawget"),
                gv(&var_of, "rawequal")
            ),
        ),
        (
            "REF",
            format!(
                "local DBG={0};local GI=DBG and DBG[{1}];local LS={2};",
                gv(&var_of, "debug"),
                var_of[if program.target.is_luau() {
                    "info"
                } else {
                    "getinfo"
                }],
                gv(&var_of, "loadstring")
            ),
        ),
    ];
    if program.target.is_luau() {
        units.push((
            "IF",
            format!(
                "local IG=G[{0}];local IF=IG and IG[{1}];",
                var_of["integer"], var_of["fromstring"]
            ),
        ));
        units.push((
            "Freeze",
            format!("local Freeze=G[{}][{}];", var_of["table"], var_of["freeze"]),
        ));
    }
    structure.shuffle(&mut units);
    let sc_at = units.iter().position(|(name, _)| *name == "SC").unwrap();
    let z_at = units.iter().position(|(name, _)| *name == "Z").unwrap();
    if z_at < sc_at {
        units.swap(z_at, sc_at);
    }
    s.push('\n');
    for (_, statement) in &units {
        s.push_str(statement);
    }
    // Shared exact-integer primitives. ChaCha8 deliberately reuses arithmetic
    // X8 and does not depend on target-specific bit libraries.
    s.push_str("local X8=function(a,b)local r=0;for j=0,7 do r=r+(a+b)%2*2^j;a=MF(a/2);b=MF(b/2)end;return r end;local AD=function(S,a,b)local x,y=1,0;for i=a,b do x=(x+SB(S,i))%65521;y=(y+x)%65521 end;return x+y*65536 end;local L32=function(S,p)return SB(S,p)+SB(S,p+1)*256+SB(S,p+2)*65536+SB(S,p+3)*16777216 end;");
    let mut ret_order: Vec<&str> = vec![
        "SC", "Z", "U", "G", "E", "PC", "SB", "SS", "SF", "NCH", "TC", "MF", "TN", "TY", "TS",
        "NX", "MT", "SM", "RG", "RE", "IF", "Freeze", "DBG", "GI", "LS", "X8", "AD", "L32",
    ];
    structure.shuffle(&mut ret_order);
    let ret_names = ret_order.join(",");
    s.push_str(&format!("\nreturn {ret_names}\nend,"));
    // Entry reconstructs three source-witness shares in shuffled call order.
    // Both ChaCha8 domains then derive final key/nonce/counter words only at
    // runtime after anti-hook attestation. Pure arithmetic stays below 2^53,
    // keeping Lua 5.1/Luau behavior bit-identical without bit libraries.
    let shares = cipher_shares(&keys, &params, program.target);
    // B1: the payload seed additionally carries the permutation term,
    // computed on both ends from the rebuilt renumbering table at three
    // per-seed slots (the entry derives it from the forms field's output
    // before calling the decrypt field).
    let pv = perm_term(seed);
    let pv_slots = perm_indices(seed);
    // Compress the complete private semantic image before any cipher. The
    // bounded LZW frame is emitted only when it is strictly smaller; its body
    // is protected by the inner ChaCha8 domain. Encrypting after compression
    // preserves compressibility. Public canonical `.obf` bytes stay unchanged.
    let mut payload = match compression_override {
        Some(frame) => frame,
        None => compress_bytecode(&semantic_image.bytes)?,
    };
    apply_compression_cipher(&mut payload, &shares, pv, program.target, &chacha)?;
    // ChaCha8 supplies two domain-separated confidentiality passes. The
    // strict frame between them authenticates descriptor, exact length,
    // cookie, payload tag and deterministic padding before exposure.
    let framed = seal_transport_frame(&payload, &shares, pv, &frame)?;
    let encrypted = chacha8_xor(
        &framed,
        &shares,
        pv,
        framed.len() as u32,
        CHACHA8_OUTER_DOMAIN,
        program.target,
        &chacha,
    );
    // Transport layer: the framed double-ChaCha8 image is base86-encoded (all
    // printable alphabet characters, ~1.25 chars per byte instead of 4-char
    // decimal escapes) and split into three segments placed in seed-shuffled
    // payload-table functions. Each segment function re-runs the audited
    // native-loadstring probe and decodes only its own slice, so payload
    // recovery is itself split across several [n]=function pieces.
    // Fixed transport watermark: the decoded stream must begin with the
    // literal bytes "XXS:". The check itself is split across two payload
    // functions -- a generic big-endian packer over the first four bytes of
    // the first stream segment, and a comparator against one opaque u32 --
    // so neither function spells out the watermark and the string "XXS:"
    // never appears in the script. A mismatch aborts silently via E().
    let expected_watermark = u32::from_be_bytes(*b"XXS:");
    let mut marked = Vec::with_capacity(encrypted.len() + 4);
    marked.extend_from_slice(b"XXS:");
    marked.extend_from_slice(&encrypted);
    let encoded = base86_encode(&marked);
    let groups = marked.len() / 4;
    let tail = marked.len() % 4;
    let base = groups / 3;
    let extra = groups % 3;
    let mut counts = [
        base + usize::from(extra > 0),
        base + usize::from(extra > 1),
        0,
    ];
    counts[2] = groups - counts[0] - counts[1];
    // Which of the three segment keys holds which stream part is shuffled.
    let mut hold = [0usize, 1, 2];
    crate::random::Prng::new(seed ^ 0x7365_676d_3373_6866).shuffle(&mut hold);
    let mut at = 0usize;
    let mut segment_fields = Vec::new();
    for part in 0..3 {
        let mut chars = counts[part] * 5;
        if part == 2 {
            chars += if tail > 0 { tail + 1 } else { 0 };
        }
        let text = &encoded[at..at + chars];
        at += chars;
        let (probe, gate) = if program.target.is_luau() {
            ("DB and GI(LS,\"s\")", "if A~=\"[C]\" then E()end;")
        } else {
            (
                "DB and GI(LS,\"S\")",
                "if not(A and A.what==\"C\")then E()end;",
            )
        };
        // Control-flow flattening: the base86 decode is a seeded state
        // machine -- main-step self-loop, tail handling, finish -- with
        // per-seed state numbers, shuffled branch order and varied
        // condition spellings; every data local flows through the
        // scratch table g[...] and is cleared before returning.
        let sv = state_values(&mut structure, 3);
        let (k_main, k_tail, k_done) = (sv[0], sv[1], sv[2]);
        let decode5 = "local v=0;local m=1;\
for j=0,4 do local b=SB(S,i+j);if b==92 or b<35 or b>121 then E()end;\
if b>92 then b=b-36 else b=b-35 end;v=v+b*m;m=m*86 end;\
if v>4294967295 then E()end;o[#o+1]=NCH(v%256);v=(v-v%256)/256;\
o[#o+1]=NCH(v%256);v=(v-v%256)/256;o[#o+1]=NCH(v%256);v=(v-v%256)/256;\
o[#o+1]=NCH(v);";
        let decode_tail = "local v=0;local m=1;for j=0,r2-1 do local b=SB(S,#S-r2+1+j);\
if b==92 or b<35 or b>121 then E()end;\
if b>92 then b=b-36 else b=b-35 end;v=v+b*m;m=m*86 end;\
if v>256^(r2-1)-1 then E()end;\
for j=1,r2-1 do o[#o+1]=NCH(v%256);v=(v-v%256)/256 end;";
        let machine = state_machine(
            &mut structure,
            "st",
            vec![
                (
                    k_main,
                    format!("if i>L then st={k_tail} else {decode5} i=i+5 end;"),
                ),
                (
                    k_tail,
                    format!(
                        "local r2=#S%5;if r2==1 then E()end;\
if r2>0 then {decode_tail} end;st={k_done};"
                    ),
                ),
                (k_done, "local rr=TC(o);g=nil;return rr;".to_owned()),
            ],
        );
        let mut body = format!(
            "local S=\"{text}\";local o={{}};local i=1;local L=#S-#S%5;local st={k_main};{machine}",
            text = text,
            k_main = k_main,
            machine = machine,
        );
        body = slot_rewrite(
            &mut structure,
            &body,
            &["S", "o", "i", "L", "st", "v", "m", "b", "r2"],
        );
        let mut chunk = String::new();
        write!(
            chunk,
            "[{key}]=function(E,SB,NCH,TC,DB,GI,LS)local A={probe};{gate}\
local g={{}};{body}end,",
            key = keys[8 + hold[part]],
            probe = probe,
            gate = gate,
            body = body,
        )
        .unwrap();
        segment_fields.push(chunk);
    }
    // The split watermark check: W1 is a plain 4-byte packer, W2 compares
    // against the opaque expected value. Hidden in plain sight among the
    // other numeric-keyed payload functions.
    let watermark_fields = vec![
        format!(
            "[{}]=function(S,E,SB)local a,b,c,d=SB(S,1),SB(S,2),SB(S,3),SB(S,4);\
if not d then E()end;return((a*256+b)*256+c)*256+d;end,",
            keys[11]
        ),
        format!(
            "[{}]=function(v,E)if v~={expected_watermark} then E()end;end,",
            keys[12]
        ),
    ];
    // Random decoder sections: the anti-hook gate, 32-bit word operations,
    // quarter round, ChaCha8 block, stream/KDF, outer frame inverse and inner
    // LZW inverse are all sibling numeric-keyed fields. The final layout pass
    // globally shuffles them; entry wiring alone composes the decryptor.
    let (crypto_fields, crypto_wiring) = chacha_decoder_sections(&chacha, program.target, &keys);
    let frame_decode = transport_frame_decoder(&frame);
    let decrypt_field = format!(
        "[{}]=function(B,s1,s2,s3,pv,CC,AH,CB,E,SB,SS,NCH,TC,MF,X8,AD,L32,DBG,GI,LS)\nlocal aw=AH(AH,CC,CB,X8,E,SB,NCH,TC,MF,DBG,GI,LS);B=CC(B,s1,s2,s3,pv,#B,1,aw,CB,E,SB,NCH,TC,MF,X8);{frame_decode}return B end,",
        keys[1]
    );
    let split_lzw_helpers =
        crate::random::Prng::new(seed ^ 0x6c7a_775f_7370_6c38).next_u64() % 2 == 0;
    let (compression_fields, compression_wiring) =
        compression_decoder_sections(&keys, split_lzw_helpers);
    let g1 = r#"local bp=1;
local b8=function()local v=SB(B,bp);if v==nil then E()end;bp=bp+1;return v end;
local b16=function()local a,b=b8(),b8();return a+b*256 end;
local b32=function()local a,b,c,d=b8(),b8(),b8(),b8();return a+b*256+c*65536+d*16777216 end;
local take=function(n)if n>#B-bp+1 then E()end;local v=SS(B,bp,bp+n-1);bp=bp+n;return v end;
local str=function()return take(b32())end;
local pos=function()return bp end;"#
        .to_owned();
    let g2 = r#"local fin=function(lo,hi)local sg=hi>=2147483648 and -1 or 1;local ex=MF(hi/1048576)%2048;local fr=(hi%1048576)*4294967296+lo;if ex==2047 then if fr==0 then return sg/0 else return 0/0 end elseif ex==0 then return sg*(fr*2^-1074) else return sg*((1+fr/4503599627370496)*2^(ex-1023))end end;local num=function()return fin(b32(),b32())end;"#
        .to_owned();
    // The semantic parser now sees an exact decompressed ISA image, so its
    // helpers are only ordinary bounded readers and the number reconstructor.
    // The former constant-only decrypt closures are replaced by the stronger
    // whole-compression-body stream in `compression_decoder_sections`.
    let groups: Vec<(&[&str], &[&str], String)> = vec![
        (
            &["B", "E", "SB", "SS"],
            &["b8", "b16", "b32", "take", "str", "pos"],
            g1,
        ),
        (&["MF", "b32"], &["fin", "num"], g2),
    ];
    let base_names = ["B", "E", "SB", "SS", "MF"];
    let cluster_count = 1 + structure.next_u64() % 2;
    let mut bounds_set = std::collections::BTreeSet::new();
    while bounds_set.len() < (cluster_count - 1) as usize {
        bounds_set.insert(1);
    }
    let mut bounds: Vec<usize> = bounds_set.into_iter().map(|b| b as usize).collect();
    bounds.push(groups.len());
    let mut decoder_fields = vec![decrypt_field];
    decoder_fields.extend(crypto_fields);
    decoder_fields.extend(compression_fields);
    // Forms first yields the permutation term. Five shuffled crypto fields
    // are then composed locally; both anti-hook gates run before ChaCha8.
    let mut decoder_wiring = format!(
        "local FMt,PT=VMS[{forms}](E,SB);\
local pv=1+(PT[{i0}]*31+PT[{i1}]*7+PT[{i2}])%2147483646;\
{crypto_wiring}\
local C=VMS[{decrypt}](SS(Y1..Y2..Y3,5),c1,c2,c3,pv,CC,AH,CB,E,SB,SS,NCH,TC,MF,X8,AD,L32,DBG,GI,LS);\
{compression_wiring}",
        forms = keys[13],
        i0 = pv_slots[0],
        i1 = pv_slots[1],
        i2 = pv_slots[2],
        decrypt = keys[1],
        crypto_wiring = crypto_wiring,
        compression_wiring = compression_wiring,
    );
    let mut prior_exports: Vec<&str> = Vec::new();
    let mut start = 0usize;
    for (index, bound) in bounds.iter().enumerate() {
        let cluster = &groups[start..*bound];
        start = *bound;
        let mut params: Vec<&str> = Vec::new();
        for (needs, _, _) in cluster {
            for need in *needs {
                if !params.contains(need)
                    && (base_names.contains(need) || prior_exports.contains(need))
                {
                    params.push(need);
                }
            }
        }
        let mut exports: Vec<&str> = Vec::new();
        let mut text = String::new();
        for (_, group_exports, group_text) in cluster {
            text.push_str(group_text);
            text.push('\n');
            exports.extend_from_slice(group_exports);
        }
        let key = keys[16 + index];
        decoder_fields.push(format!(
            "[{key}]=function({})\n{text}return {};\nend,",
            params.join(","),
            exports.join(",")
        ));
        let args = params.iter().copied().collect::<Vec<_>>().join(",");
        decoder_wiring.push_str(&format!(
            "\nlocal {}=VMS[{key}]({args});",
            exports.join(",")
        ));
        prior_exports.extend(exports);
    }
    let mut core_text = String::from(
        r#"if b8()~=79 or b8()~=66 or b8()~=70 or b8()~=2 then E()end;
"#,
    );
    write!(
        core_text,
        "if b8()~={} then E()end;",
        if program.target.is_luau() { 117 } else { 81 }
    )
    .unwrap();
    write!(
        core_text,
        r#"
if b8()~=1 or b8()~=1 or b8()~=0 or b32()~=32 or b32()~=#B then E()end;
local np=b32();local entry=b32();local isa=b32();if np==0 or np>32767 or entry~=0 or isa~={} then E()end;
local check=b32();if AD(B,33,#B)~=check then E()end;
"#,
        semantic::WIRE_ISA_VERSION
    )
    .unwrap();
    // Flattened parse core: the per-prototype stages are split into local
    // functions -- header read/validate (PH), upvalue wiring (PU), constant
    // pool (PK) -- whose definition order shuffles per seed, driven by a
    // seeded state machine (next/header+commit -> pool A -> pool B ->
    // slice -> finish). The pool states read the two global shuffled
    // pools (captures/constants, order baked per image) into CU/CK tables;
    // the slice state wires each prototype from those tables; the finish
    // state reads the one global shuffled code-segment graph, validates
    // masked ids/owners/roots/next links and exact coverage, then
    // reconstructs each stream before semantic parsing.
    let csv = state_values(&mut structure, 5);
    let (c_next, c_pool_a, c_pool_b, c_slice, c_fin) = (csv[0], csv[1], csv[2], csv[3], csv[4]);
    let mut ph = format!(
        "local PH=function()\n local F={{__obf_proto_k={{}},__obf_proto_tags={{}},__obf_proto_u={{}}}};{}\n",
        field_order.metadata_reads_lua()
    );
    ph.push_str(
        " if F.__obf_proto_m<1 or F.__obf_proto_m>256 or F.__obf_proto_p>F.__obf_proto_m or F.__obf_proto_nu>256 or F.__obf_proto_nk>65536 or F.__obf_proto_nc<1 or F.__obf_proto_flags>15 or VMCS<4 or VMCS>16777216 then E()end;\n F.__obf_proto_shared=MF(F.__obf_proto_flags/8)%2==1;if F.__obf_proto_shared and (isa<2 or id==0)then E()end;\n if id==0 then if F.__obf_proto_parent~=4294967295 or F.__obf_proto_nu~=0 or MF(F.__obf_proto_flags/2)%2~=0 then E()end\n elseif F.__obf_proto_parent>=id then E()end;\n local legacy=MF(F.__obf_proto_flags/2)%2;\n if legacy==1 and (F.__obf_proto_flags%2==0 or F.__obf_proto_p>=F.__obf_proto_m)or MF(F.__obf_proto_flags/4)%2==1 and legacy==0 then E()end;\n",
    );
    if program.target.is_luau() {
        ph.push_str("if legacy~=0 then E()end;");
    } else {
        ph.push_str("if F.__obf_proto_shared then E()end;");
    }
    ph.push_str("\n return F,VMCS,RT\nend;\n");
    let pu = "local PU=function()\n local UT=CU[id];if UT==nil then UT={} end;for j=0,F.__obf_proto_nu-1 do local rec=UT[j];if not rec then E()end;local tag,index=rec[1],rec[2];local parent=P[F.__obf_proto_parent];\n  if tag>2 or not parent or tag~=1 and index>=parent.__obf_proto_m or tag==1 and index>=parent.__obf_proto_nu then E()end;\n  if tag==2 then if not F.__obf_proto_shared or F.__obf_proto_self~=nil then E()end;F.__obf_proto_self=j end;\n  F.__obf_proto_u[j]={tag,index};\n end;\nend;\n"
        .to_owned();
    let mut pk = String::from(
        "local PK=function()\n local KT=CK[id];if KT==nil then KT={} end;for j=0,F.__obf_proto_nk-1 do local rec=KT[j];if not rec then E()end;local tg=rec[1];if tg>5 then E()end;F.__obf_proto_tags[j]=tg;F.__obf_proto_k[j]=rec[2] end;",
    );
    pk.push_str("\nend;\n");
    let mut defs = vec![ph, pu, pk];
    structure.shuffle(&mut defs);
    core_text.push('\n');
    for definition in &defs {
        core_text.push_str(definition);
    }
    core_text.push_str(&format!(
        "local P={{}};local work=0;local id=0;local TU,TK=0,0;local w={c_next};\n"
    ));
    let segment_add = semantic_image.token_layers[0].add;
    let segment_multiplier = semantic_image.token_layers[0].multiplier;
    let pool_add = semantic_image.token_layers[1].add;
    let pool_multiplier = semantic_image.token_layers[1].multiplier;
    let (pool_first, pool_second) =
        pool_loops_lua(field_order, pool_add, pool_multiplier, program.target);
    core_text.push_str(&state_machine(
        &mut structure,
        "w",
        vec![
            (
                c_next,
                format!(
                    "if id>=np then w={c_pool_a} else F,VMCS,RT=PH();TU=TU+F.__obf_proto_nu;TK=TK+F.__obf_proto_nk;work=work+F.__obf_proto_nu+F.__obf_proto_nk+F.__obf_proto_nc;if work>1000000 then E()end;F.__obf_proto_code={{VMCS,RT}};P[id]=F;id=id+1;w={c_next}; end;"
                ),
            ),
            (
                c_pool_a,
                format!("{pool_first}w={c_pool_b};"),
            ),
            (
                c_pool_b,
                format!("{pool_second}w={c_slice};"),
            ),
            (
                c_slice,
                format!("for fid=0,np-1 do id=fid;F=P[id];PU();PK() end;w={c_fin};"),
            ),
            (
                c_fin,
                format!(
                    "local Q={{}};local SN=np*2;for slot=1,SN do {segment_decode}local sid=(st[sont[1]]-slot*{segment_multiplier}-{segment_add})%65536;if sid<1 or sid>SN or Q[sid]then E()end;local owner=MF((sid-1)/2);local claimed=(st[sont[2]]-sid*{segment_multiplier}-slot-{segment_add})%65536;if claimed~=owner then E()end;local part=(sid-1)%2;local SP=P[owner].__obf_proto_code;local nxt=(st[sont[3]]-sid*{segment_multiplier}-owner-{segment_add})%65536;local split=1+MF((SP[1]-1)*(({segment_add}+owner*{segment_multiplier})%65536)/65536);local n=part==0 and split or SP[1]-split;Q[sid]={{owner,nxt,take(n)}}end;if pos()~=#B+1 then E()end;local used={{}};local roots={{}};for owner=0,np-1 do local SP=P[owner].__obf_proto_code;local sid=(SP[2]-owner*{segment_multiplier}-{segment_add})%65536;if sid~=owner*2+1 or roots[sid]then E()end;roots[sid]=1;local code='';for count=1,2 do local S=Q[sid];if not S or S[1]~=owner or used[sid]then E()end;used[sid]=1;code=code..S[3];sid=S[2]end;if sid~=0 or #code~=SP[1]then E()end;SP[2]=code end;for sid=1,SN do if not used[sid]then E()end end;B=nil;break;",
                    segment_decode = field_order.segment_decode_lua(),
                ),
            ),
        ],
    ));
    core_text.push_str("\nlocal rP,rnp,ren=P,np,entry;g=nil;return rP,rnp,ren\n");
    core_text = slot_rewrite(
        &mut structure,
        &core_text,
        &[
            "P", "work", "id", "w", "np", "entry", "isa", "check", "sa", "sb", "F", "VMCS", "RT",
            "legacy", "tag", "index", "parent", "v", "lo", "hi", "CU", "CK",
        ],
    );
    decoder_fields.push(format!(
        "[{}]=function(B,E,SB,SF,NCH,TC,MF,IF,AD,b8,b16,b32,take,str,pos,num)\nlocal g={{}};{core_text}end,",
        keys[20]
    ));
    decoder_wiring.push_str(&format!(
        "\nlocal P,np,entry=VMS[{}](B,E,SB,SF,NCH,TC,MF,IF,AD,b8,b16,b32,take,str,pos,num);",
        keys[20]
    ));
    let f3_start = s.len();
    // Feature-split hiding: the operand validator used to carry three
    // instant static signatures inside one field -- the sequential-key
    // `[0]=3,[1]=4,...` form-table literal, the varint reader with its
    // `if f==1 elseif f==2 ...` operand-shape chain, and the per-opcode
    // bounds arms. Each now lives in its own numeric-keyed payload field
    // (shuffled into a random file position by the layout pass). The form
    // table is no longer a literal at all: a dedicated field rebuilds it
    // from a packed, per-seed rotated one-char-per-opcode string over the
    // backslash-free base86 alphabet, unused opcode slots encoding an
    // invalid form so unknown opcodes are still rejected before dispatch.
    let forms: std::collections::BTreeMap<u8, u8> = primitive_ops
        .iter()
        .map(|op| (*op as u8, custom::encoding_form(*op)))
        .collect();
    let forms_rot = structure.next_u64() % 86;
    let mut forms_text = String::new();
    for slot in 0..=*forms.keys().max().unwrap() {
        let packed = match forms.get(&slot) {
            Some(form) => (u64::from(form - 1) + forms_rot) % 86,
            None => (5 + forms_rot) % 86,
        };
        forms_text.push(pack86(packed as u8));
    }
    // The per-seed opcode renumbering rides along as a second packed
    // string: two base86 chars per canonical slot (value%86, value/86).
    let mut perm_text = String::new();
    for slot in 0..64u8 {
        let value = perm[slot as usize];
        perm_text.push(pack86(value % 86));
        perm_text.push(pack86(value / 86));
    }
    // A `~` marker byte prefixes both packed strings: it is outside the
    // base86 alphabet, so the payload-segment audit (which collects the
    // three longest alphabet-only literals) never mistakes them for
    // transport segments however small the program is.
    let mut forms_body = format!(
        "local t={{}};local p={{}};local S=\"~{text}\";for i=2,#S do local b=SB(S,i);\
if b==92 or b<35 or b>121 then E()end;if b>92 then b=b-1 end;t[i-2]=(b-35-{rot})%86+1 end;\
local U=\"~{renum}\";for i=2,#U,2 do local x=SB(U,i);local y=SB(U,i+1);\
if x==92 or x<35 or x>121 or y==92 or y<35 or y>121 then E()end;\
if x>92 then x=x-1 end;if y>92 then y=y-1 end;p[(i-2)/2]=x-35+(y-35)*86 end;\
local rt,rp=t,p;g=nil;return rt,rp;",
        text = forms_text,
        rot = forms_rot,
        renum = perm_text,
    );
    forms_body = slot_rewrite(
        &mut structure,
        &forms_body,
        &["t", "p", "S", "U", "b", "x", "y"],
    );
    let forms_field = format!(
        "[{key}]=function(E,SB)local g={{}};{body}end,",
        key = keys[13],
        body = forms_body,
    );
    // Semantic-wire operand decoder. Opcode bytes no longer occur at bundle
    // use sites: the recipe dictionary supplies a context-specific opcode
    // sequence, and this closure reads only the operands for one advertised
    // primitive form.
    let mut decode_body = format!(
        "[{key}]=function(E,SB,FM)local g={{}};\nlocal Dv=function(CD,p)local w=SB(CD,p);if w==nil then E()end;p=p+1;local v=w%128;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*128;if w<128 and v<128 then E()end;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*16384;if w<128 and v<16384 then E()end;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*2097152;if v<2097152 then E()end;\
if w>=128 then E()end;end;end;end;return v,p end;\nreturn function(CD,p,o)local f=FM[o];if f==nil or f>5 then E()end;\
if f==1 then j,p=Dv(CD,p);if {jx} then E()end;a=j%256;local k2=(j-j%256)/256;b=k2%256;c=(k2-k2%256)/256;\
elseif f==2 then a,p=Dv(CD,p);if {ax} then E()end;b=0;c=0;\
elseif f==3 then a,p=Dv(CD,p);b,p=Dv(CD,p);if {ax} or {bx} then E()end;c=0;\
elseif f==4 then a,p=Dv(CD,p);if {ax} then E()end;k2,p=Dv(CD,p);if {kx} then E()end;b=k2%256;c=(k2-k2%256)/256;\
else a,p=Dv(CD,p);b,p=Dv(CD,p);c,p=Dv(CD,p);if {ax} or {bx} or {cx} then E()end end;\
return a,b,c,p end;\nend,",
        key = keys[14],
        jx = jx,
        ax = ax,
        bx = bx,
        kx = kx,
        cx = cx,
    );
    decode_body = slot_rewrite(
        &mut structure,
        &decode_body,
        &["w", "v", "f", "a", "b", "c", "j", "k2"],
    );
    let decode_field = decode_body;
    let mut f3_arms: Vec<(u8, String)> = primitive_ops
        .iter()
        .map(|op| {
            (
                perm[(*op as u8) as usize],
                format!(
                    "{} then ok={};",
                    structure.dispatch_condition(
                        u64::from(perm[(*op as u8) as usize]) as u16,
                        program.target.is_luau()
                    ),
                    validation(*op)
                ),
            )
        })
        .collect();
    f3_arms.extend(f3_decoys);
    let f3_groups = (2 + structure.next_u64() % 3) as u8;
    let validate_body = format!(
        "local ok=false;{chain}if not ok then E()end;return true",
        chain = grouped_chain(&mut structure, f3_arms, f3_groups, "o"),
    );
    let validate_body = slot_rewrite(&mut structure, &validate_body, &["ok"]);
    let validate_field = format!(
        "[{key}]=function(E)\nreturn function(o,a,b,c,j,k,at,F,P,id)local g={{}};{body} end;\nend,",
        key = keys[15],
        body = validate_body,
    );
    // Semantic graph validator. The parser has already fail-closed the global
    // segment graph (masked root/id/next, owner, count, total and coverage) and
    // reconstructed each exact code image. Every stream begins with a masked
    // recipe dictionary and random entry label. Records
    // then carry four anonymous u16 slots (label, next/skip edge tokens and
    // recipe token in per-prototype factorial order) plus operand-only
    // varints. Shared three/five-stage nested state machines resolve edge and
    // recipe tokens from graph/prototype context both here and on every runtime
    // fetch. The persistent table retains only tokens. The validator builds a
    // label-keyed table, checks every primitive operand,
    // rejects control operations in the middle of a recipe, and verifies all
    // graph successors only after the shuffled records have been read.
    write!(s, "[{}]=function(P,np,SB,E,dec,vld,PT,FM,NX)\n", keys[2]).unwrap();
    let recipe_decoder = layered_recipe_decoder(&mut structure, &semantic_image.token_layers);
    let edge_decoder = layered_edge_decoder(&mut structure, &semantic_image.edge_layers);
    let tuple_slots = field_order.tuple_slots();
    let semantic_validator = format!(
        r#"{edge_decoder}{recipe_decoder}{operand_getter}
for id=0,np-1 do
 local F=P[id];local SP=F.__obf_proto_code;local CD=SP[2];if not CD or #CD~=SP[1] then E()end;F.__obf_proto_code=CD;local p=1;{operand_profile}{field_profile}
 local D16=function()local a,b=SB(CD,p),SB(CD,p+1);if b==nil then E()end;p=p+2;return a+b*256 end;
 local nr=D16();if nr==0 or nr>512 then E()end;local RM={{}};
 for z=1,nr do {dict_head}if rid==0 or n==nil or n<1 or n>4 or RM[rid]~=nil then E()end;
  local q={{}};for qi=0,n-1 do local raw=SB(CD,p);p=p+1;if raw==nil then E()end;
   local op=(raw-(rid*{mask_mul}+qi*{mask_add}+{mask_salt})%64)%64;
   if op>48 or FM[op]==nil or qi<n-1 and (op==44 or op==45 or op==46 or op==47)then E()end;q[qi+1]=op;
  end;RM[rid]=q;
 end;
 local start=D16();local code={{}};
 for at=0,F.__obf_proto_nc-1 do {record_head}local next1=ED(nextToken,label,id,0);local skip=ED(skipToken,label,id,1);local rid=RD(token,label,next1,skip,id);local recipe=RM[rid];
  if label==0 or code[label]~=nil or recipe==nil then E()end;{tuple_construct}
  for qi=1,#recipe do local op=recipe[qi];local a,b,c,p2=dec(CD,p,op);p=p2;local k=b+c*256;local j=a+k*256;
   if not vld(PT[op],a,b,c,j,k,at,F,P,id)then E()end;{operand_store}
  end;code[label]=I;
 end;
 if p~=#CD+1 or start==0 or code[start]==nil then E()end;
 for label,I in NX,code do local next1=ED(I[{tuple_next}],label,id,0);local skip=ED(I[{tuple_skip}],label,id,1);local last=I[4];local n=I[5];local a,b,c,k,j=OG(id,I,n,0);
  if last=={jump} then if next1~=0 or skip~=0 or code[j]==nil then E()end
  elseif last=={ret} or last=={tail} then if next1~=0 or skip~=0 then E()end
  elseif last=={test} then if code[next1]==nil or code[skip]==nil then E()end
  elseif code[next1]==nil or skip~=0 then E()end;
 end;code[0]=start;F.__obf_proto_code=code;
end;return RD,ED,OG;"#,
        mask_mul = semantic_image.mask_mul,
        mask_add = semantic_image.mask_add,
        mask_salt = semantic_image.mask_salt,
        operand_getter = operand_abi.getter_lua(),
        operand_profile = operand_abi.parser_profile_lua(),
        field_profile = field_order.record_profile_lua(),
        dict_head = field_order.dictionary_head_lua(),
        record_head = FieldLayout::record_head_lua(),
        tuple_construct = field_order.tuple_construct_lua(),
        tuple_next = tuple_slots[1],
        tuple_skip = tuple_slots[2],
        operand_store = OperandLayout::parser_store_lua(),
        jump = perm[Opcode::Jump as usize],
        test = perm[Opcode::Test as usize],
        ret = perm[Opcode::Return as usize],
        tail = perm[Opcode::TailCall as usize],
    );
    s.push_str(&semantic_validator);
    s.push_str("\nend,");
    let f4_start = s.len();
    write!(s, "[{}]=function(TY,E)\n", keys[3]).unwrap();
    s.push_str(
        r#"
local CV=function(cell)if cell[2]then return cell[2][cell[3]]else return cell[1]end end;
local SV=function(cell,value)if cell[2]then cell[2][cell[3]]=value else cell[1]=value end end;
"#,
    );
    if program.target.is_luau() && !program.methods().is_empty() {
        s.push_str("local Lookup=function(object,key)if ");
        s.push_str(ud_check);
        s.push_str("then ");
        for (index, method) in program.methods().iter().enumerate() {
            write!(s, "{} key==", if index == 0 { "if" } else { "elseif" }).unwrap();
            crate::vm::lua51::emit_byte_string(&mut s, method.as_bytes());
            write!(
                s,
                " then return function(_,...)return object:{method}(...)end;"
            )
            .unwrap();
        }
        s.push_str("else E()end;end;return object[key]end;");
    } else {
        if program.target.is_luau() {
            // Without a static method identifier we cannot synthesize a
            // faithful userdata NAMECALL; never silently use indexing instead.
            s.push_str("local Lookup=function(object,key)if ");
            s.push_str(ud_check);
            s.push_str("then E()end;return object[key]end;");
        } else {
            s.push_str("local Lookup=function(object,key)return object[key]end;");
        }
    }
    // Three audited key-probe functions: each consumes the target runtime's
    // debug-source transcript for `loadstring`, folds returned bytes into its
    // share after the seeded rounds, and returns no standalone witness. A
    // malformed transcript faults closed; a well-shaped but wrong transcript
    // derives wrong ChaCha8/frame keys and fails strict gates. The entry
    // calls the functions in seeded shuffled order.
    // Shuffled CALL order of the three probe functions (indices 0..=2 into
    // keys[5..8] / probe_inputs / shares).
    let mut probe_order = [0usize, 1, 2];
    crate::random::Prng::new(seed ^ 0x6f72_6433_6873_7663).shuffle(&mut probe_order);
    // Structural inputs per probe: pairs of payload-table numeric keys the
    // entry passes positionally. The Rust cipher derives the exact same
    // shares from the exact same pairs, so no share or final keystream state
    // exists as a script literal: each probe computes its transient share at
    // run time after consuming its environment transcript, using exact double
    // arithmetic.
    let probe_inputs = cipher_probe_inputs(&keys);
    let mut probe_fields = Vec::new();
    for (index, _) in shares.iter().enumerate() {
        let mut steps = String::new();
        for _ in 0..params.probe_rounds[index] {
            steps.push_str(&format!("x={}*x%2147483647;", params.outer));
        }
        let mut field = format!("[{}]=function(SB,a,b,DB,GI,LS)local A=", keys[5 + index]);
        if program.target.is_luau() {
            field.push_str("DB and GI(LS,\"s\");");
        } else {
            field.push_str("DB and GI(LS,\"S\");A=A and A.source;");
        }
        let _ = write!(
            field,
            "local x=(a*{}+b)%2147483647;{steps}a=0;b=1;while b<=#A do a=(a*257+SB(A,b))%2147483647;b=b+1 end;return 1+(x+a*{})%2147483646;end,",
            params.mix,
            params.mix,
        );
        probe_fields.push(field);
    }
    // ISA12-C entry stage graph. The dependency order remains strict, but the
    // former top-level decode -> decrypt -> decompress -> parse -> validate ->
    // execute statement chain is no longer a stable textual anchor. Six
    // seeded states are emitted in shuffled branch order with varied equality
    // spellings. Only the narrow stage outputs survive across iterations;
    // decoder helpers remain local to their state. This is a bounded entry
    // de-self-documenting measure, not a claim that the shipped inverses or
    // dependency graph are secret.
    s.push_str("\nreturn CV,SV,Lookup\nend,");
    let mut decoder_stage = decoder_wiring.replacen("local FMt,PT=", "FMt,PT=", 1);
    decoder_stage = decoder_stage.replacen("local P,np,entry=", "P,np,entry=", 1);
    if decoder_stage.contains("local FMt,PT=") || decoder_stage.contains("local P,np,entry=") {
        return Err(Diagnostic::new("entry decoder stage export rewrite failed"));
    }
    let entry_states = state_values(&mut structure, 6);
    let (e_prelude, e_probe, e_segments, e_decode, e_bind, e_run) = (
        entry_states[0],
        entry_states[1],
        entry_states[2],
        entry_states[3],
        entry_states[4],
        entry_states[5],
    );
    let prelude_stage = format!("{ret_names}=VMS[{}]();es={e_probe};", keys[0]);
    let probe_stage = format!(
        "c{cn0}=VMS[{}](SB,{},{},DBG,GI,LS);c{cn1}=VMS[{}](SB,{},{},DBG,GI,LS);c{cn2}=VMS[{}](SB,{},{},DBG,GI,LS);es={e_segments};",
        keys[5 + probe_order[0]],
        probe_inputs[probe_order[0]].0,
        probe_inputs[probe_order[0]].1,
        keys[5 + probe_order[1]],
        probe_inputs[probe_order[1]].0,
        probe_inputs[probe_order[1]].1,
        keys[5 + probe_order[2]],
        probe_inputs[probe_order[2]].0,
        probe_inputs[probe_order[2]].1,
        cn0 = probe_order[0] + 1,
        cn1 = probe_order[1] + 1,
        cn2 = probe_order[2] + 1,
    );
    let segment_stage = format!(
        "Y1=VMS[{}](E,SB,NCH,TC,DBG,GI,LS);Y2=VMS[{}](E,SB,NCH,TC,DBG,GI,LS);Y3=VMS[{}](E,SB,NCH,TC,DBG,GI,LS);local mV=VMS[{}](Y1,E,SB);VMS[{}](mV,E);es={e_decode};",
        keys[8 + hold[0]],
        keys[8 + hold[1]],
        keys[8 + hold[2]],
        keys[11],
        keys[12],
    );
    let decode_stage = format!("{decoder_stage}es={e_bind};");
    let bind_stage = format!(
        "P.__obf_proto_control=(c1+c2+c3)%65520;local dec=VMS[{}](E,SB,FMt);local vld=VMS[{}](E);RD,ED,OG=VMS[{}](P,np,SB,E,dec,vld,PT,FMt,NX);CV,SV,Lookup=VMS[{}](TY,E);es={e_run};",
        keys[14], keys[15], keys[2], keys[3],
    );
    let run_stage = format!(
        "local H=VMS[{}](SC,Z,U,G,E,PC,SB,SS,SF,MF,TN,TY,TS,NX,MT,SM,RG,RE,IF,Freeze,P,CV,SV,Lookup,RD,ED,OG);local result=H(entry,Z(...),{{}});return U(result,1,result.n);",
        keys[4]
    );
    let entry_machine = state_machine(
        &mut structure,
        "es",
        vec![
            (e_prelude, prelude_stage),
            (e_probe, probe_stage),
            (e_segments, segment_stage),
            (e_decode, decode_stage),
            (e_bind, bind_stage),
            (e_run, run_stage),
        ],
    );
    write!(
        s,
        "[\"{method}\"]=function(VMS,...){entry_head}\nlocal {ret_names};local c1,c2,c3,Y1,Y2,Y3,FMt,PT,P,np,entry,RD,ED,OG,CV,SV,Lookup;local es={e_prelude};{entry_machine}{entry_tail}\nend,\n"
    )
    .unwrap();
    write!(
        s,
        "[{}]=function(SC,Z,U,G,E,PC,SB,SS,SF,MF,TN,TY,TS,NX,MT,SM,RG,RE,IF,Freeze,P,CV,SV,Lookup,RD,ED,OG)\n",
        keys[4]
    )
    .unwrap();
    // Resolve after the opaque-wrapped entry graph; its length is now final.
    let f5_start = s
        .rfind(&format!("[{}]=function(SC,Z,U,G,E,", keys[4]))
        .expect("interpreter field anchor");
    s.push_str(
        r#"
local W=SM({},{__mode='kv'});local H;local Make;
"#,
    );
    s.push_str(call_body);
    s.push_str(&register_abi.factory_lua());
    s.push_str(
        r#"
Make=function(id,up)
 local F=P[id];local cached=F.__obf_proto_cached;
 if cached then local previous=W[cached][2];local same=true;
  for j=0,F.__obf_proto_nu-1 do if j~=F.__obf_proto_self and not RE(CV(previous[j]),CV(up[j]))then same=false;break end end;
  if same then return cached end;
 end;
 local d={id,up};local fn=function(...)local vv=H(d[1],Z(...),d[2]);return U(vv,1,vv.n)end;W[fn]=d;
 if F.__obf_proto_shared and not cached then F.__obf_proto_cached=fn end;return fn
end;
local SETUP=function(fid,args)
 local F=P[fid];local R={};local RX,RF=RK(fid,R);local nn=args.n-F.__obf_proto_p;if nn<0 then nn=0 end;
 local va2={};va2.n=nn;for i=1,nn do va2[i]=args[F.__obf_proto_p+i]end;
 for i=0,F.__obf_proto_p-1 do R[RX(i)]={args[i+1]}end;
 if MF(F.__obf_proto_flags/2)%2==1 then R[RX(F.__obf_proto_p)]={};if MF(F.__obf_proto_flags/4)%2==1 then local vv={};vv.n=nn;for i=1,nn do vv[i]=va2[i]end;R[RX(F.__obf_proto_p)][1]=vv end end;
 return F,R,va2,RX,RF,nn
end;
"#);
    // SETUP-only scratch slots: the frame registers F/R keep their locals
    // because the interpreter recurses (nested frames would clobber a
    // single slot), but SETUP's own intermediates flow through g[key].
    {
        let original = r#"local SETUP=function(fid,args)
 local F=P[fid];local R={};local RX,RF=RK(fid,R);local nn=args.n-F.__obf_proto_p;if nn<0 then nn=0 end;
 local va2={};va2.n=nn;for i=1,nn do va2[i]=args[F.__obf_proto_p+i]end;
 for i=0,F.__obf_proto_p-1 do R[RX(i)]={args[i+1]}end;
 if MF(F.__obf_proto_flags/2)%2==1 then R[RX(F.__obf_proto_p)]={};if MF(F.__obf_proto_flags/4)%2==1 then local vv={};vv.n=nn;for i=1,nn do vv[i]=va2[i]end;R[RX(F.__obf_proto_p)][1]=vv end end;
 return F,R,va2,RX,RF,nn
end;
"#;
        let slotted = original.to_owned();
        let slotted = slotted.replacen(
            "local SETUP=function(fid,args)\n",
            "local SETUP=function(fid,args)\nlocal g={};",
            1,
        );
        s = s.replacen(original, &slotted, 1);
    }
    // Recipe-threaded semantic interpreter. The fetch phase follows a
    // random label graph (there is no linear four-byte PC), then resolves the
    // record's two edge tokens through ED and its context token through RD.
    // ED has three live/three dead states; RD has five real states, 4..5 nested
    // opaque guards per state, and five dense dead states before dispatch.
    // Reachable neutral bundles split entries and selected CFG edges. ISA12-C
    // keeps random global fragment states but replaces the old "two raw
    // handlers in one arm" convention with maximum non-overlapping, structurally
    // safe carried-value pairs. Every selected 2-op range is true dataflow
    // fusion; unsupported pairs are emitted as separate one-op fragments.
    // Control primitives stay single, preserving return/tail-call/break lexical
    // behavior in this loop.
    let mut chunk_ranges: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut fragment_count = 0usize;
    for recipe in &semantic_image.recipes {
        if !(1..=semantic::MAX_BUNDLE_WORDS).contains(&recipe.execute_ops.len()) {
            return Err(Diagnostic::new("invalid semantic recipe length"));
        }
        // P0: every op runs its seed routine; fragments are always single
        // (textual dataflow fusion retired with the classic handler bodies).
        let ranges: Vec<(usize, usize)> = (0..recipe.execute_ops.len()).map(|i| (i, 1)).collect();
        fragment_count += ranges.len();
        chunk_ranges.push(ranges);
    }
    if fragment_count >= 900 {
        return Err(Diagnostic::new("semantic fragment state space exhausted"));
    }
    let mut fragment_states = state_values(&mut structure, fragment_count + 1);
    structure.shuffle(&mut fragment_states);
    let semantic_init = fragment_states.pop().unwrap();
    let mut state_cursor = 0usize;
    let recipe_chunks: Vec<Vec<(usize, usize, u16)>> = chunk_ranges
        .into_iter()
        .map(|ranges| {
            ranges
                .into_iter()
                .map(|(start, length)| {
                    let state = fragment_states[state_cursor];
                    state_cursor += 1;
                    (start, length, state)
                })
                .collect()
        })
        .collect();
    debug_assert_eq!(state_cursor, fragment_count);

    let fsv = state_values(&mut structure, 4);
    let (k_fetch, k_disp, k_fetch_alt, k_disp_alt) = (fsv[0], fsv[1], fsv[2], fsv[3]);
    let control_mask = "P.__obf_proto_control";
    let c_fetch =
        selected_masked_state_condition(&mut structure, "w", control_mask, k_fetch, k_fetch_alt);
    let c_disp =
        selected_masked_state_condition(&mut structure, "w", control_mask, k_disp, k_disp_alt);
    let v_fetch = selected_masked_state_value(k_fetch, k_fetch_alt, control_mask);
    let v_disp = selected_masked_state_value(k_disp, k_disp_alt, control_mask);
    let dispatch_first = structure.next_u64() % 2 == 0;
    // Seed-ISA v1 prelude: after Make binds (so the helper pool captures
    // live values) and before H (so every arm reaches it lexically).
    let mut seed_used = 0u64;
    for recipe in &semantic_image.recipes {
        for op in &recipe.execute_ops {
            seed_used |= seed_op_bit(*op);
        }
    }
    s.push_str(&seed_prelude_lua_v1(program.target, seed, seed_used));
    let fetch_branch = format!(
        "{c_fetch} then\n   I=code[pc];if I==nil then E()end;next1=ED(I[{tuple_next}],pc,fid,0);skip1=ED(I[{tuple_skip}],pc,fid,1);rid=RD(I[{tuple_token}],pc,next1,skip1,fid);sid={semantic_init};pc=next1;w={v_disp};",
        tuple_next = tuple_slots[1],
        tuple_skip = tuple_slots[2],
        tuple_token = tuple_slots[0],
    );
    write!(
        s,
        "H=function(fid,args,ups)\n local F,R,va,RX,RF,K;\n{seed_loop} while true do\n  F,R,va,RX,RF=SETUP(fid,args);K=F.__obf_proto_k;\n  local code=F.__obf_proto_code;local pc=code[0];\n  local I,rid,sid,next1,skip1,a,b,c,k,j;local w={v_fetch};\n  while true do\n   {machine_open}",
        seed_loop = seed_loop_lua(program.target),
        machine_open = if dispatch_first {
            format!("if {c_disp} then ")
        } else {
            format!("if {fetch_branch}\n   elseif {c_disp} then ")
        },
    )
    .unwrap();
    let mut recipe_entries: Vec<(u16, String)> = Vec::new();
    let mut fragment_arms: Vec<(u16, String)> = Vec::new();
    let mut binding_forms = [0usize, 1, 2, 3];
    debug_assert_eq!(binding_forms.len(), OPERAND_BINDING_FORMS);
    structure.shuffle(&mut binding_forms);
    let mut binding_cursor = 0usize;
    for (recipe, chunks) in semantic_image.recipes.iter().zip(&recipe_chunks) {
        if recipe.live {
            debug_assert!(recipe.descriptor_ops.iter().zip(&recipe.execute_ops).all(
                |(&descriptor, &actual)| {
                    semantic::descriptor_class(descriptor) == semantic::descriptor_class(actual)
                        && custom::encoding_form(descriptor) == custom::encoding_form(actual)
                }
            ));
        } else {
            debug_assert_ne!(recipe.descriptor_ops, recipe.execute_ops);
        }
        let entry_condition =
            structure.dispatch_condition_for("rid", recipe.id, program.target.is_luau());
        recipe_entries.push((
            recipe.id,
            format!("{entry_condition} then sid={};", chunks[0].2),
        ));
        for (chunk_index, &(start, length, stage)) in chunks.iter().enumerate() {
            let mut body = String::new();
            if length == 1 {
                let op = recipe.execute_ops[start];
                if binding_cursor == binding_forms.len() {
                    structure.shuffle(&mut binding_forms);
                    binding_cursor = 0;
                }
                let form = binding_forms[binding_cursor];
                binding_cursor += 1;
                body.push_str(&operand_binding_lua(start + 1, form));
                // P0: every supported op runs its seed routine.
                let arm = seed_arm_lua_for(program.target, op)
                    .ok_or_else(|| Diagnostic::new("missing seed arm for opcode"))?;
                body.push_str(&arm);
            } else {
                return Err(Diagnostic::new("invalid semantic fragment width"));
            }
            let exits_frame = matches!(
                recipe.execute_ops[start + length - 1],
                Opcode::Return | Opcode::TailCall
            );
            if !exits_frame {
                if let Some(next) = chunks.get(chunk_index + 1) {
                    write!(body, "sid={};", next.2).unwrap();
                } else {
                    write!(body, "sid={semantic_init};").unwrap();
                }
            }
            let condition =
                structure.dispatch_condition_for("sid", stage, program.target.is_luau());
            fragment_arms.push((stage, format!("{condition} then {body}")));
        }
    }
    let recipe_groups = (2 + structure.next_u64() % 3) as u8;
    let fragment_groups = (2 + structure.next_u64() % 3) as u8;
    let recipe_chain = grouped_recipe_chain(&mut structure, recipe_entries, recipe_groups, "rid");
    let fragment_chain =
        grouped_recipe_chain(&mut structure, fragment_arms, fragment_groups, "sid");
    let init_condition = state_condition(&mut structure, "sid", semantic_init);
    write!(
        s,
        "if {init_condition} then {recipe_chain}else {fragment_chain}end;if {init_condition} then w={v_fetch};end;"
    )
    .unwrap();
    if dispatch_first {
        write!(s, "\n   elseif {fetch_branch}\n   else E()end;").unwrap();
    } else {
        s.push_str("\n   else E()end;");
    }
    s.push_str("\n  end;end;end;return H");
    let forwards_varargs = program.prototypes[program.entry]
        .code
        .iter()
        .any(|word| matches!(word.opcode(), Ok(Opcode::Varargs)));
    s.push_str("\nend");
    let tail_start = s.len();
    write!(
        s,
        "}},x):{method}({})",
        if forwards_varargs { "..." } else { "" }
    )
    .unwrap();
    // Full code randomization: every payload field except the (entry +
    // interpreter) anchor chunk is emitted in a seeded shuffled textual
    // order. Field semantics are numeric-key based, so layout order is
    // free; the decryption/probe/segment functions now also land at random
    // positions in the file, and the interpreter's dispatch arms were
    // shuffled above.
    let entry_start = s
        .rfind(&format!("[\"{method}\"]=function(VMS,...)"))
        .expect("entry field anchor");
    // Full-field unanchoring: the entry and interpreter fields leave the
    // fixed tail too; all seventeen payload fields shuffle together and the
    // file ends with the bare wrapper close.
    let entry_chunk = s[entry_start..f5_start].to_owned();
    let f5_chunk = s[f5_start..tail_start].to_owned();
    let tail = s[tail_start..].to_owned();
    // Scratch-table slots for the two remaining core fields: the operand
    // validation loop and the interpreter (its frame registers R and frame
    // F included -- every read/write goes through g[key] with per-seed
    // keys, the value constantly changing). The interpreter's table lives
    // as long as its closures do, so it is not cleared.
    let f3_chunk = slot_rewrite(
        &mut structure,
        &s[f3_start..f4_start],
        &["F", "CD", "p", "XB", "o", "a", "b", "c", "p2", "k", "j"],
    );
    let f3_chunk = f3_chunk.replacen(")\n", ")\nlocal g={};", 1);
    // The interpreter itself keeps plain locals: it recurses through
    // nested frames (closures, pcall), and a single g[key] slot per frame
    // register would be clobbered by the inner frame. All non-recursive
    // core stages flow through g[key] scratch slots instead.
    let mut fields: Vec<String> = vec![
        s[header_end..f3_start].to_owned(),
        f3_chunk,
        s[f4_start..entry_start].to_owned(),
    ];
    fields.extend(probe_fields);
    fields.extend(segment_fields);
    fields.extend(watermark_fields);
    fields.extend([forms_field, decode_field, validate_field]);
    fields.extend(decoder_fields);
    fields.extend([entry_chunk, f5_chunk]);
    structure.shuffle(&mut fields);
    let mut out = s[..header_end].to_owned();
    for field in &fields {
        // Field-separator variant: `,` and `;` are interchangeable field
        // separators, and a trailing one before `}` is equally legal; the
        // choice is drawn per field from the structure stream.
        let (body, suffix) = if let Some(stripped) = field.strip_suffix(",\n") {
            (stripped, "\n")
        } else if let Some(stripped) = field.strip_suffix(',') {
            (stripped, "")
        } else {
            (field.as_str(), "")
        };
        assert!(
            body.ends_with("end"),
            "field does not end in end; tail: {:?}",
            &body[body.len().saturating_sub(60)..]
        );
        out.push_str(body);
        out.push(if structure.next_u64() % 2 == 0 {
            ','
        } else {
            ';'
        });
        out.push_str(suffix);
    }
    out.push_str(&tail);
    s = out;
    if s.len() > crate::lexer::MAX_SOURCE_BYTES {
        return Err(Diagnostic::new(
            "generated custom VM exceeds source safety limit",
        ));
    }
    Ok(s)
}

/// Build the strict Lua-side inverse of the bounded LZW frame. The bit-reader
/// and dictionary stages are either separate sibling payload functions or one
/// combined function according to the seed; the inner-ChaCha8/frame stage is
/// always a third independently keyed field. The outer layout pass shuffles all of them
/// among unrelated VM sections, so neither count nor physical position is a
/// stable decoder signature.
fn compression_decoder_sections(keys: &[u64], split_helpers: bool) -> (Vec<String>, String) {
    let bit_reader = r#"local BR=function(S,N)local p=0;local R=function(n)if p>N-n then E()end;local v=0;for j=0,n-1 do local q=p+j;v=v+MF(SB(S,MF(q/8)+1)/2^(q%8))%2*2^j end;p=p+n;return v end;return R,function()return p end end;"#;
    let lzw_decoder = r#"local LD=function(S,N,L)local R,RP=BR(S,N);local O={};local total=0;while total<L do local lim=total+8192;if lim>L then lim=L end;local DP,ST={},{};local nx=256;local prev=nil;local pf=0;while total<lim do local t=R(1);local code;if t==1 then code=R(8);if code<32 then E()end else t=R(1);if t==1 then code=R(5)else if prev==nil then E()end;local w=0;local z=nx-256;while z>0 do w=w+1;z=MF(z/2)end;code=256+R(w)end end;if code>nx then E()end;local special=code==nx;if special then DP[nx]=prev*256+pf end;local sn=0;local cur=code;while cur>=256 do local z=DP[cur];sn=sn+1;ST[sn]=z%256;cur=MF(z/256)end;sn=sn+1;ST[sn]=cur;local first=cur;if not special and prev~=nil then DP[nx]=prev*256+first end;if prev~=nil then nx=nx+1 end;prev=code;pf=first;if total+sn>lim then E()end;for j=sn,1,-1 do total=total+1;O[total]=NCH(ST[j])end end end;if RP()~=N then E()end;return TC(O)end;"#;
    let mut fields = Vec::new();
    let wiring = if split_helpers {
        fields.push(format!(
            "[{}]=function(E,SB,MF){bit_reader}return BR end,",
            keys[21]
        ));
        fields.push(format!(
            "[{}]=function(E,SB,NCH,TC,MF,BR){lzw_decoder}return LD end,",
            keys[22]
        ));
        format!(
            "local BR=VMS[{}](E,SB,MF);local LD=VMS[{}](E,SB,NCH,TC,MF,BR);",
            keys[21], keys[22]
        )
    } else {
        fields.push(format!(
            "[{}]=function(E,SB,NCH,TC,MF){bit_reader}{lzw_decoder}return LD end,",
            keys[22]
        ));
        format!("local LD=VMS[{}](E,SB,NCH,TC,MF);", keys[22])
    };
    let core = r#"if #C<17 or L32(C,1)~=22501964 then E()end;local n=L32(C,5);local bits=L32(C,9);local cs=L32(C,13);local bl=MF((bits+7)/8);local cc=MF((n+8191)/8192);if n<1 or n>16777216 or bits<1 or bl~=#C-16 or #C>=n then E()end;local ctx=(n*31+bits*17+cs*7+cc*13+bl)%4294967296;local aw=AH(AH,CC,CB,X8,E,SB,NCH,TC,MF,DBG,GI,LS);local D=CC(SS(C,17),s1,s2,s3,pv,ctx,2,aw,CB,E,SB,NCH,TC,MF,X8);local pad=#D*8-bits;if pad>7 or pad>0 and MF(SB(D,#D)/2^(8-pad))~=0 then E()end;local B=LD(D,bits,n);if AD(B,1,#B)~=cs then E()end;return B"#;
    fields.push(format!(
        "[{}]=function(C,s1,s2,s3,pv,CC,AH,CB,LD,E,SB,SS,NCH,TC,MF,X8,AD,L32,DBG,GI,LS){core} end,",
        keys[23]
    ));
    let wiring = format!(
        "{wiring}local B=VMS[{}](C,c1,c2,c3,pv,CC,AH,CB,LD,E,SB,SS,NCH,TC,MF,X8,AD,L32,DBG,GI,LS);",
        keys[23]
    );
    (fields, wiring)
}

/// Compact strict frame-v2 inverse. Confidentiality is handled by the outer
/// ChaCha8 field; this stage validates every framed byte before returning the
/// independently encrypted compression frame.
fn transport_frame_decoder(params: &FrameParams) -> String {
    let c0 = params.key_coefficients[0];
    let c1 = params.key_coefficients[1];
    format!(
        "if #B<{header} or #B%4~=0 or #B>16777232 then E()end;local fk0=1+(s1*{c00}+s2*{c01}+s3*{c02}+pv*{c03}+#B*{c04}+{s0})%2147483646;local fk1=1+(s1*{c10}+s2*{c11}+s3*{c12}+pv*{c13}+#B*{c14}+{s1})%2147483646;local fd={version}+{header}*256+(fk0+fk1+{descriptor})%65536*65536;local d=L32(B,1);local n=L32(B,5);local c=L32(B,9);local t=L32(B,13);local pad=(4-(16+n)%4)%4;if n>16777216 or #B~=16+n+pad or d~=fd then E()end;local ex=(n+d*257+(fk0%65536)*65536+(fk1%65536)*17+{cookie})%4294967296;if c~=ex then E()end;ex=(AD(B,17,16+n)+c*263+d*31+(fk0%65536)*65536+fk1%65536+{tag})%4294967296;if t~=ex then E()end;for i=1,pad do if SB(B,16+n+i)~=(fk0+fk1*i+{padding})%256 then E()end end;B=SS(B,17,16+n);",
        header = TRANSPORT_FRAME_HEADER,
        version = TRANSPORT_FRAME_VERSION,
        c00 = c0[0],
        c01 = c0[1],
        c02 = c0[2],
        c03 = c0[3],
        c04 = c0[4],
        c10 = c1[0],
        c11 = c1[1],
        c12 = c1[2],
        c13 = c1[3],
        c14 = c1[4],
        s0 = params.key_salts[0],
        s1 = params.key_salts[1],
        descriptor = params.descriptor_salt,
        cookie = params.cookie_salt,
        tag = params.tag_salt,
        padding = params.padding_salt,
    )
}

#[cfg(test)]
pub(crate) fn generate_from_semantic_image(
    program: &Program,
    seed: u64,
    semantic_image: semantic::SemanticImage,
) -> Result<String, Diagnostic> {
    custom::validate(program)?;
    generate_semantic(program, seed, semantic_image, None)
}

#[cfg(test)]
pub(crate) fn generate_from_compression_frame(
    program: &Program,
    seed: u64,
    semantic_image: semantic::SemanticImage,
    frame: Vec<u8>,
) -> Result<String, Diagnostic> {
    custom::validate(program)?;
    generate_semantic(program, seed, semantic_image, Some(frame))
}

pub(super) fn validation(op: Opcode) -> &'static str {
    use Opcode::*;
    match op {
        Jump => "j>0 and j<=65535",
        Constant => "a<F.__obf_proto_m and k<F.__obf_proto_nk",
        ReadGlobal | WriteGlobal => {
            "a<F.__obf_proto_m and (F.__obf_proto_tags[k]==3 or F.__obf_proto_tags[k]==5)"
        }
        Closure => "a<F.__obf_proto_m and P[k]~=nil and P[k].__obf_proto_parent==id",
        ReadUpvalue | WriteUpvalue => "a<F.__obf_proto_m and b<F.__obf_proto_nu and c==0",
        Extract => "a<F.__obf_proto_m and b<F.__obf_proto_m and c>0",
        Clear => "a<=b and b<F.__obf_proto_m and c==0",
        NumberPrepare | NumberStep => "a+2<F.__obf_proto_m and b==0 and c==0",
        NumberTest => "a<F.__obf_proto_m and b+2<F.__obf_proto_m and c==0",
        Test => "a<F.__obf_proto_m and b==0 and c==0",
        Varargs => "a<F.__obf_proto_m and b==0 and c==0 and F.__obf_proto_flags%2==1",
        Nil | NewTable | NewPack | IteratorPrepare | Return | Freeze => {
            "a<F.__obf_proto_m and b==0 and c==0"
        }
        Move | NewCell | ReadCell | WriteCell | Push | Extend | Not | Negate | Length
        | IteratorNext | ToString | TailCall => "a<F.__obf_proto_m and b<F.__obf_proto_m and c==0",
        GetTable | SetTable | Method | Call | Add | Subtract | Multiply | Divide | FloorDivide
        | Modulo | Power | Concat | Equal | Less | LessEqual | SetList | Export => {
            "a<F.__obf_proto_m and b<F.__obf_proto_m and c<F.__obf_proto_m"
        }
    }
}
