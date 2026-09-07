use super::*;

use std::fmt::Write as _;

pub(crate) fn generate(
    bytecode: &[u8],
    program: &Program,
    seed: u64,
) -> Result<String, Diagnostic> {
    custom::validate(program)?;
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
    // The embedded payload is byte-encrypted at generation time with a
    // seed-derived Lehmer keystream; the key is split into three shares, one
    // per probe function, and the entry calls them in seeded shuffled order
    // before combining the shares and decrypting at runtime. The method call
    // resolves the entry directly as an own key of the payload table,
    // receives (self) — or (self,...) when the chunk reads `...` — chains
    // the sections in order and returns the program result. The metatable
    // local is the plain empty table required by the format.
    let method = wrapper_method(program.target, seed);
    let keys = wrapper_keys(seed);
    let params = cipher_params(seed);
    // Per-seed opcode renumbering: every canonical ISA slot is mapped to a
    // fresh distinct byte value, so the dispatch chains of each generation
    // run on a different numbering. The canonical numbering survives only
    // inside the `.obf` file and the encrypted varint stream; the Lua side
    // rebuilds the identical table from the packed string of the forms
    // field and rewrites each opcode byte during validation expansion.
    let perm = opcode_permutation(seed, 64);
    let opcode_image: std::collections::BTreeSet<u8> = program
        .opcodes()
        .iter()
        .map(|op| perm[(*op as u8) as usize])
        .collect();
    // The interpreter's classic decoys must dodge the FULL permutation
    // image (all 64 slots, not just the program's opcodes): the in-image
    // decoy arms below own every unused-slot value, so a decoy colliding
    // with one would silently duplicate a poisoned arm's key.
    let perm_image: std::collections::BTreeSet<u8> = perm.iter().copied().collect();
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
    let mut f5_decoys = decoy_arms(
        &mut structure,
        2,
        program.target.is_luau(),
        &[
            "R[a]={R[b]};pc=j;",
            "R[a]=R[b][R[c]];pc=pc+4;",
            "k=j;R[a]=k;pc=pc+4;",
        ],
        &perm_image,
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
    let mut ret_order: Vec<&str> = vec![
        "SC", "Z", "U", "G", "E", "SB", "SS", "SF", "NCH", "TC", "MF", "TN", "TY", "TS", "NX",
        "MT", "SM", "RG", "RE", "IF", "Freeze", "DBG", "GI", "LS",
    ];
    structure.shuffle(&mut ret_order);
    let ret_names = ret_order.join(",");
    s.push_str(&format!("\nreturn {ret_names}\nend,"));
    // The decoder section receives the three audited probe shares (each probe
    // function already verified the environment and was called by the entry
    // in seeded shuffled order), the two structural constant-cipher keys and
    // the shared helpers. It combines the shares into the outer keystream
    // seed, byte-decrypts the embedded blob, then decrypts every constant
    // record payload with the SECOND, independent keystream while parsing.
    // Lehmer 48271 mod 2147483647 keeps every intermediate below 2^53, so the
    // Lua-side double arithmetic reproduces both Rust streams bit-for-bit.
    let shares = cipher_shares(&keys, &params);
    // Second, independent cipher layer over the constant pool: every
    // constant-record payload inside the embedded image (boolean value byte,
    // number/integer 8 bytes, string length + content) is XORed with its own
    // structurally derived keystream before the whole image enters the outer
    // cipher, so constants stay encrypted even for an analyst who strips the
    // outer layer. The Adler-32 is patched over the constant-encrypted
    // image; the canonical `.obf` on disk stays plaintext and unchanged.
    let mut payload = bytecode.to_vec();
    apply_constant_cipher(&mut payload, &keys, program.target, &params)?;
    let encrypted = lehmer_cipher(&payload, &shares, params.outer, params.mix);
    // Transport layer: the doubly encrypted image is base86-encoded (all
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
    // Random decoder sections: the monolithic decoder is flattened into
    // sibling payload fields -- a decrypt field, a seeded 2..4 cluster
    // split of the six helper groups (byte-stream readers, double
    // reconstructor, constant keystream, XOR core, encrypted readers,
    // number family) and the parse core. Every field lands at a random
    // layout position; the call order in the entry is the fixed
    // dependency chain. `bp` stays an upvalue inside the reader cluster;
    // the core's final position check goes through the exported `pos`
    // accessor (a returned copy of the number would go stale).
    // Flattened outer-decrypt machine: keystream XOR self-loop, rebuild
    // and size gate, finish -- state numbers and spellings per seed. All
    // data locals flow through the scratch table g[...] (per-seed keys),
    // cleared before the field returns.
    let dsv = state_values(&mut structure, 3);
    let (d_loop, d_gate, d_done) = (dsv[0], dsv[1], dsv[2]);
    let xor_step = format!(
        "st={outer}*st%2147483647;local x=SB(B,i);local y=st%256;local r=0;local p=1;\
for j=1,8 do local q=(x%2+y%2)%2;if q==1 then r=r+p end;x=(x-x%2)/2;y=(y-y%2)/2;p=p*2 end;\
XB[i]=NCH(r);i=i+1;",
        outer = params.outer
    );
    let mut decrypt_text = format!(
        "local st=1+(s1+s2+s3+{mix}*#B)%2147483646;local XB={{}};local i=1;local w={d_loop};\
{machine}",
        mix = params.mix,
        machine = state_machine(
            &mut structure,
            "w",
            vec![
                (
                    d_loop,
                    format!("if i>#B then w={d_gate} else {xor_step} end;"),
                ),
                (
                    d_gate,
                    format!("B=TC(XB);XB=nil;if #B>16777216 then E()end;w={d_done};"),
                ),
                (d_done, "g=nil;return B;".to_owned()),
            ],
        ),
    );
    decrypt_text = slot_rewrite(
        &mut structure,
        &decrypt_text,
        &["st", "XB", "i", "w", "x", "y", "r", "p", "q"],
    );
    let decrypt_field = format!(
        "[{}]=function(B,s1,s2,s3,E,SB,SS,SF,NCH,TC,MF,IF)\nlocal g={{}};\n{decrypt_text}\nend,",
        keys[1]
    );
    let g1 = r#"local bp=1;
local b8=function()local v=SB(B,bp);if v==nil then E()end;bp=bp+1;return v end;
local b16=function()local a,b=b8(),b8();return a+b*256 end;
local b32=function()local a,b,c,d=b8(),b8(),b8(),b8();return a+b*256+c*65536+d*16777216 end;
local take=function(n)if n>#B-bp+1 then E()end;local v=SS(B,bp,bp+n-1);bp=bp+n;return v end;
local str=function()return take(b32())end;
local pos=function()return bp end;"#
        .to_owned();
    let g2 = r#"local fin=function(lo,hi)local sg=hi>=2147483648 and -1 or 1;local ex=MF(hi/1048576)%2048;local fr=(hi%1048576)*4294967296+lo;if ex==2047 then if fr==0 then return sg/0 else return 0/0 end elseif ex==0 then return sg*(fr*2^-1074) else return sg*((1+fr/4503599627370496)*2^(ex-1023))end end;"#
        .to_owned();
    let mut ku_steps = String::new();
    for _ in 0..params.constant_rounds {
        ku_steps.push_str(&format!("ku={}*ku%2147483647;", params.constant));
    }
    let g3 = format!(
        "local ku=(ca*{mix}+cb)%2147483647;{ku_steps}\nlocal ks=1+(ku+{mix}*#B)%2147483646;local KA=function()ks={mult}*ks%2147483647;return ks%256 end;",
        mix = params.mix,
        mult = params.constant
    );
    let g4g5g6 = r#"local DX=function(u)local y=KA();local r=0;local w=1;for j=1,8 do local q=(u%2+y%2)%2;if q==1 then r=r+w end;u=(u-u%2)/2;y=(y-y%2)/2;w=w*2 end;return r end;
local db8=function()return DX(b8())end;
local db32=function()local p,q,r,t=db8(),db8(),db8(),db8();return p+q*256+r*65536+t*16777216 end;
local dstr=function()local v=take(b32());local o={}for i=1,#v do o[i]=NCH(DX(SB(v,i)))end;return TC(o)end;
local num=function()return fin(b32(),b32())end;
local dnum=function()return fin(db32(),db32())end;"#
        .to_owned();
    let (g4, g5, g6) = (
        g4g5g6[..g4g5g6.find("local db8").unwrap()].to_owned(),
        g4g5g6[g4g5g6.find("local db8").unwrap()..g4g5g6.find("local num").unwrap()].to_owned(),
        g4g5g6[g4g5g6.find("local num").unwrap()..].to_owned(),
    );
    // (params, exports, text) per helper group, in dependency order.
    let groups: Vec<(&[&str], &[&str], String)> = vec![
        (
            &["B", "E", "SB", "SS"],
            &["b8", "b16", "b32", "take", "str", "pos"],
            g1,
        ),
        (&["MF"], &["fin"], g2),
        (&["B", "ca", "cb"], &["KA"], g3),
        (&["KA"], &["DX"], g4),
        (
            &["b8", "b32", "take", "SB", "NCH", "TC", "DX"],
            &["db8", "db32", "dstr"],
            g5,
        ),
        (&["fin", "b32", "db32"], &["num", "dnum"], g6),
    ];
    let base_names = ["B", "E", "SB", "SS", "NCH", "TC", "MF", "ca", "cb"];
    let cluster_count = 2 + structure.next_u64() % 3;
    let mut bounds_set = std::collections::BTreeSet::new();
    while bounds_set.len() < (cluster_count - 1) as usize {
        bounds_set.insert(1 + structure.next_u64() % 5);
    }
    let mut bounds: Vec<usize> = bounds_set.into_iter().map(|b| b as usize).collect();
    bounds.push(groups.len());
    let mut decoder_fields = vec![decrypt_field];
    let mut decoder_wiring = format!(
        "local B=VMS[{}](SS(Y1..Y2..Y3,5),c1,c2,c3,E,SB,SS,SF,NCH,TC,MF,IF);",
        keys[1]
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
        let args = params
            .iter()
            .map(|name| match *name {
                "ca" => keys[4].to_string(),
                "cb" => keys[7].to_string(),
                other => other.to_owned(),
            })
            .collect::<Vec<_>>()
            .join(",");
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
    core_text.push_str(
        r#"
if b8()~=1 or b8()~=0 or b8()~=0 or b32()~=32 or b32()~=#B then E()end;
local np=b32();local entry=b32();local isa=b32();if np==0 or np>65536 or entry~=0 or isa<1 or isa>2 then E()end;
local check=b32();local sa,sb=1,0;for q=33,#B do sa=(sa+SB(B,q))%65521;sb=(sb+sa)%65521 end;
if sa+sb*65536~=check then E()end;
"#,
    );
    // Flattened parse core: the per-prototype stages are split into local
    // functions -- header read/validate (PH), upvalue wiring (PU), constant
    // pool (PK) -- whose definition order shuffles per seed, driven by a
    // seeded state machine (next/header -> upvalues -> constants -> take
    // code -> advance; finish breaks out to the field's return).
    let csv = state_values(&mut structure, 5);
    let (c_next, c_up, c_konst, c_code, c_fin) = (csv[0], csv[1], csv[2], csv[3], csv[4]);
    let mut ph = String::from(
        "local PH=function()\n local F={__obf_proto_k={},__obf_proto_tags={},__obf_proto_u={}};F.__obf_proto_parent=b32();F.__obf_proto_m=b16();F.__obf_proto_p=b8();F.__obf_proto_flags=b8();F.__obf_proto_nu=b16();\n",
    );
    ph.push_str(
        " if b16()~=0 then E()end;F.__obf_proto_nk=b32();F.__obf_proto_nc=b32();local VMCS=b32();\n if F.__obf_proto_m<1 or F.__obf_proto_m>256 or F.__obf_proto_p>F.__obf_proto_m or F.__obf_proto_nu>256 or F.__obf_proto_nk>65536 or F.__obf_proto_nc<1 or F.__obf_proto_flags>15 or VMCS<F.__obf_proto_nc*2 or VMCS>F.__obf_proto_nc*7 then E()end;\n F.__obf_proto_shared=MF(F.__obf_proto_flags/8)%2==1;if F.__obf_proto_shared and (isa<2 or id==0)then E()end;\n if id==0 then if F.__obf_proto_parent~=4294967295 or F.__obf_proto_nu~=0 or MF(F.__obf_proto_flags/2)%2~=0 then E()end\n elseif F.__obf_proto_parent>=id then E()end;\n local legacy=MF(F.__obf_proto_flags/2)%2;\n if legacy==1 and (F.__obf_proto_flags%2==0 or F.__obf_proto_p>=F.__obf_proto_m)or MF(F.__obf_proto_flags/4)%2==1 and legacy==0 then E()end;\n",
    );
    if program.target.is_luau() {
        ph.push_str("if legacy~=0 then E()end;");
    } else {
        ph.push_str("if F.__obf_proto_shared then E()end;");
    }
    ph.push_str("\n return F,VMCS\nend;\n");
    let pu = "local PU=function()\n for j=0,F.__obf_proto_nu-1 do local tag,index=b8(),b8();local parent=P[F.__obf_proto_parent];\n  if tag>2 or not parent or tag~=1 and index>=parent.__obf_proto_m or tag==1 and index>=parent.__obf_proto_nu then E()end;\n  if tag==2 then if not F.__obf_proto_shared or F.__obf_proto_self~=nil then E()end;F.__obf_proto_self=j end;\n  F.__obf_proto_u[j]={tag,index};\n end;\nend;\n"
        .to_owned();
    let mut pk = String::from(
        "local PK=function()\n for j=0,F.__obf_proto_nk-1 do local tag=b8();F.__obf_proto_tags[j]=tag;\n  if tag==0 then F.__obf_proto_k[j]=nil\n  elseif tag==1 then local v=db8();if v>1 then E()end;F.__obf_proto_k[j]=v==1\n  elseif tag==2 then F.__obf_proto_k[j]=dnum()\n  elseif tag==3 or tag==5 then F.__obf_proto_k[j]=dstr()\n",
    );
    if program.target.is_luau() {
        pk.push_str(r#"elseif tag==4 then local lo,hi=db32(),db32();if not IF then E()end;local v=IF(SF('%08x%08x',hi,lo),16);if v==nil then E()end;F.__obf_proto_k[j]=v;"#);
    }
    pk.push_str("else E()end end;\nend;\n");
    let mut defs = vec![ph, pu, pk];
    structure.shuffle(&mut defs);
    core_text.push('\n');
    for definition in &defs {
        core_text.push_str(definition);
    }
    core_text.push_str(&format!(
        "local P={{}};local work=0;local id=0;local w={c_next};\n"
    ));
    core_text.push_str(&state_machine(
        &mut structure,
        "w",
        vec![
            (
                c_next,
                format!(
                    "if id>=np then w={c_fin} else F,VMCS=PH();\
work=work+F.__obf_proto_nu+F.__obf_proto_nk+F.__obf_proto_nc;if work>1000000 then E()end;w={c_up}; end;"
                ),
            ),
            (c_up, format!("PU();w={c_konst};")),
            (c_konst, format!("PK();w={c_code};")),
            (
                c_code,
                format!(
                    "F.__obf_proto_code=take(VMCS);P[id]=F;id=id+1;w={c_next};"
                ),
            ),
            (
                c_fin,
                "if pos()~=#B+1 then E()end;B=nil;break;".to_owned(),
            ),
        ],
    ));
    core_text.push_str("\nlocal rP,rnp,ren=P,np,entry;g=nil;return rP,rnp,ren\n");
    core_text = slot_rewrite(
        &mut structure,
        &core_text,
        &[
            "P", "work", "id", "w", "np", "entry", "isa", "check", "sa", "sb", "F", "VMCS",
            "legacy", "tag", "index", "parent", "v", "lo", "hi",
        ],
    );
    decoder_fields.push(format!(
        "[{}]=function(B,E,SB,SF,NCH,TC,MF,IF,b8,b16,b32,take,pos,db8,db32,dstr,dnum)\nlocal g={{}};{core_text}end,",
        keys[20]
    ));
    decoder_wiring.push_str(&format!(
        "\nlocal P,np,entry=VMS[{}](B,E,SB,SF,NCH,TC,MF,IF,b8,b16,b32,take,pos,db8,db32,dstr,dnum);",
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
    let forms: std::collections::BTreeMap<u8, u8> = program
        .opcodes()
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
    // 4-byte-per-instruction string the interpreter fetches from.
    let mut decode_body = format!(
        "[{key}]=function(E,SB,FM)local g={{}};\nlocal Dv=function(CD,p)local w=SB(CD,p);if w==nil then E()end;p=p+1;local v=w%128;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*128;if v<128 then E()end;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*16384;if v<16384 then E()end;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*2097152;if v<2097152 then E()end;\
if w>=128 then E()end;end;end;end;return v,p end;\nreturn function(CD,p)local o=SB(CD,p);if o==nil then E()end;p=p+1;\
local f=FM[o];if f==nil or f>5 then E()end;\
if f==1 then j,p=Dv(CD,p);if {jx} then E()end;a=j%256;local k2=(j-j%256)/256;b=k2%256;c=(k2-k2%256)/256;\
elseif f==2 then a,p=Dv(CD,p);if {ax} then E()end;b=0;c=0;\
elseif f==3 then a,p=Dv(CD,p);b,p=Dv(CD,p);if {ax} or {bx} then E()end;c=0;\
elseif f==4 then a,p=Dv(CD,p);if {ax} then E()end;k2,p=Dv(CD,p);if {kx} then E()end;b=k2%256;c=(k2-k2%256)/256;\
else a,p=Dv(CD,p);b,p=Dv(CD,p);c,p=Dv(CD,p);if {ax} or {bx} or {cx} then E()end end;\
return o,a,b,c,p end;\nend,",
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
        &["w", "v", "o", "f", "a", "b", "c", "j", "k2"],
    );
    let decode_field = decode_body;
    let mut f3_arms: Vec<(u8, String)> = program
        .opcodes()
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
    // The bounds verdict itself flows through a scratch slot: the arms
    // write g[key] instead of a named local (the table is per-call, no
    // clearing needed -- the closure returns immediately after the gate).
    let validate_body = slot_rewrite(&mut structure, &validate_body, &["ok"]);
    let validate_field = format!(
        "[{key}]=function(E)\nreturn function(o,a,b,c,j,k,at,F,P,id)local g={{}};{body} end;\nend,",
        key = keys[15],
        body = validate_body,
    );
    // The validator field itself shrinks to the loop: per instruction it
    // calls the decoder field's closure, re-derives the packed operands and
    // hands everything to the bounds-arms closure.
    write!(s, "[{}]=function(P,np,SB,E,NCH,TC,dec,vld,PT)\n", keys[2]).unwrap();
    s.push_str(
        "for id=0,np-1 do local F=P[id];local CD=F.__obf_proto_code;local p=1;local XB={};\
for at=0,F.__obf_proto_nc-1 do local o,a,b,c,p2=dec(CD,p);p=p2;local k=b+c*256;local j=a+k*256;\
if not vld(PT[o],a,b,c,j,k,at,F,P,id)then E()end;XB[at+1]=NCH(PT[o],a,b,c);end;\
if p~=#CD+1 then E()end;F.__obf_proto_code=TC(XB);local last=SB(F.__obf_proto_code,#F.__obf_proto_code-3);",
    );
    write!(
        s,
        "if last~={} and last~={} and last~={} then E()end;end;",
        perm[Opcode::Jump as usize],
        perm[Opcode::Return as usize],
        perm[Opcode::TailCall as usize]
    )
    .unwrap();
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
    // Three audited probe functions: each verifies a distinct environment
    // invariant of its host (native `loadstring` visible through the debug
    // library) BEFORE contributing its key share; a failed probe aborts with
    // no output. The entry calls the three functions in seeded shuffled
    // order; the decoder section combines the shares into the keystream.
    // Shuffled CALL order of the three probe functions (indices 0..=2 into
    // keys[5..8] / probe_inputs / shares).
    let mut probe_order = [0usize, 1, 2];
    crate::random::Prng::new(seed ^ 0x6f72_6433_6873_7663).shuffle(&mut probe_order);
    // Structural inputs per probe: pairs of payload-table numeric keys the
    // entry passes positionally. The Rust cipher derives the exact same
    // shares from the exact same pairs, so no share -- and no keystream
    // state -- is ever stored in the script: each probe computes its share
    // at run time, after its environment check, in plain double arithmetic.
    let probe_inputs = cipher_probe_inputs(&keys);
    let mut probe_fields = Vec::new();
    for (index, _) in shares.iter().enumerate() {
        let mut steps = String::new();
        for _ in 0..params.probe_rounds[index] {
            steps.push_str(&format!("x={}*x%2147483647;", params.outer));
        }
        let mut field = format!("[{}]=function(E,a,b,DB,GI,LS)local A=", keys[5 + index]);
        if program.target.is_luau() {
            field.push_str("DB and GI(LS,\"s\");if A~=\"[C]\" then E()end;");
        } else {
            field.push_str("DB and GI(LS,\"S\");if not(A and A.what==\"C\")then E()end;");
        }
        let _ = write!(
            field,
            "local x=(a*{}+b)%2147483647;{steps}return x;end,",
            params.mix
        );
        probe_fields.push(field);
    }
    // Entry method: chains the section functions in order, then runs the
    // program. IF/Freeze bind to nil on Lua 5.1 (20 prelude results); unused
    // parameters of target-specific sections accept nil the same way.
    s.push_str("\nreturn CV,SV,Lookup\nend,");
    write!(
        s,
        "[\"{method}\"]=function(VMS,...)\nlocal {names}=VMS[{}]();
local c1=VMS[{}](E,{},{},DBG,GI,LS);local c2=VMS[{}](E,{},{},DBG,GI,LS);local c3=VMS[{}](E,{},{},DBG,GI,LS);
local Y1=VMS[{}](E,SB,NCH,TC,DBG,GI,LS);local Y2=VMS[{}](E,SB,NCH,TC,DBG,GI,LS);local Y3=VMS[{}](E,SB,NCH,TC,DBG,GI,LS);
local mV=VMS[{}](Y1,E,SB);VMS[{}](mV,E);
local P,np,entry=VMS[{}](SS(Y1..Y2..Y3,5),c1,c2,c3,E,SB,SS,SF,NCH,TC,MF,IF,{},{});\nlocal FMt,PT=VMS[{}](E,SB);local dec=VMS[{}](E,SB,FMt);local vld=VMS[{}](E);\nVMS[{}](P,np,SB,E,NCH,TC,dec,vld,PT);
local CV,SV,Lookup=VMS[{}](TY,E);
local H=VMS[{}](SC,Z,U,G,E,SB,SS,SF,MF,TN,TY,TS,NX,MT,SM,RG,RE,IF,Freeze,P,CV,SV,Lookup);
local result=H(entry,Z(...),{{}});return U(result,1,result.n)\nend,\n",
        keys[0],
        keys[5 + probe_order[0]],
        probe_inputs[probe_order[0]].0,
        probe_inputs[probe_order[0]].1,
        keys[5 + probe_order[1]],
        probe_inputs[probe_order[1]].0,
        probe_inputs[probe_order[1]].1,
        keys[5 + probe_order[2]],
        probe_inputs[probe_order[2]].0,
        probe_inputs[probe_order[2]].1,
        keys[8 + hold[0]],
        keys[8 + hold[1]],
        keys[8 + hold[2]],
        keys[11],
        keys[12],
        keys[1],
        keys[4],
        keys[7],
        keys[13],
        keys[14],
        keys[15],
        keys[2],
        keys[3],
        keys[4],
        names = ret_names
    )
    .unwrap();
    write!(
        s,
        "[{}]=function(SC,Z,U,G,E,SB,SS,SF,MF,TN,TY,TS,NX,MT,SM,RG,RE,IF,Freeze,P,CV,SV,Lookup)\n",
        keys[4]
    )
    .unwrap();
    // Swap the monolithic decoder call for the random-section wiring.
    let old_decoder_line = format!(
        "local P,np,entry=VMS[{}](SS(Y1..Y2..Y3,5),c1,c2,c3,E,SB,SS,SF,NCH,TC,MF,IF,{},{});",
        keys[1], keys[4], keys[7]
    );
    s = s.replacen(&old_decoder_line, &decoder_wiring, 1);
    // M7: wrap the just-emitted entry body in an opaque branch. The live
    // side carries the real chain; the dead side carries real-looking,
    // never-executing instructions behind a constant contradiction.
    {
        let head_anchor = format!("[\"{method}\"]=function(VMS,...)\n");
        let head_wrapped = format!("[\"{method}\"]=function(VMS,...){entry_head}\n");
        s = s.replacen(&head_anchor, &head_wrapped, 1).replace(
            "return U(result,1,result.n)\nend,",
            &format!("return U(result,1,result.n)\n{entry_tail}\nend,"),
        );
    }
    // Resolved after the opaque wrap: its replacements insert text inside
    // the entry field, so any index recorded before them would drift. The
    // opener text is unique, so locate it instead.
    let f5_start = s
        .rfind(&format!("[{}]=function(SC,Z,U,G,E,", keys[4]))
        .expect("interpreter field anchor");
    s.push_str(
        r#"
local W=SM({},{__mode='kv'});local H;local Make;
"#,
    );
    s.push_str(call_body);
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
 local F=P[fid];local R={};local nn=args.n-F.__obf_proto_p;if nn<0 then nn=0 end;
 local va2={};va2.n=nn;for i=1,nn do va2[i]=args[F.__obf_proto_p+i]end;
 for i=0,F.__obf_proto_p-1 do R[i]={args[i+1]}end;
 if MF(F.__obf_proto_flags/2)%2==1 then R[F.__obf_proto_p]={};if MF(F.__obf_proto_flags/4)%2==1 then local vv={};vv.n=nn;for i=1,nn do vv[i]=va2[i]end;R[F.__obf_proto_p][1]=vv end end;
 return F,R,va2,nn
end;
"#);
    // SETUP-only scratch slots: the frame registers F/R keep their locals
    // because the interpreter recurses (nested frames would clobber a
    // single slot), but SETUP's own intermediates flow through g[key].
    {
        let original = r#"local SETUP=function(fid,args)
 local F=P[fid];local R={};local nn=args.n-F.__obf_proto_p;if nn<0 then nn=0 end;
 local va2={};va2.n=nn;for i=1,nn do va2[i]=args[F.__obf_proto_p+i]end;
 for i=0,F.__obf_proto_p-1 do R[i]={args[i+1]}end;
 if MF(F.__obf_proto_flags/2)%2==1 then R[F.__obf_proto_p]={};if MF(F.__obf_proto_flags/4)%2==1 then local vv={};vv.n=nn;for i=1,nn do vv[i]=va2[i]end;R[F.__obf_proto_p][1]=vv end end;
 return F,R,va2,nn
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
    // Interpreter flattening: the frame setup moves into its own function
    // and the fetch/dispatch loop becomes a two-phase state machine whose
    // branch order, state numbers and condition spellings are per seed.
    let fsv = state_values(&mut structure, 2);
    let (k_fetch, k_disp) = (fsv[0], fsv[1]);
    let c_fetch = state_condition(&mut structure, "w", k_fetch);
    let c_disp = state_condition(&mut structure, "w", k_disp);
    let dispatch_first = structure.next_u64() % 2 == 0;
    let fetch_branch = format!(
        "{c_fetch} then\n   o,a,b,c=SB(code,pc,pc+3);if c==nil then E()end;pc=pc+4;\n   k=b+c*256;j=a+k*256;w={k_disp};"
    );
    write!(
        s,
        "H=function(fid,args,ups)\n while true do\n  local F,R,va=SETUP(fid,args);\n  local pc=1;local code=F.__obf_proto_code;\n  local o,a,b,c,k,j;local w={k_fetch};\n  while true do\n   {machine_open}",
        k_fetch = k_fetch,
        machine_open = if dispatch_first {
            format!("if {c_disp} then ")
        } else {
            format!("if {fetch_branch}\n   elseif {c_disp} then ")
        },
    )
    .unwrap();
    let mut f5_arms: Vec<(u8, String)> = Vec::new();
    for op in program.opcodes() {
        let code = crate::vm::opcode::custom(program.target, op)
            .ok_or_else(|| Diagnostic::new("missing custom opcode implementation"))?;
        f5_arms.push((
            perm[(op as u8) as usize],
            format!(
                "{} then {}",
                structure.dispatch_condition(
                    u64::from(perm[(op as u8) as usize]) as u16,
                    program.target.is_luau()
                ),
                code
            ),
        ));
    }
    // In-image decoy arms: keys are the perm image of canonical opcodes
    // the program never uses. Rebuilding the packed permutation table
    // statically cannot filter these -- they look exactly like live
    // dispatch values -- yet they are unreachable at runtime because the
    // forms table encodes every unused slot with an invalid form, so the
    // decoder aborts before dispatch. Each decoy runs the handler text of
    // a DIFFERENT opcode: static semantic recovery that trusts every arm
    // reconstructs a poisoned opcode table the program's own asserts can
    // never contradict, because these opcodes never execute here.
    let used_ops: Vec<u8> = program.opcodes().iter().map(|op| *op as u8).collect();
    let used_set: std::collections::BTreeSet<u8> = used_ops.iter().copied().collect();
    let mut unused_slots: Vec<u8> = (0u8..64).filter(|slot| !used_set.contains(slot)).collect();
    let dropped = unused_slots.len().min((structure.next_u64() % 3) as usize);
    let keep = unused_slots.len() - dropped;
    structure.shuffle(&mut unused_slots);
    for slot in unused_slots.into_iter().take(keep) {
        let key = perm[slot as usize];
        let own =
            Opcode::from_byte(slot).and_then(|op| crate::vm::opcode::custom(program.target, op));
        let live = |byte: u8| {
            crate::vm::opcode::custom(
                program.target,
                Opcode::from_byte(byte).expect("live opcode"),
            )
            .expect("live handler")
        };
        let mut index = (structure.next_u64() % used_ops.len().max(1) as u64) as usize;
        let mut body = live(used_ops[index]);
        if Some(body) == own && used_ops.len() > 1 {
            // Never hand a decoy its own canonical semantics.
            index = (index + 1) % used_ops.len();
            body = live(used_ops[index]);
        }
        f5_decoys.push((
            key,
            format!(
                "{} then {}",
                structure.dispatch_condition(u16::from(key), program.target.is_luau()),
                body
            ),
        ));
    }
    f5_arms.extend(f5_decoys);
    let f5_groups = (2 + structure.next_u64() % 3) as u8;
    s.push_str(&grouped_chain(&mut structure, f5_arms, f5_groups, "o"));
    if dispatch_first {
        write!(
            s,
            " w={k_fetch};\n   elseif {fetch_branch}\n   else E()end;"
        )
        .unwrap();
    } else {
        write!(s, " w={k_fetch};\n   else E()end;").unwrap();
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

fn validation(op: Opcode) -> &'static str {
    use Opcode::*;
    match op {
        Jump => "j<F.__obf_proto_nc",
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
        Test => "a<F.__obf_proto_m and b==0 and c==0 and at+2<F.__obf_proto_nc",
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
