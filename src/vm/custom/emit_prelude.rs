//! Host-capture prelude stage of the generated VM.
//!
//! This is the first payload section function: the environment capture, the
//! hidden-name char pool and per-name assembly locals, the shuffled unit
//! statements (stdlib captures, Luau word layer, anti-hook/key-probe
//! captures), the K7 bit toolbox rendering and the prelude's shuffled return
//! list. Split out of `emit.rs` by stage without touching the emitted text:
//! the rng objects are threaded in by mutable reference and consumed in the
//! original order, so output is byte-for-byte identical (proven by the
//! fixed-seed goldens, which regenerate unchanged, and by every surface-audit
//! pin staying at its recorded value).

use super::*;

use std::fmt::Write as _;

/// What the prelude stage hands back to the orchestrator: its own script text
/// (with the whole-output wrapper prefix), the wrapper header length used by
/// the final assembly, the prelude's return list, and the run-time assembled
/// Luau probe transcript (`None` on Lua 5.1, which folds the raw source field).
pub(crate) struct PreludeStage {
    pub(crate) text: String,
    pub(crate) header_end: usize,
    pub(crate) ret_names: String,
    pub(crate) probe_transcript: Option<ProbeTranscript>,
}

pub(crate) fn emit_prelude(
    program: &Program,
    keys: &[u64],
    structure: &mut crate::random::Prng,
    bitops_rng: &mut crate::random::Prng,
) -> PreludeStage {
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
        // K7: bit32/buffer libs plus every method the Luau word toolbox
        // touches. All resolve through the char pool; none is ever spelled.
        hidden.extend([
            "bit32", "buffer", "bxor", "band", "bor", "bnot", "lrotate", "lshift", "rshift",
            "create", "writeu8", "readu8", "readu32",
        ]);
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
        let expression = if structure.index(100) < 92 {
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
        units.push((
                "B32",
                format!(
                    "local B32,BUF=G[{0}],G[{1}];local BX,BA,BO,BN,LR,SHL,RS=B32[{2}],B32[{3}],B32[{4}],B32[{5}],B32[{6}],B32[{7}],B32[{8}];local BNE,BW8,BR8,BFS,BR3=BUF[{9}],BUF[{10}],BUF[{11}],BUF[{12}],BUF[{13}];",
                    var_of["bit32"],
                    var_of["buffer"],
                    var_of["bxor"],
                    var_of["band"],
                    var_of["bor"],
                    var_of["bnot"],
                    var_of["lrotate"],
                    var_of["lshift"],
                    var_of["rshift"],
                    var_of["create"],
                    var_of["writeu8"],
                    var_of["readu8"],
                    var_of["fromstring"],
                    var_of["readu32"],
                ),
            ));
    }
    // T7: the Luau probe transcript is a pool-assembled prelude local.
    let probe_transcript = program
        .target
        .is_luau()
        .then(|| probe_transcript_unit(&var_of));
    if let Some(t) = &probe_transcript {
        units.push((t.unit, t.definition.clone()));
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
    // K7 word toolbox: hot X8 (inner stream loop) plus cold X8C (table
    // builds, anti-hook KAT) always draw distinct variants; L32 draws one of
    // three. Lua 5.1 stays pure arithmetic, Luau runs bit32+buffer. AD (the
    // Adler fold) is untouched arithmetic on both targets.
    let bit_names = BitNames::emit();
    let (x8_hot, x8_cold) = draw_dual(bitops_rng);
    let (pre_hot, decl_hot) = render_x8(program.target, x8_hot, "X8", &bit_names);
    let (pre_cold, decl_cold) = render_x8(program.target, x8_cold, "X8C", &bit_names);
    let l32_variant = bitops_rng.index(3);
    let l32_decl = render_l32(program.target, l32_variant, "L32", &bit_names, bitops_rng);
    s.push_str(&pre_hot);
    s.push_str(&pre_cold);
    s.push_str(&decl_hot);
    s.push_str(&decl_cold);
    s.push_str("local AD=function(S,a,b)local x,y=1,0;for i=a,b do x=(x+SB(S,i))%65521;y=(y+x)%65521 end;return x+y*65536 end;");
    s.push_str(&l32_decl);
    // K13c step 2: the constant region primitives. `UK` shifts a byte run back
    // into plaintext from a running stream position, `U32` reads a little-endian
    // word out of *any* string (the image cursor cannot be used inside `DC`),
    // and `NU` rebuilds the double -- the same `fin` arithmetic the reader
    // cluster uses, so a number read from the region is bit-identical to one
    // read through the cursor (subnormals, NaN and -0.0 included). All three are
    // key-agnostic: callers pass the baked mask/modulus and the accumulator, so
    // the parser and `DC` cannot drift into two different ciphers.
    s.push_str(
        "local U32=function(S,i)local a,b,c,d=SB(S,i),SB(S,i+1),SB(S,i+2),SB(S,i+3);if not d then E()end;return((d*256+c)*256+b)*256+a end;",
    );
    s.push_str("local UK=function(S,p,n,acc)local o={};local k=(acc+119)%256;for j=1,n do o[j]=NCH((SB(S,p+j-1)+256-k)%256);k=(k+119)%256 end;return TC(o)end;");
    s.push_str("local NU=function(S,i)local lo,hi=U32(S,i),U32(S,i+4);local sg=hi>=2147483648 and -1 or 1;local ex=MF(hi/1048576)%2048;local fr=(hi%1048576)*4294967296+lo;if ex==2047 then if fr==0 then return sg/0 else return 0/0 end elseif ex==0 then return sg*(fr*2^-1074) else return sg*((1+fr/4503599627370496)*2^(ex-1023))end end;");
    let mut ret_order: Vec<&str> = vec![
        "SC", "Z", "U", "G", "E", "PC", "SB", "SS", "SF", "NCH", "TC", "MF", "TN", "TY", "TS",
        "NX", "MT", "SM", "RG", "RE", "IF", "Freeze", "DBG", "GI", "LS", "X8", "X8C", "AD", "L32",
        "B32", "BUF", "BX", "BA", "BO", "BN", "LR", "SHL", "RS", "BNE", "BW8", "BR8", "BFS", "BR3",
        "UK", "U32", "NU",
    ];
    ret_order.extend(probe_transcript.as_ref().map(|t| t.unit));
    structure.shuffle(&mut ret_order);
    let ret_names = ret_order.join(",");
    s.push_str(&format!("\nreturn {ret_names}\nend,"));
    PreludeStage {
        text: s,
        header_end,
        ret_names,
        probe_transcript,
    }
}
