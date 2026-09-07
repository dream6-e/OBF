//! Executable VM for AST-produced OBF v2 bytecode. The file encodes every
//! instruction as an opcode byte plus 7-bit varint operands; the generated
//! decoder validates them and expands the stream back into the fixed
//! 4-byte-per-instruction string that the fetch loop then executes. Only
//! handlers in the program are emitted; all opcode definitions exist in the
//! two target subfolders. `seed` affects final local/private-field names
//! only, never bytecode.

use crate::bytecode::custom::{self, Opcode, Program};
use crate::{Diagnostic, Target};
use std::fmt::Write;

pub fn compile(source: &str, target: Target) -> Result<Vec<u8>, Diagnostic> {
    custom::encode(&crate::ir::compile(source, target)?)
}

pub fn virtualize(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    let bytecode = compile(source, target)?;
    emit(&bytecode, target, seed)
}

/// Validate externally supplied custom bytecode before generating a runtime.
pub fn emit(bytecode: &[u8], target: Target, seed: u64) -> Result<String, Diagnostic> {
    let program = custom::decode(bytecode, target)?;
    let raw = generate(bytecode, &program, seed)?;
    finalize(&raw, target, seed)
}

// All source (including static host method adapters) is complete before
// shortening private fields and then applying the existing final local pass.
fn finalize(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    let source = super::fields::shorten(source, target, seed)?;
    crate::minify::finalize_vm(&source, target, seed)
}

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
    let entry_decoy = format!(
        "local d1=VMS[{}](E);local d2=VMS[{}](d1,E);if d2 then E()end;",
        keys[0], keys[1]
    );
    let f3_decoys = decoy_arms(
        &mut structure,
        2,
        program.target.is_luau(),
        &["ok=j%2==0;", "ok=a+b<511;", "ok=c<256;"],
        &opcode_image,
    );
    let f5_decoys = decoy_arms(
        &mut structure,
        2,
        program.target.is_luau(),
        &[
            "R[a]={R[b]};pc=j;",
            "R[a]=R[b][R[c]];pc=pc+4;",
            "k=j;R[a]=k;pc=pc+4;",
        ],
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
    s.push_str(
        r#"
local SC=select;local Z=function(...)return{n=SC('#',...),...}end;
local U=unpack or table.unpack;local G=(getfenv and getfenv(0))or _G;local E=error;
local SB,SS,SF=string.byte,string.sub,string.format;
local NCH,TC=string.char,table.concat;
local MF,TN,TY,TS,NX,MT,SM,RG,RE=math.floor,tonumber,type,tostring,next,getmetatable,setmetatable,rawget,rawequal;
"#,
    );
    if program.target.is_luau() {
        s.push_str("local IF=integer and integer.fromstring;local Freeze=table.freeze;");
    }
    // Section functions thread state through parameters/returns; the mutually
    // recursive Call/Make/H cluster stays together in one section function.
    s.push_str(if program.target.is_luau() {
        "\nreturn SC,Z,U,G,E,SB,SS,SF,NCH,TC,MF,TN,TY,TS,NX,MT,SM,RG,RE,IF,Freeze\nend,"
    } else {
        "\nreturn SC,Z,U,G,E,SB,SS,SF,NCH,TC,MF,TN,TY,TS,NX,MT,SM,RG,RE,IF,Freeze\nend,"
    });
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
            ("debug.info(loadstring,\"s\")", "if A~=\"[C]\" then E()end;")
        } else {
            (
                "debug.getinfo(loadstring,\"S\")",
                "if not(A and A.what==\"C\")then E()end;",
            )
        };
        let mut chunk = String::new();
        write!(
            chunk,
            "[{key}]=function(E,SB,NCH,TC)local A=debug and {probe};{gate}\
local S=\"{text}\";local o={{}};for i=1,#S-#S%5,5 do local v=0;local m=1;\
for j=0,4 do local b=SB(S,i+j);if b==92 or b<35 or b>121 then E()end;\
if b>92 then b=b-36 else b=b-35 end;v=v+b*m;m=m*86 end;\
if v>4294967295 then E()end;o[#o+1]=NCH(v%256);v=(v-v%256)/256;\
o[#o+1]=NCH(v%256);v=(v-v%256)/256;o[#o+1]=NCH(v%256);v=(v-v%256)/256;\
o[#o+1]=NCH(v)end;local r2=#S%5;if r2==1 then E()end;\
if r2>0 then local v=0;local m=1;for j=0,r2-1 do local b=SB(S,#S-r2+1+j);\
if b==92 or b<35 or b>121 then E()end;\
if b>92 then b=b-36 else b=b-35 end;v=v+b*m;m=m*86 end;\
if v>256^(r2-1)-1 then E()end;\
for j=1,r2-1 do o[#o+1]=NCH(v%256);v=(v-v%256)/256 end end;return TC(o);end,",
            key = keys[8 + hold[part]],
            probe = probe,
            gate = gate,
            text = text,
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
    let f2_start = s.len();
    write!(
        s,
        "[{}]=function(B,s1,s2,s3,E,SB,SS,SF,NCH,TC,MF,IF,ca,cb)\n",
        keys[1]
    )
    .unwrap();
    write!(
        s,
        "local st=1+(s1+s2+s3+{mix}*#B)%2147483646;local XB={{}};for i=1,#B do \
st={outer}*st%2147483647;local x=SB(B,i);local y=st%256;local r=0;local p=1;\
for j=1,8 do local q=(x%2+y%2)%2;if q==1 then r=r+p end;x=(x-x%2)/2;y=(y-y%2)/2;p=p*2 end;\
XB[i]=NCH(r)end;B=TC(XB);XB=nil;",
        mix = params.mix,
        outer = params.outer
    )
    .unwrap();
    s.push_str(
        r#"
if #B>16777216 then E()end;
local bp=1;
local b8=function()local v=SB(B,bp);if v==nil then E()end;bp=bp+1;return v end;
local b16=function()local a,b=b8(),b8();return a+b*256 end;
local b32=function()local a,b,c,d=b8(),b8(),b8(),b8();return a+b*256+c*65536+d*16777216 end;
local take=function(n)if n>#B-bp+1 then E()end;local v=SS(B,bp,bp+n-1);bp=bp+n;return v end;
local str=function()return take(b32())end;
"#,
    );
    s.push_str(
        r#"
local fin=function(lo,hi)local sg=hi>=2147483648 and -1 or 1;local ex=MF(hi/1048576)%2048;local fr=(hi%1048576)*4294967296+lo;if ex==2047 then if fr==0 then return sg/0 else return 0/0 end elseif ex==0 then return sg*(fr*2^-1074) else return sg*((1+fr/4503599627370496)*2^(ex-1023))end end;
"#,
    );
    let mut ku_steps = String::new();
    for _ in 0..params.constant_rounds {
        ku_steps.push_str(&format!("ku={}*ku%2147483647;", params.constant));
    }
    write!(
        s,
        "local ku=(ca*{mix}+cb)%2147483647;{ku_steps}\nlocal ks=1+(ku+{mix}*#B)%2147483646;local KA=function()ks={mult}*ks%2147483647;return ks%256 end;\n",
        mix = params.mix,
        mult = params.constant
    )
    .unwrap();
    s.push_str(
        r#"
local DX=function(u)local y=KA();local r=0;local w=1;for j=1,8 do local q=(u%2+y%2)%2;if q==1 then r=r+w end;u=(u-u%2)/2;y=(y-y%2)/2;w=w*2 end;return r end;
local db8=function()return DX(b8())end;
local db32=function()local p,q,r,t=db8(),db8(),db8(),db8();return p+q*256+r*65536+t*16777216 end;
local dstr=function()local v=take(b32());local o={}for i=1,#v do o[i]=NCH(DX(SB(v,i)))end;return TC(o)end;
local num=function()return fin(b32(),b32())end;
local dnum=function()return fin(db32(),db32())end;
if b8()~=79 or b8()~=66 or b8()~=70 or b8()~=2 then E()end;
"#,
    );
    write!(
        s,
        "if b8()~={} then E()end;",
        if program.target.is_luau() { 117 } else { 81 }
    )
    .unwrap();
    s.push_str(
        r#"
if b8()~=1 or b8()~=0 or b8()~=0 or b32()~=32 or b32()~=#B then E()end;
local np=b32();local entry=b32();local isa=b32();if np==0 or np>65536 or entry~=0 or isa<1 or isa>2 then E()end;
local check=b32();local sa,sb=1,0;for q=33,#B do sa=(sa+SB(B,q))%65521;sb=(sb+sa)%65521 end;
if sa+sb*65536~=check then E()end;
local P={};local work=0;
for id=0,np-1 do
 local F={__obf_proto_k={},__obf_proto_tags={},__obf_proto_u={}};F.__obf_proto_parent=b32();F.__obf_proto_m=b16();F.__obf_proto_p=b8();F.__obf_proto_flags=b8();F.__obf_proto_nu=b16();
 if b16()~=0 then E()end;F.__obf_proto_nk=b32();F.__obf_proto_nc=b32();local VMCS=b32();
 if F.__obf_proto_m<1 or F.__obf_proto_m>256 or F.__obf_proto_p>F.__obf_proto_m or F.__obf_proto_nu>256 or F.__obf_proto_nk>65536 or F.__obf_proto_nc<1 or F.__obf_proto_flags>15 or VMCS<F.__obf_proto_nc*2 or VMCS>F.__obf_proto_nc*7 then E()end;
 F.__obf_proto_shared=MF(F.__obf_proto_flags/8)%2==1;if F.__obf_proto_shared and (isa<2 or id==0)then E()end;
 if id==0 then if F.__obf_proto_parent~=4294967295 or F.__obf_proto_nu~=0 or MF(F.__obf_proto_flags/2)%2~=0 then E()end
 elseif F.__obf_proto_parent>=id then E()end;
 local legacy=MF(F.__obf_proto_flags/2)%2;
 if legacy==1 and (F.__obf_proto_flags%2==0 or F.__obf_proto_p>=F.__obf_proto_m)or MF(F.__obf_proto_flags/4)%2==1 and legacy==0 then E()end;
"#,
    );
    if program.target.is_luau() {
        s.push_str("if legacy~=0 then E()end;");
    } else {
        s.push_str("if F.__obf_proto_shared then E()end;");
    }
    s.push_str(
        r#"
 work=work+F.__obf_proto_nu+F.__obf_proto_nk+F.__obf_proto_nc;if work>1000000 then E()end;
 for j=0,F.__obf_proto_nu-1 do local tag,index=b8(),b8();local parent=P[F.__obf_proto_parent];
  if tag>2 or not parent or tag~=1 and index>=parent.__obf_proto_m or tag==1 and index>=parent.__obf_proto_nu then E()end;
  if tag==2 then if not F.__obf_proto_shared or F.__obf_proto_self~=nil then E()end;F.__obf_proto_self=j end;
  F.__obf_proto_u[j]={tag,index};
 end;
 for j=0,F.__obf_proto_nk-1 do local tag=b8();F.__obf_proto_tags[j]=tag;
  if tag==0 then F.__obf_proto_k[j]=nil
  elseif tag==1 then local v=db8();if v>1 then E()end;F.__obf_proto_k[j]=v==1
  elseif tag==2 then F.__obf_proto_k[j]=dnum()
  elseif tag==3 or tag==5 then F.__obf_proto_k[j]=dstr()
"#,
    );
    if program.target.is_luau() {
        s.push_str(r#"elseif tag==4 then local lo,hi=db32(),db32();if not IF then E()end;local v=IF(SF('%08x%08x',hi,lo),16);if v==nil then E()end;F.__obf_proto_k[j]=v;"#);
    }
    s.push_str(
        "else E()end end;F.__obf_proto_code=take(VMCS);P[id]=F;end;if bp~=#B+1 then E()end;B=nil;",
    );
    s.push_str("\nreturn P,np,entry\nend,");
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
    let forms_field = format!(
        "[{key}]=function(E,SB)local t={{}};local p={{}};local S=\"~{text}\";for i=2,#S do local b=SB(S,i);\
if b==92 or b<35 or b>121 then E()end;if b>92 then b=b-1 end;t[i-2]=(b-35-{rot})%86+1 end;\
local U=\"~{renum}\";for i=2,#U,2 do local x=SB(U,i);local y=SB(U,i+1);\
if x==92 or x<35 or x>121 or y==92 or y<35 or y>121 then E()end;\
if x>92 then x=x-1 end;if y>92 then y=y-1 end;p[(i-2)/2]=x-35+(y-35)*86 end;return t,p;end,",
        key = keys[13],
        text = forms_text,
        rot = forms_rot,
        renum = perm_text,
    );
    // Both Rust and target decoders validate operands before any execution.
    // The 7-bit varint stream is decoded by this field's returned closure
    // and validated per shape; the consumer expands it back into the fixed
    // 4-byte-per-instruction string the interpreter fetches from.
    let decode_field = format!(
        "[{key}]=function(E,SB,FM)\nlocal Dv=function(CD,p)local w=SB(CD,p);if w==nil then E()end;p=p+1;local v=w%128;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*128;if v<128 then E()end;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*16384;if v<16384 then E()end;\
if w>=128 then w=SB(CD,p);if w==nil then E()end;p=p+1;v=v+w%128*2097152;if v<2097152 then E()end;\
if w>=128 then E()end;end;end;end;return v,p end;\nreturn function(CD,p)local o=SB(CD,p);if o==nil then E()end;p=p+1;\
local f=FM[o];if f==nil or f>5 then E()end;local a,b,c;\
if f==1 then local j;j,p=Dv(CD,p);if {jx} then E()end;a=j%256;local k2=(j-j%256)/256;b=k2%256;c=(k2-k2%256)/256;\
elseif f==2 then a,p=Dv(CD,p);if {ax} then E()end;b=0;c=0;\
elseif f==3 then a,p=Dv(CD,p);b,p=Dv(CD,p);if {ax} or {bx} then E()end;c=0;\
elseif f==4 then a,p=Dv(CD,p);if {ax} then E()end;local k2;k2,p=Dv(CD,p);if {kx} then E()end;b=k2%256;c=(k2-k2%256)/256;\
else a,p=Dv(CD,p);b,p=Dv(CD,p);c,p=Dv(CD,p);if {ax} or {bx} or {cx} then E()end end;\
return o,a,b,c,p end;\nend,",
        key = keys[14],
        jx = jx,
        ax = ax,
        bx = bx,
        kx = kx,
        cx = cx,
    );
    let mut f3_arms: Vec<String> = program
        .opcodes()
        .iter()
        .map(|op| {
            format!(
                "{} then ok={};",
                structure.dispatch_condition(
                    u64::from(perm[(*op as u8) as usize]) as u16,
                    program.target.is_luau()
                ),
                validation(*op)
            )
        })
        .collect();
    f3_arms.extend(f3_decoys);
    structure.shuffle(&mut f3_arms);
    let mut arms_text = String::new();
    for (index, arm) in f3_arms.iter().enumerate() {
        write!(
            arms_text,
            "{} {arm}",
            if index == 0 { "if" } else { "elseif" }
        )
        .unwrap();
    }
    let validate_field = format!(
        "[{key}]=function(E)\nreturn function(o,a,b,c,j,k,at,F,P,id)local ok=false;{arms} else E()end;\
if not ok then E()end;return true end;\nend,",
        key = keys[15],
        arms = arms_text,
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
            super::lua51::emit_byte_string(&mut s, method.as_bytes());
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
        let mut field = format!("[{}]=function(E,a,b)local A=debug and ", keys[5 + index]);
        if program.target.is_luau() {
            field.push_str("debug.info(loadstring,\"s\");if A~=\"[C]\" then E()end;");
        } else {
            field.push_str(
                "debug.getinfo(loadstring,\"S\");if not(A and A.what==\"C\")then E()end;",
            );
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
        "[\"{method}\"]=function(VMS,...)\nlocal SC,Z,U,G,E,SB,SS,SF,NCH,TC,MF,TN,TY,TS,NX,MT,SM,RG,RE,IF,Freeze=VMS[{}]();
local c1=VMS[{}](E,{},{});local c2=VMS[{}](E,{},{});local c3=VMS[{}](E,{},{});
local Y1=VMS[{}](E,SB,NCH,TC);local Y2=VMS[{}](E,SB,NCH,TC);local Y3=VMS[{}](E,SB,NCH,TC);
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
        keys[4]
    )
    .unwrap();
    write!(
        s,
        "[{}]=function(SC,Z,U,G,E,SB,SS,SF,MF,TN,TY,TS,NX,MT,SM,RG,RE,IF,Freeze,P,CV,SV,Lookup)\n",
        keys[4]
    )
    .unwrap();
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
 local d={id,up};local fn=function(...)local v=H(d[1],Z(...),d[2]);return U(v,1,v.n)end;W[fn]=d;
 if F.__obf_proto_shared and not cached then F.__obf_proto_cached=fn end;return fn
end;
H=function(fid,args,ups)
 while true do
  local F=P[fid];local R={};local n=args.n-F.__obf_proto_p;if n<0 then n=0 end;
  local va={n=n};for i=1,n do va[i]=args[F.__obf_proto_p+i]end;
  for i=0,F.__obf_proto_p-1 do R[i]={args[i+1]}end;
  if MF(F.__obf_proto_flags/2)%2==1 then R[F.__obf_proto_p]={};if MF(F.__obf_proto_flags/4)%2==1 then local v={n=n};for i=1,n do v[i]=va[i]end;R[F.__obf_proto_p][1]=v end end;
  local pc=1;local code=F.__obf_proto_code;
  while true do
   local o,a,b,c=SB(code,pc,pc+3);if c==nil then E()end;pc=pc+4;
   local k=b+c*256;local j=a+k*256;
"#);
    let mut f5_arms: Vec<String> = Vec::new();
    for op in program.opcodes() {
        let code = super::opcode::custom(program.target, op)
            .ok_or_else(|| Diagnostic::new("missing custom opcode implementation"))?;
        f5_arms.push(format!(
            "{} then {}",
            structure.dispatch_condition(
                u64::from(perm[(op as u8) as usize]) as u16,
                program.target.is_luau()
            ),
            code
        ));
    }
    f5_arms.extend(f5_decoys);
    structure.shuffle(&mut f5_arms);
    for (index, arm) in f5_arms.iter().enumerate() {
        write!(s, "{} {arm}", if index == 0 { "if" } else { "elseif" }).unwrap();
    }
    s.push_str("else E()end;end;end;end;return H");
    let forwards_varargs = program.prototypes[program.entry]
        .code
        .iter()
        .any(|word| matches!(word.opcode(), Ok(Opcode::Varargs)));
    write!(
        s,
        "\nend}},x):{method}({})",
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
    let mut fields: Vec<String> = vec![
        s[header_end..f2_start].to_owned(),
        s[f2_start..f3_start].to_owned(),
        s[f3_start..f4_start].to_owned(),
        s[f4_start..entry_start].to_owned(),
    ];
    fields.extend(probe_fields);
    fields.extend(segment_fields);
    fields.extend(watermark_fields);
    fields.extend([forms_field, decode_field, validate_field]);
    structure.shuffle(&mut fields);
    let mut out = s[..header_end].to_owned();
    for field in &fields {
        out.push_str(field);
    }
    out.push_str(&s[entry_start..]);
    s = out;
    if s.len() > crate::lexer::MAX_SOURCE_BYTES {
        return Err(Diagnostic::new(
            "generated custom VM exceeds source safety limit",
        ));
    }
    Ok(s)
}

/// Random non-keyword single-letter name for the wrapper's entry method. No
/// Lua 5.1 or Luau keyword is a single letter. Drawn from a dedicated seeded
/// stream: the same seed reproduces the whole script while bytecode, final
/// local names and private fields stay on their own existing streams.
fn wrapper_method(target: Target, seed: u64) -> String {
    let mut random = crate::random::Prng::new(seed ^ 0x6d65_7468_6f64_3276);
    let mut pool: Vec<char> = (b'a'..=b'z').map(char::from).collect();
    random.shuffle(&mut pool);
    let name = pool[0].to_string();
    debug_assert!(!crate::lexer::is_keyword(&name, target));
    name
}

/// Thirteen distinct random numeric keys for the section functions of the
/// payload table (five sections, three key-share probes, three base86
/// payload segments, two split watermark-check functions). Separate seeded
/// stream; same reproducibility guarantees as the method name.
fn wrapper_keys(seed: u64) -> Vec<u64> {
    let mut random = crate::random::Prng::new(seed ^ 0x6b65_7973_3276_6d35);
    let mut used = std::collections::BTreeSet::new();
    let mut keys = Vec::new();
    while keys.len() < 16 {
        let key = 100 + random.next_u64() % 9900;
        if used.insert(key) {
            keys.push(key);
        }
    }
    keys
}

/// M7 opaque branch predicates: constant integer tautologies and their
/// matched contradictions. Same shape, flipped truth value; no NaN, no
/// metamethods, no floats -- the truth value is fixed at generation time.
fn opaque_pair(structure: &mut crate::random::Prng) -> (String, String) {
    const TAUTOLOGIES: [(&str, &str); 4] = [
        ("48271%2==1", "48271%2==0"),
        ("2147483647>2147483646", "2147483647>2147483647"),
        ("65536%256==0", "65536%256==1"),
        ("16777216%2==0", "16777216%2==1"),
    ];
    let index = (structure.next_u64() % TAUTOLOGIES.len() as u64) as usize;
    let (truthy, falsy) = TAUTOLOGIES[index];
    (truthy.to_owned(), falsy.to_owned())
}

/// M7 unreachable decoy arms for the F3/F5 dispatch chains: `elseif o==K`
/// (in the chain's current comparison spelling) with byte values drawn
/// from outside the per-seed opcode image. The expanded instruction
/// stream only ever carries renumbered values of real opcodes, so these
/// arms are dead by construction while carrying real, plausible
/// instructions.
fn decoy_arms(
    structure: &mut crate::random::Prng,
    count: usize,
    luau: bool,
    bodies: &[&str],
    image: &std::collections::BTreeSet<u8>,
) -> Vec<String> {
    let mut used = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    while used.len() < count {
        let opcode = loop {
            let value = (structure.next_u64() % 256) as u8;
            if !image.contains(&value) && used.insert(value) {
                break value;
            }
        };
        let body = bodies[(structure.next_u64() % bodies.len() as u64) as usize];
        let condition = structure.dispatch_condition(u16::from(opcode), luau);
        out.push(format!("{condition} then {body}"));
    }
    out
}

/// Per-seed opcode renumbering: an injective map from the 64 canonical ISA
/// slots to byte values 0..=255, drawn by rejection sampling from a
/// seed-salted stream. Both sides derive it identically: the generator
/// renumbers every dispatch/bounds arm and the termination check, the
/// target rebuilds the table from the packed base86 string (two chars per
/// slot, see the forms field) and rewrites each opcode byte while
/// expanding the validated varint stream.
fn opcode_permutation(seed: u64, slots: u8) -> Vec<u8> {
    let mut random = crate::random::Prng::new(seed ^ 0x6f70_636f_6465_7333);
    let mut taken = std::collections::BTreeSet::new();
    (0..slots)
        .map(|_| loop {
            let value = (random.next_u64() % 256) as u8;
            if taken.insert(value) {
                return value;
            }
        })
        .collect()
}

/// One base86 digit (0..=85) as the backslash-free printable char shared
/// by the packed strings of the forms field.
fn pack86(digit: u8) -> char {
    let mut byte = 35 + digit;
    if byte >= 92 {
        byte += 1;
    }
    byte as char
}

/// M7 structural variant: one of three exactly equivalent integer bound
/// checks. The operands are always integers decoded from 7-bit varints, so
/// `x>K`, `K<x` and `not(x<=K)` are interchangeable -- NaN cannot occur and
/// raw numeric comparison has no metamethod dispatch. Only the spelling of
/// the emitted check changes; behavior and rejection behavior are identical.
fn gt(structure: &mut crate::random::Prng, value: &str, bound: &str) -> String {
    match structure.next_u64() % 3 {
        0 => format!("{value}>{bound}"),
        1 => format!("{bound}<{value}"),
        _ => format!("not({value}<={bound})"),
    }
}

/// Per-generation cipher parameters ("the cipher algorithm varies every
/// build"): Lehmer multiplier drawn from three full-period primitives mod
/// 2^31-1 (independently for the outer blob cipher and the constant-pool
/// layer), the structural mixing constant, the per-probe derivation round
/// counts and the constant-layer round count. All drawn from a dedicated
/// seeded stream; the generated Lua side emits the identical values, and
/// every product stays below 2^53 (65539 * (2^31-2) < 2^47).
struct CipherParams {
    outer: u64,
    constant: u64,
    mix: u64,
    probe_rounds: [u32; 3],
    constant_rounds: u32,
}

fn cipher_params(seed: u64) -> CipherParams {
    const MULTIPLIERS: [u64; 3] = [16_807, 48_271, 65_539];
    const MIXES: [u64; 4] = [31, 33, 37, 41];
    let mut random = crate::random::Prng::new(seed ^ 0x616c_676f_7661_7237);
    let pick = |random: &mut crate::random::Prng, table: &[u64]| {
        table[(random.next_u64() % table.len() as u64) as usize]
    };
    CipherParams {
        outer: pick(&mut random, &MULTIPLIERS),
        constant: pick(&mut random, &MULTIPLIERS),
        mix: pick(&mut random, &MIXES),
        probe_rounds: [
            3 + (random.next_u64() % 7) as u32,
            3 + (random.next_u64() % 7) as u32,
            3 + (random.next_u64() % 7) as u32,
        ],
        constant_rounds: 9 + (random.next_u64() % 5) as u32,
    }
}

/// Structural inputs each audited probe function receives from the entry:
/// pairs of payload-table numeric keys (prelude/interpreter, validator/
/// helpers, and the first two probe keys). The same pairs feed the Rust-side
/// share derivation, keeping both ends bit-identical without ever storing a
/// share in the script.
fn cipher_probe_inputs(keys: &[u64]) -> [(u64, u64); 3] {
    [(keys[0], keys[4]), (keys[2], keys[3]), (keys[5], keys[6])]
}

/// Three key shares for the payload cipher, each COMPUTED at run time inside
/// one audited probe function from its structural input pair: mix 31*a+b,
/// then 3/5/7 Lehmer rounds (one more pair of rounds per probe). No share
/// literal exists anywhere in the generated script; the Rust cipher runs the
/// identical derivation.
fn cipher_shares(keys: &[u64], params: &CipherParams) -> [u64; 3] {
    let inputs = cipher_probe_inputs(keys);
    let mut shares = [0u64; 3];
    for (index, share) in shares.iter_mut().enumerate() {
        let (a, b) = inputs[index];
        let mut state = (a * params.mix + b) % 2_147_483_647;
        for _ in 0..params.probe_rounds[index] {
            state = params.outer * state % 2_147_483_647;
        }
        *share = state;
    }
    shares
}

/// Combined keystream seed: the three dynamically computed shares plus the
/// ciphertext length (31*#B on the Lua side). Every operand stays below 2^53,
/// so the generated decoder reproduces this value exactly.
fn cipher_state(shares: &[u64; 3], length: usize, mix: u64) -> u64 {
    1 + (shares[0] + shares[1] + shares[2] + mix * length as u64) % 2_147_483_646
}

/// Symmetric byte cipher over a Lehmer keystream (48271 mod 2147483647; the
/// combined seed is 1 + (s1+s2+s3+31*#B) mod 2147483646). Every intermediate
/// stays below 2^53, so the Lua-side double arithmetic in the generated
/// decoder reproduces this stream bit-for-bit. This raises the embedded
/// blob's entropy; it is obfuscation, NOT a cryptographic primitive.
fn lehmer_cipher(bytes: &[u8], shares: &[u64; 3], multiplier: u64, mix: u64) -> Vec<u8> {
    let mut state = cipher_state(shares, bytes.len(), mix);
    bytes
        .iter()
        .map(|&byte| {
            state = multiplier * state % 2_147_483_647;
            byte ^ (state % 256) as u8
        })
        .collect()
}

/// Byte ranges of every constant-record payload (all bytes after the type
/// tag: boolean value byte, number/integer 8 bytes, string content -- the
/// u32 string length stays plaintext as frame metadata) inside a canonical
/// `.obf` image, in file order. Bounded parsing: any truncation, bad count
/// or unknown tag is a diagnostic, never a panic. The framing (tags and
/// string lengths) is readable on both plaintext and encrypted images, so
/// the same scan locates the ranges for encryption and decryption.
fn constant_ranges(
    bytes: &[u8],
    target: Target,
) -> Result<Vec<std::ops::Range<usize>>, Diagnostic> {
    let bad = |message: &str| Diagnostic::new(format!("constant scan: {message}"));
    let u16at = |off: usize| u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap());
    let u32at = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    if bytes.len() < 32 || &bytes[..4] != b"OBF\x02" {
        return Err(bad("bad magic"));
    }
    let expected = if target.is_luau() { 0x75u8 } else { 0x51 };
    if bytes[4] != expected {
        return Err(bad("target mismatch"));
    }
    let np = u32at(16) as usize;
    if np == 0 || np > 65536 {
        return Err(bad("prototype count out of range"));
    }
    let mut position = 32usize;
    let mut ranges = Vec::new();
    let room = |position: usize, extra: usize| -> Result<(), Diagnostic> {
        position
            .checked_add(extra)
            .filter(|end| *end <= bytes.len())
            .map(|_| ())
            .ok_or_else(|| bad("truncated image"))
    };
    for _ in 0..np {
        room(position, 24)?;
        let upvalues = u16at(position + 8) as usize;
        let constants = u32at(position + 12) as usize;
        let code = u32at(position + 20) as usize;
        if upvalues > 256 || constants > 65536 {
            return Err(bad("prototype counts out of range"));
        }
        position += 24 + upvalues * 2;
        for _ in 0..constants {
            room(position, 1)?;
            let tag = bytes[position];
            position += 1;
            match tag {
                0 => {}
                1 => {
                    room(position, 1)?;
                    ranges.push(position..position + 1);
                    position += 1;
                }
                2 | 4 => {
                    room(position, 8)?;
                    ranges.push(position..position + 8);
                    position += 8;
                }
                3 | 5 => {
                    // The u32 length stays plaintext so the frame itself is
                    // scannable on both plaintext and ciphertext images
                    // (symmetric apply); only the content is encrypted.
                    room(position, 4)?;
                    let length = u32at(position) as usize;
                    room(position, 4 + length)?;
                    ranges.push(position + 4..position + 4 + length);
                    position += 4 + length;
                }
                _ => return Err(bad("unknown constant tag")),
            }
        }
        room(position, code)?;
        position += code;
    }
    if position != bytes.len() {
        return Err(bad("trailing bytes"));
    }
    Ok(ranges)
}

/// Keystream seed of the independent constant-pool cipher, derived from a
/// DIFFERENT structural key pair (wrapper keys 4/7) than the outer blob
/// cipher shares, advanced by 11 Lehmer rounds and mixed with the image
/// length. Never stored in the script; the target parser derives the same
/// value from the two structural keys the entry passes in.
fn constant_cipher_state(keys: &[u64], length: usize, params: &CipherParams) -> u64 {
    let mut state = (keys[4] * params.mix + keys[7]) % 2_147_483_647;
    for _ in 0..params.constant_rounds {
        state = params.constant * state % 2_147_483_647;
    }
    1 + (state + params.mix * length as u64) % 2_147_483_646
}

/// Symmetric constant-pool cipher: XOR every constant payload byte with the
/// Lehmer keystream (continuing across records in file order) and patch the
/// header Adler-32 over the transformed image. Applying it twice restores
/// the canonical bytes; the generated decoder runs the identical stream.
fn apply_constant_cipher(
    bytes: &mut [u8],
    keys: &[u64],
    target: Target,
    params: &CipherParams,
) -> Result<(), Diagnostic> {
    let ranges = constant_ranges(bytes, target)?;
    let mut state = constant_cipher_state(keys, bytes.len(), params);
    for range in ranges {
        for byte in &mut bytes[range] {
            state = params.constant * state % 2_147_483_647;
            *byte ^= (state % 256) as u8;
        }
    }
    let sum = custom::checksum(&bytes[32..]);
    bytes[28..32].copy_from_slice(&sum.to_le_bytes());
    Ok(())
}

/// Base86 alphabet: printable ASCII 35..=121 excluding backslash (92) --
/// 86 characters, all safe inside double-quoted Lua string literals.
fn base86_alphabet() -> Vec<u8> {
    (35u8..=121).filter(|&byte| byte != 92).collect()
}

/// Encode bytes as base86 text: every 4-byte little-endian group becomes 5
/// alphabet characters (least significant digit first); a 1..3-byte tail
/// becomes 2..4 characters. All arithmetic stays below 2^53 so the emitted
/// target decoder reproduces the decode in plain doubles.
fn base86_encode(bytes: &[u8]) -> String {
    let alphabet = base86_alphabet();
    debug_assert_eq!(alphabet.len(), 86);
    let mut out = String::new();
    for chunk in bytes.chunks(4) {
        let mut value = 0u64;
        for (index, &byte) in chunk.iter().enumerate() {
            value |= u64::from(byte) << (8 * index);
        }
        let digits = if chunk.len() == 4 { 5 } else { chunk.len() + 1 };
        for _ in 0..digits {
            out.push(alphabet[(value % 86) as usize] as char);
            value /= 86;
        }
    }
    out
}

/// Decode base86 text produced by `base86_encode`, mirroring the validation
/// of the emitted segment decoders exactly: alphabet range, tail length,
/// 32-bit group bound and tail width bound are all checked.
fn base86_decode(text: &str) -> Result<Vec<u8>, Diagnostic> {
    let bad = |message: &str| Diagnostic::new(format!("base86: {message}"));
    let value_of = |byte: u8| -> Result<u64, Diagnostic> {
        if byte == 92 || !(35..=121).contains(&byte) {
            return Err(bad("character outside the alphabet"));
        }
        Ok(u64::from(if byte > 92 { byte - 36 } else { byte - 35 }))
    };
    let bytes = text.as_bytes();
    if bytes.len() % 5 == 1 {
        return Err(bad("dangling single character"));
    }
    let mut out = Vec::new();
    for group in bytes.chunks(5) {
        let mut value = 0u64;
        let mut multiplier = 1u64;
        for &byte in group {
            value += value_of(byte)? * multiplier;
            multiplier *= 86;
        }
        if group.len() == 5 {
            if value > u64::from(u32::MAX) {
                return Err(bad("group value overflows 32 bits"));
            }
            for _ in 0..4 {
                out.push((value % 256) as u8);
                value /= 256;
            }
        } else {
            let width = group.len() - 1;
            if value > (1u64 << (8 * width)) - 1 {
                return Err(bad("tail value overflows its byte width"));
            }
            for _ in 0..width {
                out.push((value % 256) as u8);
                value /= 256;
            }
        }
    }
    Ok(out)
}

/// The three base86 segment literals of a generated VM script: the longest
/// alphabet-only string literals (short literals such as format strings or
/// probe tags never pass the length and alphabet filters).
fn segment_literals(source: &str, target: Target) -> Result<Vec<Vec<u8>>, Diagnostic> {
    let mut candidates = Vec::new();
    for token in crate::lexer::lex(source, target)? {
        if token.kind != crate::lexer::TokenKind::String {
            continue;
        }
        let value = crate::minify::literal_bytes(token.text(source), target)
            .map_err(|error| Diagnostic::new(format!("generated VM blob: {error}")))?;
        if value.len() >= 12
            && value.len() % 5 != 1
            && value
                .iter()
                .all(|&byte| (35..=121).contains(&byte) && byte != 92)
        {
            candidates.push(value);
        }
    }
    if candidates.len() < 3 {
        return Err(Diagnostic::new(
            "generated VM is missing its three payload segments",
        ));
    }
    candidates.sort_by_key(|literal| std::cmp::Reverse(literal.len()));
    candidates.truncate(3);
    Ok(candidates)
}

/// Reassemble the outer ciphertext of a generated VM script: try the six
/// segment orders, base86-decode and outer-decrypt each, and accept the
/// unique order whose plaintext image carries the magic and target byte.
/// The order itself is derived nowhere -- it is validated, not stored.
fn embedded_outer_ciphertext(
    source: &str,
    target: Target,
    seed: u64,
) -> Result<Vec<u8>, Diagnostic> {
    let segments = segment_literals(source, target)?;
    let params = cipher_params(seed);
    let shares = cipher_shares(&wrapper_keys(seed), &params);
    let expected = if target.is_luau() { 0x75u8 } else { 0x51 };
    let permutations = [
        [0usize, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut winners = Vec::new();
    for permutation in permutations {
        let mut text = Vec::new();
        for index in permutation {
            text.extend_from_slice(&segments[index]);
        }
        let Ok(stream) = base86_decode(&String::from_utf8_lossy(&text)) else {
            continue;
        };
        // The decoded stream must open with the fixed transport watermark;
        // everything after it is the outer ciphertext body. The watermark
        // also pins which segment is stream-first, so it strengthens the
        // order resolution on top of the full-image Adler gate.
        if !stream.starts_with(b"XXS:") {
            continue;
        }
        let cipher = &stream[4..];
        let plain = lehmer_cipher(cipher, &shares, params.outer, params.mix);
        // Magic + target byte alone cannot discriminate orders that share
        // the same first segment; the header Adler-32 over the whole image
        // is order-sensitive end to end, so a winner is a fully valid frame.
        let recorded = plain
            .get(28..32)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
        if plain.starts_with(b"OBF\x02")
            && plain[4] == expected
            && recorded == Some(custom::checksum(&plain[32..]))
        {
            winners.push(cipher.to_vec());
        }
    }
    if winners.len() != 1 {
        return Err(Diagnostic::new(
            "generated VM payload segments do not resolve to a unique order",
        ));
    }
    Ok(winners.pop().unwrap())
}

/// Extract the embedded payload image of a generated VM script with the
/// outer blob cipher removed: framing intact, constant pool still encrypted.
pub fn extract_embedded(source: &str, target: Target, seed: u64) -> Result<Vec<u8>, Diagnostic> {
    let cipher = embedded_outer_ciphertext(source, target, seed)?;
    let params = cipher_params(seed);
    Ok(lehmer_cipher(
        &cipher,
        &cipher_shares(&wrapper_keys(seed), &params),
        params.outer,
        params.mix,
    ))
}

/// Verification helper: extract the encrypted payload blob (by construction
/// the longest string literal of a generated VM script) and remove BOTH
/// cipher layers. The result equals the original canonical `.obf` bytes.
pub fn decrypt_embedded(source: &str, target: Target, seed: u64) -> Result<Vec<u8>, Diagnostic> {
    let mut payload = extract_embedded(source, target, seed)?;
    apply_constant_cipher(
        &mut payload,
        &wrapper_keys(seed),
        target,
        &cipher_params(seed),
    )?;
    Ok(payload)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{self, Instruction as I, Terminator as T};
    use std::collections::BTreeSet;
    use std::fs;
    use std::process::Command;

    mod native {
        use crate as obf;
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/mod.rs"));
    }

    fn blob(source: &str, target: Target, seed: u64) -> Vec<u8> {
        let chunk = crate::parse(source, target).unwrap();
        assert!(crate::vm::tests::no_inline_metadata(&chunk));
        // The embedded payload is encrypted; decrypt it with the seed that
        // produced this script and compare against the canonical bytecode.
        decrypt_embedded(source, target, seed).unwrap()
    }

    #[test]
    fn custom_finalizer_changes_every_explicit_local_and_never_changes_bytecode() {
        for target in [Target::Lua51, Target::Luau] {
            let data = compile(
                "local function add(a,b)return a+b end print(add(1,2))",
                target,
            )
            .unwrap();
            let program = custom::decode(&data, target).unwrap();
            let raw = generate(&data, &program, 735).unwrap();
            let before = crate::scope::analyze(&raw, target).unwrap();
            let mut layouts = BTreeSet::new();
            for seed in [0, 1, 735, u64::MAX] {
                let output = emit(&data, target, seed).unwrap();
                assert_eq!(emit(&data, target, seed).unwrap(), output);
                assert_eq!(blob(&raw, target, 735), data);
                assert_eq!(blob(&output, target, seed), data);
                assert!(!output.contains(['\r', '\n']));
                // Field shuffling reorders the payload table per seed, so the
                // per-position local comparison runs against the same-seed
                // finalizer output (identical layout, renamed locals) while
                // the distinct-layout check below uses the emitted script.
                let renamed = finalize(&raw, target, seed).unwrap();
                let after = crate::scope::analyze(&renamed, target).unwrap();
                let layout_after = crate::scope::analyze(&output, target).unwrap();
                assert_eq!(before.globals, after.globals);
                let mut groups = BTreeSet::new();
                let mut spellings = BTreeSet::new();
                for (old, new) in before.bindings.iter().zip(&after.bindings) {
                    if old.declaration.is_some() {
                        assert_ne!(old.name, new.name);
                        assert!((1..=2).contains(&new.name.len()));
                        assert!(new.name.bytes().all(|b| b.is_ascii_lowercase()));
                        assert!(
                            groups.insert((after.scopes[new.scope].name_scope, new.name.clone()))
                        );
                        spellings.insert(new.name.clone());
                    } else {
                        assert_eq!(old.name, new.name);
                    }
                }
                assert!(groups.len() > 100);
                assert!(spellings.len() < groups.len());
                assert!(layouts.insert(
                    layout_after
                        .bindings
                        .iter()
                        .map(|b| b.name.clone())
                        .collect::<Vec<_>>()
                ));
            }
        }
    }

    fn execute_coverage(data: &[u8], target: Target) -> BTreeSet<Opcode> {
        let program = custom::decode(data, target).unwrap();
        let raw = generate(data, &program, 735).unwrap();
        // Instrument the real fetch loop BEFORE the same final whole-output
        // naming/audit pass. This measures executed handlers, not just words
        // present in dead branches or uncalled prototypes.
        assert_eq!(raw.matches("if c==nil then E()end;pc=pc+4;").count(), 1);
        let raw=raw.replace("if c==nil then E()end;pc=pc+4;","if c==nil then E()end;pc=pc+4;Probe[o]=true;")
            .replace("return U(result,1,result.n)","for id in ProbePairs(Probe)do ProbePrint('opcode:'..id)end;return U(result,1,result.n)");
        let raw = format!("local Probe={{}};local ProbePrint,ProbePairs=print,pairs;{raw}");
        let output = finalize(&raw, target, 735).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join("coverage.lua");
        fs::write(&path, output).unwrap();
        let stdout = native::compile_and_run(target, &path);
        // The probe records renumbered dispatch values; translate them back
        // through the inverse of this seed's opcode permutation.
        let perm = opcode_permutation(735, 64);
        let inverse: std::collections::BTreeMap<u8, u8> = perm
            .iter()
            .enumerate()
            .map(|(slot, value)| (*value, slot as u8))
            .collect();
        String::from_utf8(stdout)
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_prefix("opcode:"))
            .map(|id| {
                Opcode::from_byte(inverse[&id.parse::<u8>().unwrap()])
                    .expect("probed value outside the permutation image")
            })
            .collect()
    }

    #[test]
    fn every_supported_opcode_is_actually_executed_in_the_target_runtime() {
        for (target, corpora) in [
            (
                Target::Lua51,
                [
                    include_str!("../../tests/fixtures/vm_lua51.lua"),
                    include_str!("../../tests/fixtures/scope_lua51.lua"),
                ],
            ),
            (
                Target::Luau,
                [
                    include_str!("../../tests/fixtures/vm_luau.lua"),
                    include_str!("../../tests/fixtures/scope_luau.lua"),
                ],
            ),
        ] {
            let mut executed = BTreeSet::new();
            for corpus in corpora {
                executed.extend(execute_coverage(&compile(corpus, target).unwrap(), target));
            }
            // TOSTRING is directly useful in handwritten Lua 5.1 IR as well as
            // Luau interpolation; prove its value, not a synthetic no-op hit.
            let mut module = ir::compile("return", target).unwrap();
            let f = &mut module.functions[0];
            f.registers = 7;
            f.constants = vec![
                ir::Constant::number(42.0),
                ir::Constant::String(b"42".to_vec()),
                ir::Constant::String(b"assert".to_vec()),
            ];
            f.blocks = vec![ir::Block {
                instructions: vec![
                    I::Constant(0, 0),
                    I::ToString(1, 0),
                    I::Constant(2, 1),
                    I::Binary(crate::ast::BinaryOperator::Equal, 3, 1, 2),
                    I::ReadGlobal(4, 2),
                    I::NewPack(5),
                    I::Push(5, 3),
                    I::Call(6, 4, 5),
                    I::NewPack(0),
                ],
                terminator: T::Return(0),
            }];
            executed.extend(execute_coverage(&custom::encode(&module).unwrap(), target));
            let expected: BTreeSet<_> = Opcode::ALL
                .iter()
                .copied()
                .filter(|op| op.supported(target))
                .collect();
            assert_eq!(executed, expected, "unexecuted custom opcode on {target}");
        }
    }

    #[test]
    fn target_decoder_rejects_corrupt_repaired_payload_before_user_code_runs() {
        for target in [Target::Lua51, Target::Luau] {
            let data = compile("print('MUST_NOT_RUN')", target).unwrap();
            let program = custom::decode(&data, target).unwrap();
            for kind in 0..5 {
                let mut bad = data.clone();
                match kind {
                    0 => bad[39] = 255,
                    1 => bad[36..38].copy_from_slice(&257u16.to_le_bytes()),
                    2 => bad[48..52].copy_from_slice(&u32::MAX.to_le_bytes()),
                    // dangling varint continuation in the final instruction
                    3 => {
                        let last = bad.len() - 1;
                        bad[last] = 0x80;
                    }
                    // instruction byte count outside the 2..=7-per-instruction band
                    _ => {
                        bad[52..56].copy_from_slice(&u32::MAX.to_le_bytes());
                    }
                }
                let checksum = custom::checksum(&bad[32..]);
                bad[28..32].copy_from_slice(&checksum.to_le_bytes());
                assert!(custom::decode(&bad, target).is_err());
                // Bypass only Rust's input gate inside this unit test to
                // independently exercise the emitted target-language gate.
                // Since the constant-pool cipher scans the payload frame,
                // corruption that breaks the frame itself (kind 4's
                // impossible code byte count) is rejected by the generator;
                // every other kind still reaches the target decoder and is
                // rejected there. Either way no user code ever runs.
                let output = match generate(&bad, &program, 735) {
                    Ok(raw) => Some(finalize(&raw, target, 735).unwrap()),
                    Err(_) => {
                        assert_eq!(kind, 4, "{target}: unexpected generator rejection");
                        None
                    }
                };
                if let Some(output) = output {
                    let work = native::Workspace::new();
                    let path = work.0.join("invalid.lua");
                    fs::write(&path, output).unwrap();
                    assert!(native::compile(target, &path).status.success());
                    let runner = if target.is_luau() { "luau" } else { "lua5.1" };
                    let result = Command::new(native::root().join("toolchains/bin").join(runner))
                        .arg(&path)
                        .output()
                        .unwrap();
                    assert!(!result.status.success());
                    assert!(result.stdout.is_empty());
                }
            }
        }
    }

    #[test]
    fn target_decoder_independently_rejects_invalid_closure_sharing_metadata() {
        let source = "local function f(n)if n>0 then return f(n-1)end return 3 end print('MUST_NOT_RUN',f(2))";
        let data = compile(source, Target::Luau).unwrap();
        let program = custom::decode(&data, Target::Luau).unwrap();
        let root = &program.prototypes[0];
        let constant_bytes: usize = root
            .constants
            .iter()
            .map(|c| match c {
                ir::Constant::Nil => 1,
                ir::Constant::Boolean(_) => 2,
                ir::Constant::Number(_) | ir::Constant::Integer(_) => 9,
                ir::Constant::String(s) => 5 + s.len(),
                ir::Constant::Method(s) => 5 + s.len(),
            })
            .sum();
        let child = 32
            + 24
            + root.captures.len() * 2
            + constant_bytes
            + custom::encode_code(&root.code).unwrap().len();
        assert_eq!(data[child + 24], 2);
        for kind in 0..5 {
            let mut bad = data.clone();
            match kind {
                0 => bad[24..28].copy_from_slice(&1u32.to_le_bytes()),
                1 => bad[child + 7] &= !8,
                2 => bad[child + 7] |= 16,
                3 => bad[child + 24] = 3,
                _ => bad[child + 25] = 255,
            }
            let checksum = custom::checksum(&bad[32..]);
            bad[28..32].copy_from_slice(&checksum.to_le_bytes());
            assert!(custom::decode(&bad, Target::Luau).is_err());
            let raw = generate(&bad, &program, 735).unwrap();
            let output = finalize(&raw, Target::Luau, 735).unwrap();
            let work = native::Workspace::new();
            let path = work.0.join("invalid.luau");
            fs::write(&path, output).unwrap();
            assert!(native::compile(Target::Luau, &path).status.success());
            let result = Command::new(native::root().join("toolchains/bin/luau"))
                .arg(path)
                .output()
                .unwrap();
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
        }
    }

    #[test]
    fn whole_output_is_a_setmetatable_method_call_over_split_section_functions() {
        use crate::ast::{ExpressionKind, StatementKind, TableField};
        for target in [Target::Lua51, Target::Luau] {
            // `forwards` is true exactly when the chunk itself reads `...`;
            // only then does the wrapper method call forward varargs.
            for (source, forwards) in [
                ("local a=2 print(a*21)", false),
                ("local a,b=... print((a or 0)+(b or 0))", true),
            ] {
                let data = compile(source, target).unwrap();
                let output = emit(&data, target, 735).unwrap();
                assert_eq!(emit(&data, target, 735).unwrap(), output);
                let chunk = crate::parser::parse_source(&output, target).unwrap();
                let statements = &chunk.block.statements;
                assert_eq!(statements.len(), 2, "{target}: {output}");
                // local <short>={}
                let StatementKind::Local {
                    bindings, values, ..
                } = &statements[0].kind
                else {
                    panic!("{target}: {output}");
                };
                assert_eq!(bindings.len(), 1);
                let wrapper_name = bindings[0].name.value.clone();
                assert!((1..=2).contains(&wrapper_name.len()));
                assert!(wrapper_name.bytes().all(|byte| byte.is_ascii_lowercase()));
                assert!(
                    matches!(&values[0].kind, ExpressionKind::Table(fields) if fields.is_empty())
                );
                // return setmetatable({sections},<wrapper local>):<random letter>(...)
                let StatementKind::Return(returned) = &statements[1].kind else {
                    panic!("{target}: {output}");
                };
                assert_eq!(returned.len(), 1);
                let ExpressionKind::Call {
                    function,
                    method,
                    type_arguments,
                    arguments,
                } = &returned[0].kind
                else {
                    panic!("{target}: {output}");
                };
                assert!(type_arguments.is_empty());
                let Some(method) = method else {
                    panic!("{target}: {output}");
                };
                assert!((1..=2).contains(&method.value.len()));
                assert!(method.value.bytes().all(|byte| byte.is_ascii_lowercase()));
                assert!(!crate::lexer::is_keyword(&method.value, target));
                assert_eq!(arguments.len(), usize::from(forwards));
                if forwards {
                    assert!(matches!(arguments[0].kind, ExpressionKind::Vararg));
                }
                let ExpressionKind::Call {
                    function: setmetatable,
                    method: None,
                    type_arguments: setmetatable_types,
                    arguments: setmetatable_arguments,
                } = &function.kind
                else {
                    panic!("{target}: {output}");
                };
                assert!(setmetatable_types.is_empty());
                assert!(matches!(
                    &setmetatable.kind,
                    ExpressionKind::Name(name) if name.value == "setmetatable"
                ));
                assert_eq!(setmetatable_arguments.len(), 2);
                match &setmetatable_arguments[1].kind {
                    ExpressionKind::Name(reference) => assert_eq!(reference.value, wrapper_name),
                    _ => panic!("{target}: {output}"),
                }
                // payload table: thirteen numeric-keyed functions (five
                // sections, three probe/share functions, three base86
                // payload-segment decoders, two split watermark-check
                // functions) and exactly one string-keyed entry function
                // (the called method)
                let ExpressionKind::Table(fields) = &setmetatable_arguments[0].kind else {
                    panic!("{target}: {output}");
                };
                assert_eq!(fields.len(), 17, "{target}: {output}");
                let mut numeric_keys = std::collections::BTreeSet::new();
                let mut entries = 0;
                for field in fields {
                    let TableField::Computed { key, value, .. } = field else {
                        panic!("{target}: {output}");
                    };
                    let ExpressionKind::Function(body) = &value.kind else {
                        panic!("{target}: {output}");
                    };
                    match &key.kind {
                        ExpressionKind::Number(raw) => {
                            assert!(numeric_keys.insert(raw.clone()), "{target}: {output}");
                        }
                        ExpressionKind::String(raw) => {
                            entries += 1;
                            assert_eq!(
                                crate::minify::literal_bytes(raw, target).unwrap(),
                                method.value.as_bytes(),
                                "{target}: {output}"
                            );
                            // entry receives (self) plus the forwarded chunk varargs
                            assert!(body.has_vararg);
                            assert_eq!(body.parameters.len(), 1);
                        }
                        _ => panic!("{target}: {output}"),
                    }
                }
                assert_eq!(entries, 1);
                assert_eq!(numeric_keys.len(), 16);
                // The wrapper is not just structural: it runs the program.
                let workspace = native::Workspace::new();
                let path = workspace.0.join("wrapped.lua");
                fs::write(&path, source).unwrap();
                let expected = native::compile_and_run(target, &path);
                fs::write(&path, &output).unwrap();
                assert_eq!(expected, native::compile_and_run(target, &path));
            }
        }
    }

    #[test]
    fn cipher_key_is_derived_dynamically_and_never_appears_in_plaintext() {
        // The shares and the combined keystream seed are COMPUTED at run
        // time from the script's own structure; none of them may appear as
        // any numeric literal (or any digit run at all) in the output.
        for (target, fixture) in [
            (
                Target::Lua51,
                include_str!("../../tests/fixtures/vm_lua51.lua"),
            ),
            (
                Target::Luau,
                include_str!("../../tests/fixtures/vm_luau.lua"),
            ),
        ] {
            for seed in [0u64, 1, 735, 7351, u64::MAX] {
                let data = compile(fixture, target).unwrap();
                let output = emit(&data, target, seed).unwrap();
                let keys = wrapper_keys(seed);
                let params = cipher_params(seed);
                let shares = cipher_shares(&keys, &params);
                let state = cipher_state(&shares, data.len(), params.mix);
                let secrets = [
                    shares[0].to_string(),
                    shares[1].to_string(),
                    shares[2].to_string(),
                    state.to_string(),
                    constant_cipher_state(&keys, data.len(), &params).to_string(),
                ];
                for secret in &secrets {
                    assert!(
                        !output.contains(secret.as_str()),
                        "{target} seed {seed}: cipher key material {secret} leaked"
                    );
                }
                for token in crate::lexer::lex(&output, target).unwrap() {
                    if token.kind != crate::lexer::TokenKind::Number {
                        continue;
                    }
                    let text = token.text(&output);
                    assert!(
                        secrets.iter().all(|secret| secret != text),
                        "{target} seed {seed}: numeric literal {text} leaks key material"
                    );
                }
                // The derivation is structural: the same seed must still
                // reproduce the exact same script, and decrypt back to the
                // canonical bytes.
                assert_eq!(emit(&data, target, seed).unwrap(), output);
                assert_eq!(decrypt_embedded(&output, target, seed).unwrap(), data);
            }
        }
    }

    #[test]
    fn constant_pool_cipher_is_an_independent_second_layer() {
        let source = "local s='OBF_UNIQUE_SECRET_7351' local n=3.25 print(s,n)";
        for target in [Target::Lua51, Target::Luau] {
            let data = compile(source, target).unwrap();
            let output = emit(&data, target, 735).unwrap();
            let payload = extract_embedded(&output, target, 735).unwrap();
            // Framing stays intact, but the image is no longer canonical:
            // its constant pool is ciphertext and the Adler is patched.
            assert_eq!(&payload[..4], b"OBF\x02");
            assert_ne!(payload, data);
            // With only the outer blob cipher removed, neither the string
            // constant nor the number constant is visible anywhere.
            let secret = b"OBF_UNIQUE_SECRET_7351";
            assert!(!payload.windows(secret.len()).any(|w| w == secret));
            let number = 3.25f64.to_le_bytes();
            assert!(!payload.windows(8).any(|w| w == number));
            // Different seeds derive different constant keystreams.
            let other = emit(&data, target, 736).unwrap();
            let other = extract_embedded(&other, target, 736).unwrap();
            assert_ne!(payload, other);
            // Removing both layers restores the canonical bytes exactly.
            assert_eq!(decrypt_embedded(&output, target, 735).unwrap(), data);
        }
    }

    #[test]
    fn constant_cipher_scan_rejects_malformed_images() {
        let data = compile("local a='const' return a", Target::Lua51).unwrap();
        let ranges = constant_ranges(&data, Target::Lua51).unwrap();
        assert!(!ranges.is_empty());
        assert!(ranges.iter().all(|range| range.end <= data.len()));
        let corrupted_magic = {
            let mut bytes = data.clone();
            bytes[0] = b'X';
            bytes
        };
        let zeroed_prototypes = {
            let mut bytes = data.clone();
            bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
            bytes
        };
        let unknown_tag = {
            // Proto header at 32: force nu=0/nk=1 so the first constant
            // tag lands at 56, then make it an unknown tag.
            let mut bytes = data.clone();
            bytes[40..42].copy_from_slice(&0u16.to_le_bytes());
            bytes[44..48].copy_from_slice(&1u32.to_le_bytes());
            bytes[56] = 9;
            bytes
        };
        let mut trailing = data.clone();
        trailing.push(0);
        for bytes in [
            Vec::new(),
            b"OBF".to_vec(),
            corrupted_magic,
            zeroed_prototypes,
            unknown_tag,
            trailing,
            data[..data.len() - 1].to_vec(),
            data[..32].to_vec(),
        ] {
            assert!(constant_ranges(&bytes, Target::Lua51).is_err());
        }
    }

    #[test]
    fn m7_structural_variants_vary_across_seeds_and_stay_reproducible() {
        // Token-level, name-agnostic detection works on the FINAL output
        // (the finalizer renames every explicit local).
        let forms = |output: &str, target: Target| -> (usize, usize, usize, usize) {
            let tokens = crate::lexer::lex(output, target).unwrap();
            let text = |index: usize| tokens[index].text(output);
            let kind = |index: usize| tokens[index].kind;
            let mut dispatch = [false; 4];
            let mut bound = [false; 3];
            let mut call = 0usize;
            let mut userdata = [false; 2];
            for index in 0..tokens.len() {
                // name==number / number==name / not(name~=number) /
                if index + 2 < tokens.len() {
                    if kind(index) == crate::lexer::TokenKind::Identifier
                        && text(index + 1) == "=="
                        && kind(index + 2) == crate::lexer::TokenKind::Number
                    {
                        dispatch[0] = true;
                    }
                    if kind(index) == crate::lexer::TokenKind::Number
                        && text(index + 1) == "=="
                        && kind(index + 2) == crate::lexer::TokenKind::Identifier
                    {
                        dispatch[1] = true;
                    }
                }
                if index + 4 < tokens.len()
                    && text(index) == "not"
                    && text(index + 1) == "("
                    && kind(index + 2) == crate::lexer::TokenKind::Identifier
                    && text(index + 3) == "~="
                    && kind(index + 4) == crate::lexer::TokenKind::Number
                {
                    dispatch[2] = true;
                }
                if index + 4 < tokens.len()
                    && kind(index) == crate::lexer::TokenKind::Identifier
                    && text(index + 1) == "-"
                    && kind(index + 2) == crate::lexer::TokenKind::Number
                    && text(index + 3) == "=="
                    && text(index + 4) == "0"
                {
                    dispatch[3] = true;
                }
                // Bound-check spellings over the operand bound.
                if index + 2 < tokens.len() {
                    if kind(index) == crate::lexer::TokenKind::Identifier
                        && text(index + 1) == ">"
                        && text(index + 2) == "255"
                    {
                        bound[0] = true;
                    }
                    if text(index) == "255"
                        && text(index + 1) == "<"
                        && kind(index + 2) == crate::lexer::TokenKind::Identifier
                    {
                        bound[1] = true;
                    }
                    if text(index) == "<=" && text(index + 1) == "255" {
                        bound[2] = true;
                    }
                }
                // Call-wrapper inversion: `if not <name> then return`.
                if index + 4 < tokens.len()
                    && text(index) == "if"
                    && text(index + 1) == "not"
                    && kind(index + 2) == crate::lexer::TokenKind::Identifier
                    && text(index + 3) == "then"
                    && text(index + 4) == "return"
                {
                    call = 1;
                }
                // Userdata guard equality order (substring forms are stable
                // under the finalizer's quote normalization to `"..."`).
                if output.contains("==\"userdata\"") {
                    userdata[0] = true;
                }
                if output.contains("\"userdata\"==") {
                    userdata[1] = true;
                }
            }
            (
                dispatch.iter().filter(|&&hit| hit).count(),
                bound.iter().filter(|&&hit| hit).count(),
                call,
                userdata.iter().filter(|&&hit| hit).count(),
            )
        };
        // UNION across seeds and targets: a family counts as observed if
        // ANY output exhibits it (a single output may carry only one of the
        // mutually exclusive spellings).
        let mut dispatch_total = 0usize;
        let mut bound_total = 0usize;
        let mut call_total = 0usize;
        let mut userdata_seen = [false; 2];
        for (target, fixture) in [
            (
                Target::Lua51,
                include_str!("../../tests/fixtures/vm_lua51.lua"),
            ),
            (
                Target::Luau,
                include_str!("../../tests/fixtures/vm_luau.lua"),
            ),
        ] {
            let data = compile(fixture, target).unwrap();
            for seed in 0..=15u64 {
                let output = emit(&data, target, seed).unwrap();
                // Reproducibility with structural variants enabled.
                assert_eq!(emit(&data, target, seed).unwrap(), output);
                let (dispatch, bound, call, userdata) = forms(&output, target);
                dispatch_total |= dispatch;
                bound_total |= bound;
                call_total |= call;
                if output.contains("==\"userdata\"") {
                    userdata_seen[0] = true;
                }
                if output.contains("\"userdata\"==") {
                    userdata_seen[1] = true;
                }
            }
        }
        assert!(
            dispatch_total >= 3,
            "dispatch variant families: {dispatch_total}"
        );
        assert_eq!(bound_total, 3, "bound variant families: {bound_total}");
        assert_eq!(call_total, 1, "call-wrapper inversion never observed");
        assert!(
            userdata_seen == [true, true],
            "userdata guard orders: {userdata_seen:?}"
        );
    }

    #[test]
    fn opcode_dispatch_numbers_are_renumbered_per_seed() {
        // Per-seed opcode renumbering: the canonical ISA numbering stays in
        // the `.obf` file and the embedded varint stream, but the script's
        // dispatch chains run on a per-seed shuffled numbering rebuilt from
        // the packed base86 string. Across seeds the numbering must differ;
        // within a seed it must be a reproducible injection whose packed
        // form round-trips, and the program must still run unchanged.
        let source = "local t={} for i=1,4 do t[i]=i*3 end print(t[2],#t)";
        for target in [Target::Lua51, Target::Luau] {
            let data = compile(source, target).unwrap();
            let program = custom::decode(&data, target).unwrap();
            let mut numberings = BTreeSet::new();
            for seed in [0u64, 1, 2, 3, 735, u64::MAX] {
                let perm = opcode_permutation(seed, 64);
                assert_eq!(opcode_permutation(seed, 64), perm);
                let distinct: BTreeSet<u8> = perm.iter().copied().collect();
                assert_eq!(distinct.len(), perm.len(), "not injective");
                // Renumbered dispatch values must leave the canonical range
                // 0..=63 for real opcodes, so no generation runs on the
                // public canonical numbering.
                let renumbered_real: BTreeSet<u8> = program
                    .opcodes()
                    .iter()
                    .map(|op| perm[(*op as u8) as usize])
                    .collect();
                assert!(
                    renumbered_real.iter().any(|value| *value > 63),
                    "{target} seed {seed}: dispatch numbering still canonical"
                );
                assert!(numberings.insert(perm.clone()));
                // The packed renumbering string decodes back to the same
                // permutation the generator used for its arms.
                let raw = generate(&data, &program, seed).unwrap();
                let at = raw.find("local U=\"").expect("packed renumbering string");
                let start = at + "local U=\"".len();
                let end = raw[start..].find('"').expect("unterminated") + start;
                let packed = &raw[start..end];
                assert_eq!(packed.len(), 129);
                assert_eq!(packed.as_bytes()[0], b'~');
                for slot in 0..64usize {
                    let x = packed.as_bytes()[1 + slot * 2];
                    let y = packed.as_bytes()[2 + slot * 2];
                    let dx = (if x > 92 { x - 1 } else { x }) - 35;
                    let dy = (if y > 92 { y - 1 } else { y }) - 35;
                    assert_eq!(u8::from(dx + dy * 86), perm[slot]);
                }
                // Differential: the embedded payload is untouched canonical
                // bytecode regardless of the renumbering.
                let output = emit(&data, target, seed).unwrap();
                assert_eq!(blob(&output, target, seed), data);
            }
            assert_eq!(numberings.len(), 6, "{target}: identical renumberings");
            // The renumbered dispatch still executes the program verbatim.
            let workspace = native::Workspace::new();
            let path = workspace.0.join("renumbered.lua");
            fs::write(&path, source).unwrap();
            let expected = native::compile_and_run(target, &path);
            fs::write(&path, emit(&data, target, 735).unwrap()).unwrap();
            assert_eq!(expected, native::compile_and_run(target, &path));
        }
    }

    #[test]
    fn operand_features_are_split_into_separate_shuffled_fields() {
        // The operand-form map (`[0]=3,[1]=4,...` sequential-key literal),
        // the varint reader with its `if f==1 elseif f==2 ...` shape chain
        // and the per-opcode bounds arms used to be one field's static
        // signature. They must now be three separate payload fields, with
        // the form map rebuilt from a per-seed rotated packed string.
        for target in [Target::Lua51, Target::Luau] {
            let source = "local function add(a,b)return a+b end print(add(1,2))";
            let data = compile(source, target).unwrap();
            let program = custom::decode(&data, target).unwrap();
            let mut packed_strings = BTreeSet::new();
            for seed in [0u64, 1, 735, u64::MAX] {
                let raw = generate(&data, &program, seed).unwrap();
                let keys = wrapper_keys(seed);
                assert!(!raw.contains("local FM={"), "{target} seed {seed}");
                assert!(raw.contains(&format!("[{}]=function(E,SB)", keys[13])));
                assert!(raw.contains(&format!("[{}]=function(E,SB,FM)", keys[14])));
                assert!(raw.contains(&format!("[{}]=function(E)", keys[15])));
                assert!(raw.contains(&format!(
                    "[{}]=function(P,np,SB,E,NCH,TC,dec,vld,PT)",
                    keys[2]
                )));
                assert!(raw.contains(&format!("VMS[{}](E,SB)", keys[13])));
                // The packed form string is the only short `local S="..."`
                // in the raw script (segment fields carry long base86
                // text); its bytes must rotate with the seed.
                let mut at = 0usize;
                while let Some(found) = raw[at..].find("local S=\"") {
                    let start = at + found + 9;
                    let end = raw[start..].find('"').expect("unterminated string") + start;
                    if end - start <= 96 {
                        packed_strings.insert(raw[start..end].to_owned());
                    }
                    at = end;
                }
                let output = emit(&data, target, seed).unwrap();
                assert_eq!(blob(&output, target, seed), data);
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

    #[test]
    fn full_code_randomization_layout_and_cipher_vary_per_seed() {
        // Full code randomization: payload fields (including every
        // decryption/probe/segment function) are emitted in a seeded
        // shuffled textual order, and the cipher parameters (Lehmer
        // multiplier, mixing constant) are drawn per seed. Across seeds the
        // layouts and parameters must differ; per seed everything must stay
        // byte-reproducible.
        let mut layouts = std::collections::BTreeSet::new();
        let mut multipliers = std::collections::BTreeSet::new();
        let mut mixes = std::collections::BTreeSet::new();
        for (target, fixture) in [
            (
                Target::Lua51,
                include_str!("../../tests/fixtures/vm_lua51.lua"),
            ),
            (
                Target::Luau,
                include_str!("../../tests/fixtures/vm_luau.lua"),
            ),
        ] {
            let data = compile(fixture, target).unwrap();
            for seed in 0..=11u64 {
                let output = emit(&data, target, seed).unwrap();
                assert_eq!(emit(&data, target, seed).unwrap(), output);
                // Textual order of the numeric-keyed payload fields.
                let tokens = crate::lexer::lex(&output, target).unwrap();
                let mut order = Vec::new();
                for index in 0..tokens.len().saturating_sub(4) {
                    if tokens[index].text(&output) == "["
                        && tokens[index + 1].kind == crate::lexer::TokenKind::Number
                        && tokens[index + 2].text(&output) == "]"
                        && tokens[index + 3].text(&output) == "="
                        && tokens[index + 4].text(&output) == "function"
                    {
                        order.push(tokens[index + 1].text(&output).to_owned());
                    }
                }
                assert_eq!(order.len(), 16, "{target} seed {seed}");
                layouts.insert((format!("{target:?}"), order));
                for multiplier in [16_807u64, 48_271, 65_539] {
                    if output.contains(&format!("={multiplier}*"))
                        || output.contains(&format!("*{multiplier}*"))
                    {
                        multipliers.insert(multiplier);
                    }
                }
                for mix in [31u64, 33, 37, 41] {
                    if output.contains(&format!("{mix}*#")) {
                        mixes.insert(mix);
                    }
                }
            }
        }
        // 24 outputs (12 seeds x 2 targets) must not share layouts.
        assert!(
            layouts.len() >= 20,
            "only {} distinct layouts across 24 outputs",
            layouts.len()
        );
        assert_eq!(multipliers.len(), 3, "multiplier variety: {multipliers:?}");
        assert!(mixes.len() >= 3, "mixing constant variety: {mixes:?}");
    }

    #[test]
    fn opaque_true_false_branches_carry_real_but_unreachable_instructions() {
        // Both user-requested forms, detected on the FINAL renamed output:
        //  - the entry body wrapped as `if <tautology> then <real chain>
        //    else <decoy>` (or the flipped `if <contradiction>` form);
        //  - dead elseif arms in the F3/F5 dispatch chains keyed on opcode
        //    numbers 200..=254, which can never occur (real opcodes stay
        //    below 64 and F3 rejects unknown opcodes through the FM gate).
        // The decoy branches carry real instructions; the native-parity
        // differentials prove they never execute.
        const TRUTHY: [&str; 4] = [
            "48271%2==1",
            "2147483647>2147483646",
            "65536%256==0",
            "16777216%2==0",
        ];
        const FALSY: [&str; 4] = [
            "48271%2==0",
            "2147483647>2147483647",
            "65536%256==1",
            "16777216%2==1",
        ];
        let mut truthy_wraps = 0usize;
        let mut falsy_wraps = 0usize;
        for (target, fixture) in [
            (
                Target::Lua51,
                include_str!("../../tests/fixtures/vm_lua51.lua"),
            ),
            (
                Target::Luau,
                include_str!("../../tests/fixtures/vm_luau.lua"),
            ),
        ] {
            let data = compile(fixture, target).unwrap();
            for seed in 0..=7u64 {
                let output = emit(&data, target, seed).unwrap();
                assert_eq!(emit(&data, target, seed).unwrap(), output);
                // Dead dispatch arms: an identifier/number equality where
                // the number sits in the impossible 200..=254 band.
                let tokens = crate::lexer::lex(&output, target).unwrap();
                let mut dead_arms = 0usize;
                // Numeric literals appear in decimal, hex or digit-grouped
                // binary spellings (integer_literal variants).
                let numeric = |text: &str| -> Option<u32> {
                    let (radix, digits) = if let Some(rest) = text.strip_prefix("0x") {
                        (16, rest)
                    } else if let Some(rest) = text.strip_prefix("0b") {
                        (2, rest)
                    } else {
                        (10, text)
                    };
                    u32::from_str_radix(&digits.replace('_', ""), radix).ok()
                };
                for index in 0..tokens.len().saturating_sub(5) {
                    let band = |token: usize| {
                        tokens[token].kind == crate::lexer::TokenKind::Number
                            && numeric(tokens[token].text(&output))
                                .is_some_and(|value| (200..=254).contains(&value))
                    };
                    if tokens[index + 1].text(&output) == "=="
                        && ((tokens[index].kind == crate::lexer::TokenKind::Identifier
                            && band(index + 2))
                            || (band(index)
                                && tokens[index + 2].kind == crate::lexer::TokenKind::Identifier))
                    {
                        dead_arms += 1;
                    }
                    // not(A~=K) spelling.
                    if tokens[index].text(&output) == "not"
                        && tokens[index + 1].text(&output) == "("
                        && tokens[index + 2].kind == crate::lexer::TokenKind::Identifier
                        && tokens[index + 3].text(&output) == "~="
                        && band(index + 4)
                    {
                        dead_arms += 1;
                    }
                    // A-K==0 spelling.
                    if tokens[index].kind == crate::lexer::TokenKind::Identifier
                        && tokens[index + 1].text(&output) == "-"
                        && band(index + 2)
                        && tokens[index + 3].text(&output) == "=="
                        && tokens[index + 4].text(&output) == "0"
                    {
                        dead_arms += 1;
                    }
                }
                assert!(
                    dead_arms >= 2,
                    "{target} seed {seed}: {dead_arms} dead arms"
                );
                // Entry opaque guard: exactly one pool predicate wraps the
                // entry, in either the tautology or the contradiction form.
                let truthy = TRUTHY.iter().filter(|p| output.contains(*p)).count();
                let falsy = FALSY.iter().filter(|p| output.contains(*p)).count();
                assert_eq!(truthy + falsy, 1, "{target} seed {seed}");
                truthy_wraps += truthy;
                falsy_wraps += falsy;
            }
        }
        assert!(truthy_wraps > 0 && falsy_wraps > 0, "both forms must occur");
    }

    #[test]
    fn generation_respects_the_documented_size_budget() {
        // M7 size budget: the structural variants must not inflate a
        // generated script beyond the documented caps (~15% headroom over
        // the current goldens; raise the caps deliberately, never silently).
        for (target, fixture, budget) in [
            (
                Target::Lua51,
                include_str!("../../tests/fixtures/vm_lua51.lua"),
                24_000usize,
            ),
            (
                Target::Luau,
                include_str!("../../tests/fixtures/vm_luau.lua"),
                26_000usize,
            ),
        ] {
            let data = compile(fixture, target).unwrap();
            for seed in [0u64, 735, 7001, 7351, u64::MAX] {
                let output = emit(&data, target, seed).unwrap();
                assert!(
                    output.len() <= budget,
                    "{target} seed {seed}: {} bytes exceeds the {} byte budget",
                    output.len(),
                    budget
                );
            }
        }
    }

    #[test]
    fn transport_watermark_is_present_checked_and_never_spelled_out() {
        for (target, fixture) in [
            (
                Target::Lua51,
                include_str!("../../tests/fixtures/vm_lua51.lua"),
            ),
            (
                Target::Luau,
                include_str!("../../tests/fixtures/vm_luau.lua"),
            ),
        ] {
            let data = compile(fixture, target).unwrap();
            let output = emit(&data, target, 735).unwrap();
            // The hidden check must not leak the watermark text itself.
            assert!(!output.contains("XXS:"));
            // Exactly one segment is stream-first: its decode opens with
            // the fixed watermark bytes.
            let segments = segment_literals(&output, target).unwrap();
            let stamped = segments
                .iter()
                .filter(|literal| {
                    base86_decode(&String::from_utf8_lossy(literal))
                        .is_ok_and(|bytes| bytes.starts_with(b"XXS:"))
                })
                .count();
            assert_eq!(stamped, 1, "{target}");
            // The split functions carry no watermark spelling: W1 is a
            // byte packer, W2 holds only the packed u32 as a number.
            let expected = u32::from_be_bytes(*b"XXS:").to_string();
            assert!(output.contains(&expected));
            // Extraction strips the watermark; full roundtrip still holds.
            assert_eq!(decrypt_embedded(&output, target, 735).unwrap(), data);
        }
    }

    #[test]
    fn base86_codec_roundtrips_and_rejects_invalid_text() {
        for length in 0..40usize {
            let bytes: Vec<u8> = (0..length)
                .map(|index| ((index * 31 + length * 7) % 256) as u8)
                .collect();
            let text = base86_encode(&bytes);
            assert!(text
                .bytes()
                .all(|byte| (35..=121).contains(&byte) && byte != 92));
            assert_eq!(base86_decode(&text).unwrap(), bytes);
        }
        let big: Vec<u8> = (0..5000u32)
            .map(|index| (index.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let text = base86_encode(&big);
        assert_eq!(base86_decode(&text).unwrap(), big);
        // dangling single character (tail length 1)
        assert!(base86_decode("9").is_err());
        // characters outside the alphabet: quote, backslash, space, 7-bit edge
        for bad in ["\"9", "\\9", " 9", "\u{7f}9"] {
            assert!(base86_decode(bad).is_err(), "{bad:?}");
        }
        // five max-digit characters exceed 32 bits
        assert!(base86_decode("xxxxx").is_err());
        // a 4-character tail encoding more than 3 bytes
        assert!(base86_decode("zzzz").is_err());
    }

    #[test]
    fn embedded_payload_is_high_entropy_ciphertext_and_seed_dependent() {
        fn entropy(bytes: &[u8]) -> f64 {
            let mut counts = [0u64; 256];
            for &byte in bytes {
                counts[usize::from(byte)] += 1;
            }
            let total = f64::from(bytes.len() as u32);
            counts
                .iter()
                .filter(|&&count| count > 0)
                .map(|&count| {
                    let probability = count as f64 / total;
                    -probability * probability.log2()
                })
                .sum()
        }
        let ciphertext = |source: &str, target: Target| {
            // Reassemble the outer ciphertext from the three base86 segment
            // literals (order resolved and validated, not stored).
            embedded_outer_ciphertext(source, target, 735).unwrap()
        };
        for (target, fixture) in [
            (
                Target::Lua51,
                include_str!("../../tests/fixtures/vm_lua51.lua"),
            ),
            (
                Target::Luau,
                include_str!("../../tests/fixtures/vm_luau.lua"),
            ),
        ] {
            let data = compile(fixture, target).unwrap();
            let output = emit(&data, target, 735).unwrap();
            assert_eq!(decrypt_embedded(&output, target, 735).unwrap(), data);
            assert_ne!(emit(&data, target, 736).unwrap(), output);
            let encrypted = ciphertext(&output, target);
            assert_ne!(&encrypted[..4], b"OBF\x02");
            let (plain, cipher) = (entropy(&data), entropy(&encrypted));
            assert!(cipher > plain, "{target}: {cipher} <= {plain}");
            assert!(cipher > 7.5, "{target}: entropy {cipher}");
        }
    }
}
