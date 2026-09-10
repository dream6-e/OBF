//! Emitted-text builders for the decoder/transport stage of the generated VM.
//!
//! These are pure Lua-text helpers split out of `emit.rs` by stage: the
//! capture/constant pool readers (ISA14), the K9a base86 digit-take/emit forms,
//! the LZW/bit-reader decoder sections and the strict frame-v2 inverse. They
//! draw from the same seeded rng objects they received before the split, so the
//! generated script is byte-for-byte unchanged; the orchestration, ordering and
//! all validators stay in `emit.rs`.

use super::*;

/// Global capture/constant pool readers (ISA14). Each pool loop runs
/// exactly its validated total (`TU`/`TK`, accumulated from header
/// metadata), and decodes three anonymous u16 slots per record under the
/// per-record pool factorial profile. Every record is range-checked
/// (owner, slot/index), duplicate-checked, and stored into `CU`/`CK`
/// for the per-prototype slicers. Pool order follows the per-image flip
/// bit the encoder mirrors.
pub(crate) fn pool_loops_lua(
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
        "CK={{}};for slot=1,TK do {pool_decode}local owner=(st[sont[1]]-slot*{pm}-{pa})%65536;if owner>=np then E()end;local ix=(st[sont[2]]-owner*{pm}-slot-{pa})%65536;local OW=P[owner];if ix>=OW.__obf_proto_nk then E()end;local tg=(st[sont[3]]-ix*{pm}-owner-{pa})%65536;local val;if tg==0 then val=nil elseif tg==1 then val=b8();if val>1 then E()end elseif tg==2 then val=num() elseif tg==3 or tg==5 then val=str(){tag4} else E()end;local T=CK[owner];if T==nil then T={{}};CK[owner]=T end;if T[ix]~=nil then E()end;T[ix]={{tg,val}} end;",
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

/// One K9a digit-take: `width` chars from S at `base` (1-based Lua exprs)
/// accumulate into vv through the VAL table at radix r. Nil bytes (reads
/// past #S) and non-alphabet bytes both abort via E(); callers snapshot
/// pv, advance i and emit bytes themselves.
pub(crate) fn k9a_take(width: &str, base: &str) -> String {
    format!(
        "local vv=0;local mm=1;for j=1,{width} do local bb=SB(S,{base}+j-1);\
if bb==nil then E()end;local cc=VAL[bb];if cc==nil then E()end;vv=vv+cc*mm;mm=mm*r end;",
    )
}

/// One K9a byte-emission: exactly `count` low bytes of vv (a padded group
/// value) via the opaque byte width MM; leftover high padding is dropped.
pub(crate) fn k9a_emit(count: &str) -> String {
    format!("for j=1,{count} do o[#o+1]=NCH(vv%MM);vv=(vv-vv%MM)/MM end;")
}

/// Build the strict Lua-side inverse of the bounded LZW frame. The bit-reader
/// and dictionary stages are either separate sibling payload functions or one
/// combined function according to the seed; the inner-ChaCha8/frame stage is
/// always a third independently keyed field. The outer layout pass shuffles all of them
/// among unrelated VM sections, so neither count nor physical position is a
/// stable decoder signature.
pub(crate) fn compression_decoder_sections(
    keys: &[u64],
    split_helpers: bool,
    bitops: &mut crate::random::Prng,
) -> (Vec<String>, String) {
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
    let ctx_sum = render_modsum(bitops, &["n*31", "bits*17", "cs*7", "cc*13", "bl"]);
    let core = format!("if #C<17 or L32(C,1)~=22501964 then E()end;local n=L32(C,5);local bits=L32(C,9);local cs=L32(C,13);local bl=MF((bits+7)/8);local cc=MF((n+8191)/8192);if n<1 or n>16777216 or bits<1 or bl~=#C-16 or #C>=n then E()end;local ctx={ctx_sum};local aw=AH(AH,CC,CB,X8C,E,SB,NCH,TC,MF,DBG,GI,LS);local D=CC(SS(C,17),s1,s2,s3,pv,ctx,2,aw,CB,E,SB,NCH,TC,MF,X8);local pad=#D*8-bits;if pad>7 or pad>0 and MF(SB(D,#D)/2^(8-pad))~=0 then E()end;local B=LD(D,bits,n);if AD(B,1,#B)~=cs then E()end;return B");
    fields.push(format!(
        "[{}]=function(C,s1,s2,s3,pv,CC,AH,CB,LD,E,SB,SS,NCH,TC,MF,X8,X8C,AD,L32,DBG,GI,LS){core} end,",
        keys[23]
    ));
    let wiring = format!(
        "{wiring}local B=VMS[{}](C,c1,c2,c3,pv,CC,AH,CB,LD,E,SB,SS,NCH,TC,MF,X8,X8C,AD,L32,DBG,GI,LS);",
        keys[23]
    );
    (fields, wiring)
}

/// Compact strict frame-v2 inverse. Confidentiality is handled by the outer
/// ChaCha8 field; this stage validates every framed byte before returning the
/// independently encrypted compression frame.
pub(crate) fn transport_frame_decoder(
    params: &FrameParams,
    bitops: &mut crate::random::Prng,
) -> String {
    let c0 = params.key_coefficients[0];
    let c1 = params.key_coefficients[1];
    let cookie = params.cookie_salt.to_string();
    let tag = params.tag_salt.to_string();
    let ex0 = render_modsum(
        bitops,
        &["n", "d*257", "(fk0%65536)*65536", "(fk1%65536)*17", &cookie],
    );
    let ex1 = render_modsum(bitops, &["left", "right*65521", "c*17", "d*31"]);
    format!(
        "if #B<{header} or #B%4~=0 or #B>16777232 then E()end;local fk0=1+(s1*{c00}+s2*{c01}+s3*{c02}+pv*{c03}+#B*{c04}+{s0})%2147483646;local fk1=1+(s1*{c10}+s2*{c11}+s3*{c12}+pv*{c13}+#B*{c14}+{s1})%2147483646;local fd={version}+{header}*256+(fk0+fk1+{descriptor})%65536*65536;local d=L32(B,1);local n=L32(B,5);local c=L32(B,9);local t=L32(B,13);local pad=(4-(16+n)%4)%4;if n>16777216 or #B~=16+n+pad or d~=fd then E()end;local ex={ex0};if c~=ex then E()end;local left=(fk0+{tag})%65521;local right=(fk1+{cookie})%65521;for i=17,16+n do local byte=SB(B,i);left=(left*257+byte)%65521;right=(right*263+byte+left)%65521 end;local ex={ex1};if t~=ex then E()end;for i=1,pad do if SB(B,16+n+i)~=(fk0+fk1*i+{padding})%256 then E()end end;B=SS(B,17,16+n);",
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
        padding = params.padding_salt,
    )
}
