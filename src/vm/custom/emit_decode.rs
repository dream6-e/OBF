//! Emitted-text builders for the decoder/transport stage of the generated VM.
//!
//! These are pure Lua-text helpers split out of `emit.rs` by stage: the capture
//! pool reader (ISA14), the goal-5 per-use constant synthesizer walker, the K9a
//! base86 digit-take/emit forms, the LZW/bit-reader decoder sections and the
//! strict frame-v2 inverse. They draw from the same seeded rng objects they
//! received before the split; the orchestration, ordering and all validators
//! stay in `emit.rs`.

use super::*;

/// The capture pool reader (ISA14). The loop runs exactly its validated total
/// (`TU`, accumulated from header metadata) and decodes three anonymous u16
/// slots per record under the per-record pool factorial profile. Every record is
/// range-checked (owner, slot) and duplicate-checked, then stored into `CU` for
/// the per-prototype slicers. Pool order is the fixed global order the encoder
/// wrote.
///
/// Goal 5 removed the sibling *constant* reader that used to follow it: there is
/// no constant pool and no `(owner, index, tag, extent, key)` coordinate record
/// to read back any more. Each prototype's constants now ride inside its own
/// code region and are synthesized per use by [`constant_walker_lua`], so the
/// wire carries exactly one pool.
pub(crate) fn capture_pool_lua(
    field_order: FieldLayout,
    pool_add: u16,
    pool_multiplier: u16,
) -> String {
    format!(
        "CU={{}};for slot=1,TU do {pool_decode}local owner=(st[sont[1]]-slot*{pm}-{pa})%65536;if owner>=np then E()end;local sl=(st[sont[2]]-owner*{pm}-slot-{pa})%65536;local OW=P[owner];if sl>=OW.__obf_proto_nu then E()end;local pay=(st[sont[3]]-sl*{pm}-owner-{pa})%65536;local tg=pay%4;local ix=(pay-tg)/4;if tg>2 or ix>255 then E()end;local T=CU[owner];if T==nil then T={{}};CU[owner]=T end;if T[sl]~=nil then E()end;T[sl]={{tg,ix}} end;",
        pool_decode = field_order.pool_decode_lua(),
        pm = pool_multiplier,
        pa = pool_add,
    )
}

/// Goal 5: the per-use constant synthesizer (`KGC`) as emitted text.
///
/// A prototype's constants live in the tail of its own code region: `n` entries
/// `[tag][payload]` in constant-index order, then a clear u32 block length. This
/// walker is the only code that can turn those bytes into a value, and it keeps
/// none: it steps entry by entry (in seed mode it walks all of them and fills
/// the offset/tag tables `DC` validates against), and it decrypts exactly the
/// entry the caller asked for using the key chain (`pool_key_fold` /
/// `pool_key_byte`) recomputed from the entry lengths it passed over. So a
/// constant can be re-derived per use and never has to exist as a table.
///
/// Shape, per the batch's structural rule: the walk is one flattened state
/// machine (seeded opaque state ids, shuffled branch order) and the two
/// value-keyed decisions inside it -- the entry extent by tag, and the value
/// form by conversion code -- are each a value-partitioning binary search tree,
/// not the linear `if tg==0 elseif tg==1 ...` chain the removed pool reader was.
/// Symbols: `Q` region, `n` constant count, `m` wanted index, `KS`/`KT` the seed
/// mode output tables, `bk` the running key, `z` the block start. Every position
/// the walk carries (`at`, `p`, `off`, `z`) is a 0-based region index -- that is
/// what the stride arithmetic `off=off+p-at+ln` needs -- so the keyed-value
/// helpers, which are 1-based like `SB`/`U32`, are called with `p+1`.
/// One arm of the synthesizer's value-keyed decision trees: `grouped_tree`
/// renders a leaf as `if <arm>`, so every arm carries its own equality test in
/// the shared opaque dispatcher spelling. Keeping the comparator in one place
/// means both trees compare their key exactly the way the ISA dispatch does.
fn decode_arm(
    structure: &mut crate::random::Prng,
    luau: bool,
    variable: &str,
    key: u8,
    body: &str,
) -> (u8, String) {
    (
        key,
        format!(
            "{} then {body}",
            structure.dispatch_condition_for(variable, u16::from(key), luau)
        ),
    )
}

pub(crate) fn constant_walker_lua(
    structure: &mut crate::random::Prng,
    target: Target,
    pool_mask: u64,
    pool_mod: u64,
) -> String {
    let luau = target.is_luau();
    let states = super::structure::state_values(structure, 5);
    let (s_loop, s_extent, s_advance, s_convert, s_commit) =
        (states[0], states[1], states[2], states[3], states[4]);
    // Entry extent by tag: `p` becomes the first keyed byte, `ln` the keyed
    // length and `code` the value form. Tag 4 (64-bit integer) exists only on
    // Luau; on Lua 5.1 the arm rejects it exactly like the old pool reader did.
    let int_arm = if luau {
        "p=at+1;ln=8;code=4;".to_owned()
    } else {
        "E();".to_owned()
    };
    let string_arm =
        "ln=U32(Q,at+2);if ln<0 or off+ln+5>blen then E()end;p=at+5;code=3;".to_owned();
    let extent_arms = vec![
        decode_arm(structure, luau, "tg", 0, "p=at+1;ln=0;code=0;"),
        decode_arm(structure, luau, "tg", 1, "p=at+1;ln=1;code=1;"),
        decode_arm(structure, luau, "tg", 2, "p=at+1;ln=8;code=2;"),
        decode_arm(structure, luau, "tg", 3, &string_arm),
        decode_arm(structure, luau, "tg", 4, &int_arm),
        decode_arm(structure, luau, "tg", 5, &string_arm),
    ];
    let extent_groups = (2 + structure.index(2)) as u8;
    let extent =
        super::structure::grouped_tree(structure, extent_arms, extent_groups, "tg", luau, false);
    // Value form by conversion code. Goal 6: a leaf no longer returns
    // straight out -- it assigns the synthesized value to `v` and hands control
    // to the commit state, which folds the entry into the *rolling cursor* and
    // only then returns. That is what makes the decryption lazy: nothing is
    // decrypted until a use asks for it, the walk resumes where the previous
    // use stopped, and the only thing that survives a call is the cursor
    // (offset, running key, entry index) -- never a value.
    let go_commit = super::structure::state_assign(structure, "w", s_commit, luau);
    let go_extent = super::structure::state_assign(structure, "w", s_extent, luau);
    let go_advance = super::structure::state_assign(structure, "w", s_advance, luau);
    let go_loop = super::structure::state_assign(structure, "w", s_loop, luau);
    let go_convert = super::structure::state_assign(structure, "w", s_convert, luau);
    // Goal 6 (part 3): the walker's own state labels are opaque too, so the
    // laziness machinery cannot be read off as a state table. The commit is the
    // transition every conversion arm shares.
    let commit_go = |body: String| format!("{body}{go_commit}");
    let int_form = if luau {
        "local s4=UK(Q,p+1,8,bk);local iv=IF(SF('%08x%08x',U32(s4,5),U32(s4,1)),16);if iv==nil then E()end;v=iv;"
            .to_owned()
    } else {
        "E();".to_owned()
    };
    let convert_arms = vec![
        decode_arm(structure, luau, "code", 0, &commit_go("v=nil;".to_owned())),
        decode_arm(
            structure,
            luau,
            "code",
            1,
            &commit_go(
                "local b0=SB(UK(Q,p+1,1,bk),1);if b0~=0 and b0~=1 then E()end;v=b0==1;".to_owned(),
            ),
        ),
        decode_arm(
            structure,
            luau,
            "code",
            2,
            &commit_go("local nb=NU(UK(Q,p+1,8,bk),1);v=nb;".to_owned()),
        ),
        decode_arm(
            structure,
            luau,
            "code",
            3,
            &commit_go("local ns=UK(Q,p+1,ln,bk);v=ns;".to_owned()),
        ),
        decode_arm(structure, luau, "code", 4, &commit_go(int_form)),
    ];
    let convert_groups = (2 + structure.index(2)) as u8;
    let convert = super::structure::grouped_tree(
        structure,
        convert_arms,
        convert_groups,
        "code",
        luau,
        false,
    );
    let loop_body = format!(
        "if off>=blen then if seed then return off,ix else E()end end;at=z+off;tg=SB(Q,at+1);if tg==nil then E()end;{go_extent}"
    );
    let extent_body = format!("{extent}{go_advance}");
    // One entry consumed: the entry-level chain folds its keyed length (what
    // the seed-mode walk and the encoder both advance) and the normal path
    // either keeps skipping towards the wanted index or converts it.
    let advance_body = format!(
        "off=off+p-at+ln;local nb=(bk+ln*257+{mask})%{mod};if seed then KS[ix]=at;KT[ix]=tg;ix=ix+1;bk=nb;{go_loop} elseif ix<m then ix=ix+1;bk=nb;{go_loop} else {go_convert} end;",
        mask = pool_mask,
        mod = pool_mod,
    );
    // The commit: fold this entry into the cursor, publish it back to the
    // caller's slot (nil for a stateless caller such as the seed harness or
    // `DC`), and return the one value that was asked for. No table, no cache.
    let commit_body = format!(
        "off=off+p-at+ln;bk=(bk+ln*257+{mask})%{mod};if ST~=nil then ST[1],ST[2],ST[3]=off,bk,ix+1 end;return v;",
        mask = pool_mask,
        mod = pool_mod,
    );
    let convert_body = convert.clone();
    let machine = super::structure::state_machine(
        structure,
        "w",
        vec![
            (s_loop, loop_body),
            (s_extent, extent_body),
            (s_advance, advance_body),
            (s_convert, convert_body),
            (s_commit, commit_body),
        ],
        luau,
    );
    // `off` is already bound (to 0) in the walker's own head, so it can carry
    // the guard of the initial-state reconstruction.
    let w_start = structure.opaque_literal(u64::from(s_loop), luau, "off");
    format!(
        "KGC=function(Q,n,m,KS,KT,ST)\nlocal kend=#Q-4;if kend<0 then E()end;local blen=U32(Q,kend+1);if blen<0 or blen>kend then E()end;\nlocal z,off,bk,at,tg,ln,p,code,ix,v=kend-blen,0,0,0,0,0,0,0,0,nil;local seed=KS~=nil;\nif seed then if n%1~=0 or n<0 or n>65536 then E()end else if m%1~=0 or m<0 or m>=n then E()end end;\nif not seed then if ST==nil then off,bk,ix=0,0,0 else off,bk,ix=ST[1],ST[2],ST[3];if ST[4]~=Q then off,bk,ix=0,0,0;ST[4]=Q end;if ix>m then off,bk,ix=0,0,0 end end end;\nlocal w={w_start};{machine}end;\n"
    )
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
