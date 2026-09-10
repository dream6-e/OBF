use super::*;

pub(crate) const CHACHA8_OUTER_DOMAIN: u32 = 1;
pub(crate) const CHACHA8_INNER_DOMAIN: u32 = 2;
const WORD_MODULUS: u64 = 4_294_967_296;
const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
const SELF_TEST_WORDS: [(usize, u32); 3] = [(0, 0x2fef_003e), (7, 0x1e1a_71ef), (15, 0x42fe_0c0e)];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChaChaParams {
    pub(crate) key_salts: [u32; 8],
    pub(crate) nonce_salts: [[u32; 3]; 2],
    pub(crate) counters: [u32; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChaChaMaterial {
    pub(crate) key: [u32; 8],
    pub(crate) nonce: [u32; 3],
    pub(crate) counter: u32,
}

pub(crate) fn chacha_params(seed: u64) -> ChaChaParams {
    let mut random = crate::random::Prng::new(seed ^ 0x6368_6163_6861_385f);
    let mut next = || {
        random.next_u64().to_le_bytes()[..4]
            .try_into()
            .map(u32::from_le_bytes)
            .unwrap()
    };
    let mut key_salts = [0u32; 8];
    for salt in &mut key_salts {
        *salt = next();
    }
    let mut nonce_salts = [[0u32; 3]; 2];
    for domain in &mut nonce_salts {
        for salt in domain {
            *salt = next();
        }
    }
    let counters = [next(), next()];
    ChaChaParams {
        key_salts,
        nonce_salts,
        counters,
    }
}

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Standard IETF-layout ChaCha8 block: four column/diagonal double rounds,
/// 256-bit key, 32-bit counter and 96-bit nonce.
pub(crate) fn chacha8_block(key: [u32; 8], counter: u32, nonce: [u32; 3]) -> [u32; 16] {
    let initial = [
        CHACHA_CONSTANTS[0],
        CHACHA_CONSTANTS[1],
        CHACHA_CONSTANTS[2],
        CHACHA_CONSTANTS[3],
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        counter,
        nonce[0],
        nonce[1],
        nonce[2],
    ];
    let mut state = initial;
    for _ in 0..4 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    for (word, initial) in state.iter_mut().zip(initial) {
        *word = word.wrapping_add(initial);
    }
    state
}

fn fold_attestation(mut state: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        state = state.wrapping_mul(257).wrapping_add(u32::from(byte));
    }
    state
}

/// Canonical result of the runtime anti-hook gate. The generated gate folds
/// two independently queried native source transcripts, verifies critical
/// primitive behavior and checks three words of the published zero-key
/// ChaCha8 block before returning this value to the key schedule.
pub(crate) fn runtime_attestation(target: Target) -> u32 {
    let source: &[u8] = if target.is_luau() { b"[C]" } else { b"=[C]" };
    let mut state = fold_attestation(0, source);
    state = fold_attestation(state, source);
    SELF_TEST_WORDS
        .iter()
        .fold(state.wrapping_add(255), |sum, &(_, word)| {
            sum.wrapping_add(word)
        })
}

fn sum32(values: &[u64]) -> u32 {
    (values.iter().copied().sum::<u64>() % WORD_MODULUS) as u32
}

/// Runtime-only ChaCha material. The delivered script contains salts and the
/// derivation, but not these final key/nonce/counter words. The anti-hook
/// attestation and three source-witness-bound shares are mandatory inputs;
/// outer and inner streams use disjoint domains and contexts.
pub(crate) fn chacha_material(
    shares: &[u64; 3],
    permutation: u64,
    context: u32,
    domain: u32,
    attestation: u32,
    params: &ChaChaParams,
) -> ChaChaMaterial {
    let domain_index = match domain {
        CHACHA8_OUTER_DOMAIN => 0,
        CHACHA8_INNER_DOMAIN => 1,
        _ => panic!("invalid internal ChaCha8 domain"),
    };
    let [s1, s2, s3] = *shares;
    let pv = permutation;
    let ctx = u64::from(context);
    let guard = u64::from(attestation);
    let d = u64::from(domain);
    let salt = params.key_salts.map(u64::from);
    let base_key = [
        sum32(&[s1, salt[0], guard]),
        sum32(&[s2, salt[1], ctx]),
        sum32(&[s3, salt[2], guard]),
        sum32(&[pv, salt[3], ctx]),
        sum32(&[s1, s2, salt[4], d]),
        sum32(&[s2, s3, salt[5], ctx * d]),
        sum32(&[s3, s1, salt[6], guard, ctx]),
        sum32(&[s1, s2, s3, pv, salt[7], guard, d]),
    ];
    let nonce_salt = params.nonce_salts[domain_index].map(u64::from);
    let base_nonce = [
        sum32(&[ctx, nonce_salt[0]]),
        sum32(&[guard, nonce_salt[1]]),
        sum32(&[s1, s3, pv, nonce_salt[2]]),
    ];
    let base_counter = params.counters[domain_index];
    let expanded = chacha8_block(base_key, base_counter, base_nonce);
    let mut key = [0u32; 8];
    key.copy_from_slice(&expanded[..8]);
    ChaChaMaterial {
        key,
        nonce: [expanded[8], expanded[9], expanded[10]],
        counter: expanded[11].wrapping_add(base_counter).wrapping_add(domain),
    }
}

pub(crate) fn chacha8_xor(
    bytes: &[u8],
    shares: &[u64; 3],
    permutation: u64,
    context: u32,
    domain: u32,
    target: Target,
    params: &ChaChaParams,
) -> Vec<u8> {
    chacha8_xor_with_attestation(
        bytes,
        shares,
        permutation,
        context,
        domain,
        runtime_attestation(target),
        params,
    )
}

pub(crate) fn chacha8_xor_with_attestation(
    bytes: &[u8],
    shares: &[u64; 3],
    permutation: u64,
    context: u32,
    domain: u32,
    attestation: u32,
    params: &ChaChaParams,
) -> Vec<u8> {
    let material = chacha_material(shares, permutation, context, domain, attestation, params);
    let mut out = Vec::with_capacity(bytes.len());
    for (block_index, chunk) in bytes.chunks(64).enumerate() {
        let words = chacha8_block(
            material.key,
            material.counter.wrapping_add(block_index as u32),
            material.nonce,
        );
        let mut stream = [0u8; 64];
        for (word, output) in words.iter().zip(stream.chunks_exact_mut(4)) {
            output.copy_from_slice(&word.to_le_bytes());
        }
        out.extend(chunk.iter().zip(stream).map(|(&byte, key)| byte ^ key));
    }
    out
}

/// Ciphertext-feedback variants used by the payload path. The existing
/// `chacha8_xor` remains a stateless test/vector primitive; these variants make
/// each byte depend on the preceding ciphertext byte and therefore cannot be
/// decoded out of order.
pub(crate) fn chacha8_feedback_encrypt(
    bytes: &[u8],
    shares: &[u64; 3],
    permutation: u64,
    context: u32,
    domain: u32,
    target: Target,
    params: &ChaChaParams,
) -> Vec<u8> {
    chacha8_feedback(
        bytes,
        shares,
        permutation,
        context,
        domain,
        target,
        params,
        true,
    )
}

pub(crate) fn chacha8_feedback_decrypt(
    bytes: &[u8],
    shares: &[u64; 3],
    permutation: u64,
    context: u32,
    domain: u32,
    target: Target,
    params: &ChaChaParams,
) -> Vec<u8> {
    chacha8_feedback(
        bytes,
        shares,
        permutation,
        context,
        domain,
        target,
        params,
        false,
    )
}

fn chacha8_feedback(
    bytes: &[u8],
    shares: &[u64; 3],
    permutation: u64,
    context: u32,
    domain: u32,
    target: Target,
    params: &ChaChaParams,
    encrypt: bool,
) -> Vec<u8> {
    let material = chacha_material(
        shares,
        permutation,
        context,
        domain,
        runtime_attestation(target),
        params,
    );
    let mut out = Vec::with_capacity(bytes.len());
    let mut previous = 0u8;
    for (block_index, chunk) in bytes.chunks(64).enumerate() {
        let words = chacha8_block(
            material.key,
            material.counter.wrapping_add(block_index as u32),
            material.nonce,
        );
        let mut stream = [0u8; 64];
        for (word, output) in words.iter().zip(stream.chunks_exact_mut(4)) {
            output.copy_from_slice(&word.to_le_bytes());
        }
        for (offset, &byte) in chunk.iter().enumerate() {
            let value = byte ^ stream[offset] ^ previous;
            out.push(value);
            previous = if encrypt { value } else { byte };
        }
    }
    out
}

pub(crate) const CHACHA_WORD_FIELD: usize = 24;
pub(crate) const CHACHA_QUARTER_FIELD: usize = 25;
pub(crate) const CHACHA_BLOCK_FIELD: usize = 26;
pub(crate) const CHACHA_STREAM_FIELD: usize = 27;
pub(crate) const ANTI_HOOK_FIELD: usize = 28;

/// Five independently shuffled payload functions: 32-bit word operations,
/// quarter round, ChaCha8 block, runtime KDF/stream application and anti-hook
/// attestation. Entry wiring combines them only through local references.
/// K7: the word section renders the per-target polymorphic toolbox (dual xor
/// plus dual rotate closures); every u32 modulus below draws its spelling
/// per site and every modular sum shuffles its terms.
pub(crate) fn chacha_decoder_sections(
    params: &ChaChaParams,
    target: Target,
    keys: &[u64],
    bitops: &mut crate::random::Prng,
) -> (Vec<String>, String) {
    assert!(keys.len() > ANTI_HOOK_FIELD);
    let word = render_word_section(target, keys[CHACHA_WORD_FIELD], bitops);
    let xor_pick = |draw: &mut crate::random::Prng| ["Xa", "Xb"][draw.index(2)];
    let rot_pick = |draw: &mut crate::random::Prng| ["Ra", "Rb"][draw.index(2)];
    let add = |draw: &mut crate::random::Prng, terms: &[&str]| render_modsum(draw, terms);
    // Term shapes mirror the canonical quarter round exactly; only the
    // closure pair draws, term orders and modulus spellings vary.
    let quarter_body = [
        format!("s[a]={}", add(bitops, &["s[a]", "s[b]"])),
        format!(
            "s[d]={}({}(s[d],s[a]),16)",
            rot_pick(bitops),
            xor_pick(bitops)
        ),
        format!("s[c]={}", add(bitops, &["s[c]", "s[d]"])),
        format!(
            "s[b]={}({}(s[b],s[c]),12)",
            rot_pick(bitops),
            xor_pick(bitops)
        ),
        format!("s[a]={}", add(bitops, &["s[a]", "s[b]"])),
        format!(
            "s[d]={}({}(s[d],s[a]),8)",
            rot_pick(bitops),
            xor_pick(bitops)
        ),
        format!("s[c]={}", add(bitops, &["s[c]", "s[d]"])),
        format!(
            "s[b]={}({}(s[b],s[c]),7)",
            rot_pick(bitops),
            xor_pick(bitops)
        ),
    ];
    let quarter = format!(
        "[{}]=function(Xa,Xb,Ra,Rb)return function(s,a,b,c,d){}end end,",
        keys[CHACHA_QUARTER_FIELD],
        quarter_body.join(";"),
    );
    let block_add = add(bitops, &["x[i]", "s[i]"]);
    let block = format!(
        "[{}]=function(Q)return function(K,C,N)local s={{1634760805,857760878,2036477234,1797285236,K[1],K[2],K[3],K[4],K[5],K[6],K[7],K[8],C,N[1],N[2],N[3]}};local x={{}};for i=1,16 do x[i]=s[i]end;for i=1,4 do Q(x,1,5,9,13);Q(x,2,6,10,14);Q(x,3,7,11,15);Q(x,4,8,12,16);Q(x,1,6,11,16);Q(x,2,7,12,13);Q(x,3,8,9,14);Q(x,4,5,10,15)end;for i=1,16 do x[i]={block_add} end;return x end end,",
        keys[CHACHA_BLOCK_FIELD]
    );
    let salts = params
        .key_salts
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let n0 = params.nonce_salts[0];
    let n1 = params.nonce_salts[1];
    // KDF term sets, byte-identical to the pre-K7 schedule; only the order
    // and modulus spelling draw per site.
    let salt_terms: [&[&str]; 8] = [
        &["s1", "S[1]", "aw"],
        &["s2", "S[2]", "ctx"],
        &["s3", "S[3]", "aw"],
        &["pv", "S[4]", "ctx"],
        &["s1", "s2", "S[5]", "d"],
        &["s2", "s3", "S[6]", "ctx*d"],
        &["s3", "s1", "S[7]", "aw", "ctx"],
        &["s1", "s2", "s3", "pv", "S[8]", "aw", "d"],
    ];
    let key_sums: Vec<String> = salt_terms.iter().map(|terms| add(bitops, terms)).collect();
    let bound = render_u32_atom(bitops);
    let q_sum = add(bitops, &["Z[12]", "q", "d"]);
    let counter_sum = add(bitops, &["q", "(p-1)/64"]);
    // Nonce term sets per domain (salts owned so the shuffle sees &str).
    let nonce_sets: [Vec<String>; 6] = [
        vec!["ctx".to_owned(), n0[0].to_string()],
        vec!["aw".to_owned(), n0[1].to_string()],
        vec![
            "s1".to_owned(),
            "s3".to_owned(),
            "pv".to_owned(),
            n0[2].to_string(),
        ],
        vec!["ctx".to_owned(), n1[0].to_string()],
        vec!["aw".to_owned(), n1[1].to_string()],
        vec![
            "s1".to_owned(),
            "s3".to_owned(),
            "pv".to_owned(),
            n1[2].to_string(),
        ],
    ];
    let mut nonce_sums = Vec::new();
    for terms in &nonce_sets {
        let refs: Vec<&str> = terms.iter().map(String::as_str).collect();
        nonce_sums.push(render_modsum(bitops, &refs));
    }
    let stream = format!(
        "[{}]=function(B,s1,s2,s3,pv,ctx,d,aw,CB,E,SB,NCH,TC,MF,X8)if d~=1 and d~=2 or ctx<0 or ctx>={bound} then E()end;local S={{{salts}}};local K={{{keys}}};local q=d==1 and {c0} or {c1};local N=d==1 and {{{n00},{n01},{n02}}}or{{{n10},{n11},{n12}}};local Z=CB(K,q,N);K={{Z[1],Z[2],Z[3],Z[4],Z[5],Z[6],Z[7],Z[8]}};N={{Z[9],Z[10],Z[11]}};q={q_sum};local O={{}};local prev=0;for p=1,#B,64 do local W=CB(K,{counter_sum},N);local n=#B-p;if n>63 then n=63 end;for i=0,n do local y=MF(W[MF(i/4)+1]/2^(8*(i%4)))%256;local ct=SB(B,p+i);O[p+i]=NCH(X8(X8(ct,y),prev));prev=ct end end;return TC(O)end,",
        keys[CHACHA_STREAM_FIELD],
        keys = key_sums.join(","),
        c0 = params.counters[0],
        c1 = params.counters[1],
        n00 = nonce_sums[0],
        n01 = nonce_sums[1],
        n02 = nonce_sums[2],
        n10 = nonce_sums[3],
        n11 = nonce_sums[4],
        n12 = nonce_sums[5],
    );
    let metadata = if target.is_luau() {
        "local A=DB and GI(LS,\"s\");local B=DB and GI(SB,\"s\");local C=DB and GI(AH,\"s\");local D=DB and GI(CC,\"s\");local F=DB and GI(CB,\"s\");local H=DB and GI(X8C,\"s\");if A~=\"[C]\" or B~=\"[C]\" or C~=D or C~=F or C~=H or C==\"[C]\" then E()end;"
            .to_owned()
    } else {
        "local A=DB and GI(LS,\"S\");local B=DB and GI(SB,\"S\");local C=DB and GI(AH,\"S\");local D=DB and GI(CC,\"S\");local F=DB and GI(CB,\"S\");local H=DB and GI(X8C,\"S\");if not(A and B and C and D and F and H and A.what==\"C\" and B.what==\"C\" and C.what==\"Lua\" and D.what==\"Lua\" and F.what==\"Lua\" and H.what==\"Lua\" and A.source==\"=[C]\" and B.source==\"=[C]\" and C.source==D.source and C.source==F.source and C.source==H.source)then E()end;A=A.source;B=B.source;"
            .to_owned()
    };
    let fold_a = add(bitops, &["w*257", "SB(A,i)"]);
    let fold_b = add(bitops, &["w*257", "SB(B,i)"]);
    let kat_expr = |value: u32| {
        let bytes = value.to_be_bytes();
        format!(
            "(({}*256+{})*256+{})*256+{}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    };
    let kat1 = kat_expr(804192318);
    let kat8 = kat_expr(505049583);
    let kat16 = kat_expr(1123945486);
    let att_terms = ["w", kat1.as_str(), kat8.as_str(), kat16.as_str(), "255"];
    let att = add(bitops, &att_terms);
    let anti = format!(
        "[{}]=function(AH,CC,CB,X8C,E,SB,NCH,TC,MF,DB,GI,LS){metadata}if SB(\"AZ\",1)~=65 or SB(\"AZ\",2)~=90 or NCH(65)~=\"A\" or TC({{\"A\",\"B\"}})~=\"AB\" or MF(15/4)~=3 or X8C(90,165)~=255 then E()end;local Z=CB({{0,0,0,0,0,0,0,0}},0,{{0,0,0}});if Z[1]~={kat1} or Z[8]~={kat8} or Z[16]~={kat16} then E()end;local w=0;for i=1,#A do w={fold_a} end;for i=1,#B do w={fold_b} end;return {att} end,",
        keys[ANTI_HOOK_FIELD]
    );
    let word_args = if target.is_luau() {
        "MF,X8,X8C,BX,BA,BO,BN,LR,SHL,RS,BNE,BW8,BR8,BFS,BR3"
    } else {
        "MF,X8,X8C"
    };
    let wiring = format!(
        "local CXa,CXb,CRa,CRb=VMS[{}]({word_args});local CQ=VMS[{}](CXa,CXb,CRa,CRb);local CB=VMS[{}](CQ);local CC=VMS[{}];local AH=VMS[{}];",
        keys[CHACHA_WORD_FIELD],
        keys[CHACHA_QUARTER_FIELD],
        keys[CHACHA_BLOCK_FIELD],
        keys[CHACHA_STREAM_FIELD],
        keys[ANTI_HOOK_FIELD],
    );
    (vec![word, quarter, block, stream, anti], wiring)
}
