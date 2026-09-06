/// TailCall: fixed OBF v2 register instruction (opcode 47).
pub(super) fn code() -> &'static str {
    r#"local fn,ar=R[a],R[b];local d=W[fn];if d then fid=d[1];args=ar;ups=d[2];break else return Z(fn(U(ar,1,ar.n)))end;"#
}
