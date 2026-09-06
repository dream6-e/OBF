/// Extend: fixed OBF v2 register instruction (opcode 16).
pub(super) fn code() -> &'static str {
    r#"local v,x=R[a],R[b];local n=v.n;for j=1,x.n do v[n+j]=x[j]end;v.n=n+x.n;"#
}
