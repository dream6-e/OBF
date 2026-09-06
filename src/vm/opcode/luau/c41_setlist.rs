/// SetList: fixed OBF v2 register instruction (opcode 41).
pub(super) fn code() -> &'static str {
    r#"local v=R[b];local start=R[c];for j=1,v.n do R[a][start+j-1]=v[j]end;"#
}
