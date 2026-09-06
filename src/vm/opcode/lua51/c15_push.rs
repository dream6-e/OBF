/// Push: fixed OBF v2 register instruction (opcode 15).
pub(super) fn code() -> &'static str {
    r#"local v=R[a];v.n=v.n+1;v[v.n]=R[b];"#
}
