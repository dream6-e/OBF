/// NumberTest: fixed OBF v2 register instruction (opcode 38).
pub(super) fn code() -> &'static str {
    r#"local v,n,s=R[b],R[b+1],R[b+2];if s>0 then R[a]=v<=n else R[a]=v>=n end;"#
}
