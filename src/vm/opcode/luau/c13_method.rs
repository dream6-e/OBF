/// Method: fixed OBF v2 register instruction (opcode 13).
pub(super) fn code() -> &'static str {
    r#"R[a]=Lookup(R[b],R[c]);"#
}
