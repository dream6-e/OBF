/// Call: fixed OBF v2 register instruction (opcode 19).
pub(super) fn code() -> &'static str {
    r#"R[a]=Call(R[b],R[c]);"#
}
