/// Negate: fixed OBF v2 register instruction (opcode 34).
pub(super) fn code() -> &'static str {
    r#"R[a]=-R[b];"#
}
