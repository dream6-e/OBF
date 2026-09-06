/// Not: fixed OBF v2 register instruction (opcode 33).
pub(super) fn code() -> &'static str {
    r#"R[a]=not R[b];"#
}
