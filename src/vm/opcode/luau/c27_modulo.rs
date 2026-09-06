/// Modulo: fixed OBF v2 register instruction (opcode 27).
pub(super) fn code() -> &'static str {
    r#"R[a]=R[b]%R[c];"#
}
