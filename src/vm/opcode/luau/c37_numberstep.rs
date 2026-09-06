/// NumberStep: fixed OBF v2 register instruction (opcode 37).
pub(super) fn code() -> &'static str {
    r#"R[a]=R[a]+R[a+2];"#
}
