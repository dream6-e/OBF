/// ReadCell: fixed OBF v2 register instruction (opcode 4).
pub(super) fn code() -> &'static str {
    r#"R[a]=CV(R[b]);"#
}
