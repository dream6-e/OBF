/// ReadUpvalue: fixed OBF v2 register instruction (opcode 6).
pub(super) fn code() -> &'static str {
    r#"R[a]=CV(ups[b]);"#
}
