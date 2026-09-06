/// WriteCell: fixed OBF v2 register instruction (opcode 5).
pub(super) fn code() -> &'static str {
    r#"SV(R[a],R[b]);"#
}
