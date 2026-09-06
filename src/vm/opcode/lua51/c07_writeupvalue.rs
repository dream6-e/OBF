/// WriteUpvalue: fixed OBF v2 register instruction (opcode 7).
pub(super) fn code() -> &'static str {
    r#"SV(ups[b],R[a]);"#
}
