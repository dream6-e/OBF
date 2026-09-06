/// Test: fixed OBF v2 register instruction (opcode 45).
pub(super) fn code() -> &'static str {
    r#"if not R[a]then pc=pc+4 end;"#
}
