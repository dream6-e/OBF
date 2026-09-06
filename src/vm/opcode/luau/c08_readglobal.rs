/// ReadGlobal: fixed OBF v2 register instruction (opcode 8).
pub(super) fn code() -> &'static str {
    r#"R[a]=G[F.k[k]];"#
}
