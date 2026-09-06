/// WriteGlobal: fixed OBF v2 register instruction (opcode 9).
pub(super) fn code() -> &'static str {
    r#"G[F.__obf_proto_k[k]]=R[a];"#
}
