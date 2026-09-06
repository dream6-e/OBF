/// IteratorNext: fixed OBF v2 register instruction (opcode 40).
pub(super) fn code() -> &'static str {
    r#"local it=R[b];local v=Call(it[1],{n=2,it[2],it[3]});it[3]=v[1];R[a]=v;"#
}
