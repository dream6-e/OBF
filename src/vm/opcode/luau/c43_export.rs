/// Export: fixed OBF v2 register instruction (opcode 43).
pub(super) fn code() -> &'static str {
    r#"local cell=R[a];R[b][R[c]]=cell[1];cell[1]=nil;cell[2]=R[b];cell[3]=R[c];"#
}
