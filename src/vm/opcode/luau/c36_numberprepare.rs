/// NumberPrepare: fixed OBF v2 register instruction (opcode 36).
pub(super) fn code() -> &'static str {
    r#"local v,n,s=TN(R[a]),TN(R[a+1]),TN(R[a+2]);if v==nil or n==nil or s==nil then E()end;R[a]=v;R[a+1]=n;R[a+2]=s;"#
}
