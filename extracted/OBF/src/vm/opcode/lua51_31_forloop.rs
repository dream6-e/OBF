/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=rv(i[2])+rv(i[2]+2);local l=rv(i[2]+1);sv(i[2],x);if (rv(i[2]+2)>0 and x<=l)or(rv(i[2]+2)<=0 and x>=l)then sv(i[2]+3,x);pc=pc+i[6]end;"
}
