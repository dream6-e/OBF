/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local x=tonumber(rv(i[2]));local l=tonumber(rv(i[2]+1));local s=tonumber(rv(i[2]+2));if not x or not l or not s then E()end;sv(i[2],x-s);sv(i[2]+1,l);sv(i[2]+2,s);pc=pc+i[6];"
}
