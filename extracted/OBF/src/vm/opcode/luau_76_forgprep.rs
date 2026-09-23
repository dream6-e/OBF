/// Fixed interpreter template for this native opcode.
pub(super) fn code() -> &'static str {
    "local v=rv(i[2]);if type(v)~='function'then local mt=getmetatable(v);local it=mt and mt.__iter;if it then local z=Z(it(v));sv(i[2],z[1]);sv(i[2]+1,z[2]);sv(i[2]+2,z[3])elseif type(v)=='table'then sv(i[2],next);sv(i[2]+1,v);sv(i[2]+2,nil)else E()end end;pc=pc+i[5];"
}
