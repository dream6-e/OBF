/// IteratorPrepare: fixed OBF v2 register instruction (opcode 39).
pub(super) fn code() -> &'static str {
    r#"local ar=R[a];local v=ar[1];if TY(v)~='function'then local mt=MT(v);if mt~=nil and TY(mt)~='table'then E()end;local it=mt and RG(mt,'__iter');if it~=nil then ar=Z(it(v));if ar[1]==nil then E()end elseif mt and RG(mt,'__call')~=nil then elseif TY(v)=='table'then ar={n=3,NX,v}else E()end end;ar.n=3;R[a]=ar;"#
}
