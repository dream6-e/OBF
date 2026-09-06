/// Closure: fixed OBF v2 register instruction (opcode 20).
pub(super) fn code() -> &'static str {
    r#"local child=P[k];local up={};for j=0,child.nu-1 do local d=child.u[j];if d[1]~=1 then up[j]=R[d[2]]else up[j]=ups[d[2]]end end;R[a]=Make(k,up);"#
}
