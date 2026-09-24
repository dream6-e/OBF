use super::{OpcodeBuilder, OpcodeConfig, OpcodesRng};

pub fn generate(m: &[Vec<u32>], cfg: &OpcodeConfig, rng: &mut OpcodesRng) -> String {
    let mut out = String::new();

    let mut getupval = OpcodeBuilder::new(m[4].clone(), cfg, rng);
    let gu_b = getupval.raw_inst(3);
    let gu_a = getupval.raw_inst(2);
    out.push_str(&getupval.build(&format!("{{STK}}[{}] = {{UPVALS}}[{}+1][1][{{UPVALS}}[{}+1][2]]", gu_a, gu_b, gu_b)));

    let mut getglobal = OpcodeBuilder::new(m[5].clone(), cfg, rng);
    let gg_b = getglobal.raw_inst(3);
    let gg_a = getglobal.raw_inst(2);
    out.push_str(&getglobal.build(&format!(
        "local k = {{CONSTS}}[{}+1]; local v = {{ENV}}[k]; if v == nil and getgenv then v = getgenv()[k] end; {{STK}}[{}] = v", 
        gg_b, gg_a
    )));

    let mut gettable = OpcodeBuilder::new(m[6].clone(), cfg, rng);
    let gt_b = gettable.reg(3);
    let gt_c = gettable.rk(4);
    let gt_a = gettable.raw_inst(2);
    out.push_str(&gettable.build(&format!("{{STK}}[{}] = {}[{}]", gt_a, gt_b, gt_c)));

    let mut setglobal = OpcodeBuilder::new(m[7].clone(), cfg, rng);
    let sg_b = setglobal.raw_inst(3);
    let sg_a = setglobal.raw_inst(2);
    out.push_str(&setglobal.build(&format!(
        "local k = {{CONSTS}}[{}+1]; {{ENV}}[k] = {{STK}}[{}]; if getgenv then getgenv()[k] = {{STK}}[{}] end", 
        sg_b, sg_a, sg_a
    )));

    let mut setupval = OpcodeBuilder::new(m[8].clone(), cfg, rng);
    let su_b = setupval.raw_inst(3);
    let su_a = setupval.raw_inst(2);
    out.push_str(&setupval.build(&format!("{{UPVALS}}[{}+1][1][{{UPVALS}}[{}+1][2]] = {{STK}}[{}]", su_b, su_b, su_a)));

    let mut settable = OpcodeBuilder::new(m[9].clone(), cfg, rng);
    let st_b = settable.rk(3);
    let st_c = settable.rk(4);
    let st_a = settable.raw_inst(2);
    out.push_str(&settable.build(&format!("{{STK}}[{}] [{}] = {}", st_a, st_b, st_c)));

    let mut newtable = OpcodeBuilder::new(m[10].clone(), cfg, rng);
    let nt_a = newtable.raw_inst(2);
    out.push_str(&newtable.build(&format!("{{STK}}[{}] = {{}}", nt_a)));

    let mut self_op = OpcodeBuilder::new(m[11].clone(), cfg, rng);
    let s_b = self_op.raw_inst(3);
    let s_c = self_op.rk(4);
    let s_a = self_op.raw_inst(2);
    out.push_str(&self_op.build(&format!("local b = {{STK}}[{}]; {{STK}}[{}+1] = b; {{STK}}[{}] = b[{}]", s_b, s_a, s_a, s_c)));

    let mut setlist = OpcodeBuilder::new(m[34].clone(), cfg, rng);
    let sl_a = setlist.raw_inst(2);
    let sl_b = setlist.raw_inst(3);
    let sl_c = setlist.raw_inst(4);
    out.push_str(&setlist.build(&format!(
        "local c = {}; if c == 0 then c = {{INSTS}}[{{PC}}][2]; {{PC}} = {{PC}} + 1 end; local b = {}; if b == 0 then b = {{TOP}} - {} end; local offset = (c - 1) * 50; for j = 1, b do {{STK}}[{}][offset + j] = {{STK}}[{} + j] end; for j = {} + 1, {} + b do {{STK}}[j] = nil end",
        sl_c, sl_b, sl_a, sl_a, sl_a, sl_a, sl_a
    )));

    let mut close = OpcodeBuilder::new(m[35].clone(), cfg, rng);
    let cl_a = close.raw_inst(2);
    out.push_str(&close.build(&format!(
        "if {{STK}}.open_ups then for reg, uv_obj in pairs({{STK}}.open_ups) do if reg >= {} then uv_obj[1] = {{uv_obj[1][uv_obj[2]]}}; uv_obj[2] = 1; {{STK}}.open_ups[reg] = nil end end end",
        cl_a
    )));

    let mut closure = OpcodeBuilder::new(m[36].clone(), cfg, rng);
    let cl_a = closure.raw_inst(2);
    let cl_b = closure.raw_inst(3);
    
    let m0_checks: Vec<String> = m[0].iter().map(|op| format!("uv_inst[1] == {}", op)).collect();
    let m88_checks: Vec<String> = m[88].iter().map(|op| format!("uv_inst[1] == {}", op)).collect();
    let mut all_checks = m0_checks;
    all_checks.extend(m88_checks);
    let check_str = all_checks.join(" or ");

    out.push_str(&closure.build(&format!(
        "local p = {{PROTOS}}[{}+1]; local uv = {{}}; {{STK}}.open_ups = {{STK}}.open_ups or {{}}; for j = 1, p.nups do local uv_inst = {{INSTS}}[{{PC}}]; {{PC}} = {{PC}} + 1; if {} then local reg = uv_inst[3]; if not {{STK}}.open_ups[reg] then {{STK}}.open_ups[reg] = {{{{STK}}, reg}} end; uv[j] = {{STK}}.open_ups[reg] else uv[j] = {{UPVALS}}[uv_inst[3]+1] end end; {{STK}}[{}] = function(...) return execute(p, getfenv and getfenv(1) or env, uv, ...) end",
        cl_b, check_str, cl_a
    )));

    let mut vararg = OpcodeBuilder::new(m[37].clone(), cfg, rng);
    let va_a = vararg.raw_inst(2);
    let va_b = vararg.raw_inst(3);
    out.push_str(&vararg.build(&format!(
        "if {} > 0 then for j = 1, {} - 1 do {{STK}}[{}+j-1] = {{VARARGS}}[j] end else local old_top = {{TOP}}; {{TOP}} = {} - 1; for j = 1, {{VARARGS_LEN}} do {{STK}}[{}+j-1] = {{VARARGS}}[j]; {{TOP}} = {{TOP}} + 1 end; for j = {{TOP}} + 1, old_top do {{STK}}[j] = nil end end",
        va_b, va_b, va_a, va_a, va_a
    )));

    let mut getimport = OpcodeBuilder::new(m[49].clone(), cfg, rng);
    let gi_b = getimport.raw_inst(3);
    let gi_a = getimport.raw_inst(2);
    out.push_str(&getimport.build(&format!(
        "local k = {{CONSTS}}[{}+1]; local v = {{ENV}}[k]; if v == nil and getgenv then v = getgenv()[k] end; {{STK}}[{}] = v", 
        gi_b, gi_a
    )));

    let mut namecall = OpcodeBuilder::new(m[50].clone(), cfg, rng);
    let nc_b = namecall.raw_inst(3);
    let nc_c = namecall.raw_inst(4);
    let nc_a = namecall.raw_inst(2);
    out.push_str(&namecall.build(&format!("local b = {{STK}}[{}]; {{STK}}[{}+1] = b; {{STK}}[{}] = b[{{CONSTS}}[{}+1]]", nc_b, nc_a, nc_a, nc_c)));

    let mut gettablestr = OpcodeBuilder::new(m[54].clone(), cfg, rng);
    let gts_b = gettablestr.raw_inst(3);
    let gts_c = gettablestr.raw_inst(4);
    let gts_a = gettablestr.raw_inst(2);
    out.push_str(&gettablestr.build(&format!("{{STK}}[{}] = {{STK}}[{}][{{CONSTS}}[{}+1]]", gts_a, gts_b, gts_c)));

    let mut settablestr = OpcodeBuilder::new(m[55].clone(), cfg, rng);
    let sts_b = settablestr.raw_inst(3);
    let sts_c = settablestr.raw_inst(4);
    let sts_a = settablestr.raw_inst(2);
    out.push_str(&settablestr.build(&format!("{{STK}}[{}] [{{CONSTS}}[{}+1]] = {{STK}}[{}]", sts_a, sts_c, sts_b)));

    let mut getglobalstr = OpcodeBuilder::new(m[56].clone(), cfg, rng);
    let ggs_b = getglobalstr.raw_inst(3);
    let ggs_a = getglobalstr.raw_inst(2);
    out.push_str(&getglobalstr.build(&format!(
        "local k = {{CONSTS}}[{}+1]; local v = {{ENV}}[k]; if v == nil and getgenv then v = getgenv()[k] end; {{STK}}[{}] = v", 
        ggs_b, ggs_a
    )));

    let mut setglobalstr = OpcodeBuilder::new(m[57].clone(), cfg, rng);
    let sgs_b = setglobalstr.raw_inst(3);
    let sgs_a = setglobalstr.raw_inst(2);
    out.push_str(&setglobalstr.build(&format!(
        "local k = {{CONSTS}}[{}+1]; {{ENV}}[k] = {{STK}}[{}]; if getgenv then getgenv()[k] = {{STK}}[{}] end", 
        sgs_b, sgs_a, sgs_a
    )));

    let mut newtablearr = OpcodeBuilder::new(m[77].clone(), cfg, rng);
    let nta_a = newtablearr.raw_inst(2);
    out.push_str(&newtablearr.build(&format!("{{STK}}[{}] = {{}}", nta_a)));

    let mut newtablehash = OpcodeBuilder::new(m[78].clone(), cfg, rng);
    let nth_a = newtablehash.raw_inst(2);
    out.push_str(&newtablehash.build(&format!("{{STK}}[{}] = {{}}", nth_a)));

    let mut gettableconst = OpcodeBuilder::new(m[79].clone(), cfg, rng);
    let gtc_b = gettableconst.raw_inst(3);
    let gtc_c = gettableconst.raw_inst(4);
    let gtc_a = gettableconst.raw_inst(2);
    out.push_str(&gettableconst.build(&format!("{{STK}}[{}] = {{STK}}[{}][{{CONSTS}}[{}+1]]", gtc_a, gtc_b, gtc_c)));

    let mut settableconst = OpcodeBuilder::new(m[80].clone(), cfg, rng);
    let stc_b = settableconst.raw_inst(3);
    let stc_c = settableconst.raw_inst(4);
    let stc_a = settableconst.raw_inst(2);
    out.push_str(&settableconst.build(&format!("{{STK}}[{}] [{{CONSTS}}[{}+1]] = {{STK}}[{}]", stc_a, stc_c, stc_b)));

    out
}