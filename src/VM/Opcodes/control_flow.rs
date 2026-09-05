use super::{OpcodeBuilder, OpcodeConfig, OpcodesRng};

pub fn generate(m: &[Vec<u32>], cfg: &OpcodeConfig, rng: &mut OpcodesRng) -> String {
    let mut out = String::new();

    let mut jmp = OpcodeBuilder::new(m[22].clone(), cfg, rng);
    let jmp_c = jmp.raw_inst(3);
    out.push_str(&jmp.build(&format!("{{PC}} = {{PC}} + {}", jmp_c)));

    let mut eq = OpcodeBuilder::new(m[23].clone(), cfg, rng);
    let eq_b = eq.rk(3); let eq_c = eq.rk(4); let eq_a = eq.raw_inst(2);
    out.push_str(&eq.build(&format!("if ({} == {}) ~= ({} ~= 0) then {{PC}} = {{PC}} + 1 end", eq_b, eq_c, eq_a)));

    let mut lt = OpcodeBuilder::new(m[24].clone(), cfg, rng);
    let lt_b = lt.rk(3); let lt_c = lt.rk(4); let lt_a = lt.raw_inst(2);
    out.push_str(&lt.build(&format!("if ({} < {}) ~= ({} ~= 0) then {{PC}} = {{PC}} + 1 end", lt_b, lt_c, lt_a)));

    let mut le = OpcodeBuilder::new(m[25].clone(), cfg, rng);
    let le_b = le.rk(3); let le_c = le.rk(4); let le_a = le.raw_inst(2);
    out.push_str(&le.build(&format!("if ({} <= {}) ~= ({} ~= 0) then {{PC}} = {{PC}} + 1 end", le_b, le_c, le_a)));

    let mut test = OpcodeBuilder::new(m[26].clone(), cfg, rng);
    let test_a = test.reg(2); let test_c = test.raw_inst(4);
    out.push_str(&test.build(&format!("if (not {}) == ({} ~= 0) then {{PC}} = {{PC}} + 1 end", test_a, test_c)));

    let mut testset = OpcodeBuilder::new(m[27].clone(), cfg, rng);
    let testset_a = testset.reg(2); let testset_b = testset.reg(3); let testset_c = testset.raw_inst(4);
    out.push_str(&testset.build(&format!("if (not {}) ~= ({} ~= 0) then {} = {} else {{PC}} = {{PC}} + 1 end", testset_b, testset_c, testset_a, testset_b)));

    let mut forloop = OpcodeBuilder::new(m[31].clone(), cfg, rng);
    let fl_a = forloop.raw_inst(2); let fl_c = forloop.raw_inst(3);
    out.push_str(&forloop.build(&format!("local step = {{STK}}[{}+2]; local idx = {{STK}}[{}] + step; {{STK}}[{}] = idx; if (step > 0 and idx <= {{STK}}[{}+1]) or (step <= 0 and idx >= {{STK}}[{}+1]) then {{PC}} = {{PC}} + {}; {{STK}}[{}+3] = idx end", fl_a, fl_a, fl_a, fl_a, fl_a, fl_c, fl_a)));

    let mut forprep = OpcodeBuilder::new(m[32].clone(), cfg, rng);
    let fp_a = forprep.raw_inst(2); let fp_c = forprep.raw_inst(3);
    out.push_str(&forprep.build(&format!("{{STK}}[{}+1] = {{STK}}[{}+1] + 0; {{STK}}[{}+2] = {{STK}}[{}+2] + 0; {{STK}}[{}] = {{STK}}[{}] - {{STK}}[{}+2]; {{PC}} = {{PC}} + {}", fp_a, fp_a, fp_a, fp_a, fp_a, fp_a, fp_a, fp_c)));

    let mut tforloop = OpcodeBuilder::new(m[33].clone(), cfg, rng);
    let tfl_a = tforloop.raw_inst(2); let tfl_c = tforloop.raw_inst(4);
    out.push_str(&tforloop.build(&format!("local r1, r2, r3, r4, r5, r6 = {{STK}}[{}]({{STK}}[{}+1], {{STK}}[{}+2]); {{STK}}[{}+3] = r1; if {} > 1 then {{STK}}[{}+4] = r2; if {} > 2 then {{STK}}[{}+5] = r3; if {} > 3 then {{STK}}[{}+6] = r4; if {} > 4 then {{STK}}[{}+7] = r5; if {} > 5 then {{STK}}[{}+8] = r6 end end end end end; if {{STK}}[{}+3] ~= nil then {{STK}}[{}+2] = {{STK}}[{}+3] else {{PC}} = {{PC}} + 1 end", tfl_a, tfl_a, tfl_a, tfl_a, tfl_c, tfl_a, tfl_c, tfl_a, tfl_c, tfl_a, tfl_c, tfl_a, tfl_c, tfl_a, tfl_a, tfl_a, tfl_a)));

    let mut call = OpcodeBuilder::new(m[28].clone(), cfg, rng);
    let c_a = call.raw_inst(2); let c_b = call.raw_inst(3); let c_c = call.raw_inst(4);
    let call_lua = format!("local limit = {}>0 and {}-1 or {{TOP}}-{}; for j={}+limit+1, {{TOP}} do {{STK}}[j]=nil end; local res=zm({{STK}}[{}](unpack({{STK}}, {}+1, {}+limit))); local clean_from={}+( {} > 0 and {} - 1 or res.n ); local clean_to={}>0 and ({}+{}-1) or {{TOP}}; for j=clean_from, clean_to do {{STK}}[j]=nil end; if {}>0 then for j=1, {}-1 do {{STK}}[{}+j-1]=res[j] end else {{TOP}}={}-1; for j=1, res.n do {{STK}}[{}+j-1]=res[j]; {{TOP}}={{TOP}}+1 end end", c_b, c_b, c_a, c_a, c_a, c_a, c_a, c_a, c_c, c_c, c_b, c_a, c_b, c_c, c_c, c_a, c_a, c_a);
    out.push_str(&call.build(&call_lua));

    let mut tailcall = OpcodeBuilder::new(m[29].clone(), cfg, rng);
    let tc_a = tailcall.raw_inst(2); let tc_b = tailcall.raw_inst(3);
    let tc_lua = format!("if {{STK}}.open_ups then for reg, uv_obj in pairs({{STK}}.open_ups) do uv_obj[1] = {{uv_obj[1][uv_obj[2]]}}; uv_obj[2] = 1; end; {{STK}}.open_ups = nil; end; local limit = {}>0 and {}-1 or {{TOP}}-{}; local res=zm({{STK}}[{}](unpack({{STK}}, {}+1, {}+limit))); return unpack(res, 1, res.n)", tc_b, tc_b, tc_a, tc_a, tc_a, tc_a);
    out.push_str(&tailcall.build(&tc_lua));

    let mut ret = OpcodeBuilder::new(m[30].clone(), cfg, rng);
    let r_a = ret.raw_inst(2); let r_b = ret.raw_inst(3);
    let ret_lua = format!("if {{STK}}.open_ups then for reg, uv_obj in pairs({{STK}}.open_ups) do uv_obj[1] = {{uv_obj[1][uv_obj[2]]}}; uv_obj[2] = 1; end; {{STK}}.open_ups = nil; end; local limit = {}>0 and {}-1 or {{TOP}}-{}+1; return unpack({{STK}}, {}, {}+limit-1)", r_b, r_b, r_a, r_a, r_a);
    out.push_str(&ret.build(&ret_lua));

    let mut tforcall = OpcodeBuilder::new(m[47].clone(), cfg, rng);
    let tfc_a = tforcall.raw_inst(2); let tfc_c = tforcall.raw_inst(4);
    out.push_str(&tforcall.build(&format!("local r1, r2, r3, r4, r5, r6 = {{STK}}[{}]({{STK}}[{}+1], {{STK}}[{}+2]); {{STK}}[{}+3] = r1; if {} > 1 then {{STK}}[{}+4] = r2; if {} > 2 then {{STK}}[{}+5] = r3; if {} > 3 then {{STK}}[{}+6] = r4; if {} > 4 then {{STK}}[{}+7] = r5; if {} > 5 then {{STK}}[{}+8] = r6 end end end end end", tfc_a, tfc_a, tfc_a, tfc_a, tfc_c, tfc_a, tfc_c, tfc_a, tfc_c, tfc_a, tfc_c, tfc_a, tfc_c, tfc_a)));

    let mut tforprep = OpcodeBuilder::new(m[48].clone(), cfg, rng);
    let tfp_a = tforprep.raw_inst(2); let tfp_b = tforprep.raw_inst(3);
    out.push_str(&tforprep.build(&format!("if {{STK}}[{}+1] ~= nil then {{STK}}[{}] = {{STK}}[{}+1]; {{PC}} = {{PC}} + {} end", tfp_a, tfp_a, tfp_a, tfp_b)));

    let mut eqint = OpcodeBuilder::new(m[69].clone(), cfg, rng);
    let eqi_b = eqint.rk(3); let eqi_c = eqint.rk(4); let eqi_a = eqint.raw_inst(2);
    out.push_str(&eqint.build(&format!("if ({} == {}) ~= ({} ~= 0) then {{PC}} = {{PC}} + 1 end", eqi_b, eqi_c, eqi_a)));

    let mut jmpif = OpcodeBuilder::new(m[81].clone(), cfg, rng);
    let jmpif_a = jmpif.raw_inst(2); let jmpif_b = jmpif.raw_inst(3);
    out.push_str(&jmpif.build(&format!("if {{STK}}[{}] then {{PC}} = {{PC}} + {} end", jmpif_a, jmpif_b)));

    let mut jmpifnot = OpcodeBuilder::new(m[82].clone(), cfg, rng);
    let jn_a = jmpifnot.raw_inst(2); let jn_b = jmpifnot.raw_inst(3);
    out.push_str(&jmpifnot.build(&format!("if not {{STK}}[{}] then {{PC}} = {{PC}} + {} end", jn_a, jn_b)));

    let mut jmpeq = OpcodeBuilder::new(m[83].clone(), cfg, rng);
    let jeq_a = jmpeq.raw_inst(2); let jeq_c = jmpeq.raw_inst(4); let jeq_b = jmpeq.raw_inst(3);
    out.push_str(&jmpeq.build(&format!("if {{STK}}[{}] == {{STK}}[{}] then {{PC}} = {{PC}} + {} end", jeq_a, jeq_c, jeq_b)));

    let mut jmpne = OpcodeBuilder::new(m[84].clone(), cfg, rng);
    let jne_a = jmpne.raw_inst(2); let jne_c = jmpne.raw_inst(4); let jne_b = jmpne.raw_inst(3);
    out.push_str(&jmpne.build(&format!("if {{STK}}[{}] ~= {{STK}}[{}] then {{PC}} = {{PC}} + {} end", jne_a, jne_c, jne_b)));

    let close_ups_stmt = "if {STK}.open_ups then for reg, uv_obj in pairs({STK}.open_ups) do uv_obj[1] = {uv_obj[1][uv_obj[2]]}; uv_obj[2] = 1; end; {STK}.open_ups = nil; end; ";

    let mut ret0 = OpcodeBuilder::new(m[85].clone(), cfg, rng);
    out.push_str(&ret0.build(&format!("{}return", close_ups_stmt)));

    let mut ret1 = OpcodeBuilder::new(m[86].clone(), cfg, rng);
    let r1_a = ret1.raw_inst(2);
    out.push_str(&ret1.build(&format!("{}return {{STK}}[{}]", close_ups_stmt, r1_a)));

    let mut ret2 = OpcodeBuilder::new(m[87].clone(), cfg, rng);
    let r2_a = ret2.raw_inst(2);
    out.push_str(&ret2.build(&format!("{}return {{STK}}[{}], {{STK}}[{}+1]", close_ups_stmt, r2_a, r2_a)));

    out
}