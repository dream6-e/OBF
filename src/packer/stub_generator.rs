use rand::Rng;
use std::time::SystemTime;
use super::utils::NamePool;
use crate::VM::VM_Backend::Generator_util::{loadstring_probe_lua, UniStream, GenRng};
use crate::VM::Control_Flow::ControlFlowBuilder;

pub struct StubGenerator;

impl StubGenerator {
    pub fn build_decoder(payload: &str, keys: &[u8], alphabet: &[char; 85]) -> String {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(0x1337BEEF);
        let mut pool = NamePool::new(seed);

        let m_bxor = pool.get();
        let m_next = pool.get();
        let m_init_map = pool.get();
        let m_init_insts = pool.get();
        let m_init_handlers = pool.get();
        let m_run = pool.get();
        let m_main = pool.get();

        let f_load = pool.get();
        let f_isnat = pool.get();
        let f_getls = pool.get();
        let v_pload = pool.get();
        let f_pcall = pool.get();
        let f_char = pool.get();
        let f_byte = pool.get();
        let f_floor = pool.get();
        let f_concat = pool.get();
        let f_gsub = pool.get();
        let f_remove = pool.get();
        
        let p_pc = pool.get();
        let p_insts = pool.get();
        let p_handlers = pool.get();
        let p_tamper = pool.get();
        let p_r_flg = pool.get();
        let p_r_vals = pool.get();
        let p_map = pool.get();
        let p_idx = pool.get();
        let p_len = pool.get();
        let p_k = pool.get();
        let p_kidx = pool.get();
        let p_memo = pool.get();
        let p_bc = pool.get();
        let p_res = pool.get();
        let p_f = pool.get();
        let p_p1 = pool.get();
        let p_p2 = pool.get();
        let p_w = pool.get();
        let p_u = pool.get();
        let p_ptr = pool.get();
        let p_data = pool.get();
        let p_buf = pool.get();

        let v_data = pool.get();
        let v_entry = pool.get();
        let v_q = pool.get();
        let v_s = pool.get();
        let v_a = pool.get();
        let v_b = pool.get();
        let v_ra = pool.get();
        let v_rb = pool.get();
        let v_p = pool.get();
        let v_c = pool.get();
        let v_rra = pool.get();
        let v_rrb = pool.get();
        let v_k = pool.get();
        let v_v = pool.get();
        let v_dec = pool.get();
        let v_st = pool.get();
        let v_current = pool.get();
        let v_i = pool.get();
        let v_h = pool.get();
        let v_succ = pool.get();
        let v_err = pool.get();
        let v_iter = pool.get();
        let v_r = pool.get();
        let v_len = pool.get();
        let v_lb = pool.get();

        let op_state0 = pool.rng_mut().next_range(100, 200);
        let op_state1 = pool.rng_mut().next_range(201, 300);
        let op_state2 = pool.rng_mut().next_range(301, 400);
        let op_state3 = pool.rng_mut().next_range(401, 500);
        let op_state4 = pool.rng_mut().next_range(501, 600);
        let op_state5 = pool.rng_mut().next_range(601, 700);
        let op_state6 = pool.rng_mut().next_range(701, 800);
        let op_state7 = pool.rng_mut().next_range(801, 900);
        let op_state8 = pool.rng_mut().next_range(901, 1000);
        let op_state9 = pool.rng_mut().next_range(1001, 1100);

        // ㉕ pc 状态号运行时耦合（与主打包器同规格）：值域保持 1..10 稠密排列
        // （路由器按 #insts/pc+1 语义）；状态表直接写入数值字面量，
        // 引用走状态表/恒等委托两形态。
        let mut srng = GenRng::new(seed as u64);
        let mut pcs: Vec<usize> = (0..10).collect();
        for i in (1..10).rev() {
            let j = pool.rng_mut().next_range(0, i + 1);
            pcs.swap(i, j);
        }
        let (pct, pcdv) = (pool.get(), pool.get());
        let mut pc_fills: Vec<String> = Vec::new();
        for n in 0..10 {
            pc_fills.push(format!("{}[{}]={};", pct,
                ControlFlowBuilder::obf_num((n + 1) as i64, &mut srng),
                ControlFlowBuilder::obf_num((pcs[n] + 1) as i64, &mut srng)));
        }
        for i in (1..pc_fills.len()).rev() {
            let j = pool.rng_mut().next_range(0, i + 1);
            pc_fills.swap(i, j);
        }
        let pc_infra = format!("local {}={{}};{}local {}=function(w,u) local z=w%0X2 return u+(z-z) end;",
            pct, pc_fills.join(""), pcdv);
        // 每个 pc 值两枚引用形态：a=表引用（给 insts 键/初值），b=表引用或委托（给句柄体）
        let mut pc_refs_a: Vec<String> = Vec::new();
        let mut pc_refs_b: Vec<String> = Vec::new();
        for n in 0..10 {
            let idx_a = ControlFlowBuilder::obf_num((n + 1) as i64, &mut srng);
            pc_refs_a.push(format!("{}[{}]", pct, idx_a));
            let idx_b = ControlFlowBuilder::obf_num((n + 1) as i64, &mut srng);
            if srng.range(0, 3) == 0 {
                let junk = ControlFlowBuilder::obf_num(srng.range64(0x100, 0xFFFF), &mut srng);
                pc_refs_b.push(format!("{}({},{}[{}])", pcdv, junk, pct, idx_b));
            } else {
                pc_refs_b.push(format!("{}[{}]", pct, idx_b));
            }
        }
        // ㉕ op/tamper 数值统一以数值字面量下发
        let obf_op = |v: usize, r: &mut GenRng| ControlFlowBuilder::obf_num(v as i64, r);

        let tamper_val = pool.rng_mut().next_range(10, 50);

        let mut insts_init = Vec::new();
        // ㉕ pc 键=状态表引用；op 值=直接数值字面量
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[0], opx=obf_op(op_state0, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[1], opx=obf_op(op_state1, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[2], opx=obf_op(op_state2, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[3], opx=obf_op(op_state3, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[4], opx=obf_op(op_state4, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[5], opx=obf_op(op_state5, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[6], opx=obf_op(op_state6, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[7], opx=obf_op(op_state7, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[8], opx=obf_op(op_state8, &mut srng)));
        insts_init.push(format!("{v_s}.{p_insts}[{pck}]={{{opx}}};", v_s=v_s, p_insts=p_insts, pck=pc_refs_a[9], opx=obf_op(op_state9, &mut srng)));

        // ㉕ 初始化状态机运行时耦合化：状态号文本零出现（等差数列运行期填表）
        let (insts_decl, insts_body) =
            ControlFlowBuilder::build_router_machine(&insts_init, "while ky(false) do ", &v_st, &format!("({v_s}.{p_len})+({v_s}.{p_k}[1])", v_s=v_s, p_len=p_len, p_k=p_k), &mut srng);
        let m_init_insts_body = format!("local function ky(...) return not(...) end {}{}", insts_decl, insts_body);

        let mut handlers_init = Vec::new();
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state0}+{tamper_val}] = function({v_i}) {v_s}.{p_bc}=8; {v_s}.{p_res}={{}}; {v_s}.{p_pc}={pc_state1}; end;", v_s=v_s, p_handlers=p_handlers, op_state0=obf_op(op_state0, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, p_bc=p_bc, p_res=p_res, p_pc=p_pc, pc_state1=pc_refs_b[1]));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state1}+{tamper_val}] = function({v_i}) if {v_s}.{p_bc}>7 then {v_s}.{p_pc}={pc_state2} else {v_s}.{p_pc}={pc_state3} end end;", v_s=v_s, p_handlers=p_handlers, op_state1=obf_op(op_state1, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, p_bc=p_bc, p_pc=p_pc, pc_state2=pc_refs_b[2], pc_state3=pc_refs_b[3]));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state2}+{tamper_val}] = function({v_i}) {v_s}.{p_f}={v_q}:{m_next}({v_s}); if not {v_s}.{p_f} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_s}.{p_bc}=0; {v_s}.{p_pc}={pc_state3}; end;", v_s=v_s, p_handlers=p_handlers, op_state2=obf_op(op_state2, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, p_f=p_f, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, p_bc=p_bc, p_pc=p_pc, pc_state3=pc_refs_b[3]));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state3}+{tamper_val}] = function({v_i}) if ({v_s}.{p_f}%2)==1 then {v_s}.{p_pc}={pc_state4} else {v_s}.{p_pc}={pc_state5} end end;", v_s=v_s, p_handlers=p_handlers, op_state3=obf_op(op_state3, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, p_f=p_f, p_pc=p_pc, pc_state4=pc_refs_b[4], pc_state5=pc_refs_b[5]));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state4}+{tamper_val}] = function({v_i}) {v_s}.{p_u}={v_q}:{m_next}({v_s}); if not {v_s}.{p_u} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_s}.{p_res}[#{v_s}.{p_res}+1]={f_char}({v_s}.{p_u}); {v_s}.{p_pc}={pc_state9}; end;", v_s=v_s, p_handlers=p_handlers, op_state4=obf_op(op_state4, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, p_u=p_u, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, f_char=f_char, p_pc=p_pc, pc_state9=pc_refs_b[9]));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state5}+{tamper_val}] = function({v_i}) {v_s}.{p_p1}={v_q}:{m_next}({v_s}); if not {v_s}.{p_p1} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_s}.{p_pc}={pc_state6}; end;", v_s=v_s, p_handlers=p_handlers, op_state5=obf_op(op_state5, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, p_p1=p_p1, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, p_pc=p_pc, pc_state6=pc_refs_b[6]));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state6}+{tamper_val}] = function({v_i}) {v_s}.{p_p2}={v_q}:{m_next}({v_s}); if not {v_s}.{p_p2} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_s}.{p_pc}={pc_state7}; end;", v_s=v_s, p_handlers=p_handlers, op_state6=obf_op(op_state6, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, p_p2=p_p2, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, p_pc=p_pc, pc_state7=pc_refs_b[7]));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state7}+{tamper_val}] = function({v_i}) local {v_len}=0; while true do local {v_lb}={v_q}:{m_next}({v_s}); if not {v_lb} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_len}={v_len}+{v_lb}; if {v_lb}<255 then break end end; {v_s}.{p_w}={v_len}; {v_s}.{p_pc}={pc_state8}; end;", v_s=v_s, p_handlers=p_handlers, op_state7=obf_op(op_state7, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, v_len=v_len, v_lb=v_lb, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, p_w=p_w, p_pc=p_pc, pc_state8=pc_refs_b[8]));
        // 字节拼装权重直接使用 0X100，不再包成加减乘除恒等式。
        let bp1 = format!("{v_s}.{p_p1}", v_s = v_s, p_p1 = p_p1);
        let bp2 = format!("{v_s}.{p_p2}", v_s = v_s, p_p2 = p_p2);
        let w256 = format!("{}*0X100+{}", bp1, bp2);
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state8}+{tamper_val}] = function({v_i}, {v_iter}) {v_s}.{p_ptr}=#{v_s}.{p_res}-({w256})+1; {v_iter}=0; while true do if {v_iter}>={v_s}.{p_w}+3 then break end; {v_s}.{p_res}[#{v_s}.{p_res}+1]={v_s}.{p_res}[{v_s}.{p_ptr}+{v_iter}]; {v_iter}={v_iter}+1; end; {v_s}.{p_pc}={pc_state9}; end;", v_s=v_s, p_handlers=p_handlers, op_state8=obf_op(op_state8, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, v_iter=v_iter, p_ptr=p_ptr, p_res=p_res, p_w=p_w, p_pc=p_pc, pc_state9=pc_refs_b[9]));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state9}+{tamper_val}] = function({v_i}) {v_s}.{p_f}={f_floor}({v_s}.{p_f}/2); {v_s}.{p_bc}={v_s}.{p_bc}+1; {v_s}.{p_pc}={pc_state1}; end;", v_s=v_s, p_handlers=p_handlers, op_state9=obf_op(op_state9, &mut srng), tamper_val=obf_op(tamper_val, &mut srng), v_i=v_i, p_f=p_f, f_floor=f_floor, p_bc=p_bc, p_pc=p_pc, pc_state1=pc_refs_b[1]));

        // ㉕ 句柄注册状态机同样运行时耦合化
        let (handlers_decl, handlers_body) =
            ControlFlowBuilder::build_router_machine(&handlers_init, "while not(nil) or false do ", &v_st, &format!("({v_s}.{p_len})+({v_s}.{p_k}[1])", v_s=v_s, p_len=p_len, p_k=p_k), &mut srng);
        let m_init_handlers_body = format!("{}{}", handlers_decl, handlers_body);

        let mut map_init = String::new();
        for (i, &c) in alphabet.iter().enumerate() {
            let b = c as u8 as u32;
            let line = if pool.rng_mut().next_range(0, 2) == 0 {
                format!("{v_s}.{p_map}[{b}]={i};\n", v_s=v_s, p_map=p_map, b=b, i=i)
            } else {
                let mask = pool.rng_mut().next_range(1, 90) as u32;
                let obf = b ^ mask;
                format!("{v_s}.{p_map}[{v_q}:{m_bxor}({v_s},{obf},{mask})]={i};\n", v_s=v_s, p_map=p_map, v_q=v_q, m_bxor=m_bxor, obf=obf, mask=mask, i=i)
            };
            map_init.push_str(&line);
        }

        let m_init_map_body = format!("
            {map_init}
        ", map_init=map_init);

        let m_bxor_body = format!("
            local {v_k} = {v_a} * 256 + {v_b};
            if {v_s}.{p_memo}[{v_k}] then return {v_s}.{p_memo}[{v_k}] end
            local {v_ra}, {v_rb}, {v_p}, {v_c} = {v_a}, {v_b}, 1, 0;
            while true do
                if {v_ra} > 0 or {v_rb} > 0 then
                    local {v_rra}, {v_rrb} = {v_ra} % 2, {v_rb} % 2;
                    if {v_rra} ~= {v_rrb} then {v_c} = {v_c} + {v_p} end
                    {v_ra} = {f_floor}({v_ra} / 2);
                    {v_rb} = {f_floor}({v_rb} / 2);
                    {v_p} = {v_p} * 2;
                else break end
            end
            {v_s}.{p_memo}[{v_k}] = {v_c};
            return {v_c};
        ", v_k=v_k, v_a=v_a, v_b=v_b, v_s=v_s, p_memo=p_memo, v_ra=v_ra, v_rb=v_rb, v_p=v_p, v_c=v_c, v_rra=v_rra, v_rrb=v_rrb, f_floor=f_floor);

        let m_next_body = format!("
            if #{v_s}.{p_buf} > 0 then
                local {v_r} = {f_remove}({v_s}.{p_buf}, 1);
                local {v_dec} = {v_q}:{m_bxor}({v_s}, {v_r}, {v_s}.{p_k}[{v_s}.{p_kidx} + 1]);
                {v_s}.{p_kidx} = ({v_s}.{p_kidx} + 1) % 16;
                return {v_dec};
            end
            if {v_s}.{p_idx} > {v_s}.{p_len} then return nil end
            local {v_v} = {v_s}.{p_map}[{f_byte}({v_s}.{p_data}, {v_s}.{p_idx})]
                        + {v_s}.{p_map}[{f_byte}({v_s}.{p_data}, {v_s}.{p_idx}+1)] * 85
                        + {v_s}.{p_map}[{f_byte}({v_s}.{p_data}, {v_s}.{p_idx}+2)] * 7225
                        + {v_s}.{p_map}[{f_byte}({v_s}.{p_data}, {v_s}.{p_idx}+3)] * 614125
                        + {v_s}.{p_map}[{f_byte}({v_s}.{p_data}, {v_s}.{p_idx}+4)] * 52200625;
            {v_s}.{p_idx} = {v_s}.{p_idx} + 5;
            {v_s}.{p_buf}[1] = {v_v} % 256;
            {v_v} = {f_floor}({v_v} / 256);
            {v_s}.{p_buf}[2] = {v_v} % 256;
            {v_v} = {f_floor}({v_v} / 256);
            {v_s}.{p_buf}[3] = {v_v} % 256;
            {v_s}.{p_buf}[4] = {f_floor}({v_v} / 256);
            return {v_q}:{m_next}({v_s});
        ", v_s=v_s, p_buf=p_buf, v_r=v_r, f_remove=f_remove, v_dec=v_dec, v_q=v_q, m_bxor=m_bxor, p_k=p_k, p_kidx=p_kidx, p_idx=p_idx, p_len=p_len, v_v=v_v, p_map=p_map, f_byte=f_byte, p_data=p_data, f_floor=f_floor, m_next=m_next);

        let m_run_body = format!("
            local {v_current} = {v_s}.{p_pc};
            while true do
                local {v_i} = {v_s}.{p_insts}[{v_current}];
                if not {v_i} then
                    if {v_s}.{p_tamper} == 0 then return end
                    break
                end
                if {v_s}.{p_tamper} ~= {tcmp} then {v_current} = {v_current} - {tsub} end
                local {v_h} = {v_s}.{p_handlers}[{v_i}[1] + {v_s}.{p_tamper}];
                if {v_h} then
                    local {v_succ}, {v_err} = {f_pcall}({v_h}, {v_i});
                    if not {v_succ} then break end
                else
                    break
                end
                if {v_s}.{p_r_flg} then break end
                {v_current} = {v_s}.{p_pc};
            end
            return {f_concat}({v_s}.{p_r_vals});
        ", v_current=v_current, v_s=v_s, p_pc=p_pc, v_i=v_i, p_insts=p_insts, p_tamper=p_tamper,
        tcmp=ControlFlowBuilder::obf_num(tamper_val as i64, &mut srng), tsub=ControlFlowBuilder::obf_num(tamper_val as i64, &mut srng),
        v_h=v_h, p_handlers=p_handlers, v_succ=v_succ, v_err=v_err, f_pcall=f_pcall, p_r_flg=p_r_flg, f_concat=f_concat, p_r_vals=p_r_vals);

        let mut k_str = String::from("{");
        for (i, &k) in keys.iter().enumerate() {
            if i > 0 { k_str.push(','); }
            k_str.push_str(&k.to_string());
        }
        k_str.push('}');

        // ㉓ 统一流：壳脚本自带一只（惰性解密+数字密文），与主产物同一机制。
        let mut uni_rng = GenRng::new(seed as u64);
        let mut uni = UniStream::new(&mut uni_rng);
        let probe = loadstring_probe_lua(&f_isnat, &f_getls, &v_pload, &mut uni, &mut uni_rng);
        // ④E：加载器不以标识符落盘——探测结果优先，取不到再从环境表按
        // 运行期还原的名字取；产物里没有 `loadstring` / `load` 两个词。
        let (ld_setup, ld_var) = crate::VM::VM_Backend::Generator_util::loader_lookup(
            &mut uni, &mut uni_rng, Some(&v_pload), true);
        let sc_def = uni.emit_prelude(&mut uni_rng);
        format!("
return (function(...)
    {sc_def}{probe}{lds}
    local {f_load}=function(c) local f;if not(f) then return ({ld})(c) else return {{}} end;end
    local {f_pcall}=function(r) local c,v=3,type;if v(c)==\"string\" then return error(r) else return pcall(r) end;end
    local {f_char}=function(...) return string.char(...) end
    local {f_byte} = function(...) local k,g=3.0,0X0;local ui=k+g;if ui < k-g then return math.floor(...) elseif ui==k-g then return string.byte(...) end;end
    local {f_floor} = function(x) return math.floor(x) end
    local {f_concat} = function(t, sep) local fg=function(sd,qw) if true then return math.random(sd,qw) end end;local ty,zx,nm=0X1,5,0X14; if fg(ty,zx) <= fg(zx,nm) then return table.concat(t, sep) else return tonumber(t,sep) end;end
    local {f_gsub} = function(s, p, r) return string.gsub(s, p, r) end
    local {f_remove} = function(t, pos) return table.remove(t, pos) end
    local function {v_entry}({v_data}, ...)
        {pc_infra}
        local {v_q} = {{
            {m_bxor} = function({v_q}, {v_s}, {v_a}, {v_b})
                {m_bxor_body}
            end,
            {m_next} = function({v_q}, {v_s})
                {m_next_body}
            end,
            {m_init_map} = function({v_q}, {v_s})
                {m_init_map_body}
            end,
            {m_init_insts} = function({v_q}, {v_s})
                {m_init_insts_body}
            end,
            {m_init_handlers} = function({v_q}, {v_s})
                {m_init_handlers_body}
            end,
            {m_run} = function({v_q}, {v_s})
                {m_run_body}
            end,
            {m_main} = function({v_q}, {v_data}, ...)
                local {v_s} = {{
                    {p_data}={v_data},
                    {p_pc}={pc_state0x},
                    {p_insts}={{}},
                    {p_tamper}={tamper_tbl},
                    {p_handlers}={{}},
                    {p_r_flg}=false,
                    {p_r_vals}={{}},
                    {p_map}={{}},
                    {p_idx}=1,
                    {p_len}=#{v_data},
                    {p_k}={k_str},
                    {p_kidx}=0,
                    {p_memo}={{}},
                    {p_bc}=0,
                    {p_res}={{}},
                    {p_f}=0,
                    {p_p1}=0,
                    {p_p2}=0,
                    {p_w}=0,
                    {p_u}=0,
                    {p_ptr}=0,
                    {p_buf}={{}}
                }}
                {v_q}:{m_init_map}({v_s})
                {v_q}:{m_init_insts}({v_s})
                {v_q}:{m_init_handlers}({v_s})
                local {v_r} = {v_q}:{m_run}({v_s})
                {v_r} = {f_gsub}({v_r}, \"%z+$\", \"\")
                return {f_load}({v_r})(...)
            end
        }}
        return {v_q}.{m_main}({v_q}, {v_data}, ...)
    end
    return {v_entry}([=[{payload}]=], ...)
end)(...)
",
        f_load=f_load, f_pcall=f_pcall, lds=ld_setup, ld=ld_var, f_char=f_char, f_byte=f_byte, f_floor=f_floor, f_concat=f_concat, f_gsub=f_gsub, f_remove=f_remove,
        v_entry=v_entry, v_data=v_data, v_q=v_q, m_bxor=m_bxor, v_s=v_s, v_a=v_a, v_b=v_b, m_bxor_body=m_bxor_body, m_next=m_next,
        m_next_body=m_next_body, m_init_map=m_init_map, m_init_map_body=m_init_map_body, m_init_insts=m_init_insts,
        m_init_insts_body=m_init_insts_body, m_init_handlers=m_init_handlers, m_init_handlers_body=m_init_handlers_body,
        m_run=m_run, m_run_body=m_run_body, m_main=m_main, p_data=p_data, p_pc=p_pc, p_insts=p_insts,
        p_tamper=p_tamper, tamper_tbl=ControlFlowBuilder::obf_num(tamper_val as i64, &mut srng),
        pc_state0x=pc_refs_a[0], p_handlers=p_handlers, p_r_flg=p_r_flg, p_r_vals=p_r_vals,
        p_map=p_map, p_idx=p_idx, p_len=p_len, p_k=p_k, k_str=k_str, p_kidx=p_kidx, p_memo=p_memo, p_bc=p_bc, p_res=p_res,
        p_f=p_f, p_p1=p_p1, p_p2=p_p2, p_w=p_w, p_u=p_u, p_ptr=p_ptr, p_buf=p_buf, v_r=v_r, payload=payload
        )
    }
}