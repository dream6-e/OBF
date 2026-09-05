use std::time::SystemTime;
use super::utils::NamePool;

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

        let mut pcs: Vec<usize> = (1..=10).collect();
        for i in (1..10).rev() {
            let j = pool.rng_mut().next_range(0, i + 1);
            pcs.swap(i, j);
        }
        let pc_state0 = pcs[0];
        let pc_state1 = pcs[1];
        let pc_state2 = pcs[2];
        let pc_state3 = pcs[3];
        let pc_state4 = pcs[4];
        let pc_state5 = pcs[5];
        let pc_state6 = pcs[6];
        let pc_state7 = pcs[7];
        let pc_state8 = pcs[8];
        let pc_state9 = pcs[9];

        let tamper_val = pool.rng_mut().next_range(10, 50);

        let mut insts_init = Vec::new();
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state0}]={{{op_state0}}};", v_s=v_s, p_insts=p_insts, pc_state0=pc_state0, op_state0=op_state0));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state1}]={{{op_state1}}};", v_s=v_s, p_insts=p_insts, pc_state1=pc_state1, op_state1=op_state1));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state2}]={{{op_state2}}};", v_s=v_s, p_insts=p_insts, pc_state2=pc_state2, op_state2=op_state2));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state3}]={{{op_state3}}};", v_s=v_s, p_insts=p_insts, pc_state3=pc_state3, op_state3=op_state3));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state4}]={{{op_state4}}};", v_s=v_s, p_insts=p_insts, pc_state4=pc_state4, op_state4=op_state4));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state5}]={{{op_state5}}};", v_s=v_s, p_insts=p_insts, pc_state5=pc_state5, op_state5=op_state5));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state6}]={{{op_state6}}};", v_s=v_s, p_insts=p_insts, pc_state6=pc_state6, op_state6=op_state6));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state7}]={{{op_state7}}};", v_s=v_s, p_insts=p_insts, pc_state7=pc_state7, op_state7=op_state7));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state8}]={{{op_state8}}};", v_s=v_s, p_insts=p_insts, pc_state8=pc_state8, op_state8=op_state8));
        insts_init.push(format!("{v_s}.{p_insts}[{pc_state9}]={{{op_state9}}};", v_s=v_s, p_insts=p_insts, pc_state9=pc_state9, op_state9=op_state9));

        let mut insts_states: Vec<usize> = (1..=insts_init.len()+1).collect();
        for i in (1..insts_states.len()).rev() {
            let j = pool.rng_mut().next_range(0, i + 1);
            insts_states.swap(i, j);
        }
        
        let mut m_init_insts_body = String::new();
        m_init_insts_body.push_str(&format!("local {v_st}={init_st};local function ky(...) return not(...) end while ky(false) do ", v_st=v_st, init_st=insts_states[0]));
        for (i, inst) in insts_init.iter().enumerate() {
            let curr_st = insts_states[i];
            let next_st = insts_states[i+1];
            if i == 0 {
                m_init_insts_body.push_str(&format!("if {v_st}=={curr_st} then {inst} {v_st}={next_st}; ", v_st=v_st, curr_st=curr_st, inst=inst, next_st=next_st));
            } else {
                m_init_insts_body.push_str(&format!("elseif {v_st}=={curr_st} then {inst} {v_st}={next_st}; ", v_st=v_st, curr_st=curr_st, inst=inst, next_st=next_st));
            }
        }
        m_init_insts_body.push_str("else break end end;");

        let mut handlers_init = Vec::new();
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state0}+{tamper_val}] = function({v_i}) {v_s}.{p_bc}=8; {v_s}.{p_res}={{}}; {v_s}.{p_pc}={pc_state1}; end;", v_s=v_s, p_handlers=p_handlers, op_state0=op_state0, tamper_val=tamper_val, v_i=v_i, p_bc=p_bc, p_res=p_res, p_pc=p_pc, pc_state1=pc_state1));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state1}+{tamper_val}] = function({v_i}) if {v_s}.{p_bc}>7 then {v_s}.{p_pc}={pc_state2} else {v_s}.{p_pc}={pc_state3} end end;", v_s=v_s, p_handlers=p_handlers, op_state1=op_state1, tamper_val=tamper_val, v_i=v_i, p_bc=p_bc, p_pc=p_pc, pc_state2=pc_state2, pc_state3=pc_state3));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state2}+{tamper_val}] = function({v_i}) {v_s}.{p_f}={v_q}:{m_next}({v_s}); if not {v_s}.{p_f} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_s}.{p_bc}=0; {v_s}.{p_pc}={pc_state3}; end;", v_s=v_s, p_handlers=p_handlers, op_state2=op_state2, tamper_val=tamper_val, v_i=v_i, p_f=p_f, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, p_bc=p_bc, p_pc=p_pc, pc_state3=pc_state3));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state3}+{tamper_val}] = function({v_i}) if ({v_s}.{p_f}%2)==1 then {v_s}.{p_pc}={pc_state4} else {v_s}.{p_pc}={pc_state5} end end;", v_s=v_s, p_handlers=p_handlers, op_state3=op_state3, tamper_val=tamper_val, v_i=v_i, p_f=p_f, p_pc=p_pc, pc_state4=pc_state4, pc_state5=pc_state5));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state4}+{tamper_val}] = function({v_i}) {v_s}.{p_u}={v_q}:{m_next}({v_s}); if not {v_s}.{p_u} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_s}.{p_res}[#{v_s}.{p_res}+1]={f_char}({v_s}.{p_u}); {v_s}.{p_pc}={pc_state9}; end;", v_s=v_s, p_handlers=p_handlers, op_state4=op_state4, tamper_val=tamper_val, v_i=v_i, p_u=p_u, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, f_char=f_char, p_pc=p_pc, pc_state9=pc_state9));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state5}+{tamper_val}] = function({v_i}) {v_s}.{p_p1}={v_q}:{m_next}({v_s}); if not {v_s}.{p_p1} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_s}.{p_pc}={pc_state6}; end;", v_s=v_s, p_handlers=p_handlers, op_state5=op_state5, tamper_val=tamper_val, v_i=v_i, p_p1=p_p1, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, p_pc=p_pc, pc_state6=pc_state6));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state6}+{tamper_val}] = function({v_i}) {v_s}.{p_p2}={v_q}:{m_next}({v_s}); if not {v_s}.{p_p2} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_s}.{p_pc}={pc_state7}; end;", v_s=v_s, p_handlers=p_handlers, op_state6=op_state6, tamper_val=tamper_val, v_i=v_i, p_p2=p_p2, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, p_pc=p_pc, pc_state7=pc_state7));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state7}+{tamper_val}] = function({v_i}) local {v_len}=0; while true do local {v_lb}={v_q}:{m_next}({v_s}); if not {v_lb} then {v_s}.{p_r_flg}=true; {v_s}.{p_r_vals}={{{f_concat}({v_s}.{p_res})}}; return end; {v_len}={v_len}+{v_lb}; if {v_lb}<255 then break end end; {v_s}.{p_w}={v_len}; {v_s}.{p_pc}={pc_state8}; end;", v_s=v_s, p_handlers=p_handlers, op_state7=op_state7, tamper_val=tamper_val, v_i=v_i, v_len=v_len, v_lb=v_lb, v_q=v_q, m_next=m_next, p_r_flg=p_r_flg, p_r_vals=p_r_vals, f_concat=f_concat, p_res=p_res, p_w=p_w, p_pc=p_pc, pc_state8=pc_state8));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state8}+{tamper_val}] = function({v_i}, {v_iter}) {v_s}.{p_ptr}=#{v_s}.{p_res}-({v_s}.{p_p1}*256+{v_s}.{p_p2})+1; {v_iter}=0; while true do if {v_iter}>={v_s}.{p_w}+3 then break end; {v_s}.{p_res}[#{v_s}.{p_res}+1]={v_s}.{p_res}[{v_s}.{p_ptr}+{v_iter}]; {v_iter}={v_iter}+1; end; {v_s}.{p_pc}={pc_state9}; end;", v_s=v_s, p_handlers=p_handlers, op_state8=op_state8, tamper_val=tamper_val, v_i=v_i, v_iter=v_iter, p_ptr=p_ptr, p_res=p_res, p_p1=p_p1, p_p2=p_p2, p_w=p_w, p_pc=p_pc, pc_state9=pc_state9));
        handlers_init.push(format!("{v_s}.{p_handlers}[{op_state9}+{tamper_val}] = function({v_i}) {v_s}.{p_f}={f_floor}({v_s}.{p_f}/2); {v_s}.{p_bc}={v_s}.{p_bc}+1; {v_s}.{p_pc}={pc_state1}; end;", v_s=v_s, p_handlers=p_handlers, op_state9=op_state9, tamper_val=tamper_val, v_i=v_i, p_f=p_f, f_floor=f_floor, p_bc=p_bc, p_pc=p_pc, pc_state1=pc_state1));

        let mut handlers_states: Vec<usize> = (1..=handlers_init.len()+1).collect();
        for i in (1..handlers_states.len()).rev() {
            let j = pool.rng_mut().next_range(0, i + 1);
            handlers_states.swap(i, j);
        }
        
        let mut m_init_handlers_body = String::new();
        m_init_handlers_body.push_str(&format!("local {v_st}={init_st}; while not(nil) or false do ", v_st=v_st, init_st=handlers_states[0]));
        for (i, h) in handlers_init.iter().enumerate() {
            let curr_st = handlers_states[i];
            let next_st = handlers_states[i+1];
            if i == 0 {
                m_init_handlers_body.push_str(&format!("if {v_st}=={curr_st} then {h} {v_st}={next_st}; ", v_st=v_st, curr_st=curr_st, h=h, next_st=next_st));
            } else {
                m_init_handlers_body.push_str(&format!("elseif {v_st}=={curr_st} then {h} {v_st}={next_st}; ", v_st=v_st, curr_st=curr_st, h=h, next_st=next_st));
            }
        }
        m_init_handlers_body.push_str("else break end end;");

        let mut map_init = String::new();
        for (i, &c) in alphabet.iter().enumerate() {
            let b = c as u8 as u32;
            let variant = pool.rng_mut().next_range(0, 4);
            let line = match variant {
                0 => {
                    let off = pool.rng_mut().next_range(10, 120) as u32;
                    let mult = pool.rng_mut().next_range(3, 9) as u32;
                    let obf = (b + off) * mult;
                    format!("{v_s}.{p_map}[{f_floor}(({obf}/{mult})-{off})]={i};\n", v_s=v_s, p_map=p_map, f_floor=f_floor, obf=obf, mult=mult, off=off, i=i)
                }
                1 => {
                    let off = pool.rng_mut().next_range(10, 120) as i64;
                    let mult = pool.rng_mut().next_range(3, 9) as i64;
                    let obf = (b as i64 - off) * mult;
                    format!("{v_s}.{p_map}[{f_floor}(({obf}/{mult})+{off})]={i};\n", v_s=v_s, p_map=p_map, f_floor=f_floor, obf=obf, mult=mult, off=off, i=i)
                }
                2 => {
                    let mask = pool.rng_mut().next_range(1, 90) as u32;
                    let obf = b ^ mask;
                    format!("{v_s}.{p_map}[{v_q}:{m_bxor}({v_s},{obf},{mask})]={i};\n", v_s=v_s, p_map=p_map, v_q=v_q, m_bxor=m_bxor, obf=obf, mask=mask, i=i)
                }
                _ => {
                    let off = pool.rng_mut().next_range(10, 120) as i64;
                    let mult = pool.rng_mut().next_range(3, 9) as i64;
                    let obf = (b as i64) * mult + off;
                    format!("{v_s}.{p_map}[{f_floor}(({obf}-{off})/{mult})]={i};\n", v_s=v_s, p_map=p_map, f_floor=f_floor, obf=obf, off=off, mult=mult, i=i)
                }
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
                if {v_s}.{p_tamper} ~= {tamper_val} then {v_current} = {v_current} - {tamper_val} end
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
        ", v_current=v_current, v_s=v_s, p_pc=p_pc, v_i=v_i, p_insts=p_insts, p_tamper=p_tamper, tamper_val=tamper_val, v_h=v_h, p_handlers=p_handlers, v_succ=v_succ, v_err=v_err, f_pcall=f_pcall, p_r_flg=p_r_flg, f_concat=f_concat, p_r_vals=p_r_vals);

        let mut k_str = String::from("{");
        for (i, &k) in keys.iter().enumerate() {
            if i > 0 { k_str.push(','); }
            k_str.push_str(&k.to_string());
        }
        k_str.push('}');

        format!("
return (function(...)
    local {f_load}=function(c) local f;if not(f) then return (loadstring or load)(c) else return {{}} end;end
    local {f_pcall}=function(r) local c,v=3,type;if v(c)==\"string\" then return error(r) else return pcall(r) end;end
    local {f_char}=function(...) return string.char(...) end
    local {f_byte} = function(...) local k,g=3.0,0x0;local ui=k+g;if ui < k-g then return math.floor(...) elseif ui==k-g then return string.byte(...) end;end
    local {f_floor} = function(x) return math.floor(x) end
    local {f_concat} = function(t, sep) local fg=function(sd,qw) if true then return math.random(sd,qw) end end;local ty,zx,nm=0x1,5,0x14; if fg(ty,zx) <= fg(zx,nm) then return table.concat(t, sep) else return tonumber(t,sep) end;end
    local {f_gsub} = function(s, p, r) return string.gsub(s, p, r) end
    local {f_remove} = function(t, pos) return table.remove(t, pos) end
    local function {v_entry}({v_data}, ...)
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
                    {p_pc}={pc_state0},
                    {p_insts}={{}},
                    {p_tamper}={tamper_val},
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
        f_load=f_load, f_pcall=f_pcall, f_char=f_char, f_byte=f_byte, f_floor=f_floor, f_concat=f_concat, f_gsub=f_gsub, f_remove=f_remove,
        v_entry=v_entry, v_data=v_data, v_q=v_q, m_bxor=m_bxor, v_s=v_s, v_a=v_a, v_b=v_b, m_bxor_body=m_bxor_body, m_next=m_next,
        m_next_body=m_next_body, m_init_map=m_init_map, m_init_map_body=m_init_map_body, m_init_insts=m_init_insts,
        m_init_insts_body=m_init_insts_body, m_init_handlers=m_init_handlers, m_init_handlers_body=m_init_handlers_body,
        m_run=m_run, m_run_body=m_run_body, m_main=m_main, p_data=p_data, p_pc=p_pc, pc_state0=pc_state0, p_insts=p_insts,
        p_tamper=p_tamper, tamper_val=tamper_val, p_handlers=p_handlers, p_r_flg=p_r_flg, p_r_vals=p_r_vals,
        p_map=p_map, p_idx=p_idx, p_len=p_len, p_k=p_k, k_str=k_str, p_kidx=p_kidx, p_memo=p_memo, p_bc=p_bc, p_res=p_res,
        p_f=p_f, p_p1=p_p1, p_p2=p_p2, p_w=p_w, p_u=p_u, p_ptr=p_ptr, p_buf=p_buf, v_r=v_r, payload=payload
        )
    }
}