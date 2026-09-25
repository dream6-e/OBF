use crate::VM::VM_Backend::Context::VmContext;
use crate::VM::VM_Backend::Lua_core;
use crate::VM::Opcodes::{self, OpcodeConfig};
use crate::VM::packer::Packer;
use crate::compiler::instructions::{OpCode, OpMode, OpArgMask};
use std::collections::HashSet;
use rand::{rng, Rng, SeedableRng};
use rand::rngs::StdRng;
use super::AntiTamper;

// 底层工具层已拆到 Generator_util.rs（原文件 69 KB 太大）。
// GenRng 继续从这里 re-export，保持 crate 内既有的引用路径不变。
pub use super::Generator_util::{CipherKeys, GenRng};
use super::Generator_util::{
    build_opcode_tree, chacha8_xor, rename_ident, rewrite_chunk, scan_setglobal_targets,
    scan_used_opcodes, uses_ident, write_string, PayloadReader,
};


pub struct Generator { ctx: VmContext }

impl Generator {
    pub fn new(ctx: VmContext) -> Self { Self { ctx } }

    pub fn build(&self, payload: &[u8]) -> String {
        let mut rng = GenRng::new(self.ctx.seed);
        let var_l = rng.name();

        // 载荷里 Proto 表的字段名、zm(...) 变参表的计数字段名、open_ups 表名
        // 全部逐产物随机化。它们原先以明文出现在产物里（n / ld / lld / nups /
        // numparams / consts / protos / open_ups ...）。压缩器只重命名长度 > 4
        // 的成员名，短名会一路留到产物里，所以在生成端就先换掉。
        let pf_n = rng.name();
        let pf_ld = rng.name();
        let pf_lld = rng.name();
        let pf_nups = rng.name();
        let pf_numparams = rng.name();
        let pf_is_vararg = rng.name();
        let pf_maxstack = rng.name();
        let pf_opcodes = rng.name();
        let pf_a_arr = rng.name();
        let pf_b_arr = rng.name();
        let pf_c_arr = rng.name();
        let pf_consts = rng.name();
        let pf_protos = rng.name();
        let pf_open_ups = rng.name();
        let pf_vn = rng.name();
        
        let key_seed_var = rng.name();
        let mut at = AntiTamper::generate_split(true, &key_seed_var);
        
        let mut used_ops = HashSet::new();
        { let mut scan_reader = PayloadReader { data: payload, pos: 0 }; scan_used_opcodes(&mut scan_reader, &mut used_ops); }

        let mut setglobal_targets: HashSet<Vec<u8>> = HashSet::new();
        let setglobal_op = self.ctx.opcode_map[7];
        let getglobal_op = self.ctx.opcode_map[5];
        let getglobalstr_op = self.ctx.opcode_map[56];
        let mut inverse_opcode_map = [0u8; 90];
        for i in 0..90 { inverse_opcode_map[self.ctx.opcode_map[i] as usize] = i as u8; }
        let builtin_slot_perm = Opcodes::builtins::slot_permutation(self.ctx.seed);
        { let mut sg_reader = PayloadReader { data: payload, pos: 0 }; scan_setglobal_targets(&mut sg_reader, &mut setglobal_targets, setglobal_op); }

        let mut mapped_opcodes: [Vec<u32>; Opcodes::builtins::TOTAL_OPCODES] = std::array::from_fn(|_| Vec::new());
        let mut fused_opcodes: [Vec<u32>; Opcodes::builtins::FUSED_OP_COUNT] = std::array::from_fn(|_| Vec::new());
        let mut transpile_map: [Vec<u32>; 90] = std::array::from_fn(|_| Vec::new());
        {
            let mut map_rng = StdRng::seed_from_u64(self.ctx.seed);
            let mut used = std::collections::HashSet::new();
            for i in 0..90 {
                let shuffled_val = self.ctx.opcode_map[i];
                let count = if used_ops.contains(&shuffled_val) { map_rng.random_range(3..=6) } else { 1 };
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); transpile_map[shuffled_val as usize].push(val); break; }
                    }
                }
            }
            for i in 90..Opcodes::builtins::TOTAL_OPCODES {
                let count = map_rng.random_range(3..=6);
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { mapped_opcodes[i].push(val); break; }
                    }
                }
            }
            // 融合指令（SuperOperator）也各分一组别名，和 builtin-load 一样按 slot 索引
            for i in 0..Opcodes::builtins::FUSED_OP_COUNT {
                let count = map_rng.random_range(3..=6);
                for _ in 0..count {
                    loop {
                        let val = map_rng.random_range(80000..99999);
                        if used.insert(val) { fused_opcodes[i].push(val); break; }
                    }
                }
            }
        }

        let mut strings = Vec::new(); let mut numbers = Vec::new(); let mut rewritten_chunks = Vec::new();
        let mut reader = PayloadReader { data: payload, pos: 0 };
        let mut rewrite_rng = StdRng::seed_from_u64(self.ctx.seed + 1);
        let mut fused_used: HashSet<usize> = HashSet::new();
        rewrite_chunk(&mut reader, &mut rewritten_chunks, &mut strings, &mut numbers, &transpile_map, &mapped_opcodes, &fused_opcodes, &mut fused_used, &setglobal_targets, getglobal_op, getglobalstr_op, &inverse_opcode_map, &builtin_slot_perm, &mut rewrite_rng);

        let mut builtin_pool_indices: Vec<usize> = Vec::with_capacity(Opcodes::builtins::BUILTIN_NAMES.len());
        for name in Opcodes::builtins::BUILTIN_NAMES.iter() {
            let nb = name.as_bytes().to_vec();
            let pos = strings.iter().position(|x| x == &nb).unwrap_or_else(|| { strings.push(nb); strings.len() - 1 });
            builtin_pool_indices.push(pos);
        }

        let chacha_key: [u32; 8] = std::array::from_fn(|_| rng.next());
        let chacha_salt: u32 = rng.next();

        let mut pool_bytes = Vec::new();
        pool_bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        for (idx, s) in strings.iter().enumerate() {
            let enc_s = chacha8_xor(&chacha_key, chacha_salt, idx as u32, 0, s);
            write_string(&mut pool_bytes, &enc_s);
        }
        pool_bytes.extend_from_slice(&(numbers.len() as u32).to_le_bytes());
        for (idx, n) in numbers.iter().enumerate() {
            let enc_n_bytes = chacha8_xor(&chacha_key, chacha_salt, idx as u32, 1, &n.to_le_bytes());
            pool_bytes.extend_from_slice(&enc_n_bytes);
        }
        
        let mut combined_payload = Vec::new();
        let (mut k1, mut k2, mut k3, mut k4) = ((rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8, (rng.next() & 0xFF) as u8);
        combined_payload.push(k1); combined_payload.push(k2); combined_payload.push(k3); combined_payload.push(k4);
        
        combined_payload.extend(pool_bytes); combined_payload.extend(rewritten_chunks);

        // 对 4 字节密钥之后的**全部内容**做同一道滚动字节变换 —— 常量池和指令流
        // 共用一条连续的 keystream。指令流此前是明文追加的，固定 10 字节一条
        // 剥掉外层 base86 之后可以直接切片还原；现在和池一样被覆盖。
        // Lua 侧的 chunk 读取器相应改成走 fn_read_dec（见 block_dec_readers）。
        // ⑤ 滚动层常数逐产物随机（正向这五个数在 Rust 侧，逆向在 Lua 读取器里
        // 两边由下面这组变量同时生成 —— 抓产物的人看到的是另一组数）
        let sc_add: u8 = (rng.range(0, 128) * 2 + 1) as u8; // 奇数 1..255
        let sc_rot_in: u32 = rng.range(1, 8) as u32;
        let sc_add_k1: u8 = rng.range(1, 8) as u8;
        let sc_mul_k2: u8 = rng.range(2, 8) as u8;
        let sc_rot_k2: u32 = rng.range(1, 8) as u32;
        let sc_rot_k4: u32 = rng.range(1, 8) as u32;
        for b in combined_payload[4..].iter_mut() {
            let orig = *b;
            *b = orig ^ k1; *b = b.wrapping_sub(k2); *b = b.rotate_left((k3 % 8) as u32); *b = *b ^ k4; *b = b.wrapping_add(sc_add);
            k1 = k1.wrapping_add(orig).rotate_left(sc_rot_in).wrapping_add(sc_add_k1);
            k2 = k2.wrapping_mul(sc_mul_k2).wrapping_add(*b).rotate_right(sc_rot_k2);
            k3 = k3 ^ k1.wrapping_sub(k4);
            k4 = k4.wrapping_add(k2).rotate_left(sc_rot_k4);
        }
        
        let key_kryvex = String::from("x1"); let p_out: Vec<String> = (0..6).map(|_| rng.name()).collect();
        let var_s = rng.name(); let fn_N_ = rng.name(); let var_fU = rng.name(); let var_L = rng.name(); let var_get_count = rng.name();
        let hex_select_idx = format!("0X{:X}", rng.range(10, 255));
        let var_state_flag = rng.name();
        let wai = rng.name();
        let mut header_block = String::new();
        header_block.push_str(&format!("return ({{ {} = function(agv,aggv,agv,agv,agv,aggv,agv,agv,aggv,aggv,aggv,agggv,agggv,agggv,agggv,aggv,{},{},{},{}, ...)\n", wai, p_out[0], p_out[1], p_out[2], p_out[3]));
        header_block.push_str(&format!("local {} = {{}}; local {} = false; ", var_s, var_state_flag));
        header_block.push_str(&format!("local {} = bit32 and bit32.rshift or bit and bit.rshift; ", var_fU));
        header_block.push_str(&format!("local {} = function(q, s, M, C) s[{}] = select; end; ", fn_N_, hex_select_idx));
        header_block.push_str(&format!("{}(nil, {}, nil, nil); ", fn_N_, var_s));
        
        // 8 个下标必须互不相同（撞车会让辅助表槽位互相覆盖），见 GenRng
        let idx = rng.distinct(8, 0x10, 0x7F);
        let keys = CipherKeys {
            grp1: idx[0],
            grp2: idx[1],
            key_bx: idx[2],
            key_ba: idx[3],
            key_add: idx[4],
            key_bs: idx[5],
            key_ba2: idx[6],
            key_bs2: idx[7],
            tbl_p: rng.name(),
        };

        let fn_bx = rng.name();
        let fn_ba = rng.name();
        let fn_bs = rng.name();
        let mut block_p_def = String::new();
        block_p_def.push_str(&format!("local {}={}; local {}={}; local {}={}; ", 
            fn_bx, "bit32 and bit32.bxor or bit and bit.bxor or function(a,b)local r,p=0,1;while a>0 or b>0 do local ra,rb=a%2,b%2;if ra~=rb then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end",
            fn_ba, "bit32 and bit32.band or bit and bit.band or function(a,b)local r,p=0,1;while a>0 and b>0 do local ra,rb=a%2,b%2;if ra==1 and rb==1 then r=r+p end;a,b,p=(a-ra)*0.5,(b-rb)*0.5,p+p end;return r end",
            fn_bs, "bit32 and bit32.rshift or bit and bit.rshift or function(a,n)local d=2^n return (a-a%d)/d end"
        ));
        let tbl_def = format!(
            "local {p}={{}};{p}[{g1}]={{}};{p}[{g1}][{bx}]={fbx};{p}[{g1}][{add}]=function(a,b)return a+b end;{p}[{g1}][{ba}]={fba};{p}[{g2}]={{}};{p}[{g2}][{ba2}]=function(a)return {fba}(a,{max_u32})end;{p}[{g2}][{bs2}]=function(a)return {fbs}(a,{one})end;",
            p = keys.tbl_p,
            g1 = rng.format_num(keys.grp1 as i64),
            g2 = rng.format_num(keys.grp2 as i64),
            bx = rng.format_num(keys.key_bx as i64),
            add = rng.format_num(keys.key_add as i64),
            ba = rng.format_num(keys.key_ba as i64),
            ba2 = rng.format_num(keys.key_ba2 as i64),
            bs2 = rng.format_num(keys.key_bs2 as i64),
            fbx = fn_bx,
            fba = fn_ba,
            fbs = fn_bs,
            max_u32 = rng.format_num(4294967295i64),
            one = rng.format_num(1i64)
        );
        block_p_def.push_str(&tbl_def);

        let block_vm_core = Lua_core::build_vm_core().replace("\n", " ");
        
        let (payload_str, decoder_script, entry_func) = Packer::pack(&combined_payload, &mut rng);
        let var_junk = rng.name(); let var_vc = rng.name(); let var_builtin_reg = rng.name();
        let block_packer_vars = format!("local {}, {}, {}; ", var_junk, var_vc, var_builtin_reg);

        let fn_execute = "execute";
        let var_pc = rng.name();
        let var_stk = rng.name();
        let var_top = rng.name();
        let var_inst = rng.name();
        let var_varargs = rng.name();
        let var_varargs_len = rng.name();
        let var_insts = rng.name();
        let var_opcodes = rng.name();
        let var_a_arr = rng.name();
        let var_b_arr = rng.name();
        let var_c_arr = rng.name();
        // 方法化 / 数据流：
        let var_consts = rng.name();
        let var_protos = rng.name();
        let var_upvals = rng.name();
        let var_env = rng.name();
        let var_vm = rng.name();      // VM 对象（方法 + 状态槽位都挂在它上面）
        let var_r1 = rng.name();
        let var_r2 = rng.name();
        let var_r3 = rng.name();
        let var_st = rng.name();      // 当前状态号
        let var_md = rng.name();      // 返回载荷模式
        let var_smap = rng.name();    // 操作码 → 状态号 映射表
        let fn_ret0 = rng.name();
        let fn_ret1 = rng.name();
        let fn_ret2 = rng.name();
        let var_methods = rng.name(); // 共享方法表（所有调用共用一个）
        let var_proto = rng.name();   // 状态对象的元表（__index → 方法表）
        let mut block_execute_def = String::new();
        
        let cfg = OpcodeConfig { pc: var_pc.clone(), stk: var_stk.clone(), consts: var_consts.clone(), top: var_top.clone(), insts: var_insts.clone(), inst: var_inst.clone(), upvals: var_upvals.clone(), env: var_env.clone(), protos: var_protos.clone(), handlers: String::new(), varargs: var_varargs.clone(), varargs_len: var_varargs_len.clone(), virtual_closures: var_vc.clone(), builtin_reg: var_builtin_reg.clone(), vararg_count: pf_vn.clone(), proto_nups: pf_nups.clone(), open_ups: pf_open_ups.clone(), ret0: format!("{}:{}", var_vm, fn_ret0), ret1: format!("{}:{}", var_vm, fn_ret1), ret2: format!("{}:{}", var_vm, fn_ret2) };
        let mut raw_handlers = Opcodes::generate_handlers(&mapped_opcodes, &fused_opcodes, &fused_used, &cfg, self.ctx.seed).replace("execute(", &format!("{}(", fn_execute));
        
        raw_handlers = raw_handlers.replace(
            &format!("{}[{}][1]", var_insts, var_pc),
            &format!("{}[{}]", var_opcodes, var_pc)
        ).replace(
            &format!("{}[{}][2]", var_insts, var_pc),
            &format!("{}[{}]", var_a_arr, var_pc)
        ).replace(
            &format!("{}[{}][3]", var_insts, var_pc),
            &format!("{}[{}]", var_b_arr, var_pc)
        ).replace(
            &format!("{}[{}][4]", var_insts, var_pc),
            &format!("{}[{}]", var_c_arr, var_pc)
        ).replace(
            &format!("{}[{}]", var_insts, var_pc),
            &format!("({{ {}[{}], {}[{}], {}[{}], {}[{}] }})", var_opcodes, var_pc, var_a_arr, var_pc, var_b_arr, var_pc, var_c_arr, var_pc)
        ).replace(
            &format!("{}[1]", var_inst), "op"
        ).replace(
            &format!("{}[2]", var_inst), "inst_A"
        ).replace(
            &format!("{}[3]", var_inst), "inst_B"
        ).replace(
            &format!("{}[4]", var_inst), "inst_C"
        ).replace(
            &var_inst, "({op, inst_A, inst_B, inst_C})"
        );

        // 返回协议：模板里的 {RET0}/{RET1}/{RET2} 换成 VM 对象上的钩子方法
        // （`:` 调用）。块被提升成方法后，`return` 只能返回给分发器，
        // 载荷放槽位里，由分发器决定真正返回什么。
        raw_handlers = raw_handlers
            .replace("{RET0}", &format!("self:{}", fn_ret0))
            .replace("{RET1}", &format!("self:{}", fn_ret1))
            .replace("{RET2}", &format!("self:{}", fn_ret2));

        if raw_handlers.trim_start().starts_with("if op") { raw_handlers = raw_handlers.replacen("if op", "elseif op", 1); }

        // handlers 成块：多个 op 共用一个方法（省体积）
        let mut parsed: Vec<(Vec<u32>, String)> = Vec::new();
        let mut remaining = raw_handlers.as_str();
        let mut current_ops: Vec<u32> = Vec::new(); let mut current_code = String::new();
        while let Some(idx) = remaining.find("elseif op") {
            let before = &remaining[..idx];
            if !current_ops.is_empty() {
                current_code.push_str(before); let code_str = current_code.trim().to_string();
                parsed.push((current_ops.clone(), code_str));
                current_code.clear();
            }
            remaining = &remaining[idx + 9..];
            if let Some(then_idx) = remaining.find("then") {
                let ops: Vec<u32> = remaining[..then_idx].split(|c: char| !c.is_numeric()).filter_map(|s| s.parse::<u32>().ok()).collect();
                if !ops.is_empty() { current_ops = ops; remaining = &remaining[then_idx + 4..]; } else { current_code.push_str("elseif op"); current_code.push_str(&remaining[..then_idx]); current_code.push_str("then"); remaining = &remaining[then_idx + 4..]; }
            }
        }
        if !current_ops.is_empty() {
            current_code.push_str(remaining); let code_str = current_code.trim().to_string();
            parsed.push((current_ops.clone(), code_str));
        }

        // 去重 + 分配随机方法名 / 随机状态号
        let mut blocks: Vec<(Vec<u32>, String, String, u32)> = Vec::new();
        let mut used_states: Vec<u32> = Vec::new();
        for (ops, code) in parsed {
            if let Some(b) = blocks.iter_mut().find(|b| b.1 == code) { b.0.extend(ops); continue; }
            let name = rng.name();
            let st = loop {
                let v = rng.range(0x0100_0000, 0x7FFF_0000) as u32;
                if !used_states.contains(&v) { used_states.push(v); break v; }
            };
            blocks.push((ops, code, name, st));
        }

        // ① 方法化 + ② 数据流打乱
        // 而是按随机槽位号从 VM 对象里取自己的那份状态，出口再写回
        // 每个块的局部别名逐块新取，同一个逻辑变量跨块看到的不是同一个名字
        // ④ 槽位号不再写死在产物里
        // `GenRng::slot_key_block`）。这里拿到的全是**局部名字**，插值进 Lua 源码
        let (sk, sk_setup) = rng.slot_key_block(20);
        let k_pc = sk[0].clone(); let k_stk = sk[1].clone(); let k_top = sk[2].clone();
        let k_ops = sk[3].clone(); let k_aa = sk[4].clone(); let k_bb = sk[5].clone(); let k_cc = sk[6].clone();
        let k_consts = sk[7].clone(); let k_protos = sk[8].clone();
        let k_upv = sk[9].clone(); let k_env = sk[10].clone();
        let k_va = sk[11].clone(); let k_valen = sk[12].clone();
        let k_vc = sk[13].clone(); let k_breg = sk[14].clone();
        let k_state = sk[15].clone(); let k_mode = sk[16].clone();
        let k_retv = sk[17].clone(); let k_retf = sk[18].clone(); let k_rett = sk[19].clone();

        // 表类状态按块取一次（表是引用，不需要写回）
        // 直接把槽位表达式替换进块体 —— 就地读写，不依赖出口写回
        // （Lua 的 `return` 必须是块的最后一条语句，写回语句没法追加在它后面）
        let state_fields: Vec<(String, String, bool)> = vec![
            (var_opcodes.clone(), k_ops.clone(), false),
            (var_a_arr.clone(), k_aa.clone(), false),
            (var_b_arr.clone(), k_bb.clone(), false),
            (var_c_arr.clone(), k_cc.clone(), false),
            (var_stk.clone(), k_stk.clone(), false),
            (var_consts.clone(), k_consts.clone(), false),
            (var_protos.clone(), k_protos.clone(), false),
            (var_upvals.clone(), k_upv.clone(), false),
            (var_env.clone(), k_env.clone(), false),
            (var_varargs.clone(), k_va.clone(), false),
            (var_varargs_len.clone(), k_valen.clone(), false),
            (var_vc.clone(), k_vc.clone(), false),
            (var_builtin_reg.clone(), k_breg.clone(), false),
        ];
        let mut defs: Vec<String> = Vec::new();
        let mut tree_entries: Vec<(u32, String)> = Vec::new();
        // 热块内联时要用的状态名 → 槽位号（驱动里声明成局部变量）
        let mut hot_locals: Vec<(String, String)> = Vec::new();
        for (ops, code, name, st) in blocks.iter() {
            let st_lua = rng.format_num(*st as i64);
            // 预算：热路径（算术/比较/跳转/栈与表存取）保留**内联**，冷路径
            // （调用/返回/闭包/全局/上值/内建）才提升成方法。全量方法化会把每条
            // 指令都变成一次 Lua 函数调用 —— 实测慢 5.6 倍，超出预算
            let cold = uses_ident(code, &var_vc)
                || uses_ident(code, &var_builtin_reg)
                || uses_ident(code, &var_env)
                || uses_ident(code, &var_protos)
                || uses_ident(code, &var_varargs)
                || code.contains(&pf_open_ups)
                || code.contains("zm(")
                || code.contains(&format!("{}(", fn_execute));
            if cold {
                let mut body = code.clone();
                // 标量状态：槽位表达式就地替换（pc/top 的读写直接落在 VM 对象上）
                body = rename_ident(&body, &var_pc, &format!("self[{}]", k_pc));
                body = rename_ident(&body, &var_top, &format!("self[{}]", k_top));
                // CLOSURE 模板里有字面量 env（内层闭包用），方法表是共享的
                // 必须走槽位拿当前调用的环境，不能捕获第一次调用的 env
                body = rename_ident(&body, "env", &format!("self[{}]", k_env));
                let mut fetch = String::new();
                for (old, key, _mutable) in state_fields.iter() {
                    if !uses_ident(&body, old) { continue; }
                    let alias = rng.name();
                    body = rename_ident(&body, old, &alias);
                    fetch.push_str(&format!("local {}={}[{}];", alias, "self", key));
                }
                body = body.replace("{STOREBACK}", "");
                let mut text = String::from("local rk1,rk2;");
                // 状态号自校验：分发器刚把本块的状态号写进槽位，对不上说明跳错了块
                text.push_str(&format!("if self[{}]~={} then return end;", k_state, st_lua));
                text.push_str(&fetch);
                text.push_str(&body);
                // 必须用 `.名字=function` 注册
                // 成员名统一改名时字符串键不改，两边对不上变 nil。
                defs.push(format!("{}.{}=function(self,op,inst_A,inst_B,inst_C) {} end;", var_methods, name, text));
                // 冷路径才付同步代价：进出方法前后各存/取一次 pc 与 top
                // 并把本块状态号写进槽位（方法入口自校验）。
                let leaf = format!(
                    "{}[{}]={};{}[{}]={};{}[{}]={};{},{},{}={}:{}(op,inst_A,inst_B,inst_C);{}={}[{}];{}={}[{}]",
                    var_vm, k_pc, var_pc, var_vm, k_top, var_top, var_vm, k_state, st_lua,
                    var_r1, var_r2, var_r3, var_vm, name,
                    var_pc, var_vm, k_pc, var_top, var_vm, k_top
                );
                for &op in ops.iter() {
                    tree_entries.push((op, leaf.clone()));
                }
            } else {
                // 热块完全内联：pc/top/栈 都是 execute 的局部变量，和基线一样快
                // 冷块调用前后由调用点负责把 pc/top 同步进/出 VM 对象的槽位
                let body = code.replace("{STOREBACK}", "").replace("self:", &format!("{}:", var_vm));
                for (old, key, _mutable) in state_fields.iter() {
                    if uses_ident(&body, old) && !hot_locals.iter().any(|(n, _)| n == old) {
                        hot_locals.push((old.clone(), key.clone()));
                    }
                }
                for &op in ops.iter() {
                    tree_entries.push((op, body.clone()));
                }
            }
        }
        // ③ 随机代码块分配：注册顺序打乱，分发树按**状态号**（随机大整数）路由
        rng.shuffle(&mut defs);
        tree_entries.sort_by_key(|e| e.0);

        // 这几个哨兵常量在**每次 VM 调用**和**每次 return** 时都要重新求值（下面的
        // execute 前导 + 三个返回钩子 + 返回分派）。按用户要求，一律走 obfuscate_num
        // 的位运算风格（`V[a][b](x,y)`），不为了热路径换成简单表达式。
        let obf0 = rng.obfuscate_num(0i64, 1, &keys);
        let obf1 = rng.obfuscate_num(1i64, 1, &keys);
        let obf2 = rng.obfuscate_num(2i64, 1, &keys);

        // 方法表必须建在 execute **外面**：execute 每次调用都跑一遍，
        // 在里面定义 60 个闭包会让每次函数调用都重建一遍方法表（实测慢 2.5 倍）
        // 状态对象每个调用一个，方法通过 __index 原型共享，调用仍是 `V
        let mut block_methods = String::new();
        block_methods.push_str(&format!("local {}; ", fn_execute));
        let (h0, h1) = crate::VM::VM_Backend::Generator_util::stream_key("#", &mut rng);
        let sc_hash = at.st.call("#", h0, h1);
        block_methods.push_str(&format!("local {} = function(...) return {}[{}]({}, ...) end; ", var_get_count, var_s, hex_select_idx, sc_hash));
        block_methods.push_str(&format!("local unpack, zm = unpack or table and table.unpack or function() end, function(...) return {{{}={}(...),...}} end; ", pf_vn, var_get_count));
        block_methods.push_str(&format!("local {}={{}};local {}={{}};", var_methods, var_proto));
        for d in defs.iter() { block_methods.push_str(d); block_methods.push(' '); }
        let (ix0, ix1) = crate::VM::VM_Backend::Generator_util::stream_key("__index", &mut rng);
        let sc_index = at.st.call("__index", ix0, ix1);
        block_methods.push_str(&format!("{}[{}]={};", var_proto, sc_index, var_methods));

        block_execute_def.push_str(&format!("{} = function(chunk, env, upvals, ...) ", fn_execute));
        block_execute_def.push_str(&format!("local {} = {}(...); ", var_L, var_get_count));
        block_execute_def.push_str(&format!("local {} = setmetatable({{}}, {}); ", var_vm, var_proto));
        block_execute_def.push_str(&format!("{}[{}]={};{}[{}]={{}};{}[{}]={};", var_vm, k_pc, obf1, var_vm, k_stk, var_vm, k_top, obf0));
        block_execute_def.push_str(&format!("{}[{}]=chunk.{};{}[{}]=chunk.{};{}[{}]=chunk.{};{}[{}]=chunk.{};", var_vm, k_ops, pf_opcodes, var_vm, k_aa, pf_a_arr, var_vm, k_bb, pf_b_arr, var_vm, k_cc, pf_c_arr));
        block_execute_def.push_str(&format!("{}[{}]=chunk.{};{}[{}]=chunk.{};", var_vm, k_consts, pf_consts, var_vm, k_protos, pf_protos));
        block_execute_def.push_str(&format!("{}[{}]=upvals;{}[{}]=env;{}[{}]={};{}[{}]={};", var_vm, k_upv, var_vm, k_env, var_vm, k_vc, var_vc, var_vm, k_breg, var_builtin_reg));
        block_execute_def.push_str(&format!("for _=1,chunk.{} do {}[{}][_-1] = {}[{}](_,...) end; ", pf_numparams, var_vm, k_stk, var_s, hex_select_idx));
        block_execute_def.push_str(&format!("local {} = {} - chunk.{}; local {} = {{{}[{}](chunk.{} + 1, ...)}}; ", var_varargs_len, var_L, pf_numparams, var_varargs, var_s, hex_select_idx, pf_numparams));
        block_execute_def.push_str(&format!("{}[{}]={};{}[{}]={};", var_vm, k_va, var_varargs, var_vm, k_valen, var_varargs_len));
        block_execute_def.push_str(&format!("{}[{}]={};{}[{}]={};{}[{}]=nil;{}[{}]={};{}[{}]={};", var_vm, k_state, obf0, var_vm, k_mode, obf0, var_vm, k_retv, var_vm, k_retf, obf0, var_vm, k_rett, obf0));
        // 热块内联时用到的状态
        if !hot_locals.is_empty() {
            // 注意：Lua 里一个 local 只能有一个 `=`，必须写成
            // `local a,b; a,b=V[k1],V[k2];`（不能写 `local a=V[k1],b=V[k2]`）
            let names: Vec<String> = hot_locals.iter().map(|(n, _)| n.clone()).collect();
            let vals: Vec<String> = hot_locals.iter().map(|(_, k)| format!("{}[{}]", var_vm, k)).collect();
            block_execute_def.push_str(&format!("local {};{}={};", names.join(","), names.join(","), vals.join(",")));
        }
        // 返回钩子也是方法（挂在共享方法表上），块里用 `:` 调
        block_methods.push_str(&format!("{}.{}=function(self)self[{}]={};return true end;", var_methods, fn_ret0, k_mode, obf0));
        block_methods.push_str(&format!("{}.{}=function(self,v)self[{}]={};self[{}]=v;return true end;", var_methods, fn_ret1, k_mode, obf1, k_retv));
        block_methods.push_str(&format!("{}.{}=function(self,t,f,l)self[{}]={};self[{}]=t;self[{}]=f;self[{}]=l;return true end;", var_methods, fn_ret2, k_mode, obf2, k_retv, k_retf, k_rett));



        // 数组槽位只读一次（热路径每指令都读会白花 4 次哈希查找）
        let arrs = format!("{}, {}, {}, {}", var_opcodes, var_a_arr, var_b_arr, var_c_arr);
        block_execute_def.push_str(&format!("local {};{}={}[{}],{}[{}],{}[{}],{}[{}];", arrs, arrs, var_vm, k_ops, var_vm, k_aa, var_vm, k_bb, var_vm, k_cc));
        // pc/top 是**循环外**的局部变量
        // 冷块调用前后由调用点负责与 VM 对象的槽位同步。
        block_execute_def.push_str(&format!("local {},{}={}[{}],{}[{}];", var_pc, var_top, var_vm, k_pc, var_vm, k_top));

        if tree_entries.is_empty() {
            // 理论上不会发生（没有任何 handler）
            block_execute_def.push_str("while true do break end end ");
        } else {
            block_execute_def.push_str("while true do ");
            block_execute_def.push_str(&format!("{}={};", var_state_flag, "true"));

            block_execute_def.push_str(&format!("local op={}[{}];", var_opcodes, var_pc));
            block_execute_def.push_str(&format!("local inst_A={}[{}];", var_a_arr, var_pc));
            block_execute_def.push_str(&format!("local inst_B={}[{}];", var_b_arr, var_pc));
            block_execute_def.push_str(&format!("local inst_C={}[{}];", var_c_arr, var_pc));
            // 热路径：pc 就是普通局部变量，推进也用普通字面量
            block_execute_def.push_str(&format!("{}={}+1;", var_pc, var_pc));

            block_execute_def.push_str(&format!("local rk1,rk2;local {},{},{};", var_r1, var_r2, var_r3));
            block_execute_def.push_str(&build_opcode_tree(&tree_entries, 0, tree_entries.len() - 1, "op", &keys, &mut rng));
            block_execute_def.push_str(&format!("if {} then local {}={}[{}]; if {}=={} then return {}[{}] elseif {}=={} then return unpack({}[{}],{}[{}],{}[{}]) end; return end;", var_r1, var_md, var_vm, k_mode, var_md, obf1, var_vm, k_retv, var_md, obf2, var_vm, k_retv, var_vm, k_retf, var_vm, k_rett));
            block_execute_def.push_str(&format!("{}={};", var_state_flag, "false"));
            block_execute_def.push_str("end end ");
        }

        let block_decoder_script = decoder_script.replace("\n", " ");
        
        let var_idx = rng.name(); let var_b = rng.name(); let var_tamper = rng.name(); let fn_s_byte = rng.name(); let fn_s_sub = rng.name(); let var_raw_p = rng.name(); let var_chk = rng.name(); let var_p = rng.name(); let var_a2 = rng.name(); let fn_a3 = rng.name(); let x = rng.name(); let var__a = rng.name(); let var__b = rng.name(); let fn_read_dec = rng.name(); let fn_bxor = rng.name(); let fn_b_rotr = rng.name(); let fn_a5 = rng.name(); let fn_read_string = rng.name(); let fn_a10 = rng.name(); let fn_dec_num = rng.name(); let fn_dec_str = rng.name(); let global_strings = rng.name(); let global_numbers = rng.name(); let fn_decode_chunk = rng.name(); let fn_u32_dec = rng.name(); let l = rng.name(); let s_t = rng.name(); let v = rng.name(); let v_sign = rng.name(); let v_exp = rng.name(); let v_mant = rng.name(); let t = rng.name(); let fn_c = rng.name();
        let var_boot_env = rng.name(); let var_bname = rng.name();

        let fn_qr = rng.name();
        let fn_xor32 = rng.name();
        let fn_rotl32 = rng.name();
        let fn_chacha_block = rng.name();
        let fn_chacha_stream = rng.name();
        let xor_tbl_var = rng.name();
        let chacha_key_var = rng.name();
        let chacha_salt_var = rng.name();
        let kind_str_obf = rng.obfuscate_num(0i64, 1, &keys);
        let kind_num_obf = rng.obfuscate_num(1i64, 1, &keys);
        let chacha_key_lua = (0..8).map(|i| rng.obfuscate_num(chacha_key[i] as i64, 1, &keys)).collect::<Vec<_>>().join(",");
        let chacha_salt_lua = rng.obfuscate_num(chacha_salt as i64, 1, &keys);

        // ChaCha 的 4 个 sigma 常量（"expand 32-byte k"）不再以字面量出现在产物里
        // 改成逐产物派生：sigma_i = (d_i + K[idx_i]) mod 2^32，其中
        // d_i = sigma_i - K[idx_i]（wrapping_sub），K 就是下面那份随机 key 的 Lua 表
        // idx 打乱(3,7,2,6)：恢复式与 K 排列不对应，静态看不出原值。
        let sigma: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
        let sig_idx: [usize; 4] = [3, 7, 2, 6];
        let sigma_lua = (0..4)
            .map(|i| {
                let d = sigma[i].wrapping_sub(chacha_key[sig_idx[i] - 1]);
                format!("(({}+K[{}])%4294967296)", rng.obfuscate_num(d as i64, 1, &keys), sig_idx[i])
            })
            .collect::<Vec<_>>()
            .join(",");

        let mut block_chacha_setup = String::new();
        block_chacha_setup.push_str(&format!(
            "local {xt}={{}}; for a=0,255 do local row={{}}; for b=0,255 do local x,y,r,p=a,b,0,1; while x>0 or y>0 do local rx,ry=x%2,y%2; if rx~=ry then r=r+p end; x,y,p=math_floor(x/2),math_floor(y/2),p*2 end; row[b]=r end; {xt}[a]=row end; ",
            xt = xor_tbl_var
        ));
        block_chacha_setup.push_str(&format!(
            "local function {xor32}(a,b) local a1,a2,a3,a4=a%256,math_floor(a/256)%256,math_floor(a/65536)%256,math_floor(a/16777216)%256; local b1,b2,b3,b4=b%256,math_floor(b/256)%256,math_floor(b/65536)%256,math_floor(b/16777216)%256; return {xt}[a1][b1]+{xt}[a2][b2]*256+{xt}[a3][b3]*65536+{xt}[a4][b4]*16777216 end; ",
            xor32 = fn_xor32, xt = xor_tbl_var
        ));
        block_chacha_setup.push_str(&format!(
            "local function {rotl32}(x,n) local m=2^n; return ((x*m)%4294967296)+math_floor(x/(4294967296/m)) end; ",
            rotl32 = fn_rotl32
        ));
        block_chacha_setup.push_str(&format!(
            "local function {qr}(s,a,b,c,d) s[a]=(s[a]+s[b])%4294967296; s[d]={xor32}(s[d],s[a]); s[d]={rotl32}(s[d],16); s[c]=(s[c]+s[d])%4294967296; s[b]={xor32}(s[b],s[c]); s[b]={rotl32}(s[b],12); s[a]=(s[a]+s[b])%4294967296; s[d]={xor32}(s[d],s[a]); s[d]={rotl32}(s[d],8); s[c]=(s[c]+s[d])%4294967296; s[b]={xor32}(s[b],s[c]); s[b]={rotl32}(s[b],7) end; ",
            qr = fn_qr, xor32 = fn_xor32, rotl32 = fn_rotl32
        ));
        block_chacha_setup.push_str(&format!(
            "local {ckey}={{{key_lua}}}; local {csalt}={salt_lua}; ",
            ckey = chacha_key_var, key_lua = chacha_key_lua, csalt = chacha_salt_var, salt_lua = chacha_salt_lua
        ));
        block_chacha_setup.push_str(&format!(
            "local function {cblock}(n1,n2,n3,ctr) local K={ckey}; local s={{{sig},K[1],K[2],K[3],K[4],K[5],K[6],K[7],K[8],ctr,n1,n2,n3}}; local o={{}}; for i=1,16 do o[i]=s[i] end; for _=1,4 do {qr}(s,1,5,9,13); {qr}(s,2,6,10,14); {qr}(s,3,7,11,15); {qr}(s,4,8,12,16); {qr}(s,1,6,11,16); {qr}(s,2,7,12,13); {qr}(s,3,8,9,14); {qr}(s,4,5,10,15) end; local out={{}}; for i=1,16 do local w=(s[i]+o[i])%4294967296; out[(i-1)*4+1]=w%256; out[(i-1)*4+2]=math_floor(w/256)%256; out[(i-1)*4+3]=math_floor(w/65536)%256; out[(i-1)*4+4]=math_floor(w/16777216)%256 end; return out end; ",
            cblock = fn_chacha_block, ckey = chacha_key_var, qr = fn_qr, sig = sigma_lua
        ));
        block_chacha_setup.push_str(&format!(
            "local function {cstream}(pool_idx,kind,n) local out={{}}; local ctr=0; local pos=1; while pos<=n do local blk={cblock}({csalt},pool_idx,kind,ctr); for i=1,64 do if pos>n then break end; out[pos]=blk[i]; pos=pos+1 end; ctr=ctr+1 end; return out end; ",
            cstream = fn_chacha_stream, cblock = fn_chacha_block, csalt = chacha_salt_var
        ));
        
        let (fh0, fh1) = crate::VM::VM_Backend::Generator_util::stream_key("function", &mut rng);
        let sc_fn_hdr = at.st.call("function", fh0, fh1);
        let (md0, md1) = crate::VM::VM_Backend::Generator_util::stream_key("__mode", &mut rng);
        let sc_mode = at.st.call("__mode", md0, md1);
        let (mk0, mk1) = crate::VM::VM_Backend::Generator_util::stream_key("k", &mut rng);
        let sc_k = at.st.call("k", mk0, mk1);
        let block_dec_header = format!("local {}, {} = {}, {}; local {} = ([=[KRYVEX{}]=]); local {}, {}, {} = {}, {}, {}; repeat local {}={}({},{}); {}={}+{}; {}={}+{}; {}={}+({}%{}); until {}>={}; {} = ({}-{}) + ({}-{}); {}={}+(type({})=={fn_lit} and 0 or {}); local mt_vc={{}}; mt_vc[{mode_lit}]={k_lit}; {} = setmetatable({{}}, mt_vc); local {}, {} = {}({}({},{}+{}*{})), {}; local function {}() local {}={}({},{},{}); {}={}+{}; return {} end; local k1,k2,k3,k4 = {}(),{}(),{}(),{}(); ", fn_s_byte, fn_s_sub, "string_byte", "string_sub", var_raw_p, payload_str, var_chk, var_idx, var_junk, rng.obfuscate_num(0i64, 1, &keys), rng.obfuscate_num(1i64, 1, &keys), rng.obfuscate_num(0i64, 1, &keys), var_b, fn_s_byte, var_raw_p, var_idx, var_chk, var_chk, var_b, var_idx, var_idx, rng.obfuscate_num(1i64, 1, &keys), var_junk, var_junk, var_b, rng.obfuscate_num(2i64, 1, &keys), var_idx, rng.obfuscate_num(7i64, 1, &keys), var_tamper, var_chk, var_chk, var_junk, var_junk, var_tamper, var_tamper, fn_s_byte, rng.obfuscate_num(73i64, 1, &keys), var_vc, var_p, var_a2, entry_func, fn_s_sub, var_raw_p, var_idx, var_tamper, rng.obfuscate_num(1337i64, 2, &keys), rng.obfuscate_num(1i64, 1, &keys), fn_a3, x, fn_s_byte, var_p, var_a2, var_a2, var_a2, var_a2, rng.obfuscate_num(1i64, 1, &keys), x, fn_a3, fn_a3, fn_a3, fn_a3,
            fn_lit = sc_fn_hdr, mode_lit = sc_mode, k_lit = sc_k);
        // ── 解码链（第 6 项：解密逻辑打乱）──
        // 冷路径一次性函数，放心打乱形态。
        let (v_bx_a, v_bx_b, v_bx_r, v_bx_w, v_bx_g, v_bx_s) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (v_rt_x, v_rt_n, v_rt_d, v_rt_g, v_rt_t) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        let (v_rd_o, v_rd_g, v_rd_e) = (rng.name(), rng.name(), rng.name());
        let (v_rd_c1, v_rd_c2, v_rd_c3, v_rd_c4, v_rd_c5) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name());

        // 注意：产物里的 k1..k4 是固定局部名，模板里只能写裸标识符 k1 —— 写成 {k1}
        // 会被 format! 隐式捕获抓走同名生成器变量（产物语法错）；
        // 同理 Lua 的空表要写 {{}}，裸 {} 是位置参数占位符。
        // 原形态：逐位比较累权重、n==0早返回右移、滚动密钥顺序赋值
        // 现在：位异或写成 (xa+xb)%2 乘权重、右移用 256/2^n 代 2^(8-n) 去早返回
        // 解密链拆 5 个中间变量、密钥演化换等价变形（-229 代 +27、
        // (v-v%d)/d 代 floor、k2*2+k2 代 k2*3，包单次循环+影子计数器。
        let block_dec_helpers = format!(
            "local function {bx}({a},{b}) local {r},{w},{g},{s}=0,1,0,0; \
             while {g}<({r}-{r})+1 do \
             if {a}<=0 and {b}<=0 then {g}={g}+1 else \
             {s}=(({a}%2)+({b}%2))%2; {r}={r}+{s}*{w}; \
             {a}=({a}-({a}%2))/2; {b}=({b}-({b}%2))/2; {w}={w}+{w}; end end; \
             return {r} end; \
             local function {rt}({x},{n}) local {d},{g},{t}=2^{n},0,0; \
             while {g}<({t}-{t})+1 do \
             {t}=(({x}*(256/{d}))%256)+(({x}-({x}%{d}))/{d}); {g}={g}+1; end; \
             return {t} end; \
             {rd_scatter} ",
            bx = fn_bxor, a = v_bx_a, b = v_bx_b, r = v_bx_r, w = v_bx_w, g = v_bx_g, s = v_bx_s,
            rt = fn_b_rotr, x = v_rt_x, n = v_rt_n, d = v_rt_d, t = v_rt_t,
            rd_scatter = {
                // ──⑥ 滚动读取器打散
                // 真实顺序只在键名/调度表
                // 循环壳与假出口逐产物随机 —— 静态读产物看不出解密链
                // 铁律：k1 吃解后字节、k2 吃原始字节、k34 最后跑。
                // 键用随机整数（不引入新名字——未声明的标识符在 Lua 里是全局 nil
                // aE[名字]=… 直接 table index is nil）
                let mut ikeys: Vec<u32> = Vec::new();
                while ikeys.len() < 7 {
                    let k = rng.range(1, 100) as u32;
                    if !ikeys.contains(&k) { ikeys.push(k); }
                }
                let (d1, d2, d3, d4) = (ikeys[0], ikeys[1], ikeys[2], ikeys[3]);
                let (u1, u2, u34) = (ikeys[4], ikeys[5], ikeys[6]);
                let inv_add_v = 256 - sc_add as i32;
                let mut defs = vec![
                    format!("{}[{}]=function(e) return (e+{})%256 end; ", v_rd_c4, d1, inv_add_v),
                    format!("{}[{}]=function(e) return {}(e,k4) end; ", v_rd_c4, d2, fn_bxor),
                    format!("{}[{}]=function(e) return {}(e,k3%8) end; ", v_rd_c4, d3, fn_b_rotr),
                    format!("{}[{}]=function(e) return {}((e+k2)%256,k1) end; ", v_rd_c4, d4, fn_bxor),
                    format!("{}[{}]=function(e) k1=(k1+e)%256; k1=((k1*{})%256)+((k1-(k1%{}))/{}); k1=(k1+{})%256 end; ",
                        v_rd_c4, u1, 1u32 << sc_rot_in, 1u32 << (8 - sc_rot_in), 1u32 << (8 - sc_rot_in), sc_add_k1),
                    format!("{}[{}]=function(e) k2=(k2*{}+e)%256; k2=((k2*{})%256)+((k2-(k2%{}))/{}); end; ",
                        v_rd_c4, u2, sc_mul_k2, 1u32 << (8 - sc_rot_k2), 1u32 << sc_rot_k2, 1u32 << sc_rot_k2),
                    format!("{}[{}]=function() k3={}(k3,(k1-k4+256)%256); k4=(k4+k2)%256; k4=((k4*{})%256)+((k4-(k4%{}))/{}); end; ",
                        v_rd_c4, u34, fn_bxor, 1u32 << sc_rot_k4, 1u32 << (8 - sc_rot_k4), 1u32 << (8 - sc_rot_k4)),
                ];
                rng.shuffle(&mut defs);
                let (fupd, farg, supd, sarg) = if rng.range(0, 2) == 0 {
                    (u1.clone(), v_rd_c1.clone(), u2.clone(), v_rd_e.clone())
                } else {
                    (u2.clone(), v_rd_e.clone(), u1.clone(), v_rd_c1.clone())
                };
                let (s0, sl) = [(0i32, 1i32), (5, 6), (17, 18), (-3, -2)][rng.range(0, 4)];
                let big = rng.range(9, 99);
                let mut lua = format!("local {}={{}}", v_rd_c4);
                for d in &defs { lua.push_str(d); }
                // 调度表：键序即执行序 —— 键是随机名，静态看不出对应哪步
                lua.push_str(&format!("local {}={{{},{},{},{}}}; ", v_rd_c5, d1, d2, d3, d4));
                let chain = format!(
                    "local {e}={raw} local {j}=1 while {j}<=4 do {e}={st}[{seq}[{j}]]({e}) {j}={j}+1 end {o}={e} ",
                    e = v_rd_c1, raw = v_rd_e, j = v_rd_c2, st = v_rd_c4, seq = v_rd_c5, o = v_rd_o
                );
                let upds = format!(
                    "{st}[{fu}]({fa}) {st}[{su}]({sa}) {st}[{u34}]() ",
                    st = v_rd_c4, fu = fupd, fa = farg, su = supd, sa = sarg, u34 = u34
                );
                let (open, close, inc) = match rng.range(0, 3) {
                    0 => (
                        format!("local {g}={s0} while {g}<{sl} do ", g = v_rd_c3, s0 = s0, sl = sl),
                        "end; ".to_string(),
                        format!("{g}={g}+1; ", g = v_rd_c3),
                    ),
                    1 => (
                        format!("local {g}={s0} repeat ", g = v_rd_c3, s0 = s0),
                        format!("until {g}>={sl} ", g = v_rd_c3, sl = sl),
                        format!("{g}={g}+1; ", g = v_rd_c3),
                    ),
                    _ => (
                        format!("for {g}={s0},{s1} do ", g = v_rd_c3, s0 = s0, s1 = s0),
                        "end; ".to_string(),
                        String::new(),
                    ),
                };
                let fake = if inc.is_empty() { String::new() } else {
                    format!("if {g}>{big} then {g}={sl} end; ", g = v_rd_c3, big = big, sl = sl)
                };
                lua.push_str(&format!(
                    "local function {rd}() local {o}=0; {open}local {raw}={a3}() {chain}{upds}{fake}{inc}{close}return {o} end; ",
                    rd = fn_read_dec, o = v_rd_o, open = open, raw = v_rd_e, a3 = fn_a3,
                    chain = chain, upds = upds, fake = fake, inc = inc, close = close
                ));
                lua
            }
        );
        // 形态1~5共享件：K表=魔数派生源；PJ=恒空谓词表
        let (kt_name, pj_name) = (rng.name(), rng.name());
        let kv: [i64; 9] = loop {
            let mut kv = [0i64; 9];
            for i in 0..9 { kv[i] = rng.range(1 << 20, (1 << 24) - 1) as i64; }
            let g = |i: usize, j: usize, add: bool| -> i64 {
                if add { kv[i] + kv[j] } else if kv[i] >= kv[j] { kv[i] - kv[j] } else { kv[j] - kv[i] }
            };
            let mut vs = vec![
                g(0, 1, false), g(2, 3, true), g(4, 5, false), g(6, 7, true),
                g(8, 2, true), g(7, 4, false), g(5, 3, true),
                g(2, 5, true), g(3, 6, true), g(1, 5, true), g(0, 6, true), g(7, 2, true),
            ];
            vs.sort(); vs.dedup();
            if vs.len() == 12 { break kv; }
        };
        let kspell: Vec<String> = (0..9)
            .map(|i| if rng.range(0, 2) == 0 { format!("0X{:X}", kv[i]) } else { format!("{}", kv[i]) })
            .collect();
        fn kval(kv: &[i64; 9], i: usize, j: usize, add: bool) -> i64 {
            if add { kv[i] + kv[j] } else if kv[i] >= kv[j] { kv[i] - kv[j] } else { kv[j] - kv[i] }
        }
        fn kexpr(kt: &str, kv: &[i64; 9], i: usize, j: usize, add: bool) -> String {
            if add { format!("{0}[{1}]+{0}[{2}]", kt, i + 1, j + 1) }
            else if kv[i] >= kv[j] { format!("{0}[{1}]-{0}[{2}]", kt, i + 1, j + 1) }
            else { format!("{0}[{2}]-{0}[{1}]", kt, i + 1, j + 1) }
        }
        let (m_a, e_a) = (kval(&kv, 0, 1, false), kexpr(&kt_name, &kv, 0, 1, false));
        let (m_b, e_b) = (kval(&kv, 2, 3, true), kexpr(&kt_name, &kv, 2, 3, true));
        let (m_c, e_c) = (kval(&kv, 4, 5, false), kexpr(&kt_name, &kv, 4, 5, false));
        let (m_d, e_d) = (kval(&kv, 6, 7, true), kexpr(&kt_name, &kv, 6, 7, true));
        let (h_ka, e_ka) = (kval(&kv, 8, 2, true), kexpr(&kt_name, &kv, 8, 2, true));
        let (h_kb, e_kb) = (kval(&kv, 7, 4, false), kexpr(&kt_name, &kv, 7, 4, false));
        let (h_kc, e_kc) = (kval(&kv, 5, 3, true), kexpr(&kt_name, &kv, 5, 3, true));
        // HH 码同走 K 派生
        let (hh_ret, eh_ret) = (kval(&kv, 2, 5, true), kexpr(&kt_name, &kv, 2, 5, true));
        let (hh_nil, eh_nil) = (kval(&kv, 3, 6, true), kexpr(&kt_name, &kv, 3, 6, true));
        let (hh_next, eh_next) = (kval(&kv, 1, 5, true), kexpr(&kt_name, &kv, 1, 5, true));
        let (hh_val, eh_val) = (kval(&kv, 0, 6, true), kexpr(&kt_name, &kv, 0, 6, true));
        let (hh_fail, eh_fail) = (kval(&kv, 7, 2, true), kexpr(&kt_name, &kv, 7, 2, true));
        let (v_u32_t, v_u32_n, v_u32_i, v_u32_v) = (rng.name(), rng.name(), rng.name(), rng.name());
        let (v_a5_t, v_a5_n, v_a5_i) = (rng.name(), rng.name(), rng.name());
        let (v_rs_l, v_rs_t, v_rs_i) = (rng.name(), rng.name(), rng.name());
        let (v_a10_v, v_a10_h) = (rng.name(), rng.name());

        // 原形态：for 循环按 1..4 读、再按固定顺序累加、权重全是十进制常量
        // 现在：while + 显式自增下标、累加项顺序打乱（整数加法精确，顺序无影响）
        // 权重换 2^8/2^16/2^24 与自减零初值、零长度短路、有符号转换改形
        let block_dec_readers = format!(
            "{u32_family} ",
            u32_family = {
                // u32 读取族打散；铁律
                fn combine_u32(b: [&str; 4], rng: &mut GenRng) -> String {
                    match rng.range(0, 3) {
                        0 => {
                            // 霍纳（高字节在前进）：(((b4*W+b3)*W+b2)*W+b1)
                            let w = if rng.range(0, 2) == 0 { "256" } else { "2^8" };
                            format!("((({x}*{w}+{y})*{w}+{z})*{w}+{r})", x = b[3], y = b[2], z = b[1], r = b[0], w = w)
                        }
                        1 => {
                            // 双 u16 段拼：lo=b1+b2*W、hi=b3+b4*W，段权 W16
                            let w1 = if rng.range(0, 2) == 0 { "256" } else { "2^8" };
                            let w2 = if rng.range(0, 2) == 0 { "65536" } else { "2^16" };
                            let lo = format!("({}+{}*{})", b[0], b[1], w1);
                            let hi = format!("({}+{}*{})", b[2], b[3], w1);
                            if rng.range(0, 2) == 0 { format!("{}+{}*{}", lo, hi, w2) } else { format!("{}*{}+{}", hi, w2, lo) }
                        }
                        _ => {
                            // 乱序加权和：权重拼写独立、项序洗牌、累加起点换随机零种子
                            let w8 = if rng.range(0, 2) == 0 { "256" } else { "2^8" };
                            let w16 = if rng.range(0, 2) == 0 { "65536" } else { "2^16" };
                            let w24 = ["16777216", "2^24", "2^16*256"][rng.range(0, 3)];
                            let mut terms = vec![
                                b[0].to_string(),
                                format!("{}*{}", b[1], w8),
                                format!("{}*{}", b[2], w16),
                                format!("{}*{}", b[3], w24),
                            ];
                            rng.shuffle(&mut terms);
                            let seed = match rng.range(0, 3) {
                                0 => "0".to_string(),
                                1 => format!("({}-{})", b[1], b[1]),
                                _ => format!("({}*0)", b[3]),
                            };
                            if rng.range(0, 2) == 0 { format!("{}+({})", seed, terms.join("+")) }
                            else { format!("({})+{}", terms.join("+"), seed) }
                        }
                    }
                }
                let mut family = String::new();
                // K/PJ 表先行（形态②⑤的派生源/探针源，读取族与常量池共用）
                family.push_str(&format!(
                    "local {kt}={{{k0},{k1},{k2},{k3},{k4},{k5},{k6},{k7},{k8}}}; local {pj}={{}}; ",
                    kt = kt_name, pj = pj_name,
                    k0 = kspell[0], k1 = kspell[1], k2 = kspell[2], k3 = kspell[3], k4 = kspell[4],
                    k5 = kspell[5], k6 = kspell[6], k7 = kspell[7], k8 = kspell[8]));
                for (fname, is_u32) in [(fn_u32_dec.as_str(), true), (fn_a5.as_str(), false)] {
                    let comb_bytes: [String; 4];
                    let reversed: bool = rng.range(0, 2) == 1;
                    let head: String;      // 声明段（不含 function 头）
                    let collect: String;   // 收集段（空 = B 变体，读取在声明里完成）
                    match rng.range(0, 3) {
                        0 => {
                            // 收集 A：表 + while 正向
                            head = format!("local {t},{n},{i}={{}},4,0; ",
                                t = v_u32_t, n = v_u32_n, i = v_u32_i);
                            collect = format!("while {i}<{n} do {i}={i}+1; {t}[{i}]={rd}() end; ",
                                t = v_u32_t, n = v_u32_n, i = v_u32_i, rd = fn_read_dec);
                            comb_bytes = [
                                format!("{}[1]", v_u32_t), format!("{}[2]", v_u32_t),
                                format!("{}[3]", v_u32_t), format!("{}[4]", v_u32_t),
                            ];
                        }
                        1 => {
                            // 收集B：逐局部；方向随机（反向时倒写、逗号不少）
                            let q: Vec<String> = (0..4).map(|_| rng.name()).collect();
                            if !reversed {
                                head = format!(
                                    "local {a}={rd}() local {b}={rd}() local {c}={rd}() local {d}={rd}() ",
                                    a = q[0], b = q[1], c = q[2], d = q[3], rd = fn_read_dec
                                );
                            } else {
                                head = format!(
                                    "local {d},{c},{b},{a}={rd}(),{rd}(),{rd}(),{rd}() ",
                                    a = q[0], b = q[1], c = q[2], d = q[3], rd = fn_read_dec
                                );
                            }
                            // 多赋值左名字收右值：反向声明时字节归属跟着镜像
                            if !reversed {
                                comb_bytes = [q[0].clone(), q[1].clone(), q[2].clone(), q[3].clone()];
                            } else {
                                comb_bytes = [q[3].clone(), q[2].clone(), q[1].clone(), q[0].clone()];
                            }
                            collect = String::new();
                        }
                        _ => {
                            // 收集 C：表 + repeat until（换壳）
                            let (t, i) = (rng.name(), rng.name());
                            head = format!("local {t}={{}} local {i}=0 ", t = t, i = i);
                            collect = format!("repeat {i}={i}+1 {t}[{i}]={rd}() until {i}>=4 ",
                                t = t, i = i, rd = fn_read_dec);
                            comb_bytes = [
                                format!("{}[1]", t), format!("{}[2]", t),
                                format!("{}[3]", t), format!("{}[4]", t),
                            ];
                        }
                    }
                    let comb = combine_u32(
                        [&comb_bytes[0], &comb_bytes[1], &comb_bytes[2], &comb_bytes[3]], &mut rng
                    );
                    // 形态③⑤：状态梯子（elseif+嵌套 else if 混用），双否定探针臂=诱饵
                    let sv = rng.name();
                    let (lit_a, lit_b, lit_c) = (e_a.as_str(), e_b.as_str(), e_c.as_str());
                    let pk1 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    let (pkA, numA) = (format!("0X{:X}", rng.range(0x10000, 0xFFFFF)), rng.range(100000, 9999999));
                    if collect.is_empty() {
                        // B 变体：收集在声明段完成，第一态直接拼装返回
                        family.push_str(&format!(
                            "local function {f}() {head}local {sv}={e_a}; while true do \
                             if {sv}=={lit_a} then if {pj}[{pkA}]=={numA} then else return {comb} end; \
                             elseif not(not {pj}[{pk1}]) then {sv}={e_c}; \
                             else if {sv}=={lit_b} then return ({b0}-{b0}) end; {sv}={e_d}; end; end end; ",
                            f = fname, head = head, sv = sv, e_a = e_a, lit_a = lit_a, comb = comb,
                            pj = pj_name, pk1 = pk1, pkA = pkA, numA = numA, e_c = e_c, lit_b = lit_b, b0 = comb_bytes[0],
                            e_d = e_d));
                    } else {
                        // A/C 变体：收集、拼装拆成两个真实状态
                        family.push_str(&format!(
                            "local function {f}() {head}local {sv}={e_a}; while true do \
                             if {sv}=={lit_a} then {collect}{sv}={e_b}; \
                             elseif not(not {pj}[{pk1}]) then {sv}={e_c}; \
                             else if {sv}=={lit_b} then if {pj}[{pkA}]=={numA} then else return {comb} end end; {sv}={e_d}; end; end end; ",
                            f = fname, head = head, sv = sv, e_a = e_a, lit_a = lit_a,
                            collect = collect, e_b = e_b, pj = pj_name, pk1 = pk1, pkA = pkA, numA = numA,
                            e_c = e_c, lit_b = lit_b, comb = comb, e_d = e_d));
                    }
                }
                // read_string 四态梯子
                {
                    let (t, i, j) = (rng.name(), rng.name(), rng.name());
                    let shell = if rng.range(0, 2) == 0 {
                        format!("local {i}=0; while {i}<{l} do {i}={i}+1; {t}[{i}]=string_char({rd}()) end", i = i, l = v_rs_l, t = t, rd = fn_read_dec)
                    } else {
                        format!("for {j}=1,{l} do {t}[{j}]=string_char({rd}()) end", j = j, l = v_rs_l, t = t, rd = fn_read_dec)
                    };
                    let sv = rng.name();
                    let (lit_a, lit_b, lit_c) = (e_a.as_str(), e_b.as_str(), e_c.as_str());
                    let pk2 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    let pk3 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    let wk1 = format!("0X{:X}", rng.range(0x51, 0xFFFFF));
                    family.push_str(&format!(
                        "local function {rs}() local {l},{tb}=0,{{}}; local {sv}={e_a}; while true do \
                         if {sv}=={lit_a} then {l}={a5}(); {sv}={e_b}; \
                         elseif {sv}=={lit_b} then if {l}~={zero} then else return '' end; {sv}={e_c}; \
                         elseif not(not {pj}[{pk2}]) then {sv}={e_d}; {pj}[{pk3}]={l}; \
                         else if {sv}=={lit_c} then {shell}; while {wk1} do return table_concat({tb}) end end; {sv}={e_a}; end; end end; ",
                        rs = fn_read_string, l = v_rs_l, tb = t, sv = sv, e_a = e_a,
                        lit_a = lit_a, a5 = fn_a5, e_b = e_b, lit_b = lit_b,
                        zero = rng.obfuscate_num(0i64, 1, &keys), e_c = e_c,
                        pj = pj_name, pk2 = pk2, e_d = e_d, pk3 = pk3,
                        lit_c = lit_c, shell = shell, wk1 = wk1));
                }
                // a10（i32 符号还原）
                {
                    let hexp = ["2^31", "2^30*2", "2147483648", "2^16*2^15"][rng.range(0, 4)];
                    let cond = match rng.range(0, 3) {
                        0 => format!("{v}>=2*{h}-{h}", v = v_u32_v, h = v_a10_h),
                        1 => format!("not({v}<{h})", v = v_u32_v, h = v_a10_h),
                        _ => format!("{v}-{h}>=0", v = v_u32_v, h = v_a10_h),
                    };
                    let ret = match rng.range(0, 3) {
                        0 => format!("{v}-{h}-{h}", v = v_u32_v, h = v_a10_h),
                        1 => format!("{v}-({h}+{h})", v = v_u32_v, h = v_a10_h),
                        _ => format!("{v}-2*{h}", v = v_u32_v, h = v_a10_h),
                    };
                    let sv = rng.name();
                    let (lit_c, lit_d) = (e_c.as_str(), e_d.as_str());
                    let pk4 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                    family.push_str(&format!(
                        "local function {a10}() local {v},{h}=0,0; local {sv}={e_c}; while true do \
                         if {sv}=={lit_c} then {v}={a5}(); if not(not {pj}[{pk4}]) then {h}=0X0; else {h}={hexp}; end; {sv}={e_d}; \
                         elseif {sv}=={lit_d} then if not {pj}[{pk4}] then if {cond} then return {ret} end end; return {v}; \
                         else {sv}={e_c}; end; end end; ",
                        a10 = fn_a10, v = v_u32_v, h = v_a10_h, sv = sv, e_c = e_c,
                        lit_c = lit_c, a5 = fn_a5, hexp = hexp, e_d = e_d,
                        lit_d = lit_d, pj = pj_name, pk4 = pk4, cond = cond, ret = ret
                    ));
                }
                family
            }
        );
        
        let mut f64_parts = vec![format!("({}[7]%16)*2^48", var__b), format!("({}[6]*2^40)", var__b), format!("({}[5]*2^32)", var__b), format!("({}[4]*2^24)", var__b), format!("({}[3]*2^16)", var__b), format!("({}[2]*2^8)", var__b), format!("{}[1]", var__b)];
        rng.shuffle(&mut f64_parts);

        let (v_num_i, v_num_g, v_num_ks) = (rng.name(), rng.name(), rng.name());
        // 原形态：for+「v[8]>=128 and -1 or 1」+floor 取指数，一眼 IEEE754。
        // 现在：while + 显式下标；符号位改成 1-2*((v8-v8%128)/128)；
        // 指数位用 (v8%128)*8*2 + (v7-v7%16)/16（等价于 (v8%128)*16+floor(v7/16)）
        // 分支顺序也换（互斥）。2^(-1074)/2^(exp-1075) 是浮点语义，
        // 绝不能改成 1/2^1074 这类写法（会下溢成 0），所以原样保留。
        let block_dec_numbers = format!(
            "local function {fn_dec_num}(v_enc, pool_idx) local {ks}={fn_chacha_stream}(pool_idx,{kind_num},8); \
             local {vb}, {i}, {g} = {{}}, 0, 0; \
             while {i} < 8 do {i} = {i} + 1; {vb}[{i}] = {xt}[v_enc[{i}]][{ks}[{i}]] end; \
             local {v_sign} = 1 - 2 * (({vb}[8] - ({vb}[8] % 128)) / 128); \
             local {v_exp} = ({vb}[8] % 128) * 8 * 2 + (({vb}[7] - ({vb}[7] % 16)) / 16); \
             local {v_mant} = {f64parts}; \
             if {v_exp} == 2047 then return {v_mant} == 0 and {v_sign} * (1/0) or (0/0) \
             elseif {v_exp} == 0 then return {v_sign} * {v_mant} * (2^(-1074)) \
             else return {v_sign} * ({v_mant} + 2^52) * (2^({v_exp} - 1075)) end end; ",
            fn_dec_num = fn_dec_num, fn_chacha_stream = fn_chacha_stream, kind_num = kind_num_obf,
            vb = var__b, xt = xor_tbl_var,
            v_sign = v_sign, v_exp = v_exp, v_mant = v_mant, f64parts = f64_parts.join("+"),
            ks = v_num_ks, i = v_num_i, g = v_num_g
        );

        let (v_str_i, v_str_g, v_str_ks, v_str_s) = (rng.name(), rng.name(), rng.name(), rng.name());
        // 原形态：for j=1,len + 表下标拼接。现在
        let block_dec_strings = format!(
            "local function {fn_dec_str}({e},{p}) local {n}=#{e}; local {ks}={fn_chacha_stream}({p},{kind_str},{n}); \
             local {s}, {i}, {g} = {{}}, 0, 0; \
             while {i} < {n} do {i} = {i} + 1; {s}[{i}] = string_char({xt}[{fn_s_byte}({e},{i})][{ks}[{i}]]) end; \
             return table_concat({s}) end; ",
            fn_dec_str = fn_dec_str, fn_chacha_stream = fn_chacha_stream, kind_str = kind_str_obf, xt = xor_tbl_var,
            fn_s_byte = fn_s_byte, e = rng.name(), p = rng.name(), n = rng.name(),
            ks = v_str_ks, s = v_str_s, i = v_str_i, g = v_str_g
        );

        let (v_pl_i, v_pl_c, v_pl_n, v_pl_s, v_pl_k, v_pl_v) =
            (rng.name(), rng.name(), rng.name(), rng.name(), rng.name(), rng.name());
        // 池初始化原本是两个干净的 for 循环（`for i=1,n do ... end`），现在都换成
        // while + 显式自增下标 + 独立局部计数，长度/个数也不再和循环变量同名
        let block_pools_init_strings = format!(
            "local {gs}={{}}; local {i}=0; local {c}={u32d}(); \
             while {i} < {c} do {i} = {i} + 1; local {n}={u32d}(); local {s}={{}}; local {k}=0; \
             while {k} < {n} do {k} = {k} + 1; {s}[{k}]=string_char({rd}()) end; \
             {gs}[{i}]=table_concat({s}); end; ",
            gs = global_strings, u32d = fn_u32_dec, rd = fn_read_dec,
            i = v_pl_i, c = v_pl_c, n = v_pl_n, s = v_pl_s, k = v_pl_k
        );
        let block_pools_init_numbers = format!(
            "local {gn}={{}}; local {i}=0; local {c}={u32d}(); \
             while {i} < {c} do {i} = {i} + 1; local {v}={{}}; local {k}=0; \
             while {k} < 8 do {k} = {k} + 1; {v}[{k}]={rd}() end; {gn}[{i}]={v}; end; ",
            gn = global_numbers, u32d = fn_u32_dec, rd = fn_read_dec,
            i = v_pl_i, c = v_pl_c, v = v_pl_v, k = v_pl_k
        );

        let var_enc_c = rng.name();
        let var_tbl = rng.name();
        let var_idx_chunk = rng.name();
        let var_e = rng.name();
        let var_cache = rng.name();

        let var_state = rng.name();
        let s_init = rng.range(0x100, 0xFFF) as i64;
        let s_insts = rng.range(0x1000, 0x1FFF) as i64;
        let s_consts = rng.range(0x2000, 0x2FFF) as i64;
        let s_protos = rng.range(0x3000, 0x3FFF) as i64;
        let s_debug = rng.range(0x4000, 0x4FFF) as i64;
        let s_ret = rng.range(0x5000, 0x5FFF) as i64;

        let obf_s_init = rng.format_num(s_init);
        let obf_s_insts = rng.format_num(s_insts);
        let obf_s_consts = rng.format_num(s_consts);
        let obf_s_protos = rng.format_num(s_protos);
        let obf_s_debug = rng.format_num(s_debug);
        let obf_s_ret = rng.format_num(s_ret);
        
        // ── 状态机（第 6 项：解密逻辑打乱）──
        // 原形态：if state==A then <体>
        // 状态推进总在体尾，一眼就是「顺序状态机」。现在：
        //   ① 六个状态体各自构造后 **shuffle**（分支条件互相排斥，顺序无关）
        //   ② 状态推进提到体首（体内不读 state，等价）；
        //   ③ 所有 for 循环换成 while + 显式自增下标 + 独立局部下标；
        //   ④ 结尾统一 return（不再是分支内 return），并带一个恒假谓词与影子守卫
        // 注意：体内的**读流顺序**一个字都不能动 —— 那些字节是按顺序读进来的
        let (v_ch_g, v_ch_out, v_ch_i, v_ch_n) = (rng.name(), rng.name(), rng.name(), rng.name());

        let body_init = format!(
            "{st}={nxt}; {c}.{pf_n}={rs}(); {c}.{pf_ld}={a5}(); {c}.{pf_lld}={a5}(); {c}.{pf_nups}={rd}(); \
             {c}.{pf_numparams}={rd}(); {c}.{pf_is_vararg}={rd}(); {c}.{pf_maxstack}={rd}(); if {i} > {i} then {i} = {i} - 1 end; ",
            st = var_state, nxt = obf_s_insts, c = fn_c, rs = fn_read_string, a5 = fn_a5, rd = fn_read_dec,
            pf_n = pf_n, pf_ld = pf_ld, pf_lld = pf_lld, pf_nups = pf_nups,
            pf_numparams = pf_numparams, pf_is_vararg = pf_is_vararg, pf_maxstack = pf_maxstack, i = v_ch_i
        );
        let body_insts = format!(
            "{st}={nxt}; {c}.{pf_opcodes}={{}}; {c}.{pf_a_arr}={{}}; {c}.{pf_b_arr}={{}}; {c}.{pf_c_arr}={{}}; \
             local {i}=0; local {n}={a5}(); while {i} < {n} do {i} = {i} + 1; \
             {c}.{pf_opcodes}[{i}]={a5}(); {c}.{pf_a_arr}[{i}]={rd}(); {c}.{pf_b_arr}[{i}]={a10}(); {c}.{pf_c_arr}[{i}]={a10}(); end; ",
            st = var_state, nxt = obf_s_consts, c = fn_c, a5 = fn_a5, rd = fn_read_dec, a10 = fn_a10,
            pf_opcodes = pf_opcodes, pf_a_arr = pf_a_arr, pf_b_arr = pf_b_arr, pf_c_arr = pf_c_arr,
            i = v_ch_i, n = v_ch_n
        );
        let (bi0, bi1) = crate::VM::VM_Backend::Generator_util::stream_key("__index", &mut rng);
        let sc_index2 = at.st.call("__index", bi0, bi1);
        let (ko0, ko1) = crate::VM::VM_Backend::Generator_util::stream_key("KryvexObf_", &mut rng);
        let sc_kobf = at.st.call("KryvexObf_", ko0, ko1);
        let body_consts = format!(
            "{st}={nxt}; {bc_scatter} ",
            st = var_state, nxt = obf_s_protos,
            bc_scatter = {
                // ── ⑥ 常量池查表打散
                // 读入侧/访问侧各一张调度表，键 = 混淆数字展开式（运行期才是 1/2/3）
                // 注册洗牌；挂永不命中诱饵键
                // 缓存检查拆成独立前哨闭包。缓存值只可能是 string/number/false
                // 用 ~=nil 判命中无歧义。
                let mt_name = rng.name();
                let dsp_name = rng.name();
                // 形态①②：__index 三handler+驱动换相
                let hh_name = rng.name();
                let (hh_cur, hh_c, hh_a2, hh_aux) = (rng.name(), rng.name(), rng.name(), rng.name());
                let hh_codes: Vec<i64> = {
                    let mut cs = Vec::new();
                    while cs.len() < 5 {
                        let m = rng.range(1 << 20, (1 << 24) - 1) as i64;
                        if !cs.contains(&m) { cs.push(m); }
                    }
                    cs
                };
                let (hh_ret, hh_nil, hh_next, hh_val, hh_fail) =
                    (hh_codes[0], hh_codes[1], hh_codes[2], hh_codes[3], hh_codes[4]);
                let (x_ret1, x_nil1, x_next1, x_val1, x_fail1) =
                    (eh_ret.as_str(), eh_nil.as_str(), eh_next.as_str(), eh_val.as_str(), eh_fail.as_str());
                let x_ka = e_ka.as_str();
                let pk6 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
                let (pkB, numB) = (format!("0X{:X}", rng.range(0x10000, 0xFFFFF)), rng.range(100000, 9999999));
                let (pkC, numC) = (format!("0X{:X}", rng.range(0x10000, 0xFFFFF)), rng.range(100000, 9999999));
                let (wk2, wk3, wk4) = (format!("0X{:X}", rng.range(0x51, 0xFFFFF)), format!("0X{:X}", rng.range(0x51, 0xFFFFF)), format!("0X{:X}", rng.range(0x51, 0xFFFFF)));
                let ld_name = rng.name();
                let memo_name = rng.name();
                let h_name = rng.name();
                let _got_name = rng.name();
                let val_name = rng.name();
                let one = rng.obfuscate_num(1i64, 1, &keys);
                let two = rng.obfuscate_num(2i64, 1, &keys);
                let three = rng.obfuscate_num(3i64, 1, &keys);
                let zero = rng.obfuscate_num(0i64, 1, &keys);
                let decoy_ld = rng.range(60, 250);
                let decoy_dsp = rng.range(60, 250);
                // 访问侧：tag → 解码闭包（定义顺序洗牌）
                let mut dsp_defs = vec![
                    format!("{d}[{t3}]=function(ev) return {fds}(ev[2],ev[3]) end; ",
                        d = dsp_name, t3 = three, fds = fn_dec_str),
                    format!("{d}[{t2}]=function(ev) return {fdn}(ev[2],ev[3]) end; ",
                        d = dsp_name, t2 = two, fdn = fn_dec_num),
                    format!("{d}[{t1}]=function(ev) return ev[2] end; ", d = dsp_name, t1 = one),
                    format!("{d}[{dd}]=function(ev) return nil end; ", d = dsp_name, dd = decoy_dsp),
                ];
                rng.shuffle(&mut dsp_defs);
                // 读入侧：tag → 装载闭包（定义顺序洗牌）
                let mut ld_defs = vec![
                    format!("{l}[{t3}]=function(pos) local ri={a5}() {ec}[pos]={{3,{gs}[ri+1],ri}} end; ",
                        l = ld_name, t3 = three, a5 = fn_a5, ec = var_enc_c, gs = global_strings),
                    format!("{l}[{t2}]=function(pos) local ri={a5}() {ec}[pos]={{2,{gn}[ri+1],ri}} end; ",
                        l = ld_name, t2 = two, a5 = fn_a5, ec = var_enc_c, gn = global_numbers),
                    format!("{l}[{t1}]=function(pos) {ec}[pos]={{1,{rd}()~={zero}}} end; ",
                        l = ld_name, t1 = one, ec = var_enc_c, rd = fn_read_dec, zero = zero),
                    format!("{l}[{dd}]=function() end; ", l = ld_name, dd = decoy_ld),
                ];
                rng.shuffle(&mut ld_defs);
                let mut lua = format!(
                    "local {ec}={{}}; local {ca}={{}}; local {dsp}={{}}; local {ld}={{}}; ",
                    ec = var_enc_c, ca = var_cache, dsp = dsp_name, ld = ld_name);
                for x in &dsp_defs { lua.push_str(x); }
                // 缓存前哨：命中（值非 nil）直接短路
                lua.push_str(&format!(
                    "local {memo}=function({ix}) local cd={ca}[{ix}] if cd~=nil then return cd end end; ",
                    memo = memo_name, ix = var_idx_chunk, ca = var_cache));
                lua.push_str(&format!("local {mt}={{}}; ", mt = mt_name));
                lua.push_str(&format!(
                    "local {hh}={{}}; \
                     {hh}[{e_ka}]=function({ix},{aux}) if {flg} then else return {x_fail1},({kobf}..{ix}) end; \
                       local g={memo}({ix}) if g~=nil then if {pj}[{pkB}]=={numB} then else return {x_ret1},g end end while {wk2} do return {x_next1} end end; \
                     {hh}[{e_kb}]=function({ix}) local {ev}={ec}[{ix}] if not {ev} then return {x_nil1} end \
                       local {h}={dsp}[{ev}[1]] if not {h} then return {x_nil1} end return {x_val1},{h}({ev}) end; \
                     {hh}[{e_kc}]=function({ix},{aux}) {ca}[{ix}]={aux} while {wk3} do return {x_ret1},{aux} end end; ",
                    hh = hh_name, e_ka = e_ka, e_kb = e_kb, e_kc = e_kc,
                    ix = var_idx_chunk, aux = hh_aux, flg = var_state_flag,
                    x_fail1 = x_fail1, kobf = sc_kobf, memo = memo_name,
                    x_ret1 = x_ret1, x_next1 = x_next1, ec = var_enc_c,
                    ev = var_e, h = h_name, dsp = dsp_name, x_nil1 = x_nil1,
                    x_val1 = x_val1, ca = var_cache, pj = pj_name, pkB = pkB, numB = numB, wk2 = wk2, wk3 = wk3));
                lua.push_str(&format!(
                    "{mt}[{idx}]=function({tb},{ix}) local {cur}={x_ka}; local {aux}; \
                     while true do local {c},{a2}={hh}[{cur}]({ix},{aux}); \
                       if {c}=={x_ret1} then return {a2} end; \
                       if {c}=={x_fail1} then return {a2} end; \
                       if {c}=={x_nil1} then while {wk4} do return nil end end; \
                       if {c}=={x_next1} then {cur}={e_kb}; else {cur}={e_kc}; {aux}={a2} end; \
                     end end; ",
                    mt = mt_name, idx = sc_index2, tb = var_tbl, ix = var_idx_chunk,
                    cur = hh_cur, x_ka = x_ka, aux = hh_aux, c = hh_c, a2 = hh_a2,
                    hh = hh_name, x_fail1 = x_fail1, e_kb = e_kb, e_kc = e_kc, wk4 = wk4));
                lua.push_str(&format!(
                    "{c}.{pf}=setmetatable({{}},{mt}); ",
                    c = fn_c, pf = pf_consts, mt = mt_name));
                for x in &ld_defs { lua.push_str(x); }
                lua.push_str(&format!(
                    "local {i}=0; local {n}={a5}(); if not(not {pj}[{pk6}]) then {i}={n}; else \
                     while {i}<{n} do {i}={i}+1; local {t}={rd}(); \
                     local {h}={ld}[{t}]; if {h} then if {pj}[{pkC}]=={numC} then else {h}({i}) end end end end; ",
                    i = v_ch_i, n = v_ch_n, a5 = fn_a5, pj = pj_name, pk6 = pk6,
                    t = t, rd = fn_read_dec, h = h_name, ld = ld_name, pkC = pkC, numC = numC));
                lua
            }
        );
        let pkx1 = format!("0X{:X}", rng.range(0x10000, 0xFFFFF));
        let body_protos = format!(
            "{st}={nxt}; {c}.{pf_protos}={{}}; local {i}=0; local {n}={a5}(); \
             if not {pj}[{pkx1}] then while {i} < {n} do {i} = {i} + 1; {c}.{pf_protos}[{i}]={dc}() end else {i}={n}; {n}=0X0; end; ",
            st = var_state, nxt = obf_s_debug, c = fn_c, pf_protos = pf_protos, a5 = fn_a5,
            dc = fn_decode_chunk, i = v_ch_i, n = v_ch_n, pj = pj_name, pkx1 = pkx1
        );
        let body_debug = format!(
            "{st}={nxt}; local {i}=0; local {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {a5}() end; \
             {i}=0; {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {rs}(); {a5}(); {a5}() end; \
             {i}=0; {n}={a5}(); while {i} < {n} do {i} = {i} + 1; {rs}() end; ",
            st = var_state, nxt = obf_s_ret, a5 = fn_a5, rs = fn_read_string, i = v_ch_i, n = v_ch_n
        );
        let body_ret = format!("if not(not {pj}[{pkx1}]) then {g}={g}+1; else {out}={c}; {g}={g}+1; end; ",
            out = v_ch_out, c = fn_c, g = v_ch_g, pj = pj_name, pkx1 = pkx1);

        let mut ch_pairs: Vec<(String, String)> = vec![
            (obf_s_init.clone(), body_init),
            (obf_s_insts.clone(), body_insts),
            (obf_s_consts.clone(), body_consts),
            (obf_s_protos.clone(), body_protos),
            (obf_s_debug.clone(), body_debug),
            (obf_s_ret.clone(), body_ret),
        ];
        rng.shuffle(&mut ch_pairs);
        let mut chain = String::new();
        for (idx, (val, body)) in ch_pairs.iter().enumerate() {
            let kw = if idx == 0 { "if" } else { "elseif" };
            chain.push_str(&format!("{} {} == {} then {} ", kw, var_state, val, body));
        }
        chain.push_str(&format!("else {} = {} + 1; end; ", v_ch_g, v_ch_g));

        let block_dec_chunk = format!(
            "local function {fn_dec_chunk}() local {fn_c}, {t}, {var_state} = {{}}, nil, {obf_s_init}; \
             local {g}, {out}, {i}, {n} = 0, nil, 0, 0; \
             while {g} < 1 do {chain} end; \
             return {out} end; ",
            fn_dec_chunk = fn_decode_chunk, fn_c = fn_c, t = t, var_state = var_state,
            obf_s_init = obf_s_init, g = v_ch_g, out = v_ch_out, i = v_ch_i, n = v_ch_n,
            chain = chain
        );

        let mut parts = vec![
            block_p_def,
            block_methods,
            block_vm_core,
            block_packer_vars,
            block_execute_def,
            block_decoder_script,
            block_dec_header,
            block_dec_helpers,
            block_dec_readers,
            block_chacha_setup,
            block_dec_numbers,
            block_dec_strings,
            block_pools_init_strings,
            block_pools_init_numbers,
            block_dec_chunk,
        ];

        let mut shuffled_guards = at.guards.clone();
        rng.shuffle(&mut shuffled_guards);

        for guard in shuffled_guards {
            let gap_idx = rng.range(0, parts.len() + 1);
            parts.insert(gap_idx, guard);
        }

        let mut out = String::new();
        out.push_str(&format!("local {} = ...;\n", var_l));
        out.push_str(&header_block);
        // ④ 槽位键的运行期推导块必须在所有用键代码之前；
        // finish_setup 把状态链种子/陷阱门等收尾语句并进 setup（在全部注册后调用）
        out.push_str(&sk_setup);
        at.finish_setup();
        out.push_str(&at.setup);
        out.push_str(&format!(" local {} = 0; ", key_seed_var));
        out.push_str(" ");
        out.push_str("local math_floor, string_char, string_sub, string_byte, table_concat = math.floor, string.char, string.sub, string.byte, table.concat; ");

        for part in parts {
            out.push_str(&part);
            out.push_str(" ");
        }

        out.push_str(&format!("local main_chunk={}(); ", fn_decode_chunk));
        out.push_str(&at.trigger);
        out.push_str(&format!(" {} = {{}}; local {} = (getfenv and getfenv() or _ENV or _G); local {}; ", var_builtin_reg, var_boot_env, var_bname));
        for (i, name) in Opcodes::builtins::BUILTIN_NAMES.iter().enumerate() {
            let slot = builtin_slot_perm[i];
            let raw_idx = builtin_pool_indices[i];
            let lua_idx = raw_idx + 1;
            out.push_str(&format!(
                "{bname}={fn_dec_str}({gs}[{lidx}],{ridx}); {reg}[{slot}]={benv}[{bname}]; if {reg}[{slot}]==nil and getgenv then {reg}[{slot}]=getgenv()[{bname}] end; ",
                bname = var_bname, fn_dec_str = fn_dec_str, gs = global_strings,
                lidx = lua_idx, ridx = raw_idx, reg = var_builtin_reg, slot = slot + 1, benv = var_boot_env
            ));
            let _ = name;
        }
        let fu = rng.name();
        
        out.push_str(" ");
        out.push_str(&format!("return {}(main_chunk, {}, {{}}, {}) end,{}=function(x) x:{}() end", fn_execute, var_boot_env, var_l, fu, wai));
        out.push_str(&format!(" }}):{}()", fu));
        out
    }
}
