use rand::{rng, Rng};

pub mod arithmetic;
pub mod builtins;
pub mod control_flow;
pub mod environment;
pub mod load_store;

pub struct OpcodesRng;

impl OpcodesRng {
    pub fn new(_seed: u32) -> Self {
        Self
    }
    
    pub fn next(&mut self) -> u32 {
        rng().random::<u32>()
    }
    
    pub fn next_range(&mut self, min: usize, max: usize) -> usize {
        rng().random_range(min..max)
    }
    
    pub fn name(&mut self) -> String {
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
        let keywords = ["and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"];
        let mut r = rng();
        loop {
            let len = self.next_range(5, 11);
            let s: String = (0..len).map(|_| chars[r.random_range(0..chars.len())]).collect();
            if !keywords.contains(&s.as_str()) { return s; }
        }
    }
}

/// ㉒ 数值字面量（仿 Luraph）：hex/bin 随机 + 随机下划线分段（0X2__5 / 0B1010_10）
pub fn num_lit(rng: &mut OpcodesRng, v: u32) -> String {
    if rng.next_range(0, 2) == 0 {
        format!("0X{:X}", v)
    } else {
        format!("{}", v)
    }
}

/// ㉒ 恒等转移式：静态上不可读出目标态（-r+(r+t) / (r-r)+t / ((r+r)-r2) 当 r2=2r）
pub fn ident(rng: &mut OpcodesRng, target: u32) -> String {
    // 数值域约束：r 与 r+target 都必须 ≤0xFFFFFE——压缩管线会截断 >24bit 的
    // 十六进制字面量（0X16F6FC9→0XCF6FC9 级别的损坏），状态链一断机器就死循环
    let r = rng.next_range(0x1000, (0x7FFFFFusize).min((0xFFFFFE - target) as usize)) as u32;
    match rng.next_range(0, 3) {
        0 => format!("-{}+{}", num_lit(rng, r), num_lit(rng, r.wrapping_add(target))),
        1 => format!("({}-{})+{}", num_lit(rng, r), num_lit(rng, r), num_lit(rng, target)),
        _ => format!("(({}*{})-({}+{}))+{}", num_lit(rng, 2), num_lit(rng, r), num_lit(rng, r), num_lit(rng, r), num_lit(rng, target)),
    }
}

/// ㉒ 顶层语句切分 v2：跟踪括号深度 + **Lua 块深度**（if/for/while/function/
/// repeat 的 do/then..end 配对）——分号只有在括号与块深度都为 0 时才是语句边界；
/// 旧版只看括号，把 if..then..end 体里的分号当边界，TFORCALL 嵌套 if 被切碎，
/// elseif 串接进内层 if，语义全乱（死循环根因）
pub fn split_top_stmts(lua: &str) -> Vec<String> {
    let toks: Vec<char> = lua.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let (mut dq, mut sq) = (false, false);
    let (mut bracket, mut block) = (0i32, 0i32);
    let mut i = 0;
    let lc = |cs: &[char], k: usize, w: &str| -> bool {
        if k + w.len() > cs.len() { return false; }
        let after_ok = k + w.len() == cs.len() || !cs[k + w.len()].is_ascii_alphanumeric() && cs[k + w.len()] != '_';
        let before_ok = k == 0 || !cs[k - 1].is_ascii_alphanumeric() && cs[k - 1] != '_';
        before_ok && after_ok && cs[k..k + w.len()].iter().collect::<String>() == w
    };
    while i < toks.len() {
        let c = toks[i];
        if dq {
            cur.push(c);
            if c == '\\' && i + 1 < toks.len() { cur.push(toks[i + 1]); i += 2; continue; }
            if c == '"' { dq = false; }
            i += 1; continue;
        }
        if sq {
            cur.push(c);
            if c == '\\' && i + 1 < toks.len() { cur.push(toks[i + 1]); i += 2; continue; }
            if c == '\'' { sq = false; }
            i += 1; continue;
        }
        if c == '"' { dq = true; cur.push(c); i += 1; continue; }
        if c == '\'' { sq = true; cur.push(c); i += 1; continue; }
        if c == '(' || c == '[' || c == '{' { bracket += 1; cur.push(c); i += 1; continue; }
        if c == ')' || c == ']' || c == '}' { bracket -= 1; cur.push(c); i += 1; continue; }
        if c.is_ascii_alphabetic() || c == '_' {
            let kw: String = toks[i..].iter().take_while(|x| x.is_ascii_alphanumeric() || **x == '_').collect();
            match kw.as_str() {
                "function" | "repeat" | "if" => block += 1,
                "end" | "until" => block -= 1,
                "do" => block += 1,
                _ => {}
            }
            cur.push_str(&kw);
            i += kw.len();
            continue;
        }
        if c == ';' && bracket == 0 && block == 0 {
            out.push(cur.trim().to_string());
            cur.clear();
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    let last = cur.trim().to_string();
    if !last.is_empty() { out.push(last); }
    out.into_iter().filter(|x| !x.is_empty()).collect()
}

pub struct OpcodeConfig {
    pub pc: String,
    pub stk: String,
    pub consts: String,
    pub top: String,
    pub insts: String,
    pub inst: String,
    pub upvals: String,
    pub env: String,
    pub protos: String,
    pub handlers: String,
    pub varargs: String,
    pub varargs_len: String,
    pub vararg_count: String,
    pub proto_nups: String,
    pub open_ups: String,
    pub virtual_closures: String,
    pub builtin_reg: String,
    /// 方法化后的返回协议：`{RET0}`（无返回值）/`{RET1}`（单值）/
    /// `{RET2}`（表+区间）三个返回钩子的调用点。
    pub ret0: String,
    pub ret1: String,
    pub ret2: String,
}

pub struct OpcodeBuilder<'a> {
    pub opcodes: Vec<u32>,
    pub cfg: &'a OpcodeConfig,
    pub rng: &'a mut OpcodesRng,
    pub local_inst: String,
    pub pre_statements: String,
}

impl<'a> OpcodeBuilder<'a> {
    pub fn new(opcodes: Vec<u32>, cfg: &'a OpcodeConfig, rng: &'a mut OpcodesRng) -> Self {
        let local_inst = rng.name();
        Self { 
            opcodes, 
            cfg, 
            rng, 
            local_inst, 
            pre_statements: String::new() 
        }
    }

    pub fn reg(&mut self, idx: usize) -> String {
        format!("{}[{}]", self.cfg.stk, self.raw_inst(idx))
    }

    pub fn raw_inst(&self, idx: usize) -> String {
        match idx {
            2 => "inst_A".to_string(),
            3 => "inst_B".to_string(),
            4 => "inst_C".to_string(),
            _ => "0".to_string(),
        }
    }

    pub fn rk(&mut self, idx: usize) -> String {
        let rk_var = if idx == 3 { "rk1" } else { "rk2" };
        let val = self.raw_inst(idx);
        let c = &self.cfg.consts;
        let s = &self.cfg.stk;
        
        self.pre_statements.push_str(&format!(
            "if {}>127 then {}={}[{}-127] else {}={}[{}] end; ",
            val, rk_var, c, val, rk_var, s, val
        ));
        
        rk_var.to_string()
    }

    pub fn cnst(&self, idx: usize) -> String {
        format!("{}[{}+1]", self.cfg.consts, self.raw_inst(idx))
    }

    /// ㉒ 数值状态机化（仿 Luraph）：语句切顶层 → 随机分组 3~6 段 →
    /// while true + if sm==随机态 转移（恒等算式），末段 break；
    /// 语义严格保序，仅适用无 break/无中途 return 的纯算术 handler
    pub fn build_staged(&mut self, lua_template: &str) -> String {
        let stmts = split_top_stmts(lua_template);
        if stmts.len() < 3 {
            return self.build(lua_template);
        }
        // ㉒ local 提升：stage 是 if..end 块作用域，声明与使用跨段会读到 nil
        // （TFORCALL 的 local r1..r6 拆段后迭代器协议崩→死循环）。把所有
        // local 声明提升到机器之前，声明语句改写为赋值（纯声明则删除）
        let mut hoisted: Vec<String> = Vec::new();
        let mut stmts2: Vec<String> = Vec::new();
        for st0 in stmts.iter() {
            let t = st0.trim();
            if let Some(rest) = t.strip_prefix("local ") {
                let rest = rest.trim();
                if let Some(frest) = rest.strip_prefix("function ") {
                    if let Some(eq) = frest.find("(") {
                        let name = frest[..eq].trim().to_string();
                        hoisted.push(name.clone());
                        stmts2.push(format!("{} = function{}", name, &frest[eq..]));
                        continue;
                    }
                } else {
                    let (names_part, init) = match rest.find("=") {
                        Some(eq) => (rest[..eq].trim(), Some(rest[eq..].trim_start_matches('=').trim())),
                        None => (rest, None),
                    };
                    let names: Vec<String> = names_part.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                    for nm in &names { hoisted.push(nm.clone()); }
                    match init {
                        Some(e) if !e.is_empty() => stmts2.push(format!("{} = {}", names_part, e)),
                        _ => { /* 纯声明：提升即可 */ }
                    }
                    continue;
                }
            }
            stmts2.push(t.to_string());
        }
        let stmts = stmts2;
        if stmts.len() < 3 {
            return self.build(lua_template);
        }
        let k = self.rng.next_range(3, 7).min(stmts.len());
        let mut bounds: Vec<usize> = Vec::new();
        {
            let mut remaining = stmts.len();
            let mut stages = k;
            while stages > 1 {
                let max_take = remaining - (stages - 1);
                let take = self.rng.next_range(1, max_take + 1);
                bounds.push(take);
                remaining -= take;
                stages -= 1;
            }
            bounds.push(remaining);
        }
        let mut states: Vec<u32> = Vec::new();
        while states.len() < k {
            let v = 0x10000 + self.rng.next() % 0xEDFFFF;
            if !states.contains(&v) { states.push(v); }
        }
        let sm = self.rng.name();
        let hoist_decl = if hoisted.is_empty() { String::new() } else { format!("local {}; ", hoisted.join(",")) };
        let mut out = format!("{}local {}={}; while true do ", hoist_decl, sm, ident(self.rng, states[0]));
        let mut idx = 0;
        for si in 0..k {
            let mut chunk = String::new();
            for _ in 0..bounds[si] {
                chunk.push_str(&stmts[idx]);
                chunk.push_str("; ");
                idx += 1;
            }
            if si == 0 {
                out.push_str(&format!("if {}=={} then {} {}={}; ",
                    sm, num_lit(self.rng, states[0]), chunk, sm, ident(self.rng, states[1])));
            } else if si + 1 < k {
                out.push_str(&format!("elseif {}=={} then {} {}={}; ",
                    sm, num_lit(self.rng, states[si]), chunk, sm, ident(self.rng, states[si + 1])));
            } else {
                out.push_str(&format!("elseif {}=={} then {} break; end end ",
                    sm, num_lit(self.rng, states[si]), chunk));
            }
        }
        self.build(&out)
    }

    pub fn build(&mut self, lua_template: &str) -> String {
        let mut code = format!("{}{}", self.pre_statements, lua_template);
        
        code = code.replace("{PC}", &self.cfg.pc);
        code = code.replace("{STK}", &self.cfg.stk);
        code = code.replace("{CONSTS}", &self.cfg.consts);
        code = code.replace("{TOP}", &self.cfg.top);
        code = code.replace("{INSTS}", &self.cfg.insts);
        code = code.replace("{INST}", &self.local_inst);
        code = code.replace("{UPVALS}", &self.cfg.upvals);
        code = code.replace("{ENV}", &self.cfg.env);
        code = code.replace("{PROTOS}", &self.cfg.protos);
        code = code.replace("{HANDLERS}", &self.cfg.handlers);
        code = code.replace("{VARARGS}", &self.cfg.varargs);
        code = code.replace("{VARARGS_LEN}", &self.cfg.varargs_len);
        code = code.replace("{VC}", &self.cfg.virtual_closures);
        code = code.replace("{BUILTINREG}", &self.cfg.builtin_reg);
        code = code.replace("{VARARG_COUNT}", &self.cfg.vararg_count);
        code = code.replace("{PROTO_NUPS}", &self.cfg.proto_nups);
        code = code.replace("{OPEN_UPS}", &self.cfg.open_ups);
        
        let conditions: Vec<String> = self.opcodes.iter().map(|op| format!("op == {}", op)).collect();
        let condition = conditions.join(" or ");
        
        format!("elseif {} then {} ", condition, code)
    }
}

pub fn generate_opcode_map() -> [Vec<u32>; builtins::TOTAL_OPCODES] {
    let mut rng = rand::rng();
    let mut map: [Vec<u32>; builtins::TOTAL_OPCODES] = std::array::from_fn(|_| Vec::new());
    let mut used = std::collections::HashSet::new();

    for i in 0..builtins::TOTAL_OPCODES {
        let count = rng.random_range(3..=6);
        for _ in 0..count {
            loop {
                let val = rng.random_range(80000..99999);
                if used.insert(val) {
                    map[i].push(val);
                    break;
                }
            }
        }
    }
    map
}

pub fn generate_handlers(opcode_map: &[Vec<u32>; builtins::TOTAL_OPCODES], fused_map: &[Vec<u32>; builtins::FUSED_OP_COUNT], fused_used: &std::collections::HashSet<usize>, cfg: &OpcodeConfig, seed: u64) -> String {
    let mut rng = OpcodesRng::new(seed as u32);
    let perm = builtins::slot_permutation(seed);
    let mut out = String::new();
    out.push_str("local rk1, rk2; "); 
    out.push_str(&load_store::generate(opcode_map, cfg, &mut rng));
    out.push_str(&arithmetic::generate(opcode_map, cfg, &mut rng));
    out.push_str(&control_flow::generate(opcode_map, cfg, &mut rng));
    out.push_str(&environment::generate(opcode_map, cfg, &mut rng));
    out.push_str(&builtins::generate(opcode_map, cfg, &mut rng, &perm));
    out.push_str(&builtins::generate_fused(fused_map, cfg, &mut rng, &perm, fused_used));
    out
}

pub fn obfuscate_handler(opcode: u32, code: &str) -> String {
    format!("handlers[{}] = function(inst)\n{}\nend\n", opcode, code)
}