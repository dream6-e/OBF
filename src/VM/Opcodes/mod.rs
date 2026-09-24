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
    pub virtual_closures: String,
    pub builtin_reg: String,
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

pub fn generate_handlers(opcode_map: &[Vec<u32>; builtins::TOTAL_OPCODES], cfg: &OpcodeConfig, seed: u64) -> String {
    let mut rng = OpcodesRng::new(seed as u32);
    let perm = builtins::slot_permutation(seed);
    let mut out = String::new();
    out.push_str("local rk1, rk2; "); 
    out.push_str(&load_store::generate(opcode_map, cfg, &mut rng));
    out.push_str(&arithmetic::generate(opcode_map, cfg, &mut rng));
    out.push_str(&control_flow::generate(opcode_map, cfg, &mut rng));
    out.push_str(&environment::generate(opcode_map, cfg, &mut rng));
    out.push_str(&builtins::generate(opcode_map, cfg, &mut rng, &perm));
    out
}

pub fn obfuscate_handler(opcode: u32, code: &str) -> String {
    format!("handlers[{}] = function(inst)\n{}\nend\n", opcode, code)
}