//! Executable VM for AST-produced OBF v2 bytecode. Generated code fetches four
//! bytes per instruction from each prototype's byte string. Only handlers in
//! the program are emitted; all opcode definitions exist in the two target
//! subfolders. `seed` affects final local/private-field names only, never bytecode.

use crate::bytecode::custom::{self, Opcode, Program};
use crate::{Diagnostic, Target};
use std::fmt::Write;

pub fn compile(source: &str, target: Target) -> Result<Vec<u8>, Diagnostic> {
    custom::encode(&crate::ir::compile(source, target)?)
}

pub fn virtualize(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    let bytecode = compile(source, target)?;
    emit(&bytecode, target, seed)
}

/// Validate externally supplied custom bytecode before generating a runtime.
pub fn emit(bytecode: &[u8], target: Target, seed: u64) -> Result<String, Diagnostic> {
    let program = custom::decode(bytecode, target)?;
    let raw = generate(bytecode, &program)?;
    finalize(&raw, target, seed)
}

// All source (including static host method adapters) is complete before
// shortening private fields and then applying the existing final local pass.
fn finalize(source: &str, target: Target, seed: u64) -> Result<String, Diagnostic> {
    let source = super::fields::shorten(source, target, seed)?;
    crate::minify::finalize_vm(&source, target, seed)
}

pub(crate) fn generate(bytecode: &[u8], program: &Program) -> Result<String, Diagnostic> {
    custom::validate(program)?;
    let mut s = String::from(
        r#"
local SC=select;local Z=function(...)return{n=SC('#',...),...}end;
local U=unpack or table.unpack;local G=(getfenv and getfenv(0))or _G;local E=error;
local SB,SS,SF=string.byte,string.sub,string.format;
local MF,TN,TY,TS,NX,MT,SM,RG,RE=math.floor,tonumber,type,tostring,next,getmetatable,setmetatable,rawget,rawequal;
"#,
    );
    if program.target.is_luau() {
        s.push_str("local IF=integer and integer.fromstring;local Freeze=table.freeze;");
    }
    s.push_str("local B=");
    super::lua51::emit_byte_string(&mut s, bytecode);
    s.push(';');
    s.push_str(
        r#"
if #B>16777216 then E()end;
local bp=1;
local b8=function()local v=SB(B,bp);if v==nil then E()end;bp=bp+1;return v end;
local b16=function()local a,b=b8(),b8();return a+b*256 end;
local b32=function()local a,b,c,d=b8(),b8(),b8(),b8();return a+b*256+c*65536+d*16777216 end;
local take=function(n)if n>#B-bp+1 then E()end;local v=SS(B,bp,bp+n-1);bp=bp+n;return v end;
local str=function()return take(b32())end;
local num=function()
 local lo,hi=b32(),b32();local sg=hi>=2147483648 and -1 or 1;
 local ex=MF(hi/1048576)%2048;local fr=(hi%1048576)*4294967296+lo;
 if ex==2047 then if fr==0 then return sg/0 else return 0/0 end
 elseif ex==0 then return sg*(fr*2^-1074)
 else return sg*((1+fr/4503599627370496)*2^(ex-1023))end
end;
if b8()~=79 or b8()~=66 or b8()~=70 or b8()~=2 then E()end;
"#,
    );
    write!(
        s,
        "if b8()~={} then E()end;",
        if program.target.is_luau() { 117 } else { 81 }
    )
    .unwrap();
    s.push_str(
        r#"
if b8()~=1 or b8()~=4 or b8()~=0 or b32()~=32 or b32()~=#B then E()end;
local np=b32();local entry=b32();local isa=b32();if np==0 or np>65536 or entry~=0 or isa<1 or isa>2 then E()end;
local check=b32();local sa,sb=1,0;for q=33,#B do sa=(sa+SB(B,q))%65521;sb=(sb+sa)%65521 end;
if sa+sb*65536~=check then E()end;
local P={};local work=0;
for id=0,np-1 do
 local F={__obf_proto_k={},__obf_proto_tags={},__obf_proto_u={}};F.__obf_proto_parent=b32();F.__obf_proto_m=b16();F.__obf_proto_p=b8();F.__obf_proto_flags=b8();F.__obf_proto_nu=b16();
 if b16()~=0 then E()end;F.__obf_proto_nk=b32();F.__obf_proto_nc=b32();
 if F.__obf_proto_m<1 or F.__obf_proto_m>256 or F.__obf_proto_p>F.__obf_proto_m or F.__obf_proto_nu>256 or F.__obf_proto_nk>65536 or F.__obf_proto_nc<1 or F.__obf_proto_flags>15 then E()end;
 F.__obf_proto_shared=MF(F.__obf_proto_flags/8)%2==1;if F.__obf_proto_shared and (isa<2 or id==0)then E()end;
 if id==0 then if F.__obf_proto_parent~=4294967295 or F.__obf_proto_nu~=0 or MF(F.__obf_proto_flags/2)%2~=0 then E()end
 elseif F.__obf_proto_parent>=id then E()end;
 local legacy=MF(F.__obf_proto_flags/2)%2;
 if legacy==1 and (F.__obf_proto_flags%2==0 or F.__obf_proto_p>=F.__obf_proto_m)or MF(F.__obf_proto_flags/4)%2==1 and legacy==0 then E()end;
"#,
    );
    if program.target.is_luau() {
        s.push_str("if legacy~=0 then E()end;");
    } else {
        s.push_str("if F.__obf_proto_shared then E()end;");
    }
    s.push_str(
        r#"
 work=work+F.__obf_proto_nu+F.__obf_proto_nk+F.__obf_proto_nc;if work>1000000 then E()end;
 for j=0,F.__obf_proto_nu-1 do local tag,index=b8(),b8();local parent=P[F.__obf_proto_parent];
  if tag>2 or not parent or tag~=1 and index>=parent.__obf_proto_m or tag==1 and index>=parent.__obf_proto_nu then E()end;
  if tag==2 then if not F.__obf_proto_shared or F.__obf_proto_self~=nil then E()end;F.__obf_proto_self=j end;
  F.__obf_proto_u[j]={tag,index};
 end;
 for j=0,F.__obf_proto_nk-1 do local tag=b8();F.__obf_proto_tags[j]=tag;
  if tag==0 then F.__obf_proto_k[j]=nil
  elseif tag==1 then local v=b8();if v>1 then E()end;F.__obf_proto_k[j]=v==1
  elseif tag==2 then F.__obf_proto_k[j]=num()
  elseif tag==3 or tag==5 then F.__obf_proto_k[j]=str()
"#,
    );
    if program.target.is_luau() {
        s.push_str(r#"elseif tag==4 then local lo,hi=b32(),b32();if not IF then E()end;local v=IF(SF('%08x%08x',hi,lo),16);if v==nil then E()end;F.__obf_proto_k[j]=v;"#);
    }
    s.push_str("else E()end end;F.__obf_proto_code=take(F.__obf_proto_nc*4);P[id]=F;end;if bp~=#B+1 then E()end;B=nil;");
    // Both Rust and target decoders validate operands before any execution.
    s.push_str("for id=0,np-1 do local F=P[id];for at=0,F.__obf_proto_nc-1 do local o,a,b,c=SB(F.__obf_proto_code,at*4+1,at*4+4);local k=b+c*256;local j=a+k*256;local ok=false;");
    for (index, op) in program.opcodes().iter().enumerate() {
        write!(
            s,
            "{} o=={} then ok={};",
            if index == 0 { "if" } else { "elseif" },
            *op as u8,
            validation(*op)
        )
        .unwrap();
    }
    s.push_str("else E()end;if not ok then E()end;end;local last=SB(F.__obf_proto_code,#F.__obf_proto_code-3);");
    write!(
        s,
        "if last~={} and last~={} and last~={} then E()end;end;",
        Opcode::Jump as u8,
        Opcode::Return as u8,
        Opcode::TailCall as u8
    )
    .unwrap();
    s.push_str(
        r#"
local CV=function(cell)if cell[2]then return cell[2][cell[3]]else return cell[1]end end;
local SV=function(cell,value)if cell[2]then cell[2][cell[3]]=value else cell[1]=value end end;
"#,
    );
    if program.target.is_luau() && !program.methods().is_empty() {
        s.push_str("local Lookup=function(object,key)if TY(object)=='userdata'then ");
        for (index, method) in program.methods().iter().enumerate() {
            write!(s, "{} key==", if index == 0 { "if" } else { "elseif" }).unwrap();
            super::lua51::emit_byte_string(&mut s, method.as_bytes());
            write!(
                s,
                " then return function(_,...)return object:{method}(...)end;"
            )
            .unwrap();
        }
        s.push_str("else E()end;end;return object[key]end;");
    } else {
        if program.target.is_luau() {
            // Without a static method identifier we cannot synthesize a
            // faithful userdata NAMECALL; never silently use indexing instead.
            s.push_str("local Lookup=function(object,key)if TY(object)=='userdata'then E()end;return object[key]end;");
        } else {
            s.push_str("local Lookup=function(object,key)return object[key]end;");
        }
    }
    s.push_str(r#"
local W=SM({},{__mode='kv'});local H;local Make;
local Call=function(fn,args)local d=W[fn];if d then return H(d[1],args,d[2])else return Z(fn(U(args,1,args.n)))end end;
Make=function(id,up)
 local F=P[id];local cached=F.__obf_proto_cached;
 if cached then local previous=W[cached][2];local same=true;
  for j=0,F.__obf_proto_nu-1 do if j~=F.__obf_proto_self and not RE(CV(previous[j]),CV(up[j]))then same=false;break end end;
  if same then return cached end;
 end;
 local d={id,up};local fn=function(...)local v=H(d[1],Z(...),d[2]);return U(v,1,v.n)end;W[fn]=d;
 if F.__obf_proto_shared and not cached then F.__obf_proto_cached=fn end;return fn
end;
H=function(fid,args,ups)
 while true do
  local F=P[fid];local R={};local n=args.n-F.__obf_proto_p;if n<0 then n=0 end;
  local va={n=n};for i=1,n do va[i]=args[F.__obf_proto_p+i]end;
  for i=0,F.__obf_proto_p-1 do R[i]={args[i+1]}end;
  if MF(F.__obf_proto_flags/2)%2==1 then R[F.__obf_proto_p]={};if MF(F.__obf_proto_flags/4)%2==1 then local v={n=n};for i=1,n do v[i]=va[i]end;R[F.__obf_proto_p][1]=v end end;
  local pc=1;local code=F.__obf_proto_code;
  while true do
   local o,a,b,c=SB(code,pc,pc+3);if c==nil then E()end;pc=pc+4;
   local k=b+c*256;local j=a+k*256;
"#);
    for (index, op) in program.opcodes().iter().enumerate() {
        let code = super::opcode::custom(program.target, *op)
            .ok_or_else(|| Diagnostic::new("missing custom opcode implementation"))?;
        write!(
            s,
            "{} o=={} then {}",
            if index == 0 { "if" } else { "elseif" },
            *op as u8,
            code
        )
        .unwrap();
    }
    s.push_str(
        "else E()end;end;end;end;local result=H(entry,Z(...),{});return U(result,1,result.n)",
    );
    if s.len() > crate::lexer::MAX_SOURCE_BYTES {
        return Err(Diagnostic::new(
            "generated custom VM exceeds source safety limit",
        ));
    }
    Ok(s)
}

fn validation(op: Opcode) -> &'static str {
    use Opcode::*;
    match op {
        Jump => "j<F.__obf_proto_nc",
        Constant => "a<F.__obf_proto_m and k<F.__obf_proto_nk",
        ReadGlobal | WriteGlobal => {
            "a<F.__obf_proto_m and (F.__obf_proto_tags[k]==3 or F.__obf_proto_tags[k]==5)"
        }
        Closure => "a<F.__obf_proto_m and P[k]~=nil and P[k].__obf_proto_parent==id",
        ReadUpvalue | WriteUpvalue => "a<F.__obf_proto_m and b<F.__obf_proto_nu and c==0",
        Extract => "a<F.__obf_proto_m and b<F.__obf_proto_m and c>0",
        Clear => "a<=b and b<F.__obf_proto_m and c==0",
        NumberPrepare | NumberStep => "a+2<F.__obf_proto_m and b==0 and c==0",
        NumberTest => "a<F.__obf_proto_m and b+2<F.__obf_proto_m and c==0",
        Test => "a<F.__obf_proto_m and b==0 and c==0 and at+2<F.__obf_proto_nc",
        Varargs => "a<F.__obf_proto_m and b==0 and c==0 and F.__obf_proto_flags%2==1",
        Nil | NewTable | NewPack | IteratorPrepare | Return | Freeze => {
            "a<F.__obf_proto_m and b==0 and c==0"
        }
        Move | NewCell | ReadCell | WriteCell | Push | Extend | Not | Negate | Length
        | IteratorNext | ToString | TailCall => "a<F.__obf_proto_m and b<F.__obf_proto_m and c==0",
        GetTable | SetTable | Method | Call | Add | Subtract | Multiply | Divide | FloorDivide
        | Modulo | Power | Concat | Equal | Less | LessEqual | SetList | Export => {
            "a<F.__obf_proto_m and b<F.__obf_proto_m and c<F.__obf_proto_m"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{self, Instruction as I, Terminator as T};
    use std::collections::BTreeSet;
    use std::fs;
    use std::process::Command;

    mod native {
        use crate as obf;
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/mod.rs"));
    }

    fn blob(source: &str, target: Target) -> Vec<u8> {
        let chunk = crate::parse(source, target).unwrap();
        assert!(crate::vm::tests::no_inline_metadata(&chunk));
        let tokens = crate::lexer::lex(source, target).unwrap();
        let found: Vec<_> = tokens
            .iter()
            .filter_map(|token| {
                if token.kind != crate::lexer::TokenKind::String {
                    return None;
                }
                let value =
                    crate::minify::literal_bytes(&source[token.span.start..token.span.end], target)
                        .unwrap();
                value.starts_with(b"OBF\x02").then_some(value)
            })
            .collect();
        assert_eq!(found.len(), 1);
        found.into_iter().next().unwrap()
    }

    #[test]
    fn custom_finalizer_changes_every_explicit_local_and_never_changes_bytecode() {
        for target in [Target::Lua51, Target::Luau] {
            let data = compile(
                "local function add(a,b)return a+b end print(add(1,2))",
                target,
            )
            .unwrap();
            let program = custom::decode(&data, target).unwrap();
            let raw = generate(&data, &program).unwrap();
            let before = crate::scope::analyze(&raw, target).unwrap();
            let mut layouts = BTreeSet::new();
            for seed in [0, 1, 735, u64::MAX] {
                let output = emit(&data, target, seed).unwrap();
                assert_eq!(emit(&data, target, seed).unwrap(), output);
                assert_eq!(blob(&raw, target), data);
                assert_eq!(blob(&output, target), data);
                assert!(!output.contains(['\r', '\n']));
                let after = crate::scope::analyze(&output, target).unwrap();
                assert_eq!(before.globals, after.globals);
                let mut groups = BTreeSet::new();
                let mut spellings = BTreeSet::new();
                for (old, new) in before.bindings.iter().zip(&after.bindings) {
                    if old.declaration.is_some() {
                        assert_ne!(old.name, new.name);
                        assert!((1..=2).contains(&new.name.len()));
                        assert!(new.name.bytes().all(|b| b.is_ascii_lowercase()));
                        assert!(
                            groups.insert((after.scopes[new.scope].name_scope, new.name.clone()))
                        );
                        spellings.insert(new.name.clone());
                    } else {
                        assert_eq!(old.name, new.name);
                    }
                }
                assert!(groups.len() > 100);
                assert!(spellings.len() < groups.len());
                assert!(layouts.insert(
                    after
                        .bindings
                        .iter()
                        .map(|b| b.name.clone())
                        .collect::<Vec<_>>()
                ));
            }
        }
    }

    fn execute_coverage(data: &[u8], target: Target) -> BTreeSet<Opcode> {
        let program = custom::decode(data, target).unwrap();
        let raw = generate(data, &program).unwrap();
        // Instrument the real fetch loop BEFORE the same final whole-output
        // naming/audit pass. This measures executed handlers, not just words
        // present in dead branches or uncalled prototypes.
        assert_eq!(raw.matches("if c==nil then E()end;pc=pc+4;").count(), 1);
        let raw=raw.replace("if c==nil then E()end;pc=pc+4;","if c==nil then E()end;pc=pc+4;Probe[o]=true;")
            .replace("return U(result,1,result.n)","for id in ProbePairs(Probe)do ProbePrint('opcode:'..id)end;return U(result,1,result.n)");
        let raw = format!("local Probe={{}};local ProbePrint,ProbePairs=print,pairs;{raw}");
        let output = finalize(&raw, target, 735).unwrap();
        let work = native::Workspace::new();
        let path = work.0.join("coverage.lua");
        fs::write(&path, output).unwrap();
        let stdout = native::compile_and_run(target, &path);
        String::from_utf8(stdout)
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_prefix("opcode:"))
            .map(|id| Opcode::from_byte(id.parse().unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn every_supported_opcode_is_actually_executed_in_the_target_runtime() {
        for (target, corpora) in [
            (
                Target::Lua51,
                [
                    include_str!("../../tests/fixtures/vm_lua51.lua"),
                    include_str!("../../tests/fixtures/scope_lua51.lua"),
                ],
            ),
            (
                Target::Luau,
                [
                    include_str!("../../tests/fixtures/vm_luau.lua"),
                    include_str!("../../tests/fixtures/scope_luau.lua"),
                ],
            ),
        ] {
            let mut executed = BTreeSet::new();
            for corpus in corpora {
                executed.extend(execute_coverage(&compile(corpus, target).unwrap(), target));
            }
            // TOSTRING is directly useful in handwritten Lua 5.1 IR as well as
            // Luau interpolation; prove its value, not a synthetic no-op hit.
            let mut module = ir::compile("return", target).unwrap();
            let f = &mut module.functions[0];
            f.registers = 7;
            f.constants = vec![
                ir::Constant::number(42.0),
                ir::Constant::String(b"42".to_vec()),
                ir::Constant::String(b"assert".to_vec()),
            ];
            f.blocks = vec![ir::Block {
                instructions: vec![
                    I::Constant(0, 0),
                    I::ToString(1, 0),
                    I::Constant(2, 1),
                    I::Binary(crate::ast::BinaryOperator::Equal, 3, 1, 2),
                    I::ReadGlobal(4, 2),
                    I::NewPack(5),
                    I::Push(5, 3),
                    I::Call(6, 4, 5),
                    I::NewPack(0),
                ],
                terminator: T::Return(0),
            }];
            executed.extend(execute_coverage(&custom::encode(&module).unwrap(), target));
            let expected: BTreeSet<_> = Opcode::ALL
                .iter()
                .copied()
                .filter(|op| op.supported(target))
                .collect();
            assert_eq!(executed, expected, "unexecuted custom opcode on {target}");
        }
    }

    #[test]
    fn target_decoder_rejects_corrupt_repaired_payload_before_user_code_runs() {
        for target in [Target::Lua51, Target::Luau] {
            let data = compile("print('MUST_NOT_RUN')", target).unwrap();
            let program = custom::decode(&data, target).unwrap();
            for kind in 0..5 {
                let mut bad = data.clone();
                match kind {
                    0 => bad[39] = 255,
                    1 => bad[36..38].copy_from_slice(&257u16.to_le_bytes()),
                    2 => bad[48..52].copy_from_slice(&u32::MAX.to_le_bytes()),
                    3 => {
                        let last = bad.len() - 4;
                        bad[last..].copy_from_slice(&[Opcode::Jump as u8, 255, 255, 255]);
                    }
                    _ => {
                        let last = bad.len() - 4;
                        bad[last + 1] = 255;
                    }
                }
                let checksum = custom::checksum(&bad[32..]);
                bad[28..32].copy_from_slice(&checksum.to_le_bytes());
                assert!(custom::decode(&bad, target).is_err());
                // Bypass only Rust's input gate inside this unit test to
                // independently exercise the emitted target-language gate.
                let raw = generate(&bad, &program).unwrap();
                let output = finalize(&raw, target, 735).unwrap();
                let work = native::Workspace::new();
                let path = work.0.join("invalid.lua");
                fs::write(&path, output).unwrap();
                assert!(native::compile(target, &path).status.success());
                let runner = if target.is_luau() { "luau" } else { "lua5.1" };
                let result = Command::new(native::root().join("toolchains/bin").join(runner))
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(!result.status.success());
                assert!(result.stdout.is_empty());
            }
        }
    }

    #[test]
    fn target_decoder_independently_rejects_invalid_closure_sharing_metadata() {
        let source = "local function f(n)if n>0 then return f(n-1)end return 3 end print('MUST_NOT_RUN',f(2))";
        let data = compile(source, Target::Luau).unwrap();
        let program = custom::decode(&data, Target::Luau).unwrap();
        let root = &program.prototypes[0];
        let constant_bytes: usize = root
            .constants
            .iter()
            .map(|c| match c {
                ir::Constant::Nil => 1,
                ir::Constant::Boolean(_) => 2,
                ir::Constant::Number(_) | ir::Constant::Integer(_) => 9,
                ir::Constant::String(s) => 5 + s.len(),
                ir::Constant::Method(s) => 5 + s.len(),
            })
            .sum();
        let child = 32 + 20 + root.captures.len() * 2 + constant_bytes + root.code.len() * 4;
        assert_eq!(data[child + 20], 2);
        for kind in 0..5 {
            let mut bad = data.clone();
            match kind {
                0 => bad[24..28].copy_from_slice(&1u32.to_le_bytes()),
                1 => bad[child + 7] &= !8,
                2 => bad[child + 7] |= 16,
                3 => bad[child + 20] = 3,
                _ => bad[child + 21] = 255,
            }
            let checksum = custom::checksum(&bad[32..]);
            bad[28..32].copy_from_slice(&checksum.to_le_bytes());
            assert!(custom::decode(&bad, Target::Luau).is_err());
            let raw = generate(&bad, &program).unwrap();
            let output = finalize(&raw, Target::Luau, 735).unwrap();
            let work = native::Workspace::new();
            let path = work.0.join("invalid.luau");
            fs::write(&path, output).unwrap();
            assert!(native::compile(Target::Luau, &path).status.success());
            let result = Command::new(native::root().join("toolchains/bin/luau"))
                .arg(path)
                .output()
                .unwrap();
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
        }
    }
}
