use crate::lexer::TokenKind;
use crate::{Diagnostic, Target};

/// ISA12's per-prototype operand ABI. The three independently affine profile
/// components use pairwise-coprime moduli whose product is 32,772, so every one
/// of the at-most 32,767 private prototype ids receives a distinct
/// (family, rotation, lane) tuple. The Lua parser stores decoded operands
/// through that tuple and the interpreter recovers
/// them only when a semantic fragment runs; there is no image-wide `6+3*i`
/// operand convention left for a static handler scanner to reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OperandLayout {
    pub(crate) family_multiplier: u8,
    pub(crate) family_add: u8,
    pub(crate) rotation_multiplier: u8,
    pub(crate) rotation_add: u8,
    pub(crate) lane_multiplier: u16,
    pub(crate) lane_add: u16,
}

pub(crate) const OPERAND_LAYOUT_FAMILIES: usize = 4;
pub(crate) const OPERAND_LAYOUT_ROTATIONS: usize = 3;
// 2,731 is prime and 4 * 3 * 2,731 = 32,772, just above the private image's
// strict 32,767-prototype ceiling. The sparse numeric key remains at most 35,507.
pub(crate) const OPERAND_LAYOUT_LANES: usize = 2_731;
#[cfg(test)]
pub(crate) const OPERAND_LAYOUT_PRIVATE_PROTOTYPE_LIMIT: usize = 32_767;
#[cfg(test)]
pub(crate) const OPERAND_LAYOUT_UNIQUE_SPAN: usize =
    OPERAND_LAYOUT_FAMILIES * OPERAND_LAYOUT_ROTATIONS * OPERAND_LAYOUT_LANES;
pub(crate) const OPERAND_BINDING_FORMS: usize = 4;

pub(crate) fn operand_layout(seed: u64) -> OperandLayout {
    // This stream is independent of section/layout randomization. Adding a new
    // handler does not silently perturb the ABI selected for existing ids.
    let mut random = crate::random::Prng::new(seed ^ 0x6f70_6572_616e_6431);
    OperandLayout {
        family_multiplier: [1, 3][(random.next_u64() % 2) as usize],
        family_add: (random.next_u64() % OPERAND_LAYOUT_FAMILIES as u64) as u8,
        rotation_multiplier: [1, 2][(random.next_u64() % 2) as usize],
        rotation_add: (random.next_u64() % OPERAND_LAYOUT_ROTATIONS as u64) as u8,
        // 2,731 is prime, so every non-zero multiplier is invertible.
        lane_multiplier: (1 + random.next_u64() % (OPERAND_LAYOUT_LANES as u64 - 1)) as u16,
        lane_add: (random.next_u64() % OPERAND_LAYOUT_LANES as u64) as u16,
    }
}

impl OperandLayout {
    #[cfg(test)]
    pub(crate) fn profile(self, prototype: usize) -> (usize, usize, usize) {
        (
            (prototype * usize::from(self.family_multiplier) + usize::from(self.family_add))
                % OPERAND_LAYOUT_FAMILIES,
            (prototype * usize::from(self.rotation_multiplier) + usize::from(self.rotation_add))
                % OPERAND_LAYOUT_ROTATIONS,
            (prototype * usize::from(self.lane_multiplier) + usize::from(self.lane_add))
                % OPERAND_LAYOUT_LANES,
        )
    }

    /// Lua definitions shared by the strict validator and the interpreter.
    /// Four layouts are intentionally structurally different:
    ///
    /// 0. one rotated packed-u24 slot;
    /// 1. reverse-indexed AC pair plus a separate B lane;
    /// 2. three rotated transposed columns;
    /// 3. reverse-indexed table with rotated component keys.
    ///
    /// `form` also changes the five-result binding order. Every caller lists
    /// the matching lvalues, so this is semantic-preserving while removing the
    /// report's one canonical `a,b,c=record[...] ; k=... ; j=...` prelude.
    pub(crate) fn getter_lua(self) -> String {
        format!(
            "local OG=function(fid,I,qi,form)local om=(fid*{fm}+{fa})%4;local rot=(fid*{rm}+{ra})%3;local lane=(fid*{lm}+{la})%{lanes};local ob=6+lane*13;local a,b,c,v=0,0,0,0;if om==0 then v=I[ob+(qi-1+rot)%4];a=v%256;v=(v-a)/256;b=v%256;c=(v-b)/256 elseif om==1 then local at=ob+4-qi;v=I[at];a=v%256;c=(v-a)/256;b=I[at+4]elseif om==2 then a=I[ob+qi-1+rot*4];b=I[ob+qi-1+((rot+1)%3)*4];c=I[ob+qi-1+((rot+2)%3)*4]else v=I[ob+4-qi];a=v[1+rot];b=v[1+(rot+1)%3];c=v[1+(rot+2)%3]end;local k=b+c*256;local j=a+k*256;if form==0 then return a,b,c,k,j elseif form==1 then return j,c,a,k,b elseif form==2 then return b,j,k,a,c else return k,a,j,c,b end end;",
            fm = self.family_multiplier,
            fa = self.family_add,
            rm = self.rotation_multiplier,
            ra = self.rotation_add,
            lm = self.lane_multiplier,
            la = self.lane_add,
            lanes = OPERAND_LAYOUT_LANES,
        )
    }

    /// Compute one prototype's profile once before its records are normalized.
    pub(crate) fn parser_profile_lua(self) -> String {
        format!(
            "local om=(id*{fm}+{fa})%4;local rot=(id*{rm}+{ra})%3;local lane=(id*{lm}+{la})%{lanes};local ob=6+lane*13;",
            fm = self.family_multiplier,
            fa = self.family_add,
            rm = self.rotation_multiplier,
            ra = self.rotation_add,
            lm = self.lane_multiplier,
            la = self.lane_add,
            lanes = OPERAND_LAYOUT_LANES,
        )
    }

    /// Store the current decoder locals `a,b,c` for operation `qi` according
    /// to the current prototype's `om,rot,ob` profile locals.
    pub(crate) fn parser_store_lua() -> &'static str {
        "if om==0 then I[ob+(qi-1+rot)%4]=a+b*256+c*65536 elseif om==1 then local at=ob+4-qi;I[at]=a+c*256;I[at+4]=b elseif om==2 then I[ob+qi-1+rot*4]=a;I[ob+qi-1+((rot+1)%3)*4]=b;I[ob+qi-1+((rot+2)%3)*4]=c else local v={};v[1+rot]=a;v[1+(rot+1)%3]=b;v[1+(rot+2)%3]=c;I[ob+4-qi]=v end;"
    }
}

pub(crate) fn operand_binding_lhs(form: usize) -> &'static str {
    match form {
        0 => "a,b,c,k,j",
        1 => "j,c,a,k,b",
        2 => "b,j,k,a,c",
        3 => "k,a,j,c,b",
        _ => panic!("invalid operand binding form"),
    }
}

pub(crate) fn operand_binding_lua(operation: usize, form: usize) -> String {
    format!(
        "{}=OG(fid,I,{operation},{form});",
        operand_binding_lhs(form)
    )
}

/// ISA12-B's private register ABI. The profile moduli are pairwise coprime and
/// have a 130,556-id product, so the complete 32,767-prototype private range has
/// no repeated (family, stride, shift) tuple. Each family maps the 256 logical
/// register ids injectively into one of four disjoint 257-key physical banks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegisterLayout {
    pub(crate) family_multiplier: u8,
    pub(crate) family_add: u8,
    pub(crate) stride_multiplier: u8,
    pub(crate) stride_add: u8,
    pub(crate) shift_multiplier: u16,
    pub(crate) shift_add: u16,
}

pub(crate) const REGISTER_LAYOUT_FAMILIES: usize = 4;
pub(crate) const REGISTER_LAYOUT_STRIDES: usize = 127;
pub(crate) const REGISTER_LAYOUT_SHIFTS: usize = 257;
#[cfg(test)]
pub(crate) const REGISTER_LAYOUT_LOGICAL_SLOTS: usize = 256;
#[cfg(test)]
pub(crate) const REGISTER_LAYOUT_PHYSICAL_SLOTS: usize =
    REGISTER_LAYOUT_FAMILIES * REGISTER_LAYOUT_SHIFTS;
#[cfg(test)]
pub(crate) const REGISTER_LAYOUT_PRIVATE_PROTOTYPE_LIMIT: usize = 32_767;
#[cfg(test)]
pub(crate) const REGISTER_LAYOUT_UNIQUE_SPAN: usize =
    REGISTER_LAYOUT_FAMILIES * REGISTER_LAYOUT_STRIDES * REGISTER_LAYOUT_SHIFTS;

pub(crate) fn register_layout(seed: u64) -> RegisterLayout {
    let mut random = crate::random::Prng::new(seed ^ 0x7265_6769_7374_6572);
    RegisterLayout {
        family_multiplier: [1, 3][(random.next_u64() % 2) as usize],
        family_add: (random.next_u64() % REGISTER_LAYOUT_FAMILIES as u64) as u8,
        // 127 and 257 are prime, so all non-zero multipliers are invertible.
        stride_multiplier: (1 + random.next_u64() % 126) as u8,
        stride_add: (random.next_u64() % REGISTER_LAYOUT_STRIDES as u64) as u8,
        shift_multiplier: (1 + random.next_u64() % 256) as u16,
        shift_add: (random.next_u64() % REGISTER_LAYOUT_SHIFTS as u64) as u16,
    }
}

impl RegisterLayout {
    #[cfg(test)]
    pub(crate) fn profile(self, prototype: usize) -> (usize, usize, usize) {
        (
            (prototype * usize::from(self.family_multiplier) + usize::from(self.family_add))
                % REGISTER_LAYOUT_FAMILIES,
            (prototype * usize::from(self.stride_multiplier) + usize::from(self.stride_add))
                % REGISTER_LAYOUT_STRIDES,
            (prototype * usize::from(self.shift_multiplier) + usize::from(self.shift_add))
                % REGISTER_LAYOUT_SHIFTS,
        )
    }

    #[cfg(test)]
    pub(crate) fn physical_key(self, prototype: usize, register: usize) -> usize {
        debug_assert!(register < REGISTER_LAYOUT_LOGICAL_SLOTS);
        let (family, stride, shift) = self.profile(prototype);
        let multiplier = 1 + stride * 2;
        let offset = match family {
            0 => (register * multiplier + shift) % REGISTER_LAYOUT_SHIFTS,
            1 => {
                REGISTER_LAYOUT_SHIFTS
                    - 1
                    - (register * multiplier + shift) % REGISTER_LAYOUT_SHIFTS
            }
            2 => {
                ((REGISTER_LAYOUT_LOGICAL_SLOTS - 1 - register) * multiplier + shift)
                    % REGISTER_LAYOUT_SHIFTS
            }
            3 => {
                (((register + shift) % REGISTER_LAYOUT_SHIFTS) * multiplier + stride)
                    % REGISTER_LAYOUT_SHIFTS
            }
            _ => unreachable!(),
        };
        family * REGISTER_LAYOUT_SHIFTS + offset
    }

    /// Build a frame-local logical-register mapper. Computing the profile once
    /// per frame avoids repeating its affine derivation at every register use;
    /// selecting one of four closure bodies also gives the families distinct
    /// target-side shapes without storing an explicit register permutation.
    pub(crate) fn factory_lua(self) -> String {
        format!(
            "local RK=function(fid)local rf=(fid*{fm}+{fa})%4;local rs=(fid*{sm}+{sa})%127;local rt=(fid*{tm}+{ta})%257;local m=1+rs*2;local base=rf*257;if rf==0 then return function(r)return base+(r*m+rt)%257 end elseif rf==1 then return function(r)return base+256-(r*m+rt)%257 end elseif rf==2 then return function(r)return base+((255-r)*m+rt)%257 end else return function(r)return base+(((r+rt)%257)*m+rs)%257 end end end;",
            fm = self.family_multiplier,
            fa = self.family_add,
            sm = self.stride_multiplier,
            sa = self.stride_add,
            tm = self.shift_multiplier,
            ta = self.shift_add,
        )
    }
}

/// Rewrite only the generated primitive template's register table accesses.
/// `R[index]` becomes `R[RX(index)]`, including range-loop and capture-derived
/// indices. Token spans, rather than global text replacement, protect strings
/// such as Luau metamethod names and diagnose an unbalanced generated template.
pub(crate) fn lower_register_accesses(source: &str, target: Target) -> Result<String, Diagnostic> {
    let tokens = crate::lexer::lex(source, target)?;
    let mut insertions: Vec<(usize, &'static str)> = Vec::new();
    for index in 0..tokens.len().saturating_sub(1) {
        if tokens[index].kind != TokenKind::Identifier
            || tokens[index].text(source) != "R"
            || tokens[index + 1].text(source) != "["
        {
            continue;
        }
        let mut depth = 0usize;
        let mut close = None;
        for token in &tokens[index + 1..] {
            match token.text(source) {
                "[" => depth += 1,
                "]" => {
                    depth = depth.checked_sub(1).ok_or_else(|| {
                        Diagnostic::new("generated register access has an unmatched bracket")
                    })?;
                    if depth == 0 {
                        close = Some(token.span.start);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.ok_or_else(|| {
            Diagnostic::new("generated register access is missing its closing bracket")
        })?;
        insertions.push((tokens[index + 1].span.end, "RX("));
        insertions.push((close, ")"));
    }
    insertions.sort_unstable_by_key(|(offset, _)| *offset);
    let mut output = source.to_owned();
    for (offset, text) in insertions.into_iter().rev() {
        output.insert_str(offset, text);
    }
    Ok(output)
}
