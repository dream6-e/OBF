use crate::bytecode::custom::Opcode;
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

    /// Build the two frame-local register closures used by ISA12-C. `RX`
    /// maps logical ids to the private physical bank. `RF` is the fused-read
    /// forwarding primitive: when a second primitive consumes the first
    /// primitive's destination it returns the carried value directly,
    /// including nil/false, rather than loading the just-written register.
    ///
    /// The forwarding predicate follows the same per-prototype family as the
    /// register mapper (logical equality, inverted equality, physical-key
    /// equality, or a shifted mod-257 equality). Thus fused handlers remain
    /// shared globally while their register/dataflow ABI differs by frame; no
    /// 256-entry map and no per-prototype handler copy is emitted.
    pub(crate) fn factory_lua(self) -> String {
        format!(
            "local RK=function(fid,R)local rf=(fid*{fm}+{fa})%4;local rs=(fid*{sm}+{sa})%127;local rt=(fid*{tm}+{ta})%257;local m=1+rs*2;local base=rf*257;local RX;if rf==0 then RX=function(r)return base+(r*m+rt)%257 end elseif rf==1 then RX=function(r)return base+256-(r*m+rt)%257 end elseif rf==2 then RX=function(r)return base+((255-r)*m+rt)%257 end else RX=function(r)return base+(((r+rt)%257)*m+rs)%257 end end;local RF;if rf==0 then RF=function(q,k,v)if q==k then return v end;return R[RX(q)]end elseif rf==1 then RF=function(q,k,v)if q~=k then return R[RX(q)]end;return v end elseif rf==2 then RF=function(q,k,v)local p=RX(q);if p==RX(k)then return v end;return R[p]end else RF=function(q,k,v)if (q+rt)%257==(k+rt)%257 then return v end;return R[RX(q)]end end;return RX,RF end;",
            fm = self.family_multiplier,
            fa = self.family_add,
            sm = self.stride_multiplier,
            sa = self.stride_add,
            tm = self.shift_multiplier,
            ta = self.shift_add,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DataflowFusion {
    pub(crate) producer: String,
    pub(crate) consumer: String,
    pub(crate) forwarded_reads: usize,
}

#[derive(Clone, Copy, Debug)]
struct RegisterAccess {
    token_index: usize,
    start: usize,
    end: usize,
    expression_start: usize,
    expression_end: usize,
    direct_write: bool,
}

fn register_accesses(
    source: &str,
    tokens: &[crate::lexer::Token],
) -> Result<Vec<RegisterAccess>, Diagnostic> {
    let mut accesses = Vec::new();
    for index in 0..tokens.len().saturating_sub(1) {
        if tokens[index].kind != TokenKind::Identifier
            || tokens[index].text(source) != "R"
            || tokens[index + 1].text(source) != "["
        {
            continue;
        }
        let mut depth = 0usize;
        let mut close_token_index = None;
        for (offset, token) in tokens[index + 1..].iter().enumerate() {
            match token.text(source) {
                "[" => depth += 1,
                "]" => {
                    depth = depth.checked_sub(1).ok_or_else(|| {
                        Diagnostic::new("generated register access has an unmatched bracket")
                    })?;
                    if depth == 0 {
                        close_token_index = Some(index + 1 + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close_token_index = close_token_index.ok_or_else(|| {
            Diagnostic::new("generated register access is missing its closing bracket")
        })?;
        let direct_write = tokens
            .get(close_token_index + 1)
            .is_some_and(|token| token.text(source) == "=");
        accesses.push(RegisterAccess {
            token_index: index,
            start: tokens[index].span.start,
            end: tokens[close_token_index].span.end,
            expression_start: tokens[index + 1].span.end,
            expression_end: tokens[close_token_index].span.start,
            direct_write,
        });
    }
    Ok(accesses)
}

fn is_control(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Jump | Opcode::Test | Opcode::Return | Opcode::TailCall
    )
}

fn one_statement_assignment<'a>(
    source: &'a str,
    target: Target,
) -> Result<Option<&'a str>, Diagnostic> {
    let tokens = crate::lexer::lex(source, target)?;
    let live = tokens
        .iter()
        .filter(|token| token.kind != TokenKind::Eof)
        .collect::<Vec<_>>();
    if live.len() < 7
        || live[0].kind != TokenKind::Identifier
        || live[0].text(source) != "R"
        || live[1].text(source) != "["
        || live[2].text(source) != "a"
        || live[3].text(source) != "]"
        || live[4].text(source) != "="
        || live.last().unwrap().text(source) != ";"
        || live
            .iter()
            .filter(|token| token.text(source) == ";")
            .count()
            != 1
    {
        return Ok(None);
    }
    let accesses = register_accesses(source, &tokens)?;
    if accesses.is_empty()
        || accesses[0].token_index != 0
        || !accesses[0].direct_write
        || accesses.iter().filter(|access| access.direct_write).count() != 1
    {
        return Ok(None);
    }
    let rhs_start = live[4].span.end;
    let rhs_end = live.last().unwrap().span.start;
    if source[rhs_start..rhs_end].trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(&source[rhs_start..rhs_end]))
}

fn fused_consumer(source: &str, target: Target) -> Result<Option<(String, usize)>, Diagnostic> {
    let tokens = crate::lexer::lex(source, target)?;
    let live = tokens
        .iter()
        .filter(|token| token.kind != TokenKind::Eof)
        .collect::<Vec<_>>();
    let accesses = register_accesses(source, &tokens)?;
    if accesses.is_empty() {
        return Ok(None);
    }
    // Overlapping R[R[...]] spans need a recursive rewrite. None of the
    // crate-owned primitive templates uses that shape, so reject it rather
    // than applying an ambiguous textual edit.
    if accesses.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Ok(None);
    }
    let writes = accesses.iter().filter(|access| access.direct_write).count();
    if writes > 1 {
        return Ok(None);
    }
    if writes == 1 {
        // A direct register write is safe only for the single-assignment
        // primitive shape R[a]=<expression>. Then all forwarded reads belong
        // to the RHS and happen before that assignment commits.
        if !accesses[0].direct_write
            || accesses[0].token_index != 0
            || live.last().is_none_or(|token| token.text(source) != ";")
            || live
                .iter()
                .filter(|token| token.text(source) == ";")
                .count()
                != 1
        {
            return Ok(None);
        }
    }
    let forwarded_reads = accesses
        .iter()
        .filter(|access| !access.direct_write)
        .count();
    if forwarded_reads == 0 {
        return Ok(None);
    }

    let mut replacements = Vec::with_capacity(accesses.len());
    for access in accesses {
        let expression = &source[access.expression_start..access.expression_end];
        let replacement = if access.direct_write {
            format!("R[RX({expression})]")
        } else {
            // RF's explicit third argument preserves both nil and false; an
            // and/or selector here would silently lose those values.
            format!("RF({expression},__obf_fl,__obf_fv)")
        };
        replacements.push((access.start, access.end, replacement));
    }
    let mut output = source.to_owned();
    for (start, end, replacement) in replacements.into_iter().rev() {
        output.replace_range(start..end, &replacement);
    }
    Ok(Some((output, forwarded_reads)))
}

/// Fuse two non-control primitive templates through an explicit value carry.
/// The first primitive must be a one-statement R[a] producer. The second may
/// either be another one-statement register producer or a primitive that only
/// reads/mutates register-held objects. Every read in the second template is
/// lowered to RF(logical, first_destination, carried_value), so a true
/// dependency bypasses the register reload while non-aliasing operands use the
/// current frame mapper. Unsupported shapes fail closed to two single
/// fragments; evaluation order and the first register write are retained.
pub(crate) fn fuse_dataflow_pair(
    first_op: Opcode,
    first_source: &str,
    second_op: Opcode,
    second_source: &str,
    target: Target,
) -> Result<Option<DataflowFusion>, Diagnostic> {
    if is_control(first_op) || is_control(second_op) {
        return Ok(None);
    }
    let Some(rhs) = one_statement_assignment(first_source, target)? else {
        return Ok(None);
    };
    let Some((consumer, forwarded_reads)) = fused_consumer(second_source, target)? else {
        return Ok(None);
    };
    let rhs = lower_register_accesses(rhs, target)?;
    Ok(Some(DataflowFusion {
        // RX(a) is deliberately evaluated before the RHS, matching Lua's
        // lvalue-before-rvalue assignment order even though RX is pure.
        producer: format!(
            "local __obf_fl=a;local __obf_fk=RX(__obf_fl);local __obf_fv={rhs};R[__obf_fk]=__obf_fv;"
        ),
        consumer,
        forwarded_reads,
    }))
}

/// Rewrite only the generated primitive template's register table accesses.
/// `R[index]` becomes `R[RX(index)]`, including range-loop and capture-derived
/// indices. Token spans, rather than global text replacement, protect strings
/// such as Luau metamethod names and diagnose an unbalanced generated template.
pub(crate) fn lower_register_accesses(source: &str, target: Target) -> Result<String, Diagnostic> {
    let tokens = crate::lexer::lex(source, target)?;
    let accesses = register_accesses(source, &tokens)?;
    let mut insertions: Vec<(usize, &'static str)> = Vec::with_capacity(accesses.len() * 2);
    for access in accesses {
        insertions.push((access.expression_start, "RX("));
        insertions.push((access.expression_end, ")"));
    }
    insertions.sort_unstable_by_key(|(offset, _)| *offset);
    let mut output = source.to_owned();
    for (offset, text) in insertions.into_iter().rev() {
        output.insert_str(offset, text);
    }
    Ok(output)
}
