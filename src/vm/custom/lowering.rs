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

/// ISA13's private field-order layout. Every multi-field wire structure is
/// parsed as anonymous fixed-width slots; the slot-to-meaning map is never a
/// fixed canonical order:
///
/// * record headers (4 x u16) use a per-prototype permutation computed from
///   `(prototype * multiplier + add) % 24` with a multiplier coprime to 24,
///   decoded by an identical factorial routine on both ends;
/// * segment tokens (3 x u16) use a per-segment permutation computed from
///   `(physical_slot * multiplier + add) % 6`;
/// * dictionary entry headers ([rid:u16, len:u8] vs [len:u8, rid:u8]), the
///   prototype metadata width groups (u32 x 4, u16 x 3, u8 x 2) and the
///   in-memory record tuple slots are per-image permutations baked into the
///   generated parser text, so only one order is ever visible per script.
///
/// Fixed-width slot reads stay in place; only the semantic assignment
/// permutes. A wrong order trips the pre-existing label/token/operand/count
/// gates before any user code runs. No complete permutation table is emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FieldLayout {
    pub(crate) record_mul: u8,
    pub(crate) record_add: u8,
    pub(crate) segment_mul: u8,
    pub(crate) segment_add: u8,
    pub(crate) dict_flipped: bool,
    /// u32 metadata field at each wire slot: 0=parent, 1=nk, 2=nc, 3=codelen.
    pub(crate) meta_u32: [u8; 4],
    /// u16 metadata field at each wire slot: 0=registers, 1=nu, 2=root.
    pub(crate) meta_u16: [u8; 3],
    /// u8 metadata field at each wire slot: 0=parameters, 1=flags.
    pub(crate) meta_u8: [u8; 2],
    /// Record field at each in-memory tuple slot: 0=token, 1=next, 2=skip.
    pub(crate) tuple: [u8; 3],
}

pub(crate) const FIELD_RECORD_ORDERS: usize = 24;
pub(crate) const FIELD_SEGMENT_ORDERS: usize = 6;

/// Byte offsets of prototype metadata fields under an [`FieldLayout`].
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct MetadataPositions {
    pub parent: usize,
    pub registers: usize,
    pub parameters: usize,
    pub flags: usize,
    pub captures: usize,
    pub root: usize,
    pub constants: usize,
    pub records: usize,
    pub code_len: usize,
}

pub(crate) fn field_layout(seed: u64) -> FieldLayout {
    // Independent stream: adding a field never perturbs operand, register,
    // section, or transport randomization.
    let mut random = crate::random::Prng::new(seed ^ 0x6669_656c_645f_3133);
    let units_24 = [1u8, 5, 7, 11, 13, 17, 19, 23];
    let mut meta_u32 = [0u8, 1, 2, 3];
    random.shuffle(&mut meta_u32);
    let mut meta_u16 = [0u8, 1, 2];
    random.shuffle(&mut meta_u16);
    let mut meta_u8 = [0u8, 1];
    random.shuffle(&mut meta_u8);
    let mut tuple = [0u8, 1, 2];
    random.shuffle(&mut tuple);
    FieldLayout {
        record_mul: units_24[(random.next_u64() % units_24.len() as u64) as usize],
        record_add: (random.next_u64() % FIELD_RECORD_ORDERS as u64) as u8,
        segment_mul: [1u8, 5][(random.next_u64() % 2) as usize],
        segment_add: (random.next_u64() % FIELD_SEGMENT_ORDERS as u64) as u8,
        dict_flipped: random.next_u64() % 2 == 1,
        meta_u32,
        meta_u16,
        meta_u8,
        tuple,
    }
}

/// Factorial (factoradic) decode shared conceptually by the Rust encoder and
/// the generated Lua parser. Returns the field index stored at each wire
/// slot, in slot order. Both ends implement this same loop; execution parity
/// tests prove they agree.
pub(crate) fn factorial_field_at_slot(q: usize, fields: usize) -> Vec<usize> {
    let mut remaining: Vec<usize> = (0..fields).collect();
    let mut order = Vec::with_capacity(fields);
    let mut q = q;
    for position in 1..=fields {
        let mut divisor = 1usize;
        for factor in 2..=(fields - position) {
            divisor *= factor;
        }
        let index = q / divisor;
        q %= divisor;
        order.push(remaining.remove(index));
    }
    order
}

fn invert_order(field_at_slot: &[usize]) -> Vec<usize> {
    let mut slot_of_field = vec![0usize; field_at_slot.len()];
    for (slot, &field) in field_at_slot.iter().enumerate() {
        slot_of_field[field] = slot;
    }
    slot_of_field
}

impl FieldLayout {
    pub(crate) fn record_quotient(self, prototype: usize) -> usize {
        (prototype * usize::from(self.record_mul) + usize::from(self.record_add))
            % FIELD_RECORD_ORDERS
    }

    pub(crate) fn segment_quotient(self, physical_slot: usize) -> usize {
        debug_assert!(physical_slot >= 1);
        (physical_slot * usize::from(self.segment_mul) + usize::from(self.segment_add))
            % FIELD_SEGMENT_ORDERS
    }

    /// Byte offsets (relative to the 24-byte header start) of each metadata
    /// field under the per-image width-group permutation. Consumed only by
    /// the verification harness, which must parse the same anonymous slots.
    #[cfg(test)]
    pub(crate) fn metadata_positions(self) -> MetadataPositions {
        const WIDE_SLOTS: [usize; 4] = [0, 12, 16, 20];
        const MEDIUM_SLOTS: [usize; 3] = [4, 8, 10];
        const NARROW_SLOTS: [usize; 2] = [6, 7];
        let mut wide = [0usize; 4];
        for (slot, &field) in self.meta_u32.iter().enumerate() {
            wide[field as usize] = WIDE_SLOTS[slot];
        }
        let mut medium = [0usize; 3];
        for (slot, &field) in self.meta_u16.iter().enumerate() {
            medium[field as usize] = MEDIUM_SLOTS[slot];
        }
        let mut narrow = [0usize; 2];
        for (slot, &field) in self.meta_u8.iter().enumerate() {
            narrow[field as usize] = NARROW_SLOTS[slot];
        }
        MetadataPositions {
            parent: wide[0],
            constants: wide[1],
            records: wide[2],
            code_len: wide[3],
            registers: medium[0],
            captures: medium[1],
            root: medium[2],
            parameters: narrow[0],
            flags: narrow[1],
        }
    }

    /// Wire-slot position of each record field
    /// ([label, next_token, skip_token, recipe_token]).
    #[cfg(test)]
    pub(crate) fn record_field_slots(self, prototype: usize) -> [usize; 4] {
        let order = factorial_field_at_slot(self.record_quotient(prototype), 4);
        let inverted = invert_order(&order);
        [inverted[0], inverted[1], inverted[2], inverted[3]]
    }

    /// Field index at each record wire slot, in slot order.
    pub(crate) fn record_slot_fields(self, prototype: usize) -> [usize; 4] {
        let order = factorial_field_at_slot(self.record_quotient(prototype), 4);
        [order[0], order[1], order[2], order[3]]
    }

    /// Wire-slot position of each segment token ([id, owner, next]).
    /// `physical_slot` is the Lua-visible 1-based pool position.
    #[cfg(test)]
    pub(crate) fn segment_field_slots(self, physical_slot: usize) -> [usize; 3] {
        let order = factorial_field_at_slot(self.segment_quotient(physical_slot), 3);
        let inverted = invert_order(&order);
        [inverted[0], inverted[1], inverted[2]]
    }

    /// Token index at each segment wire slot, in slot order.
    pub(crate) fn segment_slot_fields(self, physical_slot: usize) -> [usize; 3] {
        let order = factorial_field_at_slot(self.segment_quotient(physical_slot), 3);
        [order[0], order[1], order[2]]
    }

    /// In-memory tuple slot (1-based Lua index) of each record field
    /// ([token, next_token, skip_token]).
    pub(crate) fn tuple_slots(self) -> [usize; 3] {
        let order: Vec<usize> = self.tuple.iter().map(|&slot| slot as usize).collect();
        let inverted = invert_order(&order);
        [inverted[0] + 1, inverted[1] + 1, inverted[2] + 1]
    }

    /// Per-prototype record-order decode. Emits `ford[1..4]`, the 1-based wire
    /// slot of [label, next, skip, recipe]. Runs once per prototype before its
    /// record loop; `id` is the parser loop variable. Uses only exact integer
    /// arithmetic and small tables, so Lua 5.1 and Luau agree bit for bit.
    pub(crate) fn record_profile_lua(self) -> String {
        format!(
            "local fq=(id*{mul}+{add})%24;local fd1=(fq-fq%6)/6;fq=fq%6;local fd2=(fq-fq%2)/2;local fd3=fq%2;local frem={{0,1,2,3}};local fix={{fd1,fd2,fd3,0}};local fky={{0,0,0,0}};for fk=1,4 do local fw=fix[fk];local fn2=0;for fj=1,4 do if frem[fj]>=0 then if fn2==fw then fky[fk]=frem[fj];frem[fj]=-1;break end;fn2=fn2+1 end end end;local ford={{0,0,0,0}};for fk=1,4 do ford[fky[fk]+1]=fk end;",
            mul = self.record_mul,
            add = self.record_add,
        )
    }

    /// Record header read. Slot reads stay in place; the semantic assignment
    /// follows the per-prototype `ford` map computed above.
    pub(crate) fn record_head_lua() -> &'static str {
        "local fs1,fs2,fs3,fs4=D16(),D16(),D16(),D16();local fsl={fs1,fs2,fs3,fs4};local label=fsl[ford[1]];local nextToken=fsl[ford[2]];local skipToken=fsl[ford[3]];local token=fsl[ford[4]];"
    }

    /// In-memory record tuple construction with the per-image slot order.
    pub(crate) fn tuple_construct_lua(self) -> String {
        let names = ["token", "nextToken", "skipToken"];
        let slots: Vec<&str> = self
            .tuple
            .iter()
            .map(|&field| names[field as usize])
            .collect();
        format!(
            "local I={{{},{},{},PT[recipe[#recipe]],#recipe}};",
            slots[0], slots[1], slots[2]
        )
    }

    /// Dictionary entry header read in the per-image order.
    pub(crate) fn dictionary_head_lua(self) -> &'static str {
        if self.dict_flipped {
            "local n=SB(CD,p);p=p+1;local rid=D16();"
        } else {
            "local rid=D16();local n=SB(CD,p);p=p+1;"
        }
    }

    /// Prototype metadata reads. The wire read sequence is unchanged; only
    /// the destination fields follow the per-image width-group permutations.
    pub(crate) fn metadata_reads_lua(self) -> String {
        let u32_names = [
            "F.__obf_proto_parent",
            "F.__obf_proto_nk",
            "F.__obf_proto_nc",
            "local VMCS",
        ];
        let u16_names = ["F.__obf_proto_m", "F.__obf_proto_nu", "local RT"];
        let u8_names = ["F.__obf_proto_p", "F.__obf_proto_flags"];
        let mut reads = String::new();
        reads.push_str(&format!("{}=b32();", u32_names[self.meta_u32[0] as usize]));
        reads.push_str(&format!("{}=b16();", u16_names[self.meta_u16[0] as usize]));
        reads.push_str(&format!("{}=b8();", u8_names[self.meta_u8[0] as usize]));
        reads.push_str(&format!("{}=b8();", u8_names[self.meta_u8[1] as usize]));
        reads.push_str(&format!("{}=b16();", u16_names[self.meta_u16[1] as usize]));
        reads.push_str(&format!("{}=b16();", u16_names[self.meta_u16[2] as usize]));
        reads.push_str(&format!("{}=b32();", u32_names[self.meta_u32[1] as usize]));
        reads.push_str(&format!("{}=b32();", u32_names[self.meta_u32[2] as usize]));
        reads.push_str(&format!("{}=b32();", u32_names[self.meta_u32[3] as usize]));
        reads
    }

    /// Per-segment token-order decode for the global pool reader. `slot` is
    /// the 1-based physical position. Emits `sont[1..3]`, the 1-based wire
    /// slot of [id, owner, next], plus the three raw token reads in `st`.
    pub(crate) fn segment_decode_lua(self) -> String {
        format!(
            "local tk1,tk2,tk3=b16(),b16(),b16();local sq=(slot*{mul}+{add})%6;local sd1=(sq-sq%2)/2;local sd2=sq%2;local srem={{0,1,2}};local six={{sd1,sd2,0}};local skey={{0,0,0}};for sk=1,3 do local sw=six[sk];local scn=0;for sj=1,3 do if srem[sj]>=0 then if scn==sw then skey[sk]=srem[sj];srem[sj]=-1;break end;scn=scn+1 end end end;local st={{tk1,tk2,tk3}};local sont={{0,0,0}};for sk=1,3 do sont[skey[sk]+1]=sk end;",
            mul = self.segment_mul,
            add = self.segment_add,
        )
    }
}
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
