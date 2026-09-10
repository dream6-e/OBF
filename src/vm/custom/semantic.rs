//! Seeded semantic virtualization used only by generated VM scripts.
//!
//! Public `.obf` files remain the canonical OBF v2/ISA2 format. Before a
//! canonical program is embedded in a generated script, this module lowers
//! its fixed one-word instructions into a private ISA13 wire image:
//!
//! * straight-line words are grouped into program-specific superoperators;
//! * each superoperator has a random 16-bit recipe id, while every use site
//!   carries a different five-stage context token rather than that stable id;
//! * successor labels are independently encoded by three-stage edge tokens;
//! * reachable neutral bundles split real entry/CFG edges, and all records are
//!   emitted in shuffled physical order rather than source/chunk order;
//! * live dictionary descriptors are replaced by validation-equivalent opcode
//!   sequences, decoupling wire schemas from the execution semantics;
//! * sibling prototypes are seed-shuffled, Closure operands are rewritten, and
//!   an unreachable synthetic prototype subtree breaks count/tree isomorphism;
//! * each prototype code image becomes a two-node, owner-bound chain with a
//!   seed/context-derived non-empty split; masked roots stay in metadata while
//!   compact id/owner/next records are globally shuffled across prototypes;
//! * unused recipe descriptors also have deliberately mismatched bodies.
//!
//! The generated target validator reconstructs and validates the linked
//! bundle graph before execution. This is still obfuscation, not a claim that
//! static recovery is impossible, but it removes the old global
//! `one byte opcode -> one Lua operation` translation layer attacked by the
//! static report.

use super::*;
use crate::bytecode::custom::{Opcode, Program, Prototype, Word};
use crate::ir::{Capture, Constant};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const WIRE_INSTRUCTION_ENCODING: u8 = 1;
pub(crate) const WIRE_ISA_VERSION: u32 = 15;
pub(crate) const RECIPE_TOKEN_STAGES: usize = 5;
pub(crate) const EDGE_TOKEN_STAGES: usize = 3;
const MAX_MULTI_RECIPES: usize = 96;
pub(crate) const MAX_BUNDLE_WORDS: usize = 4;
const DECOY_RECIPES: usize = 4;

/// One reversible stage of the context-dependent record-token transform.
/// Every multiplier is odd and therefore invertible modulo 2^16. Context
/// coefficients bind the wire token to its physical graph node, successors,
/// and prototype rather than exposing one stable recipe id at every use site.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecipeTokenLayer {
    pub multiplier: u16,
    pub inverse: u16,
    pub add: u16,
    pub label: u16,
    pub next: u16,
    pub skip: u16,
    pub prototype: u16,
    pub cross: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EdgeTokenLayer {
    pub multiplier: u16,
    pub inverse: u16,
    pub add: u16,
    pub source: u16,
    pub prototype: u16,
    pub kind: u16,
    pub cross: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct SemanticRecipe {
    pub id: u16,
    /// Validation-equivalent sequence advertised by the encrypted dictionary.
    /// Since ISA6 this is intentionally not semantic ground truth, even for
    /// live recipes; it supplies only operand forms and fail-closed bounds.
    pub descriptor_ops: Vec<Opcode>,
    /// Actual sequence emitted into the globally shuffled semantic fragments.
    pub execute_ops: Vec<Opcode>,
    pub live: bool,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // structural counters are consumed by the test gate
pub(crate) struct SemanticImage {
    pub bytes: Vec<u8>,
    pub recipes: Vec<SemanticRecipe>,
    pub mask_mul: u16,
    pub mask_add: u16,
    pub mask_salt: u16,
    pub token_layers: [RecipeTokenLayer; RECIPE_TOKEN_STAGES],
    pub edge_layers: [EdgeTokenLayer; EDGE_TOKEN_STAGES],
    pub field_layout: FieldLayout,
    pub canonical_words: usize,
    pub bundles: usize,
    pub bundled_words: usize,
    pub reachable_decoy_bundles: usize,
    pub reachable_decoy_words: usize,
    pub neutral_decoy_recipe_ids: BTreeSet<u16>,
    pub camouflaged_live_recipes: usize,
    pub camouflaged_live_ops: usize,
    pub live_recipe_ops: usize,
    pub prototype_order: Vec<usize>,
    pub decoy_prototypes: usize,
    pub shuffled_records: usize,
    pub code_segments: usize,
    pub prototype_segment_counts: Vec<usize>,
    pub segment_physical_ids: Vec<usize>,
    pub segment_physical_owners: Vec<usize>,
    pub segment_next_ids: Vec<usize>,
    pub segment_root_ids: Vec<usize>,
    pub segments_interleaved: bool,
    pub capture_pool_owners: Vec<usize>,
    pub capture_pool_slots: Vec<usize>,
    pub constant_pool_owners: Vec<usize>,
    pub constant_pool_indices: Vec<usize>,
    pub pools_interleaved: bool,
    pub referenced_recipe_ids: BTreeSet<u16>,
}

#[derive(Clone, Debug)]
struct Bundle {
    label: u16,
    next: u16,
    skip: u16,
    recipe: usize,
    words: Vec<Word>,
}

#[derive(Clone, Debug)]
struct PrototypePlan {
    prototype: Prototype,
    start: u16,
    bundles: Vec<Bundle>,
    physical: Vec<usize>,
    recipe_indices: BTreeSet<usize>,
}

#[derive(Clone, Debug)]
struct CodeSegment {
    id: u16,
    owner: u16,
    next: u16,
    bytes: Vec<u8>,
}

/// One capture record in the global capture pool: the owning prototype,
/// the capture slot within that owner, and the (tag, index) value.
#[derive(Clone, Debug)]
struct PooledCapture {
    owner: u16,
    slot: u16,
    tag: u8,
    index: u8,
}

/// One constant record in the global constant pool: the owning
/// prototype, the constant index within that owner, and the value.
#[derive(Clone, Debug)]
struct PooledConstant {
    owner: u16,
    index: u16,
    constant: Constant,
}

/// Physical pool layout published for the verification harness.
#[derive(Clone, Debug)]
struct PoolPhysicalLayout {
    capture_owners: Vec<usize>,
    capture_slots: Vec<usize>,
    constant_owners: Vec<usize>,
    constant_indices: Vec<usize>,
    interleaved: bool,
}

fn error(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(format!("semantic wire image: {}", message.into()))
}

fn control(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Jump | Opcode::Test | Opcode::Return | Opcode::TailCall
    )
}

/// Exact target-validator/operand-form equivalence classes used for live
/// descriptor camouflage. Control primitives intentionally remain singleton
/// classes because their graph role is checked separately after record parse.
pub(crate) fn descriptor_class(op: Opcode) -> u8 {
    use Opcode::*;
    match op {
        Nil | NewTable | NewPack | IteratorPrepare | Freeze => 1,
        NumberPrepare | NumberStep => 2,
        Move | NewCell | ReadCell | WriteCell | Push | Extend | Not | Negate | Length
        | IteratorNext | ToString => 3,
        ReadUpvalue | WriteUpvalue => 4,
        ReadGlobal | WriteGlobal => 5,
        GetTable | SetTable | Method | Call | Add | Subtract | Multiply | Divide | FloorDivide
        | Modulo | Power | Concat | Equal | Less | LessEqual | SetList | Export => 6,
        _ => 16 + op as u8,
    }
}

fn camouflage_descriptor_op(
    op: Opcode,
    target: Target,
    random: &mut crate::random::Prng,
) -> Opcode {
    use Opcode::*;
    const A_REG: &[Opcode] = &[Nil, NewTable, NewPack, IteratorPrepare, Freeze];
    const A_WINDOW: &[Opcode] = &[NumberPrepare, NumberStep];
    const AB_REG: &[Opcode] = &[
        Move,
        NewCell,
        ReadCell,
        WriteCell,
        Push,
        Extend,
        Not,
        Negate,
        Length,
        IteratorNext,
        ToString,
    ];
    const UPVALUE: &[Opcode] = &[ReadUpvalue, WriteUpvalue];
    const GLOBAL: &[Opcode] = &[ReadGlobal, WriteGlobal];
    const ABC_REG: &[Opcode] = &[
        GetTable,
        SetTable,
        Method,
        Call,
        Add,
        Subtract,
        Multiply,
        Divide,
        FloorDivide,
        Modulo,
        Power,
        Concat,
        Equal,
        Less,
        LessEqual,
        SetList,
        Export,
    ];
    let pool = match descriptor_class(op) {
        1 => A_REG,
        2 => A_WINDOW,
        3 => AB_REG,
        4 => UPVALUE,
        5 => GLOBAL,
        6 => ABC_REG,
        _ => return op,
    };
    let candidates: Vec<Opcode> = pool
        .iter()
        .copied()
        .filter(|candidate| *candidate != op && candidate.supported(target))
        .collect();
    if candidates.is_empty() {
        return op;
    }
    let candidate = candidates[random.next_u64() as usize % candidates.len()];
    debug_assert_eq!(descriptor_class(candidate), descriptor_class(op));
    debug_assert_eq!(custom::encoding_form(candidate), custom::encoding_form(op));
    debug_assert_eq!(control(candidate), control(op));
    candidate
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: usize) -> Result<(), Diagnostic> {
    let value = u32::try_from(value).map_err(|_| error("32-bit length overflow"))?;
    out.extend_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Diagnostic> {
    write_u32(out, value.len())?;
    out.extend_from_slice(value);
    Ok(())
}

fn write_varint(out: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        out.push(0x80 | (value & 127) as u8);
        value >>= 7;
    }
    out.push(value as u8);
}

const K9_BYTE_MUL: [u32; 8] = [1, 3, 5, 7, 9, 11, 13, 15];

pub(crate) fn k9_index(token: u16, prototype: u16, lane: u32, salt: u16) -> usize {
    ((u32::from(token) * 17 + u32::from(prototype) * 31 + lane * 53 + u32::from(salt)) % 8) as usize
}

pub(crate) fn k9_add(token: u16, prototype: u16, lane: u32, add: u16, modulus: u32) -> u32 {
    (u32::from(token) * 257 + u32::from(prototype) * 911 + lane * 193 + u32::from(add)) % modulus
}

pub(crate) fn k9_affine(
    value: usize,
    token: u16,
    prototype: u16,
    lane: u32,
    image: &SemanticImage,
    modulus: u32,
) -> u32 {
    let index = k9_index(token, prototype, lane, image.mask_salt);
    (value as u32 * K9_BYTE_MUL[index] + k9_add(token, prototype, lane, image.mask_add, modulus))
        % modulus
}

fn write_operands(
    out: &mut Vec<u8>,
    word: Word,
    token: u16,
    prototype: u16,
    image: &SemanticImage,
) -> Result<(), Diagnostic> {
    let op = word.opcode()?;
    match custom::encoding_form(op) {
        1 => {
            let value = word.ax();
            let a = k9_affine(value & 255, token, prototype, 0, image, 256);
            let b = k9_affine((value >> 8) & 255, token, prototype, 1, image, 256);
            let c = k9_affine((value >> 16) & 255, token, prototype, 2, image, 256);
            write_varint(out, (a | b << 8 | c << 16) as usize);
        }
        2 => write_varint(
            out,
            k9_affine(word.a(), token, prototype, 0, image, 256) as usize,
        ),
        3 => {
            write_varint(
                out,
                k9_affine(word.a(), token, prototype, 0, image, 256) as usize,
            );
            write_varint(
                out,
                k9_affine(word.b(), token, prototype, 1, image, 256) as usize,
            );
        }
        4 => {
            write_varint(
                out,
                k9_affine(word.a(), token, prototype, 0, image, 256) as usize,
            );
            write_varint(
                out,
                k9_affine(word.bx(), token, prototype, 1, image, 65536) as usize,
            );
        }
        _ => {
            write_varint(
                out,
                k9_affine(word.a(), token, prototype, 0, image, 256) as usize,
            );
            write_varint(
                out,
                k9_affine(word.b(), token, prototype, 1, image, 256) as usize,
            );
            write_varint(
                out,
                k9_affine(word.c(), token, prototype, 2, image, 256) as usize,
            );
        }
    }
    Ok(())
}

fn intern_recipe(
    key: Vec<u8>,
    recipes: &mut Vec<(Vec<Opcode>, bool)>,
    by_key: &mut BTreeMap<Vec<u8>, usize>,
    multi_count: &mut usize,
) -> Option<usize> {
    if let Some(&index) = by_key.get(&key) {
        return Some(index);
    }
    if key.len() > 1 && *multi_count >= MAX_MULTI_RECIPES {
        return None;
    }
    let mut ops = Vec::with_capacity(key.len());
    for &byte in &key {
        ops.push(Opcode::from_byte(byte)?);
    }
    let index = recipes.len();
    if key.len() > 1 {
        *multi_count += 1;
    }
    by_key.insert(key, index);
    recipes.push((ops, true));
    Some(index)
}

fn random_nonzero_u16(random: &mut crate::random::Prng, used: &mut BTreeSet<u16>) -> u16 {
    loop {
        let value = 1 + (random.next_u64() % u64::from(u16::MAX)) as u16;
        if used.insert(value) {
            return value;
        }
    }
}

fn inverse_odd_u16(value: u16) -> u16 {
    debug_assert_eq!(value % 2, 1);
    let (mut t, mut new_t) = (0i64, 1i64);
    let (mut remainder, mut new_remainder) = (65_536i64, i64::from(value));
    while new_remainder != 0 {
        let quotient = remainder / new_remainder;
        (t, new_t) = (new_t, t - quotient * new_t);
        (remainder, new_remainder) = (new_remainder, remainder - quotient * new_remainder);
    }
    debug_assert_eq!(remainder, 1);
    let inverse = t.rem_euclid(65_536) as u16;
    debug_assert_eq!(u32::from(value) * u32::from(inverse) % 65_536, 1);
    inverse
}

fn recipe_token_layers(
    random: &mut crate::random::Prng,
) -> [RecipeTokenLayer; RECIPE_TOKEN_STAGES] {
    std::array::from_fn(|_| {
        let multiplier = loop {
            let candidate = (random.next_u64() as u16) | 1;
            if candidate > 1 {
                break candidate;
            }
        };
        let add = random.next_u64() as u16;
        let coefficients: [u16; 5] =
            std::array::from_fn(|_| 1 + (random.next_u64() % u64::from(u16::MAX)) as u16);
        RecipeTokenLayer {
            multiplier,
            inverse: inverse_odd_u16(multiplier),
            add,
            label: coefficients[0],
            next: coefficients[1],
            skip: coefficients[2],
            prototype: coefficients[3],
            cross: coefficients[4],
        }
    })
}

fn recipe_token_context(
    layer: RecipeTokenLayer,
    label: u16,
    next: u16,
    skip: u16,
    prototype: u16,
) -> u64 {
    let (label, next, skip, prototype) = (
        u64::from(label),
        u64::from(next),
        u64::from(skip),
        u64::from(prototype),
    );
    let cross = (label * next + skip * prototype) % 65_536;
    (u64::from(layer.add)
        + label * u64::from(layer.label)
        + next * u64::from(layer.next)
        + skip * u64::from(layer.skip)
        + prototype * u64::from(layer.prototype)
        + cross * u64::from(layer.cross))
        % 65_536
}

pub(crate) fn encode_recipe_token(
    mut recipe: u16,
    label: u16,
    next: u16,
    skip: u16,
    prototype: u16,
    layers: &[RecipeTokenLayer; RECIPE_TOKEN_STAGES],
) -> u16 {
    for &layer in layers {
        recipe = ((u64::from(recipe) * u64::from(layer.multiplier)
            + recipe_token_context(layer, label, next, skip, prototype))
            % 65_536) as u16;
    }
    recipe
}

pub(crate) fn decode_recipe_token(
    mut token: u16,
    label: u16,
    next: u16,
    skip: u16,
    prototype: u16,
    layers: &[RecipeTokenLayer; RECIPE_TOKEN_STAGES],
) -> u16 {
    for &layer in layers.iter().rev() {
        let context = recipe_token_context(layer, label, next, skip, prototype);
        token =
            (((u64::from(token) + 65_536 - context) * u64::from(layer.inverse)) % 65_536) as u16;
    }
    token
}

fn edge_token_layers(random: &mut crate::random::Prng) -> [EdgeTokenLayer; EDGE_TOKEN_STAGES] {
    std::array::from_fn(|_| {
        let multiplier = loop {
            let candidate = (random.next_u64() as u16) | 1;
            if candidate > 1 {
                break candidate;
            }
        };
        let coefficients: [u16; 4] =
            std::array::from_fn(|_| 1 + (random.next_u64() % u64::from(u16::MAX)) as u16);
        EdgeTokenLayer {
            multiplier,
            inverse: inverse_odd_u16(multiplier),
            add: random.next_u64() as u16,
            source: coefficients[0],
            prototype: coefficients[1],
            kind: coefficients[2],
            cross: coefficients[3],
        }
    })
}

fn edge_token_context(layer: EdgeTokenLayer, source: u16, prototype: u16, kind: u16) -> u64 {
    let (source, prototype, kind) = (u64::from(source), u64::from(prototype), u64::from(kind));
    let cross = ((source + kind) * (prototype + 1)) % 65_536;
    (u64::from(layer.add)
        + source * u64::from(layer.source)
        + prototype * u64::from(layer.prototype)
        + kind * u64::from(layer.kind)
        + cross * u64::from(layer.cross))
        % 65_536
}

pub(crate) fn encode_edge_token(
    mut target: u16,
    source: u16,
    prototype: u16,
    kind: u16,
    layers: &[EdgeTokenLayer; EDGE_TOKEN_STAGES],
) -> u16 {
    for &layer in layers {
        target = ((u64::from(target) * u64::from(layer.multiplier)
            + edge_token_context(layer, source, prototype, kind))
            % 65_536) as u16;
    }
    target
}

pub(crate) fn decode_edge_token(
    mut token: u16,
    source: u16,
    prototype: u16,
    kind: u16,
    layers: &[EdgeTokenLayer; EDGE_TOKEN_STAGES],
) -> u16 {
    for &layer in layers.iter().rev() {
        let context = edge_token_context(layer, source, prototype, kind);
        token =
            (((u64::from(token) + 65_536 - context) * u64::from(layer.inverse)) % 65_536) as u16;
    }
    token
}

/// Add an internally coherent but unreachable prototype subtree. Its first
/// node has a valid parent relationship but no live Closure points to it;
/// subsequent nodes are linked by real Closure operands. This changes both
/// prototype count and tree topology, so the canonical tree cannot be copied
/// out without a reachability pass. Near the u16 Closure-id ceiling we retain
/// compatibility by omitting this optional subtree.
fn add_decoy_prototypes(program: &mut Program, random: &mut crate::random::Prng) -> usize {
    let real_count = program.prototypes.len();
    if real_count == 0 || real_count > usize::from(u16::MAX) - 4 {
        return 0;
    }
    let count = 2 + (random.next_u64() % 3) as usize;
    let first = real_count;
    let root_parent = (random.next_u64() % real_count as u64) as usize;
    for offset in 0..count {
        let id = first + offset;
        let parent = if offset == 0 { root_parent } else { id - 1 };
        let mut constants = Vec::new();
        let first_word = if offset + 1 < count {
            let child = u16::try_from(id + 1).expect("decoy prototype id was bounded above");
            Word([
                Opcode::Closure as u8,
                0,
                (child & 255) as u8,
                (child >> 8) as u8,
            ])
        } else {
            constants.push(Constant::Number(
                (1.0 + (random.next_u64() % 1024) as f64).to_bits(),
            ));
            Word([Opcode::Constant as u8, 0, 0, 0])
        };
        program.prototypes.push(Prototype {
            parent: Some(parent),
            registers: 2,
            parameters: 0,
            flags: 0,
            captures: Vec::new(),
            constants,
            code: vec![
                first_word,
                Word([Opcode::NewPack as u8, 1, 0, 0]),
                Word([Opcode::Push as u8, 1, 0, 0]),
                Word([Opcode::Return as u8, 1, 0, 0]),
            ],
        });
    }
    count
}

/// Shuffle siblings while preserving the only structural constraint the wire
/// parser needs: every parent precedes its children. Closure prototype ids are
/// rewritten to the new order.
fn reorder_program(
    program: &Program,
    random: &mut crate::random::Prng,
) -> Result<(Program, Vec<usize>), Diagnostic> {
    let count = program.prototypes.len();
    let mut children = vec![Vec::new(); count];
    for (id, prototype) in program.prototypes.iter().enumerate().skip(1) {
        let parent = prototype
            .parent
            .ok_or_else(|| error(format!("prototype {id} has no parent")))?;
        children
            .get_mut(parent)
            .ok_or_else(|| error("prototype parent is out of range"))?
            .push(id);
    }
    for list in &mut children {
        random.shuffle(list);
    }
    let mut order = Vec::with_capacity(count);
    let mut stack = vec![program.entry];
    while let Some(id) = stack.pop() {
        order.push(id);
        for &child in children[id].iter().rev() {
            stack.push(child);
        }
    }
    if order.len() != count {
        return Err(error("prototype graph is not a rooted tree"));
    }
    let mut remap = vec![usize::MAX; count];
    for (new, &old) in order.iter().enumerate() {
        remap[old] = new;
    }
    let mut prototypes = Vec::with_capacity(count);
    for &old_id in &order {
        let mut prototype = program.prototypes[old_id].clone();
        prototype.parent = prototype.parent.map(|parent| remap[parent]);
        for word in &mut prototype.code {
            if word.opcode()? == Opcode::Closure {
                let child = remap
                    .get(word.bx())
                    .copied()
                    .filter(|id| *id != usize::MAX)
                    .ok_or_else(|| error("closure prototype is out of range"))?;
                let child = u16::try_from(child)
                    .map_err(|_| error("closure prototype exceeds 16-bit range"))?;
                word.0[2] = (child & 255) as u8;
                word.0[3] = (child >> 8) as u8;
            }
        }
        prototypes.push(prototype);
    }
    Ok((
        Program {
            target: program.target,
            isa_version: program.isa_version,
            entry: remap[program.entry],
            prototypes,
        },
        order,
    ))
}

fn choose_bundle(
    code: &[Word],
    pc: usize,
    limit: usize,
    forced_single: &[bool],
    recipes: &mut Vec<(Vec<Opcode>, bool)>,
    by_key: &mut BTreeMap<Vec<u8>, usize>,
    multi_count: &mut usize,
    random: &mut crate::random::Prng,
) -> Result<(usize, usize), Diagnostic> {
    if forced_single[pc] || control(code[pc].opcode()?) {
        let key = vec![code[pc].0[0]];
        let recipe = intern_recipe(key, recipes, by_key, multi_count)
            .ok_or_else(|| error("cannot intern single-word recipe"))?;
        return Ok((1, recipe));
    }
    let max = (limit - pc).min(MAX_BUNDLE_WORDS);
    let mut lengths: Vec<usize> = (2..=max).collect();
    random.shuffle(&mut lengths);
    lengths.sort_by_key(|length| std::cmp::Reverse(*length + (random.next_u64() % 2) as usize));
    for length in lengths {
        if code[pc..pc + length]
            .iter()
            .any(|word| word.opcode().is_ok_and(control))
        {
            continue;
        }
        let key = code[pc..pc + length]
            .iter()
            .map(|word| word.0[0])
            .collect::<Vec<_>>();
        if let Some(recipe) = intern_recipe(key, recipes, by_key, multi_count) {
            return Ok((length, recipe));
        }
    }
    let key = vec![code[pc].0[0]];
    let recipe = intern_recipe(key, recipes, by_key, multi_count)
        .ok_or_else(|| error("cannot intern fallback recipe"))?;
    Ok((1, recipe))
}

fn plan_prototype(
    prototype: &Prototype,
    recipes: &mut Vec<(Vec<Opcode>, bool)>,
    by_key: &mut BTreeMap<Vec<u8>, usize>,
    multi_count: &mut usize,
    random: &mut crate::random::Prng,
) -> Result<PrototypePlan, Diagnostic> {
    let count = prototype.code.len();
    let mut leaders = vec![false; count];
    let mut forced_single = vec![false; count];
    leaders[0] = true;
    for (pc, &word) in prototype.code.iter().enumerate() {
        match word.opcode()? {
            Opcode::Jump => {
                if let Some(leader) = leaders.get_mut(word.ax()) {
                    *leader = true;
                } else {
                    return Err(error("jump target is out of range"));
                }
                if let Some(leader) = leaders.get_mut(pc + 1) {
                    *leader = true;
                }
            }
            Opcode::Test => {
                if let Some(leader) = leaders.get_mut(pc + 1) {
                    *leader = true;
                    forced_single[pc + 1] = true;
                }
                if let Some(leader) = leaders.get_mut(pc + 2) {
                    *leader = true;
                }
            }
            Opcode::Return | Opcode::TailCall => {
                if let Some(leader) = leaders.get_mut(pc + 1) {
                    *leader = true;
                }
            }
            _ => {}
        }
    }

    let mut temporary: Vec<(usize, Vec<Word>)> = Vec::new();
    let mut pc_to_bundle = vec![usize::MAX; count];
    let mut pc = 0usize;
    while pc < count {
        let mut limit = pc + 1;
        while limit < count && !leaders[limit] && !control(prototype.code[limit].opcode()?) {
            limit += 1;
        }
        if !control(prototype.code[pc].opcode()?) {
            while limit < count && !leaders[limit] && !control(prototype.code[limit].opcode()?) {
                limit += 1;
            }
        }
        let (length, recipe) = choose_bundle(
            &prototype.code,
            pc,
            limit.max(pc + 1),
            &forced_single,
            recipes,
            by_key,
            multi_count,
            random,
        )?;
        let index = temporary.len();
        for slot in &mut pc_to_bundle[pc..pc + length] {
            *slot = index;
        }
        temporary.push((recipe, prototype.code[pc..pc + length].to_vec()));
        pc += length;
    }
    if pc_to_bundle.iter().any(|index| *index == usize::MAX) {
        return Err(error("not every instruction belongs to a bundle"));
    }
    // Reserve four nonzero labels so every real prototype can receive the
    // promised 2..=4-node neutral entry chain during semantic lowering.
    if temporary.len() > usize::from(u16::MAX) - 4 {
        return Err(error(
            "prototype leaves no private label space for neutral entry bundles",
        ));
    }

    let mut used_labels = BTreeSet::new();
    let labels: Vec<u16> = (0..temporary.len())
        .map(|_| random_nonzero_u16(random, &mut used_labels))
        .collect();
    let mut bundles = Vec::with_capacity(temporary.len());
    let mut recipe_indices = BTreeSet::new();
    for (index, (recipe, mut words)) in temporary.into_iter().enumerate() {
        for word in &mut words {
            if word.opcode()? == Opcode::Jump {
                let target_bundle = pc_to_bundle[word.ax()];
                let target = labels[target_bundle];
                word.0[1] = (target & 255) as u8;
                word.0[2] = (target >> 8) as u8;
                word.0[3] = 0;
            }
        }
        let last = words.last().unwrap().opcode()?;
        let next = if matches!(last, Opcode::Jump | Opcode::Return | Opcode::TailCall) {
            0
        } else {
            *labels
                .get(index + 1)
                .ok_or_else(|| error("non-terminal bundle has no successor"))?
        };
        let skip = if last == Opcode::Test {
            *labels
                .get(index + 2)
                .ok_or_else(|| error("test bundle has no skip successor"))?
        } else {
            0
        };
        recipe_indices.insert(recipe);
        bundles.push(Bundle {
            label: labels[index],
            next,
            skip,
            recipe,
            words,
        });
    }
    let mut physical: Vec<usize> = (0..bundles.len()).collect();
    random.shuffle(&mut physical);
    Ok(PrototypePlan {
        prototype: prototype.clone(),
        start: labels[0],
        bundles,
        physical,
        recipe_indices,
    })
}

fn inject_reachable_decoys(
    plan: &mut PrototypePlan,
    recipes: &mut Vec<(Vec<Opcode>, bool)>,
    by_key: &mut BTreeMap<Vec<u8>, usize>,
    multi_count: &mut usize,
    neutral_recipes: &mut BTreeSet<usize>,
    random: &mut crate::random::Prng,
) -> Result<(usize, usize), Diagnostic> {
    let base_count = plan.bundles.len();
    let available = usize::from(u16::MAX).saturating_sub(base_count);
    debug_assert!(available >= 4);

    let words = if plan.prototype.registers < 256 {
        let scratch = plan.prototype.registers as u8;
        plan.prototype.registers += 1;
        match random.next_u64() % 3 {
            0 => vec![
                Word([Opcode::Nil as u8, scratch, 0, 0]),
                Word([Opcode::Not as u8, scratch, scratch, 0]),
                Word([Opcode::Not as u8, scratch, scratch, 0]),
                Word([Opcode::Clear as u8, scratch, scratch, 0]),
            ],
            1 => vec![
                Word([Opcode::Move as u8, scratch, scratch, 0]),
                Word([Opcode::Nil as u8, scratch, 0, 0]),
                Word([Opcode::Not as u8, scratch, scratch, 0]),
                Word([Opcode::Clear as u8, scratch, scratch, 0]),
            ],
            _ => vec![
                Word([Opcode::Nil as u8, scratch, 0, 0]),
                Word([Opcode::Move as u8, scratch, scratch, 0]),
                Word([Opcode::Move as u8, scratch, scratch, 0]),
                Word([Opcode::Clear as u8, scratch, scratch, 0]),
            ],
        }
    } else {
        // A full 256-slot frame has no private scratch register. A self move
        // is still neutral for values, cells, packs, functions, and nil.
        vec![Word([Opcode::Move as u8, 0, 0, 0])]
    };
    let key = words.iter().map(|word| word.0[0]).collect::<Vec<_>>();
    let (recipe, words) = match intern_recipe(key, recipes, by_key, multi_count) {
        Some(recipe) => (recipe, words),
        None => {
            let words = vec![Word([Opcode::Move as u8, 0, 0, 0])];
            let recipe = intern_recipe(vec![Opcode::Move as u8], recipes, by_key, multi_count)
                .ok_or_else(|| error("cannot intern neutral fallback recipe"))?;
            (recipe, words)
        }
    };
    neutral_recipes.insert(recipe);
    plan.recipe_indices.insert(recipe);

    let mut used_labels: BTreeSet<u16> = plan.bundles.iter().map(|bundle| bundle.label).collect();
    let mut edge_candidates = Vec::new();
    for (index, bundle) in plan.bundles[..base_count].iter().enumerate() {
        if bundle.next != 0 {
            edge_candidates.push((index, false));
        }
        if bundle.skip != 0 {
            edge_candidates.push((index, true));
        }
    }
    random.shuffle(&mut edge_candidates);
    let entry_count = (2 + random.next_u64() % 3) as usize;
    let edge_count = (1 + base_count / 24)
        .min(5)
        .min(edge_candidates.len())
        .min(available - entry_count);
    let mut inserted = 0usize;

    for &(source, is_skip) in edge_candidates.iter().take(edge_count) {
        let old_target = if is_skip {
            plan.bundles[source].skip
        } else {
            plan.bundles[source].next
        };
        let label = random_nonzero_u16(random, &mut used_labels);
        if is_skip {
            plan.bundles[source].skip = label;
        } else {
            plan.bundles[source].next = label;
        }
        plan.bundles.push(Bundle {
            label,
            next: old_target,
            skip: 0,
            recipe,
            words: words.clone(),
        });
        inserted += 1;
    }

    if entry_count > 0 {
        let old_start = plan.start;
        let labels: Vec<u16> = (0..entry_count)
            .map(|_| random_nonzero_u16(random, &mut used_labels))
            .collect();
        for (index, &label) in labels.iter().enumerate() {
            plan.bundles.push(Bundle {
                label,
                next: labels.get(index + 1).copied().unwrap_or(old_start),
                skip: 0,
                recipe,
                words: words.clone(),
            });
        }
        plan.start = labels[0];
        inserted += labels.len();
    }

    plan.physical = (0..plan.bundles.len()).collect();
    random.shuffle(&mut plan.physical);
    Ok((inserted, inserted * words.len()))
}

fn add_decoy_recipes(
    used: &[Opcode],
    recipes: &mut Vec<(Vec<Opcode>, bool)>,
    by_key: &mut BTreeMap<Vec<u8>, usize>,
    random: &mut crate::random::Prng,
) -> Vec<usize> {
    let mut added = Vec::new();
    // A descriptor is parsed and structurally checked even when no record
    // references it. Keep control transfers out of decoy middles so the
    // validator can enforce the same recipe invariant without a decoy
    // exception.
    let mut safe: Vec<Opcode> = used.iter().copied().filter(|op| !control(*op)).collect();
    // Even a synthetic one-word terminal program gets the same decoy cohort.
    // Add a target-common fallback alphabet. Its 336 length-2..4 sequences
    // exceed the 96 live multi-recipe cap, so four unique decoys always
    // exist. No record ever requests operands for these descriptors.
    const FALLBACK: [Opcode; 4] = [Opcode::Move, Opcode::Nil, Opcode::NewTable, Opcode::NewPack];
    for op in FALLBACK {
        if !safe.contains(&op) {
            safe.push(op);
        }
    }
    let mut attempts = 0usize;
    while added.len() < DECOY_RECIPES && attempts < 256 {
        attempts += 1;
        let length = 2 + (random.next_u64() % 3) as usize;
        let key = (0..length)
            .map(|_| safe[(random.next_u64() % safe.len() as u64) as usize] as u8)
            .collect::<Vec<_>>();
        if by_key.contains_key(&key) {
            continue;
        }
        let index = recipes.len();
        let ops = key
            .iter()
            .filter_map(|byte| Opcode::from_byte(*byte))
            .collect();
        by_key.insert(key, index);
        recipes.push((ops, false));
        added.push(index);
    }
    if added.len() == DECOY_RECIPES {
        return added;
    }
    // Exhaust a bounded deterministic set if the random attempts collide.
    // The four common primitives provide 336 length-2..=4 candidates.
    let fallback = &FALLBACK;
    'fill: for length in 2..=MAX_BUNDLE_WORDS {
        let combinations = fallback.len().pow(length as u32);
        for mut ordinal in 0..combinations {
            let mut ops = Vec::with_capacity(length);
            for _ in 0..length {
                ops.push(fallback[ordinal % fallback.len()]);
                ordinal /= fallback.len();
            }
            let key = ops.iter().map(|op| *op as u8).collect::<Vec<_>>();
            if by_key.contains_key(&key) {
                continue;
            }
            let index = recipes.len();
            by_key.insert(key, index);
            recipes.push((ops, false));
            added.push(index);
            if added.len() == DECOY_RECIPES {
                break 'fill;
            }
        }
    }
    debug_assert_eq!(added.len(), DECOY_RECIPES);
    added
}

fn encode_masked_opcode(op: Opcode, id: u16, position: usize, image: &SemanticImage) -> u8 {
    let mask = (u64::from(id) * u64::from(image.mask_mul)
        + position as u64 * u64::from(image.mask_add)
        + u64::from(image.mask_salt))
        % 64;
    ((u64::from(op as u8) + mask) % 64) as u8
}

fn encode_code(
    prototype_id: u16,
    plan: &PrototypePlan,
    recipes: &[SemanticRecipe],
    decoys: &[usize],
    image: &SemanticImage,
    random: &mut crate::random::Prng,
) -> Result<Vec<u8>, Diagnostic> {
    let mut dictionary: Vec<usize> = plan.recipe_indices.iter().copied().collect();
    for &decoy in decoys {
        if !dictionary.contains(&decoy) && dictionary.len() < u16::MAX as usize {
            dictionary.push(decoy);
        }
    }
    random.shuffle(&mut dictionary);
    let mut out = Vec::new();
    write_u16(
        &mut out,
        u16::try_from(dictionary.len()).map_err(|_| error("too many recipes"))?,
    );
    for index in dictionary {
        let recipe = &recipes[index];
        let length =
            u8::try_from(recipe.descriptor_ops.len()).map_err(|_| error("recipe is too long"))?;
        // ISA13 de-documents the entry header: the per-image order is baked
        // into the generated parser, so only one order is visible per script.
        if image.field_layout.dict_flipped {
            out.push(length);
            write_u16(&mut out, recipe.id);
        } else {
            write_u16(&mut out, recipe.id);
            out.push(length);
        }
        for (position, &op) in recipe.descriptor_ops.iter().enumerate() {
            out.push(encode_masked_opcode(op, recipe.id, position, image));
        }
    }
    write_u16(&mut out, plan.start);
    let record_order = image
        .field_layout
        .record_slot_fields(usize::from(prototype_id));
    for &index in &plan.physical {
        let bundle = &plan.bundles[index];
        let next_token = encode_edge_token(
            bundle.next,
            bundle.label,
            prototype_id,
            0,
            &image.edge_layers,
        );
        let skip_token = encode_edge_token(
            bundle.skip,
            bundle.label,
            prototype_id,
            1,
            &image.edge_layers,
        );
        debug_assert_eq!(
            decode_edge_token(
                next_token,
                bundle.label,
                prototype_id,
                0,
                &image.edge_layers,
            ),
            bundle.next
        );
        debug_assert_eq!(
            decode_edge_token(
                skip_token,
                bundle.label,
                prototype_id,
                1,
                &image.edge_layers,
            ),
            bundle.skip
        );
        let token = encode_recipe_token(
            recipes[bundle.recipe].id,
            bundle.label,
            bundle.next,
            bundle.skip,
            prototype_id,
            &image.token_layers,
        );
        debug_assert_eq!(
            decode_recipe_token(
                token,
                bundle.label,
                bundle.next,
                bundle.skip,
                prototype_id,
                &image.token_layers,
            ),
            recipes[bundle.recipe].id
        );
        // Fixed-width slots stay in place; the per-prototype field assignment
        // is recomputed from the same factorial profile by the Lua parser.
        let fields = [bundle.label, next_token, skip_token, token];
        for slot in record_order {
            write_u16(&mut out, fields[slot]);
        }
        for &word in &bundle.words {
            write_operands(&mut out, word, token, prototype_id, image)?;
        }
    }
    Ok(out)
}

fn owners_are_interleaved(segments: &[CodeSegment]) -> bool {
    let mut closed = BTreeSet::new();
    let mut previous = None;
    for segment in segments {
        if previous != Some(segment.owner) {
            if let Some(owner) = previous {
                closed.insert(owner);
            }
            if closed.contains(&segment.owner) {
                return true;
            }
            previous = Some(segment.owner);
        }
    }
    false
}

/// Context used by the compact segment graph (introduced in ISA9 and retained
/// by ISA13). Reusing one full-width
/// recipe-token layer keeps the segment links seed-coupled without adding a
/// self-describing key block to the wire image.
fn segment_parameters(image: &SemanticImage) -> (u16, u16) {
    (image.token_layers[0].add, image.token_layers[0].multiplier)
}

/// Every prototype has exactly two non-empty nodes in the retained segment
/// graph. Their
/// boundary is seed- and owner-dependent; it is never serialized as a plain
/// offset. `context` is in 0..=65535, so the result is always in 1..code_len.
pub(crate) fn code_segment_split(code_len: usize, owner: u16, image: &SemanticImage) -> usize {
    debug_assert!(code_len >= 2);
    let (add, multiplier) = segment_parameters(image);
    let context = add.wrapping_add(owner.wrapping_mul(multiplier));
    1 + ((code_len - 1) as u64 * u64::from(context) / 65_536) as usize
}

pub(crate) fn encode_segment_root(root: u16, owner: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = segment_parameters(image);
    root.wrapping_add(add)
        .wrapping_add(owner.wrapping_mul(multiplier))
}

#[cfg(test)]
pub(crate) fn decode_segment_root(token: u16, owner: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = segment_parameters(image);
    token
        .wrapping_sub(owner.wrapping_mul(multiplier))
        .wrapping_sub(add)
}

pub(crate) fn encode_segment_id(id: u16, physical_slot: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = segment_parameters(image);
    id.wrapping_add(add)
        .wrapping_add(physical_slot.wrapping_mul(multiplier))
}

#[cfg(test)]
pub(crate) fn decode_segment_id(token: u16, physical_slot: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = segment_parameters(image);
    token
        .wrapping_sub(physical_slot.wrapping_mul(multiplier))
        .wrapping_sub(add)
}

pub(crate) fn encode_segment_owner(
    owner: u16,
    id: u16,
    physical_slot: u16,
    image: &SemanticImage,
) -> u16 {
    let (add, multiplier) = segment_parameters(image);
    owner
        .wrapping_add(add)
        .wrapping_add(id.wrapping_mul(multiplier))
        .wrapping_add(physical_slot)
}

#[cfg(test)]
pub(crate) fn decode_segment_owner(
    token: u16,
    id: u16,
    physical_slot: u16,
    image: &SemanticImage,
) -> u16 {
    let (add, multiplier) = segment_parameters(image);
    token
        .wrapping_sub(id.wrapping_mul(multiplier))
        .wrapping_sub(physical_slot)
        .wrapping_sub(add)
}

pub(crate) fn encode_segment_next(next: u16, id: u16, owner: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = segment_parameters(image);
    next.wrapping_add(add)
        .wrapping_add(id.wrapping_mul(multiplier))
        .wrapping_add(owner)
}

#[cfg(test)]
pub(crate) fn decode_segment_next(token: u16, id: u16, owner: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = segment_parameters(image);
    token
        .wrapping_sub(id.wrapping_mul(multiplier))
        .wrapping_sub(owner)
        .wrapping_sub(add)
}

/// Masking context for the global capture/constant pools (ISA14). Uses
/// recipe-token layer 1 while segments use layer 0; the recipe chain
/// itself passes through all layers, so layer sharing with distinct
/// slot/owner/index contexts is the established precedent.
fn pool_parameters(image: &SemanticImage) -> (u16, u16) {
    (image.token_layers[1].add, image.token_layers[1].multiplier)
}

/// Capture records carry [owner, slot, payload] and constant records
/// carry [owner, index, tag] in three anonymous factorial-profiled u16
/// slots. The constant index reuses the slot formula and the constant
/// tag reuses the payload formula with the index as the id-like context.
pub(crate) fn encode_pool_owner(owner: u16, physical_slot: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = pool_parameters(image);
    owner
        .wrapping_add(add)
        .wrapping_add(physical_slot.wrapping_mul(multiplier))
}

#[cfg(test)]
pub(crate) fn decode_pool_owner(token: u16, physical_slot: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = pool_parameters(image);
    token
        .wrapping_sub(physical_slot.wrapping_mul(multiplier))
        .wrapping_sub(add)
}

pub(crate) fn encode_pool_slot(
    slot: u16,
    owner: u16,
    physical_slot: u16,
    image: &SemanticImage,
) -> u16 {
    let (add, multiplier) = pool_parameters(image);
    slot.wrapping_add(add)
        .wrapping_add(owner.wrapping_mul(multiplier))
        .wrapping_add(physical_slot)
}

#[cfg(test)]
pub(crate) fn decode_pool_slot(
    token: u16,
    owner: u16,
    physical_slot: u16,
    image: &SemanticImage,
) -> u16 {
    let (add, multiplier) = pool_parameters(image);
    token
        .wrapping_sub(owner.wrapping_mul(multiplier))
        .wrapping_sub(physical_slot)
        .wrapping_sub(add)
}

pub(crate) fn encode_pool_payload(
    payload: u16,
    slot: u16,
    owner: u16,
    image: &SemanticImage,
) -> u16 {
    let (add, multiplier) = pool_parameters(image);
    payload
        .wrapping_add(add)
        .wrapping_add(slot.wrapping_mul(multiplier))
        .wrapping_add(owner)
}

#[cfg(test)]
pub(crate) fn decode_pool_payload(token: u16, slot: u16, owner: u16, image: &SemanticImage) -> u16 {
    let (add, multiplier) = pool_parameters(image);
    token
        .wrapping_sub(slot.wrapping_mul(multiplier))
        .wrapping_sub(owner)
        .wrapping_sub(add)
}

/// Build one globally shuffled graph rather than serializing code after each
/// prototype. Odd ids are roots and even ids are terminal nodes. Every record
/// carries independently checked id, owner, and next tokens; roots and split
/// boundaries also use seed/context-dependent u16 encodings.
fn build_code_segment_pool(
    codes: Vec<Vec<u8>>,
    image: &SemanticImage,
    random: &mut crate::random::Prng,
) -> Result<(Vec<CodeSegment>, Vec<usize>, bool), Diagnostic> {
    if codes.is_empty() {
        return Err(error("global code segment pool is empty"));
    }
    if codes.len() > usize::from(u16::MAX / 2) {
        return Err(error("too many prototypes for the segment id graph"));
    }
    let owner_count = codes.len();
    let mut pool = Vec::with_capacity(owner_count * 2);
    for (owner, code) in codes.into_iter().enumerate() {
        if code.len() < 2 {
            return Err(error("prototype code is too short to segment"));
        }
        let owner =
            u16::try_from(owner).map_err(|_| error("prototype id exceeds segment owner range"))?;
        let root = owner
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| error("segment id overflow"))?;
        let terminal = root
            .checked_add(1)
            .ok_or_else(|| error("segment id overflow"))?;
        let split = code_segment_split(code.len(), owner, image);
        pool.push(CodeSegment {
            id: root,
            owner,
            next: terminal,
            bytes: code[..split].to_vec(),
        });
        pool.push(CodeSegment {
            id: terminal,
            owner,
            next: 0,
            bytes: code[split..].to_vec(),
        });
    }
    // A full-record shuffle makes physical order independent of both owner
    // and chain order. Reject the rare owner-grouped permutation rather than
    // silently weakening the global-pool invariant.
    for _ in 0..64 {
        random.shuffle(&mut pool);
        if pool.len() <= 2 || owners_are_interleaved(&pool) {
            return Ok((pool, vec![2; owner_count], true));
        }
    }
    Err(error("failed to interleave global code segment pool"))
}

/// Owner-interleave check shared by the capture and constant pools. A pool
/// with fewer than two owners, or in which no owner appears twice, cannot
/// exhibit grouping, so every shuffle is acceptable there; only pools with
/// a repeated owner must show an owner that reappears after another closed.
/// (The segment pool never hits the all-singleton case: every owner owns
/// exactly two nodes.)
fn pool_owners_are_interleaved(owners: &[u16]) -> bool {
    let distinct = owners.iter().collect::<BTreeSet<_>>().len();
    if distinct < 2 || distinct == owners.len() {
        return true;
    }
    let mut closed = BTreeSet::new();
    let mut previous = None;
    for &owner in owners {
        if previous != Some(owner) {
            if let Some(done) = previous {
                closed.insert(done);
            }
            if closed.contains(&owner) {
                return true;
            }
            previous = Some(owner);
        }
    }
    false
}

/// Build one globally shuffled capture pool. Every prototype captures
/// become anonymous (owner, slot, tag, index) records; physical order is
/// independent of owner and slot order. Multi-owner pools of three or
/// more records must interleave owners (the segment-pool rule).
fn build_capture_pool(
    plans: &[PrototypePlan],
    _image: &SemanticImage,
    random: &mut crate::random::Prng,
) -> Result<Vec<PooledCapture>, Diagnostic> {
    if plans.len() > usize::from(u16::MAX) {
        return Err(error("too many prototypes for the capture pool"));
    }
    let mut pool = Vec::new();
    for (owner, plan) in plans.iter().enumerate() {
        let owner = u16::try_from(owner)
            .map_err(|_| error("prototype id exceeds capture pool owner range"))?;
        for (slot, capture) in plan.prototype.captures.iter().enumerate() {
            let (tag, index) = match *capture {
                Capture::Local(register) => (0, register),
                Capture::Upvalue(upvalue) => (1, upvalue),
                Capture::RecursiveLocal(register) => (2, register),
            };
            let slot = u16::try_from(slot).map_err(|_| error("capture slot overflow"))?;
            let index = u8::try_from(index).map_err(|_| error("capture index overflow"))?;
            pool.push(PooledCapture {
                owner,
                slot,
                tag,
                index,
            });
        }
    }
    // A full-record shuffle makes physical order independent of owner
    // and slot order. Reject the rare owner-grouped permutation rather
    // than silently weakening the global-pool invariant.
    for _ in 0..64 {
        random.shuffle(&mut pool);
        let owners: Vec<u16> = pool.iter().map(|record| record.owner).collect();
        if pool_owners_are_interleaved(&owners) {
            return Ok(pool);
        }
    }
    Err(error("failed to interleave global capture pool"))
}

/// Build one globally shuffled constant pool. Every prototype constants
/// become anonymous (owner, index, value) records; physical order is
/// independent of owner and index order. Interleaving follows the same
/// rule as the capture pool.
fn build_constant_pool(
    plans: &[PrototypePlan],
    _image: &SemanticImage,
    random: &mut crate::random::Prng,
) -> Result<Vec<PooledConstant>, Diagnostic> {
    if plans.len() > usize::from(u16::MAX) {
        return Err(error("too many prototypes for the constant pool"));
    }
    let mut pool = Vec::new();
    for (owner, plan) in plans.iter().enumerate() {
        let owner = u16::try_from(owner)
            .map_err(|_| error("prototype id exceeds constant pool owner range"))?;
        for (index, constant) in plan.prototype.constants.iter().enumerate() {
            let index = u16::try_from(index).map_err(|_| error("constant index overflow"))?;
            pool.push(PooledConstant {
                owner,
                index,
                constant: constant.clone(),
            });
        }
    }
    for _ in 0..64 {
        random.shuffle(&mut pool);
        let owners: Vec<u16> = pool.iter().map(|record| record.owner).collect();
        if pool_owners_are_interleaved(&owners) {
            return Ok(pool);
        }
    }
    Err(error("failed to interleave global constant pool"))
}

/// Serialize one global capture pool: fixed 6-byte records of three
/// anonymous u16 slots ([owner, slot, payload]) under the per-record pool
/// factorial profile. `payload` packs the 2-bit tag and the 8-bit index
/// as `tag + index * 4`, so every value fits the u16 token.
fn write_capture_pool(
    out: &mut Vec<u8>,
    pool: &[PooledCapture],
    image: &SemanticImage,
) -> Result<(), Diagnostic> {
    for (slot, record) in pool.iter().enumerate() {
        let physical_slot =
            u16::try_from(slot + 1).map_err(|_| error("capture pool slot exceeds u16 range"))?;
        let payload = u16::from(record.tag) + u16::from(record.index) * 4;
        let tokens = [
            encode_pool_owner(record.owner, physical_slot, image),
            encode_pool_slot(record.slot, record.owner, physical_slot, image),
            encode_pool_payload(payload, record.slot, record.owner, image),
        ];
        // Per-record token order from the same factorial profile the pool
        // reader recomputes from its 1-based physical slot.
        for token_slot in image.field_layout.pool_slot_fields(slot + 1) {
            write_u16(out, tokens[token_slot]);
        }
        if out.len() > custom::MAX_BYTES {
            return Err(error("image exceeds size limit"));
        }
    }
    Ok(())
}

/// Serialize one global constant pool: a 6-byte token header ([owner,
/// index, tag]) plus the tag-dependent value payload. The tag travels
/// only in the masked token; the payload carries no tag byte.
fn write_constant_pool(
    out: &mut Vec<u8>,
    pool: &[PooledConstant],
    image: &SemanticImage,
) -> Result<(), Diagnostic> {
    for (slot, record) in pool.iter().enumerate() {
        let physical_slot =
            u16::try_from(slot + 1).map_err(|_| error("constant pool slot exceeds u16 range"))?;
        let tag = match &record.constant {
            Constant::Nil => 0,
            Constant::Boolean(_) => 1,
            Constant::Number(_) => 2,
            Constant::String(_) => 3,
            Constant::Integer(_) => 4,
            Constant::Method(_) => 5,
        };
        let tokens = [
            encode_pool_owner(record.owner, physical_slot, image),
            encode_pool_slot(record.index, record.owner, physical_slot, image),
            encode_pool_payload(tag, record.index, record.owner, image),
        ];
        for token_slot in image.field_layout.pool_slot_fields(slot + 1) {
            write_u16(out, tokens[token_slot]);
        }
        match &record.constant {
            Constant::Nil => {}
            Constant::Boolean(value) => out.push(u8::from(*value)),
            Constant::Number(bits) => out.extend_from_slice(&bits.to_le_bytes()),
            Constant::String(value) => write_bytes(out, value)?,
            Constant::Integer(value) => out.extend_from_slice(&value.to_le_bytes()),
            Constant::Method(value) => write_bytes(out, value.as_bytes())?,
        }
        if out.len() > custom::MAX_BYTES {
            return Err(error("image exceeds size limit"));
        }
    }
    Ok(())
}

fn serialize(
    plans: &[PrototypePlan],
    image: &SemanticImage,
    decoys: &[usize],
    target: Target,
    random: &mut crate::random::Prng,
) -> Result<
    (
        Vec<u8>,
        Vec<usize>,
        Vec<usize>,
        Vec<usize>,
        Vec<usize>,
        Vec<usize>,
        bool,
        PoolPhysicalLayout,
    ),
    Diagnostic,
> {
    let mut codes = Vec::with_capacity(plans.len());
    for (prototype_id, plan) in plans.iter().enumerate() {
        let prototype_id = u16::try_from(prototype_id)
            .map_err(|_| error("prototype id exceeds recipe-token range"))?;
        codes.push(encode_code(
            prototype_id,
            plan,
            &image.recipes,
            decoys,
            image,
            random,
        )?);
    }
    let code_lengths: Vec<usize> = codes.iter().map(Vec::len).collect();
    let (segments, segment_counts, segments_interleaved) =
        build_code_segment_pool(codes, image, random)?;
    let physical_ids = segments
        .iter()
        .map(|segment| usize::from(segment.id))
        .collect::<Vec<_>>();
    let physical_owners = segments
        .iter()
        .map(|segment| usize::from(segment.owner))
        .collect::<Vec<_>>();
    let next_ids = segments
        .iter()
        .map(|segment| usize::from(segment.next))
        .collect::<Vec<_>>();
    let capture_pool = build_capture_pool(plans, image, random)?;
    let constant_pool = build_constant_pool(plans, image, random)?;
    let pool_layout = PoolPhysicalLayout {
        capture_owners: capture_pool
            .iter()
            .map(|record| usize::from(record.owner))
            .collect(),
        capture_slots: capture_pool
            .iter()
            .map(|record| usize::from(record.slot))
            .collect(),
        constant_owners: constant_pool
            .iter()
            .map(|record| usize::from(record.owner))
            .collect(),
        constant_indices: constant_pool
            .iter()
            .map(|record| usize::from(record.index))
            .collect(),
        interleaved: true,
    };
    let root_ids = (0..plans.len()).map(|owner| owner * 2 + 1).collect();
    let mut out = Vec::from(*b"OBF\x02");
    out.extend_from_slice(&[
        if target.is_luau() { 0x75 } else { 0x51 },
        1,
        WIRE_INSTRUCTION_ENCODING,
        0,
    ]);
    write_u32(&mut out, custom::HEADER_SIZE)?;
    write_u32(&mut out, 0)?;
    write_u32(&mut out, plans.len())?;
    write_u32(&mut out, 0)?;
    out.extend_from_slice(&WIRE_ISA_VERSION.to_le_bytes());
    write_u32(&mut out, 0)?;
    // Prototype metadata remains parent-indexed, but no function code bytes
    // follow it. The formerly reserved u16 is now a context-masked unique root
    // id; all actual nodes live only in the global shuffled segment pool.
    for (prototype_id, plan) in plans.iter().enumerate() {
        let prototype = &plan.prototype;
        let code_len = code_lengths[prototype_id];
        let owner = u16::try_from(prototype_id)
            .map_err(|_| error("prototype id exceeds segment owner range"))?;
        let root = owner
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| error("segment root id overflow"))?;
        // ISA13 keeps the 24-byte shape and the wire read sequence, but the
        // field assigned to each same-width slot follows the per-image
        // metadata permutation. The generated PH mirrors this assignment.
        let wide = [
            prototype.parent.map_or(u32::MAX, |parent| parent as u32),
            u32::try_from(prototype.constants.len()).map_err(|_| error("too many constants"))?,
            u32::try_from(plan.bundles.len()).map_err(|_| error("too many bundles"))?,
            u32::try_from(code_len).map_err(|_| error("code length overflow"))?,
        ];
        let medium = [
            prototype.registers,
            u16::try_from(prototype.captures.len()).map_err(|_| error("too many captures"))?,
            encode_segment_root(root, owner, image),
        ];
        let narrow = [prototype.parameters, prototype.flags];
        let layout = &image.field_layout;
        out.extend_from_slice(&wide[usize::from(layout.meta_u32[0])].to_le_bytes());
        write_u16(&mut out, medium[usize::from(layout.meta_u16[0])]);
        out.push(narrow[usize::from(layout.meta_u8[0])]);
        out.push(narrow[usize::from(layout.meta_u8[1])]);
        write_u16(&mut out, medium[usize::from(layout.meta_u16[1])]);
        write_u16(&mut out, medium[usize::from(layout.meta_u16[2])]);
        out.extend_from_slice(&wide[usize::from(layout.meta_u32[1])].to_le_bytes());
        out.extend_from_slice(&wide[usize::from(layout.meta_u32[2])].to_le_bytes());
        out.extend_from_slice(&wide[usize::from(layout.meta_u32[3])].to_le_bytes());
        // ISA14: captures and constants live only in the global pools
        // written below; headers carry just the 24 metadata bytes.
        if out.len() > custom::MAX_BYTES {
            return Err(error("image exceeds size limit"));
        }
    }
    // ISA14 global pools: captures and constants live only here, each
    // record carrying masked owner/index tokens under a per-record
    // factorial profile. Pool order follows the per-image flip bit the
    // generated parser mirrors.
    if image.field_layout.pools_flipped {
        write_constant_pool(&mut out, &constant_pool, image)?;
        write_capture_pool(&mut out, &capture_pool, image)?;
    } else {
        write_capture_pool(&mut out, &capture_pool, image)?;
        write_constant_pool(&mut out, &constant_pool, image)?;
    }
    for (slot, segment) in segments.iter().enumerate() {
        let physical_slot = u16::try_from(slot + 1)
            .map_err(|_| error("segment physical slot exceeds u16 range"))?;
        let tokens = [
            encode_segment_id(segment.id, physical_slot, image),
            encode_segment_owner(segment.owner, segment.id, physical_slot, image),
            encode_segment_next(segment.next, segment.id, segment.owner, image),
        ];
        // Per-segment token order from the same factorial profile the pool
        // reader recomputes from its 1-based physical slot.
        for token_slot in image.field_layout.segment_slot_fields(slot + 1) {
            write_u16(&mut out, tokens[token_slot]);
        }
        out.extend_from_slice(&segment.bytes);
        if out.len() > custom::MAX_BYTES {
            return Err(error("image exceeds size limit"));
        }
    }
    let length = u32::try_from(out.len()).map_err(|_| error("image length overflow"))?;
    out[12..16].copy_from_slice(&length.to_le_bytes());
    let checksum = custom::checksum(&out[custom::HEADER_SIZE..]);
    out[28..32].copy_from_slice(&checksum.to_le_bytes());
    Ok((
        out,
        segment_counts,
        physical_ids,
        physical_owners,
        next_ids,
        root_ids,
        segments_interleaved,
        pool_layout,
    ))
}

pub(crate) fn encode(program: &Program, seed: u64) -> Result<SemanticImage, Diagnostic> {
    custom::validate(program)?;
    let real_prototypes = program.prototypes.len();
    let canonical_words = program
        .prototypes
        .iter()
        .map(|prototype| prototype.code.len())
        .sum();
    let mut random = crate::random::Prng::new(seed ^ 0x7365_6d61_6e74_6963);
    let mut augmented = program.clone();
    let decoy_prototypes = add_decoy_prototypes(&mut augmented, &mut random);
    let (program, prototype_order) = reorder_program(&augmented, &mut random)?;
    let used_ops: Vec<Opcode> = program.opcodes().into_iter().collect();
    let mut recipes_raw: Vec<(Vec<Opcode>, bool)> = Vec::new();
    let mut by_key = BTreeMap::new();
    let mut multi_count = 0usize;
    let mut plans = Vec::with_capacity(program.prototypes.len());
    let mut neutral_recipe_indices = BTreeSet::new();
    let mut reachable_decoy_bundles = 0usize;
    let mut reachable_decoy_words = 0usize;
    let mut bundled_words = 0usize;
    for (prototype_id, prototype) in program.prototypes.iter().enumerate() {
        let mut plan = plan_prototype(
            prototype,
            &mut recipes_raw,
            &mut by_key,
            &mut multi_count,
            &mut random,
        )?;
        if prototype_order[prototype_id] < real_prototypes {
            bundled_words += plan
                .bundles
                .iter()
                .filter(|bundle| bundle.words.len() > 1)
                .map(|bundle| bundle.words.len())
                .sum::<usize>();
            let (bundles, words) = inject_reachable_decoys(
                &mut plan,
                &mut recipes_raw,
                &mut by_key,
                &mut multi_count,
                &mut neutral_recipe_indices,
                &mut random,
            )?;
            reachable_decoy_bundles += bundles;
            reachable_decoy_words += words;
        }
        plans.push(plan);
    }
    let decoys = add_decoy_recipes(&used_ops, &mut recipes_raw, &mut by_key, &mut random);
    let mut used_ids = BTreeSet::new();
    let mut recipes = Vec::with_capacity(recipes_raw.len());
    let mut camouflaged_live_recipes = 0usize;
    let mut camouflaged_live_ops = 0usize;
    let mut live_recipe_ops = 0usize;
    for (actual_ops, live) in recipes_raw {
        let id = random_nonzero_u16(&mut random, &mut used_ids);
        let mut execute_ops = actual_ops.clone();
        let descriptor_ops = if live {
            let descriptor: Vec<Opcode> = actual_ops
                .iter()
                .copied()
                .map(|op| camouflage_descriptor_op(op, program.target, &mut random))
                .collect();
            let changed = descriptor
                .iter()
                .zip(&actual_ops)
                .filter(|(advertised, actual)| advertised != actual)
                .count();
            camouflaged_live_recipes += usize::from(changed > 0);
            camouflaged_live_ops += changed;
            live_recipe_ops += actual_ops.len();
            descriptor
        } else {
            actual_ops.clone()
        };
        if !live {
            let replacement = loop {
                let candidate =
                    Opcode::ALL[(random.next_u64() % Opcode::ALL.len() as u64) as usize];
                if candidate.supported(program.target) && !control(candidate) {
                    break candidate;
                }
            };
            if let Some(first) = execute_ops.first_mut() {
                *first = replacement;
                if *first == descriptor_ops[0] {
                    *first = if descriptor_ops[0] == Opcode::Move {
                        Opcode::Nil
                    } else {
                        Opcode::Move
                    };
                }
            }
        }
        recipes.push(SemanticRecipe {
            id,
            descriptor_ops,
            execute_ops,
            live,
        });
    }
    let neutral_decoy_recipe_ids = neutral_recipe_indices
        .iter()
        .map(|index| recipes[*index].id)
        .collect();
    let bundles = plans.iter().map(|plan| plan.bundles.len()).sum();
    let shuffled_records = plans
        .iter()
        .filter(|plan| {
            plan.physical
                .iter()
                .enumerate()
                .any(|(at, value)| at != *value)
        })
        .count();
    let referenced_recipe_ids = plans
        .iter()
        .flat_map(|plan| &plan.bundles)
        .map(|bundle| recipes[bundle.recipe].id)
        .collect();
    let token_layers = recipe_token_layers(&mut random);
    let edge_layers = edge_token_layers(&mut random);
    let mut image = SemanticImage {
        bytes: Vec::new(),
        recipes,
        mask_mul: [17u16, 29, 37, 43, 53, 61][(random.next_u64() % 6) as usize],
        mask_add: [11u16, 19, 23, 31, 41, 47][(random.next_u64() % 6) as usize],
        mask_salt: (random.next_u64() % 64) as u16,
        token_layers,
        edge_layers,
        field_layout: field_layout(seed),
        canonical_words,
        bundles,
        bundled_words,
        reachable_decoy_bundles,
        reachable_decoy_words,
        neutral_decoy_recipe_ids,
        camouflaged_live_recipes,
        camouflaged_live_ops,
        live_recipe_ops,
        prototype_order,
        decoy_prototypes,
        shuffled_records,
        code_segments: 0,
        prototype_segment_counts: Vec::new(),
        segment_physical_ids: Vec::new(),
        segment_physical_owners: Vec::new(),
        segment_next_ids: Vec::new(),
        segment_root_ids: Vec::new(),
        segments_interleaved: false,
        capture_pool_owners: Vec::new(),
        capture_pool_slots: Vec::new(),
        constant_pool_owners: Vec::new(),
        constant_pool_indices: Vec::new(),
        pools_interleaved: false,
        referenced_recipe_ids,
    };
    let (
        bytes,
        segment_counts,
        physical_ids,
        physical_owners,
        next_ids,
        root_ids,
        segments_interleaved,
        pool_layout,
    ) = serialize(&plans, &image, &decoys, program.target, &mut random)?;
    image.bytes = bytes;
    image.code_segments = physical_owners.len();
    image.prototype_segment_counts = segment_counts;
    image.segment_physical_ids = physical_ids;
    image.segment_physical_owners = physical_owners;
    image.segment_next_ids = next_ids;
    image.segment_root_ids = root_ids;
    image.segments_interleaved = segments_interleaved;
    image.capture_pool_owners = pool_layout.capture_owners;
    image.capture_pool_slots = pool_layout.capture_slots;
    image.constant_pool_owners = pool_layout.constant_owners;
    image.constant_pool_indices = pool_layout.constant_indices;
    image.pools_interleaved = pool_layout.interleaved;
    Ok(image)
}
