//! Seeded semantic virtualization used only by generated VM scripts.
//!
//! Public `.obf` files remain the canonical OBF v2/ISA2 format. Before a
//! canonical program is embedded in a generated script, this module lowers
//! its fixed one-word instructions into a private ISA7 wire image:
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
pub(crate) const WIRE_ISA_VERSION: u32 = 7;
pub(crate) const RECIPE_TOKEN_STAGES: usize = 5;
pub(crate) const EDGE_TOKEN_STAGES: usize = 3;
const MAX_MULTI_RECIPES: usize = 96;
const MAX_BUNDLE_WORDS: usize = 4;
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

fn write_operands(out: &mut Vec<u8>, word: Word) -> Result<(), Diagnostic> {
    let op = word.opcode()?;
    match custom::encoding_form(op) {
        1 => write_varint(out, word.ax()),
        2 => write_varint(out, word.a()),
        3 => {
            write_varint(out, word.a());
            write_varint(out, word.b());
        }
        4 => {
            write_varint(out, word.a());
            write_varint(out, word.bx());
        }
        _ => {
            write_varint(out, word.a());
            write_varint(out, word.b());
            write_varint(out, word.c());
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
        write_u16(&mut out, recipe.id);
        out.push(
            u8::try_from(recipe.descriptor_ops.len()).map_err(|_| error("recipe is too long"))?,
        );
        for (position, &op) in recipe.descriptor_ops.iter().enumerate() {
            out.push(encode_masked_opcode(op, recipe.id, position, image));
        }
    }
    write_u16(&mut out, plan.start);
    for &index in &plan.physical {
        let bundle = &plan.bundles[index];
        write_u16(&mut out, bundle.label);
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
        write_u16(&mut out, next_token);
        write_u16(&mut out, skip_token);
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
        write_u16(&mut out, token);
        for &word in &bundle.words {
            write_operands(&mut out, word)?;
        }
    }
    Ok(out)
}

fn serialize(
    plans: &[PrototypePlan],
    image: &SemanticImage,
    decoys: &[usize],
    target: Target,
    random: &mut crate::random::Prng,
) -> Result<Vec<u8>, Diagnostic> {
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
    for (plan, code) in plans.iter().zip(codes) {
        let prototype = &plan.prototype;
        out.extend_from_slice(
            &prototype
                .parent
                .map_or(u32::MAX, |parent| parent as u32)
                .to_le_bytes(),
        );
        write_u16(&mut out, prototype.registers);
        out.extend_from_slice(&[prototype.parameters, prototype.flags]);
        write_u16(
            &mut out,
            u16::try_from(prototype.captures.len()).map_err(|_| error("too many captures"))?,
        );
        write_u16(&mut out, 0);
        write_u32(&mut out, prototype.constants.len())?;
        write_u32(&mut out, plan.bundles.len())?;
        write_u32(&mut out, code.len())?;
        for capture in &prototype.captures {
            let (tag, index) = match *capture {
                Capture::Local(register) => (0, register),
                Capture::Upvalue(upvalue) => (1, upvalue),
                Capture::RecursiveLocal(register) => (2, register),
            };
            let index = u8::try_from(index).map_err(|_| error("capture index overflow"))?;
            out.extend_from_slice(&[tag, index]);
        }
        for constant in &prototype.constants {
            match constant {
                Constant::Nil => out.push(0),
                Constant::Boolean(value) => out.extend_from_slice(&[1, u8::from(*value)]),
                Constant::Number(bits) => {
                    out.push(2);
                    out.extend_from_slice(&bits.to_le_bytes());
                }
                Constant::String(value) => {
                    out.push(3);
                    write_bytes(&mut out, value)?;
                }
                Constant::Integer(value) => {
                    out.push(4);
                    out.extend_from_slice(&value.to_le_bytes());
                }
                Constant::Method(value) => {
                    out.push(5);
                    write_bytes(&mut out, value.as_bytes())?;
                }
            }
        }
        out.extend_from_slice(&code);
        if out.len() > custom::MAX_BYTES {
            return Err(error("image exceeds size limit"));
        }
    }
    let length = u32::try_from(out.len()).map_err(|_| error("image length overflow"))?;
    out[12..16].copy_from_slice(&length.to_le_bytes());
    let checksum = custom::checksum(&out[custom::HEADER_SIZE..]);
    out[28..32].copy_from_slice(&checksum.to_le_bytes());
    Ok(out)
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
        referenced_recipe_ids,
    };
    image.bytes = serialize(&plans, &image, &decoys, program.target, &mut random)?;
    Ok(image)
}
