//! Seeded semantic virtualization used only by generated VM scripts.
//!
//! Public `.obf` files remain the canonical OBF v2/ISA2 format. Before a
//! canonical program is embedded in a generated script, this module lowers
//! its fixed one-word instructions into a private ISA3 wire image:
//!
//! * straight-line words are grouped into program-specific superoperators;
//! * each superoperator has a random 16-bit recipe id and carries no opcode
//!   bytes at its use sites;
//! * code records use random labels and explicit successors, and are emitted
//!   in shuffled physical order rather than source/chunk order;
//! * sibling prototypes are seed-shuffled, Closure operands are rewritten, and
//!   an unreachable synthetic prototype subtree breaks count/tree isomorphism;
//! * unused recipe descriptors have deliberately mismatched execution bodies.
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
pub(crate) const WIRE_ISA_VERSION: u32 = 3;
const MAX_MULTI_RECIPES: usize = 96;
const MAX_BUNDLE_WORDS: usize = 4;
const DECOY_RECIPES: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct SemanticRecipe {
    pub id: u16,
    /// Sequence advertised by the encrypted recipe dictionary and used for
    /// operand decoding/validation.
    pub ops: Vec<Opcode>,
    /// Sequence emitted in the superoperator arm. It differs only for an
    /// unreachable decoy recipe.
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
    pub canonical_words: usize,
    pub bundles: usize,
    pub bundled_words: usize,
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
    if temporary.len() > usize::from(u16::MAX) {
        return Err(error("prototype exceeds the private label space"));
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
        out.push(u8::try_from(recipe.ops.len()).map_err(|_| error("recipe is too long"))?);
        for (position, &op) in recipe.ops.iter().enumerate() {
            out.push(encode_masked_opcode(op, recipe.id, position, image));
        }
    }
    write_u16(&mut out, plan.start);
    for &index in &plan.physical {
        let bundle = &plan.bundles[index];
        write_u16(&mut out, bundle.label);
        write_u16(&mut out, bundle.next);
        write_u16(&mut out, bundle.skip);
        write_u16(&mut out, recipes[bundle.recipe].id);
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
    for plan in plans {
        codes.push(encode_code(plan, &image.recipes, decoys, image, random)?);
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
    for prototype in &program.prototypes {
        plans.push(plan_prototype(
            prototype,
            &mut recipes_raw,
            &mut by_key,
            &mut multi_count,
            &mut random,
        )?);
    }
    let decoys = add_decoy_recipes(&used_ops, &mut recipes_raw, &mut by_key, &mut random);
    let mut used_ids = BTreeSet::new();
    let mut recipes = Vec::with_capacity(recipes_raw.len());
    for (ops, live) in recipes_raw {
        let id = random_nonzero_u16(&mut random, &mut used_ids);
        let mut execute_ops = ops.clone();
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
                if *first == ops[0] {
                    *first = if ops[0] == Opcode::Move {
                        Opcode::Nil
                    } else {
                        Opcode::Move
                    };
                }
            }
        }
        recipes.push(SemanticRecipe {
            id,
            ops,
            execute_ops,
            live,
        });
    }
    let bundles = plans.iter().map(|plan| plan.bundles.len()).sum();
    let bundled_words = plans
        .iter()
        .flat_map(|plan| &plan.bundles)
        .filter(|bundle| bundle.words.len() > 1)
        .map(|bundle| bundle.words.len())
        .sum();
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
    let mut image = SemanticImage {
        bytes: Vec::new(),
        recipes,
        mask_mul: [17u16, 29, 37, 43, 53, 61][(random.next_u64() % 6) as usize],
        mask_add: [11u16, 19, 23, 31, 41, 47][(random.next_u64() % 6) as usize],
        mask_salt: (random.next_u64() % 64) as u16,
        canonical_words,
        bundles,
        bundled_words,
        prototype_order,
        decoy_prototypes,
        shuffled_records,
        referenced_recipe_ids,
    };
    image.bytes = serialize(&plans, &image, &decoys, program.target, &mut random)?;
    Ok(image)
}
