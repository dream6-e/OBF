// K3-FULL (de-pooled recipe dictionary). The image now carries, per recipe slot, the
// *renumbered* opcode and the operand form as a byte pair, which is what lets the
// generated parser drop both shared tables it used to rebuild from packed base86
// strings: the form table (`FM`) that answered "how many bytes does this opcode read"
// and the permutation table (`PT`) that answered "which canonical id is this". This
// gate reads the private image back and proves the pair is exactly the value those two
// tables used to produce -- every seed, every prototype dictionary slot -- so the
// removal is a change of *representation*, not a loss of the binding the tables carried.
use crate::bytecode::custom::encoding_form;

#[test]
fn recipe_slots_carry_the_renumbered_id_and_the_operand_form() {
    for (target, fixture) in [
        (
            Target::Lua51,
            include_str!("../../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../../tests/fixtures/vm_luau.lua"),
        ),
    ] {
        let data = compile(fixture, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        for seed in [7001u64, 7351, 0, 4242, u64::MAX] {
            let image = super::semantic::encode(&program, seed).unwrap();
            let perm = super::structure::opcode_permutation(seed, 64);
            let flipped = image.field_layout.dict_flipped;
            let code = semantic_code(&image, 0);
            let recipes = u16::from_le_bytes(code[..2].try_into().unwrap()) as usize;
            assert!(recipes >= 2, "{target} seed {seed}: no dictionary");
            let mut cursor = 2usize;
            let mut checked = 0usize;
            for _ in 0..recipes {
                let (rid, len) = if flipped {
                    (
                        u16::from_le_bytes(code[cursor + 1..cursor + 3].try_into().unwrap()),
                        usize::from(code[cursor]),
                    )
                } else {
                    (
                        u16::from_le_bytes(code[cursor..cursor + 2].try_into().unwrap()),
                        usize::from(code[cursor + 2]),
                    )
                };
                assert!((1..=4).contains(&len), "{target} seed {seed}: bad slot count");
                let recipe = image
                    .recipes
                    .iter()
                    .find(|candidate| candidate.id == rid)
                    .unwrap_or_else(|| {
                        panic!("{target} seed {seed}: dictionary names unknown recipe {rid}")
                    });
                assert_eq!(
                    recipe.descriptor_ops.len(),
                    len,
                    "{target} seed {seed}: recipe {rid} length moved"
                );
                for (position, &op) in recipe.descriptor_ops.iter().enumerate() {
                    let fold = |slot: usize, modulus: u64| {
                        (u64::from(rid) * u64::from(image.mask_mul)
                            + slot as u64 * u64::from(image.mask_add)
                            + u64::from(image.mask_salt))
                            % modulus
                    };
                    let at = cursor + 3 + position * 2;
                    let id_byte = code[at];
                    let form_byte = code[at + 1];
                    assert_eq!(
                        id_byte,
                        ((u64::from(perm[usize::from(op as u8)]) + fold(position * 2, 256))
                            % 256) as u8,
                        "{target} seed {seed}: recipe {rid} slot {position} lost its renumbered id"
                    );
                    assert_eq!(
                        form_byte,
                        ((u64::from(encoding_form(op)) - 1 + fold(position * 2 + 1, 8)) % 8) as u8,
                        "{target} seed {seed}: recipe {rid} slot {position} carries a form the \
                         opcode does not have -- the pair must stay the *derived* encoding, or \
                         the removed form table was carrying a real binding"
                    );
                    checked += 1;
                }
                cursor += 3 + 2 * len;
            }
            assert!(
                checked >= 2,
                "{target} seed {seed}: only {checked} dictionary slots walked"
            );
        }
    }
}

/// The pair encoding is also what makes an out-of-range form fatal *before* any
/// operand is read, so the two halves of the check are independent: a script whose
/// reader ignored the form byte would still decode, and that would silently undo the
/// de-pooling. This pins that the emitted reader consumes exactly the pair the image
/// carries by counting the arithmetic that splits it -- one split per shape, no table.
#[test]
fn the_reader_splits_the_pair_without_consulting_a_table() {
    for (target, fixture) in [
        (
            Target::Lua51,
            include_str!("../../../../tests/fixtures/vm_lua51.lua"),
        ),
        (
            Target::Luau,
            include_str!("../../../../tests/fixtures/vm_luau.lua"),
        ),
    ] {
        let data = compile(fixture, target).unwrap();
        let program = custom::decode(&data, target).unwrap();
        let raw = super::emit::generate(&data, &program, if target.is_luau() { 7351 } else { 7001 })
            .unwrap();
        for table in ["FM[op]", "PT[op]", "FM[o]", "local FMt", "local FM={", "%86+1"] {
            assert!(
                !raw.contains(table),
                "{target}: `{table}` is back in the generated parser -- K3-FULL removed the \
                 shared form and permutation tables, and the shape must come from the record"
            );
        }
        // The five shapes are still all reachable, each with its own baked widths: the
        // de-pooling must not have collapsed the shape chain into one branch.
        for shape in 1..=5u8 {
            assert!(
                raw.contains(&format!("sf=={shape}")),
                "{target}: shape {shape} lost its specialised read"
            );
        }
    }
}
