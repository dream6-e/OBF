use obf::bytecode::custom::{self as bc, Opcode, Word};
use obf::ir::{self, Constant, Instruction as I, Terminator as T};
use obf::{vm, Target};

fn bytes(target: Target) -> Vec<u8> {
    vm::custom::compile("return 7", target).unwrap()
}
fn recalc(bytes: &mut [u8]) {
    let len = bytes.len() as u32;
    bytes[12..16].copy_from_slice(&len.to_le_bytes());
    let sum = bc::checksum(&bytes[bc::HEADER_SIZE..]);
    bytes[28..32].copy_from_slice(&sum.to_le_bytes());
}

#[test]
fn header_is_fixed_32_bytes_and_all_instruction_records_are_four_bytes() {
    for target in [Target::Lua51, Target::Luau] {
        let bytes = bytes(target);
        let p = bc::decode(&bytes, target).unwrap();
        assert_eq!(&bytes[..4], b"OBF\x02");
        assert_eq!(bytes[4], if target.is_luau() { 0x75 } else { 0x51 });
        assert_eq!(&bytes[5..8], &[1, 4, 0]);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 32);
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize,
            bytes.len()
        );
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 1);
        assert_eq!(std::mem::size_of::<Word>(), 4);
        // This fixture has one 20-byte prototype header and one tagged f64.
        assert_eq!(bytes.len(), 32 + 20 + 9 + p.prototypes[0].code.len() * 4);
        assert_eq!(bc::serialize(&p).unwrap(), bytes);
        assert!(bc::decode(
            &bytes,
            if target.is_luau() {
                Target::Lua51
            } else {
                Target::Luau
            }
        )
        .is_err());
    }
}

#[test]
fn every_truncation_and_unrepaired_single_byte_corruption_is_rejected() {
    for target in [Target::Lua51, Target::Luau] {
        let bytes = bytes(target);
        for end in 0..bytes.len() {
            assert!(bc::decode(&bytes[..end], target).is_err(), "prefix {end}");
        }
        for at in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0x80;
            assert!(bc::decode(&damaged, target).is_err(), "byte {at}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(bc::decode(&trailing, target).is_err());
        recalc(&mut trailing);
        assert!(bc::decode(&trailing, target).is_err());
    }
}

#[test]
fn repaired_checksums_do_not_bypass_structural_validation() {
    let target = Target::Luau;
    let bytes = bytes(target);
    let code = 32 + 20 + 9;
    for (at, replacement) in [
        (32, vec![0, 0, 0, 0]), // entry cannot have a parent
        (36, vec![0, 0]),
        (36, vec![1, 1]), // zero / 257 registers
        (38, vec![255]),
        (39, vec![8]),
        (39, vec![7]),
        (40, vec![1, 1]),
        (42, vec![1, 0]),               // captures/reserved
        (44, vec![1, 0, 1, 0]),         // 65537 constants
        (48, vec![255, 255, 255, 255]), // oversized instruction stream
        (52, vec![255]),                // constant tag
        (code, vec![255, 0, 0, 0]),
        (code, vec![Opcode::Nil as u8, 255, 0, 0]),
        (code, vec![Opcode::Jump as u8, 255, 255, 255]),
        (code, vec![Opcode::Constant as u8, 0, 1, 0]),
        (code, vec![Opcode::ReadGlobal as u8, 0, 0, 0]), // numeric global name
        (code, vec![Opcode::Closure as u8, 0, 0, 0]),    // not a child
        (code, vec![Opcode::ReadUpvalue as u8, 0, 0, 0]),
        (code, vec![Opcode::Clear as u8, 1, 0, 0]),
        (code, vec![Opcode::Extract as u8, 0, 0, 0]),
        (code, vec![Opcode::NumberPrepare as u8, 0, 0, 0]),
        (bytes.len() - 4, vec![Opcode::Move as u8, 0, 0, 0]),
        (bytes.len() - 4, vec![Opcode::Test as u8, 0, 0, 0]),
    ] {
        let mut damaged = bytes.clone();
        damaged[at..at + replacement.len()].copy_from_slice(&replacement);
        recalc(&mut damaged);
        assert!(
            bc::decode(&damaged, target).is_err(),
            "offset {at}, {replacement:?}"
        );
    }
}

#[test]
fn constant_roundtrip_preserves_ieee_bits_binary_strings_and_signed_integers() {
    for target in [Target::Lua51, Target::Luau] {
        let mut p = bc::decode(&bytes(target), target).unwrap();
        let mut constants = vec![
            Constant::Nil,
            Constant::Boolean(false),
            Constant::Boolean(true),
            Constant::number(0.0),
            Constant::number(-0.0),
            Constant::Number(1),
            Constant::number(f64::INFINITY),
            Constant::number(f64::NEG_INFINITY),
            Constant::Number(0x7ff8000000000001),
            Constant::String((0..=255).collect()),
            Constant::Method("valid_method".into()),
        ];
        if target.is_luau() {
            constants.extend([Constant::Integer(i64::MIN), Constant::Integer(i64::MAX)]);
        }
        p.prototypes[0].constants = constants;
        let serialized = bc::serialize(&p).unwrap();
        assert_eq!(bc::decode(&serialized, target).unwrap(), p);
    }
}

#[test]
fn corrupt_counts_strings_captures_and_parent_graphs_fail_closed() {
    for target in [Target::Lua51, Target::Luau] {
        let source = "local x=1 return function()return function()x=x+1 return x end end";
        let mut p = bc::decode(&vm::custom::compile(source, target).unwrap(), target).unwrap();
        assert_eq!(p.prototypes.len(), 3);
        for capture in [ir::Capture::Local(256), ir::Capture::Upvalue(255)] {
            let mut invalid = p.clone();
            invalid.prototypes[1].captures[0] = capture;
            assert!(bc::serialize(&invalid).is_err());
        }
        p.prototypes[2].parent = Some(2);
        assert!(bc::serialize(&p).is_err());
        let b = vm::custom::compile("return 'abc'", target).unwrap();
        let mut b = b;
        b[53..57].copy_from_slice(&u32::MAX.to_le_bytes());
        recalc(&mut b);
        assert!(bc::decode(&b, target).is_err());
    }
}

#[test]
fn all_opcodes_have_stable_numbers_and_target_extensions_are_rejected_on_lua51() {
    assert_eq!(Opcode::ALL.len(), 49);
    for (id, &op) in Opcode::ALL.iter().enumerate() {
        assert_eq!(op as usize, id);
        assert_eq!(Opcode::from_byte(id as u8), Some(op));
    }
    assert_eq!(
        Opcode::ALL
            .iter()
            .filter(|op| op.supported(Target::Lua51))
            .count(),
        46
    );
    let p = bc::decode(&bytes(Target::Lua51), Target::Lua51).unwrap();
    for op in [Opcode::FloorDivide, Opcode::Export, Opcode::Freeze] {
        let mut invalid = p.clone();
        invalid.prototypes[0].code[0] = Word([op as u8, 0, 0, 0]);
        assert!(bc::serialize(&invalid).is_err());
    }
    let mut invalid = p.clone();
    invalid.prototypes[0].constants.push(Constant::Integer(1));
    assert!(bc::serialize(&invalid).is_err());
    for name in ["end", "bad-name", "a:evil()", "", "é"] {
        let mut invalid = p.clone();
        invalid.prototypes[0]
            .constants
            .push(Constant::Method(name.into()));
        assert!(bc::serialize(&invalid).is_err());
    }
}

#[test]
fn ir_has_symbolic_control_flow_and_wide_absolute_jumps_without_aux_words() {
    let mut ir = ir::compile("return", Target::Lua51).unwrap();
    let f = &mut ir.functions[0];
    f.blocks = vec![
        ir::Block {
            instructions: vec![],
            terminator: T::Jump(2),
        },
        ir::Block {
            instructions: vec![I::Nil(0); 70_000],
            terminator: T::Jump(2),
        },
        ir::Block {
            instructions: vec![I::NewPack(0)],
            terminator: T::Return(0),
        },
    ];
    let encoded = bc::encode(&ir).unwrap();
    let p = bc::decode(&encoded, Target::Lua51).unwrap();
    assert_eq!(p.prototypes[0].code[0].ax(), 70_002);
    assert_eq!(p.prototypes[0].code.len(), 70_004);
    assert_eq!(encoded.len(), 32 + 20 + 70_004 * 4);
}

#[test]
fn invalid_ir_is_rejected_instead_of_truncating_operands_or_emitting_partial_code() {
    let original = ir::compile("return 7", Target::Lua51).unwrap();
    for instruction in [
        I::Nil(256),
        I::Constant(0, 65_536),
        I::Extract(0, 0, 256),
        I::ReadUpvalue(0, 256),
        I::Closure(0, 65_536),
    ] {
        let mut invalid = original.clone();
        invalid.functions[0].blocks[0]
            .instructions
            .push(instruction);
        assert!(bc::encode(&invalid).is_err());
    }
    for terminator in [
        T::Unreachable,
        T::Jump(10),
        T::Branch {
            condition: 256,
            then_block: 0,
            else_block: 0,
        },
    ] {
        let mut invalid = original.clone();
        invalid.functions[0].blocks[0].terminator = terminator;
        assert!(bc::encode(&invalid).is_err());
    }
    let mut invalid = original.clone();
    invalid.functions[0].registers = 257;
    assert!(bc::encode(&invalid).is_err());
    let names = (0..260)
        .map(|n| format!("p{n}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(
        vm::custom::compile(&format!("local {names}"), Target::Lua51)
            .unwrap_err()
            .message
            .contains("256 live registers")
    );
}
