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
fn header_is_32_bytes_and_instructions_are_seven_bit_varints() {
    for target in [Target::Lua51, Target::Luau] {
        let bytes = bytes(target);
        let p = bc::decode(&bytes, target).unwrap();
        assert_eq!(&bytes[..4], b"OBF\x02");
        assert_eq!(bytes[4], if target.is_luau() { 0x75 } else { 0x51 });
        // endianness 1, instruction width code 0 (varint), flags 0
        assert_eq!(&bytes[5..8], &[1, 0, 0]);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 32);
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize,
            bytes.len()
        );
        assert_eq!(
            u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            bc::ISA_VERSION
        );
        // Logical VM instructions stay fixed (opcode, A, B, C) words; only
        // the serialized operand stream uses 7-bit varints.
        assert_eq!(std::mem::size_of::<Word>(), 4);
        // One 24-byte prototype header, one tagged f64 constant, then the
        // varint code stream: NewPack 2B, Constant 3B, Push 3B, Clear 3B,
        // Return 2B -- 13 bytes instead of the old fixed 5x4.
        let stream = bc::encode_code(&p.prototypes[0].code).unwrap();
        assert_eq!(
            stream,
            vec![
                Opcode::NewPack as u8,
                0,
                Opcode::Constant as u8,
                1,
                0,
                Opcode::Push as u8,
                0,
                1,
                Opcode::Clear as u8,
                1,
                1,
                Opcode::Return as u8,
                0,
            ]
        );
        let cs = u32::from_le_bytes(bytes[52..56].try_into().unwrap()) as usize;
        assert_eq!(cs, stream.len());
        assert_eq!(bytes.len(), 32 + 24 + 9 + cs);
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
fn varint_stream_is_canonical_banded_and_fully_consumed() {
    let target = Target::Lua51;
    let base = bytes(target);
    let code = 32 + 24 + 9;
    let original = bc::encode_code(&bc::decode(&base, target).unwrap().prototypes[0].code).unwrap();
    let rebuild = |stream: &[u8], damaged: &mut Vec<u8>| {
        damaged.splice(code..code + original.len(), stream.iter().copied());
        damaged[52..56].copy_from_slice(&(stream.len() as u32).to_le_bytes());
        recalc(damaged);
    };
    // NewPack(a=0) opens the stream; corrupt its own operand, keep the rest.
    let head_of = |prefix: &[u8]| -> Vec<u8> {
        let mut stream = prefix.to_vec();
        stream.extend_from_slice(&original[2..]);
        stream
    };
    for prefix in [
        // non-canonical two-byte encoding of a=0
        &[Opcode::NewPack as u8, 0x80, 0x00][..],
        // register operand overflows the 8-bit range (300)
        &[Opcode::NewPack as u8, 0x80 | 44, 0x02],
        // dangling continuation beyond the final stream byte
        &[Opcode::NewPack as u8, 0x80],
    ] {
        let mut damaged = base.clone();
        let stream = head_of(prefix);
        rebuild(&stream, &mut damaged);
        assert!(bc::decode(&damaged, target).is_err(), "{prefix:?}");
    }
    // a valid constant index (0) re-spelled as three non-canonical bytes
    let mut damaged = base.clone();
    let mut stream = original.clone();
    stream.splice(2..5, [0x80, 0x80, 0x00]); // Constant's k=0 as 3 zero groups
    rebuild(&stream, &mut damaged);
    assert!(bc::decode(&damaged, target).is_err());
    // a fully valid walk that leaves one unread byte in the code stream
    let mut damaged = base.clone();
    let mut stream = original.clone();
    stream.push(0);
    rebuild(&stream, &mut damaged);
    assert!(bc::decode(&damaged, target).is_err());
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
    let code = 32 + 24 + 9;
    for (at, replacement) in [
        (32, vec![0, 0, 0, 0]), // entry cannot have a parent
        (36, vec![0, 0]),
        (36, vec![1, 1]), // zero / 257 registers
        (38, vec![255]),
        (39, vec![8]),
        (39, vec![7]),
        (40, vec![1, 1]),
        (42, vec![1, 0]),                             // captures/reserved
        (44, vec![1, 0, 1, 0]),                       // 65537 constants
        (48, vec![255, 255, 255, 255]),               // oversized instruction count
        (52, vec![255, 255, 255, 255]),               // code bytes outside 2..=7 per instruction
        (56, vec![255]),                              // constant tag
        (code, vec![255, 0, 0, 0, 0, 0, 0, 0, 0, 0]), // unknown opcode
    ] {
        let mut damaged = bytes.clone();
        damaged[at..at + replacement.len()].copy_from_slice(&replacement);
        recalc(&mut damaged);
        assert!(
            bc::decode(&damaged, target).is_err(),
            "offset {at}, {replacement:?}"
        );
    }
    // Operand semantics survive repaired checksums at the Word level: decode,
    // corrupt one logical instruction, and the serializer's own validation
    // must still refuse it (varint re-encoding cannot launder operands).
    let mut program = bc::decode(&bytes, target).unwrap();
    let last = program.prototypes[0].code.len() - 1;
    for (at, word) in [
        (0, Word([Opcode::Nil as u8, 255, 0, 0])), // register 255
        (0, Word([Opcode::Constant as u8, 0, 1, 0])), // k == nk
        (0, Word([Opcode::ReadGlobal as u8, 0, 1, 0])), // numeric global name
        (0, Word([Opcode::Closure as u8, 0, 1, 0])), // not a child
        (0, Word([Opcode::ReadUpvalue as u8, 0, 0, 0])), // no captures
        (0, Word([Opcode::Clear as u8, 1, 0, 0])), // a > b
        (0, Word([Opcode::Extract as u8, 0, 0, 0])), // c == 0
        (0, Word([Opcode::NumberPrepare as u8, 0, 0, 0])), // a+2 >= registers
        (0, Word([Opcode::Jump as u8, 255, 255, 127])), // jump overflow
        (last, Word([Opcode::NewPack as u8, 1, 0, 0])), // falls off the end
        (last, Word([Opcode::Test as u8, 0, 0, 0])), // pc+2 >= nc
    ] {
        let mut invalid = program.clone();
        invalid.prototypes[0].code[at] = word;
        assert!(bc::serialize(&invalid).is_err(), "{at}, {word:?}");
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
        b[57..61].copy_from_slice(&u32::MAX.to_le_bytes());
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
    let stream = bc::encode_code(&p.prototypes[0].code).unwrap();
    // Nil(0) costs two bytes, Jump(70_002) four: varints beat 4-per-word.
    assert_eq!(stream.len(), 140_012);
    assert!(stream.len() < p.prototypes[0].code.len() * 4);
    assert_eq!(encoded.len(), 32 + 24 + stream.len());
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

#[test]
fn isa_revisions_roundtrip_without_silently_upgrading_legacy_programs() {
    for target in [Target::Lua51, Target::Luau] {
        let data =
            vm::custom::compile("local function f(x)return x+1 end print(f(2))", target).unwrap();
        let mut program = bc::decode(&data, target).unwrap();
        assert_eq!(program.isa_version, 2);
        program.isa_version = 1;
        for p in &mut program.prototypes {
            p.flags &= 7;
        }
        let legacy = bc::serialize(&program).unwrap();
        assert_eq!(&legacy[24..28], &1u32.to_le_bytes());
        let decoded = bc::decode(&legacy, target).unwrap();
        assert_eq!(decoded, program);
        assert_eq!(bc::serialize(&decoded).unwrap(), legacy);
        for revision in [0, 3, u32::MAX] {
            let mut bad = legacy.clone();
            bad[24..28].copy_from_slice(&revision.to_le_bytes());
            assert!(bc::decode(&bad, target)
                .unwrap_err()
                .message
                .contains("ISA version"));
        }
    }
}

#[test]
fn closure_sharing_metadata_is_target_version_scope_and_capture_checked() {
    let source="local function make() local function recursive(n)if n>0 then return recursive(n-1)end return 3 end return recursive end print(make()==make())";
    let data = vm::custom::compile(source, Target::Luau).unwrap();
    let valid = bc::decode(&data, Target::Luau).unwrap();
    let index = valid
        .prototypes
        .iter()
        .position(|p| {
            p.captures
                .iter()
                .any(|c| matches!(c, ir::Capture::RecursiveLocal(_)))
        })
        .unwrap();
    assert_ne!(valid.prototypes[index].flags & 8, 0);
    assert_eq!(bc::serialize(&valid).unwrap(), data);
    let mut bad = valid.clone();
    bad.isa_version = 1;
    assert!(bc::validate(&bad).is_err());
    let mut bad = valid.clone();
    bad.target = Target::Lua51;
    assert!(bc::validate(&bad).is_err());
    let mut bad = valid.clone();
    bad.prototypes[0].flags |= 8;
    assert!(bc::validate(&bad).is_err());
    let mut bad = valid.clone();
    bad.prototypes[index].flags &= !8;
    assert!(bc::validate(&bad).is_err());
    let mut bad = valid.clone();
    let capture = bad.prototypes[index].captures[0];
    bad.prototypes[index].captures.push(capture);
    assert!(bc::validate(&bad).is_err());
    let mut bad = valid.clone();
    bad.prototypes[index].captures[0] = ir::Capture::RecursiveLocal(256);
    assert!(bc::validate(&bad).is_err());
    let mut bad = valid.clone();
    bad.prototypes[index].flags |= 16;
    assert!(bc::validate(&bad).is_err());
}
