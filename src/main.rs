use obf::{bytecode, vm};
use obf::{Diagnostic, Target};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Diagnostic> {
    let mut arguments = env::args().skip(1);
    let Some(command) = arguments.next() else {
        print_help();
        return Ok(());
    };
    if matches!(command.as_str(), "-h" | "--help" | "help") {
        print_help();
        return Ok(());
    }
    if matches!(command.as_str(), "-V" | "--version" | "version") {
        println!("obf {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if !matches!(
        command.as_str(),
        "check"
            | "minify"
            | "virtualize"
            | "inspect-bytecode"
            | "compile"
            | "dump-ir"
            | "wrap-bytecode"
    ) {
        return Err(Diagnostic::new(format!("unknown command '{command}'")));
    }

    let mut target = None;
    let mut output = None;
    let mut input = None;
    let mut seed = 0;
    let mut seed_was_set = false;
    let mut no_rename = false;
    let mut native_backend = None;
    let mut rest = arguments.peekable();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "-t" | "--target" => {
                let value = rest
                    .next()
                    .ok_or_else(|| Diagnostic::new("missing value after --target"))?;
                target = Some(parse_target(&value)?);
            }
            "-o" | "--output" => {
                let value = rest
                    .next()
                    .ok_or_else(|| Diagnostic::new("missing value after --output"))?;
                output = Some(PathBuf::from(value));
            }
            "--no-rename" => no_rename = true,
            "--backend" => {
                let value = rest
                    .next()
                    .ok_or_else(|| Diagnostic::new("missing value after --backend"))?;
                native_backend = Some(parse_backend(&value)?);
            }
            _ if argument.starts_with("--backend=") => {
                native_backend = Some(parse_backend(&argument[10..])?);
            }
            "--seed" => {
                let value = rest
                    .next()
                    .ok_or_else(|| Diagnostic::new("missing value after --seed"))?;
                seed = parse_seed(&value)?;
                seed_was_set = true;
            }
            _ if argument.starts_with("--target=") => {
                target = Some(parse_target(&argument[9..])?);
            }
            _ if argument.starts_with("--seed=") => {
                seed = parse_seed(&argument[7..])?;
                seed_was_set = true;
            }
            _ if argument.starts_with('-') && argument != "-" => {
                return Err(Diagnostic::new(format!("unknown option '{argument}'")));
            }
            _ => {
                if input.replace(PathBuf::from(&argument)).is_some() {
                    return Err(Diagnostic::new("only one input file may be specified"));
                }
            }
        }
    }

    let target = target.ok_or_else(|| Diagnostic::new("--target is required"))?;
    let input =
        input.ok_or_else(|| Diagnostic::new("input file is required (use '-' for stdin)"))?;
    let data = read_input(&input)?;

    if seed_was_set && !matches!(command.as_str(), "minify" | "virtualize" | "wrap-bytecode") {
        return Err(Diagnostic::new(
            "--seed is only valid for 'minify', 'virtualize' or 'wrap-bytecode'",
        ));
    }
    if seed_was_set && no_rename {
        return Err(Diagnostic::new(
            "--seed cannot be combined with --no-rename",
        ));
    }

    if native_backend.is_some() && command != "virtualize" {
        return Err(Diagnostic::new("--backend is only valid for 'virtualize'"));
    }
    if no_rename && command != "minify" {
        return Err(Diagnostic::new(
            "--no-rename is only valid for the 'minify' command",
        ));
    }

    if !seed_was_set
        && !no_rename
        && matches!(command.as_str(), "minify" | "virtualize" | "wrap-bytecode")
    {
        seed = vm::Options::default().seed;
        // Keep stdout a pure single-line script, while making default random
        // generations reproducible with a reported --seed value.
        eprintln!("seed: {seed}");
    }

    match command.as_str() {
        "check" => {
            if output.is_some() {
                return Err(Diagnostic::new("--output is not valid for 'check'"));
            }
            let source = decode_source(&data)?;
            obf::check(source, target)
        }
        "minify" => {
            let source = decode_source(&data)?;
            let result = obf::minify_with_options(
                source,
                target,
                obf::MinifyOptions {
                    rename_locals: !no_rename,
                    seed,
                },
            )?;
            write_output(output, result.as_bytes())
        }
        "virtualize" => {
            decode_source(&data)?;
            let result = if native_backend == Some(true) {
                vm::virtualize_native(&data, target, vm::Options { seed })?
            } else {
                vm::virtualize(&data, target, vm::Options { seed })?
            };
            write_output(output, result.as_bytes())
        }
        "compile" => {
            let bytes = vm::custom::compile(decode_source(&data)?, target)?;
            write_output(output, &bytes)
        }
        "dump-ir" => {
            let ir = obf::ir::compile(decode_source(&data)?, target)?;
            write_output(output, format!("{ir:#?}\n").as_bytes())
        }
        "wrap-bytecode" => {
            let source = vm::custom::emit(&data, target, seed)?;
            write_output(output, source.as_bytes())
        }
        "inspect-bytecode" => {
            if output.is_some() {
                return Err(Diagnostic::new(
                    "--output is not valid for 'inspect-bytecode'",
                ));
            }
            let custom_program = if data.starts_with(b"OBF") {
                Some(bytecode::custom::decode(&data, target)?)
            } else {
                None
            };
            let report = if let Some(program) = &custom_program {
                program.report()
            } else {
                bytecode::inspect(&data, target)?
            };
            if let Some(program) = &custom_program {
                println!("format: OBF v2");
                println!("header-size: {}", bytecode::custom::HEADER_SIZE);
                println!("instruction-size: {}", bytecode::custom::INSTRUCTION_SIZE);
                println!("isa-version: {}", bytecode::custom::ISA_VERSION);
                println!(
                    "opcodes: {}",
                    program
                        .opcodes()
                        .iter()
                        .map(|op| format!("{}:{}", *op as u8, op.name()))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            println!("target: {}", report.target);
            println!("bytecode-version: {}", report.version);
            if let Some(version) = report.type_version {
                println!("type-version: {version}");
            }
            println!("strings: {}", report.strings);
            println!("prototypes: {}", report.prototypes);
            println!("instructions: {}", report.instructions);
            println!("constants: {}", report.constants);
            println!("main-prototype: {}", report.main_prototype);
            Ok(())
        }
        _ => unreachable!(),
    }
}

fn parse_backend(value: &str) -> Result<bool, Diagnostic> {
    match value {
        "ast" => Ok(false),
        "native" => Ok(true),
        _ => Err(Diagnostic::new(format!(
            "unknown VM backend '{value}' (expected ast or native)"
        ))),
    }
}

fn parse_target(value: &str) -> Result<Target, Diagnostic> {
    Target::from_str(value).map_err(Diagnostic::new)
}

fn parse_seed(value: &str) -> Result<u64, Diagnostic> {
    let result = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    };
    result.map_err(|_| Diagnostic::new(format!("invalid 64-bit seed '{value}'")))
}

fn read_input(path: &PathBuf) -> Result<Vec<u8>, Diagnostic> {
    if path.as_os_str() == "-" {
        let mut data = Vec::new();
        io::stdin()
            .read_to_end(&mut data)
            .map_err(|error| Diagnostic::new(format!("failed to read stdin: {error}")))?;
        Ok(data)
    } else {
        fs::read(path).map_err(|error| {
            Diagnostic::new(format!("failed to read '{}': {error}", path.display()))
        })
    }
}

fn decode_source(data: &[u8]) -> Result<&str, Diagnostic> {
    std::str::from_utf8(data).map_err(|error| {
        Diagnostic::byte(
            format!("source is not valid UTF-8: {error}"),
            error.valid_up_to(),
        )
    })
}

fn write_output(path: Option<PathBuf>, data: &[u8]) -> Result<(), Diagnostic> {
    if let Some(path) = path {
        fs::write(&path, data).map_err(|error| {
            Diagnostic::new(format!("failed to write '{}': {error}", path.display()))
        })
    } else {
        io::stdout()
            .write_all(data)
            .map_err(|error| Diagnostic::new(format!("failed to write stdout: {error}")))
    }
}

fn print_help() {
    println!(
        "OBF - std-only Lua 5.1 and Luau toolchain\n\n\
Usage:\n  obf check --target <lua51|luau> <input|->\n  \
obf minify --target <lua51|luau> [--seed N | --no-rename] [-o FILE] <input|->\n  \
obf virtualize --target <lua51|luau> [--backend ast|native] [--seed N] [-o FILE] <input|->\n  \
obf dump-ir --target <lua51|luau> [-o FILE] <input|->\n  \
obf compile --target <lua51|luau> [-o FILE] <input|->\n  \
obf wrap-bytecode --target <lua51|luau> [--seed N] [-o FILE] <input.obf|->\n  \
obf inspect-bytecode --target <lua51|luau> <input|->\n\n\
Default virtualize: AST -> IR -> OBF v2 (32-byte header, 4-byte instructions).\n\
No external compiler, encryption, compression or randomized bytecode layout.\n\
compile emits binary bytecode; dump-ir emits typed register IR.\n\
wrap-bytecode validates OBF v2 and emits its single-line register VM.\n\
inspect-bytecode accepts OBF v2 and native target bytecode.\n\
--backend native explicitly selects the legacy external-compiler OBF v1 path.\n\
Generated scripts receive randomized 1-2 letter locals only after assembly.\n\
Use --seed for reproducibility; omitted seeds are fresh and printed to stderr.\n\
Known reflection disables minify renaming; the AST VM rejects known unsupported reflection."
    );
}
