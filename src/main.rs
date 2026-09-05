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
        "check" | "minify" | "virtualize" | "inspect-bytecode"
    ) {
        return Err(Diagnostic::new(format!("unknown command '{command}'")));
    }

    let mut target = None;
    let mut output = None;
    let mut input = None;
    let mut seed = vm::Options::default().seed;
    let mut seed_was_set = false;
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

    if seed_was_set && command != "virtualize" {
        return Err(Diagnostic::new(
            "--seed is only valid for the 'virtualize' command",
        ));
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
            let result = obf::minify(source, target)?;
            write_output(output, result.as_bytes())
        }
        "virtualize" => {
            decode_source(&data)?;
            let result = vm::virtualize(&data, target, vm::Options { seed })?;
            write_output(output, result.as_bytes())
        }
        "inspect-bytecode" => {
            if output.is_some() {
                return Err(Diagnostic::new(
                    "--output is not valid for 'inspect-bytecode'",
                ));
            }
            let report = bytecode::inspect(&data, target)?;
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
obf minify --target <lua51|luau> [-o FILE] <input|->\n  \
obf virtualize --target <lua51|luau> [--seed N] [-o FILE] <input|->\n  \
obf inspect-bytecode --target <lua51|luau> <input>\n\n\
The virtualize command compiles source into a randomized private instruction\n\
format and emits a single-line target-language interpreter."
    );
}
