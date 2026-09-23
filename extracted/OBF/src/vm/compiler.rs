use crate::{Diagnostic, Target};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn compile(source: &[u8], target: Target) -> Result<Vec<u8>, Diagnostic> {
    let workspace = TemporaryDirectory::new()?;
    let input = workspace.path.join(match target {
        Target::Lua51 => "input.lua",
        Target::Luau => "input.luau",
    });
    fs::write(&input, source)
        .map_err(|error| Diagnostic::new(format!("failed to write compiler input: {error}")))?;

    match target {
        Target::Lua51 => compile_lua51(&workspace.path, &input),
        Target::Luau => compile_luau(&input),
    }
}

fn compile_lua51(directory: &Path, input: &Path) -> Result<Vec<u8>, Diagnostic> {
    let output_path = directory.join("output.luac");
    let compiler = find_tool("OBF_LUAC51", "luac5.1")?;
    let output = Command::new(&compiler)
        .arg("-s")
        .arg("-o")
        .arg(&output_path)
        .arg(input)
        .output()
        .map_err(|error| command_error(&compiler, error))?;
    ensure_success(&compiler, &output)?;
    fs::read(&output_path)
        .map_err(|error| Diagnostic::new(format!("failed to read Lua 5.1 bytecode: {error}")))
}

fn compile_luau(input: &Path) -> Result<Vec<u8>, Diagnostic> {
    let compiler = find_tool("OBF_LUAU_COMPILE", "luau-compile")?;
    let output = Command::new(&compiler)
        .arg("--binary")
        .arg("-O1")
        .arg("-g0")
        .arg(input)
        .output()
        .map_err(|error| command_error(&compiler, error))?;
    ensure_success(&compiler, &output)?;
    if output.stdout.first() == Some(&0) {
        return Err(Diagnostic::new(format!(
            "Luau compilation failed: {}",
            String::from_utf8_lossy(&output.stdout[1..])
        )));
    }
    Ok(output.stdout)
}

fn find_tool(environment: &str, name: &str) -> Result<PathBuf, Diagnostic> {
    if let Some(path) = env::var_os(environment) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(Diagnostic::new(format!(
            "{environment} points to missing tool '{}'",
            path.display()
        )));
    }

    let mut roots = Vec::new();
    if let Ok(current) = env::current_dir() {
        roots.push(current);
    }
    if let Ok(executable) = env::current_exe() {
        roots.extend(executable.ancestors().map(Path::to_path_buf));
    }
    for root in roots {
        let candidate = root.join("toolchains/bin").join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    if let Some(paths) = env::var_os("PATH") {
        for directory in env::split_paths(&paths) {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(Diagnostic::new(format!(
        "could not find {name}; run tools/build-reference-tools.sh or set {environment}"
    )))
}

fn ensure_success(program: &Path, output: &Output) -> Result<(), Diagnostic> {
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Diagnostic::new(format!(
            "'{}' failed with {}: {}",
            program.display(),
            output.status,
            stderr.trim()
        )))
    }
}

fn command_error(program: &Path, error: std::io::Error) -> Diagnostic {
    Diagnostic::new(format!(
        "failed to execute '{}': {error}",
        program.display()
    ))
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new() -> Result<Self, Diagnostic> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = env::temp_dir().join(format!("obf-vm-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).map_err(|error| {
            Diagnostic::new(format!(
                "failed to create temporary directory '{}': {error}",
                path.display()
            ))
        })?;
        Ok(Self { path })
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
