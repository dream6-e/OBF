use obf::Target;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_WORKSPACE: AtomicU64 = AtomicU64::new(0);

pub struct Workspace(pub PathBuf);

impl Workspace {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "obf-tests-{}-{}",
            std::process::id(),
            NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

pub fn success(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub fn compile(target: Target, path: &Path) -> Output {
    let compiler = match target {
        Target::Lua51 => "luac5.1",
        Target::Luau => "luau-compile",
    };
    let mut compiler = Command::new(root().join("toolchains/bin").join(compiler));
    if target == Target::Lua51 {
        compiler.arg("-p");
    }
    compiler.arg(path).output().unwrap()
}

pub fn compile_and_run(target: Target, path: &Path) -> Vec<u8> {
    let compiled = compile(target, path);
    assert!(
        compiled.status.success(),
        "{target} compilation failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let runtime = if target == Target::Lua51 {
        "lua5.1"
    } else {
        "luau"
    };
    success(Command::new(root().join("toolchains/bin").join(runtime)).arg(path)).stdout
}
