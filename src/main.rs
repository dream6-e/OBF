#![allow(warnings)]

/*
 (c)KRYVEX Ob
 BY ssssss85
 Virtualization obfuscation
*/

use std::io::Write;
use std::process;
use std::thread;
use std::time::Instant;

use kryvex_ob::compiler::codegen;
use kryvex_ob::compiler::instructions;
use kryvex_ob::compiler::dump;
use kryvex_ob::BytecodeCompiler::virtualizer::deserializer::Deserializer;
use kryvex_ob::VM::VM_Backend::Context::VmContext;
use kryvex_ob::VM::VM_Backend::Serializer::Serializer;
use kryvex_ob::VM::VM_Backend::Generator::Generator;
use kryvex_ob::compressor::Compressor;
use kryvex_ob::VM::RadixSieve;
use kryvex_ob::packer;
use kryvex_ob::secure_io;

/// 命令行开关：`--key <口令>` / `--key-file <路径>` / 环境变量 `KRYVEX_KEY`。
fn resolve_passphrase(args: &[String]) -> Option<String> {
    if let Some(pos) = args.iter().position(|a| a == "--key") {
        return args.get(pos + 1).cloned();
    }
    if let Some(pos) = args.iter().position(|a| a == "--key-file") {
        if let Some(path) = args.get(pos + 1) {
            return std::fs::read_to_string(path)
                .ok()
                .map(|s| s.trim_end_matches(['\n', '\r']).to_string());
        }
    }
    std::env::var("KRYVEX_KEY").ok().filter(|s| !s.is_empty())
}

/// 读取输入：若文件是我们封存的容器则要求口令并解封，否则按普通文本读取。
fn load_source(path: &str, pass: Option<&str>) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("无法读取输入文件: {:?}", e))?;
    let plain = if secure_io::is_sealed(&bytes) {
        let pass = pass.ok_or_else(|| {
            "输入是封存文件，需要用 --key <口令>、--key-file <路径> 或环境变量 KRYVEX_KEY 提供口令".to_string()
        })?;
        secure_io::open_with_limit(&bytes, pass)?
    } else {
        bytes
    };
    String::from_utf8(plain).map_err(|_| "输入不是合法 UTF-8 文本".to_string())
}

/// `--seal <in.lua> [out]`：把源码封存成密文文件（默认写到 <in>.sealed）
fn run_seal(args: &[String]) -> i32 {
    let pos = match args.iter().position(|a| a == "--seal") {
        Some(p) => p,
        None => return -1,
    };
    let input = match args.get(pos + 1).filter(|a| !a.starts_with("--")) {
        Some(v) => v.clone(),
        None => {
            eprintln!("用法: kryvex-simple --seal <源码.lua> [输出.sealed] [--key <口令>]");
            return 1;
        }
    };
    let output = args
        .get(pos + 2)
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| format!("{}.sealed", input));
    let pass = match resolve_passphrase(args) {
        Some(p) => p,
        None => {
            eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 封存必须提供口令：--key <口令> / --key-file <路径> / 环境变量 KRYVEX_KEY");
            return 1;
        }
    };
    let plain = match std::fs::read(&input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 无法读取源码: {:?}", e);
            return 1;
        }
    };
    if secure_io::is_sealed(&plain) {
        eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 输入已经是封存文件，无需重复封存");
        return 1;
    }
    let sealed = secure_io::seal(&plain, &pass);
    if let Err(e) = std::fs::write(&output, &sealed) {
        eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 写出封存文件失败: {:?}", e);
        return 1;
    }
    println!(
        "\x1b[1;33mKRYVEX: \x1b[0m 已封存 \x1b[1m{}\x1b[0m → \x1b[1m{}\x1b[0m（{} B → {} B）",
        input,
        output,
        plain.len(),
        sealed.len()
    );
    0
}

/// `--open <in.sealed> [out.lua]`：解封回明文源码（默认去掉 .sealed 后缀）
fn run_open(args: &[String]) -> i32 {
    let pos = match args.iter().position(|a| a == "--open") {
        Some(p) => p,
        None => return -1,
    };
    let input = match args.get(pos + 1).filter(|a| !a.starts_with("--")) {
        Some(v) => v.clone(),
        None => {
            eprintln!("用法: kryvex-simple --open <源码.sealed> [输出.lua] [--key <口令>]");
            return 1;
        }
    };
    let output = args
        .get(pos + 2)
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| match input.strip_suffix(".sealed") {
            Some(base) => base.to_string(),
            None => format!("{}.lua", input),
        });
    let pass = match resolve_passphrase(args) {
        Some(p) => p,
        None => {
            eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 解封必须提供口令：--key <口令> / --key-file <路径> / 环境变量 KRYVEX_KEY");
            return 1;
        }
    };
    let bytes = match std::fs::read(&input) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 无法读取封存文件: {:?}", e);
            return 1;
        }
    };
    let explicit_out = args.get(pos + 2).filter(|a| !a.starts_with("--")).is_some();
    if !explicit_out && std::path::Path::new(&output).exists() {
        eprintln!(
            "\x1b[1;31mKRYVEX: \x1b[0m 默认输出 {} 已存在，避免覆盖源码——请显式指定输出路径",
            output
        );
        return 1;
    }
    match secure_io::open_with_limit(&bytes, &pass) {
        Ok(plain) => {
            if let Err(e) = std::fs::write(&output, &plain) {
                eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 写出源码失败: {:?}", e);
                return 1;
            }
            println!(
                "\x1b[1;33mKRYVEX: \x1b[0m 已解封 \x1b[1m{}\x1b[0m → \x1b[1m{}\x1b[0m（{} B）",
                input,
                output,
                plain.len()
            );
            0
        }
        Err(e) => {
            eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 解封失败：{}", e);
            1
        }
    }
}

fn main() {
    let start_time = Instant::now();
    let args: Vec<String> = std::env::args().collect();

    // 先拦截封存/解封子命令；未命中直接返回 -1 继续走混淆流程。
    for sub in [run_seal, run_open] {
        let code = sub(&args);
        if code >= 0 {
            std::process::exit(code);
        }
    }

    let source_code;
    let mut current_file = String::new();

    if args.len() >= 2 {
        let mut input_path = args[1].clone();
        
        if input_path == "-h" || input_path == "--help" {
            eprintln!("Usage: cargo run --release -- <input_file.lua>");
            return;
        }

        // 补后缀只在按原名找不到文件时进行（封存件是 .sealed，不能补成 .sealed.lua）
        if !input_path.ends_with(".lua") && !std::path::Path::new(&input_path).exists() {
            input_path.push_str(".lua");
        }
        current_file = input_path.clone();
        source_code = match load_source(&input_path, resolve_passphrase(&args).as_deref()) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("\x1b[1;31mKRYVEX: \x1b[0m {}", e);
                return;
            }
        };
    } else {
        let mut loop_source = String::new();
        print!("KRYVEX: obfuscation\n");
        loop {
            print!("\x1b[1;33m请输入目标文件: \x1b[0m");
            std::io::stdout().flush().unwrap();
            
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            
            let mut input_path = input.trim().to_string();
            if input_path.is_empty() {
                continue;
            }

            if !input_path.ends_with(".lua") && !std::path::Path::new(&input_path).exists() {
                input_path.push_str(".lua");
            }

            match load_source(&input_path, resolve_passphrase(&args).as_deref()) {
                Ok(content) => {
                    current_file = input_path;
                    loop_source = content;
                    break;
                }
                Err(_) => {
                    println!("\x1b[1;31m文件不存在或无法读取，请重新输入！\x1b[0m");
                }
            }
        }
        source_code = loop_source;
    }

    // 第 ⓪ 步：源码最小化（去注释 + 最少空白 + 单行化，纯词法级，非 LZ）。
    // 只删注释与可忽略空白，令牌序列逐字节不变 ⇒ 语义不变；自带重新分词自检，
    // 拿不准的输入原样放行。放在 --rob 拼接之前，Check.lua 不参与最小化。
    let raw_source = source_code.clone();
    let minified_source = kryvex_ob::minifier::minify_source(&source_code);

    // --rob：编译成字节码前，把 Roblox 执行器环境检测（samples/Check.lua）原样
    // 插到源码顶部——include_str! 逐字嵌入不改动一个字节，检测随源码一起进
    // 字节码被混淆；非执行器环境（无 getgenv 等）会在检测段 error(0,0) 死循环。
    let with_check = |body: &str| -> String {
        if args.contains(&"--rob".to_string()) {
            format!("{}\n{}", include_str!("../samples/Check.lua"), body)
        } else {
            body.to_string()
        }
    };
    let source_code = with_check(&minified_source);

    // 指令布局逐产物随机化（种子会写进容器头部，反序列化端据此恢复）
    instructions::randomize_global_seed();

    // 编译：先编最小化后的源码；若失败则用原始源码再编一次（用户真正写错语法时，
    // 报错仍取原始源码，行号才有意义；最小化若有意外也会在此处被兜住）。
    let chunk_name = format!("@{}", current_file);
    let compiled = match codegen::compile(source_code.as_bytes(), &chunk_name) {
        Ok(proto) => Ok(proto),
        Err(_) => match codegen::compile(with_check(&raw_source).as_bytes(), &chunk_name) {
            // 最小化版本编不过、原文能编：静默回退（并提示一句），用户无感。
            Ok(proto) => {
                eprintln!("\x1b[1;33mKRYVEX: \x1b[0m 最小化源码编译失败，已回退到原始源码");
                Ok(proto)
            }
            // 两边都编不过：报原始源码的错误——行号是用户真正能对上的那个。
            Err(original_err) => Err(original_err),
        },
    };

    match compiled {
        Ok(proto) => {
            let bytes = dump::dump(&proto, true);

            let _ = std::fs::create_dir_all("process");

            if let Ok(entries) = std::fs::read_dir("process") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let _ = std::fs::remove_file(path);
                    } else if path.is_dir() {
                        let _ = std::fs::remove_dir_all(path);
                    }
                }
            }
            
            let bytes_clone = bytes.clone();
            let h1 = thread::spawn(move || {
                let _ = std::fs::write("process/luac out.bin", bytes_clone);
            });

            let mut deserializer = Deserializer::new(bytes);
            let decoded_chunk = deserializer.decode_file();
            let vm_ctx = VmContext::new();
            
            let private_payload = Serializer::serialize(&decoded_chunk, &vm_ctx);
            
            let vm_generator = Generator::new(vm_ctx);
            let obfuscated_vm = vm_generator.build(&private_payload);

            let obfuscated_vm_clone = obfuscated_vm.clone();
            let h2 = thread::spawn(move || {
                let _ = std::fs::write("process/process1.lua", obfuscated_vm_clone);
            });
            let compressed_vm = match Compressor::compress(&obfuscated_vm) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("{}", e);
                    process::exit(1);
                }
            };

            let compressed_vm_clone = compressed_vm.clone();
            let h3 = thread::spawn(move || {
                let _ = std::fs::write("process/process2.lua", compressed_vm_clone);
            });

            let processed_vm = match RadixSieve::apply(&compressed_vm, None) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 数字转换失败: {}", e);
                    process::exit(1);
                }
            };
            let _ = std::fs::write("process/process3.lua", &processed_vm);

            let final_code = if args.contains(&"MB".to_string()) {
                // MB：新外壳自带解压器（DP/LZ + base85），不需要再过源码级压缩器；
                // 外壳里的负载已经是压缩态，再解析一遍只会白花时间。
                // ⑳ MB：载荷头部补同一注释行，使解压后 VM 逻辑与默认模式同为第 2 行（行守卫期望一致）
                packer::pack_lua(&format!("--Kryvex v2.2\n{}", processed_vm))
            } else {
                format!(
    "--Kryvex v2.2,by 1%@\n{}",
    processed_vm
)
            };

            let mut file = match std::fs::File::create("obfuscated.lua") {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 无法创建最终文件: {:?}", e);
                    return;
                }
            };
            if let Err(e) = file.write_all(final_code.as_bytes()) {
                eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 写入最终文件失败: {:?}", e);
                return;
            }

            let _ = h1.join();
            let _ = h2.join();
            let _ = h3.join();
            println!("\x1b[1;33mKRYVEX: \x1b[0m 混淆已保存至 \x1b[1m\x1b[4mobfuscated.lua\x1b[0m");
            println!("\x1b[1;33mKRYVEX: \x1b[0m {:?}", start_time.elapsed());
        },
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    }
}