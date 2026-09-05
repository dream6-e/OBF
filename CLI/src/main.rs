#![allow(warnings)]

///cargo run -p kryvex_cli

use std::io::{stdout, Write};
use std::time::Instant;
use std::thread;
use std::process;
use crossterm::{
    cursor::{Hide, Show, MoveTo},
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{self, Clear, ClearType},
};

mod three_d;
use three_d::Coin3D;

use kryvex_ob::compiler::codegen;
use kryvex_ob::compiler::dump;
use kryvex_ob::BytecodeCompiler::virtualizer::deserializer::Deserializer;
use kryvex_ob::VM::VM_Backend::Context::VmContext;
use kryvex_ob::VM::VM_Backend::Serializer::Serializer;
use kryvex_ob::VM::VM_Backend::Generator::Generator;
use kryvex_ob::compressor::Compressor;
use kryvex_ob::VM::RadixSieve;
use kryvex_ob::packer;

enum AppState {
    FileSelect,
    OptionSelect { selected_file: String },
}

struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Self {
        let _ = terminal::enable_raw_mode();
        let mut out = stdout();
        let _ = execute!(out, Hide, Clear(ClearType::All));
        RawModeGuard
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let mut out = stdout();
        let _ = execute!(out, Show, Clear(ClearType::All), MoveTo(0, 0));
    }
}

fn main() {
    let mut lua_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(".") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "lua" {
                        if let Some(file_name) = path.file_name() {
                            let name = file_name.to_string_lossy().into_owned();
                            if name != "obfuscated.lua" {
                                lua_files.push(name);
                            }
                        }
                    }
                }
            }
        }
    }
    lua_files.sort();

    let _guard = RawModeGuard::new();

    let coin = Coin3D::new();

    let mut angle_x = 0.0f32;
    let mut angle_y = 0.0f32;
    let mut angle_z = 0.0f32;

    let width = 68;
    let height = 16;

    let mut state = AppState::FileSelect;
    let mut selected_file_idx = 0;
    let mut selected_option_idx = 0;

    let mut run_compilation = false;
    let mut target_file_name = String::new();
    let mut enable_packer = false;

    loop {
        let coin_frame = coin.render_frame(angle_x, angle_y, angle_z, width, height);

        let mut frame_data = String::new();
        frame_data.push_str("\x1b[H");

        frame_data.push_str(&coin_frame);
        frame_data.push_str("\x1b[K\r\n");

        match &state {
            AppState::FileSelect => {
                frame_data.push_str("  \x1b[1m[+] Select target Lua file to obfuscate:\x1b[0m\x1b[K\r\n\x1b[K\r\n");
                if lua_files.is_empty() {
                    frame_data.push_str("    \x1b[1;31mNo .lua files found in current directory!\x1b[0m\x1b[K\r\n");
                    frame_data.push_str("    Please place .lua files in this folder and restart.\x1b[K\r\n\x1b[K\r\n");
                } else {
                    for (i, name) in lua_files.iter().enumerate() {
                        if i == selected_file_idx {
                            frame_data.push_str(&format!("    \x1b[1;36m> {}\x1b[0m\x1b[K\r\n", name));
                        } else {
                            frame_data.push_str(&format!("      {}\x1b[K\r\n", name));
                        }
                    }
                    frame_data.push_str("\x1b[K\r\n");
                }
            }
            AppState::OptionSelect { selected_file } => {
                frame_data.push_str(&format!("  \x1b[1m[+] Target File:\x1b[0m \x1b[1;32m{}\x1b[0m\x1b[K\r\n\x1b[K\r\n", selected_file));
                frame_data.push_str("  \x1b[1m[+] Select Obfuscation Option:\x1b[0m\x1b[K\r\n\x1b[K\r\n");

                let options = [
                    "1. 开启压缩壳 (Enable Packer) [MB mode]",
                    "2. 不开启压缩壳 (Standard Obfuscation)",
                ];

                for (i, opt) in options.iter().enumerate() {
                    if i == selected_option_idx {
                        frame_data.push_str(&format!("    \x1b[1;36m> {}\x1b[0m\x1b[K\r\n", opt));
                    } else {
                        frame_data.push_str(&format!("      {}\x1b[K\r\n", opt));
                    }
                }
                frame_data.push_str("\x1b[K\r\n");
            }
        }

        frame_data.push_str("  Press Enter to Select | Esc to Exit\x1b[K\r\n");
        frame_data.push_str("\x1b[J");

        print!("{}", frame_data);
        let _ = stdout().flush();

        angle_x += 0.015;
        angle_y += 0.035;
        angle_z += 0.010;

        if event::poll(std::time::Duration::from_millis(30)).unwrap_or(false) {
            if let Event::Key(key_event) = event::read().unwrap() {
                if key_event.kind != KeyEventKind::Release {
                    match key_event.code {
                        KeyCode::Up => {
                            match &state {
                                AppState::FileSelect => {
                                    if !lua_files.is_empty() {
                                        if selected_file_idx > 0 {
                                            selected_file_idx -= 1;
                                        } else {
                                            selected_file_idx = lua_files.len() - 1;
                                        }
                                    }
                                }
                                AppState::OptionSelect { .. } => {
                                    if selected_option_idx > 0 {
                                        selected_option_idx -= 1;
                                    } else {
                                        selected_option_idx = 1;
                                    }
                                }
                            }
                        }
                        KeyCode::Down => {
                            match &state {
                                AppState::FileSelect => {
                                    if !lua_files.is_empty() {
                                        if selected_file_idx < lua_files.len() - 1 {
                                            selected_file_idx += 1;
                                        } else {
                                            selected_file_idx = 0;
                                        }
                                    }
                                }
                                AppState::OptionSelect { .. } => {
                                    if selected_option_idx < 1 {
                                        selected_option_idx += 1;
                                    } else {
                                        selected_option_idx = 0;
                                    }
                                }
                            }
                        }
                        KeyCode::Enter => {
                            match &state {
                                AppState::FileSelect => {
                                    if !lua_files.is_empty() {
                                        let selected_file = lua_files[selected_file_idx].clone();
                                        state = AppState::OptionSelect { selected_file };
                                    }
                                }
                                AppState::OptionSelect { selected_file } => {
                                    target_file_name = selected_file.clone();
                                    enable_packer = selected_option_idx == 0;
                                    run_compilation = true;
                                    break;
                                }
                            }
                        }
                        KeyCode::Esc => {
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    if run_compilation {
        let _ = terminal::disable_raw_mode();
        let mut out = stdout();
        let _ = execute!(out, Show, Clear(ClearType::All), MoveTo(0, 0));

        let start_time = Instant::now();
        println!("KRYVEX: Starting obfuscation on {}...", target_file_name);

        let source_code = match std::fs::read_to_string(&target_file_name) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("\x1b[1;31mKRYVEX: \x1b[0m 无法读取文件: {:?}", e);
                return;
            }
        };

        match codegen::compile(source_code.as_bytes(), &format!("@{}", target_file_name)) {
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

                let final_code = if enable_packer {
                    let packed_vm = packer::pack_lua(&processed_vm);
                    let compressed_packed_vm = match Compressor::compress(&packed_vm) {
                        Ok(code) => code,
                        Err(e) => {
                            eprintln!("{}", e);
                            process::exit(1);
                        }
                    };
                    format!(
                        "--This file was protected using Kryvex Obfuscated v1\n\n{}",
                        compressed_packed_vm
                    )
                } else {
                    format!(
                        "--This file was protected using Kryvex Obfuscated v1\n\n{}",
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
            }
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        }
    }
}