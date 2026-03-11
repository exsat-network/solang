// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use tempfile::tempdir;
use wasm_encoder::{
    ConstExpr, EntityType, GlobalSection, GlobalType, ImportSection, MemoryType, Module,
    RawSection, ValType,
};
use wasmparser::{Global, Import, Parser, Payload::*, SectionLimited, TypeRef};

/// Link an Antelope WASM object file into a final .wasm binary.
///
/// Antelope WASM requirements:
/// - Must export `apply(uint64, uint64, uint64)` entry point
/// - All host function imports come from the "env" module
/// - Memory is imported from "env" "memory" (not exported)
pub fn link(input: &[u8], name: &str) -> Vec<u8> {
    let dir = tempdir().expect("failed to create temp directory for linking");

    let object_filename = dir.path().join(format!("{name}.o"));
    let res_filename = dir.path().join(format!("{name}.wasm"));

    let mut objectfile =
        File::create(object_filename.clone()).expect("failed to create object file");

    objectfile
        .write_all(input)
        .expect("failed to write object file to temp file");

    let mut command_line = vec![
        CString::new("--no-entry").unwrap(),
        CString::new("--allow-undefined").unwrap(),
        CString::new("--gc-sections").unwrap(),
        CString::new("--global-base=0").unwrap(),
        CString::new("--initial-memory=1048576").unwrap(), // 1 MiB — heap at 0x10000, stack at top
        CString::new("--export-dynamic").unwrap(),
    ];

    command_line.push(
        CString::new(
            object_filename
                .to_str()
                .expect("temp path should be unicode"),
        )
        .unwrap(),
    );
    command_line.push(CString::new("-o").unwrap());
    command_line
        .push(CString::new(res_filename.to_str().expect("temp path should be unicode")).unwrap());

    assert!(!super::wasm_linker(&command_line), "linker failed");

    let mut output = Vec::new();
    let mut outputfile = File::open(res_filename).expect("output file should exist");
    outputfile
        .read_to_end(&mut output)
        .expect("failed to read output file");

    // Post-process: remap imports to "env" module, set stack pointer global
    generate_module(&output)
}

/// Post-process the linked WASM: remap imports to "env" module and set stack pointer.
fn generate_module(input: &[u8]) -> Vec<u8> {
    let mut module = Module::new();
    for payload in Parser::new(0).parse_all(input).map(|s| s.unwrap()) {
        match payload {
            ImportSection(s) => generate_import_section(s, &mut module),
            GlobalSection(s) => generate_global_section(s, &mut module),
            ModuleSection { .. } | ComponentSection { .. } => panic!("nested WASM module"),
            _ => {
                if let Some((id, range)) = payload.as_section() {
                    module.section(&RawSection {
                        id,
                        data: &input[range],
                    });
                }
            }
        }
    }
    module.finish()
}

/// Rewrite all imports to use "env" module.
fn generate_import_section(section: SectionLimited<Import>, module: &mut Module) {
    let mut imports = ImportSection::new();
    for import in section.into_iter().map(|import| import.unwrap()) {
        let import_type = match import.ty {
            TypeRef::Func(n) => EntityType::Function(n),
            TypeRef::Memory(m) => EntityType::Memory(MemoryType {
                maximum: m.maximum,
                minimum: m.initial,
                memory64: m.memory64,
                shared: m.shared,
            }),
            _ => panic!("unexpected WASM import type {import:?}"),
        };

        // All Antelope host functions live in the "env" module.
        imports.import("env", import.name, import_type);
    }
    module.section(&imports);
}

/// Set the stack pointer global to top of memory (1 MiB).
/// Stack grows downward from 1 MiB; heap grows upward from 0x10000.
fn generate_global_section(_section: SectionLimited<Global>, module: &mut Module) {
    let mut globals = GlobalSection::new();
    let global_type = GlobalType {
        val_type: ValType::I32,
        mutable: true,
    };
    // Stack pointer at top of 1 MiB initial memory
    globals.global(global_type, &ConstExpr::i32_const(1048576));
    module.section(&globals);
}
