// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use tempfile::tempdir;
use wasm_encoder::{
    EntityType, ImportSection, MemoryType, Module, RawSection,
};
use wasmparser::{Import, Parser, Payload::*, SectionLimited, TypeRef};

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
        CString::new("--initial-memory=131072").unwrap(), // 2 pages = 128 KiB
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

    // Post-process: remap imports to "env" module (Antelope convention)
    remap_imports(&output)
}

/// Remap all WASM imports to use "env" as the module name,
/// which is what the Antelope WASM runtime expects.
fn remap_imports(input: &[u8]) -> Vec<u8> {
    let mut module = Module::new();
    for payload in Parser::new(0).parse_all(input).map(|s| s.unwrap()) {
        match payload {
            ImportSection(s) => generate_import_section(s, &mut module),
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
