// SPDX-License-Identifier: Apache-2.0

use crate::sema::ast::{Namespace, Type};
use serde::Serialize;
use solang_parser::pt::FunctionTy;

#[derive(Serialize)]
pub struct AntelopeAbi {
    pub version: String,
    pub types: Vec<serde_json::Value>,
    pub structs: Vec<AbiStruct>,
    pub actions: Vec<AbiAction>,
    pub tables: Vec<AbiTable>,
}

#[derive(Serialize)]
pub struct AbiStruct {
    pub name: String,
    pub base: String,
    pub fields: Vec<AbiField>,
}

#[derive(Serialize)]
pub struct AbiField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Serialize)]
pub struct AbiAction {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub ricardian_contract: String,
}

#[derive(Serialize)]
pub struct AbiTable {
    pub name: String,
    pub index_type: String,
    pub key_names: Vec<String>,
    pub key_types: Vec<String>,
    #[serde(rename = "type")]
    pub ty: String,
}

fn solidity_type_to_antelope(ty: &Type, ns: &Namespace) -> String {
    match ty {
        Type::Uint(8) => "uint8".to_string(),
        Type::Uint(16) => "uint16".to_string(),
        Type::Uint(32) => "uint32".to_string(),
        Type::Uint(64) => "uint64".to_string(),
        Type::Uint(128) => "uint128".to_string(),
        Type::Uint(256) => "checksum256".to_string(),
        Type::Int(8) => "int8".to_string(),
        Type::Int(16) => "int16".to_string(),
        Type::Int(32) => "int32".to_string(),
        Type::Int(64) => "int64".to_string(),
        Type::Int(128) => "int128".to_string(),
        Type::Bool => "bool".to_string(),
        Type::String => "string".to_string(),
        Type::Address(_) => "uint64".to_string(),
        _ => "bytes".to_string(),
    }
}

/// Generate Antelope ABI for a contract.
pub fn gen_abi(contract_no: usize, ns: &Namespace) -> AntelopeAbi {
    let contract = &ns.contracts[contract_no];
    let mut structs = Vec::new();
    let mut actions = Vec::new();

    // For each public function, create a struct (for action params) and an action entry.
    for func_no in contract.all_functions.keys() {
        let func = &ns.functions[*func_no];

        if !func.is_public() {
            continue;
        }
        if func.ty == FunctionTy::Constructor {
            continue;
        }

        let func_name = &func.id.name;

        // Antelope action names are max 12 chars, lowercase + 1-5 + dot.
        let action_name = func_name
            .chars()
            .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '.')
            .take(12)
            .collect::<String>();

        if action_name.is_empty() {
            continue;
        }

        // Build the struct fields from function parameters.
        let fields: Vec<AbiField> = func
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| AbiField {
                name: p
                    .id
                    .as_ref()
                    .map(|id| id.name.clone())
                    .unwrap_or_else(|| format!("arg{i}")),
                ty: solidity_type_to_antelope(&p.ty, ns),
            })
            .collect();

        structs.push(AbiStruct {
            name: action_name.clone(),
            base: String::new(),
            fields,
        });

        actions.push(AbiAction {
            name: action_name.clone(),
            ty: action_name,
            ricardian_contract: String::new(),
        });
    }

    // Add the "state" table entry so explorers can decode storage.
    // Our storage model: table "state" with rows (key: uint64, value: bytes).
    // For the POC, we describe the row as having a uint64 key and uint64 value.
    let has_state_vars = !contract.variables.iter().all(|v| v.constant);
    let mut tables = Vec::new();

    if has_state_vars {
        structs.push(AbiStruct {
            name: "state.row".to_string(),
            base: String::new(),
            fields: vec![
                AbiField {
                    name: "key".to_string(),
                    ty: "uint64".to_string(),
                },
                AbiField {
                    name: "value".to_string(),
                    ty: "uint64".to_string(),
                },
            ],
        });

        tables.push(AbiTable {
            name: "state".to_string(),
            index_type: "i64".to_string(),
            key_names: vec!["key".to_string()],
            key_types: vec!["uint64".to_string()],
            ty: "state.row".to_string(),
        });
    }

    AntelopeAbi {
        version: "eosio::abi/1.2".to_string(),
        types: Vec::new(),
        structs,
        actions,
        tables,
    }
}
