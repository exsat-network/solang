// SPDX-License-Identifier: Apache-2.0

use crate::sema::ast::{Namespace, Type};
use num_traits::ToPrimitive;
use serde::Serialize;
use solang_parser::pt::FunctionTy;

/// Normalize a Solidity identifier into a valid eosio::name-compatible action name.
///
/// eosio::name only admits the charset `.`, `1`-`5`, `a`-`z` and at most 13 chars
/// (12 used here for the 5-bit region). We therefore:
///   1. lowercase first — eosio::name has no uppercase, so `putHash` must become
///      `puthash`, NOT `putash` (dropping the uppercase byte silently mangles the
///      name and can collide two functions);
///   2. keep only the eosio charset — digits `0` and `6`-`9` are NOT valid
///      eosio::name characters, so `putu8` normalizes to `putu`, matching what
///      nodeos itself would do at `set abi` time;
///   3. truncate to 12 characters.
///
/// This is the single authority for action-name derivation: the ABI's
/// `actions[].name` (here) and the emitter's dispatch switch (`emit_apply`) must
/// agree exactly, or dispatch silently fails to route. Event names follow the
/// same charset in `codegen/events/antelope.rs`. Lives in the always-compiled
/// `abi` module so `sema` can reach it without depending on the llvm-gated `emit`.
pub fn normalize_action_name(name: &str) -> String {
    name.chars()
        .flat_map(char::to_lowercase)
        .filter(|c| c.is_ascii_lowercase() || matches!(c, '1'..='5') || *c == '.')
        .take(12)
        .collect()
}

/// Type id used in `abi_extensions` to mark a Solang storage-layout blob.
/// ASCII for 'S','L' (Solang). The payload is UTF-8 JSON; see [`AntelopeLayout`].
pub const SOLANG_LAYOUT_EXT_TYPE: u16 = 0x534C;

/// Schema version for the layout JSON.
pub const SOLANG_LAYOUT_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct AntelopeAbi {
    pub version: String,
    pub types: Vec<serde_json::Value>,
    pub structs: Vec<AbiStruct>,
    pub actions: Vec<AbiAction>,
    pub tables: Vec<AbiTable>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub abi_extensions: Vec<AbiExtension>,
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

/// One entry of the standard `abi_extensions: pair<uint16, bytes>[]` array.
/// `data` is the hex-encoded payload (the standard wire form for the `bytes` field).
///
/// fc's `extensions_type` is `vector<pair<uint16_t, vector<char>>>`, whose JSON
/// representation is a 2-element tuple `[type, dataHex]` — NOT an object
/// `{"type":…,"data":…}`. nodeos/fc cannot parse the object form and rejects
/// `cleos set abi` with "Bad Cast: Invalid cast from object_type to Array", so we
/// serialize as a tuple. (The struct keeps named fields for ergonomic construction
/// and testing; only the wire form is a tuple.)
pub struct AbiExtension {
    pub ty: u16,
    pub data: String,
}

impl Serialize for AbiExtension {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut tup = serializer.serialize_tuple(2)?;
        tup.serialize_element(&self.ty)?;
        tup.serialize_element(&self.data)?;
        tup.end()
    }
}

/// Solang-private storage layout descriptor, packed into `abi_extensions`.
/// Documents the slot/type of every state variable so clients can derive
/// idx256 keys and decode raw row bytes without re-reading the source.
///
/// JSON shape:
/// ```json
/// {
///   "version": 1,
///   "state_table": "state",
///   "vars": [
///     { "name": "owner", "slot": 0, "kind": "plain", "type": "uint64" },
///     { "name": "balances", "slot": 2, "kind": "map", "keys": ["uint64"], "type": "uint256" },
///     { "name": "users", "slot": 4, "kind": "map", "keys": ["uint64"],
///       "type": { "kind": "struct", "fields": [
///         { "name": "balance", "type": "uint64" },
///         { "name": "score",   "type": "uint64" }
///       ]}
///     }
///   ]
/// }
/// ```
#[derive(Serialize)]
pub struct AntelopeLayout {
    pub version: u32,
    pub state_table: String,
    pub vars: Vec<LayoutVar>,
}

#[derive(Serialize)]
pub struct LayoutVar {
    pub name: String,
    pub slot: u64,
    /// One of: "plain", "map", "unsupported". Arrays/dynamic-length compound
    /// values are emitted as `"unsupported"` for now — readers must skip them.
    pub kind: String,
    /// Only present when `kind == "map"`. Lists the chain of key types,
    /// outermost first. Nested mappings produce multiple entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub ty: LayoutType,
}

/// Value type. Strings denote primitives ("uint64", "address", "string", ...).
/// Objects describe compound shapes (struct, array, unsupported).
#[derive(Serialize)]
#[serde(untagged)]
pub enum LayoutType {
    Primitive(String),
    Compound(LayoutCompound),
}

#[derive(Serialize)]
#[serde(tag = "kind")]
pub enum LayoutCompound {
    #[serde(rename = "struct")]
    Struct { fields: Vec<LayoutField> },
    #[serde(rename = "array")]
    Array { element: Box<LayoutType> },
    #[serde(rename = "unsupported")]
    Unsupported { reason: String },
}

#[derive(Serialize)]
pub struct LayoutField {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: LayoutType,
}

fn solidity_type_to_antelope(ty: &Type, _ns: &Namespace) -> String {
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
        // A 32-byte value (e.g. a sha256/keccak hash) is a fixed 32 raw bytes with
        // no length prefix — that is exactly `checksum256`. Mapping it to `bytes`
        // (which carries a varuint32 length prefix) would misalign action data.
        Type::Bytes(32) => "checksum256".to_string(),
        Type::Address(_) => "uint64".to_string(),
        _ => "bytes".to_string(),
    }
}

/// Render a Solang `Type` as the layout-JSON primitive name.
/// Mirrors Solidity's own type names rather than the ABI's Antelope renaming
/// (e.g. `address`, not `uint64`) because the reader does its own type-aware
/// decoding from the raw row bytes.
fn primitive_name(ty: &Type) -> Option<String> {
    Some(match ty {
        Type::Bool => "bool".to_string(),
        Type::Uint(w) => format!("uint{w}"),
        Type::Int(w) => format!("int{w}"),
        Type::Address(_) => "address".to_string(),
        Type::String => "string".to_string(),
        Type::DynamicBytes => "bytes".to_string(),
        Type::Bytes(n) => format!("bytes{n}"),
        _ => return None,
    })
}

fn type_to_layout(ty: &Type, ns: &Namespace) -> LayoutType {
    if let Some(p) = primitive_name(ty) {
        return LayoutType::Primitive(p);
    }
    match ty {
        Type::Struct(st) => {
            let decl = st.definition(ns);
            let fields = decl
                .fields
                .iter()
                .map(|f| LayoutField {
                    name: f.id.as_ref().map(|i| i.name.clone()).unwrap_or_default(),
                    ty: type_to_layout(&f.ty, ns),
                })
                .collect();
            LayoutType::Compound(LayoutCompound::Struct { fields })
        }
        Type::Enum(_) => LayoutType::Primitive("uint8".to_string()),
        Type::Array(elem, _) => LayoutType::Compound(LayoutCompound::Array {
            element: Box::new(type_to_layout(elem, ns)),
        }),
        // Mappings appear as the value of a map only when nested — handled by
        // `extract_map_keys`. Any other case is something the reader can't decode.
        other => LayoutType::Compound(LayoutCompound::Unsupported {
            reason: format!("{other:?}"),
        }),
    }
}

/// Walk through nested `Mapping` types, collecting key type names and returning
/// the innermost value type. Returns (keys, value_ty). If `ty` is not a mapping,
/// returns an empty key vec and `ty` unchanged.
fn extract_map_keys<'a>(ty: &'a Type) -> (Vec<String>, &'a Type) {
    let mut keys = Vec::new();
    let mut cur = ty;
    while let Type::Mapping(m) = cur {
        keys.push(primitive_name(&m.key).unwrap_or_else(|| "bytes".to_string()));
        cur = &m.value;
    }
    (keys, cur)
}

/// Build the storage-layout descriptor for a contract.
pub fn gen_layout(contract_no: usize, ns: &Namespace) -> AntelopeLayout {
    let contract = &ns.contracts[contract_no];
    let mut vars = Vec::new();

    for entry in &contract.layout {
        // Solang's slot allocator hands out small dense indices; if a contract ever
        // declares enough variables to overflow u64, drop the entry — the reader
        // would not be able to encode it as a varuint anyway.
        let slot = match entry.slot.to_u64() {
            Some(s) => s,
            None => continue,
        };

        let base_var = &ns.contracts[entry.contract_no].variables[entry.var_no];
        let (keys, value_ty) = extract_map_keys(&entry.ty);
        let value_layout = type_to_layout(value_ty, ns);

        let kind = if keys.is_empty() {
            "plain"
        } else {
            "map"
        }
        .to_string();

        vars.push(LayoutVar {
            name: base_var.name.clone(),
            slot,
            kind,
            keys: if keys.is_empty() { None } else { Some(keys) },
            ty: value_layout,
        });
    }

    AntelopeLayout {
        version: SOLANG_LAYOUT_VERSION,
        state_table: "state".to_string(),
        vars,
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
        // Shared normalizer keeps this identical to the emitter's dispatch switch.
        let action_name = normalize_action_name(func_name);

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
    // Storage model: auto-increment primary key, idx256 secondary index for slot lookup.
    // Row data = raw value bytes (variable length: uint64, uint256, strings, etc.).
    let has_state_vars = !contract.variables.iter().all(|v| v.constant);
    let mut tables = Vec::new();

    if has_state_vars {
        structs.push(AbiStruct {
            name: "state.row".to_string(),
            base: String::new(),
            fields: vec![
                AbiField {
                    name: "id".to_string(),
                    ty: "uint64".to_string(),
                },
                AbiField {
                    name: "key".to_string(),
                    ty: "checksum256".to_string(),
                },
                AbiField {
                    name: "value".to_string(),
                    ty: "bytes".to_string(),
                },
            ],
        });

        tables.push(AbiTable {
            name: "state".to_string(),
            index_type: "i64".to_string(),
            key_names: vec![],
            key_types: vec![],
            ty: "state.row".to_string(),
        });
    }

    // Emit the storage-layout descriptor inside abi_extensions so it survives
    // the on-chain `setabi` round-trip. Only emit when there's something to say.
    let mut abi_extensions = Vec::new();
    if has_state_vars {
        let layout = gen_layout(contract_no, ns);
        if !layout.vars.is_empty() {
            let json = serde_json::to_vec(&layout)
                .expect("AntelopeLayout always serializes to JSON");
            abi_extensions.push(AbiExtension {
                ty: SOLANG_LAYOUT_EXT_TYPE,
                data: hex::encode(json),
            });
        }
    }

    AntelopeAbi {
        version: "eosio::abi/1.2".to_string(),
        types: Vec::new(),
        structs,
        actions,
        tables,
        abi_extensions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::{codegen, Options};
    use crate::file_resolver::FileResolver;
    use crate::{parse_and_resolve, Target};
    use std::ffi::OsStr;

    fn build_ns(src: &str) -> (crate::sema::ast::Namespace, usize) {
        let mut resolver = FileResolver::default();
        resolver.set_file_contents("test.sol", src.to_string());
        let mut ns = parse_and_resolve(OsStr::new("test.sol"), &mut resolver, Target::Antelope);
        assert!(
            !ns.diagnostics.any_errors(),
            "sema reported errors compiling test contract"
        );
        // Codegen populates `contract.layout` — required for gen_layout.
        codegen(&mut ns, &Options::default());
        assert!(!ns.contracts.is_empty(), "no contracts compiled");
        // The deepest derived contract is the last one — its layout reflects inheritance.
        let contract_no = ns.contracts.len() - 1;
        (ns, contract_no)
    }

    fn compile_to_layout(src: &str) -> AntelopeLayout {
        let (ns, contract_no) = build_ns(src);
        gen_layout(contract_no, &ns)
    }

    fn compile_to_abi(src: &str) -> AntelopeAbi {
        let (ns, contract_no) = build_ns(src);
        gen_abi(contract_no, &ns)
    }

    #[test]
    fn layout_plain_vars_get_dense_slots_and_primitive_types() {
        let layout = compile_to_layout(
            r#"
            contract C {
                uint64 a;
                uint256 b;
                bool c;
                address d;
                string e;
            }
            "#,
        );

        assert_eq!(layout.version, SOLANG_LAYOUT_VERSION);
        assert_eq!(layout.state_table, "state");

        let names: Vec<&str> = layout.vars.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c", "d", "e"]);

        // Slot 0 is always the first declared variable.
        assert_eq!(layout.vars[0].slot, 0);
        // Plain variables always have kind="plain" and no `keys` entry.
        for v in &layout.vars {
            assert_eq!(v.kind, "plain");
            assert!(v.keys.is_none());
        }

        // Primitive types are serialized as bare strings.
        let types: Vec<String> = layout
            .vars
            .iter()
            .map(|v| match &v.ty {
                LayoutType::Primitive(s) => s.clone(),
                _ => panic!("expected primitive"),
            })
            .collect();
        assert_eq!(types, vec!["uint64", "uint256", "bool", "address", "string"]);
    }

    #[test]
    fn layout_mapping_captures_key_chain() {
        let layout = compile_to_layout(
            r#"
            contract C {
                mapping(uint64 => uint256) balances;
                mapping(uint64 => mapping(uint64 => uint256)) allowed;
            }
            "#,
        );

        assert_eq!(layout.vars.len(), 2);

        let bal = &layout.vars[0];
        assert_eq!(bal.name, "balances");
        assert_eq!(bal.kind, "map");
        assert_eq!(bal.keys.as_deref(), Some(&["uint64".to_string()][..]));
        match &bal.ty {
            LayoutType::Primitive(s) => assert_eq!(s, "uint256"),
            _ => panic!("expected primitive uint256"),
        }

        let allowed = &layout.vars[1];
        assert_eq!(allowed.name, "allowed");
        assert_eq!(allowed.kind, "map");
        assert_eq!(
            allowed.keys.as_deref(),
            Some(&["uint64".to_string(), "uint64".to_string()][..])
        );
    }

    #[test]
    fn layout_mapping_to_struct_expands_fields() {
        let layout = compile_to_layout(
            r#"
            contract C {
                struct User { uint64 balance; uint64 score; }
                mapping(uint64 => User) users;
            }
            "#,
        );

        assert_eq!(layout.vars.len(), 1);
        let users = &layout.vars[0];
        assert_eq!(users.name, "users");
        assert_eq!(users.kind, "map");

        match &users.ty {
            LayoutType::Compound(LayoutCompound::Struct { fields }) => {
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].name, "balance");
                assert_eq!(fields[1].name, "score");
                match (&fields[0].ty, &fields[1].ty) {
                    (LayoutType::Primitive(a), LayoutType::Primitive(b)) => {
                        assert_eq!(a, "uint64");
                        assert_eq!(b, "uint64");
                    }
                    _ => panic!("expected primitive fields"),
                }
            }
            _ => panic!("expected struct value"),
        }
    }

    #[test]
    fn layout_enum_serializes_as_uint8() {
        let layout = compile_to_layout(
            r#"
            contract C {
                enum Status { Open, Closed, Frozen }
                Status s;
            }
            "#,
        );
        assert_eq!(layout.vars.len(), 1);
        match &layout.vars[0].ty {
            LayoutType::Primitive(s) => assert_eq!(s, "uint8"),
            _ => panic!("expected primitive"),
        }
    }

    #[test]
    fn layout_dynamic_array_marked_array() {
        let layout = compile_to_layout(
            r#"
            contract C {
                uint64[] xs;
            }
            "#,
        );
        assert_eq!(layout.vars.len(), 1);
        match &layout.vars[0].ty {
            LayoutType::Compound(LayoutCompound::Array { element }) => match element.as_ref() {
                LayoutType::Primitive(s) => assert_eq!(s, "uint64"),
                _ => panic!("expected primitive element"),
            },
            _ => panic!("expected array"),
        }
    }

    #[test]
    fn layout_inherited_vars_get_correct_slots() {
        // Both base + derived variables should appear, in declaration order.
        let layout = compile_to_layout(
            r#"
            contract Base { uint64 baseVar; }
            contract Child is Base { uint64 childVar; }
            "#,
        );
        let names: Vec<&str> = layout.vars.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["baseVar", "childVar"]);
        assert_eq!(layout.vars[0].slot, 0);
        // baseVar takes one slot, so childVar starts at slot 1.
        assert_eq!(layout.vars[1].slot, 1);
    }

    #[test]
    fn layout_constants_are_excluded() {
        let layout = compile_to_layout(
            r#"
            contract C {
                uint64 constant K = 42;
                uint64 v;
            }
            "#,
        );
        // The constant must not appear; only `v` is stored.
        assert_eq!(layout.vars.len(), 1);
        assert_eq!(layout.vars[0].name, "v");
        assert_eq!(layout.vars[0].slot, 0);
    }

    #[test]
    fn abi_includes_layout_in_abi_extensions() {
        let abi = compile_to_abi(
            r#"
            contract C {
                uint64 owner;
                mapping(uint64 => uint256) balances;
            }
            "#,
        );

        assert_eq!(abi.abi_extensions.len(), 1);
        let ext = &abi.abi_extensions[0];
        assert_eq!(ext.ty, SOLANG_LAYOUT_EXT_TYPE);

        // C5: the wire form must be a 2-element tuple `[type, dataHex]`, not an
        // object `{"type":…,"data":…}` — fc's extensions_type is
        // vector<pair<uint16,bytes>> and nodeos rejects the object form.
        let wire: serde_json::Value =
            serde_json::to_value(&abi.abi_extensions).expect("abi_extensions serializes");
        let entry = &wire[0];
        assert!(
            entry.is_array(),
            "abi_extensions entry must be a tuple array, got: {entry}"
        );
        assert_eq!(entry[0], SOLANG_LAYOUT_EXT_TYPE);
        assert_eq!(entry[1], serde_json::Value::String(ext.data.clone()));

        // Decode and re-parse the layout JSON to verify the on-chain round-trip.
        // Use serde_json::Value so we don't have to add Deserialize impls just for the test.
        let bytes = hex::decode(&ext.data).expect("data must be hex");
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("data must be valid layout JSON");

        assert_eq!(parsed["version"], SOLANG_LAYOUT_VERSION);
        assert_eq!(parsed["state_table"], "state");
        let vars = parsed["vars"].as_array().expect("vars must be an array");
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0]["name"], "owner");
        assert_eq!(vars[1]["name"], "balances");
        assert_eq!(vars[1]["kind"], "map");
        assert_eq!(vars[1]["keys"][0], "uint64");
        assert_eq!(vars[1]["type"], "uint256");
    }

    #[test]
    fn normalize_action_name_lowercases_and_restricts_charset() {
        // C1: camelCase lowercases (not drops uppercase) — `putHash` → `puthash`,
        // NOT the old buggy `putash`/`setorker`.
        assert_eq!(normalize_action_name("putHash"), "puthash");
        assert_eq!(normalize_action_name("setWorker"), "setworker");
        // Truncated to 12 chars.
        assert_eq!(normalize_action_name("averylongfunctionname"), "averylongfun");
    }

    #[test]
    fn abi_action_names_are_lowercased_not_dropped() {
        // C1: an action named with camelCase must lowercase, not drop uppercase.
        let abi = compile_to_abi(
            r#"
            contract C {
                uint64 x;
                function putHash(uint64 v) public { x = v; }
                function setWorker(uint64 v) public { x = v; }
            }
            "#,
        );
        let names: Vec<&str> = abi.actions.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"puthash"), "actions: {names:?}");
        assert!(names.contains(&"setworker"), "actions: {names:?}");
    }

    #[test]
    fn abi_action_names_restrict_digits_to_eosio_charset() {
        // C2: digits 0 and 6-9 are not valid eosio::name chars and are dropped;
        // 1-5 are kept. `putu8` → `putu`, `slot12` → `slot12`.
        assert_eq!(normalize_action_name("putu8"), "putu");
        assert_eq!(normalize_action_name("slot12"), "slot12");
        assert_eq!(normalize_action_name("get9"), "get");
    }

    #[test]
    fn abi_omits_extensions_when_no_state_vars() {
        // A contract with only constants has nothing to describe in the layout —
        // the extension array should be empty.
        let abi = compile_to_abi(
            r#"
            contract C {
                uint64 constant K = 7;
                function get() public pure returns (uint64) { return K; }
            }
            "#,
        );
        assert!(abi.abi_extensions.is_empty());
    }
}
