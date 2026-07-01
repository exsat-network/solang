// SPDX-License-Identifier: Apache-2.0

/// Mock runtime for the Antelope target.
/// Executes compiled Antelope WASM in wasmi with mocked host functions.

use std::collections::HashMap;
use std::ffi::OsStr;
use tiny_keccak::{Hasher, Keccak};
use wasmi::core::{Trap, TrapCode};
use wasmi::{Engine, Error, Linker, Memory, Module, Store, Value};

use solang::codegen::Options;
use solang::file_resolver::FileResolver;
use solang::{compile, Target};

use wasm_host_attr::wasm_host;

mod antelope_tests;

// ─── Antelope name encoding ───

/// Encode a string as an Antelope eosio::name uint64.
pub fn string_to_name(s: &str) -> u64 {
    let char_to_value = |c: u8| -> u64 {
        match c {
            b'.' => 0,
            b'1'..=b'5' => (c - b'1' + 1) as u64,
            b'a'..=b'z' => (c - b'a' + 6) as u64,
            _ => 0,
        }
    };
    let bytes = s.as_bytes();
    let len = bytes.len().min(13);
    let mut value: u64 = 0;
    for i in 0..len.min(12) {
        value |= char_to_value(bytes[i]) << (64 - 5 * (i + 1));
    }
    if len == 13 {
        value |= char_to_value(bytes[12]) & 0x0F;
    }
    value
}

// ─── DataStream encoding helpers ───

pub enum ActionParam {
    U64(u64),
    I64(i64),
    U32(u32),
    Bool(bool),
    String(String),
}

pub fn encode_action_data(params: &[ActionParam]) -> Vec<u8> {
    let mut buf = Vec::new();
    for param in params {
        match param {
            ActionParam::U64(v) => buf.extend_from_slice(&v.to_le_bytes()),
            ActionParam::I64(v) => buf.extend_from_slice(&v.to_le_bytes()),
            ActionParam::U32(v) => buf.extend_from_slice(&v.to_le_bytes()),
            ActionParam::Bool(v) => buf.push(if *v { 1 } else { 0 }),
            ActionParam::String(s) => {
                encode_varuint32(&mut buf, s.len() as u32);
                buf.extend_from_slice(s.as_bytes());
            }
        }
    }
    buf
}

fn encode_varuint32(buf: &mut Vec<u8>, mut val: u32) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

// ─── Table storage types ───

type TableKey = (u64, u64, u64); // (code, scope, table)

#[derive(Clone, Debug)]
pub struct TableRow {
    pub pk: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SecondaryIdx256 {
    pub pk: u64,
    pub value: [u8; 32],
    pub iter_id: i32,
}

#[derive(Clone, Debug, Default)]
pub struct Table {
    pub rows: Vec<TableRow>,
    pub idx256: Vec<SecondaryIdx256>,
}

// ─── Runtime state ───

pub struct Runtime {
    pub memory: Option<Memory>,
    pub receiver: u64,
    pub action_data: Vec<u8>,
    pub auth_accounts: Vec<u64>,
    pub prints: String,
    pub tables: HashMap<TableKey, Table>,
    pub inline_actions: Vec<Vec<u8>>,
    pub notifications: Vec<u64>,
    // Iterator tracking
    next_iter: i32,
    next_end_iter: i32,
    iter_map: HashMap<i32, (TableKey, usize)>,       // normal iter -> (table, row_idx)
    end_iter_map: HashMap<i32, TableKey>,             // end iter -> table key
    // Secondary index iterators
    idx256_iter_map: HashMap<i32, (TableKey, usize)>, // sec iter -> (table, idx_pos)
}

impl Runtime {
    fn new(receiver: u64) -> Self {
        Self {
            memory: None,
            receiver,
            action_data: Vec::new(),
            auth_accounts: vec![receiver],
            prints: String::new(),
            tables: HashMap::new(),
            inline_actions: Vec::new(),
            notifications: Vec::new(),
            next_iter: 0,
            next_end_iter: -2,
            iter_map: HashMap::new(),
            end_iter_map: HashMap::new(),
            idx256_iter_map: HashMap::new(),
        }
    }

    fn alloc_iter(&mut self, key: TableKey, row_idx: usize) -> i32 {
        let id = self.next_iter;
        self.next_iter += 1;
        self.iter_map.insert(id, (key, row_idx));
        id
    }

    fn alloc_end_iter(&mut self, key: TableKey) -> i32 {
        let id = self.next_end_iter;
        self.next_end_iter -= 1;
        self.end_iter_map.insert(id, key);
        id
    }

    fn alloc_idx256_iter(&mut self, key: TableKey, idx_pos: usize) -> i32 {
        let id = self.next_iter;
        self.next_iter += 1;
        self.idx256_iter_map.insert(id, (key, idx_pos));
        id
    }
}

// ─── Memory helpers ───

fn read_buf(mem: &[u8], ptr: u32, len: u32) -> Vec<u8> {
    mem[ptr as usize..(ptr + len) as usize].to_vec()
}

fn write_buf(mem: &mut [u8], ptr: u32, data: &[u8]) {
    mem[ptr as usize..ptr as usize + data.len()].copy_from_slice(data);
}

fn read_string(mem: &[u8], ptr: u32) -> String {
    let start = ptr as usize;
    let end = mem[start..].iter().position(|&b| b == 0).unwrap_or(0) + start;
    String::from_utf8_lossy(&mem[start..end]).to_string()
}

// ─── Host function implementations ───

#[wasm_host]
impl Runtime {
    // --- Print / Assert ---

    #[host("env")]
    fn prints_l(ptr: u32, len: u32) -> Result<(), Trap> {
        let s = String::from_utf8_lossy(&read_buf(mem, ptr, len)).to_string();
        vm.prints.push_str(&s);
        Ok(())
    }

    #[host("env")]
    fn eosio_assert(test: u32, msg_ptr: u32) -> Result<(), Trap> {
        if test == 0 {
            let msg = read_string(mem, msg_ptr);
            eprintln!("eosio_assert failed: {msg}");
            return Err(TrapCode::UnreachableCodeReached.into());
        }
        Ok(())
    }

    // --- Action data ---

    #[host("env")]
    fn action_data_size() -> Result<u32, Trap> {
        Ok(vm.action_data.len() as u32)
    }

    #[host("env")]
    fn read_action_data(ptr: u32, len: u32) -> Result<u32, Trap> {
        let copy_len = std::cmp::min(len as usize, vm.action_data.len());
        write_buf(mem, ptr, &vm.action_data[..copy_len]);
        Ok(copy_len as u32)
    }

    // --- Auth ---

    #[host("env")]
    fn require_auth(account: u64) -> Result<(), Trap> {
        if !vm.auth_accounts.contains(&account) {
            eprintln!("require_auth: missing authority for account {account}");
            return Err(TrapCode::UnreachableCodeReached.into());
        }
        Ok(())
    }

    #[host("env")]
    fn has_auth(account: u64) -> Result<u32, Trap> {
        Ok(if vm.auth_accounts.contains(&account) { 1 } else { 0 })
    }

    #[host("env")]
    fn require_auth2(account: u64, _permission: u64) -> Result<(), Trap> {
        if !vm.auth_accounts.contains(&account) {
            eprintln!("require_auth2: missing authority for account {account}");
            return Err(TrapCode::UnreachableCodeReached.into());
        }
        Ok(())
    }

    // --- Identity ---

    #[host("env")]
    fn current_receiver() -> Result<u64, Trap> {
        Ok(vm.receiver)
    }

    #[host("env")]
    fn current_time() -> Result<u64, Trap> {
        // Return a fixed mock timestamp: 2024-01-01T00:00:00Z in microseconds
        Ok(1704067200_000_000u64)
    }

    // --- Notifications ---

    #[host("env")]
    fn require_recipient(name: u64) -> Result<(), Trap> {
        vm.notifications.push(name);
        Ok(())
    }

    // --- Inline actions ---

    #[host("env")]
    fn send_inline(ptr: u32, len: u32) -> Result<(), Trap> {
        let data = read_buf(mem, ptr, len);
        vm.inline_actions.push(data);
        Ok(())
    }

    // --- Return value ---

    #[host("env")]
    fn set_action_return_value(_ptr: u32, _len: u32) -> Result<(), Trap> {
        // In a real environment this captures the return value; mock ignores it.
        Ok(())
    }

    // --- Crypto ---

    #[host("env")]
    fn sha3(data_ptr: u32, data_len: u32, hash_ptr: u32, _hash_len: u32, _keccak: u32) -> Result<(), Trap> {
        let data = read_buf(mem, data_ptr, data_len);
        let mut hasher = Keccak::v256();
        hasher.update(&data);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        write_buf(mem, hash_ptr, &output);
        Ok(())
    }

    // --- Primary table: db_store_i64 ---

    #[host("env")]
    fn db_store_i64(scope: u64, table: u64, payer: u64, id: u64, data_ptr: u32, data_len: u32) -> Result<i32, Trap> {
        let _ = payer;
        let key: TableKey = (vm.receiver, scope, table);
        let data = read_buf(mem, data_ptr, data_len);
        let tbl = vm.tables.entry(key).or_default();
        tbl.rows.push(TableRow { pk: id, data });
        let row_idx = tbl.rows.len() - 1;
        Ok(vm.alloc_iter(key, row_idx))
    }

    // --- Primary table: db_find_i64 ---

    #[host("env")]
    fn db_find_i64(code: u64, scope: u64, table: u64, id: u64) -> Result<i32, Trap> {
        let key: TableKey = (code, scope, table);
        if let Some(tbl) = vm.tables.get(&key) {
            if let Some(pos) = tbl.rows.iter().position(|r| r.pk == id) {
                return Ok(vm.alloc_iter(key, pos));
            }
        }
        Ok(-1)
    }

    // --- Primary table: db_get_i64 ---

    #[host("env")]
    fn db_get_i64(iterator: i32, data_ptr: u32, data_len: u32) -> Result<i32, Trap> {
        let (key, row_idx) = vm.iter_map[&iterator];
        let row = &vm.tables[&key].rows[row_idx];
        let size = row.data.len() as i32;
        if data_len > 0 {
            let copy_len = std::cmp::min(data_len as usize, row.data.len());
            write_buf(mem, data_ptr, &row.data[..copy_len]);
        }
        Ok(size)
    }

    // --- Primary table: db_update_i64 ---

    #[host("env")]
    fn db_update_i64(iterator: i32, _payer: u64, data_ptr: u32, data_len: u32) -> Result<(), Trap> {
        let (key, row_idx) = vm.iter_map[&iterator];
        let data = read_buf(mem, data_ptr, data_len);
        vm.tables.get_mut(&key).unwrap().rows[row_idx].data = data;
        Ok(())
    }

    // --- Primary table: db_remove_i64 ---

    #[host("env")]
    fn db_remove_i64(iterator: i32) -> Result<(), Trap> {
        let (key, row_idx) = vm.iter_map[&iterator];
        vm.tables.get_mut(&key).unwrap().rows.remove(row_idx);
        Ok(())
    }

    // --- Primary table: db_end_i64 ---

    #[host("env")]
    fn db_end_i64(code: u64, scope: u64, table: u64) -> Result<i32, Trap> {
        let key: TableKey = (code, scope, table);
        match vm.tables.get(&key) {
            Some(tbl) if !tbl.rows.is_empty() => {
                Ok(vm.alloc_end_iter(key))
            }
            _ => Ok(-1),
        }
    }

    // --- Primary table: db_previous_i64 ---

    #[host("env")]
    fn db_previous_i64(iterator: i32, pk_ptr: u32) -> Result<i32, Trap> {
        if iterator < -1 {
            // End iterator — return last row
            let key = vm.end_iter_map[&iterator];
            let tbl = &vm.tables[&key];
            if tbl.rows.is_empty() {
                return Ok(-1);
            }
            let last_idx = tbl.rows.len() - 1;
            let pk = tbl.rows[last_idx].pk;
            write_buf(mem, pk_ptr, &pk.to_le_bytes());
            return Ok(vm.alloc_iter(key, last_idx));
        }
        // Normal iterator — go to previous row
        let (key, row_idx) = vm.iter_map[&iterator];
        if row_idx == 0 {
            return Ok(-1);
        }
        let prev_idx = row_idx - 1;
        let pk = vm.tables[&key].rows[prev_idx].pk;
        write_buf(mem, pk_ptr, &pk.to_le_bytes());
        Ok(vm.alloc_iter(key, prev_idx))
    }

    // --- Primary table: db_next_i64 ---

    #[host("env")]
    fn db_next_i64(iterator: i32, pk_ptr: u32) -> Result<i32, Trap> {
        let (key, row_idx) = vm.iter_map[&iterator];
        let tbl = &vm.tables[&key];
        let next_idx = row_idx + 1;
        if next_idx >= tbl.rows.len() {
            return Ok(-1);
        }
        let pk = tbl.rows[next_idx].pk;
        write_buf(mem, pk_ptr, &pk.to_le_bytes());
        Ok(vm.alloc_iter(key, next_idx))
    }

    // --- Primary table: db_lowerbound_i64 ---

    #[host("env")]
    fn db_lowerbound_i64(code: u64, scope: u64, table: u64, id: u64) -> Result<i32, Trap> {
        let key: TableKey = (code, scope, table);
        if let Some(tbl) = vm.tables.get(&key) {
            // Find first row with pk >= id
            if let Some(pos) = tbl.rows.iter().position(|r| r.pk >= id) {
                return Ok(vm.alloc_iter(key, pos));
            }
        }
        Ok(-1)
    }

    // --- idx256 secondary index: store ---

    #[host("env")]
    fn db_idx256_store(scope: u64, table: u64, payer: u64, id: u64, data_ptr: u32, _data_len: u32) -> Result<i32, Trap> {
        let _ = payer;
        let key: TableKey = (vm.receiver, scope, table);
        let mut value = [0u8; 32];
        value.copy_from_slice(&read_buf(mem, data_ptr, 32));
        let tbl = vm.tables.entry(key).or_default();
        tbl.idx256.push(SecondaryIdx256 { pk: id, value, iter_id: 0 });
        let idx_pos = tbl.idx256.len() - 1;
        Ok(vm.alloc_idx256_iter(key, idx_pos))
    }

    // --- idx256 secondary index: find ---

    #[host("env")]
    fn db_idx256_find_secondary(code: u64, scope: u64, table: u64, data_ptr: u32, _data_len: u32, pk_ptr: u32) -> Result<i32, Trap> {
        let key: TableKey = (code, scope, table);
        let mut search_value = [0u8; 32];
        search_value.copy_from_slice(&read_buf(mem, data_ptr, 32));
        if let Some(tbl) = vm.tables.get(&key) {
            if let Some(pos) = tbl.idx256.iter().position(|e| e.value == search_value) {
                let pk = tbl.idx256[pos].pk;
                write_buf(mem, pk_ptr, &pk.to_le_bytes());
                return Ok(vm.alloc_idx256_iter(key, pos));
            }
        }
        Ok(-1)
    }

    // --- idx256 secondary index: update ---

    #[host("env")]
    fn db_idx256_update(iterator: i32, _payer: u64, data_ptr: u32, _data_len: u32) -> Result<(), Trap> {
        let (key, idx_pos) = vm.idx256_iter_map[&iterator];
        let mut value = [0u8; 32];
        value.copy_from_slice(&read_buf(mem, data_ptr, 32));
        vm.tables.get_mut(&key).unwrap().idx256[idx_pos].value = value;
        Ok(())
    }

    // --- idx256 secondary index: remove ---

    #[host("env")]
    fn db_idx256_remove(iterator: i32) -> Result<(), Trap> {
        let (key, idx_pos) = vm.idx256_iter_map[&iterator];
        vm.tables.get_mut(&key).unwrap().idx256.remove(idx_pos);
        Ok(())
    }

    // --- idx64 secondary index (stubs for compilation — not deeply tested yet) ---

    #[host("env")]
    fn db_idx64_find_secondary(code: u64, scope: u64, table: u64, _secondary_ptr: u32, _primary_ptr: u32) -> Result<i32, Trap> {
        let _key: TableKey = (code, scope, table);
        Ok(-1) // not found — stub
    }

    #[host("env")]
    fn db_idx64_lowerbound(code: u64, scope: u64, table: u64, _secondary_ptr: u32, _primary_ptr: u32) -> Result<i32, Trap> {
        let _key: TableKey = (code, scope, table);
        Ok(-1) // not found — stub
    }

    // --- idx128 secondary index (stubs) ---

    #[host("env")]
    fn db_idx128_find_secondary(code: u64, scope: u64, table: u64, _secondary_ptr: u32, _primary_ptr: u32) -> Result<i32, Trap> {
        let _key: TableKey = (code, scope, table);
        Ok(-1)
    }

    #[host("env")]
    fn db_idx128_lowerbound(code: u64, scope: u64, table: u64, _secondary_ptr: u32, _primary_ptr: u32) -> Result<i32, Trap> {
        let _key: TableKey = (code, scope, table);
        Ok(-1)
    }

    // --- idx256 lowerbound ---

    #[host("env")]
    fn db_idx256_lowerbound(code: u64, scope: u64, table: u64, _data_ptr: u32, _data_len: u32, _primary_ptr: u32) -> Result<i32, Trap> {
        let _key: TableKey = (code, scope, table);
        Ok(-1) // stub
    }

    // --- Standard C library functions (imported by some WASM modules) ---

    #[host("env")]
    fn memcpy(dest: u32, src: u32, len: u32) -> Result<u32, Trap> {
        let data = mem[src as usize..(src + len) as usize].to_vec();
        mem[dest as usize..(dest + len) as usize].copy_from_slice(&data);
        Ok(dest)
    }

    #[host("env")]
    fn memmove(dest: u32, src: u32, len: u32) -> Result<u32, Trap> {
        let data = mem[src as usize..(src + len) as usize].to_vec();
        mem[dest as usize..(dest + len) as usize].copy_from_slice(&data);
        Ok(dest)
    }

    #[host("env")]
    fn memset(dest: u32, val: u32, len: u32) -> Result<u32, Trap> {
        let byte = val as u8;
        for i in 0..len as usize {
            mem[dest as usize + i] = byte;
        }
        Ok(dest)
    }

    #[host("env")]
    fn memcmp(s1: u32, s2: u32, len: u32) -> Result<i32, Trap> {
        for i in 0..len as usize {
            let a = mem[s1 as usize + i];
            let b = mem[s2 as usize + i];
            if a != b {
                return Ok(if a < b { -1 } else { 1 });
            }
        }
        Ok(0)
    }
}

// ─── MockAntelope ───

pub struct MockAntelope {
    wasm: Vec<u8>,
    runtime: Runtime,
}

impl MockAntelope {
    /// Compile Solidity source to Antelope WASM and prepare a mock runtime.
    pub fn build(src: &str) -> Self {
        let wasm = build_antelope_wasm(src);
        let receiver = string_to_name("testaccount");
        Self {
            wasm,
            runtime: Runtime::new(receiver),
        }
    }

    /// Call an action by name. `data` is the DataStream-encoded action parameters.
    /// Receiver == code (direct call, not notification).
    pub fn action(&mut self, action_name: &str, data: Vec<u8>) {
        let action_encoded = string_to_name(action_name) as i64;
        let receiver = self.runtime.receiver as i64;
        self.runtime.action_data = data;
        self.runtime.prints.clear();
        self.runtime.inline_actions.clear();
        self.runtime.notifications.clear();
        self.execute_apply(receiver, receiver, action_encoded)
            .expect("action should not trap");
    }

    /// Call an action, expecting it to trap/revert.
    pub fn action_expect_failure(&mut self, action_name: &str, data: Vec<u8>) {
        let action_encoded = string_to_name(action_name) as i64;
        let receiver = self.runtime.receiver as i64;
        self.runtime.action_data = data;
        self.runtime.prints.clear();
        self.runtime.inline_actions.clear();
        self.runtime.notifications.clear();
        match self.execute_apply(receiver, receiver, action_encoded) {
            Err(_) => (), // Expected failure
            Ok(_) => panic!("expected action to fail, but it succeeded"),
        }
    }

    /// Call as a notification: code != receiver.
    /// This simulates receiving an inline action from another contract.
    pub fn notification(&mut self, code: u64, action_name: &str, data: Vec<u8>) {
        let action_encoded = string_to_name(action_name) as i64;
        let receiver = self.runtime.receiver as i64;
        self.runtime.action_data = data;
        self.runtime.prints.clear();
        self.runtime.inline_actions.clear();
        self.runtime.notifications.clear();
        self.execute_apply(receiver, code as i64, action_encoded)
            .expect("notification should not trap");
    }

    /// Get the accumulated print output from the last action call.
    pub fn prints(&self) -> &str {
        &self.runtime.prints
    }

    /// Set authorized accounts for subsequent actions.
    pub fn set_auth(&mut self, accounts: Vec<u64>) {
        self.runtime.auth_accounts = accounts;
    }

    /// Get inline actions sent during the last call.
    pub fn inline_actions(&self) -> &[Vec<u8>] {
        &self.runtime.inline_actions
    }

    /// Get the raw table storage.
    pub fn tables(&self) -> &HashMap<TableKey, Table> {
        &self.runtime.tables
    }

    fn execute_apply(&mut self, receiver: i64, code: i64, action: i64) -> Result<(), Error> {
        let engine = Engine::default();
        let mut store = Store::new(&engine, std::mem::replace(
            &mut self.runtime,
            Runtime::new(receiver as u64),
        ));
        // Restore actual receiver
        store.data_mut().receiver = receiver as u64;

        let mut linker = Linker::new(&engine);

        // Define all host functions (must come before instantiation)
        Runtime::define(&mut store, &mut linker);

        let module = Module::new(&engine, &self.wasm[..]).expect("WASM should be valid");
        let instance = linker
            .instantiate(&mut store, &module)
            .expect("instantiation should succeed")
            .ensure_no_start(&mut store)
            .expect("no start function expected");

        // Get the exported memory (WASM defines its own memory and exports it)
        let memory = instance
            .get_export(&store, "memory")
            .and_then(|e| e.into_memory())
            .expect("memory export should exist");
        store.data_mut().memory = Some(memory);

        // Call apply(receiver, code, action)
        let apply = instance
            .get_export(&store, "apply")
            .and_then(|e| e.into_func())
            .expect("apply export should exist");

        let args = [
            Value::I64(receiver),
            Value::I64(code),
            Value::I64(action),
        ];
        let result = apply.call(&mut store, &args, &mut []);

        // Transfer state back
        self.runtime = store.into_data();

        result
    }
}

// ─── Compilation ───

fn build_antelope_wasm(src: &str) -> Vec<u8> {
    let tmp_file = OsStr::new("test.sol");
    let mut cache = FileResolver::default();
    cache.set_file_contents(tmp_file.to_str().unwrap(), src.to_string());
    let (wasm, ns) = compile(
        tmp_file,
        &mut cache,
        Target::Antelope,
        &Options {
            opt_level: inkwell::OptimizationLevel::Default.into(),
            ..Default::default()
        },
        vec!["test".to_string()],
        "0.0.1",
    );
    ns.print_diagnostics_in_plain(&cache, false);
    assert!(!wasm.is_empty(), "compilation should produce WASM output");
    // wasm is Vec<(Vec<u8>, String)> — first element is (wasm_bytes, abi_json)
    wasm[0].0.clone()
}

/// Helper: build a MockAntelope from Solidity source
pub fn build_solidity(src: &str) -> MockAntelope {
    MockAntelope::build(src)
}
