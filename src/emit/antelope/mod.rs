// SPDX-License-Identifier: Apache-2.0

pub(super) mod target;

use crate::codegen::Options;
use crate::emit::binary::Binary;
use crate::emit::cfg::emit_cfg;
use crate::sema::ast;
use crate::sema::ast::Type;
use inkwell::context::Context;
use inkwell::module::{Linkage, Module};
use inkwell::values::{BasicMetadataValueEnum, GlobalValue};
use inkwell::AddressSpace;
use inkwell::IntPredicate;

pub struct AntelopeTarget;

/// Encode a string as an Antelope eosio::name uint64.
/// Characters: '.' = 0, '1'-'5' = 1-5, 'a'-'z' = 6-31
/// First 12 chars use 5 bits each (bits 59..0), 13th char uses 4 bits.
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

/// The table name used for all Solidity state variable storage.
/// Encoded as eosio::name("state").
pub const STATE_TABLE_NAME: u64 = {
    // "state" = s(24) t(25) a(6) t(25) e(10)
    // = (24<<59) | (25<<54) | (6<<49) | (25<<44) | (10<<39)
    (24 << 59) | (25 << 54) | (6 << 49) | (25 << 44) | (10 << 39)
};

impl AntelopeTarget {
    pub fn build<'a>(
        context: &'a Context,
        std_lib: &Module<'a>,
        contract: &'a ast::Contract,
        ns: &'a ast::Namespace,
        opt: &'a Options,
    ) -> Binary<'a> {
        let filename = ns.files[contract.loc.file_no()].file_name();
        let mut bin = Binary::new(
            context,
            ns,
            &contract.id.name,
            &filename,
            opt,
            std_lib,
            None,
        );

        let mut export_list = Vec::new();

        Self::declare_externals(&mut bin);
        Self::add_receiver_global(&mut bin);
        Self::emit_functions(contract, &mut bin);
        Self::emit_apply(context, &mut bin, contract, &mut export_list);

        bin.internalize(export_list.as_slice());

        bin
    }

    /// Declare Antelope host function imports.
    fn declare_externals(bin: &mut Binary) {
        let i32_ty = bin.context.i32_type();
        let i64_ty = bin.context.i64_type();
        let void_ty = bin.context.void_type();
        let ptr_ty = bin.context.ptr_type(AddressSpace::default());

        // void prints_l(const char* msg, uint32_t len)
        let prints_l_ty = void_ty.fn_type(&[ptr_ty.into(), i32_ty.into()], false);
        bin.module
            .add_function("prints_l", prints_l_ty, Some(Linkage::External));

        // void eosio_assert(uint32_t test, const char* msg)
        let eosio_assert_ty = void_ty.fn_type(&[i32_ty.into(), ptr_ty.into()], false);
        bin.module
            .add_function("eosio_assert", eosio_assert_ty, Some(Linkage::External));

        // int32_t db_find_i64(uint64_t code, uint64_t scope, uint64_t table, uint64_t id)
        let db_find_ty = i32_ty.fn_type(
            &[i64_ty.into(), i64_ty.into(), i64_ty.into(), i64_ty.into()],
            false,
        );
        bin.module
            .add_function("db_find_i64", db_find_ty, Some(Linkage::External));

        // int32_t db_store_i64(uint64_t scope, uint64_t table, uint64_t payer, uint64_t id, const void* data, uint32_t len)
        let db_store_ty = i32_ty.fn_type(
            &[
                i64_ty.into(),
                i64_ty.into(),
                i64_ty.into(),
                i64_ty.into(),
                ptr_ty.into(),
                i32_ty.into(),
            ],
            false,
        );
        bin.module
            .add_function("db_store_i64", db_store_ty, Some(Linkage::External));

        // void db_update_i64(int32_t iterator, uint64_t payer, const void* data, uint32_t len)
        let db_update_ty = void_ty.fn_type(
            &[i32_ty.into(), i64_ty.into(), ptr_ty.into(), i32_ty.into()],
            false,
        );
        bin.module
            .add_function("db_update_i64", db_update_ty, Some(Linkage::External));

        // int32_t db_get_i64(int32_t iterator, void* data, uint32_t len)
        let db_get_ty =
            i32_ty.fn_type(&[i32_ty.into(), ptr_ty.into(), i32_ty.into()], false);
        bin.module
            .add_function("db_get_i64", db_get_ty, Some(Linkage::External));

        // uint32_t action_data_size()
        let action_data_size_ty = i32_ty.fn_type(&[], false);
        bin.module.add_function(
            "action_data_size",
            action_data_size_ty,
            Some(Linkage::External),
        );

        // uint32_t read_action_data(void* msg, uint32_t len)
        let read_action_data_ty = i32_ty.fn_type(&[ptr_ty.into(), i32_ty.into()], false);
        bin.module.add_function(
            "read_action_data",
            read_action_data_ty,
            Some(Linkage::External),
        );

        // void sha3(const char* data, uint32_t data_len, char* hash, uint32_t hash_len, int32_t keccak)
        // keccak=1 for keccak256 mode (Ethereum-compatible)
        let sha3_ty = void_ty.fn_type(
            &[ptr_ty.into(), i32_ty.into(), ptr_ty.into(), i32_ty.into(), i32_ty.into()],
            false,
        );
        bin.module
            .add_function("sha3", sha3_ty, Some(Linkage::External));

        // int32_t db_end_i64(uint64_t code, uint64_t scope, uint64_t table)
        let db_end_ty = i32_ty.fn_type(
            &[i64_ty.into(), i64_ty.into(), i64_ty.into()],
            false,
        );
        bin.module
            .add_function("db_end_i64", db_end_ty, Some(Linkage::External));

        // int32_t db_previous_i64(int32_t iterator, uint64_t* primary)
        let db_previous_ty = i32_ty.fn_type(&[i32_ty.into(), ptr_ty.into()], false);
        bin.module
            .add_function("db_previous_i64", db_previous_ty, Some(Linkage::External));

        // int32_t db_idx256_store(uint64_t scope, uint64_t table, uint64_t payer, uint64_t id, const uint128_t data[], uint32_t data_len)
        let db_idx256_store_ty = i32_ty.fn_type(
            &[
                i64_ty.into(),
                i64_ty.into(),
                i64_ty.into(),
                i64_ty.into(),
                ptr_ty.into(),
                i32_ty.into(),
            ],
            false,
        );
        bin.module.add_function(
            "db_idx256_store",
            db_idx256_store_ty,
            Some(Linkage::External),
        );

        // int32_t db_idx256_find_secondary(uint64_t code, uint64_t scope, uint64_t table, const uint128_t data[], uint32_t data_len, uint64_t* primary)
        let db_idx256_find_ty = i32_ty.fn_type(
            &[
                i64_ty.into(),
                i64_ty.into(),
                i64_ty.into(),
                ptr_ty.into(),
                i32_ty.into(),
                ptr_ty.into(),
            ],
            false,
        );
        bin.module.add_function(
            "db_idx256_find_secondary",
            db_idx256_find_ty,
            Some(Linkage::External),
        );

        // void db_idx256_update(int32_t iterator, uint64_t payer, const uint128_t data[], uint32_t data_len)
        let db_idx256_update_ty = void_ty.fn_type(
            &[i32_ty.into(), i64_ty.into(), ptr_ty.into(), i32_ty.into()],
            false,
        );
        bin.module.add_function(
            "db_idx256_update",
            db_idx256_update_ty,
            Some(Linkage::External),
        );

        // void db_remove_i64(int32_t iterator)
        let db_remove_ty = void_ty.fn_type(&[i32_ty.into()], false);
        bin.module
            .add_function("db_remove_i64", db_remove_ty, Some(Linkage::External));

        // void db_idx256_remove(int32_t iterator)
        let db_idx256_remove_ty = void_ty.fn_type(&[i32_ty.into()], false);
        bin.module.add_function(
            "db_idx256_remove",
            db_idx256_remove_ty,
            Some(Linkage::External),
        );

        // void require_auth(uint64_t name)
        let require_auth_ty = void_ty.fn_type(&[i64_ty.into()], false);
        bin.module
            .add_function("require_auth", require_auth_ty, Some(Linkage::External));

        // uint64_t current_receiver()
        let current_receiver_ty = i64_ty.fn_type(&[], false);
        bin.module.add_function(
            "current_receiver",
            current_receiver_ty,
            Some(Linkage::External),
        );
    }

    /// Add WASM globals for receiver and auto-increment pk cache.
    fn add_receiver_global(bin: &mut Binary) {
        let i64_ty = bin.context.i64_type();

        // __receiver: stores the current contract's account name (set in apply()).
        let global = bin.module.add_global(i64_ty, None, "__receiver");
        global.set_initializer(&i64_ty.const_zero());
        global.set_linkage(Linkage::Internal);

        // __next_pk: cached next primary key for auto-increment storage inserts.
        // Initialized to UINT64_MAX as sentinel meaning "not yet computed".
        // On first insert, computed via db_end_i64/db_previous_i64, then incremented.
        let pk_global = bin.module.add_global(i64_ty, None, "__next_pk");
        pk_global.set_initializer(&i64_ty.const_all_ones()); // UINT64_MAX sentinel
        pk_global.set_linkage(Linkage::Internal);
    }

    /// Get the __receiver global value.
    pub fn get_receiver_global<'a>(bin: &Binary<'a>) -> GlobalValue<'a> {
        bin.module.get_global("__receiver").unwrap()
    }

    /// Get the __next_pk global value.
    pub fn get_next_pk_global<'a>(bin: &Binary<'a>) -> GlobalValue<'a> {
        bin.module.get_global("__next_pk").unwrap()
    }

    fn emit_functions<'a>(contract: &'a ast::Contract, bin: &mut Binary<'a>) {
        let mut defines = Vec::new();

        for (cfg_no, cfg) in contract.cfg.iter().enumerate() {
            let ftype = bin.function_type(
                &cfg.params.iter().map(|p| p.ty.clone()).collect::<Vec<_>>(),
                &cfg.returns.iter().map(|p| p.ty.clone()).collect::<Vec<_>>(),
            );

            // All user functions are internal; apply() is the only export.
            let func_decl = if let Some(func) = bin.module.get_function(&cfg.name) {
                assert_eq!(func.get_first_basic_block(), None);
                func
            } else {
                bin.module
                    .add_function(&cfg.name, ftype, Some(Linkage::Internal))
            };

            bin.functions.insert(cfg_no, func_decl);
            defines.push((func_decl, cfg));
        }

        for (func_decl, cfg) in defines {
            emit_cfg(&mut AntelopeTarget, bin, contract, cfg, func_decl);
        }
    }

    /// Compute the byte size of a fixed-size type in Antelope DataStream serialization.
    /// Returns None for variable-length types (string, bytes).
    fn datastream_fixed_size(ty: &Type, bin: &Binary) -> Option<u32> {
        match ty {
            Type::Bool => Some(1),
            Type::Uint(n) | Type::Int(n) => Some(((*n as u32) + 7) / 8),
            Type::Bytes(n) => Some(*n as u32),
            Type::Enum(n) => {
                let bits = bin.ns.enums[*n].ty.bits(bin.ns) as u32;
                Some((bits + 7) / 8)
            }
            Type::Value => Some(bin.ns.value_length as u32),
            Type::Contract(_) | Type::Address(_) => Some(bin.ns.address_length as u32),
            Type::String | Type::DynamicBytes => None,
            _ => panic!(
                "Antelope: unsupported parameter type for action data deserialization: {ty:?}"
            ),
        }
    }

    /// Check if any parameter in the list requires variable-length deserialization.
    fn has_variable_length_params(params: &[ast::Parameter<Type>], bin: &Binary) -> bool {
        params
            .iter()
            .any(|p| Self::datastream_fixed_size(&p.ty, bin).is_none())
    }

    /// Emit the `apply(receiver, code, action)` entry point.
    /// Dispatches to the correct function based on the `action` parameter.
    fn emit_apply<'a>(
        context: &'a Context,
        bin: &mut Binary<'a>,
        contract: &'a ast::Contract,
        export_list: &mut Vec<&'a str>,
    ) {
        let i64_ty = context.i64_type();
        let void_ty = context.void_type();

        let apply_ty =
            void_ty.fn_type(&[i64_ty.into(), i64_ty.into(), i64_ty.into()], false);
        let apply_func = bin
            .module
            .add_function("apply", apply_ty, Some(Linkage::External));
        export_list.push("apply");

        let entry = context.append_basic_block(apply_func, "entry");
        bin.builder.position_at_end(entry);

        let receiver = apply_func.get_nth_param(0).unwrap().into_int_value();
        let code = apply_func.get_nth_param(1).unwrap().into_int_value();
        let action = apply_func.get_nth_param(2).unwrap().into_int_value();

        // Initialize the heap allocator (linked-list at HEAP_START=0x10000).
        // Must be called before any code that allocates (strings, dynamic arrays, etc.).
        if let Some(init_heap) = bin.module.get_function("__init_heap") {
            bin.builder.build_call(init_heap, &[], "").unwrap();
        }

        // Store receiver in global for use by storage functions.
        let receiver_global = Self::get_receiver_global(bin);
        bin.builder
            .build_store(receiver_global.as_pointer_value(), receiver)
            .unwrap();

        // Only dispatch if code == receiver (i.e., action is directed at this contract).
        let code_eq_receiver = bin
            .builder
            .build_int_compare(IntPredicate::EQ, code, receiver, "code_eq_recv")
            .unwrap();

        let dispatch_bb = context.append_basic_block(apply_func, "dispatch");
        let return_bb = context.append_basic_block(apply_func, "return");

        bin.builder
            .build_conditional_branch(code_eq_receiver, dispatch_bb, return_bb)
            .unwrap();

        bin.builder.position_at_end(dispatch_bb);

        // For each public function, compare action name and call if matched.
        for cfg in &contract.cfg {
            if !cfg.public || cfg.is_placeholder() {
                continue;
            }

            // Extract the short function name (after last "::" if mangled).
            let func_name = if cfg.name.contains("::") {
                cfg.name.split("::").last().unwrap_or(&cfg.name)
            } else {
                &cfg.name
            };

            // Skip constructor-like functions (they contain hex selectors).
            if func_name.starts_with("constructor") {
                continue;
            }

            // Strip mangled parameter suffix: "record__uint64_uint64" → "record"
            let action_name = func_name.split("__").next().unwrap_or(func_name);
            let action_encoded = string_to_name(action_name);

            let action_const = i64_ty.const_int(action_encoded, false);
            let matches = bin
                .builder
                .build_int_compare(IntPredicate::EQ, action, action_const, "action_match")
                .unwrap();

            let call_bb =
                context.append_basic_block(apply_func, &format!("call_{action_name}"));
            let next_bb = context.append_basic_block(apply_func, "next");

            bin.builder
                .build_conditional_branch(matches, call_bb, next_bb)
                .unwrap();

            bin.builder.position_at_end(call_bb);

            if let Some(func) = bin.module.get_function(&cfg.name) {
                let mut args: Vec<BasicMetadataValueEnum> = Vec::new();

                if !cfg.params.is_empty() {
                    // Read raw action data into a stack buffer.
                    let i32_ty = context.i32_type();
                    let data_size_fn =
                        bin.module.get_function("action_data_size").unwrap();
                    let data_size = bin
                        .builder
                        .build_call(data_size_fn, &[], "data_size")
                        .unwrap()
                        .try_as_basic_value()
                        .left()
                        .unwrap()
                        .into_int_value();

                    let data_buf = bin
                        .builder
                        .build_array_alloca(
                            context.i8_type(),
                            data_size,
                            "action_data",
                        )
                        .unwrap();

                    let read_fn =
                        bin.module.get_function("read_action_data").unwrap();
                    bin.builder
                        .build_call(
                            read_fn,
                            &[data_buf.into(), data_size.into()],
                            "",
                        )
                        .unwrap();

                    // Use dynamic offset for deserialization (needed for variable-length types).
                    let offset_alloca = bin
                        .builder
                        .build_alloca(i32_ty, "ds_offset")
                        .unwrap();
                    bin.builder
                        .build_store(offset_alloca, i32_ty.const_zero())
                        .unwrap();

                    for param in cfg.params.iter() {
                        let cur_offset = bin
                            .builder
                            .build_load(i32_ty, offset_alloca, "cur_off")
                            .unwrap()
                            .into_int_value();

                        let param_ptr = unsafe {
                            bin.builder
                                .build_gep(
                                    context.i8_type(),
                                    data_buf,
                                    &[cur_offset],
                                    "param_ptr",
                                )
                                .unwrap()
                        };

                        if let Some(byte_size) = Self::datastream_fixed_size(&param.ty, bin) {
                            // Fixed-size type: load directly from buffer.
                            let llvm_ty = bin.llvm_var_ty(&param.ty);
                            let param_val = bin
                                .builder
                                .build_load(llvm_ty, param_ptr, "param")
                                .unwrap();
                            args.push(param_val.into());

                            let new_offset = bin
                                .builder
                                .build_int_add(
                                    cur_offset,
                                    i32_ty.const_int(byte_size as u64, false),
                                    "new_off",
                                )
                                .unwrap();
                            bin.builder
                                .build_store(offset_alloca, new_offset)
                                .unwrap();
                        } else {
                            // Variable-length type (string/bytes): read varuint32 length, then data.
                            // Antelope DataStream encodes strings as: varuint32 length + raw bytes.
                            // For simplicity, we support lengths < 128 (single-byte varuint).
                            // This covers virtually all action parameter strings.
                            let str_len = bin
                                .builder
                                .build_load(context.i8_type(), param_ptr, "str_len_byte")
                                .unwrap()
                                .into_int_value();
                            let str_len_i32 = bin
                                .builder
                                .build_int_z_extend(str_len, i32_ty, "str_len")
                                .unwrap();

                            // Advance past the varuint32 length byte.
                            let after_len = bin
                                .builder
                                .build_int_add(
                                    cur_offset,
                                    i32_ty.const_int(1, false),
                                    "after_len",
                                )
                                .unwrap();

                            let str_data_ptr = unsafe {
                                bin.builder
                                    .build_gep(
                                        context.i8_type(),
                                        data_buf,
                                        &[after_len],
                                        "str_data",
                                    )
                                    .unwrap()
                            };

                            // Allocate a vector on the heap: vector_new(len, 1, data_ptr)
                            let vector_new_fn =
                                bin.module.get_function("vector_new").unwrap();
                            let vec_ptr = bin
                                .builder
                                .build_call(
                                    vector_new_fn,
                                    &[
                                        str_len_i32.into(),
                                        i32_ty.const_int(1, false).into(),
                                        str_data_ptr.into(),
                                    ],
                                    "str_vec",
                                )
                                .unwrap()
                                .try_as_basic_value()
                                .left()
                                .unwrap();

                            args.push(vec_ptr.into());

                            // Advance offset past length byte + string data.
                            let new_offset = bin
                                .builder
                                .build_int_add(after_len, str_len_i32, "new_off")
                                .unwrap();
                            bin.builder
                                .build_store(offset_alloca, new_offset)
                                .unwrap();
                        }
                    }
                }

                // Add output pointers for return values (passed by pointer).
                for ret in cfg.returns.iter() {
                    let ret_alloca = bin
                        .builder
                        .build_alloca(bin.llvm_var_ty(&ret.ty), "ret")
                        .unwrap();
                    args.push(ret_alloca.into());
                }

                bin.builder.build_call(func, &args, "").unwrap();
            }
            bin.builder.build_unconditional_branch(return_bb).unwrap();

            bin.builder.position_at_end(next_bb);
        }

        // Fall through (no action matched) — just return.
        bin.builder.build_unconditional_branch(return_bb).unwrap();

        bin.builder.position_at_end(return_bb);
        bin.builder.build_return(None).unwrap();
    }
}
