// SPDX-License-Identifier: Apache-2.0

pub(super) mod target;

use crate::codegen::Options;
use crate::emit::binary::Binary;
use crate::emit::cfg::emit_cfg;
use crate::sema::ast;
use inkwell::context::Context;
use inkwell::module::{Linkage, Module};
use inkwell::values::GlobalValue;
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
    }

    /// Add a WASM global to store the `receiver` account name (set in apply()).
    fn add_receiver_global(bin: &mut Binary) {
        let i64_ty = bin.context.i64_type();
        let global = bin.module.add_global(i64_ty, None, "__receiver");
        global.set_initializer(&i64_ty.const_zero());
        global.set_linkage(Linkage::Internal);
    }

    /// Get the __receiver global value.
    pub fn get_receiver_global<'a>(bin: &Binary<'a>) -> GlobalValue<'a> {
        bin.module.get_global("__receiver").unwrap()
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

            // Strip "function::" prefix pattern: "Contract::Contract::function::name"
            let action_name = func_name;
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
                // For now, only call functions with no parameters.
                // TODO: deserialize action data for functions with parameters.
                if cfg.params.is_empty() {
                    bin.builder.build_call(func, &[], "").unwrap();
                }
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
