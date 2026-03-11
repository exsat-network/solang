// SPDX-License-Identifier: Apache-2.0

use crate::codegen::cfg::HashTy;
use crate::codegen::Expression;
use crate::emit::antelope::{AntelopeTarget, STATE_TABLE_NAME};
use crate::emit::binary::Binary;
use crate::emit::ContractArgs;
use crate::emit::{TargetRuntime, Variable};
use crate::sema::ast;
use crate::sema::ast::CallTy;
use crate::sema::ast::{Function, Type};

use inkwell::types::{BasicTypeEnum, IntType};
use inkwell::values::{
    ArrayValue, BasicMetadataValueEnum, BasicValueEnum, FunctionValue, IntValue, PointerValue,
};
use inkwell::IntPredicate;

use solang_parser::pt::{Loc, StorageType};

use std::collections::HashMap;

// Antelope TargetRuntime implementation.
// Storage model: one "state" table per contract. Primary key = slot number.
// Each row stores raw bytes of the state variable value.
#[allow(unused_variables)]
impl<'a> TargetRuntime<'a> for AntelopeTarget {
    fn get_storage_int(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue,
        slot: PointerValue<'a>,
        ty: IntType<'a>,
    ) -> IntValue<'a> {
        todo!("antelope: get_storage_int")
    }

    /// Load a value from Antelope table storage.
    ///
    /// 1. receiver = load __receiver global
    /// 2. iter = db_find_i64(receiver, receiver, STATE_TABLE_NAME, slot)
    /// 3. if iter >= 0: db_get_i64(iter, &buf, size); return load(buf)
    /// 4. else: return zero
    fn storage_load(
        &self,
        bin: &Binary<'a>,
        ty: &ast::Type,
        slot: &mut IntValue<'a>,
        function: FunctionValue<'a>,
        storage_type: &Option<StorageType>,
    ) -> BasicValueEnum<'a> {
        let i32_ty = bin.context.i32_type();
        let i64_ty = bin.context.i64_type();

        // Determine byte size of the value being stored.
        let bits = ty.bits(bin.ns) as u32;
        let byte_size = (bits + 7) / 8;

        // Load receiver from global.
        let receiver_global = AntelopeTarget::get_receiver_global(bin);
        let receiver = bin
            .builder
            .build_load(i64_ty, receiver_global.as_pointer_value(), "receiver")
            .unwrap()
            .into_int_value();

        // Slot as u64 (truncate if wider, extend if narrower).
        let slot_i64 = if slot.get_type().get_bit_width() == 64 {
            *slot
        } else if slot.get_type().get_bit_width() > 64 {
            bin.builder
                .build_int_truncate(*slot, i64_ty, "slot64")
                .unwrap()
        } else {
            bin.builder
                .build_int_z_extend(*slot, i64_ty, "slot64")
                .unwrap()
        };

        let table_name = i64_ty.const_int(STATE_TABLE_NAME, false);

        // Call db_find_i64(receiver, receiver, table, slot).
        let db_find = bin.module.get_function("db_find_i64").unwrap();
        let iter = bin
            .builder
            .build_call(
                db_find,
                &[
                    receiver.into(),
                    receiver.into(),
                    table_name.into(),
                    slot_i64.into(),
                ],
                "iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // Check if iter >= 0 (found).
        let found = bin
            .builder
            .build_int_compare(
                IntPredicate::SGE,
                iter,
                i32_ty.const_zero(),
                "found",
            )
            .unwrap();

        let found_bb = bin.context.append_basic_block(function, "db_found");
        let notfound_bb = bin.context.append_basic_block(function, "db_notfound");
        let merge_bb = bin.context.append_basic_block(function, "db_merge");

        bin.builder
            .build_conditional_branch(found, found_bb, notfound_bb)
            .unwrap();

        // FOUND: read row from table.
        // Row format: [key: u64, value: N bytes] to match Antelope ABI.
        bin.builder.position_at_end(found_bb);

        let val_ty = bin.context.custom_width_int_type(bits);
        let row_size = 8 + byte_size; // key (8 bytes) + value

        // Allocate row buffer on stack.
        let row_buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(row_size as u64, false),
                "row_buf",
            )
            .unwrap();

        let db_get = bin.module.get_function("db_get_i64").unwrap();
        let row_size_const = i32_ty.const_int(row_size as u64, false);
        bin.builder
            .build_call(
                db_get,
                &[iter.into(), row_buf.into(), row_size_const.into()],
                "",
            )
            .unwrap();

        // Value starts at offset 8 (after the key).
        let val_ptr = unsafe {
            bin.builder
                .build_gep(
                    bin.context.i8_type(),
                    row_buf,
                    &[i32_ty.const_int(8, false)],
                    "val_ptr",
                )
                .unwrap()
        };

        let loaded_val = bin
            .builder
            .build_load(val_ty, val_ptr, "loaded")
            .unwrap()
            .into_int_value();
        bin.builder.build_unconditional_branch(merge_bb).unwrap();

        // NOT FOUND: return zero.
        bin.builder.position_at_end(notfound_bb);
        let zero_val = val_ty.const_zero();
        bin.builder.build_unconditional_branch(merge_bb).unwrap();

        // MERGE with phi.
        bin.builder.position_at_end(merge_bb);
        let phi = bin
            .builder
            .build_phi(val_ty, "storage_val")
            .unwrap();
        phi.add_incoming(&[(&loaded_val, found_bb), (&zero_val, notfound_bb)]);

        phi.as_basic_value()
    }

    /// Store a value to Antelope table storage.
    ///
    /// 1. receiver = load __receiver global
    /// 2. iter = db_find_i64(receiver, receiver, STATE_TABLE_NAME, slot)
    /// 3. store dest bytes to stack buffer
    /// 4. if iter >= 0: db_update_i64(iter, receiver, &buf, size)
    /// 5. else: db_store_i64(receiver, STATE_TABLE_NAME, receiver, slot, &buf, size)
    fn storage_store(
        &self,
        bin: &Binary<'a>,
        ty: &ast::Type,
        existing: bool,
        slot: &mut IntValue<'a>,
        dest: BasicValueEnum<'a>,
        function: FunctionValue<'a>,
        storage_type: &Option<StorageType>,
    ) {
        let i32_ty = bin.context.i32_type();
        let i64_ty = bin.context.i64_type();

        let bits = ty.bits(bin.ns) as u32;
        let byte_size = (bits + 7) / 8;

        // Load receiver.
        let receiver_global = AntelopeTarget::get_receiver_global(bin);
        let receiver = bin
            .builder
            .build_load(i64_ty, receiver_global.as_pointer_value(), "receiver")
            .unwrap()
            .into_int_value();

        let slot_i64 = if slot.get_type().get_bit_width() == 64 {
            *slot
        } else if slot.get_type().get_bit_width() > 64 {
            bin.builder
                .build_int_truncate(*slot, i64_ty, "slot64")
                .unwrap()
        } else {
            bin.builder
                .build_int_z_extend(*slot, i64_ty, "slot64")
                .unwrap()
        };

        let table_name = i64_ty.const_int(STATE_TABLE_NAME, false);

        // Row format: [key: u64, value: N bytes] to match Antelope ABI.
        let val_ty = bin.context.custom_width_int_type(bits);
        let row_size = 8 + byte_size; // key (8 bytes) + value

        // Allocate row buffer on stack.
        let row_buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(row_size as u64, false),
                "row_buf",
            )
            .unwrap();

        // Write key (slot) at offset 0.
        bin.builder.build_store(row_buf, slot_i64).unwrap();

        // Write value at offset 8.
        let val_ptr = unsafe {
            bin.builder
                .build_gep(
                    bin.context.i8_type(),
                    row_buf,
                    &[i32_ty.const_int(8, false)],
                    "val_ptr",
                )
                .unwrap()
        };

        let dest_int = dest.into_int_value();
        let store_val = if dest_int.get_type().get_bit_width() == bits {
            dest_int
        } else if dest_int.get_type().get_bit_width() > bits {
            bin.builder
                .build_int_truncate(dest_int, val_ty, "trunc")
                .unwrap()
        } else {
            bin.builder
                .build_int_z_extend(dest_int, val_ty, "extend")
                .unwrap()
        };
        bin.builder.build_store(val_ptr, store_val).unwrap();

        let row_size_const = i32_ty.const_int(row_size as u64, false);

        // Check if row already exists.
        let db_find = bin.module.get_function("db_find_i64").unwrap();
        let iter = bin
            .builder
            .build_call(
                db_find,
                &[
                    receiver.into(),
                    receiver.into(),
                    table_name.into(),
                    slot_i64.into(),
                ],
                "iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let found = bin
            .builder
            .build_int_compare(IntPredicate::SGE, iter, i32_ty.const_zero(), "found")
            .unwrap();

        let update_bb = bin.context.append_basic_block(function, "db_update");
        let insert_bb = bin.context.append_basic_block(function, "db_insert");
        let done_bb = bin.context.append_basic_block(function, "db_done");

        bin.builder
            .build_conditional_branch(found, update_bb, insert_bb)
            .unwrap();

        // UPDATE existing row.
        bin.builder.position_at_end(update_bb);
        let db_update = bin.module.get_function("db_update_i64").unwrap();
        bin.builder
            .build_call(
                db_update,
                &[iter.into(), receiver.into(), row_buf.into(), row_size_const.into()],
                "",
            )
            .unwrap();
        bin.builder.build_unconditional_branch(done_bb).unwrap();

        // INSERT new row.
        bin.builder.position_at_end(insert_bb);
        let db_store = bin.module.get_function("db_store_i64").unwrap();
        bin.builder
            .build_call(
                db_store,
                &[
                    receiver.into(),
                    table_name.into(),
                    receiver.into(),
                    slot_i64.into(),
                    row_buf.into(),
                    row_size_const.into(),
                ],
                "",
            )
            .unwrap();
        bin.builder.build_unconditional_branch(done_bb).unwrap();

        bin.builder.position_at_end(done_bb);
    }

    fn storage_delete(
        &self,
        bin: &Binary<'a>,
        ty: &Type,
        slot: &mut IntValue<'a>,
        function: FunctionValue<'a>,
    ) {
        todo!("antelope: storage_delete")
    }

    fn set_storage_string(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue<'a>,
        slot: PointerValue<'a>,
        dest: BasicValueEnum<'a>,
    ) {
        todo!("antelope: set_storage_string")
    }

    fn get_storage_string(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue,
        slot: PointerValue<'a>,
    ) -> PointerValue<'a> {
        todo!("antelope: get_storage_string")
    }

    fn set_storage_extfunc(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue,
        slot: PointerValue,
        dest: PointerValue,
        dest_ty: BasicTypeEnum,
    ) {
        todo!("antelope: set_storage_extfunc")
    }

    fn get_storage_extfunc(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue,
        slot: PointerValue<'a>,
    ) -> PointerValue<'a> {
        todo!("antelope: get_storage_extfunc")
    }

    fn get_storage_bytes_subscript(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue,
        slot: IntValue<'a>,
        index: IntValue<'a>,
        loc: Loc,
    ) -> IntValue<'a> {
        todo!("antelope: get_storage_bytes_subscript")
    }

    fn set_storage_bytes_subscript(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue,
        slot: IntValue<'a>,
        index: IntValue<'a>,
        value: IntValue<'a>,
        loc: Loc,
    ) {
        todo!("antelope: set_storage_bytes_subscript")
    }

    fn storage_subscript(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue<'a>,
        ty: &Type,
        slot: IntValue<'a>,
        index: BasicValueEnum<'a>,
    ) -> IntValue<'a> {
        todo!("antelope: storage_subscript")
    }

    fn storage_push(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue<'a>,
        ty: &Type,
        slot: IntValue<'a>,
        val: Option<BasicValueEnum<'a>>,
    ) -> BasicValueEnum<'a> {
        todo!("antelope: storage_push")
    }

    fn storage_pop(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue<'a>,
        ty: &Type,
        slot: IntValue<'a>,
        load: bool,
        loc: Loc,
    ) -> Option<BasicValueEnum<'a>> {
        todo!("antelope: storage_pop")
    }

    fn storage_array_length(
        &self,
        _bin: &Binary<'a>,
        _function: FunctionValue,
        _slot: IntValue<'a>,
        _elem_ty: &Type,
    ) -> IntValue<'a> {
        todo!("antelope: storage_array_length")
    }

    /// Hash using Antelope's sha256 host function.
    /// Used for mapping key slot derivation. Not actual keccak256 — this is fine
    /// for internal storage slot computation (only needs to be deterministic and
    /// collision-resistant). User-callable keccak256() would need a software impl.
    fn keccak256_hash(
        &self,
        bin: &Binary<'a>,
        src: PointerValue,
        length: IntValue,
        dest: PointerValue,
    ) {
        let sha256_fn = bin.module.get_function("sha256").unwrap();
        let len_i32 = if length.get_type().get_bit_width() == 32 {
            length
        } else {
            bin.builder
                .build_int_truncate(length, bin.context.i32_type(), "len32")
                .unwrap()
        };
        bin.builder
            .build_call(sha256_fn, &[src.into(), len_i32.into(), dest.into()], "")
            .unwrap();
    }

    /// Print a string by calling the Antelope `prints_l(msg, len)` host function.
    fn print<'b>(&self, bin: &Binary<'b>, string: PointerValue<'b>, length: IntValue<'b>) {
        let prints_l = bin.module.get_function("prints_l").unwrap();

        let len_i32 = if length.get_type().get_bit_width() == 32 {
            length
        } else {
            bin.builder
                .build_int_truncate(length, bin.context.i32_type(), "len32")
                .unwrap()
        };

        bin.builder
            .build_call(prints_l, &[string.into(), len_i32.into()], "")
            .unwrap();
    }

    fn return_empty_abi(&self, bin: &Binary) {}

    fn return_code<'b>(&self, bin: &'b Binary, ret: IntValue<'b>) {}

    fn assert_failure(&self, bin: &Binary, data: PointerValue, length: IntValue) {
        let eosio_assert = bin.module.get_function("eosio_assert").unwrap();
        let zero = bin.context.i32_type().const_zero();
        let msg = bin.emit_global_string("assert_failure", b"assertion failed\0", true);
        bin.builder
            .build_call(eosio_assert, &[zero.into(), msg.into()], "")
            .unwrap();
        bin.builder.build_unreachable().unwrap();
    }

    fn builtin_function(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue<'a>,
        builtin_func: &Function,
        args: &[BasicMetadataValueEnum<'a>],
        first_arg_type: Option<BasicTypeEnum>,
    ) -> Option<BasicValueEnum<'a>> {
        todo!("antelope: builtin_function")
    }

    fn create_contract<'b>(
        &mut self,
        bin: &Binary<'b>,
        function: FunctionValue<'b>,
        success: Option<&mut BasicValueEnum<'b>>,
        contract_no: usize,
        address: PointerValue<'b>,
        encoded_args: BasicValueEnum<'b>,
        encoded_args_len: BasicValueEnum<'b>,
        contract_args: ContractArgs<'b>,
        loc: Loc,
    ) {
        todo!("antelope: create_contract")
    }

    fn external_call<'b>(
        &self,
        bin: &Binary<'b>,
        function: FunctionValue<'b>,
        success: Option<&mut BasicValueEnum<'b>>,
        payload: PointerValue<'b>,
        payload_len: IntValue<'b>,
        address: Option<BasicValueEnum<'b>>,
        contract_args: ContractArgs<'b>,
        ty: CallTy,
        loc: Loc,
    ) {
        todo!("antelope: external_call")
    }

    fn value_transfer<'b>(
        &self,
        _bin: &Binary<'b>,
        _function: FunctionValue,
        _success: Option<&mut BasicValueEnum<'b>>,
        _address: PointerValue<'b>,
        _value: IntValue<'b>,
        loc: Loc,
    ) {
        unimplemented!("antelope: value_transfer not supported")
    }

    fn builtin<'b>(
        &self,
        bin: &Binary<'b>,
        expr: &Expression,
        vartab: &HashMap<usize, Variable<'b>>,
        function: FunctionValue<'b>,
    ) -> BasicValueEnum<'b> {
        todo!("antelope: builtin expressions")
    }

    fn return_data<'b>(&self, bin: &Binary<'b>, function: FunctionValue<'b>) -> PointerValue<'b> {
        todo!("antelope: return_data")
    }

    fn value_transferred<'b>(&self, bin: &Binary<'b>) -> IntValue<'b> {
        unimplemented!("antelope: value_transferred not supported")
    }

    fn selfdestruct<'b>(&self, bin: &Binary<'b>, addr: ArrayValue<'b>) {
        unimplemented!("antelope: selfdestruct not supported")
    }

    fn hash<'b>(
        &self,
        bin: &Binary<'b>,
        function: FunctionValue<'b>,
        hash: HashTy,
        string: PointerValue<'b>,
        length: IntValue<'b>,
    ) -> IntValue<'b> {
        todo!("antelope: hash")
    }

    fn emit_event<'b>(
        &self,
        bin: &Binary<'b>,
        function: FunctionValue<'b>,
        data: BasicValueEnum<'b>,
        topics: &[BasicValueEnum<'b>],
    ) {
        todo!("antelope: emit_event")
    }

    fn return_abi_data<'b>(
        &self,
        bin: &Binary<'b>,
        data: PointerValue<'b>,
        data_len: BasicValueEnum<'b>,
    ) {
        // Antelope actions don't return ABI data; no-op.
    }
}
