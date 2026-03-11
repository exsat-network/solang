// SPDX-License-Identifier: Apache-2.0

use crate::codegen::cfg::HashTy;
use crate::codegen::{Builtin, Expression};
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
// Storage model: one "state" table per contract.
// Lookup via idx256 secondary index (full 256-bit slot hash).
// Auto-increment primary key (like CDT available_primary_key).
// Row data = raw value bytes only.
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

    /// Load a value from Antelope table storage via idx256 secondary index.
    ///
    /// 1. receiver = load __receiver global
    /// 2. Convert slot to 256-bit hash, store to stack buffer
    /// 3. sec_iter = db_idx256_find_secondary(receiver, receiver, table, slot_buf, 2, &pk)
    /// 4. if sec_iter >= 0: db_find_i64(pk) → db_get_i64 → return value
    /// 5. else: return zero
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
        let i256_ty = bin.context.custom_width_int_type(256);

        let bits = ty.bits(bin.ns) as u32;
        let byte_size = (bits + 7) / 8;

        // Load receiver from global.
        let receiver_global = AntelopeTarget::get_receiver_global(bin);
        let receiver = bin
            .builder
            .build_load(i64_ty, receiver_global.as_pointer_value(), "receiver")
            .unwrap()
            .into_int_value();

        let table_name = i64_ty.const_int(STATE_TABLE_NAME, false);

        // Convert slot to 256-bit value and store to stack buffer.
        let slot_i256 = if slot.get_type().get_bit_width() == 256 {
            *slot
        } else if slot.get_type().get_bit_width() > 256 {
            bin.builder
                .build_int_truncate(*slot, i256_ty, "slot256")
                .unwrap()
        } else {
            bin.builder
                .build_int_z_extend(*slot, i256_ty, "slot256")
                .unwrap()
        };

        let slot_buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(32, false),
                "slot_buf",
            )
            .unwrap();
        bin.builder.build_store(slot_buf, slot_i256).unwrap();

        // Allocate output for primary key.
        let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();

        // Look up via idx256 secondary index.
        let db_idx256_find = bin
            .module
            .get_function("db_idx256_find_secondary")
            .unwrap();
        let data_len = i32_ty.const_int(2, false); // 2 x uint128_t = 256 bits
        let sec_iter = bin
            .builder
            .build_call(
                db_idx256_find,
                &[
                    receiver.into(),
                    receiver.into(),
                    table_name.into(),
                    slot_buf.into(),
                    data_len.into(),
                    pk_out.into(),
                ],
                "sec_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // Check if found (iter >= 0).
        let found = bin
            .builder
            .build_int_compare(
                IntPredicate::SGE,
                sec_iter,
                i32_ty.const_zero(),
                "found",
            )
            .unwrap();

        let found_bb = bin.context.append_basic_block(function, "idx_found");
        let notfound_bb = bin.context.append_basic_block(function, "idx_notfound");
        let merge_bb = bin.context.append_basic_block(function, "idx_merge");

        bin.builder
            .build_conditional_branch(found, found_bb, notfound_bb)
            .unwrap();

        // FOUND: look up primary row by pk, then read value.
        bin.builder.position_at_end(found_bb);

        let val_ty = bin.context.custom_width_int_type(bits);
        let pk = bin
            .builder
            .build_load(i64_ty, pk_out, "pk")
            .unwrap()
            .into_int_value();

        // Find primary row by pk.
        let db_find = bin.module.get_function("db_find_i64").unwrap();
        let pri_iter = bin
            .builder
            .build_call(
                db_find,
                &[
                    receiver.into(),
                    receiver.into(),
                    table_name.into(),
                    pk.into(),
                ],
                "pri_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // Read row data: [pk: u64, slot_hash: checksum256, value: N bytes].
        let row_size = 8 + 32 + byte_size; // pk(8) + hash(32) + value(N)
        let row_buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(row_size as u64, false),
                "row_buf",
            )
            .unwrap();

        let db_get = bin.module.get_function("db_get_i64").unwrap();
        bin.builder
            .build_call(
                db_get,
                &[
                    pri_iter.into(),
                    row_buf.into(),
                    i32_ty.const_int(row_size as u64, false).into(),
                ],
                "",
            )
            .unwrap();

        // Value starts at offset 40 (after pk + slot_hash).
        let val_ptr = unsafe {
            bin.builder
                .build_gep(
                    bin.context.i8_type(),
                    row_buf,
                    &[i32_ty.const_int(40, false)],
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

    /// Store a value to Antelope table storage via idx256 secondary index.
    ///
    /// 1. receiver = load __receiver global
    /// 2. Convert slot to 256-bit hash buffer
    /// 3. sec_iter = db_idx256_find_secondary(receiver, receiver, table, slot_buf, 2, &pk)
    /// 4. if found: db_find_i64(pk) → db_update_i64(pri_iter, receiver, &val, size)
    /// 5. else: new_pk = available_primary_key() via db_end_i64/db_previous_i64
    ///          db_store_i64(new_pk, &val) + db_idx256_store(new_pk, slot_buf)
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
        let i256_ty = bin.context.custom_width_int_type(256);

        let bits = ty.bits(bin.ns) as u32;
        let byte_size = (bits + 7) / 8;

        // Load receiver.
        let receiver_global = AntelopeTarget::get_receiver_global(bin);
        let receiver = bin
            .builder
            .build_load(i64_ty, receiver_global.as_pointer_value(), "receiver")
            .unwrap()
            .into_int_value();

        let table_name = i64_ty.const_int(STATE_TABLE_NAME, false);

        // Convert slot to 256-bit value and store to stack buffer.
        let slot_i256 = if slot.get_type().get_bit_width() == 256 {
            *slot
        } else if slot.get_type().get_bit_width() > 256 {
            bin.builder
                .build_int_truncate(*slot, i256_ty, "slot256")
                .unwrap()
        } else {
            bin.builder
                .build_int_z_extend(*slot, i256_ty, "slot256")
                .unwrap()
        };

        let slot_buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(32, false),
                "slot_buf",
            )
            .unwrap();
        bin.builder.build_store(slot_buf, slot_i256).unwrap();

        // Row format: [pk: u64, slot_hash: checksum256, value: N bytes].
        let val_ty = bin.context.custom_width_int_type(bits);
        let row_size = 8 + 32 + byte_size; // pk(8) + hash(32) + value(N)
        let row_buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(row_size as u64, false),
                "row_buf",
            )
            .unwrap();

        // Write slot_hash at offset 8.
        let hash_ptr = unsafe {
            bin.builder
                .build_gep(
                    bin.context.i8_type(),
                    row_buf,
                    &[i32_ty.const_int(8, false)],
                    "hash_ptr",
                )
                .unwrap()
        };
        bin.builder.build_store(hash_ptr, slot_i256).unwrap();

        // Write value at offset 40 (8 + 32).
        let val_ptr = unsafe {
            bin.builder
                .build_gep(
                    bin.context.i8_type(),
                    row_buf,
                    &[i32_ty.const_int(40, false)],
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
        let data_len = i32_ty.const_int(2, false); // 2 x uint128_t = 256 bits

        // Look up via idx256 secondary index.
        let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();
        let db_idx256_find = bin
            .module
            .get_function("db_idx256_find_secondary")
            .unwrap();
        let sec_iter = bin
            .builder
            .build_call(
                db_idx256_find,
                &[
                    receiver.into(),
                    receiver.into(),
                    table_name.into(),
                    slot_buf.into(),
                    data_len.into(),
                    pk_out.into(),
                ],
                "sec_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let found = bin
            .builder
            .build_int_compare(
                IntPredicate::SGE,
                sec_iter,
                i32_ty.const_zero(),
                "found",
            )
            .unwrap();

        let update_bb = bin.context.append_basic_block(function, "idx_update");
        let insert_bb = bin.context.append_basic_block(function, "idx_insert");
        let done_bb = bin.context.append_basic_block(function, "idx_done");

        bin.builder
            .build_conditional_branch(found, update_bb, insert_bb)
            .unwrap();

        // UPDATE existing row: write pk at offset 0, find primary, then update.
        bin.builder.position_at_end(update_bb);
        let pk = bin
            .builder
            .build_load(i64_ty, pk_out, "pk")
            .unwrap()
            .into_int_value();
        // Write pk at offset 0 of row_buf.
        bin.builder.build_store(row_buf, pk).unwrap();

        let db_find = bin.module.get_function("db_find_i64").unwrap();
        let pri_iter = bin
            .builder
            .build_call(
                db_find,
                &[
                    receiver.into(),
                    receiver.into(),
                    table_name.into(),
                    pk.into(),
                ],
                "pri_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();
        let db_update = bin.module.get_function("db_update_i64").unwrap();
        bin.builder
            .build_call(
                db_update,
                &[
                    pri_iter.into(),
                    receiver.into(),
                    row_buf.into(),
                    row_size_const.into(),
                ],
                "",
            )
            .unwrap();
        bin.builder.build_unconditional_branch(done_bb).unwrap();

        // INSERT new row with auto-increment primary key.
        // Uses cached __next_pk global: UINT64_MAX sentinel means "compute from DB".
        // After first compute, just increment the cached value for each insert.
        bin.builder.position_at_end(insert_bb);

        let pk_global = AntelopeTarget::get_next_pk_global(bin);
        let cached_pk = bin
            .builder
            .build_load(i64_ty, pk_global.as_pointer_value(), "cached_pk")
            .unwrap()
            .into_int_value();

        let sentinel = i64_ty.const_all_ones(); // UINT64_MAX
        let need_init = bin
            .builder
            .build_int_compare(IntPredicate::EQ, cached_pk, sentinel, "need_init")
            .unwrap();

        let init_bb = bin.context.append_basic_block(function, "pk_init");
        let use_cached_bb = bin.context.append_basic_block(function, "pk_cached");
        let do_insert_bb = bin.context.append_basic_block(function, "do_insert");

        bin.builder
            .build_conditional_branch(need_init, init_bb, use_cached_bb)
            .unwrap();

        // INIT: compute next pk from database via db_end_i64/db_previous_i64.
        bin.builder.position_at_end(init_bb);
        let db_end = bin.module.get_function("db_end_i64").unwrap();
        let end_iter = bin
            .builder
            .build_call(
                db_end,
                &[receiver.into(), receiver.into(), table_name.into()],
                "end_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // db_end_i64 returns -1 for empty table, < -1 for valid end iterator.
        let end_neg = bin
            .builder
            .build_int_compare(
                IntPredicate::EQ,
                end_iter,
                i32_ty.const_int(u64::MAX, true), // -1
                "end_neg",
            )
            .unwrap();

        let empty_bb = bin.context.append_basic_block(function, "table_empty");
        let has_rows_bb = bin.context.append_basic_block(function, "table_has_rows");
        let init_done_bb = bin.context.append_basic_block(function, "pk_init_done");

        bin.builder
            .build_conditional_branch(end_neg, empty_bb, has_rows_bb)
            .unwrap();

        // Table empty: start at pk = 0.
        bin.builder.position_at_end(empty_bb);
        let pk_zero = i64_ty.const_zero();
        bin.builder
            .build_unconditional_branch(init_done_bb)
            .unwrap();

        // Table has rows: get last pk via db_previous_i64, use pk + 1.
        bin.builder.position_at_end(has_rows_bb);
        let last_pk_out = bin.builder.build_alloca(i64_ty, "last_pk_out").unwrap();
        let db_previous = bin.module.get_function("db_previous_i64").unwrap();
        bin.builder
            .build_call(
                db_previous,
                &[end_iter.into(), last_pk_out.into()],
                "",
            )
            .unwrap();
        let last_pk = bin
            .builder
            .build_load(i64_ty, last_pk_out, "last_pk")
            .unwrap()
            .into_int_value();
        let pk_from_db = bin
            .builder
            .build_int_add(last_pk, i64_ty.const_int(1, false), "pk_from_db")
            .unwrap();
        bin.builder
            .build_unconditional_branch(init_done_bb)
            .unwrap();

        // Merge init result.
        bin.builder.position_at_end(init_done_bb);
        let init_pk = bin.builder.build_phi(i64_ty, "init_pk").unwrap();
        init_pk.add_incoming(&[(&pk_zero, empty_bb), (&pk_from_db, has_rows_bb)]);
        let init_pk_val = init_pk.as_basic_value().into_int_value();
        bin.builder
            .build_unconditional_branch(do_insert_bb)
            .unwrap();

        // USE CACHED: just use the cached value directly.
        bin.builder.position_at_end(use_cached_bb);
        bin.builder
            .build_unconditional_branch(do_insert_bb)
            .unwrap();

        // Do the actual insert with the chosen pk, then increment __next_pk.
        bin.builder.position_at_end(do_insert_bb);
        let new_pk = bin.builder.build_phi(i64_ty, "new_pk").unwrap();
        new_pk.add_incoming(&[(&init_pk_val, init_done_bb), (&cached_pk, use_cached_bb)]);
        let new_pk_val = new_pk.as_basic_value().into_int_value();

        // Write new_pk at offset 0 of row_buf.
        bin.builder.build_store(row_buf, new_pk_val).unwrap();

        // Increment and store back to __next_pk for next insert.
        let next_pk_inc = bin
            .builder
            .build_int_add(new_pk_val, i64_ty.const_int(1, false), "next_pk_inc")
            .unwrap();
        bin.builder
            .build_store(pk_global.as_pointer_value(), next_pk_inc)
            .unwrap();

        // db_store_i64(scope, table, payer, id, data, len)
        let db_store = bin.module.get_function("db_store_i64").unwrap();
        bin.builder
            .build_call(
                db_store,
                &[
                    receiver.into(),
                    table_name.into(),
                    receiver.into(),
                    new_pk_val.into(),
                    row_buf.into(),
                    row_size_const.into(),
                ],
                "",
            )
            .unwrap();

        // db_idx256_store(scope, table, payer, id, data, data_len)
        let db_idx256_store = bin.module.get_function("db_idx256_store").unwrap();
        bin.builder
            .build_call(
                db_idx256_store,
                &[
                    receiver.into(),
                    table_name.into(),
                    receiver.into(),
                    new_pk_val.into(),
                    slot_buf.into(),
                    data_len.into(),
                ],
                "",
            )
            .unwrap();

        bin.builder.build_unconditional_branch(done_bb).unwrap();

        bin.builder.position_at_end(done_bb);
    }

    /// Delete a value from Antelope table storage via idx256 secondary index.
    ///
    /// 1. Find via idx256: db_idx256_find_secondary(slot_hash) → sec_iter, pk
    /// 2. If found: db_find_i64(pk) → pri_iter, then db_remove_i64(pri_iter) + db_idx256_remove(sec_iter)
    /// 3. If not found: no-op (deleting non-existent slot is fine)
    fn storage_delete(
        &self,
        bin: &Binary<'a>,
        ty: &Type,
        slot: &mut IntValue<'a>,
        function: FunctionValue<'a>,
    ) {
        let i32_ty = bin.context.i32_type();
        let i64_ty = bin.context.i64_type();
        let i256_ty = bin.context.custom_width_int_type(256);

        // Load receiver.
        let receiver_global = AntelopeTarget::get_receiver_global(bin);
        let receiver = bin
            .builder
            .build_load(i64_ty, receiver_global.as_pointer_value(), "receiver")
            .unwrap()
            .into_int_value();

        let table_name = i64_ty.const_int(STATE_TABLE_NAME, false);

        // Convert slot to 256-bit value and store to stack buffer.
        let slot_i256 = if slot.get_type().get_bit_width() == 256 {
            *slot
        } else if slot.get_type().get_bit_width() > 256 {
            bin.builder
                .build_int_truncate(*slot, i256_ty, "slot256")
                .unwrap()
        } else {
            bin.builder
                .build_int_z_extend(*slot, i256_ty, "slot256")
                .unwrap()
        };

        let slot_buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(32, false),
                "slot_buf",
            )
            .unwrap();
        bin.builder.build_store(slot_buf, slot_i256).unwrap();

        // Look up via idx256.
        let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();
        let db_idx256_find = bin
            .module
            .get_function("db_idx256_find_secondary")
            .unwrap();
        let data_len = i32_ty.const_int(2, false);
        let sec_iter = bin
            .builder
            .build_call(
                db_idx256_find,
                &[
                    receiver.into(),
                    receiver.into(),
                    table_name.into(),
                    slot_buf.into(),
                    data_len.into(),
                    pk_out.into(),
                ],
                "sec_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let found = bin
            .builder
            .build_int_compare(
                IntPredicate::SGE,
                sec_iter,
                i32_ty.const_zero(),
                "found",
            )
            .unwrap();

        let delete_bb = bin.context.append_basic_block(function, "del_found");
        let done_bb = bin.context.append_basic_block(function, "del_done");

        bin.builder
            .build_conditional_branch(found, delete_bb, done_bb)
            .unwrap();

        // FOUND: remove both primary row and secondary index entry.
        bin.builder.position_at_end(delete_bb);

        let pk = bin
            .builder
            .build_load(i64_ty, pk_out, "pk")
            .unwrap()
            .into_int_value();

        // Find primary row iterator.
        let db_find = bin.module.get_function("db_find_i64").unwrap();
        let pri_iter = bin
            .builder
            .build_call(
                db_find,
                &[
                    receiver.into(),
                    receiver.into(),
                    table_name.into(),
                    pk.into(),
                ],
                "pri_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // db_remove_i64(pri_iter)
        let db_remove = bin.module.get_function("db_remove_i64").unwrap();
        bin.builder
            .build_call(db_remove, &[pri_iter.into()], "")
            .unwrap();

        // db_idx256_remove(sec_iter)
        let db_idx256_remove = bin.module.get_function("db_idx256_remove").unwrap();
        bin.builder
            .build_call(db_idx256_remove, &[sec_iter.into()], "")
            .unwrap();

        bin.builder.build_unconditional_branch(done_bb).unwrap();

        bin.builder.position_at_end(done_bb);
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

    /// Hash using Antelope's sha3 host function in keccak256 mode.
    /// Matches Ethereum's keccak256 for storage slot derivation.
    /// Requires CRYPTO_PRIMITIVES protocol feature (active on EOS mainnet).
    fn keccak256_hash(
        &self,
        bin: &Binary<'a>,
        src: PointerValue,
        length: IntValue,
        dest: PointerValue,
    ) {
        let sha3_fn = bin.module.get_function("sha3").unwrap();
        let i32_ty = bin.context.i32_type();
        let len_i32 = if length.get_type().get_bit_width() == 32 {
            length
        } else {
            bin.builder
                .build_int_truncate(length, i32_ty, "len32")
                .unwrap()
        };
        let hash_len = i32_ty.const_int(32, false); // checksum256 = 32 bytes
        let keccak_flag = i32_ty.const_int(1, false); // 1 = keccak256 mode
        bin.builder
            .build_call(
                sha3_fn,
                &[src.into(), len_i32.into(), dest.into(), hash_len.into(), keccak_flag.into()],
                "",
            )
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
        match expr {
            Expression::Builtin {
                kind: Builtin::AntelopeRequireAuth,
                args,
                ..
            } => {
                let account = crate::emit::expression::expression(
                    &AntelopeTarget,
                    bin,
                    &args[0],
                    vartab,
                    function,
                )
                .into_int_value();

                let require_auth_fn = bin.module.get_function("require_auth").unwrap();
                bin.builder
                    .build_call(require_auth_fn, &[account.into()], "")
                    .unwrap();

                // requireAuth returns void; return a dummy value.
                bin.context
                    .i64_type()
                    .const_zero()
                    .into()
            }
            Expression::Builtin {
                kind: Builtin::AntelopeSelf,
                ..
            } => {
                let i64_ty = bin.context.i64_type();
                let receiver_global = AntelopeTarget::get_receiver_global(bin);
                bin.builder
                    .build_load(i64_ty, receiver_global.as_pointer_value(), "self_recv")
                    .unwrap()
            }
            _ => panic!("antelope: unimplemented builtin expression: {expr:?}"),
        }
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
