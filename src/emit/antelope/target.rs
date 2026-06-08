// SPDX-License-Identifier: Apache-2.0

use crate::codegen::cfg::HashTy;
use crate::codegen::{Builtin, Expression};
use crate::emit::antelope::{AntelopeTarget, STATE_TABLE_NAME};
use crate::emit::binary::Binary;
use crate::emit::ContractArgs;
use crate::emit::{TargetRuntime, Variable};
use crate::sema::ast;
use crate::sema::ast::CallTy;
use crate::sema::ast::{Function, RetrieveType, Type};

use inkwell::types::{BasicTypeEnum, IntType};
use inkwell::values::{
    ArrayValue, BasicMetadataValueEnum, BasicValueEnum, FunctionValue, IntValue, PointerValue,
};
use inkwell::IntPredicate;

use solang_parser::pt::{Loc, StorageType};

use num_traits::{ToPrimitive, Zero};
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
        // Struct: load each field recursively at consecutive slots.
        if let Type::Struct(struct_type) = ty {
            let struct_def = struct_type.definition(bin.ns);
            let llvm_ty = bin.llvm_type(ty);
            let struct_ptr = bin.build_alloca(function, llvm_ty, "struct_alloc");

            let mut current_slot = *slot;
            for (i, field) in struct_def.fields.iter().enumerate() {
                if field.infinite_size {
                    continue;
                }
                let field_val =
                    self.storage_load(bin, &field.ty, &mut current_slot, function, storage_type);
                let field_ptr = bin
                    .builder
                    .build_struct_gep(llvm_ty.into_struct_type(), struct_ptr, i as u32, "field_ptr")
                    .unwrap();
                bin.builder.build_store(field_ptr, field_val).unwrap();
                // Advance slot by number of storage slots this field occupies.
                let slots = field.ty.storage_slots(bin.ns);
                if !slots.is_zero() {
                    let slot_inc = bin
                        .context
                        .custom_width_int_type(256)
                        .const_int(slots.to_u64().unwrap_or(1), false);
                    current_slot = bin
                        .builder
                        .build_int_add(current_slot, slot_inc, "next_slot")
                        .unwrap();
                }
            }
            return bin
                .builder
                .build_load(llvm_ty, struct_ptr, "struct_loaded")
                .unwrap();
        }

        // String/DynamicBytes: variable-length row.
        if matches!(ty, Type::String | Type::DynamicBytes) {
            return self
                .storage_load_string(bin, slot, function)
                .into();
        }

        let i32_ty = bin.context.i32_type();
        let i256_ty = bin.context.custom_width_int_type(256);

        let bits = ty.bits(bin.ns) as u32;
        let byte_size = (bits + 7) / 8;
        let val_ty = bin.context.custom_width_int_type(bits);

        // Convert slot to a 256-bit value for the shared helper.
        let slot_i256 = if slot.get_type().get_bit_width() == 256 {
            *slot
        } else if slot.get_type().get_bit_width() > 256 {
            bin.builder.build_int_truncate(*slot, i256_ty, "slot256").unwrap()
        } else {
            bin.builder.build_int_z_extend(*slot, i256_ty, "slot256").unwrap()
        };

        // Pre-zero the value buffer so an unset slot reads as 0, then let the shared
        // helper overwrite it on a hit. Collapses the inline find/get sequence to a call.
        let buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(byte_size as u64, false),
                "load_buf",
            )
            .unwrap();
        bin.builder.build_store(buf, val_ty.const_zero()).unwrap();

        let helper = bin.module.get_function("__antelope_load_slot").unwrap();
        bin.builder
            .build_call(
                helper,
                &[
                    slot_i256.into(),
                    buf.into(),
                    i32_ty.const_int(byte_size as u64, false).into(),
                ],
                "",
            )
            .unwrap();

        bin.builder.build_load(val_ty, buf, "storage_val").unwrap()
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
        // Struct: store each field recursively at consecutive slots.
        if let Type::Struct(struct_type) = ty {
            let struct_def = struct_type.definition(bin.ns);
            let llvm_ty = bin.llvm_type(ty);

            // dest may be a pointer to the struct (heap-allocated) or a struct value.
            let struct_ptr = if dest.is_pointer_value() {
                // Already a pointer — use it directly.
                dest.into_pointer_value()
            } else {
                // Struct value — store to temp alloca so we can GEP fields.
                let tmp = bin.build_alloca(function, llvm_ty, "struct_tmp");
                bin.builder.build_store(tmp, dest).unwrap();
                tmp
            };

            let mut current_slot = *slot;
            for (i, field) in struct_def.fields.iter().enumerate() {
                if field.infinite_size {
                    continue;
                }
                let field_ptr = bin
                    .builder
                    .build_struct_gep(llvm_ty.into_struct_type(), struct_ptr, i as u32, "field_ptr")
                    .unwrap();
                let field_val = bin
                    .builder
                    .build_load(bin.llvm_type(&field.ty), field_ptr, "field_val")
                    .unwrap();
                self.storage_store(
                    bin,
                    &field.ty,
                    existing,
                    &mut current_slot,
                    field_val,
                    function,
                    storage_type,
                );
                let slots = field.ty.storage_slots(bin.ns);
                if !slots.is_zero() {
                    let slot_inc = bin
                        .context
                        .custom_width_int_type(256)
                        .const_int(slots.to_u64().unwrap_or(1), false);
                    current_slot = bin
                        .builder
                        .build_int_add(current_slot, slot_inc, "next_slot")
                        .unwrap();
                }
            }
            return;
        }

        // String/DynamicBytes: variable-length row.
        if matches!(ty, Type::String | Type::DynamicBytes) {
            self.storage_store_string(bin, slot, dest, function);
            return;
        }

        let i32_ty = bin.context.i32_type();
        let i256_ty = bin.context.custom_width_int_type(256);

        let bits = ty.bits(bin.ns) as u32;
        let byte_size = (bits + 7) / 8;
        let val_ty = bin.context.custom_width_int_type(bits);
        assert!(byte_size <= 127, "fixed-size value too large for 1-byte varuint32");

        // Convert slot to a 256-bit value for the shared helper.
        let slot_i256 = if slot.get_type().get_bit_width() == 256 {
            *slot
        } else if slot.get_type().get_bit_width() > 256 {
            bin.builder.build_int_truncate(*slot, i256_ty, "slot256").unwrap()
        } else {
            bin.builder.build_int_z_extend(*slot, i256_ty, "slot256").unwrap()
        };

        // Materialize the value into a little-endian byte buffer, then hand off to the
        // shared helper, which does the find + update-or-insert row write.
        let dest_int = dest.into_int_value();
        let store_val = if dest_int.get_type().get_bit_width() == bits {
            dest_int
        } else if dest_int.get_type().get_bit_width() > bits {
            bin.builder.build_int_truncate(dest_int, val_ty, "trunc").unwrap()
        } else {
            bin.builder.build_int_z_extend(dest_int, val_ty, "extend").unwrap()
        };
        let buf = bin
            .builder
            .build_array_alloca(
                bin.context.i8_type(),
                i32_ty.const_int(byte_size as u64, false),
                "store_buf",
            )
            .unwrap();
        bin.builder.build_store(buf, store_val).unwrap();

        let helper = bin.module.get_function("__antelope_store_slot").unwrap();
        bin.builder
            .build_call(
                helper,
                &[
                    slot_i256.into(),
                    buf.into(),
                    i32_ty.const_int(byte_size as u64, false).into(),
                ],
                "",
            )
            .unwrap();
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
        // Struct: delete each field recursively at consecutive slots.
        if let Type::Struct(struct_type) = ty {
            let struct_def = struct_type.definition(bin.ns);
            let mut current_slot = *slot;
            for field in &struct_def.fields {
                if field.infinite_size {
                    continue;
                }
                self.storage_delete(bin, &field.ty, &mut current_slot, function);
                let slots = field.ty.storage_slots(bin.ns);
                if !slots.is_zero() {
                    let slot_inc = bin
                        .context
                        .custom_width_int_type(256)
                        .const_int(slots.to_u64().unwrap_or(1), false);
                    current_slot = bin
                        .builder
                        .build_int_add(current_slot, slot_inc, "next_slot")
                        .unwrap();
                }
            }
            return;
        }

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
        // Load the slot as i256 from the pointer.
        let i256_ty = bin.context.custom_width_int_type(256);
        let slot_val = bin
            .builder
            .build_load(i256_ty, slot, "slot_val")
            .unwrap()
            .into_int_value();
        let mut slot_mut = slot_val;
        self.storage_store_string(bin, &mut slot_mut, dest.into(), function);
    }

    fn get_storage_string(
        &self,
        bin: &Binary<'a>,
        function: FunctionValue,
        slot: PointerValue<'a>,
    ) -> PointerValue<'a> {
        let i256_ty = bin.context.custom_width_int_type(256);
        let slot_val = bin
            .builder
            .build_load(i256_ty, slot, "slot_val")
            .unwrap()
            .into_int_value();
        let mut slot_mut = slot_val;
        self.storage_load_string(bin, &mut slot_mut, function)
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

    fn return_code<'b>(&self, bin: &'b Binary, _ret: IntValue<'b>) {
        // Antelope has no selector return-code path — the real entrypoint is the
        // hand-written `apply`, so `Instr::ReturnCode` only appears in the inherited
        // (dead) dispatch CFGs. Still, this must emit a terminator: an empty body left
        // the `fb_or_recv` block unterminated, producing invalid IR that crashed the
        // backend at -O none/less (it was only masked at -O default by global_dce).
        // Mirror the Polkadot target: abort via assert_failure, which ends in unreachable.
        let ptr_null = bin
            .context
            .ptr_type(inkwell::AddressSpace::default())
            .const_null();
        let zero = bin.context.i32_type().const_zero();
        self.assert_failure(bin, ptr_null, zero);
    }

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
            Expression::Builtin {
                kind: Builtin::AntelopeCode,
                ..
            } => {
                let i64_ty = bin.context.i64_type();
                let code_global = bin.module.get_global("__code").unwrap();
                bin.builder
                    .build_load(i64_ty, code_global.as_pointer_value(), "code_acct")
                    .unwrap()
            }
            Expression::Builtin {
                kind: Builtin::AntelopeRequireRecipient,
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

                let require_recipient_fn =
                    bin.module.get_function("require_recipient").unwrap();
                bin.builder
                    .build_call(require_recipient_fn, &[account.into()], "")
                    .unwrap();

                bin.context.i64_type().const_zero().into()
            }
            Expression::Builtin {
                kind: Builtin::AntelopeCall,
                args,
                ..
            } => {
                // antelope.call(contract, action_name, packed_data)
                // Serializes an Antelope action struct and calls send_inline.
                //
                // Antelope serialized action format:
                //   account:     uint64   (8 bytes)  — target contract
                //   action_name: uint64   (8 bytes)  — action name
                //   auth_count:  varuint32(1 byte)   — number of permission entries (we use 1)
                //   auth[0].actor:      uint64 (8 bytes) — self (current contract)
                //   auth[0].permission: uint64 (8 bytes) — eosio::name("active") = 0x3232EDA800000000
                //   data_len:    varuint32(1 byte)   — length of packed action data
                //   data:        bytes                — raw packed action data
                //
                // Total header = 8 + 8 + 1 + 8 + 8 + 1 = 34 bytes, then data.

                let i32_ty = bin.context.i32_type();
                let i64_ty = bin.context.i64_type();
                let i8_ty = bin.context.i8_type();

                let contract_account = crate::emit::expression::expression(
                    &AntelopeTarget,
                    bin,
                    &args[0],
                    vartab,
                    function,
                )
                .into_int_value();

                let action_name = crate::emit::expression::expression(
                    &AntelopeTarget,
                    bin,
                    &args[1],
                    vartab,
                    function,
                )
                .into_int_value();

                // The third argument is a bytes vector (pointer to vector struct).
                let data_vec = crate::emit::expression::expression(
                    &AntelopeTarget,
                    bin,
                    &args[2],
                    vartab,
                    function,
                );

                // Get data length and data pointer from the vector.
                // Vector layout: [length: u32, ...data]
                let data_len = bin.vector_len(data_vec);

                let data_ptr = bin.vector_bytes(data_vec);

                // Load receiver (self) for the authorization.
                let receiver_global = AntelopeTarget::get_receiver_global(bin);
                let self_account = bin
                    .builder
                    .build_load(i64_ty, receiver_global.as_pointer_value(), "self_acct")
                    .unwrap()
                    .into_int_value();

                let active_perm = i64_ty.const_int(crate::emit::antelope::string_to_name("active"), false);

                // Encode data_len as varuint32 to know its byte size.
                let encode_fn = bin.module.get_function("__encode_varuint32").unwrap();
                let vi_tmp = bin
                    .builder
                    .build_array_alloca(i8_ty, i32_ty.const_int(5, false), "vi_tmp")
                    .unwrap();
                let data_vi_size = bin
                    .builder
                    .build_call(encode_fn, &[vi_tmp.into(), data_len.into()], "dvi_sz")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_int_value();

                // Serialized action layout:
                //   account(8) + action_name(8) + auth_count(1=varuint for 1)
                //   + actor(8) + permission(8) + data_len(varuint) + data(N)
                // Fixed part = 8+8+1+8+8 = 33, then data_vi_size + data_len
                let fixed_part = i32_ty.const_int(33, false);
                let total_size = bin.builder.build_int_add(fixed_part, data_vi_size, "ts1").unwrap();
                let total_size = bin.builder.build_int_add(total_size, data_len, "total_size").unwrap();

                let malloc_fn = bin.module.get_function("__malloc").unwrap();
                let buf = bin
                    .builder
                    .build_call(malloc_fn, &[total_size.into()], "action_buf")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_pointer_value();

                // Write account (offset 0)
                bin.builder.build_store(buf, contract_account).unwrap();

                // Write action_name (offset 8)
                let off8 = unsafe {
                    bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(8, false)], "off8").unwrap()
                };
                bin.builder.build_store(off8, action_name).unwrap();

                // Write auth_count = 1 (offset 16, varuint32 for value 1 = single byte 0x01)
                let off16 = unsafe {
                    bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(16, false)], "off16").unwrap()
                };
                bin.builder
                    .build_store(off16, i8_ty.const_int(1, false))
                    .unwrap();

                // Write auth[0].actor = self (offset 17)
                let off17 = unsafe {
                    bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(17, false)], "off17").unwrap()
                };
                bin.builder.build_store(off17, self_account).unwrap();

                // Write auth[0].permission = active (offset 25)
                let off25 = unsafe {
                    bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(25, false)], "off25").unwrap()
                };
                bin.builder.build_store(off25, active_perm).unwrap();

                // Write data_len as varuint32 (offset 33)
                let off33 = unsafe {
                    bin.builder.build_gep(i8_ty, buf, &[fixed_part], "off33").unwrap()
                };
                bin.builder
                    .build_call(encode_fn, &[off33.into(), data_len.into()], "")
                    .unwrap();

                // Copy data after varuint32
                let data_offset = bin.builder.build_int_add(fixed_part, data_vi_size, "doff").unwrap();
                let data_dst = unsafe {
                    bin.builder.build_gep(i8_ty, buf, &[data_offset], "ddst").unwrap()
                };
                bin.builder
                    .build_memcpy(data_dst, 1, data_ptr, 1, data_len)
                    .unwrap();

                // Call send_inline(buf, total_size)
                let send_inline_fn = bin.module.get_function("send_inline").unwrap();
                bin.builder
                    .build_call(send_inline_fn, &[buf.into(), total_size.into()], "")
                    .unwrap();

                bin.context.i64_type().const_zero().into()
            }
            Expression::Builtin {
                kind: Builtin::AntelopeCallAuth,
                args,
                ..
            } => {
                // antelope.callauth(contract, action_name, data, actor, permission)
                let i32_ty = bin.context.i32_type();
                let i64_ty = bin.context.i64_type();
                let i8_ty = bin.context.i8_type();

                let contract_account = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[0], vartab, function,
                ).into_int_value();
                let action_name = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[1], vartab, function,
                ).into_int_value();
                let data_vec = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[2], vartab, function,
                );
                let actor = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[3], vartab, function,
                ).into_int_value();
                let permission = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[4], vartab, function,
                ).into_int_value();

                let data_len = bin.vector_len(data_vec);
                let data_ptr = bin.vector_bytes(data_vec);

                let encode_fn = bin.module.get_function("__encode_varuint32").unwrap();
                let vi_tmp = bin.builder
                    .build_array_alloca(i8_ty, i32_ty.const_int(5, false), "vi_tmp")
                    .unwrap();
                let data_vi_size = bin.builder
                    .build_call(encode_fn, &[vi_tmp.into(), data_len.into()], "dvi_sz")
                    .unwrap().try_as_basic_value().left().unwrap().into_int_value();

                let fixed_part = i32_ty.const_int(33, false);
                let total_size = bin.builder.build_int_add(fixed_part, data_vi_size, "ts1").unwrap();
                let total_size = bin.builder.build_int_add(total_size, data_len, "total_size").unwrap();

                let malloc_fn = bin.module.get_function("__malloc").unwrap();
                let buf = bin.builder
                    .build_call(malloc_fn, &[total_size.into()], "action_buf")
                    .unwrap().try_as_basic_value().left().unwrap().into_pointer_value();

                // account (offset 0)
                bin.builder.build_store(buf, contract_account).unwrap();
                // action_name (offset 8)
                let off8 = unsafe { bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(8, false)], "off8").unwrap() };
                bin.builder.build_store(off8, action_name).unwrap();
                // auth_count = 1 (offset 16)
                let off16 = unsafe { bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(16, false)], "off16").unwrap() };
                bin.builder.build_store(off16, i8_ty.const_int(1, false)).unwrap();
                // auth[0].actor (offset 17)
                let off17 = unsafe { bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(17, false)], "off17").unwrap() };
                bin.builder.build_store(off17, actor).unwrap();
                // auth[0].permission (offset 25)
                let off25 = unsafe { bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(25, false)], "off25").unwrap() };
                bin.builder.build_store(off25, permission).unwrap();
                // data_len varuint32 (offset 33)
                let off33 = unsafe { bin.builder.build_gep(i8_ty, buf, &[fixed_part], "off33").unwrap() };
                bin.builder.build_call(encode_fn, &[off33.into(), data_len.into()], "").unwrap();
                // data bytes
                let data_offset = bin.builder.build_int_add(fixed_part, data_vi_size, "doff").unwrap();
                let data_dst = unsafe { bin.builder.build_gep(i8_ty, buf, &[data_offset], "ddst").unwrap() };
                bin.builder.build_memcpy(data_dst, 1, data_ptr, 1, data_len).unwrap();

                let send_inline_fn = bin.module.get_function("send_inline").unwrap();
                bin.builder.build_call(send_inline_fn, &[buf.into(), total_size.into()], "").unwrap();

                bin.context.i64_type().const_zero().into()
            }
            Expression::Builtin {
                kind: Builtin::AntelopeSetPayer,
                args,
                ..
            } => {
                let payer = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[0], vartab, function,
                ).into_int_value();

                let payer_global = bin.module.get_global("__ram_payer").unwrap();
                bin.builder
                    .build_store(payer_global.as_pointer_value(), payer)
                    .unwrap();

                bin.context.i64_type().const_zero().into()
            }
            Expression::Builtin {
                kind: Builtin::AntelopeHasAuth,
                args,
                ..
            } => {
                let account = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[0], vartab, function,
                ).into_int_value();

                let has_auth_fn = bin.module.get_function("has_auth").unwrap();
                let result = bin.builder
                    .build_call(has_auth_fn, &[account.into()], "has_auth_result")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_int_value();

                // has_auth returns i32 (C bool); truncate to i1 for Solidity bool.
                bin.builder
                    .build_int_truncate(result, bin.context.bool_type(), "has_auth_bool")
                    .unwrap()
                    .into()
            }
            Expression::Builtin {
                kind: Builtin::AntelopeRequireAuth2,
                args,
                ..
            } => {
                let account = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[0], vartab, function,
                ).into_int_value();
                let permission = crate::emit::expression::expression(
                    &AntelopeTarget, bin, &args[1], vartab, function,
                ).into_int_value();

                let require_auth2_fn = bin.module.get_function("require_auth2").unwrap();
                bin.builder
                    .build_call(require_auth2_fn, &[account.into(), permission.into()], "")
                    .unwrap();

                bin.context.i64_type().const_zero().into()
            }
            Expression::Builtin {
                kind: Builtin::AntelopeTimestamp,
                ..
            } => {
                let current_time_fn = bin.module.get_function("current_time").unwrap();
                bin.builder
                    .build_call(current_time_fn, &[], "timestamp")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
            }
            Expression::Builtin {
                kind: Builtin::AntelopePack,
                args,
                ..
            } => {
                // antelope.pack(arg0, arg1, ...) → bytes memory
                // Serialises each argument in Antelope CDT little-endian format:
                //   integers  → N bytes stored directly (WASM is LE, so store is already LE)
                //   bool      → 1 byte (0 or 1)
                //   string/bytes → varuint32(len) + raw bytes
                //
                // Steps: evaluate all args, compute total byte count, malloc,
                // write each arg, return as a bytes vector.

                let i8_ty  = bin.context.i8_type();
                let i32_ty = bin.context.i32_type();

                let encode_fn = bin.module.get_function("__encode_varuint32").unwrap();
                let malloc_fn = bin.module.get_function("__malloc").unwrap();
                let vector_new_fn = bin.module.get_function("vector_new").unwrap();

                // Peel through ZeroExt/SignExt wrappers to get the declared type.
                // Storage-loaded variables are widened to Uint(256) by codegen, but
                // for packing we want the original declared type (e.g. Uint(64)).
                fn peel_type(e: &crate::codegen::Expression) -> crate::sema::ast::Type {
                    match e {
                        crate::codegen::Expression::ZeroExt { expr, .. }
                        | crate::codegen::Expression::SignExt { expr, .. } => peel_type(expr),
                        other => other.ty(),
                    }
                }

                // Evaluate all args once and pair with their declared (peeled) types.
                let arg_vals: Vec<(crate::sema::ast::Type, inkwell::values::BasicValueEnum)> = args
                    .iter()
                    .map(|a| {
                        let ty = peel_type(a);
                        let val = crate::emit::expression::expression(
                            &AntelopeTarget, bin, a, vartab, function,
                        );
                        (ty, val)
                    })
                    .collect();

                // Pass 1: compute total packed byte count.
                // Fixed-size widths come from the SHARED datastream_fixed_size (same
                // authority as the deserializer), so pack can never drift from it.
                // None = variable-length (string/bytes): varuint32(len) + raw bytes.
                let mut total = i32_ty.const_int(0, false);
                for (ty, val) in &arg_vals {
                    let fixed: Option<u64> =
                        AntelopeTarget::datastream_fixed_size(ty, bin).map(|n| n as u64);
                    if let Some(n) = fixed {
                        total = bin.builder.build_int_add(total, i32_ty.const_int(n, false), "").unwrap();
                    } else {
                        // string/bytes: varuint32(len) + len bytes
                        let data_len = bin.vector_len(*val);
                        let scratch = bin.builder.build_array_alloca(i8_ty, i32_ty.const_int(5, false), "vi_sc").unwrap();
                        let vi_sz = bin.builder
                            .build_call(encode_fn, &[scratch.into(), data_len.into()], "vi_sz")
                            .unwrap().try_as_basic_value().left().unwrap().into_int_value();
                        total = bin.builder.build_int_add(total, vi_sz, "").unwrap();
                        total = bin.builder.build_int_add(total, data_len, "").unwrap();
                    }
                }

                // Allocate output buffer.
                let buf = bin.builder
                    .build_call(malloc_fn, &[total.into()], "pack_buf")
                    .unwrap().try_as_basic_value().left().unwrap().into_pointer_value();

                // Pass 2: write each arg into buf.
                let mut offset = i32_ty.const_int(0, false);
                for (ty, val) in &arg_vals {
                    macro_rules! write_int {
                        ($nbytes:expr) => {{
                            let ptr = unsafe {
                                bin.builder.build_gep(i8_ty, buf, &[offset], "iptr").unwrap()
                            };
                            let int_val = val.into_int_value();
                            let target_bits = ($nbytes as u32) * 8;
                            let actual_bits = int_val.get_type().get_bit_width();
                            if actual_bits > target_bits {
                                let trunc = bin.builder.build_int_truncate(
                                    int_val,
                                    bin.context.custom_width_int_type(target_bits),
                                    "pack_trunc",
                                ).unwrap();
                                bin.builder.build_store(ptr, trunc).unwrap();
                            } else {
                                bin.builder.build_store(ptr, int_val).unwrap();
                            };
                            offset = bin.builder.build_int_add(
                                offset, i32_ty.const_int($nbytes, false), ""
                            ).unwrap();
                        }};
                    }
                    match ty {
                        crate::sema::ast::Type::Bool => {
                            let byte_val = bin.builder
                                .build_int_z_extend((*val).into_int_value(), i8_ty, "boolbyte")
                                .unwrap();
                            let ptr = unsafe {
                                bin.builder.build_gep(i8_ty, buf, &[offset], "bptr").unwrap()
                            };
                            bin.builder.build_store(ptr, byte_val).unwrap();
                            offset = bin.builder.build_int_add(offset, i32_ty.const_int(1, false), "").unwrap();
                        }
                        crate::sema::ast::Type::String | crate::sema::ast::Type::DynamicBytes => {
                            // Write varuint32(len) then copy bytes.
                            let data_len = bin.vector_len(*val);
                            let data_ptr = bin.vector_bytes(*val);
                            let vi_dst = unsafe {
                                bin.builder.build_gep(i8_ty, buf, &[offset], "vidst").unwrap()
                            };
                            let vi_sz = bin.builder
                                .build_call(encode_fn, &[vi_dst.into(), data_len.into()], "vi_sz2")
                                .unwrap().try_as_basic_value().left().unwrap().into_int_value();
                            let data_off = bin.builder.build_int_add(offset, vi_sz, "").unwrap();
                            let data_dst = unsafe {
                                bin.builder.build_gep(i8_ty, buf, &[data_off], "ddst").unwrap()
                            };
                            bin.builder.build_memcpy(data_dst, 1, data_ptr, 1, data_len).unwrap();
                            let field_total = bin.builder.build_int_add(vi_sz, data_len, "").unwrap();
                            offset = bin.builder.build_int_add(offset, field_total, "").unwrap();
                        }
                        // Every other supported type is fixed-size (int/uint of any
                        // width, bytesN, address, enum, value): write its N raw
                        // little-endian bytes. Size from the shared authority.
                        _ => {
                            let n = AntelopeTarget::datastream_fixed_size(ty, bin)
                                .expect("antelope.pack: variable-length type in fixed branch") as u64;
                            write_int!(n);
                        }
                    }
                }

                // Return as bytes vector: vector_new(total, 1, buf).
                bin.builder
                    .build_call(vector_new_fn, &[total.into(), i32_ty.const_int(1, false).into(), buf.into()], "packed_vec")
                    .unwrap().try_as_basic_value().left().unwrap()
            }
            // ===== Decode helpers =====
            // antelope.toUint64(bytes, offset), toInt64, toUint32, toUint128, toBytes32
            Expression::Builtin {
                kind: kind @ (Builtin::AntelopeToUint64
                    | Builtin::AntelopeToInt64
                    | Builtin::AntelopeToUint32
                    | Builtin::AntelopeToUint128
                    | Builtin::AntelopeToBytes32),
                args,
                ..
            } => {
                let i32_ty = bin.context.i32_type();
                let data = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function);
                let offset = crate::emit::expression::expression(&AntelopeTarget, bin, &args[1], vartab, function).into_int_value();
                let data_ptr = bin.vector_bytes(data);

                // GEP to data_ptr + offset
                let elem_ptr = unsafe {
                    bin.builder.build_gep(
                        bin.context.i8_type(),
                        data_ptr,
                        &[offset],
                        "elem_ptr",
                    ).unwrap()
                };

                match kind {
                    Builtin::AntelopeToUint64 | Builtin::AntelopeToInt64 => {
                        bin.builder.build_load(bin.context.i64_type(), elem_ptr, "decoded").unwrap()
                    }
                    Builtin::AntelopeToUint32 => {
                        bin.builder.build_load(i32_ty, elem_ptr, "decoded").unwrap()
                    }
                    Builtin::AntelopeToUint128 => {
                        bin.builder.build_load(bin.context.custom_width_int_type(128), elem_ptr, "decoded").unwrap()
                    }
                    Builtin::AntelopeToBytes32 => {
                        bin.builder.build_load(bin.context.custom_width_int_type(256), elem_ptr, "decoded").unwrap()
                    }
                    _ => unreachable!(),
                }
            }

            // antelope.toString(bytes, offset)
            Expression::Builtin {
                kind: Builtin::AntelopeToString,
                args,
                ..
            } => {
                let i32_ty = bin.context.i32_type();
                let i64_ty = bin.context.i64_type();

                let data = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function);
                let offset = crate::emit::expression::expression(&AntelopeTarget, bin, &args[1], vartab, function).into_int_value();
                let data_ptr = bin.vector_bytes(data);

                // Pointer to the varuint32 at offset
                let varuint_ptr = unsafe {
                    bin.builder.build_gep(bin.context.i8_type(), data_ptr, &[offset], "varuint_ptr").unwrap()
                };

                // Decode varuint32: returns packed u64 (low32=value, high32=bytes_read)
                let decode_fn = bin.module.get_function("__decode_varuint32").unwrap();
                let packed = bin.builder
                    .build_call(decode_fn, &[varuint_ptr.into()], "packed")
                    .unwrap().try_as_basic_value().left().unwrap().into_int_value();

                let str_len_i64 = bin.builder
                    .build_and(packed, i64_ty.const_int(0xFFFF_FFFF, false), "str_len_64").unwrap();
                let str_len = bin.builder
                    .build_int_truncate(str_len_i64, i32_ty, "str_len").unwrap();
                let bytes_read_i64 = bin.builder
                    .build_right_shift(packed, i64_ty.const_int(32, false), false, "br_64").unwrap();
                let bytes_read = bin.builder
                    .build_int_truncate(bytes_read_i64, i32_ty, "bytes_read").unwrap();

                // String data starts at offset + bytes_read
                let after_len = bin.builder.build_int_add(offset, bytes_read, "after_len").unwrap();
                let str_data_ptr = unsafe {
                    bin.builder.build_gep(bin.context.i8_type(), data_ptr, &[after_len], "str_data").unwrap()
                };

                // Create a vector (string) from the data
                let vector_new_fn = bin.module.get_function("vector_new").unwrap();
                bin.builder
                    .build_call(vector_new_fn, &[str_len.into(), i32_ty.const_int(1, false).into(), str_data_ptr.into()], "str_vec")
                    .unwrap().try_as_basic_value().left().unwrap()
            }

            // ===== Table read builtins =====

            // antelope.dbFind(code, scope, table, pk) -> int32 iterator
            Expression::Builtin {
                kind: Builtin::AntelopeDbFind,
                args,
                ..
            } => {
                let code = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function).into_int_value();
                let scope = crate::emit::expression::expression(&AntelopeTarget, bin, &args[1], vartab, function).into_int_value();
                let table = crate::emit::expression::expression(&AntelopeTarget, bin, &args[2], vartab, function).into_int_value();
                let pk = crate::emit::expression::expression(&AntelopeTarget, bin, &args[3], vartab, function).into_int_value();

                let db_find_fn = bin.module.get_function("db_find_i64").unwrap();
                bin.builder
                    .build_call(db_find_fn, &[code.into(), scope.into(), table.into(), pk.into()], "db_find")
                    .unwrap().try_as_basic_value().left().unwrap()
            }

            // antelope.dbLowerbound(code, scope, table, id) -> int32 iterator
            Expression::Builtin {
                kind: Builtin::AntelopeDbLowerbound,
                args,
                ..
            } => {
                let code = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function).into_int_value();
                let scope = crate::emit::expression::expression(&AntelopeTarget, bin, &args[1], vartab, function).into_int_value();
                let table = crate::emit::expression::expression(&AntelopeTarget, bin, &args[2], vartab, function).into_int_value();
                let id = crate::emit::expression::expression(&AntelopeTarget, bin, &args[3], vartab, function).into_int_value();

                let db_lb_fn = bin.module.get_function("db_lowerbound_i64").unwrap();
                bin.builder
                    .build_call(db_lb_fn, &[code.into(), scope.into(), table.into(), id.into()], "db_lb")
                    .unwrap().try_as_basic_value().left().unwrap()
            }

            // antelope.dbGet(iterator) -> bytes
            Expression::Builtin {
                kind: Builtin::AntelopeDbGet,
                args,
                ..
            } => {
                let i32_ty = bin.context.i32_type();
                let iterator = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function).into_int_value();

                let db_get_fn = bin.module.get_function("db_get_i64").unwrap();
                let ptr_ty = bin.context.ptr_type(inkwell::AddressSpace::default());

                // First call: get data size (pass null ptr, len 0)
                let data_size = bin.builder
                    .build_call(db_get_fn, &[iterator.into(), ptr_ty.const_null().into(), i32_ty.const_zero().into()], "data_size")
                    .unwrap().try_as_basic_value().left().unwrap().into_int_value();

                // Allocate buffer via __malloc
                let malloc_fn = bin.module.get_function("__malloc").unwrap();
                let buf = bin.builder
                    .build_call(malloc_fn, &[data_size.into()], "buf")
                    .unwrap().try_as_basic_value().left().unwrap().into_pointer_value();

                // Second call: read data into buffer
                bin.builder
                    .build_call(db_get_fn, &[iterator.into(), buf.into(), data_size.into()], "")
                    .unwrap();

                // Wrap as bytes vector
                let vector_new_fn = bin.module.get_function("vector_new").unwrap();
                bin.builder
                    .build_call(vector_new_fn, &[data_size.into(), i32_ty.const_int(1, false).into(), buf.into()], "row_bytes")
                    .unwrap().try_as_basic_value().left().unwrap()
            }

            // antelope.dbNext(iterator) -> int32 new_iterator; caches pk in __last_pk
            Expression::Builtin {
                kind: Builtin::AntelopeDbNext,
                args,
                ..
            } => {
                let i64_ty = bin.context.i64_type();
                let iterator = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function).into_int_value();

                // Alloca for pk output
                let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();

                let db_next_fn = bin.module.get_function("db_next_i64").unwrap();
                let next_iter = bin.builder
                    .build_call(db_next_fn, &[iterator.into(), pk_out.into()], "next_iter")
                    .unwrap().try_as_basic_value().left().unwrap().into_int_value();

                // Cache pk in __last_pk global
                let pk_val = bin.builder.build_load(i64_ty, pk_out, "pk_val").unwrap().into_int_value();
                let last_pk_global = bin.module.get_global("__last_pk").unwrap().as_pointer_value();
                bin.builder.build_store(last_pk_global, pk_val).unwrap();

                next_iter.into()
            }

            // antelope.lastPk() -> uint64
            Expression::Builtin {
                kind: Builtin::AntelopeLastPk,
                ..
            } => {
                let i64_ty = bin.context.i64_type();
                let last_pk_global = bin.module.get_global("__last_pk").unwrap().as_pointer_value();
                bin.builder.build_load(i64_ty, last_pk_global, "last_pk").unwrap()
            }

            // ===== Secondary index builtins =====
            // All share the same pattern: compute secondary table name, call host, cache pk

            // antelope.dbIdx64Find(code, scope, table, indexNum, key) -> int32
            // antelope.dbIdx64Lowerbound(code, scope, table, indexNum, key) -> int32
            Expression::Builtin {
                kind: kind @ (Builtin::AntelopeDbIdx64Find | Builtin::AntelopeDbIdx64Lowerbound),
                args,
                ..
            } => {
                let i64_ty = bin.context.i64_type();
                let code = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function).into_int_value();
                let scope = crate::emit::expression::expression(&AntelopeTarget, bin, &args[1], vartab, function).into_int_value();
                let table = crate::emit::expression::expression(&AntelopeTarget, bin, &args[2], vartab, function).into_int_value();
                let index_num = crate::emit::expression::expression(&AntelopeTarget, bin, &args[3], vartab, function).into_int_value();
                let key = crate::emit::expression::expression(&AntelopeTarget, bin, &args[4], vartab, function).into_int_value();

                // Compute secondary table name: (table & 0xFFFFFFFFFFFFFFF0) | (indexNum & 0xF)
                let mask = i64_ty.const_int(0xFFFFFFFFFFFFFFF0, false);
                let table_masked = bin.builder.build_and(table, mask, "tbl_masked").unwrap();
                let idx_mask = i64_ty.const_int(0xF, false);
                let idx_masked = bin.builder.build_and(index_num, idx_mask, "idx_masked").unwrap();
                let sec_table = bin.builder.build_or(table_masked, idx_masked, "sec_table").unwrap();

                // Alloca for key and pk output
                let key_ptr = bin.builder.build_alloca(i64_ty, "sec_key").unwrap();
                bin.builder.build_store(key_ptr, key).unwrap();
                let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();

                let host_fn_name = match kind {
                    Builtin::AntelopeDbIdx64Find => "db_idx64_find_secondary",
                    Builtin::AntelopeDbIdx64Lowerbound => "db_idx64_lowerbound",
                    _ => unreachable!(),
                };
                let host_fn = bin.module.get_function(host_fn_name).unwrap();
                let iter = bin.builder
                    .build_call(host_fn, &[code.into(), scope.into(), sec_table.into(), key_ptr.into(), pk_out.into()], "idx64_iter")
                    .unwrap().try_as_basic_value().left().unwrap().into_int_value();

                // Cache pk
                let pk_val = bin.builder.build_load(i64_ty, pk_out, "pk_val").unwrap().into_int_value();
                let last_pk_global = bin.module.get_global("__last_pk").unwrap().as_pointer_value();
                bin.builder.build_store(last_pk_global, pk_val).unwrap();

                iter.into()
            }

            // antelope.dbIdx128Find(code, scope, table, indexNum, key) -> int32
            // antelope.dbIdx128Lowerbound(code, scope, table, indexNum, key) -> int32
            Expression::Builtin {
                kind: kind @ (Builtin::AntelopeDbIdx128Find | Builtin::AntelopeDbIdx128Lowerbound),
                args,
                ..
            } => {
                let i64_ty = bin.context.i64_type();
                let i128_ty = bin.context.custom_width_int_type(128);
                let code = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function).into_int_value();
                let scope = crate::emit::expression::expression(&AntelopeTarget, bin, &args[1], vartab, function).into_int_value();
                let table = crate::emit::expression::expression(&AntelopeTarget, bin, &args[2], vartab, function).into_int_value();
                let index_num = crate::emit::expression::expression(&AntelopeTarget, bin, &args[3], vartab, function).into_int_value();
                let key = crate::emit::expression::expression(&AntelopeTarget, bin, &args[4], vartab, function).into_int_value();

                // Compute secondary table name
                let mask = i64_ty.const_int(0xFFFFFFFFFFFFFFF0, false);
                let table_masked = bin.builder.build_and(table, mask, "tbl_masked").unwrap();
                let idx_mask = i64_ty.const_int(0xF, false);
                let idx_masked = bin.builder.build_and(index_num, idx_mask, "idx_masked").unwrap();
                let sec_table = bin.builder.build_or(table_masked, idx_masked, "sec_table").unwrap();

                // Alloca for 128-bit key and pk output
                let key_ptr = bin.builder.build_alloca(i128_ty, "sec_key128").unwrap();
                bin.builder.build_store(key_ptr, key).unwrap();
                let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();

                let host_fn_name = match kind {
                    Builtin::AntelopeDbIdx128Find => "db_idx128_find_secondary",
                    Builtin::AntelopeDbIdx128Lowerbound => "db_idx128_lowerbound",
                    _ => unreachable!(),
                };
                let host_fn = bin.module.get_function(host_fn_name).unwrap();
                let iter = bin.builder
                    .build_call(host_fn, &[code.into(), scope.into(), sec_table.into(), key_ptr.into(), pk_out.into()], "idx128_iter")
                    .unwrap().try_as_basic_value().left().unwrap().into_int_value();

                // Cache pk
                let pk_val = bin.builder.build_load(i64_ty, pk_out, "pk_val").unwrap().into_int_value();
                let last_pk_global = bin.module.get_global("__last_pk").unwrap().as_pointer_value();
                bin.builder.build_store(last_pk_global, pk_val).unwrap();

                iter.into()
            }

            // antelope.dbIdx256Find(code, scope, table, indexNum, key) -> int32
            // antelope.dbIdx256Lowerbound(code, scope, table, indexNum, key) -> int32
            Expression::Builtin {
                kind: kind @ (Builtin::AntelopeDbIdx256Find | Builtin::AntelopeDbIdx256Lowerbound),
                args,
                ..
            } => {
                let i32_ty = bin.context.i32_type();
                let i64_ty = bin.context.i64_type();
                let i256_ty = bin.context.custom_width_int_type(256);
                let code = crate::emit::expression::expression(&AntelopeTarget, bin, &args[0], vartab, function).into_int_value();
                let scope = crate::emit::expression::expression(&AntelopeTarget, bin, &args[1], vartab, function).into_int_value();
                let table = crate::emit::expression::expression(&AntelopeTarget, bin, &args[2], vartab, function).into_int_value();
                let index_num = crate::emit::expression::expression(&AntelopeTarget, bin, &args[3], vartab, function).into_int_value();
                let key = crate::emit::expression::expression(&AntelopeTarget, bin, &args[4], vartab, function).into_int_value();

                // Compute secondary table name
                let mask = i64_ty.const_int(0xFFFFFFFFFFFFFFF0, false);
                let table_masked = bin.builder.build_and(table, mask, "tbl_masked").unwrap();
                let idx_mask = i64_ty.const_int(0xF, false);
                let idx_masked = bin.builder.build_and(index_num, idx_mask, "idx_masked").unwrap();
                let sec_table = bin.builder.build_or(table_masked, idx_masked, "sec_table").unwrap();

                // Alloca for 256-bit key and pk output
                let key_ptr = bin.builder.build_alloca(i256_ty, "sec_key256").unwrap();
                bin.builder.build_store(key_ptr, key).unwrap();
                let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();

                let host_fn_name = match kind {
                    Builtin::AntelopeDbIdx256Find => "db_idx256_find_secondary",
                    Builtin::AntelopeDbIdx256Lowerbound => "db_idx256_lowerbound",
                    _ => unreachable!(),
                };
                let host_fn = bin.module.get_function(host_fn_name).unwrap();
                // idx256 host functions take data_len = 2 (number of 128-bit words)
                let iter = bin.builder
                    .build_call(host_fn, &[code.into(), scope.into(), sec_table.into(), key_ptr.into(), i32_ty.const_int(2, false).into(), pk_out.into()], "idx256_iter")
                    .unwrap().try_as_basic_value().left().unwrap().into_int_value();

                // Cache pk
                let pk_val = bin.builder.build_load(i64_ty, pk_out, "pk_val").unwrap().into_int_value();
                let last_pk_global = bin.module.get_global("__last_pk").unwrap().as_pointer_value();
                bin.builder.build_store(last_pk_global, pk_val).unwrap();

                iter.into()
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
        // Antelope events are emitted as inline actions to self via send_inline.
        //
        // topics[0] = eosio::name(event_name) as uint64 (compile-time constant)
        // data = ABI-encoded event fields (vector of bytes)
        //
        // Serialized action layout:
        //   account(8) + action_name(8) + auth_count(1) + actor(8) + perm(8)
        //   + data_len(varuint32) + data(N)

        let i32_ty = bin.context.i32_type();
        let i64_ty = bin.context.i64_type();
        let i8_ty = bin.context.i8_type();

        // topics[0] is the event name as eosio::name uint64.
        let event_name = if !topics.is_empty() {
            topics[0].into_int_value()
        } else {
            i64_ty.const_zero()
        };

        // Get data length and pointer from the ABI-encoded vector.
        let data_len = bin.vector_len(data);
        let data_ptr = bin.vector_bytes(data);

        // Load self account.
        let receiver_global = AntelopeTarget::get_receiver_global(bin);
        let self_account = bin
            .builder
            .build_load(i64_ty, receiver_global.as_pointer_value(), "self_acct")
            .unwrap()
            .into_int_value();

        let active_perm = i64_ty.const_int(crate::emit::antelope::string_to_name("active"), false);

        // Encode data_len as varuint32 to know its byte size.
        let encode_fn = bin.module.get_function("__encode_varuint32").unwrap();
        let vi_tmp = bin
            .builder
            .build_array_alloca(i8_ty, i32_ty.const_int(5, false), "vi_tmp")
            .unwrap();
        let data_vi_size = bin
            .builder
            .build_call(encode_fn, &[vi_tmp.into(), data_len.into()], "dvi_sz")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // Total = 33 (fixed) + varuint_size + data_len
        let fixed_part = i32_ty.const_int(33, false);
        let total_size = bin.builder.build_int_add(fixed_part, data_vi_size, "ts1").unwrap();
        let total_size = bin.builder.build_int_add(total_size, data_len, "total_size").unwrap();

        let malloc_fn = bin.module.get_function("__malloc").unwrap();
        let buf = bin
            .builder
            .build_call(malloc_fn, &[total_size.into()], "evt_buf")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();

        // account = self (offset 0)
        bin.builder.build_store(buf, self_account).unwrap();

        // action_name = event name (offset 8)
        let off8 = unsafe {
            bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(8, false)], "off8").unwrap()
        };
        bin.builder.build_store(off8, event_name).unwrap();

        // auth_count = 1 (offset 16)
        let off16 = unsafe {
            bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(16, false)], "off16").unwrap()
        };
        bin.builder.build_store(off16, i8_ty.const_int(1, false)).unwrap();

        // auth[0].actor = self (offset 17)
        let off17 = unsafe {
            bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(17, false)], "off17").unwrap()
        };
        bin.builder.build_store(off17, self_account).unwrap();

        // auth[0].permission = active (offset 25)
        let off25 = unsafe {
            bin.builder.build_gep(i8_ty, buf, &[i32_ty.const_int(25, false)], "off25").unwrap()
        };
        bin.builder.build_store(off25, active_perm).unwrap();

        // data_len as varuint32 (offset 33)
        let off33 = unsafe {
            bin.builder.build_gep(i8_ty, buf, &[fixed_part], "off33").unwrap()
        };
        bin.builder
            .build_call(encode_fn, &[off33.into(), data_len.into()], "")
            .unwrap();

        // data bytes (offset 33 + varuint_size)
        let data_offset = bin.builder.build_int_add(fixed_part, data_vi_size, "doff").unwrap();
        let data_dst = unsafe {
            bin.builder.build_gep(i8_ty, buf, &[data_offset], "ddst").unwrap()
        };
        bin.builder
            .build_memcpy(data_dst, 1, data_ptr, 1, data_len)
            .unwrap();

        // send_inline(buf, total_size)
        let send_inline_fn = bin.module.get_function("send_inline").unwrap();
        bin.builder
            .build_call(send_inline_fn, &[buf.into(), total_size.into()], "")
            .unwrap();
    }

    fn return_abi_data<'b>(
        &self,
        bin: &Binary<'b>,
        data: PointerValue<'b>,
        data_len: BasicValueEnum<'b>,
    ) {
        let set_return = bin.module.get_function("set_action_return_value").unwrap();
        bin.builder
            .build_call(set_return, &[data.into(), data_len.into()], "")
            .unwrap();
    }
}

/// Helper methods for Antelope string/variable-length storage.
impl AntelopeTarget {
    /// Store a string (Solang vector) to the state table.
    /// Row format: [pk(8) + slot_hash(32) + string_bytes(N)].
    fn storage_store_string<'a>(
        &self,
        bin: &Binary<'a>,
        slot: &mut IntValue<'a>,
        dest: BasicValueEnum<'a>,
        function: FunctionValue,
    ) {
        let i32_ty = bin.context.i32_type();
        let i64_ty = bin.context.i64_type();
        let i256_ty = bin.context.custom_width_int_type(256);

        // Get string data pointer and length from Solang vector.
        let string_len = bin.vector_len(dest);
        let string_data = bin.vector_bytes(dest);

        // Load receiver.
        let receiver_global = Self::get_receiver_global(bin);
        let receiver = bin
            .builder
            .build_load(i64_ty, receiver_global.as_pointer_value(), "receiver")
            .unwrap()
            .into_int_value();
        let ram_payer = Self::get_ram_payer(bin);
        let table_name = i64_ty.const_int(STATE_TABLE_NAME, false);

        // Convert slot to 256-bit.
        let slot_i256 = if slot.get_type().get_bit_width() == 256 {
            *slot
        } else {
            bin.builder
                .build_int_z_extend(*slot, i256_ty, "slot256")
                .unwrap()
        };
        let slot_buf = bin
            .builder
            .build_array_alloca(bin.context.i8_type(), i32_ty.const_int(32, false), "slot_buf")
            .unwrap();
        bin.builder.build_store(slot_buf, slot_i256).unwrap();

        // Encode string_len as varuint32 into a temp buffer to know how many bytes it takes.
        let encode_fn = bin.module.get_function("__encode_varuint32").unwrap();
        let varuint_tmp = bin
            .builder
            .build_array_alloca(bin.context.i8_type(), i32_ty.const_int(5, false), "vi_tmp")
            .unwrap();
        let varuint_size = bin
            .builder
            .build_call(encode_fn, &[varuint_tmp.into(), string_len.into()], "vi_sz")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // Row size = 8 (pk) + 32 (hash) + varuint_size + string_len.
        let fixed_header = i32_ty.const_int(40, false); // pk(8) + hash(32)
        let row_size = bin.builder.build_int_add(fixed_header, varuint_size, "rs1").unwrap();
        let row_size = bin.builder.build_int_add(row_size, string_len, "row_size").unwrap();

        // Allocate row buffer via malloc (dynamic size, can't use stack alloca).
        let malloc = bin.module.get_function("__malloc").unwrap();
        let row_buf = bin
            .builder
            .build_call(malloc, &[row_size.into()], "row_buf")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();

        // Write slot_hash at offset 8.
        let hash_ptr = unsafe {
            bin.builder
                .build_gep(bin.context.i8_type(), row_buf, &[i32_ty.const_int(8, false)], "hash_ptr")
                .unwrap()
        };
        bin.builder.build_store(hash_ptr, slot_i256).unwrap();

        // Write varuint32(string_len) at offset 40 using __encode_varuint32.
        let varuint_ptr = unsafe {
            bin.builder
                .build_gep(bin.context.i8_type(), row_buf, &[fixed_header], "vi_ptr")
                .unwrap()
        };
        bin.builder
            .build_call(encode_fn, &[varuint_ptr.into(), string_len.into()], "")
            .unwrap();

        // Copy string bytes after the varuint32.
        let data_offset = bin.builder.build_int_add(fixed_header, varuint_size, "doff").unwrap();
        let val_ptr = unsafe {
            bin.builder
                .build_gep(bin.context.i8_type(), row_buf, &[data_offset], "val_ptr")
                .unwrap()
        };
        let memcpy = bin.module.get_function("__memcpy").unwrap();
        bin.builder
            .build_call(memcpy, &[val_ptr.into(), string_data.into(), string_len.into()], "")
            .unwrap();

        let data_len = i32_ty.const_int(2, false); // idx256 data_len

        // Look up existing row via idx256.
        let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();
        let db_idx256_find = bin.module.get_function("db_idx256_find_secondary").unwrap();
        let sec_iter = bin
            .builder
            .build_call(
                db_idx256_find,
                &[receiver.into(), receiver.into(), table_name.into(), slot_buf.into(), data_len.into(), pk_out.into()],
                "sec_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let found = bin
            .builder
            .build_int_compare(IntPredicate::SGE, sec_iter, i32_ty.const_zero(), "found")
            .unwrap();

        let update_bb = bin.context.append_basic_block(function, "str_update");
        let insert_bb = bin.context.append_basic_block(function, "str_insert");
        let done_bb = bin.context.append_basic_block(function, "str_done");

        bin.builder.build_conditional_branch(found, update_bb, insert_bb).unwrap();

        // UPDATE: write pk, find primary, update row.
        bin.builder.position_at_end(update_bb);
        let pk = bin.builder.build_load(i64_ty, pk_out, "pk").unwrap().into_int_value();
        bin.builder.build_store(row_buf, pk).unwrap();

        let db_find = bin.module.get_function("db_find_i64").unwrap();
        let pri_iter = bin
            .builder
            .build_call(db_find, &[receiver.into(), receiver.into(), table_name.into(), pk.into()], "pri_iter")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();
        let db_update = bin.module.get_function("db_update_i64").unwrap();
        bin.builder
            .build_call(db_update, &[pri_iter.into(), ram_payer.into(), row_buf.into(), row_size.into()], "")
            .unwrap();
        bin.builder.build_unconditional_branch(done_bb).unwrap();

        // INSERT: allocate new pk, store row + idx256.
        bin.builder.position_at_end(insert_bb);
        let pk_global = Self::get_next_pk_global(bin);
        let cached_pk = bin
            .builder
            .build_load(i64_ty, pk_global.as_pointer_value(), "cached_pk")
            .unwrap()
            .into_int_value();

        let sentinel = i64_ty.const_all_ones();
        let need_init = bin
            .builder
            .build_int_compare(IntPredicate::EQ, cached_pk, sentinel, "need_init")
            .unwrap();

        let init_bb = bin.context.append_basic_block(function, "str_pk_init");
        let use_cached_bb = bin.context.append_basic_block(function, "str_pk_cached");
        let do_insert_bb = bin.context.append_basic_block(function, "str_do_insert");

        bin.builder.build_conditional_branch(need_init, init_bb, use_cached_bb).unwrap();

        // INIT pk from DB.
        bin.builder.position_at_end(init_bb);
        let db_end = bin.module.get_function("db_end_i64").unwrap();
        let end_iter = bin
            .builder
            .build_call(db_end, &[receiver.into(), receiver.into(), table_name.into()], "end_iter")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let end_neg = bin
            .builder
            .build_int_compare(IntPredicate::EQ, end_iter, i32_ty.const_int(u64::MAX, true), "end_neg")
            .unwrap();

        let empty_bb = bin.context.append_basic_block(function, "str_empty");
        let has_rows_bb = bin.context.append_basic_block(function, "str_has_rows");
        let init_done_bb = bin.context.append_basic_block(function, "str_init_done");

        bin.builder.build_conditional_branch(end_neg, empty_bb, has_rows_bb).unwrap();

        bin.builder.position_at_end(empty_bb);
        let pk_zero = i64_ty.const_zero();
        bin.builder.build_unconditional_branch(init_done_bb).unwrap();

        bin.builder.position_at_end(has_rows_bb);
        let last_pk_out = bin.builder.build_alloca(i64_ty, "last_pk_out").unwrap();
        let db_previous = bin.module.get_function("db_previous_i64").unwrap();
        bin.builder.build_call(db_previous, &[end_iter.into(), last_pk_out.into()], "").unwrap();
        let last_pk = bin.builder.build_load(i64_ty, last_pk_out, "last_pk").unwrap().into_int_value();
        let pk_from_db = bin.builder.build_int_add(last_pk, i64_ty.const_int(1, false), "pk_from_db").unwrap();
        bin.builder.build_unconditional_branch(init_done_bb).unwrap();

        bin.builder.position_at_end(init_done_bb);
        let init_pk = bin.builder.build_phi(i64_ty, "init_pk").unwrap();
        init_pk.add_incoming(&[(&pk_zero, empty_bb), (&pk_from_db, has_rows_bb)]);
        let init_pk_val = init_pk.as_basic_value().into_int_value();
        bin.builder.build_unconditional_branch(do_insert_bb).unwrap();

        bin.builder.position_at_end(use_cached_bb);
        bin.builder.build_unconditional_branch(do_insert_bb).unwrap();

        bin.builder.position_at_end(do_insert_bb);
        let new_pk = bin.builder.build_phi(i64_ty, "new_pk").unwrap();
        new_pk.add_incoming(&[(&init_pk_val, init_done_bb), (&cached_pk, use_cached_bb)]);
        let new_pk_val = new_pk.as_basic_value().into_int_value();

        bin.builder.build_store(row_buf, new_pk_val).unwrap();

        let next_pk_inc = bin
            .builder
            .build_int_add(new_pk_val, i64_ty.const_int(1, false), "next_pk_inc")
            .unwrap();
        bin.builder.build_store(pk_global.as_pointer_value(), next_pk_inc).unwrap();

        let db_store = bin.module.get_function("db_store_i64").unwrap();
        bin.builder
            .build_call(
                db_store,
                &[receiver.into(), table_name.into(), ram_payer.into(), new_pk_val.into(), row_buf.into(), row_size.into()],
                "",
            )
            .unwrap();

        let db_idx256_store = bin.module.get_function("db_idx256_store").unwrap();
        bin.builder
            .build_call(
                db_idx256_store,
                &[receiver.into(), table_name.into(), ram_payer.into(), new_pk_val.into(), slot_buf.into(), data_len.into()],
                "",
            )
            .unwrap();

        bin.builder.build_unconditional_branch(done_bb).unwrap();
        bin.builder.position_at_end(done_bb);
    }

    /// Load a string from the state table into a Solang vector.
    /// Row format: [pk(8) + slot_hash(32) + string_bytes(N)].
    /// Returns a pointer to a new vector (or empty vector if not found).
    fn storage_load_string<'a>(
        &self,
        bin: &Binary<'a>,
        slot: &mut IntValue<'a>,
        function: FunctionValue,
    ) -> PointerValue<'a> {
        let i32_ty = bin.context.i32_type();
        let i64_ty = bin.context.i64_type();
        let i256_ty = bin.context.custom_width_int_type(256);

        // Load receiver.
        let receiver_global = Self::get_receiver_global(bin);
        let receiver = bin
            .builder
            .build_load(i64_ty, receiver_global.as_pointer_value(), "receiver")
            .unwrap()
            .into_int_value();
        let table_name = i64_ty.const_int(STATE_TABLE_NAME, false);

        // Convert slot to 256-bit.
        let slot_i256 = if slot.get_type().get_bit_width() == 256 {
            *slot
        } else {
            bin.builder
                .build_int_z_extend(*slot, i256_ty, "slot256")
                .unwrap()
        };
        let slot_buf = bin
            .builder
            .build_array_alloca(bin.context.i8_type(), i32_ty.const_int(32, false), "slot_buf")
            .unwrap();
        bin.builder.build_store(slot_buf, slot_i256).unwrap();

        // Look up via idx256.
        let pk_out = bin.builder.build_alloca(i64_ty, "pk_out").unwrap();
        let db_idx256_find = bin.module.get_function("db_idx256_find_secondary").unwrap();
        let data_len = i32_ty.const_int(2, false);
        let sec_iter = bin
            .builder
            .build_call(
                db_idx256_find,
                &[receiver.into(), receiver.into(), table_name.into(), slot_buf.into(), data_len.into(), pk_out.into()],
                "sec_iter",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let found = bin
            .builder
            .build_int_compare(IntPredicate::SGE, sec_iter, i32_ty.const_zero(), "found")
            .unwrap();

        // Allocate scratch buffer before branching (must dominate both paths).
        let scratch_buf = bin.builder.build_alloca(bin.context.i8_type(), "scratch").unwrap();
        let vector_new = bin.module.get_function("vector_new").unwrap();
        let db_find = bin.module.get_function("db_find_i64").unwrap();
        let db_get = bin.module.get_function("db_get_i64").unwrap();
        let malloc = bin.module.get_function("__malloc").unwrap();

        let found_bb = bin.context.append_basic_block(function, "str_found");
        let notfound_bb = bin.context.append_basic_block(function, "str_notfound");
        let merge_bb = bin.context.append_basic_block(function, "str_merge");

        bin.builder.build_conditional_branch(found, found_bb, notfound_bb).unwrap();

        // FOUND: read row, extract string bytes, create vector.
        bin.builder.position_at_end(found_bb);
        let pk = bin.builder.build_load(i64_ty, pk_out, "pk").unwrap().into_int_value();

        let pri_iter = bin
            .builder
            .build_call(db_find, &[receiver.into(), receiver.into(), table_name.into(), pk.into()], "pri_iter")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();
        let row_total_size = bin
            .builder
            .build_call(db_get, &[pri_iter.into(), scratch_buf.into(), i32_ty.const_zero().into()], "row_size")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // Allocate row buffer via malloc (dynamic size).
        let row_buf = bin
            .builder
            .build_call(malloc, &[row_total_size.into()], "row_buf")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();

        // Need to re-find since db_get_i64 may have invalidated the iterator.
        let pri_iter2 = bin
            .builder
            .build_call(db_find, &[receiver.into(), receiver.into(), table_name.into(), pk.into()], "pri_iter2")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        bin.builder
            .build_call(db_get, &[pri_iter2.into(), row_buf.into(), row_total_size.into()], "")
            .unwrap();

        // Decode varuint32 at offset 40 to get string length and varuint byte count.
        let fixed_header = i32_ty.const_int(40, false); // pk(8) + hash(32)
        let varuint_ptr = unsafe {
            bin.builder
                .build_gep(bin.context.i8_type(), row_buf, &[fixed_header], "vi_ptr")
                .unwrap()
        };
        let decode_fn = bin.module.get_function("__decode_varuint32").unwrap();
        let packed = bin
            .builder
            .build_call(decode_fn, &[varuint_ptr.into()], "packed")
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        // Unpack: low 32 bits = string length, high 32 bits = varuint byte count
        let str_len = bin
            .builder
            .build_int_truncate(packed, i32_ty, "str_len")
            .unwrap();
        let varuint_size = bin
            .builder
            .build_int_truncate(
                bin.builder
                    .build_right_shift(packed, bin.context.i64_type().const_int(32, false), false, "hi")
                    .unwrap(),
                i32_ty,
                "vi_sz",
            )
            .unwrap();

        // String data starts at offset 40 + varuint_size.
        let data_offset = bin.builder.build_int_add(fixed_header, varuint_size, "doff").unwrap();
        let str_ptr = unsafe {
            bin.builder
                .build_gep(bin.context.i8_type(), row_buf, &[data_offset], "str_ptr")
                .unwrap()
        };

        // Create a vector: vector_new(len, 1, data_ptr).
        let found_vec = bin
            .builder
            .build_call(
                vector_new,
                &[str_len.into(), i32_ty.const_int(1, false).into(), str_ptr.into()],
                "str_vec",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();
        bin.builder.build_unconditional_branch(merge_bb).unwrap();

        // NOT FOUND: return empty vector.
        bin.builder.position_at_end(notfound_bb);
        let empty_vec = bin
            .builder
            .build_call(
                vector_new,
                &[i32_ty.const_zero().into(), i32_ty.const_int(1, false).into(), scratch_buf.into()],
                "empty_vec",
            )
            .unwrap()
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();
        bin.builder.build_unconditional_branch(merge_bb).unwrap();

        // MERGE.
        bin.builder.position_at_end(merge_bb);
        let ptr_ty = bin.context.ptr_type(inkwell::AddressSpace::default());
        let phi = bin.builder.build_phi(ptr_ty, "str_result").unwrap();
        phi.add_incoming(&[(&found_vec, found_bb), (&empty_vec, notfound_bb)]);
        phi.as_basic_value().into_pointer_value()
    }
}
