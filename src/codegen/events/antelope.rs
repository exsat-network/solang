// SPDX-License-Identifier: Apache-2.0

use crate::codegen::cfg::{ControlFlowGraph, Instr};
use crate::codegen::encoding::abi_encode;
use crate::codegen::events::EventEmitter;
use crate::codegen::expression::expression;
use crate::codegen::vartable::Vartable;
use crate::codegen::{Expression, Options};
use crate::emit::antelope::string_to_name;
use crate::sema::ast::{self, Function, Namespace, Type};
use solang_parser::pt;

/// Antelope event emitter.
///
/// Events are emitted as inline actions (send_inline) to the contract itself.
/// topics[0] = eosio::name(event_name) as uint64 — used as the action name.
/// data = ABI-encoded event fields — used as the action data.
pub(super) struct AntelopeEventEmitter<'a> {
    pub(super) args: &'a [ast::Expression],
    pub(super) ns: &'a Namespace,
    pub(super) event_no: usize,
}

impl EventEmitter for AntelopeEventEmitter<'_> {
    fn selector(&self, _emitting_contract_no: usize) -> Vec<u8> {
        let event = &self.ns.events[self.event_no];
        event.id.name.as_bytes().to_vec()
    }

    fn emit(
        &self,
        contract_no: usize,
        func: &Function,
        cfg: &mut ControlFlowGraph,
        vartab: &mut Vartable,
        opt: &Options,
    ) {
        let loc = pt::Loc::Builtin;
        let event = &self.ns.events[self.event_no];

        // Encode the event name as eosio::name uint64 at compile time.
        // This will be used as the action name in the send_inline call.
        let event_name = &event.id.name;
        // Antelope names: max 12 chars, lowercase + 1-5 + dot.
        // Prefix with "e." to avoid collisions with real contract action names.
        // E.g. event "Mint" → "e.mint", "Transfer" → "e.transfer".
        let action_name: String = std::iter::once('e')
            .chain(std::iter::once('.'))
            .chain(
                event_name
                    .to_lowercase()
                    .chars()
                    .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            )
            .take(12)
            .collect();
        let name_encoded = string_to_name(&action_name);

        let topics = vec![Expression::NumberLiteral {
            loc,
            ty: Type::Uint(64),
            value: name_encoded.into(),
        }];

        // Evaluate and ABI-encode all event fields.
        let data: Vec<Expression> = self
            .args
            .iter()
            .map(|e| expression(e, cfg, contract_no, Some(func), self.ns, vartab, opt))
            .collect();

        let encoded_data = if data.is_empty() {
            Expression::AllocDynamicBytes {
                loc,
                ty: Type::DynamicBytes,
                size: Expression::NumberLiteral {
                    loc,
                    ty: Type::Uint(32),
                    value: 0.into(),
                }
                .into(),
                initializer: Some(Vec::new()),
            }
        } else {
            abi_encode(&loc, data, self.ns, vartab, cfg, false).0
        };

        cfg.add(
            vartab,
            Instr::EmitEvent {
                event_no: self.event_no,
                data: encoded_data,
                topics,
            },
        );
    }
}
