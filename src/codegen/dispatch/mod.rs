// SPDX-License-Identifier: Apache-2.0

use super::{cfg::ControlFlowGraph, Options};
use crate::{sema::ast::Namespace, Target};

pub(crate) mod polkadot;
pub(super) mod solana;
pub(super) mod soroban;

pub(super) fn function_dispatch(
    contract_no: usize,
    all_cfg: &mut [ControlFlowGraph],
    ns: &mut Namespace,
    opt: &Options,
) -> Vec<ControlFlowGraph> {
    match &ns.target {
        Target::Solana => vec![solana::function_dispatch(contract_no, all_cfg, ns, opt)],
        Target::Polkadot { .. } | Target::EVM => {
            polkadot::function_dispatch(contract_no, all_cfg, ns, opt)
        }
        Target::Soroban => soroban::function_dispatch(contract_no, all_cfg, ns, opt),
        // Antelope's entry point is the hand-written `apply` (see emit/antelope), which
        // dispatches actions by name — it does not use these selector-based dispatch CFGs.
        // Generating the Polkadot ones only emitted dead functions whose Polkadot-specific
        // terminators (ReturnCode / the ReturnData success path) Antelope's emit doesn't
        // lower, leaving blocks unterminated → invalid IR that crashed the backend at
        // -O none/less (masked at -O default only because global_dce drops dead functions).
        Target::Antelope => vec![],
    }
}
