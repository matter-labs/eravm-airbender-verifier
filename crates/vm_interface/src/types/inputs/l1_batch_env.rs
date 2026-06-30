use serde::{Deserialize, Serialize};
use zksync_types::{
    fee_model::BatchFeeInput, settlement::SettlementLayer, Address, L1BatchNumber, H256, U256,
};

use super::L2BlockEnv;

/// Unique params for each L1 batch.
///
/// Eventually, most of these parameters (`l1_gas_price`, `fair_l2_gas_price`, `fee_account`,
/// `enforced_base_fee`) will be moved to [`L2BlockEnv`]. For now, the VM doesn't support changing
/// them in the middle of execution; that's why these params are specified here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct L1BatchEnv {
    // If previous batch hash is None, then this is the first batch
    pub previous_batch_hash: Option<H256>,
    pub number: L1BatchNumber,
    pub timestamp: u64,

    /// The fee input into the batch. It contains information such as L1 gas price, L2 fair gas price, etc.
    pub fee_input: BatchFeeInput,
    /// Introduced in v31. `#[serde(default)]` tolerates a JSON payload that
    /// omits the field, filling `0`.
    #[serde(default)]
    pub interop_fee: U256,
    pub fee_account: Address,
    pub enforced_base_fee: Option<u64>,
    pub first_l2_block: L2BlockEnv,
    /// Introduced in v31. Required on the wire — no serde default, so a missing
    /// `settlement_layer` is a hard decode error.
    pub settlement_layer: SettlementLayer,
}
