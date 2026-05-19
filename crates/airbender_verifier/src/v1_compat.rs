//! Pre-v31 wire-format snapshots for [`crate::types::V1AirbenderVerifierInput`].
//!
//! `L1BatchEnv` and `PubdataParams` changed shape in v31 (added `interop_fee`
//! and `settlement_layer`; replaced `l2_da_validator_address: Address` with
//! `L2PubdataValidator`). Bincode is positional, so old corpus bytes will not
//! decode against the new types. We snapshot the old field layouts here and
//! bind them to the V1 wire variant; new inputs ride V2 with the canonical
//! post-v31 types.

use serde::{Deserialize, Serialize};
use zksync_types::{
    commitment::{L2PubdataValidator, PubdataParams, PubdataType},
    fee_model::BatchFeeInput,
    settlement::SettlementLayer,
    Address, L1BatchNumber, H256, U256,
};
use zksync_vm_interface::{L1BatchEnv, L2BlockEnv};

/// Pre-v31 [`PubdataParams`] layout.
#[derive(Default, Copy, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PubdataParamsV1 {
    pub l2_da_validator_address: Address,
    pub pubdata_type: PubdataType,
}

impl PubdataParamsV1 {
    /// Wrap the address in `L2PubdataValidator::Address`, preserving the zero
    /// address. Pre-medium-interop dispatch reads back through
    /// `l2_da_validator()`, so the variant must be `Address` regardless of
    /// the underlying value.
    pub fn upgrade(self) -> PubdataParams {
        PubdataParams::new(
            L2PubdataValidator::Address(self.l2_da_validator_address),
            self.pubdata_type,
        )
        .expect("Address variant is always a valid PubdataParams")
    }
}

/// Pre-v31 [`L1BatchEnv`] layout.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct L1BatchEnvV1 {
    pub previous_batch_hash: Option<H256>,
    pub number: L1BatchNumber,
    pub timestamp: u64,
    pub fee_input: BatchFeeInput,
    pub fee_account: Address,
    pub enforced_base_fee: Option<u64>,
    pub first_l2_block: L2BlockEnv,
}

impl L1BatchEnvV1 {
    pub fn upgrade(self) -> L1BatchEnv {
        // The v31 verifier gates settlement_layer / interop_fee reads on
        // `is_pre_medium_interop()`, so pre-v31 batches never observe these
        // fields — any well-formed default is fine.
        L1BatchEnv {
            previous_batch_hash: self.previous_batch_hash,
            number: self.number,
            timestamp: self.timestamp,
            fee_input: self.fee_input,
            interop_fee: U256::zero(),
            fee_account: self.fee_account,
            enforced_base_fee: self.enforced_base_fee,
            first_l2_block: self.first_l2_block,
            settlement_layer: SettlementLayer::default(),
        }
    }
}
