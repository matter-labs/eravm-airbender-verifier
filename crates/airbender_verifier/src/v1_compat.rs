//! Pre-v31 wire-format snapshots.
//!
//! The existing on-disk corpus (`testdata/era_mainnet_batches/*.bin.gz`) was
//! produced before v31 landed. Those files encode an
//! `AirbenderVerifierInput::V1(V1AirbenderVerifierInput)` whose inner
//! `L1BatchEnv` and `PubdataParams` use the pre-v31 shape:
//!
//! - `L1BatchEnv` has no `interop_fee` and no `settlement_layer`.
//! - `PubdataParams` is `{ l2_da_validator_address: Address, pubdata_type: PubdataType }`,
//!   not the new `L2PubdataValidator` shape.
//!
//! Because bincode is positional, decoding old bytes against the new in-tree
//! types fails. Rather than freeze the old types behind `cfg`, we snapshot
//! them here and bind them to the V1 wire variant. The current
//! (post-v31) types remain canonical for the rest of the codebase and are
//! used by the new `V2` variant.
//!
//! `V1AirbenderVerifierInput::into_v2` (in `types.rs`) upgrades a decoded V1
//! input to V2 with zero `interop_fee` and a sentinel `SettlementLayer` —
//! that matches what a pre-v31 chain would have if the fields had existed.

use serde::{Deserialize, Serialize};
use zksync_types::{
    commitment::{L2DACommitmentScheme, L2PubdataValidator, PubdataParams, PubdataType},
    fee_model::BatchFeeInput,
    settlement::SettlementLayer,
    Address, L1BatchNumber, H256, U256,
};
use zksync_vm_interface::{L1BatchEnv, L2BlockEnv};

/// Pre-v31 `PubdataParams` shape. Matches the bincode layout used by every
/// corpus file generated before this PR.
#[derive(Default, Copy, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PubdataParamsV1 {
    pub l2_da_validator_address: Address,
    pub pubdata_type: PubdataType,
}

impl PubdataParamsV1 {
    /// Upgrade to the post-v31 `PubdataParams` by wrapping the address in
    /// `L2PubdataValidator::Address`. A zero address — emitted by pre-gateway
    /// chains — becomes `L2PubdataValidator::CommitmentScheme(BlobsAndPubdataKeccak256)`
    /// to match what `PubdataParams::genesis()` would produce post-v31.
    pub fn upgrade(self) -> PubdataParams {
        let validator = if self.l2_da_validator_address == Address::zero() {
            L2PubdataValidator::CommitmentScheme(L2DACommitmentScheme::BlobsAndPubdataKeccak256)
        } else {
            L2PubdataValidator::Address(self.l2_da_validator_address)
        };
        // `PubdataParams::new` rejects `CommitmentScheme(None)`; neither branch above
        // can produce that, so `expect` is sound.
        PubdataParams::new(validator, self.pubdata_type)
            .expect("PubdataParamsV1::upgrade never builds CommitmentScheme(None)")
    }
}

/// Pre-v31 `L1BatchEnv` shape. Identical to the post-v31 layout except for
/// the absent `interop_fee` and `settlement_layer` fields. Field order
/// matches the original bincode layout exactly.
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
    /// Upgrade to the post-v31 `L1BatchEnv` by filling the new fields with
    /// the values a pre-v31 chain would have implicitly carried: no interop
    /// fee, and a `SettlementLayer::for_tests()` placeholder (the verifier
    /// does not consult `settlement_layer` for pre-v31 protocol versions, so
    /// the exact value is immaterial as long as the field is present).
    pub fn upgrade(self) -> L1BatchEnv {
        L1BatchEnv {
            previous_batch_hash: self.previous_batch_hash,
            number: self.number,
            timestamp: self.timestamp,
            fee_input: self.fee_input,
            interop_fee: U256::zero(),
            fee_account: self.fee_account,
            enforced_base_fee: self.enforced_base_fee,
            first_l2_block: self.first_l2_block,
            settlement_layer: SettlementLayer::for_tests(),
        }
    }
}
