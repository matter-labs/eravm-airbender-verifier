//! Pre-v31 bincode wire adapter for `AirbenderVerifierInput::V1`.
//!
//! The on-disk corpus in `testdata/era_mainnet_batches/` was produced before
//! v31 changed `L1BatchEnv` (added `interop_fee`, `settlement_layer`) and
//! `PubdataParams` (replaced `l2_da_validator_address: Address` with the
//! `L2PubdataValidator` enum). Bincode is positional, so old bytes don't
//! decode against the new field layouts.
//!
//! Wired in via `#[serde(with = "crate::v1_compat")]` on the V1 enum variant.
//! The deserializer reads the legacy layout and reconstructs a canonical
//! [`V2AirbenderVerifierInput`] with `interop_fee = 0`, the default
//! `settlement_layer`, and the address wrapped in
//! `L2PubdataValidator::Address`. The serializer is lossy in the other
//! direction: it errors if the payload carries any post-v31-only state
//! (`CommitmentScheme` validator, non-zero `interop_fee`, non-default
//! `settlement_layer`) — V1 only exists to consume the old corpus, so the
//! lossy path is the test round-trip only.

use serde::{
    de::Error as DeError, ser::Error as SerError, Deserialize, Deserializer, Serialize, Serializer,
};
use zksync_types::{
    block::L2BlockExecutionData,
    commitment::{L2PubdataValidator, PubdataParams, PubdataType},
    fee_model::BatchFeeInput,
    settlement::SettlementLayer,
    Address, L1BatchNumber, H256, U256,
};
use zksync_vm_interface::{L1BatchEnv, L2BlockEnv, SystemEnv};

use crate::types::{
    CommitmentInput, V2AirbenderVerifierInput, VMRunWitnessInputData, WitnessInputMerklePaths,
};

/// Pre-v31 mirror of [`V2AirbenderVerifierInput`]. Field types match the
/// canonical payload except for the two that changed shape; field order
/// matches the bincode layout of the on-disk corpus.
#[derive(Serialize, Deserialize)]
struct Legacy {
    vm_run_data: VMRunWitnessInputData,
    merkle_paths: WitnessInputMerklePaths,
    l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    l1_batch_env: LegacyL1BatchEnv,
    system_env: SystemEnv,
    pubdata_params: LegacyPubdataParams,
    commitment_input: Option<CommitmentInput>,
}

#[derive(Serialize, Deserialize)]
struct LegacyL1BatchEnv {
    previous_batch_hash: Option<H256>,
    number: L1BatchNumber,
    timestamp: u64,
    fee_input: BatchFeeInput,
    fee_account: Address,
    enforced_base_fee: Option<u64>,
    first_l2_block: L2BlockEnv,
}

#[derive(Serialize, Deserialize)]
struct LegacyPubdataParams {
    l2_da_validator_address: Address,
    pubdata_type: PubdataType,
}

pub fn serialize<S: Serializer>(
    payload: &V2AirbenderVerifierInput,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let l1_batch_env = &payload.l1_batch_env;
    if !l1_batch_env.interop_fee.is_zero() {
        return Err(S::Error::custom(
            "V1 wire cannot encode non-zero L1BatchEnv::interop_fee",
        ));
    }
    if l1_batch_env.settlement_layer != SettlementLayer::default() {
        return Err(S::Error::custom(
            "V1 wire cannot encode non-default L1BatchEnv::settlement_layer",
        ));
    }
    let l2_da_validator_address = match payload.pubdata_params.pubdata_validator() {
        L2PubdataValidator::Address(addr) => addr,
        L2PubdataValidator::CommitmentScheme(_) => {
            return Err(S::Error::custom(
                "V1 wire cannot encode L2PubdataValidator::CommitmentScheme",
            ));
        }
    };

    Legacy {
        vm_run_data: payload.vm_run_data.clone(),
        merkle_paths: payload.merkle_paths.clone(),
        l2_blocks_execution_data: payload.l2_blocks_execution_data.clone(),
        l1_batch_env: LegacyL1BatchEnv {
            previous_batch_hash: l1_batch_env.previous_batch_hash,
            number: l1_batch_env.number,
            timestamp: l1_batch_env.timestamp,
            fee_input: l1_batch_env.fee_input,
            fee_account: l1_batch_env.fee_account,
            enforced_base_fee: l1_batch_env.enforced_base_fee,
            first_l2_block: l1_batch_env.first_l2_block.clone(),
        },
        system_env: payload.system_env.clone(),
        pubdata_params: LegacyPubdataParams {
            l2_da_validator_address,
            pubdata_type: payload.pubdata_params.pubdata_type(),
        },
        commitment_input: payload.commitment_input.clone(),
    }
    .serialize(ser)
}

pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<V2AirbenderVerifierInput, D::Error> {
    let legacy = Legacy::deserialize(de)?;
    let pubdata_params = PubdataParams::new(
        L2PubdataValidator::Address(legacy.pubdata_params.l2_da_validator_address),
        legacy.pubdata_params.pubdata_type,
    )
    .map_err(D::Error::custom)?;
    Ok(V2AirbenderVerifierInput {
        vm_run_data: legacy.vm_run_data,
        merkle_paths: legacy.merkle_paths,
        l2_blocks_execution_data: legacy.l2_blocks_execution_data,
        l1_batch_env: L1BatchEnv {
            previous_batch_hash: legacy.l1_batch_env.previous_batch_hash,
            number: legacy.l1_batch_env.number,
            timestamp: legacy.l1_batch_env.timestamp,
            fee_input: legacy.l1_batch_env.fee_input,
            interop_fee: U256::zero(),
            fee_account: legacy.l1_batch_env.fee_account,
            enforced_base_fee: legacy.l1_batch_env.enforced_base_fee,
            first_l2_block: legacy.l1_batch_env.first_l2_block,
            settlement_layer: SettlementLayer::default(),
        },
        system_env: legacy.system_env,
        pubdata_params,
        commitment_input: legacy.commitment_input,
    })
}
