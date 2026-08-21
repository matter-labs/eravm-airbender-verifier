use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use zksync_contracts::BaseSystemContracts;
use zksync_types::{
    protocol_version::deserialize_wire_protocol_version, L2ChainId, ProtocolVersionId,
};

/// Params related to the execution process, not batch it self
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemEnv {
    // Always false for VM
    pub zk_porter_available: bool,
    /// Protocol minor the operator claims this batch executed under.
    ///
    /// Read leniently so an Era minor this build cannot name still decodes
    /// instead of aborting the whole payload — see
    /// [`deserialize_wire_protocol_version`]. The verifier checks it and then
    /// overwrites it with `airbender_verifier::PINNED_PROTOCOL_VERSION`, so no
    /// version-gated behaviour is selected by this field.
    #[serde(deserialize_with = "deserialize_wire_protocol_version")]
    pub version: ProtocolVersionId,
    pub base_system_smart_contracts: BaseSystemContracts,
    pub bootloader_gas_limit: u32,
    pub execution_mode: TxExecutionMode,
    pub default_validation_computational_gas_limit: u32,
    pub chain_id: L2ChainId,
}

impl Debug for SystemEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemEnv")
            .field("zk_porter_available", &self.zk_porter_available)
            .field("version", &self.version)
            .field(
                "base_system_smart_contracts",
                &self.base_system_smart_contracts.hashes(),
            )
            .field("gas_limit", &self.bootloader_gas_limit)
            .field(
                "default_validation_computational_gas_limit",
                &self.default_validation_computational_gas_limit,
            )
            .field("execution_mode", &self.execution_mode)
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

/// Enum denoting the *in-server* execution mode for the bootloader transactions.
///
/// If `EthCall` mode is chosen, the bootloader will use `mimicCall` opcode
/// to simulate the call instead of using the standard `execute` method of account.
/// This is needed to be able to behave equivalently to Ethereum without much overhead for custom account builders.
/// With `VerifyExecute` mode, transaction will be executed normally.
/// With `EstimateFee`, the bootloader will be used that has the same behavior
/// as the full `VerifyExecute` block, but errors in the account validation will be ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxExecutionMode {
    VerifyExecute,
    EstimateFee,
    EthCall,
}
