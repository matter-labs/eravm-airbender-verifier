use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::api::{
    CompilerType, CompilerVersions, SourceCodeData, VerificationEvmSettings,
    VerificationIncomingRequest, VerificationInfo, VerificationRequestStatus,
};
use crate::{web3::Bytes, Address};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanVerification {
    pub etherscan_verification_id: Option<String>,
    pub attempts: i32,
    pub retry_at: Option<DateTime<Utc>>,
}

/// Code format supported by Etherscan API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EtherscanCodeFormat {
    #[serde(rename = "solidity-single-file")]
    SingleFile,

    #[serde(rename = "solidity-standard-json-input")]
    StandardJsonInput,
}

/// It is used to represent boolean values in the API requests. "1" means true and "0" means false.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum EtherscanBoolean {
    #[default]
    #[serde(rename = "0")]
    False,
    #[serde(rename = "1")]
    True,
}

impl EtherscanBoolean {
    /// Converts EtherscanBoolean to a boolean value.
    pub fn to_bool(&self) -> bool {
        match self {
            EtherscanBoolean::True => true,
            EtherscanBoolean::False => false,
        }
    }
}

impl From<bool> for EtherscanBoolean {
    /// Converts a boolean value to EtherscanBoolean.
    fn from(value: bool) -> Self {
        if value {
            EtherscanBoolean::True
        } else {
            EtherscanBoolean::False
        }
    }
}

/// Etherscan verification request. It is used for Etherscan-like API requests and is transformed into
/// `VerificationIncomingRequest` before being sent to the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
// This struct is deserialized with serde_urlencoded which doesn't support all serde attributes including serde
// `rename_all`. Therefore, we need to use rename attributes for each field individually.
pub struct EtherscanVerificationRequest {
    #[serde(rename = "codeformat")]
    pub code_format: EtherscanCodeFormat,
    // The struct is deserialized with serde_urlencoded which doesn't support complex enum types and serde tag
    // attribute, that's why the source_code field is of type String and not SourceCodeData.
    #[serde(rename = "sourceCode")]
    pub source_code: String,
    #[serde(default, rename = "constructorArguements")]
    // Bytes deserializer requires leading 0x, so String is used here and then converted to Bytes in the
    // `to_verification_request` method.
    pub constructor_arguments: String,
    #[serde(rename = "contractaddress")]
    pub contract_address: Address,
    #[serde(rename = "contractname")]
    pub contract_name: String,
    #[serde(rename = "compilerversion")]
    pub compiler_version: String,
    #[serde(rename = "zksolcVersion")]
    pub zksolc_version: Option<String>,
    #[serde(rename = "optimizationUsed")]
    pub optimization_used: Option<EtherscanBoolean>,
    #[serde(rename = "optimizerMode")]
    pub optimizer_mode: Option<String>,
    pub runs: Option<String>,
    #[serde(rename = "evmversion")]
    pub evm_version: Option<String>,
    #[serde(rename = "compilermode")]
    pub compiler_mode: Option<String>,
    #[serde(default, rename = "isSystem")]
    pub is_system: Option<EtherscanBoolean>,
    #[serde(default, rename = "forceEvmla")]
    pub force_evmla: Option<EtherscanBoolean>,
}

impl EtherscanVerificationRequest {
    /// Converts the Etherscan verification request to a `VerificationIncomingRequest` which can be processed by the
    /// verifier in a usual way.
    /// Returns result with VerificationIncomingRequest or an error if the source code is not valid JSON.
    pub fn to_verification_request(self) -> Result<VerificationIncomingRequest, anyhow::Error> {
        Ok(VerificationIncomingRequest {
            contract_address: self.contract_address,
            source_code_data: match self.code_format {
                EtherscanCodeFormat::SingleFile => SourceCodeData::SolSingleFile(self.source_code),
                EtherscanCodeFormat::StandardJsonInput => {
                    SourceCodeData::StandardJsonInput(serde_json::from_str(&self.source_code)?)
                }
            },
            contract_name: self.contract_name,
            compiler_versions: CompilerVersions::Solc {
                compiler_solc_version: {
                    let compiler_version = self.compiler_version;
                    if compiler_version.starts_with("zkVM") {
                        // Return as is for zkVM compiler versions
                        compiler_version
                    } else {
                        // Otherwise, extract short solc version from the full version string
                        // e.g. "v0.8.24+commit.e11b9ed9" -> "0.8.24"
                        compiler_version
                            .strip_prefix('v')
                            .unwrap_or(&compiler_version)
                            .split_once('+')
                            .map(|(version, _)| version.to_string())
                            .unwrap_or(compiler_version)
                    }
                },
                compiler_zksolc_version: self.zksolc_version,
            },
            optimization_used: self.optimization_used.map(|x| x.to_bool()).unwrap_or(false),
            optimizer_mode: self.optimizer_mode,
            constructor_arguments: Bytes::from(
                hex::decode(self.constructor_arguments)
                    .map_err(|_| anyhow::anyhow!("Invalid constructor arguments"))?,
            ),
            is_system: self.is_system.map(|x| x.to_bool()).unwrap_or(false),
            force_evmla: self.force_evmla.map(|x| x.to_bool()).unwrap_or(false),
            evm_specific: VerificationEvmSettings {
                evm_version: self.evm_version,
                optimizer_runs: self.runs.map(|x| x.parse().unwrap()),
            },
        })
    }
}

/// Etherscan getsourcecode response.
#[derive(Default, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct EtherscanSourceCodeResponse {
    pub source_code: String,
    #[serde(rename = "ABI")]
    pub abi: String,
    pub contract_name: String,
    pub compiler_version: String,
    pub zk_solc_version: String,
    #[serde(default)]
    pub compiler_type: String,
    pub optimization_used: EtherscanBoolean,
    pub runs: String,
    #[serde(default)]
    pub constructor_arguments: String,
    #[serde(rename = "EVMVersion")]
    pub evm_version: String,
    #[serde(default)]
    pub library: String,
    #[serde(default)]
    pub license_type: String,
    pub proxy: EtherscanBoolean,
    #[serde(default)]
    pub implementation: String,
    #[serde(default)]
    pub swarm_source: String,
    #[serde(default)]
    pub similar_match: String,
}

impl From<Option<VerificationInfo>> for EtherscanSourceCodeResponse {
    /// Converts a VerificationInfo to an EtherscanSourceCodeResponse.
    fn from(verification_info: Option<VerificationInfo>) -> Self {
        // Etherscan API returns an empty response if the contract source code is not verified.
        if verification_info.is_none() {
            return EtherscanSourceCodeResponse {
                abi: "Contract source code not verified".to_string(),
                ..Default::default()
            };
        }
        let verification_info = verification_info.unwrap();
        let compiler_type = match verification_info
            .request
            .req
            .compiler_versions
            .compiler_type()
        {
            CompilerType::Solc => "solc",
            CompilerType::Vyper => "vyper",
        };
        Self {
            source_code: serde_json::to_string(&verification_info.request.req.source_code_data)
                .unwrap_or_default(),
            abi: verification_info.artifacts.abi.to_string(),
            contract_name: verification_info.request.req.contract_name,
            compiler_version: verification_info
                .request
                .req
                .compiler_versions
                .compiler_version()
                .to_string(),
            zk_solc_version: verification_info
                .request
                .req
                .compiler_versions
                .zk_compiler_version()
                .unwrap_or_default()
                .to_string(),
            compiler_type: compiler_type.to_string(),
            optimization_used: EtherscanBoolean::from(
                verification_info.request.req.optimization_used,
            ),
            runs: verification_info
                .request
                .req
                .evm_specific
                .optimizer_runs
                .map(|runs| runs.to_string())
                .unwrap_or_default(),
            // Bytes deserializer returns a string with a leading 0x, so we encode the constructor arguments to hex
            // string manually.
            constructor_arguments: hex::encode(
                verification_info.request.req.constructor_arguments.0,
            ),
            evm_version: verification_info
                .request
                .req
                .evm_specific
                .evm_version
                .unwrap_or_default(),
            library: String::default(),
            license_type: String::default(),
            proxy: EtherscanBoolean::False,
            implementation: String::default(),
            swarm_source: String::default(),
            similar_match: String::default(),
        }
    }
}

/// Payload for Etherscan GET requests. It is used to specify the action to be performed and
/// the data required for that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EtherscanGetPayload {
    GetAbi(Address),
    GetSourceCode(Address),
    CheckVerifyStatus(usize),
}

/// Etherscan API GET request params. Contains the module name and query params for any Etherscan GET action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanGetParams {
    pub module: Option<String>,
    pub action: Option<String>,
    pub address: Option<String>,
    pub guid: Option<String>,
}

impl EtherscanGetParams {
    /// Extracts the address from the Etherscan GET parameters. Returns the same error message as Etherscan
    /// if the address is not valid.
    fn get_address(&self) -> Result<Address, anyhow::Error> {
        if let Ok(address) = Address::from_str(self.address.as_deref().unwrap_or("")) {
            Ok(address)
        } else {
            Err(anyhow::anyhow!("Invalid Address format"))
        }
    }

    /// Converts the Etherscan GET parameters to a payload for the Etherscan API.
    /// Error messages are the same as Etherscan API error messages.
    pub fn get_payload(&self) -> Result<EtherscanGetPayload, anyhow::Error> {
        if self.module != Some("contract".to_string()) {
            return Err(anyhow::anyhow!("Error! Missing Or invalid Module name"));
        }

        if self.action.is_none() {
            return Err(anyhow::anyhow!("Error! Missing Or invalid Action name"));
        }
        let action = self.action.as_deref().unwrap();

        match action {
            "getabi" => Ok(EtherscanGetPayload::GetAbi(self.get_address()?)),
            "getsourcecode" => Ok(EtherscanGetPayload::GetSourceCode(self.get_address()?)),
            "checkverifystatus" => {
                let verification_id = self.guid.clone().unwrap_or_default().parse::<usize>();
                match verification_id {
                    Ok(id) => Ok(EtherscanGetPayload::CheckVerifyStatus(id)),
                    _ => Err(anyhow::anyhow!("Invalid GUID")),
                }
            }
            _ => Err(anyhow::anyhow!("Error! Missing Or invalid Action name")),
        }
    }
}

/// Etherscan API POST request. Contains the module name and the payload for the particular action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanPostRequest {
    pub module: String,
    #[serde(flatten)]
    pub payload: EtherscanPostPayload,
}

/// Etherscan API POST request payload. It is used to specify the action to be performed and the data required for that.
/// Only two actions are supported: `verifysourcecode` and `checkverifystatus`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum EtherscanPostPayload {
    /// Payload for the 'verifysourcecode' action.
    #[serde(rename = "verifysourcecode")]
    VerifySourceCode(EtherscanVerificationRequest),
    /// Payload for the 'checkverifystatus' action.
    #[serde(rename = "checkverifystatus")]
    CheckVerifyStatus { guid: String },
}

/// Etherscan API response result. It can either be a string or a structured response containing the source code.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum EtherscanResult {
    String(String),
    SourceCode(EtherscanSourceCodeResponse),
}

/// Response from Etherscan API. For all supported actions, the result is always a string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherscanResponse {
    pub status: String,
    pub message: String,
    pub result: EtherscanResult,
}

impl EtherscanResponse {
    /// Creates a successful response instance.
    pub fn successful(result: String) -> Self {
        Self {
            status: "1".to_string(),
            message: "OK".to_string(),
            result: EtherscanResult::String(result),
        }
    }

    /// Creates a failed response instance.
    pub fn failed(result: String) -> Self {
        Self {
            status: "0".to_string(),
            message: "NOTOK".to_string(),
            result: EtherscanResult::String(result),
        }
    }
}

impl From<VerificationRequestStatus> for EtherscanResponse {
    /// Converts a `VerificationRequestStatus` to an `EtherscanResponse`.
    fn from(verification_status: VerificationRequestStatus) -> Self {
        match verification_status.status.as_str() {
            "queued" | "in_progress" => EtherscanResponse::failed("Pending in queue".to_string()),
            "successful" => EtherscanResponse::successful("Pass - Verified".to_string()),
            "failed" => EtherscanResponse::failed(format!(
                "Fail - Unable to verify. {}",
                verification_status.error.unwrap_or_default()
            )),
            _ => Self::failed(format!(
                "Fail - Unable to verify. Unknown verification status: {}.",
                verification_status.status
            )),
        }
    }
}
