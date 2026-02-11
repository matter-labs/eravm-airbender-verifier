use std::fmt;

use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};

use crate::{bytecode::BytecodeMarker, web3::keccak256, H256};

/// An identifier of the contract bytecode.
///
/// This identifier can be used to detect different contracts that share the same sources,
/// even if they differ in bytecode verbatim (e.g. if the contract metadata is different).
///
/// Identifier depends on the marker of the bytecode of the contract.
/// This might be important, since the metadata can be different for EVM and EraVM,
/// e.g. `zksolc` [supports][zksolc_keccak] keccak256 hash of the metadata as an alternative to CBOR.
///
/// [zksolc_keccak]: https://matter-labs.github.io/era-compiler-solidity/latest/02-command-line-interface.html#--metadata-hash
// Note: there are missing opportunities here, e.g. Etherscan is able to detect the contracts
// that differ in creation bytecode and/or constructor arguments (for partial match). This is
// less relevant for ZKsync, since there is no concept of creation bytecode there; although
// this may become needed if we will extend the EVM support.
#[derive(Debug, Clone)]
pub struct ContractIdentifier {
    /// Marker of the bytecode of the contract.
    pub bytecode_marker: BytecodeMarker,
    /// keccak256 hash of the full contract bytecode.
    /// Can be used as an identifier of precise contract compilation.
    pub bytecode_keccak256: H256,
    /// keccak256 hash of the contract bytecode without metadata (e.g. with either
    /// CBOR or keccak256 metadata hash being stripped).
    /// If no metadata is detected, equal to `bytecode_keccak256`.
    pub bytecode_without_metadata_keccak256: H256,
    /// Kind of detected metadata.
    pub detected_metadata: Option<DetectedMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Match {
    /// Contracts are identical.
    Full,
    /// Metadata is different.
    Partial,
    /// No match.
    None,
}

/// Metadata detected in the contract bytecode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedMetadata {
    /// keccak256 metadata (only for EraVM)
    Keccak256,
    /// CBOR metadata
    Cbor {
        /// Length of metadata in the bytecode, including encoded length of CBOR and padding.
        full_length: usize,
        metadata: CborMetadata,
    },
}

impl DetectedMetadata {
    /// Returns full length (in bytes) of metadata in the bytecode.
    pub fn length(&self) -> usize {
        match self {
            DetectedMetadata::Keccak256 => 32,
            DetectedMetadata::Cbor {
                full_length,
                metadata: _,
            } => *full_length,
        }
    }
}

/// Represents the compiler version in the Cbor metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CborCompilerVersion {
    /// For native solidity and vyper compilers, it is a 3 byte encoding of the compiler version: one byte each for major,
    /// minor and patch version number. For example, 0.8.28 is encoded as [0, 8, 28].
    /// More details can be found here:
    /// https://docs.soliditylang.org/en/latest/metadata.html#encoding-of-the-metadata-hash-in-the-bytecode
    Native(Vec<u8>),
    /// For ZKsync solidity compiler, the value consists of semicolon-separated pairs of colon-separated
    /// compiler names and versions. For example: "zksolc:<version>" or "zksolc:<version>;solc:<version>;llvm:<version>".
    /// More details can be found here:
    /// https://matter-labs.github.io/era-compiler-solidity/latest/02-command-line-interface.html#--metadata-hash
    ///
    /// For ZKsync vyper compiler, it's "zkvyper:<version>" or "zkvyper:<version>;vyper:<version>".
    /// More details can be found here:
    /// https://matter-labs.github.io/era-compiler-vyper/latest/02-command-line-interface.html#--metadata-hash
    ZKsync(String),
}

impl CborCompilerVersion {
    /// Returns the compiler versions from the metadata in a tuple (compiler_version, zk_compiler_version).
    pub fn get_compiler_versions(&self) -> (Option<String>, Option<String>) {
        match self {
            CborCompilerVersion::Native(compiler_version) => {
                // For native Solc and Vyper compilers, CBOR is a 3 byte encoding of the compiler version: one byte each
                // for major, minor and patch version number. For example, 0.8.28 is encoded as [0, 8, 28].
                if compiler_version.len() == 3 {
                    let version_str = format!(
                        "{}.{}.{}",
                        compiler_version[0], compiler_version[1], compiler_version[2]
                    );
                    (Some(version_str), None)
                } else {
                    (None, None)
                }
            }
            CborCompilerVersion::ZKsync(compiler_versions) => {
                // For ZKsync compilers, the value consists of semicolon-separated pairs of colon-separated compiler names
                // and versions. For example: "zksolc:1.5.13", "zkvyper:1.5.10;vyper:0.4.1" or
                // "zksolc:1.5.13;solc:0.8.29;llvm:1.0.2".
                // It can also contain a pre-release compiler version as a string, but we intentionally return None in such cases,
                // as we don't support verification for such contracts.
                let compilers_parts: Vec<&str> = compiler_versions
                    .split(';')
                    .filter_map(|part| part.split_once(':').map(|(_, value)| value))
                    .collect();

                // Prerelease compiler version is not supported for verification so None is returned.
                if compilers_parts.is_empty() {
                    return (None, None);
                }
                let mut compiler_version = None;
                // Extract zk compiler version
                let zk_compiler_version = Some(format!("v{}", compilers_parts[0]));

                // Processing "zkvyper:<version>;vyper:<version>" version
                if compilers_parts.len() == 2 {
                    compiler_version = Some(compilers_parts[1].to_string());
                } else if compilers_parts.len() == 3 {
                    // Processing "zksolc:<version>;solc:<version>;llvm:<version>" version.
                    compiler_version = Some(format!(
                        "zkVM-{}-{}",
                        compilers_parts[1], compilers_parts[2]
                    ));
                }

                (compiler_version, zk_compiler_version)
            }
        }
    }
}

/// Possible values for the metadata hashes structure.
/// Details can be found here: https://docs.soliditylang.org/en/latest/metadata.html
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CborMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipfs: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bzzr1: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bzzr0: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<bool>,
    // CborMetadata is deserialized with ciborium which doesn't properly deserialize CborCompilerVersion
    // with it's variants. That's why we need a custom deserializer.
    #[serde(default, deserialize_with = "deserialize_cbor_compiler")]
    pub solc: Option<CborCompilerVersion>,
    #[serde(default, deserialize_with = "deserialize_cbor_compiler")]
    pub vyper: Option<CborCompilerVersion>,
}

impl CborMetadata {
    /// Returns the compiler versions from the metadata in a tuple (compiler_version, zk_compiler_version)
    /// for both solc and vyper.
    pub fn get_compiler_versions(&self) -> (Option<String>, Option<String>) {
        let compiler_version = self.solc.as_ref().or(self.vyper.as_ref());
        match compiler_version {
            Some(compiler_version) => compiler_version.get_compiler_versions(),
            None => (None, None),
        }
    }
}

struct CborCompilerVersionVisitor;
impl<'de> Visitor<'de> for CborCompilerVersionVisitor {
    type Value = Option<CborCompilerVersion>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte array or a string")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Some(CborCompilerVersion::Native(value.to_vec())))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Some(CborCompilerVersion::ZKsync(value.to_string())))
    }
}

/// Custom deserializer for CborCompilerVersion so it's properly deserialized with ciborium.
fn deserialize_cbor_compiler<'de, D>(
    deserializer: D,
) -> Result<Option<CborCompilerVersion>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_any(CborCompilerVersionVisitor)
}

impl ContractIdentifier {
    pub fn from_bytecode(bytecode_marker: BytecodeMarker, bytecode: &[u8]) -> Self {
        // Calculate the hash for bytecode with metadata.
        let bytecode_keccak256 = H256(keccak256(bytecode));

        // Try to detect metadata.
        // CBOR takes precedence (since keccak doesn't have direct markers, so it's partially a
        // fallback).
        let (detected_metadata, bytecode_without_metadata_keccak256) =
            if let Some((full_length, hash, metadata)) =
                Self::detect_cbor_metadata(bytecode_marker, bytecode)
            {
                let detected_metadata = DetectedMetadata::Cbor {
                    full_length,
                    metadata,
                };
                (Some(detected_metadata), hash)
            } else if let Some(hash) = Self::detect_keccak_metadata(bytecode_marker, bytecode) {
                (Some(DetectedMetadata::Keccak256), hash)
            } else {
                // Fallback
                (None, bytecode_keccak256)
            };

        Self {
            bytecode_marker,
            bytecode_keccak256,
            bytecode_without_metadata_keccak256,
            detected_metadata,
        }
    }

    /// Will try to detect keccak256 metadata hash (only for EraVM)
    fn detect_keccak_metadata(bytecode_marker: BytecodeMarker, bytecode: &[u8]) -> Option<H256> {
        // For EraVM, the one option for metadata hash is keccak256 hash of the metadata.
        if bytecode_marker == BytecodeMarker::EraVm {
            // For metadata, we might have padding: it takes either 32 or 64 bytes depending
            // on whether the amount of words in the contract is odd, so we need to check
            // if there is padding.
            let bytecode_without_metadata = Self::strip_padding(bytecode, 32)?;
            let hash = H256(keccak256(bytecode_without_metadata));
            Some(hash)
        } else {
            None
        }
    }

    /// Will try to detect CBOR metadata.
    fn detect_cbor_metadata(
        bytecode_marker: BytecodeMarker,
        bytecode: &[u8],
    ) -> Option<(usize, H256, CborMetadata)> {
        let length = bytecode.len();

        // Last two bytes is the length of the metadata in big endian.
        if length < 2 {
            return None;
        }
        let metadata_length =
            u16::from_be_bytes([bytecode[length - 2], bytecode[length - 1]]) as usize;
        // Including size
        let full_metadata_length = metadata_length + 2;

        // Get slice for the metadata.
        if length < full_metadata_length {
            return None;
        }
        let raw_metadata = &bytecode[length - full_metadata_length..length - 2];
        // Try decoding. We are not interested in the actual value.
        let metadata: CborMetadata = match ciborium::from_reader(raw_metadata) {
            Ok(metadata) => metadata,
            Err(_) => return None,
        };

        // Strip metadata and calculate hash.
        let bytecode_without_metadata = match bytecode_marker {
            BytecodeMarker::Evm => {
                // On EVM, there is no padding.
                &bytecode[..length - full_metadata_length]
            }
            BytecodeMarker::EraVm => {
                // On EraVM, there is padding:
                // 1. We must align the metadata length to 32 bytes.
                // 2. We may need to add 32 bytes of padding.
                let aligned_metadata_length = metadata_length.div_ceil(32) * 32;
                Self::strip_padding(bytecode, aligned_metadata_length)?
            }
        };
        let hash = H256(keccak256(bytecode_without_metadata));
        Some((full_metadata_length, hash, metadata))
    }

    /// Adds one word to the metadata length and check if it's a padding word.
    /// If it is, strips the padding.
    /// Returns `None` if `metadata_length` + padding won't fit into the bytecode.
    fn strip_padding(bytecode: &[u8], metadata_length: usize) -> Option<&[u8]> {
        const PADDING_WORD: [u8; 32] = [0u8; 32];

        let length = bytecode.len();
        let metadata_with_padding_length = metadata_length + 32;
        if length < metadata_with_padding_length {
            return None;
        }
        if bytecode[length - metadata_with_padding_length..length - metadata_length] == PADDING_WORD
        {
            // Padding was added, strip it.
            Some(&bytecode[..length - metadata_with_padding_length])
        } else {
            // Padding wasn't added, strip metadata only.
            Some(&bytecode[..length - metadata_length])
        }
    }

    /// Checks the kind of match between identifier and other bytecode.
    pub fn matches(&self, other: &Self) -> Match {
        if self.bytecode_keccak256 == other.bytecode_keccak256 {
            return Match::Full;
        }

        // Check if metadata is different.
        // Note that here we do not handle "complex" cases, e.g. lack of metadata in one contract
        // and presence in another, or different kinds of metadata. This is OK: partial
        // match is needed mostly when you cannot reproduce the original metadata, but one always
        // can submit the contract with the same metadata kind.
        if self.bytecode_without_metadata_keccak256 == other.bytecode_without_metadata_keccak256 {
            return Match::Partial;
        }

        Match::None
    }

    /// Returns the length of the metadata in the bytecode.
    pub fn metadata_length(&self) -> usize {
        self.detected_metadata
            .clone()
            .as_ref()
            .map_or(0, DetectedMetadata::length)
    }
}
