use std::{
    convert::{TryFrom, TryInto},
    fmt,
    num::ParseIntError,
    ops::{Add, Deref, DerefMut, Sub},
    str::FromStr,
};

use num_enum::TryFromPrimitive;
use serde::{de, Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{
    ethabi::Token,
    vm::VmVersion,
    web3::contract::{Detokenize, Error},
    H256, U256,
};

pub const PACKED_SEMVER_MINOR_OFFSET: u32 = 32;
pub const PACKED_SEMVER_MINOR_MASK: u32 = 0xFFFF;

/// `ProtocolVersionId` is a unique identifier of the protocol version.
///
/// Note, that it is an identifier of the `minor` semver version of the protocol, with
/// the `major` version being `0`. Also, the protocol version on the contracts may contain
/// potential minor versions, that may have different contract behavior (e.g. Verifier), but it should not
/// impact the users.
#[repr(u16)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    TryFromPrimitive,
    Serialize,
    Deserialize,
)]
pub enum ProtocolVersionId {
    Version0 = 0,
    Version1,
    Version2,
    Version3,
    Version4,
    Version5,
    Version6,
    Version7,
    Version8,
    Version9,
    Version10,
    Version11,
    Version12,
    Version13,
    Version14,
    Version15,
    Version16,
    Version17,
    Version18,
    Version19,
    Version20,
    Version21,
    Version22,
    // Version `23` is only present on the internal staging networks.
    // All the user-facing environments were switched from 22 to 24 right away.
    Version23,
    Version24,
    Version25,
    Version26,
    Version27,
    Version28,
    Version29,
    // Version `30` was skipped as an Era upgrade due to version clash with ZKsync OS.
    Version30,
    Version31,
    // Speculative next protocol version for the upgrade integration tests etc.
    Version32,
}

impl ProtocolVersionId {
    pub const fn latest() -> Self {
        Self::Version31
    }

    pub const fn next() -> Self {
        Self::Version32
    }

    pub fn try_from_packed_semver(packed_semver: U256) -> Result<Self, String> {
        ProtocolSemanticVersion::try_from_packed(packed_semver).map(|p| p.minor)
    }

    pub fn into_packed_semver_with_patch(self, patch: usize) -> U256 {
        let minor = U256::from(self as u16);
        let patch = U256::from(patch as u32);

        (minor << U256::from(PACKED_SEMVER_MINOR_OFFSET)) | patch
    }

    /// Returns VM version to be used by API for this protocol version.
    /// We temporary support only two latest VM versions for API.
    pub fn into_api_vm_version(self) -> VmVersion {
        match self {
            ProtocolVersionId::Version0 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version1 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version2 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version3 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version4 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version5 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version6 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version7 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version8 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version9 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version10 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version11 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version12 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version13 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version14 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version15 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version16 => VmVersion::VmVirtualBlocksRefundsEnhancement,
            ProtocolVersionId::Version17 => VmVersion::VmVirtualBlocksRefundsEnhancement,
            ProtocolVersionId::Version18 => VmVersion::VmBoojumIntegration,
            ProtocolVersionId::Version19 => VmVersion::VmBoojumIntegration,
            ProtocolVersionId::Version20 => VmVersion::Vm1_4_1,
            ProtocolVersionId::Version21 => VmVersion::Vm1_4_2,
            ProtocolVersionId::Version22 => VmVersion::Vm1_4_2,
            ProtocolVersionId::Version23 => VmVersion::Vm1_5_0SmallBootloaderMemory,
            ProtocolVersionId::Version24 => VmVersion::Vm1_5_0IncreasedBootloaderMemory,
            ProtocolVersionId::Version25 => VmVersion::Vm1_5_0IncreasedBootloaderMemory,
            ProtocolVersionId::Version26 => VmVersion::VmGateway,
            ProtocolVersionId::Version27 => VmVersion::VmEvmEmulator,
            ProtocolVersionId::Version28 => VmVersion::VmEcPrecompiles,
            ProtocolVersionId::Version29 => VmVersion::VmInterop,
            // Note V30 is only present on zksync os
            ProtocolVersionId::Version30 => VmVersion::VmInterop,
            ProtocolVersionId::Version31 => VmVersion::VmMediumInterop,
            // Speculative VM version for the next protocol version to be used in the upgrade integration test etc.
            ProtocolVersionId::Version32 => VmVersion::VmMediumInterop,
        }
    }

    // It is possible that some external nodes do not store protocol versions for versions below 9.
    // That's why we assume that whenever a protocol version is not present, version 9 is to be used.
    pub fn last_potentially_undefined() -> Self {
        Self::Version9
    }

    pub fn is_pre_boojum(&self) -> bool {
        self <= &Self::Version17
    }

    pub fn is_pre_shared_bridge(&self) -> bool {
        self <= &Self::Version22
    }

    pub fn is_pre_gateway(&self) -> bool {
        self < &Self::gateway_upgrade()
    }

    pub fn is_post_gateway(&self) -> bool {
        self >= &Self::gateway_upgrade()
    }

    pub fn is_pre_fflonk(&self) -> bool {
        self < &Self::Version27
    }

    pub fn is_post_fflonk(&self) -> bool {
        self >= &Self::Version27
    }

    pub fn is_pre_interop_fast_blocks(&self) -> bool {
        self < &Self::Version29
    }

    pub fn is_pre_medium_interop(&self) -> bool {
        self < &Self::Version31
    }

    pub fn is_1_4_0(&self) -> bool {
        self >= &ProtocolVersionId::Version18 && self < &ProtocolVersionId::Version20
    }

    pub fn is_1_4_1(&self) -> bool {
        self == &ProtocolVersionId::Version20
    }

    pub fn is_pre_1_4_1(&self) -> bool {
        self < &ProtocolVersionId::Version20
    }

    pub fn is_post_1_4_1(&self) -> bool {
        self >= &ProtocolVersionId::Version20
    }

    pub fn is_post_1_4_2(&self) -> bool {
        self >= &ProtocolVersionId::Version21
    }

    pub fn is_pre_1_4_2(&self) -> bool {
        self < &ProtocolVersionId::Version21
    }

    pub fn is_1_4_2(&self) -> bool {
        self == &ProtocolVersionId::Version21 || self == &ProtocolVersionId::Version22
    }

    pub fn is_pre_1_5_0(&self) -> bool {
        self < &ProtocolVersionId::Version23
    }

    pub fn is_post_1_5_0(&self) -> bool {
        self >= &ProtocolVersionId::Version23
    }

    pub const fn gateway_upgrade() -> Self {
        ProtocolVersionId::Version26
    }
}

impl Default for ProtocolVersionId {
    fn default() -> Self {
        Self::latest()
    }
}

impl fmt::Display for ProtocolVersionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", *self as u16)
    }
}

impl TryFrom<U256> for ProtocolVersionId {
    type Error = String;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value > U256::from(u16::MAX) {
            Err(format!("unknown protocol version ID: {}", value))
        } else {
            (value.as_u32() as u16)
                .try_into()
                .map_err(|_| format!("unknown protocol version ID: {}", value))
        }
    }
}

/// Highest protocol minor this build can name, and the ceiling
/// [`deserialize_wire_protocol_version`] saturates anything newer to.
///
/// Pinned by `max_known_is_last_variant`: a dependency bump that adds a variant
/// to [`ProtocolVersionId`] must move this constant in the same commit.
pub const MAX_KNOWN_PROTOCOL_VERSION: ProtocolVersionId = ProtocolVersionId::Version32;

/// `serde` adapter for the protocol-minor label on the verifier's input wire.
///
/// # What it does, and why
///
/// [`ProtocolVersionId`] is a closed enum, so its derived codec *rejects* a minor
/// this build cannot name — and on a non-self-describing wire that rejection
/// kills the whole payload decode, leaving nothing able to report which version
/// arrived. This adapter saturates instead: any minor above
/// [`MAX_KNOWN_PROTOCOL_VERSION`] reads as that ceiling. The payload decodes, and
/// the verifier's version gate is what rejects it — a clear domain error instead
/// of a serde error buried in the payload.
///
/// That is the whole gain. The guest aborts either way (`read().expect(..)` in
/// `guest/src/main.rs`), so this buys diagnosis, not a different outcome.
///
/// # Why saturating is safe
///
/// The decoded label selects nothing. `execute` checks it, then overwrites both
/// copies with `PINNED_PROTOCOL_VERSION` before the VM runs, and no commitment
/// ever hashes it. Today a saturated label cannot even reach the overwrite: the
/// gate is an equality and `PINNED_PROTOCOL_VERSION` (`Version31`) sits strictly
/// below the ceiling (`Version32`), so it is always rejected — pinned by
/// `pinned_version_below_max_known_wire_version`.
///
/// Saturating is lossy: raw 33 and raw 60000 both read as `Version32`. That only
/// matters if the gate is ever widened to accept newer minors, where the
/// `vm_run_data` cross-bind could no longer tell two unnameable labels apart.
///
/// # Scope
///
/// The two labels `execute` gates on: `SystemEnv::version` and
/// `VMRunWitnessInputData::protocol_version`. A protocol-upgrade transaction
/// carries a third minor, `ProtocolUpgradeTxCommonData::upgrade_id`, which is not
/// handled here: it feeds the upgrade tx's nonce, so it is carried losslessly as
/// [`ProtocolUpgradeId`] instead.
///
/// # Wire formats
///
/// *Binary* — bincode `standard()`: the fixture corpus, era's mirror structs and
/// the host↔guest `AirbenderCodecV0` channel. The field is a varint integer, and
/// bincode writes a `u16` and an enum variant index identically across the whole
/// `u16` range, so reading it as a `u16` is a drop-in: no fixture needs
/// re-encoding. Pinned by `wire_version_bincode_is_byte_identical`.
///
/// *JSON* — era's prover API: the derived `"VersionNN"` form, plus a bare integer
/// accepted defensively.
///
/// [`Serialize`] stays the derive, making the codec deliberately asymmetric: a
/// label can be read that cannot be written. Round-tripping is unaffected —
/// `load(save(x)) == x` for every `x` constructible in Rust.
pub fn deserialize_wire_protocol_version<'de, D>(
    deserializer: D,
) -> Result<ProtocolVersionId, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // bincode cannot `deserialize_any` (it is not self-describing), so the form
    // has to be chosen by wire kind — the same split `PubdataParams` uses.
    let raw = if deserializer.is_human_readable() {
        deserializer.deserialize_any(WireProtocolVersionVisitor)?
    } else {
        deserializer.deserialize_u16(WireProtocolVersionVisitor)?
    };

    match ProtocolVersionId::try_from(raw) {
        Ok(version) => Ok(version),
        Err(_) if raw > MAX_KNOWN_PROTOCOL_VERSION as u16 => Ok(MAX_KNOWN_PROTOCOL_VERSION),
        // Unreachable while the enum is contiguous; kept so a future gap in the
        // variant list fails loudly instead of saturating a *lower* unknown.
        Err(err) => Err(de::Error::custom(err)),
    }
}

/// Reads the raw minor number from either wire form. See
/// [`deserialize_wire_protocol_version`].
struct WireProtocolVersionVisitor;

impl<'de> de::Visitor<'de> for WireProtocolVersionVisitor {
    type Value = u16;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a protocol minor version as `\"VersionNN\"` or a number")
    }

    /// Accepts exactly the form the derived `Serialize` writes. `u16::from_str`
    /// alone would also take `"Version+31"` and `"Version031"`, which nothing
    /// produces and the derived codec rejects.
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        value
            .strip_prefix("Version")
            .filter(|digits| {
                !digits.is_empty()
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && (digits.len() == 1 || !digits.starts_with('0'))
            })
            .and_then(|digits| digits.parse::<u16>().ok())
            .ok_or_else(|| E::invalid_value(de::Unexpected::Str(value), &self))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        u16::try_from(value).map_err(|_| E::invalid_value(de::Unexpected::Unsigned(value), &self))
    }
}

/// The protocol minor named by a protocol-upgrade transaction, as the raw wire
/// number.
///
/// Unlike the two labels it is not clamped: the value becomes the upgrade tx's
/// nonce and so feeds its canonical hash. Wire form is byte-identical to the
/// derived [`ProtocolVersionId`] codec in both directions; it can additionally
/// carry, and re-emit unchanged, a minor this build cannot name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolUpgradeId(u16);

impl ProtocolUpgradeId {
    /// The raw minor as it appeared on the wire; the upgrade tx's nonce.
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl Default for ProtocolUpgradeId {
    fn default() -> Self {
        Self::from(ProtocolVersionId::default())
    }
}

impl From<ProtocolVersionId> for ProtocolUpgradeId {
    fn from(value: ProtocolVersionId) -> Self {
        Self(value as u16)
    }
}

impl From<u16> for ProtocolUpgradeId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// Fails for a minor this build cannot name; use [`ProtocolUpgradeId::raw`] for
/// the nonce.
impl TryFrom<ProtocolUpgradeId> for ProtocolVersionId {
    type Error = String;

    fn try_from(value: ProtocolUpgradeId) -> Result<Self, Self::Error> {
        Self::try_from(value.0).map_err(|_| format!("unknown protocol version ID: {}", value.0))
    }
}

impl TryFrom<U256> for ProtocolUpgradeId {
    type Error = String;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value > U256::from(u16::MAX) {
            Err(format!("protocol upgrade ID out of range: {value}"))
        } else {
            Ok(Self(value.as_u32() as u16))
        }
    }
}

impl Serialize for ProtocolUpgradeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Mirror the derived codec: variant name when self-describing, index
        // otherwise. The host re-encodes for the guest, so this side matters too.
        if s.is_human_readable() {
            s.serialize_str(&format!("Version{}", self.0))
        } else {
            s.serialize_u16(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ProtocolUpgradeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // bincode cannot `deserialize_any`, so pick the form by wire kind.
        let raw = if d.is_human_readable() {
            d.deserialize_any(WireProtocolVersionVisitor)?
        } else {
            d.deserialize_u16(WireProtocolVersionVisitor)?
        };
        Ok(Self(raw))
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierParams {
    pub recursion_node_level_vk_hash: H256,
    pub recursion_leaf_level_vk_hash: H256,
    pub recursion_circuits_set_vks_hash: H256,
}

impl Detokenize for VerifierParams {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self, Error> {
        if tokens.len() != 1 {
            return Err(Error::InvalidOutputType(format!(
                "expected single token, got {tokens:?}"
            )));
        }

        let tokens = match tokens[0].clone() {
            Token::Tuple(tokens) => tokens,
            other => {
                return Err(Error::InvalidOutputType(format!(
                    "expected a tuple, got {other:?}"
                )));
            }
        };

        let vks_vec: Vec<H256> = tokens
            .into_iter()
            .map(|token| H256::from_slice(&token.into_fixed_bytes().unwrap()))
            .collect();
        Ok(VerifierParams {
            recursion_node_level_vk_hash: vks_vec[0],
            recursion_leaf_level_vk_hash: vks_vec[1],
            recursion_circuits_set_vks_hash: vks_vec[2],
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct L1VerifierConfig {
    // Rename is required to not introduce breaking changes in the API for existing clients.
    #[serde(
        alias = "recursion_scheduler_level_vk_hash",
        rename(serialize = "recursion_scheduler_level_vk_hash")
    )]
    pub snark_wrapper_vk_hash: H256,
    pub fflonk_snark_wrapper_vk_hash: Option<H256>,
}

impl From<ProtocolVersionId> for VmVersion {
    fn from(value: ProtocolVersionId) -> Self {
        match value {
            ProtocolVersionId::Version0 => VmVersion::M5WithoutRefunds,
            ProtocolVersionId::Version1 => VmVersion::M5WithoutRefunds,
            ProtocolVersionId::Version2 => VmVersion::M5WithRefunds,
            ProtocolVersionId::Version3 => VmVersion::M5WithRefunds,
            ProtocolVersionId::Version4 => VmVersion::M6Initial,
            ProtocolVersionId::Version5 => VmVersion::M6BugWithCompressionFixed,
            ProtocolVersionId::Version6 => VmVersion::M6BugWithCompressionFixed,
            ProtocolVersionId::Version7 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version8 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version9 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version10 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version11 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version12 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version13 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version14 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version15 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version16 => VmVersion::VmVirtualBlocksRefundsEnhancement,
            ProtocolVersionId::Version17 => VmVersion::VmVirtualBlocksRefundsEnhancement,
            ProtocolVersionId::Version18 => VmVersion::VmBoojumIntegration,
            ProtocolVersionId::Version19 => VmVersion::VmBoojumIntegration,
            ProtocolVersionId::Version20 => VmVersion::Vm1_4_1,
            ProtocolVersionId::Version21 => VmVersion::Vm1_4_2,
            ProtocolVersionId::Version22 => VmVersion::Vm1_4_2,
            ProtocolVersionId::Version23 => VmVersion::Vm1_5_0SmallBootloaderMemory,
            ProtocolVersionId::Version24 => VmVersion::Vm1_5_0IncreasedBootloaderMemory,
            ProtocolVersionId::Version25 => VmVersion::Vm1_5_0IncreasedBootloaderMemory,
            ProtocolVersionId::Version26 => VmVersion::VmGateway,
            ProtocolVersionId::Version27 => VmVersion::VmEvmEmulator,
            ProtocolVersionId::Version28 => VmVersion::VmEcPrecompiles,
            ProtocolVersionId::Version29 => VmVersion::VmInterop,
            ProtocolVersionId::Version30 => VmVersion::VmInterop,
            ProtocolVersionId::Version31 => VmVersion::VmMediumInterop,
            // Speculative VM version for the next protocol version to be used in the upgrade integration test etc.
            ProtocolVersionId::Version32 => VmVersion::VmMediumInterop,
        }
    }
}

basic_type!(
    /// Patch part of semantic protocol version.
    VersionPatch,
    u32
);

/// Semantic protocol version.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializeDisplay, DeserializeFromStr, Hash, PartialOrd, Ord,
)]
pub struct ProtocolSemanticVersion {
    pub minor: ProtocolVersionId,
    pub patch: VersionPatch,
}

impl ProtocolSemanticVersion {
    const MAJOR_VERSION: u8 = 0;

    pub fn new(minor: ProtocolVersionId, patch: VersionPatch) -> Self {
        Self { minor, patch }
    }

    pub fn try_from_packed(packed: U256) -> Result<Self, String> {
        let minor = ((packed >> U256::from(PACKED_SEMVER_MINOR_OFFSET))
            & U256::from(PACKED_SEMVER_MINOR_MASK))
        .try_into()?;
        let patch = packed.0[0] as u32;

        Ok(Self {
            minor,
            patch: VersionPatch(patch),
        })
    }

    pub fn pack(&self) -> U256 {
        (U256::from(self.minor as u16) << U256::from(PACKED_SEMVER_MINOR_OFFSET))
            | U256::from(self.patch.0)
    }
}

impl fmt::Display for ProtocolSemanticVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            Self::MAJOR_VERSION,
            self.minor as u16,
            self.patch
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseProtocolSemanticVersionError {
    #[error("invalid format")]
    InvalidFormat,
    #[error("non zero major version")]
    NonZeroMajorVersion,
    #[error("{0}")]
    ParseIntError(ParseIntError),
}

impl FromStr for ProtocolSemanticVersion {
    type Err = ParseProtocolSemanticVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(ParseProtocolSemanticVersionError::InvalidFormat);
        }

        let major = parts[0]
            .parse::<u16>()
            .map_err(ParseProtocolSemanticVersionError::ParseIntError)?;
        if major != 0 {
            return Err(ParseProtocolSemanticVersionError::NonZeroMajorVersion);
        }

        let minor = parts[1]
            .parse::<u16>()
            .map_err(ParseProtocolSemanticVersionError::ParseIntError)?;
        let minor = ProtocolVersionId::try_from(minor)
            .map_err(|_| ParseProtocolSemanticVersionError::InvalidFormat)?;

        let patch = parts[2]
            .parse::<u32>()
            .map_err(ParseProtocolSemanticVersionError::ParseIntError)?;

        Ok(ProtocolSemanticVersion {
            minor,
            patch: patch.into(),
        })
    }
}

impl Default for ProtocolSemanticVersion {
    fn default() -> Self {
        Self {
            minor: Default::default(),
            patch: 0.into(),
        }
    }
}

#[cfg(test)]
mod wire_protocol_version_tests {
    use super::*;

    /// Stand-in for the real input fields that carry the label
    /// (`SystemEnv::version`, `VMRunWitnessInputData::protocol_version`). bincode
    /// writes no struct header, so a one-field struct encodes exactly as its
    /// field — which is what makes the byte-identity assertion below meaningful.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Wrapper {
        #[serde(deserialize_with = "deserialize_wire_protocol_version")]
        version: ProtocolVersionId,
    }

    fn nameable_versions() -> impl Iterator<Item = ProtocolVersionId> {
        (0..=MAX_KNOWN_PROTOCOL_VERSION as u16)
            .map(|raw| ProtocolVersionId::try_from(raw).expect("the variant list is contiguous"))
    }

    /// Change detector: a bump that appends a variant must move
    /// [`MAX_KNOWN_PROTOCOL_VERSION`] in the same commit.
    ///
    /// A stale constant does *not* cause rejections — `try_from` still succeeds
    /// for every nameable variant. The hazard is the inverse: an unnameable value
    /// would saturate to a ceiling *below* the newest nameable version, falsifying
    /// the invariant [`deserialize_wire_protocol_version`] rests on.
    #[test]
    fn max_known_is_last_variant() {
        let max = MAX_KNOWN_PROTOCOL_VERSION as u16;
        assert!(ProtocolVersionId::try_from(max).is_ok());
        assert!(
            ProtocolVersionId::try_from(max + 1).is_err(),
            "ProtocolVersionId gained a variant above {MAX_KNOWN_PROTOCOL_VERSION:?}; \
             update MAX_KNOWN_PROTOCOL_VERSION"
        );
    }

    /// The corpus-compatibility pin: the adapter reads exactly what the derived
    /// enum codec writes, so no `*.bin.gz` fixture needs re-encoding.
    #[test]
    fn wire_version_bincode_is_byte_identical() {
        let cfg = bincode::config::standard();
        for version in nameable_versions() {
            let from_enum = bincode::serde::encode_to_vec(version, cfg).expect("encode enum");
            let from_u16 =
                bincode::serde::encode_to_vec(version as u16, cfg).expect("encode raw u16");
            assert_eq!(from_enum, from_u16, "byte layout differs for {version:?}");

            let (decoded, read) = bincode::serde::decode_from_slice::<Wrapper, _>(&from_enum, cfg)
                .expect("adapter decode");
            assert_eq!(decoded.version, version);
            assert_eq!(read, from_enum.len(), "trailing bytes for {version:?}");
        }
    }

    #[test]
    fn wire_version_json_matches_derived() {
        for version in nameable_versions() {
            // The form era's derived `Serialize` puts on the JSON prover API.
            let derived = serde_json::to_string(&version).expect("serialize");
            let decoded: Wrapper =
                serde_json::from_str(&format!(r#"{{"version":{derived}}}"#)).expect("named form");
            assert_eq!(decoded.version, version);

            // The defensive bare-number form.
            let decoded: Wrapper =
                serde_json::from_str(&format!(r#"{{"version":{}}}"#, version as u16))
                    .expect("numeric form");
            assert_eq!(decoded.version, version);
        }
    }

    /// The point of the adapter: a minor this build cannot name decodes instead
    /// of aborting the whole payload, and lands on the newest one it can name.
    #[test]
    fn wire_version_accepts_unnameable_newer() {
        let cfg = bincode::config::standard();
        let raw = MAX_KNOWN_PROTOCOL_VERSION as u16 + 1;

        // `raw` is a single-byte varint; 60_000 exercises the `U16_BYTE` marker
        // path, which no honest payload carries but a hostile one can. Both must
        // decode rather than abort the payload; rejecting them is the verifier's
        // accept gate's job, not the codec's.
        for raw in [raw, 60_000_u16] {
            let bytes = bincode::serde::encode_to_vec(raw, cfg).expect("encode raw u16");
            let (decoded, read) = bincode::serde::decode_from_slice::<Wrapper, _>(&bytes, cfg)
                .unwrap_or_else(|e| panic!("binary decode of {raw}: {e}"));
            assert_eq!(decoded.version, MAX_KNOWN_PROTOCOL_VERSION, "raw {raw}");
            assert_eq!(read, bytes.len(), "raw {raw}");
        }

        for json in [
            format!(r#"{{"version":"Version{raw}"}}"#),
            format!(r#"{{"version":{raw}}}"#),
            r#"{"version":60000}"#.to_owned(),
        ] {
            let decoded: Wrapper = serde_json::from_str(&json).expect(&json);
            assert_eq!(decoded.version, MAX_KNOWN_PROTOCOL_VERSION, "{json}");
        }
    }

    #[test]
    fn wire_version_rejects_unparseable_label() {
        for json in [
            r#"{"version":"nonsense"}"#,
            r#"{"version":"Version"}"#,
            r#"{"version":-1}"#,
            r#"{"version":null}"#,
            // Non-canonical string forms `u16::from_str` would otherwise accept.
            r#"{"version":"Version+31"}"#,
            r#"{"version":"Version031"}"#,
            r#"{"version":"Version 31"}"#,
            // The bare-digit form is the numeric case, not the string one.
            r#"{"version":"31"}"#,
        ] {
            assert!(
                serde_json::from_str::<Wrapper>(json).is_err(),
                "expected {json} to be rejected"
            );
        }
    }
}

#[cfg(test)]
mod protocol_upgrade_id_tests {
    use super::*;

    fn nameable() -> impl Iterator<Item = ProtocolVersionId> {
        (0..=MAX_KNOWN_PROTOCOL_VERSION as u16)
            .map(|raw| ProtocolVersionId::try_from(raw).expect("the variant list is contiguous"))
    }

    /// Byte-identical to the codec it replaces, both directions — the host
    /// re-encodes the input for the guest.
    #[test]
    fn upgrade_id_bincode_matches_protocol_version_id() {
        let cfg = bincode::config::standard();
        for version in nameable() {
            let from_enum = bincode::serde::encode_to_vec(version, cfg).expect("encode enum");
            let from_new = bincode::serde::encode_to_vec(ProtocolUpgradeId::from(version), cfg)
                .expect("encode newtype");
            assert_eq!(from_new, from_enum, "byte layout differs for {version:?}");

            let (decoded, read) =
                bincode::serde::decode_from_slice::<ProtocolUpgradeId, _>(&from_enum, cfg)
                    .expect("decode newtype");
            assert_eq!(decoded.raw(), version as u16, "{version:?}");
            assert_eq!(read, from_enum.len(), "trailing bytes for {version:?}");
        }
    }

    /// Same on the JSON wire.
    #[test]
    fn upgrade_id_json_matches_protocol_version_id() {
        for version in nameable() {
            let from_enum = serde_json::to_string(&version).expect("serialize enum");
            let from_new = serde_json::to_string(&ProtocolUpgradeId::from(version))
                .expect("serialize newtype");
            assert_eq!(from_new, from_enum, "JSON form differs for {version:?}");

            let decoded: ProtocolUpgradeId =
                serde_json::from_str(&from_enum).expect("decode newtype");
            assert_eq!(decoded.raw(), version as u16);
        }
    }

    /// Why this type exists: the value is the tx nonce, so an unnameable minor
    /// must decode *and re-encode to the same bytes*. Clamping must not happen.
    #[test]
    fn unnameable_minor_round_trips_losslessly() {
        let cfg = bincode::config::standard();
        for raw in [MAX_KNOWN_PROTOCOL_VERSION as u16 + 1, 45, 60_000, u16::MAX] {
            assert!(
                ProtocolVersionId::try_from(raw).is_err(),
                "raw {raw} is nameable; pick a value this build cannot name"
            );

            let bytes = bincode::serde::encode_to_vec(raw, cfg).expect("encode raw u16");

            // The strict enum rejects exactly these bytes — the original abort.
            assert!(
                bincode::serde::decode_from_slice::<ProtocolVersionId, _>(&bytes, cfg).is_err(),
                "raw {raw} should be undecodable as the closed enum; the comparison below is \
                 meaningless otherwise"
            );

            let (decoded, read) =
                bincode::serde::decode_from_slice::<ProtocolUpgradeId, _>(&bytes, cfg)
                    .unwrap_or_else(|e| panic!("decode of raw {raw}: {e}"));

            assert_eq!(decoded.raw(), raw, "value must survive decode unchanged");
            assert_ne!(
                decoded.raw(),
                MAX_KNOWN_PROTOCOL_VERSION as u16,
                "raw {raw} was saturated — that would corrupt the upgrade tx nonce"
            );
            assert_eq!(read, bytes.len(), "trailing bytes for raw {raw}");

            let re_encoded = bincode::serde::encode_to_vec(decoded, cfg).expect("re-encode");
            assert_eq!(re_encoded, bytes, "re-encode differs for raw {raw}");

            // The same value on the JSON wire, and back.
            let json = serde_json::to_string(&decoded).expect("serialize");
            assert_eq!(json, format!("\"Version{raw}\""));
            let back: ProtocolUpgradeId = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back.raw(), raw);
        }
    }

    /// Naming stays fallible; the newtype only widens what can be carried.
    #[test]
    fn naming_an_unnameable_minor_fails() {
        assert_eq!(
            ProtocolVersionId::try_from(ProtocolUpgradeId::from(PINNED_SELF_CHECK)).unwrap(),
            PINNED_SELF_CHECK
        );
        assert!(ProtocolVersionId::try_from(ProtocolUpgradeId::from(
            MAX_KNOWN_PROTOCOL_VERSION as u16 + 1
        ))
        .is_err());
    }

    const PINNED_SELF_CHECK: ProtocolVersionId = ProtocolVersionId::Version31;
}
