use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SLChainId;

/// An enum which is used to describe whether a zkSync network settles to L1 or to the gateway.
/// Gateway is an Ethereum-compatible L2 and so it requires different treatment with regards to DA handling.
///
/// Wire format depends on the serializer: human-readable formats (JSON) emit
/// the adjacent-tagged form upstream uses (`{"type":"L1","chain_id":1}`), so a
/// payload produced by upstream's `axum::Json(...)` round-trips here. Binary
/// formats (bincode) fall back to the externally-tagged form, which they can
/// actually encode — bincode does not implement `deserialize_identifier`, so
/// `#[serde(tag, content)]` is unusable on the binary wire.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SettlementLayer {
    L1(SLChainId),
    Gateway(SLChainId),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "chain_id")]
enum JsonRepr {
    L1(SLChainId),
    Gateway(SLChainId),
}

#[derive(Serialize, Deserialize)]
enum BinaryRepr {
    L1(SLChainId),
    Gateway(SLChainId),
}

impl From<SettlementLayer> for JsonRepr {
    fn from(value: SettlementLayer) -> Self {
        match value {
            SettlementLayer::L1(id) => Self::L1(id),
            SettlementLayer::Gateway(id) => Self::Gateway(id),
        }
    }
}

impl From<JsonRepr> for SettlementLayer {
    fn from(value: JsonRepr) -> Self {
        match value {
            JsonRepr::L1(id) => Self::L1(id),
            JsonRepr::Gateway(id) => Self::Gateway(id),
        }
    }
}

impl From<SettlementLayer> for BinaryRepr {
    fn from(value: SettlementLayer) -> Self {
        match value {
            SettlementLayer::L1(id) => Self::L1(id),
            SettlementLayer::Gateway(id) => Self::Gateway(id),
        }
    }
}

impl From<BinaryRepr> for SettlementLayer {
    fn from(value: BinaryRepr) -> Self {
        match value {
            BinaryRepr::L1(id) => Self::L1(id),
            BinaryRepr::Gateway(id) => Self::Gateway(id),
        }
    }
}

impl Serialize for SettlementLayer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            JsonRepr::from(*self).serialize(serializer)
        } else {
            BinaryRepr::from(*self).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for SettlementLayer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            JsonRepr::deserialize(deserializer).map(Self::from)
        } else {
            BinaryRepr::deserialize(deserializer).map(Self::from)
        }
    }
}

impl Default for SettlementLayer {
    fn default() -> Self {
        Self::L1(SLChainId(1))
    }
}

impl SettlementLayer {
    pub fn is_gateway(self) -> bool {
        matches!(self, Self::Gateway(_))
    }
    pub fn chain_id(&self) -> SLChainId {
        match self {
            Self::L1(chain_id) | Self::Gateway(chain_id) => *chain_id,
        }
    }
    pub fn for_tests() -> Self {
        // 9 is a common chain id for localhost
        Self::L1(SLChainId(9))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the JSON wire format to upstream zksync-era's adjacent-tagged form.
    /// Upstream emits this shape via `axum::Json(...)` from
    /// `core/node/airbender_proof_data_handler/src/lib.rs`, and our server
    /// consumes it via `reqwest::Response::json`. If this test breaks, our
    /// server will fail to deserialize upstream's proof inputs.
    #[test]
    fn json_wire_matches_upstream_adjacent_tagged_form() {
        let json = serde_json::to_string(&SettlementLayer::L1(SLChainId(42))).unwrap();
        assert_eq!(json, r#"{"type":"L1","chain_id":42}"#);

        let gw = serde_json::to_string(&SettlementLayer::Gateway(SLChainId(7))).unwrap();
        assert_eq!(gw, r#"{"type":"Gateway","chain_id":7}"#);

        let parsed: SettlementLayer = serde_json::from_str(r#"{"type":"L1","chain_id":42}"#).unwrap();
        assert_eq!(parsed, SettlementLayer::L1(SLChainId(42)));
    }

    /// Bincode encoders (used by the local corpus and the cli_utils
    /// load/save path) cannot drive serde's adjacent-tagged form because
    /// `Deserializer::deserialize_identifier` is unimplemented. The
    /// is_human_readable=false branch must round-trip cleanly.
    #[test]
    fn bincode_roundtrip() {
        let original = SettlementLayer::Gateway(SLChainId(123));
        let bytes = bincode::serde::encode_to_vec(original, bincode::config::standard()).unwrap();
        let (decoded, _): (SettlementLayer, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded, original);
    }
}
