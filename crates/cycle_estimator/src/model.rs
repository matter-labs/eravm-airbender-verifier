//! The fitted cost model and cycle-count prediction.
//!
//! The model is a set of non-negative linear predictors (one per verify() phase,
//! plus an aggregate `total`) of the form `cycles = base + Σ coeff_i · feature_i`,
//! learned offline by `scripts/cycle_model/fit_cost_model.py`. The canonical
//! fitted table is committed at `model/cost_table.json` and compiled into the
//! binary via `include_str!`, so a deployed sequencer needs no model file on disk.
//!
//! To ship a new model: refit, drop the resulting `cost_table.json` into
//! `crates/cycle_estimator/model/`, and rebuild (see `scripts/cycle_model/README.md`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::estimator::CycleEstimate;
use crate::features::{FeatureId, FeatureVector, SAFETY_CRITICAL_FEATURES, VM_TRACE_FEATURES};

/// The committed cost table, embedded at compile time. Public so external
/// consumers (e.g. zksync-era's in-tree cycle-estimator tracer) can source the
/// calibrated constants from this repo — the single source of truth — instead of
/// vendoring their own copy.
pub const EMBEDDED_COST_TABLE: &str = include_str!("../model/cost_table.json");

/// One linear predictor: `base + Σ features[i] · counts[i]`. Coefficients are
/// keyed by [`FeatureId`] (the JSON uses the same snake_case names), so a table
/// that references an unknown feature fails to parse — a built-in drift guard.
#[derive(Debug, Clone, Deserialize)]
pub struct LinearModel {
    pub features: BTreeMap<FeatureId, f64>,
    pub base: f64,
    #[serde(default)]
    pub r2: f64,
}

impl LinearModel {
    /// Predict cycles for a feature vector. Missing features count as 0. The
    /// result is clamped at 0 and rounded (cycle counts are non-negative integers).
    pub fn predict(&self, fv: &FeatureVector) -> u64 {
        let mut acc = self.base;
        for (id, coeff) in &self.features {
            acc += coeff * fv.get(*id) as f64;
        }
        acc.max(0.0).round() as u64
    }
}

/// Calibration envelope emitted by the fit, used by the extrapolation guard.
///
/// `deny_unknown_fields` is load-bearing, not tidiness: every field here defaults
/// to a value that DISABLES its guard, so a typo or a rename in the emitted table
/// (`feature_value_maxx`) would parse cleanly and silently unfence everything. An
/// unknown key must fail the build instead — the same reasoning that makes an
/// unknown `FeatureId` a hard parse error.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Calibration {
    /// Largest share of the TOTAL prediction that `rich_addressing_op` reached in
    /// any organic training batch. It is intentionally under-priced (see the fit
    /// script's OPCODE_FLOORS note), so a batch whose arithmetic drives the
    /// estimate past this envelope is compute-dominated and must fail safe.
    ///
    /// **Do not retire this guard** until the frame-churn / pooled-stack-clear
    /// vector has a cost feature of its own. It is the only thing rejecting that
    /// attack today (36.5× under-predicted per iteration on vm2 v0.6.0, 46.1×
    /// under vm2 #124), and it does so *incidentally* — via the cheap arithmetic
    /// the attack must run, not via anything modelled. `feature_value_max` does
    /// not cover it: stack-clear cost is a function of host-cache history, not of
    /// any counter in the schema.
    #[serde(default)]
    pub rich_addressing_share_max: f64,
    /// Largest raw value each fenced feature reached in the calibration corpus. A
    /// linear model says nothing about a batch far outside it, and the shapes that
    /// get there are adversarial by construction. Values above
    /// `value × VOLUME_EXTRAPOLATION_FACTOR` are flagged by
    /// [`CostModel::extrapolated_features`], which declines to certify rather than
    /// prices.
    ///
    /// Against the committed 176-batch fence: a fresh decommit flood sits 8.2×
    /// beyond the `decommit_cycles` max, a repeat-decode thrash 3.6×. A bare
    /// far-call flood is fenced only at batch scale — one 80M-gas tx reaches
    /// ~437k calls, under the 859,529 trip; two exceed it, and a full batch sits
    /// ~23× over. The unfenced single-tx case needs no fence: the `far_call` floor
    /// over-prices it 2.4–4.0× against the measured per-call anchors. Two more
    /// gaps to preserve when re-deriving:
    /// - The `decommit_cycles` fence covers the thrash only while the program
    ///   cache is unbounded, or capped well above organic decommit volume
    ///   (~19.4 MB). A small cache cap would let a thrash hide inside it.
    /// - Repeat `World::decommit_code` queries move no counter at all (see the
    ///   crate-level premises).
    #[serde(default)]
    pub feature_value_max: BTreeMap<FeatureId, u64>,
    /// Which corpus `feature_value_max` came from — the envelope is only as wide
    /// as its sample. A narrow one fails *closed* (batches seal early), but
    /// expensively: fences derived from the 49-row fixture flagged 52/176 = 29.5%
    /// of ordinary training batches.
    #[serde(default)]
    pub feature_value_max_source: Option<String>,
}

/// Identity of the guest/verifier the table was calibrated against.
///
/// Without it a stale table is invisible: the table models one specific guest
/// binary, and every guest optimisation raises its real error while the in-repo
/// regression test — frozen table vs frozen fixture — stays green. That is how
/// the pre-delegation table reached 2.05× over-prediction undetected. The stamp
/// is what lets a drift job separate "the model changed" from "the thing being
/// modelled changed".
///
/// Ship only a table that is either fully stamped ([`Self::is_stamped`]) or
/// explicitly [`stale`](Self::stale_reason) — enforced by
/// `model::tests::embedded_table_declares_its_calibration_identity`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Provenance {
    /// sha256 of the Airbender guest `app.bin` the ground truth was measured on.
    #[serde(default)]
    pub guest_sha256: Option<String>,
    /// Verifier commit the guest + measurement tooling were built from.
    #[serde(default)]
    pub verifier_commit: Option<String>,
    /// `zksync_vm2` revision the features were traced with.
    #[serde(default)]
    pub vm2_rev: Option<String>,
    /// Protocol version of the corpus batches.
    #[serde(default)]
    pub protocol_version: Option<String>,
    /// ISO date the fit was produced.
    #[serde(default)]
    pub fit_date: Option<String>,
    /// Corpus description (batch ranges, counts) the fit consumed.
    #[serde(default)]
    pub dataset: Option<String>,
    /// Set when the table is KNOWN to be mis-calibrated for the current guest.
    /// Present ⇒ the table must not be trusted for a live seal gate; the string
    /// says why and what has to happen before it can be.
    #[serde(default)]
    pub stale_reason: Option<String>,
}

impl Provenance {
    /// True when every identity field needed to reproduce/compare the fit is set.
    /// Blank and whitespace-only values do NOT count: `""` satisfies `is_some()`
    /// while identifying nothing, which would let a table pass the stamp test
    /// while remaining a model of an unknown guest.
    pub fn is_stamped(&self) -> bool {
        [
            &self.guest_sha256,
            &self.verifier_commit,
            &self.vm2_rev,
            &self.protocol_version,
            &self.fit_date,
        ]
        .iter()
        .all(|f| f.as_deref().is_some_and(|v| !v.trim().is_empty()))
    }
}

/// Multiplier on the organic arithmetic-SHARE envelope
/// ([`Calibration::rich_addressing_share_max`]) before flagging extrapolation.
///
/// Deliberately lower than [`VOLUME_EXTRAPOLATION_FACTOR`]: the two guards are
/// not comparable. A share is a ratio whose organic maximum the corpus pins
/// exactly, so **any factor ≥ 1.0 admits every training batch by construction**
/// (measured: 0/176 flagged at 1.0, 1.2, 1.5 and 1.8 alike). A volume max is a
/// sample of an open-ended count and needs slack for unseen-but-legitimate
/// batches. Sharing one constant meant the share guard carried volume-sized
/// headroom for no reason.
///
/// 1.2 was chosen against the 176-batch corpus, on the reasoning above; it is
/// kept here, and the bound it was said to buy is now known to be far more
/// optimistic than stated.
///
/// The bound is `1 + s(k−1)` for share `s` and arithmetic under-priced `k×`. The
/// original estimate used `k ≈ 2.7`, DERIVED by attributing a compute-dominated
/// fixture's whole residual to arithmetic (~315 cyc/op), and concluded ~23% worst
/// under-prediction for a trusted batch. **Direct measurement refutes the input.**
/// On a local era node, three volume tiers per opcode with R² = 1.000000 and
/// intercepts reproducing the empty-batch baseline:
///
/// | opcode | effective cyc/op | vs the 65.01 priced here |
/// |---|---:|---:|
/// | `add` | 137 | 2.1× |
/// | `mul` | 734 | 11.3× |
/// | `div` | 7,515 | **115.6×** |
///
/// At `k = 115.6` and this table's trip point (cap 0.0587 × 1.2 = 0.0704) the
/// worst under-prediction of a *trusted* compute-heavy batch is **~89%**, not
/// ~23%. The factor is still worth keeping — 1.8 would make it ~92% — but it must
/// not be read as bounding the exposure. It does not.
///
/// Nor can any share threshold: covering `k = 115.6` inside the 1.05 seal margin
/// needs `s ≤ 0.04%`, three orders below the 5.87% organic batches reach. Neither
/// can the volume half — the largest organic arithmetic count is 7,448,659 ops
/// while reaching 2^36 with `div` takes 9,144,308, a separation of only 1.23×, so
/// any fence with practical slack admits an unprovable batch. `add` and `div`
/// differ 54.8× at identical count AND identical share, so no function of the
/// aggregate bucket separates them: **the information is not in the feature.**
/// Closing this needs finer featurization — splitting the bucket by opcode
/// subtype. Flooring instead is not an option: a single coefficient safe against
/// 7,515 costs 496% organic MAPE.
///
/// Do not raise the factor without re-deriving these numbers. Lowering it to 1.0
/// gains a little margin but leaves no slack for a legitimately more
/// arithmetic-heavy batch than any observed.
pub const SHARE_EXTRAPOLATION_FACTOR: f64 = 1.2;

/// Multiplier on the per-feature volume envelope
/// ([`Calibration::feature_value_max`]) before flagging extrapolation — headroom
/// so ordinary organic variance never trips the fence. Unchanged at 1.8, where
/// every fenced counter trips 0/176 organic batches.
pub const VOLUME_EXTRAPOLATION_FACTOR: f64 = 1.8;

/// The full fitted cost model: an aggregate `total` predictor over effective cycles
/// plus a per-phase predictor for each verify() phase.
#[derive(Debug, Clone, Deserialize)]
pub struct CostModel {
    /// Number of batches the model was fit on (provenance only).
    #[serde(default)]
    pub batches: u64,
    pub phases: BTreeMap<String, LinearModel>,
    pub total: LinearModel,
    /// Calibration envelope for the extrapolation guard (empty ⇒ guard disabled,
    /// for backward compat with tables that predate it).
    #[serde(default)]
    pub calibration: Calibration,
    /// What guest/verifier this table was calibrated against (see [`Provenance`]).
    #[serde(default)]
    pub provenance: Provenance,
}

impl CostModel {
    /// Parse a cost table from JSON (as emitted by `fit_cost_model.py`).
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// The canonical model committed in this crate, parsed once.
    pub fn embedded() -> &'static CostModel {
        static MODEL: OnceLock<CostModel> = OnceLock::new();
        MODEL.get_or_init(|| {
            CostModel::from_json(EMBEDDED_COST_TABLE).expect(
                "embedded cost_table.json is malformed — regenerate it with fit_cost_model.py",
            )
        })
    }

    /// Full estimate for a complete feature vector: total, per-phase breakdown,
    /// and both fail-safe signals ([`CycleEstimate::is_reliable`] /
    /// [`CycleEstimate::is_within_calibration`]). This is the one place a
    /// [`CycleEstimate`] is built; the free functions in [`crate::estimator`]
    /// only assemble the feature vector before calling it.
    pub fn estimate(&self, fv: &FeatureVector) -> CycleEstimate {
        CycleEstimate {
            total: self.predict_total(fv),
            phases_insight: self.predict_phases(fv),
            unpriced: self.unpriced_used(fv),
            extrapolated: self.extrapolated_features(fv),
            trace_missing: Self::trace_missing(fv),
        }
    }

    /// True when the batch claims work yet its VM trace is empty — **no tracer
    /// ran**, so the prediction degenerates to `base` plus whatever batch scalars
    /// the caller passed.
    ///
    /// Impossible for a real execution (see [`VM_TRACE_FEATURES`]) but
    /// indistinguishable from a tiny batch to every other signal: no crypto counts
    /// ⇒ nothing unpriced, zero arithmetic ⇒ inside the envelope. So a consumer
    /// that forgets to wire a tracer gets a small *trustworthy-looking* estimate
    /// and an unconditionally-passing gate. Folded into
    /// [`CycleEstimate::is_reliable`], not just [`CycleEstimate::fits`], because
    /// consumers test the trust signals directly.
    pub fn trace_missing(fv: &FeatureVector) -> bool {
        // pubdata and state diffs count as claimed work: they come from the
        // FINISHED batch, independently of the tracer, so 200 KB of pubdata with
        // an empty opcode trace is the same unwired-tracer shape.
        let claims_work = [
            FeatureId::TransactionCount,
            FeatureId::MerkleLeafCount,
            FeatureId::PubdataBytes,
            FeatureId::StateDiffCount,
        ]
        .iter()
        .any(|id| fv.get(*id) > 0);
        let traced: u64 = VM_TRACE_FEATURES.iter().map(|id| fv.get(*id)).sum();
        claims_work && traced == 0
    }

    /// Aggregate prediction of **effective (native-computational) cycles** — the
    /// main RISC-V trace plus the weighted delegation-circuit cost (Blake2 ×16,
    /// keccak/bigint ×4) that the raw cycle count omits. Includes the guest
    /// prologue/epilogue (absorbed by the base). This is the number to compare
    /// against the per-proof native budget.
    pub fn predict_total(&self, fv: &FeatureVector) -> u64 {
        self.total.predict(fv)
    }

    /// Per-phase predictions (setup / vm_execution / merkle_verification /
    /// commitment) — **diagnostic only, never a gate input**. Only `total` is
    /// validated and only `total` carries the safety machinery (opcode floors,
    /// envelope guard, asymmetric loss).
    ///
    /// The reason a phase number must not be compared to a limit is train/serve
    /// skew, not a weak fit. The committed `setup` predictor fits *offline* very
    /// well (R² = 0.9999995, MAPE 0.02% over the 176-batch corpus) precisely
    /// because it prices `used_bytecode_bytes` / `used_bytecode_count` /
    /// `storage_key_count` — and all three are
    /// [`OFFLINE_ONLY_FEATURES`](crate::features::OFFLINE_ONLY_FEATURES) with no
    /// online producer. On the deployed path they are structurally 0, so `setup`
    /// collapses to `base + 2110·merkle_leaf_count`: not a weak estimate of setup
    /// cost, not an estimate of it at all. The offline accuracy makes this worse,
    /// not better — it is what makes the online number look credible.
    pub fn predict_phases(&self, fv: &FeatureVector) -> BTreeMap<String, u64> {
        self.phases
            .iter()
            .map(|(name, m)| (name.clone(), m.predict(fv)))
            .collect()
    }

    /// Safety-critical precompile/crypto features (see
    /// [`SAFETY_CRITICAL_FEATURES`]) the batch uses but that the model **never
    /// calibrated** — i.e. absent from the aggregate predictor because the
    /// corpus never exercised that precompile (e.g. ec_pairing, modexp). A
    /// non-empty result means the prediction omits an unbounded, un-priced cost
    /// and must not be trusted (fail safe); no safety multiplier rescues it.
    ///
    /// A feature that IS in the model but with a zero coefficient is *not*
    /// flagged: it was calibrated and found cheap/near-constant (e.g. sha256,
    /// which the corpus contains at low volume), so the base already covers it.
    /// Its only risk is linear extrapolation to volumes far beyond the corpus —
    /// that is the safety-margin's job, not the unknown-op guard's. (Presence,
    /// not coefficient sign, is the signal — else every batch, which all use a
    /// little sha256, would be falsely rejected.)
    pub fn unpriced_used(&self, fv: &FeatureVector) -> Vec<FeatureId> {
        SAFETY_CRITICAL_FEATURES
            .iter()
            .copied()
            .filter(|id| fv.get(*id) > 0 && !self.total.features.contains_key(id))
            .collect()
    }

    /// Features whose contribution pushes the batch OUTSIDE the model's calibration
    /// envelope, so the (linear) prediction cannot be trusted and the caller must
    /// fail safe. Two independent checks, both data-derived by the fit:
    ///
    /// 1. **Arithmetic share** (`rich_addressing_op`), against
    ///    [`SHARE_EXTRAPOLATION_FACTOR`] — left under-priced because flooring it
    ///    wrecks organic accuracy: `total.rich_addressing_op` is 65.01 on the
    ///    reproducible refit (was ~117, ~71 before that) against a MEASURED
    ///    7,515/op for `div`, so 115.6× on the worst member of the bucket — not
    ///    the ~2× previously assumed. Harmless organically, where arithmetic rides
    ///    alongside priced storage; a batch *dominated* by it is under-estimated
    ///    up to two orders of magnitude. NB use the `total` figure —
    ///    `phases.vm_execution.rich_addressing_op` is a different number (86.41)
    ///    that appears earlier in cost_table.json and is easy to misread.
    /// 2. **Volume envelope** ([`Calibration::feature_value_max`]), against
    ///    [`VOLUME_EXTRAPOLATION_FACTOR`] — a raw count
    ///    far outside the corpus is pure extrapolation. Fences the
    ///    bytecode/decommit floods, which the share guard cannot see (their
    ///    arithmetic share is ~0). A bare far-call flood is fenced at batch scale
    ///    but not per-transaction (~437k calls/tx vs a 859,529 trip); there the
    ///    `far_call` floor over-prices it 2.4–4.0×.
    ///
    /// Returns empty when the table carries no calibration data (guard disabled).
    ///
    /// Neither check *prices* an attack — they refuse to certify one. The share
    /// guard is here to stay (a dispatch-decomposition refit that would have
    /// priced arithmetic uniformly was evaluated and REJECTED — it shifts cost off
    /// the storage coefficients and creates a new under-estimation vector; see the
    /// `OPCODE_FLOORS` notes in `scripts/cycle_model/fit_cost_model.py`). Retiring
    /// it takes finer featurization of the compute vector, not re-attribution —
    /// and see [`Calibration::rich_addressing_share_max`] for the frame-churn
    /// vector that currently depends on it.
    pub fn extrapolated_features(&self, fv: &FeatureVector) -> Vec<FeatureId> {
        let mut out = Vec::new();
        let cap = self.calibration.rich_addressing_share_max;
        let total = self.predict_total(fv);
        if cap > 0.0 && total > 0 {
            let coeff = self
                .total
                .features
                .get(&FeatureId::RichAddressingOp)
                .copied()
                .unwrap_or(0.0);
            let share = coeff * fv.get(FeatureId::RichAddressingOp) as f64 / total as f64;
            if share > cap * SHARE_EXTRAPOLATION_FACTOR {
                out.push(FeatureId::RichAddressingOp);
            }
        }
        for (id, max_seen) in &self.calibration.feature_value_max {
            if *max_seen > 0
                && fv.get(*id) as f64 > (*max_seen as f64) * VOLUME_EXTRAPOLATION_FACTOR
                && !out.contains(id)
            {
                out.push(*id);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_model_parses_and_has_all_phases() {
        let m = CostModel::embedded();
        for phase in ["setup", "vm_execution", "merkle_verification", "commitment"] {
            assert!(m.phases.contains_key(phase), "missing phase {phase}");
        }
        // The total predictor must have learned coefficients (its base may be 0
        // once per-feature terms absorb the offset).
        assert!(!m.total.features.is_empty());
    }

    #[test]
    fn predict_is_base_plus_weighted_features() {
        let model = LinearModel {
            features: BTreeMap::from([
                (FeatureId::MerkleLeafCount, 100.0),
                (FeatureId::StateDiffCount, 10.0),
            ]),
            base: 1000.0,
            r2: 1.0,
        };
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::MerkleLeafCount, 5);
        fv.add(FeatureId::StateDiffCount, 2);
        // 1000 + 100*5 + 10*2
        assert_eq!(model.predict(&fv), 1520);
    }

    #[test]
    fn embedded_model_features_are_all_known_ids() {
        // from_json already enforces this (FeatureId keys); this documents intent
        // and fails loudly if the committed table drifts from the enum.
        let _ = CostModel::embedded();
    }

    #[test]
    fn total_prices_no_offline_only_feature() {
        // Train/serve skew tripwire: `total` may only price features an online
        // producer supplies. A non-zero coefficient here means the deployed
        // estimator feeds 0 for real work and under-predicts. The fix is never to
        // relax this — extend BatchContext + a producer, or keep the cost on the
        // online proxy (`decommit_cycles` for bytecode, `merkle_leaf_count` for
        // storage keys).
        let m = CostModel::embedded();
        for id in crate::features::OFFLINE_ONLY_FEATURES {
            let coeff = m.total.features.get(id).copied().unwrap_or(0.0);
            assert_eq!(
                coeff, 0.0,
                "`total` prices offline-only feature {id:?} at {coeff} — no online \
                 producer supplies it, so the deployed gate would feed 0 and \
                 under-predict. Extend BatchContext + a producer first, or keep \
                 the cost on an online feature (see TOTAL_EXCLUDE in fit_cost_model.py)."
            );
        }
    }

    #[test]
    fn embedded_table_declares_its_calibration_identity() {
        // Staleness is invisible without a stamp: the frozen-fixture regression
        // test cannot see it, because the fixture ages with the table. So a
        // shipped table is either fully stamped or declared stale — anything else
        // is an unlabelled model of an unknown guest.
        let p = &CostModel::embedded().provenance;
        assert!(
            p.is_stamped() || p.stale_reason.is_some(),
            "the committed cost_table.json carries neither a complete provenance \
             stamp (guest_sha256 / verifier_commit / vm2_rev / protocol_version / \
             fit_date) nor an explicit `stale_reason` — refit with \
             fit_cost_model.py --provenance, or declare the staleness"
        );
    }

    #[test]
    fn value_envelope_flags_a_flood_and_passes_an_organic_shape() {
        let m = CostModel::embedded();
        let max_decommit = m
            .calibration
            .feature_value_max
            .get(&FeatureId::DecommitCycles)
            .copied()
            .expect("shipped table must fence decommit_cycles");

        // A fresh-decommit flood: same shape as an organic batch except for a
        // bytecode volume no organic batch comes near. The arithmetic-share
        // guard cannot see it (its arithmetic share is ~0) — only the volume
        // envelope can.
        let mut flood = FeatureVector::default();
        flood.add(FeatureId::DecommitCycles, max_decommit * 15);
        flood.add(FeatureId::FarCall, 304);
        flood.add(FeatureId::TransactionCount, 1);
        assert!(
            m.extrapolated_features(&flood)
                .contains(&FeatureId::DecommitCycles),
            "a bytecode-volume flood must be refused by the calibration envelope"
        );

        // Just inside the envelope: not flagged (the guard fences extrapolation,
        // it does not second-guess the corpus itself).
        let mut organic = FeatureVector::default();
        organic.add(FeatureId::DecommitCycles, max_decommit);
        organic.add(FeatureId::TransactionCount, 1);
        assert!(!m
            .extrapolated_features(&organic)
            .contains(&FeatureId::DecommitCycles));
    }

    #[test]
    fn embedded_table_keeps_both_envelope_halves_armed() {
        // Both guards are disable-able BY DATA, no code change, nothing else
        // failing: a zero/absent share cap reads as "guard disabled" (backward
        // compat for pre-envelope tables) and an empty `feature_value_max` fences
        // nothing. An ordinary refit can do it — a corpus that prices
        // `rich_addressing_op` at 0 emits `rich_addressing_share_max = 0.0`
        // (reproduced on a 2-batch candidate), retiring the only thing that
        // rejects the frame-churn vector. Allowed once that vector has a cost
        // feature of its own; never as a side effect.
        let cal = &CostModel::embedded().calibration;
        assert!(
            cal.rich_addressing_share_max > 0.0,
            "rich_addressing_share_max is 0 — the arithmetic-share guard is DISABLED in \
             this table. A refit must not retire it as a side effect; see \
             Calibration::rich_addressing_share_max."
        );
        assert!(
            !cal.feature_value_max.is_empty() && cal.feature_value_max.values().any(|&v| v > 0),
            "feature_value_max is empty/zeroed — the volume fence is DISABLED, so a \
             bytecode or far-call flood reads as within calibration"
        );
        assert!(
            cal.feature_value_max
                .get(&FeatureId::DecommitCycles)
                .is_some_and(|&v| v > 0),
            "decommit_cycles is unfenced — it is the counter every measured \
             bytecode-volume attack has to move (a fresh flood sits 8.2x beyond \
             organic, a repeat-decode thrash 3.6x), so dropping it from \
             ENVELOPE_FEATURES silently uncovers that whole class"
        );
    }

    #[test]
    fn trace_missing_needs_both_claimed_work_and_an_empty_trace() {
        let mut claims_work_untraced = FeatureVector::default();
        claims_work_untraced.add(FeatureId::TransactionCount, 1);
        assert!(CostModel::trace_missing(&claims_work_untraced));

        let mut claims_work_traced = claims_work_untraced.clone();
        claims_work_traced.add(FeatureId::FarCall, 1);
        assert!(!CostModel::trace_missing(&claims_work_traced));

        assert!(!CostModel::trace_missing(&FeatureVector::default()));
    }
}
