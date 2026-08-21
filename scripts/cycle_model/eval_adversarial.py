#!/usr/bin/env python3
"""Check the adversarial no-under-estimation invariant for a CANDIDATE cost table.

The Rust test (crates/cycle_estimator/tests/adversarial_safety.rs) locks the
invariant in CI for the EMBEDDED table — i.e. after a table is committed. This
script is the pre-commit half: point it at any candidate `cost_table.json`
(e.g. a fresh refit under artifacts/) and it replays the same gate semantics
over the committed adversarial fixture, so an unsafe refit is caught BEFORE it
replaces the embedded model.

Invariant (same as the Rust test): for every adversarial batch, the gate must
EITHER cover its true cycles within conservative(margin) OR refuse to trust it
(out of the calibration envelope). A batch that is trusted AND under-predicted
past the margin is a live under-estimation vector -> exit 1.

Usage:
    python eval_adversarial.py --cost-table artifacts/cycle_model/cost_table.json
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fit_cost_model import ARITHMETIC_FEATURES, feature_counts, predict_row

# Keep in lockstep with the Rust gate constants:
# SHARE_EXTRAPOLATION_FACTOR / VOLUME_EXTRAPOLATION_FACTOR in
# crates/cycle_estimator/src/model.rs, and the GATE_MARGIN the
# adversarial_safety test holds the model to. The two factors differ on purpose:
# the share cap is the organic maximum (any factor >= 1.0 admits all organic
# traffic), a volume max is a sample and needs slack.
SHARE_EXTRAPOLATION_FACTOR = 1.2
VOLUME_EXTRAPOLATION_FACTOR = 1.8
GATE_MARGIN = 1.05

FIXTURE = Path(__file__).resolve().parents[2] / \
    "crates/cycle_estimator/tests/fixtures/adversarial.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cost-table", required=True)
    ap.add_argument("--margin", type=float, default=GATE_MARGIN)
    ap.add_argument("--fixture", default=str(FIXTURE))
    args = ap.parse_args()

    model = json.loads(Path(args.cost_table).read_text())
    rows = json.loads(Path(args.fixture).read_text())
    tot = model["total"]
    calibration = model.get("calibration", {})
    # Post-split the arithmetic envelope is the WEIGHTED share of the prediction
    # contributed by all arithmetic cost classes; pre-split tables carry only the
    # single-bucket cap. Mirror the Rust fallback exactly.
    arith_cap = calibration.get("arithmetic_share_max", 0.0)
    if arith_cap > 0.0:
        cap, arith_axes = arith_cap, ARITHMETIC_FEATURES
    else:
        cap, arith_axes = calibration.get("rich_addressing_share_max", 0.0), \
            ["rich_addressing_op"]
    value_max = calibration.get("feature_value_max", {})

    violations = []
    print(f"{'label':>24}  {'actual':>14}  {'pred':>14}  share   verdict")
    for r in rows:
        feats = feature_counts(r)
        pred = predict_row(tot["base"], tot["features"], feats)
        weighted = sum(tot["features"].get(c, 0.0) * feats.get(c, 0) for c in arith_axes)
        share = weighted / pred if pred > 0 else 0.0
        # mirrors CostModel::extrapolated_features — BOTH halves of the envelope:
        # the arithmetic share and the per-feature volume fence. (The fixture uses
        # no unpriced precompile and always has a real trace, so is_reliable is not
        # exercised here.) Keep this in lockstep with the Rust guard: this script
        # is the pre-commit gate, the Rust test the post-commit one, and they must
        # not be able to disagree about which tables are safe.
        over_volume = [
            f for f, mx in value_max.items()
            if mx > 0 and feats.get(f, 0) > mx * VOLUME_EXTRAPOLATION_FACTOR
        ]
        extrapolated = (cap > 0.0 and share > cap * SHARE_EXTRAPOLATION_FACTOR) \
            or over_volume
        trusted = not extrapolated
        covered = pred * args.margin >= r["effective_cycles"]
        if trusted and not covered:
            verdict = "VIOLATION (trusted + under-predicted)"
            violations.append(r["label"])
        elif not trusted:
            why = f"volume {over_volume}" if over_volume else "arithmetic share"
            verdict = f"rejected by envelope guard, {why} (safe)"
        else:
            verdict = "covered"
        print(f"{r['label']:>24}  {r['effective_cycles']:>14,}  {pred:>14,.0f}"
              f"  {share:.3f}  {verdict}")

    if violations:
        print(f"\nINVARIANT VIOLATED by {violations} — this table must not ship.")
        return 1
    print(f"\ninvariant holds over {len(rows)} adversarial batches "
          f"(margin {args.margin}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
