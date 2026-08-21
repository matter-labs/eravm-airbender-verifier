"""Evaluate a *pre-trained* cycle-cost model on a held-out test set.

This performs NO fitting. It loads a `cost_table.json` produced by
`fit_cost_model.py` on the training corpus and applies it verbatim to a
held-out `dataset.json`, reporting out-of-sample accuracy (R^2, MAPE, worst
case).

NB there is currently NO held-out set: the committed table is fit on every batch
current code can decode (`testdata/cycle_model/dataset.json`, 53 rows), and
`crates/cycle_estimator/tests/fixtures/measured_corpus.json` is that same corpus,
so pointing this script at it measures training error. Use it when a genuinely
disjoint corpus exists — see `docs/generating-batches.md`. Until then the honest
out-of-sample number is the leave-one-out CV in
`crates/cycle_estimator/tests/model_regression.rs`.

Targets match the fit: the aggregate `total` predictor is scored against
EFFECTIVE cycles (raw + weighted delegations — what it was fit on and what the
sequencer gates on); the per-phase predictors are scored against raw phase
cycles (skipped when the test set carries no phase measurements).

Prediction (linear, as fit):  pred = base + sum_i coeff_i * feature_i
Features absent from a test row count as 0 (the feature simply did not occur).

Usage:
    python eval_holdout.py --cost-table crates/cycle_estimator/model/cost_table.json \
                           --dataset    artifacts/cycle_model_test/dataset.json \
                           --out        artifacts/cycle_model_test

With `--max-under-pct` / `--max-over-pct` it becomes a **drift check** that exits
non-zero: point it at a dataset measured with the CURRENT guest and it fails when
the committed table no longer describes that guest. That is the one check the
in-repo Rust regression test cannot make — there both the prediction and the
ground truth are frozen committed data, so they age together. See
`.github/workflows/cycle-model-drift.yaml`.

Use the signed bounds, not `--max-mape-pct`. The table is deliberately biased
+9.7%..+20.5% over its own training corpus (the OPCODE_FLOORS), so a symmetric
bound tight enough to catch a real under-prediction fails the correct table, and
one loose enough to pass it cannot catch a 15% under-prediction.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fit_cost_model import effective_cycles, feature_counts, predict_row


def metrics(actual, pred):
    """Out-of-sample fit stats for paired lists."""
    n = len(actual)
    mean = sum(actual) / n
    ss_tot = sum((a - mean) ** 2 for a in actual) or 1.0
    ss_res = sum((a - p) ** 2 for a, p in zip(actual, pred))
    ape = [abs(p - a) / a for a, p in zip(actual, pred) if a != 0] or [0.0]
    ape_sorted = sorted(ape)
    return {
        "n": n,
        "r2": 1.0 - ss_res / ss_tot,
        "mape": 100 * sum(ape) / len(ape),
        "medape": 100 * ape_sorted[len(ape_sorted) // 2],
        "maxape": 100 * max(ape),
        "mae": sum(abs(p - a) for a, p in zip(actual, pred)) / n,
    }


def fmt(m):
    return (f"R2={m['r2']:.4f}  MAPE={m['mape']:.2f}%  median={m['medape']:.2f}%  "
            f"max={m['maxape']:.2f}%  MAE={m['mae']:,.0f}  (n={m['n']})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cost-table", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--out", default=None)
    # Signed on purpose: the directions are not comparable. Under-prediction
    # certifies an over-budget batch; over-prediction is the table's deliberate
    # bias (+9.7%..+20.5% over the training corpus, from OPCODE_FLOORS). One
    # |error| bound either passes a real under-prediction or fails a correct table.
    ap.add_argument("--max-under-pct", type=float, default=None,
                    help="drift mode, SAFETY: exit 1 if any batch is under-predicted "
                         "by more than this (use with a CURRENT-guest dataset)")
    ap.add_argument("--max-over-pct", type=float, default=None,
                    help="drift mode, STALENESS: exit 1 if any batch is over-predicted "
                         "by more than this — catches a table that no longer describes "
                         "the guest (the known stale event was +105%%)")
    ap.add_argument("--max-mape-pct", type=float, default=None,
                    help="DEPRECATED, direction-blind: exit 1 if the TOTAL model's MAPE "
                         "exceeds this. Prefer --max-under-pct/--max-over-pct")
    ap.add_argument("--max-single-err-pct", type=float, default=None,
                    help="drift mode: exit 1 if any single batch's |error| exceeds this")
    args = ap.parse_args()

    model = json.loads(Path(args.cost_table).read_text())
    rows = json.loads(Path(args.dataset).read_text())

    feats = [feature_counts(r) for r in rows]
    effective = [effective_cycles(r) for r in rows]
    phase_cycles = [r.get("phase_cycles", {}) for r in rows]

    report = ["# Hold-out validation report\n",
              f"- model trained on: {model.get('batches', '?')} batches",
              f"- test batches: {len(rows)} (held out; NOT used for fitting)",
              f"- batch range: {min(r['batch_number'] for r in rows)}"
              f"-{max(r['batch_number'] for r in rows)}\n"]

    # --- Aggregate TOTAL predictor vs EFFECTIVE guest cycles (its fit target) ---
    tot = model["total"]
    pred_tot = [predict_row(tot["base"], tot["features"], f) for f in feats]
    m_tot = metrics(effective, pred_tot)
    report.append("## TOTAL model -> effective_cycles")
    report.append(f"- {fmt(m_tot)}\n")

    # --- Per-phase predictors vs measured phase cycles ---
    if any(phase_cycles):
        report.append("## Per-phase models")
        phase_pred_sum = [0.0] * len(rows)
        phase_actual_sum = [0.0] * len(rows)
        for ph, d in model["phases"].items():
            actual = [pc.get(ph, 0) for pc in phase_cycles]
            pred = [predict_row(d["base"], d["features"], f) for f in feats]
            for i in range(len(rows)):
                phase_pred_sum[i] += pred[i]
                phase_actual_sum[i] += actual[i]
            if all(a == 0 for a in actual):
                report.append(f"- `{ph}`: (no measured cycles in test set)")
                continue
            report.append(f"- `{ph}`: {fmt(metrics(actual, pred))}")
        report.append(f"- sum-of-phases -> sum-of-phase-cycles: "
                      f"{fmt(metrics(phase_actual_sum, phase_pred_sum))}\n")

        # --- Merkle-per-leaf sanity: does the trained coeff hold out-of-sample?
        # Subtract every NON-leaf term of the phase model (base + state_diff_count
        # + ...) so the implied per-leaf cost isolates the leaf coefficient.
        merkle = model["phases"].get("merkle_verification")
        if merkle:
            coeff = merkle["features"].get("merkle_leaf_count", 0.0)
            others = {f: w for f, w in merkle["features"].items()
                      if f != "merkle_leaf_count"}
            obs = []
            for f, pc in zip(feats, phase_cycles):
                leaves = f.get("merkle_leaf_count", 0)
                measured = pc.get("merkle_verification", 0)
                if leaves and measured:
                    non_leaf = predict_row(merkle["base"], others, f)
                    obs.append((measured - non_leaf) / leaves)
            if obs:
                obs.sort()
                report.append("## Merkle overhead per proven slot")
                report.append(f"- trained coeff: {coeff:,.0f} cyc/leaf")
                report.append(f"- test-set implied (median of (phase-rest)/leaves): "
                              f"{obs[len(obs)//2]:,.0f} cyc/leaf over {len(obs)} batches\n")

    # --- Per-batch table (total model) ---
    report.append("## Per-batch (TOTAL model)")
    report.append("| batch | actual (cyc) | predicted (cyc) | err % |")
    report.append("|---|---:|---:|---:|")
    worst = sorted(range(len(rows)),
                   key=lambda i: abs(pred_tot[i] - effective[i]) / effective[i],
                   reverse=True)
    for i in sorted(range(len(rows)), key=lambda i: rows[i]["batch_number"]):
        err = 100 * (pred_tot[i] - effective[i]) / effective[i]
        report.append(f"| {rows[i]['batch_number']} | {effective[i]:,.0f} "
                      f"| {pred_tot[i]:,.0f} | {err:+.2f}% |")

    text = "\n".join(report) + "\n"
    print(text)
    print(f"Worst 3 (total model): "
          + ", ".join(f"{rows[i]['batch_number']} "
                      f"({100*(pred_tot[i]-effective[i])/effective[i]:+.1f}%)"
                      for i in worst[:3]))
    if args.out:
        out = Path(args.out) / "holdout_report.md"
        out.write_text(text)
        print(f"\nWrote {out}")

    # Drift mode. Also print the mean prediction/actual RATIO: that is the shape
    # calibration staleness takes (a systematic multiplier, e.g. 2.05x after the
    # guest's crypto moved to delegated circuits), and it is more legible than
    # MAPE when the whole corpus shifts one way.
    ratios = [p / a for a, p in zip(effective, pred_tot) if a]
    mean_ratio = sum(ratios) / len(ratios) if ratios else 0.0
    print(f"mean pred/actual ratio: {mean_ratio:.3f}x  "
          f"(range {min(ratios, default=0):.3f}-{max(ratios, default=0):.3f})")

    # Signed per-batch errors, in percent: positive = over-predicted (safe),
    # negative = under-predicted (unsafe).
    signed = [100.0 * (p - a) / a for a, p in zip(effective, pred_tot) if a]
    worst_under = min(signed, default=0.0)   # most negative
    worst_over = max(signed, default=0.0)
    print(f"signed error: worst under {worst_under:+.3f}%  worst over {worst_over:+.3f}%")
    failures = []
    if args.max_under_pct is not None and -worst_under > args.max_under_pct:
        failures.append(
            f"UNDER-predicted by {-worst_under:.2f}% > {args.max_under_pct}% "
            f"(unsafe direction: an over-budget batch would be certified)"
        )
    if args.max_over_pct is not None and worst_over > args.max_over_pct:
        failures.append(
            f"OVER-predicted by {worst_over:.2f}% > {args.max_over_pct}% "
            f"(safe direction, but the table no longer describes this guest)"
        )
    if args.max_mape_pct is not None and m_tot["mape"] > args.max_mape_pct:
        failures.append(f"MAPE {m_tot['mape']:.2f}% > {args.max_mape_pct}%")
    if args.max_single_err_pct is not None and m_tot["maxape"] > args.max_single_err_pct:
        failures.append(f"worst batch {m_tot['maxape']:.2f}% > {args.max_single_err_pct}%")
    if failures:
        provenance = model.get("provenance", {})
        print(
            "\nDRIFT: the committed cost table no longer describes the measured guest — "
            + "; ".join(failures)
            + f"\n  table provenance: guest_sha256={provenance.get('guest_sha256')} "
            f"verifier_commit={provenance.get('verifier_commit')} "
            f"fit_date={provenance.get('fit_date')}"
            + (f"\n  table already declares itself stale: {provenance['stale_reason']}"
               if provenance.get("stale_reason") else "")
            + "\n  This is a calibration failure, not a test bug: refit against the "
            "current guest (scripts/cycle_model/REFIT-RUNBOOK.md). Do not raise the "
            "threshold to make it pass."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
