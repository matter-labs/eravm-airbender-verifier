"""Evaluate a *pre-trained* cycle-cost model on a held-out test set.

This performs NO fitting. It loads a `cost_table.json` produced by
`fit_cost_model.py` on the training corpus and applies it verbatim to a
held-out `dataset.json`, reporting out-of-sample accuracy (R^2, MAPE, worst
case) for the aggregate `total` predictor and each per-phase predictor.

Prediction (linear, as fit):  pred = base + sum_i coeff_i * feature_i
Features absent from a test row count as 0 (the feature simply did not occur).

Usage:
    python eval_holdout.py --cost-table artifacts/trained_model_v29/cost_table.json \
                           --dataset    artifacts/cycle_model_test/dataset.json \
                           --out        artifacts/cycle_model_test
"""
import argparse
import json
from pathlib import Path


def predict(base, coeffs, feats):
    """base + sum coeff_i * feats[name]  (missing feature -> 0)."""
    return base + sum(w * feats.get(name, 0) for name, w in coeffs.items())


def metrics(actual, pred):
    """Out-of-sample fit stats for paired lists."""
    n = len(actual)
    mean = sum(actual) / n
    ss_tot = sum((a - mean) ** 2 for a in actual) or 1.0
    ss_res = sum((a - p) ** 2 for a, p in zip(actual, pred))
    ape = [abs(p - a) / a for a, p in zip(actual, pred) if a != 0]
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
    args = ap.parse_args()

    model = json.loads(Path(args.cost_table).read_text())
    rows = json.loads(Path(args.dataset).read_text())

    feats = [r["features"]["counts"] for r in rows]
    raw = [r["raw_cycles"] for r in rows]

    report = ["# Hold-out validation report\n",
              f"- model trained on: {model.get('batches', '?')} batches",
              f"- test batches: {len(rows)} (held out; NOT used for fitting)",
              f"- batch range: {min(r['batch_number'] for r in rows)}"
              f"-{max(r['batch_number'] for r in rows)}\n"]

    # --- Aggregate TOTAL predictor vs raw guest cycles ---
    tot = model["total"]
    pred_tot = [predict(tot["base"], tot["features"], f) for f in feats]
    m_tot = metrics(raw, pred_tot)
    report.append("## TOTAL model -> raw_cycles")
    report.append(f"- {fmt(m_tot)}\n")

    # --- Per-phase predictors vs measured phase cycles ---
    report.append("## Per-phase models")
    phase_pred_sum = [0.0] * len(rows)
    phase_actual_sum = [0.0] * len(rows)
    for ph, d in model["phases"].items():
        actual = [r["phase_cycles"].get(ph, 0) for r in rows]
        pred = [predict(d["base"], d["features"], f) for f in feats]
        for i in range(len(rows)):
            phase_pred_sum[i] += pred[i]
            phase_actual_sum[i] += actual[i]
        if all(a == 0 for a in actual):
            report.append(f"- `{ph}`: (no measured cycles in test set)")
            continue
        report.append(f"- `{ph}`: {fmt(metrics(actual, pred))}")
    report.append(f"- sum-of-phases -> sum-of-phase-cycles: "
                  f"{fmt(metrics(phase_actual_sum, phase_pred_sum))}\n")

    # --- Merkle-per-leaf sanity: does the trained coeff hold out-of-sample? ---
    coeff = model["phases"]["merkle_verification"]["features"].get("merkle_leaf_count")
    base = model["phases"]["merkle_verification"]["base"]
    obs = []
    for r in rows:
        leaves = r["features"]["counts"].get("merkle_leaf_count", 0)
        if leaves:
            obs.append((r["phase_cycles"].get("merkle_verification", 0) - base) / leaves)
    obs.sort()
    report.append("## Merkle overhead per proven slot")
    report.append(f"- trained coeff: {coeff:,.0f} cyc/leaf")
    report.append(f"- test-set implied (median of (phase-base)/leaves): "
                  f"{obs[len(obs)//2]:,.0f} cyc/leaf over {len(obs)} batches\n")

    # --- Per-batch table (total model) ---
    report.append("## Per-batch (TOTAL model)")
    report.append("| batch | actual (cyc) | predicted (cyc) | err % |")
    report.append("|---|---:|---:|---:|")
    worst = sorted(range(len(rows)),
                   key=lambda i: abs(pred_tot[i] - raw[i]) / raw[i], reverse=True)
    for i in sorted(range(len(rows)), key=lambda i: rows[i]["batch_number"]):
        err = 100 * (pred_tot[i] - raw[i]) / raw[i]
        report.append(f"| {rows[i]['batch_number']} | {raw[i]:,} "
                      f"| {pred_tot[i]:,.0f} | {err:+.2f}% |")

    text = "\n".join(report) + "\n"
    print(text)
    print(f"Worst 3 (total model): "
          + ", ".join(f"{rows[i]['batch_number']} "
                      f"({100*(pred_tot[i]-raw[i])/raw[i]:+.1f}%)" for i in worst[:3]))
    if args.out:
        out = Path(args.out) / "holdout_report.md"
        out.write_text(text)
        print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
