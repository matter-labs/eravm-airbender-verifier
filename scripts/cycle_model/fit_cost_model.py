"""Fit a non-negative per-feature cycle-cost model from the calibration dataset.

Target: effective guest cycles. For the first cut this is raw `cycles_executed`
(the dataset column `raw_cycles`); once Airbender per-delegation weights are
pinned, fold them in as `raw + Σ wᵢ·delegationᵢ` before fitting.

Inputs: the `f_*` feature columns (model inputs the sequencer can compute
natively). Delegation counts are NOT model inputs — they are only measurable by
running the guest — so they never appear as `f_*` columns.

Outputs (under --out):
  - cost_table.json : {feature: cycles-per-unit, ..., "__base__": intercept}
  - report.md       : R^2, per-feature cost + corpus variance + confidence flag
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.optimize import nnls


def fit(X: np.ndarray, y: np.ndarray):
    """Non-negative least squares with an intercept column.

    Returns (coeffs, base, r2) where coeffs[i] is the cost of feature column i.
    """
    A = np.hstack([X, np.ones((X.shape[0], 1))])
    sol, _ = nnls(A, y)
    coeffs, base = sol[:-1], sol[-1]
    pred = A @ sol
    ss_res = float(((y - pred) ** 2).sum())
    ss_tot = float(((y - y.mean()) ** 2).sum()) or 1.0
    return coeffs, base, 1.0 - ss_res / ss_tot


def fit_with_pinned(X: np.ndarray, y: np.ndarray, feature_cols, pinned: dict):
    """Hold `pinned` feature costs fixed (e.g. from crypto microbenchmarks) and
    NNLS-fit the remaining feature costs against the residual target.

    `pinned` maps bare feature name (column without the `f_` prefix) to a cost.
    Returns (coeffs, base, r2) with coeffs aligned to `feature_cols`.
    """
    pin_idx = {i: pinned[c[2:]] for i, c in enumerate(feature_cols) if c[2:] in pinned}
    y_adj = y.copy()
    for i, w in pin_idx.items():
        y_adj = y_adj - X[:, i] * w
    free_idx = [i for i in range(len(feature_cols)) if i not in pin_idx]
    coeffs_free, base, r2 = fit(X[:, free_idx], y_adj) if free_idx else (np.array([]), 0.0, 1.0)
    coeffs = np.zeros(len(feature_cols))
    for i, w in pin_idx.items():
        coeffs[i] = w
    for j, i in enumerate(free_idx):
        coeffs[i] = coeffs_free[j]
    return coeffs, base, r2


def _write_report(out: Path, df, feature_cols, cost_table, r2):
    stds = df[feature_cols].std().to_dict()
    lines = [
        "# Cycle cost model report\n",
        f"- batches: {len(df)}",
        f"- R^2: {r2:.4f}\n",
        "| feature | cost (cycles) | corpus std | confidence |",
        "|---|---:|---:|---|",
    ]
    for c in feature_cols:
        std = float(stds.get(c) or 0.0)
        conf = "ok" if std > 0 else "UNIDENTIFIED (no variance)"
        lines.append(f"| {c[2:]} | {cost_table[c[2:]]:.2f} | {std:.1f} | {conf} |")
    (out / "report.md").write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="artifacts/cycle_model/dataset.csv")
    ap.add_argument("--out", default="artifacts/cycle_model")
    ap.add_argument(
        "--pinned",
        default=None,
        help="JSON file mapping feature name -> fixed cost (e.g. crypto microbench results)",
    )
    args = ap.parse_args()

    df = pd.read_csv(args.dataset)
    feature_cols = [c for c in df.columns if c.startswith("f_")]
    X = df[feature_cols].to_numpy(dtype=float)
    y = df["raw_cycles"].to_numpy(dtype=float)

    if args.pinned:
        pinned = json.loads(Path(args.pinned).read_text())
        coeffs, base, r2 = fit_with_pinned(X, y, feature_cols, pinned)
    else:
        coeffs, base, r2 = fit(X, y)

    cost_table = {c[2:]: float(w) for c, w in zip(feature_cols, coeffs)}
    cost_table["__base__"] = float(base)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cost_table.json").write_text(json.dumps(cost_table, indent=2))
    _write_report(out, df, feature_cols, cost_table, r2)
    print(f"Wrote cost_table.json and report.md (R^2={r2:.4f})")


if __name__ == "__main__":
    sys.exit(main())
