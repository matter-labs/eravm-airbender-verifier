#!/usr/bin/env python3
"""Size-stratified cross-validation of the organic cycle-cost fit.

Answers "does the model generalize across the whole batch-size range, especially
NEAR THE CYCLE LIMIT?" without a single fixed holdout — which is misleading when
the available fixed holdout happens to be disjoint in size from the training set
(the committed 513xxx holdout is all small batches: 9-19B vs the 506xxx corpus's
14-64B, so it only ever tested the small tail and looked "consistently low").

Round-robin over size-sorted batches into K folds (each fold spans all sizes),
refit the SAME asymmetric (τ) NNLS organic model on K-1 folds, predict the held
fold, and aggregate the out-of-sample error by size. Precompile features are ~0
in organic batches, so this exercises the organic model (the part that varies
with batch composition).

EVALUATION ONLY: this never writes cost_table.json — the shipped weights are
untouched. Reproduce the committed model with fit_cost_model.py. Two deliberate
approximations vs the shipped pipeline: ALL precompile columns are excluded
(incl. sha256_cycles, which the real total fit keeps as an organic column), and
the post-fit OPCODE_FLOORS are not applied — so this slightly understates the
shipped model's conservative bias. It answers "does the organic fit generalize",
not "what exact error does the shipped table have".

    python cross_validate.py --dataset <506xxx>/dataset.json \
        --extra crates/cycle_estimator/tests/fixtures/holdout_513xxx.json
"""
import argparse, json, sys
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fit_cost_model import (  # reuse the exact fit + helpers the model ships with
    fit_asymmetric, effective_cycles, feature_counts, TOTAL_EXCLUDE, PRECOMPILE_FEATURES,
)


def load(path: Path) -> list:
    d = json.loads(path.read_text())
    rows = d if isinstance(d, list) else d.get("rows", d)
    return [(r["batch_number"], feature_counts(r), effective_cycles(r)) for r in rows]


def predict(sol: np.ndarray, X: np.ndarray) -> np.ndarray:
    return np.hstack([X, np.ones((X.shape[0], 1))]) @ sol


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True, type=Path)
    ap.add_argument("--extra", type=Path, default=None,
                    help="additional dataset to pool in (e.g. the fixed holdout)")
    ap.add_argument("--tau", type=float, default=0.9)
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    data = load(args.dataset) + (load(args.extra) if args.extra else [])
    exclude = TOTAL_EXCLUDE | set(PRECOMPILE_FEATURES)
    cols = sorted({k for _, c, _ in data for k in c} - exclude)
    X = np.array([[c.get(k, 0) for k in cols] for _, c, _ in data], float)
    y = np.array([v for _, _, v in data], float)
    sizes = y  # stratify folds by effective cycles ("size")

    # round-robin over size-sorted index -> each fold is a size-representative sample
    order = np.argsort(sizes)
    fold = np.empty(len(data), int)
    for rank, idx in enumerate(order):
        fold[idx] = rank % args.folds
    oos = np.empty(len(data))
    for k in range(args.folds):
        tr, te = fold != k, fold == k
        coeffs, base, _ = fit_asymmetric(X[tr], y[tr], args.tau)
        sol = np.concatenate([coeffs, [base]])
        oos[te] = predict(sol, X[te])
    err = (oos - y) / y * 100

    print(f"{len(data)} batches, {args.folds}-fold size-stratified CV, τ={args.tau}")
    print(f"overall OOS: MAPE={np.mean(np.abs(err)):.3f}%  mean={err.mean():+.3f}%  "
          f"under={100*(err < 0).mean():.0f}%")
    qs = np.quantile(sizes, np.linspace(0, 1, 6))
    print("\nOOS error by size quintile:")
    print(f"  {'size (B)':>16} | n  | MAPE   | mean    | under% | worst under")
    for i in range(5):
        lo, hi = qs[i], qs[i + 1]
        m = (sizes >= lo) & (sizes <= hi if i == 4 else sizes < hi)
        e = err[m]
        print(f"  {lo/1e9:6.1f}-{hi/1e9:5.1f}   | {m.sum():2} | {np.mean(np.abs(e)):5.3f}% | "
              f"{e.mean():+6.3f}% | {100*(e < 0).mean():4.0f}%  | {e.min():+.2f}%")
    thr = np.quantile(sizes, 0.9)
    big = sizes >= thr
    print(f"\nnear-limit (top 10% by size, >={thr/1e9:.1f}B, n={big.sum()}): "
          f"OOS MAPE={np.mean(np.abs(err[big])):.3f}%  mean={err[big].mean():+.3f}%  "
          f"worst under={err[big].min():+.2f}%  worst over={err[big].max():+.2f}%")


if __name__ == "__main__":
    main()
