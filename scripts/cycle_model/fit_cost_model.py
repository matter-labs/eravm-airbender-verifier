"""Fit a non-negative cycle-cost model from the calibration dataset.

Two complementary fits:

  * **Per-phase** — regress each measured guest phase against the features that
    drive it, giving isolated, interpretable coefficients:
      - vm_execution      ~ opcode-family + crypto features
      - merkle_verification ~ merkle_leaf_count   (Merkle-tree overhead per slot)
      - setup             ~ merkle_leaf_count + transaction_count
      - commitment        ~ pubdata_bytes
    The phase split matters: it prices Merkle-tree work (driven by the number of
    proven storage slots, not by SSTORE opcode count) separately from VM
    execution, free of opcode collinearity.

  * **Total** — regress raw_cycles against all features, for a single aggregate
    predictor. The sequencer can either sum the per-phase predictions or use this.

Target: effective guest cycles. First cut = raw `cycles_executed`; fold in
Airbender per-delegation weights (recorded in the dataset) once pinned.

Inputs: vm2 features the sequencer can compute natively. Delegation counts and
per-phase cycles are ground-truth measurements, never model inputs.

Reads `dataset.json` (has features + phase_cycles + raw_cycles). Outputs under
--out: `cost_table.json` and `report.md`.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.optimize import nnls

# Which features drive each measured phase. Only features actually present in the
# dataset are used; the rest are ignored. `vm_execution` gets everything
# execution-related, the others get their specific cost drivers.
VM_FEATURES = [
    "rich_addressing_op", "average_op", "storage_read", "storage_write",
    "transient_storage_read", "transient_storage_write", "event",
    "precompile_call", "decommit", "far_call", "uma_write", "uma_read",
    "near_call_count", "keccak256_cycles", "sha256_cycles", "ec_recover_cycles",
    "secp256r1_verify_cycles", "modexp_cycles", "ec_add_cycles", "ec_mul_cycles",
    "ec_pairing_cycles", "decommit_cycles", "storage_application",
    "transaction_count",
]
PHASE_FEATURES = {
    "vm_execution": VM_FEATURES,
    # Two-sided cost: proving pre-state for each witnessed slot (leaf_count) plus
    # updating the tree for each actual state change (state_diff_count =
    # insertions + updates). Adding state_diff_count takes hold-out MAPE 1.85%->0.03%.
    "merkle_verification": ["merkle_leaf_count", "state_diff_count"],
    # Setup hashes every used bytecode and builds the storage view + initial heap
    # before the VM runs; these are its real cost drivers (leaf/tx counts were
    # only loose proxies).
    "setup": [
        "merkle_leaf_count", "transaction_count", "used_bytecode_bytes",
        "used_bytecode_count", "storage_key_count", "initial_heap_words",
    ],
    # Commitment is near-constant (base + pubdata blob hashing). State-diff /
    # system-log counts were tried but overfit the tiny in-sample variance and
    # worsened hold-out MAPE (they are ~constant across batches), so they are
    # left out — the base term already captures the fixed keccak/blake work.
    "commitment": ["pubdata_bytes"],
}


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

    `pinned` maps bare feature name to a cost. Returns (coeffs, base, r2) aligned
    to `feature_cols`.
    """
    pin_idx = {i: pinned[c] for i, c in enumerate(feature_cols) if c in pinned}
    y_adj = y.copy()
    for i, w in pin_idx.items():
        y_adj = y_adj - X[:, i] * w
    free_idx = [i for i in range(len(feature_cols)) if i not in pin_idx]
    if free_idx:
        coeffs_free, base, r2 = fit(X[:, free_idx], y_adj)
    else:
        coeffs_free, base, r2 = np.array([]), 0.0, 1.0
    coeffs = np.zeros(len(feature_cols))
    for i, w in pin_idx.items():
        coeffs[i] = w
    for j, i in enumerate(free_idx):
        coeffs[i] = coeffs_free[j]
    return coeffs, base, r2


def load_dataset(path: Path) -> pd.DataFrame:
    """Flatten dataset.json into a DataFrame: one column per feature, one per
    phase (`phase_*`), plus raw_cycles."""
    rows = json.loads(path.read_text())
    records = []
    for r in rows:
        rec = {"batch_number": r["batch_number"], "raw_cycles": r["raw_cycles"]}
        rec.update(r["features"]["counts"])
        for phase, cyc in r.get("phase_cycles", {}).items():
            rec[f"phase_{phase}"] = cyc
        records.append(rec)
    return pd.DataFrame(records).fillna(0)


def _fit_block(df: pd.DataFrame, feature_cols, y: np.ndarray):
    """Fit `y` against present feature_cols; return (table, base, r2, used_cols)."""
    used = [c for c in feature_cols if c in df.columns]
    if not used:
        return {}, 0.0, float("nan"), []
    X = df[used].to_numpy(dtype=float)
    coeffs, base, r2 = fit(X, y)
    return {c: float(w) for c, w in zip(used, coeffs)}, float(base), r2, used


def _confidence(df, col):
    std = float(df[col].std() or 0.0) if col in df.columns else 0.0
    return "ok" if std > 0 else "UNIDENTIFIED (no corpus variance)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="artifacts/cycle_model/dataset.json")
    ap.add_argument("--out", default="artifacts/cycle_model")
    ap.add_argument("--pinned", default=None,
                    help="JSON file mapping feature -> fixed cost (crypto microbench results)")
    args = ap.parse_args()

    df = load_dataset(Path(args.dataset))
    feature_cols = [
        c for c in df.columns
        if c not in ("batch_number", "raw_cycles") and not c.startswith("phase_")
    ]
    pinned = json.loads(Path(args.pinned).read_text()) if args.pinned else {}

    result = {"batches": int(len(df)), "phases": {}, "total": {}}
    report = [
        "# Cycle cost model report\n",
        f"- batches: {len(df)}",
        f"- target: raw guest cycles\n",
    ]

    # Per-phase fits.
    for phase, feats in PHASE_FEATURES.items():
        col = f"phase_{phase}"
        if col not in df.columns:
            continue
        y = df[col].to_numpy(dtype=float)
        table, base, r2, used = _fit_block(df, feats, y)
        result["phases"][phase] = {"features": table, "base": base, "r2": r2}
        report.append(f"\n## phase `{phase}`  (R^2 = {r2:.4f}, base = {base:,.0f})")
        report.append("| feature | cost (cycles) | confidence |")
        report.append("|---|---:|---|")
        for c in used:
            report.append(f"| {c} | {table[c]:,.2f} | {_confidence(df, c)} |")

    # Total fit (all features -> raw_cycles), optionally with pinned crypto costs.
    y = df["raw_cycles"].to_numpy(dtype=float)
    used = [c for c in feature_cols if c in df.columns]
    X = df[used].to_numpy(dtype=float)
    if pinned:
        coeffs, base, r2 = fit_with_pinned(X, y, used, pinned)
    else:
        coeffs, base, r2 = fit(X, y)
    total_table = {c: float(w) for c, w in zip(used, coeffs)}
    result["total"] = {"features": total_table, "base": float(base), "r2": r2}
    report.append(f"\n## total  (R^2 = {r2:.4f}, base = {base:,.0f})")
    report.append("| feature | cost (cycles) | confidence |")
    report.append("|---|---:|---|")
    for c in used:
        report.append(f"| {c} | {total_table[c]:,.2f} | {_confidence(df, c)} |")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cost_table.json").write_text(json.dumps(result, indent=2))
    (out / "report.md").write_text("\n".join(report) + "\n")

    merkle = result["phases"].get("merkle_verification", {})
    per_leaf = merkle.get("features", {}).get("merkle_leaf_count")
    extra = f", merkle ~ {per_leaf:,.0f} cyc/slot" if per_leaf is not None else ""
    print(f"Wrote cost_table.json + report.md (total R^2={r2:.4f}{extra})")


if __name__ == "__main__":
    sys.exit(main())
