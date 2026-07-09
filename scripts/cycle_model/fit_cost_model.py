"""Fit a non-negative cycle-cost model from the calibration dataset.

Two complementary fits:

  * **Per-phase** — regress each measured guest phase against the features that
    drive it, giving isolated, interpretable coefficients:
      - vm_execution      ~ opcode-family + crypto features
      - merkle_verification ~ merkle_leaf_count + state_diff_count
                             (leaf-proof + tree-update work per slot / state change)
      - setup             ~ used_bytecode_bytes/-count + storage_key_count
                             + merkle_leaf_count + transaction_count (bytecode hashing)
      - commitment        ~ pubdata_bytes
    The authoritative mapping is `PHASE_FEATURES` / `TOTAL_EXCLUDE` below.
    The phase split matters: it prices Merkle-tree work (driven by the number of
    proven storage slots, not by SSTORE opcode count) separately from VM
    execution, free of opcode collinearity.

  * **Total** — regress *effective* (native-computational) cycles against all
    features, for a single aggregate predictor. This is the number to compare
    against the per-proof budget.

Target: **effective/native cycles** = `cycles_executed` (main RISC-V trace) +
Σ(delegation_count · weight). Airbender proves delegations (Blake2, U256/bigint,
keccak) in separate circuits whose cost the main cycle count does not include;
the Airbender/zksync-os native budget (`MAX_NATIVE_COMPUTATIONAL`) folds them in
with per-type weights (see `DELEGATION_WEIGHTS`). The per-phase fits stay on raw
phase cycles (delegations are only counted batch-wide), so they remain a
raw-cycle breakdown for insight; the TOTAL predictor is the effective one.

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
    # only loose proxies). initial_heap_words is deliberately excluded — it is a
    # witness-only quantity the online estimator cannot supply (see TOTAL_EXCLUDE).
    "setup": [
        "merkle_leaf_count", "transaction_count", "used_bytecode_bytes",
        "used_bytecode_count", "storage_key_count",
    ],
    # Commitment is near-constant (base + pubdata blob hashing). State-diff /
    # system-log counts were tried but overfit the tiny in-sample variance and
    # worsened hold-out MAPE (they are ~constant across batches), so they are
    # left out — the base term already captures the fixed keccak/blake work.
    "commitment": ["pubdata_bytes"],
}

# Features excluded from the aggregate TOTAL fit because the ONLINE estimator
# cannot supply them, so pricing them would create a train/serve skew (the model
# would expect a value the sequencer never provides → systematic under-estimate):
#   - system_log_count: near-constant; the total NNLS otherwise hands it a huge
#     coefficient as a pseudo-intercept, which the online path (which omits it)
#     silently drops.
#   - initial_heap_words: a witness-only quantity, unavailable at sequencing time.
# The base term absorbs their (near-constant) contribution instead.
TOTAL_EXCLUDE = {"system_log_count", "initial_heap_words"}

# Precompile crypto features, calibrated separately from synthetic precompile-heavy
# batches (see scripts/precompile_calibration/). They are ~0 in the organic mainnet
# corpus, so a JOINT fit lets collinear generic-opcode features (far_call /
# rich_addressing_op / precompile_call, which scale with precompile calls) absorb
# their cost and wreck organic accuracy (513xxx hold-out 0.45% -> 37%). Instead they
# are fit on the RESIDUAL with the organic model frozen — see residual_precompile_fit.
PRECOMPILE_FEATURES = [
    "mod_exp_cycles", "sha256_cycles", "ec_add_cycles", "ec_mul_cycles",
    "ec_pairing_cycles", "secp256r1_verify_cycles",
]

# Native-computational weight per delegation, keyed by the airbender delegation
# CSR id recorded in the guest's `delegation_counter` (NON_DETERMINISM_CSR=0x7c0
# =1984 + offset). Values are zksync-os's `native_with_delegations!` coefficients
# (basic_system/cost_constants.rs):
#   1991 = Blake2 round function (+7)  -> BLAKE_DELEGATION_COEFFICIENT  = 16
#   1995 = Keccak special5      (+11)  -> KECCAK_DELEGATION_COEFFICIENT = 4
# The guest delegates keccak (1995), so keccak is NOT software here. The U256/
# bigint delegation (1994, +10, weight 4) exists but does not appear in this
# corpus. Any delegation id NOT in this map raises an error in load_dataset — a
# fail-safe against silently under-counting a new/enabled delegation.
DELEGATION_WEIGHTS = {"1991": 16, "1994": 4, "1995": 4}


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


def residual_precompile_fit(pdf: pd.DataFrame, frozen_features: dict,
                            frozen_base: float, target_col: str) -> dict:
    """Freeze an organic (base + non-precompile) model and NNLS-fit the precompile
    coefficients on the residual `target - organic_prediction` over the
    precompile-dominated batches. No intercept: the base is frozen. Returns a
    {feature: cost} map for the nonzero precompile coeffs.
    """
    used = [c for c in PRECOMPILE_FEATURES if c in pdf.columns]
    if not used or target_col not in pdf.columns:
        return {}
    pred = np.full(len(pdf), frozen_base, dtype=float)
    for c, w in frozen_features.items():  # precompile feats are 0 in the frozen model
        if c in pdf.columns:
            pred = pred + pdf[c].to_numpy(dtype=float) * w
    resid = pdf[target_col].to_numpy(dtype=float) - pred
    coeffs, _ = nnls(pdf[used].to_numpy(dtype=float), resid)
    return {c: float(w) for c, w in zip(used, coeffs) if w > 0}


def load_dataset(path: Path) -> pd.DataFrame:
    """Flatten dataset.json into a DataFrame: one column per feature, one per
    phase (`phase_*`), plus raw_cycles."""
    rows = json.loads(path.read_text())
    records = []
    for r in rows:
        rec = {"batch_number": r["batch_number"], "raw_cycles": r["raw_cycles"]}
        # Effective (native-computational) cycles = main RISC-V cycles + the
        # weighted delegation-circuit cost the main trace doesn't account for.
        deleg_cost = 0
        for did, cnt in r.get("delegations", {}).items():
            if did not in DELEGATION_WEIGHTS:
                raise ValueError(
                    f"batch {r['batch_number']}: unknown delegation id {did!r} — add its "
                    f"native weight to DELEGATION_WEIGHTS (see zksync-os cost_constants.rs)"
                )
            deleg_cost += DELEGATION_WEIGHTS[did] * cnt
        rec["effective_cycles"] = r["raw_cycles"] + deleg_cost
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
    ap.add_argument("--precompile-dataset", default=None,
                    help="synthetic precompile-batch dataset.json; its precompile "
                         "coeffs are residual-fit with the organic model frozen")
    args = ap.parse_args()

    df = load_dataset(Path(args.dataset))
    pdf = load_dataset(Path(args.precompile_dataset)) if args.precompile_dataset else None
    feature_cols = [
        c for c in df.columns
        if c not in ("batch_number", "raw_cycles", "effective_cycles")
        and not c.startswith("phase_")
        and c not in TOTAL_EXCLUDE
    ]
    pinned = json.loads(Path(args.pinned).read_text()) if args.pinned else {}

    result = {"batches": int(len(df)), "phases": {}, "total": {}}
    report = [
        "# Cycle cost model report\n",
        f"- batches: {len(df)}",
        f"- total target: effective/native cycles (raw + weighted delegations);"
        f" per-phase target: raw phase cycles\n",
    ]

    # Per-phase fits.
    for phase, feats in PHASE_FEATURES.items():
        col = f"phase_{phase}"
        if col not in df.columns:
            continue
        y = df[col].to_numpy(dtype=float)
        table, base, r2, used = _fit_block(df, feats, y)
        # Precompiles run during execution: residual-fit their coeffs into the
        # vm_execution phase (raw phase cycles) with the organic phase model frozen.
        if pdf is not None and phase == "vm_execution":
            table.update(residual_precompile_fit(pdf, table, base, col))
        result["phases"][phase] = {"features": table, "base": base, "r2": r2}
        report.append(f"\n## phase `{phase}`  (R^2 = {r2:.4f}, base = {base:,.0f})")
        report.append("| feature | cost (cycles) | confidence |")
        report.append("|---|---:|---|")
        for c in used:
            report.append(f"| {c} | {table[c]:,.2f} | {_confidence(df, c)} |")

    # Total fit (all features -> EFFECTIVE/native cycles = raw + weighted
    # delegations), optionally with pinned crypto costs. This is the predictor the
    # sequencer compares against the per-proof native budget.
    y = df["effective_cycles"].to_numpy(dtype=float)
    used = [c for c in feature_cols if c in df.columns]
    X = df[used].to_numpy(dtype=float)
    if pinned:
        coeffs, base, r2 = fit_with_pinned(X, y, used, pinned)
    else:
        coeffs, base, r2 = fit(X, y)
    total_table = {c: float(w) for c, w in zip(used, coeffs)}
    # Add precompile coeffs via residual fit (organic total frozen) so their cost is
    # attributed to the precompile features, not to collinear generic opcodes.
    if pdf is not None:
        pc = residual_precompile_fit(pdf, total_table, base, "effective_cycles")
        total_table.update(pc)
        report.append(f"\n## precompile residual fit ({len(pdf)} synthetic batches)")
        report.append("| feature | cost (cycles) |")
        report.append("|---|---:|")
        for c, w in pc.items():
            report.append(f"| {c} | {w:,.2f} |")
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
