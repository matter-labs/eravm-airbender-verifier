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

# Minimum guest cost per opcode-count feature, in effective cycles. The NNLS fit
# prices these buckets from mainnet batches where they co-occur with (and get
# attributed to) costlier priced work, so a batch DOMINATED by one bucket — an
# attacker's lever — is badly under-predicted. Measured directly from isolated
# adversarial batches (scripts/cycle_model/adversarial_dataset.json) and applied as
# a post-fit lower bound: coef = max(fitted, floor). Floors only ever RAISE a
# prediction, so they are strictly conservative for the seal gate.
#   - transient_storage_write: ~11k cyc/op with DISTINCT keys (the transient map
#     grows like storage); the fit prices it 0 (mainnet uses ~800/batch). Measured
#     9x total under-estimate on a transient-dominated batch.
#   - transient_storage_read (tload): ~323 cyc/op measured via a matched control
#     (readLoop - nopLoop) — dispatch + an O(1) in-memory map lookup, ~18x cheaper
#     than a write (no map growth, no rollback-log entry). Floored at 500 for
#     headroom. NB reads ARE counted by the tracer — the earlier "0 reads" was
#     zksolc folding a write-then-read-same-slot into the stored value (no opcode).
#   - average_op (context ops: caller/gasleft/address/…): ~236 cyc dispatch;
#     priced 0 by the fit. Measured 1.5x under-estimate.
#   - near_call_count: dispatch minimum (no clean isolate available; conservative).
# rich_addressing_op is deliberately NOT floored: its true per-op cost (~236) is 3x
# the fitted 71, but flooring it costs ~6% on organic batches (which run millions of
# arithmetic ops that legitimately share cost with priced storage). That compute
# vector is handled by the calibration-envelope guard in the estimator crate.
#
# TODO(cycle-model): dispatch decomposition. The precise fix is to add a
# `total_opcode_count * ~236` dispatch term and subtract 236 from every per-bucket
# coefficient, so the uniform per-opcode dispatch cost is priced ONCE and cannot be
# dodged by routing opcodes into a cheap/zero bucket, while organic totals stay
# accurate. That supersedes both the floors here and the envelope guard. Until then
# the two of them together keep the gate safe.
OPCODE_FLOORS = {
    "transient_storage_write": 11000,
    "transient_storage_read": 500,
    "average_op": 236,
    "near_call_count": 236,
}


def apply_opcode_floors(table: dict) -> list:
    """Raise under-priced opcode buckets to their measured minimum (see
    OPCODE_FLOORS). Returns the (feature, fitted, floor) rows actually raised."""
    raised = []
    for feat, floor in OPCODE_FLOORS.items():
        if table.get(feat, 0.0) < floor:
            raised.append((feat, table.get(feat, 0.0), float(floor)))
            table[feat] = float(floor)
    return raised

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


def fit_asymmetric(X: np.ndarray, y: np.ndarray, tau: float, iters: int = 50):
    """Expectile (asymmetric least-squares) NNLS: penalize UNDER-prediction
    (actual > pred) by weight `tau` and OVER-prediction by `1 - tau`. tau=0.5 is
    ordinary least squares; tau>0.5 pushes the model to over-predict (safe for a
    seal gate, where under-estimating cycles = accepting an unprovable batch).

    Solved by iteratively-reweighted NNLS: scale each row by sqrt(weight) and
    re-solve until the weights (hence residual signs) converge. Keeps the
    non-negativity/monotonicity guarantee.
    """
    A = np.hstack([X, np.ones((X.shape[0], 1))])
    sol = np.zeros(A.shape[1])
    for _ in range(iters):
        resid = y - A @ sol
        w = np.where(resid > 0, tau, 1.0 - tau)  # resid>0 == under-prediction
        sw = np.sqrt(w)
        new, _ = nnls(A * sw[:, None], y * sw)
        if np.allclose(new, sol, rtol=1e-9, atol=1e-6):
            sol = new
            break
        sol = new
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
    ap.add_argument("--tau", type=float, default=0.5,
                    help="expectile for the TOTAL fit; >0.5 penalizes UNDER-prediction "
                         "(safer seal gate). 0.5 = ordinary NNLS (default).")
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
        if phase == "vm_execution":
            apply_opcode_floors(table)  # same safety floors as the total (gate uses total)
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
    elif args.tau != 0.5:
        coeffs, base, r2 = fit_asymmetric(X, y, args.tau)
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
    # Post-fit safety floors on under-priced opcode buckets (see OPCODE_FLOORS).
    raised = apply_opcode_floors(total_table)
    if raised:
        report.append("\n## opcode-cost floors applied (adversarial hardening)")
        report.append("| feature | fitted | floored to |")
        report.append("|---|---:|---:|")
        for feat, fitted, floor in raised:
            report.append(f"| {feat} | {fitted:,.2f} | {floor:,.0f} |")
    result["total"] = {"features": total_table, "base": float(base), "r2": r2}
    # Calibration envelope for the compute-vector guard. rich_addressing_op is left
    # UNDER-priced (coef ~71 vs true ~236) because flooring it wrecks organic
    # accuracy; instead the estimator flags any batch where rich_addressing's SHARE
    # of the prediction exceeds what organic batches ever reach (absolute count
    # can't separate them — big mainnet batches have more rich ops than an attack
    # batch, but carry heavy priced storage that dwarfs it). Such a batch is
    # compute-dominated and its under-priced arithmetic drives the estimate, so the
    # gate fails safe. Emit the organic max share as the data-derived basis.
    def _pred_row(row):
        return base + sum(w * row.get(f, 0) for f, w in total_table.items())
    crich = total_table.get("rich_addressing_op", 0.0)
    rich_shares = [
        crich * row["rich_addressing_op"] / _pred_row(row)
        for _, row in df.iterrows()
        if _pred_row(row) > 0
    ]
    result["calibration"] = {
        "rich_addressing_share_max": max(rich_shares) if rich_shares else 0.0,
    }
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
