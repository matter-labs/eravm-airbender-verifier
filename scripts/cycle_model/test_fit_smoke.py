"""Synthetic-recovery tests for the cost-model fit. No corpus / no guest needed."""
import json

import numpy as np
import pandas as pd

from fit_cost_model import (
    fit, fit_asymmetric, load_dataset, residual_precompile_fit, _fit_block,
)


def test_recovers_known_costs():
    rng = np.random.default_rng(0)
    X = rng.integers(0, 100, size=(200, 3)).astype(float)
    true = np.array([10.0, 3.0, 0.5])
    y = X @ true + 1000.0  # base 1000
    coeffs, base, r2 = fit(X, y)
    assert np.allclose(coeffs, true, atol=1e-6)
    assert abs(base - 1000.0) < 1e-6
    assert r2 > 0.999


def test_asymmetric_fit_leans_conservative():
    # On noisy data, τ=0.9 must produce a fit that under-predicts far less often
    # than ordinary least squares (the whole point of the expectile loss).
    rng = np.random.default_rng(3)
    X = rng.integers(1, 100, size=(300, 2)).astype(float)
    y = X @ np.array([10.0, 3.0]) + 500.0 + rng.normal(0, 50.0, size=300)
    A = np.hstack([X, np.ones((300, 1))])
    c_ols, b_ols, _ = fit_asymmetric(X, y, tau=0.5)
    c_hi, b_hi, _ = fit_asymmetric(X, y, tau=0.9)
    under_ols = (y > A @ np.concatenate([c_ols, [b_ols]])).mean()
    under_hi = (y > A @ np.concatenate([c_hi, [b_hi]])).mean()
    assert under_hi < under_ols
    assert under_hi < 0.25  # τ=0.9 → only a small tail still under-predicted


def test_residual_fit_excludes_organically_priced_precompile():
    # The residual coefficients REPLACE organic ones (table.update), so the frozen
    # prediction must EXCLUDE the organic term of every residual-fit feature —
    # else its cost is double-counted in the prediction and then dropped from the
    # table. With exclusion, the residual coefficient must come out the same
    # whether or not the frozen model carried an organic value for it.
    pdf = pd.DataFrame({
        "sha256_cycles": [100.0, 200.0, 300.0],
        "effective_cycles": [1e6, 2e6, 3e6],
    })
    without = residual_precompile_fit(pdf, {}, 0.0, "effective_cycles")
    with_organic = residual_precompile_fit(
        pdf, {"sha256_cycles": 17.0}, 0.0, "effective_cycles")
    assert without["sha256_cycles"] > 0
    assert with_organic["sha256_cycles"] == without["sha256_cycles"]


def test_load_dataset_and_merkle_phase_fit(tmp_path):
    # Synthetic dataset.json where merkle_verification = 700*leaves + 5000.
    rng = np.random.default_rng(2)
    rows = []
    for i in range(20):
        leaves = int(rng.integers(100, 5000))
        rows.append({
            "batch_number": 500000 + i,
            "raw_cycles": 1000 * leaves,
            "features": {"counts": {"merkle_leaf_count": leaves, "storage_write": leaves // 2}},
            "phase_cycles": {"merkle_verification": 700 * leaves + 5000},
            "delegations": {},
        })
    ds = tmp_path / "dataset.json"
    ds.write_text(json.dumps(rows))

    df = load_dataset(ds)
    assert "merkle_leaf_count" in df.columns
    assert "phase_merkle_verification" in df.columns

    y = df["phase_merkle_verification"].to_numpy(dtype=float)
    table, base, r2, used = _fit_block(df, ["merkle_leaf_count"], y)
    assert used == ["merkle_leaf_count"]
    assert abs(table["merkle_leaf_count"] - 700.0) < 1e-3  # recovers per-slot merkle cost
    assert abs(base - 5000.0) < 1.0
    assert r2 > 0.999
