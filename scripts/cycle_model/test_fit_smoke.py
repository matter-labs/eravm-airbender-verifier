"""Synthetic-recovery tests for the cost-model fit. No corpus / no guest needed."""
import json

import numpy as np

from fit_cost_model import fit, fit_with_pinned, load_dataset, _fit_block


def test_recovers_known_costs():
    rng = np.random.default_rng(0)
    X = rng.integers(0, 100, size=(200, 3)).astype(float)
    true = np.array([10.0, 3.0, 0.5])
    y = X @ true + 1000.0  # base 1000
    coeffs, base, r2 = fit(X, y)
    assert np.allclose(coeffs, true, atol=1e-6)
    assert abs(base - 1000.0) < 1e-6
    assert r2 > 0.999


def test_pinned_fit_holds_pinned_and_fits_rest():
    rng = np.random.default_rng(1)
    X = rng.integers(0, 50, size=(300, 3)).astype(float)
    true = np.array([12.0, 7.0, 2.0])
    y = X @ true + 500.0
    cols = ["A", "B", "C"]
    coeffs, base, r2 = fit_with_pinned(X, y, cols, {"A": 12.0})
    assert abs(coeffs[0] - 12.0) < 1e-9  # pinned held exactly
    assert np.allclose(coeffs[1:], true[1:], atol=1e-6)
    assert r2 > 0.999


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
