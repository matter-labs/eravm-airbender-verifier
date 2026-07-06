"""Synthetic-recovery tests for the cost-model fit. No corpus / no guest needed."""
import numpy as np

from fit_cost_model import fit, fit_with_pinned


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
    cols = ["f_A", "f_B", "f_C"]
    coeffs, base, r2 = fit_with_pinned(X, y, cols, {"A": 12.0})
    assert abs(coeffs[0] - 12.0) < 1e-9  # pinned held exactly
    assert np.allclose(coeffs[1:], true[1:], atol=1e-6)
    assert r2 > 0.999
