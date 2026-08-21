#!/usr/bin/env python3
"""Turn a measured isolation corpus into per-axis rates, with the checks that make
them believable.

The organic corpus cannot set per-op rates: its features all move together, so the
design matrix is near-singular (`far_call` had multiple R² = 0.999988 against the
rest) and no amount of extra organic data fixes it. Rates come from single-axis
synthetic batches instead — three or more volume tiers per family, so the answer is
a SLOPE and per-batch fixed cost cancels.

This script reports, per family:

  * the slope in effective cycles per unit of the family's intended axis;
  * R², because a designed experiment should be almost perfectly linear and
    anything else means a second axis is moving;
  * the fitted intercept against the measured empty-batch baseline — a free
    falsification test. A family whose intercept drifts from the baseline has
    something else scaling with its axis. This is how a sha256 family's
    size/arithmetic collinearity announced itself (intercept 2.27e9 vs a 9.4e8
    baseline);
  * cycles per erg, and what the stock per-batch erg budget buys in units of the
    2^36 proving ceiling. **This is the number that decides whether an axis needs a
    floor.** Every axis draws from the same erg budget, so moving ergs from a dear
    axis into a cheap one strictly lowers the true total: an axis that cannot reach
    the ceiling alone cannot be combined with another to exceed what that other one
    reaches alone. Floor the axes that can; leave the rest to the fit, where a floor
    costs organic accuracy for nothing.

Usage:
    python scripts/cycle_model/isolation_rates.py \\
        --dataset artifacts/isolation/dataset.json \\
        --manifest .../ISOLATION_CORPUS.csv \\
        [--baseline 9.4e8] [--batch-erg-budget 200000000]
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fit_cost_model import effective_cycles, feature_counts

CEILING = 2 ** 36  # MAX_NUMBER_OF_CYCLES, zksync-airbender cs/src/definitions/constants.rs

# An axis needs its rate pinned once it can reach a material fraction of the
# ceiling on its own. Below this it cannot threaten provability even if priced at
# zero, so flooring it only costs organic accuracy.
FLOOR_THRESHOLD = 0.5


def ols(xs, ys):
    """Slope, intercept, R² — the whole point being that a designed experiment
    should be almost perfectly linear."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None, None, None
    m = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    b = my - m * mx
    ss_res = sum((y - (m * x + b)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys)
    return m, b, (1 - ss_res / ss_tot if ss_tot else 1.0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True, help="measured isolation dataset.json")
    ap.add_argument("--manifest", required=True,
                    help="CSV: fixture,family,tier,intended_axis,axis_count,ergs_used,...,status")
    ap.add_argument("--baseline", type=float, default=None,
                    help="measured empty-batch effective cycles; intercepts are checked "
                         "against it. Defaults to the smallest actual in the corpus.")
    ap.add_argument("--batch-erg-budget", type=float, default=200_000_000,
                    help="stock max_gas_per_batch; the reachability column uses it")
    args = ap.parse_args()

    rows = {r["batch_number"]: r for r in json.loads(Path(args.dataset).read_text())}
    fams = defaultdict(list)
    skipped = []
    for m in csv.DictReader(Path(args.manifest).open()):
        if m["status"].startswith("DEAD"):
            skipped.append((m["fixture"], m["status"].split(";")[0][:60]))
            continue
        b = int(m["fixture"])
        if b in rows:
            fams[m["family"]].append((m, rows[b]))

    baseline = args.baseline or min(effective_cycles(r) for r in rows.values())
    print(f"baseline (empty-batch effective cycles): {baseline:,.0f}")
    print(f"ceiling 2^36 = {CEILING:,}   batch erg budget = {args.batch_erg_budget:,.0f}\n")

    hdr = (f"{'family':<12}{'axis':<26}{'n':>3}{'cyc/unit':>12}{'R2':>10}"
           f"{'intercept':>15}{'vs base':>9}{'ergs/unit':>11}{'cyc/erg':>9}{'x ceiling':>11}  verdict")
    print(hdr)
    print("-" * len(hdr))
    for fam in sorted(fams):
        entries = sorted(fams[fam], key=lambda e: int(e[0]["axis_count"]))
        axis = entries[0][0]["intended_axis"]
        xs = [feature_counts(r).get(axis, 0) for _, r in entries]
        ys = [effective_cycles(r) for _, r in entries]
        ergs = [float(m["ergs_used"]) for m, _ in entries]
        if len(set(xs)) < 2:
            print(f"{fam:<12}{axis:<26}{len(xs):>3}   AXIS DOES NOT VARY — family is dead, "
                  f"counts {xs}")
            continue
        m, b, r2 = ols(xs, ys)
        # ergs per unit from the tier span, so per-batch overhead cancels the same
        # way the cycle slope does
        depu = (ergs[-1] - ergs[0]) / (xs[-1] - xs[0]) if xs[-1] != xs[0] else float("nan")
        cpe = m / depu if depu and depu == depu else float("nan")
        reach = args.batch_erg_budget * cpe / CEILING if cpe == cpe else float("nan")
        drift = b / baseline
        verdict = ("MUST be priced" if reach >= FLOOR_THRESHOLD
                   else "cannot threaten the ceiling")
        flag = "" if 0.9 <= drift <= 1.1 else "  <-- INTERCEPT DRIFT: another axis is moving"
        print(f"{fam:<12}{axis:<26}{len(xs):>3}{m:>12,.0f}{r2:>10.6f}"
              f"{b:>15,.0f}{drift:>8.2f}x{depu:>11,.1f}{cpe:>9,.0f}{reach:>10.2f}x  {verdict}{flag}")

    if skipped:
        print("\nskipped (manifest marks DEAD):")
        for f, why in skipped:
            print(f"  {f}  {why}")
    print("\nReachability is the floor criterion: an axis below the threshold cannot be "
          f"combined with another to exceed what that other reaches alone,\nbecause they "
          "compete for the same erg budget. Floor what can reach it; leave the rest to the fit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
