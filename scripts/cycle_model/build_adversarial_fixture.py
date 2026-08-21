#!/usr/bin/env python3
"""Rebuild `fixtures/adversarial.json` from a measured dataset + a family manifest.

Why this exists. The adversarial fixture is the only thing asserting that no
attacker-shaped batch is both trusted by the gate and materially under-predicted,
and for most of its life it was hand-maintained: nine rows whose batch *inputs*
were never committed, so they could not be re-measured when the guest changed.
Eight went stale that way (measured 2026-07-09, pre-delegation), and the
2026-08-21 arithmetic split made them worse than stale — their single
`rich_addressing_op` count cannot be reinterpreted under the split schema at all.
Over-attributing it to the dear class makes the test *weaker* (a higher prediction
is easier to cover); under-attributing makes it fail spuriously. Neither is
acceptable in a safety test.

So the fixture becomes a build product of the isolation corpus: inputs are
committed as `.bin.gz` batches, `cycle_bench` measures them against whatever guest
is current, and this script turns that measurement into the fixture. Re-measuring
after a guest change is then a CI job, not an expedition to a local era node.

Usage:
    python scripts/cycle_model/build_adversarial_fixture.py \\
        --dataset artifacts/isolation/dataset.json \\
        --manifest testdata/cycle_model/isolation_manifest.json \\
        --guest "delegation guest, app.bin sha256 8b9436a8…" \\
        --out crates/cycle_estimator/tests/fixtures/adversarial.json

The manifest maps batch number -> {label, family, tier, dominant_axis}, and is what
the corpus generator writes; only rows it marks `adversarial: true` land in the
fixture (a tier sweep is for fitting rates, one saturated member of it is what the
invariant needs).
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fit_cost_model import DELEGATION_WEIGHTS, effective_cycles, feature_counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True,
                    help="measured dataset.json covering the isolation batches")
    ap.add_argument("--manifest", required=True,
                    help="isolation-corpus manifest (batch -> label/family/tier/adversarial)")
    ap.add_argument("--guest", required=True,
                    help="human identity of the guest these were measured on; "
                         "recorded per row so a mixed-vintage fixture is visible")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = {r["batch_number"]: r for r in json.loads(Path(args.dataset).read_text())}
    manifest = json.loads(Path(args.manifest).read_text())

    out, missing = [], []
    for entry in manifest:
        if not entry.get("adversarial"):
            continue
        b = entry["batch_number"]
        if b not in rows:
            missing.append(b)
            continue
        r = rows[b]
        out.append({
            "batch_number": b,
            "label": entry["label"],
            # The target the gate compares against: raw main-trace cycles plus the
            # weighted delegation cost. Stored precomputed because the Rust test
            # must not have to know the weights — but see `delegations` below.
            "effective_cycles": int(effective_cycles(r)),
            "guest": args.guest,
            # Delegation counts are kept so a future weight revision can RE-SCALE
            # this actual instead of invalidating it. The previous fixture stored
            # only effective_cycles, which is why a delegation-weight sensitivity
            # sweep silently compared a re-weighted model against a w=16 actual and
            # produced margins that did not mean what they appeared to.
            "delegations": {str(k): int(v) for k, v in (r.get("delegations") or {}).items()},
            "delegation_weights": dict(DELEGATION_WEIGHTS),
            "features": {"counts": feature_counts(r)},
        })

    if missing:
        raise SystemExit(
            f"ERROR: manifest marks {missing} adversarial but the dataset has no "
            f"measurement for them. Measure the whole isolation corpus before "
            f"rebuilding the fixture — a fixture missing a family silently drops "
            f"that invariant."
        )
    if not out:
        raise SystemExit("ERROR: manifest marked no rows adversarial; nothing to build.")

    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(f"Wrote {args.out}: {len(out)} rows")
    for r in out:
        print(f"  {r['label']:<24} batch {r['batch_number']:<8} "
              f"effective {r['effective_cycles']:>16,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
