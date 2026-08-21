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

The emitted table carries three things beyond the coefficients, each of which the
estimator or CI enforces:

  * `calibration` — the extrapolation envelope: the max organic arithmetic SHARE
    plus the max organic VALUE of each fenced volume feature (ENVELOPE_FEATURES).
    `CostModel::extrapolated_features` refuses to certify a batch beyond them.
  * `provenance` — what guest/corpus the table describes. The fit REFUSES to emit
    an unstamped table (pass --provenance/--guest-sha256/... or an explicit
    --stale-reason), because a table with no identity cannot be checked for drift.
  * only features an ONLINE producer can supply (TOTAL_EXCLUDE), enforced again on
    the Rust side by `total_prices_no_offline_only_feature`.

Two fail-loud guards protect the fit itself: a dataset missing a declared cost
driver aborts instead of silently shrinking the model (REQUIRED_DATASET_FEATURES),
and a precompile the synthetic set cannot identify aborts instead of replacing a
real coefficient with residual noise (see residual_precompile_fit).
"""
import argparse
import datetime
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
    "secp256r1_verify_cycles", "mod_exp_cycles", "ec_add_cycles", "ec_mul_cycles",
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
#   - used_bytecode_bytes / used_bytecode_count / storage_key_count: no online
#     producer exists (the vm2/legacy tracer cannot emit them and BatchContext
#     does not carry them — `git grep used_bytecode_bytes` hits only the enum and
#     the offline fixtures). They are collinear with the ONLINE `decommit_cycles`
#     (bytecode volume) and `merkle_leaf_count` respectively, so excluding them
#     forces the per-byte bytecode cost onto `decommit_cycles` in `total` — where
#     the deployed estimator can actually supply it — instead of letting NNLS park
#     it on an offline feature the sequencer feeds as 0 (which silently prices a
#     decommit flood at ~0: 22.7x under). They remain available to the per-phase
#     `setup` fit (insight-only), just never to `total`.
# The base term absorbs the near-constant ones' contribution instead.
TOTAL_EXCLUDE = {
    "system_log_count",
    "initial_heap_words",
    "used_bytecode_bytes",
    "used_bytecode_count",
    "storage_key_count",
}

# Precompile crypto features, calibrated separately from synthetic precompile-heavy
# batches (see scripts/precompile_calibration/). They are ~0 in the organic mainnet
# corpus, so a JOINT fit lets collinear generic-opcode features (far_call /
# rich_addressing_op / precompile_call, which scale with precompile calls) absorb
# their cost and wreck organic accuracy (513xxx hold-out 0.45% -> 37%). Instead they
# are fit on the RESIDUAL with the organic model frozen — see residual_precompile_fit.
#
# `ec_recover_cycles` belongs here even though it DOES appear organically: its
# organic volume is near-constant (293-2,504 across the 176-batch corpus — every tx
# does about one signature ecrecover, and secp256k1 is not delegated), and a
# near-constant column is collinear with the intercept, so NNLS cannot identify its
# per-unit cost. It lands wherever the base term leaves room: the pre-delegation
# table carried 11.47M while an unfloored refit on the current corpus gives 230,993
# — a ~50x swing, with both predicting organic batches equally well. Organic
# accuracy is unaffected either way, but an ecrecover-flood batch is priced by
# whichever value the fit happened to park, and `unpriced_used()` does not catch it
# (it flags ABSENT safety-critical features, not present-but-meaningless ones).
#
# NOTE this makes the fit REFUSE to run against the current synthetic dataset: it
# has no ecrecover family (`ec_recover_cycles` ranges 1-8 there, incidental tx
# signature checks), so the coefficient is unidentifiable from it too. See the
# identifiability guard in residual_precompile_fit; the real fix is an ecrecover
# family in scripts/precompile_calibration/ (PrecompileHammer.ecRecover +
# gen_inputs) measured on an era node.
#
# What that guard protects, now that OPCODE_FLOORS exists. The residual fit
# REPLACES the organic coefficient, so an unidentifiable column used to mean
# "priced at ~0 on a flood". Unreachable now for the six floored crypto
# precompiles — apply_opcode_floors runs AFTER the residual update, raising a ~0
# residual back to the floor. But `sha256_cycles` is in PRECOMPILE_FEATURES with
# NO floor, and the residual fit really does move it (10,311 -> 1,620 on the
# committed synthetic set). Do not downgrade the abort to a warning because "the
# floors cover it" — they do not cover sha256.
PRECOMPILE_FEATURES = [
    "mod_exp_cycles", "sha256_cycles", "ec_add_cycles", "ec_mul_cycles",
    "ec_pairing_cycles", "secp256r1_verify_cycles", "ec_recover_cycles",
]

# Volume features fenced by the estimator's calibration envelope: the fit emits the
# max organic value of each, and `CostModel::extrapolated_features` refuses to
# certify a batch beyond `max * EXTRAPOLATION_FACTOR`. These are the counters the
# known attack shapes must move — against the 176-batch fence a fresh-decommit
# flood sits 8.2x beyond the organic `decommit_cycles` max and a repeat-decode
# thrash 3.6x, and a linear model has nothing to say that far outside its corpus.
# NB a bare far-call flood only trips the `far_call` entry at batch scale (~437k
# calls per 80M-gas tx vs a 859,529 trip); below that its floor over-prices it
# 2.4-4.0x. The fence does not price an attack; it declines to
# certify one, so the seal gate falls back to sealing conservatively.
#
# Keep this list SHORT and volume-oriented: every entry is also a false-positive
# risk on an unusually busy organic batch (the failure is a smaller batch, not a
# wrong one, but it costs throughput). Widening the corpus widens the fence.
ENVELOPE_FEATURES = [
    "decommit_cycles", "far_call", "decommit", "storage_write", "uma_write",
]

# Features whose ABSENCE from the dataset must abort the fit instead of silently
# shrinking the model. Both `_fit_block` and the total fit intersect their declared
# feature list with `df.columns`, so a dataset that is missing a column simply
# produces a model without it — and NNLS then parks that cost on whatever collinear
# feature remains. That is not hypothetical: the committed table lost its three
# setup drivers (used_bytecode_bytes 62.88 cyc/B, used_bytecode_count,
# storage_key_count) and its `total` per-byte bytecode term in a single "regenerate"
# commit, which is exactly the shape of a dataset measured without those columns.
# The cost moved onto the collinear `decommit_cycles`, which happens to be online
# and so happens to be safe — luck, not design.
#
# Precompile features are deliberately NOT required: they are legitimately ~0 (and
# often absent) in an organic corpus, which is the entire reason for the residual
# fit against the synthetic set.
#
# That exemption cannot be blanket, though: two are exercised by every ordinary
# transaction, so their absence is a broken dataset, not a quiet corpus. Over the
# 176-batch corpus `ec_recover_cycles` runs 293-2,504/batch and `sha256_cycles`
# 6-5,942 — non-zero in 176/176. Dropping ec_recover_cycles drains
# `transaction_count` to 0.00 and inflates `storage_read` 5.7x, no guard firing,
# because NNLS re-parks the per-tx cost on whatever correlates.
ALWAYS_PRESENT_PRECOMPILES = ["ec_recover_cycles", "sha256_cycles"]

REQUIRED_DATASET_FEATURES = sorted(
    ({f for feats in PHASE_FEATURES.values() for f in feats} - set(PRECOMPILE_FEATURES))
    | set(ALWAYS_PRESENT_PRECOMPILES)
)

# Minimum guest cost per opcode-count feature, in effective cycles. The NNLS fit
# prices these buckets from mainnet batches where they co-occur with (and get
# attributed to) costlier priced work, so a batch DOMINATED by one bucket — an
# attacker's lever — is badly under-predicted. Measured directly from isolated
# adversarial batches (crates/cycle_estimator/tests/fixtures/adversarial.json) and applied as
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
# EVALUATED AND REJECTED — dispatch decomposition. The natural-looking fix
# (pin a uniform ~236 cyc/op dispatch term by fitting on
# `y - 236*total_opcode_count` and folding 236 back into every bucket, so no
# bucket can be routed to for free) was implemented and refit on the real
# corpus, and it makes the gate LESS safe:
#   - total attribution is conserved, so forcing 236 into every opcode bucket
#     makes the fit SHRINK the storage/merkle coefficients to keep matching
#     organic totals — the isolated storage_reads_80k adversarial batch then
#     under-predicts past the seal margin (-11%), a NEW invariant violation the
#     shipped floors+guard model does not have;
#   - the mandatory dispatch term is re-absorbed by the asymmetric fit, erasing
#     the floors' deliberate conservative bias (513xxx hold-out flips from 0/49
#     under-predicted, worst +0.03%, to 40+/49 under, worst -1.9%); raising tau
#     to 0.97 does not fix either effect.
# The structural lesson: post-fit FLOORS only ever add cost (strictly
# conservative), while re-attribution inside the fit moves cost away from other
# levers — some of which (storage) are load-bearing for isolated batches. Run
# `eval_adversarial.py` against any candidate table to check the invariant
# before committing it. The long-term fix for the compute vector is finer
# featurization (split rich_addressing by op subtype) plus compute-heavy
# synthetic batches residual-fit like the precompiles — not re-attribution.
OPCODE_FLOORS = {
    "transient_storage_write": 11000,
    "transient_storage_read": 500,
    "average_op": 236,
    "near_call_count": 236,
    # --- collinear-zeroed buckets (added 2026-08-19) ------------------------
    # NNLS prices these at exactly 0 on organic mainnet: each is near-perfectly
    # collinear with costlier priced work that absorbs its cost (far_call with
    # near_call_count/storage_read at |r| > 0.99; uma_read with
    # rich_addressing_op). The TOTAL stays accurate, but a batch DOMINATED by
    # one bucket is then priced at ~0 on that axis. A zero coefficient is
    # invisible to every guard: `unpriced_used` keys on a feature's ABSENCE
    # from the table, not on its value (model.rs:148), and
    # `extrapolated_features` only watches the rich-addressing share — which a
    # degenerate flood has none of. Floors only ever RAISE a prediction, so
    # they are strictly conservative for the seal gate.
    #
    # far_call: `far_call r0, r0, @self` is a complete attack iteration at
    # exactly 183 ergs (STORAGE_READ_IO_PRICE 150 + CALL_LIKE_ERGS_COST 20 +
    # 8+2+1+1+1; the code-hash sload is inside the 183) with ZERO
    # rich_addressing_op — the ABI register may be r0 and the exception handler
    # is a free back-edge. With no batch-level gas cap, ~46 txs x 80M gas reach
    # ~20M far calls (46*80e6/183 = 20.1M).
    #
    # NOT priced at zero before this floor: the Ret<Panic> back-edge bumps
    # `average_op` (tracer.rs:80, `Opcode::Ret(_) => FeatureId::AverageOp`),
    # which is floored at 236 — so the flood was under-priced ~15x, not
    # infinitely. Still load-bearing: at 236 the flood predicts 4.7e9 and the
    # gate ACCEPTS a batch whose true cost is >=72e9, past the 2^36 budget; at
    # 15,000 it predicts 300e9 and the gate rejects.
    #
    # 15,000 is a deliberately conservative STOPGAP, not a measurement. The
    # empirical anchors, all well below it:
    #   6,156  fitted far_call, 49-batch total fit (effective cycles)
    #   5,794  fitted far_call, 176-batch vm_execution phase fit (raw cycles)
    #   ~3.6k  measured per-iteration intercept B, the floor a bare iteration
    #          cannot go below. Across every arm and mode in stackbench
    #          dos-cycle-test/results/stack-clear/RESULTS.md:134-143 it spans
    #          3,555-3,755 (dense-master mode 1 = 3,723; S115 = 3,680;
    #          S124 = 3,607). The pinned v0.6.3 (be1e50b) carries chunked-stack
    #          machinery (SlotChunk/zeroed_chunk) that the plain dense revs lack
    #          but does not map cleanly onto one bench arm, so the band — not any
    #          single arm — is the honest anchor. The cost is the `pointer_flags`
    #          Bitset reset, NOT Stack::zero, which runs only on pool REUSE.
    # 15,000 is ~2.4x the highest anchor, chosen to leave headroom for the
    # per-call work none of these isolate (code-hash storage read, decommit +
    # program-cache lookups, two heap allocations, 512-byte register wipe).
    # It is NOT de-staled from the old table's 15,004: a warm far call does no
    # blake2/keccak, so the ~2.06x delegation speedup never applied to it.
    # REPLACE WITH A DIRECT MEASUREMENT (~1 day) — this value is not derived
    # from one, and its closeness to the old coefficient is not evidence.
    "far_call": 15000,
    # decommit: the CodeOracle.decommitCode repeat path refunds the ergs but
    # still re-resolves the bytes O(len) per query (vm_fast/world.rs:237-260),
    # and `decommit_cycles` does NOT cover it — that counter fires only on a
    # FRESH decommit. For a 2 MiB contract this value is ~4x under on that
    # path, and ~70x under on the program_cache-hit rebuild (world.rs:104-115)
    # an attacker can force with a single far call. Not de-staled either.
    "decommit": 285000,
    "event": 2287,
    "uma_read": 77,
    # --- crypto precompiles (added 2026-08-19) -----------------------------
    # These previously came from `residual_precompile_fit` on SYNTHETIC batches
    # (--precompile-dataset). No such dataset exists for the delegation guest —
    # regenerating one needs a local era node (scripts/precompile_calibration) —
    # so this refit ran WITHOUT it and the values below are pinned literals
    # carried forward from the pre-delegation table.
    #
    # ⚠️ UNITS: despite the `_cycles` names these are CALL COUNTS, so a
    # coefficient is the cost of ONE call and must be compared against a
    # per-call derivation, never a per-cycle figure. Both live paths emit 1:
    # OptimizedPrecompiles' fast path returns `CycleStats::EcRecover(1)`
    # directly (vm_fast/world.rs:292), and everything else falls through to
    # LegacyPrecompiles, which forwards `ecrecover_function`'s round count —
    # and that is `const NUM_ROUNDS: usize = 1` in zk_evm's ECRecoverPrecompile
    # (zk_evm_abstractions/src/precompiles/ecrecover.rs:33). Sanity check: the
    # corpus averages ~1,026/batch, consistent with one signature check per tx.
    #
    # Four have zero volume in all 176 organic batches (columns absent
    # entirely), so the organic fit cannot price them at any corpus size and
    # their floors are FREE organically. Their values are carried forward from
    # the pre-delegation table where that is conservative against
    # native_cost_conversion.md's per-call derivation (secp256r1 16.2x over,
    # ec_add 3.2x, ec_pairing ~9.6x).
    #
    # TWO are raised to that derivation instead, because carrying the old value
    # forward is NOT conservative for them:
    #   ec_recover_cycles — the only one with real organic volume
    #     (~1,026 calls/batch). Unfloored the fit gives 230,993 = 0.63x the
    #     derived 368,000 (240,000 raw + 32,000 bigint delegations at the
    #     target's own w=4). It is in SAFETY_CRITICAL_FEATURES and
    #     unprivileged-callable (every ecrecover), and because it is PRESENT
    #     `unpriced_used` can never flag it. NOTE the old table's 11,467,511 is
    #     NOT a valid floor here: at 1,026 calls/batch it prices ecrecover at
    #     ~98% of an entire mean batch (11.8e9 of 12.0e9) and drives organic
    #     MAPE to 106.7%. That value is a residual-fit artifact, not a per-call
    #     cost, and this refit correcting it 49.6x downward is a FIX, not a
    #     regression.
    #   ec_mul_cycles — 201,185 is 0.25x the derived 811,000 (647,000 +
    #     41,000 x 4). Pre-existing under-pricing, not introduced here, but free
    #     to close (zero organic volume).
    # Cost of both floors on organic traffic: 1.17% per batch.
    #
    # These previously came from `residual_precompile_fit` on SYNTHETIC batches
    # (--precompile-dataset). No such dataset exists for the delegation guest —
    # regenerating one needs a local era node (scripts/precompile_calibration) —
    # so this refit ran WITHOUT it and these are pinned literals. Kept PRESENT
    # rather than absent deliberately: absence would trip `unpriced_used` and
    # reject every batch touching a pairing outright, a liveness regression
    # against the deployed table. The tradeoff is real — presence disarms the
    # one fail-closed guard that would otherwise catch under-pricing here.
    # At the doc's provisional d~40 (rather than w=4) ec_recover would derive to
    # 1,520,000 and ec_mul to 2,287,000; that costs ~11% organically, so it is
    # deliberately NOT applied while d is unpinned. Re-measure all six.
    "ec_add_cycles": 185724,
    "ec_mul_cycles": 811000,
    "ec_pairing_cycles": 66604671,
    "mod_exp_cycles": 952644,
    "secp256r1_verify_cycles": 12665313,
    "ec_recover_cycles": 368000,
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
# bigint delegation (1994, +10, weight 4) appears in ALL 176 batches of the
# delegation-guest corpus (7.43e9 counts -> 2.97e10 weighted cycles = 1.31% of
# corpus effective, 18.9% of delegation cost) — the earlier note that it 'does
# not appear in this corpus' was true only of the pre-delegation corpus.
# TODO(unverified): the 16/4/4 weights have NO authoritative source in-tree and
# are attributed above to zksync-os's `native_with_delegations!`, but per
# native_cost_conversion.md that macro supplies delegation COUNTS, and its own
# calibration puts a delegation at d ~ 40 raw cycles — 2.5-10x from 16/4/4. The
# two in-tree documents disagree; a microbench should pin d. Sensitivity: refits
# at w(1994) in {0,2,4,8,16,40} leave fitted far_call at 0.0 and worst-under at
# 0.000%, moving MAPE only 11.85%->10.49%, so conclusions hold — but the
# absolute SCALE of the effective-cycle target against the real native budget
# does not (d=40 would raise corpus effective +13.2%). Any delegation id NOT in this map raises an error in load_dataset — a
# fail-safe against silently under-counting a new/enabled delegation.
DELEGATION_WEIGHTS = {"1991": 16, "1994": 4, "1995": 4}


def fit(X: np.ndarray, y: np.ndarray):
    """Non-negative least squares with an intercept column (= expectile τ=0.5).

    Returns (coeffs, base, r2) where coeffs[i] is the cost of feature column i.
    """
    return fit_asymmetric(X, y, tau=0.5)


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


# Identifiability thresholds for a residual-fit precompile coefficient. A column
# that barely varies, or that carries only a handful of incidental units, cannot
# determine a per-unit cost — NNLS will return whatever the residual noise implies,
# typically ~0, and the caller REPLACES the organic coefficient with it. Since these
# are SAFETY_CRITICAL features, a spurious ~0 is an under-pricing hole precisely on
# the flood vector the coefficient exists to price. The synthetic set is supposed to
# sweep each target precompile over 2-3 orders of magnitude (see
# scripts/precompile_calibration/README.md), so a column that fails these is a
# missing hammer family, not a tight threshold.
MIN_RESIDUAL_TIERS = 3        # distinct values, including the 0 of other families
MIN_RESIDUAL_VOLUME = 100     # units in the most precompile-dominated batch


def unidentifiable_precompiles(pdf: pd.DataFrame, cols) -> list:
    """Residual-fit columns the synthetic set cannot determine a coefficient for."""
    bad = []
    for c in cols:
        col = pdf[c]
        if col.nunique() < MIN_RESIDUAL_TIERS or float(col.max()) < MIN_RESIDUAL_VOLUME:
            bad.append((c, int(col.nunique()), float(col.max())))
    return bad


def residual_precompile_fit(pdf: pd.DataFrame, frozen_features: dict,
                            frozen_base: float, target_col: str,
                            allow_unidentified: bool = False) -> dict:
    """Freeze an organic (base + non-precompile) model and NNLS-fit the precompile
    coefficients on the residual `target - organic_prediction` over the
    precompile-dominated batches. No intercept: the base is frozen. Returns a
    {feature: cost} map for the nonzero precompile coeffs.
    """
    used = [c for c in PRECOMPILE_FEATURES if c in pdf.columns]
    if not used or target_col not in pdf.columns:
        return {}
    # Drop (or reject) columns the synthetic set cannot identify, BEFORE they are
    # used: a skipped feature keeps its organic coefficient, because `used` is also
    # the exclusion list for the frozen prediction below.
    bad = unidentifiable_precompiles(pdf, used)
    if bad:
        detail = "; ".join(f"{c}: {n} distinct values, max {m:,.0f}" for c, n, m in bad)
        if not allow_unidentified:
            raise ValueError(
                f"precompile dataset cannot identify a coefficient for: {detail}. "
                f"The residual fit REPLACES the organic coefficient, so shipping this "
                f"would price those precompiles at ~0 on a flood. Add a hammer family "
                f"that sweeps each one (scripts/precompile_calibration/: "
                f"PrecompileHammer.sol + gen_inputs.py + run_calibration.sh) and "
                f"re-measure on an era node. Pass --allow-unidentified-precompiles to "
                f"keep the organic coefficient instead (reference runs only)."
            )
        print(f"WARNING: keeping organic coefficients (unidentifiable here) for {detail}",
              file=sys.stderr)
        used = [c for c in used if c not in {b[0] for b in bad}]
        if not used:
            return {}
    # The residual coefficients REPLACE (table.update) any organic coefficient the
    # frozen model has for a feature in `used`, so the frozen prediction must
    # EXCLUDE those features' organic terms — otherwise their cost is counted in
    # the prediction, the residual under-states it, and the replacement drops the
    # organic term (net under-pricing). `sha256_cycles` sits in both VM_FEATURES
    # and PRECOMPILE_FEATURES and the organic vm_execution phase fit does price
    # it, so this exclusion is load-bearing, not defensive.
    pred = np.full(len(pdf), frozen_base, dtype=float)
    for c, w in frozen_features.items():
        if c in pdf.columns and c not in used:
            pred = pred + pdf[c].to_numpy(dtype=float) * w
    resid = pdf[target_col].to_numpy(dtype=float) - pred
    coeffs, _ = nnls(pdf[used].to_numpy(dtype=float), resid)
    # Return a coefficient for every residual-fit feature (including 0.0): the
    # caller replaces the organic coefficient, so omitting a zero here would
    # leave a stale organic term that the residual above did not account for.
    return {c: float(w) for c, w in zip(used, coeffs)}


def effective_cycles(r: dict) -> float:
    """Effective (native-computational) cycles for one dataset/fixture row =
    main RISC-V cycles + the weighted delegation-circuit cost the main trace
    doesn't account for. Fixture rows may carry it precomputed."""
    if "effective_cycles" in r:
        return float(r["effective_cycles"])
    deleg_cost = 0
    for did, cnt in (r.get("delegations") or {}).items():
        if did not in DELEGATION_WEIGHTS:
            raise ValueError(
                f"batch {r['batch_number']}: unknown delegation id {did!r} — add its "
                f"native weight to DELEGATION_WEIGHTS (see zksync-os cost_constants.rs)"
            )
        deleg_cost += DELEGATION_WEIGHTS[did] * cnt
    return float(r["raw_cycles"] + deleg_cost)


def feature_counts(r: dict) -> dict:
    """The feature-count map of one dataset/fixture row (both layouts)."""
    f = r["features"]
    return f["counts"] if "counts" in f else f


def predict_row(base: float, coeffs: dict, feats) -> float:
    """One linear prediction: base + Σ coeff·feature (missing feature -> 0).
    `feats` is any mapping with .get (a dict or a pandas row)."""
    return base + sum(w * feats.get(name, 0) for name, w in coeffs.items())


def load_dataset(path: Path) -> pd.DataFrame:
    """Flatten dataset.json into a DataFrame: one column per feature, one per
    phase (`phase_*`), plus raw_cycles + effective_cycles."""
    rows = json.loads(path.read_text())
    records = []
    for r in rows:
        rec = {"batch_number": r["batch_number"], "raw_cycles": r["raw_cycles"]}
        rec["effective_cycles"] = effective_cycles(r)
        rec.update(feature_counts(r))
        for phase, cyc in r.get("phase_cycles", {}).items():
            rec[f"phase_{phase}"] = cyc
        records.append(rec)
    return pd.DataFrame(records).fillna(0)


def _fit_block(df: pd.DataFrame, feature_cols, y: np.ndarray):
    """Fit `y` against present feature_cols; return (table, base, r2, used_cols)."""
    used = [c for c in feature_cols if c in df.columns]
    if not used:
        # r2 must stay a number: NaN would serialize as bare `NaN`, which is
        # invalid JSON and the Rust estimator's serde parse rejects it.
        return {}, 0.0, 0.0, []
    X = df[used].to_numpy(dtype=float)
    coeffs, base, r2 = fit(X, y)
    return {c: float(w) for c, w in zip(used, coeffs)}, float(base), r2, used


def _confidence(df, col):
    std = float(df[col].std() or 0.0) if col in df.columns else 0.0
    return "ok" if std > 0 else "UNIDENTIFIED (no corpus variance)"


def require_dataset_features(df: pd.DataFrame, allow_missing: bool) -> None:
    """Abort when the dataset lacks a feature the model declares it prices.

    See REQUIRED_DATASET_FEATURES: a missing column does not fail, it silently
    shrinks the model and re-parks that cost on a collinear survivor.
    """
    missing = [f for f in REQUIRED_DATASET_FEATURES if f not in df.columns]
    if not missing:
        return
    msg = (
        f"dataset is missing declared cost drivers: {missing}. The fit would "
        f"silently drop them and re-attribute their cost to whatever collinear "
        f"feature survives (this is how the committed table lost its per-byte "
        f"bytecode term). Re-measure with a current `cycle_bench` so every "
        f"feature in PHASE_FEATURES is present, or pass --allow-missing-features "
        f"if you deliberately want a reduced model."
    )
    if not allow_missing:
        raise SystemExit(f"ERROR: {msg}")
    print(f"WARNING: {msg}", file=sys.stderr)


def build_provenance(args) -> dict:
    """Identity of the guest/corpus this table describes (see the Provenance
    struct in crates/cycle_estimator/src/model.rs).

    An unstamped table is a model of an unknown guest: nothing downstream can
    tell whether it still describes the binary it gates. So refuse to emit one
    unless the caller either supplies the identity or says out loud why it is
    unknown.
    """
    prov = {}
    if args.provenance:
        prov.update(json.loads(Path(args.provenance).read_text()))
    for field in ("guest_sha256", "verifier_commit", "vm2_rev", "protocol_version",
                  "fit_date"):
        val = getattr(args, field, None)
        if val:
            prov[field] = val
    if args.dataset_desc:
        prov["dataset"] = args.dataset_desc
    prov.setdefault("dataset", f"{args.dataset} (tau={args.tau})")
    # The fit date is the one identity field this process always knows, and
    # cycle_bench's manifest cannot carry it (it is written at MEASUREMENT time,
    # possibly days earlier). Defaulting it here keeps the "unstamped" refusal
    # pointed at the fields that are genuinely unknowable from inside the fit.
    prov.setdefault("fit_date", datetime.date.today().isoformat())
    if args.stale_reason:
        prov["stale_reason"] = args.stale_reason
    identity = ("guest_sha256", "verifier_commit", "vm2_rev", "protocol_version", "fit_date")
    unknown = [f for f in identity if not prov.get(f)]
    if unknown and not args.stale_reason:
        raise SystemExit(
            f"ERROR: refusing to emit an unstamped cost table — missing {unknown}. "
            f"Pass --provenance <manifest.json> (cycle_bench writes one next to "
            f"dataset.json) or the individual flags; or pass --stale-reason '<why "
            f"this table is knowingly not a description of the current guest>' to "
            f"ship it declared-stale."
        )
    for f in identity:
        prov.setdefault(f, None)
    return prov


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="artifacts/cycle_model/dataset.json")
    ap.add_argument("--out", default="artifacts/cycle_model")
    ap.add_argument("--precompile-dataset", default=None,
                    help="synthetic precompile-batch dataset.json; its precompile "
                         "coeffs are residual-fit with the organic model frozen")
    ap.add_argument("--tau", type=float, default=0.5,
                    help="expectile for the TOTAL fit; >0.5 penalizes UNDER-prediction "
                         "(safer seal gate). 0.5 = ordinary NNLS (default).")
    ap.add_argument("--allow-missing-features", action="store_true",
                    help="downgrade a dataset missing declared cost drivers from an "
                         "error to a warning (reduced model; reference runs only)")
    ap.add_argument("--allow-unidentified-precompiles", action="store_true",
                    help="keep the organic coefficient for a precompile the synthetic "
                         "set cannot identify, instead of aborting (reference runs only)")
    ap.add_argument("--provenance", default=None,
                    help="JSON manifest of the measurement identity (guest_sha256, "
                         "verifier_commit, vm2_rev, protocol_version, fit_date); "
                         "cycle_bench writes one next to dataset.json")
    ap.add_argument("--guest-sha256", default=None,
                    help="provenance: sha256 of the guest app.bin the truth was measured on")
    ap.add_argument("--verifier-commit", default=None,
                    help="provenance: verifier commit the guest + tooling were built from")
    ap.add_argument("--vm2-rev", default=None,
                    help="provenance: zksync_vm2 revision the features were traced with")
    ap.add_argument("--protocol-version", default=None,
                    help="provenance: protocol version of the corpus batches")
    ap.add_argument("--fit-date", default=None, help="provenance: ISO date of this fit")
    ap.add_argument("--dataset-desc", default=None,
                    help="provenance: human description of the corpus (batch ranges, counts)")
    ap.add_argument("--stale-reason", default=None,
                    help="declare the emitted table knowingly stale (why, and what "
                         "must happen before it can be trusted). Required when the "
                         "identity fields are not supplied.")
    args = ap.parse_args()

    provenance = build_provenance(args)
    df = load_dataset(Path(args.dataset))
    require_dataset_features(df, args.allow_missing_features)
    pdf = load_dataset(Path(args.precompile_dataset)) if args.precompile_dataset else None
    feature_cols = [
        c for c in df.columns
        if c not in ("batch_number", "raw_cycles", "effective_cycles")
        and not c.startswith("phase_")
        and c not in TOTAL_EXCLUDE
    ]

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
            table.update(residual_precompile_fit(
                pdf, table, base, col, args.allow_unidentified_precompiles))
        if phase == "vm_execution":
            apply_opcode_floors(table)  # same safety floors as the total (gate uses total)
        result["phases"][phase] = {"features": table, "base": base, "r2": r2}
        report.append(f"\n## phase `{phase}`  (R^2 = {r2:.4f}, base = {base:,.0f})")
        report.append("| feature | cost (cycles) | confidence |")
        report.append("|---|---:|---|")
        for c in used:
            report.append(f"| {c} | {table[c]:,.2f} | {_confidence(df, c)} |")

    # Total fit (all features -> EFFECTIVE/native cycles = raw + weighted
    # delegations). This is the predictor the sequencer compares against the
    # per-proof native budget. τ=0.5 is ordinary NNLS.
    y = df["effective_cycles"].to_numpy(dtype=float)
    used = [c for c in feature_cols if c in df.columns]
    X = df[used].to_numpy(dtype=float)
    coeffs, base, r2 = fit_asymmetric(X, y, args.tau)
    total_table = {c: float(w) for c, w in zip(used, coeffs)}
    # Add precompile coeffs via residual fit (organic total frozen) so their cost is
    # attributed to the precompile features, not to collinear generic opcodes.
    if pdf is not None:
        pc = residual_precompile_fit(pdf, total_table, base, "effective_cycles",
                                     args.allow_unidentified_precompiles)
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
    # UNDER-priced (coef ~117 after the 2026-08-19 refit, was ~71, vs true ~236)
    # because flooring it wrecks organic
    # accuracy; instead the estimator flags any batch where rich_addressing's SHARE
    # of the prediction exceeds what organic batches ever reach (absolute count
    # can't separate them — big mainnet batches have more rich ops than an attack
    # batch, but carry heavy priced storage that dwarfs it). Such a batch is
    # compute-dominated and its under-priced arithmetic drives the estimate, so the
    # gate fails safe. Emit the organic max share as the data-derived basis.
    crich = total_table.get("rich_addressing_op", 0.0)
    rich_shares = [
        crich * row["rich_addressing_op"] / predict_row(base, total_table, row)
        for _, row in df.iterrows()
        if predict_row(base, total_table, row) > 0
    ]
    # Second half of the envelope: the max organic VALUE of each fenced volume
    # feature (see ENVELOPE_FEATURES). The share guard above cannot see a flood —
    # a bytecode/decommit or far-call flood carries almost no arithmetic — so
    # without these the estimator reports "within calibration" for a batch sitting
    # 6-15x outside every counter the corpus ever showed.
    result["calibration"] = {
        "rich_addressing_share_max": max(rich_shares) if rich_shares else 0.0,
        "feature_value_max": {
            f: int(df[f].max()) for f in ENVELOPE_FEATURES if f in df.columns
        },
        "feature_value_max_source": args.dataset_desc or str(args.dataset),
    }
    result["provenance"] = provenance
    missing_envelope = [f for f in ENVELOPE_FEATURES if f not in df.columns]
    if missing_envelope:
        print(f"WARNING: no calibration envelope emitted for {missing_envelope} "
              f"(absent from the dataset) — those features are unfenced",
              file=sys.stderr)
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
    try:
        sys.exit(main())
    except ValueError as e:
        # The fit's own safety guards (identifiability, delegation weights) raise
        # ValueError; a traceback adds nothing to a message that already says what
        # to do about it.
        sys.exit(f"ERROR: {e}")
