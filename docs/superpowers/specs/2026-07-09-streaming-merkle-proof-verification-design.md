# Streaming Merkle-proof verification (`get_bowp` fix)

**Date:** 2026-07-09
**Status:** design approved, pending spec review
**Area:** `crates/airbender_verifier` (`merkle_witness.rs`, `lib.rs`), reusing `crates/merkle_tree`

## Problem

`execute()` verifies the batch's storage against the tree in three steps:

1. `get_bowp(input.merkle_paths)` — expands every witness path to full depth and builds
   `BlockOutputWithProofs { logs: Vec<TreeLogEntryWithProof> }` (all `N` proofs) plus `Vec<U256>` leaf keys.
2. `generate_tree_instructions(...)` — builds `Vec<TreeInstruction>` (all `N`) by zipping the VM's
   deduplicated storage logs with `bowp.logs` and the leaf keys.
3. `bowp.verify_proofs(hasher, old_root_hash, &instructions)` — sequential fold, then
   `new_root_hash = bowp.root_hash()`.

Merkle paths ship delta-compressed (each stored path is the differing tail relative to the first/longest
path) but `into_merkle_paths` re-expands **every** path to full depth (256 hashes × 32 B ≈ 8 KiB each), and
`get_bowp` holds all `N` simultaneously. Peak = `O(N · 8 KiB)`.

`N` (deduplicated storage slots = protective-reads ∪ writes) is bounded **only by gas** — cold read =
2000 ergs, and there is no per-batch cap on reads (only initial *writes* are capped, at `u16::MAX`). A batch
that reads many distinct slots therefore drives this to arbitrary size.

**Validated (v31 `main`, real adversarial batch `batch_140k_unique_storage_reads`, ~280M gas ≈ 3.5 max txs):**

| point | live |
|---|---|
| before `get_bowp` | 147 MiB |
| after `get_bowp` (expanded) | **1148 MiB** (+1001) |
| final talc peak | **1218 MiB** |

`N = 140,059`, depth `L = 256` → expanded ≈ 1094 MiB. The guest heap is **952 MiB**, so this OOMs at
`get_bowp` → the batch cannot be proven → **settlement liveness DoS**. The blowup is entirely at `get_bowp`;
every prior phase is ≤154 MiB. This is **independent of** and **unmitigated by** the returndata-heap reclaim
(that targets `finish_batch`, upstream of and unrelated to `get_bowp`).

## Goal

Verify the Merkle paths and compute the new root **without materializing all `N` expanded proofs at once**,
with **byte-identical behavior** (same `new_root_hash`, same `enumeration_index`, same accept/reject on every
input). Peak for the proof phase → `O(1)` full paths.

## Non-goals

- No defensive read cap / metering (a separate, complementary change; not required once the peak is `O(1)`).
- No change to the `merkle_tree` public API — reuse the existing `HashTree::fold_merkle_path`.
- The returndata reclaim (separate vm2 PR) is orthogonal and not part of this.

## Design (Approach A — verifier-local fused pass)

A single new function in `crates/airbender_verifier/src/merkle_witness.rs`:

```rust
fn verify_paths_and_new_root(
    witness: WitnessInputMerklePaths,
    vm_logs: Vec<StorageLog>,          // moved out of vm_out.final_execution_state.deduplicated_storage_logs
    hasher: &Blake2Hasher,
    old_root_hash: ValueHash,
    enumeration_index: u64,
) -> anyhow::Result<(ValueHash, u64)>  // (new_root_hash, new_enumeration_index)
```

`execute()` replaces the `get_bowp` → `generate_tree_instructions` → `verify_proofs` → `root_hash()` block with
one call to this function and uses the returned pair.

### Lazy delta-expansion

Retain entry 0's `merkle_paths` as the prefix source `first` (length `L`). Entry 0's full path **is** `first`.
For entry `i > 0`: `full = first[0 .. L - compact_i.len()]  ++  compact_i`, preserving the existing guard
`compact_i.len() <= L` (today an `assert!` in `into_merkle_paths`; kept as a fail-closed check). Only `first`
(~8 KiB) and the current `full` (~8 KiB) are live at once.

### Per-entry pass (reproduces the current logic verbatim, in the same order)

**Up front, before the loop** (soundness-critical — a bare `zip` would silently truncate to the shorter
sequence): `ensure!(witness.len() == vm_logs.len())`. This is the same length equality the current
`generate_tree_instructions` asserts before zipping; `leaf_keys` count equals `witness` count by construction.

For each entry `i`, zipping the witness with `vm_logs` in order, threading `root_hash` (init `old_root_hash`)
and `enumeration_index`:

1. **classify** `classify_witness_leaf(&meta)` → base `TreeLogEntry`, preserving all bail cases:
   - read + `first_write` → bail; read + index 0 → `ReadMissingKey`; read + index>0 → `Read{index, value_read}`;
   - write + `first_write` → `Inserted`; write + index 0 → bail; write + index>0 → `Updated{index, value_read}`.
2. **key binding** `ensure!(meta.leaf_hashed_key == vm_log.key.hashed_key_u256())` — the soundness bind that
   makes positional zip safe.
3. **instruction** `map_log_tree(key, &vm_log, &base, &mut enumeration_index)` verbatim:
   - write+`Updated` → `Write(key, leaf_index, value)`; write+`Inserted` → `Write(key, enumeration_index++, value)`;
   - read+`Read` → check `vm_log.value == base.value` (bail on mismatch) → `Read(key)`; read+`ReadMissingKey` → `Read(key)`;
   - every other `(is_write, base)` combination → bail.
4. **fold / verify** verbatim from `verify_proofs`:
   - `ensure!(full.len() <= TREE_DEPTH)`;
   - if `Read`: `ensure!(meta.root_hash == root_hash)` and `base.is_read()`; else `ensure!(!base.is_read())`;
   - `prev_entry` from `base` (`TreeEntry::empty(key)` for `Inserted`/`ReadMissingKey`, else `TreeEntry::new(key, leaf_index, value)`);
   - `prev_hash = hasher.fold_merkle_path(&full, prev_entry); ensure!(prev_hash == root_hash)`;
   - if `Write(new_entry)`: `ensure!(hasher.fold_merkle_path(&full, new_entry) == meta.root_hash)`;
   - `root_hash = meta.root_hash`.
5. drop `full`.

After the loop:

- `new_root_hash`: the final threaded `root_hash` (= `logs.last().root_hash` = `bowp.root_hash()`). **`N == 0`
  reproduces today's `root_hash().context(...)` error** — empty batch is rejected exactly as now.
- return `(new_root_hash, enumeration_index)`.

**Correctness claim:** identical operations, identical order, identical `ensure!`/`bail!`/`assert!` conditions,
identical `idx`/`root_hash` threading. The *only* behavioral difference is not holding all `N` proofs at once.

## Testing (the soundness gate — proof by differential oracle, not by reading)

The existing `get_bowp` / `generate_tree_instructions` / `verify_proofs` stay in the tree **unchanged** and
serve as the reference oracle.

1. **Differential equivalence test.** A helper runs both paths on identical inputs and asserts:
   - identical `Ok((new_root_hash, enumeration_index))`, **and**
   - identical `Err` (same rejection) on failure inputs.
2. **Inputs:**
   - real batch(es) from the corpus (e.g. 506093 integration batch);
   - the adversarial `batch_140k_unique_storage_reads` (also asserts peak stays well under 952 MiB — see below);
   - hand-built edge cases: empty witness (both error), single entry, and each `(is_write, first_write, index)`
     class (insert / update / existing-read / missing-key-read);
   - **negative/soundness cases** (both must reject identically): key-binding mismatch, `first_write` on a read,
     repeated write with index 0, `read` value mismatch, corrupted `root_hash`, path longer than `TREE_DEPTH`,
     malformed first path (later path longer than first).
3. **Commitment invariance.** End-to-end `verify()` `proof_public_input` byte-identical with vs without the
   streaming path (the check already used to validate the returndata reclaim).
4. **Memory.** Under the talc harness, proof-phase peak on the 140K batch drops from ~1094 MiB to ~tens of KiB;
   full-run peak stays under 952 MiB.

## Memory & fail-closed

Proof-phase peak: `O(N · 8 KiB)` → `O(2 · 8 KiB)`. All malformed-witness / mismatch paths remain fail-closed
(bail/panic → no proof), identical to today.

## Risks

- **Ordering:** positional zip of witness vs `vm_logs` — safe because the per-entry key binding rejects any
  positional disagreement (same guard the current code relies on). Preserved verbatim.
- **Behavioral drift:** mitigated by the differential oracle test — the old path is the ground truth.
- The change is confined to the verifier crate; `merkle_tree` and vm2 are untouched.
