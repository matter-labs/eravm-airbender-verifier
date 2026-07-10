# Streaming Merkle-proof verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify the batch's Merkle paths and compute the new root without materializing all `N` expanded depth-256 proofs at once, closing the unique-cold-read RAM-exhaustion DoS while preserving byte-identical behavior.

**Architecture:** Fuse the current `get_bowp` → `generate_tree_instructions` → `verify_proofs` → `root_hash()` block into a single streaming pass in the verifier crate that expands, instruction-maps, and fold-verifies one proof at a time (`O(1)` full paths live). The existing three functions stay in the tree as the differential-test oracle. Reuses `merkle_tree`'s existing `HashTree::fold_merkle_path`; no `merkle_tree` API change, no vm2 change.

**Tech Stack:** Rust, `crates/airbender_verifier` (`merkle_witness.rs`, `lib.rs`), `zksync_merkle_tree`, `zksync_crypto_primitives::hasher::blake2::Blake2Hasher`.

## Global Constraints

- **Byte-identical behavior.** The streaming path MUST produce the same `(new_root_hash, enumeration_index)` and the same accept/reject (Ok/Err) as the current three-step path on every input. This is consensus-critical (soundness). Proven by a differential oracle test, not by inspection.
- **Reuse the proven `merkle_tree` fold; do NOT reimplement it.** `fold_merkle_path` (on `impl dyn HashTree`), `TreeEntry::empty`, `TreeLogEntry::is_read`, and `TREE_DEPTH` are private/`pub(crate)` — widen them to `pub` (visibility-only, no logic change) so the streaming pass calls the exact same fold as `verify_proofs`. (This supersedes the original "no merkle_tree API change" goal — decided in favor of soundness: reusing the proven fold beats re-expressing it.) No vm2 change.
- **Fail-closed.** Every malformed-witness / mismatch path must bail or panic (no proof), never succeed with wrong data.
- **Keep the existing `get_bowp` / `generate_tree_instructions` / `verify_proofs` / `map_log_tree` / `classify_witness_leaf`** — they are the oracle.
- Branch: `vv/streaming-merkle-verification` (off `main`, v31). Spec: `docs/superpowers/specs/2026-07-09-streaming-merkle-proof-verification-design.md`.

---

## File Structure

- `crates/airbender_verifier/src/merkle_witness.rs` — add `tree_log_entry_from_witness` (shared classifier, extracted from `get_bowp`), `expand_full_path` (lazy delta-expansion), `verify_paths_and_new_root` (the fused streaming pass), and a `#[cfg(test)]` differential-oracle test module.
- `crates/airbender_verifier/src/lib.rs` — refactor `generate_tree_instructions` to take `vm_logs: Vec<StorageLog>`; replace the three-step block in `execute()` with one call to `verify_paths_and_new_root`.

---

## Task 1: Refactor `generate_tree_instructions` to take `vm_logs` (behavior-preserving)

Enables the oracle (and the current caller) to be driven without constructing a whole `FinishedL1Batch`.

**Files:**
- Modify: `crates/airbender_verifier/src/lib.rs` (`generate_tree_instructions` signature + body head; its single caller in `execute()`)

**Interfaces:**
- Produces: `fn generate_tree_instructions(idx: u64, bowp: &BlockOutputWithProofs, leaf_keys: &[U256], vm_logs: Vec<StorageLog>) -> anyhow::Result<Vec<TreeInstruction>>`

- [ ] **Step 1: Change the signature and drop the `FinishedL1Batch` unwrap.**

Replace the head of `generate_tree_instructions`:
```rust
fn generate_tree_instructions(
    mut idx: u64,
    bowp: &BlockOutputWithProofs,
    leaf_keys: &[U256],
    vm_logs: Vec<StorageLog>,
) -> anyhow::Result<Vec<TreeInstruction>> {
    anyhow::ensure!(
        vm_logs.len() == bowp.logs.len() && bowp.logs.len() == leaf_keys.len(),
        "VM deduplicated storage logs count mismatch with merkle proofs: vm_logs={}, merkle_logs={}",
        vm_logs.len(),
        bowp.logs.len(),
    );
```
Delete the old first line `let vm_logs = vm_out.final_execution_state.deduplicated_storage_logs;`. The rest of the body (the `.zip` map, key binding, `map_log_tree`) is unchanged.

- [ ] **Step 2: Update the caller in `execute()`.**

Where `execute()` currently calls it, extract the logs first (the other `vm_out` fields — `system_logs`, `pubdata_input`, `state_diffs`, `final_bootloader_memory` — are already `take()`n out just above, so `vm_out` is otherwise unused after this except by `generate_tree_instructions`):
```rust
    let vm_logs = std::mem::take(&mut vm_out.final_execution_state.deduplicated_storage_logs);
    let instructions: Vec<TreeInstruction> =
        generate_tree_instructions(enumeration_index, &block_output_with_proofs, &leaf_keys, vm_logs)?;
```
Remove the now-unused `vm_out` binding if the compiler flags it (it is fully consumed).

- [ ] **Step 3: Build + existing tests.**

Run: `cargo test -p zksync_airbender_verifier`
Expected: PASS (behavior unchanged; `get_bowp_rejects_*` tests still pass).

- [ ] **Step 4: Commit.**
```bash
git add crates/airbender_verifier/src/lib.rs
git commit -m "refactor: generate_tree_instructions takes vm_logs, not FinishedL1Batch"
```

---

## Task 2: Extract `tree_log_entry_from_witness` (shared classifier)

So the oracle (`get_bowp`) and the streaming pass classify witness leaves through the *exact same* code.

**Files:**
- Modify: `crates/airbender_verifier/src/merkle_witness.rs` (add fn; refactor `get_bowp` to call it)

**Interfaces:**
- Produces: `fn tree_log_entry_from_witness(log: &StorageLogMetadata) -> anyhow::Result<TreeLogEntry>`

- [ ] **Step 1: Add the function** (the exact `WitnessLeaf` → `TreeLogEntry` mapping currently inline in `get_bowp`):
```rust
/// Classify a witness leaf and map it to its `TreeLogEntry` base. Shared by
/// `get_bowp` (oracle) and `verify_paths_and_new_root` (streaming) so the two
/// can never disagree on classification.
fn tree_log_entry_from_witness(log: &StorageLogMetadata) -> anyhow::Result<TreeLogEntry> {
    Ok(match classify_witness_leaf(log)? {
        WitnessLeaf::Empty { is_write: false } => TreeLogEntry::ReadMissingKey,
        WitnessLeaf::Empty { is_write: true } => TreeLogEntry::Inserted,
        WitnessLeaf::Existing { is_write: false, index, value } => TreeLogEntry::Read {
            leaf_index: index,
            value: value.0.into(),
        },
        WitnessLeaf::Existing { is_write: true, index, value } => TreeLogEntry::Updated {
            leaf_index: index,
            previous_value: value.0.into(),
        },
    })
}
```

- [ ] **Step 2: Refactor `get_bowp` to use it.** Replace the inline `let base = match classify_witness_leaf(&log)? { ... };` block with:
```rust
            let base = tree_log_entry_from_witness(&log)?;
```
(leaving the surrounding `root_hash`, `leaf_hashed_key`, `merkle_path`, and `TreeLogEntryWithProof { .. }` construction unchanged).

- [ ] **Step 3: Build + tests.**

Run: `cargo test -p zksync_airbender_verifier`
Expected: PASS (classification identical; existing `get_bowp_rejects_*` tests still pass).

- [ ] **Step 4: Commit.**
```bash
git add crates/airbender_verifier/src/merkle_witness.rs
git commit -m "refactor: extract tree_log_entry_from_witness shared by get_bowp"
```

---

## Task 3: `expand_full_path` (lazy delta-expansion) + unit test vs `into_merkle_paths`

**Files:**
- Modify: `crates/airbender_verifier/src/merkle_witness.rs` (add fn + test)

**Interfaces:**
- Consumes: `HASH_LEN` (from `crate::types`), `ValueHash` (from `zksync_merkle_tree`)
- Produces: `fn expand_full_path(first: &[[u8; HASH_LEN]], compact: &[[u8; HASH_LEN]]) -> anyhow::Result<Vec<ValueHash>>`

- [ ] **Step 1: Write the failing test** (oracle = the crate's own `into_merkle_paths`):
```rust
#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::types::HASH_LEN;

    fn meta(paths: Vec<[u8; HASH_LEN]>) -> StorageLogMetadata {
        StorageLogMetadata {
            root_hash: [0; HASH_LEN],
            is_write: false,
            first_write: false,
            merkle_paths: paths,
            leaf_hashed_key: U256::zero(),
            leaf_enumeration_index: 1,
            value_written: [0; HASH_LEN],
            value_read: [0; HASH_LEN],
        }
    }

    #[test]
    fn expand_full_path_matches_into_merkle_paths() {
        // first (longest) path of 4 hashes, then two shorter deltas.
        let first = vec![[1u8; HASH_LEN], [2; HASH_LEN], [3; HASH_LEN], [4; HASH_LEN]];
        let second = vec![[9u8; HASH_LEN]]; // shares first[0..3]
        let third = vec![[8u8; HASH_LEN], [7; HASH_LEN]]; // shares first[0..2]

        let witness = WitnessInputMerklePaths {
            merkle_paths: vec![meta(first.clone()), meta(second.clone()), meta(third.clone())],
            ..WitnessInputMerklePaths::new(4)
        };
        let oracle: Vec<Vec<ValueHash>> = witness
            .clone()
            .into_merkle_paths()
            .map(|m| m.merkle_paths.into_iter().map(Into::into).collect())
            .collect();

        let firsts = &witness.merkle_paths[0].merkle_paths;
        let got: Vec<Vec<ValueHash>> = witness
            .merkle_paths
            .iter()
            .map(|m| expand_full_path(firsts, &m.merkle_paths).unwrap())
            .collect();

        assert_eq!(got, oracle);
    }
}
```
(Confirm the exact `WitnessInputMerklePaths` construction against `crates/airbender_verifier/src/types.rs`; adjust the struct literal / `new(depth)` call to match. If `merkle_paths` is not directly constructible, use `push_merkle_path` as in the existing `witness_merkle_paths_roundtrip` test.)

- [ ] **Step 2: Run to verify it fails** (`expand_full_path` undefined).

Run: `cargo test -p zksync_airbender_verifier streaming_tests::expand_full_path_matches`
Expected: FAIL (cannot find function `expand_full_path`).

- [ ] **Step 3: Implement `expand_full_path`.**
```rust
/// Reconstruct entry `i`'s full Merkle path from the delta-compressed witness
/// form: the shared prefix is taken from `first` (the first/longest stored
/// path). Mirrors `WitnessInputMerklePaths::into_merkle_paths`, one entry at a
/// time (entry 0 passes `first` as `compact` and is returned unchanged).
fn expand_full_path(
    first: &[[u8; HASH_LEN]],
    compact: &[[u8; HASH_LEN]],
) -> anyhow::Result<Vec<ValueHash>> {
    anyhow::ensure!(
        compact.len() <= first.len(),
        "Merkle paths malformed: a later path ({}) is longer than the first ({})",
        compact.len(),
        first.len(),
    );
    let prefix_len = first.len() - compact.len();
    let mut full = Vec::with_capacity(first.len());
    full.extend(first[..prefix_len].iter().map(|h| ValueHash::from(*h)));
    full.extend(compact.iter().map(|h| ValueHash::from(*h)));
    Ok(full)
}
```
Add imports at the top of `merkle_witness.rs`: `use zksync_merkle_tree::ValueHash;` and `use crate::types::HASH_LEN;` (adjust to the actual `HASH_LEN` path).

- [ ] **Step 4: Run to verify it passes.**

Run: `cargo test -p zksync_airbender_verifier streaming_tests::expand_full_path_matches`
Expected: PASS.

- [ ] **Step 5: Commit.**
```bash
git add crates/airbender_verifier/src/merkle_witness.rs
git commit -m "feat: expand_full_path (lazy delta-expansion) + test vs into_merkle_paths"
```

---

## Task 4: `verify_paths_and_new_root` (streaming) + differential oracle test

The core change. Reproduces `get_bowp` classification + `generate_tree_instructions` key-binding/`map_log_tree` + `verify_proofs` fold, streaming one entry at a time.

**Files:**
- Modify: `crates/airbender_verifier/src/merkle_witness.rs` (add fn + differential test)

**Interfaces:**
- Consumes: `tree_log_entry_from_witness`, `expand_full_path`, `map_log_tree` (from `lib.rs` — make it `pub(crate)` if not already), `classify_witness_leaf`, `get_bowp`, `generate_tree_instructions`, `verify_proofs`.
- Produces: `pub(crate) fn verify_paths_and_new_root(witness: WitnessInputMerklePaths, vm_logs: Vec<StorageLog>, hasher: &Blake2Hasher, old_root_hash: ValueHash, enumeration_index: u64) -> anyhow::Result<(ValueHash, u64)>`

- [ ] **Step 1: Ensure `map_log_tree` is reachable.** In `lib.rs`, change `fn map_log_tree` to `pub(crate) fn map_log_tree`. In `merkle_witness.rs` add `use crate::map_log_tree;`.

- [ ] **Step 2: Write the failing differential test.** Add to the `streaming_tests` module a helper that runs the **oracle** (the current three-step path) and asserts the streaming result matches, for a set of inputs built from `StorageLog` + witness. Because building inputs by hand is verbose, drive it from a real batch when available and from small hand-built cases:
```rust
    use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
    use zksync_merkle_tree::TreeInstruction;
    use zksync_types::{StorageLog, StorageKey, AccountTreeId, H160};

    /// Oracle: the exact current three-step path.
    fn reference(
        witness: WitnessInputMerklePaths,
        vm_logs: Vec<StorageLog>,
        old_root: ValueHash,
        idx: u64,
    ) -> anyhow::Result<(ValueHash, u64)> {
        let (bowp, leaf_keys) = get_bowp(witness)?;
        let mut idx_mut = idx;
        // Recompute enumeration index the same way generate_tree_instructions does,
        // by counting Inserted instructions.
        let instructions = generate_tree_instructions(idx, &bowp, &leaf_keys, vm_logs)?;
        for instr in &instructions {
            if let TreeInstruction::Write(_) = instr { /* idx handled inside map_log_tree */ }
        }
        bowp.verify_proofs(&Blake2Hasher, old_root, &instructions)?;
        // enumeration index after = idx + number of freshly Inserted leaves.
        // generate_tree_instructions threads it internally; recompute for the oracle:
        idx_mut = idx + instructions.iter().filter(|i| matches!(i, TreeInstruction::Write(e) if e.leaf_index >= idx)).count() as u64;
        let new_root = bowp.root_hash().context("root_hash unavailable after verify_proofs")?;
        Ok((new_root, idx_mut))
    }

    fn assert_equivalent(witness: WitnessInputMerklePaths, vm_logs: Vec<StorageLog>, old_root: ValueHash, idx: u64) {
        let expect = reference(witness.clone(), vm_logs.clone(), old_root, idx);
        let got = verify_paths_and_new_root(witness, vm_logs, &Blake2Hasher, old_root, idx);
        match (expect, got) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "streaming result diverged from oracle"),
            (Err(_), Err(_)) => {}
            (a, b) => panic!("accept/reject diverged: oracle={a:?} streaming={b:?}"),
        }
    }

    #[test]
    fn streaming_matches_oracle_on_missing_key_read() {
        // A single read of a missing key: index 0, not first_write, root unchanged.
        // Build a witness entry + a matching read StorageLog whose hashed key equals leaf_hashed_key.
        // ... (construct via helpers; the storage-view / hashed-key must match) ...
        // assert_equivalent(witness, vm_logs, old_root, 0);
    }
```

> **NOTE for the implementer:** the hand-built cases require a witness whose `leaf_hashed_key` equals the `StorageLog` key's `hashed_key_u256()`, and (for reads) `root_hash` equal to the folded pre-state root so `verify_proofs` accepts. Constructing self-consistent Merkle roots by hand is fiddly. **Prefer driving `assert_equivalent` from real batch data**: in a test gated on a corpus file (e.g. the 506093 integration batch, or a decoded `proof_inputs.json`), run the VM to obtain `vm_out`, then feed `input.merkle_paths` + `deduplicated_storage_logs` into `assert_equivalent`. Use the existing integration-test scaffolding in `host/tests/integration_test.rs` / `crates/cli_utils` as the loader. For the **negative** cases (key-binding mismatch, `first_write`-on-read, repeated-write index 0, read-value mismatch, corrupted `root_hash`, over-`TREE_DEPTH` path), mutate a valid real entry and assert BOTH paths `Err` (via `assert_equivalent`). For the malformed-first-path case (later path longer than first), the oracle `into_merkle_paths` *panics* (`assert!`) while streaming bails — test streaming alone with `verify_paths_and_new_root(...).is_err()` and do not route it through `assert_equivalent`.

- [ ] **Step 3: Run to verify it fails** (`verify_paths_and_new_root` undefined).

Run: `cargo test -p zksync_airbender_verifier streaming_tests::streaming_matches`
Expected: FAIL (cannot find function).

- [ ] **Step 4: Implement `verify_paths_and_new_root`.**
```rust
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_merkle_tree::{HashTree, TreeEntry, TreeInstruction, ValueHash, TREE_DEPTH};
use zksync_types::StorageLog;
use crate::map_log_tree;

/// Streaming replacement for `get_bowp` + `generate_tree_instructions` +
/// `verify_proofs` + `root_hash()`. Verifies every Merkle path against the
/// running root and returns `(new_root_hash, new_enumeration_index)`, holding
/// only one expanded path at a time. Behavior MUST match the three-step path
/// exactly (see the differential test).
pub(crate) fn verify_paths_and_new_root(
    witness: WitnessInputMerklePaths,
    vm_logs: Vec<StorageLog>,
    hasher: &Blake2Hasher,
    old_root_hash: ValueHash,
    mut enumeration_index: u64,
) -> anyhow::Result<(ValueHash, u64)> {
    let metas = witness.merkle_paths;
    // Up front (a bare zip would silently truncate to the shorter side):
    anyhow::ensure!(
        metas.len() == vm_logs.len(),
        "VM deduplicated storage logs count mismatch with merkle proofs: vm_logs={}, merkle_logs={}",
        vm_logs.len(),
        metas.len(),
    );
    anyhow::ensure!(
        !metas.is_empty(),
        "root_hash unavailable after verify_proofs", // matches N==0 -> root_hash() None -> context()
    );
    let first_path = metas[0].merkle_paths.clone();

    let mut root_hash = old_root_hash;
    for (meta, vm_log) in metas.iter().zip(vm_logs.iter()) {
        // (1) classify (shared with get_bowp)
        let base = tree_log_entry_from_witness(meta)?;
        // (2) key binding (from generate_tree_instructions)
        let key = meta.leaf_hashed_key;
        let vm_key = vm_log.key.hashed_key_u256();
        anyhow::ensure!(
            key == vm_key,
            "merkle_paths leaf_hashed_key {key:?} does not match VM storage-log key {vm_key:?}",
        );
        // (3) instruction (from map_log_tree; increments enumeration_index on Inserted)
        let instruction = map_log_tree(key, vm_log, &base, &mut enumeration_index)?;
        // (4) expand + fold-verify (from verify_proofs)
        let full = expand_full_path(&first_path, &meta.merkle_paths)?;
        anyhow::ensure!(full.len() <= TREE_DEPTH);
        let op_root = ValueHash::from(meta.root_hash);
        if matches!(instruction, TreeInstruction::Read(_)) {
            anyhow::ensure!(
                op_root == root_hash,
                "Condition failed: `op.root_hash == root_hash` ({op_root:?} vs {root_hash:?})",
            );
            anyhow::ensure!(base.is_read());
        } else {
            anyhow::ensure!(!base.is_read());
        }
        let prev_entry = match base {
            TreeLogEntry::Inserted | TreeLogEntry::ReadMissingKey => TreeEntry::empty(instruction.key()),
            TreeLogEntry::Updated { leaf_index, previous_value: value }
            | TreeLogEntry::Read { leaf_index, value } => {
                TreeEntry::new(instruction.key(), leaf_index, value)
            }
        };
        let prev_hash = hasher.fold_merkle_path(&full, prev_entry);
        anyhow::ensure!(
            prev_hash == root_hash,
            "Condition failed: `prev_hash == root_hash` ({prev_hash:?} vs {root_hash:?})",
        );
        if let TreeInstruction::Write(new_entry) = instruction {
            let next_hash = hasher.fold_merkle_path(&full, new_entry);
            anyhow::ensure!(
                next_hash == op_root,
                "Condition failed: `next_hash == op.root_hash` ({next_hash:?} vs {op_root:?})",
            );
        }
        root_hash = op_root;
    }
    Ok((root_hash, enumeration_index))
}
```
> Verify while implementing: `ValueHash::from([u8;32])` (get_bowp uses `.into()` on `[u8;HASH_LEN]`); `TreeInstruction::key()` returns the same key type `map_log_tree` used; `HashTree` is the trait carrying `fold_merkle_path` and `Blake2Hasher: HashTree`. Adjust imports/paths to the actual crate exports.

- [ ] **Step 5: Run the differential test to verify it passes.**

Run: `cargo test -p zksync_airbender_verifier streaming_tests`
Expected: PASS — streaming result equals the oracle on every case (accept AND reject).

- [ ] **Step 6: Commit.**
```bash
git add crates/airbender_verifier/src/merkle_witness.rs crates/airbender_verifier/src/lib.rs
git commit -m "feat: streaming verify_paths_and_new_root + differential oracle test"
```

---

## Task 5: Wire `execute()` to the streaming pass; keep the oracle

**Files:**
- Modify: `crates/airbender_verifier/src/lib.rs` (`execute()` block; `#[allow(dead_code)]`/`#[cfg(test)]` on the now-test-only oracle fns as needed)

**Interfaces:**
- Consumes: `verify_paths_and_new_root` (Task 4)

- [ ] **Step 1: Replace the three-step block.** In `execute()`, replace:
```rust
    let (block_output_with_proofs, leaf_keys) = get_bowp(input.merkle_paths)?;
    let vm_logs = std::mem::take(&mut vm_out.final_execution_state.deduplicated_storage_logs);
    let instructions: Vec<TreeInstruction> =
        generate_tree_instructions(enumeration_index, &block_output_with_proofs, &leaf_keys, vm_logs)?;
    block_output_with_proofs
        .verify_proofs(&Blake2Hasher, old_root_hash, &instructions)
        .with_context(|| format!("Failed to verify_proofs {batch_number} correctly!"))?;
    let new_root_hash = block_output_with_proofs
        .root_hash()
        .context("root_hash unavailable after verify_proofs")?;
```
with (note the enumeration-index handling — the streaming fn RETURNS the *new* index, so keep the input as `prev` and delete the old `num_insertions` counting block, which depended on `block_output_with_proofs`):
```rust
    let vm_logs = std::mem::take(&mut vm_out.final_execution_state.deduplicated_storage_logs);
    let prev_enumeration_index = enumeration_index; // = input.merkle_paths.next_enumeration_index()
    let (new_root_hash, new_enumeration_index) = crate::merkle_witness::verify_paths_and_new_root(
        input.merkle_paths,
        vm_logs,
        &Blake2Hasher,
        old_root_hash,
        prev_enumeration_index,
    )
    .with_context(|| format!("Failed to verify Merkle paths for batch {batch_number}"))?;
```
Then DELETE the now-dead block that computed `new_root_hash` via `block_output_with_proofs.root_hash()` AND the `num_insertions`/`new_enumeration_index` block (lines that filter `block_output_with_proofs.logs` for `Inserted`) — `verify_paths_and_new_root` already returns `new_enumeration_index = prev + count(Inserted writes)`, which equals the old `enumeration_index + num_insertions` (every `Inserted` is a write on success). In the returned `VmExecutionState`, use `prev_enumeration_index` for the `prev_enumeration_index` field and the returned `new_enumeration_index` for `new_enumeration_index`. **Do not shadow `enumeration_index` with the new value** — prev and new are distinct. Confirm nothing else consumed `block_output_with_proofs`, `leaf_keys`, or `instructions` after this block (per the read of `execute()`, they do not).

- [ ] **Step 2: Silence dead-code on the oracle.** `get_bowp`, `generate_tree_instructions`, `map_log_tree`, `classify_witness_leaf`, `tree_log_entry_from_witness`, `WitnessLeaf` are now used only by tests. Add `#[cfg_attr(not(test), allow(dead_code))]` to each (do NOT delete — they are the oracle).

- [ ] **Step 3: Build + full test suite.**

Run: `cargo test -p zksync_airbender_verifier && cargo clippy -p zksync_airbender_verifier --all-targets`
Expected: PASS, clippy clean.

- [ ] **Step 4: Commit.**
```bash
git add crates/airbender_verifier/src/lib.rs crates/airbender_verifier/src/merkle_witness.rs
git commit -m "perf: route execute() Merkle verification through streaming pass"
```

---

## Task 6: End-to-end validation (commitment invariance + memory)

**Files:**
- No source changes. Validation only (uses the throwaway talc/mem_probe harness from the `v31-mem` worktree, or `probe_guest_memory.sh`).

- [ ] **Step 1: Commitment invariance.** Run full `verify()` (via the host integration test or the `verify_check` example) on a real batch (e.g. 506093) with the streaming path, and confirm `proof_public_input` + `value_hash` are byte-identical to the pre-change (`main`) result. Expected: identical.

- [ ] **Step 2: Memory — real batch.** Run the talc timeline on 506093/67912-class input; confirm the `get_bowp`/verification phase no longer spikes (peak stays far below prior levels). Expected: proof-phase peak drops to tens of KiB of paths.

- [ ] **Step 3: Memory — adversarial batch.** Run `batch_140k_unique_storage_reads` (the v31 batch). Confirm the peak stays well under 952 MiB (previously ~1218 MiB at `get_bowp`). Expected: no OOM; peak ≈ the ~150 MiB pre-`get_bowp` level.

- [ ] **Step 4: Record results** in the spec/PR description; open the PR.

---

## Self-Review

- **Spec coverage:** streaming fused pass (Tasks 2–5) ✓; lazy expansion (Task 3) ✓; verbatim classify/key-binding/map_log_tree/fold (Task 4 code) ✓; count-check up front (Task 4 Step 4) ✓; N==0 error preserved (Task 4) ✓; differential oracle test on real+adversarial+negative+edge (Task 4 Step 2, Task 6) ✓; commitment invariance + memory (Task 6) ✓; oracle kept (Task 5 Step 2) ✓; no merkle_tree/vm2 API change ✓.
- **Placeholder scan:** the only soft spots are the *test input construction* in Task 4 Step 2 — deliberately flagged as "prefer real-batch-driven" with an implementer NOTE because hand-rolling self-consistent Merkle roots is error-prone; the assertion logic and negative cases are concrete.
- **Type consistency:** `verify_paths_and_new_root` signature, `expand_full_path`, `tree_log_entry_from_witness`, and the refactored `generate_tree_instructions(vm_logs)` are consistent across tasks; `map_log_tree` made `pub(crate)`.
