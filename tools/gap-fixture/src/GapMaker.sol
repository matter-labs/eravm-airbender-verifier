// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Mints the "rolled-back write" gap shape that the airbender verifier's
/// `rolled_back_write_gap_is_harmless` regression needs.
///
/// A "gap" is a storage slot the VM **accessed but that `merkle_paths` omits**.
/// `merkle_paths` = net writes ∪ protective reads. A slot is a gap when it is
/// **written but nets to zero** (so it's excluded from writes) yet its access is
/// **committed** (so it's recorded in `read_storage_key` / `is_write_initial`).
/// The verifier serves such a slot empty and must ignore any operator-supplied
/// value for it — the property under test.
///
/// A frame revert does NOT work: the fast VM drops a reverted write entirely from
/// its world-diff (no net change *and* no recorded access), so no gap appears. The
/// write-back must be **committed**. This contract exercises three committed
/// net-zero patterns on distinct slots so a single batch can be inspected to see
/// which the witness pipeline surfaces as a gap.
contract GapMaker {
    /// Write a fresh slot nonzero, then back to its original (0). Net change zero;
    /// the slot is written (→ not a protective read) but has no net write (→ not in
    /// merkle_paths), while its cold access is recorded.
    function netZeroWrite(uint256 slot) public {
        assembly {
            sstore(slot, 1)
            sstore(slot, 0)
        }
    }

    /// Explicit SLOAD first (forces the slot into the read set), then a net-zero
    /// write around the read value.
    function sloadNetZero(uint256 slot) public {
        assembly {
            let v := sload(slot)
            sstore(slot, add(v, 1))
            sstore(slot, v)
        }
    }

    /// Inner frame writes then reverts (kept for comparison — expected NOT to
    /// produce a gap under the fast VM, but harmless to include).
    function writeAndRevert(uint256 slot) external {
        assembly {
            sstore(slot, 7)
        }
        revert("rollback");
    }

    function revertWrite(uint256 slot) public {
        try this.writeAndRevert(slot) {
            revert("unreachable");
        } catch {}
    }

    /// Run all three patterns on distinct slots (`base`, `base+1`, `base+2`) in one
    /// committed transaction. Inspect the resulting batch to see which slot lands in
    /// `read_storage_key`/`is_write_initial` but not `merkle_paths`.
    function makeGaps(uint256 base) external {
        netZeroWrite(base);
        sloadNetZero(base + 1);
        revertWrite(base + 2);
    }
}
