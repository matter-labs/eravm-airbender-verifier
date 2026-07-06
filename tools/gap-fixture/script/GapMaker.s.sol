// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {GapMaker} from "../src/GapMaker.sol";

/// Deploys `GapMaker` and submits one `makeGaps` transaction (three committed
/// net-zero storage patterns on distinct slots), producing a batch with a
/// rolled-back-write gap. Run against a zksync-era node with `--zksync`.
///
///   forge script script/GapMaker.s.sol:DeployAndMakeGap \
///       --zksync --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
///
/// Env overrides:
///   GAP_BASE  base storage slot; the tx touches base, base+1, base+2 (default: a
///             fixed, unlikely constant so they're fresh first-writes)
contract DeployAndMakeGap is Script {
    function run() external {
        // Deterministic, unlikely-to-collide base slot; any fresh slots work since
        // the contract is freshly deployed (all its slots start empty).
        uint256 defaultBase = uint256(keccak256("eravm-airbender-verifier/gap-fixture/v2"));
        uint256 base = vm.envOr("GAP_BASE", defaultBase);

        vm.startBroadcast();
        GapMaker gm = new GapMaker();
        gm.makeGaps(base);
        vm.stopBroadcast();

        console.log("GapMaker deployed at:", address(gm));
        console.log("candidate gap slots (base, base+1, base+2):");
        console.logBytes32(bytes32(base));
        console.logBytes32(bytes32(base + 1));
        console.logBytes32(bytes32(base + 2));
        console.log("Find the L1 batch this tx landed in and share its number to export the fixture");
        console.log("(see tools/gap-fixture/README.md).");
    }
}
