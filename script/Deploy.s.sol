// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {PGPRegistry} from "../PGPRegistry.sol";

/**
 * Deploys PGPRegistry v2 through the canonical CREATE2 deployer with a fixed salt, so the
 * address is identical on every chain that has the deployer (Sepolia, mainnet). On a chain
 * without it (a plain anvil instance) it falls back to a normal CREATE and says so.
 * The deployer account has no privileges over the contract.
 *
 *   forge script script/Deploy.s.sol --rpc-url sepolia --account <name> --broadcast --verify
 *   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --private-key <anvil key> --broadcast
 */
contract Deploy is Script {
    bytes32 public constant SALT = keccak256("thurin.pgp-registry.v2");
    address public constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() external {
        bool haveDeployer = CREATE2_DEPLOYER.code.length > 0;
        PGPRegistry registry;

        if (haveDeployer) {
            address predicted = vm.computeCreate2Address(SALT, keccak256(type(PGPRegistry).creationCode));
            console.log("CREATE2 predicted address:", predicted);
            vm.startBroadcast();
            registry = new PGPRegistry{salt: SALT}();
            vm.stopBroadcast();
            require(address(registry) == predicted, "CREATE2 address mismatch");
        } else {
            console.log("No CREATE2 deployer on this chain (local anvil?) - plain deploy, address will differ.");
            vm.startBroadcast();
            registry = new PGPRegistry();
            vm.stopBroadcast();
        }

        console.log("PGPRegistry v2 deployed at:", address(registry));
        console.log("VERSION:", registry.VERSION());
    }
}
