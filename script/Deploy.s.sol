// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {PGPRegistry} from "../PGPRegistry.sol";

/**
 * Deploys PGPRegistry v2 through the canonical CREATE2 deployer with a fixed salt, so the
 * address is identical on every chain (Sepolia and mainnet). Run with --broadcast and an
 * --account keystore; the deployer has no privileges over the contract.
 *
 *   forge script script/Deploy.s.sol --rpc-url sepolia --account <name> --broadcast --verify
 */
contract Deploy is Script {
    bytes32 public constant SALT = keccak256("thurin.pgp-registry.v2");

    function run() external {
        address predicted = vm.computeCreate2Address(SALT, keccak256(type(PGPRegistry).creationCode));
        console.log("Predicted address:", predicted);

        vm.startBroadcast();
        PGPRegistry registry = new PGPRegistry{salt: SALT}();
        vm.stopBroadcast();

        require(address(registry) == predicted, "CREATE2 address mismatch");
        console.log("PGPRegistry v2 deployed at:", address(registry));
    }
}
