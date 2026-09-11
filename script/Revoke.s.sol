// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {PGPRegistry} from "../PGPRegistry.sol";

/**
 *   REGISTRY=0x... INDEX=0 forge script script/Revoke.s.sol --rpc-url sepolia --account <name> --broadcast
 */
contract Revoke is Script {
    function run() external {
        PGPRegistry registry = PGPRegistry(vm.envAddress("REGISTRY"));
        uint256 index = vm.envUint("INDEX");

        vm.startBroadcast();
        registry.revoke(index);
        vm.stopBroadcast();

        console.log("Revoked attestation at index:", index);
    }
}
