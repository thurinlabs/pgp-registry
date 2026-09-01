// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {PGPRegistry} from "../PGPRegistry.sol";

contract Revoke is Script {
    function run() external {
        vm.startBroadcast();
        PGPRegistry registry = PGPRegistry(0x6Ccb62769675B1f19375E5f4C6E8Fc418e50BFD0);
        registry.revoke(0);
        vm.stopBroadcast();

        console.log("Revoked attestation at index 0");
    }
}
