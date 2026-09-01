// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {PGPRegistry} from "../PGPRegistry.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        PGPRegistry registry = new PGPRegistry();
        vm.stopBroadcast();

        console.log("PGPRegistry deployed at:", address(registry));
    }
}
