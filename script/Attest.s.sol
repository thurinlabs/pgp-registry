// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {PGPRegistry} from "../PGPRegistry.sol";

/**
 * Direct attest from the broadcasting account.
 *
 *   REGISTRY=0x... FINGERPRINT=0x<40 or 64 hex> \
 *   forge script script/Attest.s.sol --rpc-url sepolia --account <name> --broadcast
 *
 * Reads script/pgp-sig.txt (clearsigned message) and script/pgp-key.txt (armored key).
 */
contract Attest is Script {
    function run() external {
        PGPRegistry registry = PGPRegistry(vm.envAddress("REGISTRY"));
        bytes memory fingerprint = vm.envBytes("FINGERPRINT");
        // forge-lint: disable-next-line(unsafe-cheatcode)
        bytes memory pgpSignature = bytes(vm.readFile("script/pgp-sig.txt"));
        // forge-lint: disable-next-line(unsafe-cheatcode)
        bytes memory pgpPublicKey = bytes(vm.readFile("script/pgp-key.txt"));

        vm.startBroadcast();
        uint256 index = registry.attest(fingerprint, pgpSignature, pgpPublicKey);
        vm.stopBroadcast();

        console.log("Attested at index:", index);
    }
}
