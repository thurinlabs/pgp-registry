// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {PGPRegistry} from "../PGPRegistry.sol";

/**
 * Produce an EIP-712 authorization for a relayed write, signed by the unlocked --account
 * (keystore or hardware wallet). Nothing is broadcast; the printed signature is handed to
 * whoever submits the matching `…For` call and pays the gas (e.g. `cast send`).
 *
 *   ACTION=attest    REGISTRY=0x... OWNER=0x... FINGERPRINT=0x... [DEADLINE=<unix>] \
 *   forge script script/Authorize.s.sol --rpc-url sepolia --account <name>
 *
 *   ACTION=revoke    … INDEX=0
 *   ACTION=updateKey … INDEX=0                      (reads script/pgp-key.txt)
 *   ACTION=reattest  … INDEX=<revokeIndex> FINGERPRINT=0x...
 *   ACTION=setRecord … INDEX=0 KIND=0x<bytes32> VALUE=0x<hex>
 *
 * Deadline defaults to now + 1 hour. Never sign an authorization you did not compose.
 * The submitter must pass byte-identical payloads (same trailing newline) or the hash won't match.
 * To burn an outstanding authorization: `cast send <registry> "cancelAuthorization()"`.
 */
contract Authorize is Script {
    function run() external view {
        PGPRegistry registry = PGPRegistry(vm.envAddress("REGISTRY"));
        address owner = vm.envAddress("OWNER");
        string memory action = vm.envString("ACTION");
        uint256 deadline = vm.envOr("DEADLINE", block.timestamp + 1 hours);
        // NONCE overrides the on-chain value when preparing several authorizations ahead of time.
        uint256 nonce = vm.envOr("NONCE", registry.nonces(owner));

        bytes32 structHash;
        bytes32 a = keccak256(bytes(action));
        if (a == keccak256("attest")) {
            structHash = keccak256(abi.encode(
                registry.ATTEST_TYPEHASH(), owner, keccak256(vm.envBytes("FINGERPRINT")),
                keccak256(_file("script/pgp-sig.txt")), keccak256(_file("script/pgp-key.txt")), nonce, deadline
            ));
        } else if (a == keccak256("reattest")) {
            structHash = keccak256(abi.encode(
                registry.REATTEST_TYPEHASH(), owner, vm.envUint("INDEX"), keccak256(vm.envBytes("FINGERPRINT")),
                keccak256(_file("script/pgp-sig.txt")), keccak256(_file("script/pgp-key.txt")), nonce, deadline
            ));
        } else if (a == keccak256("updateKey")) {
            structHash = keccak256(abi.encode(
                registry.UPDATE_KEY_TYPEHASH(), owner, vm.envUint("INDEX"), keccak256(_file("script/pgp-key.txt")), nonce, deadline
            ));
        } else if (a == keccak256("revoke")) {
            structHash = keccak256(abi.encode(registry.REVOKE_TYPEHASH(), owner, vm.envUint("INDEX"), nonce, deadline));
        } else if (a == keccak256("setRecord")) {
            structHash = keccak256(abi.encode(
                registry.SET_RECORD_TYPEHASH(), owner, vm.envUint("INDEX"), vm.envBytes32("KIND"),
                keccak256(vm.envBytes("VALUE")), nonce, deadline
            ));
        } else {
            revert("ACTION must be attest|reattest|updateKey|revoke|setRecord");
        }

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner, digest);

        console.log("digest:   ", vm.toString(digest));
        console.log("action:   ", action);
        console.log("owner:    ", owner);
        console.log("nonce:    ", nonce);
        console.log("deadline: ", deadline);
        console.log("signature:", vm.toString(abi.encodePacked(r, s, v)));
    }

    function _file(string memory path) internal view returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-cheatcode)
        return bytes(vm.readFile(path));
    }
}
