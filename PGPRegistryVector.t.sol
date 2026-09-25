// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {PGPRegistry} from "./PGPRegistry.sol";

/// @dev EIP-712 vectors for identity-kit's tests: each digest is signed and the registry accepts it.
///      Run with `forge test --match-contract PGPRegistryVectorTest -vv` and copy the logged digests.
contract PGPRegistryVectorTest is Test {
    uint256 constant PK = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d; // anvil account 1
    bytes constant FP = hex"6e0053911942a889426c1866e34d9266098f7fe7";
    bytes constant FP2 = hex"03e53d807ce38c130ed42ecece3d0d7f0c9e5fb8";
    bytes constant SIG = hex"c20b0401160a00000000000000";
    bytes constant KEY = hex"c60b0400000000160900000000";
    bytes constant KEY2 = hex"c60b0400000000160900000001";
    uint256 constant DEADLINE = 1_800_000_000;

    PGPRegistry reg;
    address owner;

    function _sign(bytes32 structHash, string memory label) internal returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), structHash));
        emit log_named_bytes32(label, digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_eip712_vectors() public {
        vm.chainId(31337);
        vm.warp(1_790_000_000);
        reg = new PGPRegistry();
        owner = vm.addr(PK);
        emit log_named_address("registry", address(reg));
        emit log_named_address("owner", owner);
        emit log_named_bytes32("domainSeparator", reg.DOMAIN_SEPARATOR());

        bytes memory p = _sign(keccak256(abi.encode(
            reg.ATTEST_TYPEHASH(), owner, keccak256(FP), keccak256(SIG), keccak256(KEY), uint256(0), DEADLINE
        )), "attestDigest (nonce 0)");
        reg.attestFor(owner, FP, SIG, KEY, DEADLINE, p);

        p = _sign(keccak256(abi.encode(
            reg.SET_RECORD_TYPEHASH(), owner, uint256(0), keccak256("security"), keccak256("mailto:x@example.com"), uint256(1), DEADLINE
        )), "setRecordDigest (nonce 1)");
        reg.setRecordFor(owner, 0, "security", "mailto:x@example.com", DEADLINE, p);

        p = _sign(keccak256(abi.encode(
            reg.UPDATE_KEY_TYPEHASH(), owner, uint256(0), keccak256(KEY2), uint256(2), DEADLINE
        )), "updateKeyDigest (nonce 2)");
        reg.updateKeyFor(owner, 0, KEY2, DEADLINE, p);

        p = _sign(keccak256(abi.encode(
            reg.REATTEST_TYPEHASH(), owner, uint256(0), keccak256(FP2), keccak256(SIG), keccak256(KEY), true, uint256(3), DEADLINE
        )), "reattestDigest (nonce 3)");
        reg.reattestFor(owner, 0, FP2, SIG, KEY, true, DEADLINE, p);

        p = _sign(keccak256(abi.encode(
            reg.REVOKE_TYPEHASH(), owner, uint256(1), keccak256("compromised"), uint256(4), DEADLINE
        )), "revokeDigest (nonce 4)");
        reg.revokeFor(owner, 1, "compromised", DEADLINE, p);

        p = _sign(keccak256(abi.encode(
            reg.MARK_COMPROMISED_TYPEHASH(), owner, uint256(0), uint256(5), DEADLINE
        )), "markCompromisedDigest (nonce 5)");
        reg.markCompromisedFor(owner, 0, DEADLINE, p);

        assertEq(reg.nonces(owner), 6);
        assertEq(reg.recordText(owner, 1, "security"), "mailto:x@example.com");
    }
}
