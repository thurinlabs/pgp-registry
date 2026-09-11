// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {PGPRegistry} from "./PGPRegistry.sol";
import {SSTORE2} from "./SSTORE2.sol";

/// @dev EIP-1271 wallet that accepts signatures from one EOA.
contract MockWallet {
    address public immutable signer;
    constructor(address s) { signer = s; }
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(abi.encodePacked(sig[0:32], sig[32:64], uint256(uint8(sig[64]))), (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s) == signer ? bytes4(0x1626ba7e) : bytes4(0);
    }
}

contract RejectingWallet {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) { return 0; }
}

contract SSTORE2Harness {
    function write(bytes calldata d) external returns (address) { return SSTORE2.write(d); }
    function read(address p) external view returns (bytes memory) { return SSTORE2.read(p); }
}

contract PGPRegistryTest is Test {
    PGPRegistry registry;

    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    address alice;
    address bob;
    address relayer = address(0x5E1A7E5);

    bytes constant FP4  = hex"6e0053911942a889426c1866e34d9266098f7fe7";                                  // 20 bytes
    bytes constant FP4B = hex"76bf00000000000000000000e34d9266098f7fe7";                                  // 20 bytes, same key id as FP4
    bytes constant FP6  = hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";          // 32 bytes
    bytes constant SIG  = "-----BEGIN PGP SIGNED MESSAGE-----\nI control the Ethereum address: 0x...\n-----END PGP SIGNATURE-----";
    bytes constant KEY  = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmDMEZ...\n-----END PGP PUBLIC KEY BLOCK-----";
    bytes constant KEY2 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmDMEZ...with-notations\n-----END PGP PUBLIC KEY BLOCK-----";

    bytes32 constant KIND = keccak256("thurin.test");

    function setUp() public {
        registry = new PGPRegistry();
        alice = vm.addr(ALICE_PK);
        bob = vm.addr(BOB_PK);
        vm.warp(1_700_000_000);
    }

    // ─── helpers ────────────────────────────────────────────────────────────

    function _filled(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; i++) b[i] = bytes1(uint8(0x41 + (i % 26)));
    }

    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), structHash));
    }

    function _sign(uint256 pk, bytes32 structHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _digest(structHash));
        return abi.encodePacked(r, s, v);
    }

    function _attestHash(address owner, bytes memory fp, bytes memory sig, bytes memory key, uint256 nonce, uint256 deadline)
        internal view returns (bytes32)
    {
        return keccak256(abi.encode(registry.ATTEST_TYPEHASH(), owner, keccak256(fp), keccak256(sig), keccak256(key), nonce, deadline));
    }

    function _reattestHash(address owner, uint256 idx, bytes memory fp, bytes memory sig, bytes memory key, uint256 nonce, uint256 deadline)
        internal view returns (bytes32)
    {
        return keccak256(abi.encode(registry.REATTEST_TYPEHASH(), owner, idx, keccak256(fp), keccak256(sig), keccak256(key), nonce, deadline));
    }

    function _updateKeyHash(address owner, uint256 idx, bytes memory key, uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        return keccak256(abi.encode(registry.UPDATE_KEY_TYPEHASH(), owner, idx, keccak256(key), nonce, deadline));
    }

    function _revokeHash(address owner, uint256 idx, uint256 nonce, uint256 deadline) internal view returns (bytes32) {
        return keccak256(abi.encode(registry.REVOKE_TYPEHASH(), owner, idx, nonce, deadline));
    }

    function _setRecordHash(address owner, uint256 idx, bytes32 kind, bytes memory value, uint256 nonce, uint256 deadline)
        internal view returns (bytes32)
    {
        return keccak256(abi.encode(registry.SET_RECORD_TYPEHASH(), owner, idx, kind, keccak256(value), nonce, deadline));
    }

    function _attestAlice() internal returns (uint256) {
        vm.prank(alice);
        return registry.attest(FP4, SIG, KEY);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  attest
    // ═══════════════════════════════════════════════════════════════════════

    function test_attest_stores_and_reads_back() public {
        uint256 idx = _attestAlice();
        assertEq(idx, 0);
        assertEq(registry.attestationCount(alice), 1);

        PGPRegistry.Attestation memory a = registry.getAttestation(alice, 0);
        assertEq(a.fingerprint, FP4);
        assertEq(a.createdAt, uint64(block.timestamp));
        assertEq(a.revokedAt, 0);
        assertEq(a.messageVersion, registry.MESSAGE_VERSION());
        assertTrue(a.keyPtr != address(0));
        assertTrue(a.sigPtr != address(0));

        (bytes memory sig, bytes memory key) = registry.getPayload(alice, 0);
        assertEq(sig, SIG);
        assertEq(key, KEY);
    }

    function test_attest_emits_event() public {
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.Attested(alice, keccak256(FP4), 0, FP4, 1, alice);
        registry.attest(FP4, SIG, KEY);
    }

    function test_attest_accepts_v6_fingerprint() public {
        vm.prank(alice);
        registry.attest(FP6, SIG, KEY);
        assertEq(registry.getAttestation(alice, 0).fingerprint, FP6);
    }

    function test_attest_revert_fingerprint_lengths() public {
        uint8[5] memory bad = [0, 19, 21, 31, 33];
        for (uint256 i = 0; i < bad.length; i++) {
            vm.prank(alice);
            vm.expectRevert(PGPRegistry.InvalidFingerprintLength.selector);
            registry.attest(_filled(bad[i]), SIG, KEY);
        }
    }

    function test_attest_revert_empty_payloads() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.EmptySignature.selector);
        registry.attest(FP4, "", KEY);

        vm.prank(alice);
        vm.expectRevert(PGPRegistry.EmptyPublicKey.selector);
        registry.attest(FP4, SIG, "");
    }

    function test_attest_revert_oversized_payloads() public {
        bytes memory bigSig = _filled(registry.MAX_SIG_BYTES() + 1);
        bytes memory bigKey = _filled(registry.MAX_KEY_BYTES() + 1);

        vm.prank(alice);
        vm.expectRevert(PGPRegistry.SignatureTooLarge.selector);
        registry.attest(FP4, bigSig, KEY);

        vm.prank(alice);
        vm.expectRevert(PGPRegistry.PublicKeyTooLarge.selector);
        registry.attest(FP4, SIG, bigKey);
    }

    function test_attest_accepts_max_payloads() public {
        bytes memory sig = _filled(registry.MAX_SIG_BYTES());
        bytes memory key = _filled(registry.MAX_KEY_BYTES());
        vm.prank(alice);
        registry.attest(FP4, sig, key);
        (bytes memory s, bytes memory k) = registry.getPayload(alice, 0);
        assertEq(s, sig);
        assertEq(k, key);
    }

    function test_attest_revert_duplicate_active() public {
        _attestAlice();
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.DuplicateActiveFingerprint.selector);
        registry.attest(FP4, SIG, KEY);
    }

    function test_attest_multiple_fingerprints_same_owner() public {
        vm.startPrank(alice);
        registry.attest(FP4, SIG, KEY);
        registry.attest(FP6, SIG, KEY);
        vm.stopPrank();
        assertEq(registry.attestationCount(alice), 2);
        assertEq(registry.getAttestation(alice, 1).fingerprint, FP6);
    }

    function test_attest_same_fingerprint_many_owners() public {
        _attestAlice();
        vm.prank(bob);
        registry.attest(FP4, SIG, KEY);
        assertEq(registry.attestationCount(bob), 1);
        address[] memory owners = registry.addressesFor(keccak256(FP4));
        assertEq(owners.length, 2);
        assertEq(owners[0], alice);
        assertEq(owners[1], bob);
    }

    function test_attest_allowed_after_revoke() public {
        _attestAlice();
        vm.startPrank(alice);
        registry.revoke(0);
        registry.attest(FP4, SIG, KEY);
        vm.stopPrank();
        assertEq(registry.attestationCount(alice), 2);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  reattest
    // ═══════════════════════════════════════════════════════════════════════

    function test_reattest_same_fingerprint_is_atomic() public {
        _attestAlice();
        vm.warp(block.timestamp + 100);
        vm.prank(alice);
        uint256 idx = registry.reattest(0, FP4, SIG, KEY2);
        assertEq(idx, 1);
        assertEq(registry.getAttestation(alice, 0).revokedAt, uint64(block.timestamp));
        assertEq(registry.getAttestation(alice, 1).revokedAt, 0);
        (, bytes memory key) = registry.getPayload(alice, 1);
        assertEq(key, KEY2);
    }

    function test_reattest_different_fingerprint_rotates_key() public {
        _attestAlice();
        vm.prank(alice);
        registry.reattest(0, FP6, SIG, KEY);
        (bool found, uint256 idx, PGPRegistry.Attestation memory a) = registry.current(alice);
        assertTrue(found);
        assertEq(idx, 1);
        assertEq(a.fingerprint, FP6);
    }

    function test_reattest_emits_both_events() public {
        _attestAlice();
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.Revoked(alice, keccak256(FP4), 0, alice);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.Attested(alice, keccak256(FP6), 1, FP6, 1, alice);
        registry.reattest(0, FP6, SIG, KEY);
    }

    function test_reattest_revert_when_index_not_active() public {
        _attestAlice();
        vm.startPrank(alice);
        registry.revoke(0);
        vm.expectRevert(PGPRegistry.AlreadyRevoked.selector);
        registry.reattest(0, FP4, SIG, KEY);
        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.reattest(5, FP4, SIG, KEY);
        vm.stopPrank();
    }

    function test_reattest_reverts_atomically_on_bad_payload() public {
        _attestAlice();
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.EmptyPublicKey.selector);
        registry.reattest(0, FP4, SIG, "");
        assertEq(registry.getAttestation(alice, 0).revokedAt, 0); // revoke rolled back
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  updateKey
    // ═══════════════════════════════════════════════════════════════════════

    function test_updateKey_replaces_key_only() public {
        _attestAlice();
        address oldPtr = registry.getAttestation(alice, 0).keyPtr;
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.KeyUpdated(alice, keccak256(FP4), 0, alice);
        registry.updateKey(0, KEY2);

        PGPRegistry.Attestation memory a = registry.getAttestation(alice, 0);
        assertTrue(a.keyPtr != oldPtr);
        assertEq(a.fingerprint, FP4);
        (bytes memory sig, bytes memory key) = registry.getPayload(alice, 0);
        assertEq(sig, SIG);
        assertEq(key, KEY2);
        assertEq(SSTORE2.read(oldPtr), KEY); // old data contract untouched
    }

    function test_updateKey_reverts() public {
        _attestAlice();
        vm.startPrank(alice);
        vm.expectRevert(PGPRegistry.EmptyPublicKey.selector);
        registry.updateKey(0, "");
        bytes memory bigKey = _filled(registry.MAX_KEY_BYTES() + 1);
        vm.expectRevert(PGPRegistry.PublicKeyTooLarge.selector);
        registry.updateKey(0, bigKey);
        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.updateKey(1, KEY2);
        registry.revoke(0);
        vm.expectRevert(PGPRegistry.AlreadyRevoked.selector);
        registry.updateKey(0, KEY2);
        vm.stopPrank();

        // bob has no attestation at index 0 — cannot touch alice's
        vm.prank(bob);
        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.updateKey(0, KEY2);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  revoke
    // ═══════════════════════════════════════════════════════════════════════

    function test_revoke_marks_and_emits() public {
        _attestAlice();
        vm.warp(block.timestamp + 5);
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.Revoked(alice, keccak256(FP4), 0, alice);
        registry.revoke(0);
        assertEq(registry.getAttestation(alice, 0).revokedAt, uint64(block.timestamp));
        (bool found,,) = registry.current(alice);
        assertFalse(found);
    }

    function test_revoke_reverts() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.revoke(0);

        _attestAlice();
        vm.startPrank(alice);
        registry.revoke(0);
        vm.expectRevert(PGPRegistry.AlreadyRevoked.selector);
        registry.revoke(0);
        vm.stopPrank();
    }

    function test_revoke_does_not_affect_other_owners() public {
        _attestAlice();
        vm.prank(bob);
        registry.attest(FP4, SIG, KEY);
        vm.prank(alice);
        registry.revoke(0);
        assertTrue(registry.getAttestation(alice, 0).revokedAt != 0);
        assertEq(registry.getAttestation(bob, 0).revokedAt, 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  records
    // ═══════════════════════════════════════════════════════════════════════

    function test_record_set_read_clear() public {
        _attestAlice();
        assertEq(registry.record(alice, 0, KIND), "");

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.RecordSet(alice, 0, KIND, alice);
        registry.setRecord(0, KIND, "ipfs://bafy...");
        assertEq(registry.record(alice, 0, KIND), "ipfs://bafy...");
        assertEq(registry.record(alice, 0, keccak256("other")), "");

        vm.prank(alice);
        registry.setRecord(0, KIND, "");
        assertEq(registry.record(alice, 0, KIND), "");
    }

    function test_record_accepts_max_and_rejects_over() public {
        _attestAlice();
        vm.startPrank(alice);
        registry.setRecord(0, KIND, _filled(registry.MAX_RECORD_BYTES()));
        assertEq(registry.record(alice, 0, KIND).length, registry.MAX_RECORD_BYTES());
        bytes memory bigRecord = _filled(registry.MAX_RECORD_BYTES() + 1);
        vm.expectRevert(PGPRegistry.RecordTooLarge.selector);
        registry.setRecord(0, KIND, bigRecord);
        vm.stopPrank();
    }

    function test_record_requires_active_attestation() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.setRecord(0, KIND, "x");

        _attestAlice();
        vm.startPrank(alice);
        registry.revoke(0);
        vm.expectRevert(PGPRegistry.AlreadyRevoked.selector);
        registry.setRecord(0, KIND, "x");
        vm.stopPrank();
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  views / indexes
    // ═══════════════════════════════════════════════════════════════════════

    function test_attestationsOf_returns_history() public {
        vm.startPrank(alice);
        registry.attest(FP4, SIG, KEY);
        registry.attest(FP6, SIG, KEY);
        registry.revoke(0);
        vm.stopPrank();
        PGPRegistry.Attestation[] memory all = registry.attestationsOf(alice);
        assertEq(all.length, 2);
        assertTrue(all[0].revokedAt != 0);
        assertEq(all[1].fingerprint, FP6);
        assertEq(registry.attestationsOf(bob).length, 0);
    }

    function test_current_picks_latest_active() public {
        vm.startPrank(alice);
        registry.attest(FP4, SIG, KEY);   // 0
        registry.attest(FP6, SIG, KEY);   // 1
        registry.revoke(1);
        vm.stopPrank();
        (bool found, uint256 idx, PGPRegistry.Attestation memory a) = registry.current(alice);
        assertTrue(found);
        assertEq(idx, 0);
        assertEq(a.fingerprint, FP4);

        (bool none,,) = registry.current(bob);
        assertFalse(none);
    }

    function test_getAttestation_and_getPayload_out_of_bounds() public {
        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.getAttestation(alice, 0);
        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.getPayload(alice, 0);
    }

    function test_addressesFor_dedups_repeat_owner() public {
        vm.startPrank(alice);
        registry.attest(FP4, SIG, KEY);
        registry.revoke(0);
        registry.attest(FP4, SIG, KEY);
        vm.stopPrank();
        assertEq(registry.addressesFor(keccak256(FP4)).length, 1);
        assertEq(registry.addressesFor(keccak256(FP6)).length, 0);
    }

    function test_fingerprintsForKeyId_indexes_and_dedups() public {
        bytes8 keyId = bytes8(hex"e34d9266098f7fe7");
        vm.startPrank(alice);
        registry.attest(FP4, SIG, KEY);
        registry.revoke(0);
        registry.attest(FP4, SIG, KEY);     // same fingerprint again → no duplicate entry
        registry.attest(FP4B, SIG, KEY);    // different fingerprint, same key id
        vm.stopPrank();

        bytes[] memory fps = registry.fingerprintsForKeyId(keyId);
        assertEq(fps.length, 2);
        assertEq(fps[0], FP4);
        assertEq(fps[1], FP4B);
        assertEq(registry.fingerprintsForKeyId(bytes8(hex"0000000000000000")).length, 0);

        // v6: key id is still the last 8 bytes
        vm.prank(bob);
        registry.attest(FP6, SIG, KEY);
        assertEq(registry.fingerprintsForKeyId(bytes8(hex"0123456789abcdef")).length, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  authorized writes (EIP-712)
    // ═══════════════════════════════════════════════════════════════════════

    function test_attestFor_by_relayer() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _attestHash(alice, FP4, SIG, KEY, 0, deadline));

        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.Attested(alice, keccak256(FP4), 0, FP4, 1, relayer);
        uint256 idx = registry.attestFor(alice, FP4, SIG, KEY, deadline, sig);

        assertEq(idx, 0);
        assertEq(registry.nonces(alice), 1);
        assertEq(registry.attestationCount(alice), 1);
        assertEq(registry.attestationCount(relayer), 0);
        (bytes memory s, bytes memory k) = registry.getPayload(alice, 0);
        assertEq(s, SIG);
        assertEq(k, KEY);
    }

    function test_attestFor_revert_wrong_signer() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(BOB_PK, _attestHash(alice, FP4, SIG, KEY, 0, deadline));
        vm.prank(relayer);
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, sig);
    }

    function test_attestFor_revert_replayed_nonce() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _attestHash(alice, FP4, SIG, KEY, 0, deadline));
        vm.prank(relayer);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, sig);

        vm.prank(alice);
        registry.revoke(0); // so a replay would otherwise be accepted as a fresh attest

        vm.prank(relayer);
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, sig);
    }

    function test_attestFor_revert_expired() public {
        uint256 deadline = block.timestamp + 10;
        bytes memory sig = _sign(ALICE_PK, _attestHash(alice, FP4, SIG, KEY, 0, deadline));
        vm.warp(deadline + 1);
        vm.prank(relayer);
        vm.expectRevert(PGPRegistry.AuthorizationExpired.selector);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, sig);
    }

    function test_attestFor_revert_tampered_payload() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _attestHash(alice, FP4, SIG, KEY, 0, deadline));
        vm.startPrank(relayer);
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP4, SIG, KEY2, deadline, sig);      // different key
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP6, SIG, KEY, deadline, sig);       // different fingerprint
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP4, SIG, KEY, deadline + 1, sig);   // different deadline
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(bob, FP4, SIG, KEY, deadline, sig);         // different owner
        vm.stopPrank();
    }

    function test_attestFor_revert_cross_chain_replay() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _attestHash(alice, FP4, SIG, KEY, 0, deadline)); // signed for chain 31337
        vm.chainId(1);
        vm.prank(relayer);
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, sig);
    }

    function test_attestFor_revert_malformed_signature() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 h = _attestHash(alice, FP4, SIG, KEY, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, _digest(h));

        vm.startPrank(relayer);
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, abi.encodePacked(r, s));            // 64 bytes
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, abi.encodePacked(r, s, uint8(29))); // bad v
        // high-s form of the same signature
        bytes32 highS = bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, abi.encodePacked(r, highS, flippedV));
        vm.stopPrank();
    }

    function test_reattestFor() public {
        _attestAlice();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _reattestHash(alice, 0, FP6, SIG, KEY, 0, deadline));
        vm.prank(relayer);
        uint256 idx = registry.reattestFor(alice, 0, FP6, SIG, KEY, deadline, sig);
        assertEq(idx, 1);
        assertTrue(registry.getAttestation(alice, 0).revokedAt != 0);
        assertEq(registry.getAttestation(alice, 1).fingerprint, FP6);
        assertEq(registry.nonces(alice), 1);
    }

    function test_updateKeyFor() public {
        _attestAlice();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _updateKeyHash(alice, 0, KEY2, 0, deadline));
        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.KeyUpdated(alice, keccak256(FP4), 0, relayer);
        registry.updateKeyFor(alice, 0, KEY2, deadline, sig);
        (, bytes memory key) = registry.getPayload(alice, 0);
        assertEq(key, KEY2);
    }

    function test_revokeFor() public {
        _attestAlice();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _revokeHash(alice, 0, 0, deadline));
        vm.prank(relayer);
        vm.expectEmit(true, true, true, true);
        emit PGPRegistry.Revoked(alice, keccak256(FP4), 0, relayer);
        registry.revokeFor(alice, 0, deadline, sig);
        assertTrue(registry.getAttestation(alice, 0).revokedAt != 0);
    }

    function test_setRecordFor() public {
        _attestAlice();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _setRecordHash(alice, 0, KIND, "hello", 0, deadline));
        vm.prank(relayer);
        registry.setRecordFor(alice, 0, KIND, "hello", deadline, sig);
        assertEq(registry.record(alice, 0, KIND), "hello");
    }

    function test_nonce_is_sequential_across_actions() public {
        uint256 deadline = block.timestamp + 1 hours;
        vm.startPrank(relayer);
        registry.attestFor(alice, FP4, SIG, KEY, deadline, _sign(ALICE_PK, _attestHash(alice, FP4, SIG, KEY, 0, deadline)));
        registry.updateKeyFor(alice, 0, KEY2, deadline, _sign(ALICE_PK, _updateKeyHash(alice, 0, KEY2, 1, deadline)));
        registry.revokeFor(alice, 0, deadline, _sign(ALICE_PK, _revokeHash(alice, 0, 2, deadline)));
        vm.stopPrank();
        assertEq(registry.nonces(alice), 3);

        // a direct call does not consume a nonce
        vm.prank(alice);
        registry.attest(FP4, SIG, KEY);
        assertEq(registry.nonces(alice), 3);
    }

    function test_attestFor_erc1271_wallet() public {
        MockWallet wallet = new MockWallet(alice);
        address owner = address(wallet);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _attestHash(owner, FP4, SIG, KEY, 0, deadline));

        vm.prank(relayer);
        registry.attestFor(owner, FP4, SIG, KEY, deadline, sig);
        assertEq(registry.attestationCount(owner), 1);
        assertEq(registry.nonces(owner), 1);

        // wrong EOA behind the wallet
        bytes memory bad = _sign(BOB_PK, _attestHash(owner, FP6, SIG, KEY, 1, deadline));
        vm.prank(relayer);
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(owner, FP6, SIG, KEY, deadline, bad);
    }

    function test_attestFor_erc1271_rejecting_wallet() public {
        address owner = address(new RejectingWallet());
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _attestHash(owner, FP4, SIG, KEY, 0, deadline));
        vm.prank(relayer);
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(owner, FP4, SIG, KEY, deadline, sig);
    }

    function test_attestFor_contract_without_1271_reverts() public {
        address owner = address(registry); // has code, no isValidSignature
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(ALICE_PK, _attestHash(owner, FP4, SIG, KEY, 0, deadline));
        vm.prank(relayer);
        vm.expectRevert(PGPRegistry.InvalidAuthorization.selector);
        registry.attestFor(owner, FP4, SIG, KEY, deadline, sig);
    }

    function test_version_constant() public view {
        assertEq(registry.VERSION(), 2);
    }

    function test_domain_separator_binds_chain_and_address() public {
        bytes32 expected = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Thurin PGPRegistry"), keccak256("2"), block.chainid, address(registry)
        ));
        assertEq(registry.DOMAIN_SEPARATOR(), expected);
        vm.chainId(11155111);
        assertTrue(registry.DOMAIN_SEPARATOR() != expected);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  fuzz
    // ═══════════════════════════════════════════════════════════════════════

    function testFuzz_payload_roundtrip(bytes calldata sig, bytes calldata key) public {
        vm.assume(sig.length > 0 && sig.length <= 4096);
        vm.assume(key.length > 0 && key.length <= 8192);
        vm.prank(alice);
        registry.attest(FP4, sig, key);
        (bytes memory s, bytes memory k) = registry.getPayload(alice, 0);
        assertEq(s, sig);
        assertEq(k, key);
    }

    function testFuzz_fingerprint_roundtrip(bytes32 raw, bool v6) public {
        bytes memory fp = v6 ? abi.encodePacked(raw) : abi.encodePacked(bytes20(raw));
        vm.prank(alice);
        registry.attest(fp, SIG, KEY);
        assertEq(registry.getAttestation(alice, 0).fingerprint, fp);
        assertEq(registry.addressesFor(keccak256(fp))[0], alice);
        bytes8 keyId = v6 ? bytes8(raw << 192) : bytes8(raw << 96);
        assertEq(registry.fingerprintsForKeyId(keyId)[0], fp);
    }

    /// At most one active attestation per (owner, fingerprint) across a random op sequence.
    function testFuzz_one_active_per_fingerprint(uint8[16] calldata ops) public {
        bytes[2] memory fps = [FP4, FP6];
        vm.startPrank(alice);
        for (uint256 i = 0; i < ops.length; i++) {
            uint256 op = ops[i] % 4;
            bytes memory fp = fps[(ops[i] / 4) % 2];
            uint256 n = registry.attestationCount(alice);
            if (op == 0) {
                try registry.attest(fp, SIG, KEY) {} catch {}
            } else if (op == 1 && n > 0) {
                try registry.revoke(ops[i] % n) {} catch {}
            } else if (op == 2 && n > 0) {
                try registry.reattest(ops[i] % n, fp, SIG, KEY) {} catch {}
            } else if (op == 3 && n > 0) {
                try registry.updateKey(ops[i] % n, KEY2) {} catch {}
            }
        }
        vm.stopPrank();

        PGPRegistry.Attestation[] memory all = registry.attestationsOf(alice);
        uint256 active4; uint256 active6;
        for (uint256 i = 0; i < all.length; i++) {
            if (all[i].revokedAt != 0) continue;
            if (keccak256(all[i].fingerprint) == keccak256(FP4)) active4++; else active6++;
        }
        assertLe(active4, 1);
        assertLe(active6, 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  SSTORE2
    // ═══════════════════════════════════════════════════════════════════════

    function test_sstore2_roundtrip() public {
        SSTORE2Harness h = new SSTORE2Harness();
        bytes memory data = hex"ef0000ff"; // starts with 0xEF: only legal because of the STOP prefix
        address p = h.write(data);
        assertEq(h.read(p), data);
        assertEq(p.code.length, data.length + 1);
        assertEq(uint8(p.code[0]), 0);

        bytes memory big = _filled(8192);
        assertEq(h.read(h.write(big)), big);
        assertEq(h.read(h.write("")), "");
    }

    function test_sstore2_pointer_is_inert() public {
        SSTORE2Harness h = new SSTORE2Harness();
        address p = h.write(hex"60006000fd"); // PUSH1 0 PUSH1 0 REVERT — would revert if executed
        (bool ok, bytes memory ret) = p.call("");
        assertTrue(ok);              // STOP prefix: call succeeds, does nothing
        assertEq(ret.length, 0);
    }
}

/// Realistic gas with the repo's fixture key (a full key with an email user ID; stripped keys are smaller).
contract PGPRegistryGasTest is Test {
    PGPRegistry registry;
    address alice = address(0xA11CE);
    bytes constant FP = hex"6e0053911942a889426c1866e34d9266098f7fe7";

    function setUp() public { registry = new PGPRegistry(); }

    function test_gas_attest_fixture_key() public {
        bytes memory key = bytes(vm.readFile("script/pgp-key.txt"));
        bytes memory sig = bytes(vm.readFile("script/pgp-sig.txt"));
        vm.startPrank(alice);
        uint256 g0 = gasleft();
        registry.attest(FP, sig, key);
        uint256 attestGas = g0 - gasleft();
        g0 = gasleft();
        registry.updateKey(0, key);
        uint256 updateGas = g0 - gasleft();
        g0 = gasleft();
        registry.reattest(0, FP, sig, key);
        uint256 reattestGas = g0 - gasleft();
        g0 = gasleft();
        registry.revoke(1);
        uint256 revokeGas = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("key bytes", key.length);
        emit log_named_uint("attest gas", attestGas);
        emit log_named_uint("updateKey gas", updateGas);
        emit log_named_uint("reattest gas", reattestGas);
        emit log_named_uint("revoke gas", revokeGas);
        (bytes memory s, bytes memory k) = registry.getPayload(alice, 1);
        assertEq(s, sig);
        assertEq(k, key);
    }
}

/// Prints an EIP-712 vector for identity-kit's tests: fixed inputs, fixed chain id, fixed address.
contract PGPRegistryVectorTest is Test {
    function test_eip712_vector() public {
        vm.chainId(31337);
        PGPRegistry registry = new PGPRegistry();
        address owner = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        bytes memory fp = hex"6e0053911942a889426c1866e34d9266098f7fe7";
        bytes memory sig = "sig-bytes";
        bytes memory key = "key-bytes";
        uint256 nonce = 3;
        uint256 deadline = 1_800_000_000;
        bytes32 structHash = keccak256(abi.encode(
            registry.ATTEST_TYPEHASH(), owner, keccak256(fp), keccak256(sig), keccak256(key), nonce, deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), structHash));
        emit log_named_address("registry", address(registry));
        emit log_named_bytes32("domainSeparator", registry.DOMAIN_SEPARATOR());
        emit log_named_bytes32("attestStructHash", structHash);
        emit log_named_bytes32("attestDigest", digest);
        bytes32 revokeHash = keccak256(abi.encode(registry.REVOKE_TYPEHASH(), owner, uint256(1), nonce, deadline));
        emit log_named_bytes32("revokeDigest", keccak256(abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), revokeHash)));
    }
}
