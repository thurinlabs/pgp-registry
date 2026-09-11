// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {PGPRegistryV1 as PGPRegistry} from "./PGPRegistryV1.sol";

contract PGPRegistryV1Test is Test {
    PGPRegistry registry;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    string constant FP1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    string constant FP2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    string constant FP1_LOWER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    string constant FP2_LOWER = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    string constant FP_LOWER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    string constant FP_MIXED = "AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa";
    string constant FP_HEX = "0123456789ABCDEFabcdef0123456789ABCDEFab";
    string constant FP_HEX_LOWER = "0123456789abcdefabcdef0123456789abcdefab";
    string constant FP_INVALID_HEX = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
    string constant FP_INVALID_PUNCT = "AAAA!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    string constant SIG = "-----BEGIN PGP SIGNED MESSAGE-----\ntest\n-----END PGP SIGNATURE-----";
    string constant KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----";

    function setUp() public {
        registry = new PGPRegistry();
    }

    // ─── attest: happy path ─────────────────────────────────────────────────

    function test_attest_stores_correctly() public {
        vm.prank(alice);
        registry.attest(FP1, SIG, KEY);

        assertEq(registry.attestationCount(alice), 1);

        (string memory fp, uint256 createdAt, bool revoked) = registry.getAttestation(alice, 0);
        assertEq(fp, FP1_LOWER); // stored as normalized lowercase
        assertGt(createdAt, 0);
        assertFalse(revoked);
    }

    function test_attest_emits_event_with_normalized_fingerprint() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        // indexed fingerprintHash is normalized lowercase; non-indexed fingerprint is original case
        emit PGPRegistry.Attested(alice, FP_LOWER, FP1, SIG, KEY, 0, block.timestamp);
        registry.attest(FP1, SIG, KEY);
    }

    function test_attest_multiple_addresses_same_fingerprint() public {
        vm.prank(alice);
        registry.attest(FP1, SIG, KEY);

        // Bob can also claim the same fingerprint (many-to-many)
        vm.prank(bob);
        registry.attest(FP1, SIG, KEY);

        assertEq(registry.attestationCount(alice), 1);
        assertEq(registry.attestationCount(bob), 1);
    }

    // ─── attest: validation ─────────────────────────────────────────────────

    function test_attest_revert_fingerprint_too_short() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.InvalidFingerprintLength.selector);
        registry.attest("AAAAAA", SIG, KEY);
    }

    function test_attest_revert_fingerprint_too_long() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.InvalidFingerprintLength.selector);
        registry.attest("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SIG, KEY); // 41 chars
    }

    function test_attest_revert_empty_signature() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.EmptySignature.selector);
        registry.attest(FP1, "", KEY);
    }

    function test_attest_revert_empty_public_key() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.EmptyPublicKey.selector);
        registry.attest(FP1, SIG, "");
    }

    // ─── attest: hex validation (M-02) ──────────────────────────────────────

    function test_attest_accepts_valid_hex() public {
        vm.prank(alice);
        registry.attest(FP_HEX, SIG, KEY); // mixed 0-9, A-F, a-f
        assertEq(registry.attestationCount(alice), 1);
    }

    function test_attest_revert_non_hex_letters() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.InvalidFingerprintHex.selector);
        registry.attest(FP_INVALID_HEX, SIG, KEY); // "ZZZ..."
    }

    function test_attest_revert_punctuation() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.InvalidFingerprintHex.selector);
        registry.attest(FP_INVALID_PUNCT, SIG, KEY); // contains "!"
    }

    // ─── attest: payload size limits (L-03) ─────────────────────────────────

    function test_attest_revert_signature_too_large() public {
        bytes memory bigSig = new bytes(16385);
        for (uint256 i = 0; i < bigSig.length; i++) {
            bigSig[i] = "X";
        }

        vm.prank(alice);
        vm.expectRevert(PGPRegistry.SignatureTooLarge.selector);
        registry.attest(FP1, string(bigSig), KEY);
    }

    function test_attest_revert_public_key_too_large() public {
        bytes memory bigKey = new bytes(16385);
        for (uint256 i = 0; i < bigKey.length; i++) {
            bigKey[i] = "X";
        }

        vm.prank(alice);
        vm.expectRevert(PGPRegistry.PublicKeyTooLarge.selector);
        registry.attest(FP1, SIG, string(bigKey));
    }

    function test_attest_accepts_max_payload() public {
        bytes memory maxSig = new bytes(16384);
        for (uint256 i = 0; i < maxSig.length; i++) {
            maxSig[i] = "X";
        }

        vm.prank(alice);
        registry.attest(FP1, string(maxSig), KEY);
        assertEq(registry.attestationCount(alice), 1);
    }

    // ─── attest: cardinality ────────────────────────────────────────────────

    function test_attest_multiple_fingerprints_same_address() public {
        vm.startPrank(alice);
        registry.attest(FP1, SIG, KEY);
        registry.attest(FP2, SIG, KEY);
        vm.stopPrank();

        assertEq(registry.attestationCount(alice), 2);

        (string memory fp0,,) = registry.getAttestation(alice, 0);
        (string memory fp1,,) = registry.getAttestation(alice, 1);
        assertEq(fp0, FP1_LOWER);
        assertEq(fp1, FP2_LOWER);
    }

    function test_attest_revert_duplicate_active_fingerprint() public {
        vm.startPrank(alice);
        registry.attest(FP1, SIG, KEY);

        vm.expectRevert(PGPRegistry.DuplicateActiveFingerprint.selector);
        registry.attest(FP1, SIG, KEY);
        vm.stopPrank();
    }

    function test_attest_allows_reattest_after_revoke() public {
        vm.startPrank(alice);
        registry.attest(FP1, SIG, KEY);
        registry.revoke(0);
        registry.attest(FP1, SIG, KEY); // should succeed — previous was revoked
        vm.stopPrank();

        assertEq(registry.attestationCount(alice), 2);
    }

    // ─── attest: case insensitivity ─────────────────────────────────────────

    function test_attest_case_insensitive_duplicate_same_address() public {
        vm.startPrank(alice);
        registry.attest(FP1, SIG, KEY); // "AAA..."

        vm.expectRevert(PGPRegistry.DuplicateActiveFingerprint.selector);
        registry.attest(FP_LOWER, SIG, KEY); // "aaa..." — same key, different case
        vm.stopPrank();
    }

    function test_attest_mixed_case_different_addresses() public {
        vm.prank(alice);
        registry.attest(FP1, SIG, KEY); // "AAA..."

        // Bob can claim the same fingerprint in different case (many-to-many)
        vm.prank(bob);
        registry.attest(FP_LOWER, SIG, KEY); // "aaa..." — same key, different case

        assertEq(registry.attestationCount(bob), 1);
    }

    // ─── revoke: happy path ─────────────────────────────────────────────────

    function test_revoke_marks_revoked() public {
        vm.startPrank(alice);
        registry.attest(FP1, SIG, KEY);
        registry.revoke(0);
        vm.stopPrank();

        (,, bool revoked) = registry.getAttestation(alice, 0);
        assertTrue(revoked);
    }

    function test_revoke_allows_reattest_same_address() public {
        vm.startPrank(alice);
        registry.attest(FP1, SIG, KEY);
        registry.revoke(0);
        registry.attest(FP1, SIG, KEY); // re-attest after revoke
        vm.stopPrank();

        assertEq(registry.attestationCount(alice), 2);
        (,, bool revoked0) = registry.getAttestation(alice, 0);
        (,, bool revoked1) = registry.getAttestation(alice, 1);
        assertTrue(revoked0);
        assertFalse(revoked1);
    }

    function test_revoke_emits_event() public {
        vm.prank(alice);
        registry.attest(FP1, SIG, KEY);

        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit PGPRegistry.Revoked(alice, FP1_LOWER, 0, block.timestamp); // stored as lowercase
        registry.revoke(0);
    }

    // ─── revoke: validation ─────────────────────────────────────────────────

    function test_revoke_revert_out_of_bounds() public {
        vm.prank(alice);
        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.revoke(0);
    }

    function test_revoke_revert_already_revoked() public {
        vm.startPrank(alice);
        registry.attest(FP1, SIG, KEY);
        registry.revoke(0);

        vm.expectRevert(PGPRegistry.AlreadyRevoked.selector);
        registry.revoke(0);
        vm.stopPrank();
    }

    // ─── revoke: fingerprint reuse ──────────────────────────────────────────

    function test_revoke_does_not_affect_other_addresses() public {
        // Alice and Bob both claim the same fingerprint
        vm.prank(alice);
        registry.attest(FP1, SIG, KEY);
        vm.prank(bob);
        registry.attest(FP1, SIG, KEY);

        // Alice revokes — Bob's attestation is unaffected
        vm.prank(alice);
        registry.revoke(0);

        (,, bool aliceRevoked) = registry.getAttestation(alice, 0);
        (,, bool bobRevoked) = registry.getAttestation(bob, 0);
        assertTrue(aliceRevoked);
        assertFalse(bobRevoked);
    }

    // ─── views ──────────────────────────────────────────────────────────────

    function test_attestationCount_includes_revoked() public {
        vm.startPrank(alice);
        registry.attest(FP1, SIG, KEY);
        registry.attest(FP2, SIG, KEY);
        registry.revoke(0);
        vm.stopPrank();

        assertEq(registry.attestationCount(alice), 2);
    }

    function test_attestationCount_zero_for_unknown() public view {
        assertEq(registry.attestationCount(alice), 0);
    }

    function test_getAttestation_revert_out_of_bounds() public {
        vm.prank(alice);
        registry.attest(FP1, SIG, KEY);

        vm.expectRevert(PGPRegistry.IndexOutOfBounds.selector);
        registry.getAttestation(alice, 1);
    }

    function test_getAttestation_returns_correct_fingerprint() public {
        vm.prank(alice);
        registry.attest(FP_HEX, SIG, KEY);

        (string memory fp,,) = registry.getAttestation(alice, 0);
        assertEq(fp, FP_HEX_LOWER); // stored as normalized lowercase
    }
}
