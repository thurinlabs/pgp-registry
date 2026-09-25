// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {PGPRegistry} from "./PGPRegistry.sol";
import {Armor} from "./Armor.sol";

/// @dev EIP-1271 wallet that accepts permissions signed by one EOA.
contract MockWallet {
    address public immutable signer;
    constructor(address s) { signer = s; }
    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        (bytes32 r, bytes32 s, uint8 v) = (bytes32(sig[0:32]), bytes32(sig[32:64]), uint8(sig[64]));
        return ecrecover(hash, v, r, s) == signer ? bytes4(0x1626ba7e) : bytes4(0);
    }
}

/// @dev Exposes the armor library for direct tests.
contract ArmorHarness {
    function armor(string memory label, bytes memory data) external pure returns (string memory) { return Armor.armor(label, data); }
    function decode(string memory s) external pure returns (bytes memory) { return Armor.decode(s); }
    function crc24(bytes memory data) external pure returns (uint256) { return Armor.crc24(data); }
    function base64(bytes memory data) external pure returns (bytes memory) { return Armor.base64(data); }
    /// base64 with the memory just past `data` dirtied, as scratch use can leave it.
    function base64Dirty(bytes memory data) external pure returns (bytes memory) {
        assembly {
            let e := add(add(data, 0x20), mload(data))
            mstore(e, not(0))
            mstore(0x40, add(e, 0x40))
        }
        return Armor.base64(data);
    }
}

contract PGPRegistryTest is Test {
    PGPRegistry reg;
    ArmorHarness armorLib;

    // Real gpg output from a throwaway key (fixtures/): the statement is signed for OWNER.
    address constant OWNER = 0x1111111111111111111111111111111111111111;
    bytes fp;        // 20-byte v4 fingerprint
    bytes key;       // gpg's lean binary export
    bytes sig;       // gpg --detach-sign --textmode over statementFor(OWNER)
    bytes clearsign; // echo <statement> | gpg --clearsign (text)
    bytes fullKey;   // the full key, binary

    // Stand-ins with valid packet tags, for tests that don't need real PGP data.
    bytes constant K = hex"c60b0400000000160900000000";
    bytes constant S = hex"c20b0401160a00000000000000";
    bytes constant FP_A = hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bytes constant FP_B = hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    bytes constant FP_V6 = hex"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    uint256 constant ALICE_PK = 0xA11CE;
    address alice;

    event Attested(address indexed owner, bytes32 indexed fingerprintHash, uint256 indexed index, bytes fingerprint, address payload, uint8 messageVersion, address submitter);
    event Revoked(address indexed owner, bytes32 indexed fingerprintHash, uint256 indexed index, string reason, uint256 replacedBy, address submitter);
    event RecordSet(address indexed owner, uint256 indexed index, bytes32 indexed kindHash, string kind, string value, address submitter);

    function setUp() public {
        vm.warp(1_790_000_000); // Sep 2026
        reg = new PGPRegistry();
        armorLib = new ArmorHarness();
        fp = vm.parseBytes(string.concat("0x", vm.trim(vm.readFile("fixtures/lean-fingerprint.txt"))));
        key = vm.readFileBinary("fixtures/lean-gpg-key.gpg");
        sig = vm.readFileBinary("fixtures/lean-detached.sig");
        clearsign = bytes(vm.readFile("fixtures/lean-echo-clearsign.asc"));
        fullKey = vm.readFileBinary("fixtures/lean-full-key.gpg");
        alice = vm.addr(ALICE_PK);
    }

    // ─── Attest with real gpg data ───────────────────────────────────────────

    function test_attest_realGpgData_storesExactBytes() public {
        vm.prank(OWNER);
        uint256 idx = reg.attest(fp, sig, key);
        assertEq(idx, 0);
        assertEq(reg.keyBytes(OWNER, 0), key);
        assertEq(reg.signatureBytes(OWNER, 0), sig);
        PGPRegistry.ClaimView[] memory list = reg.claimsOf(OWNER);
        assertEq(list.length, 1);
        assertEq(list[0].fingerprint, fp);
        assertEq(list[0].state, "active");
        assertEq(list[0].messageVersion, 1);
        assertEq(list[0].createdAt, 1_790_000_000);
        assertEq(list[0].revokedAt, 0);
    }

    function test_attest_emitsAttested() public {
        vm.expectEmit(true, true, true, false);
        emit Attested(OWNER, keccak256(fp), 0, fp, address(0), 1, OWNER);
        vm.prank(OWNER);
        reg.attest(fp, sig, key);
    }

    function test_statementFor_isLowercase() public view {
        assertEq(reg.statementFor(0xaBCdEf0000000000000000000000000000000001), "I control the Ethereum address: 0xabcdef0000000000000000000000000000000001");
    }

    function test_armoredKey_roundTripsAndLooksLikeGpg() public {
        vm.prank(OWNER);
        reg.attest(fp, sig, key);
        string memory a = reg.armoredKey(OWNER, 0);
        assertTrue(_startsWith(bytes(a), "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"));
        assertTrue(_endsWith(bytes(a), "\n-----END PGP PUBLIC KEY BLOCK-----\n"));
        assertEq(reg.armorToBytes(a), key);
    }

    function test_clearsigned_rebuildsStatementWithHashHeader() public {
        vm.prank(OWNER);
        reg.attest(fp, sig, key);
        string memory c = reg.clearsigned(OWNER, 0);
        string memory expectHead = string.concat(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n", reg.statementFor(OWNER), "\n-----BEGIN PGP SIGNATURE-----\n\n"
        );
        assertTrue(_startsWith(bytes(c), bytes(expectHead)));
        assertEq(reg.armorToBytes(c), sig); // the signature block inside decodes to the stored signature
    }

    function test_clearsignedStatement_isMessageVersion0_andReturnedAsIs() public {
        vm.prank(OWNER);
        reg.attest(fp, clearsign, key);
        assertEq(reg.claimsOf(OWNER)[0].messageVersion, 0);
        assertEq(bytes(reg.clearsigned(OWNER, 0)), clearsign);
    }

    function test_claim_returnsEverythingInOneCall() public {
        vm.startPrank(OWNER);
        reg.attest(fp, sig, key);
        reg.setRecord(0, "security", "mailto:sec@example.com");
        vm.stopPrank();
        (PGPRegistry.ClaimView memory d, string memory k, string memory st, string[] memory kinds) = reg.claim(OWNER, 0);
        assertEq(d.fingerprint, fp);
        assertEq(reg.armorToBytes(k), key);
        assertEq(reg.armorToBytes(st), sig);
        assertEq(kinds.length, 1);
        assertEq(kinds[0], "thurin.security");
    }

    // ─── Format and size checks ──────────────────────────────────────────────

    function test_rejects_swappedFields() public {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.NotAKey.selector, bytes1(sig[0])));
        reg.attest(fp, key, sig);
    }

    function test_rejects_armoredKeyInBytesField() public {
        bytes memory armored = bytes(vm.readFile("fixtures/lean-full-key.asc"));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.NotAKey.selector, bytes1("-")));
        reg.attest(fp, sig, armored);
    }

    function test_rejects_notASignature() public {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.NotASignature.selector, bytes1(0x41)));
        reg.attest(FP_A, hex"414243", K);
    }

    function test_accepts_oldAndNewPacketHeaders() public {
        bytes1[4] memory keyTags = [bytes1(0x98), bytes1(0x99), bytes1(0x9A), bytes1(0xC6)];
        bytes1[4] memory sigTags = [bytes1(0x88), bytes1(0x89), bytes1(0x8A), bytes1(0xC2)];
        for (uint256 i; i < 4; ++i) {
            bytes memory k = bytes.concat(keyTags[i], hex"0000");
            bytes memory s = bytes.concat(sigTags[i], hex"0000");
            vm.prank(address(uint160(0x5000 + i)));
            reg.attest(FP_A, s, k);
        }
    }

    function test_rejects_badFingerprintLength() public {
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.InvalidFingerprintLength.selector, 19));
        reg.attest(hex"00112233445566778899aabbccddeeff001122", S, K);
    }

    function test_rejects_emptyAndOversized() public {
        vm.expectRevert(PGPRegistry.EmptySignature.selector);
        reg.attest(FP_A, "", K);
        vm.expectRevert(PGPRegistry.EmptyKey.selector);
        reg.attest(FP_A, S, "");
        bytes memory bigKey = bytes.concat(hex"c6", new bytes(16_384));
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.KeyTooLarge.selector, 16_385, 16_384));
        reg.attest(FP_A, S, bigKey);
        bytes memory bigSig = bytes.concat(hex"c2", new bytes(8_192));
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.SignatureTooLarge.selector, 8_193, 8_192));
        reg.attest(FP_A, bigSig, K);
        bytes memory k16 = bytes.concat(hex"c6", new bytes(16_000));
        bytes memory s8 = bytes.concat(hex"c2", new bytes(8_000));
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.PayloadTooLarge.selector, 24_002, 24_000));
        reg.attest(FP_A, s8, k16);
    }

    function test_largestPayloadFits() public {
        bytes memory k = bytes.concat(hex"c6", new bytes(15_999));
        bytes memory s = bytes.concat(hex"c2", new bytes(7_999));
        reg.attest(FP_A, s, k); // 24,000 bytes together
        assertEq(reg.keyBytes(address(this), 0).length, 16_000);
    }

    // ─── One active claim per key; revoke; reattest ──────────────────────────

    function test_duplicateActive_reverts_thenAllowedAfterRevoke() public {
        reg.attest(FP_A, S, K);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.DuplicateActiveFingerprint.selector, FP_A));
        reg.attest(FP_A, S, K);
        reg.revoke(0, "retired");
        assertEq(reg.attest(FP_A, S, K), 1);
    }

    function test_revoke_reasons() public {
        reg.attest(FP_A, S, K);
        reg.attest(FP_B, S, K);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.UnknownRevokeReason.selector, "lost"));
        reg.revoke(0, "lost");
        vm.expectEmit(true, true, true, true);
        emit Revoked(address(this), keccak256(FP_A), 0, "compromised", 0, address(this));
        reg.revoke(0, "compromised");
        reg.revoke(1, "");
        PGPRegistry.ClaimView[] memory v = reg.claimsOf(address(this));
        assertEq(v[0].state, "revoked");
        assertEq(v[0].revokeReason, "compromised");
        assertEq(v[0].revokedAt, 1_790_000_000);
        assertEq(v[1].revokeReason, "");
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.AlreadyRevoked.selector, 0));
        reg.revoke(0, "other");
    }

    function test_revoke_outOfBounds() public {
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.IndexOutOfBounds.selector, 3, 0));
        reg.revoke(3, "");
    }

    function test_reattest_marksReplaced_andCarriesRecordsWhenAsked() public {
        reg.attest(FP_A, S, K);
        reg.setRecord(0, "security", "mailto:a@example.com");
        uint256 idx = reg.reattest(0, FP_B, S, K, true);
        assertEq(idx, 1);
        PGPRegistry.ClaimView[] memory v = reg.claimsOf(address(this));
        assertEq(v[0].state, "replaced");
        assertEq(v[0].replacedBy, 1);
        assertEq(v[0].revokeReason, "superseded");
        assertEq(reg.recordText(address(this), 1, "security"), "mailto:a@example.com");

        uint256 idx2 = reg.reattest(1, FP_A, S, K, false);
        assertEq(reg.recordText(address(this), idx2, "security"), "");
    }

    function test_reattest_sameKey_isAllowed() public {
        reg.attest(FP_A, S, K);
        reg.reattest(0, FP_A, S, K, false);
        assertEq(reg.claimCount(address(this)), 2);
    }

    function test_summary_and_current() public {
        reg.attest(FP_A, S, K);
        reg.attest(FP_B, S, K);
        reg.revoke(1, "");
        (uint256 total, uint256 active, bool has, uint256 cur) = reg.summary(address(this));
        assertEq(total, 2);
        assertEq(active, 1);
        assertTrue(has);
        assertEq(cur, 0);
        (bool found, uint256 index, PGPRegistry.ClaimView memory d) = reg.current(address(this));
        assertTrue(found);
        assertEq(index, 0);
        assertEq(d.fingerprint, FP_A);
        (found, , ) = reg.current(address(0xdead));
        assertFalse(found);
    }

    // ─── updateKey ───────────────────────────────────────────────────────────

    function test_updateKey_keepsSignature_changesKey() public {
        vm.prank(OWNER);
        reg.attest(fp, sig, key);
        vm.prank(OWNER);
        reg.updateKey(0, fullKey);
        assertEq(reg.keyBytes(OWNER, 0), fullKey);
        assertEq(reg.signatureBytes(OWNER, 0), sig);
    }

    function test_updateKey_onRevoked_reverts() public {
        reg.attest(FP_A, S, K);
        reg.revoke(0, "");
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.AlreadyRevoked.selector, 0));
        reg.updateKey(0, K);
    }

    // ─── Payload reuse ───────────────────────────────────────────────────────

    function test_identicalPayload_isStoredOnce() public {
        vm.prank(address(0xA1));
        reg.attest(fp, sig, key);
        uint256 g0 = gasleft();
        vm.prank(address(0xA2));
        reg.attest(fp, sig, key);
        uint256 second = g0 - gasleft();
        assertLt(second, 300_000); // no bytes paid for the second time
        vm.recordLogs();
    }

    // ─── Records ─────────────────────────────────────────────────────────────

    function test_records_inlineAndPointer_andCanonicalNames() public {
        reg.attest(FP_A, S, K);
        string memory long = "https://example.com/a/very/long/record/value/that/does/not/fit/in/one/slot";
        vm.expectEmit(true, true, true, true);
        emit RecordSet(address(this), 0, keccak256("thurin.security"), "thurin.security", "short", address(this));
        reg.setRecord(0, "security", "short");
        reg.setRecord(0, "com.example.link", long);
        assertEq(reg.recordText(address(this), 0, "security"), "short");
        assertEq(reg.recordText(address(this), 0, "thurin.security"), "short");
        assertEq(reg.recordText(address(this), 0, "com.example.link"), long);
        (string[] memory kinds, string[] memory values) = reg.recordsOf(address(this), 0);
        assertEq(kinds.length, 2);
        assertEq(kinds[0], "thurin.security");
        assertEq(values[1], long);
    }

    function test_records_clear_thenReset_noDuplicateName() public {
        reg.attest(FP_A, S, K);
        reg.setRecord(0, "canary", "one");
        reg.setRecord(0, "canary", "");
        (string[] memory kinds, ) = reg.recordsOf(address(this), 0);
        assertEq(kinds.length, 0);
        reg.setRecord(0, "canary", "two");
        reg.setRecord(0, "canary", "three");
        (kinds, ) = reg.recordsOf(address(this), 0);
        assertEq(kinds.length, 1);
        assertEq(reg.recordText(address(this), 0, "canary"), "three");
    }

    function test_records_names_rejected() public {
        reg.attest(FP_A, S, K);
        string[5] memory bad = ["Security", "sec urity", "", "a-name-that-is-twenty-five", "x.12345678901234567890123456789012"];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(PGPRegistry.InvalidKindName.selector, bad[i]));
            reg.setRecord(0, bad[i], "v");
        }
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.RecordTooLarge.selector, 1025, 1024));
        reg.setRecord(0, "security", string(new bytes(1025)));
    }

    function test_records_onRevokedClaim_setReverts_clearWorks() public {
        reg.attest(FP_A, S, K);
        reg.setRecord(0, "security", "x");
        reg.revoke(0, "");
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.AlreadyRevoked.selector, 0));
        reg.setRecord(0, "security", "y");
        reg.setRecord(0, "security", "");
        assertEq(reg.recordText(address(this), 0, "security"), "");
    }

    // ─── Lookups ─────────────────────────────────────────────────────────────

    function test_lookups_byFingerprintAndKeyId() public {
        vm.prank(address(0xA1));
        reg.attest(FP_A, S, K);
        vm.prank(address(0xA2));
        reg.attest(FP_A, S, K);
        vm.prank(address(0xA3));
        reg.attest(FP_V6, S, K);
        address[] memory owners = reg.ownersOf(FP_A);
        assertEq(owners.length, 2);
        assertEq(owners[1], address(0xA2));
        assertEq(reg.ownersOfCount(FP_V6), 1);
        bytes[] memory v4 = reg.fingerprintsForKeyId(bytes8(hex"aaaaaaaaaaaaaaaa"));
        assertEq(v4.length, 1);
        assertEq(v4[0], FP_A);
        bytes[] memory v6 = reg.fingerprintsForKeyId(bytes8(hex"cccccccccccccccc"));
        assertEq(v6[0], FP_V6);
        assertEq(reg.ownersOfRange(FP_A, 1, 5).length, 1);
    }

    // ─── Authorized writes ───────────────────────────────────────────────────

    function _permit(bytes32 structHash, uint256 pk) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _attestHash(address owner, bytes memory f, bytes memory s, bytes memory k, uint256 nonce, uint256 deadline)
        internal view returns (bytes32)
    {
        return keccak256(abi.encode(reg.ATTEST_TYPEHASH(), owner, keccak256(f), keccak256(s), keccak256(k), nonce, deadline));
    }

    function test_attestFor_eoa() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory p = _permit(_attestHash(alice, FP_A, S, K, 0, dl), ALICE_PK);
        vm.prank(address(0xBEEF));
        reg.attestFor(alice, FP_A, S, K, dl, p);
        assertEq(reg.claimCount(alice), 1);
        assertEq(reg.nonces(alice), 1);
        vm.expectRevert(PGPRegistry.InvalidPermission.selector); // replay: nonce moved on
        reg.attestFor(alice, FP_B, S, K, dl, p);
    }

    function test_attestFor_expired_wrongSigner_malleable() public {
        uint256 dl = block.timestamp - 1;
        bytes memory p = _permit(_attestHash(alice, FP_A, S, K, 0, dl), ALICE_PK);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.PermissionExpired.selector, dl));
        reg.attestFor(alice, FP_A, S, K, dl, p);

        dl = block.timestamp + 1;
        bytes memory wrong = _permit(_attestHash(alice, FP_A, S, K, 0, dl), 0xB0B);
        vm.expectRevert(PGPRegistry.InvalidPermission.selector);
        reg.attestFor(alice, FP_A, S, K, dl, wrong);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), _attestHash(alice, FP_A, S, K, 0, dl))));
        bytes32 highS = bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));
        vm.expectRevert(PGPRegistry.InvalidPermission.selector);
        reg.attestFor(alice, FP_A, S, K, dl, abi.encodePacked(r, highS, v == 27 ? uint8(28) : uint8(27)));
    }

    function test_attestFor_contractWallet() public {
        MockWallet w = new MockWallet(alice);
        uint256 dl = block.timestamp + 1 hours;
        bytes memory p = _permit(_attestHash(address(w), FP_A, S, K, 0, dl), ALICE_PK);
        reg.attestFor(address(w), FP_A, S, K, dl, p);
        assertEq(reg.claimCount(address(w)), 1);
    }

    function test_otherPermissions() public {
        uint256 dl = block.timestamp + 1 hours;
        reg.attestFor(alice, FP_A, S, K, dl, _permit(_attestHash(alice, FP_A, S, K, 0, dl), ALICE_PK));

        bytes32 h = keccak256(abi.encode(reg.SET_RECORD_TYPEHASH(), alice, 0, keccak256("security"), keccak256("x"), 1, dl));
        reg.setRecordFor(alice, 0, "security", "x", dl, _permit(h, ALICE_PK));
        assertEq(reg.recordText(alice, 0, "security"), "x");

        h = keccak256(abi.encode(reg.UPDATE_KEY_TYPEHASH(), alice, 0, keccak256(K), 2, dl));
        reg.updateKeyFor(alice, 0, K, dl, _permit(h, ALICE_PK));

        h = keccak256(abi.encode(reg.REATTEST_TYPEHASH(), alice, 0, keccak256(FP_B), keccak256(S), keccak256(K), true, 3, dl));
        reg.reattestFor(alice, 0, FP_B, S, K, true, dl, _permit(h, ALICE_PK));
        assertEq(reg.recordText(alice, 1, "security"), "x");

        h = keccak256(abi.encode(reg.REVOKE_TYPEHASH(), alice, 1, keccak256("retired"), 4, dl));
        reg.revokeFor(alice, 1, "retired", dl, _permit(h, ALICE_PK));
        assertEq(reg.claimsOf(alice)[1].revokeReason, "retired");
        assertEq(reg.nonces(alice), 5);
    }

    function test_cancelAuthorization() public {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory p = _permit(_attestHash(alice, FP_A, S, K, 0, dl), ALICE_PK);
        vm.prank(alice);
        reg.cancelAuthorization();
        vm.expectRevert(PGPRegistry.InvalidPermission.selector);
        reg.attestFor(alice, FP_A, S, K, dl, p);
    }

    function test_eip712Domain() public view {
        (bytes1 f, string memory n, string memory v, uint256 c, address a, bytes32 s, uint256[] memory e) = reg.eip712Domain();
        assertEq(f, hex"0f");
        assertEq(n, "Thurin PGPRegistry");
        assertEq(v, "3");
        assertEq(c, block.chainid);
        assertEq(a, address(reg));
        assertEq(s, bytes32(0));
        assertEq(e.length, 0);
    }

    // ─── multicall ───────────────────────────────────────────────────────────

    function test_multicall_attestAndRecord_asSender() public {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(reg.attest, (FP_A, S, K));
        calls[1] = abi.encodeCall(reg.setRecord, (0, "security", "x"));
        vm.prank(alice);
        reg.multicall(calls);
        assertEq(reg.claimCount(alice), 1);
        assertEq(reg.recordText(alice, 0, "security"), "x");
    }

    function test_multicall_bubblesRevert() public {
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeCall(reg.revoke, (0, ""));
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.IndexOutOfBounds.selector, 0, 0));
        reg.multicall(calls);
    }

    // ─── Armor ───────────────────────────────────────────────────────────────

    function test_crc24_knownValues() public view {
        assertEq(armorLib.crc24(""), 0xB704CE);
        assertEq(armorLib.crc24("123456789"), 0x21CF02);
    }

    function test_armorToBytes_readsGpgArmor_andFlattenedPastes() public view {
        bytes memory armored = bytes(vm.readFile("fixtures/lean-full-key.asc"));
        assertEq(reg.armorToBytes(string(armored)), fullKey);
        assertEq(reg.armorToBytes(_flatten(armored)), fullKey);
    }

    function test_armorToBytes_clearsign_usesSignatureBlock() public view {
        bytes memory out = reg.armorToBytes(string(clearsign));
        assertEq(uint8(out[0]) & 0x3C, 0x08); // a signature packet (tag 2)
    }

    function test_armorToBytes_badChecksum_reverts() public {
        string memory a = armorLib.armor("PUBLIC KEY BLOCK", key);
        bytes memory b = bytes(a);
        // flip one base64 character of the data (line 3, well inside the body)
        for (uint256 i = 60; i < b.length; ++i) {
            if (b[i] == "A") { b[i] = "B"; break; }
            if (b[i] != "\n" && b[i] != "A" && b[i] != "=") { b[i] = b[i] == "B" ? bytes1("C") : bytes1("B"); break; }
        }
        vm.expectRevert(Armor.BadArmorChecksum.selector);
        reg.armorToBytes(string(b));
    }

    function test_armorToBytes_notArmored() public {
        vm.expectRevert(Armor.NotArmored.selector);
        reg.armorToBytes("hello");
    }

    function test_base64_vectors() public view {
        assertEq(armorLib.base64(""), "");
        assertEq(armorLib.base64("f"), "Zg==");
        assertEq(armorLib.base64("fo"), "Zm8=");
        assertEq(armorLib.base64("foo"), "Zm9v");
        assertEq(armorLib.base64("foobar"), "Zm9vYmFy");
    }

    // ─── Fuzz ────────────────────────────────────────────────────────────────

    function testFuzz_armor_roundTrip(bytes memory data) public view {
        vm.assume(data.length > 0 && data.length < 3000);
        assertEq(armorLib.decode(armorLib.armor("MESSAGE", data)), data);
    }

    function testFuzz_attest_sizes(uint16 keyLen, uint16 sigLen) public {
        keyLen = uint16(bound(keyLen, 1, 16_384));
        sigLen = uint16(bound(sigLen, 1, 8_192));
        bytes memory k = bytes.concat(hex"c6", new bytes(keyLen - 1));
        bytes memory s = bytes.concat(hex"c2", new bytes(sigLen - 1));
        if (uint256(keyLen) + sigLen > 24_000) {
            vm.expectRevert(abi.encodeWithSelector(PGPRegistry.PayloadTooLarge.selector, uint256(keyLen) + sigLen, 24_000));
            reg.attest(FP_A, s, k);
        } else {
            reg.attest(FP_A, s, k);
            assertEq(reg.keyBytes(address(this), 0), k);
            assertEq(reg.signatureBytes(address(this), 0), s);
        }
    }

    function testFuzz_kindNames(string memory kind) public {
        reg.attest(FP_A, S, K);
        bytes memory k = bytes(kind);
        bool valid = k.length > 0 && k.length <= 31;
        bool dotted;
        for (uint256 i; i < k.length && valid; ++i) {
            bytes1 c = k[i];
            valid = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-" || c == ".";
            if (c == ".") dotted = true;
        }
        if (valid && !dotted && k.length > 24) valid = false;
        if (!valid) vm.expectRevert(abi.encodeWithSelector(PGPRegistry.InvalidKindName.selector, kind));
        reg.setRecord(0, kind, "v");
    }

    // ─── Gas snapshot with real data ─────────────────────────────────────────

    function test_gas_realClaim() public {
        vm.prank(OWNER);
        uint256 g = gasleft();
        reg.attest(fp, sig, key);
        emit log_named_uint("attest (real lean gpg claim) gas", g - gasleft());
        vm.prank(OWNER);
        g = gasleft();
        reg.updateKey(0, fullKey);
        emit log_named_uint("updateKey gas", g - gasleft());
        vm.prank(OWNER);
        g = gasleft();
        reg.setRecord(0, "security", "mailto:s@example.com");
        emit log_named_uint("setRecord (inline) gas", g - gasleft());
        vm.prank(OWNER);
        g = gasleft();
        reg.revoke(0, "retired");
        emit log_named_uint("revoke gas", g - gasleft());
        g = gasleft();
        reg.armoredKey(OWNER, 0);
        emit log_named_uint("armoredKey view gas", g - gasleft());
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    function _startsWith(bytes memory s, bytes memory p) internal pure returns (bool) {
        if (s.length < p.length) return false;
        for (uint256 i; i < p.length; ++i) if (s[i] != p[i]) return false;
        return true;
    }

    function _endsWith(bytes memory s, bytes memory p) internal pure returns (bool) {
        if (s.length < p.length) return false;
        for (uint256 i; i < p.length; ++i) if (s[s.length - p.length + i] != p[i]) return false;
        return true;
    }

    function _flatten(bytes memory s) internal pure returns (string memory) {
        bytes memory out = new bytes(s.length);
        for (uint256 i; i < s.length; ++i) out[i] = s[i] == "\n" ? bytes1(" ") : s[i];
        return string(out);
    }

    // ─── Review regressions ──────────────────────────────────────────────────

    function test_base64_ignoresBytesPastTheEnd() public view {
        assertEq(string(armorLib.base64Dirty(hex"41")), "QQ==");
        assertEq(string(armorLib.base64Dirty(hex"4141")), "QUE=");
        assertEq(string(armorLib.base64Dirty(hex"41414141")), "QUFBQQ==");
        assertEq(string(armorLib.base64Dirty(hex"414141")), "QUFB");
    }

    function testFuzz_base64_dirtyMatchesClean(bytes memory d) public view {
        assertEq(armorLib.base64Dirty(d), armorLib.base64(d));
    }

    /// A v4 claim on a v6 fingerprint's first 20 bytes can't change how the v6 entry reads.
    function test_keyIdLookup_v6NotSpoofedByV4Prefix() public {
        bytes memory v6 = hex"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        bytes memory first20 = hex"0102030405060708090a0b0c0d0e0f1011121314";
        vm.prank(alice);
        reg.attest(v6, S, K);
        vm.prank(address(0xBAD));
        reg.attest(first20, S, K);
        bytes[] memory list = reg.fingerprintsForKeyId(bytes8(hex"0102030405060708"));
        assertEq(list.length, 1);
        assertEq(list[0], v6);
        assertEq(reg.ownersOf(list[0])[0], alice);
    }

    /// Signed text holding an undashed signature block: the real (last) block is decoded.
    function test_decode_usesLastSignatureBlock() public view {
        bytes memory fake = hex"88aabbccddeeff";
        string memory m = string.concat(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhello\n",
            "Z-----BEGIN PGP SIGNATURE-----\n\n", string(armorLib.base64(fake)), "\n-----END PGP SIGNATURE-----\n",
            armorLib.armor("SIGNATURE", S)
        );
        assertEq(armorLib.decode(m), S);
    }

    /// A flattened paste with a header can't be read safely, so it is refused rather than misread.
    function test_decode_flatWithHeaderRefused() public {
        vm.expectRevert(Armor.UnsupportedHeader.selector);
        armorLib.decode("-----BEGIN PGP PUBLIC KEY BLOCK----- Comment: https://keys.example AQID -----END PGP PUBLIC KEY BLOCK-----");
        vm.expectRevert(Armor.UnsupportedHeader.selector);
        armorLib.decode("-----BEGIN PGP PUBLIC KEY BLOCK----- Version: Foo Barz AQID -----END PGP PUBLIC KEY BLOCK-----");
        assertEq(armorLib.decode("-----BEGIN PGP PUBLIC KEY BLOCK----- AQID -----END PGP PUBLIC KEY BLOCK-----"), hex"010203");
    }

    /// EOAs with EIP-7702 code still sign permissions with their own key.
    function test_attestFor_7702AccountSignsWithItsKey() public {
        vm.etch(alice, abi.encodePacked(hex"ef0100", address(0x1234)));
        uint256 deadline = block.timestamp + 1;
        bytes32 sh = keccak256(abi.encode(reg.ATTEST_TYPEHASH(), alice, keccak256(FP_A), keccak256(S), keccak256(K), uint256(0), deadline));
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(ALICE_PK, keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), sh)));
        reg.attestFor(alice, FP_A, S, K, deadline, abi.encodePacked(r, s_, v));
        assertEq(reg.claimCount(alice), 1);
    }

    /// High-s signatures are refused (no malleable duplicates).
    function test_attestFor_highSRefused() public {
        uint256 deadline = block.timestamp + 1;
        bytes32 sh = keccak256(abi.encode(reg.ATTEST_TYPEHASH(), alice, keccak256(FP_A), keccak256(S), keccak256(K), uint256(0), deadline));
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(ALICE_PK, keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), sh)));
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        vm.expectRevert(PGPRegistry.InvalidPermission.selector);
        reg.attestFor(alice, FP_A, S, K, deadline, abi.encodePacked(r, bytes32(n - uint256(s_)), v == 27 ? uint8(28) : uint8(27)));
    }

    /// Reattest keeping records moves them: the replaced claim is left with none of its own.
    function test_reattestKeep_movesRecords() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.setRecord(0, "security", "x");
        reg.reattest(0, FP_B, S, K, true);
        assertEq(reg.recordText(alice, 1, "security"), "x");
        assertEq(reg.recordText(alice, 0, "security"), "");
        reg.setRecord(1, "email", "new");
        vm.stopPrank();
        assertEq(reg.recordText(alice, 0, "email"), "");
        (string[] memory kinds, ) = reg.recordsOf(alice, 0);
        assertEq(kinds.length, 0);
    }

    /// A signature that passes the write check but isn't a readable packet still has working views.
    function test_views_unreadableSignature() public {
        vm.prank(alice);
        reg.attest(FP_A, hex"88", K);
        (, , string memory cs, ) = reg.claim(alice, 0);
        assertTrue(bytes(cs).length > 0);
    }

    /// A chain clock before EPOCH (devnets) doesn't break writes.
    function test_beforeEpoch_writesWork() public {
        vm.warp(1_000);
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.revoke(0, "");
        vm.stopPrank();
        assertEq(reg.claimsOf(alice)[0].state, "revoked");
    }

    /// A key is listed once under its key ID and each owner once, however often it is claimed.
    function test_keyIdAndOwnersListedOnce() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.reattest(0, FP_B, S, K, false);
        reg.reattest(1, FP_A, S, K, false);
        vm.stopPrank();
        vm.prank(OWNER);
        reg.attest(FP_A, S, K);
        assertEq(reg.fingerprintsForKeyIdCount(bytes8(hex"aaaaaaaaaaaaaaaa")), 1);
        assertEq(reg.ownersOfCount(FP_A), 2);
        assertEq(reg.ownersOfCount(FP_B), 1);
    }

    /// Record names stay listed once, in first-use order, through clears and rewrites.
    function test_recordNames_orderAndNoDuplicates() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.setRecord(0, "security", "a");
        reg.setRecord(0, "com.github", "b");
        reg.setRecord(0, "security", "");
        reg.setRecord(0, "canary", "c");
        reg.setRecord(0, "security", "d");
        reg.setRecord(0, "com.github", "e");
        vm.stopPrank();
        (string[] memory k, string[] memory v) = reg.recordsOf(alice, 0);
        assertEq(k.length, 3);
        assertEq(k[0], "thurin.security"); assertEq(v[0], "d");
        assertEq(k[1], "com.github");      assertEq(v[1], "e");
        assertEq(k[2], "thurin.canary");   assertEq(v[2], "c");
    }

    /// Single-line form fields (Etherscan) drop line breaks outright, fusing the checksum onto the data.
    function test_armorToBytes_newlinesStripped() public view {
        bytes memory a = bytes(vm.readFile("fixtures/lean-full-key.asc"));
        bytes memory out = new bytes(a.length);
        uint256 j;
        for (uint256 i; i < a.length; ++i) if (a[i] != "\n" && a[i] != "\r") out[j++] = a[i];
        assembly { mstore(out, j) }
        assertEq(reg.armorToBytes(string(out)), fullKey);
    }

    function testFuzz_decode_newlinesStripped(bytes memory d) public view {
        vm.assume(d.length > 0);
        bytes memory a = bytes(armorLib.armor("PUBLIC KEY BLOCK", d));
        bytes memory out = new bytes(a.length);
        uint256 j;
        for (uint256 i; i < a.length; ++i) if (a[i] != "\n") out[j++] = a[i];
        assembly { mstore(out, j) }
        assertEq(armorLib.decode(string(out)), d);
    }

    function test_attest_v6FingerprintWithZeroTailRefused() public {
        bytes memory fake = hex"0102030405060708090a0b0c0d0e0f1011121314000000000000000000000000";
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.InvalidFingerprint.selector, fake));
        reg.attest(fake, S, K);
    }

    /// Overwrites and clears keep the old values in the events.
    function test_recordSet_eventCarriesEveryValue() public {
        reg.attest(FP_A, S, K);
        string memory long = "https://example.com/a/very/long/record/value/that/does/not/fit/in/one/slot";
        vm.expectEmit(true, true, true, true);
        emit RecordSet(address(this), 0, keccak256("thurin.canary"), "thurin.canary", long, address(this));
        reg.setRecord(0, "canary", long);
        vm.expectEmit(true, true, true, true);
        emit RecordSet(address(this), 0, keccak256("thurin.canary"), "thurin.canary", "", address(this));
        reg.setRecord(0, "canary", "");
    }
}
