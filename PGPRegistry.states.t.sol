// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test, Vm} from "forge-std/Test.sol";
import {PGPRegistry} from "./PGPRegistry.sol";

/// @dev Claim states after revoking: "compromised" is final, marking it later, records moving on reattest.
contract PGPRegistryStatesTest is Test {
    PGPRegistry reg;
    address constant OWNER = 0x1111111111111111111111111111111111111111;
    bytes constant K = hex"c60b0400000000160900000000";
    bytes constant S = hex"c20b0401160a00000000000000";
    bytes constant FP_A = hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bytes constant FP_B = hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    uint256 constant ALICE_PK = 0xA11CE;
    address alice;

    event RecordsMoved(address indexed owner, uint256 indexed fromIndex, uint256 indexed toIndex);

    function setUp() public {
        vm.warp(1_790_000_000);
        reg = new PGPRegistry();
        alice = vm.addr(ALICE_PK);
    }

    /// "compromised" is final for that owner and key: no attest, reattest, or permission can bring it back.
    function test_compromisedKeyCannotBeClaimedAgain() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        assertEq(reg.keyStatus(alice, FP_A), "active");
        reg.revoke(0, "compromised");
        assertEq(reg.keyStatus(alice, FP_A), "compromised");
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.KeyCompromised.selector, FP_A));
        reg.attest(FP_A, S, K);
        reg.attest(FP_B, S, K);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.KeyCompromised.selector, FP_A));
        reg.reattest(1, FP_A, S, K, true);
        vm.stopPrank();

        uint256 deadline = block.timestamp + 1;
        bytes32 sh = keccak256(abi.encode(reg.ATTEST_TYPEHASH(), alice, keccak256(FP_A), keccak256(S), keccak256(K), reg.nonces(alice), deadline));
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(ALICE_PK, keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), sh)));
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.KeyCompromised.selector, FP_A));
        reg.attestFor(alice, FP_A, S, K, deadline, abi.encodePacked(r, s_, v));

        // Only this owner is bound: anyone else's claim on the key is unaffected.
        vm.prank(OWNER);
        reg.attest(FP_A, S, K);
        assertEq(reg.keyStatus(OWNER, FP_A), "active");
        assertEq(reg.keyStatus(address(0xBEEF), FP_A), "none");
    }

    /// Any other reason leaves the key claimable again.
    function test_retiredKeyCanBeClaimedAgain() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.revoke(0, "retired");
        assertEq(reg.keyStatus(alice, FP_A), "revoked");
        reg.attest(FP_A, S, K);
        reg.reattest(1, FP_A, S, K, true);   // superseded: also claimable
        vm.stopPrank();
        assertEq(reg.keyStatus(alice, FP_A), "active");
    }

    /// "superseded" means replaced by a newer claim; only reattest can say it.
    function test_revokeRefusesSuperseded() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        vm.expectRevert(PGPRegistry.SupersededIsSetByReattest.selector);
        reg.revoke(0, "superseded");
        vm.stopPrank();
    }

    /// Found out later: a retired claim can be marked compromised once; its date stays, the key locks.
    function test_markCompromisedLater() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.revoke(0, "retired");
        uint64 revokedAt = reg.claimsOf(alice)[0].revokedAt;
        vm.warp(block.timestamp + 30 days);
        reg.revoke(0, "compromised");
        PGPRegistry.ClaimView memory c = reg.claimsOf(alice)[0];
        assertEq(c.revokeReason, "compromised");
        assertEq(c.revokedAt, revokedAt);
        assertEq(reg.keyStatus(alice, FP_A), "compromised");
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.KeyCompromised.selector, FP_A));
        reg.attest(FP_A, S, K);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.AlreadyRevoked.selector, 0));
        reg.revoke(0, "compromised");
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.AlreadyRevoked.selector, 0));
        reg.revoke(0, "retired");
        vm.stopPrank();
    }

    /// A replaced claim can be marked compromised; it still reads replaced, and says why.
    function test_markReplacedClaimCompromised() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.reattest(0, FP_B, S, K, true);
        reg.revoke(0, "compromised");
        vm.stopPrank();
        PGPRegistry.ClaimView memory c = reg.claimsOf(alice)[0];
        assertEq(c.state, "replaced");
        assertEq(c.replacedBy, 1);
        assertEq(c.revokeReason, "compromised");
        assertEq(reg.keyStatus(alice, FP_A), "compromised");
        assertEq(reg.keyStatus(alice, FP_B), "active");
    }

    /// Not while the same key still has an active claim at this address: mark that one first.
    function test_markCompromisedRefusedWhileKeyActive() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.reattest(0, FP_A, S, K, true);     // same key, new claim #1
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.KeyStillActive.selector, FP_A));
        reg.revoke(0, "compromised");
        reg.revoke(1, "compromised");
        assertEq(reg.keyStatus(alice, FP_A), "compromised");
        reg.revoke(0, "compromised");          // now the older claim can say so too
        vm.stopPrank();
        assertEq(reg.claimsOf(alice)[0].revokeReason, "compromised");
    }

    /// A stolen key replaced in one transaction: records move, the old key is locked.
    function test_replaceCompromisedKeyInOneTransaction() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.setRecord(0, "security", "x");
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(reg.reattest, (0, FP_B, S, K, true));
        calls[1] = abi.encodeCall(reg.revoke, (0, "compromised"));
        reg.multicall(calls);
        vm.stopPrank();
        assertEq(reg.claimsOf(alice)[0].revokeReason, "compromised");
        assertEq(reg.claimsOf(alice)[0].state, "replaced");
        assertEq(reg.recordText(alice, 1, "security"), "x");
        assertEq(reg.keyStatus(alice, FP_A), "compromised");
    }

    function _sign(bytes32 structHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(ALICE_PK, keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), structHash)));
        return abi.encodePacked(r, s_, v);
    }

    /// The late mark through a permission has its own signed message.
    function test_markCompromisedWithPermission() public {
        vm.startPrank(alice);
        reg.attest(FP_A, S, K);
        reg.revoke(0, "");
        vm.stopPrank();
        uint256 deadline = block.timestamp + 1;
        bytes memory p = _sign(keccak256(abi.encode(reg.MARK_COMPROMISED_TYPEHASH(), alice, uint256(0), reg.nonces(alice), deadline)));
        reg.markCompromisedFor(alice, 0, deadline, p);
        assertEq(reg.keyStatus(alice, FP_A), "compromised");
        assertEq(reg.claimsOf(alice)[0].revokeReason, "compromised");
    }

    /// An active claim is revoked through a Revoke permission, not a MarkCompromised one.
    function test_markCompromisedForRefusesActiveClaim() public {
        vm.prank(alice);
        reg.attest(FP_A, S, K);
        uint256 deadline = block.timestamp + 1;
        bytes memory p = _sign(keccak256(abi.encode(reg.MARK_COMPROMISED_TYPEHASH(), alice, uint256(0), reg.nonces(alice), deadline)));
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.ClaimActive.selector, 0));
        reg.markCompromisedFor(alice, 0, deadline, p);
    }

    /// An unused "revoke as compromised" permission can't lock the key later, once its claim is revoked.
    function test_staleRevokePermissionCantMarkLater() public {
        vm.prank(alice);
        reg.attest(FP_A, S, K);
        uint256 deadline = block.timestamp + 365 days;
        bytes memory stale = _sign(keccak256(abi.encode(reg.REVOKE_TYPEHASH(), alice, uint256(0), keccak256("compromised"), reg.nonces(alice), deadline)));
        vm.startPrank(alice);
        reg.reattest(0, FP_A, S, K, true);       // she changes her mind: same key, new claim #1
        reg.revoke(1, "retired");               // later, the key is set aside, still claimable
        vm.stopPrank();
        vm.warp(block.timestamp + 90 days);
        vm.expectRevert(abi.encodeWithSelector(PGPRegistry.AlreadyRevoked.selector, 0));
        reg.revokeFor(alice, 0, "compromised", deadline, stale);
        assertEq(reg.keyStatus(alice, FP_A), "revoked");
        vm.prank(alice);
        reg.attest(FP_A, S, K);                  // still hers to claim
    }
}
