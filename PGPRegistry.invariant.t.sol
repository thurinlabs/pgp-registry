// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Test} from "forge-std/Test.sol";
import {PGPRegistry} from "./PGPRegistry.sol";

/// @dev Drives random writes by a few owners over a few keys, tracking what the registry should hold.
contract Handler is Test {
    PGPRegistry public reg;
    address[3] public owners = [address(0xA1), address(0xA2), address(0xA3)];
    bytes[3] internal fps;
    bytes[3] internal keys;
    bytes internal constant SIG = hex"c20b0401160a00000000000000";

    mapping(address => uint256) public lastCount;
    mapping(address => uint256) public lastNonce;
    mapping(address => mapping(uint256 => bytes32)) public expectedKeyHash; // what keyBytes must return
    bool public countWentDown;
    bool public nonceWentDown;

    constructor(PGPRegistry r) {
        reg = r;
        fps[0] = hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fps[1] = hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        fps[2] = hex"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        keys[0] = hex"c6010203";
        keys[1] = hex"c6040506";
        keys[2] = hex"990708";
    }

    function _owner(uint256 s) internal view returns (address) { return owners[s % 3]; }

    function _after(address o) internal {
        uint256 c = reg.claimCount(o);
        if (c < lastCount[o]) countWentDown = true;
        lastCount[o] = c;
        uint256 n = reg.nonces(o);
        if (n < lastNonce[o]) nonceWentDown = true;
        lastNonce[o] = n;
    }

    function attest(uint256 o, uint256 f, uint256 k) external {
        address owner = _owner(o);
        vm.prank(owner);
        try reg.attest(fps[f % 3], SIG, keys[k % 3]) returns (uint256 idx) {
            expectedKeyHash[owner][idx] = keccak256(keys[k % 3]);
        } catch {}
        _after(owner);
    }

    function reattest(uint256 o, uint256 i, uint256 f, uint256 k, bool keep) external {
        address owner = _owner(o);
        uint256 c = reg.claimCount(owner);
        if (c == 0) return;
        vm.prank(owner);
        try reg.reattest(i % c, fps[f % 3], SIG, keys[k % 3], keep) returns (uint256 idx) {
            expectedKeyHash[owner][idx] = keccak256(keys[k % 3]);
        } catch {}
        _after(owner);
    }

    function updateKey(uint256 o, uint256 i, uint256 k) external {
        address owner = _owner(o);
        uint256 c = reg.claimCount(owner);
        if (c == 0) return;
        vm.prank(owner);
        try reg.updateKey(i % c, keys[k % 3]) {
            expectedKeyHash[owner][i % c] = keccak256(keys[k % 3]);
        } catch {}
        _after(owner);
    }

    function revoke(uint256 o, uint256 i, uint256 r) external {
        address owner = _owner(o);
        uint256 c = reg.claimCount(owner);
        if (c == 0) return;
        string[3] memory reasons = ["", "compromised", "retired"];
        vm.prank(owner);
        try reg.revoke(i % c, reasons[r % 3]) {} catch {}
        _after(owner);
    }

    function setRecord(uint256 o, uint256 i, bool clear) external {
        address owner = _owner(o);
        uint256 c = reg.claimCount(owner);
        if (c == 0) return;
        vm.prank(owner);
        try reg.setRecord(i % c, "security", clear ? "" : "mailto:x@example.com") {} catch {}
        _after(owner);
    }

    function cancel(uint256 o) external {
        address owner = _owner(o);
        vm.prank(owner);
        reg.cancelAuthorization();
        _after(owner);
    }

    /// A stranger can never change someone else's claims.
    function strangerRevokes(uint256 o, uint256 i) external {
        address owner = _owner(o);
        uint256 before = reg.claimCount(owner);
        vm.prank(address(0xBAD));
        try reg.revoke(i, "") {} catch {}
        if (reg.claimCount(owner) != before) countWentDown = true;
    }
}

contract PGPRegistryInvariantTest is Test {
    PGPRegistry reg;
    Handler handler;

    function setUp() public {
        vm.warp(1_790_000_000);
        reg = new PGPRegistry();
        handler = new Handler(reg);
        targetContract(address(handler));
    }

    /// Histories only grow; nonces only increase.
    function invariant_historyAndNoncesOnlyGrow() public view {
        assertFalse(handler.countWentDown());
        assertFalse(handler.nonceWentDown());
    }

    /// At most one active claim per (owner, fingerprint); states and replacement links are consistent.
    function invariant_claimsConsistent() public view {
        for (uint256 o; o < 3; ++o) {
            address owner = handler.owners(o);
            PGPRegistry.ClaimView[] memory v = reg.claimsOf(owner);
            (uint256 total, uint256 active, bool has, uint256 cur) = reg.summary(owner);
            assertEq(total, v.length);
            uint256 activeSeen;
            for (uint256 i; i < v.length; ++i) {
                bool isActive = keccak256(bytes(v[i].state)) == keccak256("active");
                assertEq(isActive, v[i].revokedAt == 0);
                if (isActive) {
                    activeSeen++;
                    for (uint256 j = i + 1; j < v.length; ++j) {
                        if (v[j].revokedAt == 0) assertTrue(keccak256(v[j].fingerprint) != keccak256(v[i].fingerprint));
                    }
                }
                if (keccak256(bytes(v[i].state)) == keccak256("replaced")) {
                    assertGt(v[i].replacedBy, i);
                    assertLt(v[i].replacedBy, v.length);
                    assertEq(v[i].revokeReason, "superseded");
                }
            }
            assertEq(active, activeSeen);
            if (has) assertEq(v[cur].revokedAt, 0);
        }
    }

    /// Stored keys are exactly what was last written for that claim (payload reuse never changes bytes).
    function invariant_storedKeysMatch() public view {
        for (uint256 o; o < 3; ++o) {
            address owner = handler.owners(o);
            uint256 c = reg.claimCount(owner);
            for (uint256 i; i < c; ++i) {
                assertEq(keccak256(reg.keyBytes(owner, i)), handler.expectedKeyHash(owner, i));
            }
        }
    }
}
