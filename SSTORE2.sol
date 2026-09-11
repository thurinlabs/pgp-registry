// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title SSTORE2
 * @notice Store bytes as the runtime code of a throwaway contract and read them back with
 *         EXTCODECOPY. Roughly 200 gas per byte to write (vs ~625 for SSTORE) and readable
 *         from any `eth_call`. The data is prefixed with a STOP byte so it can never execute.
 *
 *         Minimal vendored implementation (pattern from 0xSequence / solmate). No dependencies.
 */
library SSTORE2 {
    error DeploymentFailed();
    error InvalidPointer();

    /// @dev Creation code that returns everything after its own 11 bytes as runtime code.
    ///      PUSH1 0x0B, MSIZE, DUP2, CODESIZE, SUB, DUP1, SWAP3, MSIZE, CODECOPY, RETURN
    bytes internal constant CREATION_PREFIX = hex"600B5981380380925939F3";

    /// @dev Runtime code is `0x00 || data`. 0x00 = STOP.
    uint256 internal constant DATA_OFFSET = 1;

    function write(bytes memory data) internal returns (address pointer) {
        bytes memory creationCode = abi.encodePacked(CREATION_PREFIX, hex"00", data);
        assembly ("memory-safe") {
            pointer := create(0, add(creationCode, 0x20), mload(creationCode))
        }
        if (pointer == address(0)) revert DeploymentFailed();
    }

    function read(address pointer) internal view returns (bytes memory data) {
        uint256 codeSize = pointer.code.length;
        if (codeSize < DATA_OFFSET) revert InvalidPointer();
        uint256 size = codeSize - DATA_OFFSET;
        data = new bytes(size);
        assembly ("memory-safe") {
            extcodecopy(pointer, add(data, 0x20), DATA_OFFSET, size)
        }
    }
}
