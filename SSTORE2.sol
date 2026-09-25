// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SSTORE2
 * @notice Bytes stored as the runtime code of a throwaway contract, read back with EXTCODECOPY:
 *         about 200 gas per byte to write (SSTORE: ~625), readable from any `eth_call`. A leading
 *         STOP byte keeps the data from ever running. Pattern from 0xSequence / solmate.
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

    /// @notice Like `write`, at a CREATE2 address derived from the data: the same bytes again return
    ///         the existing pointer and cost nothing. Only this contract deploys there, so the code is the data.
    function writeOnce(bytes memory data) internal returns (address pointer) {
        bytes memory creationCode = abi.encodePacked(CREATION_PREFIX, hex"00", data);
        bytes32 salt = keccak256(data);
        pointer = address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(creationCode))
        ))));
        if (pointer.code.length > 0) return pointer;
        address deployed;
        assembly ("memory-safe") {
            deployed := create2(0, add(creationCode, 0x20), mload(creationCode), salt)
        }
        if (deployed != pointer) revert DeploymentFailed();
    }

    /// @notice `size` bytes of the stored data starting at `start`.
    function readRange(address pointer, uint256 start, uint256 size) internal view returns (bytes memory data) {
        data = new bytes(size);
        assembly ("memory-safe") {
            extcodecopy(pointer, add(data, 0x20), add(start, DATA_OFFSET), size)
        }
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
