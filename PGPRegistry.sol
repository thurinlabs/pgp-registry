// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {SSTORE2} from "./SSTORE2.sol";

/**
 * @title PGPRegistry (v2)
 * @notice Links Ethereum addresses to PGP key fingerprints on-chain, with the signed proof and
 *         the public key stored readably so any RPC can serve them with a plain `eth_call`.
 *
 * Trust model (unchanged from v1):
 *   - Permissionless. No owner, no admin, no pause, no fees, not upgradeable.
 *   - The contract does NOT verify PGP signatures. Off-chain verifiers (identity-kit) check that
 *     the stored clearsigned message binds the exact owner address and was made by the stored key.
 *   - A claim is meaningful only if it verifies; fake claims cannot block the real owner.
 *
 * Cardinality:
 *   - PGP key → address: many-to-many.   - address → PGP key: one-to-many, append-only history.
 *   - At most one ACTIVE attestation per (owner, fingerprint).
 *
 * Writes come through two doors with identical effects and events:
 *   - direct:     the owner calls attest / reattest / updateKey / revoke / setRecord.
 *   - authorized: anyone submits the same action with the owner's EIP-712 signature
 *                 (attestFor / …). Per-owner nonces, deadlines, EIP-1271 for contract wallets.
 *                 The submitter can only submit or not submit; it cannot alter or reuse.
 *
 * Payloads (public key, signature, records) live in SSTORE2 data contracts.
 */
contract PGPRegistry {

    // ─── Constants ────────────────────────────────────────────────────────────

    /// @notice Registry version. v1 (no VERSION getter) is the legacy contract at 0xf7a45BC662A78a6fb417ED5f52b3766cbf13EbBb.
    uint8   public constant VERSION          = 2;
    /// @notice Format of the clearsigned message: "I control the Ethereum address: <lowercase 0x address>"
    uint8   public constant MESSAGE_VERSION  = 1;
    uint256 public constant MAX_KEY_BYTES    = 8192;
    uint256 public constant MAX_SIG_BYTES    = 4096;
    uint256 public constant MAX_RECORD_BYTES = 1024;

    string public constant EIP712_NAME    = "Thurin PGPRegistry";
    string public constant EIP712_VERSION = "2";

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant ATTEST_TYPEHASH =
        keccak256("Attest(address owner,bytes fingerprint,bytes pgpSignature,bytes pgpPublicKey,uint256 nonce,uint256 deadline)");
    bytes32 public constant REATTEST_TYPEHASH =
        keccak256("Reattest(address owner,uint256 revokeIndex,bytes fingerprint,bytes pgpSignature,bytes pgpPublicKey,uint256 nonce,uint256 deadline)");
    bytes32 public constant UPDATE_KEY_TYPEHASH =
        keccak256("UpdateKey(address owner,uint256 index,bytes pgpPublicKey,uint256 nonce,uint256 deadline)");
    bytes32 public constant REVOKE_TYPEHASH =
        keccak256("Revoke(address owner,uint256 index,uint256 nonce,uint256 deadline)");
    bytes32 public constant SET_RECORD_TYPEHASH =
        keccak256("SetRecord(address owner,uint256 index,bytes32 kind,bytes value,uint256 nonce,uint256 deadline)");

    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;

    // ─── Errors ───────────────────────────────────────────────────────────────

    error InvalidFingerprintLength();
    error EmptySignature();
    error EmptyPublicKey();
    error SignatureTooLarge();
    error PublicKeyTooLarge();
    error RecordTooLarge();
    error DuplicateActiveFingerprint();
    error IndexOutOfBounds();
    error AlreadyRevoked();
    error AuthorizationExpired();
    error InvalidAuthorization();

    // ─── Types ────────────────────────────────────────────────────────────────

    struct Attestation {
        bytes   fingerprint;     // 20 bytes (v4 key) or 32 bytes (v6 key), raw
        uint64  createdAt;
        uint64  revokedAt;       // 0 = active
        uint8   messageVersion;
        address keyPtr;          // SSTORE2 pointer: armored PGP public key
        address sigPtr;          // SSTORE2 pointer: PGP clearsigned message
    }

    // ─── Events ───────────────────────────────────────────────────────────────

    event Attested(
        address indexed owner,
        bytes32 indexed fingerprintHash,
        uint256 indexed index,
        bytes   fingerprint,
        uint8   messageVersion,
        address submitter
    );
    event KeyUpdated(address indexed owner, bytes32 indexed fingerprintHash, uint256 indexed index, address submitter);
    event Revoked(address indexed owner, bytes32 indexed fingerprintHash, uint256 indexed index, address submitter);
    event RecordSet(address indexed owner, uint256 indexed index, bytes32 indexed kind, address submitter);

    // ─── Storage ──────────────────────────────────────────────────────────────

    mapping(address => Attestation[]) private _attestations;
    mapping(address => mapping(bytes32 => bool)) private _active;              // owner => fpHash => active
    mapping(bytes32 => address[]) private _addressesFor;                       // fpHash => owners (ever)
    mapping(bytes32 => mapping(address => bool)) private _seenOwner;
    mapping(bytes8 => bytes[]) private _fingerprintsForKeyId;                  // keyId => fingerprints (ever)
    mapping(bytes8 => mapping(bytes32 => bool)) private _seenFingerprint;
    mapping(address => mapping(uint256 => mapping(bytes32 => address))) private _records; // owner => index => kind => ptr

    /// @notice Next EIP-712 nonce for each owner.
    mapping(address => uint256) public nonces;

    // ═══════════════════════════════════════════════════════════════════════════
    //  Direct writes (msg.sender is the owner)
    // ═══════════════════════════════════════════════════════════════════════════

    /**
     * @notice Publish an attestation linking msg.sender to a PGP fingerprint.
     * @param fingerprint   Raw key fingerprint: 20 bytes (v4) or 32 bytes (v6)
     * @param pgpSignature  PGP clearsigned message "I control the Ethereum address: <address>"
     * @param pgpPublicKey  Armored PGP public key (ideally with email user IDs stripped)
     * @return index        Position in the owner's attestation history
     */
    function attest(bytes calldata fingerprint, bytes calldata pgpSignature, bytes calldata pgpPublicKey)
        external returns (uint256 index)
    {
        return _attest(msg.sender, fingerprint, pgpSignature, pgpPublicKey);
    }

    /**
     * @notice Atomically revoke one attestation and publish a new one (same or different key).
     */
    function reattest(uint256 revokeIndex, bytes calldata fingerprint, bytes calldata pgpSignature, bytes calldata pgpPublicKey)
        external returns (uint256 index)
    {
        _revoke(msg.sender, revokeIndex);
        return _attest(msg.sender, fingerprint, pgpSignature, pgpPublicKey);
    }

    /**
     * @notice Replace the stored public key of an active attestation (e.g. new proof
     *         notations on the same key). The fingerprint and signature are unchanged.
     */
    function updateKey(uint256 index, bytes calldata pgpPublicKey) external {
        _updateKey(msg.sender, index, pgpPublicKey);
    }

    /// @notice Revoke an attestation. It stays in the history, marked with `revokedAt`.
    function revoke(uint256 index) external {
        _revoke(msg.sender, index);
    }

    /**
     * @notice Attach a typed record to an active attestation. Empty `value` clears it.
     *         Readers ignore kinds they don't understand.
     */
    function setRecord(uint256 index, bytes32 kind, bytes calldata value) external {
        _setRecord(msg.sender, index, kind, value);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Authorized writes (owner signs EIP-712, anyone submits and pays gas)
    // ═══════════════════════════════════════════════════════════════════════════

    function attestFor(
        address owner,
        bytes calldata fingerprint,
        bytes calldata pgpSignature,
        bytes calldata pgpPublicKey,
        uint256 deadline,
        bytes calldata signature
    ) external returns (uint256 index) {
        _authorize(owner, _attestHash(owner, fingerprint, pgpSignature, pgpPublicKey, deadline), deadline, signature);
        return _attest(owner, fingerprint, pgpSignature, pgpPublicKey);
    }

    function reattestFor(
        address owner,
        uint256 revokeIndex,
        bytes calldata fingerprint,
        bytes calldata pgpSignature,
        bytes calldata pgpPublicKey,
        uint256 deadline,
        bytes calldata signature
    ) external returns (uint256 index) {
        _authorize(owner, _reattestHash(owner, revokeIndex, fingerprint, pgpSignature, pgpPublicKey, deadline), deadline, signature);
        _revoke(owner, revokeIndex);
        return _attest(owner, fingerprint, pgpSignature, pgpPublicKey);
    }

    function updateKeyFor(
        address owner,
        uint256 index,
        bytes calldata pgpPublicKey,
        uint256 deadline,
        bytes calldata signature
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            UPDATE_KEY_TYPEHASH, owner, index, keccak256(pgpPublicKey), nonces[owner], deadline
        ));
        _authorize(owner, structHash, deadline, signature);
        _updateKey(owner, index, pgpPublicKey);
    }

    function revokeFor(address owner, uint256 index, uint256 deadline, bytes calldata signature) external {
        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, owner, index, nonces[owner], deadline));
        _authorize(owner, structHash, deadline, signature);
        _revoke(owner, index);
    }

    function setRecordFor(
        address owner,
        uint256 index,
        bytes32 kind,
        bytes calldata value,
        uint256 deadline,
        bytes calldata signature
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            SET_RECORD_TYPEHASH, owner, index, kind, keccak256(value), nonces[owner], deadline
        ));
        _authorize(owner, structHash, deadline, signature);
        _setRecord(owner, index, kind, value);
    }

    /// @notice EIP-712 domain separator. Bound to the current chain id, so an authorization
    ///         signed for Sepolia cannot be replayed on mainnet even at the same address.
    // forge-lint: disable-next-line(mixed-case-function)
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH, keccak256(bytes(EIP712_NAME)), keccak256(bytes(EIP712_VERSION)), block.chainid, address(this)
        ));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Views
    // ═══════════════════════════════════════════════════════════════════════════

    /// @notice Number of attestations (including revoked) for an owner.
    function attestationCount(address owner) external view returns (uint256) {
        return _attestations[owner].length;
    }

    function getAttestation(address owner, uint256 index) external view returns (Attestation memory) {
        if (index >= _attestations[owner].length) revert IndexOutOfBounds();
        return _attestations[owner][index];
    }

    /// @notice The stored clearsigned message and armored public key, byte-exact.
    function getPayload(address owner, uint256 index)
        external view returns (bytes memory pgpSignature, bytes memory pgpPublicKey)
    {
        if (index >= _attestations[owner].length) revert IndexOutOfBounds();
        Attestation storage a = _attestations[owner][index];
        return (SSTORE2.read(a.sigPtr), SSTORE2.read(a.keyPtr));
    }

    /// @notice Full history for an owner, oldest first.
    function attestationsOf(address owner) external view returns (Attestation[] memory) {
        return _attestations[owner];
    }

    /// @notice The latest active attestation for an owner, if any.
    function current(address owner) external view returns (bool found, uint256 index, Attestation memory attestation) {
        Attestation[] storage list = _attestations[owner];
        uint256 n = list.length;
        while (n > 0) {
            n--;
            if (list[n].revokedAt == 0) return (true, n, list[n]);
        }
        return (false, 0, attestation);
    }

    /// @notice A typed record on an attestation. Empty if unset or cleared.
    function record(address owner, uint256 index, bytes32 kind) external view returns (bytes memory) {
        address ptr = _records[owner][index][kind];
        if (ptr == address(0)) return "";
        return SSTORE2.read(ptr);
    }

    /// @notice Every owner that has ever attested this fingerprint (keccak256 of the raw bytes).
    ///         Check `getAttestation` / `current` for whether a claim is still active.
    function addressesFor(bytes32 fingerprintHash) external view returns (address[] memory) {
        return _addressesFor[fingerprintHash];
    }

    /// @notice Every fingerprint ever attested whose last 8 bytes are `keyId` (the long key ID).
    function fingerprintsForKeyId(bytes8 keyId) external view returns (bytes[] memory) {
        return _fingerprintsForKeyId[keyId];
    }

    // ═══════════════════════════════════════════════════════════════════════════
    //  Internal
    // ═══════════════════════════════════════════════════════════════════════════

    function _attest(address owner, bytes calldata fingerprint, bytes calldata pgpSignature, bytes calldata pgpPublicKey)
        internal returns (uint256 index)
    {
        uint256 fpLen = fingerprint.length;
        if (fpLen != 20 && fpLen != 32) revert InvalidFingerprintLength();
        if (pgpSignature.length == 0) revert EmptySignature();
        if (pgpPublicKey.length == 0) revert EmptyPublicKey();
        if (pgpSignature.length > MAX_SIG_BYTES) revert SignatureTooLarge();
        if (pgpPublicKey.length > MAX_KEY_BYTES) revert PublicKeyTooLarge();

        bytes32 fpHash = keccak256(fingerprint);
        if (_active[owner][fpHash]) revert DuplicateActiveFingerprint();
        _active[owner][fpHash] = true;

        if (!_seenOwner[fpHash][owner]) {
            _seenOwner[fpHash][owner] = true;
            _addressesFor[fpHash].push(owner);
        }
        bytes8 keyId = bytes8(fingerprint[fpLen - 8:]);
        if (!_seenFingerprint[keyId][fpHash]) {
            _seenFingerprint[keyId][fpHash] = true;
            _fingerprintsForKeyId[keyId].push(fingerprint);
        }

        index = _attestations[owner].length;
        _attestations[owner].push(Attestation({
            fingerprint: fingerprint,
            createdAt: uint64(block.timestamp),
            revokedAt: 0,
            messageVersion: MESSAGE_VERSION,
            keyPtr: SSTORE2.write(pgpPublicKey),
            sigPtr: SSTORE2.write(pgpSignature)
        }));

        emit Attested(owner, fpHash, index, fingerprint, MESSAGE_VERSION, msg.sender);
    }

    function _revoke(address owner, uint256 index) internal {
        Attestation storage a = _activeAttestation(owner, index);
        a.revokedAt = uint64(block.timestamp);
        bytes32 fpHash = keccak256(a.fingerprint);
        _active[owner][fpHash] = false;
        emit Revoked(owner, fpHash, index, msg.sender);
    }

    function _updateKey(address owner, uint256 index, bytes calldata pgpPublicKey) internal {
        if (pgpPublicKey.length == 0) revert EmptyPublicKey();
        if (pgpPublicKey.length > MAX_KEY_BYTES) revert PublicKeyTooLarge();
        Attestation storage a = _activeAttestation(owner, index);
        a.keyPtr = SSTORE2.write(pgpPublicKey);
        emit KeyUpdated(owner, keccak256(a.fingerprint), index, msg.sender);
    }

    function _setRecord(address owner, uint256 index, bytes32 kind, bytes calldata value) internal {
        if (value.length > MAX_RECORD_BYTES) revert RecordTooLarge();
        _activeAttestation(owner, index);
        if (value.length == 0) {
            delete _records[owner][index][kind];
        } else {
            _records[owner][index][kind] = SSTORE2.write(value);
        }
        emit RecordSet(owner, index, kind, msg.sender);
    }

    function _attestHash(
        address owner, bytes calldata fingerprint, bytes calldata pgpSignature, bytes calldata pgpPublicKey, uint256 deadline
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(
            ATTEST_TYPEHASH, owner, keccak256(fingerprint), keccak256(pgpSignature), keccak256(pgpPublicKey),
            nonces[owner], deadline
        ));
    }

    function _reattestHash(
        address owner, uint256 revokeIndex, bytes calldata fingerprint, bytes calldata pgpSignature, bytes calldata pgpPublicKey, uint256 deadline
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(
            REATTEST_TYPEHASH, owner, revokeIndex, keccak256(fingerprint), keccak256(pgpSignature), keccak256(pgpPublicKey),
            nonces[owner], deadline
        ));
    }

    function _activeAttestation(address owner, uint256 index) internal view returns (Attestation storage a) {
        if (index >= _attestations[owner].length) revert IndexOutOfBounds();
        a = _attestations[owner][index];
        if (a.revokedAt != 0) revert AlreadyRevoked();
    }

    /**
     * @dev Verify an EIP-712 authorization from `owner` over `structHash` and consume the nonce.
     *      EOAs: ecrecover. Accounts with code (smart wallets, EIP-7702 delegations): EIP-1271.
     */
    function _authorize(address owner, bytes32 structHash, uint256 deadline, bytes calldata signature) internal {
        if (block.timestamp > deadline) revert AuthorizationExpired();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));

        if (owner.code.length > 0) {
            (bool ok, bytes memory ret) = owner.staticcall(
                abi.encodeWithSelector(ERC1271_MAGIC, digest, signature)
            );
            if (!ok || ret.length < 32 || abi.decode(ret, (bytes4)) != ERC1271_MAGIC) revert InvalidAuthorization();
        } else {
            if (signature.length != 65) revert InvalidAuthorization();
            bytes32 r = bytes32(signature[0:32]);
            bytes32 s = bytes32(signature[32:64]);
            uint8 v = uint8(signature[64]);
            // Reject high-s and malformed v (nonces already prevent replay; this keeps signatures canonical).
            if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert InvalidAuthorization();
            if (v != 27 && v != 28) revert InvalidAuthorization();
            address recovered = ecrecover(digest, v, r, s);
            if (recovered == address(0) || recovered != owner) revert InvalidAuthorization();
        }

        unchecked { nonces[owner]++; }
    }
}
