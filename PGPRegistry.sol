// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title PGPRegistry
 * @notice Links Ethereum addresses to GPG key fingerprints on-chain.
 *
 * Cardinality:
 *   - GPG key → ETH address: many-to-many (multiple addresses may claim the same fingerprint)
 *   - ETH address → GPG key: one-to-many (append-only, supports key rotation)
 *
 * Verification is off-chain: anyone can submit a claim, but only claims with valid
 * PGP signatures are meaningful. Explorers (e.g. thurin.id) verify the PGP signature
 * against the public key stored in the event log and show verified vs. unverified.
 *
 * This design prevents fingerprint squatting — a fake claim cannot block the real
 * key owner from attesting, and fake claims are visibly unverified.
 *
 * The contract does NOT verify PGP signatures on-chain. Trust comes from:
 *   - msg.sender proves ETH ownership implicitly
 *   - The PGP clearsign block + public key are emitted in event logs for off-chain verification
 *
 * Canonical key for an address = most recent non-revoked attestation.
 */
contract PGPRegistry {

    // ─── Constants ────────────────────────────────────────────────────────────

    uint256 public constant MAX_PAYLOAD_BYTES = 16384; // 16 KB cap for sig/pubkey

    // ─── Custom Errors ───────────────────────────────────────────────────────

    error InvalidFingerprintLength();
    error InvalidFingerprintHex();
    error EmptySignature();
    error EmptyPublicKey();
    error SignatureTooLarge();
    error PublicKeyTooLarge();
    error DuplicateActiveFingerprint();
    error IndexOutOfBounds();
    error AlreadyRevoked();

    // ─── Types ───────────────────────────────────────────────────────────────

    struct Attestation {
        string  fingerprint;    // 40-char lowercase hex GPG fingerprint (normalized on storage)
        uint256 createdAt;
        bool    revoked;
    }

    // ─── Events ──────────────────────────────────────────────────────────────

    event Attested(
        address indexed ethAddress,
        string  indexed fingerprintHash,  // keccak256 of normalized fingerprint for indexed filtering
        string  fingerprint,
        string  pgpSignature,             // full PGP clearsign block
        string  pgpPublicKey,             // armored PGP public key for self-contained verification
        uint256 index,                    // position in the address's attestation array
        uint256 timestamp
    );

    event Revoked(
        address indexed ethAddress,
        string  fingerprint,
        uint256 index,
        uint256 timestamp
    );

    // ─── Storage ─────────────────────────────────────────────────────────────

    // address => ordered list of attestations (append-only)
    mapping(address => Attestation[]) private _attestations;

    // O(1) duplicate detection: keccak256(lowercase fingerprint) => address => active
    mapping(bytes32 => mapping(address => bool)) private _activeFingerprints;

    // ─── Attest ──────────────────────────────────────────────────────────────

    /**
     * @notice Publish a mutual attestation linking msg.sender to a GPG fingerprint.
     *         Appends to the attestation history; does not overwrite previous entries.
     *         Rejects duplicate active fingerprints for the same address.
     * @param fingerprint   40-char hex GPG fingerprint (case-insensitive)
     * @param pgpSignature  Full PGP clearsign block signing "I control the Ethereum address: <address>"
     * @param pgpPublicKey  Armored PGP public key for independent verification
     */
    function attest(
        string calldata fingerprint,
        string calldata pgpSignature,
        string calldata pgpPublicKey
    ) external {
        if (bytes(fingerprint).length != 40) revert InvalidFingerprintLength();
        if (!_isHex(fingerprint)) revert InvalidFingerprintHex();
        if (bytes(pgpSignature).length == 0) revert EmptySignature();
        if (bytes(pgpPublicKey).length == 0) revert EmptyPublicKey();
        if (bytes(pgpSignature).length > MAX_PAYLOAD_BYTES) revert SignatureTooLarge();
        if (bytes(pgpPublicKey).length > MAX_PAYLOAD_BYTES) revert PublicKeyTooLarge();

        string memory fp = _lower(fingerprint);
        bytes32 fpHash = keccak256(bytes(fp));

        // Reject duplicate: same address cannot have two active attestations for the same fingerprint
        if (_activeFingerprints[fpHash][msg.sender]) revert DuplicateActiveFingerprint();

        // Mark active and append to history
        _activeFingerprints[fpHash][msg.sender] = true;

        uint256 index = _attestations[msg.sender].length;
        _attestations[msg.sender].push(Attestation({
            fingerprint: fp,        // store normalized lowercase
            createdAt: block.timestamp,
            revoked: false
        }));

        emit Attested(
            msg.sender,
            fp,
            fingerprint,
            pgpSignature,
            pgpPublicKey,
            index,
            block.timestamp
        );
    }

    // ─── Revoke ──────────────────────────────────────────────────────────────

    /**
     * @notice Revoke a specific attestation by index.
     *         The entry remains in the array for auditability but is marked revoked.
     * @param index  Position in the caller's attestation array
     */
    function revoke(uint256 index) external {
        if (index >= _attestations[msg.sender].length) revert IndexOutOfBounds();

        Attestation storage a = _attestations[msg.sender][index];
        if (a.revoked) revert AlreadyRevoked();

        a.revoked = true;

        // Clear O(1) active lookup so re-attestation is allowed
        bytes32 fpHash = keccak256(bytes(a.fingerprint));
        _activeFingerprints[fpHash][msg.sender] = false;

        emit Revoked(msg.sender, a.fingerprint, index, block.timestamp);
    }

    // ─── Views ───────────────────────────────────────────────────────────────

    /**
     * @notice Number of attestations (including revoked) for an address.
     */
    function attestationCount(address addr) external view returns (uint256) {
        return _attestations[addr].length;
    }

    /**
     * @notice Get a single attestation by address and index.
     */
    function getAttestation(address addr, uint256 index)
        external view returns (string memory fingerprint, uint256 createdAt, bool revoked)
    {
        if (index >= _attestations[addr].length) revert IndexOutOfBounds();
        Attestation storage a = _attestations[addr][index];
        return (a.fingerprint, a.createdAt, a.revoked);
    }

    // ─── Internal ────────────────────────────────────────────────────────────

    /**
     * @dev Convert ASCII uppercase letters (A-Z) to lowercase.
     *      Only handles single-byte ASCII characters; does not process
     *      multi-byte UTF-8 sequences. Sufficient for hex fingerprint normalization.
     */
    function _lower(string memory s) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        bytes memory result = new bytes(b.length);
        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            if (c >= 0x41 && c <= 0x5A) {
                result[i] = bytes1(uint8(c) + 32);
            } else {
                result[i] = c;
            }
        }
        return string(result);
    }

    /**
     * @dev Validate that all characters in s are hexadecimal digits [0-9A-Fa-f].
     */
    function _isHex(string calldata s) internal pure returns (bool) {
        bytes memory b = bytes(s);
        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            if (
                !(c >= 0x30 && c <= 0x39) && // 0-9
                !(c >= 0x41 && c <= 0x46) && // A-F
                !(c >= 0x61 && c <= 0x66)    // a-f
            ) {
                return false;
            }
        }
        return true;
    }
}
