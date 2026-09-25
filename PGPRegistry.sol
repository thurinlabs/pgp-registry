// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {SSTORE2} from "./SSTORE2.sol";
import {Armor} from "./Armor.sol";

/// @title PGPRegistry (v3)
/// @notice Links an Ethereum address to an OpenPGP key. A claim stores the key and the key's signature over
/// "I control the Ethereum address: <address>"; the views return both as armored text that gpg reads directly.
/// @dev Permissionless: no owner, admin, pause, fees, or upgrades. The contract never verifies signatures or
/// parses keys beyond packet tags, so a claim counts only if it verifies off-chain. At most one active claim
/// per (owner, fingerprint); an owner's history only grows and indexes are never reused. Every write has two
/// doors with the same effect: the owner sends it, or anyone submits the owner's EIP-712 permission
/// (per-owner nonce, deadline, EIP-1271 for contract accounts).
contract PGPRegistry {
    // ─── Types ───────────────────────────────────────────────────────────────

    /// @dev Two storage slots.
    struct Claim {
        bytes32 fingerprint; // v4: 20 bytes, left-aligned; v6: 32 bytes
        address payload;     // storage contract holding [uint16 signature length][signature][key]
        uint32 createdAt;    // seconds since EPOCH
        uint32 revokedAt;    // seconds since EPOCH; 0 = active
        uint8 flags;         // bit 0: v6 fingerprint; bits 1-3: message version; bits 4-6: revoke reason
        uint16 replacedBy;   // index + 1 of the claim that replaced this one; 0 = none
    }

    /// @notice A claim as the views return it
    struct ClaimView {
        uint256 index;         // position in the owner's history
        bytes fingerprint;     // 20 bytes (v4 key) or 32 bytes (v6 key)
        uint64 createdAt;      // Unix seconds
        uint64 revokedAt;      // Unix seconds; 0 = active
        string state;          // "active", "revoked", or "replaced"
        uint256 replacedBy;    // the replacing claim's index, when state is "replaced"
        string revokeReason;   // "", "compromised", "retired", "superseded", or "other"
        uint8 messageVersion;  // 0 = clearsigned as submitted, 1 = detached signature
    }

    // ─── Constants ───────────────────────────────────────────────────────────

    /// @notice The registry's version
    uint8 public constant VERSION = 3;

    /// @notice The moment stored times count from (2026-01-01 UTC)
    /// @dev Keeps a claim in two storage slots; every view returns plain Unix seconds.
    uint256 public constant EPOCH = 1_767_225_600;

    /// @notice The largest public key accepted, in bytes
    uint256 public constant MAX_KEY_BYTES = 16_384;
    /// @notice The largest signature accepted, in bytes
    uint256 public constant MAX_SIGNATURE_BYTES = 8_192;
    /// @notice The largest signature and key together, in bytes
    /// @dev Both share one storage contract, whose code can hold at most 24,575 bytes.
    uint256 public constant MAX_PAYLOAD_BYTES = 24_000;
    /// @notice The largest record value, in bytes
    uint256 public constant MAX_RECORD_BYTES = 1_024;
    /// @notice The longest record name, in bytes, including a "thurin." prefix
    uint256 public constant MAX_KIND_BYTES = 31;
    /// @notice The most claims one address can make
    /// @dev `replacedBy` stores index + 1 in 16 bits.
    uint256 public constant MAX_CLAIMS_PER_OWNER = 65_535;

    /// @notice Message version 0: a whole clearsigned statement, stored as submitted
    uint8 public constant MESSAGE_CLEARSIGNED = 0;
    /// @notice Message version 1: a detached text-mode signature over {statementFor}
    uint8 public constant MESSAGE_DETACHED = 1;

    /// @notice The EIP-712 domain name permissions are signed under
    string public constant EIP712_NAME = "Thurin PGPRegistry";
    /// @notice The EIP-712 domain version permissions are signed under
    string public constant EIP712_VERSION = "3";

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    /// @notice EIP-712 type hash of an Attest permission, for {attestFor}
    bytes32 public constant ATTEST_TYPEHASH =
        keccak256("Attest(address owner,bytes fingerprint,bytes signature,bytes key,uint256 nonce,uint256 deadline)");
    /// @notice EIP-712 type hash of a Reattest permission, for {reattestFor}
    bytes32 public constant REATTEST_TYPEHASH = keccak256(
        "Reattest(address owner,uint256 revokeIndex,bytes fingerprint,bytes signature,bytes key,bool keepRecords,uint256 nonce,uint256 deadline)"
    );
    /// @notice EIP-712 type hash of an UpdateKey permission, for {updateKeyFor}
    bytes32 public constant UPDATE_KEY_TYPEHASH =
        keccak256("UpdateKey(address owner,uint256 index,bytes key,uint256 nonce,uint256 deadline)");
    /// @notice EIP-712 type hash of a Revoke permission, for {revokeFor}
    bytes32 public constant REVOKE_TYPEHASH =
        keccak256("Revoke(address owner,uint256 index,string reason,uint256 nonce,uint256 deadline)");
    /// @notice EIP-712 type hash of a SetRecord permission, for {setRecordFor}
    bytes32 public constant SET_RECORD_TYPEHASH =
        keccak256("SetRecord(address owner,uint256 index,string kind,string value,uint256 nonce,uint256 deadline)");
    /// @notice EIP-712 type hash of a MarkCompromised permission, for {markCompromisedFor}
    /// @dev Its own type, so a Revoke permission can never mark an ended claim compromised.
    bytes32 public constant MARK_COMPROMISED_TYPEHASH =
        keccak256("MarkCompromised(address owner,uint256 index,uint256 nonce,uint256 deadline)");

    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;
    bytes private constant CLEARSIGN_HEADER = "-----BEGIN PGP SIGNED MESSAGE-----";
    bytes32 private constant RECORD_POINTER = bytes32(uint256(0xFF) << 248);
    // Record sets given to claims whose records moved on reattest (never used by a live claim).
    uint256 private constant MOVED_SET = 1 << 128;

    uint8 private constant NEVER = 0;
    uint8 private constant INACTIVE = 1;
    uint8 private constant ACTIVE = 2;
    uint8 private constant COMPROMISED = 3; // revoked as compromised: this owner can't claim the key again

    uint8 private constant REASON_NONE = 0;
    uint8 private constant REASON_COMPROMISED = 1;
    uint8 private constant REASON_RETIRED = 2;
    uint8 private constant REASON_SUPERSEDED = 3;
    uint8 private constant REASON_OTHER = 4;

    // ─── Storage ─────────────────────────────────────────────────────────────

    mapping(address owner => Claim[]) private _claims;
    mapping(address owner => mapping(bytes32 fingerprintHash => uint8)) private _state;
    mapping(bytes32 fingerprintHash => address[]) private _owners;
    mapping(bytes8 keyId => bytes32[]) private _fingerprintsForKeyId;
    mapping(address owner => mapping(uint256 index => uint256)) private _recordSet; // 0 = own index; else set + 1
    // Record names in first-use order; the list ends at the first empty entry (a packed name is never 0).
    mapping(address owner => mapping(uint256 set => mapping(uint256 i => bytes32))) private _recordKinds;
    mapping(address owner => mapping(uint256 set => mapping(bytes32 kindHash => bytes32))) private _recordValue;

    /// @notice The nonce the owner's next permission must be signed with
    /// @dev Only permissions consume it; {cancelAuthorization} skips one.
    mapping(address owner => uint256) public nonces;

    // ─── Events ──────────────────────────────────────────────────────────────

    /// @notice Emitted when a claim is published
    /// @param owner The address the claim is for
    /// @param fingerprintHash keccak256 of the fingerprint bytes
    /// @param index The claim's position in the owner's history
    /// @param fingerprint The key's fingerprint, 20 or 32 bytes
    /// @param payload The storage contract holding the signature and key; read them with {signatureBytes} and {keyBytes}
    /// @param messageVersion 0: clearsigned statement stored as submitted; 1: detached signature over {statementFor}
    /// @param submitter Who sent the transaction: the owner, or anyone submitting the owner's permission
    event Attested(
        address indexed owner,
        bytes32 indexed fingerprintHash,
        uint256 indexed index,
        bytes fingerprint,
        address payload,
        uint8 messageVersion,
        address submitter
    );
    /// @notice Emitted when an active claim's stored key is replaced (same key, e.g. new proofs or a new expiry)
    /// @param owner The address the claim is for
    /// @param fingerprintHash keccak256 of the fingerprint bytes
    /// @param index The claim's position in the owner's history
    /// @param oldPayload The storage contract that held the signature and the old key
    /// @param newPayload The storage contract holding the signature and the new key
    /// @param submitter Who sent the transaction: the owner, or anyone submitting the owner's permission
    event KeyUpdated(
        address indexed owner,
        bytes32 indexed fingerprintHash,
        uint256 indexed index,
        address oldPayload,
        address newPayload,
        address submitter
    );
    /// @notice Emitted when a claim is revoked, and again if an ended claim is later marked compromised
    /// @param owner The address the claim is for
    /// @param fingerprintHash keccak256 of the fingerprint bytes
    /// @param index The claim's position in the owner's history
    /// @param reason "", "compromised", "retired", "superseded" (set by {reattest}), or "other"
    /// @param replacedBy The replacing claim's index + 1, or 0 if it wasn't replaced
    /// @param submitter Who sent the transaction: the owner, or anyone submitting the owner's permission
    event Revoked(
        address indexed owner,
        bytes32 indexed fingerprintHash,
        uint256 indexed index,
        string reason,
        uint256 replacedBy,
        address submitter
    );
    /// @notice Emitted when a record is set or cleared
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @param kindHash keccak256 of the full record name
    /// @param kind The full record name, e.g. "thurin.security"
    /// @param value The new text, or "" when cleared; every value a record has had stays in these events
    /// @param submitter Who sent the transaction: the owner, or anyone submitting the owner's permission
    event RecordSet(
        address indexed owner,
        uint256 indexed index,
        bytes32 indexed kindHash,
        string kind,
        string value,
        address submitter
    );
    /// @notice Emitted when {reattest} moves a claim's records to the claim that replaced it
    /// @param owner The address the claims are for
    /// @param fromIndex The replaced claim, which is left with no records
    /// @param toIndex The new claim, which now has them
    event RecordsMoved(address indexed owner, uint256 indexed fromIndex, uint256 indexed toIndex);
    /// @notice Emitted when an owner's nonce is used, by a permission or by {cancelAuthorization}
    /// @param owner The address whose nonce was used
    /// @param nonce The nonce used; the next permission must be signed with nonce + 1
    event NonceUsed(address indexed owner, uint256 nonce);

    // ─── Errors ──────────────────────────────────────────────────────────────

    /// @notice Thrown when a fingerprint isn't 20 bytes (v4 key) or 32 bytes (v6 key)
    error InvalidFingerprintLength(uint256 length);
    /// @notice Thrown when a 32-byte fingerprint ends in 12 zero bytes, which no real v6 key has
    error InvalidFingerprint(bytes fingerprint);
    /// @notice Thrown when no key is given
    error EmptyKey();
    /// @notice Thrown when no signature is given
    error EmptySignature();
    /// @notice Thrown when the key is larger than {MAX_KEY_BYTES}; export it without photos or old signatures
    error KeyTooLarge(uint256 size, uint256 max);
    /// @notice Thrown when the signature is larger than {MAX_SIGNATURE_BYTES}
    error SignatureTooLarge(uint256 size, uint256 max);
    /// @notice Thrown when the signature and key together are larger than {MAX_PAYLOAD_BYTES}
    error PayloadTooLarge(uint256 size, uint256 max);
    /// @notice Thrown when the key doesn't start with an OpenPGP public-key packet; give gpg's binary export, or use {armorToBytes}
    error NotAKey(bytes1 firstByte);
    /// @notice Thrown when the signature is neither an OpenPGP signature packet nor a clearsigned message
    error NotASignature(bytes1 firstByte);
    /// @notice Thrown when the owner already has an active claim for this key; use {updateKey} or {reattest}
    error DuplicateActiveFingerprint(bytes fingerprint);
    /// @notice Thrown when the owner marked this key compromised; it can never be claimed from this address again
    error KeyCompromised(bytes fingerprint);
    /// @notice Thrown when marking a key compromised while the owner still has an active claim for it; revoke that claim as "compromised" instead
    error KeyStillActive(bytes fingerprint);
    /// @notice Thrown when {markCompromisedFor} targets an active claim; revoke it with reason "compromised" instead
    error ClaimActive(uint256 index);
    /// @notice Thrown when "superseded" is given as a revoke reason; only {reattest} sets it
    error SupersededIsSetByReattest();
    /// @notice Thrown when the owner has no claim at `index`
    error IndexOutOfBounds(uint256 index, uint256 count);
    /// @notice Thrown when the claim has already ended, or is already marked compromised
    error AlreadyRevoked(uint256 index);
    /// @notice Thrown when the owner already has {MAX_CLAIMS_PER_OWNER} claims
    error TooManyClaims();
    /// @notice Thrown when the revoke reason isn't "", "compromised", "retired", or "other"
    error UnknownRevokeReason(string reason);
    /// @notice Thrown when a record name is empty, longer than {MAX_KIND_BYTES}, or uses anything but a-z, 0-9, '-', and '.'
    error InvalidKindName(string kind);
    /// @notice Thrown when a record value is larger than {MAX_RECORD_BYTES}
    error RecordTooLarge(uint256 size, uint256 max);
    /// @notice Thrown when a permission is used after its deadline
    error PermissionExpired(uint256 deadline);
    /// @notice Thrown when a permission isn't the owner's signature over exactly this call and the owner's current nonce
    error InvalidPermission();

    // ═════════════════════════════════════════════════════════════════════════
    //  Writes by the owner
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Publishes a claim linking your address to a PGP key
    /// @param fingerprint The key's fingerprint: 20 bytes (v4 key) or 32 bytes (v6 key)
    /// @param signature The key's detached text-mode signature over {statementFor} as raw bytes (`gpg --detach-sign --textmode`), or a whole clearsigned statement as text
    /// @param key The public key as raw bytes (`gpg --export`, not armored)
    /// @return index The new claim's position in your history
    /// @dev Emits an {Attested} event.
    function attest(bytes calldata fingerprint, bytes calldata signature, bytes calldata key)
        external
        returns (uint256 index)
    {
        return _attest(msg.sender, fingerprint, signature, key);
    }

    /// @notice Revokes one of your active claims and publishes a new one in the same transaction
    /// @param revokeIndex The active claim to replace; it's revoked with reason "superseded"
    /// @param fingerprint The key's fingerprint: 20 bytes (v4 key) or 32 bytes (v6 key)
    /// @param signature The key's detached text-mode signature over {statementFor} as raw bytes (`gpg --detach-sign --textmode`), or a whole clearsigned statement as text
    /// @param key The public key as raw bytes (`gpg --export`, not armored)
    /// @param keepRecords true moves the old claim's records to the new one (a key rotation)
    /// @return index The new claim's position in your history
    /// @dev Emits {Revoked}, {Attested}, and, with `keepRecords`, {RecordsMoved}.
    function reattest(
        uint256 revokeIndex,
        bytes calldata fingerprint,
        bytes calldata signature,
        bytes calldata key,
        bool keepRecords
    ) external returns (uint256 index) {
        return _reattest(msg.sender, revokeIndex, fingerprint, signature, key, keepRecords);
    }

    /// @notice Replaces the stored key of one of your active claims with a newer export of the same key
    /// @param index The claim's position in your history
    /// @param key The same key as raw bytes (`gpg --export`), e.g. with new proofs or a new expiry
    /// @dev The stored signature is kept, so the key must still verify it off-chain. Emits a {KeyUpdated} event.
    function updateKey(uint256 index, bytes calldata key) external {
        _updateKey(msg.sender, index, key);
    }

    /// @notice Revokes one of your claims; it stays in your history. An ended claim can later be marked "compromised", once
    /// @param index The claim's position in your history
    /// @param reason "", "compromised", "retired", or "other". IMPORTANT: "compromised" is permanent: this address can never claim the key again
    /// @dev "superseded" is set only by {reattest}. Emits a {Revoked} event.
    function revoke(uint256 index, string calldata reason) external {
        _ownerRevoke(msg.sender, index, reason, true);
    }

    /// @notice Sets a record on one of your active claims; an empty value clears it, on ended claims too
    /// @param index The claim's position in your history
    /// @param kind The record name: a-z, 0-9, '-', '.'; a name without a dot means "thurin.<kind>" (e.g. "security")
    /// @param value The text, up to {MAX_RECORD_BYTES} bytes, or "" to clear
    /// @dev Emits a {RecordSet} event.
    function setRecord(uint256 index, string calldata kind, string calldata value) external {
        _setRecord(msg.sender, index, kind, value);
    }

    /// @notice Runs several calls on this contract in one transaction, each as you
    /// @param calls The ABI-encoded calls, run in order; if one fails, all revert
    /// @return results Each call's return data
    function multicall(bytes[] calldata calls) external returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory ret) = address(this).delegatecall(calls[i]);
            if (!ok) {
                assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
            }
            results[i] = ret;
        }
    }

    /// @notice Cancels every permission signed with your current nonce, by using it up
    /// @dev Emits a {NonceUsed} event.
    function cancelAuthorization() external {
        uint256 used = nonces[msg.sender];
        unchecked { nonces[msg.sender] = used + 1; }
        emit NonceUsed(msg.sender, used);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Writes with the owner's permission (anyone submits and pays)
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice Publishes a claim for `owner`, who signed an Attest permission; anyone can submit it and pay
    /// @param owner The address the claim is for
    /// @param fingerprint The key's fingerprint: 20 bytes (v4 key) or 32 bytes (v6 key)
    /// @param signature The key's detached text-mode signature over {statementFor} as raw bytes (`gpg --detach-sign --textmode`), or a whole clearsigned statement as text
    /// @param key The public key as raw bytes (`gpg --export`, not armored)
    /// @param deadline The last Unix second the permission can be used
    /// @param permission The owner's EIP-712 signature over Attest(owner, fingerprint, signature, key, nonce, deadline), with their current {nonces}
    /// @return index The new claim's position in the owner's history
    /// @dev Same effect as {attest} from `owner`. Emits {NonceUsed} and {Attested}.
    function attestFor(
        address owner,
        bytes calldata fingerprint,
        bytes calldata signature,
        bytes calldata key,
        uint256 deadline,
        bytes calldata permission
    ) external returns (uint256 index) {
        bytes32 structHash = keccak256(abi.encode(
            ATTEST_TYPEHASH, owner, keccak256(fingerprint), keccak256(signature), keccak256(key), nonces[owner], deadline
        ));
        _authorize(owner, structHash, deadline, permission);
        return _attest(owner, fingerprint, signature, key);
    }

    /// @notice Replaces a claim for `owner`, who signed a Reattest permission; anyone can submit it and pay
    /// @param owner The address the claim is for
    /// @param revokeIndex The active claim to replace; it's revoked with reason "superseded"
    /// @param fingerprint The key's fingerprint: 20 bytes (v4 key) or 32 bytes (v6 key)
    /// @param signature The key's detached text-mode signature over {statementFor} as raw bytes (`gpg --detach-sign --textmode`), or a whole clearsigned statement as text
    /// @param key The public key as raw bytes (`gpg --export`, not armored)
    /// @param keepRecords true moves the old claim's records to the new one
    /// @param deadline The last Unix second the permission can be used
    /// @param permission The owner's EIP-712 signature over Reattest(owner, revokeIndex, fingerprint, signature, key, keepRecords, nonce, deadline), with their current {nonces}
    /// @return index The new claim's position in the owner's history
    /// @dev Same effect as {reattest} from `owner`.
    function reattestFor(
        address owner,
        uint256 revokeIndex,
        bytes calldata fingerprint,
        bytes calldata signature,
        bytes calldata key,
        bool keepRecords,
        uint256 deadline,
        bytes calldata permission
    ) external returns (uint256 index) {
        bytes32 structHash = keccak256(abi.encode(
            REATTEST_TYPEHASH, owner, revokeIndex, keccak256(fingerprint), keccak256(signature), keccak256(key),
            keepRecords, nonces[owner], deadline
        ));
        _authorize(owner, structHash, deadline, permission);
        return _reattest(owner, revokeIndex, fingerprint, signature, key, keepRecords);
    }

    /// @notice Replaces the stored key of `owner`'s active claim, with their signed UpdateKey permission
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @param key The same key as raw bytes (`gpg --export`)
    /// @param deadline The last Unix second the permission can be used
    /// @param permission The owner's EIP-712 signature over UpdateKey(owner, index, key, nonce, deadline), with their current {nonces}
    /// @dev Same effect as {updateKey} from `owner`.
    function updateKeyFor(address owner, uint256 index, bytes calldata key, uint256 deadline, bytes calldata permission)
        external
    {
        bytes32 structHash = keccak256(abi.encode(UPDATE_KEY_TYPEHASH, owner, index, keccak256(key), nonces[owner], deadline));
        _authorize(owner, structHash, deadline, permission);
        _updateKey(owner, index, key);
    }

    /// @notice Revokes `owner`'s active claim, with their signed Revoke permission; anyone can submit it
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @param reason "", "compromised", "retired", or "other". IMPORTANT: "compromised" is permanent for this owner and key
    /// @param deadline The last Unix second the permission can be used
    /// @param permission The owner's EIP-712 signature over Revoke(owner, index, reason, nonce, deadline), with their current {nonces}
    /// @dev Revokes an active claim only; to mark an ended claim compromised, use {markCompromisedFor}.
    function revokeFor(address owner, uint256 index, string calldata reason, uint256 deadline, bytes calldata permission)
        external
    {
        bytes32 structHash = keccak256(abi.encode(
            REVOKE_TYPEHASH, owner, index, keccak256(bytes(reason)), nonces[owner], deadline
        ));
        _authorize(owner, structHash, deadline, permission);
        // A permission revokes an active claim only, so an unused one can't become a late "compromised" mark.
        _ownerRevoke(owner, index, reason, false);
    }

    /// @notice Marks `owner`'s ended claim compromised, with their signed MarkCompromised permission
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @param deadline The last Unix second the permission can be used
    /// @param permission The owner's EIP-712 signature over MarkCompromised(owner, index, nonce, deadline), with their current {nonces}
    /// @dev IMPORTANT: permanent: `owner` can never claim this key again. Emits a {Revoked} event with reason "compromised".
    function markCompromisedFor(address owner, uint256 index, uint256 deadline, bytes calldata permission) external {
        bytes32 structHash = keccak256(abi.encode(MARK_COMPROMISED_TYPEHASH, owner, index, nonces[owner], deadline));
        _authorize(owner, structHash, deadline, permission);
        if (_claimAt(owner, index).revokedAt == 0) revert ClaimActive(index);
        _markCompromised(owner, index);
    }

    /// @notice Sets a record on `owner`'s claim, with their signed SetRecord permission
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @param kind The record name; a name without a dot means "thurin.<kind>"
    /// @param value The text, up to {MAX_RECORD_BYTES} bytes, or "" to clear
    /// @param deadline The last Unix second the permission can be used
    /// @param permission The owner's EIP-712 signature over SetRecord(owner, index, kind, value, nonce, deadline), with their current {nonces}
    /// @dev Same effect as {setRecord} from `owner`.
    function setRecordFor(
        address owner,
        uint256 index,
        string calldata kind,
        string calldata value,
        uint256 deadline,
        bytes calldata permission
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            SET_RECORD_TYPEHASH, owner, index, keccak256(bytes(kind)), keccak256(bytes(value)), nonces[owner], deadline
        ));
        _authorize(owner, structHash, deadline, permission);
        _setRecord(owner, index, kind, value);
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Views
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice The EIP-712 signing domain, in the EIP-5267 format wallets read
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        return (hex"0f", EIP712_NAME, EIP712_VERSION, block.chainid, address(this), bytes32(0), new uint256[](0));
    }

    /// @notice One record's text on a claim, or "" if it isn't set
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @param kind The record name; a name without a dot means "thurin.<kind>"
    /// @return The record's text
    function recordText(address owner, uint256 index, string calldata kind) external view returns (string memory) {
        _claimAt(owner, index);
        (, bytes32 kindHash) = _kindName(kind);
        return string(_readRecord(_recordValue[owner][_setOf(owner, index)][kindHash]));
    }

    /// @notice Where `owner` stands with a key
    /// @param owner The address to check
    /// @param fingerprint The key's fingerprint: 20 bytes (v4 key) or 32 bytes (v6 key)
    /// @return "none" (never claimed), "active", "revoked" (can claim it again), or "compromised" (can never claim it again)
    /// @dev Per owner: anyone can claim any fingerprint and mark it compromised under their own address.
    function keyStatus(address owner, bytes calldata fingerprint) external view returns (string memory) {
        uint8 st = _state[owner][keccak256(fingerprint)];
        if (st == ACTIVE) return "active";
        if (st == INACTIVE) return "revoked";
        if (st == COMPROMISED) return "compromised";
        return "none";
    }

    /// @notice Every claim `owner` has made, oldest first
    /// @param owner The address to read
    /// @return out The claims; for a long history, page with {claimsOfRange}
    function claimsOf(address owner) external view returns (ClaimView[] memory out) {
        return claimsOfRange(owner, 0, type(uint256).max);
    }

    /// @notice One claim in full
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @return details The claim's details
    /// @return key The armored public key
    /// @return statement The clearsigned statement
    /// @return recordKinds The names of its set records
    function claim(address owner, uint256 index)
        external
        view
        returns (ClaimView memory details, string memory key, string memory statement, string[] memory recordKinds)
    {
        details = _view(owner, index);
        key = armoredKey(owner, index);
        statement = clearsigned(owner, index);
        (recordKinds, ) = recordsOf(owner, index);
    }

    /// @notice How many claims `owner` has, and the current one
    /// @param owner The address to read
    /// @return total Every claim ever made
    /// @return active Claims not revoked
    /// @return hasCurrent Whether any claim is active
    /// @return currentIndex The newest active claim, when `hasCurrent`
    /// @dev Active isn't verified: check the signature off-chain before trusting a claim.
    function summary(address owner)
        external
        view
        returns (uint256 total, uint256 active, bool hasCurrent, uint256 currentIndex)
    {
        Claim[] storage list = _claims[owner];
        total = list.length;
        for (uint256 i = total; i > 0; --i) {
            if (list[i - 1].revokedAt == 0) {
                if (!hasCurrent) { hasCurrent = true; currentIndex = i - 1; }
                active++;
            }
        }
    }

    /// @notice Turns a pasted armored block into the raw bytes the write functions take
    /// @param armored An armored key or signature, or a clearsigned message (its signature is returned); line breaks may be missing
    /// @return The decoded bytes
    function armorToBytes(string calldata armored) external pure returns (bytes memory) {
        return Armor.decode(armored);
    }

    /// @notice How many claims `owner` has made
    /// @param owner The address to read
    /// @return The number of claims, active or not
    function claimCount(address owner) external view returns (uint256) {
        return _claims[owner].length;
    }

    /// @notice `owner`'s newest active claim
    /// @param owner The address to read
    /// @return found Whether any claim is active
    /// @return index The claim's position, when `found`
    /// @return details The claim's details, when `found`
    /// @dev Active isn't verified: check the signature off-chain before trusting a claim.
    function current(address owner) external view returns (bool found, uint256 index, ClaimView memory details) {
        Claim[] storage list = _claims[owner];
        for (uint256 i = list.length; i > 0; --i) {
            if (list[i - 1].revokedAt == 0) return (true, i - 1, _view(owner, i - 1));
        }
    }

    /// @notice A claim's public key exactly as stored
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @return key The key as raw OpenPGP bytes
    function keyBytes(address owner, uint256 index) external view returns (bytes memory key) {
        (, key) = _payload(_claimAt(owner, index));
    }

    /// @notice A claim's signature exactly as stored
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @return signature Raw OpenPGP signature bytes, or the clearsigned message as text
    function signatureBytes(address owner, uint256 index) external view returns (bytes memory signature) {
        (signature, ) = _payload(_claimAt(owner, index));
    }

    /// @notice Every address that has ever claimed a key
    /// @param fingerprint The key's fingerprint: 20 bytes (v4 key) or 32 bytes (v6 key)
    /// @return Owners in first-claim order; check each one's claims to see which are active
    function ownersOf(bytes calldata fingerprint) external view returns (address[] memory) {
        return _owners[keccak256(fingerprint)];
    }

    /// @notice How many addresses have ever claimed a key
    /// @param fingerprint The key's fingerprint: 20 bytes (v4 key) or 32 bytes (v6 key)
    /// @return The number of owners
    function ownersOfCount(bytes calldata fingerprint) external view returns (uint256) {
        return _owners[keccak256(fingerprint)].length;
    }

    /// @notice A page of the addresses that have ever claimed a key
    /// @param fingerprint The key's fingerprint: 20 bytes (v4 key) or 32 bytes (v6 key)
    /// @param start The first position to return
    /// @param count How many to return at most
    /// @return out Owners `start` to `start + count - 1`, cut off at the end of the list
    function ownersOfRange(bytes calldata fingerprint, uint256 start, uint256 count)
        external
        view
        returns (address[] memory out)
    {
        address[] storage list = _owners[keccak256(fingerprint)];
        uint256 n = start >= list.length ? 0 : (count < list.length - start ? count : list.length - start);
        out = new address[](n);
        for (uint256 i; i < n; ++i) out[i] = list[start + i];
    }

    /// @notice Every fingerprint ever claimed with a long key ID
    /// @param keyId The long key ID: a v4 fingerprint's last 8 bytes, or a v6 fingerprint's first 8
    /// @return The fingerprints, 20 or 32 bytes each
    function fingerprintsForKeyId(bytes8 keyId) external view returns (bytes[] memory) {
        return fingerprintsForKeyIdRange(keyId, 0, type(uint256).max);
    }

    /// @notice How many fingerprints have been claimed with a long key ID
    /// @param keyId The long key ID: a v4 fingerprint's last 8 bytes, or a v6 fingerprint's first 8
    /// @return The number of fingerprints
    function fingerprintsForKeyIdCount(bytes8 keyId) external view returns (uint256) {
        return _fingerprintsForKeyId[keyId].length;
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Views also used inside the contract
    // ═════════════════════════════════════════════════════════════════════════

    /// @notice The EIP-712 domain separator permissions are signed under, bound to this chain and this contract
    // forge-lint: disable-next-line(mixed-case-function)
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH, keccak256(bytes(EIP712_NAME)), keccak256(bytes(EIP712_VERSION)), block.chainid, address(this)
        ));
    }

    /// @notice The exact line a key signs to claim `owner`
    /// @param owner The address to claim
    /// @return The statement, with the address in lowercase
    function statementFor(address owner) public pure returns (string memory) {
        return string.concat("I control the Ethereum address: ", _hexLower(owner));
    }

    /// @notice A claim's key as armored text, ready for `gpg --import`
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @return The armored public key block
    function armoredKey(address owner, uint256 index) public view returns (string memory) {
        (, bytes memory key) = _payload(_claimAt(owner, index));
        return Armor.armor("PUBLIC KEY BLOCK", key);
    }

    /// @notice A claim's signed statement as a clearsigned message, ready for `gpg --verify`
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @return The clearsigned message
    function clearsigned(address owner, uint256 index) public view returns (string memory) {
        Claim storage c = _claimAt(owner, index);
        (bytes memory sig, ) = _payload(c);
        if (_messageVersion(c.flags) == MESSAGE_CLEARSIGNED) return string(sig);
        return Armor.clearsign(statementFor(owner), sig);
    }

    /// @notice Every set record on a claim
    /// @param owner The address the claim is for
    /// @param index The claim's position in the owner's history
    /// @return kinds The record names, e.g. "thurin.security", in the order first set
    /// @return values Each record's text
    function recordsOf(address owner, uint256 index) public view returns (string[] memory kinds, string[] memory values) {
        _claimAt(owner, index);
        uint256 set = _setOf(owner, index);
        mapping(uint256 => bytes32) storage names = _recordKinds[owner][set];
        uint256 total;
        uint256 n;
        for (bytes32 w = names[0]; w != 0; w = names[++total]) {
            if (_recordValue[owner][set][keccak256(_unpackName(w))] != 0) n++;
        }
        kinds = new string[](n);
        values = new string[](n);
        uint256 j;
        for (uint256 i; i < total; ++i) {
            bytes memory name = _unpackName(names[i]);
            bytes32 word = _recordValue[owner][set][keccak256(name)];
            if (word == 0) continue;
            kinds[j] = string(name);
            values[j] = string(_readRecord(word));
            j++;
        }
    }

    /// @notice A page of `owner`'s claims, oldest first
    /// @param owner The address to read
    /// @param start The first index to return
    /// @param count How many to return at most
    /// @return out Claims `start` to `start + count - 1`, cut off at the end of the history
    function claimsOfRange(address owner, uint256 start, uint256 count) public view returns (ClaimView[] memory out) {
        uint256 total = _claims[owner].length;
        uint256 n = start >= total ? 0 : (count < total - start ? count : total - start);
        out = new ClaimView[](n);
        for (uint256 i; i < n; ++i) out[i] = _view(owner, start + i);
    }

    /// @notice A page of the fingerprints claimed with a long key ID
    /// @param keyId The long key ID: a v4 fingerprint's last 8 bytes, or a v6 fingerprint's first 8
    /// @param start The first position to return
    /// @param count How many to return at most
    /// @return out Fingerprints `start` to `start + count - 1`, cut off at the end of the list
    function fingerprintsForKeyIdRange(bytes8 keyId, uint256 start, uint256 count)
        public
        view
        returns (bytes[] memory out)
    {
        bytes32[] storage list = _fingerprintsForKeyId[keyId];
        uint256 n = start >= list.length ? 0 : (count < list.length - start ? count : list.length - start);
        out = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            bytes32 w = list[start + i];
            // A v4 entry is 20 bytes then 12 zero bytes. Read from the word itself, so no other claim
            // can change how it reads.
            // forge-lint: disable-next-line(unsafe-typecast) the low 96 bits
            bool v6 = uint96(uint256(w)) != 0;
            out[i] = _fingerprintBytes(w, v6);
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  Internal
    // ═════════════════════════════════════════════════════════════════════════

    function _attest(address owner, bytes calldata fingerprint, bytes calldata signature, bytes calldata key)
        internal
        returns (uint256 index)
    {
        uint256 fpLen = fingerprint.length;
        if (fpLen != 20 && fpLen != 32) revert InvalidFingerprintLength(fpLen);
        // A v6 fingerprint ending in 12 zero bytes would be listed as a v4 one (never happens for a real key).
        if (fpLen == 32 && uint96(bytes12(fingerprint[20:32])) == 0) revert InvalidFingerprint(fingerprint);
        uint8 messageVersion = _checkPayload(signature, key);

        index = _claims[owner].length;
        if (index >= MAX_CLAIMS_PER_OWNER) revert TooManyClaims();

        bytes32 fpHash = keccak256(fingerprint);
        uint8 st = _state[owner][fpHash];
        if (st == ACTIVE) revert DuplicateActiveFingerprint(fingerprint);
        if (st == COMPROMISED) revert KeyCompromised(fingerprint);
        bool v6 = fpLen == 32;
        if (st == NEVER) {
            address[] storage owners = _owners[fpHash];
            if (owners.length == 0) {
                // First claim on this key by anyone: list it under its key ID.
                bytes8 keyId = v6 ? bytes8(fingerprint[0:8]) : bytes8(fingerprint[12:20]);
                // forge-lint: disable-next-line(unsafe-typecast) fingerprint is 20 or 32 bytes (checked above)
                _fingerprintsForKeyId[keyId].push(bytes32(fingerprint));
            }
            owners.push(owner);
        }
        _state[owner][fpHash] = ACTIVE;

        address payload = SSTORE2.writeOnce(abi.encodePacked(uint16(signature.length), signature, key));
        _claims[owner].push(Claim({
            // forge-lint: disable-next-line(unsafe-typecast) fingerprint is 20 or 32 bytes (checked above)
            fingerprint: bytes32(fingerprint),
            payload: payload,
            createdAt: _now(),
            revokedAt: 0,
            flags: (v6 ? uint8(1) : uint8(0)) | (messageVersion << 1),
            replacedBy: 0
        }));
        emit Attested(owner, fpHash, index, fingerprint, payload, messageVersion, msg.sender);
    }

    function _reattest(
        address owner,
        uint256 revokeIndex,
        bytes calldata fingerprint,
        bytes calldata signature,
        bytes calldata key,
        bool keepRecords
    ) internal returns (uint256 index) {
        uint256 next = _claims[owner].length;
        if (next >= MAX_CLAIMS_PER_OWNER) revert TooManyClaims();
        uint256 set = _setOf(owner, revokeIndex);
        _revoke(owner, revokeIndex, REASON_SUPERSEDED, next + 1);
        index = _attest(owner, fingerprint, signature, key);
        if (keepRecords) {
            // The records move: the new claim takes the set, the replaced claim gets an empty one.
            _recordSet[owner][index] = set + 1;
            _recordSet[owner][revokeIndex] = MOVED_SET + revokeIndex + 1;
            emit RecordsMoved(owner, revokeIndex, index);
        }
    }

    function _updateKey(address owner, uint256 index, bytes calldata key) internal {
        Claim storage c = _activeClaim(owner, index);
        bytes memory sig = _signature(c);
        _checkKey(key, sig.length);
        address oldPayload = c.payload;
        address newPayload = SSTORE2.writeOnce(abi.encodePacked(uint16(sig.length), sig, key));
        c.payload = newPayload;
        emit KeyUpdated(owner, _fingerprintHash(c), index, oldPayload, newPayload, msg.sender);
    }

    /// An active claim is revoked; with `allowLate`, a revoked or replaced one can be marked compromised.
    function _ownerRevoke(address owner, uint256 index, string calldata reason, bool allowLate) internal {
        uint8 code = _reasonCode(reason);
        if (code == REASON_SUPERSEDED) revert SupersededIsSetByReattest();
        Claim storage c = _claimAt(owner, index);
        if (c.revokedAt == 0) {
            _revoke(owner, index, code, 0);
            return;
        }
        if (!allowLate || code != REASON_COMPROMISED) revert AlreadyRevoked(index);
        _markCompromised(owner, index);
    }

    /// Mark a revoked or replaced claim compromised, once; not while the key has an active claim here.
    function _markCompromised(address owner, uint256 index) internal {
        Claim storage c = _claimAt(owner, index);
        if (c.flags >> 4 == REASON_COMPROMISED) revert AlreadyRevoked(index);
        bytes32 fpHash = _fingerprintHash(c);
        if (_state[owner][fpHash] == ACTIVE) revert KeyStillActive(_fingerprintBytes(c.fingerprint, c.flags & 1 == 1));
        c.flags = (c.flags & 0x0F) | (REASON_COMPROMISED << 4);
        _state[owner][fpHash] = COMPROMISED;
        emit Revoked(owner, fpHash, index, "compromised", c.replacedBy, msg.sender);
    }

    function _revoke(address owner, uint256 index, uint8 reason, uint256 replacedBy) internal {
        Claim storage c = _activeClaim(owner, index);
        uint32 t = _now();
        c.revokedAt = t == 0 ? 1 : t; // 0 means active; the stored clock wraps every 136 years
        c.flags = (c.flags & 0x0F) | (reason << 4);
        // forge-lint: disable-next-line(unsafe-typecast) replacedBy <= MAX_CLAIMS_PER_OWNER (checked by callers)
        c.replacedBy = uint16(replacedBy);
        bytes32 fpHash = _fingerprintHash(c);
        _state[owner][fpHash] = reason == REASON_COMPROMISED ? COMPROMISED : INACTIVE;
        emit Revoked(owner, fpHash, index, _reasonName(reason), replacedBy, msg.sender);
    }

    function _setRecord(address owner, uint256 index, string calldata kind, string calldata value) internal {
        (bytes memory name, bytes32 kindHash) = _kindName(kind);
        bytes calldata v = bytes(value);
        if (v.length > MAX_RECORD_BYTES) revert RecordTooLarge(v.length, MAX_RECORD_BYTES);

        if (v.length == 0) {
            _claimAt(owner, index);
            delete _recordValue[owner][_setOf(owner, index)][kindHash];
        } else {
            _activeClaim(owner, index);
            uint256 set = _setOf(owner, index);
            bytes32 word = v.length <= 31
                // forge-lint: disable-next-line(unsafe-typecast) only values of 31 bytes or less are packed
                ? bytes32(uint256(v.length) << 248) | (bytes32(v) >> 8)
                : RECORD_POINTER | bytes32(uint256(uint160(SSTORE2.writeOnce(v))));
            if (_recordValue[owner][set][kindHash] == 0) _rememberKind(owner, set, name);
            _recordValue[owner][set][kindHash] = word;
        }
        emit RecordSet(owner, index, kindHash, string(name), value, msg.sender);
    }

    /// Add a record name to the set's list the first time it is used there.
    function _rememberKind(address owner, uint256 set, bytes memory name) internal {
        bytes32 packed = _packName(name);
        mapping(uint256 => bytes32) storage names = _recordKinds[owner][set];
        uint256 i;
        for (bytes32 w = names[0]; w != 0; w = names[++i]) {
            if (w == packed) return;
        }
        names[i] = packed;
    }

    function _authorize(address owner, bytes32 structHash, uint256 deadline, bytes calldata permission) internal {
        if (block.timestamp > deadline) revert PermissionExpired(deadline);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));

        // A plain signature first: EOAs, including accounts with EIP-7702 code. Canonical only: low s,
        // v of 27 or 28. A contract's address can never be an ECDSA signer.
        bool ok;
        if (permission.length == 65) {
            bytes32 r = bytes32(permission[0:32]);
            bytes32 s = bytes32(permission[32:64]);
            uint8 v = uint8(permission[64]);
            if (uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0 && (v == 27 || v == 28)) {
                address recovered = ecrecover(digest, v, r, s);
                ok = recovered != address(0) && recovered == owner;
            }
        }
        // Then EIP-1271 for accounts with code.
        if (!ok && owner.code.length > 0) {
            (bool success, bytes memory ret) = owner.staticcall(abi.encodeWithSelector(ERC1271_MAGIC, digest, permission));
            ok = success && ret.length >= 32 && abi.decode(ret, (bytes32)) == bytes32(ERC1271_MAGIC);
        }
        if (!ok) revert InvalidPermission();

        uint256 used = nonces[owner];
        unchecked { nonces[owner] = used + 1; }
        emit NonceUsed(owner, used);
    }

    // ─── Reading storage and helpers ─────────────────────────────────────────

    /// Size checks and the first-byte format check. Returns the message version.
    function _checkPayload(bytes calldata signature, bytes calldata key) internal pure returns (uint8 messageVersion) {
        if (signature.length == 0) revert EmptySignature();
        if (signature.length > MAX_SIGNATURE_BYTES) revert SignatureTooLarge(signature.length, MAX_SIGNATURE_BYTES);
        _checkKey(key, signature.length);

        bytes1 s = signature[0];
        // Signature packet tag, old-style (gpg) or new-style (openpgp.js) header.
        if (s == 0x88 || s == 0x89 || s == 0x8A || s == 0xC2) return MESSAGE_DETACHED;
        if (signature.length >= CLEARSIGN_HEADER.length && keccak256(signature[:CLEARSIGN_HEADER.length]) == keccak256(CLEARSIGN_HEADER)) {
            return MESSAGE_CLEARSIGNED;
        }
        revert NotASignature(s);
    }

    function _checkKey(bytes calldata key, uint256 signatureLength) internal pure {
        if (key.length == 0) revert EmptyKey();
        if (key.length > MAX_KEY_BYTES) revert KeyTooLarge(key.length, MAX_KEY_BYTES);
        if (signatureLength + key.length > MAX_PAYLOAD_BYTES) {
            revert PayloadTooLarge(signatureLength + key.length, MAX_PAYLOAD_BYTES);
        }
        bytes1 k = key[0];
        // Public-key packet tag, old-style or new-style header.
        if (k != 0x98 && k != 0x99 && k != 0x9A && k != 0xC6) revert NotAKey(k);
    }

    function _claimAt(address owner, uint256 index) internal view returns (Claim storage) {
        uint256 count = _claims[owner].length;
        if (index >= count) revert IndexOutOfBounds(index, count);
        return _claims[owner][index];
    }

    function _activeClaim(address owner, uint256 index) internal view returns (Claim storage c) {
        c = _claimAt(owner, index);
        if (c.revokedAt != 0) revert AlreadyRevoked(index);
    }

    function _setOf(address owner, uint256 index) internal view returns (uint256) {
        uint256 s = _recordSet[owner][index];
        return s == 0 ? index : s - 1;
    }

    function _payload(Claim storage c) internal view returns (bytes memory sig, bytes memory key) {
        address p = c.payload;
        uint256 sigLen = _signatureLength(p);
        sig = SSTORE2.readRange(p, 2, sigLen);
        key = SSTORE2.readRange(p, 2 + sigLen, p.code.length - 1 - 2 - sigLen);
    }

    function _signature(Claim storage c) internal view returns (bytes memory) {
        address p = c.payload;
        return SSTORE2.readRange(p, 2, _signatureLength(p));
    }

    function _signatureLength(address p) internal view returns (uint256) {
        bytes memory head = SSTORE2.readRange(p, 0, 2);
        return (uint256(uint8(head[0])) << 8) | uint256(uint8(head[1]));
    }

    function _view(address owner, uint256 index) internal view returns (ClaimView memory v) {
        Claim storage c = _claimAt(owner, index);
        uint8 reason = (c.flags >> 4) & 7;
        v.index = index;
        v.fingerprint = _fingerprintBytes(c.fingerprint, c.flags & 1 == 1);
        // forge-lint: disable-next-line(unsafe-typecast) EPOCH + a uint32 fits in 64 bits
        v.createdAt = uint64(EPOCH + c.createdAt);
        // forge-lint: disable-next-line(unsafe-typecast) EPOCH + a uint32 fits in 64 bits
        v.revokedAt = c.revokedAt == 0 ? 0 : uint64(EPOCH + c.revokedAt);
        v.state = c.revokedAt == 0 ? "active" : (c.replacedBy != 0 ? "replaced" : "revoked");
        v.replacedBy = c.replacedBy == 0 ? 0 : uint256(c.replacedBy) - 1;
        v.revokeReason = _reasonName(reason);
        v.messageVersion = _messageVersion(c.flags);
    }

    function _readRecord(bytes32 word) internal view returns (bytes memory out) {
        if (word == 0) return out;
        uint256 len = uint8(word[0]);
        if (len == 0xFF) return SSTORE2.read(address(uint160(uint256(word))));
        out = new bytes(len);
        for (uint256 i; i < len; ++i) out[i] = word[1 + i];
    }

    /// Seconds since EPOCH in 32 bits: exact until 2162, then it wraps (accepted; see revoke's guard).
    function _now() internal view returns (uint32) {
        if (block.timestamp <= EPOCH) return 0;
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(block.timestamp - EPOCH);
    }

    function _messageVersion(uint8 flags) internal pure returns (uint8) {
        return (flags >> 1) & 7;
    }

    function _fingerprintBytes(bytes32 w, bool v6) internal pure returns (bytes memory) {
        // forge-lint: disable-next-line(unsafe-typecast) v4 fingerprints are the top 20 bytes
        return v6 ? abi.encodePacked(w) : abi.encodePacked(bytes20(w));
    }

    function _fingerprintHash(Claim storage c) internal view returns (bytes32) {
        return keccak256(_fingerprintBytes(c.fingerprint, c.flags & 1 == 1));
    }

    function _reasonCode(string calldata reason) internal pure returns (uint8) {
        bytes32 h = keccak256(bytes(reason));
        if (bytes(reason).length == 0) return REASON_NONE;
        if (h == keccak256("compromised")) return REASON_COMPROMISED;
        if (h == keccak256("retired")) return REASON_RETIRED;
        if (h == keccak256("superseded")) return REASON_SUPERSEDED;
        if (h == keccak256("other")) return REASON_OTHER;
        revert UnknownRevokeReason(reason);
    }

    function _reasonName(uint8 code) internal pure returns (string memory) {
        if (code == REASON_COMPROMISED) return "compromised";
        if (code == REASON_RETIRED) return "retired";
        if (code == REASON_SUPERSEDED) return "superseded";
        if (code == REASON_OTHER) return "other";
        return "";
    }

    /// A record name, checked and made canonical: lowercase a-z, 0-9, '.', '-'; a name without a dot
    /// means "thurin.<name>". Returns the canonical name and its hash (the key records live under).
    function _kindName(string calldata kind) internal pure returns (bytes memory name, bytes32 kindHash) {
        bytes calldata k = bytes(kind);
        if (k.length == 0 || k.length > MAX_KIND_BYTES) revert InvalidKindName(kind);
        bool dotted;
        for (uint256 i; i < k.length; ++i) {
            bytes1 ch = k[i];
            bool ok = (ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9") || ch == "-" || ch == ".";
            if (!ok) revert InvalidKindName(kind);
            if (ch == ".") dotted = true;
        }
        if (dotted) name = k;
        else name = abi.encodePacked("thurin.", k);
        if (name.length > MAX_KIND_BYTES) revert InvalidKindName(kind);
        kindHash = keccak256(name);
    }

    /// A name of up to 31 bytes in one word: the bytes left-aligned, the length in the last byte.
    function _packName(bytes memory name) internal pure returns (bytes32 w) {
        // forge-lint: disable-next-line(unsafe-typecast) names are at most 31 bytes (checked by _kindName)
        w = bytes32(name) | bytes32(name.length);
    }

    function _unpackName(bytes32 w) internal pure returns (bytes memory name) {
        uint256 len = uint8(w[31]);
        name = new bytes(len);
        for (uint256 i; i < len; ++i) name[i] = w[i];
    }

    function _hexLower(address a) internal pure returns (string memory) {
        bytes memory digits = "0123456789abcdef";
        bytes memory out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        uint160 x = uint160(a);
        for (uint256 i; i < 20; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast) one byte of the address at a time
            uint8 b = uint8(x >> (8 * (19 - i)));
            out[2 + 2 * i] = digits[b >> 4];
            out[3 + 2 * i] = digits[b & 15];
        }
        return string(out);
    }
}
