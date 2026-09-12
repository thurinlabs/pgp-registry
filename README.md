# PGPRegistry

On-chain PGP-to-Ethereum identity claims. This contract is the registry behind the attestation flow at [thurin.id/attest](https://thurin.id/attest). Each attestation binds an Ethereum address to a PGP key fingerprint, and the two vouch for each other: the claim is published from (or authorized by) the address it names, and the signed payload proving key ownership is stored with it — readably, so any RPC can serve it with a plain `eth_call`.

A [Thurin Labs](https://thurinlabs.id) project.

## v2

Version 2 is a fresh deployment (2026-09). Same trust model as v1 — permissionless, immutable, no admin, no fees, no on-chain PGP parsing — with a new shape:

| | v1 | v2 |
|---|---|---|
| Payload | only in the `Attested` event (log scans) | SSTORE2 data contracts, read with `getPayload` |
| Replace a claim | `revoke` + `attest` | `reattest` (one transaction) |
| Add proofs to a key | new attestation + new signature | `updateKey` (same fingerprint, no re-sign) |
| Who can write | `msg.sender` only | owner directly, **or** anyone with the owner's EIP-712 authorization |
| Lookups | log scans | `addressesFor(fingerprintHash)`, `fingerprintsForKeyId(keyId)`, `current`, `attestationsOf` |
| Fingerprint | 40-char hex string | raw `bytes` — 20 (v4) or 32 (v6) |
| Extension point | — | bounded typed records per attestation |
| Version check | — | `VERSION()` returns 2 |

Design record: the `ADR-registry-v2` note in the Thurin Labs vault.

### Deployments

| Network | Address | Deploy block |
|---|---|---|
| Sepolia | [`0x9302E02e2869e129aC8516fE5eFFd51EA3082c09`](https://sepolia.etherscan.io/address/0x9302E02e2869e129aC8516fE5eFFd51EA3082c09) | 11683667 |
| Ethereum mainnet | [`0x9302E02e2869e129aC8516fE5eFFd51EA3082c09`](https://etherscan.io/address/0x9302E02e2869e129aC8516fE5eFFd51EA3082c09) | 25962908 |

The address is the same on every chain: the deploy script uses CREATE2 via the canonical deployer with salt `keccak256("thurin.pgp-registry.v2")`. Predicted from the current source: `0x9302E02e2869e129aC8516fE5eFFd51EA3082c09` (bytecode must be built from the same commit and settings).

v1 (legacy, still on-chain, no longer read by Thurin): mainnet [`0xf7a45BC662A78a6fb417ED5f52b3766cbf13EbBb`](https://etherscan.io/address/0xf7a45BC662A78a6fb417ED5f52b3766cbf13EbBb), source in `legacy/`.

## Interface

```solidity
// direct — msg.sender is the owner and pays gas
function attest(bytes fingerprint, bytes pgpSignature, bytes pgpPublicKey) returns (uint256 index);
function reattest(uint256 revokeIndex, bytes fingerprint, bytes pgpSignature, bytes pgpPublicKey) returns (uint256 index);
function updateKey(uint256 index, bytes pgpPublicKey);
function revoke(uint256 index);
function setRecord(uint256 index, bytes32 kind, bytes value);   // empty value clears (allowed on revoked entries too)
function cancelAuthorization();                                  // burn the caller's current nonce

// authorized — same actions, owner signs EIP-712, anyone submits and pays gas
function attestFor(address owner, bytes fingerprint, bytes pgpSignature, bytes pgpPublicKey, uint256 deadline, bytes signature) returns (uint256);
function reattestFor(address owner, uint256 revokeIndex, bytes fingerprint, bytes pgpSignature, bytes pgpPublicKey, uint256 deadline, bytes signature) returns (uint256);
function updateKeyFor(address owner, uint256 index, bytes pgpPublicKey, uint256 deadline, bytes signature);
function revokeFor(address owner, uint256 index, uint256 deadline, bytes signature);
function setRecordFor(address owner, uint256 index, bytes32 kind, bytes value, uint256 deadline, bytes signature);
function nonces(address owner) view returns (uint256);
function DOMAIN_SEPARATOR() view returns (bytes32);

// views
function attestationCount(address owner) view returns (uint256);
function getAttestation(address owner, uint256 index) view returns (Attestation);
function getPayload(address owner, uint256 index) view returns (bytes pgpSignature, bytes pgpPublicKey);
function attestationsOf(address owner) view returns (Attestation[]);
function current(address owner) view returns (bool found, uint256 index, Attestation);
function record(address owner, uint256 index, bytes32 kind) view returns (bytes);
function addressesFor(bytes32 fingerprintHash) view returns (address[]);      // keccak256(raw fingerprint)
function fingerprintsForKeyId(bytes8 keyId) view returns (bytes[]);          // long key ID: v4 = last 8 bytes, v6 = first 8 (RFC 9580)
// paginated forms for large sets: attestationsOfRange, addressesForCount/Range, fingerprintsForKeyIdCount/Range
```

`Attestation { bytes fingerprint; uint64 createdAt; uint64 revokedAt; uint8 messageVersion; address keyPtr; address sigPtr; }` — `revokedAt == 0` means active. Limits: key ≤ 8192 bytes, signature ≤ 4096, record ≤ 1024, fingerprint 20 or 32 bytes. One active attestation per (owner, fingerprint); use `reattest` to replace.

The clearsigned message (`messageVersion` 1) is exactly:

```
I control the Ethereum address: 0x<lowercase address>
```

### Authorized writes

The `…For` functions are a second door, not a replacement. The owner signs an EIP-712 struct (domain `Thurin PGPRegistry` / `2` / chain id / this contract) that binds every parameter, the owner's current nonce, and a deadline. Whoever submits it pays the gas and is recorded as `submitter` in the event; they cannot alter, reuse, or delay it past the deadline. Contract wallets are checked through EIP-1271. Thurin does not run a relayer; the app uses the direct functions.

```
Attest(address owner,bytes fingerprint,bytes pgpSignature,bytes pgpPublicKey,uint256 nonce,uint256 deadline)
Reattest(address owner,uint256 revokeIndex,bytes fingerprint,bytes pgpSignature,bytes pgpPublicKey,uint256 nonce,uint256 deadline)
UpdateKey(address owner,uint256 index,bytes pgpPublicKey,uint256 nonce,uint256 deadline)
Revoke(address owner,uint256 index,uint256 nonce,uint256 deadline)
SetRecord(address owner,uint256 index,bytes32 kind,bytes value,uint256 nonce,uint256 deadline)
```

`script/Authorize.s.sol` produces a signature from a keystore or hardware wallet without broadcasting; hand it to `cast send … "attestFor(...)"` from any funded account.

### Gas (Foundry, fixture key of 656 bytes)

| Action | Gas |
|---|---|
| `attest` | ~560k |
| `reattest` | ~399k |
| `updateKey` | ~172k |
| `revoke` | ~5k |

Roughly 200 gas per payload byte on top of fixed costs, which is why the app strips email user IDs before publishing.

## Layout

```
PGPRegistry.sol       # the v2 contract
SSTORE2.sol           # minimal vendored SSTORE2 (write = CREATE, read = EXTCODECOPY)
PGPRegistry.t.sol     # v2 test suite (62 tests + invariants + gas probe + EIP-712 vectors)
legacy/               # v1 contract + its 28 tests, kept for reference
script/               # Deploy (CREATE2) / Attest / Revoke / Authorize + fixtures
broadcast/            # deployment records
```

## Development

Requires [Foundry](https://getfoundry.sh). Compiled with solc 0.8.24, via-IR, optimizer 200 runs, `bytecode_hash = none` / `cbor_metadata = false` so the CREATE2 address depends only on the code and settings, not on comments or file paths.

```bash
git clone --recurse-submodules https://github.com/thurinlabs/pgp-registry
forge build
forge test
forge snapshot
```

Deploy (dry run first, then with `--broadcast --verify`):

```bash
forge script script/Deploy.s.sol --rpc-url sepolia --account <keystore>
```

## Links

- [Attest](https://thurin.id/attest) — create identity claims
- [Thurin](https://thurin.id) — look up and verify identities
- [Contract docs](https://docs.thurin.id/#/contracts)
- [GitHub](https://github.com/thurinlabs)
