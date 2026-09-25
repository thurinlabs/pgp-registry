# PGPRegistry

The contract behind [Thurin.id](https://thurin.id). A claim puts a PGP key on an Ethereum address: the key, and the key's signature over `I control the Ethereum address: 0x…`. Anyone can publish one, only the address can change it, and nobody can take it down. No owner, no admin, no fees, no upgrades.

The contract is the tool: everything works from Etherscan or `cast` with gpg. `armoredKey` gives a key ready for `gpg --import`, `clearsigned` a statement ready for `gpg --verify`, and `armorToBytes` turns pasted armor into the bytes a write form wants.

Full reference: [docs.thurin.id/#/contracts](https://docs.thurin.id/#/contracts).

## Address

`0xFa6956c11163517249f8A67F5560a4406B519451`, the same on Ethereum mainnet and Sepolia: deployed through the canonical CREATE2 deployer (`0x4e59…956C`) with salt `keccak256("thurin.pgp-registry.v3")`. The address depends only on the code and the settings in `foundry.toml`.

## In short

```solidity
attest(bytes fingerprint, bytes signature, bytes key) → uint256 index
reattest(uint256 revokeIndex, bytes fingerprint, bytes signature, bytes key, bool keepRecords) → uint256 index
updateKey(uint256 index, bytes key)
revoke(uint256 index, string reason)                  // "", "compromised", "retired", "other"
setRecord(uint256 index, string kind, string value)   // "" clears
```

Each has a `…For` twin that anyone can send with the owner's EIP-712 permission, so the owner never needs ETH, plus `markCompromisedFor` for marking a revoked claim compromised later. Reads include `claimsOf`, `current`, `summary`, `keyStatus`, `recordsOf`, `ownersOf`, and `fingerprintsForKeyId`.

- Keys and signatures are stored as raw bytes (SSTORE2), one blob per claim: key ≤ 16 KB, signature ≤ 8 KB, 24,000 bytes together.
- A claim is 2 storage slots. Records are named text, ≤ 1 KB.
- "compromised" is final per address: it can never claim that key again.
- The contract checks formats, not PGP signatures. Readers verify (gpg, [identity-kit](https://github.com/thurinlabs/identity-kit)).

Gas for gpg's default Ed25519 key: attest 430k, updateKey 295k, reattest 640k, revoke 43k, a short record 81k.

## Layout

```
PGPRegistry.sol              the contract
Armor.sol                    ASCII armor and clearsign, for the text views
SSTORE2.sol                  write-once storage in contract code
PGPRegistry*.t.sol           tests: units, claim states, EIP-712 vectors, invariants
script/Deploy.s.sol          CREATE2 deploy
fixtures/                    real gpg output the tests read
legacy/                      earlier versions, for reference
```

## Build

[Foundry](https://getfoundry.sh). solc 0.8.37, via-IR, optimizer 200, EVM cancun, no metadata hash.

```bash
git clone --recurse-submodules https://github.com/thurinlabs/pgp-registry && cd pgp-registry
forge build
forge test
```

The address this code deploys to, which should be the one above:

```bash
cast create2 --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956C --salt $(cast keccak thurin.pgp-registry.v3) \
  --init-code-hash $(cast keccak $(forge inspect PGPRegistry bytecode))
```

Deploy (dry run first, then add `--broadcast --verify`):

```bash
forge script script/Deploy.s.sol --rpc-url sepolia --account <keystore>
```

## License

MIT. A [Thurin Labs](https://thurinlabs.id) project.
