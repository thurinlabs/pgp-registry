# PGPRegistry

On-chain PGP-to-Ethereum identity claims. This contract is the registry behind the attestation flow at [thurin.id/attest](https://thurin.id/attest). Each attestation binds an Ethereum address to a PGP key fingerprint, and the two vouch for each other: the claim is published from the address it names, and the signed payload proving key ownership is stored with it.

A [Thurin Labs](https://thurinlabs.id) project.

## Deployment

| Item | Value |
|------|-------|
| Network | Ethereum Mainnet |
| Address | [`0xf7a45BC662A78a6fb417ED5f52b3766cbf13EbBb`](https://etherscan.io/address/0xf7a45BC662A78a6fb417ED5f52b3766cbf13EbBb) |
| Deploy Block | 24515891 |

Broadcast records for the mainnet deployment and Sepolia rehearsals are in `broadcast/`.

## Layout

```
PGPRegistry.sol      # the contract
PGPRegistry.t.sol    # Foundry test suite
script/              # Deploy / Attest / Revoke scripts + attestation fixtures
broadcast/           # deployment records (mainnet + Sepolia)
```

## Development

Requires [Foundry](https://getfoundry.sh).

```bash
git clone --recurse-submodules https://github.com/thurinlabs/pgp-registry
forge build
forge test
```

## Links

- [Attest](https://thurin.id/attest) — create identity claims
- [Thurin](https://thurin.id) — look up and verify identities
- [Contract docs](https://docs.thurin.id/#/contracts)
- [GitHub](https://github.com/thurinlabs)
