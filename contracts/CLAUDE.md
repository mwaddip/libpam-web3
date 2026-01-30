# AccessCredentialNFT - Smart Contract

## Environment Variables

**Load before deploying:** `source ~/projects/sharedenv/blockhost.env`

| Variable | Purpose |
|----------|---------|
| `DEPLOYER_PRIVATE_KEY` | Private key for contract deployment |
| `BLOCKHOST_NFT` | Current AccessCredentialNFT contract address |
| `SEPOLIA_RPC` | Sepolia RPC endpoint |

**After deploying a new contract, update `BLOCKHOST_NFT` in the env file.**

---

## Quick Context

ERC-721 NFT contract for Linux server authentication credentials. Part of the libpam-web3 project.

## Essential Files

| File | Purpose |
|------|---------|
| `PROJECT.yaml` | **CRITICAL** - Machine-readable spec, flows, privacy model |
| `src/AccessCredentialNFT.sol` | Main contract |
| `test/AccessCredentialNFT.t.sol` | Foundry tests |

## Key Commands

```bash
forge build          # Compile
forge test -vv       # Run tests
forge test --summary # Quick test summary
```

## PROJECT.yaml Maintenance

**IMPORTANT**: The `PROJECT.yaml` file is the source of truth for this contract's design and mechanics.

**You MUST update PROJECT.yaml when:**
- Adding/modifying functions
- Changing struct fields
- Altering encryption flows
- Adding new features
- Making breaking changes (update changelog)

**Why this matters:**
- Future Claude sessions rely on PROJECT.yaml to understand the codebase
- The privacy model and encryption flows are complex - document changes
- Breaking changes need clear migration paths in the changelog

## Authentication Model (v0.4.0+)

**Simple ownership-based authentication. No server-side decryption needed.**

Authentication relies on:
1. **Wallet ownership**: User signs OTP challenge to prove wallet control
2. **NFT ownership**: Token ID matches GECOS entry in `/etc/passwd` (format: `nft=TOKEN_ID`)

**Server does NOT need:**
- Private keys (`server.key` is NOT required)
- Decryption of any NFT data
- Access to `serverEncrypted` (field was removed in v0.4.0)

**Optional `userEncrypted` field:**
- Stores connection details (hostname, etc.) encrypted with signature-derived key
- Only the NFT holder can decrypt by re-signing the deterministic `decryptMessage`
- Purely for user convenience - authentication works without it

## Architecture Boundaries

This contract is ONE component of a larger system:

```
[Static Signup Page] → [Sale Contract] → [AccessCredentialNFT] ← [PAM Module]
     (separate)          (separate)          (this repo)           (../src/)
```

- **Signup page**: Client-side encryption, offline-capable (DIFFERENT PROJECT)
- **Sale contract**: Payment handling, calls mint() (DIFFERENT PROJECT)
- **This contract**: Stores encrypted NFTs, provides tokenURI
- **PAM module**: Rust code in parent directory, authenticates users

## Function Signatures

Current `mint()` signature (v0.4.0):
```solidity
mint(address to, bytes userEncrypted, string decryptMessage,
     string description, string imageUri, string animationUrlBase64,
     uint256 expiresAt)
```

Note: `serverEncrypted` was removed in v0.4.0 - authentication uses ownership + GECOS matching.

## Testing New Features

Always add tests for:
1. Happy path functionality
2. Access control (onlyOwner)
3. Edge cases (empty strings, zero values)
4. Integration with tokenURI output

## Common Tasks

### Adding a new field to AccessData
1. Add field to struct in contract
2. Update mint() and mintBatch() signatures
3. Update all test mint calls
4. Update tokenURI if field should appear in metadata
5. **Update PROJECT.yaml** - struct definition, function signatures, changelog

### Adding a new update function
1. Add function with onlyOwner modifier
2. Emit CredentialUpdated event
3. Add test for functionality
4. Add test for access control
5. **Update PROJECT.yaml** - functions section, changelog
