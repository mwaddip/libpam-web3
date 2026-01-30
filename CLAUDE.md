# libpam-web3

## Environment Variables

**Essential environment variables are stored in `~/projects/sharedenv/`**

- `blockhost.env` - Deployer keys, contract addresses, RPC endpoints

Load before deploying or interacting with contracts:
```bash
source ~/projects/sharedenv/blockhost.env
```

---

## Project Overview

PAM module for Linux authentication via Ethereum wallet signatures. Two modes:

- **Wallet mode**: File-based wallet→username mapping (`/etc/pam_web3/wallets`)
- **NFT mode**: Blockchain NFT ownership + LDAP username/revocation lookup

## Architecture

```
src/
├── lib.rs           # PAM entry point, mode dispatch
├── config.rs        # TOML config loading (/etc/pam_web3/config.toml)
├── otp.rs           # OTP generation (HMAC-SHA3, machine_id + timestamp)
├── signature.rs     # secp256k1 ecrecover (personal_sign format)
├── wallet_auth.rs   # Wallet mode: file lookup
├── blockchain.rs    # NFT mode: Unix socket client to web3-auth-svc
├── ldap.rs          # NFT mode: LDAP revocation/username lookup
├── ecies.rs         # NFT mode: 3 encryption schemes (secp256k1, x25519, AES-GCM)
└── bin/
    └── pam_web3_tool.rs  # CLI for keypair gen, encryption

web3-auth-svc/       # Daemon for blockchain queries (separate binary)
contracts/           # Solidity: AccessCredentialNFT (ERC-721)
signing-page/        # Browser wallet signing UI
```

## Build Commands

```bash
cargo build --release                 # Wallet mode only
cargo build --release --features nft  # Full NFT support

# Debian packages (v0.4.0+)
./packaging/build-deb.sh              # libpam-web3 (PAM module for VMs)
./packaging/build-deb-tools.sh        # libpam-web3-tools (server tools)
```

## Key Files

| File | Purpose |
|------|---------|
| `/etc/pam_web3/config.toml` | Runtime configuration |
| `/etc/pam_web3/wallets` | Wallet→username mappings (wallet mode) |
| `/lib/security/pam_web3.so` | Installed PAM module |

Note: `server.key` is NOT required for NFT mode (v0.4.0+). Authentication uses ownership + GECOS matching.

## Config Format

```toml
[machine]
id = "server-name"
secret_key = "0x..."      # Wallet mode: HMAC key

[auth]
mode = "wallet"           # or "nft"
signing_url = "https://..."
otp_length = 6
otp_ttl_seconds = 300

[wallet]                  # Wallet mode only
wallets_path = "/etc/pam_web3/wallets"

[blockchain]              # NFT mode only
socket_path = "/run/web3-auth/web3-auth.sock"
chain_id = 1
nft_contract = "0x..."

[ldap]                    # NFT mode only
server = "ldap://..."
base_dn = "..."
bind_dn = "..."
bind_password_file = "..."
```

## Authentication Flow

1. PAM loads config, generates OTP (HMAC: machine_id + timestamp + secret)
2. User sees OTP + signing URL
3. User signs message: `Authenticate to {machine_id} with code: {otp}`
4. User pastes signature
5. PAM recovers wallet address via ecrecover
6. Mode-specific lookup:
   - Wallet: Check wallets file
   - NFT: Query blockchain for wallet's NFT token IDs → Match against GECOS (`nft=TOKEN_ID`)
7. Return username to PAM

**NFT Mode (v0.4.0+)**: No server private key needed. Authentication is purely ownership-based:
- Wallet owns NFT → Token ID matches GECOS entry → Access granted

## Feature Flags

- Default: wallet mode only (~10 deps)
- `nft`: Adds tokio, ldap3, ecies, aes-gcm, crypto_box, base64, clap

## Testing

```bash
cargo test                            # All tests
cargo test --features nft             # Include NFT module tests
```

## Important Paths

- PAM module: `target/release/libpam_web3.so`
- CLI tool: `target/release/pam_web3_tool` (requires --features nft)
- Web3 service: `web3-auth-svc/target/release/web3-auth-svc`

## Debian Packages (v0.4.0+)

Two separate packages for different deployment targets:

| Package | Install On | Contents |
|---------|------------|----------|
| `libpam-web3` | VMs (client machines) | PAM module, `/etc/pam_web3/config.toml` |
| `libpam-web3-tools` | Management server | `pam_web3_tool`, `web3-auth-svc`, signing page scripts |

## Signing Page Generator

Generate customized signing pages for NFT minting:

```bash
cd signing-page/

# Generate HTML with server pubkey and decrypt message
./generate.sh \
    --server-pubkey "04a1b2c3..." \
    --decrypt-message "Decrypt BlockHost credentials"

# Base64 encode for NFT animationUrlBase64 parameter
./build.sh
# Output: signing-page.b64
```

---

## Rules

### Pre-Push Checklist

**ALWAYS check before committing/pushing:**

1. **No private keys**: Search for hex strings 64+ chars, `0x` prefixed secrets
2. **No passwords**: Check for hardcoded credentials, `.secret` files
3. **No API keys**: Etherscan keys, RPC URLs with keys
4. **No deployment artifacts**: `broadcast/`, `out/`, `cache/`
5. **No build artifacts**: `target/`, `node_modules/`
6. **No local configs**: Files with real server IPs, domains, or user data

**Quick check command:**
```bash
git diff --cached --name-only | xargs grep -l -E '(0x[a-fA-F0-9]{64}|password|secret|apikey|private.?key)' 2>/dev/null
```

**Files that should NEVER be committed:**
- `*.key`, `*.secret`, `*.pem`
- `.env`, `.env.*`
- `config.toml` with real credentials
- `ldap.secret`, `server.key`

---

## Subproject Documentation

Each major component has its own documentation:

| Directory | Documentation | Purpose |
|-----------|---------------|---------|
| `contracts/` | `CLAUDE.md`, `PROJECT.yaml` | Smart contract specs, encryption flows |
| `web3-auth-svc/` | (see directory) | Blockchain query daemon |
| `signing-page/` | (see directory) | Browser signing UI |

### PROJECT.yaml Maintenance (CRITICAL)

**You MUST maintain `PROJECT.yaml` files when modifying code.**

These files are machine-readable specifications that:
- Document architecture, flows, and privacy properties
- Enable future Claude sessions to understand the codebase
- Track breaking changes and migration paths

**When to update PROJECT.yaml:**
- Adding/modifying functions or data structures
- Changing encryption or authentication flows
- Adding features or making breaking changes
- Updating dependencies or build processes

**The `contracts/PROJECT.yaml` is especially important** as it documents:
- Privacy model (hostnames NEVER in plaintext on-chain)
- Encryption flows (ECIES for server, AES-GCM for user)
- Complete NFT minting and authentication flows
- Contract interface and function signatures

---

## Authentication Model (NFT Mode v0.4.0+)

**Simple ownership-based authentication. No server-side decryption needed.**

```
Authentication Flow:
  1. User signs OTP challenge → proves wallet ownership
  2. PAM queries blockchain → gets wallet's NFT token IDs
  3. PAM checks /etc/passwd GECOS → finds entry with nft=TOKEN_ID
  4. Match found → user authenticated as that Linux user
```

**Server requirements (minimal):**
- Contract address (public)
- RPC endpoint (public)
- GECOS entries mapping token IDs to Linux users

**No server private keys needed.** The `serverEncrypted` field was removed in v0.4.0.

**Optional `userEncrypted` field:**
- Stores connection details encrypted with signature-derived key (AES-GCM)
- Only the NFT holder can decrypt by re-signing the `decryptMessage`
- Purely for user convenience - authentication works without it
