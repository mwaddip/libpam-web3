# libpam-web3

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
```

## Key Files

| File | Purpose |
|------|---------|
| `/etc/pam_web3/config.toml` | Runtime configuration |
| `/etc/pam_web3/wallets` | Wallet→username mappings (wallet mode) |
| `/etc/pam_web3/server.key` | Machine ECIES private key (NFT mode) |
| `/lib/security/pam_web3.so` | Installed PAM module |

## Config Format

```toml
[machine]
id = "server-name"
secret_key = "0x..."      # Wallet mode: HMAC key
private_key_file = "..."  # NFT mode: ECIES key path

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
   - NFT: Query blockchain via web3-auth-svc → Check LDAP
7. Return username to PAM

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
