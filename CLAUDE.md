# libpam-web3

## SPECIAL.md (HIGHEST PRIORITY)

**Read and internalize `SPECIAL.md` at the start of every session.** It defines per-component priority weights — where to invest extra scrutiny beyond standard professional practice. All stats at 5 = normal competence. Stats above 5 = extra focus.

| Component | Profile | Extra focus areas |
|---|---|---|
| `pam_web3_tool` (tools CLI) | S7 P9 E6 C6 I7 A8 L6 | Security (P9 — crypto operations, key handling), Performance (A8 — runs per SSH login) |
| everything else (PAM module) | S8 P10 E7 C5 I8 A8 L7 | Security (P10 — authentication boundary, every code path is a potential auth bypass), Performance (A8 — called on every SSH login) |

See `SPECIAL.md` for full stat definitions and the priority allocation model.

## Environment Variables

**Essential environment variables are stored in `~/projects/sharedenv/`**

- `blockhost.env` - Deployer keys, contract addresses, RPC endpoints

Load before deploying or interacting with contracts:
```bash
source ~/projects/sharedenv/blockhost.env
```

---

## Project Overview

PAM module for Linux authentication via wallet signatures. Verifies identity through signature verification, then maps wallet addresses to Linux usernames via GECOS fields.

Supports two signature types:
- **EVM**: secp256k1 ecrecover (raw hex signature)
- **OPNet**: JSON callback with OTP validation and wallet address

## Architecture

```
src/
├── lib.rs           # PAM entry point, signature detection, auth orchestration
├── callback.rs      # Callback-based signing session management (file IPC)
├── config.rs        # TOML config loading (/etc/pam_web3/config.toml)
├── otp.rs           # OTP generation (HMAC-SHA3, machine_id + timestamp)
├── signature.rs     # secp256k1 ecrecover (personal_sign format)
├── passwd_lookup.rs # GECOS wallet address lookup (wallet=ADDRESS)
├── ecies.rs         # Encryption schemes (secp256k1, x25519, AES-GCM)
└── bin/
    └── pam_web3_tool.rs  # CLI for keypair gen, encryption

contracts/           # Solidity: AccessCredentialNFT (ERC-721)
```

## Build Commands

```bash
cargo build --release                 # PAM module + pam_web3_tool

# Debian packages
./packaging/build-deb.sh              # libpam-web3 (PAM module for VMs)
./packaging/build-deb-tools.sh        # libpam-web3-tools (server tools)
```

## Key Files

| File | Purpose |
|------|---------|
| `/etc/pam_web3/config.toml` | Runtime configuration |
| `/lib/security/pam_web3.so` | Installed PAM module |

## Config Format

```toml
[machine]
id = "server-name"
secret_key = "0x..."      # HMAC key for OTP generation

[auth]
signing_url = "https://..."
otp_length = 6
otp_ttl_seconds = 300
```

## Authentication Flow

1. PAM loads config, generates OTP (HMAC: machine_id + timestamp + secret)
2. If `/run/libpam-web3/pending/` exists: create session file, append `?session=` to URL
3. User sees OTP + signing URL
4. User signs message: `Authenticate to {machine_id} with code: {otp}`
5. Signature delivery (two paths):
   - **Callback mode**: Browser auto-fills OTP/machine from session, POSTs signature to auth service → user presses Enter
   - **Manual mode**: User copy-pastes signature into terminal (fallback when no auth service running)
6. Content-based signature detection:
   - **Raw hex** → EVM path: secp256k1 ecrecover → wallet address
   - **JSON** `{otp, machine_id, wallet_address}` → OPNet path: validate OTP → use wallet address
7. GECOS lookup: scan `/etc/passwd` for `wallet=ADDRESS` match
8. Return username to PAM

## .sig File Content Contract

The `.sig` file (or pasted input) contains either:
- **Raw hex** (EVM): `0x` + 130 hex chars = 65-byte secp256k1 signature
- **JSON** (OPNet): `{"otp":"123456","machine_id":"server","wallet_address":"0x..."}`

JSON parse failure falls through to EVM path (fail-secure: invalid hex → deny).

## GECOS Format

```
wallet=0x1234...abcd,nft=5
```

- `wallet=ADDRESS` — required for authentication (case-insensitive match)
- `nft=TOKEN_ID` — optional metadata (token ID for reference)
- Can include other comma-separated fields: `John Doe,wallet=0x...,nft=5`

## Testing

```bash
cargo test                            # All tests
```

## Important Paths

- PAM module: `target/release/libpam_web3.so`
- CLI tool: `target/release/pam_web3_tool`

## Debian Packages

Two separate packages for different deployment targets:

| Package | Install On | Contents |
|---------|------------|----------|
| `libpam-web3` | VMs (client machines) | PAM module, self-signed TLS cert |
| `libpam-web3-tools` | Management server | `pam_web3_tool`, contract artifacts |

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
