# Session Context — libpam-web3 feature/opnet

**Generated:** 2026-02-17
**Branch:** `feature/opnet` (up-to-date with origin)
**Before starting:** Read `SPECIAL.md`, `CLAUDE.md`, then this file.

---

## What Was Done This Session

### 1. Interface Simplification (v0.7.0)

Consolidated two auth paths (wallet-file lookup + blockchain NFT query) into one unified GECOS wallet address lookup. The engine's reconciler now owns chain relationships; libpam-web3 is a pure signature/credential verification module.

### 2. Dual-Stack Bind Fix (c396fae)

Fixed `web3-auth-svc` EADDRINUSE when binding both `[::]` and `0.0.0.0`. Changed default to `["::]"` only.

### 3. Extract web3-auth-svc (v0.8.0)

Moved `web3-auth-svc/` and `signing-page/` out of libpam-web3. Auth service now ships with the engine template package. Callback mode is detected at runtime (directory existence) instead of config flag.

**Removed:**
- `web3-auth-svc/` — entire directory (Rust crate, config, systemd unit)
- `signing-page/` — HTML signing page
- `callback_enabled` and `callback_grace_seconds` from config
- web3-auth-svc binary, signing page, systemd unit from .deb packaging
- signing-page from tools .deb packaging

**Modified:**
- `src/config.rs` — removed callback config fields
- `src/lib.rs` — runtime callback detection via directory existence, constant grace period
- `packaging/build-deb.sh` — PAM module only, no auth-svc
- `packaging/build-deb-tools.sh` — removed signing-page references
- `CLAUDE.md` — updated architecture, build commands, config format
- `PROJECT.yaml` — updated to v0.8.0 with changelog

---

## Current Architecture

```
src/
├── lib.rs           # PAM entry point, signature detection, auth orchestration
├── callback.rs      # Callback session management (file IPC, unchanged)
├── config.rs        # TOML config: [machine] + [auth] only
├── otp.rs           # OTP generation (HMAC-SHA3, unchanged)
├── signature.rs     # secp256k1 ecrecover (unchanged)
├── passwd_lookup.rs # GECOS wallet=ADDRESS lookup (case-insensitive)
├── ecies.rs         # Encryption schemes (unchanged, used by pam_web3_tool)
└── bin/
    └── pam_web3_tool.rs  # CLI tool (unchanged)

contracts/           # Solidity: AccessCredentialNFT (ERC-721)
```

## Authentication Flow

1. PAM generates OTP (HMAC-SHA3, bound to machine_id + timestamp)
2. If `/run/libpam-web3/pending/` exists: create session file, append `?session=` to URL
3. Display OTP + signing URL to user
4. Get signature (callback poll or terminal paste)
5. **Content-based detection:**
   - Try JSON parse → if `{otp, machine_id, wallet_address}` → **OPNet path**: validate OTP, use wallet_address
   - Otherwise → **EVM path**: ecrecover → wallet address
6. GECOS lookup: scan `/etc/passwd` for `wallet=ADDRESS` (case-insensitive)
7. Match found → authenticate as that user

## Config Format

```toml
[machine]
id = "server-name"
secret_key = "0x..."

[auth]
signing_url = "https://..."
otp_length = 6
otp_ttl_seconds = 300
```

Callback mode is detected at runtime — no config flag needed.

## GECOS Format

```
wallet=0x1234...abcd,nft=5
```
- `wallet=ADDRESS` — required for auth (case-insensitive match, chain-agnostic)
- `nft=TOKEN_ID` — optional metadata (preserved for reconciliation)

## Key Deps (PAM module Cargo.toml)

No feature flags. All deps unconditional:
- `pam` 0.8, `alloy-primitives` 0.8, `k256` 0.13, `sha3` 0.10, `rand` 0.8, `hex` 0.4
- `libc` 0.2, `thiserror` 2, `serde` 1, `serde_json` 1, `toml` 0.8
- `ecies` 0.2, `aes-gcm` 0.10, `crypto_box` 0.9, `base64` 0.22, `hkdf` 0.12, `sha2` 0.10, `clap` 4

## Known Issues / Warnings

- `examples/config-nft.toml` and `examples/config-wallet.toml` are stale (reference removed config sections) — should be updated or removed
