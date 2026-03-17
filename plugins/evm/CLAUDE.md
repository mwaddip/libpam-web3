# libpam-web3-evm

EVM signing page and auth service for libpam-web3.

## Architecture

```
auth-svc-src/index.ts   — HTTPS auth service (Node.js): format validation + .sig writer
signing-page/
  index.html            — MetaMask signing UI (default)
  template.html         — Replaceable HTML/CSS template ({{VARIABLE}} placeholders)
  engine.js             — Wallet detection, personal_sign, callback
web3-auth-svc.service   — Systemd unit
libpam-web3.conf        — tmpfiles.d (creates /run/libpam-web3/pending/)
config.example.toml     — Auth-svc config template (optional)
```

## No Rust Plugin

EVM verification is built into the PAM module (`src/signature.rs` — secp256k1 ecrecover). This package provides only the signing page and callback transport. No plugin binary needed.

## Trust Model

The auth-svc does NOT verify the EVM signature. It validates the format (0x + 130 hex chars) and writes it as-is to the `.sig` file. PAM's built-in ecrecover does the cryptographic verification and wallet address recovery.

## .sig File Format

Raw hex written to `/run/libpam-web3/pending/{sessionId}.sig`:
```
0x + 130 hex chars (65-byte secp256k1 signature)
```

No JSON wrapper — PAM detects this format and dispatches to the built-in EVM path.

## Build

```bash
# Auth-svc bundle (requires Node.js 18+):
npx esbuild auth-svc-src/index.ts --bundle --platform=node --target=node22 --minify --outfile=auth-svc.js

# Full .deb package:
./packaging/build-deb.sh
```

## Install

```bash
sudo dpkg -i packaging/libpam-web3-evm_0.1.0_all.deb
```

## Port

`63108` — derived from `1024 + (crc32("evm") % 64511)`. No config needed.

## Dependencies

- `libpam-web3` (core PAM module)
- `nodejs >= 18` (for auth-svc runtime)
