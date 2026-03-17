# Plugin Interface Specification

## Overview

libpam-web3 uses a plugin system for chain-specific signature verification. EVM is built-in (default, stable path). All other chains are plugins — separate repos, separate packages, independently installable.

A single host can have multiple plugins active simultaneously, serving users from different blockchains. Routing is based on the `.sig` file `chain` field (callback path) or raw hex detection (EVM manual paste).

## Architecture

```
libpam-web3 (core)
├── PAM module (pam_web3.so) — OTP, sessions, GECOS lookup, plugin dispatch
├── Built-in EVM verifier — secp256k1 ecrecover
└── Plugin interface spec (this document)

libpam-web3-cardano (plugin repo)
├── Verification plugin — Ed25519/COSE verification
└── web3-auth-svc — HTTPS server (signing page + CIP-30 auth API), port 34206

libpam-web3-opnet (plugin repo)
├── Verification plugin — OTP + wallet_address validation (reference impl built into core)
└── web3-auth-svc — HTTPS server (signing page + ML-DSA auth API), port 32448

(future chains follow the same pattern)
```

## Plugin Package Contents

Each chain plugin repo produces a package that:

1. **Depends on** `libpam-web3` (the core PAM module)
2. **Supplies:**
   - Verification plugin (installed to the plugin discovery path)
   - `web3-auth-svc` binary (self-contained HTTPS server: signing page + auth API)
   - Signing page files (served by the auth-svc)
   - systemd unit for the auth-svc
3. **Registers** itself so PAM can discover it by `chain` name

### Auth-svc Port Convention

Each auth-svc derives its default port deterministically from the chain name:

```
port = 1024 + (crc32(chain_name) % 64511)
```

This gives a stable port in 1024–65534 with no cross-plugin coordination or central registry. CRC32 is available in every language's stdlib. The PAM module uses the same formula to construct the signing URL.

| Chain | Port |
|-------|------|
| `cardano` | 34206 |
| `opnet` | 32448 |

No config file is needed — port is derived, TLS certs come from the `libpam-web3` postinst (`/etc/libpam-web3/tls/`). A config file can override the port if needed.

### Auth-svc Responsibilities

Each auth-svc is a self-contained HTTPS server that:

1. **Serves the signing page** at `GET /` (`index.html`) and `GET /engine.js`
2. **Serves session data** at `GET /auth/pending/:session_id`
3. **Accepts callbacks** at `POST /auth/callback/:session_id`
4. **Writes `.sig` files** to `/run/libpam-web3/pending/`
5. **Terminates TLS** using the postinst-generated certs
6. **Binds to `::` (all interfaces)** — publicly reachable on the derived port

## Dispatch Flow

```
User connects via SSH as <username>
        │
        ▼
PAM reads username, looks up GECOS wallet= for that user
        │
        ▼
PAM generates OTP, creates session file
        │
        ▼
User signs in browser (chain-specific signing page)
        │
        ▼
Auth-svc writes .sig file to /run/libpam-web3/pending/{session_id}.sig
        │
        ▼
PAM reads .sig file
        │
        ├── Raw hex (0x + 130 chars) ──► EVM built-in ecrecover
        │
        └── JSON with "chain" field ──► Lookup plugin by chain name
                │
                ├── Plugin found ──► Invoke plugin (pass .sig, OTP message, wallet address)
                │                           │
                │                    Plugin returns: wallet address / denied
                │
                └── Plugin not found ──► Auth denied (UnsupportedChain)
        │
        ▼
PAM confirms returned wallet matches GECOS wallet (case-insensitive)
```

Manual paste → always EVM (no plugin dispatch). PAM confirms the ecrecovered address matches GECOS.

## Plugin Interface Contract

### Form Factor

Standalone executable. PAM invokes it as a subprocess, passes JSON on stdin, reads the result from stdout and exit code. Language-agnostic, crash-isolated.

### Input (stdin)

JSON object, single line:

```json
{"sig": <full .sig JSON>, "otp_message": "Authenticate to {machine_id} with code: {otp}", "wallet_address": "<from GECOS>"}
```

| Field | Description |
|-------|-------------|
| `sig` | Full `.sig` file content as a JSON object (includes `chain` and all chain-specific fields) |
| `otp_message` | The message the user was expected to sign |
| `wallet_address` | The `wallet=` value from the user's GECOS field (PAM looks up the SSH username) |

### Output

- **stdout:** Wallet address on success (single line, trimmed). This is the address PAM matches against GECOS `wallet=`.
- **exit 0:** Signature verified, stdout contains the wallet address.
- **exit non-zero:** Verification failed. stderr may contain a reason (logged by PAM).

### Timeout

Plugins have 10 seconds to complete. PAM kills the process after timeout (auth denied).

### Responsibilities

| Responsibility | Owner |
|---------------|-------|
| OTP generation | libpam-web3 (core) |
| Session file creation / `.sig` polling | libpam-web3 (core) |
| GECOS parsing (`wallet=`, `nft=`) | libpam-web3 (core) |
| GECOS wallet matching | libpam-web3 (core) — compares plugin's returned address against GECOS |
| `.sig` file format (writing) | Auth-svc (plugin package) |
| `.sig` file reading + `chain` dispatch | libpam-web3 (core) |
| Signature verification | Plugin — verifies the signature is authentic |
| Wallet address derivation | Plugin — returns the address to PAM on stdout |
| Auth decision (yes/no) | libpam-web3 (core), based on plugin result + GECOS match |

### What the auth-svc does NOT do

The auth-svc is internet-facing. Its job is to **sanitize and transport**, not authenticate:
- Accept the wallet signature from the browser
- Validate structural correctness (is this plausibly a real signature?)
- Write a well-formed `.sig` file
- It does **not** verify identity — that's the plugin's job inside PAM

## Plugin Discovery

Plugins are installed to a well-known directory. PAM reads the `chain` field from the `.sig` file and looks up the corresponding plugin.

**Discovery path:** `/usr/lib/libpam-web3/plugins/`

**Naming convention:** `{chain}` — e.g. `opnet`, `cardano`

When PAM encounters `"chain": "cardano"` in a `.sig` file, it looks for `/usr/lib/libpam-web3/plugins/cardano`.

## Implementation

Plugins are standalone executables. PAM invokes them as subprocesses — no ABI coupling, language-agnostic, crash-isolated. The ~5-10ms subprocess overhead is negligible for SSH login.

**Source:** `src/plugin.rs` in libpam-web3.

## Signing URL

PAM derives the signing URL at auth time entirely from state — no config needed:

```
https://{fqdn}:{chain_port}[?session={session_id}]
```

| Component | Source |
|-----------|--------|
| `fqdn` | `gethostname()` (FQDN if cloud-init set it), else `/etc/hosts` FQDN lookup, else short hostname |
| `chain_port` | `1024 + (crc32(chain_name) % 64511)` — deterministic from the chain name |
| `session` | Session ID appended when a callback session is active |

Each chain's auth-svc listens on its derived port and serves both the signing page and the auth API. No signing URL config, no central routing server.

Plugins do **not** return a `signing_url` — PAM constructs it independently.

## Multi-Chain Coexistence

Multiple plugins can be active on the same host:

- Each chain's auth-svc listens on its own derived port (no port conflicts by design)
- All auth-svcs write to the same `/run/libpam-web3/pending/` directory
- Session IDs are 128-bit random hex — collision-free across chains
- PAM reads the `.sig` file, routes by `chain` field to the correct plugin
- GECOS `wallet=` field is chain-agnostic — the plugin interprets the address format

**Example:** A host with EVM, Cardano, and OPNet users:
```
/etc/passwd:
  alice:x:1001:1001:wallet=0xAbCd...1234:/home/alice:/bin/bash          # EVM
  bob:x:1002:1002:wallet=addr1q9x...7f3k:/home/bob:/bin/bash            # Cardano
  carol:x:1003:1003:wallet=bc1q...m4wz:/home/carol:/bin/bash            # OPNet
```

Signing URLs shown during login (ports derived from chain name via CRC32):
```
alice → https://host.example.com:63108?session=...    # crc32("evm")    → 63108
bob   → https://host.example.com:34206?session=...    # crc32("cardano") → 34206
carol → https://host.example.com:32448?session=...    # crc32("opnet")   → 32448
```

## Installation

Plugins are installed via:

1. **Git submodules** — user checks out the plugin repos they want
2. **Install wizard** — `install_plugins.sh` (or equivalent) sets up build requirements and installs selected plugins

The core `libpam-web3` package is always installed first. Plugin packages declare it as a dependency.

## Adding a New Chain

To add support for a new blockchain:

1. Create a new repo: `libpam-web3-{chain}`
2. Implement the verification plugin (per the interface contract above)
3. Implement the auth-svc (self-contained HTTPS server: signing page + auth API + `.sig` writer)
   - Use `chainPort("{chain}")` for the default port
   - Use `/etc/libpam-web3/tls/` for TLS certs (generated by libpam-web3 postinst)
4. Implement the signing page (`index.html`, `engine.js`)
5. Package as a `.deb` that depends on `libpam-web3`:
   - Plugin binary → `/usr/lib/libpam-web3/plugins/{chain}`
   - Auth-svc binary + signing page + systemd unit
6. Add a spec to `docs/specs/{chain}.md` in the core repo

No config file edits needed — port is derived from the chain name, TLS certs are shared from the core package.
