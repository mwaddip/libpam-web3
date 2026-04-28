# EVM Authentication Spec

Chain identifier: `"evm"`

## Signature Type

secp256k1 ECDSA (`personal_sign` / EIP-191 prefix).

## Signed Message Format

```
Authenticate to {machine_id} with code: {otp}
```

Wrapped with the Ethereum personal_sign prefix:
```
\x19Ethereum Signed Message:\n{length}{message}
```

## Manual Paste Path

User pastes raw hex signature into the terminal.

**Format:** `0x` + 130 hex chars (65 bytes: r[32] + s[32] + v[1])

**Verification:** Inline in PAM module — secp256k1 ecrecover recovers the wallet address from the signature and message hash. No plugin needed.

**Trust model:** Cryptographic proof. The signature proves the signer controls the private key for the recovered address.

## Callback `.sig` File

Written by `web3-auth-svc` to `/run/libpam-web3/pending/{session_id}.sig`.

**Canonical form:** `0x` + 130 lowercase hex chars (132 chars total).

The auth-svc accepts inputs with or without the `0x` prefix and in either
case, but **normalizes to canonical form before writing**. PAM detects EVM
.sig files by exact match on `starts_with("0x") && len == 132`; an
unnormalized signature would slip past auth-svc validation but fail PAM
detection, falling through to a JSON-parse error path that hides the real
cause.

**Detection:** PAM reads the `.sig` file. If it starts with `0x` and is 132
characters, it goes to the EVM path — inline ecrecover, same as manual
paste. Otherwise PAM tries JSON; valid JSON with a `chain` field dispatches
to the named plugin, anything else is rejected.

**Verification:** Inline in PAM module — secp256k1 ecrecover recovers the
wallet address from the signature and OTP message, then `==`-compares
against the GECOS `wallet=` field via `alloy_primitives::Address` (case-
insensitive parsing handles mixed-case EIP-55 checksums correctly).

## Key Properties

- **Key recovery:** secp256k1 allows recovering the public key (and thus address) from the signature alone — no separate public key field needed.
- **Address derivation:** `keccak256(public_key)[12:]` — last 20 bytes of the keccak hash of the uncompressed public key (minus the 04 prefix).
- **Case-insensitive matching:** EVM addresses are hex, matched case-insensitively against GECOS `wallet=` field (EIP-55 checksum is not enforced).
