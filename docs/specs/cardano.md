# Cardano Authentication Spec

Chain identifier: `"cardano"`

## Signature Type

Ed25519 via CIP-30 `signData` (COSE_Sign1 + COSE_Key).

## Signed Message Format

```
Authenticate to {machine_id} with code: {otp}
```

Encoded as a COSE_Sign1 payload by the browser wallet (Nami, Eternl, etc.) via CIP-30 `signData`.

## Manual Paste Path

Not supported. Ed25519 has no key recovery — verification requires the public key alongside the signature, which the terminal paste flow doesn't carry.

## Callback `.sig` File

Written by `web3-auth-svc` to `/run/libpam-web3/pending/{session_id}.sig`.

```json
{
  "chain": "cardano",
  "ed25519_public_key": "<32-byte raw Ed25519 pubkey, hex>",
  "otp": "<otp code>",
  "machine_id": "<machine identifier>"
}
```

- `ed25519_public_key`: the **raw 32-byte Ed25519 public key**, already
  extracted from the CIP-30 COSE_Key by the auth-svc. The plugin uses
  this directly for blake2b-224 → bech32 derivation; no second CBOR
  parse, no CBOR dependency in the Rust plugin.
- `otp` and `machine_id`: plaintext, available for diagnostics.

## Verification split

| Step | Owner | What |
|------|-------|------|
| 1. CBOR-decode COSE_Sign1 + COSE_Key | auth-svc | TS, single CBOR parser |
| 2. Verify Ed25519 signature over the COSE Sig_structure | auth-svc | @noble/curves |
| 3. Confirm the signed payload matches the expected OTP message | auth-svc | exact-equal |
| 4. Extract raw 32-byte Ed25519 pubkey from COSE_Key (label −2) | auth-svc | written into the .sig file |
| 5. Derive blake2b-224(pubkey) and compare to bech32 payment credential | plugin | identity binding |

Steps 1-4: signature authenticity (was this signed by the holder of
the pubkey, over the right message?). Step 5: identity verification
(does that pubkey belong to the wallet in GECOS?). The CBOR parse
happens in exactly one place — the TS auth-svc — so there's no risk
of two parsers silently disagreeing on a malformed input.

## Key Properties

- **No key recovery:** Ed25519 does not support recovering the public key from a signature — the public key must be provided alongside the signature (via COSE_Key from CIP-30).
- **Address derivation:** blake2b-224 hash of the Ed25519 public key, bech32-encoded with `addr` or `addr_test` prefix.
- **CIP-30 transport:** `signData` returns `{ signature: COSE_Sign1, key: COSE_Key }` — the auth-svc parses both in TS, then writes only the parsed-out raw 32-byte pubkey into the .sig file.
- **Trust model:** the auth-svc verifies the Ed25519 signature before writing; the plugin trusts that the pubkey was authentic and binds it to the GECOS address. (The full COSE blobs are not retained in the .sig file — anyone who could forge them could already write a forged .sig anyway.)

## Dependencies (for verification plugin)

- blake2b-224 (for address derivation)
- bech32 encoding (for address comparison)
- hex decoder

(No CBOR parser. The auth-svc owns COSE.)
