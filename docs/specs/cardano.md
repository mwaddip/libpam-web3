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
  "signature": "<hex-encoded COSE_Sign1>",
  "public_key": "<hex-encoded COSE_Key>",
  "otp": "<otp code>",
  "machine_id": "<machine identifier>"
}
```

- `signature`: CBOR-encoded COSE_Sign1 structure from CIP-30 `signData` result
- `public_key`: CBOR-encoded COSE_Key map from CIP-30 `signData` result
- `otp` and `machine_id`: plaintext, for OTP re-validation

## Verification Steps

1. CBOR-decode `signature` as COSE_Sign1: `[protected_headers, unprotected_headers, payload, signature_bytes]`
2. CBOR-decode `public_key` as COSE_Key map, extract Ed25519 public key from key `-2` (32 bytes)
3. Verify protected header contains `alg = -8` (EdDSA)
4. Reconstruct COSE Sig_structure: `["Signature1", protected_headers_bytes, empty_external_aad, payload_bytes]`
5. Verify Ed25519 signature over `CBOR(Sig_structure)` using the extracted public key
6. Verify the payload matches the expected OTP message: `"Authenticate to {machine_id} with code: {otp}"`
7. Derive Cardano address from the public key (blake2b-224 hash of pubkey → bech32 encoding) and compare against `wallet=<addr>` from GECOS

Steps 1-6: signature authenticity (is this a real signature over the correct message?).
Step 7: identity verification (does this key belong to the wallet in GECOS?).

## Key Properties

- **No key recovery:** Ed25519 does not support recovering the public key from a signature — the public key must be provided alongside the signature (via COSE_Key from CIP-30).
- **Address derivation:** blake2b-224 hash of the Ed25519 public key, bech32-encoded with `addr` or `addr_test` prefix.
- **COSE structures:** CIP-30 `signData` returns `{ signature: COSE_Sign1, key: COSE_Key }` — both are CBOR-encoded and hex-encoded for transport.
- **Trust model:** Cryptographic proof. The `.sig` file carries the full signature and public key — the plugin can independently verify without trusting the auth-svc.

## Dependencies (for verification plugin)

- CBOR decoder (for COSE_Sign1 and COSE_Key)
- Ed25519 verification
- blake2b-224 (for address derivation)
- bech32 encoding (for address comparison)
