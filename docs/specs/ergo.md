# Ergo Authentication Spec

Chain identifier: `"ergo"`

## Signature Type

Schnorr (secp256k1) via Nautilus EIP-12 `sign_data(address, message)`.

## Signed Message Format

```
Authenticate to {machine_id} with code: {otp}
```

Passed as a hex-encoded UTF-8 string to the Nautilus `sign_data` method. The wallet produces a Sigma protocol proof (ProveDlog Schnorr signature).

## Manual Paste Path

Not supported. Schnorr signatures do not support public key recovery — verification requires the public key alongside the signature, which the terminal paste flow doesn't carry.

## Callback `.sig` File

Written by `web3-auth-svc` to `/run/libpam-web3/pending/{session_id}.sig`.

```json
{
  "chain": "ergo",
  "signature": "<hex-encoded Schnorr proof>",
  "public_key": "<hex-encoded compressed secp256k1 pubkey, 33 bytes>",
  "otp": "<otp code>",
  "machine_id": "<machine identifier>"
}
```

- `signature`: Schnorr proof bytes from `sign_data` result (hex-encoded)
- `public_key`: compressed secp256k1 public key (33 bytes, hex-encoded)
- `otp` and `machine_id`: plaintext, for OTP re-validation

## Auth-svc Port

```
crc32("ergo") = 0x8d78e5ba
port = 1024 + (2373510586 % 64511) = 22898
```

## Verification Steps

### Auth-svc (structural + signature verification)

1. Receive `{ signature, key, otp, machineId }` from signing page callback
2. Validate OTP and machine_id match the session file (timing-safe comparison)
3. Hex-decode `key` as a 33-byte compressed secp256k1 public key
4. Reconstruct the signed message: `"Authenticate to {machineId} with code: {otp}"`
5. Verify the Schnorr signature over the message using the public key
6. On success, write `.sig` file with `chain: "ergo"`

### Plugin (identity verification)

1. Hex-decode `public_key` from the `.sig` file (33 bytes, compressed secp256k1)
2. Determine network from the first character of the GECOS wallet address (`9` = mainnet, `3` = testnet)
3. Construct address bytes: `type_byte || pubkey || checksum`
   - Type byte: `0x01` (mainnet P2PK) or `0x11` (testnet P2PK)
   - Checksum: `blake2b_256(type_byte || pubkey)[0..4]`
4. Base58-encode the 38 bytes → Ergo address (51 characters)
5. Compare derived address against `wallet_address` from GECOS (case-sensitive, exact match)
6. Return the GECOS wallet address on match

## Address Format

Ergo P2PK addresses are Base58Check-encoded:

```
address = Base58(prefix || content || checksum)
  prefix  = 0x01 (mainnet) or 0x11 (testnet)     — 1 byte
  content = compressed secp256k1 pubkey            — 33 bytes
  checksum = blake2b_256(prefix || content)[0..4]  — 4 bytes
  total = 38 bytes → ~51 Base58 characters
```

- Mainnet addresses start with `9`
- Testnet addresses start with `3`

Address pattern for plugin discovery: `^[39][1-9A-HJ-NP-Za-km-z]{50}$`

## Key Properties

- **No key recovery:** secp256k1 Schnorr does not support recovering the public key from a signature — the public key must be provided alongside the signature.
- **Address derivation:** compressed pubkey directly embedded in ErgoTree (`0008cd` prefix), then Base58Check with blake2b-256 checksum. No hashing of the pubkey itself (unlike Cardano's blake2b-224).
- **Wallet connector:** Nautilus browser extension via EIP-12 dApp connector. `sign_data(address, hex_message)` returns a proof object.
- **Trust model:** Auth-svc verifies signature authenticity (Schnorr proof). Plugin verifies identity (pubkey → address derivation). Both are required for authentication.

## Dependencies

### Verification plugin (Rust)
- `serde`, `serde_json` — JSON I/O
- `blake2` — blake2b-256 for address checksum
- `bs58` — Base58 encoding
- `hex` — hex string parsing

### Auth-svc (Node.js)
- `@noble/curves` — secp256k1 Schnorr signature verification
- `@noble/hashes` — SHA-256 for Schnorr challenge derivation

## S.P.E.C.I.A.L. Profile

Inherits from libpam-web3 default: **S8 P10 E7 C5 I8 A8 L7**

Authentication boundary. The auth-svc is internet-facing. The plugin runs inside PAM with access to the auth decision. Both must treat every input as hostile.
