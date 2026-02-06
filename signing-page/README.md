# Signing Page Generator

Browser-based wallet signing interface for libpam-web3 authentication. Can be embedded in NFTs as a data URI.

## Files

| File | Purpose |
|------|---------|
| `index.html` | Template signing page (or generated output) |
| `generate.sh` | Generate customized signing page with embedded credentials |
| `build.sh` | Minify and base64 encode for NFT embedding |

## Usage

### 1. Generate customized signing page

```bash
./generate.sh \
    --public-secret "Decrypt BlockHost credentials" \
    --user-encrypted "0xa1b2c3d4..."
```

This creates `index.html` with the credentials pre-filled and read-only.

### 2. Build for NFT embedding

```bash
./build.sh
```

This outputs two files:
- `signing-page.b64` - Raw base64 (for NFT contract)
- `signing-page.datauri` - Full data URI (for direct JSON use)

## NFT Contract Interface

**IMPORTANT**: The NFT contract's `mint()` function expects **raw base64**, not a data URI.

```
mint(..., animationUrlBase64, ...)
                 │
                 └── Pass contents of signing-page.b64 (raw base64)
                     NOT signing-page.datauri (which has the prefix)
```

The contract's `tokenURI()` function automatically prepends `data:text/html;base64,` when generating the metadata JSON:

```json
{
  "animation_url": "data:text/html;base64,<animationUrlBase64>"
}
```

### Correct usage

```bash
# For manual CLI minting with forge:
forge script ... --sig "mint(...)" ... "$(cat signing-page.b64)"

# For automated minting (Python/JS):
# Use base64.b64encode() directly, or read signing-page.b64
```

### Common mistake (double prefix)

```bash
# WRONG - this causes double prefix:
forge script ... "$(cat signing-page.datauri)"
# Results in: data:text/html;base64,data:text/html;base64,PCFET...

# CORRECT - use raw base64:
forge script ... "$(cat signing-page.b64)"
# Results in: data:text/html;base64,PCFET...
```

## Features

The signing page provides two functions:

### Sign OTP Tab
- User enters OTP code and machine ID
- Signs message: `Authenticate to {machine_id} with code: {otp}`
- Copies signature to clipboard for pasting into terminal

### Decrypt Access Tab
- Pre-filled with `publicSecret` and `userEncrypted` from NFT
- User signs decrypt message to derive AES key
- Decrypts and displays connection details (hostname, port, etc.)

## Encryption Scheme

The decrypt functionality uses:
- **Key derivation**: `keccak256(signature)` where signature is from signing `publicSecret`
- **Encryption**: AES-256-GCM
- **Format**: `iv (12 bytes) || ciphertext || authTag (16 bytes)`

This matches `pam_web3_tool encrypt-symmetric` output.
