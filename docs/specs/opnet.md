# OPNet Authentication Spec

Chain identifier: `"opnet"`

## Signature Type

ML-DSA (post-quantum, via OPNet's `Blockchain.verifySignature` with `SignaturesMethods.MLDSA`).

## Callback `.sig` File

Written by `web3-auth-svc` to `/run/libpam-web3/pending/{session_id}.sig`.

```json
{
  "chain": "opnet",
  "wallet_address": "<address>",
  "otp": "<otp code>",
  "machine_id": "<machine identifier>"
}
```

The ML-DSA signature (~2KB) is **not** included in the `.sig` file. The auth-svc verifies the ML-DSA signature itself before writing the `.sig` — the file is an assertion of verified identity, not a cryptographic proof that PAM re-checks.

**Verification:** PAM dispatches to the engine's verification plugin (`/usr/lib/libpam-web3/verify.so`), which validates the OTP and machine_id, then confirms the wallet address matches GECOS. No signature re-verification — trust is in the auth-svc having already done it.

## Manual Paste Path

Not supported. OPNet authentication is callback-only — the auth service validates the wallet signature before writing the `.sig` file.

## Key Properties

- **No key recovery:** ML-DSA does not support key recovery from signatures — the public key must be provided alongside the signature. This is why the auth-svc verifies the signature rather than deferring to the plugin.
- **Large signatures:** ML-DSA signatures are ~2KB, making them impractical to include in the `.sig` file or pass through IPC.
- **Trust model:** The `.sig` file is a trusted assertion from the auth-svc, not a self-contained proof. Security depends on the auth-svc process and file permissions on `/run/libpam-web3/pending/`.
- **Address format:** OPNet addresses can be Bitcoin-style (`bc1q...`) or other formats depending on the network.
- **OTP validation:** The auth-svc verifies the OTP before writing. The plugin re-validates OTP + machine_id as a defense-in-depth check.
