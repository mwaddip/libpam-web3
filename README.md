# libpam-web3

Authenticate to Linux servers using your Ethereum wallet. No passwords, no SSH keys - just your wallet signature.

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     AUTHENTICATION FLOW                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   User                         Server                            │
│     │                            │                               │
│     │──── SSH login ────────────>│                               │
│     │                            │                               │
│     │<── OTP code + URL ─────────│  "Code: 847293"               │
│     │                            │  "Sign at: https://..."       │
│     │                            │                               │
│     │ (opens browser, connects   │                               │
│     │  wallet, signs message)    │                               │
│     │                            │                               │
│     │──── signature ────────────>│                               │
│     │                            │                               │
│     │                            │── recover wallet address      │
│     │                            │── check wallets file          │
│     │                            │── map to Linux username       │
│     │                            │                               │
│     │<── LOGIN SUCCESS ──────────│                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

1. User attempts SSH login
2. Server displays a one-time code and signing URL
3. User opens the signing page and connects their wallet (MetaMask, etc.)
4. User signs the message containing the OTP code
5. User pastes the signature into the terminal
6. Server recovers the wallet address from the signature
7. Server looks up the wallet in the authorized wallets file
8. If found, user is logged in as the mapped Linux user

## Quick Start

### 1. Build the PAM Module

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install PAM development headers
sudo apt install libpam0g-dev  # Debian/Ubuntu
sudo dnf install pam-devel     # Fedora/RHEL

# Build
cargo build --release
```

### 2. Install

```bash
# Copy the PAM module
sudo cp target/release/libpam_web3.so /lib/security/pam_web3.so

# Create config directory
sudo mkdir -p /etc/pam_web3

# Copy example config
sudo cp examples/config.conf /etc/pam_web3/config.conf
sudo cp examples/wallets /etc/pam_web3/wallets

# Edit config with your settings
sudo nano /etc/pam_web3/config.conf
```

### 3. Configure PAM

For Web3 auth **only for specific users** (recommended), add to `/etc/pam.d/sshd`:

```
# Web3 wallet authentication (only for web3user)
auth [success=1 default=ignore] pam_succeed_if.so user != web3user
auth [success=done default=die] pam_web3.so

# Standard authentication for everyone else
@include common-auth
```

See `examples/pam-sshd.conf` for more configuration options including:
- Web3 auth for a list of users
- Web3 auth for a group of users
- Web3 auth for all users

### 4. Add Authorized Wallets

Edit `/etc/pam_web3/wallets`:

```
# Format: wallet_address:linux_username
0x1234567890abcdef1234567890abcdef12345678:alice
0xabcdef1234567890abcdef1234567890abcdef12:bob
```

### 5. Host the Signing Page

Deploy `signing-page/index.html` to any web server, or use it locally.

## Configuration

### `/etc/pam_web3/config.conf`

```
# URL to the signing page
signing_url = https://your-server.com/sign

# Path to authorized wallets file
wallets_path = /etc/pam_web3/wallets

# OTP settings
otp_length = 6
otp_ttl_seconds = 300

# Machine identifier (shown to user when signing)
machine_id = my-server

# Secret key for OTP HMAC (32 bytes hex)
# Generate with: openssl rand -hex 32
secret_key = 0x<your_64_char_hex_key>
```

### `/etc/pam_web3/wallets`

```
# Authorized wallet addresses mapped to Linux usernames
# Format: wallet_address:username
# Addresses are case-insensitive, 0x prefix optional

0x1234567890abcdef1234567890abcdef12345678:alice
0xABCDEF1234567890ABCDEF1234567890ABCDEF12:bob
deadbeef1234567890deadbeef1234567890dead:charlie
```

## Security

| Feature | Description |
|---------|-------------|
| **No password storage** | Wallets are public addresses, no secrets stored |
| **Replay protection** | OTP codes are bound to machine ID + timestamp + HMAC |
| **Time-limited** | OTP codes expire (default 5 minutes) |
| **Cryptographic verification** | Signatures verified using secp256k1 ecrecover |
| **Fail-secure** | Any error results in authentication denial |
| **Memory-safe** | Written in Rust, no buffer overflows |

### Threat Model

- **Stolen wallet file**: Only contains public addresses - no secrets
- **Replay attacks**: OTP bound to timestamp, expires quickly
- **Man-in-the-middle**: Signature is over specific OTP + machine ID
- **Compromised signing page**: Attacker can't forge signatures without wallet private key

## File Structure

```
libpam-web3/
├── Cargo.toml              # Rust package manifest
├── src/
│   ├── lib.rs              # PAM module entry point
│   ├── otp.rs              # OTP generation and verification
│   └── signature.rs        # Ethereum signature recovery
├── signing-page/
│   └── index.html          # Web interface for signing
└── examples/
    ├── config.conf         # Example configuration
    ├── wallets             # Example wallets file
    └── pam-sshd.conf       # Example PAM configuration
```

## Requirements

- Linux with PAM support
- Rust 1.70+
- PAM development headers (`libpam0g-dev` or `pam-devel`)

## Troubleshooting

### "No wallet found" in signing page

Install MetaMask or another Web3 wallet browser extension.

### "Connection rejected"

Make sure to approve the wallet connection request in your wallet.

### "Invalid signature"

- Check that you're signing with the correct wallet
- Verify the OTP code and machine ID match exactly
- Ensure the signature hasn't expired (default 5 minutes)

### PAM module not loading

Check that the module is in the correct location:
```bash
ls -la /lib/security/pam_web3.so
```

Check PAM configuration syntax:
```bash
sudo pamtester sshd yourusername authenticate
```

## Roadmap

- [ ] NFT-based access credentials (authenticate via NFT ownership)
- [ ] Blockchain-verified wallet authorization
- [ ] LDAP integration for enterprise deployments
- [ ] Credential expiration and revocation
- [ ] Multi-chain support (Polygon, Arbitrum, etc.)

## License

MIT
