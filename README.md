# libpam-web3

Authenticate to Linux servers using your Ethereum wallet. No passwords, no SSH keys - just your wallet signature.

## Authentication Modes

### Wallet Mode (Default)
Simple file-based wallet → username mapping. Perfect for small deployments.

### NFT Mode
Enterprise-grade authentication via NFT ownership on EVM blockchains, with LDAP integration for username management and revocation.

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
│     │                            │── verify ownership            │
│     │                            │── map to Linux username       │
│     │                            │                               │
│     │<── LOGIN SUCCESS ──────────│                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Build the PAM Module

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install PAM development headers
sudo apt install libpam0g-dev  # Debian/Ubuntu
sudo dnf install pam-devel     # Fedora/RHEL

# Build (wallet mode only)
cargo build --release

# Build with NFT support
cargo build --release --features nft
```

### 2. Install

```bash
# Copy the PAM module
sudo cp target/release/libpam_web3.so /lib/security/pam_web3.so

# Create config directory
sudo mkdir -p /etc/pam_web3

# Copy example config (choose wallet or nft mode)
sudo cp examples/config-wallet.toml /etc/pam_web3/config.toml
sudo cp examples/wallets /etc/pam_web3/wallets

# Edit config with your settings
sudo nano /etc/pam_web3/config.toml
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

### 4. Add Authorized Wallets (Wallet Mode)

Edit `/etc/pam_web3/wallets`:

```
# Format: wallet_address:linux_username
0x1234567890abcdef1234567890abcdef12345678:alice
0xabcdef1234567890abcdef1234567890abcdef12:bob
```

### 5. Host the Signing Page

Deploy `signing-page/index.html` to any web server, or use it locally.

## Configuration

### Wallet Mode (`/etc/pam_web3/config.toml`)

```toml
[machine]
id = "my-server"
secret_key = "0x<your-64-char-hex-key>"  # openssl rand -hex 32

[auth]
mode = "wallet"
signing_url = "https://your-server.com/sign"
otp_length = 6
otp_ttl_seconds = 300

[wallet]
wallets_path = "/etc/pam_web3/wallets"
```

### NFT Mode (`/etc/pam_web3/config.toml`)

```toml
[machine]
id = "server-prod-01"
private_key_file = "/etc/pam_web3/server.key"

[auth]
mode = "nft"
signing_url = "https://auth.example.com/verify"

[blockchain]
socket_path = "/run/web3-auth/web3-auth.sock"
chain_id = 1
nft_contract = "0x1234..."

[ldap]
server = "ldap://localhost:389"
base_dn = "ou=nft,dc=example,dc=com"
bind_dn = "cn=pam,dc=example,dc=com"
bind_password_file = "/etc/pam_web3/ldap.secret"
```

## NFT Mode Setup

NFT mode requires additional components:

1. **web3-auth-svc daemon** - Handles blockchain queries
   ```bash
   cd web3-auth-svc
   cargo build --release
   sudo cp target/release/web3-auth-svc /usr/local/bin/
   ```

2. **LDAP server** - Stores NFT → username mappings and revocation status

3. **AccessCredentialNFT contract** - Deploy from `contracts/`

4. **Machine keypair** - Generate with:
   ```bash
   cargo run --features nft --bin pam_web3_tool -- generate-keypair
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
- **NFT revocation**: LDAP-based revocation immediately blocks access

## File Structure

```
libpam-web3/
├── Cargo.toml              # Rust package manifest
├── src/
│   ├── lib.rs              # PAM module entry point
│   ├── config.rs           # Configuration loading
│   ├── otp.rs              # OTP generation and verification
│   ├── signature.rs        # Ethereum signature recovery
│   ├── wallet_auth.rs      # Wallet mode authentication
│   ├── blockchain.rs       # NFT blockchain client (nft feature)
│   ├── ldap.rs             # LDAP client (nft feature)
│   ├── ecies.rs            # Encryption schemes (nft feature)
│   └── bin/
│       └── pam_web3_tool.rs  # Admin CLI tool (nft feature)
├── web3-auth-svc/          # Blockchain verification daemon
├── contracts/              # AccessCredentialNFT smart contract
├── signing-page/
│   └── index.html          # Web interface for signing
└── examples/
    ├── config-wallet.toml  # Wallet mode configuration
    ├── config-nft.toml     # NFT mode configuration
    ├── wallets             # Example wallets file
    └── pam-sshd.conf       # Example PAM configuration
```

## Requirements

- Linux with PAM support
- Rust 1.70+
- PAM development headers (`libpam0g-dev` or `pam-devel`)

For NFT mode additionally:
- Running web3-auth-svc daemon
- LDAP server
- EVM-compatible blockchain (Ethereum, Polygon, etc.)

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

### Check logs

```bash
sudo journalctl -u sshd | grep pam_web3
# or
sudo tail -f /var/log/auth.log | grep pam_web3
```

## License

MIT
