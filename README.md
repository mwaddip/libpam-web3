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
│     │──── signature ────────────>│  (paste or auto-callback)     │
│     │                            │                               │
│     │                            │── recover wallet address      │
│     │                            │── verify ownership            │
│     │                            │── map to Linux username       │
│     │                            │                               │
│     │<── LOGIN SUCCESS ──────────│                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## AI Agent Authentication

AI agents (like [OpenClaw](https://github.com/openclaw), Claude Code, or custom automation) can authenticate programmatically without a browser. The wallet signature is just secp256k1 ECDSA - any Ethereum signing library works.

### Python Example

```python
import paramiko
from eth_account import Account
from eth_account.messages import encode_defunct
import re

def ssh_with_wallet(host, username, private_key_hex):
    """SSH into a server using Ethereum wallet authentication."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Custom transport for interactive auth
    transport = paramiko.Transport((host, 22))
    transport.connect(username=username)

    def auth_handler(title, instructions, prompts):
        responses = []
        for prompt, echo in prompts:
            if 'code:' in prompt.lower():
                # Extract OTP and machine ID from prompt
                # Format: "Authenticate to {machine_id} with code: {otp}"
                match = re.search(r'to (\S+) with code: (\d+)', prompt)
                if match:
                    machine_id, otp = match.groups()
                    message = f"Authenticate to {machine_id} with code: {otp}"

                    # Sign the message with Ethereum wallet
                    signable = encode_defunct(text=message)
                    signed = Account.sign_message(signable, private_key=private_key_hex)
                    responses.append(signed.signature.hex())
            else:
                responses.append('')
        return responses

    transport.auth_interactive(username, auth_handler)
    return paramiko.SSHClient()._transport = transport

# Usage
WALLET_PRIVATE_KEY = "0x..."  # The wallet that owns the NFT or is in wallets file
ssh_with_wallet("server.example.com", "myuser", WALLET_PRIVATE_KEY)
```

### Node.js Example

```javascript
const { Client } = require('ssh2');
const { Wallet } = require('ethers');

const wallet = new Wallet('0x<private_key>');

const conn = new Client();
conn.on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
  const responses = prompts.map(p => {
    const match = p.prompt.match(/to (\S+) with code: (\d+)/);
    if (match) {
      const [, machineId, otp] = match;
      const message = `Authenticate to ${machineId} with code: ${otp}`;
      return wallet.signMessageSync(message);
    }
    return '';
  });
  finish(responses);
});

conn.connect({
  host: 'server.example.com',
  username: 'myuser',
  tryKeyboard: true
});
```

### Using Foundry's cast

```bash
# Read OTP from SSH prompt, then sign:
cast wallet sign "Authenticate to my-server with code: 123456" --private-key $WALLET_KEY
```

### Decrypting Connection Details from NFT

NFTs can store encrypted connection details (hostname, port) that only the wallet owner can decrypt. The encryption uses AES-256-GCM with a key derived from signing the `public_secret`.

#### Python Example

```python
from eth_account import Account
from eth_account.messages import encode_defunct
from Crypto.Cipher import AES
import requests
import base64
import json

def get_connection_info(contract_address, token_id, private_key, rpc_url):
    """Decrypt connection details from an NFT."""

    # 1. Fetch token URI from contract
    # tokenURI(uint256) selector = 0xc87b56dd
    call_data = f"0xc87b56dd{token_id:064x}"
    response = requests.post(rpc_url, json={
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": contract_address, "data": call_data}, "latest"],
        "id": 1
    }).json()

    # 2. Decode the base64 JSON metadata
    uri = bytes.fromhex(response["result"][2:]).decode('utf-8').strip('\x00')
    if uri.startswith("data:application/json;base64,"):
        metadata = json.loads(base64.b64decode(uri[29:]))

    # 3. Extract encrypted data and decrypt message
    access = metadata.get("access", {})
    user_encrypted = access.get("user_encrypted", "")  # hex string
    public_secret = access.get("public_secret", "")

    if not user_encrypted or not public_secret:
        raise ValueError("NFT has no encrypted connection details")

    # 4. Sign the decrypt message to derive the key
    signable = encode_defunct(text=public_secret)
    signed = Account.sign_message(signable, private_key=private_key)

    # 5. Derive AES key: keccak256(signature)
    from eth_utils import keccak
    key = keccak(signed.signature)

    # 6. Decrypt (format: IV[12] || ciphertext || authTag[16])
    data = bytes.fromhex(user_encrypted.replace("0x", ""))
    iv = data[:12]
    ciphertext = data[12:-16]
    tag = data[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return json.loads(plaintext.decode('utf-8'))

# Usage
connection = get_connection_info(
    contract_address="0x51BD579B7757BA1bDF777844e4B964678d237EA8",
    token_id=0,
    private_key="0x...",
    rpc_url="https://ethereum-sepolia-rpc.publicnode.com"
)
print(connection)  # {"hostname": "192.168.1.100", "port": 22}
```

#### Node.js Example

```javascript
const { Wallet, JsonRpcProvider, keccak256 } = require('ethers');
const crypto = require('crypto');

async function getConnectionInfo(contractAddress, tokenId, privateKey, rpcUrl) {
  const provider = new JsonRpcProvider(rpcUrl);
  const wallet = new Wallet(privateKey);

  // 1. Fetch token URI
  const abi = ['function tokenURI(uint256) view returns (string)'];
  const contract = new ethers.Contract(contractAddress, abi, provider);
  const uri = await contract.tokenURI(tokenId);

  // 2. Decode metadata
  const json = Buffer.from(uri.split(',')[1], 'base64').toString();
  const metadata = JSON.parse(json);

  // 3. Get encrypted data
  const { user_encrypted, public_secret } = metadata.access;

  // 4. Sign to derive key
  const signature = await wallet.signMessage(public_secret);
  const key = Buffer.from(keccak256(signature).slice(2), 'hex');

  // 5. Decrypt
  const data = Buffer.from(user_encrypted.replace('0x', ''), 'hex');
  const iv = data.slice(0, 12);
  const ciphertext = data.slice(12, -16);
  const tag = data.slice(-16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  return JSON.parse(plaintext.toString());
}
```

#### Complete AI Agent Flow

```python
# 1. Get connection details from NFT
connection = get_connection_info(CONTRACT, TOKEN_ID, WALLET_KEY, RPC_URL)
hostname = connection["hostname"]
port = connection.get("port", 22)

# 2. SSH with wallet authentication
ssh_with_wallet(hostname, "myuser", WALLET_KEY)
```

### Security Considerations

- Store the wallet private key securely (environment variable, secrets manager)
- The wallet must own the required NFT (NFT mode) or be listed in the wallets file (wallet mode)
- Consider using a dedicated wallet for AI agent access with limited permissions

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
callback_enabled = true     # Browser auto-POSTs signature
callback_grace_seconds = 10

[wallet]
wallets_path = "/etc/pam_web3/wallets"
```

### NFT Mode (`/etc/pam_web3/config.toml`)

```toml
[machine]
id = "server-prod-01"
secret_key = "0x<your-64-char-hex-key>"  # openssl rand -hex 32

[auth]
mode = "nft"
nft_lookup = "passwd"  # or "ldap"
signing_url = "https://auth.example.com/verify"
callback_enabled = true
callback_grace_seconds = 10

[blockchain]
socket_path = "/run/web3-auth/web3-auth.sock"
chain_id = 1
nft_contract = "0x1234..."

# Optional LDAP config (only if nft_lookup = "ldap")
# [ldap]
# server = "ldap://localhost:389"
# base_dn = "ou=nft,dc=example,dc=com"
# bind_dn = "cn=pam,dc=example,dc=com"
# bind_password_file = "/etc/pam_web3/ldap.secret"
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
│   ├── callback.rs         # Callback-based signing sessions
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
