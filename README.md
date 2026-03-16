# libpam-web3

Authenticate to Linux servers using wallet signatures. No passwords, no SSH keys - just your wallet signature.

Supports two verification paths:
- **EVM**: secp256k1 ecrecover from raw hex signature
- **OPNet**: JSON callback with OTP validation and trusted wallet address

Wallet addresses are chain-agnostic (EVM `0x...`, Bitcoin `bc1q...`, Solana, etc.) and matched case-insensitively against the GECOS field in `/etc/passwd`.

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
│     │                            │── GECOS wallet lookup         │
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
WALLET_PRIVATE_KEY = "0x..."  # The wallet matching the GECOS field
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
- The wallet address must be in the user's GECOS field (`wallet=ADDRESS`)
- Consider using a dedicated wallet for AI agent access with limited permissions

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
sudo cp examples/config.toml /etc/pam_web3/config.toml

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

### 4. Add Authorized Wallets

Set the wallet address in the user's GECOS field:

```bash
# Create user with wallet address
sudo useradd -m -c "wallet=0x1234567890abcdef1234567890abcdef12345678" alice

# Or update existing user's GECOS field
sudo usermod -c "wallet=0x1234567890abcdef1234567890abcdef12345678" alice

# Multiple fields are comma-separated
sudo usermod -c "Alice,wallet=0xAbCd...1234,nft=5" alice
```

Verify the GECOS field:
```bash
getent passwd alice
# alice:x:1001:1001:wallet=0x1234...5678:/home/alice:/bin/bash
```

### 5. Configure SSHD

Edit `/etc/ssh/sshd_config`:

```
ChallengeResponseAuthentication yes
UsePAM yes
```

Restart SSH:

```bash
sudo systemctl restart sshd
```

## Configuration

`/etc/pam_web3/config.toml`:

```toml
[machine]
id = "my-server"
secret_key = "0x<your-64-char-hex-key>"  # openssl rand -hex 32

[auth]
signing_url = "https://your-signing-page.example.com"
otp_length = 6           # 4-19 (default: 6)
otp_ttl_seconds = 300    # default: 300
```

Callback mode (browser auto-posts signature) is detected at runtime - if `/run/libpam-web3/pending/` exists, callback sessions are created automatically. No config flag needed.

## GECOS Format

```
wallet=0x1234...abcd,nft=5
```

- `wallet=ADDRESS` - required for authentication (case-insensitive match, chain-agnostic)
- `nft=TOKEN_ID` - optional metadata (token ID for reference)
- Can include other comma-separated fields: `Alice,wallet=0x...,nft=5`

## Client-Side Signing Page

The NFT contains an embedded signing page in its `animation_url` field. Users can extract and host this locally to sign authentication messages with MetaMask.

### Why Local Hosting?

Browsers (MetaMask, Firefox) block wallet connections on `file://` URLs for security reasons. The scripts below extract the signing page and serve it via `http://localhost` so MetaMask can connect.

### Linux / macOS

```bash
# Extract and host signing page from NFT
./scripts/extract-signing-page.sh \
  --contract 0xYourContractAddress \
  --token-id 0

# With custom RPC
./scripts/extract-signing-page.sh \
  --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  --contract 0xYourContractAddress \
  --token-id 5 \
  --port 9000
```

Requirements: `curl` and `python3` (pre-installed on most Linux/macOS systems)

### Windows (PowerShell)

```powershell
# Extract and host signing page from NFT
.\scripts\extract-signing-page.ps1 -Contract "0xYourContractAddress" -TokenId 0

# With custom RPC
.\scripts\extract-signing-page.ps1 `
  -RpcUrl "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" `
  -Contract "0xYourContractAddress" `
  -TokenId 5 `
  -Port 9000
```

Requirements: PowerShell 5.1+ (included in Windows 10/11)

Note: On Windows, you may need to run as Administrator or add a URL reservation:
```powershell
netsh http add urlacl url=http://+:8080/ user=Everyone
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

- **Stolen config**: Only contains machine ID and HMAC key - no wallet private keys
- **Replay attacks**: OTP bound to timestamp, expires quickly
- **Man-in-the-middle**: Signature is over specific OTP + machine ID
- **Compromised signing page**: Attacker can't forge signatures without wallet private key

## File Structure

```
libpam-web3/
├── Cargo.toml              # Rust package manifest
├── src/
│   ├── lib.rs              # PAM module entry point
│   ├── callback.rs         # Callback-based signing sessions (file IPC)
│   ├── config.rs           # Configuration loading
│   ├── otp.rs              # OTP generation and verification
│   ├── signature.rs        # secp256k1 ecrecover
│   ├── passwd_lookup.rs    # GECOS wallet address lookup
│   └── passwd_lookup.rs    # GECOS wallet address lookup
├── contracts/              # AccessCredentialNFT smart contract (ERC-721)
├── scripts/
│   ├── extract-signing-page.sh   # NFT signing page extractor (Linux/macOS)
│   └── extract-signing-page.ps1  # NFT signing page extractor (Windows)
└── examples/
    ├── config.toml         # Example configuration
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

### Check logs

```bash
sudo journalctl -u sshd | grep pam_web3
# or
sudo tail -f /var/log/auth.log | grep pam_web3
```

## License

MIT
