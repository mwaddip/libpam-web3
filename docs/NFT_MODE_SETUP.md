# NFT Mode Setup Guide

This guide covers deploying and configuring libpam-web3 in NFT mode, where authentication is based on NFT ownership verified via blockchain.

## Overview

NFT mode authentication flow:
1. User connects via SSH and sees an OTP code
2. User signs the OTP with their Ethereum wallet
3. PAM module verifies the signature and recovers the wallet address
4. web3-auth-svc queries the blockchain to find NFTs owned by the wallet
5. NFT metadata contains encrypted machine ID - decrypted with server's private key
6. If machine ID matches, LDAP is queried for username and revocation status
7. User is logged in as the mapped Linux username

## Prerequisites

- Linux server with PAM support
- Rust toolchain (for building)
- Foundry (for contract deployment)
- OpenLDAP server
- Ethereum wallet with testnet ETH (for contract deployment)

## Step 1: Deploy the NFT Contract

### Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Deploy Contract

```bash
cd contracts

# Create deployer key (store securely, add to .gitignore)
cast wallet new | grep "Private key" | awk '{print $3}' > deployer.key

# Get the deployer address
DEPLOYER=$(cast wallet address --private-key $(cat deployer.key))
echo "Fund this address with testnet ETH: $DEPLOYER"

# Deploy to Sepolia (or other network)
forge create src/AccessCredentialNFT.sol:AccessCredentialNFT \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --private-key $(cat deployer.key) \
  --constructor-args \
    "Access Credentials" \
    "ACCESS" \
    "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PHRpdGxlPldlYjMgQXV0aDwvdGl0bGU+PC9oZWFkPjxib2R5PjxoMT5TaWduaW5nIFBhZ2UgUGxhY2Vob2xkZXI8L2gxPjwvYm9keT48L2h0bWw+" \
    "ipfs://QmDefaultImageHashHere"

# Note the deployed contract address
CONTRACT_ADDRESS="0x..."  # From deployment output
```

## Step 2: Generate Server Keypair

Each server needs an ECIES keypair. The public key is used to encrypt machine IDs in NFTs, and the private key is stored on the server for decryption.

```bash
# Build the tool
cargo build --release --features nft

# Generate keypair
./target/release/pam_web3_tool generate-keypair --output /etc/pam_web3/server.key

# This outputs the public key - save it for minting NFTs
# Example: 04cade66adf51f0c...ed24
SERVER_PUBKEY="04..."
```

## Step 3: Mint Access NFT

For each user that needs access, mint an NFT with the encrypted machine ID.

### Encrypt Machine ID

```bash
# Encrypt the machine ID for the server
./target/release/pam_web3_tool encrypt \
  --machine-id "your-server-hostname" \
  --server-pubkey "$SERVER_PUBKEY"

# Output:
# Server encrypted (secp256k1 ECIES):
# 0x04d49c449c2aace791b0d70b20ca96494695a7f1022b5a506767cc1a4472cc...
ENCRYPTED_MACHINE_ID="0x04..."
```

### Mint NFT

```bash
# Mint to user's wallet
USER_WALLET="0xUserWalletAddress"

cast send $CONTRACT_ADDRESS \
  "mint(address,bytes,bytes,string,string,string,uint256)" \
  $USER_WALLET \
  $ENCRYPTED_MACHINE_ID \
  0x \
  "" \
  "Server Access - your-server-hostname" \
  "" \
  0 \
  --private-key $(cat deployer.key) \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com

# Verify the mint
cast call $CONTRACT_ADDRESS "balanceOf(address)(uint256)" $USER_WALLET \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com
```

## Step 4: Configure LDAP

### Install OpenLDAP

```bash
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd
```

### Add NFT Schema

Create `/tmp/nft-schema.ldif`:

```ldif
dn: cn=nftCredential,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: nftCredential
olcAttributeTypes: {0}( 1.3.6.1.4.1.99999.1.1 NAME 'nftTokenId'
  DESC 'NFT Token ID' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: {1}( 1.3.6.1.4.1.99999.1.2 NAME 'nftRevoked'
  DESC 'NFT Revocation Status' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )
olcAttributeTypes: {2}( 1.3.6.1.4.1.99999.1.3 NAME 'linuxUsername'
  DESC 'Linux Username' EQUALITY caseExactMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcAttributeTypes: {3}( 1.3.6.1.4.1.99999.1.4 NAME 'walletAddress'
  DESC 'Ethereum Wallet Address' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
olcObjectClasses: {0}( 1.3.6.1.4.1.99999.2.1 NAME 'nftCredential'
  DESC 'NFT-based access credential' SUP top AUXILIARY
  MUST ( nftTokenId $ linuxUsername ) MAY ( nftRevoked $ walletAddress ) )
```

```bash
sudo ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/nft-schema.ldif
```

### Create NFT OU

```ldif
# /tmp/nft-ou.ldif
dn: ou=nft,dc=example,dc=com
objectClass: organizationalUnit
ou: nft
```

```bash
ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/nft-ou.ldif
```

### Add NFT Entry

For each minted NFT, add an LDAP entry mapping token ID to Linux username:

```ldif
# /tmp/token0.ldif
dn: cn=token0,ou=nft,dc=example,dc=com
objectClass: top
objectClass: device
objectClass: nftCredential
cn: token0
nftTokenId: 0
nftRevoked: FALSE
linuxUsername: johndoe
walletAddress: 0xUserWalletAddress
description: Server access for John Doe
```

```bash
ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/token0.ldif
```

### Create LDAP Bind User

```ldif
# /tmp/pam-user.ldif
dn: cn=pam,dc=example,dc=com
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: pam
userPassword: {SSHA}GenerateHashedPassword
description: PAM bind user for NFT lookups
```

```bash
ldapadd -x -D "cn=admin,dc=example,dc=com" -W -f /tmp/pam-user.ldif
```

## Step 5: Build and Install PAM Module

```bash
# Build with NFT support
cargo build --release --features nft

# Install PAM module
sudo cp target/release/libpam_web3.so /lib/x86_64-linux-gnu/security/

# Create symlink (optional)
sudo ln -sf /lib/x86_64-linux-gnu/security/libpam_web3.so \
            /lib/x86_64-linux-gnu/security/pam_web3.so
```

## Step 6: Build and Install web3-auth-svc

```bash
cd web3-auth-svc
cargo build --release

# Install binary
sudo cp target/release/web3-auth-svc /usr/local/bin/

# Create config directory
sudo mkdir -p /etc/web3-auth

# Create config file
sudo tee /etc/web3-auth/config.toml > /dev/null << 'EOF'
socket_path = "/run/web3-auth/web3-auth.sock"
backend = "jsonrpc"
default_chain_id = 11155111  # Sepolia
default_contract = "0xYourContractAddress"

[jsonrpc]
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
timeout_seconds = 30
EOF

# Create systemd service
sudo tee /etc/systemd/system/web3-auth-svc.service > /dev/null << 'EOF'
[Unit]
Description=Web3 Authentication Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/web3-auth-svc --config /etc/web3-auth/config.toml --foreground
Restart=always
RestartSec=5
Environment=RUST_LOG=info
RuntimeDirectory=web3-auth
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable web3-auth-svc
sudo systemctl start web3-auth-svc
```

## Step 7: Configure PAM Module

### Create PAM Config

```bash
sudo mkdir -p /etc/pam_web3

# Create main config
sudo tee /etc/pam_web3/config.toml > /dev/null << 'EOF'
[machine]
id = "your-server-hostname"
private_key_file = "/etc/pam_web3/server.key"

[auth]
mode = "nft"
signing_url = "http://your-server:8080"
otp_length = 6
otp_ttl_seconds = 300

[blockchain]
socket_path = "/run/web3-auth/web3-auth.sock"
chain_id = 11155111
nft_contract = "0xYourContractAddress"
timeout_seconds = 10

[ldap]
server = "ldap://localhost:389"
base_dn = "ou=nft,dc=example,dc=com"
bind_dn = "cn=pam,dc=example,dc=com"
bind_password_file = "/etc/pam_web3/ldap.secret"
token_id_attribute = "nftTokenId"
revoked_attribute = "nftRevoked"
username_attribute = "linuxUsername"
timeout_seconds = 10
EOF

# Set LDAP password
echo -n "YourLdapPassword" | sudo tee /etc/pam_web3/ldap.secret > /dev/null
sudo chmod 600 /etc/pam_web3/ldap.secret

# Set permissions
sudo chmod 600 /etc/pam_web3/server.key
sudo chmod 644 /etc/pam_web3/config.toml
```

### Configure SSH PAM

Edit `/etc/pam.d/sshd`:

```pam
# Add before @include common-auth:
auth [success=2 default=ignore] pam_succeed_if.so user != web3user1 user != web3user2
auth [success=1 default=die] pam_web3.so

@include common-auth
```

This configuration:
- Skips web3 auth for users not in the list (falls through to common-auth)
- For listed users, requires web3 auth and denies if it fails

### Configure SSHD

Edit `/etc/ssh/sshd_config`:

```
ChallengeResponseAuthentication yes
UsePAM yes
```

Restart SSH:

```bash
sudo systemctl restart sshd
```

## Step 8: Host Signing Page (Optional)

```bash
# Create directory
sudo mkdir -p /var/www/web3-sign
sudo cp signing-page/index.html /var/www/web3-sign/

# Create systemd service for simple HTTP server
sudo tee /etc/systemd/system/web3-sign.service > /dev/null << 'EOF'
[Unit]
Description=Web3 Signing Page HTTP Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/www/web3-sign
ExecStart=/usr/bin/python3 -m http.server 8080 --bind 0.0.0.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable web3-sign
sudo systemctl start web3-sign
```

## Step 9: Create Linux Users

```bash
# Create users that match LDAP linuxUsername entries
sudo useradd -m johndoe
```

## Testing

1. Open the signing page in a browser with MetaMask
2. Import the wallet that owns the NFT
3. SSH to the server:
   ```bash
   ssh johndoe@your-server
   ```
4. You'll see:
   ```
   === Web3 Authentication ===
   Code: 123456
   Machine: your-server-hostname
   Sign at: http://your-server:8080

   Paste signature:
   ```
5. Enter the code and machine ID on the signing page
6. Sign with MetaMask
7. Copy and paste the signature
8. You're logged in!

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

---

## Troubleshooting

### Check PAM logs

```bash
sudo grep pam_web3 /var/log/auth.log | tail -20
```

### Check web3-auth-svc logs

```bash
sudo journalctl -u web3-auth-svc -f
```

### Test web3-auth-svc directly

```python
#!/usr/bin/env python3
import socket
import struct
import json

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('/run/web3-auth/web3-auth.sock')

with open('/etc/pam_web3/server.key', 'r') as f:
    private_key = f.read().strip()

request = {
    "method": "verify_access",
    "params": {
        "wallet_address": "0xYourWalletAddress",
        "machine_private_key": private_key,
        "expected_machine_id": "your-server-hostname",
        "contract_address": "0xYourContractAddress"
    }
}

data = json.dumps(request).encode()
sock.sendall(struct.pack('>I', len(data)) + data)

length = struct.unpack('>I', sock.recv(4))[0]
response = sock.recv(length)
print(json.dumps(json.loads(response), indent=2))
sock.close()
```

### Common Issues

| Issue | Solution |
|-------|----------|
| "NFT not found" | Check wallet owns NFT, contract address is correct |
| "LDAP validation failed" | Check LDAP entry exists with matching token ID |
| "Signature recovery failed" | Ensure signing correct message format |
| "Connection timed out" | Check web3-auth-svc is running, socket permissions |

## Revoking Access

To revoke access without burning the NFT:

```bash
# Update LDAP entry
ldapmodify -x -D "cn=admin,dc=example,dc=com" -W << EOF
dn: cn=token0,ou=nft,dc=example,dc=com
changetype: modify
replace: nftRevoked
nftRevoked: TRUE
EOF
```

## Security Considerations

1. **Private keys**: Store `server.key` and `deployer.key` securely, never commit to git
2. **LDAP password**: Use a strong password, restrict access to `ldap.secret`
3. **RPC endpoint**: Consider using a private RPC endpoint for production
4. **OTP TTL**: Default 300 seconds, adjust based on security requirements
5. **Socket permissions**: web3-auth-svc socket is root-only by default
