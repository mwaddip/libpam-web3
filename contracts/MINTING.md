# NFT Minting Guide

This document describes how to mint AccessCredentialNFT tokens with user-encrypted connection details.

## Overview

When a user purchases VM access, they provide a signature that will later let them decrypt their connection details. This signature is encrypted for transport to protect it in transit.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              MINTING FLOW                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  User (Browser)                    Subscription Manager         Blockchain   │
│       │                                    │                        │        │
│       │ 1. Sign decryptMessage             │                        │        │
│       │    with wallet                     │                        │        │
│       │                                    │                        │        │
│       │ 2. Encrypt signature with          │                        │        │
│       │    server public key (ECIES)       │                        │        │
│       │                                    │                        │        │
│       │──── encryptedSignature ───────────>│                        │        │
│       │     + decryptMessage               │                        │        │
│       │     + wallet address               │                        │        │
│       │                                    │                        │        │
│       │                           3. Decrypt signature              │        │
│       │                              with server private key        │        │
│       │                                    │                        │        │
│       │                           4. Provision VM                   │        │
│       │                              → get IP address               │        │
│       │                                    │                        │        │
│       │                           5. Encrypt connection details     │        │
│       │                              key = keccak256(signature)     │        │
│       │                              userEncrypted = AES-GCM(...)   │        │
│       │                                    │                        │        │
│       │                           6. Call mint() ──────────────────>│        │
│       │                                    │                        │        │
│       │<────────────────────── NFT appears in wallet ───────────────│        │
│       │                                    │                        │        │
│       │ 7. Later: sign same message        │                        │        │
│       │    → derive key → decrypt          │                        │        │
│       │    → get hostname/port             │                        │        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Step-by-Step Implementation

### Step 1: Server Keypair Setup

The subscription manager needs a secp256k1 keypair for receiving encrypted signatures.

```bash
# Generate keypair
pam_web3_tool generate-keypair --output /etc/subscription-manager/server.key --show-pubkey

# Output:
# Private key written to: /etc/subscription-manager/server.key
# Permissions set to 600 (owner read/write only)
# Public key (hex): 04a1b2c3...  ← Share this with the signing page
```

The **public key** is embedded in the signing page so users can encrypt their signatures.

### Step 2: User Signs and Encrypts (Browser/Signing Page)

The signing page handles this automatically. For reference:

```javascript
// 1. User signs the decrypt message
const decryptMessage = "Decrypt BlockHost credentials";
const signature = await ethereum.request({
    method: 'personal_sign',
    params: [decryptMessage, walletAddress]
});

// 2. Encrypt signature with server's public key (ECIES)
// Using eth-crypto or similar library
const encryptedSignature = await EthCrypto.encryptWithPublicKey(
    serverPublicKey,  // The 04... hex public key
    signature
);

// 3. Send to subscription manager
await fetch('/api/provision', {
    body: JSON.stringify({
        walletAddress,
        decryptMessage,
        encryptedSignature: EthCrypto.cipher.stringify(encryptedSignature)
    })
});
```

### Step 3: Decrypt User's Signature (Subscription Manager)

The subscription manager receives the encrypted signature and decrypts it.

#### Using pam_web3_tool (CLI)

```bash
pam_web3_tool decrypt \
    --scheme secp256k1 \
    --private-key-file /etc/subscription-manager/server.key \
    --ciphertext "<encrypted_signature_hex>"
```

#### Using Rust

```rust
use pam_web3::ecies;
use std::fs;

fn decrypt_user_signature(encrypted_signature: &str) -> Result<String, Box<dyn Error>> {
    let private_key = fs::read_to_string("/etc/subscription-manager/server.key")?
        .trim()
        .to_string();
    let private_key_bytes = hex::decode(&private_key)?;

    let signature = ecies::decrypt(&private_key_bytes, encrypted_signature)?;
    Ok(signature)
}
```

#### Using JavaScript/Node

```javascript
const EthCrypto = require('eth-crypto');
const fs = require('fs');

async function decryptUserSignature(encryptedSignature) {
    const privateKey = fs.readFileSync('/etc/subscription-manager/server.key', 'utf8').trim();

    const parsed = EthCrypto.cipher.parse(encryptedSignature);
    const signature = await EthCrypto.decryptWithPrivateKey(privateKey, parsed);

    return signature;
}
```

### Step 4: Encrypt Connection Details

After provisioning the VM and obtaining the IP address, encrypt the connection details using the user's signature.

#### Encryption Format

```
Key derivation:  key = keccak256(signature_bytes)
Cipher:          AES-256-GCM
Output format:   IV (12 bytes) || ciphertext || authTag (16 bytes)
Encoding:        Hex string (no 0x prefix)
```

#### Using pam_web3_tool (CLI)

```bash
pam_web3_tool encrypt-symmetric \
    --signature "0x<decrypted_user_signature>" \
    --plaintext '{"hostname":"192.168.1.100","port":22}'

# Output:
# Ciphertext (hex): a1b2c3d4e5f6...
```

#### Using Rust

```rust
use pam_web3::ecies::encrypt_symmetric_hex;

fn encrypt_connection_details(
    user_signature: &str,
    hostname: &str,
    port: u16,
) -> Result<String, Box<dyn Error>> {
    let connection_info = serde_json::json!({
        "hostname": hostname,
        "port": port
    }).to_string();

    let encrypted = encrypt_symmetric_hex(user_signature, &connection_info)?;
    Ok(encrypted)
}
```

#### Using JavaScript/Node

```javascript
const crypto = require('crypto');
const { keccak256, toUtf8Bytes } = require('ethers');

function encryptConnectionDetails(signatureHex, connectionDetails) {
    // Remove 0x prefix if present
    const sigBytes = Buffer.from(signatureHex.replace(/^0x/, ''), 'hex');

    // Derive key: keccak256 of signature bytes
    const key = Buffer.from(keccak256(sigBytes).slice(2), 'hex');

    // Generate random IV
    const iv = crypto.randomBytes(12);

    // Encrypt with AES-256-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = typeof connectionDetails === 'string'
        ? connectionDetails
        : JSON.stringify(connectionDetails);

    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    // Combine: IV + ciphertext + authTag
    const combined = Buffer.concat([iv, encrypted, authTag]);

    return combined.toString('hex');
}

// Usage
const userEncrypted = encryptConnectionDetails(
    userSignature,
    { hostname: '192.168.1.100', port: 22 }
);
```

### Step 5: Mint the NFT

Call the contract's `mint()` function with the encrypted data.

#### Contract Function Signature

```solidity
function mint(
    address to,
    bytes calldata userEncrypted,
    string calldata decryptMessage,
    string calldata description,
    string calldata imageUri,
    string calldata animationUrlBase64,
    uint256 expiresAt
) external onlyOwner returns (uint256 tokenId)
```

#### Using Foundry/cast

```bash
source ~/projects/sharedenv/blockhost.env

cast send $BLOCKHOST_NFT \
    "mint(address,bytes,string,string,string,string,uint256)" \
    "$RECIPIENT_WALLET" \
    "0x<userEncrypted_hex>" \
    "Decrypt BlockHost credentials" \
    "VM Access - server-123" \
    "ipfs://QmImage..." \
    "" \
    0 \
    --private-key $DEPLOYER_PRIVATE_KEY \
    --rpc-url $SEPOLIA_RPC
```

#### Using ethers.js

```javascript
const { ethers } = require('ethers');

async function mintNFT({
    recipientAddress,
    userEncrypted,      // hex string from step 4
    decryptMessage,
    description,
    imageUri,
    animationUrlBase64 = '',
    expiresAt = 0
}) {
    const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC);
    const signer = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY, provider);

    const contract = new ethers.Contract(
        process.env.BLOCKHOST_NFT,
        ['function mint(address,bytes,string,string,string,string,uint256) returns (uint256)'],
        signer
    );

    const tx = await contract.mint(
        recipientAddress,
        '0x' + userEncrypted,
        decryptMessage,
        description,
        imageUri,
        animationUrlBase64,
        expiresAt
    );

    const receipt = await tx.wait();
    const tokenId = receipt.logs[0].topics[3]; // Transfer event tokenId

    return tokenId;
}
```

## Complete Example (Node.js)

```javascript
const crypto = require('crypto');
const { ethers, keccak256 } = require('ethers');
const EthCrypto = require('eth-crypto');
const fs = require('fs');

async function provisionAndMint(request) {
    const { walletAddress, decryptMessage, encryptedSignature } = request;

    // 1. Decrypt user's signature
    const privateKey = fs.readFileSync('/etc/subscription-manager/server.key', 'utf8').trim();
    const parsed = EthCrypto.cipher.parse(encryptedSignature);
    const userSignature = await EthCrypto.decryptWithPrivateKey(privateKey, parsed);

    // 2. Provision VM (your infrastructure code)
    const vm = await provisionVM({ walletAddress });
    const hostname = vm.ipAddress;
    const port = 22;

    // 3. Encrypt connection details
    const sigBytes = Buffer.from(userSignature.replace(/^0x/, ''), 'hex');
    const key = Buffer.from(keccak256(sigBytes).slice(2), 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(JSON.stringify({ hostname, port }), 'utf8'),
        cipher.final()
    ]);
    const userEncrypted = Buffer.concat([iv, encrypted, cipher.getAuthTag()]).toString('hex');

    // 4. Mint NFT
    const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC);
    const signer = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY, provider);
    const contract = new ethers.Contract(
        process.env.BLOCKHOST_NFT,
        ['function mint(address,bytes,string,string,string,string,uint256) returns (uint256)'],
        signer
    );

    const tx = await contract.mint(
        walletAddress,
        '0x' + userEncrypted,
        decryptMessage,
        `VM Access - ${hostname}`,
        'ipfs://QmDefaultImage...',
        '',
        0
    );

    await tx.wait();
    console.log(`Minted NFT for ${walletAddress}`);
}
```

## Security Considerations

1. **Server private key**: Store securely, never commit to git, use proper permissions (600)
2. **Signature verification**: Optionally verify the signature recovers to the claimed wallet address before processing
3. **Transport security**: Always use HTTPS for API endpoints
4. **Key rotation**: If server key is compromised, only transport encryption is affected (not user's encrypted data)

## Verification

After minting, verify the token URI contains correct data:

```bash
# Get token URI
cast call $BLOCKHOST_NFT "tokenURI(uint256)" <TOKEN_ID> --rpc-url $SEPOLIA_RPC | cast --to-ascii

# The returned JSON should contain:
# - "user_encrypted": "<hex_ciphertext>"
# - "decrypt_message": "<the message user signed>"
```

## Related Files

| File | Purpose |
|------|---------|
| `pam_web3_tool` | CLI for encryption/decryption operations |
| `src/ecies.rs` | Rust implementation of encryption schemes |
| `signing-page/` | Browser UI for wallet signing |
| `contracts/src/AccessCredentialNFT.sol` | NFT contract |
