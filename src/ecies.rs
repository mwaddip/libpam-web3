//! Encryption modules for machine ID protection
//!
//! Supports three encryption schemes:
//! - **secp256k1 ECIES**: For server-side decryption (server_encrypted field)
//! - **x25519-xsalsa20-poly1305**: For user wallet decryption via eth_decrypt (legacy)
//! - **AES-256-GCM with signature-derived key**: For user decryption (user_encrypted field)
//!
//! The signature-derived encryption scheme works by:
//! 1. User signs a deterministic message with their wallet
//! 2. Key is derived: K = keccak256(signature)
//! 3. Data is encrypted/decrypted with AES-256-GCM using key K
//!
//! This allows decryption without exposing the user's private key.

use aes_gcm::{
    aead::{Aead as AesAead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use crypto_box::{
    aead::{AeadCore, OsRng},
    PublicKey as X25519PublicKey, SalsaBox, SecretKey as X25519SecretKey,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EciesError {
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid ciphertext format")]
    InvalidCiphertext,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("ecies error: {0}")]
    EciesLibError(String),
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

/// Encryption scheme identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionScheme {
    /// secp256k1 ECIES - for server decryption
    Secp256k1Ecies,
    /// x25519-xsalsa20-poly1305 - for wallet eth_decrypt (legacy)
    X25519XSalsa20Poly1305,
    /// AES-256-GCM with signature-derived key - for user decryption
    SignatureDerivedAesGcm,
}

// ============================================================================
// secp256k1 ECIES (for server_encrypted)
// ============================================================================

/// Decrypt data using secp256k1 ECIES with the machine's private key
///
/// # Arguments
/// * `private_key` - The machine's ECIES private key (32 bytes)
/// * `ciphertext` - The encrypted data (hex string with optional 0x prefix)
///
/// # Returns
/// The decrypted plaintext as a UTF-8 string
pub fn decrypt(private_key: &[u8], ciphertext: &str) -> Result<String, EciesError> {
    if private_key.len() != 32 {
        return Err(EciesError::InvalidPrivateKey);
    }

    let ciphertext_hex = ciphertext.trim();
    let ciphertext_hex = ciphertext_hex.strip_prefix("0x").unwrap_or(ciphertext_hex);
    let ciphertext_bytes = hex::decode(ciphertext_hex)?;

    if ciphertext_bytes.is_empty() {
        return Err(EciesError::InvalidCiphertext);
    }

    // Use the ecies crate for decryption
    let plaintext = ecies::decrypt(private_key, &ciphertext_bytes)
        .map_err(|e| EciesError::EciesLibError(e.to_string()))?;

    String::from_utf8(plaintext).map_err(|_| EciesError::DecryptionFailed)
}

/// Encrypt data using secp256k1 ECIES with a public key
///
/// # Arguments
/// * `public_key` - The recipient's ECIES public key (65 bytes uncompressed, or 33 bytes compressed)
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// The ciphertext as a hex string with 0x prefix
pub fn encrypt(public_key: &[u8], plaintext: &str) -> Result<String, EciesError> {
    let ciphertext = ecies::encrypt(public_key, plaintext.as_bytes())
        .map_err(|e| EciesError::EciesLibError(e.to_string()))?;

    Ok(format!("0x{}", hex::encode(ciphertext)))
}

/// Generate a new secp256k1 ECIES keypair
///
/// # Returns
/// A tuple of (private_key_hex, public_key_hex)
pub fn generate_keypair() -> (String, String) {
    let (sk, pk) = ecies::utils::generate_keypair();
    let sk_bytes = sk.serialize();
    let pk_bytes = pk.serialize();

    (hex::encode(sk_bytes), hex::encode(pk_bytes))
}

/// Derive the secp256k1 public key from a private key
///
/// # Arguments
/// * `private_key` - The ECIES private key (32 bytes)
///
/// # Returns
/// The public key as a hex string
pub fn derive_public_key(private_key: &[u8]) -> Result<String, EciesError> {
    if private_key.len() != 32 {
        return Err(EciesError::InvalidPrivateKey);
    }

    let sk = ecies::SecretKey::parse_slice(private_key)
        .map_err(|e| EciesError::EciesLibError(e.to_string()))?;

    let pk = ecies::PublicKey::from_secret_key(&sk);
    Ok(hex::encode(pk.serialize()))
}

// ============================================================================
// x25519-xsalsa20-poly1305 (for user_encrypted / eth_decrypt)
// ============================================================================

/// eth_decrypt ciphertext format (NaCl crypto_box)
#[derive(Debug, Serialize, Deserialize)]
pub struct EthEncryptedData {
    pub version: String,
    pub nonce: String,
    #[serde(rename = "ephemPublicKey")]
    pub ephem_public_key: String,
    pub ciphertext: String,
}

impl EthEncryptedData {
    pub const VERSION: &'static str = "x25519-xsalsa20-poly1305";
}

/// Encrypt data for eth_decrypt (x25519-xsalsa20-poly1305)
///
/// This produces output compatible with MetaMask's eth_decrypt method.
///
/// # Arguments
/// * `public_key` - The recipient's x25519 public key (32 bytes, from eth_getEncryptionPublicKey)
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// The ciphertext as a hex-encoded JSON string (0x prefix) for storage in NFT metadata
pub fn encrypt_for_eth_decrypt(public_key: &[u8], plaintext: &str) -> Result<String, EciesError> {
    if public_key.len() != 32 {
        return Err(EciesError::InvalidPublicKey);
    }

    // Parse the recipient's public key
    let recipient_pk: X25519PublicKey = public_key
        .try_into()
        .map_err(|_| EciesError::InvalidPublicKey)?;

    // Generate ephemeral keypair
    let ephemeral_sk = X25519SecretKey::generate(&mut OsRng);
    let ephemeral_pk = ephemeral_sk.public_key();

    // Create the box for encryption
    let salsa_box = SalsaBox::new(&recipient_pk, &ephemeral_sk);

    // Generate random nonce
    let nonce = SalsaBox::generate_nonce(&mut OsRng);

    // Encrypt
    let ciphertext = salsa_box
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| EciesError::EncryptionFailed)?;

    // Build the eth_decrypt format
    let encrypted_data = EthEncryptedData {
        version: EthEncryptedData::VERSION.to_string(),
        nonce: BASE64.encode(nonce.as_slice()),
        ephem_public_key: BASE64.encode(ephemeral_pk.as_bytes()),
        ciphertext: BASE64.encode(&ciphertext),
    };

    // Serialize to JSON, then hex encode for NFT storage
    let json = serde_json::to_string(&encrypted_data)?;
    Ok(format!("0x{}", hex::encode(json.as_bytes())))
}

/// Decrypt data from eth_decrypt format (x25519-xsalsa20-poly1305)
///
/// This is primarily for testing; actual decryption happens in the wallet.
///
/// # Arguments
/// * `private_key` - The recipient's x25519 private key (32 bytes)
/// * `ciphertext` - The encrypted data (hex-encoded JSON or raw JSON or base64 JSON)
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_eth_encrypted(private_key: &[u8], ciphertext: &str) -> Result<String, EciesError> {
    if private_key.len() != 32 {
        return Err(EciesError::InvalidPrivateKey);
    }

    // Parse the ciphertext - could be hex-encoded JSON, raw JSON, or base64 JSON
    let json_str = if ciphertext.starts_with("0x") {
        // Hex-encoded JSON
        let bytes = hex::decode(ciphertext.strip_prefix("0x").unwrap())?;
        String::from_utf8(bytes).map_err(|_| EciesError::InvalidCiphertext)?
    } else if ciphertext.starts_with('{') {
        // Raw JSON
        ciphertext.to_string()
    } else {
        // Assume base64-encoded JSON
        let bytes = BASE64.decode(ciphertext)?;
        String::from_utf8(bytes).map_err(|_| EciesError::InvalidCiphertext)?
    };

    let encrypted_data: EthEncryptedData = serde_json::from_str(&json_str)?;

    if encrypted_data.version != EthEncryptedData::VERSION {
        return Err(EciesError::InvalidCiphertext);
    }

    // Decode base64 fields
    let nonce_bytes = BASE64.decode(&encrypted_data.nonce)?;
    let ephem_pk_bytes = BASE64.decode(&encrypted_data.ephem_public_key)?;
    let ciphertext_bytes = BASE64.decode(&encrypted_data.ciphertext)?;

    // Parse keys
    let recipient_sk: X25519SecretKey = private_key
        .try_into()
        .map_err(|_| EciesError::InvalidPrivateKey)?;

    let ephem_pk: X25519PublicKey = ephem_pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| EciesError::InvalidCiphertext)?;

    let nonce: [u8; 24] = nonce_bytes
        .try_into()
        .map_err(|_| EciesError::InvalidCiphertext)?;

    // Create box and decrypt
    let salsa_box = SalsaBox::new(&ephem_pk, &recipient_sk);
    let plaintext = salsa_box
        .decrypt(&nonce.into(), ciphertext_bytes.as_slice())
        .map_err(|_| EciesError::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|_| EciesError::DecryptionFailed)
}

/// Generate a new x25519 keypair (for testing)
///
/// # Returns
/// A tuple of (private_key_hex, public_key_hex)
pub fn generate_x25519_keypair() -> (String, String) {
    let sk = X25519SecretKey::generate(&mut OsRng);
    let pk = sk.public_key();

    (hex::encode(sk.to_bytes()), hex::encode(pk.as_bytes()))
}

/// Get the x25519 encryption public key from an Ethereum private key
///
/// MetaMask derives the x25519 key using nacl.box.keyPair.fromSecretKey
/// with the raw 32-byte Ethereum private key.
///
/// # Arguments
/// * `eth_private_key` - The Ethereum private key (32 bytes)
///
/// # Returns
/// The x25519 public key as a hex string (32 bytes)
pub fn derive_x25519_public_key(eth_private_key: &[u8]) -> Result<String, EciesError> {
    if eth_private_key.len() != 32 {
        return Err(EciesError::InvalidPrivateKey);
    }

    // MetaMask uses the raw private key bytes as the x25519 secret key
    let sk: X25519SecretKey = eth_private_key
        .try_into()
        .map_err(|_| EciesError::InvalidPrivateKey)?;
    let pk = sk.public_key();

    Ok(hex::encode(pk.as_bytes()))
}

// ============================================================================
// AES-256-GCM with signature-derived key (for user_encrypted)
// ============================================================================

/// Nonce size for AES-GCM (12 bytes / 96 bits)
const AES_GCM_NONCE_SIZE: usize = 12;

/// Derive a 32-byte AES key from an Ethereum signature using keccak256
///
/// # Arguments
/// * `signature` - The Ethereum signature (65 bytes with recovery id, or 64 bytes without)
///
/// # Returns
/// A 32-byte key suitable for AES-256
pub fn derive_key_from_signature(signature: &[u8]) -> Result<[u8; 32], EciesError> {
    if signature.len() < 64 {
        return Err(EciesError::InvalidCiphertext);
    }

    let mut hasher = Keccak256::new();
    hasher.update(signature);
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    Ok(key)
}

/// Derive a 32-byte AES key from a signature hex string
///
/// # Arguments
/// * `signature_hex` - The signature as a hex string (with optional 0x prefix)
///
/// # Returns
/// A 32-byte key suitable for AES-256
pub fn derive_key_from_signature_hex(signature_hex: &str) -> Result<[u8; 32], EciesError> {
    let signature_hex = signature_hex
        .strip_prefix("0x")
        .unwrap_or(signature_hex);
    let signature_bytes = hex::decode(signature_hex)?;
    derive_key_from_signature(&signature_bytes)
}

/// Encrypt data using AES-256-GCM with a signature-derived key
///
/// The ciphertext format is: nonce (12 bytes) || ciphertext
///
/// # Arguments
/// * `signature` - The Ethereum signature to derive the key from
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// The ciphertext as a hex string with 0x prefix
pub fn encrypt_symmetric(signature: &[u8], plaintext: &str) -> Result<String, EciesError> {
    let key = derive_key_from_signature(signature)?;
    encrypt_with_key(&key, plaintext)
}

/// Encrypt data using AES-256-GCM with a signature-derived key (hex signature)
///
/// # Arguments
/// * `signature_hex` - The signature as a hex string (with optional 0x prefix)
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// The ciphertext as a hex string with 0x prefix
pub fn encrypt_symmetric_hex(signature_hex: &str, plaintext: &str) -> Result<String, EciesError> {
    let key = derive_key_from_signature_hex(signature_hex)?;
    encrypt_with_key(&key, plaintext)
}

/// Encrypt data using AES-256-GCM with a raw 32-byte key
///
/// # Arguments
/// * `key` - A 32-byte AES key
/// * `plaintext` - The data to encrypt
///
/// # Returns
/// The ciphertext as a hex string with 0x prefix (nonce || ciphertext)
pub fn encrypt_with_key(key: &[u8; 32], plaintext: &str) -> Result<String, EciesError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EciesError::EncryptionFailed)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| EciesError::EncryptionFailed)?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(format!("0x{}", hex::encode(result)))
}

/// Decrypt data using AES-256-GCM with a signature-derived key
///
/// # Arguments
/// * `signature` - The Ethereum signature to derive the key from
/// * `ciphertext` - The encrypted data (hex string with optional 0x prefix)
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_symmetric(signature: &[u8], ciphertext: &str) -> Result<String, EciesError> {
    let key = derive_key_from_signature(signature)?;
    decrypt_with_key(&key, ciphertext)
}

/// Decrypt data using AES-256-GCM with a signature-derived key (hex signature)
///
/// # Arguments
/// * `signature_hex` - The signature as a hex string (with optional 0x prefix)
/// * `ciphertext` - The encrypted data (hex string with optional 0x prefix)
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_symmetric_hex(signature_hex: &str, ciphertext: &str) -> Result<String, EciesError> {
    let key = derive_key_from_signature_hex(signature_hex)?;
    decrypt_with_key(&key, ciphertext)
}

/// Decrypt data using AES-256-GCM with a raw 32-byte key
///
/// # Arguments
/// * `key` - A 32-byte AES key
/// * `ciphertext` - The encrypted data (hex string with optional 0x prefix, format: nonce || ciphertext)
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_with_key(key: &[u8; 32], ciphertext: &str) -> Result<String, EciesError> {
    let ciphertext_hex = ciphertext.strip_prefix("0x").unwrap_or(ciphertext);
    let ciphertext_bytes = hex::decode(ciphertext_hex)?;

    if ciphertext_bytes.len() < AES_GCM_NONCE_SIZE + 1 {
        return Err(EciesError::InvalidCiphertext);
    }

    // Split nonce and ciphertext
    let (nonce_bytes, encrypted) = ciphertext_bytes.split_at(AES_GCM_NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EciesError::DecryptionFailed)?;

    let plaintext = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| EciesError::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|_| EciesError::DecryptionFailed)
}

// ============================================================================
// Unified interface
// ============================================================================

/// Encrypt data with the specified scheme
///
/// Note: For SignatureDerivedAesGcm, pass the signature bytes as `key_or_signature`
pub fn encrypt_with_scheme(
    scheme: EncryptionScheme,
    key_or_signature: &[u8],
    plaintext: &str,
) -> Result<String, EciesError> {
    match scheme {
        EncryptionScheme::Secp256k1Ecies => encrypt(key_or_signature, plaintext),
        EncryptionScheme::X25519XSalsa20Poly1305 => {
            encrypt_for_eth_decrypt(key_or_signature, plaintext)
        }
        EncryptionScheme::SignatureDerivedAesGcm => {
            encrypt_symmetric(key_or_signature, plaintext)
        }
    }
}

/// Decrypt data with the specified scheme
///
/// Note: For SignatureDerivedAesGcm, pass the signature bytes as `key_or_signature`
pub fn decrypt_with_scheme(
    scheme: EncryptionScheme,
    key_or_signature: &[u8],
    ciphertext: &str,
) -> Result<String, EciesError> {
    match scheme {
        EncryptionScheme::Secp256k1Ecies => decrypt(key_or_signature, ciphertext),
        EncryptionScheme::X25519XSalsa20Poly1305 => {
            decrypt_eth_encrypted(key_or_signature, ciphertext)
        }
        EncryptionScheme::SignatureDerivedAesGcm => {
            decrypt_symmetric(key_or_signature, ciphertext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (sk, pk) = generate_keypair();

        // Private key should be 32 bytes = 64 hex chars
        assert_eq!(sk.len(), 64);
        // Public key (uncompressed) should be 65 bytes = 130 hex chars
        assert_eq!(pk.len(), 130);
    }

    #[test]
    fn test_secp256k1_encrypt_decrypt_roundtrip() {
        let (sk_hex, pk_hex) = generate_keypair();
        let sk = hex::decode(&sk_hex).unwrap();
        let pk = hex::decode(&pk_hex).unwrap();

        let plaintext = "server-prod-01";
        let ciphertext = encrypt(&pk, plaintext).unwrap();
        let decrypted = decrypt(&sk, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_derive_public_key() {
        let (sk_hex, pk_hex) = generate_keypair();
        let sk = hex::decode(&sk_hex).unwrap();

        let derived_pk = derive_public_key(&sk).unwrap();

        assert_eq!(derived_pk, pk_hex);
    }

    #[test]
    fn test_decrypt_invalid_key_length() {
        let result = decrypt(&[0u8; 16], "0xabcd");
        assert!(matches!(result, Err(EciesError::InvalidPrivateKey)));
    }

    #[test]
    fn test_x25519_generate_keypair() {
        let (sk, pk) = generate_x25519_keypair();

        // x25519 keys are 32 bytes = 64 hex chars
        assert_eq!(sk.len(), 64);
        assert_eq!(pk.len(), 64);
    }

    #[test]
    fn test_eth_decrypt_roundtrip() {
        let (sk_hex, pk_hex) = generate_x25519_keypair();
        let sk = hex::decode(&sk_hex).unwrap();
        let pk = hex::decode(&pk_hex).unwrap();

        let plaintext = "server-prod-01";
        let ciphertext = encrypt_for_eth_decrypt(&pk, plaintext).unwrap();
        let decrypted = decrypt_eth_encrypted(&sk, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_eth_decrypt_json_format() {
        let (_, pk_hex) = generate_x25519_keypair();
        let pk = hex::decode(&pk_hex).unwrap();

        let ciphertext = encrypt_for_eth_decrypt(&pk, "test").unwrap();

        // Should be hex-encoded
        assert!(ciphertext.starts_with("0x"));

        // Decode and verify JSON structure
        let json_bytes = hex::decode(ciphertext.strip_prefix("0x").unwrap()).unwrap();
        let json_str = String::from_utf8(json_bytes).unwrap();
        let data: EthEncryptedData = serde_json::from_str(&json_str).unwrap();

        assert_eq!(data.version, "x25519-xsalsa20-poly1305");
        assert!(!data.nonce.is_empty());
        assert!(!data.ephem_public_key.is_empty());
        assert!(!data.ciphertext.is_empty());
    }

    #[test]
    fn test_derive_x25519_public_key() {
        // Use a known private key
        let private_key = [1u8; 32];
        let pk_hex = derive_x25519_public_key(&private_key).unwrap();

        // Should be 32 bytes = 64 hex chars
        assert_eq!(pk_hex.len(), 64);

        // Encrypt/decrypt should work with derived key
        let pk = hex::decode(&pk_hex).unwrap();
        let ciphertext = encrypt_for_eth_decrypt(&pk, "test").unwrap();
        let decrypted = decrypt_eth_encrypted(&private_key, &ciphertext).unwrap();
        assert_eq!(decrypted, "test");
    }

    #[test]
    fn test_unified_interface() {
        // Test secp256k1
        let (sk_hex, pk_hex) = generate_keypair();
        let sk = hex::decode(&sk_hex).unwrap();
        let pk = hex::decode(&pk_hex).unwrap();

        let ct = encrypt_with_scheme(EncryptionScheme::Secp256k1Ecies, &pk, "test1").unwrap();
        let pt = decrypt_with_scheme(EncryptionScheme::Secp256k1Ecies, &sk, &ct).unwrap();
        assert_eq!(pt, "test1");

        // Test x25519
        let (sk_hex, pk_hex) = generate_x25519_keypair();
        let sk = hex::decode(&sk_hex).unwrap();
        let pk = hex::decode(&pk_hex).unwrap();

        let ct =
            encrypt_with_scheme(EncryptionScheme::X25519XSalsa20Poly1305, &pk, "test2").unwrap();
        let pt = decrypt_with_scheme(EncryptionScheme::X25519XSalsa20Poly1305, &sk, &ct).unwrap();
        assert_eq!(pt, "test2");
    }

    // =========================================================================
    // Symmetric encryption tests (signature-derived AES-GCM)
    // =========================================================================

    #[test]
    fn test_derive_key_from_signature() {
        // A mock 65-byte signature (r, s, v)
        let signature = [0x42u8; 65];
        let key = derive_key_from_signature(&signature).unwrap();

        // Key should be 32 bytes
        assert_eq!(key.len(), 32);

        // Same signature should produce same key
        let key2 = derive_key_from_signature(&signature).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_derive_key_from_signature_hex() {
        let sig_hex = "0x" .to_string() + &"42".repeat(65);
        let key = derive_key_from_signature_hex(&sig_hex).unwrap();
        assert_eq!(key.len(), 32);

        // Without 0x prefix should work too
        let sig_hex_no_prefix = "42".repeat(65);
        let key2 = derive_key_from_signature_hex(&sig_hex_no_prefix).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_symmetric_encrypt_decrypt_roundtrip() {
        let signature = [0x42u8; 65];
        let plaintext = "server-prod-01";

        let ciphertext = encrypt_symmetric(&signature, plaintext).unwrap();
        let decrypted = decrypt_symmetric(&signature, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_symmetric_encrypt_decrypt_hex_roundtrip() {
        let sig_hex = "0x".to_string() + &"ab".repeat(65);
        let plaintext = "192.168.1.100:22";

        let ciphertext = encrypt_symmetric_hex(&sig_hex, plaintext).unwrap();
        let decrypted = decrypt_symmetric_hex(&sig_hex, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_symmetric_ciphertext_format() {
        let signature = [0x42u8; 65];
        let ciphertext = encrypt_symmetric(&signature, "test").unwrap();

        // Should be hex-encoded with 0x prefix
        assert!(ciphertext.starts_with("0x"));

        // Should contain at least nonce (12 bytes) + some ciphertext
        let ct_bytes = hex::decode(ciphertext.strip_prefix("0x").unwrap()).unwrap();
        assert!(ct_bytes.len() > 12);
    }

    #[test]
    fn test_symmetric_different_signatures_different_ciphertexts() {
        let sig1 = [0x42u8; 65];
        let sig2 = [0x43u8; 65];
        let plaintext = "test";

        let ct1 = encrypt_symmetric(&sig1, plaintext).unwrap();
        let ct2 = encrypt_symmetric(&sig2, plaintext).unwrap();

        // Different signatures should produce different keys, so decryption should fail
        let result = decrypt_symmetric(&sig1, &ct2);
        assert!(result.is_err());
    }

    #[test]
    fn test_symmetric_via_unified_interface() {
        let signature = [0xaau8; 65];
        let plaintext = "unified-test";

        let ct =
            encrypt_with_scheme(EncryptionScheme::SignatureDerivedAesGcm, &signature, plaintext)
                .unwrap();
        let pt =
            decrypt_with_scheme(EncryptionScheme::SignatureDerivedAesGcm, &signature, &ct).unwrap();

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_encrypt_with_key_roundtrip() {
        let key = [0x55u8; 32];
        let plaintext = "direct-key-test";

        let ciphertext = encrypt_with_key(&key, plaintext).unwrap();
        let decrypted = decrypt_with_key(&key, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
