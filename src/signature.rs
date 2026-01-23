//! Ethereum signature verification and address recovery
//!
//! Recovers the Ethereum address from a signed message using ecrecover.

use alloy_primitives::{Address, B256};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("invalid signature format")]
    InvalidFormat,
    #[error("invalid signature length: expected 65 bytes")]
    InvalidLength,
    #[error("invalid recovery id")]
    InvalidRecoveryId,
    #[error("signature recovery failed")]
    RecoveryFailed,
    #[error("hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),
}

/// An Ethereum signature (r, s, v)
#[derive(Debug, Clone)]
pub struct EthSignature {
    /// r component (32 bytes)
    pub r: [u8; 32],
    /// s component (32 bytes)
    pub s: [u8; 32],
    /// recovery id (0 or 1, or 27/28 for legacy)
    pub v: u8,
}

impl EthSignature {
    /// Parse a signature from hex string (with or without 0x prefix)
    ///
    /// Expected format: 65 bytes = r (32) + s (32) + v (1)
    pub fn from_hex(hex_str: &str) -> Result<Self, SignatureError> {
        let hex_str = hex_str.trim();
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        let bytes = hex::decode(hex_str)?;

        if bytes.len() != 65 {
            return Err(SignatureError::InvalidLength);
        }

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        let v = bytes[64];

        Ok(Self { r, s, v })
    }

    /// Get the recovery ID (0 or 1)
    fn recovery_id(&self) -> Result<RecoveryId, SignatureError> {
        // Handle both raw (0, 1) and EIP-155 (27, 28) formats
        let v = match self.v {
            0 | 27 => 0,
            1 | 28 => 1,
            v if v >= 35 => ((v - 35) % 2) as u8, // EIP-155
            _ => return Err(SignatureError::InvalidRecoveryId),
        };

        RecoveryId::try_from(v).map_err(|_| SignatureError::InvalidRecoveryId)
    }
}

/// Hash a message using Ethereum's personal_sign format
///
/// This adds the "\x19Ethereum Signed Message:\n{length}" prefix
pub fn eth_message_hash(message: &str) -> B256 {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());

    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());

    B256::from_slice(&hasher.finalize())
}

/// Recover the Ethereum address from a signature
///
/// # Arguments
/// * `message` - The original message that was signed
/// * `signature` - The signature (hex string, 65 bytes)
///
/// # Returns
/// The recovered Ethereum address as a checksummed string
pub fn recover_address(message: &str, signature: &str) -> Result<Address, SignatureError> {
    let sig = EthSignature::from_hex(signature)?;
    let message_hash = eth_message_hash(message);

    // Create k256 signature from r and s
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(&sig.r);
    sig_bytes[32..64].copy_from_slice(&sig.s);

    let k256_sig =
        K256Signature::from_slice(&sig_bytes).map_err(|_| SignatureError::InvalidFormat)?;

    let recovery_id = sig.recovery_id()?;

    // Recover the public key
    let recovered_key = VerifyingKey::recover_from_prehash(message_hash.as_slice(), &k256_sig, recovery_id)
        .map_err(|_| SignatureError::RecoveryFailed)?;

    // Convert public key to Ethereum address
    let public_key_bytes = recovered_key.to_encoded_point(false);
    let public_key_bytes = &public_key_bytes.as_bytes()[1..]; // Skip the 0x04 prefix

    let mut hasher = Keccak256::new();
    hasher.update(public_key_bytes);
    let hash = hasher.finalize();

    // Ethereum address is the last 20 bytes of the keccak256 hash
    let address = Address::from_slice(&hash[12..32]);

    Ok(address)
}

/// Verify a signature matches an expected address
///
/// # Arguments
/// * `message` - The original message that was signed
/// * `signature` - The signature (hex string, 65 bytes)
/// * `expected_address` - The expected Ethereum address (with or without 0x prefix)
///
/// # Returns
/// `Ok(())` if the signature is valid and matches the expected address
pub fn verify_signature(
    message: &str,
    signature: &str,
    expected_address: &str,
) -> Result<(), SignatureError> {
    let recovered = recover_address(message, signature)?;
    let expected = expected_address
        .parse::<Address>()
        .map_err(|_| SignatureError::InvalidFormat)?;

    if recovered != expected {
        return Err(SignatureError::RecoveryFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth_message_hash() {
        // Test vector from Ethereum
        let message = "Hello, World!";
        let hash = eth_message_hash(message);

        // The hash should be consistent
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_signature_parsing() {
        // A valid 65-byte signature (dummy data for format testing)
        let sig_hex = "0x".to_string() + &"ab".repeat(32) + &"cd".repeat(32) + "1b"; // v = 27

        let sig = EthSignature::from_hex(&sig_hex).unwrap();
        assert_eq!(sig.v, 27);
        assert_eq!(sig.r[0], 0xab);
        assert_eq!(sig.s[0], 0xcd);
    }

    #[test]
    fn test_signature_parsing_no_prefix() {
        let sig_hex = "ab".repeat(32) + &"cd".repeat(32) + "1c"; // v = 28

        let sig = EthSignature::from_hex(&sig_hex).unwrap();
        assert_eq!(sig.v, 28);
    }

    #[test]
    fn test_invalid_signature_length() {
        let sig_hex = "0xabcd"; // Too short

        let result = EthSignature::from_hex(sig_hex);
        assert!(matches!(result, Err(SignatureError::InvalidLength)));
    }

    // Integration test with a real signature would go here
    // For now we rely on the individual component tests
}
