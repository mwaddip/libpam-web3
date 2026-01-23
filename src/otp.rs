//! OTP (One-Time Password) generation and validation
//!
//! Generates cryptographically secure OTP codes that are bound to
//! a specific machine and have a short TTL to prevent replay attacks.

use rand::Rng;
use sha3::{Digest, Sha3_256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("OTP has expired")]
    Expired,
    #[error("OTP verification failed")]
    VerificationFailed,
    #[error("system time error")]
    TimeError,
}

/// Represents an OTP with its metadata
#[derive(Debug, Clone)]
pub struct Otp {
    /// The OTP code (numeric string)
    pub code: String,
    /// Unix timestamp when the OTP was created
    pub created_at: u64,
    /// Machine ID this OTP is bound to
    pub machine_id: String,
    /// HMAC for verification
    hmac: [u8; 32],
}

impl Otp {
    /// Generate a new OTP
    ///
    /// # Arguments
    /// * `length` - Number of digits in the OTP
    /// * `machine_id` - Machine ID to bind the OTP to
    /// * `secret` - Secret key for HMAC (should be the machine's private key or derived)
    pub fn generate(length: usize, machine_id: &str, secret: &[u8]) -> Result<Self, OtpError> {
        let mut rng = rand::thread_rng();

        // Generate random numeric code
        let max = 10u64.pow(length as u32);
        let code_num: u64 = rng.gen_range(0..max);
        let code = format!("{:0>width$}", code_num, width = length);

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OtpError::TimeError)?
            .as_secs();

        // Compute HMAC for verification
        let hmac = Self::compute_hmac(&code, created_at, machine_id, secret);

        Ok(Self {
            code,
            created_at,
            machine_id: machine_id.to_string(),
            hmac,
        })
    }

    /// Verify an OTP
    ///
    /// # Arguments
    /// * `code` - The OTP code to verify
    /// * `machine_id` - The machine ID to verify against
    /// * `secret` - The secret key used for HMAC
    /// * `ttl_seconds` - Maximum age of the OTP in seconds
    pub fn verify(
        &self,
        code: &str,
        machine_id: &str,
        secret: &[u8],
        ttl_seconds: u64,
    ) -> Result<(), OtpError> {
        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OtpError::TimeError)?
            .as_secs();

        if now > self.created_at + ttl_seconds {
            return Err(OtpError::Expired);
        }

        // Verify code matches
        if code != self.code {
            return Err(OtpError::VerificationFailed);
        }

        // Verify machine ID matches
        if machine_id != self.machine_id {
            return Err(OtpError::VerificationFailed);
        }

        // Verify HMAC
        let expected_hmac = Self::compute_hmac(&self.code, self.created_at, &self.machine_id, secret);
        if !constant_time_eq(&self.hmac, &expected_hmac) {
            return Err(OtpError::VerificationFailed);
        }

        Ok(())
    }

    /// Compute HMAC for OTP verification
    fn compute_hmac(code: &str, created_at: u64, machine_id: &str, secret: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(secret);
        hasher.update(code.as_bytes());
        hasher.update(created_at.to_le_bytes());
        hasher.update(machine_id.as_bytes());

        let result = hasher.finalize();
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&result);
        hmac
    }

    /// Get the message to be signed by the user's wallet
    ///
    /// This is what the user will sign with their Ethereum wallet
    pub fn signing_message(&self) -> String {
        format!(
            "Authenticate to {} with code: {}",
            self.machine_id, self.code
        )
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otp_generation() {
        let secret = b"test_secret_key_12345";
        let machine_id = "test-machine-01";

        let otp = Otp::generate(6, machine_id, secret).unwrap();

        assert_eq!(otp.code.len(), 6);
        assert!(otp.code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(otp.machine_id, machine_id);
    }

    #[test]
    fn test_otp_verification_success() {
        let secret = b"test_secret_key_12345";
        let machine_id = "test-machine-01";

        let otp = Otp::generate(6, machine_id, secret).unwrap();
        let code = otp.code.clone();

        let result = otp.verify(&code, machine_id, secret, 300);
        assert!(result.is_ok());
    }

    #[test]
    fn test_otp_verification_wrong_code() {
        let secret = b"test_secret_key_12345";
        let machine_id = "test-machine-01";

        let otp = Otp::generate(6, machine_id, secret).unwrap();

        let result = otp.verify("000000", machine_id, secret, 300);
        assert!(matches!(result, Err(OtpError::VerificationFailed)));
    }

    #[test]
    fn test_otp_verification_wrong_machine() {
        let secret = b"test_secret_key_12345";
        let machine_id = "test-machine-01";

        let otp = Otp::generate(6, machine_id, secret).unwrap();
        let code = otp.code.clone();

        let result = otp.verify(&code, "wrong-machine", secret, 300);
        assert!(matches!(result, Err(OtpError::VerificationFailed)));
    }

    #[test]
    fn test_signing_message() {
        let secret = b"test_secret_key_12345";
        let machine_id = "server-prod-01";

        let otp = Otp::generate(6, machine_id, secret).unwrap();
        let message = otp.signing_message();

        assert!(message.contains(&otp.code));
        assert!(message.contains(machine_id));
    }
}
