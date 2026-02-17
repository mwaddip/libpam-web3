//! Unified configuration for pam_web3
//!
//! Configuration is loaded from /etc/pam_web3/config.toml

use serde::Deserialize;
use std::fs;
use std::path::Path;
use thiserror::Error;

const DEFAULT_CONFIG_PATH: &str = "/etc/pam_web3/config.toml";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Main configuration structure
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub machine: MachineConfig,
    pub auth: AuthConfig,
}

/// Machine identification and key configuration
#[derive(Debug, Clone, Deserialize)]
pub struct MachineConfig {
    /// Unique identifier for this machine
    pub id: String,
    /// Secret key for OTP HMAC (hex encoded)
    #[serde(default)]
    pub secret_key: Option<String>,
}

/// Authentication settings
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// URL where users can sign the OTP
    pub signing_url: String,
    /// OTP code length (default: 6)
    #[serde(default = "default_otp_length")]
    pub otp_length: usize,
    /// OTP validity in seconds (default: 300)
    #[serde(default = "default_otp_ttl")]
    pub otp_ttl_seconds: u64,
}

// Default value functions
fn default_otp_length() -> usize {
    6
}

fn default_otp_ttl() -> u64 {
    300
}

impl Config {
    /// Load configuration from the default path
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(DEFAULT_CONFIG_PATH)
    }

    /// Load configuration from a specific path
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> Result<(), ConfigError> {
        let key = self
            .machine
            .secret_key
            .as_ref()
            .ok_or(ConfigError::MissingField("machine.secret_key"))?;

        // Secret key must be at least 16 bytes (32 hex chars) for HMAC security
        let hex_str = key.strip_prefix("0x").unwrap_or(key);
        if hex_str.len() < 32 {
            return Err(ConfigError::InvalidConfig(
                "machine.secret_key must be at least 16 bytes (32 hex chars)".to_string(),
            ));
        }

        // OTP length must be 4..=19 (10^20 overflows u64)
        if self.auth.otp_length < 4 || self.auth.otp_length > 19 {
            return Err(ConfigError::InvalidConfig(
                "auth.otp_length must be between 4 and 19".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the secret key bytes (for OTP HMAC)
    pub fn secret_key_bytes(&self) -> Result<Vec<u8>, ConfigError> {
        let key = self
            .machine
            .secret_key
            .as_ref()
            .ok_or(ConfigError::MissingField("machine.secret_key"))?;
        let key = key.strip_prefix("0x").unwrap_or(key);
        hex::decode(key).map_err(|e| {
            ConfigError::InvalidConfig(format!("invalid hex in secret_key: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let config_str = r#"
[machine]
id = "my-server"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
signing_url = "https://example.com/sign"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert_eq!(config.machine.id, "my-server");
        assert_eq!(config.auth.otp_length, 6); // default
        assert_eq!(config.auth.otp_ttl_seconds, 300); // default
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_full_config() {
        let config_str = r#"
[machine]
id = "server-prod-01"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
signing_url = "https://auth.example.com/verify"
otp_length = 8
otp_ttl_seconds = 600
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert_eq!(config.machine.id, "server-prod-01");
        assert_eq!(config.auth.otp_length, 8);
        assert_eq!(config.auth.otp_ttl_seconds, 600);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_missing_secret_key() {
        let config_str = r#"
[machine]
id = "my-server"

[auth]
signing_url = "https://example.com/sign"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_secret_key_bytes() {
        let config_str = r#"
[machine]
id = "my-server"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
signing_url = "https://example.com/sign"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        let bytes = config.secret_key_bytes().unwrap();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_secret_key_bytes_no_prefix() {
        let config_str = r#"
[machine]
id = "my-server"
secret_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
signing_url = "https://example.com/sign"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        let bytes = config.secret_key_bytes().unwrap();
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_short_secret_key_rejected() {
        let config_str = r#"
[machine]
id = "my-server"
secret_key = "0xdeadbeef"

[auth]
signing_url = "https://example.com/sign"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_otp_length_bounds() {
        // Too short
        let config_str = r#"
[machine]
id = "my-server"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
signing_url = "https://example.com/sign"
otp_length = 3
"#;
        let config: Config = toml::from_str(config_str).unwrap();
        assert!(config.validate().is_err());

        // Too long (would overflow u64)
        let config_str = r#"
[machine]
id = "my-server"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
signing_url = "https://example.com/sign"
otp_length = 20
"#;
        let config: Config = toml::from_str(config_str).unwrap();
        assert!(config.validate().is_err());
    }
}
