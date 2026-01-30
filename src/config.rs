//! Unified configuration for pam_web3
//!
//! Supports both wallet-based and NFT-based authentication modes.
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
    /// Wallet mode configuration (required when mode = "wallet")
    #[serde(default)]
    pub wallet: Option<WalletConfig>,
    /// Blockchain configuration (required when mode = "nft")
    #[serde(default)]
    pub blockchain: Option<BlockchainConfig>,
    /// LDAP configuration (required when mode = "nft")
    #[serde(default)]
    pub ldap: Option<LdapConfig>,
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
    /// Authentication mode: "wallet" or "nft"
    pub mode: AuthMode,
    /// URL where users can sign the OTP
    pub signing_url: String,
    /// OTP code length (default: 6)
    #[serde(default = "default_otp_length")]
    pub otp_length: usize,
    /// OTP validity in seconds (default: 300)
    #[serde(default = "default_otp_ttl")]
    pub otp_ttl_seconds: u64,
    /// NFT lookup method: "ldap" or "passwd" (default: ldap)
    /// Only used when mode = "nft"
    #[serde(default)]
    pub nft_lookup: NftLookupMethod,
}

/// Authentication mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Wallet,
    Nft,
}

/// NFT lookup method for mapping token IDs to usernames
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NftLookupMethod {
    /// Use LDAP for token ID to username mapping and revocation checking
    #[default]
    Ldap,
    /// Use /etc/passwd GECOS field (format: "nft:TOKEN_ID" in comment field)
    Passwd,
}

/// Wallet mode configuration
#[derive(Debug, Clone, Deserialize)]
pub struct WalletConfig {
    /// Path to wallets file (address:username mappings)
    #[serde(default = "default_wallets_path")]
    pub wallets_path: String,
}

/// Blockchain service configuration (for NFT mode)
#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainConfig {
    /// Unix socket path for web3-auth-svc
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
    /// Chain ID (1 = mainnet, 137 = polygon, etc.)
    pub chain_id: u64,
    /// NFT contract address
    pub nft_contract: String,
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

/// LDAP configuration (for NFT mode)
#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., ldap://localhost:389)
    pub server: String,
    /// Base DN for searches
    pub base_dn: String,
    /// Bind DN for authentication
    pub bind_dn: String,
    /// Path to file containing bind password
    pub bind_password_file: String,
    /// Attribute name for NFT token ID
    #[serde(default = "default_token_id_attr")]
    pub token_id_attribute: String,
    /// Attribute name for revocation flag
    #[serde(default = "default_revoked_attr")]
    pub revoked_attribute: String,
    /// Attribute name for Linux username
    #[serde(default = "default_username_attr")]
    pub username_attribute: String,
    /// Connection timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

// Default value functions
fn default_otp_length() -> usize {
    6
}

fn default_otp_ttl() -> u64 {
    300
}

fn default_wallets_path() -> String {
    "/etc/pam_web3/wallets".to_string()
}

fn default_socket_path() -> String {
    "/run/web3-auth/web3-auth.sock".to_string()
}

fn default_timeout() -> u64 {
    10
}

fn default_token_id_attr() -> String {
    "nftTokenId".to_string()
}

fn default_revoked_attr() -> String {
    "nftRevoked".to_string()
}

fn default_username_attr() -> String {
    "linuxUsername".to_string()
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
        match self.auth.mode {
            AuthMode::Wallet => {
                // Wallet mode requires secret_key and wallet config
                if self.machine.secret_key.is_none() {
                    return Err(ConfigError::MissingField("machine.secret_key"));
                }
                if self.wallet.is_none() {
                    return Err(ConfigError::MissingField("[wallet] section"));
                }
            }
            AuthMode::Nft => {
                // NFT mode requires blockchain config and secret_key for OTP
                if self.machine.secret_key.is_none() {
                    return Err(ConfigError::MissingField("machine.secret_key"));
                }
                if self.blockchain.is_none() {
                    return Err(ConfigError::MissingField("[blockchain] section"));
                }
                // LDAP config only required when using LDAP lookup
                if self.auth.nft_lookup == NftLookupMethod::Ldap && self.ldap.is_none() {
                    return Err(ConfigError::MissingField("[ldap] section (required when nft_lookup = \"ldap\")"));
                }
            }
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

    /// Load the LDAP bind password (for NFT mode)
    pub fn load_ldap_password(&self) -> Result<String, ConfigError> {
        let ldap = self
            .ldap
            .as_ref()
            .ok_or(ConfigError::MissingField("[ldap] section"))?;
        let password = fs::read_to_string(&ldap.bind_password_file)?;
        Ok(password.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wallet_config() {
        let config_str = r#"
[machine]
id = "my-server"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
mode = "wallet"
signing_url = "https://example.com/sign"

[wallet]
wallets_path = "/etc/pam_web3/wallets"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert_eq!(config.machine.id, "my-server");
        assert_eq!(config.auth.mode, AuthMode::Wallet);
        assert_eq!(config.auth.otp_length, 6); // default
        assert!(config.wallet.is_some());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_parse_nft_config() {
        let config_str = r#"
[machine]
id = "server-prod-01"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
mode = "nft"
signing_url = "https://auth.example.com/verify"
otp_ttl_seconds = 600

[blockchain]
chain_id = 1
nft_contract = "0x1234567890abcdef1234567890abcdef12345678"

[ldap]
server = "ldap://localhost:389"
base_dn = "ou=nft,dc=example,dc=com"
bind_dn = "cn=pam,dc=example,dc=com"
bind_password_file = "/etc/pam_web3/ldap.secret"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert_eq!(config.machine.id, "server-prod-01");
        assert_eq!(config.auth.mode, AuthMode::Nft);
        assert_eq!(config.auth.otp_ttl_seconds, 600);
        assert!(config.blockchain.is_some());
        assert!(config.ldap.is_some());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_wallet_mode_missing_secret_key() {
        let config_str = r#"
[machine]
id = "my-server"

[auth]
mode = "wallet"
signing_url = "https://example.com/sign"

[wallet]
wallets_path = "/etc/pam_web3/wallets"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_nft_mode_missing_blockchain() {
        let config_str = r#"
[machine]
id = "my-server"
secret_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[auth]
mode = "nft"
signing_url = "https://example.com/sign"

[ldap]
server = "ldap://localhost:389"
base_dn = "ou=nft,dc=example,dc=com"
bind_dn = "cn=pam,dc=example,dc=com"
bind_password_file = "/etc/pam_web3/ldap.secret"
"#;

        let config: Config = toml::from_str(config_str).unwrap();
        assert!(config.validate().is_err());
    }
}
