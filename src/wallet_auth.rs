//! Wallet-based authentication
//!
//! Simple file-based wallet → username mapping.
//! The wallets file contains one mapping per line: `address:username`

use crate::config::{Config, ConfigError};
use alloy_primitives::Address;
use std::collections::HashMap;
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletAuthError {
    #[error("failed to read wallets file: {0}")]
    WalletsFileError(#[from] std::io::Error),
    #[error("wallet not authorized: {0}")]
    WalletNotAuthorized(String),
    #[error("configuration error: {0}")]
    ConfigError(#[from] ConfigError),
}

/// Load wallet-to-username mappings from file
///
/// File format: one mapping per line
/// ```text
/// # Comments start with #
/// 0x1234567890abcdef1234567890abcdef12345678:alice
/// 0xabcdef1234567890abcdef1234567890abcdef12:bob
/// ```
pub fn load_wallets(path: &str) -> Result<HashMap<String, String>, WalletAuthError> {
    let content = fs::read_to_string(path)?;

    let mut wallets = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((address, username)) = line.split_once(':') {
            // Normalize address: lowercase, ensure 0x prefix
            let address = address.trim().to_lowercase();
            let address = if address.starts_with("0x") {
                address
            } else {
                format!("0x{}", address)
            };
            let username = username.trim().to_string();

            if !address.is_empty() && !username.is_empty() {
                wallets.insert(address, username);
            }
        }
    }

    Ok(wallets)
}

/// Look up the username for a wallet address
pub fn lookup_username(config: &Config, wallet_address: &Address) -> Result<String, WalletAuthError> {
    let wallet_config = config
        .wallet
        .as_ref()
        .ok_or_else(|| ConfigError::MissingField("[wallet] section"))?;

    let wallets = load_wallets(&wallet_config.wallets_path)?;

    // Normalize the address to lowercase with 0x prefix
    let normalized_address = format!("{}", wallet_address).to_lowercase();

    wallets
        .get(&normalized_address)
        .cloned()
        .ok_or_else(|| WalletAuthError::WalletNotAuthorized(normalized_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_wallets() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
# Authorized wallets
0x1234567890abcdef1234567890abcdef12345678:alice
0xABCDEF1234567890ABCDEF1234567890ABCDEF12:bob
deadbeef1234567890deadbeef1234567890dead:charlie
"#
        )
        .unwrap();

        let wallets = load_wallets(file.path().to_str().unwrap()).unwrap();

        assert_eq!(
            wallets.get("0x1234567890abcdef1234567890abcdef12345678"),
            Some(&"alice".to_string())
        );
        // Should be normalized to lowercase
        assert_eq!(
            wallets.get("0xabcdef1234567890abcdef1234567890abcdef12"),
            Some(&"bob".to_string())
        );
        // Should have 0x prefix added
        assert_eq!(
            wallets.get("0xdeadbeef1234567890deadbeef1234567890dead"),
            Some(&"charlie".to_string())
        );
    }

    #[test]
    fn test_load_wallets_empty_lines_and_comments() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
# This is a comment

0x1234567890abcdef1234567890abcdef12345678:alice

# Another comment
"#
        )
        .unwrap();

        let wallets = load_wallets(file.path().to_str().unwrap()).unwrap();
        assert_eq!(wallets.len(), 1);
    }
}
