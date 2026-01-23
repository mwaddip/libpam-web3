//! LDAP client for NFT validation and username mapping
//!
//! Queries a local LDAP server to:
//! - Check if an NFT is revoked
//! - Get the Linux username mapped to an NFT/wallet

use crate::config::LdapConfig;
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("LDAP connection failed: {0}")]
    ConnectionFailed(String),
    #[error("LDAP bind failed: {0}")]
    BindFailed(String),
    #[error("LDAP search failed: {0}")]
    SearchFailed(String),
    #[error("NFT is revoked")]
    NftRevoked,
    #[error("NFT not found in LDAP")]
    NftNotFound,
    #[error("username not found for NFT")]
    UsernameNotFound,
}

/// Result of LDAP validation
#[derive(Debug)]
pub struct LdapValidationResult {
    /// The Linux username associated with this NFT
    pub username: String,
    /// Whether the NFT is marked as revoked
    pub revoked: bool,
}

/// LDAP client for NFT validation
pub struct LdapClient {
    config: LdapConfig,
    password: String,
}

impl LdapClient {
    /// Create a new LDAP client
    pub fn new(config: LdapConfig, password: String) -> Self {
        Self { config, password }
    }

    /// Validate an NFT and get the associated username
    ///
    /// # Arguments
    /// * `token_id` - The NFT token ID to validate
    /// * `wallet_address` - The wallet address (for additional validation)
    ///
    /// # Returns
    /// The validation result if the NFT is valid, or an error if validation fails
    pub fn validate_nft(
        &self,
        token_id: &str,
        wallet_address: &str,
    ) -> Result<LdapValidationResult, LdapError> {
        // Connect to LDAP
        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(self.config.timeout_seconds));

        let mut ldap = LdapConn::with_settings(settings, &self.config.server)
            .map_err(|e| LdapError::ConnectionFailed(e.to_string()))?;

        // Bind with credentials
        ldap.simple_bind(&self.config.bind_dn, &self.password)
            .map_err(|e| LdapError::BindFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::BindFailed(e.to_string()))?;

        // Search for the NFT entry
        let filter = format!(
            "(&({}={}))",
            self.config.token_id_attribute,
            escape_ldap_filter(token_id)
        );

        let (rs, _res) = ldap
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                vec![
                    &self.config.token_id_attribute,
                    &self.config.revoked_attribute,
                    &self.config.username_attribute,
                    "walletAddress", // Optional: for additional validation
                ],
            )
            .map_err(|e| LdapError::SearchFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::SearchFailed(e.to_string()))?;

        // Find matching entry
        for entry in rs {
            let entry = SearchEntry::construct(entry);

            // Check revocation status
            let revoked = entry
                .attrs
                .get(&self.config.revoked_attribute)
                .and_then(|v| v.first())
                .map(|v| v.to_lowercase() == "true" || v == "1")
                .unwrap_or(false);

            if revoked {
                let _ = ldap.unbind();
                return Err(LdapError::NftRevoked);
            }

            // Optionally verify wallet address matches
            if let Some(stored_wallet) = entry.attrs.get("walletAddress").and_then(|v| v.first()) {
                let wallet_lower = wallet_address.to_lowercase();
                let stored_lower = stored_wallet.to_lowercase();

                if !stored_lower.ends_with(&wallet_lower.trim_start_matches("0x"))
                    && !wallet_lower.ends_with(&stored_lower.trim_start_matches("0x"))
                {
                    continue; // Wallet doesn't match, try next entry
                }
            }

            // Get username
            let username = entry
                .attrs
                .get(&self.config.username_attribute)
                .and_then(|v| v.first())
                .cloned()
                .ok_or(LdapError::UsernameNotFound)?;

            let _ = ldap.unbind();

            return Ok(LdapValidationResult { username, revoked });
        }

        let _ = ldap.unbind();
        Err(LdapError::NftNotFound)
    }

    /// Check if an NFT is revoked (without getting username)
    ///
    /// # Arguments
    /// * `token_id` - The NFT token ID to check
    ///
    /// # Returns
    /// `true` if revoked, `false` if valid, or an error if the check fails
    pub fn is_revoked(&self, token_id: &str) -> Result<bool, LdapError> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(self.config.timeout_seconds));

        let mut ldap = LdapConn::with_settings(settings, &self.config.server)
            .map_err(|e| LdapError::ConnectionFailed(e.to_string()))?;

        ldap.simple_bind(&self.config.bind_dn, &self.password)
            .map_err(|e| LdapError::BindFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::BindFailed(e.to_string()))?;

        let filter = format!(
            "(&({}={}))",
            self.config.token_id_attribute,
            escape_ldap_filter(token_id)
        );

        let (rs, _res) = ldap
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                vec![&self.config.revoked_attribute],
            )
            .map_err(|e| LdapError::SearchFailed(e.to_string()))?
            .success()
            .map_err(|e| LdapError::SearchFailed(e.to_string()))?;

        let _ = ldap.unbind();

        for entry in rs {
            let entry = SearchEntry::construct(entry);

            let revoked = entry
                .attrs
                .get(&self.config.revoked_attribute)
                .and_then(|v| v.first())
                .map(|v| v.to_lowercase() == "true" || v == "1")
                .unwrap_or(false);

            return Ok(revoked);
        }

        // NFT not found in LDAP - treat as not revoked (blockchain is source of truth)
        // This allows for a lazy LDAP population model
        Ok(false)
    }
}

/// Escape special characters in LDAP filter values
fn escape_ldap_filter(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());

    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\5c"),
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\0' => escaped.push_str("\\00"),
            _ => escaped.push(c),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_ldap_filter() {
        assert_eq!(escape_ldap_filter("normal"), "normal");
        assert_eq!(escape_ldap_filter("test*value"), "test\\2avalue");
        assert_eq!(escape_ldap_filter("(test)"), "\\28test\\29");
        assert_eq!(escape_ldap_filter("back\\slash"), "back\\5cslash");
    }

    #[test]
    fn test_escape_ldap_filter_token_id() {
        // Token IDs are typically hex strings, which should be safe
        assert_eq!(
            escape_ldap_filter("0x1234567890abcdef"),
            "0x1234567890abcdef"
        );
    }
}
