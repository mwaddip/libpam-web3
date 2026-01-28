//! Passwd-based NFT token ID lookup
//!
//! This module provides a simple alternative to LDAP for mapping NFT token IDs
//! to Linux usernames. It searches /etc/passwd for users with "nft=TOKEN_ID"
//! in their GECOS (comment) field.
//!
//! # GECOS Field Format
//!
//! The module looks for the pattern `nft=TOKEN_ID` in the GECOS field:
//!
//! ```text
//! johndoe:x:1001:1001:nft=0:/home/johndoe:/bin/bash
//! janedoe:x:1002:1002:Jane Doe,nft=5:/home/janedoe:/bin/bash
//! ```
//!
//! Note: We use `=` instead of `:` because the GECOS field cannot contain colons
//! (colons are the field delimiter in /etc/passwd).
//!
//! The token ID can appear anywhere in the GECOS field, separated by commas
//! or as the entire field.

use std::fs::File;
use std::io::{BufRead, BufReader};
use thiserror::Error;

const PASSWD_PATH: &str = "/etc/passwd";

#[derive(Debug, Error)]
pub enum PasswdLookupError {
    #[error("failed to read passwd file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("token ID not found in passwd")]
    TokenNotFound,
    #[error("invalid passwd entry")]
    InvalidEntry,
}

/// Result of a successful passwd lookup
#[derive(Debug)]
pub struct PasswdLookupResult {
    pub username: String,
}

/// Normalize token ID to decimal string for comparison
fn normalize_token_id(token_id: &str) -> String {
    let token_id = token_id.trim();
    // If it's a hex string, convert to decimal
    if let Some(hex_str) = token_id.strip_prefix("0x") {
        if let Ok(num) = u128::from_str_radix(hex_str, 16) {
            return num.to_string();
        }
    }
    // Also handle hex without 0x prefix if it looks like hex (64 chars of hex)
    if token_id.len() == 64 && token_id.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Ok(num) = u128::from_str_radix(token_id, 16) {
            return num.to_string();
        }
    }
    token_id.to_string()
}

/// Look up a username by NFT token ID in /etc/passwd
///
/// Searches the GECOS field of each passwd entry for "nft=TOKEN_ID".
/// The token ID is normalized (hex converted to decimal) before comparison.
pub fn lookup_by_token_id(token_id: &str) -> Result<PasswdLookupResult, PasswdLookupError> {
    lookup_by_token_id_from_file(token_id, PASSWD_PATH)
}

/// Look up a username by NFT token ID from a specific passwd file
/// (useful for testing)
pub fn lookup_by_token_id_from_file(
    token_id: &str,
    passwd_path: &str,
) -> Result<PasswdLookupResult, PasswdLookupError> {
    let normalized_id = normalize_token_id(token_id);

    let file = File::open(passwd_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse passwd entry: username:password:uid:gid:gecos:home:shell
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 5 {
            continue;
        }

        let username = fields[0];
        let gecos = fields[4];

        // Check if GECOS contains nft=TOKEN_ID
        if let Some(found_id) = extract_nft_token_id(gecos) {
            let normalized_found = normalize_token_id(&found_id);
            if normalized_found == normalized_id {
                return Ok(PasswdLookupResult {
                    username: username.to_string(),
                });
            }
        }
    }

    Err(PasswdLookupError::TokenNotFound)
}

/// Extract NFT token ID from a GECOS field
///
/// Looks for patterns like:
/// - "nft=123" (entire field or comma-separated part)
/// - "John Doe,nft=0,Room 42"
fn extract_nft_token_id(gecos: &str) -> Option<String> {
    // Split by comma and check each part
    for part in gecos.split(',') {
        let part = part.trim();
        if let Some(id) = part.strip_prefix("nft=") {
            return Some(id.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_passwd(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        // Ensure data is synced to disk
        file.as_file().sync_all().unwrap();
        file
    }

    #[test]
    fn test_simple_lookup() {
        let passwd = create_test_passwd(concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "johndoe:x:1001:1001:nft=0:/home/johndoe:/bin/bash\n",
            "janedoe:x:1002:1002:nft=1:/home/janedoe:/bin/bash\n",
        ));

        let path = passwd.path().to_str().unwrap();
        let result = lookup_by_token_id_from_file("0", path).unwrap();
        assert_eq!(result.username, "johndoe");

        let result = lookup_by_token_id_from_file("1", path).unwrap();
        assert_eq!(result.username, "janedoe");
    }

    #[test]
    fn test_lookup_with_gecos_fields() {
        let passwd = create_test_passwd(
            "johndoe:x:1001:1001:John Doe,nft=42,Engineering:/home/johndoe:/bin/bash\n",
        );

        let result = lookup_by_token_id_from_file("42", passwd.path().to_str().unwrap()).unwrap();
        assert_eq!(result.username, "johndoe");
    }

    #[test]
    fn test_hex_token_id() {
        let passwd = create_test_passwd("johndoe:x:1001:1001:nft=10:/home/johndoe:/bin/bash\n");

        // Search with hex, should find decimal 10
        let result =
            lookup_by_token_id_from_file("0xa", passwd.path().to_str().unwrap()).unwrap();
        assert_eq!(result.username, "johndoe");

        // Search with decimal 10
        let result = lookup_by_token_id_from_file("10", passwd.path().to_str().unwrap()).unwrap();
        assert_eq!(result.username, "johndoe");
    }

    #[test]
    fn test_token_not_found() {
        let passwd = create_test_passwd(concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "johndoe:x:1001:1001:nft=0:/home/johndoe:/bin/bash\n",
        ));

        let result = lookup_by_token_id_from_file("999", passwd.path().to_str().unwrap());
        assert!(matches!(result, Err(PasswdLookupError::TokenNotFound)));
    }

    #[test]
    fn test_user_without_nft() {
        let passwd = create_test_passwd(concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "normaluser:x:1000:1000:Normal User:/home/normal:/bin/bash\n",
            "johndoe:x:1001:1001:nft=0:/home/johndoe:/bin/bash\n",
        ));

        // Should still find the NFT user
        let result = lookup_by_token_id_from_file("0", passwd.path().to_str().unwrap()).unwrap();
        assert_eq!(result.username, "johndoe");
    }

    #[test]
    fn test_normalize_token_id() {
        assert_eq!(normalize_token_id("0"), "0");
        assert_eq!(normalize_token_id("123"), "123");
        assert_eq!(normalize_token_id("0x0"), "0");
        assert_eq!(normalize_token_id("0xa"), "10");
        assert_eq!(normalize_token_id("0x10"), "16");
        assert_eq!(
            normalize_token_id(
                "0x0000000000000000000000000000000000000000000000000000000000000005"
            ),
            "5"
        );
    }

    #[test]
    fn test_extract_nft_token_id() {
        assert_eq!(extract_nft_token_id("nft=0"), Some("0".to_string()));
        assert_eq!(extract_nft_token_id("nft=123"), Some("123".to_string()));
        assert_eq!(
            extract_nft_token_id("John Doe,nft=42"),
            Some("42".to_string())
        );
        assert_eq!(
            extract_nft_token_id("nft=5,Room 101"),
            Some("5".to_string())
        );
        assert_eq!(
            extract_nft_token_id("Name,nft=7,Dept"),
            Some("7".to_string())
        );
        assert_eq!(extract_nft_token_id("Just a name"), None);
        assert_eq!(extract_nft_token_id(""), None);
    }
}
