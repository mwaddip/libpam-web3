//! Passwd-based wallet address lookup
//!
//! Maps wallet addresses to Linux usernames by scanning /etc/passwd for users
//! with "wallet=ADDRESS" in their GECOS (comment) field.
//!
//! # GECOS Field Format
//!
//! The module looks for the pattern `wallet=ADDRESS` in the GECOS field:
//!
//! ```text
//! johndoe:x:1001:1001:wallet=0x1234...abcd:/home/johndoe:/bin/bash
//! janedoe:x:1002:1002:wallet=0xabcd...1234,nft=5:/home/janedoe:/bin/bash
//! ```
//!
//! The wallet address can appear anywhere in the GECOS field, separated by
//! commas or as the entire field. Matching is case-insensitive.

use std::fs::File;
use std::io::{BufRead, BufReader};
use thiserror::Error;

const PASSWD_PATH: &str = "/etc/passwd";

#[derive(Debug, Error)]
pub enum PasswdLookupError {
    #[error("failed to read passwd file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("wallet address not found in passwd")]
    WalletNotFound,
}

/// Result of a successful passwd lookup
#[derive(Debug)]
pub struct PasswdLookupResult {
    pub username: String,
}

/// Look up the wallet address for a specific username from /etc/passwd.
///
/// Reads the user's GECOS field and extracts the wallet=ADDRESS value.
pub fn lookup_wallet_for_user(username: &str) -> Result<String, PasswdLookupError> {
    lookup_wallet_for_user_from_file(username, PASSWD_PATH)
}

/// Look up the wallet address for a specific username from a specific passwd file.
pub fn lookup_wallet_for_user_from_file(
    username: &str,
    passwd_path: &str,
) -> Result<String, PasswdLookupError> {
    let file = File::open(passwd_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 5 {
            continue;
        }

        if fields[0] == username {
            let gecos = fields[4];
            if let Some(address) = extract_wallet_address(gecos) {
                return Ok(address);
            }
            return Err(PasswdLookupError::WalletNotFound);
        }
    }

    Err(PasswdLookupError::WalletNotFound)
}

/// Look up a username by wallet address in /etc/passwd
///
/// Searches the GECOS field of each passwd entry for "wallet=ADDRESS".
/// Matching is case-insensitive on the address portion.
pub fn lookup_by_wallet_address(
    wallet_address: &str,
) -> Result<PasswdLookupResult, PasswdLookupError> {
    lookup_by_wallet_address_from_file(wallet_address, PASSWD_PATH)
}

/// Look up a username by wallet address from a specific passwd file
/// (useful for testing)
pub fn lookup_by_wallet_address_from_file(
    wallet_address: &str,
    passwd_path: &str,
) -> Result<PasswdLookupResult, PasswdLookupError> {
    let normalized_target = wallet_address.to_lowercase();

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

        // Check if GECOS contains wallet=ADDRESS
        if let Some(found_address) = extract_wallet_address(gecos) {
            if found_address.to_lowercase() == normalized_target {
                return Ok(PasswdLookupResult {
                    username: username.to_string(),
                });
            }
        }
    }

    Err(PasswdLookupError::WalletNotFound)
}

/// Extract wallet address from a GECOS field
///
/// Looks for patterns like:
/// - "wallet=0x1234...abcd" (entire field or comma-separated part)
/// - "wallet=0xAbCd...1234,nft=5"
fn extract_wallet_address(gecos: &str) -> Option<String> {
    for part in gecos.split(',') {
        let part = part.trim();
        if let Some(addr) = part.strip_prefix("wallet=") {
            return Some(addr.trim().to_string());
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
        file.as_file().sync_all().unwrap();
        file
    }

    #[test]
    fn test_simple_lookup() {
        let passwd = create_test_passwd(concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "johndoe:x:1001:1001:wallet=0x1234567890abcdef1234567890abcdef12345678:/home/johndoe:/bin/bash\n",
            "janedoe:x:1002:1002:wallet=0xabcdef1234567890abcdef1234567890abcdef12:/home/janedoe:/bin/bash\n",
        ));

        let path = passwd.path().to_str().unwrap();
        let result = lookup_by_wallet_address_from_file(
            "0x1234567890abcdef1234567890abcdef12345678",
            path,
        )
        .unwrap();
        assert_eq!(result.username, "johndoe");

        let result = lookup_by_wallet_address_from_file(
            "0xabcdef1234567890abcdef1234567890abcdef12",
            path,
        )
        .unwrap();
        assert_eq!(result.username, "janedoe");
    }

    #[test]
    fn test_case_insensitive_lookup() {
        let passwd = create_test_passwd(
            "johndoe:x:1001:1001:wallet=0xAbCdEf1234567890AbCdEf1234567890AbCdEf12:/home/johndoe:/bin/bash\n",
        );

        let path = passwd.path().to_str().unwrap();
        // Search with lowercase
        let result = lookup_by_wallet_address_from_file(
            "0xabcdef1234567890abcdef1234567890abcdef12",
            path,
        )
        .unwrap();
        assert_eq!(result.username, "johndoe");

        // Search with uppercase
        let result = lookup_by_wallet_address_from_file(
            "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
            path,
        )
        .unwrap();
        assert_eq!(result.username, "johndoe");
    }

    #[test]
    fn test_lookup_with_nft_field() {
        let passwd = create_test_passwd(
            "johndoe:x:1001:1001:wallet=0x1234567890abcdef1234567890abcdef12345678,nft=5:/home/johndoe:/bin/bash\n",
        );

        let result = lookup_by_wallet_address_from_file(
            "0x1234567890abcdef1234567890abcdef12345678",
            passwd.path().to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(result.username, "johndoe");
    }

    #[test]
    fn test_wallet_not_found() {
        let passwd = create_test_passwd(concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "johndoe:x:1001:1001:wallet=0x1234567890abcdef1234567890abcdef12345678:/home/johndoe:/bin/bash\n",
        ));

        let result = lookup_by_wallet_address_from_file(
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            passwd.path().to_str().unwrap(),
        );
        assert!(matches!(result, Err(PasswdLookupError::WalletNotFound)));
    }

    #[test]
    fn test_user_without_wallet() {
        let passwd = create_test_passwd(concat!(
            "root:x:0:0:root:/root:/bin/bash\n",
            "normaluser:x:1000:1000:Normal User:/home/normal:/bin/bash\n",
            "johndoe:x:1001:1001:wallet=0x1234567890abcdef1234567890abcdef12345678:/home/johndoe:/bin/bash\n",
        ));

        let result = lookup_by_wallet_address_from_file(
            "0x1234567890abcdef1234567890abcdef12345678",
            passwd.path().to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(result.username, "johndoe");
    }

    #[test]
    fn test_extract_wallet_address() {
        assert_eq!(
            extract_wallet_address("wallet=0x1234"),
            Some("0x1234".to_string())
        );
        assert_eq!(
            extract_wallet_address("wallet=0xAbCd,nft=5"),
            Some("0xAbCd".to_string())
        );
        assert_eq!(
            extract_wallet_address("nft=5,wallet=0x1234"),
            Some("0x1234".to_string())
        );
        assert_eq!(
            extract_wallet_address("Name,wallet=0x1234,Dept"),
            Some("0x1234".to_string())
        );
        assert_eq!(extract_wallet_address("Just a name"), None);
        assert_eq!(extract_wallet_address("nft=5"), None);
        assert_eq!(extract_wallet_address(""), None);
    }
}
