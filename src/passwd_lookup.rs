//! Passwd-based wallet address lookup.
//!
//! Maps a Linux username to a wallet address by reading the user's GECOS
//! field via libc's `getpwnam_r`, which honors NSS — local /etc/passwd,
//! LDAP, sssd, systemd-userdb, etc. — instead of parsing /etc/passwd by hand.
//!
//! # GECOS Field Format
//!
//! ```text
//! johndoe:x:1001:1001:wallet=0x1234...abcd:/home/johndoe:/bin/bash
//! janedoe:x:1002:1002:wallet=0xabcd...1234,nft=5:/home/janedoe:/bin/bash
//! ```
//!
//! The wallet address can appear anywhere in the GECOS field, comma-separated.

use std::ffi::{CStr, CString};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PasswdLookupError {
    #[error("getpwnam_r failed: {0}")]
    SystemError(std::io::Error),
    #[error("invalid username")]
    InvalidUsername,
    #[error("wallet address not found in passwd")]
    WalletNotFound,
}

/// Look up the wallet address for a username via NSS.
///
/// Uses `getpwnam_r` — the thread-safe, NSS-aware variant — to find the
/// user's GECOS field and extract `wallet=ADDRESS` from it.
pub fn lookup_wallet_for_user(username: &str) -> Result<String, PasswdLookupError> {
    let username_c = CString::new(username).map_err(|_| PasswdLookupError::InvalidUsername)?;

    // getpwnam_r writes string pointers into our buffer. Start at 4KB and
    // grow on ERANGE — this matches what glibc's _SC_GETPW_R_SIZE_MAX
    // typically reports and is plenty for any sane GECOS.
    let mut buf = vec![0u8; 4096];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let rc = unsafe {
            libc::getpwnam_r(
                username_c.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };

        if rc == libc::ERANGE {
            if buf.len() >= 1 << 20 {
                return Err(PasswdLookupError::SystemError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "passwd buffer exceeded 1MB",
                )));
            }
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 {
            return Err(PasswdLookupError::SystemError(
                std::io::Error::from_raw_os_error(rc),
            ));
        }
        if result.is_null() {
            return Err(PasswdLookupError::WalletNotFound);
        }

        let gecos = unsafe { CStr::from_ptr(pwd.pw_gecos) }
            .to_str()
            .map_err(|_| PasswdLookupError::WalletNotFound)?;

        return extract_wallet_address(gecos).ok_or(PasswdLookupError::WalletNotFound);
    }
}

/// Extract wallet address from a GECOS field.
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

    /// Smoke-test getpwnam_r against an entry the test environment is
    /// guaranteed to have (root). We only assert that the lookup succeeds
    /// (or returns WalletNotFound — root almost certainly has no `wallet=`
    /// in GECOS, which is the expected outcome).
    #[test]
    fn test_lookup_root_returns_wallet_not_found() {
        let result = lookup_wallet_for_user("root");
        match result {
            Err(PasswdLookupError::WalletNotFound) => {}
            Ok(addr) => panic!("did not expect root to have wallet=: {}", addr),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_lookup_unknown_user() {
        let result = lookup_wallet_for_user("definitely-not-a-real-user-xyz");
        assert!(matches!(result, Err(PasswdLookupError::WalletNotFound)));
    }

    #[test]
    fn test_lookup_invalid_username() {
        // NUL byte → CString::new fails
        let result = lookup_wallet_for_user("foo\0bar");
        assert!(matches!(result, Err(PasswdLookupError::InvalidUsername)));
    }
}
