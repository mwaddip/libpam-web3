//! PAM Web3 Authentication Module
//!
//! Authenticate Linux users via Ethereum wallet signatures.
//!
//! # Authentication Flow
//!
//! 1. PAM generates OTP and displays signing URL
//! 2. User signs OTP with their wallet (MetaMask, etc.)
//! 3. User pastes signature into terminal
//! 4. PAM recovers wallet address from signature
//! 5. PAM looks up wallet address in the authorized wallets file
//! 6. If found, authentication succeeds with the mapped username
//!
//! # Security
//!
//! - OTP is bound to machine ID and timestamp (prevents replay attacks)
//! - Signature verification uses secp256k1 ecrecover
//! - Fail-secure: any error results in authentication denial

pub mod otp;
pub mod signature;

use otp::Otp;
use pam::ffi::{pam_conv, pam_get_item, pam_set_item, PAM_CONV, PAM_USER};
use pam::{export_pam_module, PamHandle, PamModule, PamReturnCode};
use std::collections::HashMap;
use std::ffi::{c_int, c_void, CStr, CString};
use std::fs;
use std::os::raw::c_uint;
use std::path::Path;
use std::ptr;

/// Default configuration file path
const DEFAULT_CONFIG_PATH: &str = "/etc/pam_web3/config.conf";

/// Default wallets file path
const DEFAULT_WALLETS_PATH: &str = "/etc/pam_web3/wallets";

/// Default signing URL
const DEFAULT_SIGNING_URL: &str = "https://your-signing-page.example.com";

/// Configuration for the PAM module
#[derive(Debug)]
struct Config {
    /// URL where users sign OTP codes
    signing_url: String,
    /// Path to wallets file
    wallets_path: String,
    /// OTP code length
    otp_length: usize,
    /// OTP validity in seconds
    otp_ttl_seconds: u64,
    /// Machine ID for OTP generation
    machine_id: String,
    /// Secret key for OTP HMAC (hex encoded)
    secret_key: String,
}

impl Config {
    /// Load configuration from file
    fn load() -> Result<Self, AuthError> {
        let config_path = Path::new(DEFAULT_CONFIG_PATH);

        if config_path.exists() {
            let content = fs::read_to_string(config_path).map_err(|_| AuthError::ConfigError)?;
            Self::parse(&content)
        } else {
            Err(AuthError::ConfigError)
        }
    }

    /// Parse configuration from string
    fn parse(content: &str) -> Result<Self, AuthError> {
        let mut signing_url = DEFAULT_SIGNING_URL.to_string();
        let mut wallets_path = DEFAULT_WALLETS_PATH.to_string();
        let mut otp_length = 6;
        let mut otp_ttl_seconds = 300;
        let mut machine_id = String::new();
        let mut secret_key = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "signing_url" => signing_url = value.to_string(),
                    "wallets_path" => wallets_path = value.to_string(),
                    "otp_length" => {
                        otp_length = value.parse().unwrap_or(6);
                    }
                    "otp_ttl_seconds" => {
                        otp_ttl_seconds = value.parse().unwrap_or(300);
                    }
                    "machine_id" => machine_id = value.to_string(),
                    "secret_key" => secret_key = value.to_string(),
                    _ => {}
                }
            }
        }

        if machine_id.is_empty() || secret_key.is_empty() {
            return Err(AuthError::ConfigError);
        }

        Ok(Self {
            signing_url,
            wallets_path,
            otp_length,
            otp_ttl_seconds,
            machine_id,
            secret_key,
        })
    }

    /// Get the secret key as bytes
    fn secret_key_bytes(&self) -> Result<Vec<u8>, AuthError> {
        let key = self.secret_key.strip_prefix("0x").unwrap_or(&self.secret_key);
        hex::decode(key).map_err(|_| AuthError::ConfigError)
    }
}

/// Load wallet-to-username mappings from file
///
/// File format: one mapping per line
/// ```text
/// # Comments start with #
/// 0x1234567890abcdef1234567890abcdef12345678:alice
/// 0xabcdef1234567890abcdef1234567890abcdef12:bob
/// ```
fn load_wallets(path: &str) -> Result<HashMap<String, String>, AuthError> {
    let content = fs::read_to_string(path).map_err(|_| AuthError::WalletsFileError)?;

    let mut wallets = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((address, username)) = line.split_once(':') {
            let address = address.trim().to_lowercase();
            let username = username.trim().to_string();

            if !address.is_empty() && !username.is_empty() {
                wallets.insert(address, username);
            }
        }
    }

    Ok(wallets)
}

/// PAM module entry point
pub struct PamWeb3;

impl PamModule for PamWeb3 {
    fn authenticate(handle: &PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
        match authenticate_impl(handle) {
            Ok(username) => {
                if set_pam_user(handle, &username).is_err() {
                    return PamReturnCode::Auth_Err;
                }
                PamReturnCode::Success
            }
            Err(_) => PamReturnCode::Auth_Err,
        }
    }

    fn set_credentials(_handle: &PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
        PamReturnCode::Success
    }

    fn account_management(_handle: &PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
        PamReturnCode::Success
    }
}

export_pam_module!(PamWeb3);

/// Send a message to the user and get a response via PAM conversation
fn pam_prompt(
    handle: &PamHandle,
    msg_style: c_int,
    message: &str,
) -> Result<Option<String>, AuthError> {
    let mut conv_ptr: *const c_void = ptr::null();
    let handle_ptr = handle as *const PamHandle as *mut PamHandle;

    let result = unsafe { pam_get_item(handle_ptr, PAM_CONV, &mut conv_ptr) };

    if result != 0 || conv_ptr.is_null() {
        return Err(AuthError::ConvError);
    }

    let conv = unsafe { &*(conv_ptr as *const pam_conv) };
    let conv_fn = conv.conv.ok_or(AuthError::ConvError)?;

    let msg_cstring = CString::new(message).map_err(|_| AuthError::ConvError)?;
    let pam_msg = pam::ffi::pam_message {
        msg_style,
        msg: msg_cstring.as_ptr(),
    };
    let msg_ptr: *const pam::ffi::pam_message = &pam_msg;
    let msg_ptr_ptr: *mut *const pam::ffi::pam_message = &mut (msg_ptr as *const _);

    let mut resp_ptr: *mut pam::ffi::pam_response = ptr::null_mut();

    let result = unsafe { conv_fn(1, msg_ptr_ptr, &mut resp_ptr, conv.appdata_ptr) };

    if result != 0 {
        return Err(AuthError::ConvError);
    }

    if !resp_ptr.is_null() {
        let resp = unsafe { &*resp_ptr };
        if !resp.resp.is_null() {
            let response = unsafe { CStr::from_ptr(resp.resp) }
                .to_str()
                .map_err(|_| AuthError::ConvError)?
                .to_string();
            unsafe {
                libc::free(resp.resp as *mut c_void);
                libc::free(resp_ptr as *mut c_void);
            }
            return Ok(Some(response));
        }
        unsafe {
            libc::free(resp_ptr as *mut c_void);
        }
    }

    Ok(None)
}

/// Set the PAM user
fn set_pam_user(handle: &PamHandle, username: &str) -> Result<(), AuthError> {
    let username_cstring = CString::new(username).map_err(|_| AuthError::ConvError)?;
    let handle_ptr = handle as *const PamHandle as *mut PamHandle;

    let result =
        unsafe { pam_set_item(handle_ptr, PAM_USER, username_cstring.as_ptr() as *const c_void) };

    if result != 0 {
        return Err(AuthError::ConvError);
    }

    Ok(())
}

/// Log to syslog for debugging
fn syslog(msg: &str) {
    use std::ffi::CString;
    if let Ok(c_msg) = CString::new(format!("pam_web3: {}", msg)) {
        unsafe {
            libc::openlog(
                b"pam_web3\0".as_ptr() as *const i8,
                libc::LOG_PID,
                libc::LOG_AUTH,
            );
            libc::syslog(libc::LOG_INFO, b"%s\0".as_ptr() as *const i8, c_msg.as_ptr());
            libc::closelog();
        }
    }
}

/// Internal authentication implementation
fn authenticate_impl(handle: &PamHandle) -> Result<String, AuthError> {
    syslog("Starting authentication");

    // Load configuration
    let config = Config::load().map_err(|e| {
        syslog("Failed to load config");
        e
    })?;
    let secret_key = config.secret_key_bytes()?;
    syslog("Config loaded");

    // Generate OTP
    let otp_instance = Otp::generate(config.otp_length, &config.machine_id, &secret_key)
        .map_err(|_| AuthError::OtpError)?;

    // Display OTP and signing URL to user (PAM_TEXT_INFO = 4)
    let info_message = format!(
        "\n=== Web3 Authentication ===\nCode: {}\nMachine: {}\nSign at: {}\n",
        otp_instance.code, config.machine_id, config.signing_url
    );

    pam_prompt(handle, 4, &info_message)?;

    // Prompt for signature (PAM_PROMPT_ECHO_OFF = 1)
    let sig = pam_prompt(handle, 1, "Paste signature: ")?
        .ok_or(AuthError::NoSignature)?;

    if sig.is_empty() {
        syslog("Empty signature");
        return Err(AuthError::NoSignature);
    }
    syslog(&format!("Got signature: {}...{}", &sig[..10.min(sig.len())], &sig[sig.len().saturating_sub(10)..]));

    // Recover wallet address from signature
    let message = otp_instance.signing_message();
    syslog(&format!("Message: {}", message));

    let wallet_address = signature::recover_address(&message, &sig)
        .map_err(|e| {
            syslog(&format!("Signature recovery failed: {:?}", e));
            AuthError::InvalidSignature
        })?;
    syslog(&format!("Recovered address: {}", wallet_address));

    // Verify OTP hasn't expired
    otp_instance
        .verify(
            &otp_instance.code,
            &config.machine_id,
            &secret_key,
            config.otp_ttl_seconds,
        )
        .map_err(|e| {
            syslog(&format!("OTP verification failed: {:?}", e));
            AuthError::OtpExpired
        })?;
    syslog("OTP verified");

    // Load wallet mappings and look up the address
    let wallets = load_wallets(&config.wallets_path)?;
    syslog(&format!("Loaded {} wallets", wallets.len()));

    // Normalize address to lowercase with 0x prefix
    let normalized_address = format!("{}", wallet_address).to_lowercase();
    syslog(&format!("Looking up: {}", normalized_address));

    let username = wallets
        .get(&normalized_address)
        .ok_or_else(|| {
            syslog(&format!("Wallet not found: {}", normalized_address));
            AuthError::WalletNotAuthorized
        })?;

    syslog(&format!("Auth success for user: {}", username));
    Ok(username.clone())
}

/// Authentication error types
#[derive(Debug)]
enum AuthError {
    ConfigError,
    ConvError,
    OtpError,
    OtpExpired,
    NoSignature,
    InvalidSignature,
    WalletsFileError,
    WalletNotAuthorized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let config_str = r#"
# Config
signing_url = https://example.com/sign
wallets_path = /etc/pam_web3/wallets
otp_length = 8
otp_ttl_seconds = 600
machine_id = test-server
secret_key = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
"#;

        let config = Config::parse(config_str).unwrap();
        assert_eq!(config.signing_url, "https://example.com/sign");
        assert_eq!(config.wallets_path, "/etc/pam_web3/wallets");
        assert_eq!(config.otp_length, 8);
        assert_eq!(config.otp_ttl_seconds, 600);
        assert_eq!(config.machine_id, "test-server");
    }

    #[test]
    fn test_parse_wallets() {
        let wallets_content = r#"
# Authorized wallets
0x1234567890abcdef1234567890abcdef12345678:alice
0xABCDEF1234567890ABCDEF1234567890ABCDEF12:bob
"#;

        // Write to temp file
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_wallets");
        fs::write(&temp_file, wallets_content).unwrap();

        let wallets = load_wallets(temp_file.to_str().unwrap()).unwrap();

        assert_eq!(wallets.get("0x1234567890abcdef1234567890abcdef12345678"), Some(&"alice".to_string()));
        // Should be case-insensitive (stored lowercase)
        assert_eq!(wallets.get("0xabcdef1234567890abcdef1234567890abcdef12"), Some(&"bob".to_string()));

        fs::remove_file(temp_file).ok();
    }
}
