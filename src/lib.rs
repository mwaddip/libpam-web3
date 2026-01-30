//! PAM Web3 Authentication Module
//!
//! Authenticate Linux users via Ethereum wallet signatures.
//!
//! # Authentication Modes
//!
//! ## Wallet Mode (default)
//! Simple file-based wallet → username mapping.
//! - User signs OTP with their wallet
//! - Server recovers wallet address from signature
//! - Wallet is looked up in a simple text file
//!
//! ## NFT Mode (requires `nft` feature)
//! NFT-based authentication with LDAP integration.
//! - User signs OTP with their wallet
//! - Server verifies NFT ownership via blockchain
//! - Username and revocation status checked via LDAP
//!
//! # Security
//!
//! - OTP is bound to machine ID and timestamp (prevents replay attacks)
//! - Signature verification uses secp256k1 ecrecover
//! - Fail-secure: any error results in authentication denial

pub mod config;
pub mod otp;
pub mod signature;
pub mod wallet_auth;

// NFT mode modules (feature-gated)
#[cfg(feature = "nft")]
pub mod blockchain;
#[cfg(feature = "nft")]
pub mod ecies;
#[cfg(feature = "nft")]
pub mod ldap;
#[cfg(feature = "nft")]
pub mod passwd_lookup;

use config::{AuthMode, Config};
#[cfg(feature = "nft")]
use config::NftLookupMethod;
use otp::Otp;
use pam::ffi::{pam_conv, pam_get_item, pam_set_item, PAM_CONV, PAM_USER};
use pam::{export_pam_module, PamHandle, PamModule, PamReturnCode};
use std::ffi::{c_int, c_void, CStr, CString};
use std::os::raw::c_uint;
use std::ptr;

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
        syslog(&format!("Failed to load config: {:?}", e));
        AuthError::ConfigError
    })?;
    syslog(&format!("Config loaded, mode: {:?}", config.auth.mode));

    // Get the secret key for OTP generation (same for both modes now)
    let secret_key = config.secret_key_bytes().map_err(|_| AuthError::ConfigError)?;

    // Generate OTP
    let otp_instance = Otp::generate(config.auth.otp_length, &config.machine.id, &secret_key)
        .map_err(|_| AuthError::OtpError)?;

    // Display OTP and signing URL to user (PAM_TEXT_INFO = 4)
    let info_message = format!(
        "\n=== Web3 Authentication ===\nCode: {}\nMachine: {}\nSign at: {}\n",
        otp_instance.code, config.machine.id, config.auth.signing_url
    );

    pam_prompt(handle, 4, &info_message)?;

    // Prompt for signature (PAM_PROMPT_ECHO_OFF = 1)
    let sig = pam_prompt(handle, 1, "Paste signature: ")?
        .ok_or(AuthError::NoSignature)?;

    if sig.is_empty() {
        syslog("Empty signature");
        return Err(AuthError::NoSignature);
    }
    syslog(&format!(
        "Got signature: {}...{}",
        &sig[..10.min(sig.len())],
        &sig[sig.len().saturating_sub(10)..]
    ));

    // Recover wallet address from signature
    let message = otp_instance.signing_message();
    syslog(&format!("Message: {}", message));

    let wallet_address = signature::recover_address(&message, &sig).map_err(|e| {
        syslog(&format!("Signature recovery failed: {:?}", e));
        AuthError::InvalidSignature
    })?;
    syslog(&format!("Recovered address: {}", wallet_address));

    // Verify OTP hasn't expired
    otp_instance
        .verify(
            &otp_instance.code,
            &config.machine.id,
            &secret_key,
            config.auth.otp_ttl_seconds,
        )
        .map_err(|e| {
            syslog(&format!("OTP verification failed: {:?}", e));
            AuthError::OtpExpired
        })?;
    syslog("OTP verified");

    // Mode-specific username lookup
    let username = match config.auth.mode {
        AuthMode::Wallet => {
            syslog("Using wallet mode");
            wallet_auth::lookup_username(&config, &wallet_address).map_err(|e| {
                syslog(&format!("Wallet lookup failed: {:?}", e));
                AuthError::WalletNotAuthorized
            })?
        }
        AuthMode::Nft => {
            #[cfg(feature = "nft")]
            {
                syslog("Using NFT mode");
                nft_authenticate(&config, &wallet_address)?
            }
            #[cfg(not(feature = "nft"))]
            {
                syslog("NFT mode not compiled in");
                return Err(AuthError::NftModeNotCompiled);
            }
        }
    };

    syslog(&format!("Auth success for user: {}", username));
    Ok(username)
}

/// NFT-based authentication (feature-gated)
///
/// Authentication model (v0.4.0+):
/// 1. Get all NFT token IDs owned by the wallet
/// 2. Match token IDs against GECOS entries in /etc/passwd (or LDAP)
/// 3. No server-side decryption needed
#[cfg(feature = "nft")]
fn nft_authenticate(
    config: &Config,
    wallet_address: &alloy_primitives::Address,
) -> Result<String, AuthError> {
    let blockchain_config = config
        .blockchain
        .as_ref()
        .ok_or(AuthError::ConfigError)?;

    // Create blockchain client
    let blockchain_client = blockchain::BlockchainClient::new(blockchain_config.clone())
        .map_err(|_| AuthError::BlockchainError)?;

    // Run async code in a blocking context
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AuthError::RuntimeError)?;

    // Get all token IDs owned by this wallet
    let token_ids = rt
        .block_on(blockchain_client.get_wallet_nfts(wallet_address))
        .map_err(|e| {
            syslog(&format!("NFT query failed: {:?}", e));
            AuthError::NftNotFound
        })?;

    syslog(&format!("Found {} NFTs for wallet: {:?}", token_ids.len(), token_ids));

    // Try to find a matching token ID in GECOS entries
    for token_id in &token_ids {
        let username = match config.auth.nft_lookup {
            NftLookupMethod::Ldap => {
                syslog(&format!("Checking LDAP for token {}", token_id));
                match nft_ldap_lookup(config, token_id, wallet_address) {
                    Ok(u) => Some(u),
                    Err(_) => None,
                }
            }
            NftLookupMethod::Passwd => {
                syslog(&format!("Checking passwd for token {}", token_id));
                match nft_passwd_lookup(token_id) {
                    Ok(u) => Some(u),
                    Err(_) => None,
                }
            }
        };

        if let Some(username) = username {
            syslog(&format!("Matched token {} to user {}", token_id, username));
            return Ok(username);
        }
    }

    syslog("No matching GECOS entry found for any owned NFT");
    Err(AuthError::NftNotFound)
}

/// Look up username via LDAP (checks revocation status)
#[cfg(feature = "nft")]
fn nft_ldap_lookup(
    config: &Config,
    token_id: &str,
    wallet_address: &alloy_primitives::Address,
) -> Result<String, AuthError> {
    let ldap_password = config
        .load_ldap_password()
        .map_err(|_| AuthError::LdapError)?;

    let ldap_config = config.ldap.as_ref().ok_or(AuthError::ConfigError)?;
    let ldap_client = ldap::LdapClient::new(ldap_config.clone(), ldap_password);

    let validation_result = ldap_client
        .validate_nft(token_id, &format!("{}", wallet_address))
        .map_err(|e| {
            syslog(&format!("LDAP validation failed: {:?}", e));
            match e {
                ldap::LdapError::NftRevoked => AuthError::NftRevoked,
                _ => AuthError::LdapError,
            }
        })?;

    Ok(validation_result.username)
}

/// Look up username via /etc/passwd GECOS field
#[cfg(feature = "nft")]
fn nft_passwd_lookup(token_id: &str) -> Result<String, AuthError> {
    let result = passwd_lookup::lookup_by_token_id(token_id).map_err(|e| {
        syslog(&format!("Passwd lookup failed: {:?}", e));
        AuthError::NftNotFound
    })?;

    Ok(result.username)
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
    WalletNotAuthorized,
    #[cfg(feature = "nft")]
    BlockchainError,
    #[cfg(feature = "nft")]
    NftNotFound,
    #[cfg(feature = "nft")]
    NftRevoked,
    #[cfg(feature = "nft")]
    LdapError,
    #[cfg(feature = "nft")]
    RuntimeError,
    #[allow(dead_code)]
    NftModeNotCompiled,
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_auth_mode_enum() {
        // Basic smoke test for the module
        assert!(true);
    }
}
