//! PAM Web3 Authentication Module
//!
//! Authenticate Linux users via wallet signatures.
//!
//! # Authentication Flow
//!
//! 1. PAM generates OTP challenge bound to machine ID
//! 2. User signs OTP with their wallet (EVM or OPNet)
//! 3. Signature is delivered via callback or manual paste
//! 4. PAM recovers/extracts wallet address
//! 5. Wallet address matched against GECOS field (wallet=ADDRESS)
//! 6. User authenticated as matching Linux user
//!
//! # Signature Content Detection
//!
//! - Raw hex → EVM path (secp256k1 ecrecover)
//! - JSON with otp/machine_id/wallet_address → OPNet path (OTP validation + trusted address)
//!
//! # Security
//!
//! - OTP is bound to machine ID and timestamp (prevents replay attacks)
//! - Signature verification uses secp256k1 ecrecover (EVM)
//! - OPNet path validates OTP before trusting wallet address
//! - Fail-secure: any error results in authentication denial

pub mod callback;
pub mod config;
pub mod otp;
pub mod passwd_lookup;
pub mod signature;

use config::Config;
use otp::Otp;
use pam::ffi::{pam_conv, pam_get_item, pam_set_item, PAM_CONV, PAM_USER};
use pam::{export_pam_module, PamHandle, PamModule, PamReturnCode};
use serde::Deserialize;
use std::ffi::{c_int, c_void, CStr, CString};
use std::os::raw::c_uint;
use std::ptr;

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_TEXT_INFO: c_int = 4;
const CALLBACK_GRACE_SECONDS: u64 = 10;

/// OPNet callback payload: wallet address + OTP delivered via trusted channel
#[derive(Debug, Deserialize)]
struct OPNetCallback {
    otp: String,
    machine_id: String,
    wallet_address: String,
}

/// PAM module entry point
pub struct PamWeb3;

impl PamModule for PamWeb3 {
    fn authenticate(handle: &PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
        unsafe {
            libc::openlog(
                b"pam_web3\0".as_ptr() as *const i8,
                libc::LOG_PID,
                libc::LOG_AUTH,
            );
        }

        let result = match authenticate_impl(handle) {
            Ok(username) => {
                if set_pam_user(handle, &username).is_err() {
                    PamReturnCode::Auth_Err
                } else {
                    PamReturnCode::Success
                }
            }
            Err(_) => PamReturnCode::Auth_Err,
        };

        unsafe { libc::closelog(); }
        result
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
///
/// Requires openlog() to have been called first (done in authenticate()).
fn syslog(msg: &str) {
    use std::ffi::CString;
    if let Ok(c_msg) = CString::new(format!("pam_web3: {}", msg)) {
        unsafe {
            libc::syslog(libc::LOG_INFO, b"%s\0".as_ptr() as *const i8, c_msg.as_ptr());
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
    syslog("Config loaded");

    // Get the secret key for OTP generation
    let secret_key = config.secret_key_bytes().map_err(|_| AuthError::ConfigError)?;

    // Generate OTP
    let otp_instance = Otp::generate(config.auth.otp_length, &config.machine.id, &secret_key)
        .map_err(|_| AuthError::OtpError)?;

    // Try to create a callback session (detected at runtime by directory existence)
    let session = match callback::Session::create(&otp_instance.code, &config.machine.id) {
        Ok(s) => {
            syslog(&format!("Callback session created: {}", s.session_id));
            Some(s)
        }
        Err(e) => {
            syslog(&format!("Callback not available (manual-only): {}", e));
            None
        }
    };

    // Build signing URL, append ?session= if callback session exists
    let signing_url = match &session {
        Some(s) => format!("{}?session={}", config.auth.signing_url, s.session_id),
        None => config.auth.signing_url.clone(),
    };

    // Display OTP and signing URL to user (PAM_TEXT_INFO = 4)
    let info_message = format!(
        "\n=== Web3 Authentication ===\nCode: {}\nMachine: {}\nSign at: {}\n",
        otp_instance.code, config.machine.id, signing_url
    );

    pam_prompt(handle, PAM_TEXT_INFO, &info_message)?;

    // Prompt for signature (different text when callback is available)
    let prompt_text = if session.is_some() {
        "Press Enter after signing in browser, or paste signature: "
    } else {
        "Paste signature: "
    };

    let sig_input = pam_prompt(handle, PAM_PROMPT_ECHO_OFF, prompt_text)?
        .unwrap_or_default();

    // Resolve signature and track source.
    // OPNet JSON is only trusted from callbacks (auth service validates the
    // wallet signature before writing the .sig file).  Manual paste must
    // always go through EVM ecrecover — otherwise an attacker could paste
    // JSON with a victim's wallet address and the on-screen OTP.
    let (sig, from_callback) = if !sig_input.is_empty() {
        (sig_input, false)
    } else if let Some(ref s) = session {
        syslog("Empty input, polling for callback signature...");
        match s.wait_for_callback(CALLBACK_GRACE_SECONDS) {
            Some(sig) => {
                syslog("Got callback signature");
                (sig, true)
            }
            None => {
                syslog("No callback signature received");
                return Err(AuthError::NoSignature);
            }
        }
    } else {
        syslog("Empty signature");
        return Err(AuthError::NoSignature);
    };
    syslog(&format!(
        "Got signature ({}): {}...{}",
        if from_callback { "callback" } else { "manual" },
        &sig[..10.min(sig.len())],
        &sig[sig.len().saturating_sub(10)..]
    ));

    // OPNet JSON is only accepted from callback; manual paste → always EVM
    let opnet = if from_callback {
        serde_json::from_str::<OPNetCallback>(&sig).ok()
    } else {
        None
    };

    let wallet_address_str = if let Some(opnet) = opnet {
        // OPNet path: validate OTP, then trust the wallet address from JSON
        syslog("OPNet callback detected");

        otp_instance
            .verify(
                &opnet.otp,
                &opnet.machine_id,
                &secret_key,
                config.auth.otp_ttl_seconds,
            )
            .map_err(|e| {
                syslog(&format!("OPNet OTP verification failed: {:?}", e));
                AuthError::OtpExpired
            })?;
        syslog("OPNet OTP verified");

        if opnet.wallet_address.is_empty() {
            syslog("OPNet callback has empty wallet_address");
            return Err(AuthError::InvalidSignature);
        }

        opnet.wallet_address
    } else {
        // EVM path: ecrecover to get wallet address from signature
        syslog("EVM signature detected");

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

        format!("{}", wallet_address)
    };

    // Unified GECOS lookup: wallet=ADDRESS
    let username = passwd_lookup::lookup_by_wallet_address(&wallet_address_str).map_err(|e| {
        syslog(&format!("Wallet lookup failed: {:?}", e));
        AuthError::WalletNotFound
    })?;

    syslog(&format!("Auth success for user: {}", username.username));
    Ok(username.username)
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
    WalletNotFound,
}
